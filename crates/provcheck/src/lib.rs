//! # provcheck-core
//!
//! Verify C2PA Content Credentials on any file format supported by
//! the upstream `c2pa` crate (audio, image, video).
//!
//! The library is intentionally thin — it wraps `c2pa::Reader` with a
//! stable [`Report`] type that both the CLI and the GUI render.
//! Behaviour is identical across front-ends because there is exactly
//! one code path through `verify_with_options` (and `verify` wraps
//! that with default options).
//!
//! ```no_run
//! use provcheck::prelude::*;
//! use std::path::Path;
//!
//! let report = verify(Path::new("signed.wav"))?;
//! if report.verified {
//!     println!("Signed by {:?}", report.signer);
//! }
//! # Ok::<(), Error>(())
//! ```

use std::path::Path;

use serde::{Deserialize, Serialize};

pub mod render;

pub mod prelude {
    pub use super::render;
    pub use super::{Error, Report, VerifyOptions, verify, verify_with_options};
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("file not found or unreadable: {0}")]
    Io(#[from] std::io::Error),
    #[error("C2PA read failed: {0}")]
    C2pa(#[from] c2pa::Error),
    #[error("invalid trust-store PEM: {0}")]
    InvalidTrustStore(String),
}

/// Options controlling a single `verify_with_options` call.
///
/// The default is equivalent to `verify(path)`: no trust-list policy,
/// no trust requirement. Set `trust_store_pem` + `require_trusted` to
/// enforce corporate / archival trust rules at the tool level.
#[derive(Debug, Default, Clone)]
pub struct VerifyOptions {
    /// Optional PEM bundle of additional trust-anchor root certificates.
    /// When `Some`, the bundle augments the default C2PA trust list so
    /// certificates chaining to any of these roots are marked trusted
    /// on the `Report`.
    ///
    /// The bundle is passed verbatim to `c2pa::Settings::trust.user_anchors`
    /// — see the C2PA crate docs for the exact PEM format expected
    /// (standard concatenated PEM, one BEGIN/END CERTIFICATE block per cert).
    pub trust_store_pem: Option<String>,

    /// When `true`, a manifest whose signing certificate does NOT chain
    /// to a trusted root (either the built-in C2PA trust list OR the
    /// optional `trust_store_pem` bundle) will report `verified: false`
    /// with a trust-specific failure reason.
    ///
    /// When `false` (the default), trust-list membership is advisory
    /// only — the `Report::trusted` field still reflects the check,
    /// but `verified` only tracks cryptographic integrity.
    ///
    /// This is the distinction the website's FAQ calls out: we report
    /// what the crypto says. Whether to require a trust-anchor is a
    /// separate policy call, made explicit here rather than baked in.
    pub require_trusted: bool,
}

/// The outcome of verifying a single file.
///
/// `verified` is the load-bearing field — everything else is
/// descriptive. Callers that only care about pass/fail should check
/// that one boolean; callers that display the manifest should walk
/// the richer fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// True iff the file carries a C2PA manifest that parses cleanly
    /// and whose signature validates. If `VerifyOptions::require_trusted`
    /// is set, also requires the signing certificate to be trusted.
    pub verified: bool,

    /// True iff the file has NO C2PA manifest at all (as distinct from
    /// a manifest that exists but fails verification).
    pub unsigned: bool,

    /// Tri-state trust-list membership:
    ///
    /// - `Some(true)`  — signing cert chains to a trusted root
    ///   (default C2PA list or user-provided anchors).
    /// - `Some(false)` — cert does NOT chain to any trusted root
    ///   (typical for per-install signers like rAIdio.bot's pattern).
    /// - `None` — no manifest, or trust status couldn't be determined
    ///   from the validation log.
    ///
    /// This field is reported regardless of `VerifyOptions::require_trusted`
    /// so policy decisions stay in the caller's hands.
    pub trusted: Option<bool>,

    /// Human-readable reason when `verified` is false. `None` when
    /// everything's fine.
    pub failure_reason: Option<String>,

    /// Identifier of the active manifest (`c2pa.id`), if any.
    pub active_manifest: Option<String>,

    /// Signer (certificate subject common name) of the active
    /// manifest, if any.
    pub signer: Option<String>,

    /// ISO-8601 timestamp of signing, if recorded.
    pub signed_at: Option<String>,

    /// Tool that produced the manifest (`claim_generator`).
    pub claim_generator: Option<String>,

    /// Free-form claim summary — assertion label → JSON value. Exposes
    /// AI-model assertions, training-data attestations, creator info,
    /// edit actions, etc.
    pub assertions: serde_json::Value,

    /// Count of ingredient manifests (parent files this one was
    /// derived from). 0 for a root artefact; >0 for edits / remixes.
    pub ingredient_count: usize,

    /// MIME type / format as reported by `c2pa`.
    pub format: Option<String>,

    /// Number of validation status entries. Zero means no validation
    /// errors; >0 means the signature or manifest had integrity issues
    /// (after filtering out codes that reflect trust-policy choices
    /// provcheck deliberately doesn't enforce by default).
    pub validation_errors: usize,
}

impl Report {
    /// Exit code convention used by the CLI.
    ///
    /// `0` — signed and verified (including trust, if required).
    /// `1` — unsigned OR invalid.
    /// The `2` exit-code for I/O errors is handled at the CLI layer,
    /// not by the report.
    pub fn exit_code(&self) -> i32 {
        if self.verified { 0 } else { 1 }
    }
}

/// Verify the C2PA credentials on the file at `path` with default
/// options (no trust-list enforcement).
///
/// See [`verify_with_options`] for the full-featured variant.
pub fn verify(path: &Path) -> Result<Report, Error> {
    verify_with_options(path, &VerifyOptions::default())
}

/// Verify the C2PA credentials on the file at `path` with caller-
/// controlled trust-list policy.
///
/// Returns a populated [`Report`]. Does not panic on unsigned or
/// invalid input — those are reported via the `Report` fields.
///
/// Only returns `Err` on I/O failure (file missing, unreadable) or
/// on an invalid `trust_store_pem`. An absent C2PA manifest is
/// reported as `unsigned: true` on the returned `Report`, not as an
/// error. A present-but-malformed or tamper-broken manifest is
/// reported as `verified: false` with a descriptive `failure_reason`.
pub fn verify_with_options(path: &Path, opts: &VerifyOptions) -> Result<Report, Error> {
    // Validate trust-store PEM before touching the filesystem — a
    // malformed PEM is a caller bug, not a file problem, and we want
    // it to surface cleanly regardless of whether the target file
    // exists.
    if let Some(pem) = opts.trust_store_pem.as_deref() {
        sanity_check_pem(pem)?;
    }

    // Guard: file must exist and be a file. c2pa::Reader would also
    // surface this, but a preflight check gives us a cleaner error.
    let _ = std::fs::metadata(path)?;

    let reader_result = if let Some(pem) = opts.trust_store_pem.as_deref() {
        // Build a Settings object that layers the caller's PEM bundle
        // on top of the default C2PA trust list. c2pa parses the PEM
        // lazily at verification time, so a malformed bundle surfaces
        // as a Reader error — we preflight it with `sanity_check_pem`
        // above to return a cleaner Error::InvalidTrustStore.
        let mut settings = c2pa::Settings::default();
        settings.trust.user_anchors = Some(pem.to_string());
        let context = c2pa::Context::new()
            .with_settings(settings)
            .map_err(|e| Error::InvalidTrustStore(e.to_string()))?;
        c2pa::Reader::from_context(context).with_file(path)
    } else {
        c2pa::Reader::from_file(path)
    };

    let reader = match reader_result {
        Ok(r) => r,
        Err(c2pa::Error::JumbfNotFound) | Err(c2pa::Error::JumbfBoxNotFound) => {
            return Ok(unsigned_report(None));
        }
        Err(c2pa::Error::UnsupportedType) => {
            return Ok(unsigned_report(Some(
                "file format not supported by the C2PA reader".into(),
            )));
        }
        Err(e) if is_manifest_parse_error(&e) => {
            return Ok(Report {
                verified: false,
                unsigned: false,
                trusted: None,
                failure_reason: Some(format!("manifest is malformed or tampered: {}", e)),
                active_manifest: None,
                signer: None,
                signed_at: None,
                claim_generator: None,
                assertions: serde_json::Value::Null,
                ingredient_count: 0,
                format: None,
                validation_errors: 1,
            });
        }
        Err(e) => return Err(Error::C2pa(e)),
    };

    let state = reader.validation_state();

    // Failure codes that we intentionally DO NOT treat as verification
    // failures for the default `verified` flag. Trust-list membership
    // is a separate dimension, reported via `trusted`. Callers who
    // want to enforce trust set `VerifyOptions::require_trusted`.
    const TRUST_POLICY_IGNORED: &[&str] = &[
        "signingCredential.untrusted",
        "timeStamp.untrusted",
        "timeStamp.mismatch",
        "signingCredential.ocsp.skipped",
        "signingCredential.ocsp.inaccessible",
    ];

    let status_codes: Vec<&c2pa::validation_status::ValidationStatus> = reader
        .validation_status()
        .map(|v| v.iter().collect())
        .unwrap_or_default();

    let validation_errors = status_codes
        .iter()
        .filter(|s| matches!(s.kind(), c2pa::status_tracker::LogKind::Failure))
        .filter(|s| !TRUST_POLICY_IGNORED.contains(&s.code()))
        .count();

    // Trust-list membership is only evaluated when the caller asked a
    // trust question — i.e. they supplied a trust store OR demanded
    // `require_trusted`. Without that, the `trusted` field stays None
    // and renderers omit the trust line entirely. Rationale: the c2pa
    // crate emits `signingCredential.untrusted` against its default
    // CAI trust list for any cert that isn't in it, which is most
    // per-install signing certs. Reporting "untrusted" by default
    // would be technically accurate but materially misleading.
    let trust_was_configured = opts.trust_store_pem.is_some() || opts.require_trusted;
    let trusted = if trust_was_configured {
        evaluate_trust(&reader)
    } else {
        None
    };

    // `verified` cryptographic integrity — same definition as before.
    let crypto_ok = matches!(
        state,
        c2pa::ValidationState::Valid | c2pa::ValidationState::Trusted
    );
    let crypto_and_no_errors = crypto_ok && validation_errors == 0;

    // Apply the caller's trust requirement on top of crypto.
    let verified = if opts.require_trusted {
        crypto_and_no_errors && matches!(trusted, Some(true))
    } else {
        crypto_and_no_errors
    };

    let active = reader.active_manifest();

    let (active_manifest, signer, signed_at, claim_generator, format, assertions, ingredient_count) =
        if let Some(m) = active {
            let sig = m.signature_info();
            let signer = sig.and_then(|s| s.common_name.clone().or_else(|| s.issuer.clone()));
            let signed_at = sig.and_then(|s| s.time.clone());

            let mut assertion_map = serde_json::Map::new();
            for a in m.assertions() {
                let key = a.label().to_string();
                let val = a
                    .value()
                    .cloned()
                    .unwrap_or_else(|_| serde_json::Value::String("<value unavailable>".into()));
                match assertion_map.remove(&key) {
                    Some(serde_json::Value::Array(mut arr)) => {
                        arr.push(val);
                        assertion_map.insert(key, serde_json::Value::Array(arr));
                    }
                    Some(existing) => {
                        assertion_map.insert(key, serde_json::Value::Array(vec![existing, val]));
                    }
                    None => {
                        assertion_map.insert(key, val);
                    }
                }
            }

            (
                m.label().map(|s| s.to_string()),
                signer,
                signed_at,
                m.claim_generator().map(|s| s.to_string()),
                m.format().map(|s| s.to_string()),
                serde_json::Value::Object(assertion_map),
                m.ingredients().len(),
            )
        } else {
            (None, None, None, None, None, serde_json::Value::Null, 0)
        };

    let failure_reason = if verified {
        None
    } else {
        Some(format_failure_reason(
            state,
            validation_errors,
            trusted,
            opts.require_trusted,
        ))
    };

    Ok(Report {
        verified,
        unsigned: false,
        trusted,
        failure_reason,
        active_manifest,
        signer,
        signed_at,
        claim_generator,
        assertions,
        ingredient_count,
        format,
        validation_errors,
    })
}

fn evaluate_trust(reader: &c2pa::Reader) -> Option<bool> {
    // Trust is a tri-state: trusted / untrusted / unknown.
    //
    // The c2pa crate records SIGNING_CREDENTIAL_TRUSTED as a SUCCESS
    // status and SIGNING_CREDENTIAL_UNTRUSTED as a FAILURE status.
    // `reader.validation_status()` only surfaces errors — so a
    // cleanly-trusted cert is invisible there. We have to look at
    // the full ValidationResults (success + failure lists) to
    // distinguish "trusted" from "not evaluated".
    let results = reader.validation_results()?;
    let active = results.active_manifest()?;

    if active
        .success()
        .iter()
        .any(|s| s.code() == "signingCredential.trusted")
    {
        return Some(true);
    }
    if active
        .failure()
        .iter()
        .any(|s| s.code() == "signingCredential.untrusted")
    {
        return Some(false);
    }
    None
}

fn sanity_check_pem(pem: &str) -> Result<(), Error> {
    if !pem.contains("-----BEGIN CERTIFICATE-----") {
        return Err(Error::InvalidTrustStore(
            "no BEGIN CERTIFICATE block found in PEM bundle".into(),
        ));
    }
    if !pem.contains("-----END CERTIFICATE-----") {
        return Err(Error::InvalidTrustStore(
            "no END CERTIFICATE block found in PEM bundle".into(),
        ));
    }
    Ok(())
}

/// c2pa errors that mean "the file is trying to carry a C2PA manifest
/// but it's broken / tampered / unparseable". These should surface as
/// failed-verification reports (exit 1), not as tool-level errors
/// (exit 2) — the user's question has a real answer.
///
/// Variant names tracked against c2pa 0.78.8's Error enum. When
/// bumping c2pa, recheck whether any new variants fit this category.
fn is_manifest_parse_error(err: &c2pa::Error) -> bool {
    use c2pa::Error::*;
    matches!(
        err,
        // JUMBF / manifest structure broken
        JumbfParseError(_)
            | InvalidClaim(_)
            | InvalidAsset(_)
            | ClaimDecoding(_)
            | ClaimEncoding
            | ClaimMissing { .. }
            | ClaimMissingSignatureBox
            | ClaimInvalidContent
            | AssertionMissing { .. }
            | AssertionDecoding(_)
            | AssertionEncoding(_)
            | AssertionInvalidRedaction
            // Cryptographic failure on signature verification
            | HashMismatch(_)
            | CoseSignatureAlgorithmNotSupported
            | CoseMissingKey
            | CoseX5ChainMissing
            | CoseInvalidCert
            | CoseSignature
            | CoseVerifier
            | CoseCertExpiration
            | CoseCertRevoked
            | InvalidCoseSignature { .. }
    )
}

fn unsigned_report(reason: Option<String>) -> Report {
    Report {
        verified: false,
        unsigned: true,
        trusted: None,
        failure_reason: reason,
        active_manifest: None,
        signer: None,
        signed_at: None,
        claim_generator: None,
        assertions: serde_json::Value::Null,
        ingredient_count: 0,
        format: None,
        validation_errors: 0,
    }
}

fn format_failure_reason(
    state: c2pa::ValidationState,
    error_count: usize,
    trusted: Option<bool>,
    require_trusted: bool,
) -> String {
    let plural = |n: usize| if n == 1 { "" } else { "s" };

    // Trust-requirement failure: crypto passed but cert isn't trusted.
    if require_trusted
        && matches!(trusted, Some(false) | None)
        && matches!(
            state,
            c2pa::ValidationState::Valid | c2pa::ValidationState::Trusted
        )
        && error_count == 0
    {
        return match trusted {
            Some(false) => "signing certificate is not on the configured trust list".into(),
            None => "trust status could not be established for the signing certificate".into(),
            Some(true) => unreachable!("trusted=true but failure_reason called"),
        };
    }

    // Crypto / manifest failures.
    match state {
        c2pa::ValidationState::Invalid => format!(
            "manifest failed structural or cryptographic validation ({} error{})",
            error_count.max(1),
            plural(error_count.max(1))
        ),
        c2pa::ValidationState::Valid | c2pa::ValidationState::Trusted => {
            if error_count > 0 {
                format!(
                    "content verification failed — {} validation error{} (likely tampered payload under a hash-bound manifest)",
                    error_count,
                    plural(error_count)
                )
            } else {
                "verification failed for an unspecified reason".into()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_is_io_error() {
        let err = verify(Path::new("does_not_exist_abcxyz.wav")).unwrap_err();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn exit_code_maps_verified_state() {
        let mut r = Report {
            verified: false,
            unsigned: true,
            trusted: None,
            failure_reason: None,
            active_manifest: None,
            signer: None,
            signed_at: None,
            claim_generator: None,
            assertions: serde_json::Value::Null,
            ingredient_count: 0,
            format: None,
            validation_errors: 0,
        };
        assert_eq!(r.exit_code(), 1);
        r.verified = true;
        assert_eq!(r.exit_code(), 0);
    }

    #[test]
    fn invalid_trust_store_pem_is_err() {
        let opts = VerifyOptions {
            trust_store_pem: Some("not a pem at all".into()),
            require_trusted: false,
        };
        // Use a fake path — sanity_check should reject the PEM
        // before we even look at the file.
        let err = verify_with_options(Path::new("any.wav"), &opts).unwrap_err();
        assert!(matches!(err, Error::InvalidTrustStore(_)));
    }
}
