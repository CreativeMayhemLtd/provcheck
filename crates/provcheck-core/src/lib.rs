//! # provcheck-core
//!
//! Verify C2PA Content Credentials on any file format supported by
//! the upstream `c2pa` crate (audio, image, video).
//!
//! The library is intentionally thin — it wraps `c2pa::Reader` with a
//! stable [`Report`] type that both the CLI and the GUI render.
//! Behaviour is identical across front-ends because there is exactly
//! one code path through `verify`.
//!
//! ```no_run
//! use provcheck_core::verify;
//! use std::path::Path;
//!
//! let report = verify(Path::new("signed.wav"))?;
//! if report.verified {
//!     println!("Signed by {:?}", report.signer);
//! }
//! # Ok::<(), provcheck_core::Error>(())
//! ```

use std::path::Path;

use serde::{Deserialize, Serialize};

pub mod render;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("file not found or unreadable: {0}")]
    Io(#[from] std::io::Error),
    #[error("C2PA read failed: {0}")]
    C2pa(#[from] c2pa::Error),
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
    /// and whose signature validates.
    pub verified: bool,

    /// True iff the file has NO C2PA manifest at all (as distinct from
    /// a manifest that exists but fails verification).
    pub unsigned: bool,

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
    /// errors; >0 means the signature or manifest had integrity issues.
    pub validation_errors: usize,
}

impl Report {
    /// Exit code convention used by the CLI.
    ///
    /// `0` — signed and verified.
    /// `1` — unsigned OR invalid.
    /// The `2` exit-code for I/O errors is handled at the CLI layer,
    /// not by the report.
    pub fn exit_code(&self) -> i32 {
        if self.verified { 0 } else { 1 }
    }
}

/// Verify the C2PA credentials on the file at `path`.
///
/// Returns a populated [`Report`]. Does not panic on unsigned or
/// invalid input — those are reported via the `Report` fields.
///
/// Only returns `Err` on I/O failure (file missing, unreadable). An
/// absent C2PA manifest (a file that was never signed) is reported
/// as `unsigned: true, verified: false` on the returned `Report`, not
/// as an error. A present-but-malformed or tamper-broken manifest is
/// reported as `verified: false` with a descriptive `failure_reason`.
pub fn verify(path: &Path) -> Result<Report, Error> {
    // Guard: file must exist and be a file. c2pa::Reader would also
    // surface this, but a preflight check gives us a cleaner error.
    let _ = std::fs::metadata(path)?;

    let reader = match c2pa::Reader::from_file(path) {
        Ok(r) => r,
        Err(c2pa::Error::JumbfNotFound) | Err(c2pa::Error::JumbfBoxNotFound) => {
            // File opened fine — there's just no C2PA manifest in it.
            // "Unsigned" outcome, exit 1, not an error.
            return Ok(unsigned_report(None));
        }
        Err(c2pa::Error::UnsupportedType) => {
            // File format isn't something c2pa knows how to read at all
            // (text file, proprietary blob, etc.). We can say with
            // confidence: no verifiable C2PA here. Treat as unsigned
            // with a clarifying reason — exit 1, not an IO error. The
            // user's mental model is "did it verify?" and the answer
            // is a clear no.
            return Ok(unsigned_report(Some(
                "file format not supported by the C2PA reader".into(),
            )));
        }
        Err(e) if is_manifest_parse_error(&e) => {
            // File HAS a manifest — we know because we got past the
            // not-found / unsupported branches — but the manifest
            // structure is malformed. This is the tampered-manifest
            // case. Report as failed verification (exit 1) rather
            // than internal error (exit 2) because the user's
            // question "did this verify?" has a clear answer: no.
            return Ok(Report {
                verified: false,
                unsigned: false,
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
    // failures. These reflect trust-list and timestamp-authority policy
    // decisions, not the cryptographic integrity of the manifest. A
    // per-install signer (rAIdio.bot / vAIdeo.bot pattern) will always
    // fire `signingCredential.untrusted` — reporting that as "not
    // verified" would make every real-world output look broken. Users
    // who care about trust-list membership can read `signer` +
    // `trusted` and apply their own policy.
    const TRUST_POLICY_IGNORED: &[&str] = &[
        // cert not on a public trust list (expected for per-install certs)
        "signingCredential.untrusted",
        // TSA-related — we don't require a trusted timestamp authority
        "timeStamp.untrusted",
        "timeStamp.mismatch",
        "signingCredential.ocsp.skipped",
        "signingCredential.ocsp.inaccessible",
    ];

    let validation_errors = reader
        .validation_status()
        .map(|v| {
            v.iter()
                .filter(|s| matches!(s.kind(), c2pa::status_tracker::LogKind::Failure))
                .filter(|s| !TRUST_POLICY_IGNORED.contains(&s.code()))
                .count()
        })
        .unwrap_or(0);

    // `verified` requires BOTH:
    //   - the manifest's cryptographic integrity passes
    //     (validation_state is Valid or Trusted),
    //   - AND no validation-status failure codes are present.
    //
    // c2pa-rs 0.78 can return ValidationState::Valid even when a
    // validation_status failure entry is set — e.g., tampered audio
    // under a hash-bound manifest surfaces as a failure code without
    // flipping validation_state, because validation_state reflects
    // manifest-store integrity specifically. The tool's headline
    // signal is "did anything go wrong?", so we AND the two together.
    // Callers who want the raw c2pa state can read
    // `validation_errors` directly.
    //
    // Trust-list membership (ValidationState::Trusted) is NOT
    // required — provcheck reports the signer identity and leaves
    // trust-list policy to the caller. Reporting a locally-signed
    // manifest as "unverified" would confuse the majority of users
    // whose tools sign with per-install certs (rAIdio.bot's pattern).
    let crypto_ok = matches!(
        state,
        c2pa::ValidationState::Valid | c2pa::ValidationState::Trusted
    );
    let verified = crypto_ok && validation_errors == 0;

    let active = reader.active_manifest();

    let (active_manifest, signer, signed_at, claim_generator, format, assertions, ingredient_count) =
        if let Some(m) = active {
            let sig = m.signature_info();
            let signer = sig.and_then(|s| s.common_name.clone().or_else(|| s.issuer.clone()));
            let signed_at = sig.and_then(|s| s.time.clone());

            // Flatten assertions into a JSON object keyed by label —
            // readable at a glance, preserves full payload. Assertions
            // whose value can't be extracted (rare) get a string
            // placeholder so nothing silently drops.
            let mut assertion_map = serde_json::Map::new();
            for a in m.assertions() {
                let key = a.label().to_string();
                let val = a
                    .value()
                    .cloned()
                    .unwrap_or_else(|_| serde_json::Value::String("<value unavailable>".into()));
                // If the same label appears twice (possible — e.g.,
                // multiple c2pa.actions entries) we keep them as a
                // JSON array rather than overwriting.
                match assertion_map.remove(&key) {
                    Some(serde_json::Value::Array(mut arr)) => {
                        arr.push(val);
                        assertion_map.insert(key, serde_json::Value::Array(arr));
                    }
                    Some(existing) => {
                        assertion_map
                            .insert(key, serde_json::Value::Array(vec![existing, val]));
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
        Some(format_failure_reason(state, validation_errors))
    };

    Ok(Report {
        verified,
        unsigned: false,
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

fn format_failure_reason(state: c2pa::ValidationState, error_count: usize) -> String {
    // `state` being Valid/Trusted with errors > 0 is the tamper-
    // detected-but-manifest-intact case (e.g., audio data modified
    // under a hash-bound manifest). `state` being Invalid is
    // manifest-level breakage. We narrate both clearly.
    let plural = |n: usize| if n == 1 { "" } else { "s" };
    match state {
        c2pa::ValidationState::Invalid => format!(
            "manifest failed structural or cryptographic validation ({} error{})",
            error_count.max(1),
            plural(error_count.max(1))
        ),
        c2pa::ValidationState::Valid | c2pa::ValidationState::Trusted => {
            // Only called from the non-verified code path, so
            // error_count is expected to be > 0 here. Keep it
            // defensive anyway — fall back to a generic message if
            // it isn't, so callers never see an empty reason string.
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
}
