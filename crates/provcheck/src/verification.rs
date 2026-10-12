use crate::Error;
use crate::prelude::Report;
use std::path::Path;

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
    // Validate the PEM before touching the filesystem: a malformed PEM is a caller bug, not a file problem.
    if let Some(pem) = opts.trust_store_pem.as_deref() {
        crate::sanity_check_pem(pem)?;
    }

    // Preflight metadata for a cleaner error than c2pa::Reader would give.
    let _ = std::fs::metadata(path)?;

    let reader_result = if let Some(pem) = opts.trust_store_pem.as_deref() {
        // Layer the caller's PEM onto the default trust list; c2pa parses it lazily (preflighted above).
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
            return Ok(crate::unsigned_report(None));
        }
        Err(c2pa::Error::UnsupportedType) => {
            return Ok(crate::unsigned_report(Some(
                "file format not supported by the C2PA reader".into(),
            )));
        }
        Err(e) if crate::is_manifest_parse_error(&e) => {
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
                // A present-but-unparseable C2PA box is positive tamper evidence, distinct from unsigned or hash-failing.
                provenance_tamper: Some(format!(
                    "a C2PA provenance box is present but does not parse — provenance metadata appears corrupted or partially removed ({e})"
                )),
                did_attestation: None,
                identity: None,
                parents: Vec::new(),
                watermarks: Vec::new(),
                detections: Vec::new(),
                checks: Vec::new(),
            });
        }
        Err(e) => return Err(e.into()),
    };

    let state = reader.validation_state();

    // Codes intentionally NOT counted as verification failures: trust-list membership is a separate dimension.
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

    // Only evaluate trust when the caller asked: c2pa flags most per-install certs "untrusted" by default, which would mislead.
    let trust_was_configured = opts.trust_store_pem.is_some() || opts.require_trusted;
    let trusted = if trust_was_configured {
        evaluate_trust(&reader)
    } else {
        None
    };

    let crypto_ok = matches!(
        state,
        c2pa::ValidationState::Valid | c2pa::ValidationState::Trusted
    );
    let crypto_and_no_errors = crypto_ok && validation_errors == 0;

    let verified = if opts.require_trusted {
        crypto_and_no_errors && matches!(trusted, Some(true))
    } else {
        crypto_and_no_errors
    };

    let active = reader.active_manifest();

    let (
        active_manifest,
        signer,
        signed_at,
        claim_generator,
        format,
        assertions,
        ingredient_count,
        identity,
    ) = if let Some(m) = active {
        let sig = m.signature_info();
        let signer = sig.and_then(|s| s.common_name.clone().or_else(|| s.issuer.clone()));
        let signed_at = sig.and_then(|s| s.time.clone());

        let mut assertion_map = serde_json::Map::new();
        let mut identity_claim: Option<crate::report::IdentityClaim> = None;
        for a in m.assertions() {
            let key = a.label().to_string();
            let val = a
                .value()
                .cloned()
                .unwrap_or_else(|_| serde_json::Value::String("<value unavailable>".into()));

            // c2pa-rs may suffix user labels (e.g. "...__jumbf="); is_identity_label matches both shapes, first valid wins.
            if identity_claim.is_none()
                && is_identity_label(&key)
                && let Ok(claim) =
                    serde_json::from_value::<crate::report::IdentityClaim>(val.clone())
            {
                identity_claim = Some(claim);
            }

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
            identity_claim,
        )
    } else {
        (
            None,
            None,
            None,
            None,
            None,
            serde_json::Value::Null,
            0,
            None,
        )
    };

    let failure_reason = if verified {
        None
    } else {
        Some(crate::format_failure_reason(
            state,
            validation_errors,
            trusted,
            opts.require_trusted,
        ))
    };

    let parents = walk_parent_chain(&reader);

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
        // A parseable manifest has an intact box; tampering here surfaces via validation_errors, not this field.
        provenance_tamper: None,
        did_attestation: None,
        identity,
        parents,
        watermarks: Vec::new(),
        detections: Vec::new(),
        checks: Vec::new(),
    })
}

/// Walk the active manifest's parentOf ingredients, resolving each
/// to the corresponding manifest in the store and extracting its
/// signer + identity-claim info. Returns the chain in
/// direct-parent-first order; entries deeper than the immediate
/// parent (grandparents and beyond) are followed via the matched
/// manifests' own parentOf ingredients.
///
/// The walk is best-effort — any failure to resolve a label or
/// extract a field just truncates the chain at that point. A
/// genuinely linear lineage (one parent per generation) produces
/// the cleanest output; branching is observable but the renderer
/// only sees the parentOf chain.
fn walk_parent_chain(reader: &c2pa::Reader) -> Vec<crate::report::ParentManifest> {
    let Some(active) = reader.active_manifest() else {
        return Vec::new();
    };
    let mut chain = Vec::new();
    let mut current = active;
    // Bounded so a cyclic store can't hang the verifier; real chains are 1-2 deep.
    for _ in 0..8 {
        let Some(parent_label) = current
            .ingredients()
            .iter()
            .find(|i| matches!(i.relationship(), c2pa::Relationship::ParentOf))
            .and_then(|i| i.active_manifest())
        else {
            break;
        };
        let Some(parent_manifest) = reader.get_manifest(parent_label) else {
            break;
        };
        let sig = parent_manifest.signature_info();
        let signer = sig.and_then(|s| s.common_name.clone().or_else(|| s.issuer.clone()));
        let identity = parent_manifest
            .assertions()
            .iter()
            .find(|a| is_identity_label(a.label()))
            .and_then(|a| a.value().ok())
            .and_then(|v| serde_json::from_value::<crate::report::IdentityClaim>(v.clone()).ok());
        chain.push(crate::report::ParentManifest {
            label: parent_label.to_string(),
            signer,
            claim_generator: parent_manifest.claim_generator().map(|s| s.to_string()),
            title: parent_manifest.title().map(|s| s.to_string()),
            identity,
        });
        current = parent_manifest;
    }
    chain
}

/// Match the bare `app.provcheck.identity` assertion label and any
/// label c2pa-rs has decorated with a `__<suffix>` disambiguator.
/// Producers always write the bare label; the suffix gets added by
/// c2pa-rs during manifest assembly when an assertion's payload hash
/// becomes part of the label. We accept either shape so this
/// extraction doesn't get fooled by the decoration.
fn is_identity_label(label: &str) -> bool {
    label == provcheck_attestation_spec::IDENTITY_ASSERTION_LABEL
        || label.starts_with(&format!(
            "{}__",
            provcheck_attestation_spec::IDENTITY_ASSERTION_LABEL
        ))
        || label.starts_with(&format!(
            "{}.",
            provcheck_attestation_spec::IDENTITY_ASSERTION_LABEL
        ))
}

fn evaluate_trust(reader: &c2pa::Reader) -> Option<bool> {
    // Use full ValidationResults, not validation_status() (errors-only): a trusted cert is a SUCCESS status, invisible there.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_options_default_has_no_trust_store() {
        let opts = VerifyOptions::default();
        assert!(opts.trust_store_pem.is_none());
    }

    #[test]
    fn verify_options_default_does_not_require_trusted() {
        // Flipping this default would change the exit code of every signed-but-not-trust-anchored file.
        let opts = VerifyOptions::default();
        assert!(!opts.require_trusted);
    }

    #[test]
    fn is_identity_label_accepts_bare_label() {
        assert!(is_identity_label(
            provcheck_attestation_spec::IDENTITY_ASSERTION_LABEL
        ));
    }

    #[test]
    fn is_identity_label_accepts_double_underscore_suffix() {
        let decorated = format!(
            "{}__abc123",
            provcheck_attestation_spec::IDENTITY_ASSERTION_LABEL
        );
        assert!(is_identity_label(&decorated));
    }

    #[test]
    fn is_identity_label_accepts_dot_suffix() {
        let decorated = format!(
            "{}.v2",
            provcheck_attestation_spec::IDENTITY_ASSERTION_LABEL
        );
        assert!(is_identity_label(&decorated));
    }

    #[test]
    fn is_identity_label_rejects_unrelated_label() {
        assert!(!is_identity_label("c2pa.actions.v2"));
        assert!(!is_identity_label("some.other.assertion"));
        assert!(!is_identity_label(""));
    }

    #[test]
    fn is_identity_label_rejects_prefix_match_without_separator() {
        // Only `__` and `.` are valid suffix separators; a bare prefix must not match.
        let prefix = format!("{}XX", provcheck_attestation_spec::IDENTITY_ASSERTION_LABEL);
        assert!(!is_identity_label(&prefix));
    }

    #[test]
    fn is_identity_label_rejects_substring_inside_label() {
        let inside = format!("x.{}", provcheck_attestation_spec::IDENTITY_ASSERTION_LABEL);
        assert!(!is_identity_label(&inside));
    }

    #[test]
    fn verify_missing_file_returns_io_error() {
        let r = verify(Path::new("/no/such/file/abcxyz.wav"));
        assert!(matches!(r, Err(Error::Io(_))));
    }

    #[test]
    fn verify_with_invalid_trust_store_pem_returns_invalid_trust_store_error() {
        let opts = VerifyOptions {
            trust_store_pem: Some("clearly not a PEM".into()),
            require_trusted: false,
        };
        let r = verify_with_options(Path::new("any.wav"), &opts);
        assert!(matches!(r, Err(Error::InvalidTrustStore(_))));
    }
}
