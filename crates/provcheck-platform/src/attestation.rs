//! DID-anchored second-factor attestation: orchestration layer.
//!
//! [`check_attestation`] is the pure attestation primitive — given a
//! cert fingerprint and an identity (handle or DID), it asks the
//! creator's PDS whether that fingerprint is published as a signing
//! key. Network calls go through [`crate::network`]; cache through
//! [`crate::storage`].
//!
//! [`verify_with_attestation`] wraps [`provcheck::verify_with_options`]
//! to combine offline verification with this online second factor.
//! Production callers (the CLI) reach for that wrapper; tests can
//! exercise [`check_attestation`] directly without touching c2pa.
//!
//! Architecture invariant: the `provcheck` crate has no network deps.
//! All network code lives here in `provcheck-platform`. That means
//! "provcheck never phones home" is enforceable at the dependency
//! graph level.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use provcheck::Error;
use provcheck::report::{AttestationStatus, DidAttestation, Report};
use provcheck::verification::{VerifyOptions, verify_with_options};

use crate::network::{SigningKeyRecord, list_signing_keys, resolve_handle, resolve_pds_endpoint};

// Re-export the canonical fingerprint computation from the shared
// spec crate under the original name so existing public API consumers
// (and the integration tests below) keep compiling without rename
// churn. New code should reach for `provcheck_attestation_spec::
// fingerprint_pem_chain` directly.
pub use provcheck_attestation_spec::fingerprint_pem_chain as fingerprint_leaf_cert;

/// Per-call attestation transport configuration. Tests use the
/// `*_override` fields to redirect HTTP at a localhost mock; production
/// callers leave them at default.
#[derive(Debug, Clone, Default)]
pub struct AttestationConfig {
    /// Directory where DID docs and PDS records are cached. `None`
    /// means platform default (`dirs::cache_dir()/provcheck/attestation`).
    pub cache_dir: Option<PathBuf>,
    /// When `true`, every check goes to the network — no cache reads,
    /// no cache writes.
    pub bypass_cache: bool,
    /// Override the bsky public AppView base URL (tests only).
    pub bsky_api_override: Option<String>,
    /// Override the plc.directory base URL (tests only).
    pub plc_directory_override: Option<String>,
    /// Use plain HTTP for did:web and `.well-known` URLs (tests only).
    pub use_http_for_well_known: bool,
}

/// Higher-level options consumed by [`verify_with_attestation`] and
/// the CLI. Maps cleanly to the user-facing flags
/// (`--bsky-handle` / `--did` / `--require-attested` /
/// `--no-attestation-cache`).
#[derive(Debug, Clone, Default)]
pub struct AttestationOptions {
    pub bsky_handle: Option<String>,
    pub did: Option<String>,
    /// When `true`, demote `verified` to `false` if the attestation
    /// status is anything other than [`AttestationStatus::Match`].
    pub require_attested: bool,
    pub cache_dir: Option<PathBuf>,
    pub no_cache: bool,
}

impl From<&AttestationOptions> for AttestationConfig {
    fn from(opts: &AttestationOptions) -> Self {
        AttestationConfig {
            cache_dir: opts.cache_dir.clone(),
            bypass_cache: opts.no_cache,
            ..Default::default()
        }
    }
}

/// Run the attestation check. Best-effort: never panics, never returns
/// `Err`. Failures are encoded in the returned
/// [`DidAttestation::status`].
///
/// `cert_fingerprint` should be the canonical `sha256:<hex>` form
/// from [`fingerprint_leaf_cert`].
///
/// ## Auto-bust on stale-cache miss
///
/// When the call uses cache (`config.bypass_cache == false`) and the
/// inner check returns [`AttestationStatus::Mismatch`] or
/// [`AttestationStatus::NotPublished`], the function transparently
/// retries once with caching bypassed and returns the fresh result.
///
/// This closes the post-rotation footgun: a creator who rotates
/// their signing key gets a fresh `signingKey` record published, but
/// any verifier whose `listRecords` cache hasn't expired still sees
/// the pre-rotation set and reports MISMATCH. Auto-bust forces a
/// fresh fetch on that specific failure mode, so the user doesn't
/// have to know about `--no-attestation-cache`.
///
/// Costs: one extra HTTP round trip per failed-from-cache check
/// (handle resolve + DID doc + listRecords). On a genuine Mismatch
/// or NotPublished those calls are still wasted, but those outcomes
/// are rare in steady state. Match and ResolutionFailed never pay
/// the cost.
pub fn check_attestation(
    cert_fingerprint: &str,
    handle: Option<&str>,
    did: Option<&str>,
    config: &AttestationConfig,
) -> DidAttestation {
    let initial = check_attestation_inner(cert_fingerprint, handle, did, config);

    if !config.bypass_cache
        && matches!(
            initial.status,
            AttestationStatus::Mismatch | AttestationStatus::NotPublished
        )
    {
        let fresh = AttestationConfig {
            bypass_cache: true,
            ..config.clone()
        };
        return check_attestation_inner(cert_fingerprint, handle, did, &fresh);
    }

    initial
}

fn check_attestation_inner(
    cert_fingerprint: &str,
    handle: Option<&str>,
    did: Option<&str>,
    config: &AttestationConfig,
) -> DidAttestation {
    let resolved_did = match (did, handle) {
        (Some(d), _) => d.to_string(),
        (None, Some(h)) => match resolve_handle(h, config) {
            Ok(d) => d,
            Err(msg) => return failure(handle, "", &format!("handle resolution failed: {msg}")),
        },
        (None, None) => {
            return failure(handle, "", "no handle or DID supplied to attestation");
        }
    };

    let pds = match resolve_pds_endpoint(&resolved_did, config) {
        Ok(p) => p,
        Err(msg) => {
            return failure(
                handle,
                &resolved_did,
                &format!("DID document resolution failed: {msg}"),
            );
        }
    };

    let records = match list_signing_keys(&pds, &resolved_did, config) {
        Ok(rs) => rs,
        Err(msg) => {
            return failure(
                handle,
                &resolved_did,
                &format!("PDS listRecords failed: {msg}"),
            );
        }
    };

    let now = SystemTime::now();
    let active: Vec<&SigningKeyRecord> = records
        .iter()
        .filter(|r| is_record_active(r, now))
        .collect();

    if active.is_empty() {
        return DidAttestation {
            did: resolved_did,
            handle: handle.map(str::to_string),
            status: AttestationStatus::NotPublished,
            matched_fingerprint: None,
            message: Some(if records.is_empty() {
                "no app.provcheck.signingKey records published".into()
            } else {
                "all published signingKey records are expired or not yet valid".into()
            }),
        };
    }

    if let Some(r) = active.iter().find(|r| r.fingerprint == cert_fingerprint) {
        return DidAttestation {
            did: resolved_did,
            handle: handle.map(str::to_string),
            status: AttestationStatus::Match,
            matched_fingerprint: Some(r.fingerprint.clone()),
            message: r.label.clone(),
        };
    }

    DidAttestation {
        did: resolved_did,
        handle: handle.map(str::to_string),
        status: AttestationStatus::Mismatch,
        matched_fingerprint: None,
        message: Some(format!(
            "signing cert {} not in {} active record{}",
            cert_fingerprint,
            active.len(),
            if active.len() == 1 { "" } else { "s" }
        )),
    }
}

fn failure(handle: Option<&str>, did: &str, msg: &str) -> DidAttestation {
    DidAttestation {
        did: did.to_string(),
        handle: handle.map(str::to_string),
        status: AttestationStatus::ResolutionFailed,
        matched_fingerprint: None,
        message: Some(msg.to_string()),
    }
}

fn is_record_active(record: &SigningKeyRecord, now: SystemTime) -> bool {
    let from_str = record
        .valid_from
        .as_deref()
        .unwrap_or(record.created_at.as_str());

    if let Some(from) = parse_rfc3339(from_str) {
        if now < from {
            return false;
        }
    }

    if let Some(until_str) = record.valid_until.as_deref() {
        if let Some(until) = parse_rfc3339(until_str) {
            if now >= until {
                return false;
            }
        }
    }

    true
}

fn parse_rfc3339(s: &str) -> Option<SystemTime> {
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;
    let odt = OffsetDateTime::parse(s, &Rfc3339).ok()?;
    let unix_seconds = odt.unix_timestamp();
    let nanos = odt.nanosecond();
    if unix_seconds < 0 {
        return None;
    }
    UNIX_EPOCH.checked_add(Duration::new(unix_seconds as u64, nanos))
}

// ---------- orchestration: combined verify + attest ---------------------

/// Verify a file AND check DID-anchored attestation in one call.
/// Wraps [`verify_with_options`] (offline core) and adds the network
/// step. The returned [`Report`] has `did_attestation` populated.
///
/// If `attest.require_attested` is set and the attestation status is
/// not `Match`, `verified` is demoted to `false` and `failure_reason`
/// is overwritten with an attestation-specific message.
///
/// Costs an extra `c2pa::Reader::from_file` parse to extract the cert
/// chain — c2pa is fast, so the hit is invisible on small files.
pub fn verify_with_attestation(
    path: &Path,
    verify_opts: &VerifyOptions,
    attest: &AttestationOptions,
) -> Result<Report, Error> {
    let mut report = verify_with_options(path, verify_opts)?;

    // Skip attestation cleanly if neither identity was provided —
    // matches what the CLI dispatch does, but defensive in case a
    // library caller passes empty AttestationOptions.
    if attest.bsky_handle.is_none() && attest.did.is_none() {
        return Ok(report);
    }

    let config: AttestationConfig = attest.into();

    // Re-extract the signing cert chain from the file. Independent of
    // verify_with_options — it builds its own Reader. Trust-store
    // settings don't affect cert_chain, so a default Reader is fine.
    let cert_chain: Option<String> = match c2pa::Reader::from_file(path) {
        Ok(reader) => reader
            .active_manifest()
            .and_then(|m| m.signature_info())
            .map(|s| s.cert_chain.clone()),
        Err(_) => None,
    };

    let attestation = match cert_chain.as_deref() {
        Some(chain) => match fingerprint_leaf_cert(chain) {
            Ok(fp) => check_attestation(
                &fp,
                attest.bsky_handle.as_deref(),
                attest.did.as_deref(),
                &config,
            ),
            Err(msg) => failure(
                attest.bsky_handle.as_deref(),
                attest.did.as_deref().unwrap_or(""),
                &format!("could not fingerprint signing cert: {msg}"),
            ),
        },
        None => failure(
            attest.bsky_handle.as_deref(),
            attest.did.as_deref().unwrap_or(""),
            "no signing certificate present to attest (file may be unsigned or have a malformed signature)",
        ),
    };

    if attest.require_attested && attestation.status != AttestationStatus::Match {
        report.verified = false;
        report.failure_reason = Some(attestation_failure_reason(&attestation));
    }

    report.did_attestation = Some(attestation);
    Ok(report)
}

fn attestation_failure_reason(att: &DidAttestation) -> String {
    match att.status {
        AttestationStatus::Match => {
            unreachable!("attestation_failure_reason called on Match")
        }
        AttestationStatus::Mismatch => {
            "signing certificate not attested by the requested DID".into()
        }
        AttestationStatus::NotPublished => {
            "no signing-key records published under the requested DID".into()
        }
        AttestationStatus::ResolutionFailed => {
            "DID resolution failed; attestation could not be checked".into()
        }
    }
}

#[cfg(test)]
mod attestation_config_tests {
    use super::*;

    // ----- AttestationConfig defaults ----------

    #[test]
    fn default_attestation_config_has_no_overrides() {
        let cfg = AttestationConfig::default();
        assert!(cfg.cache_dir.is_none());
        assert!(!cfg.bypass_cache);
        assert!(cfg.bsky_api_override.is_none());
        assert!(cfg.plc_directory_override.is_none());
        assert!(!cfg.use_http_for_well_known);
    }

    #[test]
    fn default_attestation_options_are_empty() {
        let opts = AttestationOptions::default();
        assert!(opts.bsky_handle.is_none());
        assert!(opts.did.is_none());
        assert!(!opts.require_attested);
        assert!(opts.cache_dir.is_none());
        assert!(!opts.no_cache);
    }

    // ----- From<&AttestationOptions> for AttestationConfig ----------
    //
    // The CLI's options struct converts to the transport config.
    // Pin the field mapping so a future maintainer can't silently
    // drop a relevant option during the conversion.

    #[test]
    fn options_to_config_preserves_cache_dir() {
        let opts = AttestationOptions {
            cache_dir: Some(std::path::PathBuf::from("/tmp/cache")),
            ..Default::default()
        };
        let cfg: AttestationConfig = (&opts).into();
        assert_eq!(
            cfg.cache_dir,
            Some(std::path::PathBuf::from("/tmp/cache"))
        );
    }

    #[test]
    fn options_to_config_maps_no_cache_to_bypass_cache() {
        let opts = AttestationOptions {
            no_cache: true,
            ..Default::default()
        };
        let cfg: AttestationConfig = (&opts).into();
        assert!(cfg.bypass_cache);
    }

    #[test]
    fn options_to_config_when_no_cache_is_false_leaves_bypass_false() {
        let opts = AttestationOptions::default();
        let cfg: AttestationConfig = (&opts).into();
        assert!(!cfg.bypass_cache);
    }

    #[test]
    fn options_to_config_does_not_set_test_overrides() {
        // The CLI options must NEVER set bsky_api_override /
        // plc_directory_override / use_http_for_well_known —
        // those are test-only fields. If a future maintainer
        // accidentally plumbs them through, this test catches it.
        let opts = AttestationOptions {
            bsky_handle: Some("creator.bsky.social".into()),
            did: Some("did:plc:abc".into()),
            require_attested: true,
            no_cache: true,
            ..Default::default()
        };
        let cfg: AttestationConfig = (&opts).into();
        assert!(
            cfg.bsky_api_override.is_none(),
            "test-only override leaked into production config"
        );
        assert!(
            cfg.plc_directory_override.is_none(),
            "test-only override leaked into production config"
        );
        assert!(
            !cfg.use_http_for_well_known,
            "test-only override leaked into production config"
        );
    }

    // ----- attestation_failure_reason ----------

    #[test]
    fn failure_reason_for_mismatch_names_signing_cert() {
        let att = DidAttestation {
            status: AttestationStatus::Mismatch,
            did: "did:plc:abc".into(),
            handle: None,
            matched_fingerprint: None,
            message: None,
        };
        let s = attestation_failure_reason(&att);
        assert!(s.contains("signing certificate"));
        assert!(s.contains("not attested"));
    }

    #[test]
    fn failure_reason_for_not_published_names_signing_key_records() {
        let att = DidAttestation {
            status: AttestationStatus::NotPublished,
            did: "did:plc:abc".into(),
            handle: None,
            matched_fingerprint: None,
            message: None,
        };
        let s = attestation_failure_reason(&att);
        assert!(s.contains("no signing-key records"));
    }

    #[test]
    fn failure_reason_for_resolution_failed_names_did_resolution() {
        let att = DidAttestation {
            status: AttestationStatus::ResolutionFailed,
            did: "did:plc:abc".into(),
            handle: None,
            matched_fingerprint: None,
            message: None,
        };
        let s = attestation_failure_reason(&att);
        assert!(s.contains("DID resolution"));
        assert!(s.contains("failed"));
    }
}
