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

use sha2::{Digest, Sha256};

use provcheck::Error;
use provcheck::report::{AttestationStatus, DidAttestation, Report};
use provcheck::verification::{VerifyOptions, verify_with_options};

use crate::network::{SigningKeyRecord, list_signing_keys, resolve_handle, resolve_pds_endpoint};

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

/// Compute the canonical SHA-256 fingerprint of the leaf certificate
/// from a PEM-encoded chain (as exposed by
/// `c2pa::SignatureInfo::cert_chain`). Returns `sha256:<lowercase-hex>`.
pub fn fingerprint_leaf_cert(pem_chain: &str) -> Result<String, String> {
    let parsed = pem::parse_many(pem_chain).map_err(|e| format!("PEM parse failed: {e}"))?;
    let leaf = parsed
        .iter()
        .find(|p| p.tag() == "CERTIFICATE")
        .ok_or_else(|| "no CERTIFICATE block found in cert chain".to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(leaf.contents());
    let digest = hasher.finalize();
    Ok(format!("sha256:{}", hex_lower(&digest[..])))
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Run the attestation check. Best-effort: never panics, never returns
/// `Err`. Failures are encoded in the returned
/// [`DidAttestation::status`].
///
/// `cert_fingerprint` should be the canonical `sha256:<hex>` form
/// from [`fingerprint_leaf_cert`].
pub fn check_attestation(
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
