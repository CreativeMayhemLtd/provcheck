//! # provcheck-attestation-spec
//!
//! The wire-format contract between the verifier (`provcheck-platform`)
//! and the publisher (`provcheck-publish`). Anyone implementing a new
//! verifier or publisher in another language can read this crate as
//! the source of truth for what an `app.provcheck.signingKey` record
//! looks like and how a cert fingerprint is computed.
//!
//! Field layout mirrors `lexicons/app/provcheck/signingKey.json`
//! exactly. The lexicon is the canonical schema; this Rust crate is
//! a typed view of it.
//!
//! ## Why this crate is separate
//!
//! Before this crate existed, the wire types were defined inside
//! `provcheck-platform` (verifier side). A future `provcheck-publish`
//! (writer side) crate would have had to either re-declare the same
//! types or take a heavy dep on the verifier crate just to access
//! them. Either path invites drift: the writer publishes records the
//! verifier silently rejects, or the verifier accepts records the
//! writer never produces.
//!
//! Splitting the contract into a tiny third crate that both sides
//! depend on prevents that whole class of bug. The crate is
//! deliberately minimal — types, fingerprint computation, the
//! algorithm allow-list. No I/O, no async, no network, no c2pa.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Wire-compatible model of an `app.provcheck.signingKey` record.
///
/// Field names + serde attrs must match the lexicon at
/// `lexicons/app/provcheck/signingKey.json`. Optional fields use
/// `#[serde(default, skip_serializing_if = "Option::is_none")]` so
/// the JSON we produce never includes `null` keys — atproto
/// validators treat present-but-null differently from absent, and
/// some PDSes reject the former.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningKeyRecord {
    /// RFC 3339 timestamp at which the record was created. Used as
    /// the implicit `valid_from` when that field is absent.
    #[serde(rename = "createdAt")]
    pub created_at: String,

    /// Canonical SHA-256 fingerprint of the leaf signing certificate.
    /// Format: `sha256:<lowercase-hex>`. Lexicon pattern:
    /// `^sha256:[0-9a-f]{64}$`.
    pub fingerprint: String,

    /// JWS algorithm identifier the signing key uses. See
    /// [`ALLOWED_ALGORITHMS`] for the lexicon's `knownValues` list.
    pub algorithm: String,

    /// Optional human-readable label ("studio mac", "ci server").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// RFC 3339 timestamp at which this record becomes active.
    /// Defaults to [`created_at`](Self::created_at) when absent.
    #[serde(
        rename = "validFrom",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub valid_from: Option<String>,

    /// RFC 3339 timestamp at which this record stops being active.
    /// Absent means open-ended validity; present means the verifier
    /// treats `now >= validUntil` as expired.
    #[serde(
        rename = "validUntil",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub valid_until: Option<String>,

    /// at-uri of a record that supersedes this one. Used for clean
    /// rotation: the old record stays as a tombstone with
    /// `validUntil` set and `supersededBy` pointing at the new
    /// record's at-uri.
    #[serde(
        rename = "supersededBy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub superseded_by: Option<String>,
}

/// JWS algorithm identifiers the lexicon's `knownValues` list. Both
/// publisher and verifier should refuse to handle records with an
/// algorithm outside this set unless explicitly opted in — the set
/// is conservative and tracks what c2pa-rs's signer constructors
/// currently support.
pub const ALLOWED_ALGORITHMS: &[&str] = &[
    "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512", "Ed25519",
];

/// Errors from the fingerprint helpers. All other functions return
/// owned strings or `bool`s — there's not much to fail at in pure
/// wire-format math.
#[derive(Debug, thiserror::Error)]
pub enum FingerprintError {
    /// The PEM chain could not be parsed (malformed armour, bad
    /// base64, etc.). Carries the inner parser error's message.
    #[error("PEM parse failed: {0}")]
    PemParse(String),

    /// The PEM chain parsed but contained no `CERTIFICATE` block.
    /// (Some chains carry private keys or other bag types; we want
    /// the leaf cert specifically.)
    #[error("no CERTIFICATE block found in cert chain")]
    NoCertificate,
}

/// Compute the canonical fingerprint of a signing certificate from
/// a PEM chain (as exposed by `c2pa::SignatureInfo::cert_chain` or
/// produced by `rcgen` via `Certificate::pem()`).
///
/// Returns `sha256:<lowercase-hex>` matching the lexicon pattern
/// `^sha256:[0-9a-f]{64}$`. The hash is taken over the DER-encoded
/// leaf certificate (the first `CERTIFICATE` block in the chain)
/// in its entirety — full cert, not just SPKI.
///
/// Verifier and publisher MUST use this same computation. The
/// integration test `fingerprint_matches_provcheck_platform` in
/// provcheck-sign locks that contract in place.
pub fn fingerprint_pem_chain(chain_pem: &str) -> Result<String, FingerprintError> {
    let parsed = pem::parse_many(chain_pem).map_err(|e| FingerprintError::PemParse(e.to_string()))?;
    let leaf = parsed
        .iter()
        .find(|p| p.tag() == "CERTIFICATE")
        .ok_or(FingerprintError::NoCertificate)?;
    Ok(fingerprint_leaf_der(leaf.contents()))
}

/// Compute the canonical fingerprint of a signing certificate from
/// its DER bytes directly. Returns `sha256:<lowercase-hex>`.
///
/// Use this when you already hold the DER (e.g. from an `rcgen`
/// `Certificate::der()` call) and want to skip the PEM round-trip.
pub fn fingerprint_leaf_der(der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(der);
    let digest = hasher.finalize();
    format!("sha256:{}", hex_lower(&digest[..]))
}

/// Lowercase-hex format of a byte slice. The lexicon's pattern is
/// `[0-9a-f]{64}` — strict lowercase. We provide this rather than
/// reaching for the `hex` crate so a downstream crate that uses
/// `hex` with different defaults can't drift on us.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trivial DER-encoded cert (precomputed) — content doesn't
    /// matter for the fingerprint test, only that the bytes are
    /// stable and the result is reproducible.
    const SAMPLE_DER: &[u8] = b"hello, der";
    /// sha256("hello, der") in lowercase hex.
    const SAMPLE_FINGERPRINT: &str =
        "sha256:ca1e203832fd853d1791b4d81ec84d86309ae1e642c863027618f44b7731d59a";

    #[test]
    fn fingerprint_leaf_der_is_deterministic_and_lowercase() {
        let fp = fingerprint_leaf_der(SAMPLE_DER);
        assert!(fp.starts_with("sha256:"), "format prefix");
        assert_eq!(fp.len(), "sha256:".len() + 64, "hex length");
        assert!(
            fp.chars().skip("sha256:".len()).all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "lowercase hex only"
        );
    }

    #[test]
    fn fingerprint_leaf_der_matches_known_value() {
        // If this test fails, the algorithm changed. That's a wire-
        // breaking change — coordinate with provcheck-platform and
        // bump the lexicon.
        assert_eq!(fingerprint_leaf_der(SAMPLE_DER), SAMPLE_FINGERPRINT);
    }

    #[test]
    fn fingerprint_pem_chain_handles_minimal_input() {
        // A PEM CERTIFICATE block whose body decodes to SAMPLE_DER.
        // base64("hello, der") = "aGVsbG8sIGRlcg==".
        let pem = "-----BEGIN CERTIFICATE-----\naGVsbG8sIGRlcg==\n-----END CERTIFICATE-----\n";
        let fp = fingerprint_pem_chain(pem).expect("parses");
        assert_eq!(fp, SAMPLE_FINGERPRINT);
    }

    #[test]
    fn fingerprint_pem_chain_rejects_no_certificate_block() {
        // A PEM PRIVATE KEY block, no CERTIFICATE.
        let pem = "-----BEGIN PRIVATE KEY-----\naGVsbG8sIGRlcg==\n-----END PRIVATE KEY-----\n";
        let err = fingerprint_pem_chain(pem).expect_err("should reject");
        assert!(matches!(err, FingerprintError::NoCertificate));
    }

    #[test]
    fn fingerprint_pem_chain_picks_first_certificate() {
        // Two CERTIFICATE blocks — the leaf (first) is what counts.
        // base64("hello, der") then base64("goodbye, der").
        let pem = "-----BEGIN CERTIFICATE-----\n\
                   aGVsbG8sIGRlcg==\n\
                   -----END CERTIFICATE-----\n\
                   -----BEGIN CERTIFICATE-----\n\
                   Z29vZGJ5ZSwgZGVy\n\
                   -----END CERTIFICATE-----\n";
        let fp = fingerprint_pem_chain(pem).expect("parses");
        assert_eq!(fp, SAMPLE_FINGERPRINT);
    }

    #[test]
    fn record_round_trips_through_json_with_optional_fields_omitted() {
        let r = SigningKeyRecord {
            created_at: "2026-06-13T12:00:00Z".to_string(),
            fingerprint: SAMPLE_FINGERPRINT.to_string(),
            algorithm: "ES256".to_string(),
            label: None,
            valid_from: None,
            valid_until: None,
            superseded_by: None,
        };
        let json = serde_json::to_string(&r).expect("serialise");
        // Optional fields are absent, not present-as-null.
        assert!(!json.contains("\"label\""));
        assert!(!json.contains("\"validFrom\""));
        assert!(!json.contains("\"validUntil\""));
        assert!(!json.contains("\"supersededBy\""));
        // Wire field names are camelCase per lexicon.
        assert!(json.contains("\"createdAt\""));
        let decoded: SigningKeyRecord = serde_json::from_str(&json).expect("round-trip");
        assert_eq!(decoded, r);
    }

    #[test]
    fn record_round_trips_through_json_with_all_fields_present() {
        let r = SigningKeyRecord {
            created_at: "2026-06-13T12:00:00Z".to_string(),
            fingerprint: SAMPLE_FINGERPRINT.to_string(),
            algorithm: "ES256".to_string(),
            label: Some("studio mac".to_string()),
            valid_from: Some("2026-06-13T12:00:00Z".to_string()),
            valid_until: Some("2027-06-13T12:00:00Z".to_string()),
            superseded_by: Some("at://did:plc:abc/app.provcheck.signingKey/xyz".to_string()),
        };
        let json = serde_json::to_string(&r).expect("serialise");
        let decoded: SigningKeyRecord = serde_json::from_str(&json).expect("round-trip");
        assert_eq!(decoded, r);
    }

    #[test]
    fn allowed_algorithms_includes_es256() {
        // Sanity check: ES256 is what every signer in the c2pa
        // ecosystem produces by default; it must be allowed.
        assert!(ALLOWED_ALGORITHMS.contains(&"ES256"));
    }
}
