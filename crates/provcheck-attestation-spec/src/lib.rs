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
    #[serde(rename = "validFrom", default, skip_serializing_if = "Option::is_none")]
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

/// C2PA assertion label under which an [`IdentityClaim`] is embedded
/// in a signed asset's manifest. Producer and verifier must agree on
/// this exact string — keeping it in the spec crate prevents drift.
pub const IDENTITY_ASSERTION_LABEL: &str = "app.provcheck.identity";

/// Current schema version emitted by the producer. The verifier
/// accepts any version it knows about; producers should emit this
/// constant.
pub const IDENTITY_CLAIM_SCHEMA_VERSION: u32 = 1;

/// Wire-compatible model of the `app.provcheck.identity` C2PA
/// assertion. Field names + serde attrs must match the lexicon at
/// `lexicons/app/provcheck/identity.json`.
///
/// Carried as a C2PA assertion (not an atproto record) — this is
/// the publisher's self-asserted claim that the asset was signed
/// under the given DID. The verifier reads it as a *hint* to skip
/// the manual identity-bar entry step, then cross-checks the DID
/// against the appropriate `app.provcheck.signingKey` record before
/// trusting it. The claim alone is never trust-anchoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityClaim {
    /// DID of the creator. Source of truth. Verifiers resolve this
    /// to find the matching `app.provcheck.signingKey` collection.
    pub did: String,

    /// Display hint only — the handle the user is likely to
    /// recognise (e.g. `creator.bsky.social`). Verifiers MUST NOT
    /// use this as the trust anchor; the DID is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,

    /// Schema version. Currently always 1; reserved for future
    /// expansion without breaking older verifiers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
}

impl IdentityClaim {
    /// Construct an [`IdentityClaim`] with the current schema
    /// version, the canonical convenience for producers.
    pub fn new(did: impl Into<String>, handle: Option<String>) -> Self {
        Self {
            did: did.into(),
            handle,
            version: Some(IDENTITY_CLAIM_SCHEMA_VERSION),
        }
    }
}

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
    let parsed =
        pem::parse_many(chain_pem).map_err(|e| FingerprintError::PemParse(e.to_string()))?;
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
mod hex_lower_tests {
    use super::hex_lower;

    #[test]
    fn empty_slice_returns_empty_string() {
        assert_eq!(hex_lower(&[]), "");
    }

    #[test]
    fn single_zero_byte_encodes_as_two_zero_chars() {
        // The 2-char-per-byte invariant: 0x00 → "00", not "0".
        assert_eq!(hex_lower(&[0]), "00");
    }

    #[test]
    fn single_max_byte_encodes_lowercase() {
        // 0xFF MUST be "ff", not "FF" — the lexicon pattern is
        // strict lowercase.
        assert_eq!(hex_lower(&[0xFF]), "ff");
    }

    #[test]
    fn each_byte_contributes_exactly_two_chars() {
        let bytes = [0xDE, 0xAD, 0xBE, 0xEF];
        let out = hex_lower(&bytes);
        assert_eq!(out.len(), bytes.len() * 2);
    }

    #[test]
    fn round_trip_against_known_value() {
        // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        // Use that to pin a specific 32-byte sequence.
        let sha = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99,
            0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95,
            0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(
            hex_lower(&sha),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn all_output_chars_match_lexicon_pattern() {
        // Lexicon `[0-9a-f]{64}` — exhaust every possible byte
        // and confirm no character outside that set appears.
        let bytes: Vec<u8> = (0..=255).collect();
        let out = hex_lower(&bytes);
        for c in out.chars() {
            assert!(
                c.is_ascii_digit() || ('a'..='f').contains(&c),
                "char {c:?} outside [0-9a-f]"
            );
        }
    }

    #[test]
    fn output_length_is_always_double_input_length() {
        // For any input length, output is exactly 2 * input.
        for len in [0, 1, 7, 16, 32, 100] {
            let bytes = vec![0u8; len];
            assert_eq!(hex_lower(&bytes).len(), 2 * len, "len={len}");
        }
    }
}

#[cfg(test)]
mod identity_claim_and_constants_tests {
    use super::*;

    // ----- ALLOWED_ALGORITHMS contents ----------

    #[test]
    fn allowed_algorithms_contains_all_documented_jws_algs() {
        // Pin every JWS alg the publisher MAY emit.
        for alg in [
            "ES256", "ES384", "ES512", "PS256", "PS384", "PS512",
            "RS256", "RS384", "RS512", "Ed25519",
        ] {
            assert!(
                ALLOWED_ALGORITHMS.contains(&alg),
                "{alg} should be in ALLOWED_ALGORITHMS"
            );
        }
    }

    #[test]
    fn allowed_algorithms_has_exactly_ten_entries() {
        // Length pin so a future addition lands with an explicit
        // test update (catches a silent expansion that lets
        // verifiers accept records under a weaker algorithm).
        assert_eq!(ALLOWED_ALGORITHMS.len(), 10);
    }

    #[test]
    fn allowed_algorithms_rejects_hmac_family() {
        // Symmetric-key algs must not appear — the C2PA chain is
        // public-key only.
        for alg in ["HS256", "HS384", "HS512", "none"] {
            assert!(
                !ALLOWED_ALGORITHMS.contains(&alg),
                "{alg} must NOT be allowed"
            );
        }
    }

    // ----- IDENTITY_ASSERTION_LABEL pin ----------

    #[test]
    fn identity_assertion_label_is_reverse_dns_form() {
        // Pin the label literal so a future maintainer can't
        // silently rename the C2PA assertion — verifiers query
        // by this exact string.
        assert_eq!(IDENTITY_ASSERTION_LABEL, "app.provcheck.identity");
        assert!(IDENTITY_ASSERTION_LABEL.starts_with("app.provcheck."));
    }

    #[test]
    fn identity_claim_schema_version_is_one() {
        assert_eq!(IDENTITY_CLAIM_SCHEMA_VERSION, 1);
    }

    // ----- IdentityClaim::new + serde ----------

    #[test]
    fn identity_claim_new_sets_current_schema_version() {
        let c = IdentityClaim::new("did:plc:abc", None);
        assert_eq!(c.version, Some(IDENTITY_CLAIM_SCHEMA_VERSION));
    }

    #[test]
    fn identity_claim_new_preserves_did_and_handle() {
        let c = IdentityClaim::new("did:plc:abc", Some("alice.bsky.social".into()));
        assert_eq!(c.did, "did:plc:abc");
        assert_eq!(c.handle.as_deref(), Some("alice.bsky.social"));
    }

    #[test]
    fn identity_claim_new_with_none_handle_leaves_handle_none() {
        let c = IdentityClaim::new("did:plc:abc", None);
        assert!(c.handle.is_none());
    }

    #[test]
    fn identity_claim_serde_omits_none_handle() {
        // skip_serializing_if = "Option::is_none" on handle.
        let c = IdentityClaim::new("did:plc:abc", None);
        let json = serde_json::to_string(&c).expect("ser");
        assert!(
            !json.contains("\"handle\""),
            "None handle should be omitted: {json}"
        );
    }

    #[test]
    fn identity_claim_serde_omits_none_version() {
        // Backward-compat: producers SHOULD send version=Some(1)
        // but a None version (older shipped builds) must not
        // serialise as null.
        let c = IdentityClaim {
            did: "did:plc:abc".into(),
            handle: None,
            version: None,
        };
        let json = serde_json::to_string(&c).expect("ser");
        assert!(
            !json.contains("\"version\""),
            "None version should be omitted: {json}"
        );
    }

    #[test]
    fn identity_claim_deserialises_legacy_record_without_version() {
        // Backward-compat: old records without a version field
        // must deserialise (version defaults to None).
        let legacy = r#"{"did":"did:plc:abc"}"#;
        let c: IdentityClaim = serde_json::from_str(legacy).expect("legacy parse");
        assert_eq!(c.did, "did:plc:abc");
        assert!(c.handle.is_none());
        assert!(c.version.is_none());
    }

    #[test]
    fn identity_claim_round_trips_through_serde() {
        let original = IdentityClaim::new("did:plc:xyz", Some("bob.bsky.social".into()));
        let json = serde_json::to_string(&original).expect("ser");
        let back: IdentityClaim = serde_json::from_str(&json).expect("de");
        assert_eq!(back, original);
    }
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
            fp.chars()
                .skip("sha256:".len())
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
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

    #[test]
    fn identity_claim_round_trips_minimum_payload() {
        // did only — handle and version absent.
        let c = IdentityClaim {
            did: "did:plc:abc123".to_string(),
            handle: None,
            version: None,
        };
        let json = serde_json::to_string(&c).expect("serialise");
        // Optional fields stay absent rather than present-as-null.
        assert!(!json.contains("\"handle\""));
        assert!(!json.contains("\"version\""));
        let back: IdentityClaim = serde_json::from_str(&json).expect("round-trip");
        assert_eq!(back, c);
    }

    #[test]
    fn identity_claim_round_trips_full_payload() {
        let c = IdentityClaim::new("did:plc:abc123", Some("creator.bsky.social".to_string()));
        assert_eq!(c.version, Some(IDENTITY_CLAIM_SCHEMA_VERSION));
        let json = serde_json::to_string(&c).expect("serialise");
        let back: IdentityClaim = serde_json::from_str(&json).expect("round-trip");
        assert_eq!(back, c);
    }

    #[test]
    fn identity_assertion_label_matches_lexicon_id() {
        // The C2PA assertion label and the lexicon's `id` must
        // be the same string — they identify the same shape on
        // either side of the wire. Locking this in code prevents
        // a typo from breaking interop.
        assert_eq!(IDENTITY_ASSERTION_LABEL, "app.provcheck.identity");
    }

    // ----- v0.9.3 coverage additions ----------

    #[test]
    fn identity_claim_new_pins_current_schema_version() {
        let c = IdentityClaim::new("did:plc:abc", Some("creator.bsky.social".into()));
        assert_eq!(c.did, "did:plc:abc");
        assert_eq!(c.handle.as_deref(), Some("creator.bsky.social"));
        assert_eq!(c.version, Some(IDENTITY_CLAIM_SCHEMA_VERSION));
    }

    #[test]
    fn identity_claim_schema_version_is_pinned_at_one() {
        // v1 is the on-the-wire baseline. Bumping requires a
        // verifier upgrade in the same release.
        assert_eq!(IDENTITY_CLAIM_SCHEMA_VERSION, 1);
    }

    #[test]
    fn allowed_algorithms_pins_the_membership_list() {
        // Each entry is referenced by SigningKeyRecord wire format.
        // Lock the exact membership so a future maintainer cannot
        // silently demote or admit an algorithm without a test
        // failure.
        assert_eq!(
            ALLOWED_ALGORITHMS,
            &[
                "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256", "RS384",
                "RS512", "Ed25519"
            ]
        );
    }

    #[test]
    fn fingerprint_error_pem_parse_message_includes_inner() {
        let e = FingerprintError::PemParse("bad base64".into());
        let s = format!("{e}");
        assert!(s.contains("PEM parse"));
        assert!(s.contains("bad base64"));
    }

    #[test]
    fn fingerprint_error_no_certificate_message_is_meaningful() {
        let e = FingerprintError::NoCertificate;
        let s = format!("{e}");
        assert!(s.contains("CERTIFICATE"));
    }

    #[test]
    fn fingerprint_pem_chain_rejects_empty_input() {
        let r = fingerprint_pem_chain("");
        assert!(matches!(r, Err(FingerprintError::NoCertificate)));
    }

    #[test]
    fn fingerprint_pem_chain_rejects_garbled_input() {
        let r = fingerprint_pem_chain("not pem at all");
        // Acceptable outcomes: parse-failed-empty OR no-certificate.
        // Load-bearing is "Err, not panic".
        assert!(r.is_err());
    }

    #[test]
    fn fingerprint_leaf_der_emits_canonical_format() {
        let der = [0u8; 16];
        let fp = fingerprint_leaf_der(&der);
        assert!(fp.starts_with("sha256:"), "expected sha256: prefix, got {fp}");
        // 7 ("sha256:") + 64 (lowercase hex) = 71 chars.
        assert_eq!(fp.len(), 71);
        let hex = &fp[7..];
        assert!(
            hex.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "non-lowercase-hex char in {fp}"
        );
    }

    #[test]
    fn fingerprint_leaf_der_deterministic_for_identical_input() {
        let der = b"sample-der-bytes";
        let a = fingerprint_leaf_der(der);
        let b = fingerprint_leaf_der(der);
        assert_eq!(a, b);
    }

    #[test]
    fn fingerprint_leaf_der_diverges_for_one_bit_change() {
        let mut der = b"sample-der-bytes".to_vec();
        let a = fingerprint_leaf_der(&der);
        der[0] ^= 0x01;
        let b = fingerprint_leaf_der(&der);
        assert_ne!(a, b);
    }
}
