// SPDX-License-Identifier: Apache-2.0
//! The Pro (seat) license + the pack catalog — ported from Lysn.fm's `lysn-dlc`.
//!
//! provcheck's core is free and open (Apache-2.0). The keyed forensic
//! watermarking tools (Backfire image + Mellin audio) are frontier tools
//! Creative Mayhem sells as a paid, opt-in **DLC pack**. The Apache binary never
//! contains the pack's payload; the pack is pulled on demand ([`crate::install`])
//! and gated on a **seat license** ([`ProLicense`]).
//!
//! A seat license is one more offline-verifiable signed record ([`DomainSigned`]):
//! an Ed25519 signature over a domain-separated canonical form, verifiable with
//! no server. What makes it a *license* is the single pinned issuer, the Creative
//! Mayhem key ([`LICENSE_ISSUER_DID`]). That pin is the whole "local unlock": no
//! account, no phone-home, just a signature check against a baked-in key.
//!
//! The wire format is identical to Lysn.fm's, so ONE seat license — issued once
//! by the offline `dlc-issue` tool — verifies in both the Lysn.fm desktop app and
//! provcheck. The €10 buys a seat, spent wherever the tools appear.

use serde::{Deserialize, Serialize};

use crate::sign::{DomainSigned, SignError};

/// The Creative Mayhem license-issuer `did:key`. Every production seat license
/// MUST be signed by this key and no other.
///
/// This is a PLACEHOLDER, byte-identical to Lysn.fm's placeholder. Generate the
/// real Creative Mayhem issuer keypair once (offline, via `dlc-issue keygen`) and
/// set this — in BOTH repos — to its `did:key` before any release. Until then it
/// is not a valid key, so [`ProLicense::authorize`] fails closed for every input:
/// no license verifies until the real trust anchor is pinned here.
pub const LICENSE_ISSUER_DID: &str =
    "did:key:zPLACEHOLDER-set-Creative-Mayhem-issuer-before-release";

/// DLC product id: the Pro Watermarking pack. The €10 seat unlocks this one id,
/// which in turn unlocks BOTH keyed marks (Backfire + Mellin). The id string is
/// shared with Lysn.fm so a license issued for it unlocks in either app.
pub const DLC_PRO_WATERMARKING: &str = "pro-watermarking";

/// Domain-separation tag for a detached signature over a pack's `SHA256SUMS`
/// manifest. Byte-identical to Lysn.fm's `lysn_dlc::DLC_MANIFEST_DOMAIN`, so the
/// offline `dlc-issue pack-sign` tool signs one manifest that verifies here.
pub const DLC_MANIFEST_DOMAIN: &[u8] = b"lysn-dlc-manifest/v1\x00";

/// Errors from authorizing a seat license.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DlcError {
    /// The license was not signed by the trusted Creative Mayhem issuer key.
    #[error("license issuer is not the trusted Creative Mayhem key")]
    WrongIssuer,
    /// The license is valid but does not unlock the product being checked.
    #[error("license does not unlock this product")]
    WrongProduct,
    /// The license carried an expiry and it is in the past.
    #[error("license has expired")]
    Expired,
    /// The signature itself is missing or invalid.
    #[error("signature: {0}")]
    Signature(#[from] SignError),
}

/// An offline-verifiable unlock for a paid DLC pack. Signed by Creative Mayhem,
/// held by the buyer, checked locally with no network.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProLicense {
    /// Issuer `did:key`. For a valid production license this equals
    /// [`LICENSE_ISSUER_DID`].
    pub issuer: String,
    /// The DLC product id this license unlocks, e.g. [`DLC_PRO_WATERMARKING`].
    pub product: String,
    /// The licensed holder: the buyer's `did:key` (their durable seat identity).
    /// Binds the license to one identity so it is not a freely shareable bearer
    /// token.
    pub subject: String,
    /// RFC 3339 UTC issuance time (e.g. `2026-08-19T12:00:00Z`).
    pub issued_at: String,
    /// Optional RFC 3339 UTC expiry. `None` means perpetual (the common case for
    /// a one-time unlock).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// base58btc Ed25519 signature over the domain-separated canonical bytes.
    /// `None` until signed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

impl DomainSigned for ProLicense {
    // Byte-identical to Lysn.fm's `lysn-prolicense/v1` domain tag so the signed
    // bytes — and therefore the signature — match across repos.
    const DOMAIN: &'static [u8] = b"lysn-prolicense/v1\x00";
    fn signer_did(&self) -> &str {
        &self.issuer
    }
    fn sig(&self) -> Option<&str> {
        self.sig.as_deref()
    }
    fn set_sig(&mut self, sig: Option<String>) {
        self.sig = sig;
    }
}

impl ProLicense {
    /// A new, unsigned license issued by the pinned Creative Mayhem key, for
    /// `subject` to use `product`. The issuer signs it with [`DomainSigned::sign`].
    pub fn new(
        product: impl Into<String>,
        subject: impl Into<String>,
        issued_at: impl Into<String>,
    ) -> Self {
        Self {
            issuer: LICENSE_ISSUER_DID.to_string(),
            product: product.into(),
            subject: subject.into(),
            issued_at: issued_at.into(),
            expires_at: None,
            sig: None,
        }
    }

    /// Full production authorization: the signature is valid, the license was
    /// issued by the pinned Creative Mayhem key, it unlocks `product`, and (when
    /// `now` is supplied, RFC 3339 UTC) it has not expired. Everything is checked
    /// offline.
    pub fn authorize(&self, product: &str, now: Option<&str>) -> Result<(), DlcError> {
        self.authorize_with(LICENSE_ISSUER_DID, product, now)
    }

    /// Like [`authorize`](Self::authorize) but against an explicit
    /// `expected_issuer`. Used by tests, and the seam for issuer-key rotation if
    /// Creative Mayhem ever rotates the pinned key.
    pub fn authorize_with(
        &self,
        expected_issuer: &str,
        product: &str,
        now: Option<&str>,
    ) -> Result<(), DlcError> {
        // Pin the issuer FIRST: a signature that verifies against some *other*
        // key is still not a license. The signature check then proves that
        // pinned issuer really signed this.
        if self.issuer != expected_issuer {
            return Err(DlcError::WrongIssuer);
        }
        DomainSigned::verify(self)?;
        if self.product != product {
            return Err(DlcError::WrongProduct);
        }
        // RFC 3339 UTC (Z-suffixed) timestamps sort lexically in chronological
        // order, so a string compare is a correct expiry test without a date lib.
        if let (Some(exp), Some(now)) = (self.expires_at.as_deref(), now)
            && now >= exp
        {
            return Err(DlcError::Expired);
        }
        Ok(())
    }
}

/// Metadata for one downloadable DLC pack, for the app to list.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DlcInfo {
    /// Stable pack id, also the product id a [`ProLicense`] must unlock.
    pub id: String,
    /// Human name.
    pub name: String,
    /// One-line description.
    pub summary: String,
    /// Whether a valid [`ProLicense`] is required to install/run this pack.
    pub requires_license: bool,
    /// Approximate download size in bytes (0 until the pack is built).
    pub approx_bytes: u64,
    /// Default https download base (an R2 mirror). The app or user may override
    /// it at install time.
    pub default_source: String,
}

/// The known DLC packs. For now just the Pro Watermarking pack (Backfire image +
/// Mellin audio); the list grows as packs ship.
///
/// Note the `id` and `requires_license` match Lysn.fm's catalog entry exactly —
/// the same seat license unlocks the same product id in either app — while the
/// human-facing name/summary/source describe *provcheck's* pack (the read/detect
/// side: the standalone `provcheck-mellin` binary + the Backfire reader).
pub fn catalog() -> Vec<DlcInfo> {
    vec![DlcInfo {
        id: DLC_PRO_WATERMARKING.to_string(),
        name: "Pro Watermarking".to_string(),
        summary: "Keyed forensic watermark detection: read your Backfire image mark and your \
                  Mellin per-copy audio serial, so you can trace your own leaks. C2PA \
                  verification stays free; this seat unlocks both keyed marks."
            .to_string(),
        requires_license: true,
        approx_bytes: 0,
        default_source: "https://dl.provcheck.ai/dlc/pro-watermarking".to_string(),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::{DomainSigned, did_key_from_verifying};
    use ed25519_dalek::SigningKey;

    /// A deterministic test issuer standing in for the (unset) Creative Mayhem
    /// key. Seed `[7u8; 32]` — the SAME seed Lysn.fm's `lysn-dlc` tests use.
    fn issuer_key() -> (SigningKey, String) {
        let k = SigningKey::from_bytes(&[7u8; 32]);
        let did = did_key_from_verifying(&k.verifying_key());
        (k, did)
    }

    fn signed(key: &SigningKey, issuer_did: &str, product: &str) -> ProLicense {
        let mut lic = ProLicense {
            issuer: issuer_did.to_string(),
            product: product.to_string(),
            subject: "did:key:zBuyer".to_string(),
            issued_at: "2026-08-19T12:00:00Z".to_string(),
            expires_at: None,
            sig: None,
        };
        lic.sign(key).unwrap();
        lic
    }

    #[test]
    fn valid_license_authorizes_offline() {
        let (k, did) = issuer_key();
        let lic = signed(&k, &did, DLC_PRO_WATERMARKING);
        assert!(lic.authorize_with(&did, DLC_PRO_WATERMARKING, None).is_ok());
    }

    #[test]
    fn a_license_from_a_different_key_is_rejected() {
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let attacker_did = did_key_from_verifying(&attacker.verifying_key());
        let lic = signed(&attacker, &attacker_did, DLC_PRO_WATERMARKING);

        let (_trusted_k, trusted_did) = issuer_key();
        assert_eq!(
            lic.authorize_with(&trusted_did, DLC_PRO_WATERMARKING, None),
            Err(DlcError::WrongIssuer)
        );
    }

    #[test]
    fn forged_issuer_field_fails_the_signature_check() {
        let (_trusted_k, trusted_did) = issuer_key();
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let mut lic = ProLicense {
            issuer: trusted_did.clone(), // lie
            product: DLC_PRO_WATERMARKING.to_string(),
            subject: "did:key:zBuyer".to_string(),
            issued_at: "2026-08-19T12:00:00Z".to_string(),
            expires_at: None,
            sig: None,
        };
        lic.sign(&attacker).unwrap(); // signs with the wrong key
        assert_eq!(
            lic.authorize_with(&trusted_did, DLC_PRO_WATERMARKING, None),
            Err(DlcError::Signature(SignError::BadSignature))
        );
    }

    #[test]
    fn tampering_after_signing_is_rejected() {
        let (k, did) = issuer_key();
        let mut lic = signed(&k, &did, DLC_PRO_WATERMARKING);
        lic.subject = "did:key:zSomeoneElse".to_string();
        assert_eq!(
            lic.authorize_with(&did, DLC_PRO_WATERMARKING, None),
            Err(DlcError::Signature(SignError::BadSignature))
        );
    }

    #[test]
    fn a_license_for_another_product_does_not_unlock_this_one() {
        let (k, did) = issuer_key();
        let lic = signed(&k, &did, "some-other-pack");
        assert_eq!(
            lic.authorize_with(&did, DLC_PRO_WATERMARKING, None),
            Err(DlcError::WrongProduct)
        );
    }

    #[test]
    fn expiry_is_enforced_when_a_clock_is_supplied() {
        let (k, did) = issuer_key();
        let mut lic = signed(&k, &did, DLC_PRO_WATERMARKING);
        lic.expires_at = Some("2027-01-01T00:00:00Z".to_string());
        lic.sign(&k).unwrap(); // re-sign to cover the new field

        assert!(
            lic.authorize_with(&did, DLC_PRO_WATERMARKING, Some("2026-12-31T23:59:59Z"))
                .is_ok()
        );
        assert_eq!(
            lic.authorize_with(&did, DLC_PRO_WATERMARKING, Some("2027-06-01T00:00:00Z")),
            Err(DlcError::Expired)
        );
        assert!(lic.authorize_with(&did, DLC_PRO_WATERMARKING, None).is_ok());
    }

    #[test]
    fn fails_closed_against_the_unset_production_issuer() {
        // Using the real production entrypoint, a test-signed license must NOT
        // authorize while the pinned issuer is still the placeholder.
        let (k, did) = issuer_key();
        let lic = signed(&k, &did, DLC_PRO_WATERMARKING);
        assert_eq!(
            lic.authorize(DLC_PRO_WATERMARKING, None),
            Err(DlcError::WrongIssuer)
        );
    }

    #[test]
    fn catalog_lists_the_pro_watermarking_pack() {
        let c = catalog();
        assert!(
            c.iter()
                .any(|d| d.id == DLC_PRO_WATERMARKING && d.requires_license)
        );
    }

    /// Cross-repo wire lock for the whole license: a fixed issuer seed + fixed
    /// license fields produce a fixed `did:key` AND a fixed signature. These are
    /// the SAME bytes Lysn.fm's `lysn-dlc` produces (a mirrored golden test lives
    /// there). If either constant changes, a seat license minted by the offline
    /// issuer will not verify across both apps — a wire break.
    #[test]
    fn golden_signed_license_matches_lysn() {
        let k = SigningKey::from_bytes(&[7u8; 32]);
        let did = did_key_from_verifying(&k.verifying_key());
        let mut lic = ProLicense {
            issuer: did.clone(),
            product: DLC_PRO_WATERMARKING.to_string(),
            subject: "did:key:zBuyer".to_string(),
            issued_at: "2026-08-19T12:00:00Z".to_string(),
            expires_at: None,
            sig: None,
        };
        lic.sign(&k).unwrap();
        assert_eq!(did, crate::testvectors::ISSUER_DID_SEED7);
        assert_eq!(
            lic.sig.as_deref(),
            Some(crate::testvectors::LICENSE_SIG_SEED7)
        );
        // And the license authorizes against that issuer.
        assert!(lic.authorize_with(&did, DLC_PRO_WATERMARKING, None).is_ok());
    }
}
