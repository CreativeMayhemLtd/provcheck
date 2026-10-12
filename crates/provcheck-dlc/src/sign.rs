// SPDX-License-Identifier: Apache-2.0
//! The one signing primitive, ported from Lysn.fm's `lysn-sign`.
//!
//! Every signed Lysn.fm record is authenticated the same way: an Ed25519
//! signature over `DOMAIN || JCS(value with its `sig` field removed)`, where
//! `DOMAIN` is a per-record-type domain-separation tag and `JCS` is RFC 8785
//! canonical JSON ([`crate::jcs`]). The signature and the `did:key` are both
//! base58btc.
//!
//! provcheck only ever needs the **verify** half (the offline `dlc-issue` tool
//! on the Lysn.fm side holds the private key and does the signing). The signing
//! helpers are included so the tests can mint licenses locally and so this crate
//! stays a faithful, self-contained mirror — but the shipped provcheck binary
//! never signs a license.
//!
//! The byte layout here is a wire contract with `lysn-sign`; it is fixed and
//! covered by the golden tests. See the crate-level note.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::Serialize;

use crate::jcs;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SignError {
    #[error("missing signature")]
    MissingSignature,
    #[error("signature verification failed")]
    BadSignature,
    #[error("malformed did:key")]
    BadDid,
}

// ─────────────────────── did:key (Ed25519) ───────────────────────

/// Encode an Ed25519 public key as a `did:key` (multicodec 0xed01, multibase
/// base58btc). Identical to `lysn_sign::did_key_from_verifying`.
pub fn did_key_from_verifying(vk: &VerifyingKey) -> String {
    let mut bytes = Vec::with_capacity(34);
    bytes.extend_from_slice(&[0xed, 0x01]); // ed25519-pub multicodec
    bytes.extend_from_slice(&vk.to_bytes());
    format!("did:key:z{}", bs58::encode(bytes).into_string())
}

/// Recover the Ed25519 public key from a `did:key`.
pub fn verifying_from_did_key(did: &str) -> Result<VerifyingKey, SignError> {
    let s = did.strip_prefix("did:key:z").ok_or(SignError::BadDid)?;
    let bytes = bs58::decode(s).into_vec().map_err(|_| SignError::BadDid)?;
    if bytes.len() != 34 || bytes[0] != 0xed || bytes[1] != 0x01 {
        return Err(SignError::BadDid);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes[2..34]);
    VerifyingKey::from_bytes(&key).map_err(|_| SignError::BadDid)
}

/// Encode a signature as base58btc.
pub fn sig_to_str(sig: &Signature) -> String {
    bs58::encode(sig.to_bytes()).into_string()
}

/// Decode a base58btc signature.
pub fn sig_from_str(s: &str) -> Result<Signature, SignError> {
    let b = bs58::decode(s)
        .into_vec()
        .map_err(|_| SignError::BadSignature)?;
    let arr: [u8; 64] = b.try_into().map_err(|_| SignError::BadSignature)?;
    Ok(Signature::from_bytes(&arr))
}

// ─────────────────────── canonical signing bytes ───────────────────────

/// The deterministic bytes an issuer signs: `domain` followed by the RFC 8785
/// JCS canonicalization of `value` with any top-level `sig` field removed.
pub fn signing_bytes(domain: &[u8], value: &(impl Serialize + ?Sized)) -> Vec<u8> {
    let mut v = serde_json::to_value(value).expect("value serializes to JSON");
    if let Some(m) = v.as_object_mut() {
        m.remove("sig");
    }
    let mut out = domain.to_vec();
    out.extend_from_slice(&jcs::canonicalize_bytes(&v));
    out
}

/// Sign `msg` with `key`, returning the base58btc signature string.
pub fn sign_bytes(key: &SigningKey, msg: &[u8]) -> String {
    sig_to_str(&key.sign(msg))
}

/// Verify a base58btc `sig` over `msg` against a `did:key`.
pub fn verify_sig(signer_did: &str, msg: &[u8], sig: &str) -> Result<(), SignError> {
    let sig = sig_from_str(sig)?;
    let vk = verifying_from_did_key(signer_did)?;
    vk.verify_strict(msg, &sig)
        .map_err(|_| SignError::BadSignature)
}

// ─────────────────────── the convenience trait ───────────────────────

/// A self-signed record with a single signer `did` and a `sig` field. Declare
/// the domain tag + the three accessors and get `sign`/`verify` for free.
/// Mirror of `lysn_sign::DomainSigned`.
pub trait DomainSigned: Serialize {
    /// Domain-separation tag for this record type.
    const DOMAIN: &'static [u8];
    /// The `did:key` expected to have signed this record.
    fn signer_did(&self) -> &str;
    /// The current signature, if any.
    fn sig(&self) -> Option<&str>;
    /// Set (or clear) the signature.
    fn set_sig(&mut self, sig: Option<String>);

    fn signing_bytes(&self) -> Vec<u8> {
        signing_bytes(Self::DOMAIN, self)
    }
    /// Sign in place with `key` (the caller ensures `signer_did()` matches
    /// `key`). Used by the offline issuer + the tests; never by shipped
    /// provcheck code.
    fn sign(&mut self, key: &SigningKey) -> Result<(), SignError> {
        self.set_sig(None);
        let sig = sign_bytes(key, &self.signing_bytes());
        self.set_sig(Some(sig));
        Ok(())
    }
    /// Verify the self-signature against `signer_did()`.
    fn verify(&self) -> Result<(), SignError> {
        let sig = self.sig().ok_or(SignError::MissingSignature)?;
        verify_sig(self.signer_did(), &self.signing_bytes(), sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[3u8; 32])
    }

    #[test]
    fn did_key_roundtrips() {
        let k = key();
        let did = did_key_from_verifying(&k.verifying_key());
        assert!(did.starts_with("did:key:z"));
        assert_eq!(verifying_from_did_key(&did).unwrap(), k.verifying_key());
        assert_eq!(
            verifying_from_did_key("did:key:zbogus"),
            Err(SignError::BadDid)
        );
    }

    #[test]
    fn signing_bytes_matches_the_legacy_formula_exactly() {
        // Known-answer: DOMAIN ++ JCS(value with "sig" removed), byte-for-byte
        // what `lysn-sign`'s own test asserts.
        let value = serde_json::json!({ "b": 2, "a": 1, "sig": "IGNORED" });
        const DOMAIN: &[u8] = b"lysn-test/v1\x00";
        let got = signing_bytes(DOMAIN, &value);

        let mut expected = DOMAIN.to_vec();
        let stripped = serde_json::json!({ "a": 1, "b": 2 });
        expected.extend_from_slice(&jcs::canonicalize_bytes(&stripped));
        assert_eq!(got, expected);
        // "sig" is excluded, so changing it does not change the signed bytes.
        let other = serde_json::json!({ "a": 1, "b": 2, "sig": "DIFFERENT" });
        assert_eq!(signing_bytes(DOMAIN, &other), got);
    }

    #[derive(Serialize, Deserialize)]
    struct Rec {
        did: String,
        text: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        sig: Option<String>,
    }
    impl DomainSigned for Rec {
        const DOMAIN: &'static [u8] = b"lysn-rec/v1\x00";
        fn signer_did(&self) -> &str {
            &self.did
        }
        fn sig(&self) -> Option<&str> {
            self.sig.as_deref()
        }
        fn set_sig(&mut self, sig: Option<String>) {
            self.sig = sig;
        }
    }

    #[test]
    fn trait_sign_verify_and_tamper() {
        let k = key();
        let mut r = Rec {
            did: did_key_from_verifying(&k.verifying_key()),
            text: "hello".into(),
            sig: None,
        };
        r.sign(&k).unwrap();
        assert!(r.verify().is_ok());

        // Tamper the signed content → verify fails.
        r.text = "tampered".into();
        assert_eq!(r.verify(), Err(SignError::BadSignature));

        // Missing signature → distinct error.
        let unsigned = Rec {
            did: r.did.clone(),
            text: "x".into(),
            sig: None,
        };
        assert_eq!(unsigned.verify(), Err(SignError::MissingSignature));
    }

    /// Cross-repo wire lock: a fixed issuer seed produces a fixed `did:key`, and
    /// the whole codec round-trips. The exact `did:key` string below is the
    /// SAME value `lysn-sign` produces for seed `[7u8; 32]` (the issuer seed the
    /// Lysn.fm `lysn-dlc` tests use). If this constant ever changes, the did:key
    /// / base58 codec has drifted from Lysn.fm and a seat license minted there
    /// will not verify here.
    #[test]
    fn golden_did_key_for_fixed_seed_matches_lysn() {
        let k = SigningKey::from_bytes(&[7u8; 32]);
        let did = did_key_from_verifying(&k.verifying_key());
        assert_eq!(did, crate::testvectors::ISSUER_DID_SEED7);
        // And it round-trips back to the same key.
        assert_eq!(verifying_from_did_key(&did).unwrap(), k.verifying_key());
    }
}
