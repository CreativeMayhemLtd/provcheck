// SPDX-License-Identifier: Apache-2.0
//
// This file contains code adapted from rAIdio.bot
// (C:\dev2\rAIdio.bot-rust\src-tauri\src\c2pa\signer.rs lines
// 765-819), originally LicenseRef-Proprietary, relicensed under
// Apache-2.0 by the rAIdio.bot owner (Chris Neitzert,
// authorisation 2026-06-13) for inclusion in provcheck-sign.
//
// The original `generate_es256_keypair_pems` is parameterised
// through `SubjectInfo` here; the cryptographic structure (P-256
// curve, self-signed CA + EE chain, KU/EKU bits) is preserved
// verbatim.

//! ES256 keypair + cert chain generation.
//!
//! Produces a self-signed root CA cert and a leaf end-entity cert
//! signed by that root, both as PEM strings ready to hand to
//! `c2pa::create_signer::from_keys`. The leaf's DER bytes are also
//! returned alongside so the canonical fingerprint can be computed
//! via [`provcheck_attestation_spec::fingerprint_leaf_der`] without
//! a second PEM round-trip.

use provcheck_attestation_spec::fingerprint_leaf_der;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};

/// Subject metadata baked into the generated certs.
///
/// The defaults intentionally describe a *generic* local-install
/// signer — they don't claim rAIdio.bot or any other product as the
/// issuing authority. Branded tools (rAIdio.bot, doomscroll.fm,
/// downstream apps that wrap provcheck-sign) override these.
///
/// Wording note: keeping "user-generated" in the organisation hint
/// is load-bearing for downstream forensic readers — it locks in
/// that the certificate represents *this install* and not the
/// upstream brand acting as a CA. The same convention rAIdio.bot
/// uses today.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectInfo {
    /// Common Name on the end-entity (signing) cert. Shown by tools
    /// that walk the cert chain — keep it short and informative.
    pub common_name: String,
    /// Organisation Name on both the CA and EE certs.
    pub organisation: String,
    /// Common Name on the self-signed root CA.
    pub ca_common_name: String,
}

impl Default for SubjectInfo {
    fn default() -> Self {
        Self {
            common_name: "Local Content Signer".to_string(),
            organisation: "provcheck-kit (user-generated)".to_string(),
            ca_common_name: "Local Install CA".to_string(),
        }
    }
}

/// A freshly-generated keypair + cert chain, ready to persist.
///
/// `chain_pem` is in the conventional order: end-entity cert first,
/// CA cert second. Both `c2pa::create_signer::from_keys` and the
/// spec crate's [`fingerprint_pem_chain`](provcheck_attestation_spec::fingerprint_pem_chain)
/// expect that ordering — the EE cert is the leaf and the CA is the
/// chain anchor.
#[derive(Debug, Clone)]
pub struct GeneratedKeypair {
    /// EE cert PEM followed by CA cert PEM, concatenated.
    pub chain_pem: String,
    /// EE private key PEM (PKCS#8 format from rcgen).
    pub key_pem: String,
    /// Canonical fingerprint of the leaf cert, ready to publish as
    /// the `fingerprint` field of an `app.provcheck.signingKey`
    /// record. Format: `sha256:<lowercase-hex>`.
    pub fingerprint: String,
    /// JWS algorithm identifier — currently always `"ES256"`.
    /// Threaded through so callers writing an
    /// `app.provcheck.signingKey` record have the right value
    /// without inferring it from the cert.
    pub algorithm: String,
}

/// Errors from cert generation. The rcgen library returns its own
/// error type at each step; we collapse them into a string here
/// because the underlying errors are not particularly actionable
/// (failures at this layer mean either the platform RNG is broken
/// or a deeper rcgen invariant was violated).
#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("CA keypair generation failed: {0}")]
    CaKeypair(String),
    #[error("CA cert signing failed: {0}")]
    CaCert(String),
    #[error("CA issuer construction failed: {0}")]
    CaIssuer(String),
    #[error("EE keypair generation failed: {0}")]
    EeKeypair(String),
    #[error("EE cert signing failed: {0}")]
    EeCert(String),
}

/// Generate a fresh ES256 keypair + a self-signed CA + an EE cert
/// signed by that CA.
///
/// The CA cert is unconstrained (no path-length limit, the only KU
/// bits set are `KeyCertSign` + `CrlSign`). The EE cert is
/// `ExplicitNoCa` with `DigitalSignature` + `EmailProtection`. The
/// EKU choice matches what c2pa-rs's signer constructor expects for
/// content-credential signing.
///
/// Subject names come from `subject`. The defaults
/// (`SubjectInfo::default()`) produce a generic local-install
/// signer; branded callers override.
pub fn generate(subject: &SubjectInfo) -> Result<GeneratedKeypair, CertError> {
    // --- Step 1: Self-signed root CA ---
    let ca_key = KeyPair::generate().map_err(|e| CertError::CaKeypair(e.to_string()))?;

    let mut ca_params = CertificateParams::default();
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, subject.ca_common_name.clone());
    ca_dn.push(DnType::OrganizationName, subject.organisation.clone());
    ca_params.distinguished_name = ca_dn;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let ca_cert = ca_params
        .self_signed(&ca_key)
        .map_err(|e| CertError::CaCert(e.to_string()))?;

    // --- Step 2: End-entity cert signed by the CA ---
    let ee_key = KeyPair::generate().map_err(|e| CertError::EeKeypair(e.to_string()))?;

    let mut ee_params = CertificateParams::default();
    let mut ee_dn = DistinguishedName::new();
    ee_dn.push(DnType::CommonName, subject.common_name.clone());
    ee_dn.push(DnType::OrganizationName, subject.organisation.clone());
    ee_params.distinguished_name = ee_dn;
    ee_params.is_ca = IsCa::ExplicitNoCa;
    ee_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    ee_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
    ee_params.use_authority_key_identifier_extension = true;

    let ca_issuer = rcgen::Issuer::from_ca_cert_der(ca_cert.der(), &ca_key)
        .map_err(|e| CertError::CaIssuer(e.to_string()))?;

    let ee_cert = ee_params
        .signed_by(&ee_key, &ca_issuer)
        .map_err(|e| CertError::EeCert(e.to_string()))?;

    // --- Step 3: Compose the return ---
    // chain_pem: EE first, CA second. The spec crate's fingerprint
    // helper takes the *first* CERTIFICATE block, which is the EE
    // (leaf) — what the verifier hashes when computing the cert
    // fingerprint to look up under app.provcheck.signingKey.
    let chain_pem = format!("{}{}", ee_cert.pem(), ca_cert.pem());
    let key_pem = ee_key.serialize_pem();
    let fingerprint = fingerprint_leaf_der(ee_cert.der());

    Ok(GeneratedKeypair {
        chain_pem,
        key_pem,
        fingerprint,
        algorithm: "ES256".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use provcheck_attestation_spec::fingerprint_pem_chain;

    #[test]
    fn generates_chain_with_two_certificate_blocks() {
        let kp = generate(&SubjectInfo::default()).expect("generation succeeds");
        // EE cert + CA cert => exactly two BEGIN CERTIFICATE markers.
        let begin_count = kp.chain_pem.matches("-----BEGIN CERTIFICATE-----").count();
        assert_eq!(begin_count, 2, "chain has EE + CA");
        let key_count = kp.chain_pem.matches("-----BEGIN PRIVATE KEY-----").count();
        assert_eq!(key_count, 0, "chain does not contain the private key");
    }

    #[test]
    fn key_pem_is_separately_emitted() {
        let kp = generate(&SubjectInfo::default()).expect("generation succeeds");
        assert!(
            kp.key_pem.contains("PRIVATE KEY"),
            "key_pem looks like a PEM-encoded private key"
        );
        assert!(
            !kp.chain_pem.contains("PRIVATE KEY"),
            "key material does not leak into the chain"
        );
    }

    #[test]
    fn fingerprint_matches_spec_crate_recomputation() {
        // Round-trip: the fingerprint field GeneratedKeypair carries
        // must equal what the spec crate's fingerprint_pem_chain
        // computes over the same chain. This is the contract that
        // ties cert generation to the on-the-wire format — the
        // verifier (using fingerprint_pem_chain) and the publisher
        // (using GeneratedKeypair.fingerprint) must agree.
        let kp = generate(&SubjectInfo::default()).expect("generation succeeds");
        let recomputed = fingerprint_pem_chain(&kp.chain_pem).expect("PEM parses");
        assert_eq!(
            kp.fingerprint, recomputed,
            "GeneratedKeypair.fingerprint == fingerprint_pem_chain(chain_pem)"
        );
    }

    #[test]
    fn fingerprint_has_lexicon_shape() {
        let kp = generate(&SubjectInfo::default()).expect("generation succeeds");
        assert!(kp.fingerprint.starts_with("sha256:"));
        assert_eq!(kp.fingerprint.len(), "sha256:".len() + 64);
        let hex = &kp.fingerprint["sha256:".len()..];
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "lowercase hex per the lexicon pattern ^sha256:[0-9a-f]{{64}}$"
        );
    }

    #[test]
    fn algorithm_is_es256() {
        // The lexicon's knownValues list accepts ES256/384/512,
        // PS256/etc., Ed25519. Right now provcheck-sign only ever
        // generates ES256 — but the field is on the struct so
        // future variants don't break the type.
        let kp = generate(&SubjectInfo::default()).expect("generation succeeds");
        assert_eq!(kp.algorithm, "ES256");
        assert!(provcheck_attestation_spec::ALLOWED_ALGORITHMS.contains(&kp.algorithm.as_str()));
    }

    #[test]
    fn subject_info_threads_through_to_the_chain() {
        // Test that overriding SubjectInfo actually affects the
        // produced cert. We re-parse the EE cert via x509-parser and
        // check the CN/O.
        let subject = SubjectInfo {
            common_name: "ProvCheckKit Test Signer".to_string(),
            organisation: "ProvCheckKit Test Org".to_string(),
            ca_common_name: "ProvCheckKit Test Root".to_string(),
        };
        let kp = generate(&subject).expect("generation succeeds");

        // Pull the first (EE) cert out of the PEM chain.
        let parsed = pem::parse_many(&kp.chain_pem).expect("PEM parses");
        let ee = parsed
            .iter()
            .find(|p| p.tag() == "CERTIFICATE")
            .expect("EE cert block present");

        let (_rest, x509) =
            x509_parser::parse_x509_certificate(ee.contents()).expect("EE cert decodes as X.509");

        let subject_str = format!("{}", x509.subject());
        assert!(
            subject_str.contains("ProvCheckKit Test Signer"),
            "EE CN threaded through: {subject_str}"
        );
        assert!(
            subject_str.contains("ProvCheckKit Test Org"),
            "EE O threaded through: {subject_str}"
        );
    }

    #[test]
    fn two_runs_produce_distinct_fingerprints() {
        // Generation must produce fresh randomness; two consecutive
        // calls should never produce the same cert. (If they did,
        // every install would publish the same fingerprint, which
        // is a privacy + correlation disaster.)
        let a = generate(&SubjectInfo::default()).expect("a");
        let b = generate(&SubjectInfo::default()).expect("b");
        assert_ne!(
            a.fingerprint, b.fingerprint,
            "fresh randomness → distinct keypairs → distinct fingerprints"
        );
    }
}
