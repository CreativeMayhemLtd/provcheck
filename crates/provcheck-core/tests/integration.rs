//! Integration tests for `provcheck-core::verify`.
//!
//! These tests generate fixtures at run-time rather than committing
//! binary fixture files:
//!
//! - A 0.1-second silent WAV (synthesised in-memory via `hound`) —
//!   zero audio content, so no copyright question.
//! - An ES256 cert chain (CA + EE) generated fresh via `rcgen`,
//!   matching rAIdio.bot's per-install signing pattern.
//!
//! Covered outcomes:
//!
//! 1. Unsigned WAV → `unsigned: true`, `verified: false`, exit 1.
//! 2. Signed WAV → `unsigned: false`, `verified: true`, exit 0,
//!    manifest + assertions populated.
//! 3. Tampered (signed then byte-flipped) → `verified: false`,
//!    `validation_errors > 0` OR `failure_reason` set.
//! 4. Non-media file (txt) → `unsigned: true` with format-not-
//!    supported reason, exit 1 (NOT exit 2).

use std::fs;
use std::path::Path;

use provcheck_core::verify;

// ---- Fixture generation helpers ---------------------------------------------

/// Write a ~0.1-second mono silent WAV to `dest`.
fn write_silent_wav(dest: &Path) {
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate: 44_100,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };
    let mut writer = hound::WavWriter::create(dest, spec).expect("wav writer");
    for _ in 0..4_410 {
        // ~0.1 s of silence at 44.1 kHz
        writer.write_sample(0_i16).expect("wav sample");
    }
    writer.finalize().expect("wav finalize");
}

/// Generate a throwaway ES256 cert chain (CA + EE) + key, in PEM
/// bytes ready to hand to `c2pa::create_signer::from_keys`. Mirrors
/// rAIdio.bot's `generate_es256_keypair` so our fixtures exercise
/// the same cert shape real users' outputs will carry.
fn generate_test_chain() -> (Vec<u8>, Vec<u8>) {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose,
    };

    let ca_key = KeyPair::generate().expect("ca keypair");
    let mut ca_params = CertificateParams::default();
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "provcheck Test CA");
    ca_dn.push(DnType::OrganizationName, "provcheck (test only)");
    ca_params.distinguished_name = ca_dn;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca self-sign");

    let ee_key = KeyPair::generate().expect("ee keypair");
    let mut ee_params = CertificateParams::default();
    let mut ee_dn = DistinguishedName::new();
    ee_dn.push(DnType::CommonName, "provcheck Test Signer");
    ee_dn.push(DnType::OrganizationName, "provcheck (test only)");
    ee_params.distinguished_name = ee_dn;
    ee_params.is_ca = IsCa::ExplicitNoCa;
    ee_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    ee_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
    ee_params.use_authority_key_identifier_extension = true;

    let ca_issuer =
        rcgen::Issuer::from_ca_cert_der(ca_cert.der(), &ca_key).expect("ca issuer");
    let ee_cert = ee_params.signed_by(&ee_key, &ca_issuer).expect("ee sign");

    // cert_pem = EE cert + CA cert (chain)
    let chain_pem = format!("{}{}", ee_cert.pem(), ca_cert.pem());
    let key_pem = ee_key.serialize_pem();
    (chain_pem.into_bytes(), key_pem.into_bytes())
}

/// Sign `src` in place (writes to `dest`) with a freshly generated
/// test cert chain. Returns nothing; panics on failure.
fn sign_file(src: &Path, dest: &Path) {
    let (cert_pem, key_pem) = generate_test_chain();
    let signer = c2pa::create_signer::from_keys(
        &cert_pem,
        &key_pem,
        c2pa::SigningAlg::Es256,
        None,
    )
    .expect("create signer");

    let manifest_json = r#"{
      "claim_generator": "provcheck-test/0.1.0",
      "title": "provcheck integration test fixture",
      "assertions": [
        {
          "label": "c2pa.actions",
          "data": {
            "actions": [ { "action": "c2pa.created" } ]
          }
        }
      ]
    }"#;

    let mut builder = c2pa::Builder::from_json(manifest_json).expect("builder from json");
    builder
        .sign_file(signer.as_ref(), src, dest)
        .expect("sign file");
}

// ---- Tests ------------------------------------------------------------------

#[test]
fn unsigned_wav_reports_unsigned() {
    let tmp = tempfile::tempdir().expect("tmp");
    let wav = tmp.path().join("silent.wav");
    write_silent_wav(&wav);

    let report = verify(&wav).expect("verify returns Ok");
    assert!(report.unsigned, "expected unsigned=true, got {:?}", report);
    assert!(!report.verified);
    assert_eq!(report.exit_code(), 1);
    assert!(report.active_manifest.is_none());
    assert!(report.assertions.is_null());
}

#[test]
fn signed_wav_verifies() {
    let tmp = tempfile::tempdir().expect("tmp");
    let src = tmp.path().join("silent.wav");
    let dest = tmp.path().join("silent-signed.wav");
    write_silent_wav(&src);
    sign_file(&src, &dest);

    let report = verify(&dest).expect("verify returns Ok");
    assert!(report.verified, "expected verified=true, got {:?}", report);
    assert!(!report.unsigned);
    assert_eq!(report.exit_code(), 0);
    assert!(report.active_manifest.is_some(), "manifest label should be present");
    assert!(
        report.signer.is_some(),
        "signer common_name should be present — got {:?}",
        report
    );
    // The manifest we built has a c2pa.actions assertion — it should
    // show up in the flattened assertion map.
    let assertions_obj = report
        .assertions
        .as_object()
        .expect("assertions should be a JSON object on a signed file");
    assert!(
        assertions_obj.keys().any(|k| k.starts_with("c2pa.actions")),
        "expected a c2pa.actions* assertion, got keys: {:?}",
        assertions_obj.keys().collect::<Vec<_>>()
    );
}

#[test]
fn tampered_wav_fails_verification() {
    let tmp = tempfile::tempdir().expect("tmp");
    let src = tmp.path().join("silent.wav");
    let dest = tmp.path().join("silent-signed.wav");
    write_silent_wav(&src);
    sign_file(&src, &dest);

    // Locate the JUMBF superbox magic ("jumb") so we can tamper with
    // a byte INSIDE the C2PA manifest region. Tampering the raw WAV
    // audio data doesn't always break verification (depends on which
    // hash-binding assertions the manifest carries) — but tampering
    // a byte inside the manifest region will always fail the claim
    // signature check. That's the test's whole point: confirm our
    // tool flags a broken-signature case as NOT verified.
    let mut bytes = fs::read(&dest).expect("read signed");
    let jumb_offset = find_subslice(&bytes, b"jumb").expect(
        "signed WAV must contain a JUMBF superbox with 'jumb' magic — \
         c2pa layout assumption broken",
    );
    // Flip a byte ~32 bytes past the JUMBF magic — almost certainly
    // inside the claim or signature payload, which is what the
    // signature covers.
    let tamper_idx = jumb_offset + 32;
    assert!(
        tamper_idx < bytes.len(),
        "JUMBF box is smaller than expected; test assumption invalid"
    );
    bytes[tamper_idx] ^= 0xFF;
    fs::write(&dest, &bytes).expect("write tampered");

    let report = verify(&dest).expect("verify returns Ok on tampered");
    assert!(
        !report.verified,
        "tampered file should NOT verify; got {:?}",
        report
    );
    assert_eq!(report.exit_code(), 1);
}

/// Minimal substring search — stdlib doesn't have one for `&[u8]`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

#[test]
fn unsupported_format_reports_unsigned_not_error() {
    let tmp = tempfile::tempdir().expect("tmp");
    let txt = tmp.path().join("not-media.txt");
    fs::write(&txt, b"just plain text, definitely no C2PA here").expect("write txt");

    let report = verify(&txt).expect("verify returns Ok — unsupported format is NOT an Err");
    assert!(report.unsigned);
    assert_eq!(report.exit_code(), 1);
    assert!(
        report
            .failure_reason
            .as_deref()
            .map(|r| r.contains("not supported"))
            .unwrap_or(false),
        "failure_reason should mention 'not supported'; got {:?}",
        report.failure_reason
    );
}
