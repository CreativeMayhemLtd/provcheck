//! C2PA signing orchestration.
//!
//! Wraps `c2pa::create_signer::from_keys` + `c2pa::Builder::sign_file`
//! around an [`UnlockedIdentity`]. The caller supplies the manifest
//! JSON (assertions list); this module handles the cert / key wiring
//! and the file IO. Pure-Rust c2pa stack: `default-features = false`
//! + `rust_native_crypto` (matching the workspace pin), no OpenSSL.
//!
//! ## What this is, what it isn't
//!
//! This is the primitive that produces signed media. It is **not**
//! the manifest builder — the caller composes the JSON. The CLI
//! ships an opinionated helper that fills in the standard
//! `c2pa.actions.v2` + `c2pa.creative_work` shape, plus the
//! `app.provcheck.identity` assertion when an identity is
//! registered (Phase 5 work). At the crate level we stay minimal
//! and let downstream callers decide the manifest shape.

use std::path::{Path, PathBuf};

use secrecy::ExposeSecret;

use crate::types::UnlockedIdentity;

/// Errors from the C2PA signing primitive.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("source asset not found or unreadable: {0}")]
    Source(std::io::Error),

    #[error("could not parse signing algorithm '{0}' as a c2pa::SigningAlg variant")]
    UnknownAlgorithm(String),

    #[error("could not construct c2pa signer: {0}")]
    SignerSetup(String),

    #[error("could not parse manifest JSON: {0}")]
    ManifestJson(String),

    #[error("c2pa signing failed: {0}")]
    C2pa(String),
}

/// What a successful signing call wrote.
#[derive(Debug, Clone)]
pub struct SignResult {
    /// Where the signed asset ended up. For in-place signing this
    /// equals the source path; for sidecar / new-file modes it's
    /// distinct.
    pub output_path: PathBuf,
    /// The serialised manifest bytes (`Vec<u8>` from c2pa's
    /// `sign_file`). The CLI can hand these to its caller for
    /// inspection without re-reading the signed file.
    pub manifest_bytes: Vec<u8>,
}

/// Sign an asset with the unlocked identity's cert chain + private
/// key.
///
/// `src` is the source asset (mp3, wav, jpeg, mp4, etc. — anything
/// the c2pa crate's `Builder::sign_file` recognises). `dst` is
/// where the signed output should land — pass the same path as
/// `src` for in-place signing, or a sibling path for sidecar /
/// new-file output. Source and destination must use the same file
/// format (extension); c2pa enforces this.
///
/// `manifest_json` is the full Builder JSON: `claim_generator`,
/// `format`, `title`, `assertions`, etc. See c2pa's documentation
/// for the schema. A minimal but valid example is in this
/// module's test suite.
pub fn sign_asset(
    identity: &UnlockedIdentity,
    src: &Path,
    dst: &Path,
    manifest_json: &str,
) -> Result<SignResult, SignError> {
    // Confirm src exists before reaching into c2pa — keeps the
    // error semantics clean (one place where "file missing" is
    // surfaced, c2pa errors are for c2pa concerns).
    std::fs::metadata(src).map_err(SignError::Source)?;

    let alg = match identity.locked.algorithm.as_str() {
        "ES256" => c2pa::SigningAlg::Es256,
        "ES384" => c2pa::SigningAlg::Es384,
        "ES512" => c2pa::SigningAlg::Es512,
        "PS256" => c2pa::SigningAlg::Ps256,
        "PS384" => c2pa::SigningAlg::Ps384,
        "PS512" => c2pa::SigningAlg::Ps512,
        "Ed25519" => c2pa::SigningAlg::Ed25519,
        other => return Err(SignError::UnknownAlgorithm(other.to_string())),
    };

    let signer = c2pa::create_signer::from_keys(
        identity.locked.chain_pem.as_bytes(),
        identity.key_pem().expose_secret().as_bytes(),
        alg,
        None, // No TSA URL — Phase 6 followup if anyone needs trusted timestamps
    )
    .map_err(|e| SignError::SignerSetup(e.to_string()))?;

    let mut builder =
        c2pa::Builder::from_json(manifest_json).map_err(|e| SignError::ManifestJson(e.to_string()))?;

    let manifest_bytes = builder
        .sign_file(signer.as_ref(), src, dst)
        .map_err(|e| SignError::C2pa(e.to_string()))?;

    Ok(SignResult {
        output_path: dst.to_path_buf(),
        manifest_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::{SubjectInfo, generate};
    use crate::types::{KeyProviderKind, LockedIdentity};
    use secrecy::SecretString;
    use tempfile::TempDir;
    use time::OffsetDateTime;

    /// Synthesise a 1-second silent mono 44.1 kHz WAV. Small,
    /// recognised by c2pa as audio/wav, fast to round-trip.
    fn write_silent_wav(path: &Path) {
        let spec = hound::WavSpec {
            channels: 1,
            sample_rate: 44_100,
            bits_per_sample: 16,
            sample_format: hound::SampleFormat::Int,
        };
        let mut w = hound::WavWriter::create(path, spec).expect("wav writer");
        for _ in 0..44_100 {
            w.write_sample(0i16).expect("write sample");
        }
        w.finalize().expect("finalize wav");
    }

    /// Build a real UnlockedIdentity from a freshly-generated cert
    /// chain. Costs ~1 cert generation per test — acceptable;
    /// keeps the tests honest about the cert / key / signer
    /// integration.
    fn fresh_identity() -> UnlockedIdentity {
        let kp = generate(&SubjectInfo::default()).expect("cert");
        let locked = LockedIdentity {
            chain_pem: kp.chain_pem,
            fingerprint: kp.fingerprint,
            algorithm: kp.algorithm,
            did: None,
            handle: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            key_provider: KeyProviderKind::Keychain,
            recovery_recipients: vec![],
        };
        UnlockedIdentity::new(locked, SecretString::from(kp.key_pem))
    }

    /// Minimal-but-valid manifest JSON for a wav signing test.
    fn minimal_wav_manifest() -> String {
        serde_json::json!({
            "claim_generator": "provcheck-kit/0.3.0",
            "claim_generator_info": [{"name": "provcheck-kit", "version": "0.3.0"}],
            "format": "audio/wav",
            "title": "test.wav",
            "assertions": [
                {
                    "label": "c2pa.actions.v2",
                    "data": {
                        "actions": [{"action": "c2pa.created"}]
                    }
                }
            ]
        })
        .to_string()
    }

    #[test]
    fn sign_then_read_round_trips() {
        let dir = TempDir::new().expect("tempdir");
        let src = dir.path().join("src.wav");
        let dst = dir.path().join("signed.wav");
        write_silent_wav(&src);

        let identity = fresh_identity();
        let expected_fingerprint = identity.locked.fingerprint.clone();

        let result = sign_asset(&identity, &src, &dst, &minimal_wav_manifest()).expect("sign");
        assert_eq!(result.output_path, dst);
        assert!(!result.manifest_bytes.is_empty(), "got manifest bytes");
        assert!(dst.exists(), "signed file written");

        // Verify by reading the signed file back through c2pa.
        let reader = c2pa::Reader::from_file(&dst).expect("reader");
        assert!(
            matches!(
                reader.validation_state(),
                c2pa::ValidationState::Valid | c2pa::ValidationState::Trusted
            ),
            "manifest crypto verifies: {:?}",
            reader.validation_state()
        );

        // And confirm the verifier's fingerprint computation of the
        // signing cert matches what GeneratedKeypair gave us — the
        // load-bearing publisher↔verifier contract for the atproto
        // attestation flow.
        let active = reader.active_manifest().expect("active manifest");
        let chain = active
            .signature_info()
            .map(|s| s.cert_chain.clone())
            .expect("cert chain available");
        let fp = provcheck_attestation_spec::fingerprint_pem_chain(&chain).expect("fingerprint");
        assert_eq!(fp, expected_fingerprint);
    }

    #[test]
    fn missing_source_surfaces_clean_io_error() {
        let dir = TempDir::new().expect("tempdir");
        let src = dir.path().join("nope.wav");
        let dst = dir.path().join("signed.wav");
        let identity = fresh_identity();

        let err = sign_asset(&identity, &src, &dst, &minimal_wav_manifest()).expect_err("");
        assert!(matches!(err, SignError::Source(_)), "got {err:?}");
        assert!(!dst.exists(), "no destination written on missing source");
    }

    #[test]
    fn invalid_manifest_json_surfaces_typed_error() {
        let dir = TempDir::new().expect("tempdir");
        let src = dir.path().join("src.wav");
        let dst = dir.path().join("signed.wav");
        write_silent_wav(&src);
        let identity = fresh_identity();

        let err = sign_asset(&identity, &src, &dst, "{not valid json}").expect_err("");
        assert!(matches!(err, SignError::ManifestJson(_)), "got {err:?}");
    }

    #[test]
    fn unknown_algorithm_is_typed_error() {
        let dir = TempDir::new().expect("tempdir");
        let src = dir.path().join("src.wav");
        let dst = dir.path().join("signed.wav");
        write_silent_wav(&src);

        let mut identity = fresh_identity();
        identity.locked.algorithm = "RSA-PSS-4096".to_string();

        let err = sign_asset(&identity, &src, &dst, &minimal_wav_manifest()).expect_err("");
        assert!(matches!(err, SignError::UnknownAlgorithm(_)), "got {err:?}");
    }

    #[test]
    fn extra_assertions_round_trip_into_the_manifest() {
        // The signing primitive doesn't transform the manifest
        // JSON — what the caller asks for is what ends up in the
        // signed file. Confirm with a custom assertion that we
        // can find when we read it back.
        let dir = TempDir::new().expect("tempdir");
        let src = dir.path().join("src.wav");
        let dst = dir.path().join("signed.wav");
        write_silent_wav(&src);
        let identity = fresh_identity();

        let manifest = serde_json::json!({
            "claim_generator": "provcheck-kit/0.3.0",
            "claim_generator_info": [{"name": "provcheck-kit", "version": "0.3.0"}],
            "format": "audio/wav",
            "title": "test.wav",
            "assertions": [
                {"label": "c2pa.actions.v2", "data": {"actions": [{"action": "c2pa.created"}]}},
                {"label": "com.provcheck.test", "data": {"flavour": "vanilla", "k": 42}}
            ]
        })
        .to_string();

        sign_asset(&identity, &src, &dst, &manifest).expect("sign");

        let reader = c2pa::Reader::from_file(&dst).expect("reader");
        let active = reader.active_manifest().expect("active manifest");
        let labels: Vec<String> = active
            .assertions()
            .iter()
            .map(|a| a.label().to_string())
            .collect();
        assert!(
            labels.iter().any(|l| l.contains("com.provcheck.test")),
            "extra assertion landed in the manifest: {labels:?}"
        );
    }
}
