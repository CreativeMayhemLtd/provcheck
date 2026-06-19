//! Passphrase-encrypted private-key storage via the age format.
//!
//! Writes `keys/signing.key.age` as a standards-conformant age file
//! with a single passphrase (scrypt) recipient. Day-to-day signing
//! prompts for that passphrase (the CLI binary's prompt callback
//! wraps `rpassword`; tests pass a closure returning a fixed
//! passphrase).
//!
//! ## Constraint: at-rest is passphrase-only
//!
//! age 0.11 actively forbids mixing a scrypt (passphrase) recipient
//! with X25519 recipients in the same file
//! (`EncryptError::MixedRecipientAndPassphrase` at the upstream
//! `protocol.rs:95`). The two recipient types produce different
//! label sets at wrap time (scrypt: a random 32-char label; X25519:
//! the empty set) and the format demands consistent labels across
//! all recipients of one file.
//!
//! The implementation therefore restricts at-rest files to
//! passphrase-only and pushes recovery-recipient encryption to
//! backup operations — see architectural decision #5 in the plan
//! and the `backup` module (Phase 2 sub-pass 6) for that flow. The
//! ergonomic tradeoff (no "Yubikey can unlock the at-rest file
//! without typing the passphrase" path) is acceptable because
//! recovery is a backup-time concern, not a daily-use concern.

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use secrecy::{ExposeSecret, SecretString};

use crate::persist::age_key_path;
use crate::types::KeyProviderKind;

use super::{KeyProvider, NewPassphrasePrompt, PassphraseResult, ProviderError, UnlockPrompt};

/// Passphrase-only at-rest key store. The state-free struct has no
/// fields — the path is computed from the per-call `dir` argument,
/// and the recipient set is fixed at "single passphrase recipient,
/// supplied by the caller's prompt closure."
#[derive(Debug, Clone, Default)]
pub struct AgeFileProvider;

impl AgeFileProvider {
    pub fn new() -> Self {
        Self
    }
}

impl KeyProvider for AgeFileProvider {
    fn kind(&self) -> KeyProviderKind {
        KeyProviderKind::EncryptedFile
    }

    fn store(
        &self,
        dir: &Path,
        _fingerprint: &str,
        key_pem: &SecretString,
        new_passphrase: &mut dyn FnMut(NewPassphrasePrompt) -> PassphraseResult,
    ) -> Result<(), ProviderError> {
        let passphrase = new_passphrase(NewPassphrasePrompt { purpose: "at-rest" })?;

        // age 0.11's with_user_passphrase wraps the passphrase as a
        // single scrypt recipient internally. The work factor is
        // age's default (log_n=18 at the time of writing), which
        // matches the format's tunable mechanism: it lives in the
        // stanza itself, so we don't pin it here.
        let encryptor =
            age::Encryptor::with_user_passphrase(passphrase.expose_secret().to_string().into());

        let final_path = age_key_path(dir);
        if let Some(parent) = final_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp_path = final_path.with_extension("age.tmp");

        // Encrypt to the temp file, then rename — same atomic-
        // rename pattern as save_public_artefacts so a crash mid-
        // write leaves the previous (or no) file intact, not a
        // half-written one.
        {
            let mut out = fs::File::create(&tmp_path)?;
            let mut writer = encryptor
                .wrap_output(&mut out)
                .map_err(|e| ProviderError::AgeFormat(e.to_string()))?;
            writer.write_all(key_pem.expose_secret().as_bytes())?;
            writer
                .finish()
                .map_err(|e| ProviderError::AgeFormat(e.to_string()))?;
        }
        fs::rename(&tmp_path, &final_path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&final_path, fs::Permissions::from_mode(0o600));
        }

        Ok(())
    }

    fn fetch(
        &self,
        dir: &Path,
        _fingerprint: &str,
        passphrase: &mut dyn FnMut(UnlockPrompt) -> PassphraseResult,
    ) -> Result<SecretString, ProviderError> {
        let path = age_key_path(dir);
        let ciphertext = fs::read(&path)?;

        let pp = passphrase(UnlockPrompt::passphrase("at-rest", 1))?;

        let identity = age::scrypt::Identity::new(pp.expose_secret().to_string().into());

        let decryptor = age::Decryptor::new(&ciphertext[..])
            .map_err(|e| ProviderError::AgeFormat(e.to_string()))?;

        let identities: [&dyn age::Identity; 1] = [&identity];
        match decryptor.decrypt(identities.into_iter()) {
            Ok(mut reader) => {
                let mut plaintext = String::new();
                reader.read_to_string(&mut plaintext)?;
                Ok(SecretString::from(plaintext))
            }
            // age 0.11 distinguishes DecryptionFailed (payload MAC
            // failed) from KeyDecryptionFailed (no recipient could
            // unwrap the file key). For the at-rest passphrase
            // backend, both map to the same user-facing meaning:
            // the passphrase was wrong.
            Err(age::DecryptError::DecryptionFailed)
            | Err(age::DecryptError::KeyDecryptionFailed) => {
                Err(ProviderError::AuthenticationFailed)
            }
            Err(e) => Err(ProviderError::AgeFormat(e.to_string())),
        }
    }

    fn delete(&self, dir: &Path, _fingerprint: &str) -> Result<(), ProviderError> {
        let path = age_key_path(dir);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            // Idempotent: deleting an absent file is success.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(ProviderError::Io(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Build a `new_passphrase` callback that returns a fixed
    /// passphrase. Useful for tests; the real CLI binary uses
    /// rpassword behind a similar closure.
    fn fixed_new(
        pass: &'static str,
    ) -> impl FnMut(NewPassphrasePrompt) -> PassphraseResult + 'static {
        move |_| Ok(SecretString::from(pass.to_string()))
    }

    fn fixed_unlock(pass: &'static str) -> impl FnMut(UnlockPrompt) -> PassphraseResult + 'static {
        move |_| Ok(SecretString::from(pass.to_string()))
    }

    /// Sample key PEM used as the plaintext. Content doesn't matter
    /// for the round-trip — only that the bytes survive intact.
    const SAMPLE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----\n";

    /// Dummy fingerprint for tests. The AgeFileProvider ignores it
    /// (only the keychain backend cares); pass the same value
    /// through every call.
    const FP: &str = "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    #[test]
    fn kind_reports_encrypted_file() {
        let p = AgeFileProvider::new();
        assert!(matches!(p.kind(), KeyProviderKind::EncryptedFile));
    }

    #[test]
    fn store_then_fetch_round_trips() {
        let dir = TempDir::new().expect("tempdir");
        let provider = AgeFileProvider::new();
        let plaintext = SecretString::from(SAMPLE_KEY.to_string());

        provider
            .store(
                dir.path(),
                FP,
                &plaintext,
                &mut fixed_new("correct horse battery staple"),
            )
            .expect("store succeeds");

        // The file exists on disk and is non-trivially-sized.
        let path = age_key_path(dir.path());
        let bytes = fs::read(&path).expect("read back the file");
        assert!(bytes.len() > 32, "encrypted file has real size");
        assert_ne!(bytes, SAMPLE_KEY.as_bytes(), "not stored as plaintext");

        // The fetch path returns exactly the original plaintext.
        let recovered = provider
            .fetch(
                dir.path(),
                FP,
                &mut fixed_unlock("correct horse battery staple"),
            )
            .expect("fetch succeeds");
        assert_eq!(recovered.expose_secret(), SAMPLE_KEY);
    }

    #[test]
    fn wrong_passphrase_returns_authentication_failed() {
        let dir = TempDir::new().expect("tempdir");
        let provider = AgeFileProvider::new();
        let plaintext = SecretString::from(SAMPLE_KEY.to_string());

        provider
            .store(dir.path(), FP, &plaintext, &mut fixed_new("right one"))
            .expect("store succeeds");

        let err = provider
            .fetch(dir.path(), FP, &mut fixed_unlock("wrong one"))
            .expect_err("fetch should fail with wrong passphrase");
        assert!(
            matches!(err, ProviderError::AuthenticationFailed),
            "got: {err:?}"
        );
    }

    #[test]
    fn store_overwrites_previous_file() {
        let dir = TempDir::new().expect("tempdir");
        let provider = AgeFileProvider::new();

        let v1 = SecretString::from("first version".to_string());
        let v2 = SecretString::from("second version".to_string());

        provider
            .store(dir.path(), FP, &v1, &mut fixed_new("pass1"))
            .expect("store v1");
        provider
            .store(dir.path(), FP, &v2, &mut fixed_new("pass2"))
            .expect("store v2 (overwrites)");

        // v1's passphrase should no longer work.
        let err = provider
            .fetch(dir.path(), FP, &mut fixed_unlock("pass1"))
            .expect_err("v1 passphrase rejected after overwrite");
        assert!(matches!(err, ProviderError::AuthenticationFailed));

        // v2's does.
        let recovered = provider
            .fetch(dir.path(), FP, &mut fixed_unlock("pass2"))
            .expect("v2 passphrase unlocks");
        assert_eq!(recovered.expose_secret(), "second version");
    }

    #[test]
    fn fetch_missing_file_surfaces_not_found_io() {
        let dir = TempDir::new().expect("tempdir");
        let provider = AgeFileProvider::new();
        let err = provider
            .fetch(dir.path(), FP, &mut fixed_unlock("anything"))
            .expect_err("no file to fetch");
        match err {
            ProviderError::Io(io) => assert_eq!(io.kind(), std::io::ErrorKind::NotFound),
            other => panic!("expected Io(NotFound), got {other:?}"),
        }
    }

    #[test]
    fn delete_removes_file() {
        let dir = TempDir::new().expect("tempdir");
        let provider = AgeFileProvider::new();
        provider
            .store(
                dir.path(),
                FP,
                &SecretString::from(SAMPLE_KEY.to_string()),
                &mut fixed_new("pass"),
            )
            .expect("store");

        assert!(age_key_path(dir.path()).exists());
        provider.delete(dir.path(), FP).expect("delete");
        assert!(!age_key_path(dir.path()).exists());
    }

    #[test]
    fn delete_is_idempotent_when_file_absent() {
        let dir = TempDir::new().expect("tempdir");
        let provider = AgeFileProvider::new();
        provider
            .delete(dir.path(), FP)
            .expect("delete on missing file is Ok");
    }

    #[test]
    fn store_creates_keys_dir_if_missing() {
        // We hand a fresh empty tempdir directly; the provider must
        // create the `keys/` subdirectory itself, mirroring what
        // persist::save_public_artefacts does.
        let dir = TempDir::new().expect("tempdir");
        let provider = AgeFileProvider::new();
        provider
            .store(
                dir.path(),
                FP,
                &SecretString::from(SAMPLE_KEY.to_string()),
                &mut fixed_new("pass"),
            )
            .expect("store creates keys dir");
        let keys = dir.path().join("keys");
        assert!(keys.is_dir(), "keys/ subdir was created");
    }

    #[test]
    fn file_on_disk_is_a_real_age_file() {
        // age files start with the ASCII header "age-encryption.org/v1".
        // If we ever silently swap formats this catches it.
        let dir = TempDir::new().expect("tempdir");
        let provider = AgeFileProvider::new();
        provider
            .store(
                dir.path(),
                FP,
                &SecretString::from(SAMPLE_KEY.to_string()),
                &mut fixed_new("pass"),
            )
            .expect("store");
        let bytes = fs::read(age_key_path(dir.path())).expect("read");
        let head = std::str::from_utf8(&bytes[..21]).expect("ASCII prefix");
        assert_eq!(head, "age-encryption.org/v1");
    }

    #[test]
    fn user_cancelled_propagates_through_store() {
        // If the prompt callback says UserCancelled, the provider
        // doesn't try to write anything to disk.
        let dir = TempDir::new().expect("tempdir");
        let provider = AgeFileProvider::new();
        let mut canceller = |_: NewPassphrasePrompt| Err(ProviderError::UserCancelled);
        let err = provider
            .store(
                dir.path(),
                FP,
                &SecretString::from(SAMPLE_KEY.to_string()),
                &mut canceller,
            )
            .expect_err("cancellation propagates");
        assert!(matches!(err, ProviderError::UserCancelled));
        assert!(
            !age_key_path(dir.path()).exists(),
            "no file written when prompt cancelled"
        );
    }

    #[test]
    fn user_cancelled_propagates_through_fetch() {
        let dir = TempDir::new().expect("tempdir");
        let provider = AgeFileProvider::new();
        provider
            .store(
                dir.path(),
                FP,
                &SecretString::from(SAMPLE_KEY.to_string()),
                &mut fixed_new("the right one"),
            )
            .expect("store");
        let mut canceller = |_: UnlockPrompt| Err(ProviderError::UserCancelled);
        let err = provider
            .fetch(dir.path(), FP, &mut canceller)
            .expect_err("cancellation propagates");
        assert!(matches!(err, ProviderError::UserCancelled));
    }
}
