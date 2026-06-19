//! Key custody backends.
//!
//! A [`KeyProvider`] is the abstraction over "how does the private
//! key get to and from somewhere durable?" Two concrete
//! implementations land in Phase 2:
//!
//! - [`age_file::AgeFileProvider`] (this sub-pass) — encrypts the
//!   key under the user's passphrase in a standard `age` file at
//!   `keys/signing.key.age`.
//! - `keychain::KeychainProvider` (sub-pass 4) — wraps the OS
//!   keychain (macOS Keychain, Windows Credential Manager, Linux
//!   Secret Service) via the `keyring` crate.
//!
//! The trait stays narrow: store / fetch / delete, with interactive
//! prompts delivered through callbacks the caller passes in. This
//! lets the CLI use `rpassword` for real prompts and lets tests use
//! constant closures for fixtures. No I/O for the prompt mechanism
//! lives inside the trait itself.
//!
//! ## Why prompts are callbacks
//!
//! Different consumers want different prompt UX. The CLI wants to
//! interactively prompt; a future GUI wants to surface a modal
//! dialog; tests want to return a fixed passphrase. The provider
//! shouldn't care which — it only needs *some* way to obtain a
//! passphrase when one is required. Passing prompt closures keeps
//! the trait implementation-agnostic.

pub mod age_file;
pub mod keychain;

pub use age_file::AgeFileProvider;
pub use keychain::KeychainProvider;

use std::path::Path;

use secrecy::SecretString;

use crate::types::KeyProviderKind;

#[cfg(test)]
mod default_signer_tests {
    use super::*;
    use crate::cert::{SubjectInfo, generate};
    use crate::types::LockedIdentity;
    use time::OffsetDateTime;

    /// Stub provider that returns a pre-set PEM from `fetch()`.
    /// Used to verify the default `signer()` trait impl wires
    /// through correctly without depending on a real backend.
    struct TestProvider {
        pem: String,
    }

    impl KeyProvider for TestProvider {
        fn kind(&self) -> KeyProviderKind {
            KeyProviderKind::EncryptedFile
        }

        fn store(
            &self,
            _: &Path,
            _: &str,
            _: &SecretString,
            _: &mut dyn FnMut(NewPassphrasePrompt) -> PassphraseResult,
        ) -> Result<(), ProviderError> {
            unreachable!("store not called in default-signer tests")
        }

        fn fetch(
            &self,
            _: &Path,
            _: &str,
            _: &mut dyn FnMut(UnlockPrompt) -> PassphraseResult,
        ) -> Result<SecretString, ProviderError> {
            Ok(SecretString::from(self.pem.clone()))
        }

        fn delete(&self, _: &Path, _: &str) -> Result<(), ProviderError> {
            unreachable!("delete not called in default-signer tests")
        }
    }

    #[test]
    fn default_signer_wraps_software_pem_into_c2pa_signer() {
        // Generate a real ES256 keypair via the cert module so the
        // chain + key are mutually consistent.
        let kp = generate(&SubjectInfo::default()).expect("generate");
        let locked = LockedIdentity {
            chain_pem: kp.chain_pem,
            fingerprint: kp.fingerprint.clone(),
            algorithm: kp.algorithm.clone(),
            did: None,
            handle: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            key_provider: KeyProviderKind::EncryptedFile,
            recovery_recipients: vec![],
        };
        let provider = TestProvider { pem: kp.key_pem };
        let mut prompt = |_: UnlockPrompt| -> PassphraseResult {
            Ok(SecretString::from(String::new()))
        };
        let tempdir = tempfile::tempdir().expect("tempdir");
        let signer = provider
            .signer(tempdir.path(), &locked, &mut prompt)
            .expect("default signer impl wraps cleanly");
        assert_eq!(signer.alg(), c2pa::SigningAlg::Es256);
        let certs = signer.certs().expect("signer exposes cert chain");
        assert!(!certs.is_empty(), "cert chain has at least the leaf");
    }

    #[test]
    fn default_signer_rejects_unknown_algorithm() {
        let kp = generate(&SubjectInfo::default()).expect("generate");
        let locked = LockedIdentity {
            chain_pem: kp.chain_pem,
            fingerprint: kp.fingerprint,
            algorithm: "RSA-PSS-WHATEVER".to_string(),
            did: None,
            handle: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            key_provider: KeyProviderKind::EncryptedFile,
            recovery_recipients: vec![],
        };
        let provider = TestProvider { pem: kp.key_pem };
        let mut prompt = |_: UnlockPrompt| -> PassphraseResult {
            Ok(SecretString::from(String::new()))
        };
        let tempdir = tempfile::tempdir().expect("tempdir");
        // Box<dyn c2pa::Signer> doesn't impl Debug; can't use
        // .expect_err. Match on the result instead.
        match provider.signer(tempdir.path(), &locked, &mut prompt) {
            Ok(_) => panic!("expected unknown-algorithm error, got success"),
            Err(ProviderError::SignerSetup(msg)) => {
                assert!(
                    msg.contains("RSA-PSS-WHATEVER") || msg.contains("unknown"),
                    "error message names the bad algorithm: {msg}"
                );
            }
            Err(other) => panic!("expected SignerSetup, got {other:?}"),
        }
    }
}

/// Context handed to a new-passphrase prompt callback. The
/// `purpose` string is for the prompt's own labelling — useful when
/// one process prompts multiple times during a session (e.g.
/// `"at-rest"`, `"backup"`, `"rotation"`).
#[derive(Debug, Clone)]
pub struct NewPassphrasePrompt {
    pub purpose: &'static str,
}

/// Context handed to an unlock-passphrase prompt callback. Carries
/// the attempt number so the prompt can render "Try again" hints on
/// retry loops the caller manages.
#[derive(Debug, Clone)]
pub struct UnlockPrompt {
    pub purpose: &'static str,
    pub attempt: u32,
}

/// Either a [`SecretString`] from the user or a [`ProviderError`]
/// the callback couldn't recover from (e.g. user pressed Ctrl-C).
pub type PassphraseResult = Result<SecretString, ProviderError>;

/// Errors a [`KeyProvider`] can return. Surfaced to the crate-level
/// [`crate::Error`] enum.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// The user cancelled the passphrase prompt — typically Ctrl-C
    /// or an empty input the prompt closure treated as cancellation.
    /// Distinct from `AuthenticationFailed` because there's no
    /// wrong-passphrase signal yet, just no input.
    #[error("user cancelled passphrase prompt")]
    UserCancelled,

    /// The passphrase (or other auth material) didn't unwrap the
    /// stored key. For age-file backends this maps from
    /// `age::DecryptError::DecryptionFailed` /
    /// `KeyDecryptionFailed`; the user-facing message is the same
    /// either way ("wrong passphrase").
    #[error("authentication failed: wrong passphrase or unknown identity")]
    AuthenticationFailed,

    /// Something went wrong inside the age format itself — corrupt
    /// header, unknown version, malformed stanza. Distinct from
    /// `AuthenticationFailed` because the file is broken, not the
    /// user input.
    #[error("age format: {0}")]
    AgeFormat(String),

    /// Operational failure inside the OS keychain backend —
    /// keychain unavailable, ambiguous match, encoding issue,
    /// platform-specific error. The inner string carries the
    /// keyring crate's structured detail. `NoEntry` is handled
    /// separately in the keychain provider (it maps to `Io` with
    /// `NotFound` kind to match the file backend's semantics).
    #[error("keychain backend: {0}")]
    Keychain(String),

    /// Hardware-token backend failure — device not present, PIV
    /// applet locked, PIN exhausted, signing operation refused.
    /// The inner string carries the underlying error's detail.
    #[error("hardware token: {0}")]
    HardwareToken(String),

    /// The unlocked key + cert chain could not be wrapped into a
    /// `c2pa::Signer`. Typically an unknown algorithm string or a
    /// malformed cert chain. Distinct from
    /// [`AuthenticationFailed`](Self::AuthenticationFailed)
    /// because the unwrap itself succeeded.
    #[error("signer setup: {0}")]
    SignerSetup(String),

    /// Filesystem error reading or writing the stored material.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Persistence-layer error (path resolution, IO, JSON shape).
    #[error("persistence: {0}")]
    Persist(#[from] crate::persist::PersistError),
}

/// Backend-agnostic interface for storing, retrieving, and deleting
/// the private key material that backs a [`crate::LockedIdentity`].
///
/// Implementations vary in where the material lives (file on disk,
/// OS keychain entry, hardware token, plugin) but share this
/// surface so the unlock / sign / rotate flows can be backend-
/// indifferent.
///
/// Auxiliary inputs (the cert fingerprint as a keychain account
/// name; recovery recipients for backup files) are carried as
/// provider-specific struct fields, not trait parameters, to keep
/// the trait small.
pub trait KeyProvider {
    /// Which [`KeyProviderKind`] this implementation reports for
    /// the `identity.json` `key_provider` field.
    fn kind(&self) -> KeyProviderKind;

    /// Persist `key_pem` somewhere durable. Called once at
    /// identity-creation time.
    ///
    /// `fingerprint` is the canonical `sha256:<hex>` of the leaf
    /// certificate. Backends like [`KeychainProvider`] use it as
    /// the credential's account identifier so a single keychain
    /// can hold multiple provcheck-kit identities side-by-side;
    /// the file backend ignores it (the path under `dir` is
    /// enough). Including it on every call removes a chicken-and-
    /// egg with identity.json — the keychain entry has to be
    /// writeable before the on-disk metadata exists.
    ///
    /// The `new_passphrase` callback is invoked for backends that
    /// need a passphrase to wrap the key (the file backend does;
    /// the keychain backend doesn't — implementations are free to
    /// ignore the closure).
    fn store(
        &self,
        dir: &Path,
        fingerprint: &str,
        key_pem: &SecretString,
        new_passphrase: &mut dyn FnMut(NewPassphrasePrompt) -> PassphraseResult,
    ) -> Result<(), ProviderError>;

    /// Retrieve the previously-stored `key_pem`. Called whenever a
    /// sign / export / rotate operation needs the secret.
    ///
    /// `fingerprint` selects which credential to fetch from
    /// backends that hold multiple. The `passphrase` callback is
    /// invoked for backends that need a passphrase to unwrap;
    /// backends that don't (the keychain) leave the closure
    /// unused.
    ///
    /// Retry policy lives at the *caller* level, not here: this
    /// method prompts once. The CLI wraps it in a small loop that
    /// re-prompts on `AuthenticationFailed` up to N times.
    fn fetch(
        &self,
        dir: &Path,
        fingerprint: &str,
        passphrase: &mut dyn FnMut(UnlockPrompt) -> PassphraseResult,
    ) -> Result<SecretString, ProviderError>;

    /// Remove the stored material. Idempotent — deleting an
    /// already-absent key is `Ok(())`, not an error. Called by
    /// `rotate` (after the new key has been persisted) and by an
    /// explicit `kit wipe` command.
    fn delete(&self, dir: &Path, fingerprint: &str) -> Result<(), ProviderError>;

    /// Construct a [`c2pa::Signer`] backed by the stored credentials.
    ///
    /// This is the integration seam between `provcheck-sign` and the
    /// c2pa crate: every C2PA signing operation (in this workspace
    /// and downstream) goes through this method. Different backends
    /// can satisfy the seam differently:
    ///
    /// - Software backends (keychain, age-file): the default impl
    ///   calls [`Self::fetch`] to recover the private key PEM, then
    ///   wraps it with `c2pa::create_signer::from_keys` — the
    ///   existing v0.4.x signing path, exactly.
    /// - Hardware backends (Yubikey, TPM, Secure Enclave): override
    ///   this method to return a `Box<dyn c2pa::Signer>` whose
    ///   `sign()` delegates to the device's signing API. The
    ///   private key never enters host RAM, so [`Self::fetch`] is
    ///   structurally inappropriate; HSM backends will typically
    ///   `panic!("call .signer() not .fetch() on this backend")`
    ///   in their `fetch` impl (or return a dedicated error).
    ///
    /// `locked` carries the cert chain and algorithm needed to
    /// construct the signer; `passphrase` is invoked by software
    /// backends to unwrap the key, by hardware backends to collect
    /// the device PIN (via the [`UnlockPrompt::Yubikey`]-style
    /// variants that may be added).
    fn signer(
        &self,
        dir: &Path,
        locked: &crate::types::LockedIdentity,
        passphrase: &mut dyn FnMut(UnlockPrompt) -> PassphraseResult,
    ) -> Result<Box<dyn c2pa::Signer>, ProviderError> {
        use secrecy::ExposeSecret;
        let key_pem = self.fetch(dir, &locked.fingerprint, passphrase)?;
        let alg = crate::sign::parse_algorithm(&locked.algorithm).ok_or_else(|| {
            ProviderError::SignerSetup(format!("unknown algorithm: {}", locked.algorithm))
        })?;
        let signer = c2pa::create_signer::from_keys(
            locked.chain_pem.as_bytes(),
            key_pem.expose_secret().as_bytes(),
            alg,
            None,
        )
        .map_err(|e| ProviderError::SignerSetup(format!("c2pa::create_signer: {e}")))?;
        Ok(signer)
    }
}
