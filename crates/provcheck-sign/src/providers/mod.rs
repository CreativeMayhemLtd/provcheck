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
}
