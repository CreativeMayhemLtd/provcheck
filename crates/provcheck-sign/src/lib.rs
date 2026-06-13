//! # provcheck-sign
//!
//! Cert generation, key custody, C2PA signing orchestration, and
//! PKCS#12 backup/restore for [`provcheck-kit`]. The crate that owns
//! every secret a creator has on disk.
//!
//! Pure-Rust, sync, no tokio. The async surface lives in
//! `provcheck-publish` and the CLI binary that composes both.
//!
//! ## Status
//!
//! Phase 2 of the v0.3.0 plan, landing in passes:
//!
//! - **Pass 1:** cert generation lifted from rAIdio.bot, parameterised
//!   through [`SubjectInfo`].
//! - **Pass 2:** [`LockedIdentity`] / [`UnlockedIdentity`] types +
//!   public-artefact persistence ([`persist::save_public_artefacts`] /
//!   [`persist::load_locked`]).
//! - **Pass 3 (this commit):** [`providers::KeyProvider`] trait +
//!   [`providers::AgeFileProvider`] — passphrase-encrypted at-rest
//!   storage via the standardised age file format.
//! - **Upcoming passes:** OS keychain `KeyProvider`, in-process
//!   secret cache with TTL, age backup (with optional recovery
//!   recipients), PKCS#12 interop backup, C2PA signing
//!   orchestration.
//!
//! See `C:\Users\Administrator\.claude\plans\ok-its-been-a-replicated-wadler.md`
//! Phase 2 for the full design.

pub mod backup;
pub mod cache;
pub mod cert;
pub mod persist;
pub mod providers;
pub mod sign;
pub mod types;

pub use backup::{BackupBundle, BackupSummary};
pub use cache::{Clock, DEFAULT_TTL, SecretCache, SystemClock};
pub use cert::{GeneratedKeypair, SubjectInfo};
pub use providers::{AgeFileProvider, KeyProvider, KeychainProvider};
pub use sign::{SignResult, sign_asset};
pub use types::{KeyProviderKind, LockedIdentity, RecoveryRecipient, UnlockedIdentity};

/// Top-level errors from the crate. Each module surfaces its own
/// typed variant; this enum aggregates them for callers that want
/// one error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cert generation: {0}")]
    Cert(#[from] cert::CertError),
    #[error("persistence: {0}")]
    Persist(#[from] persist::PersistError),
    #[error("key provider: {0}")]
    Provider(#[from] providers::ProviderError),
    #[error("backup: {0}")]
    Backup(#[from] backup::BackupError),
    #[error("c2pa signing: {0}")]
    Sign(#[from] sign::SignError),
}
