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
//! - **Pass 1 (this commit):** cert generation lifted from rAIdio.bot,
//!   parameterised through [`SubjectInfo`]. The public type surface
//!   (`SubjectInfo`, `GeneratedKeypair`) is stable; the public
//!   identity surface ([`LockedIdentity`], [`UnlockedIdentity`],
//!   `KeyProvider`) will arrive in subsequent passes alongside the
//!   persistence layer.
//! - **Upcoming passes:** persist layer (`load` / `create` /
//!   `load_or_create` / `unlock`), encrypted-file provider, OS
//!   keychain provider, in-process secret cache with TTL, PKCS#12
//!   backup/restore, C2PA signing orchestration.
//!
//! See `C:\Users\Administrator\.claude\plans\ok-its-been-a-replicated-wadler.md`
//! Phase 2 for the full design.

pub mod cert;

pub use cert::{GeneratedKeypair, SubjectInfo};

/// Top-level errors from the crate. Each module surfaces its own
/// typed variant; this enum aggregates them for callers that want
/// one error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cert generation: {0}")]
    Cert(#[from] cert::CertError),
}
