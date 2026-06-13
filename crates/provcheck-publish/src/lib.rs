//! # provcheck-publish
//!
//! atproto record CRUD for `provcheck-kit`. The crate publishes,
//! lists, updates, and (logically) revokes the
//! `app.provcheck.signingKey` records that the verifier
//! (`provcheck-platform`) reads.
//!
//! ## Status
//!
//! **Phase 3 sub-pass 1: scaffold only.** This commit lands the
//! crate skeleton, the dependency wiring (atrium-rs + tokio), and
//! the public-API surface stubs. The actual session management
//! and record CRUD implementations land in subsequent sub-passes:
//!
//! - **sub-pass 2 (task #49 cont):** `session::login` /
//!   `session::load_session` / `session::save_session` —
//!   App-password authentication and on-disk session persistence
//!   with auto-refresh.
//! - **sub-pass 3 (task #50):** `records::publish_signing_key`,
//!   `list_signing_keys`, `update_signing_key`,
//!   `delete_signing_key`, `revoke_signing_key`. Mock-PDS
//!   integration tests using the same pattern
//!   `provcheck-platform/tests/common/mod.rs` ships.
//!
//! See the plan file (Phase 3) for the full design.
//!
//! ## Architectural notes
//!
//! - **Async surface is confined here.** Per architectural
//!   decision #2 in the plan, this is the one crate that uses
//!   tokio. The verifier (`provcheck-platform`) stays sync; the
//!   CLI binary (`provcheck-kit`) takes a `#[tokio::main]` and
//!   composes this crate's async API with the sync
//!   `provcheck-sign` API.
//! - **atrium-rs is the standard.** Lexicon-typed records,
//!   active maintenance, OAuth + app-password support. Hand-
//!   rolling XRPC against raw reqwest would save a dep but
//!   forfeit the lexicon-roundtrip + session-refresh guarantees.
//! - **Custom record types via JSON.** The
//!   `app.provcheck.signingKey` lexicon isn't part of atrium's
//!   codegen surface (it's our custom type). We hand-marshal it
//!   into `serde_json::Value` at the boundary with atrium and
//!   carry the [`provcheck_attestation_spec::SigningKeyRecord`]
//!   shape internally — the same shape the verifier consumes.

pub mod records;
pub mod session;

pub use records::{AtUri, RecordWriter};
pub use session::{AtprotoClient, SessionFile};

/// Top-level errors from this crate. Each module surfaces its own
/// typed variant aggregated here.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("session: {0}")]
    Session(#[from] session::SessionError),
    #[error("records: {0}")]
    Records(#[from] records::RecordsError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}
