//! # provcheck-publish
//!
//! atproto record CRUD for `provcheck-kit`. The crate publishes,
//! lists, updates, and (logically) revokes the
//! `app.provcheck.signingKey` records that the verifier
//! (`provcheck-platform`) reads.
//!
//! ## Status
//!
//! Session management (`AtprotoClient::{login, load_session,
//! save_session, logout}`) and record CRUD
//! (`RecordWriter::{publish_signing_key, list_signing_keys,
//! update_signing_key, delete_signing_key}`) are fully implemented
//! and have unit + integration test coverage. Mock-PDS round-trips
//! cover the happy paths; the live end-to-end run against bsky.app
//! is part of the v0.3.0 release acceptance plan rather than the
//! automated suite (it would need a test account + network).
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
