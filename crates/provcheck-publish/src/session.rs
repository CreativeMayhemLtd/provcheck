//! atproto session management — login, load/save, refresh.
//!
//! **Scaffold only in this commit.** The function bodies return
//! `SessionError::NotImplemented` placeholders so the public API
//! compiles. The wire-up to `atrium-api`'s session APIs lands in
//! Phase 3 sub-pass 2.
//!
//! Implementation notes for sub-pass 2:
//!
//! - Use `atrium_xrpc_client::reqwest::ReqwestClient` as the
//!   transport.
//! - `com.atproto.server.create_session` for login (app password
//!   in the password field, handle in the identifier field).
//! - `com.atproto.server.refresh_session` for refresh when the
//!   access JWT expires. Refresh JWTs are single-use per the
//!   atproto spec — serialise refresh writes via a Mutex.
//! - Persist `session.json` with owner-only perms on Unix (0o600)
//!   under `{dir}/session.json`.
//! - If both JWTs are expired, surface `SessionError::SessionExpired`
//!   so the CLI binary can prompt the user for a fresh login.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Errors from the session layer.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// Sub-pass 2 placeholder. Function body isn't implemented yet.
    /// Locks in the compile-time surface without pretending we have
    /// a working session flow.
    #[error("not implemented: {0} — lands in Phase 3 sub-pass 2")]
    NotImplemented(&'static str),

    /// The access JWT was rejected and the refresh JWT was either
    /// missing, expired, or refused. The CLI binary maps this to
    /// exit code 3 (session expired, needs `kit login`).
    #[error("atproto session expired — re-run `kit login`")]
    SessionExpired,

    /// Network or HTTP-level failure from the atproto transport.
    #[error("http: {0}")]
    Http(String),

    /// Filesystem failure reading or writing `session.json`.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// JSON shape failure parsing the persisted session file.
    #[error("session.json shape: {0}")]
    Format(String),
}

/// Wire-format of `session.json` on disk. Public so tests can
/// construct it directly; mutable through the live
/// [`AtprotoClient`] in normal flows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionFile {
    pub did: String,
    pub handle: String,
    /// PDS host the session was created against (`bsky.social` for
    /// the typical user; could be a custom PDS).
    pub pds: String,
    pub access_jwt: String,
    pub refresh_jwt: String,
    /// RFC 3339 timestamp at which the access JWT expires. The
    /// refresh JWT's expiry isn't recorded on the session itself
    /// (the atproto spec is mute on its lifetime; ~2 months is the
    /// observed bsky.social default but isn't guaranteed).
    pub access_expires_at: String,
}

/// Live atproto session. Holds the JWTs + the resolved DID. The
/// concrete type wraps an atrium `AtpAgent`-equivalent in sub-pass
/// 2; for now it's a placeholder.
#[derive(Debug)]
pub struct AtprotoClient {
    pub session: SessionFile,
    _private: (),
}

impl AtprotoClient {
    /// App-password login. Constructs a session against `pds_host`
    /// for `handle` using `app_password`. The atproto spec
    /// requires app passwords (never the account password) for
    /// programmatic access.
    pub async fn login(
        _pds_host: &str,
        _handle: &str,
        _app_password: &str,
    ) -> Result<Self, SessionError> {
        Err(SessionError::NotImplemented("login"))
    }

    /// Load a previously-persisted session. Auto-refreshes the
    /// access JWT if it's past `access_expires_at`.
    pub async fn load_session(_dir: &Path) -> Result<Self, SessionError> {
        Err(SessionError::NotImplemented("load_session"))
    }

    /// Persist this session to `{dir}/session.json`. Owner-only
    /// file perms on Unix.
    pub fn save_session(&self, _dir: &Path) -> Result<(), SessionError> {
        Err(SessionError::NotImplemented("save_session"))
    }

    /// Delete the persisted session file. Idempotent — deleting an
    /// absent file is success.
    pub fn logout(_dir: &Path) -> Result<(), SessionError> {
        Err(SessionError::NotImplemented("logout"))
    }
}

/// Resolve `{dir}/session.json` relative to a data directory.
pub fn session_path(dir: &Path) -> PathBuf {
    dir.join("session.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn session_file_round_trips_through_json() {
        // Wire-format check — locks the camelCase field names in
        // case future implementation work fiddles with serde
        // attributes.
        let f = SessionFile {
            did: "did:plc:abc".into(),
            handle: "creator.bsky.social".into(),
            pds: "https://bsky.social".into(),
            access_jwt: "eyJ...".into(),
            refresh_jwt: "eyJ...".into(),
            access_expires_at: "2026-06-14T12:30:00Z".into(),
        };
        let json = serde_json::to_string(&f).expect("ser");
        let back: SessionFile = serde_json::from_str(&json).expect("de");
        assert_eq!(back.did, f.did);
        assert_eq!(back.handle, f.handle);
        assert_eq!(back.access_jwt, f.access_jwt);
    }

    #[test]
    fn session_path_lands_under_the_data_dir() {
        let dir = TempDir::new().unwrap();
        let p = session_path(dir.path());
        assert_eq!(p.parent(), Some(dir.path()));
        assert_eq!(p.file_name().and_then(|s| s.to_str()), Some("session.json"));
    }

    #[tokio::test]
    async fn login_stub_returns_not_implemented() {
        // Sub-pass 1's contract: the surface compiles, the body
        // returns NotImplemented. Catches any accidental "I forgot
        // to actually wire this up before claiming sub-pass 2 was
        // done" commit.
        let err = AtprotoClient::login("bsky.social", "h", "p")
            .await
            .expect_err("scaffold not implemented");
        assert!(matches!(err, SessionError::NotImplemented(_)));
    }
}
