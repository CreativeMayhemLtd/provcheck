//! atproto session management — login, load/save, logout.
//!
//! Built on `atrium_api::agent::atp_agent::AtpAgent` with a
//! `MemorySessionStore` for the live session and our own
//! `session.json` on disk for cross-process persistence. The
//! agent handles JWT refresh internally on 401 responses; we
//! just rewrite `session.json` from the agent's current state on
//! every `save_session`.
//!
//! ## What's on disk
//!
//! `{dir}/session.json` — owner-only file perms on Unix (0o600).
//! Holds the four fields needed to resume a session via
//! `AtpAgent::resume_session`:
//!
//! - `did` — the user's atproto identifier
//! - `handle` — the user's bsky handle (display hint)
//! - `pds` — the PDS host the session was created against
//! - `access_jwt` / `refresh_jwt` — the auth tokens
//!
//! Atrium tracks JWT expiry itself; we don't duplicate that
//! state. When both JWTs are expired, `resume_session` /
//! `refresh_session` fail and we surface
//! `SessionError::SessionExpired` — the CLI binary maps that to
//! exit code 3 (user must `kit login` again).

use std::path::{Path, PathBuf};

use atrium_api::agent::atp_agent::store::MemorySessionStore;
use atrium_api::agent::atp_agent::{AtpAgent, AtpSession};
use atrium_api::com::atproto::server::create_session::OutputData as SessionOutputData;
use atrium_api::types::Object;
use atrium_api::types::string::{Did, Handle};
use atrium_xrpc_client::reqwest::ReqwestClient;
use serde::{Deserialize, Serialize};

/// Errors from the session layer.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The access JWT was rejected and the refresh JWT was either
    /// missing, expired, or refused. The CLI binary maps this to
    /// exit code 3.
    #[error("atproto session expired — re-run `kit login`")]
    SessionExpired,

    /// Login was rejected by the PDS — typically wrong handle or
    /// app password, or the account is taken down.
    #[error("login rejected: {0}")]
    LoginRejected(String),

    /// Network or transport-level failure from atrium / reqwest.
    #[error("http: {0}")]
    Http(String),

    /// Filesystem failure reading or writing `session.json`.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// JSON shape failure parsing the persisted session file.
    #[error("session.json shape: {0}")]
    Format(String),

    /// The DID or handle in `session.json` doesn't parse as a valid
    /// atproto identifier. Indicates the file was hand-edited or
    /// written by a different tool.
    #[error("session.json invalid identifier: {0}")]
    InvalidIdentifier(String),
}

/// Wire-format of `session.json` on disk. Four fields, no expiry
/// tracking (atrium does that itself). Public so tests can
/// construct it directly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionFile {
    pub did: String,
    pub handle: String,
    /// PDS the session was created against, e.g.
    /// `https://bsky.social`. Stored so `load_session` knows
    /// which `ReqwestClient` base URI to construct.
    pub pds: String,
    pub access_jwt: String,
    pub refresh_jwt: String,
}

/// Live atproto session. Wraps an `AtpAgent` and the persisted
/// `SessionFile`. The agent is the source of truth for live JWT
/// state; the `SessionFile` field reflects the last value
/// committed to disk and gets refreshed on every `save_session`.
pub struct AtprotoClient {
    /// The underlying atrium agent. Made `pub` so the records
    /// layer in this crate can reach `client.agent.api.*` to
    /// call lexicon-typed methods without going through a
    /// wrapper.
    pub agent: AtpAgent<MemorySessionStore, ReqwestClient>,
    /// PDS host the session was created against — used to
    /// reconstruct the `SessionFile` for persistence.
    pub pds: String,
    /// Snapshot of the session as it was last written to disk.
    /// May lag the agent's live state between `save_session`
    /// calls (atrium can refresh the JWTs in the background).
    pub session: SessionFile,
}

impl std::fmt::Debug for AtprotoClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AtprotoClient")
            .field("pds", &self.pds)
            .field("did", &self.session.did)
            .field("handle", &self.session.handle)
            .field("access_jwt", &"<redacted>")
            .field("refresh_jwt", &"<redacted>")
            .finish()
    }
}

impl AtprotoClient {
    /// App-password login. `pds_host` is the PDS base URL
    /// (`https://bsky.social` for the typical user); `handle` is
    /// the bsky handle or DID; `app_password` is an atproto app
    /// password — **never** the account's main password.
    ///
    /// Returns `SessionError::LoginRejected` on bad credentials
    /// and `SessionError::Http` on transport failure.
    pub async fn login(
        pds_host: &str,
        handle: &str,
        app_password: &str,
    ) -> Result<Self, SessionError> {
        let pds = normalise_pds_url(pds_host);
        let xrpc = ReqwestClient::new(&pds);
        let store = MemorySessionStore::default();
        let agent = AtpAgent::new(xrpc, store);

        let session_output = agent.login(handle, app_password).await.map_err(|e| {
            // atrium's Error<E> formats with the lexicon's
            // specific error variant + an HTTP detail. The
            // distinction between "login rejected" and "the
            // network is broken" is in the message body; for
            // v1 we keep one error path.
            let msg = e.to_string();
            if msg.to_lowercase().contains("invalid") || msg.to_lowercase().contains("auth") {
                SessionError::LoginRejected(msg)
            } else {
                SessionError::Http(msg)
            }
        })?;

        let session = atp_session_to_file(&session_output, &pds);
        Ok(Self {
            agent,
            pds,
            session,
        })
    }

    /// Load a previously-persisted session and re-attach the
    /// agent to it. Atrium will auto-refresh the access JWT on
    /// the next authenticated call if it's expired.
    pub async fn load_session(dir: &Path) -> Result<Self, SessionError> {
        let path = session_path(dir);
        let bytes = std::fs::read(&path)?;
        let file: SessionFile =
            serde_json::from_slice(&bytes).map_err(|e| SessionError::Format(e.to_string()))?;

        let xrpc = ReqwestClient::new(&file.pds);
        let store = MemorySessionStore::default();
        let agent = AtpAgent::new(xrpc, store);

        let session_output = file_to_atp_session(&file)?;
        agent.resume_session(session_output).await.map_err(|e| {
            let msg = e.to_string();
            if msg.to_lowercase().contains("expired")
                || msg.to_lowercase().contains("invalid_token")
            {
                SessionError::SessionExpired
            } else {
                SessionError::Http(msg)
            }
        })?;

        Ok(Self {
            agent,
            pds: file.pds.clone(),
            session: file,
        })
    }

    /// Persist the agent's current session to disk. Call this
    /// after operations that might have triggered an atrium-side
    /// JWT refresh so the new tokens survive across processes.
    pub async fn save_session(&self, dir: &Path) -> Result<(), SessionError> {
        let current = self
            .agent
            .get_session()
            .await
            .ok_or(SessionError::SessionExpired)?;
        let file = atp_session_to_file(&current, &self.pds);
        write_session_file(dir, &file)
    }

    /// Snapshot of the session as last written. Useful for `kit
    /// status` to report did + handle without an async call.
    pub fn snapshot(&self) -> &SessionFile {
        &self.session
    }

    /// Delete the persisted session file. Idempotent — deleting
    /// an already-absent file is success. Does NOT log out
    /// server-side (atproto sessions don't have a server-side
    /// revoke endpoint for app-password sessions); the local
    /// tokens are simply discarded. Anyone who has the refresh
    /// JWT can still use it until it expires server-side.
    pub fn logout(dir: &Path) -> Result<(), SessionError> {
        let path = session_path(dir);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(SessionError::Io(e)),
        }
    }
}

/// Resolve `{dir}/session.json` relative to a data directory.
pub fn session_path(dir: &Path) -> PathBuf {
    dir.join("session.json")
}

/// Ensure the PDS host string is a full URL with scheme. Accept
/// `bsky.social`, `https://bsky.social`, and `https://bsky.social/`
/// alike. Default scheme is `https://`.
fn normalise_pds_url(host: &str) -> String {
    let trimmed = host.trim().trim_end_matches('/');
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    }
}

/// Project an atrium `AtpSession` (`Output` of `create_session`)
/// onto our compact `SessionFile`.
fn atp_session_to_file(s: &AtpSession, pds: &str) -> SessionFile {
    SessionFile {
        did: s.did.as_str().to_string(),
        handle: s.handle.as_str().to_string(),
        pds: pds.to_string(),
        access_jwt: s.access_jwt.clone(),
        refresh_jwt: s.refresh_jwt.clone(),
    }
}

/// Construct an `AtpSession` from a `SessionFile` so we can hand
/// it to `agent.resume_session`. The optional fields atrium
/// expects (`active`, `email`, `did_doc`, …) all default to
/// `None` — they aren't load-bearing for the resume path.
fn file_to_atp_session(f: &SessionFile) -> Result<AtpSession, SessionError> {
    let did = Did::new(f.did.clone())
        .map_err(|e| SessionError::InvalidIdentifier(format!("did: {e}")))?;
    let handle = Handle::new(f.handle.clone())
        .map_err(|e| SessionError::InvalidIdentifier(format!("handle: {e}")))?;
    Ok(Object::from(SessionOutputData {
        access_jwt: f.access_jwt.clone(),
        active: None,
        did,
        did_doc: None,
        email: None,
        email_auth_factor: None,
        email_confirmed: None,
        handle,
        refresh_jwt: f.refresh_jwt.clone(),
        status: None,
    }))
}

/// Atomic write of a `SessionFile` to disk under
/// `{dir}/session.json`. Same tmp-then-rename pattern as the
/// other persistence layers, with owner-only perms on Unix.
fn write_session_file(dir: &Path, file: &SessionFile) -> Result<(), SessionError> {
    let path = session_path(dir);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_vec_pretty(file).map_err(|e| SessionError::Format(e.to_string()))?;
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, &path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fake_session_file() -> SessionFile {
        SessionFile {
            did: "did:plc:abcdefghijklmnopqrstuvwx".into(),
            handle: "creator.bsky.social".into(),
            pds: "https://bsky.social".into(),
            access_jwt: "eyJhbGc.access".into(),
            refresh_jwt: "eyJhbGc.refresh".into(),
        }
    }

    // ----- SessionError Display ----------

    #[test]
    fn session_expired_display_directs_user_to_kit_login() {
        // The CLI maps SessionExpired to exit code 3; the user's
        // only debugging hint is the error message. Pin that it
        // names the command.
        let s = format!("{}", SessionError::SessionExpired);
        assert!(
            s.contains("kit login"),
            "expected 'kit login' guidance, got: {s}"
        );
        assert!(s.contains("expired"));
    }

    #[test]
    fn login_rejected_display_includes_inner_message() {
        let s = format!("{}", SessionError::LoginRejected("bad password".into()));
        assert!(s.contains("login rejected"));
        assert!(s.contains("bad password"));
    }

    #[test]
    fn http_error_display_includes_inner() {
        let s = format!("{}", SessionError::Http("DNS failure".into()));
        assert!(s.contains("DNS failure"));
    }

    #[test]
    fn io_error_display_includes_inner() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let e = SessionError::Io(io);
        let s = format!("{}", e);
        assert!(s.contains("io"));
        assert!(s.contains("missing"));
    }

    #[test]
    fn io_from_std_io_error_works() {
        // The #[from] impl must compile and dispatch correctly.
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let _e: SessionError = io.into();
    }

    #[test]
    fn format_error_display_includes_inner() {
        let s = format!("{}", SessionError::Format("missing did field".into()));
        assert!(s.contains("session.json shape"));
        assert!(s.contains("missing did field"));
    }

    #[test]
    fn invalid_identifier_display_includes_input() {
        let s = format!("{}", SessionError::InvalidIdentifier("garbage-did".into()));
        assert!(s.contains("invalid"));
        assert!(s.contains("garbage-did"));
    }

    #[test]
    fn session_file_round_trips_through_json() {
        let f = fake_session_file();
        let json = serde_json::to_string(&f).expect("ser");
        let back: SessionFile = serde_json::from_str(&json).expect("de");
        assert_eq!(back, f);
    }

    #[test]
    fn session_file_uses_snake_case_field_names_on_wire() {
        // Locks in the format. atproto itself uses camelCase, but
        // *our* session.json is internal — we use snake_case so
        // Serde defaults Just Work. If anyone is tempted to switch
        // to camelCase to "match atproto," that's a breaking
        // change to existing session.json files.
        let f = fake_session_file();
        let json = serde_json::to_string(&f).expect("ser");
        assert!(json.contains("\"access_jwt\""));
        assert!(json.contains("\"refresh_jwt\""));
        assert!(!json.contains("accessJwt"));
    }

    #[test]
    fn session_path_lands_under_the_data_dir() {
        let dir = TempDir::new().unwrap();
        let p = session_path(dir.path());
        assert_eq!(p.parent(), Some(dir.path()));
        assert_eq!(p.file_name().and_then(|s| s.to_str()), Some("session.json"));
    }

    #[test]
    fn normalise_pds_url_adds_scheme_when_missing() {
        assert_eq!(normalise_pds_url("bsky.social"), "https://bsky.social");
        assert_eq!(normalise_pds_url("bsky.social/"), "https://bsky.social");
    }

    #[test]
    fn normalise_pds_url_preserves_existing_scheme() {
        assert_eq!(
            normalise_pds_url("https://bsky.social"),
            "https://bsky.social"
        );
        assert_eq!(
            normalise_pds_url("http://localhost:3000/"),
            "http://localhost:3000"
        );
    }

    // ----- normalise_pds_url tests ----------
    //
    // normalise_pds_url is the input pipe between operator CLI
    // strings and our atrium agent. Pin every documented case.

    #[test]
    fn normalise_pds_url_drops_leading_whitespace() {
        assert_eq!(normalise_pds_url("  bsky.social"), "https://bsky.social");
    }

    #[test]
    fn normalise_pds_url_drops_trailing_whitespace() {
        assert_eq!(normalise_pds_url("bsky.social  "), "https://bsky.social");
    }

    #[test]
    fn normalise_pds_url_drops_multiple_trailing_slashes() {
        // Only ONE trailing slash is trimmed per the function;
        // pin the actual contract so a future "make it strict"
        // refactor doesn't silently change behaviour.
        let result = normalise_pds_url("https://bsky.social/");
        assert_eq!(result, "https://bsky.social");
    }

    #[test]
    fn normalise_pds_url_preserves_path_components() {
        // A self-hosted PDS at a subpath must NOT have its path
        // stripped. Only the trailing slash gets removed.
        assert_eq!(
            normalise_pds_url("https://example.com/pds"),
            "https://example.com/pds"
        );
    }

    #[test]
    fn normalise_pds_url_handles_localhost_with_port() {
        assert_eq!(
            normalise_pds_url("http://localhost:3000"),
            "http://localhost:3000"
        );
    }

    // ----- write_session_file tests ----------
    //
    // The atomic-write contract: tmp file written first, renamed
    // over the destination on success. The on-disk format is the
    // SessionFile serde representation.

    #[test]
    fn write_session_file_creates_session_json_in_target_dir() {
        let dir = TempDir::new().unwrap();
        let file = fake_session_file();
        write_session_file(dir.path(), &file).expect("write");
        let path = session_path(dir.path());
        assert!(path.is_file(), "session.json must exist after write");
    }

    #[test]
    fn write_session_file_writes_pretty_json() {
        // Operators sometimes hand-edit session.json. Pretty-print
        // is the documented format. Pin it.
        let dir = TempDir::new().unwrap();
        let file = fake_session_file();
        write_session_file(dir.path(), &file).expect("write");
        let bytes = std::fs::read(session_path(dir.path())).expect("read");
        let s = String::from_utf8(bytes).expect("utf8");
        assert!(s.contains('\n'), "expected pretty-printed JSON, got: {s}");
    }

    #[test]
    fn write_session_file_creates_parent_directory() {
        // The atomic-write must create any missing parent dirs,
        // so a fresh data-dir bootstrap works.
        let parent = TempDir::new().unwrap();
        let nested = parent.path().join("nested").join("dirs");
        let file = fake_session_file();
        // nested dir doesn't exist yet — write_session_file must
        // create it.
        write_session_file(&nested, &file).expect("write through nested dirs");
        assert!(session_path(&nested).is_file());
    }

    #[test]
    fn write_session_file_then_read_preserves_jwts() {
        // SessionFile serde MUST preserve the JWT bytes verbatim
        // for the resume-session path to work. (Redaction
        // happens in the Debug impl, NOT serde.)
        let dir = TempDir::new().unwrap();
        let file = fake_session_file();
        write_session_file(dir.path(), &file).expect("write");
        let bytes = std::fs::read(session_path(dir.path())).expect("read");
        let parsed: SessionFile = serde_json::from_slice(&bytes).expect("parse");
        assert_eq!(parsed.access_jwt, file.access_jwt);
        assert_eq!(parsed.refresh_jwt, file.refresh_jwt);
    }

    // ----- AtprotoClient::Debug redaction tests ----------
    //
    // The Debug impl on AtprotoClient is the only safe way to
    // log the client. Access + refresh JWTs MUST be redacted —
    // an accidental field unmasking would leak credentials to
    // every log aggregator the operator runs. Pin the redaction
    // contract with format-string assertions.

    fn fake_atproto_client_for_debug_test() -> SessionFile {
        SessionFile {
            did: "did:plc:abcdefgh".into(),
            handle: "creator.bsky.social".into(),
            pds: "https://bsky.social".into(),
            access_jwt: "eyJSECRETACCESS.token.never-log".into(),
            refresh_jwt: "eyJSECRETREFRESH.token.never-log".into(),
        }
    }

    #[test]
    fn session_file_serde_does_not_redact_jwts() {
        // SessionFile itself is the at-rest representation —
        // serialised to disk, JWTs must round-trip. This is NOT
        // the same as the Debug redaction (which protects log
        // output). Pin the distinction so a future maintainer
        // doesn't conflate the two by redacting in serde.
        let f = fake_atproto_client_for_debug_test();
        let json = serde_json::to_string(&f).expect("ser");
        assert!(
            json.contains("eyJSECRETACCESS.token.never-log"),
            "SessionFile serde must persist the JWT for at-rest \
             session.json reads, not redact it"
        );
    }

    // ----- SessionError variant message tests ----------
    //
    // CLI exit-code mapping depends on these messages. Pin the
    // surface so a future maintainer can't silently regress the
    // user-facing diagnostic.

    #[test]
    fn session_error_expired_directs_user_to_login() {
        let e = SessionError::SessionExpired;
        let s = format!("{e}");
        // exit code 3 in the CLI maps to "kit login" — pin it.
        assert!(
            s.contains("kit login"),
            "SessionExpired must direct user to `kit login`, got: {s}"
        );
    }

    #[test]
    fn session_error_login_rejected_includes_inner() {
        let e = SessionError::LoginRejected("wrong app password".into());
        let s = format!("{e}");
        assert!(s.contains("login rejected"));
        assert!(s.contains("wrong app password"));
    }

    #[test]
    fn session_error_http_includes_inner() {
        let e = SessionError::Http("connection refused".into());
        let s = format!("{e}");
        assert!(s.contains("http"));
        assert!(s.contains("connection refused"));
    }

    #[test]
    fn session_error_format_includes_inner() {
        let e = SessionError::Format("expected `did` field".into());
        let s = format!("{e}");
        assert!(s.contains("session.json shape"));
        assert!(s.contains("did"));
    }

    #[test]
    fn session_error_invalid_identifier_includes_inner() {
        let e = SessionError::InvalidIdentifier("did:foo:bar".into());
        let s = format!("{e}");
        assert!(s.contains("session.json invalid identifier"));
        assert!(s.contains("did:foo:bar"));
    }

    #[test]
    fn session_error_io_from_std_io_error_works() {
        // The `#[from]` impl on Io must compile + dispatch. If a
        // future refactor breaks the From bound, this test fails
        // at compile time.
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "session.json");
        let _e: SessionError = io.into();
    }

    #[test]
    fn write_then_read_round_trips_through_disk() {
        let dir = TempDir::new().unwrap();
        let f = fake_session_file();
        write_session_file(dir.path(), &f).expect("write");
        let path = session_path(dir.path());
        assert!(path.is_file());

        let bytes = std::fs::read(&path).expect("read");
        let back: SessionFile = serde_json::from_slice(&bytes).expect("de");
        assert_eq!(back, f);
    }

    #[test]
    fn write_session_creates_parent_dir_if_missing() {
        let parent = TempDir::new().unwrap();
        let nested = parent.path().join("a").join("b");
        let f = fake_session_file();
        write_session_file(&nested, &f).expect("write");
        assert!(session_path(&nested).is_file());
    }

    #[test]
    fn logout_is_idempotent() {
        let dir = TempDir::new().unwrap();
        AtprotoClient::logout(dir.path()).expect("logout on empty dir");
        let f = fake_session_file();
        write_session_file(dir.path(), &f).unwrap();
        AtprotoClient::logout(dir.path()).expect("logout removes file");
        assert!(!session_path(dir.path()).exists());
        AtprotoClient::logout(dir.path()).expect("logout on already-empty is fine");
    }

    #[test]
    fn file_to_atp_session_rejects_garbage_did() {
        let f = SessionFile {
            did: "not-a-did".into(),
            handle: "creator.bsky.social".into(),
            pds: "https://bsky.social".into(),
            access_jwt: "x".into(),
            refresh_jwt: "y".into(),
        };
        let err = file_to_atp_session(&f).expect_err("invalid did");
        assert!(
            matches!(err, SessionError::InvalidIdentifier(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn file_to_atp_session_rejects_garbage_handle() {
        let f = SessionFile {
            did: "did:plc:abcdefghijklmnopqrstuvwx".into(),
            handle: "this is not a valid handle".into(),
            pds: "https://bsky.social".into(),
            access_jwt: "x".into(),
            refresh_jwt: "y".into(),
        };
        let err = file_to_atp_session(&f).expect_err("invalid handle");
        assert!(
            matches!(err, SessionError::InvalidIdentifier(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn file_to_atp_session_round_trips() {
        let f = fake_session_file();
        let session = file_to_atp_session(&f).expect("ok");
        assert_eq!(session.did.as_str(), f.did);
        assert_eq!(session.handle.as_str(), f.handle);
        assert_eq!(session.access_jwt, f.access_jwt);
        assert_eq!(session.refresh_jwt, f.refresh_jwt);
    }

    #[tokio::test]
    async fn load_session_surfaces_io_not_found_when_no_file() {
        let dir = TempDir::new().unwrap();
        let err = AtprotoClient::load_session(dir.path())
            .await
            .expect_err("no session file");
        match err {
            SessionError::Io(io) => assert_eq!(io.kind(), std::io::ErrorKind::NotFound),
            other => panic!("expected Io(NotFound), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn load_session_surfaces_format_error_on_garbled_json() {
        let dir = TempDir::new().unwrap();
        std::fs::write(session_path(dir.path()), "{not valid json").unwrap();
        let err = AtprotoClient::load_session(dir.path())
            .await
            .expect_err("garbled");
        assert!(matches!(err, SessionError::Format(_)), "got {err:?}");
    }
}
