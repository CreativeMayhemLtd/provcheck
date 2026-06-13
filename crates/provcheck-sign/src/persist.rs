//! Public-artefact persistence on disk.
//!
//! Two files live under `{data_dir}/keys/` regardless of which
//! backend stores the private key:
//!
//! - `signing.pem` — full cert chain (EE + CA), public material
//! - `identity.json` — metadata (fingerprint, algorithm, did,
//!   handle, created_at, key_provider)
//!
//! The private key lives wherever the [`KeyProviderKind`] in
//! `identity.json` says — for `EncryptedFile` it's the third file
//! `signing.key.enc` next to the others; for `Keychain` it's in the
//! OS keychain entirely.
//!
//! This module owns the path resolution, the IO, the file
//! permissions, and the marshalling between the on-disk JSON shape
//! ([`IdentityFile`]) and the in-memory [`LockedIdentity`].

use std::fs;
use std::path::{Path, PathBuf};

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::types::{IDENTITY_SCHEMA_VERSION, IdentityFile, LockedIdentity};

/// Resolve the default data directory for `provcheck-kit`.
///
/// Returns:
/// - Linux/macOS: `$XDG_DATA_HOME/provcheck-kit/` (default
///   `~/.local/share/provcheck-kit/` per the `dirs` crate's
///   resolution).
/// - Windows: `%APPDATA%\provcheck-kit\`.
///
/// Errors only when the platform doesn't provide a data dir — rare
/// in practice (containers without a HOME envvar, mostly). Callers
/// who want a non-default location pass a `&Path` directly to
/// [`load_locked`] / [`save_public_artefacts`].
pub fn default_dir() -> Result<PathBuf, PersistError> {
    let base = dirs::data_dir().ok_or(PersistError::DataDirUnavailable)?;
    Ok(base.join("provcheck-kit"))
}

/// `{dir}/keys/`
pub fn keys_dir(base: &Path) -> PathBuf {
    base.join("keys")
}

/// `{dir}/keys/signing.pem` — cert chain.
pub fn chain_pem_path(base: &Path) -> PathBuf {
    keys_dir(base).join("signing.pem")
}

/// `{dir}/keys/identity.json` — metadata.
pub fn identity_json_path(base: &Path) -> PathBuf {
    keys_dir(base).join("identity.json")
}

/// `{dir}/keys/signing.key.age` — age-encrypted private key.
///
/// Only present when `identity.json.key_provider == EncryptedFile`.
/// The keychain backend doesn't use this path at all. The file is in
/// standard age format (`age = "0.11"`) so any age-compatible tool
/// (`rage` CLI, the Go `age` binary, etc.) can decrypt it given the
/// passphrase — see architectural decision #5 in the plan for the
/// recipient model and the documented retroactive-revocation
/// limitation.
pub fn age_key_path(base: &Path) -> PathBuf {
    keys_dir(base).join("signing.key.age")
}

/// Errors from the persistence layer. Caller surfaces these via
/// the crate-level [`crate::Error`] enum.
#[derive(Debug, thiserror::Error)]
pub enum PersistError {
    /// The platform's `dirs::data_dir()` returned None. Means the
    /// caller has to specify an explicit directory.
    #[error("could not resolve platform data directory")]
    DataDirUnavailable,

    /// An IO operation failed. The `operation` describes which path
    /// + verb (e.g. `"write keys/signing.pem"`) so the user gets a
    /// useful error message without us having to thread context
    /// through every call site.
    #[error("io {operation}: {source}")]
    Io {
        operation: String,
        source: std::io::Error,
    },

    /// `identity.json` was unreadable or had an unexpected shape.
    #[error("identity.json parse failed: {0}")]
    IdentityJson(String),

    /// The cert chain file exists but is empty / unreadable. Distinct
    /// from a missing file (`io::ErrorKind::NotFound`) — empty
    /// usually means corruption mid-write.
    #[error("cert chain at {} is empty or unreadable", path.display())]
    EmptyChain { path: PathBuf },

    /// `identity.json.schema_version` is from a different (newer)
    /// build than what this version of provcheck-sign understands.
    #[error(
        "identity.json reports schema_version {actual}, this build understands {supported}"
    )]
    UnsupportedSchemaVersion { actual: u8, supported: u8 },
}

/// Persist the public artefacts (cert chain + identity metadata)
/// for an identity to disk. Caller is responsible for the private-
/// key side via a `KeyProvider`.
///
/// Creates the `{dir}/keys/` directory if it doesn't exist. Sets
/// owner-only permissions on the written files where the platform
/// supports it (`0o600` on Unix; Windows inherits ACL from
/// `%APPDATA%` which is owner-only by default).
pub fn save_public_artefacts(dir: &Path, locked: &LockedIdentity) -> Result<(), PersistError> {
    let keys = keys_dir(dir);
    fs::create_dir_all(&keys).map_err(|e| PersistError::Io {
        operation: format!("create_dir_all {}", keys.display()),
        source: e,
    })?;

    // Cert chain: write atomically via a sibling temp file +
    // rename. Avoids a half-written chain.pem on disk if the
    // process is killed mid-write.
    let chain_path = chain_pem_path(dir);
    let tmp = chain_path.with_extension("pem.tmp");
    fs::write(&tmp, &locked.chain_pem).map_err(|e| PersistError::Io {
        operation: format!("write {}", tmp.display()),
        source: e,
    })?;
    fs::rename(&tmp, &chain_path).map_err(|e| PersistError::Io {
        operation: format!("rename {} -> {}", tmp.display(), chain_path.display()),
        source: e,
    })?;

    // identity.json: same atomic-rename pattern.
    let file = IdentityFile {
        schema_version: IDENTITY_SCHEMA_VERSION,
        fingerprint: locked.fingerprint.clone(),
        algorithm: locked.algorithm.clone(),
        created_at: locked
            .created_at
            .format(&Rfc3339)
            .map_err(|e| PersistError::IdentityJson(format!("format created_at: {e}")))?,
        did: locked.did.clone(),
        handle: locked.handle.clone(),
        key_provider: locked.key_provider,
        recovery_recipients: locked.recovery_recipients.clone(),
    };
    let json = serde_json::to_string_pretty(&file)
        .map_err(|e| PersistError::IdentityJson(format!("serialize: {e}")))?;
    let id_path = identity_json_path(dir);
    let id_tmp = id_path.with_extension("json.tmp");
    fs::write(&id_tmp, json).map_err(|e| PersistError::Io {
        operation: format!("write {}", id_tmp.display()),
        source: e,
    })?;
    fs::rename(&id_tmp, &id_path).map_err(|e| PersistError::Io {
        operation: format!("rename {} -> {}", id_tmp.display(), id_path.display()),
        source: e,
    })?;

    // Owner-only file perms on Unix. Windows inherits ACL from
    // %APPDATA%; no per-file perm bits to set.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&chain_path, fs::Permissions::from_mode(0o600));
        let _ = fs::set_permissions(&id_path, fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

/// Load the public artefacts from disk and return a
/// [`LockedIdentity`].
///
/// Does not touch the private key — that's the `KeyProvider`'s job
/// in the unlock flow.
///
/// Surface error semantics:
/// - Missing files → `PersistError::Io { source: NotFound, .. }`
///   (caller can map to "no identity yet, run `kit init`")
/// - Corrupt cert chain → `PersistError::EmptyChain`
/// - Garbled / wrong-version `identity.json` →
///   `PersistError::IdentityJson` or `UnsupportedSchemaVersion`
///
/// Never silently regenerates — that's what rAIdio.bot does for its
/// single-user-laptop model, but identity tools where regeneration
/// breaks every previously-published atproto record need explicit
/// user opt-in (`kit init --force`).
pub fn load_locked(dir: &Path) -> Result<LockedIdentity, PersistError> {
    let chain_path = chain_pem_path(dir);
    let chain_pem = fs::read_to_string(&chain_path).map_err(|e| PersistError::Io {
        operation: format!("read {}", chain_path.display()),
        source: e,
    })?;
    if chain_pem.trim().is_empty() {
        return Err(PersistError::EmptyChain {
            path: chain_path,
        });
    }

    let id_path = identity_json_path(dir);
    let json = fs::read_to_string(&id_path).map_err(|e| PersistError::Io {
        operation: format!("read {}", id_path.display()),
        source: e,
    })?;
    let file: IdentityFile = serde_json::from_str(&json)
        .map_err(|e| PersistError::IdentityJson(format!("parse: {e}")))?;

    if file.schema_version != IDENTITY_SCHEMA_VERSION {
        return Err(PersistError::UnsupportedSchemaVersion {
            actual: file.schema_version,
            supported: IDENTITY_SCHEMA_VERSION,
        });
    }

    let created_at = OffsetDateTime::parse(&file.created_at, &Rfc3339)
        .map_err(|e| PersistError::IdentityJson(format!("parse created_at: {e}")))?;

    Ok(LockedIdentity {
        chain_pem,
        fingerprint: file.fingerprint,
        algorithm: file.algorithm,
        did: file.did,
        handle: file.handle,
        created_at,
        key_provider: file.key_provider,
        recovery_recipients: file.recovery_recipients,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::KeyProviderKind;
    use tempfile::TempDir;

    fn sample_locked(kind: KeyProviderKind) -> LockedIdentity {
        LockedIdentity {
            chain_pem: "-----BEGIN CERTIFICATE-----\nfakefake\n-----END CERTIFICATE-----\n"
                .to_string(),
            fingerprint: "sha256:deadbeef".repeat(8)[.."sha256:".len() + 64].to_string(),
            algorithm: "ES256".to_string(),
            did: Some("did:plc:test".to_string()),
            handle: Some("test.bsky.social".to_string()),
            created_at: OffsetDateTime::UNIX_EPOCH,
            key_provider: kind,
            recovery_recipients: vec![],
        }
    }

    #[test]
    fn save_creates_keys_dir_and_files() {
        let dir = TempDir::new().expect("tempdir");
        let locked = sample_locked(KeyProviderKind::EncryptedFile);
        save_public_artefacts(dir.path(), &locked).expect("save");

        assert!(keys_dir(dir.path()).is_dir());
        assert!(chain_pem_path(dir.path()).is_file());
        assert!(identity_json_path(dir.path()).is_file());
        // We don't write the encrypted key file in this layer —
        // that's the EncryptedFileProvider's job (sub-pass 3).
        assert!(!age_key_path(dir.path()).exists());
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = TempDir::new().expect("tempdir");
        let locked = sample_locked(KeyProviderKind::EncryptedFile);
        save_public_artefacts(dir.path(), &locked).expect("save");
        let loaded = load_locked(dir.path()).expect("load");
        assert_eq!(loaded, locked);
    }

    #[test]
    fn save_then_load_round_trips_keychain_kind() {
        let dir = TempDir::new().expect("tempdir");
        let locked = sample_locked(KeyProviderKind::Keychain);
        save_public_artefacts(dir.path(), &locked).expect("save");
        let loaded = load_locked(dir.path()).expect("load");
        assert_eq!(loaded.key_provider, KeyProviderKind::Keychain);
    }

    #[test]
    fn load_missing_files_returns_io_not_found() {
        let dir = TempDir::new().expect("tempdir");
        let err = load_locked(dir.path()).expect_err("nothing to load");
        match err {
            PersistError::Io { source, .. } => {
                assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected Io(NotFound), got {other:?}"),
        }
    }

    #[test]
    fn load_empty_chain_pem_surfaces_typed_error() {
        let dir = TempDir::new().expect("tempdir");
        let locked = sample_locked(KeyProviderKind::EncryptedFile);
        save_public_artefacts(dir.path(), &locked).expect("save");
        // Truncate the chain file to simulate corruption.
        fs::write(chain_pem_path(dir.path()), "   \n").expect("truncate");
        let err = load_locked(dir.path()).expect_err("should fail");
        assert!(matches!(err, PersistError::EmptyChain { .. }));
    }

    #[test]
    fn load_garbled_identity_json_surfaces_typed_error() {
        let dir = TempDir::new().expect("tempdir");
        let locked = sample_locked(KeyProviderKind::EncryptedFile);
        save_public_artefacts(dir.path(), &locked).expect("save");
        fs::write(identity_json_path(dir.path()), "{not valid json").expect("garble");
        let err = load_locked(dir.path()).expect_err("should fail");
        assert!(matches!(err, PersistError::IdentityJson(_)));
    }

    #[test]
    fn load_unsupported_schema_version_surfaces_typed_error() {
        let dir = TempDir::new().expect("tempdir");
        let locked = sample_locked(KeyProviderKind::EncryptedFile);
        save_public_artefacts(dir.path(), &locked).expect("save");
        // Rewrite identity.json with a different schema version.
        let json = format!(
            r#"{{"schema_version":99,"fingerprint":"sha256:abc","algorithm":"ES256","created_at":"2026-06-13T12:00:00Z","key_provider":"encrypted_file"}}"#
        );
        fs::write(identity_json_path(dir.path()), json).expect("write");
        let err = load_locked(dir.path()).expect_err("should fail");
        match err {
            PersistError::UnsupportedSchemaVersion { actual, supported } => {
                assert_eq!(actual, 99);
                assert_eq!(supported, IDENTITY_SCHEMA_VERSION);
            }
            other => panic!("expected UnsupportedSchemaVersion, got {other:?}"),
        }
    }

    #[test]
    fn save_is_atomic_no_stale_tmp_files() {
        let dir = TempDir::new().expect("tempdir");
        let locked = sample_locked(KeyProviderKind::EncryptedFile);
        save_public_artefacts(dir.path(), &locked).expect("save");

        // The .tmp sidecar files used during the atomic-rename
        // pattern should not be left behind on success.
        let chain_tmp = keys_dir(dir.path()).join("signing.pem.tmp");
        let id_tmp = keys_dir(dir.path()).join("identity.json.tmp");
        assert!(!chain_tmp.exists(), "stale chain tmp file: {}", chain_tmp.display());
        assert!(!id_tmp.exists(), "stale identity tmp file: {}", id_tmp.display());
    }

    #[test]
    fn default_dir_returns_provcheck_kit_subdir_on_supported_platforms() {
        // On any reasonable platform with a HOME envvar (which
        // includes the test runner), default_dir succeeds and
        // names "provcheck-kit" as the leaf.
        let d = default_dir().expect("data dir resolves");
        assert_eq!(d.file_name().and_then(|s| s.to_str()), Some("provcheck-kit"));
    }
}
