//! Identity backup and restore via the age file format.
//!
//! The primary backup path. PKCS#12 is a secondary interop-only
//! path covered separately (and currently deferred to a follow-
//! up — see architectural decision #5 in the plan and the
//! `pkcs12_export_deferred` placeholder in this module).
//!
//! ## What's in a backup
//!
//! Everything an identity needs to be restored on a fresh
//! machine:
//!
//! - the cert chain PEM
//! - the private key PEM
//! - the identity metadata (fingerprint, algorithm, created_at,
//!   did, handle, key_provider, recovery_recipients)
//! - bundle metadata (format version, when the bundle was made)
//!
//! What's **not** in a backup:
//!
//! - atproto session tokens (short-lived; re-login on restore)
//! - the published-records mirror (sourced from atproto)
//! - the in-process secret cache (process-scoped)
//!
//! ## Two encryption paths
//!
//! `export_with_passphrase` writes an age file with a single
//! scrypt (passphrase) recipient. `export_with_recipients` writes
//! an age file with one or more X25519 recipients. The two
//! flavours cannot be mixed in a single age file (`age 0.11`
//! actively forbids it — see architectural decision #5).
//!
//! ## Retroactive-revocation footgun
//!
//! Once an age file has been written with recipient R, R can
//! decrypt that file forever. There is no on-format primitive
//! that retroactively revokes a recipient's access. The CLI
//! command that de-registers a recipient
//! (`kit remove-recovery-recipient`) requires an explicit
//! `--i-understand-existing-backups-stay-decryptable` flag for
//! exactly this reason. The only mechanism that actually cuts a
//! removed recipient's signing power is identity rotation, which
//! invalidates the published fingerprint via atproto and renders
//! their ability to decrypt the old backup operationally moot.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::types::{
    IDENTITY_SCHEMA_VERSION, KeyProviderKind, LockedIdentity, RecoveryRecipient, UnlockedIdentity,
};

/// Bundle format version. Bumping is wire-breaking — old kit
/// builds won't read newer bundles. Add migration logic when this
/// increments.
pub const BACKUP_BUNDLE_VERSION: u8 = 1;

/// The decrypted contents of a backup file. Holds the private key
/// material in a [`SecretString`] so it zeroises on drop. Callers
/// convert it into an [`UnlockedIdentity`] via [`Self::into_unlocked`]
/// after deciding what to do with the `key_provider` advisory.
pub struct BackupBundle {
    pub bundle_version: u8,
    /// When the backup was created (NOT when the identity was).
    pub bundle_created_at: OffsetDateTime,
    pub chain_pem: String,
    pub fingerprint: String,
    pub algorithm: String,
    pub identity_created_at: OffsetDateTime,
    pub did: Option<String>,
    pub handle: Option<String>,
    /// Advisory: which backend the original install used. The
    /// caller can honor or override.
    pub key_provider: KeyProviderKind,
    pub recovery_recipients: Vec<RecoveryRecipient>,
    key_pem: SecretString,
}

impl std::fmt::Debug for BackupBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupBundle")
            .field("bundle_version", &self.bundle_version)
            .field("bundle_created_at", &self.bundle_created_at)
            .field("fingerprint", &self.fingerprint)
            .field("algorithm", &self.algorithm)
            .field("identity_created_at", &self.identity_created_at)
            .field("did", &self.did)
            .field("handle", &self.handle)
            .field("key_provider", &self.key_provider)
            .field("recovery_recipients", &self.recovery_recipients)
            .field("chain_pem", &"<elided>")
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

impl BackupBundle {
    /// Convert the bundle into an [`UnlockedIdentity`]. Optionally
    /// override the backend recorded in the bundle (e.g. on
    /// restore the user might want to switch from `EncryptedFile`
    /// to `Keychain` regardless of how the original install was
    /// set up).
    pub fn into_unlocked(
        self,
        override_provider: Option<KeyProviderKind>,
    ) -> UnlockedIdentity {
        let key_provider = override_provider.unwrap_or(self.key_provider);
        let locked = LockedIdentity {
            chain_pem: self.chain_pem,
            fingerprint: self.fingerprint,
            algorithm: self.algorithm,
            did: self.did,
            handle: self.handle,
            created_at: self.identity_created_at,
            key_provider,
            recovery_recipients: self.recovery_recipients,
        };
        UnlockedIdentity::new(locked, self.key_pem)
    }
}

/// Wire-format envelope encrypted inside the age payload. The
/// fields mirror the bundle's identity metadata; key_pem is held
/// in plain `String` here because it's about to be encrypted (the
/// envelope is serialised, then handed to age::Encryptor). Marked
/// `pub(crate)` so the test module can construct it directly.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct EncryptedEnvelope {
    pub bundle_version: u8,
    pub bundle_created_at: String,
    pub identity_schema_version: u8,
    pub fingerprint: String,
    pub algorithm: String,
    pub identity_created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    pub key_provider: KeyProviderKind,
    #[serde(default)]
    pub recovery_recipients: Vec<RecoveryRecipient>,
    pub chain_pem: String,
    pub key_pem: String,
}

/// Summary of what a successful export wrote. Surfaced to the
/// CLI so it can print "wrote 2.4 KiB age file to /tmp/backup.age
/// at fingerprint sha256:abc..." style output.
#[derive(Debug, Clone)]
pub struct BackupSummary {
    pub out_path: PathBuf,
    pub fingerprint: String,
    pub written_bytes: u64,
    /// How many age recipients the file was sealed to. Useful for
    /// the CLI's "this backup is decryptable by N recipients" hint.
    pub recipient_count: usize,
}

/// Errors from the backup / restore code paths. Aggregated into
/// the crate-level [`crate::Error`] enum.
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("time: {0}")]
    Time(String),

    #[error("age format: {0}")]
    AgeFormat(String),

    /// The passphrase or X25519 identity could not unwrap the
    /// file's payload key. Maps from `age::DecryptError::{DecryptionFailed,
    /// KeyDecryptionFailed}`.
    #[error("authentication failed: wrong passphrase or unknown identity")]
    AuthenticationFailed,

    /// The bundle's `bundle_version` is from a newer build than
    /// this one understands. Distinct from "garbled JSON" — the
    /// envelope decoded fine but its version is out of range.
    #[error("unsupported bundle version: file is v{file}, this build understands v{ours}")]
    UnsupportedVersion { file: u8, ours: u8 },

    /// Could not parse an age public key from its `age1...` text
    /// form (e.g. `RecoveryRecipient::pubkey` is malformed).
    #[error("invalid age pubkey: {0}")]
    InvalidPubkey(String),

    /// `recipients` list is empty for `export_with_recipients`.
    #[error("at least one recipient is required for X25519 export")]
    NoRecipients,
}

/// Encrypt the identity to a passphrase-protected age file.
///
/// `out_path` is written atomically (tmp + rename). The passphrase
/// is the user's freshly-chosen backup passphrase — distinct from
/// the at-rest passphrase. Returns a summary on success.
pub fn export_with_passphrase(
    unlocked: &UnlockedIdentity,
    out_path: &Path,
    passphrase: SecretString,
) -> Result<BackupSummary, BackupError> {
    let envelope = envelope_from_unlocked(unlocked)?;
    let json = serde_json::to_vec(&envelope)?;
    let encryptor = age::Encryptor::with_user_passphrase(
        passphrase.expose_secret().to_string().into(),
    );
    let written = write_age(out_path, encryptor, &json)?;
    Ok(BackupSummary {
        out_path: out_path.to_path_buf(),
        fingerprint: unlocked.locked.fingerprint.clone(),
        written_bytes: written,
        recipient_count: 1,
    })
}

/// Encrypt the identity to one or more X25519 recipients. Anyone
/// holding any of the listed recipients' private keys can decrypt
/// the file. The passphrase prompt is not invoked on this path.
///
/// Returns `BackupError::NoRecipients` if `recipients` is empty —
/// an age file with no recipients is unrecoverable.
pub fn export_with_recipients(
    unlocked: &UnlockedIdentity,
    out_path: &Path,
    recipients: &[age::x25519::Recipient],
) -> Result<BackupSummary, BackupError> {
    if recipients.is_empty() {
        return Err(BackupError::NoRecipients);
    }
    let envelope = envelope_from_unlocked(unlocked)?;
    let json = serde_json::to_vec(&envelope)?;
    let recip_dyn: Vec<&dyn age::Recipient> = recipients
        .iter()
        .map(|r| r as &dyn age::Recipient)
        .collect();
    let encryptor = age::Encryptor::with_recipients(recip_dyn.into_iter())
        .map_err(|e| BackupError::AgeFormat(e.to_string()))?;
    let written = write_age(out_path, encryptor, &json)?;
    Ok(BackupSummary {
        out_path: out_path.to_path_buf(),
        fingerprint: unlocked.locked.fingerprint.clone(),
        written_bytes: written,
        recipient_count: recipients.len(),
    })
}

/// Read and decrypt a passphrase-encrypted backup file.
pub fn import_with_passphrase(
    path: &Path,
    passphrase: SecretString,
) -> Result<BackupBundle, BackupError> {
    let ciphertext = fs::read(path)?;
    let identity = age::scrypt::Identity::new(passphrase.expose_secret().to_string().into());
    let plaintext = decrypt_age(&ciphertext, &[&identity])?;
    envelope_to_bundle(serde_json::from_slice(&plaintext)?)
}

/// Read and decrypt an X25519-encrypted backup file using the
/// caller-supplied identity.
pub fn import_with_x25519_identity(
    path: &Path,
    identity: &age::x25519::Identity,
) -> Result<BackupBundle, BackupError> {
    let ciphertext = fs::read(path)?;
    let plaintext = decrypt_age(&ciphertext, &[identity])?;
    envelope_to_bundle(serde_json::from_slice(&plaintext)?)
}

/// Parse a `RecoveryRecipient`'s `pubkey` field into an
/// `age::x25519::Recipient`. Surface a clean error message if the
/// `age1...` text form is malformed so the CLI can refuse to
/// register garbage.
pub fn parse_recipient_pubkey(s: &str) -> Result<age::x25519::Recipient, BackupError> {
    age::x25519::Recipient::from_str(s).map_err(|e| BackupError::InvalidPubkey(e.to_string()))
}

/// Resolve a [`RecoveryRecipient`] slice into a `Vec<age::x25519::Recipient>`.
/// Used by `kit export-backup --use-recovery-recipients` to
/// project the registered set onto a concrete recipient list at
/// backup-write time.
pub fn resolve_recovery_recipients(
    recipients: &[RecoveryRecipient],
) -> Result<Vec<age::x25519::Recipient>, BackupError> {
    recipients
        .iter()
        .map(|r| parse_recipient_pubkey(&r.pubkey))
        .collect()
}

/// PKCS#12 secondary export — **deferred to follow-up**.
///
/// The Rust PKCS#12 ecosystem as of 2026-06 doesn't have a
/// dependable path for producing modern PBES2 + AES-256 + high-
/// iteration PBKDF2 output:
///
/// - `pkcs12` 0.1 is parse-only
/// - `pkcs12` 0.2 is a pre-release
/// - `p12-keystore` defaults to PBES1 + RC2/3DES (legacy crypto)
///
/// Architectural decision #5 in the plan explicitly authorises
/// dropping PKCS#12 to a follow-up when the ecosystem can't write
/// PBES2 safely — age files cover the primary backup path so the
/// drop is graceful degradation, not data loss.
///
/// This function exists as a placeholder so the CLI surface for
/// `kit export-pkcs12` compiles. It returns an explicit
/// `BackupError::AgeFormat("PKCS#12 export is deferred…")` rather
/// than panicking; the CLI can surface the rationale to the user.
pub fn export_pkcs12_deferred(
    _unlocked: &UnlockedIdentity,
    _out_path: &Path,
    _passphrase: SecretString,
) -> Result<BackupSummary, BackupError> {
    Err(BackupError::AgeFormat(
        "PKCS#12 export is deferred to a follow-up because no Rust crate as \
         of 2026-06 writes modern PBES2 + AES-256-CBC + 600k-iteration \
         PBKDF2-HMAC-SHA256 with explicit parameter control. age files \
         cover the primary backup path; use `kit export-backup` instead. \
         See architectural decision #5 in the plan."
            .to_string(),
    ))
}

// ---- private helpers ----

fn envelope_from_unlocked(unlocked: &UnlockedIdentity) -> Result<EncryptedEnvelope, BackupError> {
    Ok(EncryptedEnvelope {
        bundle_version: BACKUP_BUNDLE_VERSION,
        bundle_created_at: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|e| BackupError::Time(e.to_string()))?,
        identity_schema_version: IDENTITY_SCHEMA_VERSION,
        fingerprint: unlocked.locked.fingerprint.clone(),
        algorithm: unlocked.locked.algorithm.clone(),
        identity_created_at: unlocked
            .locked
            .created_at
            .format(&Rfc3339)
            .map_err(|e| BackupError::Time(e.to_string()))?,
        did: unlocked.locked.did.clone(),
        handle: unlocked.locked.handle.clone(),
        key_provider: unlocked.locked.key_provider,
        recovery_recipients: unlocked.locked.recovery_recipients.clone(),
        chain_pem: unlocked.locked.chain_pem.clone(),
        key_pem: unlocked.key_pem().expose_secret().to_string(),
    })
}

fn envelope_to_bundle(envelope: EncryptedEnvelope) -> Result<BackupBundle, BackupError> {
    if envelope.bundle_version != BACKUP_BUNDLE_VERSION {
        return Err(BackupError::UnsupportedVersion {
            file: envelope.bundle_version,
            ours: BACKUP_BUNDLE_VERSION,
        });
    }
    let bundle_created_at = OffsetDateTime::parse(&envelope.bundle_created_at, &Rfc3339)
        .map_err(|e| BackupError::Time(format!("parse bundle_created_at: {e}")))?;
    let identity_created_at = OffsetDateTime::parse(&envelope.identity_created_at, &Rfc3339)
        .map_err(|e| BackupError::Time(format!("parse identity_created_at: {e}")))?;

    Ok(BackupBundle {
        bundle_version: envelope.bundle_version,
        bundle_created_at,
        chain_pem: envelope.chain_pem,
        fingerprint: envelope.fingerprint,
        algorithm: envelope.algorithm,
        identity_created_at,
        did: envelope.did,
        handle: envelope.handle,
        key_provider: envelope.key_provider,
        recovery_recipients: envelope.recovery_recipients,
        key_pem: SecretString::from(envelope.key_pem),
    })
}

fn write_age(
    out_path: &Path,
    encryptor: age::Encryptor,
    plaintext: &[u8],
) -> Result<u64, BackupError> {
    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let tmp = out_path.with_extension("age.tmp");
    {
        let mut out = fs::File::create(&tmp)?;
        let mut writer = encryptor
            .wrap_output(&mut out)
            .map_err(|e| BackupError::AgeFormat(e.to_string()))?;
        writer.write_all(plaintext)?;
        writer
            .finish()
            .map_err(|e| BackupError::AgeFormat(e.to_string()))?;
    }
    fs::rename(&tmp, out_path)?;
    let written = fs::metadata(out_path)?.len();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(out_path, fs::Permissions::from_mode(0o600));
    }

    Ok(written)
}

fn decrypt_age(
    ciphertext: &[u8],
    identities: &[&dyn age::Identity],
) -> Result<Vec<u8>, BackupError> {
    let decryptor = age::Decryptor::new(ciphertext)
        .map_err(|e| BackupError::AgeFormat(e.to_string()))?;
    match decryptor.decrypt(identities.iter().copied()) {
        Ok(mut reader) => {
            let mut buf = Vec::new();
            reader.read_to_end(&mut buf)?;
            Ok(buf)
        }
        // Three error variants all mean "your supplied unwrap
        // material can't open this file":
        //   - DecryptionFailed   : the payload MAC failed
        //   - KeyDecryptionFailed: a recipient stanza was attempted
        //     and failed (e.g. wrong scrypt passphrase)
        //   - NoMatchingKeys     : none of the supplied identities
        //     matched any recipient stanza
        // The user-facing answer is the same in all three cases.
        Err(age::DecryptError::DecryptionFailed)
        | Err(age::DecryptError::KeyDecryptionFailed)
        | Err(age::DecryptError::NoMatchingKeys) => Err(BackupError::AuthenticationFailed),
        Err(e) => Err(BackupError::AgeFormat(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_unlocked() -> UnlockedIdentity {
        let locked = LockedIdentity {
            chain_pem: "-----BEGIN CERTIFICATE-----\nfakecert\n-----END CERTIFICATE-----\n"
                .to_string(),
            fingerprint: "sha256:abcdef".to_string(),
            algorithm: "ES256".to_string(),
            did: Some("did:plc:test".to_string()),
            handle: Some("test.bsky.social".to_string()),
            created_at: OffsetDateTime::UNIX_EPOCH,
            key_provider: KeyProviderKind::Keychain,
            recovery_recipients: vec![],
        };
        UnlockedIdentity::new(
            locked,
            SecretString::from("-----BEGIN PRIVATE KEY-----\nthekeyitself\n-----END PRIVATE KEY-----\n".to_string()),
        )
    }

    #[test]
    fn passphrase_round_trip_preserves_all_fields() {
        let dir = TempDir::new().unwrap();
        let out = dir.path().join("backup.age");
        let id = sample_unlocked();

        let summary = export_with_passphrase(
            &id,
            &out,
            SecretString::from("correct horse battery staple".to_string()),
        )
        .expect("export");
        assert_eq!(summary.fingerprint, id.locked.fingerprint);
        assert_eq!(summary.recipient_count, 1);
        assert!(summary.written_bytes > 50);

        let bundle = import_with_passphrase(
            &out,
            SecretString::from("correct horse battery staple".to_string()),
        )
        .expect("import");
        assert_eq!(bundle.fingerprint, id.locked.fingerprint);
        assert_eq!(bundle.algorithm, id.locked.algorithm);
        assert_eq!(bundle.did, id.locked.did);
        assert_eq!(bundle.handle, id.locked.handle);
        assert_eq!(bundle.identity_created_at, id.locked.created_at);
        assert_eq!(bundle.key_provider, id.locked.key_provider);
        assert_eq!(bundle.chain_pem, id.locked.chain_pem);

        // Convert into an UnlockedIdentity and confirm the key
        // matches what we put in.
        let restored = bundle.into_unlocked(None);
        assert_eq!(
            restored.key_pem().expose_secret(),
            id.key_pem().expose_secret()
        );
    }

    #[test]
    fn x25519_round_trip_preserves_all_fields() {
        let dir = TempDir::new().unwrap();
        let out = dir.path().join("backup.age");
        let id = sample_unlocked();

        // Generate a fresh recipient + identity for the test.
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();

        let summary =
            export_with_recipients(&id, &out, std::slice::from_ref(&recipient)).expect("export");
        assert_eq!(summary.recipient_count, 1);

        let bundle = import_with_x25519_identity(&out, &identity).expect("import");
        assert_eq!(bundle.fingerprint, id.locked.fingerprint);
        assert_eq!(bundle.chain_pem, id.locked.chain_pem);

        let restored = bundle.into_unlocked(None);
        assert_eq!(
            restored.key_pem().expose_secret(),
            id.key_pem().expose_secret()
        );
    }

    #[test]
    fn wrong_passphrase_returns_authentication_failed() {
        let dir = TempDir::new().unwrap();
        let out = dir.path().join("backup.age");
        let id = sample_unlocked();

        export_with_passphrase(&id, &out, SecretString::from("correct".to_string())).unwrap();
        let err = import_with_passphrase(&out, SecretString::from("wrong".to_string()))
            .expect_err("should fail");
        assert!(matches!(err, BackupError::AuthenticationFailed), "got {err:?}");
    }

    #[test]
    fn wrong_x25519_identity_returns_authentication_failed() {
        let dir = TempDir::new().unwrap();
        let out = dir.path().join("backup.age");
        let id = sample_unlocked();

        let real = age::x25519::Identity::generate();
        let imposter = age::x25519::Identity::generate();
        export_with_recipients(&id, &out, std::slice::from_ref(&real.to_public())).unwrap();

        let err = import_with_x25519_identity(&out, &imposter).expect_err("should fail");
        assert!(matches!(err, BackupError::AuthenticationFailed), "got {err:?}");
    }

    #[test]
    fn empty_recipients_rejected_at_export_time() {
        let dir = TempDir::new().unwrap();
        let out = dir.path().join("backup.age");
        let id = sample_unlocked();

        let err = export_with_recipients(&id, &out, &[]).expect_err("should reject");
        assert!(matches!(err, BackupError::NoRecipients), "got {err:?}");
        assert!(!out.exists(), "no file written on rejected input");
    }

    #[test]
    fn recovery_recipients_round_trip_through_bundle() {
        let dir = TempDir::new().unwrap();
        let out = dir.path().join("backup.age");
        let mut id = sample_unlocked();
        id.locked.recovery_recipients = vec![
            RecoveryRecipient {
                pubkey: "age1example1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".into(),
                label: Some("studio yubikey".into()),
                added_at: "2026-06-14T12:00:00Z".into(),
            },
            RecoveryRecipient {
                pubkey: "age1example2yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy".into(),
                label: None,
                added_at: "2026-06-14T12:01:00Z".into(),
            },
        ];

        export_with_passphrase(&id, &out, SecretString::from("p".to_string())).unwrap();
        let bundle = import_with_passphrase(&out, SecretString::from("p".to_string())).unwrap();
        assert_eq!(bundle.recovery_recipients, id.locked.recovery_recipients);
    }

    #[test]
    fn multiple_x25519_recipients_any_one_can_decrypt() {
        let dir = TempDir::new().unwrap();
        let out = dir.path().join("backup.age");
        let id = sample_unlocked();

        let a = age::x25519::Identity::generate();
        let b = age::x25519::Identity::generate();
        let c = age::x25519::Identity::generate();
        let recipients = vec![a.to_public(), b.to_public(), c.to_public()];

        let summary = export_with_recipients(&id, &out, &recipients).unwrap();
        assert_eq!(summary.recipient_count, 3);

        // Each one independently decrypts.
        for ident in [&a, &b, &c] {
            let bundle = import_with_x25519_identity(&out, ident).unwrap();
            assert_eq!(bundle.fingerprint, id.locked.fingerprint);
        }
    }

    #[test]
    fn debug_format_redacts_key_material() {
        let dir = TempDir::new().unwrap();
        let out = dir.path().join("backup.age");
        let id = sample_unlocked();
        export_with_passphrase(&id, &out, SecretString::from("p".to_string())).unwrap();
        let bundle = import_with_passphrase(&out, SecretString::from("p".to_string())).unwrap();

        let debug = format!("{bundle:?}");
        assert!(!debug.contains("thekeyitself"), "key not in debug: {debug}");
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn missing_backup_file_surfaces_io_not_found() {
        let dir = TempDir::new().unwrap();
        let nonexistent = dir.path().join("nope.age");
        let err = import_with_passphrase(&nonexistent, SecretString::from("p".to_string()))
            .expect_err("no file");
        match err {
            BackupError::Io(io) => assert_eq!(io.kind(), std::io::ErrorKind::NotFound),
            other => panic!("expected Io(NotFound), got {other:?}"),
        }
    }

    #[test]
    fn pkcs12_export_is_explicitly_deferred() {
        // The placeholder returns a typed error rather than
        // panicking. This locks in that the CLI surface won't
        // accidentally start producing PKCS#12 files via stubs.
        let dir = TempDir::new().unwrap();
        let out = dir.path().join("backup.p12");
        let id = sample_unlocked();
        let err =
            export_pkcs12_deferred(&id, &out, SecretString::from("p".to_string())).expect_err("");
        match err {
            BackupError::AgeFormat(msg) => {
                assert!(msg.contains("PKCS#12"));
                assert!(msg.contains("deferred"));
            }
            other => panic!("expected AgeFormat(deferred), got {other:?}"),
        }
        assert!(!out.exists());
    }
}
