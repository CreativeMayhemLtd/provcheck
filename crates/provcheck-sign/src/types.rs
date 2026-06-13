//! Identity types and the on-disk serialisation format.
//!
//! The crate's two load-bearing types are [`LockedIdentity`] and
//! [`UnlockedIdentity`]. The split is the central architectural
//! invariant of the whole crate: every operation declares whether
//! it needs the private key by demanding the right type.
//!
//! - [`LockedIdentity`] — everything observable about a creator's
//!   identity without access to the secret. Cheap to construct,
//!   persists across processes, readable without any passphrase or
//!   keychain prompt. Carried in CLI flows that don't need to
//!   sign: `kit status`, `kit list`, JSON output, rendering.
//! - [`UnlockedIdentity`] — same data plus the private key in a
//!   [`SecretString`] that zeroises on drop. Required by signing,
//!   backup export, and rotation.
//!
//! Conversion from locked → unlocked goes through a `KeyProvider`
//! (see the `providers` module — landing in sub-pass 3 of Phase 2).
//! There is no `From<LockedIdentity> for UnlockedIdentity` impl by
//! design: producing the secret requires user action, and the type
//! system should reflect that.

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// On-disk file-format version recorded in `identity.json`. Bumping
/// this is a wire-breaking change — old `provcheck-sign` builds
/// won't load newer identity files. Add migration logic in
/// `persist::load_locked` when the version increments.
pub const IDENTITY_SCHEMA_VERSION: u8 = 1;

/// Everything publicly observable about a creator's identity.
///
/// Holds the cert chain (public), the canonical fingerprint that
/// gets published to atproto, the algorithm string, optional bsky
/// handle and DID (for display + auto-fill), the creation
/// timestamp, and which backend stores the private key.
///
/// Does NOT hold the private key — that requires `UnlockedIdentity`,
/// which is produced via a `KeyProvider`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedIdentity {
    /// Cert chain PEM in conventional order: EE cert first, CA
    /// cert second. The leaf (first block) is what
    /// `provcheck_attestation_spec::fingerprint_pem_chain` hashes.
    pub chain_pem: String,

    /// Canonical fingerprint: `sha256:<lowercase-hex>` of the leaf
    /// cert's DER bytes. Matches the lexicon pattern
    /// `^sha256:[0-9a-f]{64}$`.
    pub fingerprint: String,

    /// JWS algorithm identifier. Currently always `"ES256"`; future
    /// variants land when other algorithms are supported.
    pub algorithm: String,

    /// Optional bsky / atproto handle for display + auto-fill in
    /// the verifier's GUI identity bar.
    pub did: Option<String>,

    /// Optional handle (`creator.bsky.social` form). Display hint
    /// only — the DID is the source of truth.
    pub handle: Option<String>,

    /// When this identity was generated. Used as the implicit
    /// `valid_from` when publishing the `app.provcheck.signingKey`
    /// record.
    pub created_at: OffsetDateTime,

    /// Which custody backend holds the private key. Recorded in
    /// `identity.json` so subsequent loads route through the right
    /// `KeyProvider` impl.
    pub key_provider: KeyProviderKind,
}

/// A [`LockedIdentity`] plus the private key in memory.
///
/// Held in a [`SecretString`] so the bytes zeroise on drop. The
/// internal field is not pub — callers who need the key call
/// [`key_pem()`](Self::key_pem) explicitly, which returns a
/// reference whose lifetime is bounded by `&self`. Never serialise
/// this type. Never `Debug`-format it without redaction (the
/// `Debug` impl is custom, see below).
pub struct UnlockedIdentity {
    /// Public-facing identity data, always available.
    pub locked: LockedIdentity,
    /// Private key PEM (PKCS#8 from rcgen). The SecretString
    /// wrapper ensures the bytes zeroise on drop and the inner
    /// string never lands in `Debug` output by default.
    key_pem: SecretString,
}

impl UnlockedIdentity {
    /// Construct an unlocked identity. Used by the providers when
    /// they successfully unwrap the private key.
    pub fn new(locked: LockedIdentity, key_pem: SecretString) -> Self {
        Self { locked, key_pem }
    }

    /// Borrow the private key PEM. The returned reference's
    /// lifetime is bounded by `&self`; the bytes stay sealed in the
    /// `SecretString`.
    pub fn key_pem(&self) -> &SecretString {
        &self.key_pem
    }

    /// Discard the secret key and return the public-facing locked
    /// identity. Use when a flow finishes with the key (the
    /// `SecretString` zeroises as it goes out of scope).
    pub fn lock(self) -> LockedIdentity {
        self.locked
    }
}

impl std::fmt::Debug for UnlockedIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedIdentity")
            .field("locked", &self.locked)
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

/// Which custody backend holds the private key.
///
/// Recorded in `identity.json` so a future `load()` knows which
/// `KeyProvider` to ask for the key. Adding a variant (e.g.
/// `HardwareToken`) is a Phase-2-followup item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyProviderKind {
    /// OS keychain: macOS Keychain, Windows Credential Manager,
    /// or Linux Secret Service. The default when `kit init` runs
    /// in an environment where the backend is available.
    Keychain,
    /// AES-256-GCM ciphertext on disk under
    /// `keys/signing.key.enc`. Used as the fallback on headless
    /// hosts and when the user explicitly opts in via
    /// `--encrypted-file`.
    EncryptedFile,
}

/// On-disk format of `identity.json`. Pub(crate) — callers should
/// go through [`crate::persist::save_public_artefacts`] and
/// [`crate::persist::load_locked`] which marshal between this and
/// [`LockedIdentity`].
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct IdentityFile {
    pub schema_version: u8,
    pub fingerprint: String,
    pub algorithm: String,
    /// RFC 3339 timestamp.
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    pub key_provider: KeyProviderKind,
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn unlocked_identity_debug_redacts_key() {
        let locked = LockedIdentity {
            chain_pem: "test-chain".into(),
            fingerprint: "sha256:deadbeef".into(),
            algorithm: "ES256".into(),
            did: Some("did:plc:abc".into()),
            handle: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            key_provider: KeyProviderKind::EncryptedFile,
        };
        let unlocked = UnlockedIdentity::new(
            locked,
            SecretString::new("super-secret-private-key".into()),
        );
        let debug = format!("{:?}", unlocked);
        assert!(
            debug.contains("<redacted>"),
            "Debug format hides the key: {debug}"
        );
        assert!(
            !debug.contains("super-secret-private-key"),
            "Debug format does not leak the key: {debug}"
        );
    }

    #[test]
    fn unlocked_identity_lock_drops_secret() {
        let locked = LockedIdentity {
            chain_pem: "x".into(),
            fingerprint: "sha256:abc".into(),
            algorithm: "ES256".into(),
            did: None,
            handle: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            key_provider: KeyProviderKind::Keychain,
        };
        let unlocked =
            UnlockedIdentity::new(locked.clone(), SecretString::new("secret".into()));
        let relocked = unlocked.lock();
        assert_eq!(relocked, locked);
        // We can't observe the SecretString zeroisation here without
        // an allocator hook, but the type system guarantees the
        // SecretString went out of scope (it was moved into the lock
        // call and not returned).
    }

    #[test]
    fn key_provider_kind_serialises_snake_case() {
        let kc = serde_json::to_string(&KeyProviderKind::Keychain).expect("ser");
        assert_eq!(kc, "\"keychain\"");
        let ef = serde_json::to_string(&KeyProviderKind::EncryptedFile).expect("ser");
        assert_eq!(ef, "\"encrypted_file\"");
    }

    #[test]
    fn identity_file_round_trips_optional_fields() {
        let full = IdentityFile {
            schema_version: IDENTITY_SCHEMA_VERSION,
            fingerprint: "sha256:abc".into(),
            algorithm: "ES256".into(),
            created_at: "2026-06-13T12:00:00Z".into(),
            did: Some("did:plc:abc".into()),
            handle: Some("creator.bsky.social".into()),
            key_provider: KeyProviderKind::EncryptedFile,
        };
        let json = serde_json::to_string(&full).expect("ser");
        let back: IdentityFile = serde_json::from_str(&json).expect("de");
        assert_eq!(back.fingerprint, full.fingerprint);
        assert_eq!(back.did, full.did);
        assert_eq!(back.handle, full.handle);

        // Minimal — None fields don't serialise as null.
        let minimal = IdentityFile {
            schema_version: IDENTITY_SCHEMA_VERSION,
            fingerprint: "sha256:abc".into(),
            algorithm: "ES256".into(),
            created_at: "2026-06-13T12:00:00Z".into(),
            did: None,
            handle: None,
            key_provider: KeyProviderKind::Keychain,
        };
        let json = serde_json::to_string(&minimal).expect("ser");
        assert!(!json.contains("\"did\""));
        assert!(!json.contains("\"handle\""));
    }

    #[test]
    fn secret_string_borrow_works() {
        // Demonstrate the borrow shape callers will use when
        // unlocked.key_pem() lands in the signing path.
        let unlocked = UnlockedIdentity::new(
            LockedIdentity {
                chain_pem: "x".into(),
                fingerprint: "sha256:abc".into(),
                algorithm: "ES256".into(),
                did: None,
                handle: None,
                created_at: OffsetDateTime::UNIX_EPOCH,
                key_provider: KeyProviderKind::Keychain,
            },
            SecretString::new("the-key-bytes".into()),
        );
        let exposed = unlocked.key_pem().expose_secret();
        assert_eq!(exposed, "the-key-bytes");
    }
}
