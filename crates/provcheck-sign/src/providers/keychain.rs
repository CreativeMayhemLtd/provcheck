//! OS-keychain-backed private-key storage.
//!
//! Wraps the `keyring` crate (`keyring = "3"`, MIT/Apache-2.0).
//! On macOS the underlying store is Keychain Services; on Windows
//! it's the Credential Manager; on Linux it's the Secret Service
//! (gnome-keyring / kwallet / libsecret). The kit doesn't care
//! which — the abstraction is uniform.
//!
//! ## Naming convention
//!
//! Every kit identity ends up as a credential under:
//!
//! - **service** = `"app.provcheck.kit"`
//! - **account** = the cert fingerprint (`sha256:<hex>`)
//!
//! Using the fingerprint as the account lets a single keychain hold
//! multiple kit identities side-by-side without collision: each
//! `kit rotate` step gets its own credential entry until the old
//! one is explicitly deleted. The CLI's status / list commands can
//! walk the persisted on-disk identities and ask the keychain for
//! each one's secret separately.
//!
//! ## What the user sees
//!
//! On first read of a credential the OS may prompt (Touch ID,
//! Credential Manager confirmation dialog, gnome-keyring unlock
//! prompt). The user can choose "Always allow" — provcheck-kit
//! does not manage that surface; it's the OS's territory.
//!
//! ## Tests
//!
//! The `keyring` crate ships an in-memory `mock` backend that
//! tests opt into via `set_default_credential_builder`. We use
//! that path so unit tests don't pollute the real OS keychain;
//! see the test module below.

use std::path::Path;

use keyring::Entry;
use secrecy::{ExposeSecret, SecretString};

use crate::types::KeyProviderKind;

use super::{KeyProvider, NewPassphrasePrompt, PassphraseResult, ProviderError, UnlockPrompt};

/// Service identifier for every kit credential in the OS keychain.
/// Stable — changing this is a wire-breaking change for existing
/// installs, equivalent to wiping every user's identity.
pub const KEYCHAIN_SERVICE: &str = "app.provcheck.kit";

/// OS-keychain-backed [`KeyProvider`]. Stateless — all per-call
/// addressing is computed from the `fingerprint` argument.
#[derive(Debug, Clone, Default)]
pub struct KeychainProvider;

impl KeychainProvider {
    pub fn new() -> Self {
        Self
    }
}

impl KeyProvider for KeychainProvider {
    fn kind(&self) -> KeyProviderKind {
        KeyProviderKind::Keychain
    }

    fn store(
        &self,
        _dir: &Path,
        fingerprint: &str,
        key_pem: &SecretString,
        _new_passphrase: &mut dyn FnMut(NewPassphrasePrompt) -> PassphraseResult,
    ) -> Result<(), ProviderError> {
        // The keychain doesn't need a passphrase from us — the OS
        // manages access control. We ignore the prompt callback;
        // the CLI binary passes one anyway because the trait
        // signature is backend-agnostic.
        let entry = Entry::new(KEYCHAIN_SERVICE, fingerprint).map_err(keychain_err)?;
        entry
            .set_password(key_pem.expose_secret())
            .map_err(keychain_err)?;
        Ok(())
    }

    fn fetch(
        &self,
        _dir: &Path,
        fingerprint: &str,
        _passphrase: &mut dyn FnMut(UnlockPrompt) -> PassphraseResult,
    ) -> Result<SecretString, ProviderError> {
        let entry = Entry::new(KEYCHAIN_SERVICE, fingerprint).map_err(keychain_err)?;
        match entry.get_password() {
            Ok(s) => Ok(SecretString::from(s)),
            // A missing credential maps to the IO not-found shape
            // so callers (especially `kit status`) see consistent
            // semantics across the two backends: "the key isn't
            // where you expected it" looks the same whether the
            // file is gone or the keychain entry was deleted out
            // of band.
            Err(keyring::Error::NoEntry) => Err(ProviderError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no keychain credential for fingerprint {fingerprint}"),
            ))),
            Err(e) => Err(keychain_err(e)),
        }
    }

    fn delete(&self, _dir: &Path, fingerprint: &str) -> Result<(), ProviderError> {
        let entry = Entry::new(KEYCHAIN_SERVICE, fingerprint).map_err(keychain_err)?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            // Idempotent: deleting an already-absent credential
            // succeeds, matching the file backend's behaviour.
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(keychain_err(e)),
        }
    }
}

/// Map keyring's structured Error into ProviderError. The keyring
/// crate distinguishes platform-backend failures, no-entry,
/// ambiguous-match, encoding, and storage-access. We collapse
/// everything except `NoEntry` (which has explicit handling above)
/// into the catch-all `Keychain` variant — these are operational
/// issues, not user-correctable ones, and the underlying error
/// message carries the actionable detail.
fn keychain_err(e: keyring::Error) -> ProviderError {
    ProviderError::Keychain(e.to_string())
}

#[cfg(test)]
mod tests {
    //! Tests run against the **real OS keychain** on the host
    //! they execute on. The keyring crate's mock backend isn't
    //! useful here — it documents `CredentialPersistence::EntryOnly`
    //! (every `Entry::new` returns a fresh, empty credential), so
    //! it can't simulate the cross-call persistence property
    //! we're testing.
    //!
    //! Consequences:
    //!
    //! 1. Tests are `#[ignore]` by default so headless CI runners
    //!    (Linux without Secret Service, Windows without
    //!    interactive desktop, etc.) don't fail.
    //! 2. Run them locally with
    //!    `cargo test -p provcheck-sign -- --ignored keychain`.
    //! 3. Each test uses a process-unique fingerprint plus a
    //!    [`KeychainTestGuard`] that deletes the credential on
    //!    `Drop` — so even on panic the user's real keychain
    //!    isn't left holding orphaned test credentials.
    //!
    //! The default-skip + manual-run pattern mirrors what
    //! `provcheck-watermark` does for its silentcipher positive-
    //! control fixture: the implementation is exercised, but the
    //! test isn't a forced gate on CI hosts that can't provide the
    //! environment.

    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tempfile::TempDir;

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Returns a unique 64-char-hex fingerprint per call, derived
    /// from the test process ID and a monotonically-increasing
    /// counter. Avoids tests stomping on each other within one
    /// process and avoids collisions with previous test runs whose
    /// cleanup may have failed.
    fn unique_fingerprint(test_name: &str) -> String {
        let n = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let body = format!("{test_name}-{pid}-{n}");
        // Pad / truncate to 64 lowercase-hex-ish chars. Real
        // fingerprints are SHA-256 hex; the keychain backend only
        // cares that the account string is stable per-credential,
        // not that it parses as hex.
        let mut s = String::with_capacity(64);
        for b in body.bytes() {
            if s.len() == 64 {
                break;
            }
            s.push((b'a' + (b % 26)) as char);
        }
        while s.len() < 64 {
            s.push('0');
        }
        format!("sha256:{s}")
    }

    /// RAII cleanup: deletes the keychain credential on drop, even
    /// on panic. Stops a failing test from polluting the dev's
    /// real OS keychain with leftover test credentials.
    struct KeychainTestGuard {
        fingerprint: String,
    }
    impl KeychainTestGuard {
        fn new(fingerprint: String) -> Self {
            Self { fingerprint }
        }
    }
    impl Drop for KeychainTestGuard {
        fn drop(&mut self) {
            if let Ok(entry) = Entry::new(KEYCHAIN_SERVICE, &self.fingerprint) {
                let _ = entry.delete_credential();
            }
        }
    }

    /// Prompt callbacks the keychain backend never invokes.
    /// Surfaces a clear panic if the trait wiring ever changes and
    /// the keychain backend starts calling them.
    fn never_new() -> impl FnMut(NewPassphrasePrompt) -> PassphraseResult {
        |_| panic!("keychain backend should not call the new-passphrase prompt")
    }
    fn never_unlock() -> impl FnMut(UnlockPrompt) -> PassphraseResult {
        |_| panic!("keychain backend should not call the unlock prompt")
    }

    const SAMPLE_KEY: &str =
        "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49\n-----END PRIVATE KEY-----\n";

    #[test]
    fn kind_reports_keychain() {
        // No OS interaction — safe to run unconditionally.
        let p = KeychainProvider::new();
        assert!(matches!(p.kind(), KeyProviderKind::Keychain));
    }

    #[test]
    #[ignore = "uses real OS keychain — run with `--ignored keychain`"]
    fn store_then_fetch_round_trips() {
        let dir = TempDir::new().expect("tempdir");
        let provider = KeychainProvider::new();
        let fp = unique_fingerprint("round_trip");
        let _guard = KeychainTestGuard::new(fp.clone());
        let plaintext = SecretString::from(SAMPLE_KEY.to_string());

        provider
            .store(dir.path(), &fp, &plaintext, &mut never_new())
            .expect("store");
        let recovered = provider
            .fetch(dir.path(), &fp, &mut never_unlock())
            .expect("fetch");
        assert_eq!(recovered.expose_secret(), SAMPLE_KEY);
    }

    #[test]
    #[ignore = "uses real OS keychain — run with `--ignored keychain`"]
    fn fetch_missing_credential_surfaces_io_not_found() {
        let dir = TempDir::new().expect("tempdir");
        let provider = KeychainProvider::new();
        let fp = unique_fingerprint("missing");
        let _guard = KeychainTestGuard::new(fp.clone());

        let err = provider
            .fetch(dir.path(), &fp, &mut never_unlock())
            .expect_err("no credential to fetch");
        match err {
            ProviderError::Io(io) => assert_eq!(io.kind(), std::io::ErrorKind::NotFound),
            other => panic!("expected Io(NotFound), got {other:?}"),
        }
    }

    #[test]
    #[ignore = "uses real OS keychain — run with `--ignored keychain`"]
    fn delete_removes_credential() {
        let dir = TempDir::new().expect("tempdir");
        let provider = KeychainProvider::new();
        let fp = unique_fingerprint("delete");
        let _guard = KeychainTestGuard::new(fp.clone());

        provider
            .store(
                dir.path(),
                &fp,
                &SecretString::from(SAMPLE_KEY.to_string()),
                &mut never_new(),
            )
            .expect("store");
        provider.delete(dir.path(), &fp).expect("delete");

        let err = provider
            .fetch(dir.path(), &fp, &mut never_unlock())
            .expect_err("deleted credential gone");
        match err {
            ProviderError::Io(io) => assert_eq!(io.kind(), std::io::ErrorKind::NotFound),
            other => panic!("expected Io(NotFound), got {other:?}"),
        }
    }

    #[test]
    #[ignore = "uses real OS keychain — run with `--ignored keychain`"]
    fn delete_is_idempotent_when_credential_absent() {
        let dir = TempDir::new().expect("tempdir");
        let provider = KeychainProvider::new();
        let fp = unique_fingerprint("idempotent_delete");
        let _guard = KeychainTestGuard::new(fp.clone());

        provider
            .delete(dir.path(), &fp)
            .expect("delete on missing credential is Ok");
    }

    #[test]
    #[ignore = "uses real OS keychain — run with `--ignored keychain`"]
    fn store_overwrites_previous_credential() {
        let dir = TempDir::new().expect("tempdir");
        let provider = KeychainProvider::new();
        let fp = unique_fingerprint("overwrite");
        let _guard = KeychainTestGuard::new(fp.clone());

        provider
            .store(
                dir.path(),
                &fp,
                &SecretString::from("first".to_string()),
                &mut never_new(),
            )
            .expect("store v1");
        provider
            .store(
                dir.path(),
                &fp,
                &SecretString::from("second".to_string()),
                &mut never_new(),
            )
            .expect("store v2");

        let recovered = provider
            .fetch(dir.path(), &fp, &mut never_unlock())
            .expect("fetch");
        assert_eq!(recovered.expose_secret(), "second");
    }

    #[test]
    #[ignore = "uses real OS keychain — run with `--ignored keychain`"]
    fn different_fingerprints_address_distinct_credentials() {
        // Confirms the per-fingerprint addressing — storing under
        // fingerprint A and B should yield two independent
        // credentials, neither shadowing the other. Load-bearing
        // property for letting one keychain hold multiple kit
        // identities during a rotate.
        let dir = TempDir::new().expect("tempdir");
        let provider = KeychainProvider::new();
        let fp_a = unique_fingerprint("distinct_a");
        let fp_b = unique_fingerprint("distinct_b");
        let _ga = KeychainTestGuard::new(fp_a.clone());
        let _gb = KeychainTestGuard::new(fp_b.clone());

        provider
            .store(
                dir.path(),
                &fp_a,
                &SecretString::from("aaa".to_string()),
                &mut never_new(),
            )
            .expect("store a");
        provider
            .store(
                dir.path(),
                &fp_b,
                &SecretString::from("bbb".to_string()),
                &mut never_new(),
            )
            .expect("store b");

        let ra = provider
            .fetch(dir.path(), &fp_a, &mut never_unlock())
            .expect("fetch a");
        let rb = provider
            .fetch(dir.path(), &fp_b, &mut never_unlock())
            .expect("fetch b");
        assert_eq!(ra.expose_secret(), "aaa");
        assert_eq!(rb.expose_secret(), "bbb");

        provider.delete(dir.path(), &fp_a).expect("delete a");
        let rb2 = provider
            .fetch(dir.path(), &fp_b, &mut never_unlock())
            .expect("fetch b still works after deleting a");
        assert_eq!(rb2.expose_secret(), "bbb");
    }
}
