//! Yubikey PIV-slot key custody backend.
//!
//! Holds the private key on a Yubikey PIV slot (`9c` —
//! "Digital Signature"). The key is generated on-device and never
//! extractable; every C2PA signature happens on the token, gated
//! by the PIV PIN per the `PinPolicy::Always` slot policy.
//!
//! Implements the v0.5.0 `KeyProvider::signer()` seam — `fetch()`
//! is structurally inappropriate for HSM-backed identities (no PEM
//! exists to return) so the impl below refuses, but `signer()`
//! returns a custom [`YubikeySigner`] that implements
//! [`c2pa::Signer`] directly.
//!
//! Wire path on every signature:
//!
//! 1. Caller invokes `c2pa::Builder::sign_file` with the
//!    `Box<dyn c2pa::Signer>` returned by `YubikeyProvider::signer`.
//! 2. c2pa-rs computes the COSE payload digest and calls
//!    `YubikeySigner::sign(payload)`.
//! 3. The signer opens the Yubikey by serial, verifies the PIN
//!    (held in-process from the `signer()` construction prompt),
//!    SHA-256's the payload, calls `yubikey::piv::sign_data` with
//!    `AlgorithmId::EccP256`.
//! 4. The Yubikey returns an ECDSA signature in ASN.1 DER
//!    `SEQUENCE { r, s }` form. The signer converts to the raw
//!    P1363 `r || s` 64-byte concatenation that COSE ES256
//!    requires.
//! 5. PIN is zeroized when the signer drops.
//!
//! ## What this module does NOT contain
//!
//! - The `kit init --backend yubikey` flow (the
//!   `create_on_device` helper that mints a fresh keypair on the
//!   token, runs `piv::generate`, builds an ephemeral software CA,
//!   issues the leaf cert, writes the cert chain into slot 9c,
//!   and persists the public artefacts) — that lands in v0.5.0 P3
//!   when the kit CLI surface adds the flag.
//! - PUK recovery / management-key rotation — out of scope; users
//!   should run `ykman piv access change-pin` /
//!   `change-management-key` directly.

use std::path::Path;

use secrecy::{ExposeSecret, SecretString};
use yubikey::{
    YubiKey,
    piv::{AlgorithmId, SlotId},
};

use super::{
    KeyProvider, NewPassphrasePrompt, PassphraseResult, ProviderError, UnlockPrompt,
};
use crate::types::{KeyProviderKind, LockedIdentity};

/// Yubikey backend. Holds the device serial + PIV slot ID that
/// identify which physical token and which slot to talk to.
#[derive(Debug, Clone)]
pub struct YubikeyProvider {
    serial: u32,
    /// PIV slot ID byte (`0x9c` for the PIV Digital Signature slot).
    slot: u8,
}

impl YubikeyProvider {
    /// Construct a provider bound to a specific Yubikey + slot. The
    /// kit `init --backend yubikey` flow constructs this AFTER it
    /// has confirmed the device is present and the slot is
    /// populated.
    pub fn new(serial: u32, slot: u8) -> Self {
        Self { serial, slot }
    }

    /// Convenience: construct from a [`KeyProviderKind::Yubikey`]
    /// variant. Returns `None` for any other variant.
    pub fn from_kind(kind: KeyProviderKind) -> Option<Self> {
        match kind {
            KeyProviderKind::Yubikey { serial, slot } => Some(Self::new(serial, slot)),
            _ => None,
        }
    }

    pub fn serial(&self) -> u32 {
        self.serial
    }

    pub fn slot(&self) -> u8 {
        self.slot
    }

    /// Convert the stored slot byte to the yubikey crate's
    /// `SlotId` enum.
    fn slot_id(&self) -> Result<SlotId, ProviderError> {
        match self.slot {
            0x9c => Ok(SlotId::Signature),
            other => Err(ProviderError::HardwareToken(format!(
                "unsupported PIV slot 0x{other:02x} — only 0x9c (Digital Signature) is wired in v0.5.0"
            ))),
        }
    }

    /// Open the Yubikey identified by `self.serial`. Surfaces a
    /// clear error when the device is unplugged or otherwise
    /// unreachable.
    fn open(&self) -> Result<YubiKey, ProviderError> {
        YubiKey::open_by_serial(yubikey::Serial::from(self.serial)).map_err(|e| {
            ProviderError::HardwareToken(format!(
                "Yubikey (serial {}) not reachable: {e}. Plug the device into a USB port and try again.",
                self.serial
            ))
        })
    }

    /// Read the PIN-tries-remaining counter from the device. Used
    /// before every PIN prompt so the caller can refuse to prompt
    /// when only one try is left (the next failure would lock the
    /// device, requiring PUK recovery).
    pub fn pin_tries_remaining(&self) -> Result<u8, ProviderError> {
        let mut yk = self.open()?;
        yk.get_pin_retries()
            .map_err(|e| ProviderError::HardwareToken(format!("get_pin_retries: {e}")))
    }
}

impl KeyProvider for YubikeyProvider {
    fn kind(&self) -> KeyProviderKind {
        KeyProviderKind::Yubikey {
            serial: self.serial,
            slot: self.slot,
        }
    }

    fn store(
        &self,
        _: &Path,
        _: &str,
        _: &SecretString,
        _: &mut dyn FnMut(NewPassphrasePrompt) -> PassphraseResult,
    ) -> Result<(), ProviderError> {
        // A Yubikey-backed identity can't be "stored" by handing it
        // a software-extractable PEM — keys are generated on-device.
        // The `kit init --backend yubikey` flow takes a different
        // code path entirely (see `create_on_device`, P3).
        Err(ProviderError::HardwareToken(
            "Yubikey backend does not accept software-extractable \
             keys. Use the create-on-device flow at \
             `kit init --backend yubikey`."
                .to_string(),
        ))
    }

    fn fetch(
        &self,
        _: &Path,
        _: &str,
        _: &mut dyn FnMut(UnlockPrompt) -> PassphraseResult,
    ) -> Result<SecretString, ProviderError> {
        // The PIV private key never leaves the device. Callers that
        // reach this path are using the v0.4.x PEM-returning seam;
        // they should switch to `KeyProvider::signer()` instead.
        Err(ProviderError::HardwareToken(
            "Yubikey-backed identities have no extractable PEM — \
             call `KeyProvider::signer()` instead of `fetch()`."
                .to_string(),
        ))
    }

    fn delete(&self, _: &Path, _: &str) -> Result<(), ProviderError> {
        // Conceptually destroys the slot's content. We do NOT
        // expose this — clearing slot 9c via the kit would be a
        // huge footgun. Users who want to wipe the slot should run
        // `ykman piv keys delete 9c` explicitly.
        Err(ProviderError::HardwareToken(
            "refusing to wipe slot 9c — run `ykman piv keys delete 9c` \
             explicitly if that's really what you want."
                .to_string(),
        ))
    }

    fn signer(
        &self,
        _dir: &Path,
        locked: &LockedIdentity,
        prompt: &mut dyn FnMut(UnlockPrompt) -> PassphraseResult,
    ) -> Result<Box<dyn c2pa::Signer>, ProviderError> {
        // Verify the device is reachable + read tries before any
        // PIN entry, so the prompt can show the counter and the
        // kit can refuse when only 1 try remains (avoiding the
        // path to PIN lockout).
        let tries = self.pin_tries_remaining()?;
        if tries == 0 {
            return Err(ProviderError::HardwareToken(format!(
                "Yubikey (serial {}) PIN is locked (0 retries remaining). \
                 Use `ykman piv access unblock-pin` to recover.",
                self.serial
            )));
        }
        if tries == 1 {
            // We let the caller decide whether to abort; some flows
            // explicitly want to risk the final attempt. The prompt
            // gets the tries count so it can render a warning.
        }

        let pin = prompt(UnlockPrompt::yubikey_pin(1, tries))?;
        let slot_id = self.slot_id()?;
        // Snapshot what the signer needs to hold so it can re-open
        // the device on every sign() call. The signer's lifetime
        // outlives `prompt`, so the PIN moves into it.
        let signer = YubikeySigner {
            serial: self.serial,
            slot: slot_id,
            pin,
            chain_pem: locked.chain_pem.clone(),
        };
        Ok(Box::new(signer))
    }
}

/// `c2pa::Signer` implementation backed by a Yubikey PIV slot.
///
/// Holds the device serial, slot, PIN (in a [`SecretString`] that
/// zeroizes on drop) and the cert chain PEM that was persisted at
/// identity-creation time. Re-opens the Yubikey on every `sign()`
/// call so the signer survives plug / unplug cycles (the next
/// signature simply errors instead of silently using a stale
/// handle).
pub struct YubikeySigner {
    serial: u32,
    slot: SlotId,
    pin: SecretString,
    chain_pem: String,
}

impl YubikeySigner {
    /// Open the Yubikey, verify the PIN, sign a SHA-256 digest of
    /// `data` via `piv::sign_data`, and convert the resulting
    /// ASN.1 DER ECDSA signature to the raw P1363 64-byte form
    /// COSE ES256 expects.
    fn sign_es256(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        use sha2::{Digest, Sha256};

        let mut yk = YubiKey::open_by_serial(yubikey::Serial::from(self.serial))
            .map_err(|e| format!("open Yubikey serial {}: {e}", self.serial))?;
        yk.verify_pin(self.pin.expose_secret().as_bytes())
            .map_err(|e| format!("verify PIN: {e}"))?;

        let digest = Sha256::digest(data);
        let der_sig = yubikey::piv::sign_data(&mut yk, &digest, AlgorithmId::EccP256, self.slot)
            .map_err(|e| format!("piv::sign_data: {e}"))?;

        // Yubikey returns `SEQUENCE { r INTEGER, s INTEGER }`. COSE
        // ES256 wants the raw P1363 concatenation `r || s` padded to
        // 32 bytes each = 64 bytes total. Use p256 for the parse +
        // re-encode since it already knows both shapes.
        let parsed = p256::ecdsa::Signature::from_der(&der_sig)
            .map_err(|e| format!("DER decode: {e}"))?;
        Ok(parsed.to_bytes().to_vec())
    }
}

impl c2pa::Signer for YubikeySigner {
    fn sign(&self, data: &[u8]) -> c2pa::Result<Vec<u8>> {
        self.sign_es256(data).map_err(c2pa::Error::OtherError)
    }

    fn alg(&self) -> c2pa::SigningAlg {
        c2pa::SigningAlg::Es256
    }

    fn certs(&self) -> c2pa::Result<Vec<Vec<u8>>> {
        // Parse the PEM chain into a Vec of DER blobs. c2pa expects
        // EE-first order (the chain_pem we persist is already
        // EE-then-CA per the existing cert.rs convention).
        let mut out: Vec<Vec<u8>> = Vec::new();
        for block in pem::parse_many(self.chain_pem.as_bytes())
            .map_err(|e| c2pa::Error::OtherError(Box::new(e)))?
        {
            out.push(block.into_contents());
        }
        Ok(out)
    }

    fn reserve_size(&self) -> usize {
        // c2pa-rs's built-in software signers reserve ~10 KB for
        // the manifest signature payload. ES256 signatures + cert
        // chain + timestamp easily fit; the value is a soft
        // ceiling, not a hard cost.
        10_000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Yubikey-touching integration tests are gated on an env var
    /// so CI hosts without a physical device can skip them
    /// cleanly. Run locally with
    /// `PROVCHECK_TEST_YUBIKEY_SERIAL=<N> cargo test -p provcheck-sign`.
    fn test_serial() -> Option<u32> {
        std::env::var("PROVCHECK_TEST_YUBIKEY_SERIAL")
            .ok()
            .and_then(|s| s.parse().ok())
    }

    #[test]
    fn slot_id_accepts_only_9c() {
        let p = YubikeyProvider::new(42, 0x9c);
        assert!(matches!(p.slot_id(), Ok(SlotId::Signature)));

        let p = YubikeyProvider::new(42, 0x9a);
        match p.slot_id() {
            Ok(_) => panic!("expected unsupported-slot error"),
            Err(ProviderError::HardwareToken(msg)) => {
                assert!(msg.contains("0x9a"), "names the bad slot: {msg}");
            }
            Err(other) => panic!("expected HardwareToken, got {other:?}"),
        }
    }

    #[test]
    fn from_kind_round_trips() {
        let kind = KeyProviderKind::Yubikey {
            serial: 12345,
            slot: 0x9c,
        };
        let p = YubikeyProvider::from_kind(kind).expect("yubikey kind");
        assert_eq!(p.serial(), 12345);
        assert_eq!(p.slot(), 0x9c);
        assert_eq!(p.kind(), kind);

        assert!(YubikeyProvider::from_kind(KeyProviderKind::Keychain).is_none());
    }

    #[test]
    fn store_refuses_software_pem() {
        let p = YubikeyProvider::new(42, 0x9c);
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut prompt =
            |_: NewPassphrasePrompt| -> PassphraseResult { Ok(SecretString::from(String::new())) };
        let err = match p.store(
            tmp.path(),
            "sha256:abc",
            &SecretString::from(String::new()),
            &mut prompt,
        ) {
            Ok(()) => panic!("expected refusal"),
            Err(e) => e,
        };
        assert!(
            matches!(err, ProviderError::HardwareToken(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn fetch_refuses_extractable_path() {
        let p = YubikeyProvider::new(42, 0x9c);
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut prompt = |_: UnlockPrompt| -> PassphraseResult {
            Ok(SecretString::from(String::new()))
        };
        let err = match p.fetch(tmp.path(), "sha256:abc", &mut prompt) {
            Ok(_) => panic!("expected refusal"),
            Err(e) => e,
        };
        assert!(
            matches!(err, ProviderError::HardwareToken(_)),
            "got {err:?}"
        );
        // Verify the message points the caller at the right API.
        if let ProviderError::HardwareToken(msg) = err {
            assert!(
                msg.contains("signer()"),
                "message names the replacement API: {msg}"
            );
        }
    }

    #[test]
    fn delete_refuses() {
        let p = YubikeyProvider::new(42, 0x9c);
        let tmp = tempfile::tempdir().expect("tempdir");
        match p.delete(tmp.path(), "sha256:abc") {
            Ok(()) => panic!("expected refusal"),
            Err(ProviderError::HardwareToken(msg)) => {
                assert!(msg.contains("ykman"), "message names the right tool: {msg}");
            }
            Err(other) => panic!("got {other:?}"),
        }
    }

    /// Real-device integration test: skipped unless
    /// `PROVCHECK_TEST_YUBIKEY_SERIAL` is set. Verifies the
    /// device is openable and reports a PIN-tries-remaining count.
    #[test]
    fn device_present_when_test_env_var_set() {
        let Some(serial) = test_serial() else {
            return;
        };
        let p = YubikeyProvider::new(serial, 0x9c);
        let tries = p
            .pin_tries_remaining()
            .expect("Yubikey reachable + PIN-tries readable");
        assert!(
            tries <= 3,
            "factory-fresh / re-init Yubikeys cap at 3 PIN tries; got {tries}"
        );
    }
}
