//! Interactive passphrase prompts.
//!
//! Wraps `rpassword` into closures that match the
//! `provcheck-sign` provider trait's prompt-callback signatures.
//! The CLI binary is the only thing that talks to the user; the
//! provcheck-sign crate doesn't depend on rpassword and isn't
//! aware of terminal IO.
//!
//! Two flavours:
#![allow(dead_code)] // prompt helpers ship in sub-pass 1; consumed by the implementation passes
//!
//! - [`new_passphrase`] — for the create-key path. Prompts twice
//!   and confirms the two entries match, enforces a minimum
//!   length, returns the final value as a [`SecretString`].
//! - [`unlock_passphrase`] — for the read-key path. Prompts once,
//!   surfaces the prompt's `attempt` counter so the prompt body
//!   can render a "Try again" hint on retries.

use provcheck_sign::providers::{
    NewPassphrasePrompt, PassphraseResult, ProviderError, UnlockPrompt,
};
use secrecy::SecretString;

/// Minimum acceptable passphrase length. The kit refuses anything
/// shorter — the rationale is in the help text printed when a
/// caller's input is rejected.
pub const MIN_PASSPHRASE_LEN: usize = 12;

/// Construct a closure suitable for
/// `provcheck_sign::providers::KeyProvider::store`'s
/// new-passphrase callback.
pub fn new_passphrase() -> impl FnMut(NewPassphrasePrompt) -> PassphraseResult {
    move |prompt: NewPassphrasePrompt| {
        eprintln!(
            "Choose a passphrase for {} key material. Minimum {} characters.",
            prompt.purpose, MIN_PASSPHRASE_LEN
        );
        eprintln!("(input is hidden)");
        let pass = rpassword::prompt_password("passphrase: ").map_err(ProviderError::Io)?;
        let confirm = rpassword::prompt_password("confirm:    ").map_err(ProviderError::Io)?;
        if pass != confirm {
            eprintln!("provcheck-kit: the two entries didn't match.");
            return Err(ProviderError::UserCancelled);
        }
        if pass.chars().count() < MIN_PASSPHRASE_LEN {
            eprintln!(
                "provcheck-kit: passphrase is too short ({} characters). \
                 Minimum {}.",
                pass.chars().count(),
                MIN_PASSPHRASE_LEN
            );
            return Err(ProviderError::UserCancelled);
        }
        Ok(SecretString::from(pass))
    }
}

/// Construct a closure suitable for
/// `provcheck_sign::providers::KeyProvider::fetch`'s
/// unlock-passphrase callback.
pub fn unlock_passphrase() -> impl FnMut(UnlockPrompt) -> PassphraseResult {
    move |prompt: UnlockPrompt| {
        if prompt.attempt == 1 {
            eprintln!("Unlock {} key material.", prompt.purpose);
        } else {
            eprintln!(
                "Wrong passphrase. Attempt {} of 3 — try again.",
                prompt.attempt
            );
        }
        let pass = rpassword::prompt_password("passphrase: ").map_err(ProviderError::Io)?;
        Ok(SecretString::from(pass))
    }
}
