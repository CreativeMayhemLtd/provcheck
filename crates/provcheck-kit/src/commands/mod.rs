//! Subcommand definitions for `provcheck-kit`.
//!
//! Each command lives in its own submodule with two things: a clap
//! `Args` struct describing its flags, and an async `run(args)`
//! function that does the work. `main.rs` dispatches based on the
//! [`Command`] enum.
//!
//! All command bodies are stubs in this commit — the scaffold pass
//! gets the clap structure compiling so subsequent passes can fill
//! in the actual implementations without re-shaping the CLI
//! surface.

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

/// Errors the CLI surfaces to `main.rs` for exit-code routing.
/// Wrapped in `anyhow::Error` for ergonomic `?` use in command
/// bodies; `main.rs` downcasts to map onto exit codes.
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // SessionExpired + Io are consumed by the implementation passes
pub enum KitError {
    #[error("atproto session expired — run `kit login`")]
    SessionExpired,
    #[error("i/o: {0}")]
    Io(std::io::Error),
    #[error("not implemented yet: {0}")]
    NotImplemented(&'static str),
}

/// Top-level CLI shape.
#[derive(Debug, Parser)]
#[command(
    name = "provcheck-kit",
    version,
    about = "Artist-side toolkit for provcheck: mint identity, sign content, publish to atproto.",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// One variant per subcommand. The variant names match the
/// dispatch arms in `main.rs`.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate keys if absent. Default backend is the OS keychain;
    /// `--age-file` forces the encrypted-file backend. Registered
    /// recovery recipients only affect backup operations
    /// (see architectural decision #5 — at-rest is passphrase-only
    /// by age format constraint).
    Init(init::CliArgs),

    /// Show identity fingerprint, key-provider backend, session
    /// state, and published-record summary.
    Status(status::CliArgs),

    /// Interactive bsky-handle + app-password login. App password
    /// input goes through rpassword (no terminal echo). Persists
    /// the session under the data directory.
    Login(login::CliArgs),

    /// Delete the persisted session. Does NOT affect the signing
    /// key or any published records.
    Logout(logout::CliArgs),

    /// Sign a file with the local key. `--embed-identity` adds the
    /// `app.provcheck.identity` C2PA assertion (auto-suggest for
    /// the verifier's identity bar; Phase 5 work).
    Sign(sign::CliArgs),

    /// Publish the current cert fingerprint to atproto. Errors on
    /// duplicate fingerprint; pass `--force` to update.
    Publish(publish::CliArgs),

    /// List every `app.provcheck.signingKey` record under the
    /// authenticated user's DID — active, revoked, and superseded.
    List(list::CliArgs),

    /// Stamp `validUntil = now` on a published record, optionally
    /// linking a successor via `supersededBy`. The record stays in
    /// atproto history as a tombstone.
    Revoke(revoke::CliArgs),

    /// Generate a new identity, publish it, revoke the old one
    /// with `supersededBy` linkage. Backs the old identity up to
    /// `keys-rotated-YYYYMMDD-<fp>.age` automatically before the
    /// swap.
    Rotate(rotate::CliArgs),

    /// Convenience: invoke `provcheck` against a file. Saves
    /// typing during dev.
    Verify(verify::CliArgs),

    /// Write the current identity to an age-format backup file.
    /// Use `--use-recovery-recipients` to encrypt to the
    /// registered X25519 recipient set instead of a passphrase.
    ExportBackup(export_backup::CliArgs),

    /// Restore an identity from an age-format backup file.
    /// Accepts both passphrase-encrypted and X25519-encrypted
    /// inputs.
    ImportBackup(import_backup::CliArgs),

    /// Prime the in-process passphrase cache. Useful before a
    /// batch-signing session. No-op when the keychain backend is
    /// in use.
    Unlock(unlock::CliArgs),

    /// Clear the in-process passphrase cache. Subsequent
    /// operations re-prompt.
    Lock(lock::CliArgs),

    /// Prompt for the current at-rest passphrase, then twice for a
    /// new one. Re-encrypts the local age file. Errors when the
    /// backend is the OS keychain (no passphrase to change there).
    ChangePassphrase(change_passphrase::CliArgs),

    /// Register an X25519 recipient into `identity.json`. Does
    /// NOT modify the at-rest file (passphrase-only by age format
    /// constraint). Affects future `export-backup
    /// --use-recovery-recipients` exports.
    AddRecoveryRecipient(add_recovery_recipient::CliArgs),

    /// Show registered recovery recipients.
    ListRecoveryRecipients(list_recovery_recipients::CliArgs),

    /// De-register a recovery recipient. CRITICAL FOOTGUN —
    /// existing backups stay decryptable by the removed recipient
    /// forever. Requires
    /// `--i-understand-existing-backups-stay-decryptable`.
    RemoveRecoveryRecipient(remove_recovery_recipient::CliArgs),
}

/// Shared helper — many commands accept `--data-dir` to override
/// the default `provcheck-sign::persist::default_dir`.
#[derive(Debug, Args)]
pub struct DataDirOpt {
    /// Override the data directory. Defaults to
    /// `$XDG_DATA_HOME/provcheck-kit/` on Linux/macOS and
    /// `%APPDATA%\provcheck-kit\` on Windows.
    #[arg(long, value_name = "PATH")]
    pub data_dir: Option<PathBuf>,
}

// ----------------------------------------------------------------
// Command modules — one per subcommand.
//
// Bodies are stubs in this commit. Each `run(args)` returns
// `KitError::NotImplemented` so the surface compiles, the dispatch
// works end-to-end, and `kit --help` renders correctly. The
// implementation passes flesh these out without changing the CLI
// surface.
// ----------------------------------------------------------------

// ----------------------------------------------------------------
// `init` — Generate a fresh identity.
// ----------------------------------------------------------------

pub mod init {
    use anyhow::{Context, Result, bail};
    use clap::Args;
    use secrecy::SecretString;
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    use provcheck_sign::cert::{SubjectInfo, generate};
    use provcheck_sign::persist::{default_dir, load_locked, save_public_artefacts};
    use provcheck_sign::providers::{AgeFileProvider, KeyProvider, KeychainProvider};
    use provcheck_sign::types::{KeyProviderKind, LockedIdentity, RecoveryRecipient};

    use crate::prompts::new_passphrase;

    use super::DataDirOpt;

    #[derive(Debug, Args)]
    pub struct CliArgs {
        #[command(flatten)]
        pub data_dir: DataDirOpt,

        /// Force the encrypted-file backend instead of the OS
        /// keychain. Used on headless CI hosts or when the user
        /// explicitly opts out of OS keychain involvement.
        #[arg(long)]
        pub age_file: bool,

        /// Register an X25519 recovery recipient (`age1...` format).
        /// Repeatable. Affects backup operations only — the at-rest
        /// file is passphrase-only by age format constraint.
        #[arg(long = "recovery-recipient", value_name = "AGE_PUBKEY")]
        pub recovery_recipients: Vec<String>,

        /// Regenerate even if an identity already exists at this
        /// data directory. **WARNING:** orphans any previously-
        /// published atproto records pointing at the old fingerprint.
        #[arg(long)]
        pub force: bool,
    }

    pub async fn run(args: CliArgs) -> Result<()> {
        let dir = args
            .data_dir
            .data_dir
            .clone()
            .map(Ok)
            .unwrap_or_else(|| default_dir().context("resolve default data directory"))?;

        if !args.force && load_locked(&dir).is_ok() {
            bail!(
                "identity already exists at {}. \
                 Re-run with `--force` to regenerate (warning: \
                 orphans any previously-published atproto records).",
                dir.display()
            );
        }

        eprintln!("Generating ES256 keypair…");
        let kp = generate(&SubjectInfo::default()).context("cert generation")?;

        let now_str = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .context("format created_at")?;
        let recovery_recipients: Vec<RecoveryRecipient> = args
            .recovery_recipients
            .iter()
            .map(|r| RecoveryRecipient {
                pubkey: r.clone(),
                label: None,
                added_at: now_str.clone(),
            })
            .collect();

        let backend = if args.age_file {
            KeyProviderKind::EncryptedFile
        } else {
            KeyProviderKind::Keychain
        };

        let locked = LockedIdentity {
            chain_pem: kp.chain_pem.clone(),
            fingerprint: kp.fingerprint.clone(),
            algorithm: kp.algorithm.clone(),
            did: None,
            handle: None,
            created_at: OffsetDateTime::now_utc(),
            key_provider: backend,
            recovery_recipients,
        };

        let key_pem = SecretString::from(kp.key_pem.clone());
        let mut prompt = new_passphrase();
        match backend {
            KeyProviderKind::Keychain => {
                KeychainProvider::new()
                    .store(&dir, &kp.fingerprint, &key_pem, &mut prompt)
                    .context("store key in OS keychain")?;
            }
            KeyProviderKind::EncryptedFile => {
                AgeFileProvider::new()
                    .store(&dir, &kp.fingerprint, &key_pem, &mut prompt)
                    .context("store key in encrypted file")?;
            }
        }

        save_public_artefacts(&dir, &locked).context("save chain + identity.json")?;

        eprintln!();
        eprintln!("✓ Identity created.");
        eprintln!("  Fingerprint: {}", kp.fingerprint);
        eprintln!("  Storage:     {}", dir.display());
        eprintln!(
            "  Backend:     {}",
            match backend {
                KeyProviderKind::Keychain => "OS keychain",
                KeyProviderKind::EncryptedFile => "encrypted file (signing.key.age)",
            }
        );
        if !args.recovery_recipients.is_empty() {
            eprintln!("  Recovery recipients: {}", args.recovery_recipients.len());
        }
        eprintln!();
        eprintln!("Next step: `kit login` to attach an atproto identity.");

        Ok(())
    }
}

// ----------------------------------------------------------------
// `status` — Report the current local + atproto state.
// ----------------------------------------------------------------

pub mod status {
    use anyhow::{Context, Result};
    use clap::Args;

    use provcheck_sign::persist::{default_dir, load_locked};

    use super::DataDirOpt;

    #[derive(Debug, Args)]
    pub struct CliArgs {
        #[command(flatten)]
        pub data_dir: DataDirOpt,
    }

    pub async fn run(args: CliArgs) -> Result<()> {
        let dir = args
            .data_dir
            .data_dir
            .clone()
            .map(Ok)
            .unwrap_or_else(|| default_dir().context("resolve default data directory"))?;

        match load_locked(&dir) {
            Ok(locked) => {
                println!("[identity]");
                println!("  fingerprint: {}", locked.fingerprint);
                println!("  algorithm:   {}", locked.algorithm);
                println!("  created:     {}", locked.created_at);
                println!(
                    "  backend:     {}",
                    match locked.key_provider {
                        provcheck_sign::types::KeyProviderKind::Keychain => "keychain",
                        provcheck_sign::types::KeyProviderKind::EncryptedFile =>
                            "encrypted-file",
                    }
                );
                println!("  storage:     {}", dir.display());
                if let Some(did) = &locked.did {
                    println!("  did:         {}", did);
                }
                if let Some(handle) = &locked.handle {
                    println!("  handle:      @{}", handle);
                }
                if !locked.recovery_recipients.is_empty() {
                    println!();
                    println!("[recovery recipients]");
                    for r in &locked.recovery_recipients {
                        let label = r.label.as_deref().unwrap_or("(no label)");
                        let prefix_len = 28.min(r.pubkey.len());
                        let prefix = &r.pubkey[..prefix_len];
                        println!("  - {prefix}… [{label}] added {}", r.added_at);
                    }
                }
            }
            Err(_) => {
                println!("[identity]");
                println!("  none — run `kit init` to create one");
                println!("  storage would be: {}", dir.display());
            }
        }
        // Session state is reported in sub-pass 4d when login/logout
        // become real.
        println!();
        println!("[atproto session]");
        println!("  (status not implemented yet — sub-pass 4d)");
        Ok(())
    }
}

macro_rules! stub_command {
    ($modname:ident, $struct_name:ident, $err_label:literal $(, $field:ident: $ty:ty $(= $attr:meta)?)* $(,)?) => {
        pub mod $modname {
            use super::*;

            #[derive(Debug, Args)]
            pub struct $struct_name {
                #[command(flatten)]
                pub data_dir: DataDirOpt,
                $(
                    $(#[$attr])?
                    pub $field: $ty,
                )*
            }

            pub async fn run(_args: $struct_name) -> anyhow::Result<()> {
                Err(anyhow::Error::from(KitError::NotImplemented($err_label)))
            }
        }
    };
}

stub_command!(login, CliArgs, "login");
stub_command!(logout, CliArgs, "logout");
stub_command!(sign, CliArgs, "sign");
stub_command!(publish, CliArgs, "publish");
stub_command!(list, CliArgs, "list");
stub_command!(revoke, CliArgs, "revoke");
stub_command!(rotate, CliArgs, "rotate");
stub_command!(verify, CliArgs, "verify");
stub_command!(export_backup, CliArgs, "export-backup");
stub_command!(import_backup, CliArgs, "import-backup");
stub_command!(unlock, CliArgs, "unlock");
stub_command!(lock, CliArgs, "lock");
stub_command!(change_passphrase, CliArgs, "change-passphrase");
stub_command!(add_recovery_recipient, CliArgs, "add-recovery-recipient");
stub_command!(list_recovery_recipients, CliArgs, "list-recovery-recipients");
stub_command!(remove_recovery_recipient, CliArgs, "remove-recovery-recipient");

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_well_formed() {
        // clap's `debug_assert` catches developer errors at test
        // time (missing names, conflicting short flags, etc.) so
        // the binary's --help output is guaranteed to render.
        Cli::command().debug_assert();
    }

    #[test]
    fn every_subcommand_is_reachable() {
        // Verify the public surface — anyone who types
        // `kit --help` sees the same 18 commands enumerated.
        let cmd = Cli::command();
        let names: Vec<&str> = cmd
            .get_subcommands()
            .map(|c| c.get_name())
            .collect();
        for required in [
            "init",
            "status",
            "login",
            "logout",
            "sign",
            "publish",
            "list",
            "revoke",
            "rotate",
            "verify",
            "export-backup",
            "import-backup",
            "unlock",
            "lock",
            "change-passphrase",
            "add-recovery-recipient",
            "list-recovery-recipients",
            "remove-recovery-recipient",
        ] {
            assert!(
                names.contains(&required),
                "subcommand {required} is missing from the CLI surface"
            );
        }
    }

    #[test]
    fn parse_init_with_no_args() {
        let cli = Cli::try_parse_from(["provcheck-kit", "init"]).expect("parse");
        assert!(matches!(cli.command, Command::Init(_)));
    }

    #[test]
    fn parse_sign_requires_no_flags_in_scaffold() {
        // The scaffold stub doesn't take a file argument yet —
        // the implementation pass adds it. Until then the parse
        // succeeds bare.
        let cli = Cli::try_parse_from(["provcheck-kit", "sign"]).expect("parse");
        assert!(matches!(cli.command, Command::Sign(_)));
    }

    #[tokio::test]
    async fn stub_run_returns_not_implemented() {
        // Locks in that scaffold stubs return the typed
        // NotImplemented error so main.rs's exit-code routing
        // works without parsing strings. Uses `login` (still a
        // scaffold stub in this sub-pass); update to another
        // stubbed command if login becomes real.
        let args = login::CliArgs {
            data_dir: DataDirOpt { data_dir: None },
        };
        let err = login::run(args).await.expect_err("not implemented");
        let kit_err = err.downcast_ref::<KitError>().expect("downcast");
        assert!(matches!(kit_err, KitError::NotImplemented(_)));
    }
}
