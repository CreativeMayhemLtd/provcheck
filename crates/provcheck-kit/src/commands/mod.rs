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

stub_command!(init, CliArgs, "init");
stub_command!(status, CliArgs, "status");
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
        // Locks in that the scaffold's stub returns the typed
        // NotImplemented error so main.rs's exit-code routing
        // works without parsing strings.
        let args = init::CliArgs {
            data_dir: DataDirOpt { data_dir: None },
        };
        let err = init::run(args).await.expect_err("not implemented");
        let kit_err = err.downcast_ref::<KitError>().expect("downcast");
        assert!(matches!(kit_err, KitError::NotImplemented(_)));
    }
}
