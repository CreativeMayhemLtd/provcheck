//! provcheck-kit — artist-side CLI for provcheck.
//!
//! Composes `provcheck-sign` (cert + key custody + signing) and
//! `provcheck-publish` (atproto session + record CRUD) into 18
//! user-facing subcommands. The verifier (`provcheck`) stays
//! read-only forever; everything that signs or writes lives here
//! or in the sibling crates this binary depends on.
//!
//! ## Architecture
//!
//! `#[tokio::main]` at the entry point so atproto calls can be
//! awaited directly. The sync `provcheck-sign` API composes
//! cleanly inside async functions (its calls are blocking but
//! short — cert generation, file IO, age decrypt — they don't
//! starve the runtime).
//!
//! ## Exit codes
//!
//! Match the existing `provcheck` CLI's convention so CI
//! pipelines have one mental model:
//!
//! - `0` — success
//! - `1` — operation failed (network, auth, publish conflict)
//! - `2` — I/O error (file missing, key dir unreadable)
//! - `3` — atproto session expired, needs `kit login`
//!
//! ## Status
//!
//! All eighteen subcommands have real bodies. Two are intentional
//! no-ops awaiting a future kit-agent daemon (`lock`, `unlock`);
//! see the [`commands`] module docs. PKCS#12 export is the only
//! piece deferred to a follow-up — the age-format primary backup
//! covers the typical case.

use std::process::ExitCode;

use clap::Parser;

mod commands;
mod prompts;

use commands::{Cli, Command};

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Init(args) => commands::init::run(args).await,
        Command::Status(args) => commands::status::run(args).await,
        Command::Login(args) => commands::login::run(args).await,
        Command::Logout(args) => commands::logout::run(args).await,
        Command::Sign(args) => commands::sign::run(args).await,
        Command::Publish(args) => commands::publish::run(args).await,
        Command::List(args) => commands::list::run(args).await,
        Command::Revoke(args) => commands::revoke::run(args).await,
        Command::Rotate(args) => commands::rotate::run(args).await,
        Command::Verify(args) => commands::verify::run(args).await,
        Command::Watermark(args) => commands::watermark::run(args).await,
        Command::Serve(args) => commands::serve::run(args).await,
        Command::Weights(args) => commands::weights::run(args).await,
        Command::ExportBackup(args) => commands::export_backup::run(args).await,
        Command::ImportBackup(args) => commands::import_backup::run(args).await,
        Command::Unlock(args) => commands::unlock::run(args).await,
        Command::Lock(args) => commands::lock::run(args).await,
        Command::ChangePassphrase(args) => commands::change_passphrase::run(args).await,
        Command::AddRecoveryRecipient(args) => commands::add_recovery_recipient::run(args).await,
        Command::ListRecoveryRecipients(args) => {
            commands::list_recovery_recipients::run(args).await
        }
        Command::RemoveRecoveryRecipient(args) => {
            commands::remove_recovery_recipient::run(args).await
        }
    };

    match result {
        Ok(()) => ExitCode::from(0),
        Err(e) => {
            eprintln!("provcheck-kit: {e:#}");
            // Surface session-expired as its own exit code so CI
            // pipelines can `kit publish || kit login && kit publish`
            // without parsing error messages. The check walks the
            // error chain so it catches deeply-wrapped SessionError
            // and RecordsError variants, not just direct
            // KitError::SessionExpired emissions.
            if commands::is_session_expired(&e) {
                return ExitCode::from(3);
            }
            if let Some(kit_err) = e.downcast_ref::<commands::KitError>()
                && matches!(kit_err, commands::KitError::Io(_))
            {
                return ExitCode::from(2);
            }
            ExitCode::from(1)
        }
    }
}
