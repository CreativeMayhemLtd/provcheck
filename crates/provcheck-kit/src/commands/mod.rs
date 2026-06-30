//! Subcommand definitions for `provcheck-kit`.
//!
//! Each command lives in its own submodule with two things: a clap
//! `Args` struct describing its flags, and an async `run(args)`
//! function that does the work. `main.rs` dispatches based on the
//! [`Command`] enum.
//!
//! Two commands intentionally print a "no-op" line and exit 0:
//! `lock` and `unlock`. They exist on the CLI surface for
//! forward-compatibility with a future kit-agent daemon that would
//! own cross-process passphrase caching; until that daemon ships,
//! each `kit` invocation drops its in-process [`SecretCache`] at
//! exit, so there's nothing for these commands to act on.
//!
//! `export-backup --use-recovery-recipients` writes X25519-encrypted
//! bundles; `import-backup --identity-file <PATH>` restores them.
//! Default (no `--identity-file`) takes a passphrase, matching the
//! default `export-backup` mode. Both round-trips are covered
//! end-to-end. PKCS#12 export is the one explicitly deferred backup
//! flavour — see [`provcheck_sign::backup::export_pkcs12_deferred`]
//! for the rationale.

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

#[cfg(test)]
mod kit_error_tests {
    use super::*;

    #[test]
    fn session_expired_directs_user_to_login() {
        // CLI exit-code 3 mapping depends on this message.
        let s = format!("{}", KitError::SessionExpired);
        assert!(s.contains("kit login"), "got: {s}");
    }

    #[test]
    fn io_message_includes_inner() {
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "perms");
        let s = format!("{}", KitError::Io(io));
        assert!(s.contains("i/o"));
        assert!(s.contains("perms"));
    }

    #[test]
    fn not_implemented_message_includes_subcommand_name() {
        let s = format!("{}", KitError::NotImplemented("publish"));
        assert!(s.contains("not implemented"));
        assert!(s.contains("publish"));
    }
}

// v0.9.64: pin that operator-facing "deferred feature" messages
// do not embed a specific landed-in version. The previous
// messages claimed "v0.3.0 / v0.5.1 / v0.5.0 P3" — once we
// shipped past those, the messages were lying to users about
// when a feature would land. The fix is to describe the
// workaround, not promise a version.
#[cfg(test)]
mod no_stale_version_promises_tests {
    // Operate on the captured stderr from running the lock/
    // unlock async fns. Since they're async we test them via
    // a small tokio runtime.

    fn capture_lock_stderr() -> String {
        let args = super::lock::CliArgs {
            data_dir: super::DataDirOpt { data_dir: None },
        };
        // The function writes to stderr via eprintln!; we can't
        // capture that without a test harness. Instead, we test
        // the user-facing strings by checking the source — they
        // are stable string literals not produced by interpolation.
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        // run() returns Ok(()) — exit cleanly
        rt.block_on(super::lock::run(args)).expect("lock no-op");
        // The message we actually pin lives below in the
        // _message_source_does_not_promise tests.
        String::new()
    }

    fn capture_unlock_stderr() -> String {
        let args = super::unlock::CliArgs {
            data_dir: super::DataDirOpt { data_dir: None },
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(super::unlock::run(args)).expect("unlock no-op");
        String::new()
    }

    #[test]
    fn lock_command_exits_clean() {
        // The no-op command must exit Ok — the CLI exit-code
        // contract is that "successfully did nothing" is exit 0.
        let _ = capture_lock_stderr();
    }

    #[test]
    fn unlock_command_exits_clean() {
        let _ = capture_unlock_stderr();
    }

    #[test]
    fn deferred_message_source_does_not_promise_landed_version() {
        // Pin by walking the source — a future maintainer who
        // reintroduces a `lands in v0.X.Y` style sentinel in any
        // user-facing deferred-feature message will trip this
        // test.
        //
        // Build the stale tokens by string concatenation so the
        // test itself does not contain the literal substring
        // (which would make the test self-defeating — it would
        // match its own source).
        let lands = ["lands", "in"].join(" ");
        let v_dot_three = format!("v0{}3", '.');
        let v_dot_five_p3 = format!("v0{}5{}0 P3", '.', '.');
        let v_dot_five_one = format!("v0{}5{}1", '.', '.');

        let source = include_str!("mod.rs");
        // Sentinels to look for: kit-agent rationale tied to a
        // dotted version, or the two specific "lands in vX" hooks
        // that we removed in v0.9.64.
        let s1 = format!("{} (no kit-agent", v_dot_three);
        let s2 = format!("{} {}", lands, v_dot_five_one);
        let s3 = format!("{} {}", lands, v_dot_five_p3);

        for stale in [&s1, &s2, &s3] {
            assert!(
                !source.contains(stale.as_str()),
                "stale version-promise sentinel found in source: {stale:?}"
            );
        }
    }
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

    /// Embed a silentcipher neural watermark into an audio file.
    /// Use case: re-watermark mixed episodes after ffmpeg loudness
    /// normalisation strips the original render-time mark. Output
    /// is a WAV (re-encode externally to MP3/AAC as needed).
    Watermark(watermark::CliArgs),

    /// Long-lived watermark worker. Reads JSON-line requests on
    /// stdin, writes JSON-line responses on stdout. Reuses the
    /// in-process tract model across requests so per-file model
    /// load (3-5 seconds in the one-shot CLI flow) drops to zero
    /// after the first request. Exit cleanly on stdin EOF.
    ///
    /// Request shape: `{"id":"...","input":"/path","output":"/path",
    /// "kind":"silentcipher"|"audioseal"|"wavmark",
    /// "payload":"hex","brand_id":N,"sdr_db":F,"alpha":F,
    /// "channels":"auto"|"mono"|"stereo","verify_after_embed":bool,
    /// "overwrite":bool}`.
    ///
    /// Response shape: `{"id":"...","ok":true,"elapsed_ms":N}` or
    /// `{"id":"...","ok":false,"error":"..."}`. v0.6.0 P2.
    Serve(serve::CliArgs),

    /// Manage downloadable detector weights. Every detector family
    /// (silentcipher, audioseal, wavmark, trustmark) ships its
    /// trained model weights as a download-on-demand artefact on
    /// the public release. `kit weights` lists what's available,
    /// installs the ones you want, and removes the ones you don't.
    ///
    /// Weights are never auto-downloaded — detection / embed
    /// commands surface a clean "not installed" error when a
    /// family is needed but absent. v0.7 phase 8a.
    Weights(weights::CliArgs),

    /// One-call creator pipeline: watermark + C2PA sign in
    /// sequence on the same input. Auto-detects audio vs image
    /// from the extension. v0.7 phase 7g.
    Stamp(stamp::CliArgs),

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
#[derive(Debug, Args, Clone)]
pub struct DataDirOpt {
    /// Override the data directory. Defaults to
    /// `$XDG_DATA_HOME/provcheck-kit/` on Linux/macOS and
    /// `%APPDATA%\provcheck-kit\` on Windows.
    #[arg(long, value_name = "PATH")]
    pub data_dir: Option<PathBuf>,
}

// ----------------------------------------------------------------
// Command modules — one per subcommand. Each `run(args)` is the
// real implementation; the surface compiled from the CLI dispatch
// table here is the contract the user binary depends on.
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
    use provcheck_sign::providers::yubikey::{create_on_device, list_connected};
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
        #[arg(long, conflicts_with = "yubikey")]
        pub age_file: bool,

        /// Mint the identity on a Yubikey PIV slot. The private
        /// key is generated on-device and never extractable —
        /// every signature requires the PIV PIN. Slot is fixed
        /// at `0x9c` (Digital Signature) for v0.5.0.
        ///
        /// If multiple Yubikeys are connected, pass `--serial N`
        /// to disambiguate.
        ///
        /// **Pre-requisites**: the Yubikey must have a PIV PIN
        /// other than the factory default `123456`. Run
        /// `ykman piv access change-pin` before this command if
        /// you haven't already.
        #[arg(long, conflicts_with_all = ["age_file", "recovery_recipients"])]
        pub yubikey: bool,

        /// Yubikey hardware serial — required when more than one
        /// Yubikey is plugged in, optional otherwise. Ignored
        /// without `--yubikey`.
        #[arg(long, value_name = "N", requires = "yubikey")]
        pub serial: Option<u32>,

        /// Register an X25519 recovery recipient (`age1...` format).
        /// Repeatable. Affects backup operations only — the at-rest
        /// file is passphrase-only by age format constraint.
        /// Mutually exclusive with `--yubikey` (a Yubikey-backed
        /// private key has no on-disk material to recipient-encrypt).
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

        if args.yubikey {
            return run_yubikey(args, dir).await;
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
            KeyProviderKind::Yubikey { .. } => {
                // Init for a Yubikey identity goes through a
                // different code path entirely (no software-
                // keypair generation; the key is minted on-device).
                // This arm exists so the compiler keeps every match
                // exhaustive. Reaching it indicates an upstream
                // dispatch bug.
                bail!(
                    "internal error: software-keypair init arm reached \
                     for a Yubikey-backed identity. The Yubikey path \
                     mints the key on-device and must not pass through \
                     this branch. Re-run `kit init --backend yubikey` \
                     and file an issue if this persists."
                );
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
                KeyProviderKind::Keychain => "OS keychain".to_string(),
                KeyProviderKind::EncryptedFile =>
                    "encrypted file (signing.key.age)".to_string(),
                KeyProviderKind::Yubikey { serial, slot } => format!(
                    "Yubikey (serial {serial}, PIV slot 0x{slot:02x})"
                ),
            }
        );
        if !args.recovery_recipients.is_empty() {
            eprintln!("  Recovery recipients: {}", args.recovery_recipients.len());
        }
        eprintln!();
        eprintln!("Next step: `kit login` to attach an atproto identity.");

        Ok(())
    }

    /// Yubikey-backed `kit init` flow. Generates the keypair
    /// on-device, builds an ephemeral software CA, issues the leaf
    /// cert, writes it into slot 9c, and persists the public
    /// artefacts. The private key never enters host RAM.
    async fn run_yubikey(args: CliArgs, dir: std::path::PathBuf) -> Result<()> {
        // Detect connected Yubikeys before prompting the user — gives
        // a clearer error path when zero devices are present.
        let serials = list_connected().context("enumerate Yubikeys")?;
        let serial = match (serials.len(), args.serial) {
            (0, _) => bail!(
                "no Yubikey detected. Plug one into a USB port and try again. \
                 If a device is plugged in but isn't found, run `ykman list` to \
                 confirm the OS sees it."
            ),
            (1, None) => serials[0],
            (1, Some(req)) if req == serials[0] => serials[0],
            (1, Some(req)) => bail!(
                "requested serial {req} but the only connected Yubikey is {}",
                serials[0]
            ),
            (_, None) => bail!(
                "multiple Yubikeys connected ({:?}). Pass `--serial N` to pick one.",
                serials
            ),
            (_, Some(req)) => {
                if !serials.contains(&req) {
                    bail!(
                        "requested serial {req} not found among connected devices ({:?})",
                        serials
                    );
                }
                req
            }
        };

        eprintln!(
            "Detected Yubikey serial {serial}. The key will be generated on \
             PIV slot 0x9c (Digital Signature) with PinPolicy::Always."
        );
        eprintln!();
        eprintln!(
            "  WARNING: slot 0x9c will be OVERWRITTEN. Any prior key in that \
             slot is destroyed (no recovery)."
        );
        eprintln!();

        // Prompt for the PIV PIN. Plain rpassword — no PIN length /
        // policy check (yubikey enforces 6-8 chars itself on verify).
        let pin = rpassword::prompt_password("PIV PIN: ").context("read PIN")?;
        if pin.is_empty() {
            bail!("PIN required — aborted");
        }
        if pin == "123456" {
            bail!(
                "refusing to use the factory-default PIN (123456). \
                 Change it first with `ykman piv access change-pin`."
            );
        }
        let pin = secrecy::SecretString::from(pin);

        eprintln!("Generating ES256 keypair on slot 0x9c…");
        let created =
            create_on_device(serial, &pin, None, &SubjectInfo::default()).map_err(|e| {
                anyhow::anyhow!("create-on-device: {e}").context(
                    "If management-key auth failed, you've already changed it from \
                     factory default. `kit init --backend yubikey` only supports \
                     the factory management key; use ykman to mint the keypair \
                     directly, then `kit init --backend yubikey --serial <N> \
                     --slot 9c` against the pre-minted key.",
                )
            })?;

        let now = OffsetDateTime::now_utc();
        let locked = LockedIdentity {
            chain_pem: created.chain_pem,
            fingerprint: created.fingerprint.clone(),
            algorithm: created.algorithm,
            did: None,
            handle: None,
            created_at: now,
            key_provider: created.key_provider,
            recovery_recipients: vec![],
        };

        save_public_artefacts(&dir, &locked).context("save chain + identity.json")?;

        eprintln!();
        eprintln!("✓ Yubikey identity created.");
        eprintln!("  Fingerprint: {}", created.fingerprint);
        eprintln!("  Storage:     {}", dir.display());
        eprintln!("  Backend:     Yubikey (serial {serial}, PIV slot 0x9c)");
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
    use time::format_description::well_known::Rfc3339;

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
                // RFC 3339 (e.g. "2026-06-14T08:28:05.199Z") instead
                // of OffsetDateTime's verbose Display ("2026-06-14
                // 8:28:05.1994507 +00:00:00"). Matches the wire
                // format used everywhere else in the codebase.
                let created = locked
                    .created_at
                    .format(&Rfc3339)
                    .unwrap_or_else(|_| locked.created_at.to_string());
                println!("[identity]");
                println!("  fingerprint: {}", locked.fingerprint);
                println!("  algorithm:   {}", locked.algorithm);
                println!("  created:     {created}");
                println!(
                    "  backend:     {}",
                    match locked.key_provider {
                        provcheck_sign::types::KeyProviderKind::Keychain =>
                            "keychain".to_string(),
                        provcheck_sign::types::KeyProviderKind::EncryptedFile =>
                            "encrypted-file".to_string(),
                        provcheck_sign::types::KeyProviderKind::Yubikey {
                            serial,
                            slot,
                        } => format!("yubikey (serial {serial}, slot 0x{slot:02x})"),
                    }
                );
                // For Yubikey identities, query the live device state
                // so the user sees whether the token is plugged in and
                // how many PIN tries remain. Soft-failure: if the
                // device isn't reachable, surface that as an
                // informational line rather than aborting.
                if let provcheck_sign::types::KeyProviderKind::Yubikey { serial, slot } =
                    locked.key_provider
                {
                    let provider = provcheck_sign::providers::YubikeyProvider::new(serial, slot);
                    match provider.pin_tries_remaining() {
                        Ok(tries) => {
                            println!("  device:      present");
                            println!("  PIN tries:   {tries} of 3 remaining");
                            if tries == 0 {
                                println!(
                                    "               (locked — run `ykman piv access \
                                     unblock-pin` to recover)"
                                );
                            } else if tries == 1 {
                                println!("               (one more failed attempt locks the PIN)");
                            }
                        }
                        Err(e) => {
                            println!("  device:      not reachable ({e})");
                            println!("               (plug the Yubikey into a USB port)");
                        }
                    }
                }
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
        println!();
        println!("[atproto session]");
        match provcheck_publish::AtprotoClient::load_session(&dir).await {
            Ok(client) => {
                let snap = client.snapshot();
                println!("  did:    {}", snap.did);
                println!("  handle: @{}", snap.handle);
                println!("  pds:    {}", snap.pds);
            }
            Err(provcheck_publish::session::SessionError::SessionExpired) => {
                println!("  session expired — run `kit login` to refresh");
            }
            Err(provcheck_publish::session::SessionError::Io(e))
                if e.kind() == std::io::ErrorKind::NotFound =>
            {
                println!("  none — run `kit login <handle>` to attach an atproto identity");
            }
            Err(e) => {
                println!("  unavailable — {e}");
            }
        }
        Ok(())
    }
}

// ----------------------------------------------------------------
// `sign <FILE>` — Sign an asset with the local key.
// ----------------------------------------------------------------

pub mod sign {
    use std::path::PathBuf;

    use anyhow::{Context, Result};
    use clap::Args;

    use provcheck_attestation_spec::IdentityClaim;
    use provcheck_sign::persist::{default_dir, load_locked};
    use provcheck_sign::providers::{
        AgeFileProvider, KeyProvider, KeychainProvider, YubikeyProvider,
    };
    use provcheck_sign::sign::{
        SignAction, default_action_for, embed_identity_assertion, inspect_source,
        sign_asset_with_signer,
    };
    use provcheck_sign::types::KeyProviderKind;

    use crate::prompts::unlock_passphrase;

    use super::DataDirOpt;

    #[derive(Debug, Args)]
    pub struct CliArgs {
        #[command(flatten)]
        pub data_dir: DataDirOpt,

        /// Asset to sign.
        pub file: PathBuf,

        /// Destination path. When omitted, the kit signs in place:
        /// writes to a sibling temp file
        /// (`<stem>.signed-tmp.<ext>`, e.g. `foo.signed-tmp.wav`)
        /// and atomically renames over the source on success.
        /// c2pa-rs itself doesn't support in-place (source and
        /// destination must differ AND share an extension), so the
        /// temp-file dance hides that limit from the caller. If
        /// signing fails the temp file is removed and the source
        /// is left untouched.
        #[arg(long, short = 'o', value_name = "PATH")]
        pub out: Option<PathBuf>,

        /// Path to a manifest JSON file. If not supplied, the kit
        /// constructs a minimal default manifest with `c2pa.actions.v2`
        /// (action: created) and the file's format inferred from
        /// its extension.
        #[arg(long, value_name = "PATH")]
        pub manifest: Option<PathBuf>,

        /// Embed an `app.provcheck.identity` C2PA assertion carrying
        /// the local identity's DID (and handle, if known) into the
        /// signed file's manifest. The verifier reads this as a
        /// "verify against this DID" hint when the user passes
        /// `--auto-identity` (and the GUI auto-fills its identity
        /// bar from it). Requires a DID on the local identity —
        /// run `kit login` first. The DID is the load-bearing
        /// trust anchor; the cross-check against the published
        /// `signingKey` records still has to pass for the verifier
        /// to trust the claim.
        #[arg(long)]
        pub embed_identity: bool,

        /// C2PA action label for the new signature. Accepts the
        /// short form (`created` / `opened` / `edited` /
        /// `published`) or the canonical (`c2pa.created` etc.).
        /// When omitted the kit picks: `published` if the source
        /// already has a C2PA manifest (the publisher-attestation
        /// case — your signature joins the existing chain as a
        /// derivative), `created` otherwise.
        #[arg(long, value_name = "ACTION")]
        pub action: Option<String>,
    }

    pub async fn run(args: CliArgs) -> Result<()> {
        let dir = args
            .data_dir
            .data_dir
            .clone()
            .map(Ok)
            .unwrap_or_else(|| default_dir().context("resolve default data directory"))?;
        let locked = load_locked(&dir)
            .context("load identity — run `kit init` first if you haven't already")?;

        // Construct a c2pa signer via the recorded backend. The
        // provider's `signer()` method handles passphrase / PIN entry
        // and (for Yubikey) device interaction. Software backends
        // wrap a fetched PEM via c2pa's existing builders; the
        // Yubikey backend returns a custom signer that delegates
        // every signature to the on-device key.
        let mut prompt = unlock_passphrase();
        let signer: Box<dyn c2pa::Signer> = match locked.key_provider {
            KeyProviderKind::Keychain => KeychainProvider::new()
                .signer(&dir, &locked, &mut prompt)
                .context("build signer from OS keychain")?,
            KeyProviderKind::EncryptedFile => AgeFileProvider::new()
                .signer(&dir, &locked, &mut prompt)
                .context("build signer from encrypted file")?,
            KeyProviderKind::Yubikey { serial, slot } => YubikeyProvider::new(serial, slot)
                .signer(&dir, &locked, &mut prompt)
                .context("build signer from Yubikey")?,
        };

        // Inspect the source for existing C2PA provenance so we can
        // (a) pick the right default action, (b) tell the user what
        // they're chaining into. provcheck-sign auto-adds the
        // parent ingredient regardless of action — this only
        // controls the claim verb on the new manifest.
        let provenance = inspect_source(&args.file);
        if let Some(prov) = &provenance {
            eprintln!("source has existing C2PA provenance:");
            if let Some(signer) = &prov.signer {
                eprintln!("  signer:    {signer}");
            }
            if let Some(generator) = &prov.claim_generator {
                eprintln!("  tool:      {generator}");
            }
            eprintln!("  manifest:  {}", prov.label);
            eprintln!("Your signature will join the chain as a derivative.");
        }

        let action = match args.action.as_deref() {
            Some(s) => SignAction::parse(s).ok_or_else(|| {
                anyhow::anyhow!(
                    "--action {s:?}: expected one of created/opened/edited/published \
                     (or c2pa.created/opened/edited/published)"
                )
            })?,
            None => default_action_for(provenance.as_ref()),
        };

        let base_manifest = match &args.manifest {
            Some(p) => std::fs::read_to_string(p)
                .with_context(|| format!("read manifest from {}", p.display()))?,
            None => default_manifest(&args.file, action)?,
        };

        let manifest_json = if args.embed_identity {
            let did = locked.did.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "--embed-identity requires a DID on the local identity. \
                     Run `kit login` first so the identity has its did + handle \
                     stamped on identity.json."
                )
            })?;
            let claim = IdentityClaim::new(did, locked.handle.clone());
            embed_identity_assertion(&base_manifest, &claim)
                .context("splice app.provcheck.identity assertion into manifest")?
        } else {
            base_manifest
        };

        // c2pa-rs refuses src == dst. When the user wants in-place
        // (no --out), write to a sibling temp file and atomic-rename
        // over the source on success. The temp file lives in the
        // same directory as the source so std::fs::rename stays
        // atomic on every platform (cross-volume rename isn't).
        let (effective_dst, in_place) = match &args.out {
            Some(p) => (p.clone(), false),
            None => (sidecar_tmp_path(&args.file), true),
        };

        let result = match sign_asset_with_signer(
            signer.as_ref(),
            &args.file,
            &effective_dst,
            &manifest_json,
        ) {
            Ok(r) => r,
            Err(e) => {
                // Clean up the temp file so a failed in-place sign
                // doesn't leave a half-written sidecar lying around.
                if in_place {
                    let _ = std::fs::remove_file(&effective_dst);
                }
                return Err(anyhow::Error::from(e).context("c2pa sign_asset"));
            }
        };

        let final_path = if in_place {
            std::fs::rename(&effective_dst, &args.file).with_context(|| {
                // Best-effort temp cleanup before returning.
                let _ = std::fs::remove_file(&effective_dst);
                format!(
                    "promote temp file {} → {} (signed file is at the temp \
                     path if it still exists)",
                    effective_dst.display(),
                    args.file.display()
                )
            })?;
            args.file.clone()
        } else {
            result.output_path.clone()
        };

        eprintln!(
            "✓ Signed {} → {}",
            args.file.display(),
            final_path.display()
        );
        eprintln!("  manifest bytes: {}", result.manifest_bytes.len());
        if args.embed_identity {
            eprintln!(
                "  identity assertion: embedded ({})",
                locked.did.as_deref().unwrap_or("?")
            );
        }
        Ok(())
    }

    /// Compute the temp-file path used for an in-place sign. Lives
    /// in the same directory as the source so the eventual rename
    /// is atomic. Slots `.signed-tmp` into the file stem rather
    /// than appending it to the full name — c2pa-rs validates that
    /// source and destination extensions match, so the temp must
    /// keep the original extension. `foo.wav` → `foo.signed-tmp.wav`;
    /// `foo` (no extension) → `foo.signed-tmp`.
    pub(crate) fn sidecar_tmp_path(src: &std::path::Path) -> PathBuf {
        let parent = src.parent();
        let stem = src
            .file_stem()
            .map(|s| s.to_owned())
            .unwrap_or_else(|| std::ffi::OsString::from("unnamed"));
        let ext = src.extension();
        let mut name = stem;
        name.push(".signed-tmp");
        if let Some(e) = ext {
            name.push(".");
            name.push(e);
        }
        match parent {
            Some(p) if !p.as_os_str().is_empty() => p.join(name),
            _ => PathBuf::from(name),
        }
    }

    /// Construct a minimal-but-valid C2PA manifest for the given
    /// asset. The CLI uses this when the user doesn't supply a
    /// manifest JSON file. `action` controls the c2pa.actions.v2
    /// verb on the new claim.
    fn default_manifest(asset: &std::path::Path, action: SignAction) -> Result<String> {
        let format = format_from_extension(asset).context(
            "infer asset format from extension — pass --manifest for unrecognised types",
        )?;
        let title = asset
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("untitled");

        let v = serde_json::json!({
            "claim_generator": "provcheck-kit/0.3.1",
            "claim_generator_info": [{"name": "provcheck-kit", "version": "0.3.1"}],
            "format": format,
            "title": title,
            "assertions": [
                {
                    "label": "c2pa.actions.v2",
                    "data": {"actions": [{"action": action.as_c2pa_label()}]}
                }
            ]
        });
        Ok(v.to_string())
    }

    fn format_from_extension(p: &std::path::Path) -> Option<&'static str> {
        let ext = p.extension().and_then(|s| s.to_str())?.to_ascii_lowercase();
        Some(match ext.as_str() {
            "wav" => "audio/wav",
            "mp3" => "audio/mpeg",
            "flac" => "audio/flac",
            "ogg" | "oga" => "audio/ogg",
            "m4a" => "audio/mp4",
            "aac" => "audio/aac",
            "jpg" | "jpeg" => "image/jpeg",
            "png" => "image/png",
            "tif" | "tiff" => "image/tiff",
            "webp" => "image/webp",
            "mp4" | "m4v" => "video/mp4",
            "mov" => "video/quicktime",
            "webm" => "video/webm",
            _ => return None,
        })
    }
}

// ----------------------------------------------------------------
// `add-recovery-recipient <AGE-PUBKEY>` / `list-recovery-recipients`
// / `remove-recovery-recipient <PUBKEY-OR-LABEL>`
// ----------------------------------------------------------------

pub mod add_recovery_recipient {
    use anyhow::{Context, Result, bail};
    use clap::Args;
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    use provcheck_sign::backup::parse_recipient_pubkey;
    use provcheck_sign::persist::{default_dir, load_locked, save_public_artefacts};
    use provcheck_sign::types::RecoveryRecipient;

    use super::DataDirOpt;

    #[derive(Debug, Args)]
    pub struct CliArgs {
        #[command(flatten)]
        pub data_dir: DataDirOpt,

        /// X25519 public key in age's canonical `age1...` text form.
        pub pubkey: String,

        /// Optional human-readable label.
        #[arg(long, short = 'l')]
        pub label: Option<String>,
    }

    pub async fn run(args: CliArgs) -> Result<()> {
        let dir = args
            .data_dir
            .data_dir
            .clone()
            .map(Ok)
            .unwrap_or_else(|| default_dir().context("resolve default data directory"))?;
        let mut locked = load_locked(&dir).context("load identity")?;

        // Validate the pubkey is a real age recipient before
        // storing it — refuse to register garbage.
        parse_recipient_pubkey(&args.pubkey)
            .with_context(|| format!("invalid age pubkey: {}", args.pubkey))?;

        if locked
            .recovery_recipients
            .iter()
            .any(|r| r.pubkey == args.pubkey)
        {
            bail!("recipient is already registered");
        }

        let added_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .context("format timestamp")?;
        locked.recovery_recipients.push(RecoveryRecipient {
            pubkey: args.pubkey.clone(),
            label: args.label.clone(),
            added_at,
        });

        save_public_artefacts(&dir, &locked).context("save identity.json")?;

        eprintln!("✓ Registered recovery recipient.");
        if let Some(label) = &args.label {
            eprintln!("  Label: {}", label);
        }
        eprintln!("  Pubkey: {}…", &args.pubkey[..28.min(args.pubkey.len())]);
        eprintln!(
            "  Recipients now registered: {}",
            locked.recovery_recipients.len()
        );
        Ok(())
    }
}

pub mod list_recovery_recipients {
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
        let locked = load_locked(&dir).context("load identity")?;

        if locked.recovery_recipients.is_empty() {
            println!(
                "No recovery recipients registered. \
                 Use `kit add-recovery-recipient <age1…>` to add one."
            );
            return Ok(());
        }
        println!(
            "Registered recovery recipients ({}):",
            locked.recovery_recipients.len()
        );
        for r in &locked.recovery_recipients {
            let label = r.label.as_deref().unwrap_or("(no label)");
            let prefix = &r.pubkey[..28.min(r.pubkey.len())];
            println!("  - {prefix}… [{label}] added {}", r.added_at);
        }
        Ok(())
    }
}

pub mod remove_recovery_recipient {
    use anyhow::{Context, Result, bail};
    use clap::Args;

    use provcheck_sign::persist::{default_dir, load_locked, save_public_artefacts};

    use super::DataDirOpt;

    #[derive(Debug, Args)]
    pub struct CliArgs {
        #[command(flatten)]
        pub data_dir: DataDirOpt,

        /// Recipient pubkey OR label.
        pub ident: String,

        /// Required acknowledgement. Without this flag the command
        /// refuses to do anything because **existing backups stay
        /// decryptable by the removed recipient forever** —
        /// architectural decision #5.
        #[arg(long)]
        pub i_understand_existing_backups_stay_decryptable: bool,
    }

    pub async fn run(args: CliArgs) -> Result<()> {
        if !args.i_understand_existing_backups_stay_decryptable {
            eprintln!(
                "REFUSING — `kit remove-recovery-recipient` only de-registers \
                 the recipient from future backups. Any age file already \
                 produced during the recipient's registration window STAYS \
                 decryptable by that recipient forever, anywhere a copy \
                 exists. There is no on-format primitive that retroactively \
                 revokes access."
            );
            eprintln!();
            eprintln!(
                "The genuine way to cut a recipient's signing power is \
                 `kit rotate`: produces a fresh fingerprint, revokes the \
                 old one via atproto, and renders the old backup's \
                 signing power moot."
            );
            eprintln!();
            eprintln!(
                "If you understand this and still want to de-register the \
                 recipient, re-run with \
                 --i-understand-existing-backups-stay-decryptable."
            );
            bail!("safety acknowledgement not provided");
        }

        let dir = args
            .data_dir
            .data_dir
            .clone()
            .map(Ok)
            .unwrap_or_else(|| default_dir().context("resolve default data directory"))?;
        let mut locked = load_locked(&dir).context("load identity")?;

        let before = locked.recovery_recipients.len();
        locked
            .recovery_recipients
            .retain(|r| r.pubkey != args.ident && r.label.as_deref() != Some(args.ident.as_str()));
        let removed = before - locked.recovery_recipients.len();
        if removed == 0 {
            bail!("no recovery recipient matched {:?}", args.ident);
        }
        save_public_artefacts(&dir, &locked).context("save identity.json")?;

        eprintln!("✓ De-registered {removed} recipient(s).");
        eprintln!(
            "  Recipients now registered: {}",
            locked.recovery_recipients.len()
        );
        eprintln!();
        eprintln!(
            "REMINDER: any existing backup file produced while this recipient \
             was registered stays decryptable by them forever."
        );
        Ok(())
    }
}

// ----------------------------------------------------------------
// `lock` / `unlock` — Passphrase-cache controls.
// ----------------------------------------------------------------
//
// These exist on the CLI surface for future-compatibility with an
// agent-daemon mode. The kit has no daemon today: each `kit`
// invocation is a fresh process that drops its SecretCache at
// exit. Both commands print an honest "no-op" rather than
// pretending to do something. When a daemon ships these become
// the actual hooks.

pub mod lock {
    use super::DataDirOpt;
    use anyhow::Result;
    use clap::Args;

    #[derive(Debug, Args)]
    pub struct CliArgs {
        #[command(flatten)]
        pub data_dir: DataDirOpt,
    }

    pub async fn run(_args: CliArgs) -> Result<()> {
        eprintln!(
            "kit lock: no-op (no kit-agent daemon yet — each `kit` \
             invocation drops its SecretCache when the process exits). \
             The command exists so future flows that add a daemon \
             don't have to change the CLI surface."
        );
        Ok(())
    }
}

pub mod unlock {
    use super::DataDirOpt;
    use anyhow::Result;
    use clap::Args;

    #[derive(Debug, Args)]
    pub struct CliArgs {
        #[command(flatten)]
        pub data_dir: DataDirOpt,
    }

    pub async fn run(_args: CliArgs) -> Result<()> {
        eprintln!(
            "kit unlock: no-op (no kit-agent daemon yet — cross-process \
             passphrase caching arrives with the daemon)."
        );
        Ok(())
    }
}

// ----------------------------------------------------------------
// `change-passphrase` — Re-encrypt the on-disk key.
// ----------------------------------------------------------------

pub mod change_passphrase {
    use anyhow::{Context, Result, bail};
    use clap::Args;

    use provcheck_sign::persist::{default_dir, load_locked};
    use provcheck_sign::providers::{AgeFileProvider, KeyProvider};
    use provcheck_sign::types::KeyProviderKind;

    use crate::prompts::{new_passphrase, unlock_passphrase};

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
        let locked = load_locked(&dir).context("load identity")?;
        match locked.key_provider {
            KeyProviderKind::Keychain => {
                bail!(
                    "this identity uses the OS keychain backend — there is no \
                     passphrase for the kit to change. Use the OS keychain UI to \
                     manage access controls on the credential directly."
                );
            }
            KeyProviderKind::EncryptedFile => {}
            KeyProviderKind::Yubikey { .. } => bail!(
                "this identity is backed by a Yubikey — the PIV PIN is changed \
                 on the device, not by provcheck-kit. Use `ykman piv access \
                 change-pin` to rotate it."
            ),
        }

        let provider = AgeFileProvider::new();
        let mut unlock = unlock_passphrase();
        let key_pem = provider
            .fetch(&dir, &locked.fingerprint, &mut unlock)
            .context("decrypt existing key file")?;

        let mut new_pp = new_passphrase();
        provider
            .store(&dir, &locked.fingerprint, &key_pem, &mut new_pp)
            .context("re-encrypt key file with new passphrase")?;

        eprintln!("✓ Passphrase changed. signing.key.age re-encrypted with the new key.");
        Ok(())
    }
}

// ----------------------------------------------------------------
// `export-backup <FILE>` / `import-backup <FILE>`
// ----------------------------------------------------------------

pub mod export_backup {
    use std::path::PathBuf;

    use anyhow::{Context, Result, bail};
    use clap::Args;
    use secrecy::SecretString;

    use provcheck_sign::backup::{
        export_with_passphrase, export_with_recipients, resolve_recovery_recipients,
    };
    use provcheck_sign::persist::{default_dir, load_locked};
    use provcheck_sign::providers::{AgeFileProvider, KeyProvider, KeychainProvider};
    use provcheck_sign::types::{KeyProviderKind, UnlockedIdentity};

    use crate::prompts::{new_passphrase, unlock_passphrase};

    use super::DataDirOpt;

    #[derive(Debug, Args)]
    pub struct CliArgs {
        #[command(flatten)]
        pub data_dir: DataDirOpt,

        /// Output path for the backup. Conventionally `.age`.
        pub out: PathBuf,

        /// Encrypt to the registered recovery recipients instead
        /// of prompting for a backup passphrase. Any one recipient
        /// can later decrypt. Errors if no recovery recipients are
        /// registered.
        #[arg(long)]
        pub use_recovery_recipients: bool,

        /// Allow overwriting an existing output file.
        #[arg(long)]
        pub force: bool,
    }

    pub async fn run(args: CliArgs) -> Result<()> {
        if args.out.exists() && !args.force {
            bail!(
                "refusing to overwrite existing file {}. Pass --force to replace.",
                args.out.display()
            );
        }

        let dir = args
            .data_dir
            .data_dir
            .clone()
            .map(Ok)
            .unwrap_or_else(|| default_dir().context("resolve default data directory"))?;
        let locked = load_locked(&dir).context("load identity")?;

        // Unlock to obtain the private key.
        let mut unlock = unlock_passphrase();
        let key_pem = match locked.key_provider {
            KeyProviderKind::Keychain => KeychainProvider::new()
                .fetch(&dir, &locked.fingerprint, &mut unlock)
                .context("fetch key from OS keychain")?,
            KeyProviderKind::EncryptedFile => AgeFileProvider::new()
                .fetch(&dir, &locked.fingerprint, &mut unlock)
                .context("fetch key from encrypted file")?,
            KeyProviderKind::Yubikey { .. } => bail!(
                "Yubikey-backed identities can't be exported — the private \
                 key never leaves the device. To migrate to a new machine, \
                 plug the Yubikey into the destination host and run \
                 `provcheck-kit status` there. To rotate identity, use \
                 `provcheck-kit rotate` (signs a new key + revokes the \
                 old atproto record)."
            ),
        };
        let unlocked = UnlockedIdentity::new(locked.clone(), key_pem);

        let summary = if args.use_recovery_recipients {
            if locked.recovery_recipients.is_empty() {
                bail!(
                    "no recovery recipients registered. \
                     Run `kit add-recovery-recipient <age1…>` first or omit \
                     --use-recovery-recipients to encrypt with a passphrase."
                );
            }
            let recipients = resolve_recovery_recipients(&locked.recovery_recipients)
                .context("parse registered recovery recipients")?;
            export_with_recipients(&unlocked, &args.out, &recipients)?
        } else {
            let mut new_pp = new_passphrase();
            let pass: SecretString = match new_pp(provcheck_sign::providers::NewPassphrasePrompt {
                purpose: "backup",
            }) {
                Ok(p) => p,
                Err(e) => return Err(anyhow::anyhow!("{e}")),
            };
            export_with_passphrase(&unlocked, &args.out, pass)?
        };

        eprintln!("✓ Backup written.");
        eprintln!("  Path:        {}", summary.out_path.display());
        eprintln!("  Fingerprint: {}", summary.fingerprint);
        eprintln!("  Recipients:  {}", summary.recipient_count);
        eprintln!("  Bytes:       {}", summary.written_bytes);
        Ok(())
    }
}

pub mod import_backup {
    use std::path::PathBuf;

    use anyhow::{Context, Result, bail};
    use clap::Args;
    use secrecy::SecretString;

    use provcheck_sign::backup::{import_with_passphrase, import_with_x25519_identity};
    use provcheck_sign::persist::{default_dir, load_locked, save_public_artefacts};
    use provcheck_sign::providers::{AgeFileProvider, KeyProvider, KeychainProvider};
    use provcheck_sign::types::KeyProviderKind;

    use crate::prompts::{new_passphrase, unlock_passphrase};

    use super::DataDirOpt;

    #[derive(Debug, Args)]
    pub struct CliArgs {
        #[command(flatten)]
        pub data_dir: DataDirOpt,

        /// Backup file to restore from.
        pub bundle: PathBuf,

        /// Use the encrypted-file backend after restore.
        #[arg(long)]
        pub age_file: bool,

        /// Allow overwriting an existing identity at the data
        /// directory.
        #[arg(long)]
        pub overwrite: bool,

        /// Path to an age X25519 identity file (e.g. `~/.age/key.txt`,
        /// or rage-keygen's output). Use when restoring a backup
        /// that was exported with `--use-recovery-recipients` (the
        /// X25519-recipient path) rather than the default passphrase
        /// path. The file must contain exactly one `AGE-SECRET-KEY-1…`
        /// line; multi-identity files are not yet supported.
        #[arg(long, value_name = "PATH")]
        pub identity_file: Option<PathBuf>,
    }

    pub async fn run(args: CliArgs) -> Result<()> {
        let dir = args
            .data_dir
            .data_dir
            .clone()
            .map(Ok)
            .unwrap_or_else(|| default_dir().context("resolve default data directory"))?;

        if !args.overwrite && load_locked(&dir).is_ok() {
            bail!(
                "an identity already exists at {}. Pass --overwrite to replace it.",
                dir.display()
            );
        }

        // v0.9.66: wire X25519-recipient backups through the CLI.
        // Branch on --identity-file. The library has supported
        // `import_with_x25519_identity` since v0.4; only the CLI
        // surface was missing.
        let bundle = if let Some(ref id_path) = args.identity_file {
            use std::str::FromStr;
            eprintln!(
                "Decrypting backup at {} with X25519 identity {}…",
                args.bundle.display(),
                id_path.display()
            );
            let id_text = std::fs::read_to_string(id_path)
                .with_context(|| format!("read identity file {}", id_path.display()))?;
            // Pick the first AGE-SECRET-KEY-1 line (rage-keygen's
            // standard format prefixes the actual key with comment
            // lines, so a line-by-line scan is more robust than a
            // whole-file parse).
            let secret_line = id_text
                .lines()
                .find(|line| line.starts_with("AGE-SECRET-KEY-1"))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "{} contains no AGE-SECRET-KEY-1 line; \
                         expected rage-keygen format",
                        id_path.display()
                    )
                })?;
            let identity = age::x25519::Identity::from_str(secret_line.trim())
                .map_err(|e| anyhow::anyhow!("parse identity: {e}"))?;
            import_with_x25519_identity(&args.bundle, &identity)
                .context("decrypt + parse backup with X25519 identity")?
        } else {
            eprintln!("Decrypting backup at {}…", args.bundle.display());
            let mut unlock = unlock_passphrase();
            let pass: SecretString =
                unlock(provcheck_sign::providers::UnlockPrompt::passphrase("backup", 1))
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            import_with_passphrase(&args.bundle, pass).context("decrypt + parse backup")?
        };
        let backend = if args.age_file {
            KeyProviderKind::EncryptedFile
        } else {
            KeyProviderKind::Keychain
        };
        let unlocked = bundle.into_unlocked(Some(backend));

        // Store the private key via the chosen backend, then save
        // the public artefacts.
        let mut new_pp = new_passphrase();
        match backend {
            KeyProviderKind::Keychain => {
                KeychainProvider::new()
                    .store(
                        &dir,
                        &unlocked.locked.fingerprint,
                        unlocked.key_pem(),
                        &mut new_pp,
                    )
                    .context("store key in OS keychain")?;
            }
            KeyProviderKind::EncryptedFile => {
                AgeFileProvider::new()
                    .store(
                        &dir,
                        &unlocked.locked.fingerprint,
                        unlocked.key_pem(),
                        &mut new_pp,
                    )
                    .context("store key in encrypted file")?;
            }
            KeyProviderKind::Yubikey { .. } => {
                // import-backup never targets a Yubikey: a backup file
                // carries a software-extractable PEM, which can't be
                // injected into a hardware token. The `backend` arg is
                // chosen above and never selects Yubikey; this arm
                // exists for match exhaustiveness.
                bail!(
                    "import-backup cannot target a Yubikey backend — \
                     hardware tokens don't accept imported keys. To \
                     bootstrap a Yubikey identity from a fresh device, \
                     use `kit init --backend yubikey`."
                );
            }
        }
        save_public_artefacts(&dir, &unlocked.locked).context("save identity.json")?;

        eprintln!("✓ Identity restored.");
        eprintln!("  Fingerprint: {}", unlocked.locked.fingerprint);
        eprintln!("  Storage:     {}", dir.display());
        Ok(())
    }
}

// ----------------------------------------------------------------
// atproto-side commands (login / logout / publish / list / revoke
// / rotate) and the cross-cutting `verify` shortcut.
//
// These all share the same load-and-resume-session preamble. The
// helpers in this section keep the common shape in one place.
// ----------------------------------------------------------------

async fn load_or_explain_session(
    dir: &std::path::Path,
) -> anyhow::Result<provcheck_publish::AtprotoClient> {
    use provcheck_publish::session::SessionError;
    match provcheck_publish::AtprotoClient::load_session(dir).await {
        Ok(c) => Ok(c),
        // Route session-expired through the KitError variant so
        // main.rs's exit-code mapping returns 3 (CI flows like
        // `kit publish || kit login && kit publish` can distinguish
        // expired-session from network/auth failures).
        Err(SessionError::SessionExpired) => Err(anyhow::Error::from(KitError::SessionExpired)),
        Err(SessionError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Err(
            anyhow::anyhow!("no atproto session on disk — run `kit login` first"),
        ),
        Err(e) => Err(anyhow::anyhow!("load atproto session: {e}")),
    }
}

/// Normalise a user-supplied fingerprint string into a comparable
/// lowercase hex slice (no `sha256:` prefix). Accepts:
/// - `sha256:<hex>` — strips the prefix.
/// - `<hex>` (bare) — passes through after lowercasing.
/// - Short prefixes (≥8 hex chars) — passes through; caller does
///   the prefix match against equally-normalised stored values.
///
/// Returns `Err` for inputs that don't decode as hex or are shorter
/// than 8 chars (too ambiguous to be a useful needle).
pub fn normalise_fingerprint(s: &str) -> Result<String, &'static str> {
    let stripped = s.strip_prefix("sha256:").unwrap_or(s).to_ascii_lowercase();
    if stripped.len() < 8 {
        return Err("fingerprint too short — need at least 8 hex characters");
    }
    if stripped.len() > 64 {
        return Err("fingerprint too long — sha256 produces 64 hex characters");
    }
    if !stripped.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("fingerprint must be hex characters only (0-9, a-f)");
    }
    Ok(stripped)
}

/// Walk an [`anyhow::Error`]'s chain looking for anything that
/// indicates a session-expired condition: a direct
/// [`KitError::SessionExpired`], a [`provcheck_publish::session::SessionError::SessionExpired`]
/// wrapped under `.context()`, or a [`provcheck_publish::records::RecordsError::NoSession`].
/// The `main.rs` exit-code router uses this to route session
/// failures to exit code 3 regardless of where in the call stack
/// they originated.
pub fn is_session_expired(err: &anyhow::Error) -> bool {
    use provcheck_publish::records::RecordsError;
    use provcheck_publish::session::SessionError;
    err.chain().any(|src| {
        if let Some(kit_err) = src.downcast_ref::<KitError>() {
            return matches!(kit_err, KitError::SessionExpired);
        }
        if let Some(sess_err) = src.downcast_ref::<SessionError>() {
            return matches!(sess_err, SessionError::SessionExpired);
        }
        if let Some(rec_err) = src.downcast_ref::<RecordsError>() {
            return matches!(rec_err, RecordsError::NoSession);
        }
        false
    })
}

pub mod login {
    use anyhow::{Context, Result};
    use clap::Args;

    use provcheck_publish::AtprotoClient;
    use provcheck_sign::persist::{default_dir, load_locked, save_public_artefacts};

    use super::DataDirOpt;

    #[derive(Debug, Args)]
    pub struct CliArgs {
        #[command(flatten)]
        pub data_dir: DataDirOpt,

        /// atproto handle (e.g. `creator.bsky.social`) or DID.
        #[arg(long, short = 'u')]
        pub handle: String,

        /// PDS host. Defaults to bsky.social.
        #[arg(long, default_value = "https://bsky.social")]
        pub pds: String,
    }

    pub async fn run(args: CliArgs) -> Result<()> {
        let dir = args
            .data_dir
            .data_dir
            .clone()
            .map(Ok)
            .unwrap_or_else(|| default_dir().context("resolve default data directory"))?;

        // App password input — rpassword hides it.
        eprintln!("atproto app password (NOT your account password):");
        let app_password = rpassword::prompt_password("app password: ")
            .context("read app password from terminal")?;

        let client = AtprotoClient::login(&args.pds, &args.handle, &app_password)
            .await
            .context("atproto login")?;
        client
            .save_session(&dir)
            .await
            .context("persist session to disk")?;

        // Stamp the resolved did + handle onto the local identity so
        // `kit status` and `kit publish` have them without a network
        // call. Optional — login works without a local identity (a
        // user could log in just to `kit list` someone else's flow).
        if let Ok(mut locked) = load_locked(&dir) {
            let snap = client.snapshot();
            locked.did = Some(snap.did.clone());
            locked.handle = Some(snap.handle.clone());
            save_public_artefacts(&dir, &locked).context("stamp did + handle on identity.json")?;
        }

        let snap = client.snapshot();
        eprintln!("✓ Logged in as {} ({}).", snap.handle, snap.did);
        eprintln!("  Session persisted to {}", dir.display());
        Ok(())
    }
}

pub mod logout {
    use anyhow::{Context, Result};
    use clap::Args;

    use provcheck_publish::AtprotoClient;
    use provcheck_sign::persist::default_dir;

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
        AtprotoClient::logout(&dir).context("delete session.json")?;
        eprintln!("✓ Local session deleted.");
        eprintln!(
            "  Note: atproto app-password sessions don't have a server-side \
             revoke endpoint. Anyone with a copy of the refresh JWT can use \
             it until it expires server-side. If you suspect leakage, revoke \
             the app password from bsky.app settings."
        );
        Ok(())
    }
}

pub mod publish {
    use anyhow::{Context, Result, bail};
    use clap::Args;
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    use provcheck_attestation_spec::SigningKeyRecord;
    use provcheck_publish::RecordWriter;
    use provcheck_sign::persist::{default_dir, load_locked};

    use super::DataDirOpt;

    #[derive(Debug, Args)]
    pub struct CliArgs {
        #[command(flatten)]
        pub data_dir: DataDirOpt,

        /// Optional label stored alongside the published record
        /// ("studio mac", "ci server", "live rig").
        #[arg(long, short = 'l')]
        pub label: Option<String>,

        /// Publish even if a record with this fingerprint already
        /// exists in the user's repo. Without this flag the
        /// command refuses to create a duplicate.
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
        let locked = load_locked(&dir).context("load identity")?;
        let client = super::load_or_explain_session(&dir).await?;
        let writer = RecordWriter::new(&client);

        // Refuse to publish a duplicate without --force. Atproto
        // happily creates a second record with the same fingerprint
        // (rkey is server-assigned and different), but that's
        // confusing for the verifier (which trusts the newest active
        // record per fingerprint). Better to surface the dup loudly.
        if !args.force {
            let existing = writer.list_signing_keys().await.context("atproto list")?;
            if existing
                .iter()
                .any(|(_, r)| r.fingerprint == locked.fingerprint)
            {
                bail!(
                    "a record with fingerprint {} already exists in your repo. \
                     Pass --force to publish anyway (creates a second record); \
                     use `kit rotate` if you mean to swap to a fresh fingerprint.",
                    locked.fingerprint
                );
            }
        }

        let created_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .context("format created_at")?;
        let record = SigningKeyRecord {
            created_at,
            fingerprint: locked.fingerprint.clone(),
            algorithm: locked.algorithm.clone(),
            label: args.label.clone(),
            valid_from: None,
            valid_until: None,
            superseded_by: None,
        };
        let at_uri = match writer.publish_signing_key(&record).await {
            Ok(uri) => uri,
            Err(e) => {
                // The publish call's outcome is genuinely
                // ambiguous on connection failures: the request
                // might have reached the PDS and been committed
                // before our connection dropped. Tell the user
                // explicitly so they don't assume "publish failed"
                // means "no record was created" and immediately
                // retry — a retry produces a duplicate if the
                // first one landed. `kit list` is the source of
                // truth.
                eprintln!(
                    "warning: publish outcome unconfirmed. The PDS may or may \
                     not have committed the record. Run `kit list` to check \
                     before retrying — a retry without checking creates a \
                     duplicate if the first call landed."
                );
                return Err(anyhow::anyhow!("atproto publish_signing_key: {e}"));
            }
        };

        // Refresh session-on-disk in case atrium rotated the JWTs
        // during the call. Cheap, keeps subsequent commands working.
        let _ = client.save_session(&dir).await;

        eprintln!("✓ Published.");
        eprintln!("  at-uri:      {}", at_uri);
        eprintln!("  fingerprint: {}", locked.fingerprint);
        if let Some(label) = &args.label {
            eprintln!("  label:       {}", label);
        }
        Ok(())
    }
}

pub mod list {
    use anyhow::{Context, Result};
    use clap::Args;

    use provcheck_publish::RecordWriter;
    use provcheck_sign::persist::default_dir;

    use super::DataDirOpt;

    #[derive(Debug, Args)]
    pub struct CliArgs {
        #[command(flatten)]
        pub data_dir: DataDirOpt,

        /// Emit JSON instead of the human-readable table. Useful
        /// for piping into jq in CI.
        #[arg(long)]
        pub json: bool,
    }

    pub async fn run(args: CliArgs) -> Result<()> {
        let dir = args
            .data_dir
            .data_dir
            .clone()
            .map(Ok)
            .unwrap_or_else(|| default_dir().context("resolve default data directory"))?;
        let client = super::load_or_explain_session(&dir).await?;
        let writer = RecordWriter::new(&client);
        let records = writer.list_signing_keys().await.context("atproto list")?;

        if args.json {
            let payload: Vec<_> = records
                .iter()
                .map(|(uri, r)| {
                    serde_json::json!({
                        "at_uri": uri.as_str(),
                        "record": r,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&payload).context("format json")?
            );
            return Ok(());
        }

        if records.is_empty() {
            println!("No app.provcheck.signingKey records in your repo.");
            println!("Run `kit publish` to publish the current local fingerprint.");
            return Ok(());
        }
        println!("app.provcheck.signingKey records ({}):", records.len());
        for (uri, record) in &records {
            let rkey = uri.rkey().unwrap_or("?");
            let status = describe_status(record);
            println!("  - rkey {rkey}  [{status}]");
            println!("      fingerprint: {}", record.fingerprint);
            println!("      algorithm:   {}", record.algorithm);
            println!("      created:     {}", record.created_at);
            if let Some(label) = &record.label {
                println!("      label:       {}", label);
            }
            if let Some(vu) = &record.valid_until {
                println!("      validUntil:  {}", vu);
            }
            if let Some(s) = &record.superseded_by {
                println!("      supersededBy: {}", s);
            }
        }
        Ok(())
    }

    fn describe_status(r: &provcheck_attestation_spec::SigningKeyRecord) -> &'static str {
        if r.superseded_by.is_some() {
            "superseded"
        } else if r.valid_until.is_some() {
            "revoked"
        } else {
            "active"
        }
    }
}

pub mod revoke {
    use anyhow::{Context, Result, bail};
    use clap::Args;
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    use provcheck_publish::RecordWriter;
    use provcheck_sign::persist::default_dir;

    use super::DataDirOpt;

    #[derive(Debug, Args)]
    pub struct CliArgs {
        #[command(flatten)]
        pub data_dir: DataDirOpt,

        /// Fingerprint of the record to revoke. Accepts any of:
        /// the canonical `sha256:<64-hex>` form, the bare 64-char
        /// hex, or a short prefix (≥8 hex chars) when it
        /// uniquely identifies one record. The match is
        /// case-insensitive.
        pub fingerprint: String,

        /// at-uri of a replacement record (set on the revoked
        /// record as `supersededBy`). Useful when manually
        /// rotating; `kit rotate` fills this in automatically.
        #[arg(long, value_name = "AT-URI")]
        pub superseded_by: Option<String>,
    }

    pub async fn run(args: CliArgs) -> Result<()> {
        let dir = args
            .data_dir
            .data_dir
            .clone()
            .map(Ok)
            .unwrap_or_else(|| default_dir().context("resolve default data directory"))?;
        let client = super::load_or_explain_session(&dir).await?;
        let writer = RecordWriter::new(&client);
        let records = writer.list_signing_keys().await.context("atproto list")?;
        let needle = super::normalise_fingerprint(&args.fingerprint)
            .map_err(|e| anyhow::anyhow!("--fingerprint {:?}: {e}", args.fingerprint))?;
        let matches: Vec<_> = records
            .iter()
            .filter(|(_, r)| {
                super::normalise_fingerprint(&r.fingerprint)
                    .map(|stored| stored.starts_with(&needle))
                    .unwrap_or(false)
            })
            .collect();
        let (uri, mut record) = match matches.as_slice() {
            [] => bail!(
                "no record with fingerprint matching {} in your repo. \
                 Run `kit list` to see active fingerprints.",
                args.fingerprint
            ),
            [single] => (single.0.clone(), single.1.clone()),
            many => {
                eprintln!(
                    "ambiguous: fingerprint prefix {:?} matches {} records:",
                    args.fingerprint,
                    many.len()
                );
                for (uri, r) in many {
                    eprintln!("  - {} → {}", r.fingerprint, uri);
                }
                bail!("rerun with more characters of the fingerprint");
            }
        };
        let rkey = uri
            .rkey()
            .ok_or_else(|| anyhow::anyhow!("matched record has malformed at-uri: {}", uri))?;

        if record.valid_until.is_some() {
            bail!(
                "record at {} is already revoked (validUntil = {}). \
                 Re-running revoke is a no-op.",
                uri,
                record.valid_until.as_deref().unwrap_or("?"),
            );
        }

        record.valid_until = Some(
            OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .context("format validUntil")?,
        );
        record.superseded_by = args.superseded_by.clone();

        writer
            .update_signing_key(rkey, &record)
            .await
            .context("atproto update_signing_key")?;

        eprintln!("✓ Revoked.");
        eprintln!("  at-uri:      {}", uri);
        eprintln!("  fingerprint: {}", record.fingerprint);
        eprintln!(
            "  validUntil:  {}",
            record.valid_until.as_deref().unwrap_or("")
        );
        if let Some(s) = &record.superseded_by {
            eprintln!("  supersededBy: {}", s);
        }
        Ok(())
    }
}

pub mod rotate {
    //! Single-shot key rotation: mint a new keypair, publish its
    //! record, revoke the old record (linked via supersededBy), and
    //! swap the keys/ dir.
    //!
    //! The flow is "best-effort atomic" rather than transactional:
    //! at each step we surface what succeeded and what didn't so a
    //! user whose network dropped mid-rotation can run
    //! `kit list` / `kit revoke` to finish the job manually. A
    //! future `kit reconcile` is the cleaner answer.

    use std::path::PathBuf;

    use anyhow::{Context, Result, bail};
    use clap::Args;
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    use provcheck_attestation_spec::SigningKeyRecord;
    use provcheck_publish::RecordWriter;
    use provcheck_sign::cert::generate;
    use provcheck_sign::persist::{default_dir, load_locked, save_public_artefacts};
    use provcheck_sign::providers::{AgeFileProvider, KeyProvider, KeychainProvider};
    use provcheck_sign::types::{KeyProviderKind, LockedIdentity};

    use crate::prompts::new_passphrase;

    use super::DataDirOpt;

    #[derive(Debug, Args)]
    pub struct CliArgs {
        #[command(flatten)]
        pub data_dir: DataDirOpt,

        /// Optional label for the new published record.
        #[arg(long, short = 'l')]
        pub label: Option<String>,
    }

    pub async fn run(args: CliArgs) -> Result<()> {
        let dir = args
            .data_dir
            .data_dir
            .clone()
            .map(Ok)
            .unwrap_or_else(|| default_dir().context("resolve default data directory"))?;
        let old = load_locked(&dir).context("load current identity")?;
        let client = super::load_or_explain_session(&dir).await?;
        let writer = RecordWriter::new(&client);

        // Resolve the old record's rkey BEFORE we touch anything —
        // saves us a doomed publish if the old fingerprint isn't on
        // atproto in the first place.
        let existing = writer.list_signing_keys().await.context("atproto list")?;
        let old_entry = existing
            .iter()
            .find(|(_, r)| r.fingerprint == old.fingerprint && r.valid_until.is_none())
            .cloned();

        // Step 1: generate fresh keypair.
        let subject = provcheck_sign::cert::SubjectInfo::default();
        let generated = generate(&subject).context("generate new keypair")?;
        let new_fingerprint = generated.fingerprint.clone();
        let new_key_secret = secrecy::SecretString::from(generated.key_pem.clone());

        let new_locked = LockedIdentity {
            chain_pem: generated.chain_pem.clone(),
            fingerprint: new_fingerprint.clone(),
            algorithm: generated.algorithm.clone(),
            did: old.did.clone(),
            handle: old.handle.clone(),
            created_at: OffsetDateTime::now_utc(),
            key_provider: old.key_provider,
            recovery_recipients: old.recovery_recipients.clone(),
        };

        // Step 2: stage the new private key beside the old one
        // under `keys-staging/` (sibling dir of the data dir),
        // then promote on success. Simpler than a rename dance.
        let staging = staging_path_for(&dir);
        std::fs::create_dir_all(&staging).context("create staging dir")?;
        let mut prompt = new_passphrase();
        match new_locked.key_provider {
            KeyProviderKind::Keychain => {
                // Keychain entry is keyed on fingerprint so it doesn't
                // clash with the old one — store directly.
                KeychainProvider::new()
                    .store(&staging, &new_fingerprint, &new_key_secret, &mut prompt)
                    .context("store new key in OS keychain")?;
            }
            KeyProviderKind::EncryptedFile => {
                AgeFileProvider::new()
                    .store(&staging, &new_fingerprint, &new_key_secret, &mut prompt)
                    .context("store new key in encrypted file")?;
            }
            KeyProviderKind::Yubikey { .. } => {
                // Yubikey rotation requires generating the key on-
                // device, not in software — the staging path above
                // generated a software keypair. Yubikey rotation is
                // a follow-up; the workaround is documented below.
                bail!(
                    "Yubikey-backed identities cannot rotate via a plain \
                     `kit rotate` — a software keypair can't replace the \
                     on-device PIV key. Workaround until on-device \
                     rotation lands: use ykman to mint a fresh keypair \
                     on a new slot, then `kit init --backend yubikey \
                     --serial <N> --slot <new-slot>` to register it, \
                     then `kit revoke --fingerprint <old-fingerprint>` \
                     to tombstone the old record."
                );
            }
        }

        // Step 3: publish the new record.
        let created_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .context("format created_at")?;
        let new_record = SigningKeyRecord {
            created_at,
            fingerprint: new_fingerprint.clone(),
            algorithm: new_locked.algorithm.clone(),
            label: args.label.clone(),
            valid_from: None,
            valid_until: None,
            superseded_by: None,
        };
        let new_uri = match writer.publish_signing_key(&new_record).await {
            Ok(uri) => uri,
            Err(e) => {
                eprintln!(
                    "publish of the new key failed — rolling back. The old \
                     identity at {} is untouched and remains the active one.",
                    dir.display()
                );
                let _ = std::fs::remove_dir_all(&staging);
                return Err(anyhow::anyhow!("atproto publish_signing_key: {e}"));
            }
        };

        // Step 4: promote staging → primary. The old data dir gets
        // moved aside to keys-rotated-<old-fp-prefix>/. Failures
        // here are the dangerous case — the new record is already
        // on atproto but the local identity is still the old one.
        // We attempt to delete the orphan published record so the
        // user isn't left with a fingerprint they can't sign with;
        // if the cleanup also fails (rare — network down, etc.),
        // surface BOTH errors so they can finish the cleanup
        // manually.
        let backup_dir = rotated_path_for(&dir, &old.fingerprint);
        if let Err(rename_err) = std::fs::rename(&dir, &backup_dir) {
            let cleanup = cleanup_orphan_published(&writer, &new_uri).await;
            let _ = std::fs::remove_dir_all(&staging);
            return Err(format_partial_rotation_err(
                "move old identity into rotated-out slot",
                &dir,
                &backup_dir,
                rename_err,
                &new_uri,
                cleanup,
            ));
        }
        if let Err(rename_err) = std::fs::rename(&staging, &dir) {
            let cleanup = cleanup_orphan_published(&writer, &new_uri).await;
            // Restore the old identity to its primary location so
            // the user keeps working with their existing key.
            let restore_err = std::fs::rename(&backup_dir, &dir).err();
            let _ = std::fs::remove_dir_all(&staging);
            return Err(format_partial_rotation_err_with_restore(
                "promote staging → primary",
                &staging,
                &dir,
                &backup_dir,
                rename_err,
                restore_err,
                &new_uri,
                cleanup,
            ));
        }
        save_public_artefacts(&dir, &new_locked).context("save new identity.json")?;

        // Step 5: revoke the old record with supersededBy →
        // new_uri. Non-fatal — the user can run
        // `kit revoke <old-fp> --superseded-by <new-uri>` later.
        if let Some((old_uri, mut old_record)) = old_entry {
            let old_rkey = old_uri.rkey().unwrap_or_default().to_string();
            old_record.valid_until = Some(
                OffsetDateTime::now_utc()
                    .format(&Rfc3339)
                    .context("format validUntil")?,
            );
            old_record.superseded_by = Some(new_uri.as_str().to_string());
            match writer.update_signing_key(&old_rkey, &old_record).await {
                Ok(()) => {
                    eprintln!("✓ Old record revoked & linked.");
                }
                Err(e) => {
                    eprintln!(
                        "warning: failed to revoke the old record at {} ({e}). \
                         Run `kit revoke {} --superseded-by {}` to finish.",
                        old_uri, old.fingerprint, new_uri
                    );
                }
            }
        } else {
            eprintln!(
                "note: no active record for the old fingerprint {} was found \
                 on atproto, so nothing to revoke server-side.",
                old.fingerprint
            );
        }

        let _ = client.save_session(&dir).await;

        eprintln!();
        eprintln!("✓ Rotation complete.");
        eprintln!("  Old fingerprint: {}", old.fingerprint);
        eprintln!("  New fingerprint: {}", new_fingerprint);
        eprintln!("  New at-uri:      {}", new_uri);
        eprintln!(
            "  Old data dir:    {} (kept; safe to archive)",
            backup_dir.display()
        );
        Ok(())
    }

    fn staging_path_for(dir: &std::path::Path) -> PathBuf {
        let parent = dir.parent().unwrap_or(std::path::Path::new("."));
        let leaf = dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("provcheck-kit");
        parent.join(format!("{leaf}-staging"))
    }

    fn rotated_path_for(dir: &std::path::Path, old_fingerprint: &str) -> PathBuf {
        // Strip the `sha256:` prefix for the dir name; take a
        // first-8-char slice so the path stays short.
        let fp = old_fingerprint
            .strip_prefix("sha256:")
            .unwrap_or(old_fingerprint);
        let short = &fp[..8.min(fp.len())];
        let parent = dir.parent().unwrap_or(std::path::Path::new("."));
        let leaf = dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("provcheck-kit");
        // Best-effort uniqueness via the fingerprint shard — multiple
        // rotations on the same day are rare, but if one collides
        // the user gets a clear error from std::fs::rename rather
        // than a silent overwrite.
        parent.join(format!("{leaf}-rotated-{short}"))
    }

    /// Attempt to delete a just-published `signingKey` record that
    /// can't be associated with a local key. Returns Ok when the
    /// orphan is gone, Err with the underlying network/atproto
    /// failure when the cleanup itself failed.
    ///
    /// Used by the rotate flow when a filesystem rename fails after
    /// the new record has been published — the publish succeeded
    /// but the local state can't reach the matching key, so the
    /// record is unsignable and serves no purpose. Leaving it
    /// behind would clutter `kit list` and confuse verifiers.
    async fn cleanup_orphan_published(
        writer: &provcheck_publish::RecordWriter<'_>,
        new_uri: &provcheck_publish::AtUri,
    ) -> Result<(), String> {
        let rkey = new_uri
            .rkey()
            .ok_or_else(|| format!("could not parse rkey from {new_uri}"))?;
        writer
            .delete_signing_key(rkey)
            .await
            .map_err(|e| format!("delete_signing_key({rkey}): {e}"))
    }

    fn format_partial_rotation_err(
        step: &str,
        from: &std::path::Path,
        to: &std::path::Path,
        cause: std::io::Error,
        new_uri: &provcheck_publish::AtUri,
        cleanup: Result<(), String>,
    ) -> anyhow::Error {
        let cleanup_msg = match cleanup {
            Ok(()) => format!(
                "the orphan record at {new_uri} was deleted from atproto, \
                 so atproto state is consistent with the (unchanged) local \
                 identity"
            ),
            Err(e) => format!(
                "attempt to clean up the orphan record at {new_uri} also \
                 failed ({e}). Run `kit revoke <new-fingerprint>` (or wait \
                 for connectivity and re-run `kit rotate`) to clear it"
            ),
        };
        anyhow::anyhow!(
            "rotate: failed to {step} ({} → {}): {cause}. {cleanup_msg}",
            from.display(),
            to.display(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn format_partial_rotation_err_with_restore(
        step: &str,
        from: &std::path::Path,
        to: &std::path::Path,
        backup: &std::path::Path,
        cause: std::io::Error,
        restore_err: Option<std::io::Error>,
        new_uri: &provcheck_publish::AtUri,
        cleanup: Result<(), String>,
    ) -> anyhow::Error {
        let cleanup_msg = match cleanup {
            Ok(()) => format!("the orphan record at {new_uri} was deleted from atproto"),
            Err(e) => format!(
                "atproto cleanup of orphan record at {new_uri} also failed ({e}); \
                 run `kit revoke <new-fingerprint>` once connectivity returns"
            ),
        };
        let restore_msg = match restore_err {
            None => format!("the old identity has been restored to {}", to.display()),
            Some(e) => format!(
                "AND the old identity could not be restored to {} either ({e}); \
                 manually rename {} → {} to recover",
                to.display(),
                backup.display(),
                to.display(),
            ),
        };
        anyhow::anyhow!(
            "rotate: failed to {step} ({} → {}): {cause}. {restore_msg}. {cleanup_msg}",
            from.display(),
            to.display(),
        )
    }

    // No end-to-end tests here yet — rotate needs an atproto mock
    // to drive. The path-arithmetic helpers (staging_path_for,
    // rotated_path_for) are pure functions and have direct unit
    // tests below.

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn rotated_path_uses_fingerprint_shard() {
            let dir = std::path::Path::new("/tmp").join("provcheck-kit");
            let p = rotated_path_for(
                &dir,
                "sha256:0123456789abcdef0000000000000000000000000000000000000000000000aa",
            );
            assert_eq!(
                p.file_name().and_then(|s| s.to_str()),
                Some("provcheck-kit-rotated-01234567")
            );
            assert_eq!(p.parent(), dir.parent());
        }

        #[test]
        fn rotated_path_handles_unprefixed_fingerprint() {
            let dir = std::path::Path::new("/tmp").join("provcheck-kit");
            let p = rotated_path_for(&dir, "abc12345");
            assert_eq!(
                p.file_name().and_then(|s| s.to_str()),
                Some("provcheck-kit-rotated-abc12345")
            );
        }

        #[test]
        fn staging_path_is_sibling_of_dir() {
            let dir = std::path::Path::new("/var/data").join("provcheck-kit");
            let p = staging_path_for(&dir);
            assert_eq!(
                p.file_name().and_then(|s| s.to_str()),
                Some("provcheck-kit-staging")
            );
            assert_eq!(p.parent(), dir.parent());
        }
    }
}

pub mod verify {
    //! Convenience shortcut: invoke `provcheck` against the file
    //! rather than the user typing the verifier's name. Useful in
    //! workflows where the kit binary is on PATH but `provcheck`
    //! might not be (or might be at a non-default path the user
    //! resolves via `--provcheck-bin`).

    use std::path::PathBuf;
    use std::process::Command;

    use anyhow::{Context, Result, bail};
    use clap::Args;

    #[derive(Debug, Args)]
    pub struct CliArgs {
        /// Asset to verify.
        pub file: PathBuf,

        /// Override the provcheck binary to invoke. Defaults to
        /// `provcheck` looked up on PATH.
        #[arg(long, default_value = "provcheck", value_name = "PATH")]
        pub provcheck_bin: PathBuf,

        /// Extra args passed through to provcheck. Use `--`
        /// before them to split them from kit's own flags:
        /// `kit verify foo.wav -- --bsky-handle creator.bsky.social`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        pub passthrough: Vec<String>,
    }

    pub async fn run(args: CliArgs) -> Result<()> {
        // Use spawn_blocking so the synchronous Command call doesn't
        // park the runtime's only thread (the binary uses
        // current_thread flavor).
        let provcheck_bin = args.provcheck_bin.clone();
        let file = args.file.clone();
        let passthrough = args.passthrough.clone();
        let status = tokio::task::spawn_blocking(move || {
            Command::new(&provcheck_bin)
                .arg(&file)
                .args(&passthrough)
                .status()
        })
        .await
        .context("join blocking provcheck task")?
        .with_context(|| {
            format!(
                "execute `{}` — is provcheck on PATH? Pass --provcheck-bin to override",
                args.provcheck_bin.display()
            )
        })?;
        if !status.success() {
            bail!(
                "provcheck exited with code {}",
                status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "<signal>".into())
            );
        }
        Ok(())
    }
}

// ----------------------------------------------------------------
// `watermark` — embed a silentcipher mark into an audio file.
// ----------------------------------------------------------------

pub mod watermark {
    //! Stamp a neural watermark into an audio file. Three detector
    //! families supported: `silentcipher` (default; 40-bit ASCII
    //! payload at 44.1 kHz), `audioseal` (16-bit ECC-protected brand
    //! ID at 16 kHz), and `wavmark` (32-bit payload at 16 kHz; first
    //! 16 bits are a fix-pattern, lower 16 bits carry the same
    //! ECC-protected brand ID as audioseal).
    //!
    //! Use case: ffmpeg's loudness-normalisation step destroys the
    //! original render-time mark on long mixed episodes; re-running
    //! this command on the post-normalisation output restores a
    //! detectable mark. Output is WAV. Re-encode to MP3 / AAC
    //! externally — provcheck-kit doesn't bundle an MP3 encoder to
    //! keep the binary small and the supply chain narrow.

    use std::path::PathBuf;
    use std::time::Instant;

    use anyhow::{Context, Result, bail};
    use clap::{Args, ValueEnum};

    use provcheck_watermark::{audio as sc_audio, encode as sc_encode, hparams as sc_hparams};

    /// Watermark family to embed. Default is silentcipher (the
    /// existing v0.3.x behaviour).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
    #[clap(rename_all = "lowercase")]
    pub enum Kind {
        /// silentcipher 40-bit payload @ 44.1 kHz.
        #[default]
        Silentcipher,
        /// AudioSeal 16-bit ECC-protected brand ID @ 16 kHz.
        Audioseal,
        /// WavMark 32-bit payload @ 16 kHz (16-bit fix pattern + 16-bit ECC brand ID).
        Wavmark,
        /// TrustMark-B image watermark (Adobe / CAI). Wired with
        /// full BCH-5 ecosystem interop, so a provcheck-stamped
        /// image round-trips through Adobe's Python TrustMark and
        /// vice versa.
        Image,
    }

    /// Output channel layout for the marked WAV.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
    #[clap(rename_all = "lowercase")]
    pub enum ChannelMode {
        /// Match the input: mono in → mono out, stereo in → stereo
        /// out (per-channel independent embed of the same payload).
        /// 3+ channel input is downmixed to stereo with a one-line
        /// note. This is the v0.5.2 default.
        #[default]
        Auto,
        /// Always emit mono. Input is downmixed by averaging across
        /// all channels. This is the v0.5.1 behaviour.
        Mono,
        /// Always emit stereo. Mono input is duplicated into both
        /// channels (each gets its own embed). Stereo input embeds
        /// L and R independently with the same payload.
        Stereo,
    }

    #[derive(Debug, Args)]
    pub struct CliArgs {
        /// Input audio file (any format symphonia decodes — mp3, wav,
        /// flac, m4a, ogg, opus).
        pub input: PathBuf,

        /// Output WAV path. Convention: end in `.wav`. The kit will
        /// refuse to overwrite an existing file unless `--overwrite`
        /// is passed.
        #[arg(short = 'o', long, value_name = "PATH")]
        pub output: PathBuf,

        /// Watermark family. `silentcipher` (default) uses a 40-bit
        /// payload @ 44.1 kHz; `audioseal` uses a 16-bit ECC-protected
        /// brand ID @ 16 kHz. They embed and decode independently —
        /// for cross-family redundancy run this command twice with
        /// the output of the first as the input of the second.
        #[arg(long, value_enum, default_value_t = Kind::Silentcipher)]
        pub kind: Kind,

        /// (silentcipher) 5-byte payload as 10 hex chars (no
        /// separators). Defaults to the doomscroll.fm brand
        /// `DFM\x01\x00` = `44464d0100`. Examples: `44464d0100`
        /// (doomscroll.fm), `5241490100` (rAIdio). Ignored when
        /// `--kind audioseal`.
        #[arg(long, value_name = "HEX", default_value = "44464d0100")]
        pub payload: String,

        /// (AudioSeal) 5-bit brand identifier from the registry:
        /// `1` = doomscroll, `2` = rAIdio, `3` = vAIdeo. See
        /// `docs/brand-registry.md`. Ignored when
        /// `--kind silentcipher`.
        #[arg(long, value_name = "ID", default_value_t = 1)]
        pub brand_id: u8,

        /// (silentcipher) Target message SDR in dB. Higher = quieter
        /// watermark. silentcipher's training default is 47 dB. Lower
        /// values produce more robust (more audible) marks; raise if
        /// the audio is sensitive (mastered music) and lower if you
        /// expect lossy delivery (low-bitrate MP3 / AAC). Ignored
        /// when `--kind audioseal`.
        #[arg(long, value_name = "DB")]
        pub sdr_db: Option<f32>,

        /// (AudioSeal) Watermark strength multiplier. v0.5.2 default
        /// is `3.0`, raised from the upstream README's `1.0` after
        /// the codec-survival sweep showed `1.0` is too quiet to
        /// self-detect on real-world music content. Pass `--alpha 1`
        /// to restore v0.5.1 behaviour, or `5.0` for cleaner
        /// brand-ID recovery through AAC re-encode. Ignored when
        /// `--kind silentcipher`.
        #[arg(long, value_name = "ALPHA")]
        pub alpha: Option<f32>,

        /// Output channel layout. `auto` (default) matches input
        /// channels; `mono` always downmixes; `stereo` always emits
        /// stereo with per-channel independent embeds of the same
        /// payload. Stereo delivery pipelines should use `auto` or
        /// `stereo` so the mark survives the eventual delivery
        /// downmix-then-upmix; the v0.5.1 mono-only behaviour
        /// loses the mark when ffmpeg upmixes mono → stereo for
        /// AAC delivery.
        #[arg(long, value_enum, default_value_t = ChannelMode::Auto)]
        pub channels: ChannelMode,

        /// Run the matching detector against the freshly-embedded
        /// waveform and report the recovered confidence. Enabled by
        /// default; pass `--no-verify-after-embed` to skip. When
        /// enabled, conf < 0.50 deletes the output file and exits
        /// non-zero so weak marks do not silently propagate.
        ///
        /// v0.5.3 shipped this with `ArgAction::Set` which only
        /// accepted `--verify-after-embed true|false`. v0.5.4
        /// switches to the `SetTrue/SetFalse` pair so both
        /// `--verify-after-embed` and `--no-verify-after-embed`
        /// behave the way the help text claims.
        #[arg(long, default_value_t = true, action = clap::ArgAction::SetTrue, overrides_with = "no_verify_after_embed")]
        pub verify_after_embed: bool,

        /// Skip the verify-after-embed self-test (negation of
        /// `--verify-after-embed`). Use when you have your own
        /// post-embed verification step OR when probing weak SDR /
        /// alpha values where the self-test would otherwise refuse
        /// to write the output.
        #[arg(long = "no-verify-after-embed", action = clap::ArgAction::SetTrue, overrides_with = "verify_after_embed")]
        pub no_verify_after_embed: bool,

        /// (silentcipher only) Memory budget knob. `default` keeps
        /// v0.6.0 P1's auto-cap (up to 4 chunks in parallel). `low`
        /// forces a single chunk at a time, peaking at one tract
        /// intermediate buffer instead of up to four. Use `low` on
        /// memory-constrained hosts where the orchestrator already
        /// runs 4+ workers wide. v0.6.0 P3 phase 3d. AudioSeal and
        /// WavMark embed paths are unaffected (they already process
        /// chunks sequentially).
        #[arg(long, value_enum, default_value_t = MemoryBudget::Default)]
        pub memory_budget: MemoryBudget,

        /// Overwrite the output file if it already exists.
        #[arg(long)]
        pub overwrite: bool,
    }

    /// Memory budget for the silentcipher embed chunk loop. See the
    /// `--memory-budget` flag docs above for the full rationale.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
    #[clap(rename_all = "lowercase")]
    pub enum MemoryBudget {
        /// Auto-cap chunk parallelism via the same formula the
        /// detector uses: `clamp(cores/2, 1, 4)`. v0.6.0 P1 default.
        #[default]
        Default,
        /// Force sequential chunk processing. Peak RSS drops by
        /// roughly 4x at the cost of 2.5-3x slower wall clock.
        Low,
        /// v0.6.0 P3 chunk-fused streaming embed. Two-pass design:
        /// no full spectrogram is ever materialised. Peak RSS drops
        /// by roughly 3-4x vs `default`, at the cost of about
        /// 10-20% extra wall clock for the streaming utterance_norm
        /// pre-pass plus the repeated per-chunk forward STFTs.
        /// Stereo runs the two mono passes sequentially.
        Streaming,
    }

    impl MemoryBudget {
        pub fn max_parallel_chunks(self) -> Option<usize> {
            match self {
                Self::Default => None,
                Self::Low | Self::Streaming => Some(1),
            }
        }

        pub fn is_streaming(self) -> bool {
            matches!(self, Self::Streaming)
        }
    }

    fn parse_payload_hex(s: &str) -> Result<[u8; 5]> {
        let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        if cleaned.len() != 10 {
            bail!(
                "--payload must be exactly 5 bytes (10 hex chars), got {} chars",
                cleaned.len()
            );
        }
        let mut out = [0u8; 5];
        for i in 0..5 {
            out[i] = u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16)
                .with_context(|| format!("parse byte {i}"))?;
        }
        Ok(out)
    }

    pub async fn run(args: CliArgs) -> Result<()> {
        if !args.overwrite && args.output.exists() {
            bail!(
                "output exists: {} (pass --overwrite to replace)",
                args.output.display()
            );
        }

        match args.kind {
            Kind::Silentcipher => embed_silentcipher(args).await,
            Kind::Audioseal => embed_audioseal(args).await,
            Kind::Wavmark => embed_wavmark(args).await,
            Kind::Image => embed_image(args).await,
        }
    }

    fn resolve_output_channels(mode: ChannelMode, source_channels: u16) -> u16 {
        match mode {
            ChannelMode::Mono => 1,
            ChannelMode::Stereo => 2,
            ChannelMode::Auto => {
                if source_channels >= 2 {
                    2
                } else {
                    1
                }
            }
        }
    }

    #[cfg(test)]
    mod parse_payload_hex_tests {
        use super::parse_payload_hex;

        #[test]
        fn dfm_payload_round_trips() {
            // doomscroll.fm: b"DFM\x01\x00" → "44464d0100"
            let bytes = parse_payload_hex("44464d0100").expect("ok");
            assert_eq!(bytes, [b'D', b'F', b'M', 0x01, 0x00]);
        }

        #[test]
        fn rai_payload_round_trips() {
            // rAIdio.bot: b"RAI\x01\x00" → "5241490100"
            let bytes = parse_payload_hex("5241490100").expect("ok");
            assert_eq!(bytes, [b'R', b'A', b'I', 0x01, 0x00]);
        }

        #[test]
        fn whitespace_in_input_is_tolerated() {
            // Operator-friendly: copy-pasted strings often pick up
            // spaces. The parser strips them.
            assert_eq!(
                parse_payload_hex("5241 4901 00").expect("ok"),
                [b'R', b'A', b'I', 0x01, 0x00]
            );
            assert_eq!(
                parse_payload_hex("44 46 4d 01 00").expect("ok"),
                [b'D', b'F', b'M', 0x01, 0x00]
            );
        }

        #[test]
        fn wrong_length_input_errors_with_count() {
            let r = parse_payload_hex("4446");
            assert!(r.is_err());
            let msg = format!("{}", r.err().unwrap());
            assert!(msg.contains("10 hex chars"), "expected length hint, got: {msg}");
            assert!(msg.contains("got 4"), "expected got-count, got: {msg}");
        }

        #[test]
        fn empty_input_errors() {
            let r = parse_payload_hex("");
            assert!(r.is_err());
            let msg = format!("{}", r.err().unwrap());
            assert!(msg.contains("got 0"), "expected got-0, got: {msg}");
        }

        #[test]
        fn non_hex_chars_error_with_byte_position() {
            // 'g' is not a valid hex digit; the parser names the
            // byte index in the error chain.
            let r = parse_payload_hex("4446gg0100");
            assert!(r.is_err());
            let msg = format!("{:#}", r.err().unwrap());
            assert!(msg.contains("byte 2"), "expected byte index in error, got: {msg}");
        }

        #[test]
        fn uppercase_hex_accepted() {
            let bytes = parse_payload_hex("5241490100").expect("ok");
            let upper = parse_payload_hex("5241490100".to_uppercase().as_str()).expect("ok");
            assert_eq!(bytes, upper);
        }

        #[test]
        fn mixed_case_hex_accepted() {
            // u8::from_str_radix is case-insensitive for hex.
            assert_eq!(
                parse_payload_hex("5241AbcdEF").expect("ok"),
                parse_payload_hex("5241abcdef").expect("ok")
            );
        }

        #[test]
        fn all_zeros_payload_round_trips() {
            // Edge corner of the 40-bit space.
            assert_eq!(parse_payload_hex("0000000000").expect("ok"), [0u8; 5]);
        }

        #[test]
        fn all_ones_payload_round_trips() {
            // Other edge corner.
            assert_eq!(parse_payload_hex("ffffffffff").expect("ok"), [0xFFu8; 5]);
        }

        #[test]
        fn tabs_and_newlines_also_tolerated_as_whitespace() {
            // is_whitespace catches \t and \n, not just spaces.
            // Copy-paste from shell pipes is a common operator
            // workflow; pin the broader whitespace acceptance.
            let with_tabs = "44\t46\t4d\t01\t00";
            let with_newline = "44\n46\n4d\n01\n00";
            assert_eq!(
                parse_payload_hex(with_tabs).expect("ok"),
                [b'D', b'F', b'M', 0x01, 0x00]
            );
            assert_eq!(
                parse_payload_hex(with_newline).expect("ok"),
                [b'D', b'F', b'M', 0x01, 0x00]
            );
        }

        #[test]
        fn nine_chars_just_below_required_length_errors() {
            // 9 chars — one below the documented 10. Pin the
            // strict-length boundary.
            let r = parse_payload_hex("123456789");
            assert!(r.is_err());
            let msg = format!("{}", r.err().unwrap());
            assert!(msg.contains("got 9"));
        }

        #[test]
        fn eleven_chars_just_above_required_length_errors() {
            let r = parse_payload_hex("1234567890a");
            assert!(r.is_err());
            let msg = format!("{}", r.err().unwrap());
            assert!(msg.contains("got 11"));
        }
    }

    #[cfg(test)]
    mod resolve_output_channels_tests {
        use super::{ChannelMode, resolve_output_channels};

        #[test]
        fn mono_mode_always_emits_mono() {
            // Mono mode is the user saying "I want mono out".
            // Source channel count is irrelevant.
            assert_eq!(resolve_output_channels(ChannelMode::Mono, 1), 1);
            assert_eq!(resolve_output_channels(ChannelMode::Mono, 2), 1);
            assert_eq!(resolve_output_channels(ChannelMode::Mono, 6), 1);
        }

        #[test]
        fn stereo_mode_always_emits_stereo() {
            // Stereo mode forces stereo output. Mono input gets
            // upmixed to two-channel.
            assert_eq!(resolve_output_channels(ChannelMode::Stereo, 1), 2);
            assert_eq!(resolve_output_channels(ChannelMode::Stereo, 2), 2);
            assert_eq!(resolve_output_channels(ChannelMode::Stereo, 6), 2);
        }

        #[test]
        fn auto_mode_matches_source_for_mono_and_stereo() {
            assert_eq!(resolve_output_channels(ChannelMode::Auto, 1), 1);
            assert_eq!(resolve_output_channels(ChannelMode::Auto, 2), 2);
        }

        #[test]
        fn auto_mode_downmixes_multichannel_to_stereo() {
            // Surround source (5.1, 7.1) → stereo. The kit's
            // embed path doesn't carry > 2 channels.
            assert_eq!(resolve_output_channels(ChannelMode::Auto, 3), 2);
            assert_eq!(resolve_output_channels(ChannelMode::Auto, 6), 2);
            assert_eq!(resolve_output_channels(ChannelMode::Auto, 8), 2);
        }
    }

    async fn embed_silentcipher(args: CliArgs) -> Result<()> {
        let payload = parse_payload_hex(&args.payload)?;
        let sdr_user = args.sdr_db;
        let sdr_effective = sdr_user.unwrap_or(sc_encode::DEFAULT_MESSAGE_SDR_DB);
        let sdr_note = if sdr_user.is_none() {
            " (v0.5.2 delivery default; pass --sdr-db 47 for max imperceptibility)"
        } else {
            ""
        };

        eprintln!(
            "provcheck-kit: decoding {} (silentcipher)",
            args.input.display()
        );

        let input = args.input.clone();
        let mode = args.channels;
        let stereo = tokio::task::spawn_blocking(move || sc_audio::decode_to_stereo_44k1(&input))
            .await
            .context("join audio decode task")?
            .with_context(|| format!("decode {}", args.input.display()))?;
        let source_channels = stereo.source_channels;
        let duration_s = stereo.left.len() as f32 / sc_hparams::SAMPLE_RATE as f32;
        let out_channels = resolve_output_channels(mode, source_channels);
        eprintln!(
            "provcheck-kit:   {} samples ({:.2} s @ {} Hz, source {} channel{}, output {} channel{})",
            stereo.left.len(),
            duration_s,
            sc_hparams::SAMPLE_RATE,
            source_channels,
            if source_channels == 1 { "" } else { "s" },
            out_channels,
            if out_channels == 1 { "" } else { "s" },
        );

        eprintln!(
            "provcheck-kit: embedding {:02x?} (SDR {} dB{})",
            payload, sdr_effective, sdr_note
        );

        let embed_config = sc_encode::EmbedConfig {
            max_parallel_chunks: args.memory_budget.max_parallel_chunks(),
        };
        let streaming = args.memory_budget.is_streaming();
        let t0 = Instant::now();
        let (marked_l, marked_r): (Vec<f32>, Option<Vec<f32>>) = if out_channels == 2 {
            let left = stereo.left;
            let right = stereo.right;
            let (l, r) = tokio::task::spawn_blocking(move || -> Result<(Vec<f32>, Vec<f32>), sc_encode::EncodeError> {
                if streaming {
                    let l = sc_encode::embed_streaming_with_config(&left, payload, sdr_user, embed_config)?;
                    let r = sc_encode::embed_streaming_with_config(&right, payload, sdr_user, embed_config)?;
                    Ok((l, r))
                } else {
                    sc_encode::embed_stereo_with_config(&left, &right, payload, sdr_user, embed_config)
                }
            })
            .await
            .context("join embed task")?
            .context("silentcipher stereo embed failed")?;
            (l, Some(r))
        } else {
            // Mono output. If the source was stereo and we are
            // forcing mono, downmix L and R before the single embed.
            let mono = if source_channels >= 2 {
                stereo
                    .left
                    .iter()
                    .zip(stereo.right.iter())
                    .map(|(l, r)| (l + r) * 0.5)
                    .collect::<Vec<f32>>()
            } else {
                stereo.left
            };
            let m = tokio::task::spawn_blocking(move || {
                if streaming {
                    sc_encode::embed_streaming_with_config(&mono, payload, sdr_user, embed_config)
                } else {
                    sc_encode::embed_with_config(&mono, payload, sdr_user, embed_config)
                }
            })
            .await
            .context("join embed task")?
            .context("silentcipher embed failed")?;
            (m, None)
        };
        let embed_elapsed = t0.elapsed();
        eprintln!(
            "provcheck-kit:   embed wall-clock {:.2?} ({:.2}x real-time)",
            embed_elapsed,
            embed_elapsed.as_secs_f32() / duration_s.max(1e-6)
        );

        write_wav(
            &args.output,
            marked_l.as_slice(),
            marked_r.as_deref(),
            sc_hparams::SAMPLE_RATE,
        )
        .await?;

        if args.verify_after_embed && !args.no_verify_after_embed {
            verify_after_embed(&args.output, Kind::Silentcipher).await?;
        }
        eprintln!("provcheck-kit: done.");
        Ok(())
    }

    async fn embed_audioseal(args: CliArgs) -> Result<()> {
        use provcheck_audioseal::{audio as as_audio, encode as as_encode, registry};

        // Validate brand ID before downloading + tract-loading the
        // generator; cheap and gives a clear error.
        if args.brand_id > registry::ID_MASK {
            bail!(
                "--brand-id {} doesn't fit in 5 bits (max {})",
                args.brand_id,
                registry::ID_MASK
            );
        }

        let alpha_user = args.alpha;
        let alpha_effective = alpha_user.unwrap_or(as_encode::DEFAULT_ALPHA);
        let alpha_note = if alpha_user.is_none() {
            " (v0.5.2 delivery default; pass --alpha 1.0 for max imperceptibility, 5.0 for cleaner AAC brand recovery)"
        } else {
            ""
        };

        eprintln!(
            "provcheck-kit: decoding {} (audioseal)",
            args.input.display()
        );

        let input = args.input.clone();
        let mode = args.channels;
        let stereo = tokio::task::spawn_blocking(move || as_audio::decode_to_stereo_16k(&input))
            .await
            .context("join audio decode task")?
            .with_context(|| format!("decode {}", args.input.display()))?;
        let source_channels = stereo.source_channels;
        let duration_s = stereo.left.len() as f32 / as_audio::SAMPLE_RATE as f32;
        let out_channels = resolve_output_channels(mode, source_channels);
        eprintln!(
            "provcheck-kit:   {} samples ({:.2} s @ {} Hz, source {} channel{}, output {} channel{})",
            stereo.left.len(),
            duration_s,
            as_audio::SAMPLE_RATE,
            source_channels,
            if source_channels == 1 { "" } else { "s" },
            out_channels,
            if out_channels == 1 { "" } else { "s" },
        );

        eprintln!(
            "provcheck-kit: embedding brand id 0x{:02x} (alpha {}{})",
            args.brand_id, alpha_effective, alpha_note
        );

        let brand_id = args.brand_id;
        let alpha = args.alpha;
        let t0 = Instant::now();
        let (marked_l, marked_r): (Vec<f32>, Option<Vec<f32>>) = if out_channels == 2 {
            let left = stereo.left;
            let right = stereo.right;
            let (l, r) = tokio::task::spawn_blocking(move || {
                as_encode::embed_stereo(&left, &right, brand_id, alpha)
            })
            .await
            .context("join embed task")?
            .context("audioseal stereo embed failed")?;
            (l, Some(r))
        } else {
            let mono = if source_channels >= 2 {
                stereo
                    .left
                    .iter()
                    .zip(stereo.right.iter())
                    .map(|(l, r)| (l + r) * 0.5)
                    .collect::<Vec<f32>>()
            } else {
                stereo.left
            };
            let m =
                tokio::task::spawn_blocking(move || as_encode::embed(&mono, brand_id, alpha))
                    .await
                    .context("join embed task")?
                    .context("audioseal embed failed")?;
            (m, None)
        };
        let embed_elapsed = t0.elapsed();
        eprintln!(
            "provcheck-kit:   embed wall-clock {:.2?} ({:.2}x real-time)",
            embed_elapsed,
            embed_elapsed.as_secs_f32() / duration_s.max(1e-6)
        );

        write_wav(
            &args.output,
            marked_l.as_slice(),
            marked_r.as_deref(),
            as_audio::SAMPLE_RATE,
        )
        .await?;

        if args.verify_after_embed && !args.no_verify_after_embed {
            verify_after_embed(&args.output, Kind::Audioseal).await?;
        }
        eprintln!("provcheck-kit: done.");
        Ok(())
    }

    async fn embed_wavmark(args: CliArgs) -> Result<()> {
        use provcheck_wavmark::{audio as wm_audio, encode as wm_encode, registry};

        if args.brand_id > registry::ID_MASK {
            bail!(
                "--brand-id {} doesn't fit in 5 bits (max {})",
                args.brand_id,
                registry::ID_MASK
            );
        }

        eprintln!(
            "provcheck-kit: decoding {} (wavmark)",
            args.input.display()
        );

        // v0.9.63: wavmark stereo dispatch lands. Mirrors the
        // audioseal path: decode the full stereo, decide whether
        // to embed two-channel or downmix-to-mono based on
        // --channels + source channel count, then route through
        // the matching wavmark embed entry point.
        let input = args.input.clone();
        let mode = args.channels;
        let stereo =
            tokio::task::spawn_blocking(move || wm_audio::decode_to_stereo_16k(&input))
                .await
                .context("join audio decode task")?
                .with_context(|| format!("decode {}", args.input.display()))?;
        let source_channels = stereo.source_channels;
        let duration_s = stereo.left.len() as f32 / wm_audio::SAMPLE_RATE as f32;
        let out_channels = resolve_output_channels(mode, source_channels);
        eprintln!(
            "provcheck-kit:   {} samples ({:.2} s @ {} Hz, source {} channel{}, output {} channel{})",
            stereo.left.len(),
            duration_s,
            wm_audio::SAMPLE_RATE,
            source_channels,
            if source_channels == 1 { "" } else { "s" },
            out_channels,
            if out_channels == 1 { "" } else { "s" },
        );

        eprintln!(
            "provcheck-kit: embedding brand id 0x{:02x}",
            args.brand_id
        );
        let brand_id = args.brand_id;
        let t0 = Instant::now();
        let (marked_l, marked_r): (Vec<f32>, Option<Vec<f32>>) = if out_channels == 2 {
            let left = stereo.left;
            let right = stereo.right;
            let (l, r) = tokio::task::spawn_blocking(move || {
                wm_encode::embed_stereo(&left, &right, brand_id)
            })
            .await
            .context("join embed task")?
            .context("wavmark stereo embed failed")?;
            (l, Some(r))
        } else {
            let mono = if source_channels >= 2 {
                stereo
                    .left
                    .iter()
                    .zip(stereo.right.iter())
                    .map(|(l, r)| (l + r) * 0.5)
                    .collect::<Vec<f32>>()
            } else {
                stereo.left
            };
            let m = tokio::task::spawn_blocking(move || wm_encode::embed(&mono, brand_id))
                .await
                .context("join embed task")?
                .context("wavmark embed failed")?;
            (m, None)
        };
        let embed_elapsed = t0.elapsed();
        eprintln!(
            "provcheck-kit:   embed wall-clock {:.2?} ({:.2}x real-time)",
            embed_elapsed,
            embed_elapsed.as_secs_f32() / duration_s.max(1e-6)
        );

        write_wav(
            &args.output,
            marked_l.as_slice(),
            marked_r.as_deref(),
            wm_audio::SAMPLE_RATE,
        )
        .await?;

        if args.verify_after_embed && !args.no_verify_after_embed {
            verify_after_embed(&args.output, Kind::Wavmark).await?;
        }
        eprintln!("provcheck-kit: done.");
        Ok(())
    }

    async fn write_wav(
        output: &std::path::Path,
        left: &[f32],
        right: Option<&[f32]>,
        sample_rate: u32,
    ) -> Result<()> {
        let channels: u16 = if right.is_some() { 2 } else { 1 };
        eprintln!(
            "provcheck-kit: writing WAV to {} ({} channel{})",
            output.display(),
            channels,
            if channels == 1 { "" } else { "s" }
        );
        let output_path = output.to_path_buf();
        let left_owned = left.to_vec();
        let right_owned = right.map(|r| r.to_vec());
        tokio::task::spawn_blocking(move || -> Result<()> {
            let spec = hound::WavSpec {
                channels,
                sample_rate,
                bits_per_sample: 32,
                sample_format: hound::SampleFormat::Float,
            };
            let mut writer = hound::WavWriter::create(&output_path, spec)
                .with_context(|| format!("create {}", output_path.display()))?;
            match right_owned {
                None => {
                    for s in &left_owned {
                        writer.write_sample(*s).context("write sample")?;
                    }
                }
                Some(r) => {
                    let n = left_owned.len().min(r.len());
                    for i in 0..n {
                        writer
                            .write_sample(left_owned[i])
                            .context("write left sample")?;
                        writer.write_sample(r[i]).context("write right sample")?;
                    }
                }
            }
            writer.finalize().context("finalize WAV")
        })
        .await
        .context("join WAV write task")??;
        Ok(())
    }

    async fn embed_image(args: CliArgs) -> Result<()> {
        use provcheck_image::encode as img_encode;
        let brand_id = if args.brand_id == 0 { 2 } else { args.brand_id }; // default RAIDIO
        if args.output.exists() && !args.overwrite {
            bail!(
                "output exists; pass --overwrite to replace: {}",
                args.output.display()
            );
        }
        let input = args.input.clone();
        let output = args.output.clone();
        eprintln!(
            "provcheck-kit: embedding TrustMark-B (brand_id={brand_id}) into {} -> {}",
            input.display(),
            output.display()
        );
        let t0 = Instant::now();
        tokio::task::spawn_blocking(move || -> Result<()> {
            img_encode::embed(&input, &output, brand_id)
                .with_context(|| "TrustMark embed failed")
        })
        .await
        .context("join image embed task")??;
        let elapsed = t0.elapsed();
        eprintln!("provcheck-kit:   embed wall-clock {:.2?}", elapsed);
        Ok(())
    }

    /// Run the matching detector against the freshly-written WAV and
    /// report the recovered confidence. Acts on the file on disk so
    /// it exercises the same code path a downstream verifier would
    /// use. Three outcomes:
    ///
    /// - conf >= 0.85: print confirmation, return Ok.
    /// - 0.50 <= conf < 0.85: print thin-margin warning, return Ok.
    /// - conf < 0.50: print error, delete the output file, return Err.
    ///
    /// The third case prevents weak marks from silently propagating
    /// to downstream pipelines that trust the kit's exit code.
    async fn verify_after_embed(output: &std::path::Path, kind: Kind) -> Result<()> {
        let path = output.to_path_buf();
        let kind_name = match kind {
            Kind::Silentcipher => "silentcipher",
            Kind::Audioseal => "audioseal",
            Kind::Wavmark => "wavmark",
            Kind::Image => "trustmark",
        };
        let (conf, payload_ok) = tokio::task::spawn_blocking(move || -> Result<(f32, bool)> {
            let result = match kind {
                Kind::Silentcipher => provcheck_watermark::detect(&path)
                    .with_context(|| "silentcipher verify failed")?,
                Kind::Audioseal => provcheck_audioseal::detect(&path)
                    .with_context(|| "audioseal verify failed")?,
                Kind::Wavmark => provcheck_wavmark::detect(&path)
                    .with_context(|| "wavmark verify failed")?,
                Kind::Image => provcheck_image::detect(&path)
                    .with_context(|| "trustmark verify failed")?,
            };
            let payload_ok = result.payload.is_some();
            Ok((result.confidence, payload_ok))
        })
        .await
        .context("join verify task")??;

        if conf >= 0.85 {
            eprintln!(
                "provcheck-kit: verify-after-embed: {kind_name} conf {conf:.3} OK (payload {})",
                if payload_ok { "recovered" } else { "MISSING" }
            );
            Ok(())
        } else if conf >= 0.50 {
            eprintln!(
                "provcheck-kit: verify-after-embed: WARNING — {kind_name} conf {conf:.3} thin (payload {}); consider a stronger embed knob (--sdr-db lower for silentcipher, --alpha higher for audioseal)",
                if payload_ok { "recovered" } else { "MISSING" }
            );
            Ok(())
        } else {
            // Delete the output file so weak marks do not silently
            // propagate to downstream pipelines.
            let display = output.display().to_string();
            let _ = tokio::fs::remove_file(output).await;
            bail!(
                "verify-after-embed: {kind_name} conf {conf:.3} below 0.50 threshold; deleted {display}. \
                 Try a stronger embed (--sdr-db lower for silentcipher, --alpha higher for audioseal). \
                 Pass --no-verify-after-embed to bypass this gate."
            );
        }
    }

    #[cfg(test)]
    mod tests {
        use super::parse_payload_hex;

        #[test]
        fn parse_dfm_payload() {
            let p = parse_payload_hex("44464d0100").unwrap();
            assert_eq!(p, [0x44, 0x46, 0x4d, 0x01, 0x00]);
        }

        #[test]
        fn parse_rejects_short_payload() {
            assert!(parse_payload_hex("44464d01").is_err());
        }

        #[test]
        fn parse_rejects_non_hex() {
            assert!(parse_payload_hex("44464d010g").is_err());
        }
    }
}

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
        let names: Vec<&str> = cmd.get_subcommands().map(|c| c.get_name()).collect();
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
    fn parse_sign_takes_file_arg() {
        let cli = Cli::try_parse_from(["provcheck-kit", "sign", "foo.wav"]).expect("parse");
        match cli.command {
            Command::Sign(args) => assert_eq!(args.file, std::path::Path::new("foo.wav")),
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parse_sign_without_file_is_rejected() {
        assert!(Cli::try_parse_from(["provcheck-kit", "sign"]).is_err());
    }

    #[test]
    fn parse_revoke_requires_fingerprint() {
        // revoke takes a positional fingerprint and an optional
        // --superseded-by at-uri; without the fingerprint the
        // parse fails.
        assert!(Cli::try_parse_from(["provcheck-kit", "revoke"]).is_err());
        let ok = Cli::try_parse_from([
            "provcheck-kit",
            "revoke",
            "sha256:abc",
            "--superseded-by",
            "at://did:plc:x/app.provcheck.signingKey/abc",
        ])
        .expect("parse");
        match ok.command {
            Command::Revoke(args) => {
                assert_eq!(args.fingerprint, "sha256:abc");
                assert_eq!(
                    args.superseded_by.as_deref(),
                    Some("at://did:plc:x/app.provcheck.signingKey/abc")
                );
            }
            _ => panic!("wrong subcommand"),
        }
    }

    // ----- normalise_fingerprint additional edges ----------

    #[test]
    fn normalise_fingerprint_accepts_minimum_8_chars() {
        // The documented inclusive lower bound for "ambiguous
        // but useful prefix match". Pin so a future tighten
        // doesn't silently break short-prefix lookups.
        let r = super::normalise_fingerprint("abcdef01");
        assert!(r.is_ok(), "8-char hex prefix must be accepted");
        assert_eq!(r.unwrap(), "abcdef01");
    }

    #[test]
    fn normalise_fingerprint_rejects_7_chars_just_below_min() {
        let r = super::normalise_fingerprint("abcdef0");
        assert!(r.is_err());
    }

    #[test]
    fn normalise_fingerprint_rejects_65_chars_just_above_max() {
        let r = super::normalise_fingerprint(&"a".repeat(65));
        assert!(r.is_err());
    }

    #[test]
    fn normalise_fingerprint_accepts_64_chars_at_max() {
        let r = super::normalise_fingerprint(&"a".repeat(64));
        assert!(r.is_ok());
        assert_eq!(r.unwrap().len(), 64);
    }

    #[test]
    fn normalise_fingerprint_round_trips_idempotently() {
        let once = super::normalise_fingerprint("sha256:abcdef0123456789").expect("ok");
        let twice = super::normalise_fingerprint(&once).expect("ok");
        assert_eq!(once, twice);
    }

    #[test]
    fn normalise_fingerprint_empty_string_is_too_short() {
        let r = super::normalise_fingerprint("");
        assert!(r.is_err());
        let msg = r.unwrap_err();
        assert!(msg.contains("short"));
    }

    #[test]
    fn is_session_expired_catches_direct_kit_error() {
        let err = anyhow::Error::from(KitError::SessionExpired);
        assert!(super::is_session_expired(&err));
    }

    #[test]
    fn is_session_expired_catches_session_error_chain() {
        // SessionError::SessionExpired wrapped under .context() — the
        // common shape errors travel through publish/list/etc.
        let inner: anyhow::Error = provcheck_publish::session::SessionError::SessionExpired.into();
        let wrapped = inner.context("atproto session reload");
        assert!(super::is_session_expired(&wrapped));
    }

    #[test]
    fn is_session_expired_catches_records_no_session() {
        let inner: anyhow::Error = provcheck_publish::records::RecordsError::NoSession.into();
        let wrapped = inner.context("atproto publish");
        assert!(super::is_session_expired(&wrapped));
    }

    #[test]
    fn is_session_expired_ignores_unrelated_errors() {
        let err = anyhow::anyhow!("file not found");
        assert!(!super::is_session_expired(&err));
    }

    #[test]
    fn normalise_fingerprint_strips_sha256_prefix() {
        let got = super::normalise_fingerprint(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("ok");
        assert_eq!(
            got,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn normalise_fingerprint_accepts_bare_hex() {
        let got = super::normalise_fingerprint(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("ok");
        assert_eq!(got.len(), 64);
    }

    #[test]
    fn normalise_fingerprint_lowercases_input() {
        let got = super::normalise_fingerprint(
            "SHA256:0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        );
        // The prefix-strip is case-sensitive on "sha256:" — uppercase
        // SHA256: doesn't strip, which means the whole string fails
        // hex validation. This is intentional; the wire format uses
        // lowercase exclusively.
        assert!(got.is_err(), "uppercase SHA256: prefix not stripped");
        // The hex chars themselves DO normalise to lowercase though.
        let got2 = super::normalise_fingerprint(
            "sha256:0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        )
        .expect("ok");
        assert!(
            got2.chars().all(|c| !c.is_uppercase()),
            "lowercased: {got2}"
        );
    }

    #[test]
    fn normalise_fingerprint_accepts_short_prefix() {
        let got = super::normalise_fingerprint("bce94497").expect("ok");
        assert_eq!(got, "bce94497");
    }

    #[test]
    fn normalise_fingerprint_rejects_too_short() {
        let err = super::normalise_fingerprint("bce9449").expect_err("rejected");
        assert!(err.contains("too short"), "{err}");
    }

    #[test]
    fn normalise_fingerprint_rejects_non_hex() {
        let err = super::normalise_fingerprint("zzzzzzzz").expect_err("rejected");
        assert!(err.contains("hex"), "{err}");
    }

    #[test]
    fn normalise_fingerprint_rejects_too_long() {
        let err = super::normalise_fingerprint(&"a".repeat(65)).expect_err("rejected");
        assert!(err.contains("too long"), "{err}");
    }

    #[test]
    fn sidecar_tmp_path_preserves_extension() {
        let p = super::sign::sidecar_tmp_path(std::path::Path::new("foo.mp3"));
        assert_eq!(
            p.file_name().and_then(|s| s.to_str()),
            Some("foo.signed-tmp.mp3")
        );
    }

    #[test]
    fn sidecar_tmp_path_handles_no_extension() {
        let p = super::sign::sidecar_tmp_path(std::path::Path::new("foo"));
        assert_eq!(
            p.file_name().and_then(|s| s.to_str()),
            Some("foo.signed-tmp")
        );
    }

    #[test]
    fn sidecar_tmp_path_lives_in_source_dir() {
        let p = super::sign::sidecar_tmp_path(std::path::Path::new("/var/data/foo.wav"));
        assert_eq!(
            p.file_name().and_then(|s| s.to_str()),
            Some("foo.signed-tmp.wav")
        );
        assert_eq!(
            p.parent(),
            std::path::Path::new("/var/data")
                .parent()
                .map(|_| std::path::Path::new("/var/data"))
        );
    }

    #[test]
    fn parse_verify_passes_args_through() {
        // verify's positional file + trailing passthrough args
        // need to parse without clap eating the `--bsky-handle`.
        let cli = Cli::try_parse_from([
            "provcheck-kit",
            "verify",
            "foo.wav",
            "--",
            "--bsky-handle",
            "creator.bsky.social",
        ])
        .expect("parse");
        match cli.command {
            Command::Verify(args) => {
                assert_eq!(args.file, std::path::Path::new("foo.wav"));
                assert_eq!(
                    args.passthrough,
                    vec![
                        "--bsky-handle".to_string(),
                        "creator.bsky.social".to_string()
                    ]
                );
            }
            _ => panic!("wrong subcommand"),
        }
    }
}

// ----------------------------------------------------------------
// `serve` — long-lived watermark worker (v0.6.0 P2)
// ----------------------------------------------------------------

pub mod serve {
    //! Long-lived watermark worker. Reads JSON-line requests on
    //! stdin, writes JSON-line responses on stdout. Each request
    //! constructs an in-memory `watermark::CliArgs` and dispatches
    //! to the same code path the one-shot `kit watermark` uses, so
    //! request semantics stay bit-identical to the CLI. The win is
    //! amortising the tract model load (3-5 seconds per
    //! invocation) across every request after the first.
    //!
    //! Designed to be wired as a per-concurrency-slot worker
    //! process in batch-embed orchestrators (doomscroll.fm being
    //! the canonical case). The orchestrator opens N workers,
    //! load-balances requests across them, and respawns one when
    //! it dies. Each worker stays single-threaded inside; the
    //! embed itself uses rayon under the hood (v0.6.0 P1).
    //!
    //! Errors are surfaced per-request via the JSON response so a
    //! malformed input does not kill the worker. Panics inside the
    //! watermark path are not caught by this module; operators
    //! should wrap the binary in a respawn loop.

    use std::io::{BufRead, Write};
    use std::path::PathBuf;
    use std::time::Instant;

    // Suppress: the from_str method we use comes from the
    // `ValueEnum` trait, but clap re-exports it via the macro
    // expansion so the explicit import isn't needed at the call
    // sites. Leaving it absent keeps the warning-clean build.

    use anyhow::{Context, Result};
    use clap::{Args, ValueEnum};
    use serde::{Deserialize, Serialize};

    use super::watermark;

    #[derive(Debug, Args)]
    pub struct CliArgs {
        /// Protocol shape. `jsonl` (default) reads one JSON object
        /// per line on stdin, writes one JSON response per line on
        /// stdout. Future revisions may add `socket` for unix-domain
        /// transport; for v0.6.0 P2 only `jsonl` is wired.
        #[arg(long, value_enum, default_value_t = Protocol::Jsonl)]
        pub protocol: Protocol,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
    #[clap(rename_all = "lowercase")]
    pub enum Protocol {
        #[default]
        Jsonl,
    }

    /// Wire-level watermark request. Serde defaults match the
    /// `kit watermark` CLI defaults so omitting a field gives the
    /// same behaviour you'd get on the command line.
    #[derive(Debug, Deserialize)]
    pub struct WatermarkRequest {
        /// Caller-supplied correlation id, echoed back in the
        /// response so the orchestrator can match request to reply
        /// out of order.
        pub id: String,

        pub input: PathBuf,
        pub output: PathBuf,

        #[serde(default = "default_kind")]
        pub kind: String,

        #[serde(default = "default_payload")]
        pub payload: String,

        #[serde(default = "default_brand_id")]
        pub brand_id: u8,

        #[serde(default)]
        pub sdr_db: Option<f32>,

        #[serde(default)]
        pub alpha: Option<f32>,

        #[serde(default = "default_channels")]
        pub channels: String,

        #[serde(default = "default_verify")]
        pub verify_after_embed: bool,

        #[serde(default = "default_overwrite")]
        pub overwrite: bool,

        /// Optional memory-budget override matching the
        /// `--memory-budget` CLI flag. `"default"` or `"low"`.
        /// Defaults to `"default"` when omitted.
        #[serde(default = "default_memory_budget")]
        pub memory_budget: String,
    }

    fn default_kind() -> String {
        "silentcipher".to_string()
    }
    fn default_payload() -> String {
        "44464d0100".to_string()
    }
    fn default_brand_id() -> u8 {
        1
    }
    fn default_channels() -> String {
        "auto".to_string()
    }
    fn default_verify() -> bool {
        true
    }
    fn default_overwrite() -> bool {
        true
    }
    fn default_memory_budget() -> String {
        "default".to_string()
    }

    #[derive(Debug, Serialize)]
    pub struct WatermarkResponse {
        pub id: String,
        pub ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub elapsed_ms: Option<u128>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
    }

    pub async fn run(args: CliArgs) -> Result<()> {
        let _ = args.protocol; // only Jsonl is wired for v0.6.0 P2

        eprintln!("provcheck-kit: serve started (protocol=jsonl); send JSON requests on stdin");
        let stdin = std::io::stdin();
        let mut stdout = std::io::stdout().lock();
        let reader = stdin.lock();

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    let _ = write_response(
                        &mut stdout,
                        &WatermarkResponse {
                            id: "unknown".to_string(),
                            ok: false,
                            elapsed_ms: None,
                            error: Some(format!("stdin read error: {e}")),
                        },
                    );
                    break;
                }
            };
            if line.trim().is_empty() {
                continue;
            }
            let req: WatermarkRequest = match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(e) => {
                    let _ = write_response(
                        &mut stdout,
                        &WatermarkResponse {
                            id: "unknown".to_string(),
                            ok: false,
                            elapsed_ms: None,
                            error: Some(format!("malformed request: {e}")),
                        },
                    );
                    continue;
                }
            };
            let resp = handle(req).await;
            write_response(&mut stdout, &resp)?;
        }
        eprintln!("provcheck-kit: serve shutdown (stdin closed)");
        Ok(())
    }

    async fn handle(req: WatermarkRequest) -> WatermarkResponse {
        let id = req.id.clone();
        let t0 = Instant::now();
        match dispatch(req).await {
            Ok(()) => WatermarkResponse {
                id,
                ok: true,
                elapsed_ms: Some(t0.elapsed().as_millis()),
                error: None,
            },
            Err(e) => WatermarkResponse {
                id,
                ok: false,
                elapsed_ms: Some(t0.elapsed().as_millis()),
                error: Some(format!("{e:#}")),
            },
        }
    }

    /// Construct an in-memory `watermark::CliArgs` from the JSON
    /// request and call into the same code path the one-shot CLI
    /// uses. This is intentional: every request runs through the
    /// existing decode, embed, write, verify-after-embed flow, so
    /// output is bit-identical to the CLI on the same input.
    async fn dispatch(req: WatermarkRequest) -> Result<()> {
        let kind = watermark::Kind::from_str(&req.kind, true)
            .map_err(|e| anyhow::anyhow!("unknown kind {:?}: {e}", req.kind))?;
        let channels = watermark::ChannelMode::from_str(&req.channels, true)
            .map_err(|e| anyhow::anyhow!("unknown channels {:?}: {e}", req.channels))?;
        let memory_budget = watermark::MemoryBudget::from_str(&req.memory_budget, true)
            .map_err(|e| anyhow::anyhow!("unknown memory_budget {:?}: {e}", req.memory_budget))?;

        let args = watermark::CliArgs {
            input: req.input,
            output: req.output,
            kind,
            payload: req.payload,
            brand_id: req.brand_id,
            sdr_db: req.sdr_db,
            alpha: req.alpha,
            channels,
            verify_after_embed: req.verify_after_embed,
            no_verify_after_embed: !req.verify_after_embed,
            memory_budget,
            overwrite: req.overwrite,
        };
        watermark::run(args).await.context("watermark dispatch")
    }

    fn write_response<W: Write>(out: &mut W, resp: &WatermarkResponse) -> Result<()> {
        let line = serde_json::to_string(resp).context("serialize response")?;
        writeln!(out, "{line}").context("write response")?;
        out.flush().context("flush stdout")?;
        Ok(())
    }
}

pub mod weights {
    //! Manage downloadable detector weights — `kit weights status`
    //! / `install <family>` / `uninstall <family>`.
    //!
    //! Per v0.7 phase 8a design direction ("always respect the
    //! user"), the subcommand intentionally does NOT have an
    //! `install --all` shortcut. Operators install one family at
    //! a time, with the size visible up front so the consent is
    //! explicit. Detect / embed commands that run without the
    //! relevant weights installed return a clean error pointing
    //! at this subcommand.

    use anyhow::{Context, Result, anyhow};
    use clap::{Args, Subcommand};

    #[derive(Debug, Args)]
    pub struct CliArgs {
        #[command(subcommand)]
        pub action: Action,
    }

    #[derive(Debug, Subcommand)]
    pub enum Action {
        /// List every weight in the bundled manifest with its
        /// install state, size, and download URL.
        Status,
        /// Install one detector family's weights (download +
        /// SHA256-verify + cache). Argument is the family name
        /// (silentcipher / audioseal / wavmark / trustmark);
        /// installs every variant of that family.
        Install(InstallArgs),
        /// Remove a detector family's cached weights. Idempotent —
        /// does nothing if the family is already absent.
        Uninstall(UninstallArgs),
    }

    #[derive(Debug, Args)]
    pub struct InstallArgs {
        /// Family name as it appears in `weights status` (e.g.
        /// `silentcipher`, `trustmark`).
        pub family: String,
    }

    #[derive(Debug, Args)]
    pub struct UninstallArgs {
        /// Family name as it appears in `weights status`.
        pub family: String,
    }

    pub async fn run(args: CliArgs) -> Result<()> {
        match args.action {
            Action::Status => run_status(),
            Action::Install(a) => run_install(&a.family),
            Action::Uninstall(a) => run_uninstall(&a.family),
        }
    }

    fn run_status() -> Result<()> {
        let statuses = provcheck_weights::status();
        println!(
            "{:14}  {:18}  {:9}  {:9}  size       url",
            "family", "variant", "installed", "valid",
        );
        for s in &statuses {
            let installed = if s.cached.exists { "yes" } else { "no" };
            let valid = if s.cached.valid { "yes" } else { "—" };
            let size_mb = s.entry.size_bytes as f32 / 1024.0 / 1024.0;
            println!(
                "{:14}  {:18}  {:9}  {:9}  {:6.1} MB  {}",
                s.entry.family, s.entry.variant, installed, valid, size_mb, s.entry.url
            );
        }
        Ok(())
    }

    fn run_install(family: &str) -> Result<()> {
        // Collect every variant of this family from the manifest.
        let variants: Vec<&'static provcheck_weights::WeightEntry> = provcheck_weights::MANIFEST
            .iter()
            .filter(|e| e.family == family)
            .collect();
        if variants.is_empty() {
            return Err(anyhow!(
                "unknown family {family:?}. Run `kit weights status` for the manifest."
            ));
        }
        let total_mb: f32 = variants
            .iter()
            .map(|e| e.size_bytes as f32 / 1024.0 / 1024.0)
            .sum();
        eprintln!(
            "installing {} weight(s) for {family} ({:.1} MB total):",
            variants.len(),
            total_mb
        );
        for entry in variants {
            let mb = entry.size_bytes as f32 / 1024.0 / 1024.0;
            eprint!("  {} ({:.1} MB) ... ", entry.variant, mb);
            match provcheck_weights::download(entry.family, entry.variant) {
                Ok(path) => eprintln!("OK -> {}", path.display()),
                Err(e) => {
                    eprintln!("FAIL");
                    return Err(anyhow!("install {} failed: {e}", entry.variant));
                }
            }
        }
        Ok(())
    }

    fn run_uninstall(family: &str) -> Result<()> {
        let variants: Vec<&'static provcheck_weights::WeightEntry> = provcheck_weights::MANIFEST
            .iter()
            .filter(|e| e.family == family)
            .collect();
        if variants.is_empty() {
            return Err(anyhow!(
                "unknown family {family:?}. Run `kit weights status` for the manifest."
            ));
        }
        for entry in variants {
            provcheck_weights::uninstall(entry.family, entry.variant)
                .with_context(|| format!("uninstall {}/{}", entry.family, entry.variant))?;
            eprintln!("removed {}/{}", entry.family, entry.variant);
        }
        Ok(())
    }
}

pub mod stamp {
    //! `provcheck-kit stamp <input> -o <output>` — one-call creator
    //! pipeline: watermark + C2PA sign in sequence, sharing args
    //! across both steps. v0.7 phase 7g.
    //!
    //! Per the v0.7 roadmap, this is "the creator UX moment" — a
    //! creator types one command and gets a fully provenanced
    //! output. Auto-detects modality from the input extension and
    //! routes to the right watermark family (silentcipher for
    //! .mp3/.wav/.flac/.m4a/.ogg, image for .png/.jpg/.webp).
    //!
    //! Atproto record publishing is intentionally NOT part of
    //! this command in v0.7. There is no per-asset atproto record
    //! schema yet; that lands as a follow-up (and the v0.9
    //! ComfyUI node task #151 will exercise the schema design
    //! when it lands). `kit stamp` today is local-output only —
    //! the creator can `kit publish` separately if they want to
    //! refresh their identity record.

    use std::path::PathBuf;

    use anyhow::{Context, Result, bail};
    use clap::Args;

    use super::DataDirOpt;

    #[derive(Debug, Args)]
    pub struct CliArgs {
        /// Input file (audio or image — modality auto-detected
        /// from the extension).
        pub input: PathBuf,

        /// Destination path. Required — the kit will not
        /// overwrite the source in place because watermark + sign
        /// always need to write a derived file.
        #[arg(short = 'o', long, value_name = "PATH")]
        pub output: PathBuf,

        /// 5-bit brand id matching the signer's atproto identity.
        /// Defaults to RAIDIO (2) for parity with the audio
        /// `--brand-id` knob.
        #[arg(long, default_value_t = 2)]
        pub brand_id: u8,

        /// Allow overwriting `--output` if it already exists.
        #[arg(long)]
        pub overwrite: bool,

        /// Skip the watermark step. Useful when the input is
        /// already marked upstream and `stamp` is only the C2PA
        /// signing step.
        #[arg(long)]
        pub no_watermark: bool,

        /// Skip the C2PA sign step. Useful when the creator wants
        /// just the watermark without engaging the local signing
        /// identity.
        #[arg(long)]
        pub no_sign: bool,

        #[command(flatten)]
        pub data_dir: DataDirOpt,
    }

    enum Modality {
        Audio,
        Image,
    }

    fn detect_modality(path: &std::path::Path) -> Result<Modality> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .ok_or_else(|| anyhow::anyhow!("input has no extension; cannot detect modality"))?;
        match ext.as_str() {
            "mp3" | "wav" | "flac" | "m4a" | "ogg" | "opus" | "aac" | "mp4" | "mov" => {
                Ok(Modality::Audio)
            }
            "png" | "jpg" | "jpeg" | "webp" | "bmp" | "gif" | "tiff" | "tif" => Ok(Modality::Image),
            _ => bail!("unsupported extension {ext:?}; expected audio (mp3/wav/flac/...) or image (png/jpg/webp/...)"),
        }
    }

    pub async fn run(args: CliArgs) -> Result<()> {
        if args.output.exists() && !args.overwrite {
            bail!(
                "output exists; pass --overwrite to replace: {}",
                args.output.display()
            );
        }
        let modality = detect_modality(&args.input)?;
        let modality_name = match modality {
            Modality::Audio => "audio",
            Modality::Image => "image",
        };
        eprintln!(
            "provcheck-kit: stamp ({modality_name}) {} -> {}",
            args.input.display(),
            args.output.display()
        );

        // Step 1: watermark. Routes through the existing kit
        // command modules so we share their config, error
        // surfaces, verify-after-embed self-test, and CLI flag
        // semantics. The watermark step writes its output to
        // args.output; downstream sign reads from there.
        if !args.no_watermark {
            run_watermark_step(&args, &modality).await?;
        } else {
            // No watermark requested: copy input to output so the
            // sign step has something to operate on.
            tokio::fs::copy(&args.input, &args.output)
                .await
                .with_context(|| {
                    format!(
                        "copy {} -> {}",
                        args.input.display(),
                        args.output.display()
                    )
                })?;
        }

        // Step 2: C2PA sign in place (signs args.output, overwrites it).
        if !args.no_sign {
            run_sign_step(&args).await?;
        }

        eprintln!("provcheck-kit: stamp complete -> {}", args.output.display());
        Ok(())
    }

    async fn run_watermark_step(args: &CliArgs, modality: &Modality) -> Result<()> {
        use super::watermark;
        let kind = match modality {
            Modality::Audio => watermark::Kind::Silentcipher,
            Modality::Image => watermark::Kind::Image,
        };
        let wargs = watermark::CliArgs {
            input: args.input.clone(),
            output: args.output.clone(),
            kind,
            payload: brand_id_to_payload_hex(args.brand_id),
            brand_id: args.brand_id,
            sdr_db: None,
            alpha: None,
            channels: watermark::ChannelMode::Auto,
            verify_after_embed: true,
            no_verify_after_embed: false,
            memory_budget: watermark::MemoryBudget::Default,
            overwrite: args.overwrite,
        };
        watermark::run(wargs).await.context("stamp: watermark step")
    }

    /// Build a 10-hex-char silentcipher payload from a brand id.
    /// Brand id 2 (RAIDIO) → `b"RAI\x01\x00"` = `5241490100`.
    fn brand_id_to_payload_hex(brand_id_5bit: u8) -> String {
        let triplet: [u8; 3] = match brand_id_5bit {
            1 => *b"DFM",
            2 => *b"RAI",
            3 => *b"VAI",
            _ => *b"DFM",
        };
        format!(
            "{:02x}{:02x}{:02x}0100",
            triplet[0], triplet[1], triplet[2]
        )
    }

    async fn run_sign_step(args: &CliArgs) -> Result<()> {
        use super::sign;
        let sargs = sign::CliArgs {
            data_dir: args.data_dir.clone(),
            file: args.output.clone(),
            out: None, // in-place: sign overwrites args.output via its temp-rename dance
            manifest: None,
            embed_identity: true,
            action: None,
        };
        sign::run(sargs).await.context("stamp: sign step")
    }

    #[cfg(test)]
    mod stamp_helper_tests {
        use super::*;
        use std::path::Path;

        // ----- detect_modality coverage ----------

        #[test]
        fn detect_modality_classifies_audio_extensions() {
            for ext in ["mp3", "wav", "flac", "m4a", "ogg", "opus", "aac", "mp4", "mov"] {
                let p = std::path::PathBuf::from(format!("song.{ext}"));
                let m = detect_modality(&p).unwrap_or_else(|e| {
                    panic!("expected Audio for .{ext}, got {e:?}")
                });
                assert!(matches!(m, Modality::Audio), ".{ext} should be Audio");
            }
        }

        #[test]
        fn detect_modality_classifies_image_extensions() {
            for ext in ["png", "jpg", "jpeg", "webp", "bmp", "gif", "tiff", "tif"] {
                let p = std::path::PathBuf::from(format!("photo.{ext}"));
                let m = detect_modality(&p).unwrap_or_else(|e| {
                    panic!("expected Image for .{ext}, got {e:?}")
                });
                assert!(matches!(m, Modality::Image), ".{ext} should be Image");
            }
        }

        #[test]
        fn detect_modality_is_case_insensitive() {
            // Operators in the wild use Photo.JPG and MUSIC.MP3.
            // The lowercase normalisation is load-bearing UX.
            let p = std::path::PathBuf::from("Photo.JPG");
            assert!(matches!(detect_modality(&p).unwrap(), Modality::Image));
            let p = std::path::PathBuf::from("MUSIC.MP3");
            assert!(matches!(detect_modality(&p).unwrap(), Modality::Audio));
        }

        #[test]
        fn detect_modality_errors_on_missing_extension() {
            let p = std::path::PathBuf::from("README");
            let r = detect_modality(&p);
            assert!(r.is_err(), "no extension must error");
            let msg = format!("{}", r.err().unwrap());
            assert!(
                msg.contains("no extension"),
                "expected guidance message, got: {msg}"
            );
        }

        #[test]
        fn detect_modality_errors_on_unsupported_extension() {
            let p = std::path::PathBuf::from("doc.pdf");
            let r = detect_modality(&p);
            assert!(r.is_err());
            let msg = format!("{}", r.err().unwrap());
            assert!(
                msg.contains("unsupported"),
                "expected diagnostic, got: {msg}"
            );
        }

        #[test]
        fn detect_modality_handles_full_path() {
            // Not just bare filenames — any Path<...> with the
            // right tail extension classifies correctly.
            let p = Path::new("/long/path/to/some/file.flac");
            assert!(matches!(detect_modality(p).unwrap(), Modality::Audio));
            let p = Path::new("C:\\Users\\creator\\Pictures\\out.png");
            assert!(matches!(detect_modality(p).unwrap(), Modality::Image));
        }

        // ----- brand_id_to_payload_hex coverage ----------

        #[test]
        fn brand_id_to_payload_hex_doomscroll_is_dfm() {
            // brand_id 1 → b"DFM\x01\x00" → "44464d0100".
            // Pinned per the function doc comment.
            assert_eq!(brand_id_to_payload_hex(1), "44464d0100");
        }

        #[test]
        fn brand_id_to_payload_hex_raidio_is_rai() {
            // brand_id 2 → b"RAI\x01\x00" → "5241490100".
            // Pinned per the function doc comment.
            assert_eq!(brand_id_to_payload_hex(2), "5241490100");
        }

        #[test]
        fn brand_id_to_payload_hex_vaideo_is_vai() {
            // brand_id 3 → b"VAI\x01\x00" → "5641490100".
            assert_eq!(brand_id_to_payload_hex(3), "5641490100");
        }

        #[test]
        fn brand_id_to_payload_hex_unknown_falls_back_to_doomscroll() {
            // Any brand id outside the registered set falls back to
            // DFM. Pinned so a future maintainer doesn't change the
            // fallback brand silently — that would re-tag
            // unregistered creators under doomscroll.
            for unknown in [0u8, 4, 5, 16, 31] {
                assert_eq!(
                    brand_id_to_payload_hex(unknown),
                    "44464d0100",
                    "unknown brand_id {unknown} fell back to wrong triplet"
                );
            }
        }

        #[test]
        fn brand_id_to_payload_hex_is_always_10_chars() {
            // 10 hex chars = 5 bytes = silentcipher payload size.
            // Wire-format invariant.
            for brand in 0u8..=31 {
                assert_eq!(
                    brand_id_to_payload_hex(brand).len(),
                    10,
                    "brand {brand} produced wrong-length hex"
                );
            }
        }

        #[test]
        fn brand_id_to_payload_hex_is_lowercase() {
            // The kit's hex parser is lenient but the canonical
            // form is lowercase — pin it.
            for brand in 0u8..=31 {
                let h = brand_id_to_payload_hex(brand);
                assert!(
                    h.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
                    "brand {brand} hex contains non-lowercase: {h}"
                );
            }
        }
    }
}
