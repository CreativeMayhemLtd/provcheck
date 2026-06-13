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

// ----------------------------------------------------------------
// `sign <FILE>` — Sign an asset with the local key.
// ----------------------------------------------------------------

pub mod sign {
    use std::path::PathBuf;

    use anyhow::{Context, Result};
    use clap::Args;

    use provcheck_sign::persist::{default_dir, load_locked};
    use provcheck_sign::providers::{AgeFileProvider, KeyProvider, KeychainProvider};
    use provcheck_sign::sign::sign_asset;
    use provcheck_sign::types::{KeyProviderKind, UnlockedIdentity};

    use crate::prompts::unlock_passphrase;

    use super::DataDirOpt;

    #[derive(Debug, Args)]
    pub struct CliArgs {
        #[command(flatten)]
        pub data_dir: DataDirOpt,

        /// Asset to sign.
        pub file: PathBuf,

        /// Destination path. Defaults to in-place (same as input).
        #[arg(long, short = 'o', value_name = "PATH")]
        pub out: Option<PathBuf>,

        /// Path to a manifest JSON file. If not supplied, the kit
        /// constructs a minimal default manifest with `c2pa.actions.v2`
        /// (action: created) and the file's format inferred from
        /// its extension.
        #[arg(long, value_name = "PATH")]
        pub manifest: Option<PathBuf>,

        /// Embed the `app.provcheck.identity` assertion (Phase 5
        /// auto-suggest hook). Currently a no-op until that lexicon
        /// + verifier extraction lands.
        #[arg(long)]
        pub embed_identity: bool,
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

        // Unlock via the recorded provider backend.
        let mut prompt = unlock_passphrase();
        let key_pem = match locked.key_provider {
            KeyProviderKind::Keychain => KeychainProvider::new()
                .fetch(&dir, &locked.fingerprint, &mut prompt)
                .context("fetch key from OS keychain")?,
            KeyProviderKind::EncryptedFile => AgeFileProvider::new()
                .fetch(&dir, &locked.fingerprint, &mut prompt)
                .context("fetch key from encrypted file")?,
        };
        let unlocked = UnlockedIdentity::new(locked, key_pem);

        let manifest_json = match &args.manifest {
            Some(p) => std::fs::read_to_string(p)
                .with_context(|| format!("read manifest from {}", p.display()))?,
            None => default_manifest(&args.file)?,
        };

        let dst = args.out.clone().unwrap_or_else(|| args.file.clone());
        let result = sign_asset(&unlocked, &args.file, &dst, &manifest_json)
            .context("c2pa sign_asset")?;

        if args.embed_identity {
            eprintln!(
                "note: --embed-identity is a no-op until the app.provcheck.identity \
                 lexicon and verifier extraction land (Phase 5)."
            );
        }

        eprintln!("✓ Signed {} → {}", args.file.display(), result.output_path.display());
        eprintln!("  manifest bytes: {}", result.manifest_bytes.len());
        Ok(())
    }

    /// Construct a minimal-but-valid C2PA manifest for the given
    /// asset. The CLI uses this when the user doesn't supply a
    /// manifest JSON file.
    fn default_manifest(asset: &std::path::Path) -> Result<String> {
        let format = format_from_extension(asset)
            .context("infer asset format from extension — pass --manifest for unrecognised types")?;
        let title = asset
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("untitled");

        let v = serde_json::json!({
            "claim_generator": "provcheck-kit/0.3.0",
            "claim_generator_info": [{"name": "provcheck-kit", "version": "0.3.0"}],
            "format": format,
            "title": title,
            "assertions": [
                {
                    "label": "c2pa.actions.v2",
                    "data": {"actions": [{"action": "c2pa.created"}]}
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
        eprintln!(
            "  Pubkey: {}…",
            &args.pubkey[..28.min(args.pubkey.len())]
        );
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
        println!("Registered recovery recipients ({}):", locked.recovery_recipients.len());
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
        locked.recovery_recipients.retain(|r| {
            r.pubkey != args.ident && r.label.as_deref() != Some(args.ident.as_str())
        });
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
// agent-daemon mode. v0.3.0 has no daemon: each `kit` invocation
// is a fresh process that drops its SecretCache at exit. Both
// commands print an honest "no-op for v1" rather than pretending
// to do something. When a daemon ships these become the actual
// hooks.

pub mod lock {
    use anyhow::Result;
    use clap::Args;
    use super::DataDirOpt;

    #[derive(Debug, Args)]
    pub struct CliArgs {
        #[command(flatten)]
        pub data_dir: DataDirOpt,
    }

    pub async fn run(_args: CliArgs) -> Result<()> {
        eprintln!(
            "kit lock: no-op for v0.3.0 (no kit-agent daemon yet — each \
             `kit` invocation drops its SecretCache when the process \
             exits). The command exists so future flows that add a \
             daemon don't have to change the CLI surface."
        );
        Ok(())
    }
}

pub mod unlock {
    use anyhow::Result;
    use clap::Args;
    use super::DataDirOpt;

    #[derive(Debug, Args)]
    pub struct CliArgs {
        #[command(flatten)]
        pub data_dir: DataDirOpt,
    }

    pub async fn run(_args: CliArgs) -> Result<()> {
        eprintln!(
            "kit unlock: no-op for v0.3.0 (no kit-agent daemon yet — \
             cross-process passphrase caching arrives with the daemon)."
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
            let pass: SecretString = match new_pp(
                provcheck_sign::providers::NewPassphrasePrompt { purpose: "backup" },
            ) {
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

    use provcheck_sign::backup::import_with_passphrase;
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

        // Prompt for the backup passphrase. X25519-encrypted bundles
        // would need a separate flag + identity-file input — deferred
        // to a follow-up; passphrase covers the most common case
        // (`kit export-backup` defaults to passphrase-only).
        eprintln!("Decrypting backup at {}…", args.bundle.display());
        let mut unlock = unlock_passphrase();
        let pass: SecretString = unlock(provcheck_sign::providers::UnlockPrompt {
            purpose: "backup",
            attempt: 1,
        })
        .map_err(|e| anyhow::anyhow!("{e}"))?;

        let bundle =
            import_with_passphrase(&args.bundle, pass).context("decrypt + parse backup")?;
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
    use anyhow::Context;
    provcheck_publish::AtprotoClient::load_session(dir)
        .await
        .context(
            "load atproto session — run `kit login` first if you haven't, \
             or re-run if the refresh JWT has expired",
        )
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
            if existing.iter().any(|(_, r)| r.fingerprint == locked.fingerprint) {
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
        let at_uri = writer
            .publish_signing_key(&record)
            .await
            .context("atproto publish_signing_key")?;

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

        /// Fingerprint of the record to revoke (full
        /// `sha256:<hex>` form).
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
        let (uri, mut record) = records
            .into_iter()
            .find(|(_, r)| r.fingerprint == args.fingerprint)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no record with fingerprint {} in your repo",
                    args.fingerprint
                )
            })?;
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
        eprintln!("  validUntil:  {}", record.valid_until.as_deref().unwrap_or(""));
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

    use anyhow::{Context, Result};
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
        // moved aside to keys-rotated-<old-fp-prefix>/.
        let backup_dir = rotated_path_for(&dir, &old.fingerprint);
        std::fs::rename(&dir, &backup_dir).with_context(|| {
            format!(
                "move old identity {} → {} (manual cleanup may be required; \
                 the new record at {new_uri} is on atproto but the local \
                 identity is still the old one)",
                dir.display(),
                backup_dir.display()
            )
        })?;
        std::fs::rename(&staging, &dir).with_context(|| {
            format!(
                "move staging {} → {} (rollback: rename {} back to {} \
                 to restore the old identity)",
                staging.display(),
                dir.display(),
                backup_dir.display(),
                dir.display(),
            )
        })?;
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
        eprintln!("  Old data dir:    {} (kept; safe to archive)", backup_dir.display());
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

    // No tests here yet — rotate needs an atproto mock to drive
    // end-to-end. The path-arithmetic helpers (staging_path_for,
    // rotated_path_for) are pure functions and can grow direct
    // unit tests in a follow-up.
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
                status.code().map(|c| c.to_string()).unwrap_or_else(|| "<signal>".into())
            );
        }
        Ok(())
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
