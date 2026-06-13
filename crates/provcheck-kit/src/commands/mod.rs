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
stub_command!(publish, CliArgs, "publish");
stub_command!(list, CliArgs, "list");
stub_command!(revoke, CliArgs, "revoke");
stub_command!(rotate, CliArgs, "rotate");
stub_command!(verify, CliArgs, "verify");

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
