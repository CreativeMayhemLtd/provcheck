//! Subcommand definitions for `provcheck-kit`.
//!
//! Each command lives in its own submodule with two things: a clap
//! `Args` struct describing its flags, and an async `run(args)`
//! function that does the work. `main.rs` dispatches based on the
//! [`Command`] enum.
//!
//! Two commands intentionally print a "no-op for v0.3.0" line and
//! exit 0: `lock` and `unlock`. They exist on the CLI surface for
//! forward-compatibility with a future kit-agent daemon that would
//! own cross-process passphrase caching; until that daemon ships,
//! each `kit` invocation drops its in-process [`SecretCache`] at
//! exit, so there's nothing for these commands to act on.
//!
//! `export-backup --use-recovery-recipients` writes X25519-
//! encrypted bundles, but `import-backup` currently only handles
//! passphrase-encrypted ones (X25519 identity-file input is the
//! follow-up); the bundle round-trip with the passphrase path is
//! covered end-to-end. PKCS#12 export is also follow-up — see
//! [`provcheck_sign::backup::export_pkcs12_deferred`] for the
//! explicit deferral rationale.

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

    /// Embed a silentcipher neural watermark into an audio file.
    /// Use case: re-watermark mixed episodes after ffmpeg loudness
    /// normalisation strips the original render-time mark. Output
    /// is a WAV (re-encode externally to MP3/AAC as needed).
    Watermark(watermark::CliArgs),

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
                // Yubikey backend lands in P2; init for a Yubikey
                // identity goes through a different code path entirely
                // (no software-keypair generation). This arm exists so
                // the compiler keeps every match exhaustive.
                bail!(
                    "Yubikey-backed identity init is not yet wired in this \
                     build. Use `kit init --backend keychain` or wait for \
                     v0.5.0 P2."
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
            "Detected Yubikey serial {serial}. v0.5.0 generates the key on \
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
                     factory default. v0.5.0's kit init only supports the factory \
                     management key; use ykman to mint the keypair directly, then \
                     restore via `kit import-yubikey` (lands in v0.5.1).",
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
// agent-daemon mode. v0.3.0 has no daemon: each `kit` invocation
// is a fresh process that drops its SecretCache at exit. Both
// commands print an honest "no-op for v1" rather than pretending
// to do something. When a daemon ships these become the actual
// hooks.

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
            "kit lock: no-op for v0.3.0 (no kit-agent daemon yet — each \
             `kit` invocation drops its SecretCache when the process \
             exits). The command exists so future flows that add a \
             daemon don't have to change the CLI surface."
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
        let pass: SecretString = unlock(provcheck_sign::providers::UnlockPrompt::passphrase(
            "backup", 1,
        ))
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
                // generated a software keypair. Yubikey rotation lands
                // in P3 via `kit rotate --backend yubikey` taking a
                // different code path. For now, refuse cleanly.
                bail!(
                    "Yubikey-backed identities require `kit rotate \
                     --backend yubikey` (lands in v0.5.0 P3). A plain \
                     `kit rotate` can't generate a key on-device."
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

        /// (AudioSeal) Watermark strength multiplier. AudioSeal's
        /// training default is `1.0`. Higher = more audible + more
        /// robust; lower = quieter + more fragile. Ignored when
        /// `--kind silentcipher`.
        #[arg(long, value_name = "ALPHA")]
        pub alpha: Option<f32>,

        /// Overwrite the output file if it already exists.
        #[arg(long)]
        pub overwrite: bool,
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
        }
    }

    async fn embed_silentcipher(args: CliArgs) -> Result<()> {
        let payload = parse_payload_hex(&args.payload)?;

        eprintln!(
            "provcheck-kit: decoding {} (silentcipher)",
            args.input.display()
        );
        let input = args.input.clone();
        let waveform = tokio::task::spawn_blocking(move || sc_audio::decode_to_mono_44k1(&input))
            .await
            .context("join audio decode task")?
            .with_context(|| format!("decode {}", args.input.display()))?;
        let duration_s = waveform.len() as f32 / sc_hparams::SAMPLE_RATE as f32;
        eprintln!(
            "provcheck-kit:   {} samples ({:.2} s @ {} Hz mono)",
            waveform.len(),
            duration_s,
            sc_hparams::SAMPLE_RATE
        );

        eprintln!(
            "provcheck-kit: embedding {:02x?} (SDR {} dB)",
            payload,
            args.sdr_db.unwrap_or(47.0)
        );
        let sdr = args.sdr_db;
        let t0 = Instant::now();
        let marked = tokio::task::spawn_blocking(move || sc_encode::embed(&waveform, payload, sdr))
            .await
            .context("join embed task")?
            .context("silentcipher embed failed")?;
        let embed_elapsed = t0.elapsed();
        eprintln!(
            "provcheck-kit:   embed wall-clock {:.2?} ({:.2}x real-time)",
            embed_elapsed,
            embed_elapsed.as_secs_f32() / duration_s.max(1e-6)
        );

        write_wav(&args.output, &marked, sc_hparams::SAMPLE_RATE).await?;
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

        eprintln!(
            "provcheck-kit: decoding {} (audioseal)",
            args.input.display()
        );
        let input = args.input.clone();
        let waveform = tokio::task::spawn_blocking(move || as_audio::decode_to_mono_16k(&input))
            .await
            .context("join audio decode task")?
            .with_context(|| format!("decode {}", args.input.display()))?;
        let duration_s = waveform.len() as f32 / as_audio::SAMPLE_RATE as f32;
        eprintln!(
            "provcheck-kit:   {} samples ({:.2} s @ {} Hz mono)",
            waveform.len(),
            duration_s,
            as_audio::SAMPLE_RATE
        );

        eprintln!(
            "provcheck-kit: embedding brand id 0x{:02x} (alpha {})",
            args.brand_id,
            args.alpha.unwrap_or(as_encode::DEFAULT_ALPHA)
        );
        let brand_id = args.brand_id;
        let alpha = args.alpha;
        let t0 = Instant::now();
        let marked =
            tokio::task::spawn_blocking(move || as_encode::embed(&waveform, brand_id, alpha))
                .await
                .context("join embed task")?
                .context("audioseal embed failed")?;
        let embed_elapsed = t0.elapsed();
        eprintln!(
            "provcheck-kit:   embed wall-clock {:.2?} ({:.2}x real-time)",
            embed_elapsed,
            embed_elapsed.as_secs_f32() / duration_s.max(1e-6)
        );

        write_wav(&args.output, &marked, as_audio::SAMPLE_RATE).await?;
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
        let input = args.input.clone();
        let waveform = tokio::task::spawn_blocking(move || wm_audio::decode_to_mono_16k(&input))
            .await
            .context("join audio decode task")?
            .with_context(|| format!("decode {}", args.input.display()))?;
        let duration_s = waveform.len() as f32 / wm_audio::SAMPLE_RATE as f32;
        eprintln!(
            "provcheck-kit:   {} samples ({:.2} s @ {} Hz mono)",
            waveform.len(),
            duration_s,
            wm_audio::SAMPLE_RATE
        );

        eprintln!(
            "provcheck-kit: embedding brand id 0x{:02x}",
            args.brand_id
        );
        let brand_id = args.brand_id;
        let t0 = Instant::now();
        let marked = tokio::task::spawn_blocking(move || wm_encode::embed(&waveform, brand_id))
            .await
            .context("join embed task")?
            .context("wavmark embed failed")?;
        let embed_elapsed = t0.elapsed();
        eprintln!(
            "provcheck-kit:   embed wall-clock {:.2?} ({:.2}x real-time)",
            embed_elapsed,
            embed_elapsed.as_secs_f32() / duration_s.max(1e-6)
        );

        write_wav(&args.output, &marked, wm_audio::SAMPLE_RATE).await?;
        eprintln!("provcheck-kit: done.");
        Ok(())
    }

    async fn write_wav(output: &std::path::Path, marked: &[f32], sample_rate: u32) -> Result<()> {
        eprintln!("provcheck-kit: writing WAV to {}", output.display());
        let output_path = output.to_path_buf();
        let marked_owned = marked.to_vec();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let spec = hound::WavSpec {
                channels: 1,
                sample_rate,
                bits_per_sample: 32,
                sample_format: hound::SampleFormat::Float,
            };
            let mut writer = hound::WavWriter::create(&output_path, spec)
                .with_context(|| format!("create {}", output_path.display()))?;
            for s in &marked_owned {
                writer.write_sample(*s).context("write sample")?;
            }
            writer.finalize().context("finalize WAV")
        })
        .await
        .context("join WAV write task")??;
        Ok(())
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
