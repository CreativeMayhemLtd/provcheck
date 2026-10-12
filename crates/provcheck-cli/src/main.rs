//! provcheck — command-line C2PA Content Credentials verifier.
//!
//! Single-binary cross-platform verifier. Drag a file in, get the
//! manifest out. Designed to be wrappable in CI (stable exit codes +
//! --json output) AND usable by a human at a terminal (default human
//! rendering, readable in 80 columns).
//!
//! Exit codes:
//!
//! - `0` — file carries a valid C2PA manifest that verified.
//! - `1` — file is unsigned OR has an invalid manifest.
//! - `2` — I/O error, unreadable file, internal error.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use i18n_embed_fl::fl;
use provcheck::prelude::*;
use provcheck_platform::{AttestationOptions, verify_with_attestation};

mod dlc;
mod i18n;

/// Verify C2PA Content Credentials on a file.
#[derive(Debug, Parser)]
#[command(
    name = "provcheck",
    version,
    about = "Verify C2PA Content Credentials on a file.",
    long_about = None,
)]
struct Args {
    /// Path to the file to verify. Optional only when `--install-models` or
    /// `--install-backfire` is used.
    #[arg(required_unless_present_any = [
        "install_models",
        "install_backfire",
        "dlc_status",
        "unlock_license",
        "install_pack",
    ])]
    file: Option<PathBuf>,

    /// Download every watermark-detection model (the manifest weights) into the
    /// local cache, then exit. Run this once so image, audio, and video watermark
    /// detection work; C2PA verification needs no models. No FILE is required.
    #[arg(long)]
    install_models: bool,

    /// Set up the experimental Backfire keyed-watermark reader, then exit. Runs
    /// Backfire's one-command installer (`setup_backfire.ps1` on Windows,
    /// `setup_backfire.sh` elsewhere), which stands up a self-contained Python
    /// for the numpy-only read path and smoke-tests it, so `--backfire-read`
    /// works on a clean box with no system Python. No FILE is required.
    #[arg(long)]
    install_backfire: bool,

    // ── DLC (paid keyed-watermarking pack) management ─────────────────────
    //
    // Run-and-exit commands, like --install-models. The Pro Watermarking pack
    // (Backfire + Mellin keyed tools) is gated on an offline seat license that
    // `provcheck-dlc` verifies; the same seat unlocks the pack in Lysn.fm too.
    /// List the paid keyed-watermarking packs and whether this seat is licensed
    /// for them / has them installed, then exit. No FILE required.
    #[arg(long)]
    dlc_status: bool,

    /// Store a seat license (JSON from the offline issuer), verifying it is
    /// Creative-Mayhem-signed and bound to this seat, then exit. Needs
    /// `--seat-did` (or `$PROVCHECK_SEAT_DID`). No FILE required.
    #[arg(long, value_name = "LICENSE_JSON")]
    unlock_license: Option<PathBuf>,

    /// Pull a license-gated, signed pack into this seat's DLC home, then exit.
    /// Takes the pack id (e.g. `pro-watermarking`). Needs a stored license.
    /// No FILE required.
    #[arg(long, value_name = "PACK_ID")]
    install_pack: Option<String>,

    /// The seat's durable identity (`did:key`) a license is bound to. Falls back
    /// to `$PROVCHECK_SEAT_DID`. Used by the DLC management flags above.
    #[arg(long, value_name = "DID")]
    seat_did: Option<String>,

    /// Override the pack download source for `--install-pack` (an https mirror,
    /// or a local / UNC folder for an offline install). Defaults to the catalog
    /// mirror.
    #[arg(long, value_name = "URL_OR_PATH", requires = "install_pack")]
    pack_source: Option<String>,

    /// Emit machine-readable JSON instead of the human-readable report.
    /// Handy for CI and scripting — schema matches `provcheck::Report`.
    #[arg(long)]
    json: bool,

    /// Silence all non-error output. Exit code is still set; use in
    /// shell pipelines where you only care about pass/fail.
    #[arg(long, short)]
    quiet: bool,

    /// Path to a PEM bundle of trust anchors. Any signer whose chain
    /// ends at a cert in this bundle is reported as trusted. Without
    /// this flag, provcheck verifies the cryptographic integrity of
    /// the manifest but does not assert that the signer is trusted —
    /// the `trusted` field will be null / "unknown".
    #[arg(long, value_name = "PATH")]
    trust_store: Option<PathBuf>,

    /// Require the signer to chain to a trusted anchor. Implies
    /// `--trust-store` must also be provided: a file that verifies
    /// cryptographically but whose signer is not in the trust store
    /// will exit 1 instead of 0.
    #[arg(long, requires = "trust_store")]
    require_trusted: bool,

    /// Bsky / atproto handle to second-factor the signature against
    /// (e.g. `creator.bsky.social`). Resolves the handle to a DID,
    /// fetches the creator's published `app.provcheck.signingKey`
    /// records from their PDS, and reports whether the signing
    /// certificate's SHA-256 fingerprint matches a published key.
    /// Mutually exclusive with `--did`.
    #[arg(long, value_name = "HANDLE", conflicts_with = "did")]
    bsky_handle: Option<String>,

    /// DID to second-factor against (e.g. `did:plc:abc...` or
    /// `did:web:creator.com`). Bypasses handle resolution. Mutually
    /// exclusive with `--bsky-handle`.
    #[arg(long, value_name = "DID")]
    did: Option<String>,

    /// Use the DID embedded in the asset's `app.provcheck.identity`
    /// assertion as the second-factor identity. Removes the need to
    /// type `--bsky-handle` / `--did` for files signed by
    /// provcheck-kit with `--embed-identity`. Mutually exclusive
    /// with `--bsky-handle` and `--did`. If the asset carries no
    /// identity assertion, the run exits 1 with a clear error
    /// (use plain `provcheck <file>` if you only want the offline
    /// signature check).
    #[arg(long, conflicts_with_all = ["bsky_handle", "did"])]
    auto_identity: bool,

    /// Require an attestation match. A file whose signing certificate
    /// is not attested by the supplied handle/DID will exit 1, even if
    /// the cryptographic signature itself is valid. Requires
    /// `--bsky-handle`, `--did`, or `--auto-identity`.
    #[arg(long)]
    require_attested: bool,

    /// Skip the on-disk cache for DID documents and PDS records.
    /// Every check hits the network. Useful after a creator rotates
    /// keys.
    #[arg(long)]
    no_attestation_cache: bool,

    /// Skip the neural-watermark detector. By default, provcheck
    /// runs the silentcipher detector on every input and reports
    /// the result alongside the C2PA verdict. Set this when you
    /// only care about the C2PA signal or want to avoid the
    /// inference cost.
    #[arg(long)]
    no_watermark: bool,

    /// Require a detected neural watermark. A file whose audio
    /// does not carry a recognised silentcipher mark will exit 1
    /// even if the C2PA signature is otherwise valid. Mirrors
    /// `--require-attested`. Implies the detector runs.
    #[arg(long, conflicts_with = "no_watermark")]
    require_watermark: bool,

    /// Enable the AI-content detection slot.
    ///
    /// The verifier dispatches every registered detector via the
    /// `provcheck_detect::DetectorRegistry` and collects results
    /// into `Report::detections`. provcheck-cli does NOT register
    /// any detector by default — the FOSS core ships the plumbing
    /// (the `Detector` trait + dispatch), not the models.
    ///
    /// Concrete detectors come from one of:
    ///
    /// 1. A commercial paid-DLC pack (Creative Mayhem-distributed
    ///    after v1.0; not in this open repo at any version).
    /// 2. An operator-supplied open-source third-party detector
    ///    wrapped via the public `Detector` trait in a wrapper
    ///    crate the operator builds locally.
    ///
    /// Without a registered detector, this flag still parses and
    /// the verifier still completes successfully — the
    /// `detections` field is simply empty in the report. The flag
    /// exists so operator scripts that ARE wired against a DLC
    /// pack can request the detection pass without changing the
    /// rest of the command-line surface.
    ///
    /// See `docs/public-api-stability.md` for the trait
    /// contract.
    #[arg(long = "detect")]
    detect: Option<DetectScope>,

    /// Experimental: also verify a keyed **Backfire** image watermark and check
    /// for band-notch tampering.
    ///
    /// Backfire is a separate, BUSL-licensed (free for non-commercial use),
    /// opt-in tool, NOT part of the Apache-2.0 core. This shells out to it
    /// (never links it). Run `provcheck --install-backfire` once to set up its
    /// self-contained reader, or locate an existing one via `$BACKFIRE_PY` or a
    /// `backfire/backfire.py` in the current directory. Backfire is keyed: it
    /// verifies a mark YOU embedded, so `--backfire-key` is required.
    /// Robustness is per-image and experimental.
    #[arg(long)]
    backfire_read: bool,

    /// Secret key for the Backfire mark. Required with `--backfire-read`.
    #[arg(long, value_name = "KEY", requires = "backfire_read")]
    backfire_key: Option<String>,

    /// Expected Backfire serial in hex (e.g. `0x5`), optional. When given, the
    /// report notes whether the recovered id matches.
    #[arg(long, value_name = "HEX", requires = "backfire_read")]
    backfire_serial: Option<String>,

    /// Backfire carrier mode; must match how the image was embedded.
    #[arg(long, value_name = "MODE", default_value = "band")]
    backfire_carriers: String,

    /// Experimental: also read a keyed **Mellin** per-copy forensic serial from
    /// the input audio.
    ///
    /// Mellin is a separate, BUSL-licensed (free for non-commercial use),
    /// opt-in tool, NOT part of the Apache-2.0 core. This shells out to the
    /// standalone `provcheck-mellin` binary (never links it), located via
    /// `$MELLIN_BIN`, a copy beside provcheck (bare or in a `mellin/` folder),
    /// or the dev-tree release build. Mellin is secret-keyed seller-side
    /// forensics: it reads a serial YOU embedded, so `--mellin-secret-file`
    /// and `--mellin-work-id` are required; without them there is nothing to
    /// read.
    #[arg(long)]
    mellin_read: bool,

    /// Path to a file holding the seller secret (raw bytes) for the Mellin
    /// mark. Required with `--mellin-read`. Deliberately a file path and never
    /// the secret itself, so the secret cannot leak into shell history or a
    /// process listing.
    #[arg(long, value_name = "PATH", requires = "mellin_read")]
    mellin_secret_file: Option<PathBuf>,

    /// Work id the Mellin mark was embedded with. Required with
    /// `--mellin-read`.
    #[arg(long, value_name = "STR", requires = "mellin_read")]
    mellin_work_id: Option<String>,

    /// Expected 64-bit Mellin serial in hex (e.g. `0xDEADBEEF`), optional.
    /// When given, the report notes whether the recovered serial fully
    /// matches.
    #[arg(long, value_name = "HEX", requires = "mellin_read")]
    mellin_expect: Option<String>,

    /// Mellin repetition factor used at embed time (positions per serial
    /// bit). Omit to use the tool's default (8).
    #[arg(long, value_name = "N", requires = "mellin_read")]
    mellin_repeat: Option<u32>,
}

/// Subject of an `--detect` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum DetectScope {
    /// Run every registered AI-content detector. Without a DLC
    /// pack or operator-supplied detector this is a no-op that
    /// produces an empty `detections` vec in the report.
    Ai,
}

/// Shell out to the separate Backfire tool (BUSL-licensed, never linked into
/// this Apache binary) and return its parsed JSON. Locates `backfire.py` via
/// `$BACKFIRE_PY` or `backfire/backfire.py` beside the current directory, and
/// needs `python` (tries `python3` then `python`). `read` exits 0/1 on the
/// `--expect` check, so we parse stdout regardless of the exit status.
fn run_backfire_read(
    file: &std::path::Path,
    key: &str,
    serial: Option<&str>,
    carriers: &str,
) -> Result<serde_json::Value, String> {
    use std::process::Command;
    let script = backfire_script().ok_or_else(|| {
        "Backfire tool not found. Run `provcheck --install-backfire` to set it up, \
         set BACKFIRE_PY to backfire.py, or run from a directory containing \
         backfire/backfire.py."
            .to_string()
    })?;

    // Prefer the self-contained interpreter beside backfire.py (works with no system Python); fall back to python3/python on PATH.
    let mut interpreters: Vec<String> = Vec::new();
    if let Some(dir) = script.parent() {
        let bundled = if cfg!(windows) {
            dir.join("pyembed").join("python.exe")
        } else {
            dir.join("pyembed").join("bin").join("python3")
        };
        if bundled.exists() {
            interpreters.push(bundled.to_string_lossy().into_owned());
        }
    }
    interpreters.push("python3".into());
    interpreters.push("python".into());

    let mut argv: Vec<String> = vec![
        script.to_string_lossy().into_owned(),
        "read".into(),
        file.to_string_lossy().into_owned(),
        "--key".into(),
        key.into(),
        "--carriers".into(),
        carriers.into(),
    ];
    if let Some(s) = serial {
        argv.push("--expect".into());
        argv.push(s.into());
    }

    let mut last_err = String::new();
    for py in &interpreters {
        match Command::new(py).args(&argv).output() {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let line = stdout.lines().last().unwrap_or("").trim();
                return serde_json::from_str::<serde_json::Value>(line).map_err(|e| {
                    format!(
                        "Backfire produced unparseable output ({e}). stderr: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    )
                });
            }
            Err(e) => last_err = format!("could not run {py}: {e}"),
        }
    }
    Err(format!(
        "no usable Python found for Backfire. Run `provcheck --install-backfire` to set one up. ({last_err})"
    ))
}

/// Locate `backfire.py`: `$BACKFIRE_PY` if it points at an existing file, else
/// `backfire/backfire.py` relative to the current directory. Shared by
/// `run_backfire_read` and `install_backfire`.
fn backfire_script() -> Option<std::path::PathBuf> {
    if let Some(p) = std::env::var("BACKFIRE_PY")
        .ok()
        .map(std::path::PathBuf::from)
        .filter(|p| p.exists())
    {
        return Some(p);
    }
    let p = std::path::PathBuf::from("backfire/backfire.py");
    p.exists().then_some(p)
}

/// Run Backfire's one-command environment installer, then exit. This is the
/// "auto-get Backfire like a DLC" entry point behind `--install-backfire`: it
/// finds the installer script beside backfire.py and shells out to it
/// (PowerShell on Windows, bash elsewhere), streaming its output.
fn install_backfire() -> ExitCode {
    use std::process::Command;
    let dir = match backfire_script().and_then(|s| s.parent().map(|d| d.to_path_buf())) {
        Some(d) => d,
        None => {
            eprintln!("{}", fl!(i18n::LOADER, "backfire-folder-not-found"));
            return ExitCode::FAILURE;
        }
    };
    let (prog, prog_args): (&str, Vec<String>) = if cfg!(windows) {
        let script = dir.join("setup_backfire.ps1");
        if !script.exists() {
            eprintln!(
                "{}",
                fl!(
                    i18n::LOADER,
                    "backfire-ps1-not-found",
                    dir = dir.display().to_string()
                )
            );
            return ExitCode::FAILURE;
        }
        (
            "powershell",
            vec![
                "-ExecutionPolicy".into(),
                "Bypass".into(),
                "-File".into(),
                script.to_string_lossy().into_owned(),
            ],
        )
    } else {
        let script = dir.join("setup_backfire.sh");
        if !script.exists() {
            eprintln!(
                "{}",
                fl!(
                    i18n::LOADER,
                    "backfire-sh-not-found",
                    dir = dir.display().to_string()
                )
            );
            return ExitCode::FAILURE;
        }
        ("bash", vec![script.to_string_lossy().into_owned()])
    };
    println!("{}", fl!(i18n::LOADER, "backfire-setup-start"));
    match Command::new(prog).args(&prog_args).status() {
        Ok(s) if s.success() => {
            println!("{}", fl!(i18n::LOADER, "backfire-setup-ready"));
            ExitCode::SUCCESS
        }
        Ok(s) => {
            eprintln!(
                "{}",
                fl!(
                    i18n::LOADER,
                    "backfire-setup-exit-status",
                    status = s.to_string()
                )
            );
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!(
                "{}",
                fl!(
                    i18n::LOADER,
                    "backfire-setup-run-failed",
                    err = e.to_string()
                )
            );
            ExitCode::FAILURE
        }
    }
}

/// Locate the standalone `provcheck-mellin` binary: `$MELLIN_BIN` if it points
/// at an existing file, then a copy beside the provcheck executable (bare or
/// in a `mellin/` folder), then the crate's own release build in the dev tree.
fn mellin_bin() -> Option<std::path::PathBuf> {
    let exe_name = if cfg!(windows) {
        "provcheck-mellin.exe"
    } else {
        "provcheck-mellin"
    };
    if let Some(p) = std::env::var("MELLIN_BIN")
        .ok()
        .map(std::path::PathBuf::from)
        .filter(|p| p.exists())
    {
        return Some(p);
    }
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.to_path_buf()))
    {
        for cand in [dir.join(exe_name), dir.join("mellin").join(exe_name)] {
            if cand.exists() {
                return Some(cand);
            }
        }
    }
    // The installed Pro Watermarking DLC pack (where `--install-pack pro-watermarking`
    // lands the BUSL-licensed Mellin tool). provcheck only ever shells out to it across
    // a process boundary; the keyed IP never links into this Apache binary.
    if let Ok(home) = provcheck_dlc::default_home() {
        let cand = provcheck_dlc::dlc_pack_dir(&home, "pro-watermarking").join(exe_name);
        if cand.exists() {
            return Some(cand);
        }
    }
    let dev = std::path::PathBuf::from("crates/provcheck-mellin/target/release").join(exe_name);
    dev.exists().then_some(dev)
}

/// Shell out to the separate Mellin tool (BUSL-licensed, never linked into
/// this Apache binary) and return its parsed JSON. The secret travels as a
/// FILE PATH (`--secret-file`), never as bytes on any command line, and is
/// never logged. `read --json` prints exactly one JSON line and exits 0/1 on
/// the `--expect` check, so stdout is parsed regardless of exit status.
fn run_mellin_read(
    file: &std::path::Path,
    secret_file: &std::path::Path,
    work_id: &str,
    expect: Option<&str>,
    repeat: Option<u32>,
) -> Result<serde_json::Value, String> {
    use std::process::Command;
    let bin = mellin_bin().ok_or_else(|| {
        "Mellin tool not found. Set MELLIN_BIN to the provcheck-mellin binary, place it \
         beside provcheck (or in a mellin/ folder there), or build it with `cargo build \
         --manifest-path crates/provcheck-mellin/Cargo.toml --release`."
            .to_string()
    })?;
    let mut argv: Vec<String> = vec![
        "read".into(),
        file.to_string_lossy().into_owned(),
        "--secret-file".into(),
        secret_file.to_string_lossy().into_owned(),
        "--work-id".into(),
        work_id.into(),
        "--json".into(),
    ];
    if let Some(e) = expect {
        argv.push("--expect".into());
        argv.push(e.into());
    }
    if let Some(r) = repeat {
        argv.push("--repeat".into());
        argv.push(r.to_string());
    }
    match Command::new(&bin).args(&argv).output() {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let line = stdout.lines().last().unwrap_or("").trim();
            serde_json::from_str::<serde_json::Value>(line).map_err(|e| {
                format!(
                    "Mellin produced unparseable output ({e}). stderr: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                )
            })
        }
        Err(e) => Err(format!("could not run {} ({e})", bin.display())),
    }
}

/// Human-readable Mellin block, printed under the main report.
fn print_mellin_human(m: &serde_json::Value) {
    let serial = m.get("serial").and_then(|v| v.as_str()).unwrap_or("?");
    let bits = m
        .get("bits_recovered")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let full = m
        .get("fully_recovered")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let erasure = m
        .get("erasure_rate")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let votes = m.get("min_bit_votes").and_then(|v| v.as_u64()).unwrap_or(0);
    println!();
    println!("{}", fl!(i18n::LOADER, "mellin-header"));
    if full {
        println!(
            "  {}",
            fl!(
                i18n::LOADER,
                "mellin-serial-full",
                serial = serial,
                votes = votes.to_string()
            )
        );
    } else {
        println!(
            "  {}",
            fl!(
                i18n::LOADER,
                "mellin-serial-partial",
                bits = bits.to_string(),
                votes = votes.to_string()
            )
        );
    }
    println!(
        "  {}",
        fl!(
            i18n::LOADER,
            "mellin-erasures",
            pct = format!("{:.1}", erasure * 100.0)
        )
    );
    match m.get("match") {
        Some(serde_json::Value::Bool(true)) => {
            println!("  {}", fl!(i18n::LOADER, "mellin-expected-match"))
        }
        Some(serde_json::Value::Bool(false)) => {
            println!("  {}", fl!(i18n::LOADER, "mellin-expected-no-match"))
        }
        _ => {}
    }
}

/// Human-readable Backfire block, printed under the main report.
fn print_backfire_human(bf: &serde_json::Value) {
    let valid = bf.get("valid").and_then(|v| v.as_bool()).unwrap_or(false);
    let id = bf.get("id_hex").and_then(|v| v.as_str()).unwrap_or("?");
    let margin = bf
        .get("min_bit_margin")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    println!();
    println!("{}", fl!(i18n::LOADER, "backfire-header"));
    if valid {
        println!(
            "  {}",
            fl!(
                i18n::LOADER,
                "backfire-mark-valid",
                id = id,
                margin = format!("{margin:.2}")
            )
        );
    } else {
        println!(
            "  {}",
            fl!(
                i18n::LOADER,
                "backfire-mark-none",
                margin = format!("{margin:.2}")
            )
        );
    }
    if let Some(t) = bf.get("notch_tamper") {
        let det = t.get("detected").and_then(|v| v.as_bool()).unwrap_or(false);
        let stat = t.get("stat").and_then(|v| v.as_f64()).unwrap_or(0.0);
        if det {
            println!(
                "  {}",
                fl!(
                    i18n::LOADER,
                    "backfire-tamper-detected",
                    stat = format!("{stat:.2}")
                )
            );
        } else {
            println!(
                "  {}",
                fl!(
                    i18n::LOADER,
                    "backfire-tamper-none",
                    stat = format!("{stat:.2}")
                )
            );
        }
    }
}

/// Download every detector weight in the manifest into the local cache, printing
/// per-file progress. Idempotent: a valid cached copy is skipped. Returns SUCCESS
/// only when every model is present afterwards.
fn install_all_models(quiet: bool) -> ExitCode {
    let entries = provcheck_weights::MANIFEST;
    let total_mb = entries.iter().map(|e| e.size_bytes).sum::<u64>() as f64 / 1e6;
    if !quiet {
        println!(
            "{}",
            fl!(
                i18n::LOADER,
                "install-models-start",
                count = entries.len().to_string(),
                mb = format!("{total_mb:.0}")
            )
        );
    }
    let mut failed = 0usize;
    for e in entries {
        if !quiet {
            print!(
                "  {} ",
                fl!(
                    i18n::LOADER,
                    "install-models-item",
                    family = e.family,
                    variant = e.variant,
                    mb = format!("{:.0}", e.size_bytes as f64 / 1e6)
                )
            );
            let _ = std::io::Write::flush(&mut std::io::stdout());
        }
        match provcheck_weights::download(e.family, e.variant) {
            Ok(_) => {
                if !quiet {
                    println!("{}", fl!(i18n::LOADER, "install-models-ok"));
                }
            }
            Err(err) => {
                failed += 1;
                if !quiet {
                    println!(
                        "{}",
                        fl!(
                            i18n::LOADER,
                            "install-models-item-failed",
                            err = err.to_string()
                        )
                    );
                }
            }
        }
    }
    if failed == 0 {
        if !quiet {
            println!("{}", fl!(i18n::LOADER, "install-models-done"));
        }
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "{}",
            fl!(
                i18n::LOADER,
                "install-models-summary-failed",
                count = failed.to_string()
            )
        );
        ExitCode::FAILURE
    }
}

fn main() -> ExitCode {
    i18n::init();
    let args = Args::parse();

    if args.install_models {
        return install_all_models(args.quiet);
    }
    if args.install_backfire {
        return install_backfire();
    }
    if args.dlc_status {
        return dlc::status(args.seat_did.as_deref(), args.quiet);
    }
    if let Some(file) = args.unlock_license.as_deref() {
        return dlc::unlock(file, args.seat_did.as_deref());
    }
    if let Some(product) = args.install_pack.as_deref() {
        return dlc::install(
            product,
            args.pack_source.as_deref(),
            args.seat_did.as_deref(),
        );
    }
    // Safe: clap requires FILE unless an --install-* / DLC management flag is set,
    // all handled above.
    let file: &std::path::Path = args
        .file
        .as_deref()
        .expect("clap enforces FILE unless an --install-* flag");

    // require_attested needs an identity input; clap's `requires` takes one arg, so enforce the OR here.
    if args.require_attested
        && args.bsky_handle.is_none()
        && args.did.is_none()
        && !args.auto_identity
    {
        if !args.quiet {
            eprintln!("{}", fl!(i18n::LOADER, "require-attested-needs-identity"));
        }
        return ExitCode::from(2);
    }

    let trust_store_pem = match args.trust_store.as_deref() {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(s) => Some(s),
            Err(e) => {
                if !args.quiet {
                    eprintln!(
                        "{}",
                        fl!(
                            i18n::LOADER,
                            "trust-store-read-failed",
                            path = path.display().to_string(),
                            err = e.to_string()
                        )
                    );
                }
                return ExitCode::from(2);
            }
        },
        None => None,
    };

    let verify_opts = VerifyOptions {
        trust_store_pem,
        require_trusted: args.require_trusted,
    };

    // Resolve --auto-identity from the offline report's embedded assertion; no claim = exit 1 with the cause.
    let resolved_did = if args.auto_identity {
        match verify_with_options(file, &verify_opts) {
            Ok(r) => match r.identity {
                Some(claim) => Some(claim.did),
                None => {
                    if !args.quiet {
                        eprintln!("{}", fl!(i18n::LOADER, "auto-identity-no-assertion"));
                    }
                    return ExitCode::from(1);
                }
            },
            Err(e) => {
                if !args.quiet {
                    eprintln!("provcheck: {}", e);
                }
                return ExitCode::from(2);
            }
        }
    } else {
        None
    };

    // Route through the platform wrapper only when attestation is asked, keeping the offline path free of platform-crate code.
    let want_attestation =
        args.bsky_handle.is_some() || args.did.is_some() || resolved_did.is_some();

    let mut report = if want_attestation {
        let attest_opts = AttestationOptions {
            bsky_handle: args.bsky_handle.clone(),
            // auto-identity's did wins; conflicts_with guarantees --did wasn't also passed.
            did: resolved_did.clone().or_else(|| args.did.clone()),
            require_attested: args.require_attested,
            cache_dir: None,
            no_cache: args.no_attestation_cache,
        };
        match verify_with_attestation(file, &verify_opts, &attest_opts) {
            Ok(r) => r,
            Err(e) => {
                if !args.quiet {
                    eprintln!("provcheck: {}", e);
                }
                return ExitCode::from(2);
            }
        }
    } else {
        match verify_with_options(file, &verify_opts) {
            Ok(r) => r,
            Err(e) => {
                if !args.quiet {
                    eprintln!("provcheck: {}", e);
                }
                return ExitCode::from(2);
            }
        }
    };

    // Independent of the C2PA verdict; errors are non-fatal (detectors report decoder issues via `message`). Add a detector by appending an `if let Ok(...)` block.
    if !args.no_watermark {
        if let Ok(w) = provcheck_watermark::detect(file) {
            report.watermarks.push(w);
        }
        if let Ok(w) = provcheck_audioseal::detect(file) {
            report.watermarks.push(w);
        }
        if let Ok(w) = provcheck_wavmark::detect(file) {
            report.watermarks.push(w);
        }
        if let Ok(w) = provcheck_image::detect(file) {
            report.watermarks.push(w);
        }
        if let Ok(w) = provcheck_video::detect(file) {
            report.watermarks.push(w);
        }
        if let Ok(w) = provcheck_synthid_text::detect(file) {
            report.watermarks.push(w);
        }
    }

    // AI-content detection slot: the FOSS core registers zero detectors, so without one the dispatch runs over an empty registry and leaves report.detections empty.
    if args.detect.is_some() {
        let registry = provcheck_detect::DetectorRegistry::new();
        // Read the asset once; best-effort, a failure here (after C2PA/watermark passed) is anomalous.
        match std::fs::read(file) {
            Ok(bytes) => {
                report.detections = registry.run_all(&bytes);
            }
            Err(_) => {
                // Silent: a read failure here means the file changed since c2pa::Reader opened it — bizarre, not a verifier failure.
            }
        }
    }

    // Opt-in Backfire: shells out to the separate BUSL tool (never linked); informational, doesn't change the exit code.
    let backfire = if args.backfire_read {
        let key = match args.backfire_key.as_deref() {
            Some(k) => k,
            None => {
                if !args.quiet {
                    eprintln!("{}", fl!(i18n::LOADER, "backfire-needs-key"));
                }
                return ExitCode::from(2);
            }
        };
        if !args.quiet {
            eprintln!("{}", fl!(i18n::LOADER, "backfire-experimental-notice"));
        }
        match run_backfire_read(
            file,
            key,
            args.backfire_serial.as_deref(),
            &args.backfire_carriers,
        ) {
            Ok(v) => Some(v),
            Err(e) => {
                if !args.quiet {
                    eprintln!("{}", fl!(i18n::LOADER, "backfire-read-failed", err = e));
                }
                None
            }
        }
    } else {
        None
    };

    // Opt-in Mellin: shells out to the separate BUSL tool (never linked); informational, doesn't change the exit code.
    let mellin = if args.mellin_read {
        let (secret_file, work_id) = match (
            args.mellin_secret_file.as_deref(),
            args.mellin_work_id.as_deref(),
        ) {
            (Some(s), Some(w)) => (s, w),
            _ => {
                if !args.quiet {
                    eprintln!("{}", fl!(i18n::LOADER, "mellin-needs-args"));
                }
                return ExitCode::from(2);
            }
        };
        if !args.quiet {
            eprintln!("{}", fl!(i18n::LOADER, "mellin-experimental-notice"));
        }
        match run_mellin_read(
            file,
            secret_file,
            work_id,
            args.mellin_expect.as_deref(),
            args.mellin_repeat,
        ) {
            Ok(v) => Some(v),
            Err(e) => {
                if !args.quiet {
                    eprintln!("{}", fl!(i18n::LOADER, "mellin-read-failed", err = e));
                }
                None
            }
        }
    } else {
        None
    };

    // --require-watermark escalates "no mark found" to exit 1; passes if any detector reports detected.
    let watermark_failed_requirement =
        args.require_watermark && !report.watermarks.iter().any(|w| w.detected);

    if !args.quiet {
        if args.json {
            match report.to_json_string() {
                // With backfire/mellin, wrap into {provcheck, backfire?, mellin?}; the bare-report schema is unchanged otherwise.
                Ok(j) => {
                    if backfire.is_some() || mellin.is_some() {
                        let rv: serde_json::Value =
                            serde_json::from_str(&j).unwrap_or(serde_json::Value::Null);
                        let mut wrap = serde_json::Map::new();
                        wrap.insert("provcheck".into(), rv);
                        if let Some(bf) = &backfire {
                            wrap.insert("backfire".into(), bf.clone());
                        }
                        if let Some(m) = &mellin {
                            wrap.insert("mellin".into(), m.clone());
                        }
                        println!("{}", serde_json::Value::Object(wrap));
                    } else {
                        println!("{j}");
                    }
                }
                Err(e) => {
                    eprintln!(
                        "{}",
                        fl!(i18n::LOADER, "json-serialize-failed", err = e.to_string())
                    );
                    return ExitCode::from(2);
                }
            }
        } else {
            print!("{}", report);
            // If models are missing, give ONE setup instruction instead of a "not installed" note per line that reads as "broken".
            if !args.no_watermark {
                let statuses = provcheck_weights::status();
                let n_missing = statuses.iter().filter(|s| !s.cached.exists).count();
                if n_missing > 0 {
                    let missing_mb = statuses
                        .iter()
                        .filter(|s| !s.cached.exists)
                        .map(|s| s.entry.size_bytes)
                        .sum::<u64>() as f64
                        / 1e6;
                    eprintln!(
                        "{}",
                        fl!(
                            i18n::LOADER,
                            "hint-models-missing",
                            count = n_missing.to_string(),
                            mb = format!("{missing_mb:.0}")
                        )
                    );
                }
            }
            // When the file embeds an identity claim but no attestation was asked, nudge about --auto-identity.
            if !want_attestation && let Some(claim) = &report.identity {
                let who = match &claim.handle {
                    Some(h) => format!("@{} ({})", h, claim.did),
                    None => claim.did.clone(),
                };
                eprintln!("{}", fl!(i18n::LOADER, "hint-claims-identity", who = who));
            }
            if let Some(bf) = &backfire {
                print_backfire_human(bf);
            }
            if let Some(m) = &mellin {
                print_mellin_human(m);
            }
        }
    }

    // Final exit: C2PA verdict or watermark policy can each force 1; neither moves a 1 back to 0.
    let final_exit = if watermark_failed_requirement {
        1
    } else {
        report.exit_code() as u8
    };
    ExitCode::from(final_exit)
}
