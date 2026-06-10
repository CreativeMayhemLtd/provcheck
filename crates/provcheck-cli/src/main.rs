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
use provcheck::prelude::*;
use provcheck_platform::{AttestationOptions, verify_with_attestation};

/// Verify C2PA Content Credentials on a file.
#[derive(Debug, Parser)]
#[command(
    name = "provcheck",
    version,
    about = "Verify C2PA Content Credentials on a file.",
    long_about = None,
)]
struct Args {
    /// Path to the file to verify.
    file: PathBuf,

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

    /// Require an attestation match. A file whose signing certificate
    /// is not attested by the supplied handle/DID will exit 1, even if
    /// the cryptographic signature itself is valid. Requires either
    /// `--bsky-handle` or `--did`.
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
}

fn main() -> ExitCode {
    let args = Args::parse();

    // require_attested needs either --bsky-handle or --did. clap's
    // `requires` only takes a single arg name, so enforce the OR here.
    if args.require_attested && args.bsky_handle.is_none() && args.did.is_none() {
        if !args.quiet {
            eprintln!("provcheck: --require-attested needs either --bsky-handle or --did");
        }
        return ExitCode::from(2);
    }

    let trust_store_pem = match args.trust_store.as_deref() {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(s) => Some(s),
            Err(e) => {
                if !args.quiet {
                    eprintln!(
                        "provcheck: could not read trust store '{}': {}",
                        path.display(),
                        e
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

    // Dispatch: route through the platform wrapper iff the user asked
    // for attestation. Keeps the offline path completely free of any
    // platform-crate code paths when nobody's asked for networking.
    let want_attestation = args.bsky_handle.is_some() || args.did.is_some();

    let mut report = if want_attestation {
        let attest_opts = AttestationOptions {
            bsky_handle: args.bsky_handle.clone(),
            did: args.did.clone(),
            require_attested: args.require_attested,
            cache_dir: None,
            no_cache: args.no_attestation_cache,
        };
        match verify_with_attestation(&args.file, &verify_opts, &attest_opts) {
            Ok(r) => r,
            Err(e) => {
                if !args.quiet {
                    eprintln!("provcheck: {}", e);
                }
                return ExitCode::from(2);
            }
        }
    } else {
        match verify_with_options(&args.file, &verify_opts) {
            Ok(r) => r,
            Err(e) => {
                if !args.quiet {
                    eprintln!("provcheck: {}", e);
                }
                return ExitCode::from(2);
            }
        }
    };

    // Watermark detection is independent of the C2PA verdict —
    // each enabled detector runs unconditionally unless
    // suppressed. Errors here are never fatal: a missing file
    // would already have surfaced above, and detectors report
    // decoder problems via the result's `message` field rather
    // than throwing. Adding a new FOSS detector means appending
    // another `if let Ok(...)` block here in registration
    // order; the Display + JSON layers iterate the vec.
    if !args.no_watermark {
        if let Ok(w) = provcheck_watermark::detect(&args.file) {
            report.watermarks.push(w);
        }
        if let Ok(w) = provcheck_audioseal::detect(&args.file) {
            report.watermarks.push(w);
        }
        if let Ok(w) = provcheck_wavmark::detect(&args.file) {
            report.watermarks.push(w);
        }
    }

    // `--require-watermark` escalates "no detector found a
    // mark" to exit 1, the same way `--require-attested` does.
    // A run with multiple detectors passes if at least one
    // returns `detected == true`.
    let watermark_failed_requirement =
        args.require_watermark && !report.watermarks.iter().any(|w| w.detected);

    if !args.quiet {
        if args.json {
            match report.to_json_string() {
                Ok(j) => println!("{}", j),
                Err(e) => {
                    eprintln!("provcheck: failed to serialize JSON: {}", e);
                    return ExitCode::from(2);
                }
            }
        } else {
            print!("{}", report);
        }
    }

    // Compose final exit code: C2PA verdict OR watermark policy
    // can each force exit 1. Either can move a 0 to 1 but neither
    // moves a 1 back to 0.
    let final_exit = if watermark_failed_requirement {
        1
    } else {
        report.exit_code() as u8
    };
    ExitCode::from(final_exit)
}
