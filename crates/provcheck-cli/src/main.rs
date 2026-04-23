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
use provcheck_core::prelude::*;

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
    /// Handy for CI and scripting — schema matches `provcheck_core::Report`.
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
}

fn main() -> ExitCode {
    let args = Args::parse();

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

    let opts = VerifyOptions {
        trust_store_pem,
        require_trusted: args.require_trusted,
    };

    let report = match verify_with_options(&args.file, &opts) {
        Ok(r) => r,
        Err(e) => {
            if !args.quiet {
                eprintln!("provcheck: {}", e);
            }
            return ExitCode::from(2);
        }
    };

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

    ExitCode::from(report.exit_code() as u8)
}
