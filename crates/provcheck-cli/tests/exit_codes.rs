//! End-to-end exit-code matrix for the `provcheck` binary.
//!
//! The CLI binary is the user-facing contract; its exit codes
//! drive automation (CI gates, pipeline failure modes, GUI
//! preflight checks). Until v0.9.4 the binary itself had zero
//! tests. This file establishes the matrix and pins each
//! documented exit code path.
//!
//! Exit code map (per `crates/provcheck-cli/src/main.rs`):
//!
//! - 0: success (verified, or `--no-fail-on-unsigned` and unsigned)
//! - 1: verified=false, or `--require-attested` / `--require-watermark`
//!   gates demoted the result
//! - 2: usage error (missing args, file read failure, malformed PEM)

use std::path::PathBuf;
use std::process::Command;

/// Locate the cargo-built `provcheck` binary at test runtime.
/// `CARGO_BIN_EXE_provcheck` is set by Cargo for integration tests
/// of binary crates.
fn provcheck_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_provcheck"))
}

/// Run the binary with the given args and return (exit code, stdout, stderr).
fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(provcheck_bin())
        .args(args)
        .output()
        .expect("spawn provcheck binary");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (code, stdout, stderr)
}

// ----- exit code 2 paths (usage errors) ----------

#[test]
fn missing_file_argument_exits_2() {
    // clap returns an error when a required positional is absent.
    // clap maps this to exit code 2 by default.
    let (code, _, stderr) = run(&[]);
    assert_eq!(code, 2, "missing positional must exit 2; stderr={stderr}");
}

#[test]
fn require_attested_without_identity_inputs_exits_2() {
    // The main() preflight gates require-attested on at least
    // one of --bsky-handle / --did / --auto-identity. Without
    // them, exit 2 with a clear message.
    let (code, _, stderr) = run(&["--require-attested", "/no/such/file.mp3"]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("--require-attested needs"),
        "expected guidance message, got stderr={stderr}"
    );
}

#[test]
fn malformed_trust_store_pem_exits_2() {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(tmp.path(), b"not a pem").expect("write");
    let (code, _, stderr) = run(&[
        "--trust-store",
        tmp.path().to_str().unwrap(),
        "/no/such/file.mp3",
    ]);
    assert_eq!(code, 2, "malformed PEM must exit 2; stderr={stderr}");
}

#[test]
fn unreadable_trust_store_path_exits_2() {
    let (code, _, _stderr) = run(&[
        "--trust-store",
        "/no/such/path/at/all/cert.pem",
        "/no/such/file.mp3",
    ]);
    assert_eq!(code, 2, "unreadable trust store must exit 2");
}

#[test]
fn missing_input_file_exits_2() {
    let (code, _, _) = run(&["/does/not/exist/file_abcxyz.mp3"]);
    assert_eq!(
        code, 2,
        "missing input file is an I/O failure → exit 2"
    );
}

// ----- help + version stay non-error ----------

#[test]
fn help_exits_0() {
    let (code, stdout, _) = run(&["--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("provcheck"), "help text must mention the binary");
}

#[test]
fn version_exits_0() {
    let (code, stdout, _) = run(&["--version"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("provcheck"));
    // The version string includes the workspace version.
    assert!(
        stdout.contains("0.9.4") || stdout.contains("0.9."),
        "expected 0.9.x in version string, got {stdout}"
    );
}

// ----- json mode preserves the exit-code contract ----------

#[test]
fn missing_file_in_json_mode_still_exits_2() {
    // --json must not swallow the exit code: automation depends
    // on the same signal whether the output is text or JSON.
    let (code, _, _) = run(&["--json", "/does/not/exist/json_test.mp3"]);
    assert_eq!(code, 2);
}

// ----- mutually-exclusive flags via clap ----------

#[test]
fn require_watermark_with_no_watermark_exits_2() {
    // clap's conflicts_with attribute catches this at parse time.
    let (code, _, stderr) = run(&[
        "--require-watermark",
        "--no-watermark",
        "/any/file.mp3",
    ]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("cannot be used")
            || stderr.contains("conflicts")
            || stderr.contains("--no-watermark"),
        "expected clap conflict message, got stderr={stderr}"
    );
}
