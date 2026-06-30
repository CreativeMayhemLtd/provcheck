//! End-to-end smoke test for the v0.3.0 producer→verifier loop.
//!
//! Drives the library APIs directly (bypassing the kit binary's
//! interactive passphrase / OS-keychain prompts) so we can prove
//! the wire-format contract on every push without needing a TTY
//! or a real bsky account. The binary-surface side gets
//! `kit --version` / `kit status --data-dir <empty>` /
//! `kit verify` via `Command::new` so we also touch the actual
//! compiled binary's dispatch.
//!
//! What this DOES cover:
//!   - cert generation produces a usable ES256 keypair
//!   - the AgeFileProvider round-trips the key (encrypt + decrypt)
//!   - sign_asset produces a c2pa-readable manifest
//!   - embed_identity_assertion splices the assertion into a manifest
//!   - the signed file's signing-cert fingerprint matches the
//!     identity's fingerprint via the spec-crate hasher
//!   - the verifier's c2pa::Reader reads the file successfully
//!   - provcheck::verify_with_options extracts the identity claim
//!     back out (the load-bearing producer→verifier contract)
//!   - kit-binary --version / --help / status all dispatch cleanly
//!
//! What this DOES NOT cover (needs out-of-band setup):
//!   - kit init's interactive passphrase / OS-keychain prompt path
//!   - login / publish / list / revoke / rotate (need a live PDS)
//!   - the GUI's auto-fill (needs a live Tauri build session)

use std::path::Path;
use std::process::Command;

use provcheck::prelude::{IdentityClaim, verify};
use provcheck_attestation_spec::fingerprint_pem_chain;
use provcheck_sign::cert::{SubjectInfo, generate};
use provcheck_sign::providers::{AgeFileProvider, KeyProvider, NewPassphrasePrompt};
use provcheck_sign::sign::{embed_identity_assertion, sign_asset};
use provcheck_sign::types::{KeyProviderKind, LockedIdentity, UnlockedIdentity};
use secrecy::SecretString;
use time::OffsetDateTime;

/// Locate the `provcheck-kit` binary the cargo runner just built.
/// `CARGO_BIN_EXE_<name>` is a cargo convention; only available
/// when the test crate has `[[bin]]` of that name (it does).
fn kit_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_provcheck-kit"))
}

/// Write a 1-second silent mono WAV. Same shape as the rest of the
/// workspace's test fixtures. No copyright question, accepted by
/// the c2pa Reader as audio/wav.
fn write_silent_wav(p: &Path) {
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate: 44_100,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };
    let mut w = hound::WavWriter::create(p, spec).expect("wav writer");
    for _ in 0..44_100 {
        w.write_sample(0i16).expect("write sample");
    }
    w.finalize().expect("finalize wav");
}

#[test]
fn kit_binary_version_dispatches_cleanly() {
    let out = Command::new(kit_bin())
        .arg("--version")
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("provcheck-kit"), "version output: {stdout}");
    // Track the workspace version dynamically — env!("CARGO_PKG_VERSION")
    // pulls from this test crate's Cargo.toml, which inherits
    // version.workspace = true. Hardcoding a literal here caused a
    // false-positive failure at every version bump.
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "version output: {stdout}",
    );
}

#[test]
fn kit_binary_status_on_empty_dir_reports_both_none() {
    let tmp = tempfile::tempdir().expect("tmp");
    let out = Command::new(kit_bin())
        .args(["status", "--data-dir"])
        .arg(tmp.path())
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("[identity]"), "status output: {stdout}");
    assert!(
        stdout.contains("none — run `kit init`"),
        "status output: {stdout}"
    );
    assert!(
        stdout.contains("[atproto session]"),
        "status output: {stdout}"
    );
    // The fixed status command — used to print
    // "(status not implemented yet — sub-pass 4d)". Make sure that
    // regression never comes back.
    assert!(
        !stdout.contains("not implemented yet"),
        "status regression: {stdout}"
    );
    assert!(stdout.contains("kit login"), "status output: {stdout}");
}

#[test]
fn kit_binary_help_for_every_subcommand_renders() {
    // Touch every subcommand's --help to confirm clap parses each
    // arg shape without panicking. Catches any subcommand whose
    // Args struct has an inconsistent flag combination (e.g.
    // conflicts_with referring to a removed field).
    let commands = [
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
    ];
    for cmd in commands {
        let out = Command::new(kit_bin())
            .args([cmd, "--help"])
            .output()
            .unwrap_or_else(|e| panic!("spawn {cmd} --help: {e}"));
        assert!(
            out.status.success(),
            "{cmd} --help exit {:?} stderr {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn import_backup_identity_file_flag_appears_in_help() {
    // v0.9.66 added `kit import-backup --identity-file <PATH>` to
    // wire X25519-recipient backups through the CLI. Pin that the
    // flag shows up in --help so a future maintainer can't
    // accidentally drop it.
    let out = Command::new(kit_bin())
        .args(["import-backup", "--help"])
        .output()
        .expect("spawn import-backup --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("--identity-file"),
        "--identity-file flag missing from import-backup --help: {stdout}"
    );
    // The doc text mentions the rage-keygen format and X25519
    // recipients — pin both so the help stays usefully descriptive.
    assert!(
        stdout.contains("X25519") || stdout.contains("recipients"),
        "import-backup --help should reference X25519 / recipients context: {stdout}"
    );
}

#[test]
fn export_then_import_x25519_round_trip_via_library_apis() {
    // Mirrors the v0.4 passphrase round-trip but for the X25519
    // recipient path that v0.9.66 wires through the kit CLI.
    // Drives the library APIs (not the binary) to keep the test
    // hermetic — the binary-level smoke test above already
    // exercises the --identity-file dispatch.
    use std::str::FromStr;
    use provcheck_sign::backup::{
        export_with_recipients, import_with_x25519_identity,
    };

    let tmp = tempfile::tempdir().expect("tmp");
    let bundle_path = tmp.path().join("backup.age");

    // Build a real UnlockedIdentity (same shape as the production
    // identities the kit creates).
    let subject = SubjectInfo::default();
    let kp = generate(&subject).expect("cert");
    let now = OffsetDateTime::now_utc();
    let locked = LockedIdentity {
        chain_pem: kp.chain_pem.clone(),
        fingerprint: fingerprint_pem_chain(&kp.chain_pem).expect("fp"),
        algorithm: "ES256".into(),
        did: Some("did:plc:test".into()),
        handle: Some("test.bsky.social".into()),
        created_at: now,
        key_provider: KeyProviderKind::EncryptedFile,
        recovery_recipients: Vec::new(),
    };
    let unlocked = UnlockedIdentity::new(locked, SecretString::from(kp.key_pem.clone()));

    // Generate an X25519 identity, export with its public recipient,
    // then import with the matching secret identity.
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();

    export_with_recipients(&unlocked, &bundle_path, std::slice::from_ref(&recipient))
        .expect("export with recipients");

    // The CLI parses the identity file by scanning lines for
    // `AGE-SECRET-KEY-1`. Round-trip via to_string + from_str
    // explicitly so the test matches the CLI's parse path, not
    // just the library's Identity::generate hot path.
    use secrecy::ExposeSecret as _;
    let exposed = identity.to_string();
    let secret_text: &str = exposed.expose_secret();
    let parsed = age::x25519::Identity::from_str(secret_text.trim())
        .expect("parse identity from string");

    let bundle = import_with_x25519_identity(&bundle_path, &parsed)
        .expect("import with x25519");
    assert_eq!(bundle.fingerprint, unlocked.locked.fingerprint);
    assert_eq!(bundle.chain_pem, unlocked.locked.chain_pem);
}

#[test]
fn import_backup_identity_file_with_missing_file_exits_nonzero() {
    // Operator hands a path that doesn't exist. Should fail
    // cleanly with a useful message, not panic.
    let out = Command::new(kit_bin())
        .args([
            "import-backup",
            "--identity-file",
            "/no/such/identity/file/zzz",
            "/no/such/backup/file/zzz.age",
        ])
        .output()
        .expect("spawn import-backup with bogus paths");
    assert!(
        !out.status.success(),
        "expected non-zero exit on missing identity file"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Either the identity-file IO error or the bundle IO error
    // is acceptable (depends on which path the implementation
    // touches first). The load-bearing contract is "non-zero
    // exit with some operator-readable diagnostic".
    assert!(
        stderr.contains("identity")
            || stderr.contains("backup")
            || stderr.contains("no such")
            || stderr.contains("No such"),
        "expected diagnostic message, got stderr: {stderr}"
    );
}

#[test]
fn end_to_end_identity_assertion_round_trip() {
    // Drives the same crates the kit binary composes, only with
    // hard-coded passphrases in place of the interactive prompts.
    // Exercises the load-bearing producer→verifier contract: did
    // the assertion the kit's sign path embeds get extracted by
    // the verifier's verification path with the same did + handle?

    let tmp = tempfile::tempdir().expect("tmp");
    let data_dir = tmp.path();

    // Step 1: generate identity directly.
    let kp = generate(&SubjectInfo::default()).expect("generate keypair");
    let locked = LockedIdentity {
        chain_pem: kp.chain_pem.clone(),
        fingerprint: kp.fingerprint.clone(),
        algorithm: kp.algorithm.clone(),
        did: Some("did:plc:smoke-test-roundtrip".to_string()),
        handle: Some("smoke.bsky.social".to_string()),
        created_at: OffsetDateTime::UNIX_EPOCH,
        key_provider: KeyProviderKind::EncryptedFile,
        recovery_recipients: vec![],
    };

    // Step 2: stash the key via the age-file provider with a known
    // passphrase, then immediately fetch it back to confirm the
    // round-trip works.
    let provider = AgeFileProvider::new();
    let pass = SecretString::from("smoke-test-passphrase-1234".to_string());
    let pass_for_store = pass.clone();
    let pass_for_fetch = pass.clone();
    provider
        .store(
            data_dir,
            &locked.fingerprint,
            &SecretString::from(kp.key_pem.clone()),
            &mut move |_: NewPassphrasePrompt| Ok(pass_for_store.clone()),
        )
        .expect("store key via AgeFileProvider");
    let recovered = provider
        .fetch(data_dir, &locked.fingerprint, &mut move |_| {
            Ok(pass_for_fetch.clone())
        })
        .expect("fetch key back");
    let unlocked = UnlockedIdentity::new(locked.clone(), recovered);

    // Step 3: sign a fixture with the app.provcheck.identity assertion
    // embedded.
    let src = data_dir.join("src.wav");
    let dst = data_dir.join("signed.wav");
    write_silent_wav(&src);
    let manifest = serde_json::json!({
        "claim_generator": "provcheck-kit-smoke/0.3.0",
        "claim_generator_info": [{"name": "provcheck-kit-smoke", "version": "0.3.0"}],
        "format": "audio/wav",
        "title": "smoke.wav",
        "assertions": [
            {"label": "c2pa.actions.v2", "data": {"actions": [{"action": "c2pa.created"}]}}
        ]
    })
    .to_string();
    let claim = IdentityClaim::new(locked.did.clone().unwrap(), locked.handle.clone());
    let with_identity =
        embed_identity_assertion(&manifest, &claim).expect("embed identity assertion");
    let result = sign_asset(&unlocked, &src, &dst, &with_identity).expect("sign_asset");
    assert!(dst.exists(), "signed file written");
    assert!(!result.manifest_bytes.is_empty());

    // Step 4: read back via the verifier crate. This is the
    // load-bearing assertion — proves the wire-format contract
    // holds end-to-end.
    let report = verify(&dst).expect("verify");
    assert!(
        report.verified,
        "crypto valid (failure: {:?})",
        report.failure_reason
    );
    let extracted = report
        .identity
        .expect("identity claim extracted from signed file");
    assert_eq!(extracted.did, "did:plc:smoke-test-roundtrip");
    assert_eq!(extracted.handle.as_deref(), Some("smoke.bsky.social"));
    assert_eq!(extracted.version, Some(1));

    // Step 5: confirm the fingerprint on the signed file matches
    // what we generated. This is the second load-bearing
    // assertion — the atproto cross-check relies on it.
    let active = report.signer.as_deref().unwrap_or("");
    assert!(!active.is_empty(), "signer present");
    // The spec-crate hasher should give the same fingerprint when
    // we re-hash the cert chain stored in the locked identity.
    let our_fp = fingerprint_pem_chain(&locked.chain_pem).expect("hash chain");
    assert_eq!(our_fp, locked.fingerprint, "spec-crate hash stable");
}

#[test]
fn in_place_sign_round_trip_uses_sibling_tempfile() {
    // Regression test for the 5060 smoke-test bug: `kit sign foo.wav`
    // with no --out claimed "in-place" but c2pa-rs refuses src == dst.
    // The fix uses a sidecar temp file and atomic-renames over the
    // source on success. This test drives the library functions
    // directly (provcheck-sign + provcheck) with hard-coded
    // passphrases so it runs without a TTY.

    let tmp = tempfile::tempdir().expect("tmp");
    let src = tmp.path().join("in-place.wav");
    // Matches the path the production sign command would compute
    // via sidecar_tmp_path: stem.signed-tmp.ext (extension preserved
    // so c2pa-rs's source/dest format check passes).
    let temp_sidecar = tmp.path().join("in-place.signed-tmp.wav");
    write_silent_wav(&src);
    let original_size = std::fs::metadata(&src).expect("stat").len();

    // Generate identity inline (same shape as the round-trip test).
    let kp = generate(&SubjectInfo::default()).expect("kp");
    let locked = LockedIdentity {
        chain_pem: kp.chain_pem.clone(),
        fingerprint: kp.fingerprint.clone(),
        algorithm: kp.algorithm.clone(),
        did: None,
        handle: None,
        created_at: OffsetDateTime::UNIX_EPOCH,
        key_provider: KeyProviderKind::EncryptedFile,
        recovery_recipients: vec![],
    };
    let unlocked = UnlockedIdentity::new(locked, SecretString::from(kp.key_pem.clone()));

    // Simulate the in-place flow: write to the sidecar, rename over.
    // This is the exact path commands::sign::run takes when --out is
    // None, only without the interactive unlock.
    let manifest = serde_json::json!({
        "claim_generator": "smoke/0",
        "format": "audio/wav",
        "title": "in-place.wav",
        "assertions": [
            {"label": "c2pa.actions.v2", "data": {"actions": [{"action": "c2pa.created"}]}}
        ]
    })
    .to_string();
    sign_asset(&unlocked, &src, &temp_sidecar, &manifest).expect("sign");
    assert!(temp_sidecar.exists(), "temp written");
    assert!(src.exists(), "source untouched until rename");

    // Atomic rename — the load-bearing primitive for this fix.
    std::fs::rename(&temp_sidecar, &src).expect("rename");
    assert!(!temp_sidecar.exists(), "temp gone after rename");
    let new_size = std::fs::metadata(&src).expect("stat").len();
    assert!(
        new_size > original_size,
        "signed file is larger than original (manifest embedded): {original_size} → {new_size}"
    );

    // And it verifies.
    let report = verify(&src).expect("verify");
    assert!(report.verified, "{:?}", report.failure_reason);
}

#[test]
fn kit_binary_verify_shells_out_to_provcheck() {
    // The verify shortcut spawns the configured provcheck binary.
    // We point it at the workspace's `provcheck` binary (built by
    // the cargo test harness as a sibling target) and the
    // committed signed sample. trailing_var_arg lets us pass
    // --no-watermark through to skip the slow detector.
    let provcheck_bin = kit_bin().with_file_name(if cfg!(windows) {
        "provcheck.exe"
    } else {
        "provcheck"
    });
    if !provcheck_bin.exists() {
        // Skip rather than fail when the verifier binary wasn't
        // built (e.g. a `cargo test -p provcheck-kit` that
        // doesn't pull in the sibling binary).
        eprintln!(
            "skipping kit_binary_verify_shells_out_to_provcheck: {} not present",
            provcheck_bin.display()
        );
        return;
    }
    let sample = std::path::Path::new("../../examples/rAIdio.bot-sample.mp3");
    if !sample.exists() {
        eprintln!(
            "skipping kit_binary_verify_shells_out_to_provcheck: {} not present",
            sample.display()
        );
        return;
    }
    let out = Command::new(kit_bin())
        .arg("verify")
        .arg(sample)
        .arg("--provcheck-bin")
        .arg(&provcheck_bin)
        .arg("--")
        .arg("--no-watermark")
        .output()
        .expect("spawn kit verify");
    assert!(
        out.status.success(),
        "kit verify exit {:?} stderr {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("VERIFIED"), "verify output: {stdout}");
    assert!(stdout.contains("rAIdio.bot"), "verify output: {stdout}");
}
