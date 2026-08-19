// Prevents the Windows console from appearing alongside the GUI.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};

use provcheck::prelude::*;
use provcheck_attestation_spec::{IdentityClaim, SigningKeyRecord};
use provcheck_platform::{AttestationOptions, verify_with_attestation};
use provcheck_publish::AtprotoClient;
use provcheck_sign::backup::resolve_recovery_recipients;
use provcheck_sign::cert::{SubjectInfo, generate};
use provcheck_sign::persist::{default_dir, load_locked, save_public_artefacts};
use provcheck_sign::providers::{
    KeyProvider, KeychainProvider, NewPassphrasePrompt, ProviderError, UnlockPrompt,
};
use provcheck_sign::sign::{
    SignAction, default_action_for, embed_identity_assertion, inspect_source, sign_asset,
};
use provcheck_sign::types::{KeyProviderKind, LockedIdentity, UnlockedIdentity};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tauri::Manager;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

// ============================================================================
// Tab-specific commands (v1.1.0)
// ============================================================================

/// Watermark tab entry point. Runs every one of the six detector
/// families the workspace ships against the input file. Reuses the
/// full `verify` flow to fill the Report shell — the Watermark tab's
/// UI reads `report.watermarks` and ignores the C2PA fields — but
/// this keeps the JSON envelope byte-identical to what
/// `verify_file` returns so the frontend can share render code.
#[tauri::command]
async fn watermark_only(path: String) -> VerifyResponse {
    let path = PathBuf::from(path);
    tauri::async_runtime::spawn_blocking(move || match verify(&path) {
        Ok(mut report) => {
            push_all_watermarks(&path, &mut report);
            VerifyResponse {
                ok: true,
                error: None,
                report: Some(report),
            }
        }
        Err(e) => VerifyResponse {
            ok: false,
            error: Some(e.to_string()),
            report: None,
        },
    })
    .await
    .unwrap_or_else(|e| VerifyResponse {
        ok: false,
        error: Some(format!("watermark_only task panicked: {e}")),
        report: None,
    })
}

/// Experimental Backfire verify (its own tab). Shells out to the standalone
/// BUSL-licensed `backfire.py` tool, which is never compiled into or linked with this Apache-2.0
/// app, and returns its parsed JSON. Backfire is keyed: it reads a mark YOU
/// embedded, so a key is required. The tool is located via `$BACKFIRE_PY` or a
/// `backfire/backfire.py` beside the working directory. `read` auto-detects the
/// mark's resolution (256 or 512); it exits 0/1 on the `--expect` check, so stdout is
/// parsed regardless of exit status.
#[tauri::command]
async fn backfire_read(
    app: tauri::AppHandle,
    path: String,
    key: String,
    serial: Option<String>,
    carriers: Option<String>,
) -> ApiResult<serde_json::Value> {
    let resource = app.path().resource_dir().ok();
    tauri::async_runtime::spawn_blocking(move || {
        if key.trim().is_empty() {
            return ApiResult::err("A key is required to read a Backfire mark.".to_string());
        }
        let script = match locate_backfire_py(resource.as_deref()) {
            Some(p) => p,
            None => {
                log_line("backfire read: FAILED, no backfire.py found anywhere");
                return ApiResult::err(format!(
                    "Backfire tool not found. Use the Install / Repair button to set it up, set \
                     the BACKFIRE_PY environment variable to backfire.py, or reinstall provcheck \
                     (the reader ships inside the installer).\nFull log: {}",
                    log_path_display()
                ));
            }
        };
        let carriers = carriers.unwrap_or_else(|| "band".to_string());
        let serial = serial.filter(|s| !s.trim().is_empty());
        match run_backfire_py_read(
            &script,
            resource.as_deref(),
            &path,
            &key,
            serial.as_deref(),
            &carriers,
        ) {
            Ok(v) => ApiResult::ok(v),
            Err(e) => ApiResult::err(e),
        }
    })
    .await
    .unwrap_or_else(|e| ApiResult::err(format!("backfire_read task panicked: {e}")))
}

/// Diagnostic log file: `%LOCALAPPDATA%\provcheck\logs\provcheck.log` on
/// Windows, `~/.local/share/provcheck/logs/provcheck.log` elsewhere. Plain
/// text, one timestamped line per event, rotated at ~1 MB to `.log.old`.
fn app_log_path() -> Option<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).or_else(|| {
            std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("share"))
        })
    }?;
    Some(base.join("provcheck").join("logs").join("provcheck.log"))
}

/// Append one timestamped line to the diagnostic log. Strictly best-effort:
/// logging must never crash, block, or alter app behavior. Secrets (keys,
/// serials) are never passed to this function.
fn log_line(msg: &str) {
    let Some(path) = app_log_path() else { return };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(m) = std::fs::metadata(&path) {
        if m.len() > 1_000_000 {
            let _ = std::fs::rename(&path, path.with_extension("log.old"));
        }
    }
    let ts = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "?".into());
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "[{ts}] {msg}");
    }
}

/// The log path as a display string for surfacing in UI error messages.
fn log_path_display() -> String {
    app_log_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "(log path unavailable)".into())
}

/// Per-user, writable Backfire home: `%LOCALAPPDATA%\provcheck\backfire` on
/// Windows, `$XDG_DATA_HOME/provcheck/backfire` (or `~/.local/share/...`)
/// elsewhere. The Install Backfire button seeds the tool here and builds its
/// self-contained Python here, so nothing is written under Program Files.
fn backfire_home() -> Option<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).or_else(|| {
            std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("share"))
        })
    }?;
    Some(base.join("provcheck").join("backfire"))
}

/// Whether two paths resolve to the same directory. Canonicalizes both, so
/// `\\?\`-prefixed and plain spellings of one location compare equal.
fn same_dir(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// A `backfire` folder shipped beside the app executable, if it has backfire.py.
fn exe_backfire_dir() -> Option<PathBuf> {
    let dir = std::env::current_exe().ok()?.parent()?.join("backfire");
    dir.join("backfire.py").exists().then_some(dir)
}

/// Locate `backfire.py`. Order matters: `$BACKFIRE_PY` (explicit operator
/// override) first, then the APP'S BUNDLED RESOURCE COPY — it is read-only and
/// always version-matched to this build, so a stale or half-written per-user
/// copy can never shadow it — then the per-user home, a `backfire` folder
/// beside the exe, and finally `./backfire` (dev tree).
fn locate_backfire_py(resource: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = std::env::var("BACKFIRE_PY").ok().map(PathBuf::from) {
        if p.exists() {
            return Some(p);
        }
    }
    if let Some(res) = resource {
        let p = res.join("backfire").join("backfire.py");
        if p.exists() {
            return Some(p);
        }
    }
    if let Some(home) = backfire_home() {
        let p = home.join("backfire.py");
        if p.exists() {
            return Some(p);
        }
    }
    if let Some(dir) = exe_backfire_dir() {
        return Some(dir.join("backfire.py"));
    }
    let p = PathBuf::from("backfire/backfire.py");
    p.exists().then_some(p)
}

/// The directory to seed the Backfire home FROM: the app's bundled resource copy,
/// else a `backfire` folder beside the exe, else `./backfire`.
fn backfire_seed_source(resource: Option<&Path>) -> Option<PathBuf> {
    if let Some(res) = resource {
        let d = res.join("backfire");
        if d.join("backfire.py").exists() {
            return Some(d);
        }
    }
    if let Some(d) = exe_backfire_dir() {
        return Some(d);
    }
    let d = PathBuf::from("backfire");
    d.join("backfire.py").exists().then_some(d)
}

/// Recursively copy `src` into `dst`, skipping large or generated dirs
/// (`pyembed`, `__pycache__`, `.pytest_cache`). Seeds the writable Backfire
/// home from the read-only bundled copy.
fn copy_backfire_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        if matches!(
            name.to_string_lossy().as_ref(),
            "pyembed" | "__pycache__" | ".pytest_cache"
        ) {
            continue;
        }
        let from = entry.path();
        let to = dst.join(&name);
        if from.is_dir() {
            copy_backfire_tree(&from, &to)?;
        } else if let Err(e) = std::fs::copy(&from, &to) {
            // Name the exact file so a lock (antivirus, indexer, lingering
            // process) is diagnosable from the log instead of a bare os error.
            log_line(&format!(
                "backfire seed: copy FAILED {} -> {}: {e}",
                from.display(),
                to.display()
            ));
            return Err(std::io::Error::new(
                e.kind(),
                format!("copying {} -> {}: {e}", from.display(), to.display()),
            ));
        }
    }
    Ok(())
}

/// Run `backfire.py read` (tries `python3` then `python`) and parse its last stdout
/// line as JSON. `read` auto-detects the mark's resolution (256 or 512).
fn run_backfire_py_read(
    script: &Path,
    resource: Option<&Path>,
    path: &str,
    key: &str,
    serial: Option<&str>,
    carriers: &str,
) -> Result<serde_json::Value, String> {
    use std::process::Command;
    let mut argv: Vec<String> = vec![
        script.to_string_lossy().into_owned(),
        "read".into(),
        path.to_string(),
        "--key".into(),
        key.to_string(),
        "--carriers".into(),
        carriers.to_string(),
    ];
    if let Some(s) = serial {
        argv.push("--expect".into());
        argv.push(s.to_string());
    }
    // NOTE: argv contains the user's key — never log argv itself.
    log_line(&format!(
        "backfire read: file={path} script={}",
        script.display()
    ));
    let mut last_err = String::new();
    for py in backfire_interpreters(script, resource) {
        match Command::new(&py).args(&argv).output() {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let line = stdout.lines().last().unwrap_or("").trim();
                let stderr_tail: String = {
                    let s = String::from_utf8_lossy(&out.stderr);
                    let t = s.trim();
                    t.chars().rev().take(600).collect::<Vec<_>>().into_iter().rev().collect()
                };
                log_line(&format!(
                    "backfire read: interpreter={py} exit={:?} stdout_json={} stderr_len={}",
                    out.status.code(),
                    !line.is_empty(),
                    out.stderr.len()
                ));
                return serde_json::from_str::<serde_json::Value>(line).map_err(|e| {
                    log_line(&format!(
                        "backfire read: UNPARSEABLE output ({e}); stderr tail: {stderr_tail}"
                    ));
                    format!(
                        "Backfire produced unparseable output ({e}). stderr: {stderr_tail}\n\
                         Full log: {}",
                        log_path_display()
                    )
                });
            }
            Err(e) => {
                last_err = format!("could not run {py}: {e}");
                log_line(&format!("backfire read: interpreter FAILED to start: {last_err}"));
            }
        }
    }
    log_line(&format!("backfire read: NO interpreter worked ({last_err})"));
    Err(format!(
        "no usable Python found for Backfire. Use the Install / Repair button (or run \
         provcheck --install-backfire) to set one up. ({last_err})\nFull log: {}",
        log_path_display()
    ))
}

/// The `pyembed` interpreter inside a given backfire dir, if present.
fn pyembed_in(dir: &Path) -> Option<PathBuf> {
    let py = if cfg!(windows) {
        dir.join("pyembed").join("python.exe")
    } else {
        dir.join("pyembed").join("bin").join("python3")
    };
    py.exists().then_some(py)
}

/// Interpreters to try for Backfire, in order: the one beside the resolved
/// backfire.py, the interpreter SHIPPED INSIDE the installed app's resources
/// (works on a clean box, offline, with zero setup), one beside the exe, then
/// `python3` / `python` on PATH as a last resort.
fn backfire_interpreters(script: &Path, resource: Option<&Path>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |p: PathBuf| {
        let s = p.to_string_lossy().into_owned();
        if !out.contains(&s) {
            out.push(s);
        }
    };
    if let Some(dir) = script.parent() {
        if let Some(py) = pyembed_in(dir) {
            push(py);
        }
    }
    if let Some(res) = resource {
        if let Some(py) = pyembed_in(&res.join("backfire")) {
            push(py);
        }
    }
    if let Some(dir) = exe_backfire_dir() {
        if let Some(py) = pyembed_in(&dir) {
            push(py);
        }
    }
    out.push("python3".into());
    out.push("python".into());
    out
}

/// On launch, refresh the Backfire code in the writable home from the app's
/// bundled copy, keeping the already-built Python (`pyembed`). This self-heals a
/// stale or broken `backfire.py` left by an earlier install, without the user
/// hunting for an install button that is hidden once Backfire is set up. No-op
/// if Backfire was never set up on this box.
fn refresh_backfire_code(app: &tauri::AppHandle) {
    let Some(home) = backfire_home() else {
        return;
    };
    // Only refresh an existing install; do not auto-create one on launch.
    if !home.join("backfire.py").exists() {
        log_line("launch: no per-user backfire home; nothing to refresh (bundled copy is used)");
        return;
    }
    let resource = app.path().resource_dir().ok();
    if let Some(src) = backfire_seed_source(resource.as_deref()) {
        // With the NSIS per-user default, the install dir IS
        // %LOCALAPPDATA%\provcheck, so the "home" and the bundled copy are the
        // same directory. Copying a file onto itself fails with a sharing
        // violation (os error 32); there is nothing to refresh in that layout.
        if same_dir(&src, &home) {
            log_line("launch: backfire home IS the bundled copy (same directory); no refresh needed");
            return;
        }
        match copy_backfire_tree(&src, &home) {
            Ok(()) => log_line(&format!(
                "launch: refreshed backfire home {} from {}",
                home.display(),
                src.display()
            )),
            Err(e) => log_line(&format!(
                "launch: refresh of backfire home FAILED (non-fatal, bundled copy is preferred): {e}"
            )),
        }
    }
}

/// Whether the Backfire read environment is usable right now: a backfire.py is
/// locatable AND a self-contained interpreter exists in any of the places
/// `backfire_interpreters` searches (beside the script, inside the app's
/// bundled resources, or beside the exe). With the interpreter shipped in the
/// installer this is true on first launch with zero setup.
#[tauri::command]
async fn backfire_status(app: tauri::AppHandle) -> bool {
    let resource = app.path().resource_dir().ok();
    let Some(script) = locate_backfire_py(resource.as_deref()) else {
        log_line("backfire status: NOT READY (no backfire.py found anywhere)");
        return false;
    };
    let ready_via = if script.parent().and_then(pyembed_in).is_some() {
        Some("script-adjacent")
    } else if resource
        .as_deref()
        .and_then(|r| pyembed_in(&r.join("backfire")))
        .is_some()
    {
        Some("app-resources")
    } else if exe_backfire_dir().as_deref().and_then(pyembed_in).is_some() {
        Some("exe-adjacent")
    } else {
        None
    };
    match ready_via {
        Some(via) => {
            log_line(&format!(
                "backfire status: READY (script={}, interpreter={via})",
                script.display()
            ));
            true
        }
        None => {
            log_line(&format!(
                "backfire status: NOT READY (script={} found, but no pyembed interpreter)",
                script.display()
            ));
            false
        }
    }
}

/// Install / repair Backfire's read environment. The interpreter ships INSIDE
/// the installed app's resources, so on a normal install there is nothing to
/// download: this refreshes the per-user home's code from the bundle and
/// reports ready. Only when no interpreter exists anywhere (e.g. a stripped
/// portable copy) does it fall back to the network installer script.
#[tauri::command]
async fn install_backfire(app: tauri::AppHandle) -> ApiResult<String> {
    let resource = app.path().resource_dir().ok();
    tauri::async_runtime::spawn_blocking(move || {
        use std::process::Command;
        let Some(home) = backfire_home() else {
            log_line("backfire install: FAILED, LOCALAPPDATA unset");
            return ApiResult::err(
                "Could not resolve a writable Backfire folder (LOCALAPPDATA unset).".to_string(),
            );
        };
        log_line(&format!(
            "backfire install: start (home={}, resource={})",
            home.display(),
            resource
                .as_deref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "none".into())
        ));
        // The reader ships inside the app's resources, so if that (or any other)
        // interpreter is present, the app is ALREADY functional and nothing below
        // may fail the install. Check first.
        let have_interpreter = resource
            .as_deref()
            .and_then(|r| pyembed_in(&r.join("backfire")))
            .is_some()
            || pyembed_in(&home).is_some()
            || exe_backfire_dir().and_then(|d| pyembed_in(&d)).is_some();
        // Best-effort: refresh the per-user home's code from the bundled copy
        // (copy_backfire_tree skips pyembed). When the install dir IS the home
        // (NSIS per-user default installs to %LOCALAPPDATA%\provcheck) they are
        // the same directory and there is nothing to copy. A locked file here
        // (antivirus, indexer, a lingering python process) must never break a
        // working app, so with an interpreter present a copy failure is
        // reported, not fatal.
        let seed_err = match backfire_seed_source(resource.as_deref()) {
            Some(src) if same_dir(&src, &home) => {
                log_line("backfire install: home IS the bundled copy (same directory); nothing to seed");
                None
            }
            Some(src) => copy_backfire_tree(&src, &home).err().map(|e| e.to_string()),
            None => None,
        };
        if have_interpreter {
            log_line(&format!(
                "backfire install: READY via bundled interpreter (seed_err={:?})",
                seed_err
            ));
            return ApiResult::ok(match seed_err {
                None => "Backfire is ready (bundled reader present). Enter a key and drop an image."
                    .to_string(),
                Some(e) => format!(
                    "Backfire is ready (bundled reader present). Note: refreshing the optional \
                     per-user copy was skipped ({e}); the app uses its built-in copy. \
                     Full log: {}",
                    log_path_display()
                ),
            });
        }
        if let Some(e) = seed_err {
            log_line(&format!("backfire install: FAILED seeding home: {e}"));
            return ApiResult::err(format!(
                "Could not set up the Backfire folder at {}: {e}\nFull log: {}",
                home.display(),
                log_path_display()
            ));
        }
        if !home.join("backfire.py").exists() {
            log_line("backfire install: FAILED, no seed source and no existing home copy");
            return ApiResult::err(
                "Backfire files not found to install. Reinstall provcheck, or set BACKFIRE_PY."
                    .to_string(),
            );
        }
        log_line("backfire install: no bundled interpreter; falling back to network setup script");
        let (prog, args): (&str, Vec<String>) = if cfg!(windows) {
            let script = home.join("setup_backfire.ps1");
            if !script.exists() {
                return ApiResult::err(format!("setup_backfire.ps1 not found in {}", home.display()));
            }
            (
                "powershell",
                vec![
                    "-NoProfile".into(),
                    "-ExecutionPolicy".into(),
                    "Bypass".into(),
                    "-File".into(),
                    script.to_string_lossy().into_owned(),
                    "-Quiet".into(),
                ],
            )
        } else {
            let script = home.join("setup_backfire.sh");
            if !script.exists() {
                return ApiResult::err(format!("setup_backfire.sh not found in {}", home.display()));
            }
            ("bash", vec![script.to_string_lossy().into_owned(), "--quiet".into()])
        };
        match Command::new(prog).args(&args).output() {
            Ok(out) if out.status.success() => {
                log_line("backfire install: network setup script succeeded");
                ApiResult::ok("Backfire is ready. Enter a key and drop an image.".to_string())
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                log_line(&format!(
                    "backfire install: setup script FAILED exit={:?}: {}",
                    out.status.code(),
                    stderr.trim()
                ));
                ApiResult::err(format!(
                    "Backfire setup failed: {}\nFull log: {}",
                    stderr.trim(),
                    log_path_display()
                ))
            }
            Err(e) => {
                log_line(&format!("backfire install: could not start setup script: {e}"));
                ApiResult::err(format!(
                    "Could not run the Backfire setup script ({e}). It needs PowerShell on \
                     Windows, or bash on Linux/macOS.\nFull log: {}",
                    log_path_display()
                ))
            }
        }
    })
    .await
    .unwrap_or_else(|e| ApiResult::err(format!("install_backfire task panicked: {e}")))
}

/// Locate the standalone `provcheck-mellin` binary. Order: `$MELLIN_BIN`
/// (explicit operator override), the app's bundled resource copy (read-only
/// and version-matched to this build), then a `mellin` folder or bare binary
/// beside the exe. Like Backfire, Mellin is BUSL-licensed and NEVER linked
/// into this Apache-2.0 app; the process boundary is the license boundary.
fn locate_mellin_bin(resource: Option<&Path>) -> Option<PathBuf> {
    let exe_name = if cfg!(windows) {
        "provcheck-mellin.exe"
    } else {
        "provcheck-mellin"
    };
    if let Some(p) = std::env::var("MELLIN_BIN")
        .ok()
        .map(PathBuf::from)
        .filter(|p| p.exists())
    {
        return Some(p);
    }
    if let Some(res) = resource {
        let p = res.join("mellin").join(exe_name);
        if p.exists() {
            return Some(p);
        }
    }
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.to_path_buf()))
    {
        for cand in [dir.join("mellin").join(exe_name), dir.join(exe_name)] {
            if cand.exists() {
                return Some(cand);
            }
        }
    }
    None
}

/// Whether the Mellin read environment is usable right now: the standalone
/// binary is locatable. Ships inside the installer, so on a normal install
/// this is true on first launch with zero setup.
#[tauri::command]
async fn mellin_status(app: tauri::AppHandle) -> bool {
    let resource = app.path().resource_dir().ok();
    match locate_mellin_bin(resource.as_deref()) {
        Some(bin) => {
            log_line(&format!("mellin status: READY (bin={})", bin.display()));
            true
        }
        None => {
            log_line("mellin status: NOT READY (no provcheck-mellin binary found)");
            false
        }
    }
}

/// Experimental Mellin verify (Keyed marks tab). Shells out to the standalone
/// BUSL-licensed `provcheck-mellin` binary, never compiled into or linked with
/// this Apache-2.0 app, and returns its parsed `read --json` line. Mellin is
/// secret-keyed seller-side forensics: the seller secret travels ONLY as a
/// file path handed to the child's `--secret-file`; neither the secret nor
/// its path nor the work id is ever logged.
#[tauri::command]
async fn mellin_read(
    app: tauri::AppHandle,
    path: String,
    secret_file: String,
    work_id: String,
    serial: Option<String>,
    repeat: Option<u32>,
) -> ApiResult<serde_json::Value> {
    let resource = app.path().resource_dir().ok();
    tauri::async_runtime::spawn_blocking(move || {
        use std::process::Command;
        if secret_file.trim().is_empty() || work_id.trim().is_empty() {
            return ApiResult::err(
                "A secret file and a work id are required to read a Mellin serial.".to_string(),
            );
        }
        if !Path::new(&secret_file).exists() {
            return ApiResult::err(
                "The chosen secret file does not exist (or is not readable).".to_string(),
            );
        }
        let Some(bin) = locate_mellin_bin(resource.as_deref()) else {
            log_line("mellin read: FAILED, no provcheck-mellin binary found anywhere");
            return ApiResult::err(format!(
                "Mellin tool not found. Reinstall provcheck (the tool ships inside the \
                 installer), or set the MELLIN_BIN environment variable to the \
                 provcheck-mellin binary.\nFull log: {}",
                log_path_display()
            ));
        };
        let mut argv: Vec<String> = vec![
            "read".into(),
            path.clone(),
            "--secret-file".into(),
            secret_file.clone(),
            "--work-id".into(),
            work_id.clone(),
            "--json".into(),
        ];
        if let Some(s) = serial.filter(|s| !s.trim().is_empty()) {
            argv.push("--expect".into());
            argv.push(s);
        }
        if let Some(r) = repeat {
            argv.push("--repeat".into());
            argv.push(r.to_string());
        }
        // NOTE: argv contains the secret-file path and work id — never log argv.
        log_line(&format!("mellin read: file={path} bin={}", bin.display()));
        match Command::new(&bin).args(&argv).output() {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let line = stdout.lines().last().unwrap_or("").trim();
                log_line(&format!(
                    "mellin read: exit={:?} stdout_json={} stderr_len={}",
                    out.status.code(),
                    !line.is_empty(),
                    out.stderr.len()
                ));
                match serde_json::from_str::<serde_json::Value>(line) {
                    Ok(v) => ApiResult::ok(v),
                    Err(e) => {
                        let stderr_tail: String = {
                            let s = String::from_utf8_lossy(&out.stderr);
                            let t = s.trim();
                            t.chars().rev().take(600).collect::<Vec<_>>().into_iter().rev().collect()
                        };
                        log_line(&format!(
                            "mellin read: UNPARSEABLE output ({e}); stderr tail: {stderr_tail}"
                        ));
                        ApiResult::err(format!(
                            "Mellin produced unparseable output ({e}). stderr: {stderr_tail}\n\
                             Full log: {}",
                            log_path_display()
                        ))
                    }
                }
            }
            Err(e) => {
                log_line(&format!("mellin read: could not start binary: {e}"));
                ApiResult::err(format!(
                    "Could not run the Mellin tool ({e}).\nFull log: {}",
                    log_path_display()
                ))
            }
        }
    })
    .await
    .unwrap_or_else(|e| ApiResult::err(format!("mellin_read task panicked: {e}")))
}

/// Open a native "choose any file" dialog (no extension filter) and return the
/// selected absolute path. Used for the Mellin secret file and audio input,
/// where an extension filter would only get in the way.
#[tauri::command]
async fn pick_any_file(title: String) -> Option<String> {
    tauri::async_runtime::spawn_blocking(move || {
        rfd::FileDialog::new()
            .set_title(&title)
            .pick_file()
            .map(|p| p.to_string_lossy().into_owned())
    })
    .await
    .unwrap_or(None)
}

/// Open a native "choose file" dialog and return the selected absolute path, or None if
/// the user cancelled. The webview sandbox hides real paths from `<input type=file>`, so
/// the picker runs here in Rust; the frontend then routes the path to the active tab.
#[tauri::command]
async fn pick_image() -> Option<String> {
    tauri::async_runtime::spawn_blocking(|| {
        rfd::FileDialog::new()
            .add_filter("images", &["png", "jpg", "jpeg", "webp", "bmp", "tif", "tiff"])
            .set_title("Choose a file")
            .pick_file()
            .map(|p| p.to_string_lossy().into_owned())
    })
    .await
    .unwrap_or(None)
}

/// Count of installed vs total detector weights, for the "Install models" UI.
#[derive(Serialize)]
struct ModelsStatus {
    installed: usize,
    total: usize,
}

/// Install every detector weight in the manifest (download + SHA256-verify + cache).
/// The blocking network work runs off the UI thread. Returns a short summary; the
/// frontend shows a spinner while it runs.
#[tauri::command]
async fn install_models() -> ApiResult<String> {
    tauri::async_runtime::spawn_blocking(|| {
        let entries = provcheck_weights::MANIFEST;
        let mut ok = 0usize;
        let mut failed: Vec<String> = Vec::new();
        for e in entries {
            match provcheck_weights::download(e.family, e.variant) {
                Ok(_) => ok += 1,
                Err(err) => failed.push(format!("{}/{}: {err}", e.family, e.variant)),
            }
        }
        if failed.is_empty() {
            ApiResult::ok(format!(
                "All {ok} models installed. Watermark detection is ready."
            ))
        } else {
            ApiResult::err(format!(
                "{} of {} models failed: {}",
                failed.len(),
                entries.len(),
                failed.join("; ")
            ))
        }
    })
    .await
    .unwrap_or_else(|e| ApiResult::err(format!("install_models task panicked: {e}")))
}

/// Report how many detector weights are already installed, for the UI's initial state.
#[tauri::command]
async fn models_status() -> ApiResult<ModelsStatus> {
    tauri::async_runtime::spawn_blocking(|| {
        let all = provcheck_weights::status();
        let installed = all.iter().filter(|s| s.cached.exists).count();
        ApiResult::ok(ModelsStatus {
            installed,
            total: all.len(),
        })
    })
    .await
    .unwrap_or_else(|e| ApiResult::err(format!("models_status task panicked: {e}")))
}

/// Detect tab entry point. Runs the `provcheck-detect` registry
/// against the input file. The FOSS core registers ZERO detectors —
/// the trait is public plumbing for a paid-DLC pack (Creative Mayhem
/// v1.x roadmap) OR an operator-supplied third-party detector wrapper
/// (Apache-2.0 crate). Absent either, this returns an empty
/// `detections` list and the Detect tab's UI shows an educational
/// empty-state explaining bring-your-own.
///
/// Even so, the command exists so the frontend has a stable IPC hook
/// that becomes real the moment an operator drops a wrapper crate in
/// and registers a detector.
#[tauri::command]
async fn detect_only(path: String) -> VerifyResponse {
    let path = PathBuf::from(path);
    tauri::async_runtime::spawn_blocking(move || match verify(&path) {
        Ok(report) => {
            // Registry construction lives here so an operator-supplied
            // wrapper crate can grow this file with detector registrations
            // without touching the tab wiring:
            //   let mut reg = provcheck_detect::DetectorRegistry::new();
            //   reg.register(Box::new(SomeDetector::default()));
            //   let bytes = std::fs::read(&path).unwrap_or_default();
            //   report.detections = reg.run_all(&bytes);
            // FOSS core: zero detectors registered → detections stays
            // empty, frontend renders the "bring your own" educational
            // empty-state.
            VerifyResponse {
                ok: true,
                error: None,
                report: Some(report),
            }
        }
        Err(e) => VerifyResponse {
            ok: false,
            error: Some(e.to_string()),
            report: None,
        },
    })
    .await
    .unwrap_or_else(|e| VerifyResponse {
        ok: false,
        error: Some(format!("detect_only task panicked: {e}")),
        report: None,
    })
}

/// External URL opener. Tauri 2 sandboxes the webview; anchor tags
/// with `target="_blank"` are dropped on the floor by default. The
/// frontend intercepts external anchor clicks and IPC's them here.
/// `open::that` resolves the platform's default URL handler
/// (Windows: `cmd /c start`, macOS: `open`, Linux: `xdg-open`).
#[tauri::command]
fn open_url(url: String) -> Result<(), String> {
    // Defensive check: refuse anything that isn't http/https so a
    // malicious frontend can't shell-exec `file:///` or a data-URL
    // via this path. The GUI's own copy uses http(s) links only.
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(format!("refusing to open non-http(s) URL: {url}"));
    }
    open::that(url.as_str()).map_err(|e| format!("open failed: {e}"))
}

// ============================================================================
// Shared: run every watermark detector family the workspace ships and
// push each Ok() into the report. Used by verify_file (as one part of
// the CLI-parity verify flow) and by watermark_only (as the entire
// dispatch of the dedicated Watermark tab).
// ============================================================================

fn push_all_watermarks(path: &Path, report: &mut Report) {
    if let Ok(w) = provcheck_watermark::detect(path) {
        report.watermarks.push(w);
    }
    if let Ok(w) = provcheck_audioseal::detect(path) {
        report.watermarks.push(w);
    }
    if let Ok(w) = provcheck_wavmark::detect(path) {
        report.watermarks.push(w);
    }
    if let Ok(w) = provcheck_image::detect(path) {
        report.watermarks.push(w);
    }
    if let Ok(w) = provcheck_video::detect(path) {
        report.watermarks.push(w);
    }
    if let Ok(w) = provcheck_synthid_text::detect(path) {
        report.watermarks.push(w);
    }
}

// ============================================================================
// verify_file — existing CLI-parity verify (UNCHANGED contract)
// ============================================================================

/// JSON-friendly wrapper around provcheck::Report.
#[derive(Serialize)]
struct VerifyResponse {
    ok: bool,
    error: Option<String>,
    report: Option<Report>,
}

/// Verify a file with optional DID-anchored attestation.
///
/// `run_watermark` toggles the (potentially slow) neural watermark
/// detector. Defaults to `true` when unset so the field is
/// backward-compatible with v0.3.1 callers; the GUI sets it
/// explicitly from its identity-bar checkbox so the user can opt
/// out of the silentcipher inference cost.
///
/// The body runs inside `spawn_blocking` so the backend message
/// pump keeps draining during the 10+ second silentcipher
/// inference. Without this, Windows tags the window "not
/// responding" — the result still arrives correctly, but the UI
/// reads as hung to anyone watching.
#[tauri::command]
async fn verify_file(
    path: String,
    handle: Option<String>,
    did: Option<String>,
    require_attested: Option<bool>,
    run_watermark: Option<bool>,
) -> VerifyResponse {
    let path = PathBuf::from(path);
    let run_watermark = run_watermark.unwrap_or(true);

    tauri::async_runtime::spawn_blocking(move || {
        let want_attestation = handle.is_some() || did.is_some();

        let verify_result = if want_attestation {
            let attest_opts = AttestationOptions {
                bsky_handle: handle,
                did,
                require_attested: require_attested.unwrap_or(false),
                cache_dir: None,
                no_cache: false,
            };
            verify_with_attestation(&path, &VerifyOptions::default(), &attest_opts)
        } else {
            verify(&path)
        };

        match verify_result {
            Ok(mut report) => {
                if run_watermark {
                    // Run every one of the six detector families the
                    // workspace ships (v1.1.0). Each detector's
                    // `detect(&path)` is authoritative about whether
                    // it applies to the input file — audio detectors
                    // return Err on a PNG, image detector returns Err
                    // on WAV, etc. The `if let Ok` shape keeps
                    // successes; errors drop with their own diagnostics
                    // upstream. Called from both `verify_file` and
                    // `watermark_only` — see the shared helper below.
                    push_all_watermarks(&path, &mut report);
                }
                VerifyResponse {
                    ok: true,
                    error: None,
                    report: Some(report),
                }
            }
            Err(e) => VerifyResponse {
                ok: false,
                error: Some(e.to_string()),
                report: None,
            },
        }
    })
    .await
    .unwrap_or_else(|e| VerifyResponse {
        ok: false,
        error: Some(format!("verify task panicked: {e}")),
        report: None,
    })
}

// ============================================================================
// Sign-tab commands. These compose provcheck-sign + provcheck-publish into the
// same flows the kit binary exposes, but driven by webview UI instead of
// rpassword prompts. Backend selection: OS keychain (KeychainProvider) by
// default — matches `kit init`. The age-file backend is reachable too via
// `kit_init` but not exposed in the GUI's first pass.
// ============================================================================

/// Identity panel data for the Sign + Keys tabs. Mirrors `kit status`'s
/// identity block.
#[derive(Serialize)]
struct IdentitySnapshot {
    fingerprint: String,
    algorithm: String,
    /// RFC 3339.
    created_at: String,
    /// "keychain" | "encrypted_file" | "yubikey".
    backend: String,
    /// Stamped onto identity.json by a successful kit_login. When None
    /// the identity exists but hasn't been attached to atproto yet.
    did: Option<String>,
    handle: Option<String>,
    /// Yubikey hardware serial — `Some` only for Yubikey-backed
    /// identities. Used by the Keys tab to render the device strip.
    #[serde(skip_serializing_if = "Option::is_none")]
    yubikey_serial: Option<u32>,
    /// Yubikey PIV slot byte (`0x9c` in v0.5.0). `Some` only for
    /// Yubikey-backed identities.
    #[serde(skip_serializing_if = "Option::is_none")]
    yubikey_slot: Option<u8>,
    /// Whether the Yubikey identity's hardware is currently plugged
    /// in + reachable. `Some(true)` device present, `Some(false)`
    /// device not reachable, `None` for non-Yubikey identities.
    /// Lets the Keys tab render "Insert Yubikey to sign" without the
    /// whole tab failing.
    #[serde(skip_serializing_if = "Option::is_none")]
    yubikey_present: Option<bool>,
    /// PIV PIN tries remaining (0–3). `Some` only when the device is
    /// reachable for a Yubikey-backed identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pin_tries_remaining: Option<u8>,
}

/// Session panel data for the Sign tab. None when no session.json on disk.
#[derive(Serialize)]
struct SessionSnapshot {
    did: String,
    handle: String,
    pds: String,
}

/// Top-level state envelope the Sign tab uses to pick which state-screen
/// to render. Computed by kit_status; cheap, no network.
#[derive(Serialize)]
struct KitStatus {
    identity: Option<IdentitySnapshot>,
    session: Option<SessionSnapshot>,
}

/// Wire-friendly version of a single published signingKey record. Mirrors
/// SigningKeyRecord + the at-uri the rkey lives at.
#[derive(Serialize)]
struct RecordSnapshot {
    at_uri: String,
    rkey: Option<String>,
    fingerprint: String,
    algorithm: String,
    /// "active" | "revoked" | "superseded".
    status: &'static str,
    created_at: String,
    label: Option<String>,
    valid_from: Option<String>,
    valid_until: Option<String>,
    superseded_by: Option<String>,
}

/// Result wrapper — the JS side checks `ok` before consuming `data`.
#[derive(Serialize)]
struct ApiResult<T: Serialize> {
    ok: bool,
    error: Option<String>,
    data: Option<T>,
}

impl<T: Serialize> ApiResult<T> {
    fn ok(data: T) -> Self {
        Self {
            ok: true,
            error: None,
            data: Some(data),
        }
    }
    fn err(msg: String) -> Self {
        Self {
            ok: false,
            error: Some(msg),
            data: None,
        }
    }
}

fn resolve_dir(override_dir: Option<String>) -> Result<PathBuf, String> {
    match override_dir {
        Some(s) => Ok(PathBuf::from(s)),
        None => default_dir().map_err(|e| format!("resolve data dir: {e}")),
    }
}

fn record_status(r: &SigningKeyRecord) -> &'static str {
    if r.superseded_by.is_some() {
        "superseded"
    } else if r.valid_until.is_some() {
        "revoked"
    } else {
        "active"
    }
}

// -------- kit_status -----------------------------------------------------

#[tauri::command]
async fn kit_status(data_dir: Option<String>) -> ApiResult<KitStatus> {
    let dir = match resolve_dir(data_dir) {
        Ok(d) => d,
        Err(e) => return ApiResult::err(e),
    };

    let identity = load_locked(&dir).ok().map(|locked| {
        // For Yubikey identities, query the live device state so the
        // GUI can render "device present + N PIN tries" without a
        // separate command round-trip. Soft-failure: an unreachable
        // device produces yubikey_present = Some(false) so the GUI
        // shows a clear "Insert Yubikey" affordance rather than
        // hard-failing the whole status.
        let (yk_serial, yk_slot, yk_present, pin_tries) = match locked.key_provider {
            KeyProviderKind::Yubikey { serial, slot } => {
                let provider = provcheck_sign::providers::YubikeyProvider::new(serial, slot);
                match provider.pin_tries_remaining() {
                    Ok(tries) => (Some(serial), Some(slot), Some(true), Some(tries)),
                    Err(_) => (Some(serial), Some(slot), Some(false), None),
                }
            }
            _ => (None, None, None, None),
        };
        IdentitySnapshot {
            fingerprint: locked.fingerprint.clone(),
            algorithm: locked.algorithm.clone(),
            created_at: locked
                .created_at
                .format(&Rfc3339)
                .unwrap_or_else(|_| locked.created_at.to_string()),
            backend: match locked.key_provider {
                KeyProviderKind::Keychain => "keychain".into(),
                KeyProviderKind::EncryptedFile => "encrypted_file".into(),
                KeyProviderKind::Yubikey { .. } => "yubikey".into(),
            },
            did: locked.did.clone(),
            handle: locked.handle.clone(),
            yubikey_serial: yk_serial,
            yubikey_slot: yk_slot,
            yubikey_present: yk_present,
            pin_tries_remaining: pin_tries,
        }
    });

    let session = match AtprotoClient::load_session(&dir).await {
        Ok(c) => {
            let snap = c.snapshot();
            Some(SessionSnapshot {
                did: snap.did.clone(),
                handle: snap.handle.clone(),
                pds: snap.pds.clone(),
            })
        }
        Err(_) => None,
    };

    ApiResult::ok(KitStatus { identity, session })
}

// -------- kit_init -------------------------------------------------------

/// Generate a fresh ES256 identity and persist it. Backend defaults to
/// the OS keychain (no passphrase prompt needed — the OS handles its own
/// auth flow on first read).
#[tauri::command]
async fn kit_init(
    data_dir: Option<String>,
    force: Option<bool>,
) -> ApiResult<IdentitySnapshot> {
    let dir = match resolve_dir(data_dir) {
        Ok(d) => d,
        Err(e) => return ApiResult::err(e),
    };

    if !force.unwrap_or(false) && load_locked(&dir).is_ok() {
        return ApiResult::err(
            "an identity already exists at this data directory — pass force=true \
             to regenerate (this orphans any previously-published atproto records)"
                .to_string(),
        );
    }

    let kp = match generate(&SubjectInfo::default()) {
        Ok(k) => k,
        Err(e) => return ApiResult::err(format!("generate keypair: {e}")),
    };

    let locked = LockedIdentity {
        chain_pem: kp.chain_pem.clone(),
        fingerprint: kp.fingerprint.clone(),
        algorithm: kp.algorithm.clone(),
        did: None,
        handle: None,
        created_at: OffsetDateTime::now_utc(),
        key_provider: KeyProviderKind::Keychain,
        recovery_recipients: vec![],
    };

    // No passphrase prompt — the keychain provider stashes via the OS
    // backend, which has its own auth surface.
    let mut prompt =
        |_: NewPassphrasePrompt| -> Result<SecretString, ProviderError> {
            Ok(SecretString::from(String::new()))
        };
    if let Err(e) = KeychainProvider::new().store(
        &dir,
        &locked.fingerprint,
        &SecretString::from(kp.key_pem.clone()),
        &mut prompt,
    ) {
        return ApiResult::err(format!("store key in OS keychain: {e}"));
    }
    if let Err(e) = save_public_artefacts(&dir, &locked) {
        return ApiResult::err(format!("save identity.json: {e}"));
    }

    ApiResult::ok(IdentitySnapshot {
        fingerprint: locked.fingerprint,
        algorithm: locked.algorithm,
        created_at: locked
            .created_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| locked.created_at.to_string()),
        backend: "keychain".into(),
        did: None,
        handle: None,
        yubikey_serial: None,
        yubikey_slot: None,
        yubikey_present: None,
        pin_tries_remaining: None,
    })
}

// -------- kit_login -------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginArgs {
    handle: String,
    app_password: String,
    pds: Option<String>,
    data_dir: Option<String>,
}

#[tauri::command]
async fn kit_login(args: LoginArgs) -> ApiResult<SessionSnapshot> {
    let dir = match resolve_dir(args.data_dir) {
        Ok(d) => d,
        Err(e) => return ApiResult::err(e),
    };
    let pds = args.pds.unwrap_or_else(|| "https://bsky.social".into());

    let client = match AtprotoClient::login(&pds, &args.handle, &args.app_password).await
    {
        Ok(c) => c,
        Err(e) => return ApiResult::err(format!("atproto login: {e}")),
    };
    if let Err(e) = client.save_session(&dir).await {
        return ApiResult::err(format!("persist session: {e}"));
    }

    // Stamp did + handle on identity.json so subsequent sign --embed-identity
    // has them without round-tripping login. Best-effort: if no identity
    // is present locally, skip silently.
    if let Ok(mut locked) = load_locked(&dir) {
        let snap = client.snapshot();
        locked.did = Some(snap.did.clone());
        locked.handle = Some(snap.handle.clone());
        let _ = save_public_artefacts(&dir, &locked);
    }

    let snap = client.snapshot();
    ApiResult::ok(SessionSnapshot {
        did: snap.did.clone(),
        handle: snap.handle.clone(),
        pds: snap.pds.clone(),
    })
}

// -------- kit_logout ------------------------------------------------------

#[tauri::command]
async fn kit_logout(data_dir: Option<String>) -> ApiResult<()> {
    let dir = match resolve_dir(data_dir) {
        Ok(d) => d,
        Err(e) => return ApiResult::err(e),
    };
    match AtprotoClient::logout(&dir) {
        Ok(()) => ApiResult::ok(()),
        Err(e) => ApiResult::err(format!("delete session.json: {e}")),
    }
}

// -------- kit_remember_password / kit_recall_password / kit_forget_password ------
//
// "Remember me" on the Sign tab. The bsky app password is stashed in
// the OS keychain (Keychain Services on macOS, Credential Manager on
// Windows, Secret Service on Linux). Service namespace is
// `app.provcheck.bsky`, distinct from provcheck-sign's
// `app.provcheck.kit` so password material and signing-key material
// never share an entry. Account is the bsky handle so multiple
// accounts can coexist on one device without colliding.
//
// Errors here surface as ApiResult::err to the UI, but they should
// always be soft: prefill that fails simply leaves the field empty
// and the user types the password. Login flow never depends on
// successful keychain access.

const KEYCHAIN_SERVICE: &str = "app.provcheck.bsky";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RememberArgs {
    handle: String,
    app_password: String,
}

#[tauri::command]
fn kit_remember_password(args: RememberArgs) -> ApiResult<()> {
    let entry = match keyring::Entry::new(KEYCHAIN_SERVICE, &args.handle) {
        Ok(e) => e,
        Err(e) => return ApiResult::err(format!("keychain entry: {e}")),
    };
    match entry.set_password(&args.app_password) {
        Ok(()) => ApiResult::ok(()),
        Err(e) => ApiResult::err(format!("keychain set: {e}")),
    }
}

#[tauri::command]
fn kit_recall_password(handle: String) -> ApiResult<Option<String>> {
    let entry = match keyring::Entry::new(KEYCHAIN_SERVICE, &handle) {
        Ok(e) => e,
        Err(e) => return ApiResult::err(format!("keychain entry: {e}")),
    };
    match entry.get_password() {
        Ok(p) => ApiResult::ok(Some(p)),
        // NoEntry is the expected "not stored" outcome — not an error.
        Err(keyring::Error::NoEntry) => ApiResult::ok(None),
        Err(e) => ApiResult::err(format!("keychain get: {e}")),
    }
}

#[tauri::command]
fn kit_forget_password(handle: String) -> ApiResult<()> {
    let entry = match keyring::Entry::new(KEYCHAIN_SERVICE, &handle) {
        Ok(e) => e,
        Err(e) => return ApiResult::err(format!("keychain entry: {e}")),
    };
    match entry.delete_credential() {
        Ok(()) => ApiResult::ok(()),
        Err(keyring::Error::NoEntry) => ApiResult::ok(()),
        Err(e) => ApiResult::err(format!("keychain delete: {e}")),
    }
}

// -------- kit_publish -----------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublishArgs {
    label: Option<String>,
    data_dir: Option<String>,
}

#[derive(Serialize)]
struct PublishResult {
    at_uri: String,
    fingerprint: String,
}

#[tauri::command]
async fn kit_publish(args: PublishArgs) -> ApiResult<PublishResult> {
    let dir = match resolve_dir(args.data_dir) {
        Ok(d) => d,
        Err(e) => return ApiResult::err(e),
    };
    let locked = match load_locked(&dir) {
        Ok(l) => l,
        Err(e) => return ApiResult::err(format!("load identity: {e}")),
    };
    let client = match AtprotoClient::load_session(&dir).await {
        Ok(c) => c,
        Err(e) => return ApiResult::err(format!("load session — run kit_login first: {e}")),
    };
    let writer = provcheck_publish::RecordWriter::new(&client);

    // Guard against duplicates: refuse if a record with this fingerprint
    // is already in the repo (rotate is the path for a fresh fingerprint).
    let existing = match writer.list_signing_keys().await {
        Ok(v) => v,
        Err(e) => return ApiResult::err(format!("atproto list: {e}")),
    };
    if existing
        .iter()
        .any(|(_, r)| r.fingerprint == locked.fingerprint)
    {
        return ApiResult::err(format!(
            "a record with fingerprint {} already exists in your repo",
            locked.fingerprint
        ));
    }

    let created_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| String::new());
    let record = SigningKeyRecord {
        created_at,
        fingerprint: locked.fingerprint.clone(),
        algorithm: locked.algorithm.clone(),
        label: args.label,
        valid_from: None,
        valid_until: None,
        superseded_by: None,
    };
    let at_uri = match writer.publish_signing_key(&record).await {
        Ok(u) => u,
        Err(e) => return ApiResult::err(format!("atproto publish_signing_key: {e}")),
    };
    let _ = client.save_session(&dir).await;

    ApiResult::ok(PublishResult {
        at_uri: at_uri.as_str().to_string(),
        fingerprint: locked.fingerprint,
    })
}

// -------- kit_list --------------------------------------------------------

#[tauri::command]
async fn kit_list(data_dir: Option<String>) -> ApiResult<Vec<RecordSnapshot>> {
    let dir = match resolve_dir(data_dir) {
        Ok(d) => d,
        Err(e) => return ApiResult::err(e),
    };
    let client = match AtprotoClient::load_session(&dir).await {
        Ok(c) => c,
        Err(e) => return ApiResult::err(format!("load session: {e}")),
    };
    let writer = provcheck_publish::RecordWriter::new(&client);
    let records = match writer.list_signing_keys().await {
        Ok(v) => v,
        Err(e) => return ApiResult::err(format!("atproto list: {e}")),
    };

    let snapshots = records
        .into_iter()
        .map(|(uri, r)| RecordSnapshot {
            at_uri: uri.as_str().to_string(),
            rkey: uri.rkey().map(|s| s.to_string()),
            fingerprint: r.fingerprint.clone(),
            algorithm: r.algorithm.clone(),
            status: record_status(&r),
            created_at: r.created_at.clone(),
            label: r.label.clone(),
            valid_from: r.valid_from.clone(),
            valid_until: r.valid_until.clone(),
            superseded_by: r.superseded_by.clone(),
        })
        .collect();

    ApiResult::ok(snapshots)
}

// -------- kit_revoke ------------------------------------------------------
//
// Stamp `validUntil = now()` on an atproto signing-key record. The kit's
// CLI surface has this as `kit revoke <fingerprint>`; the GUI wraps it so
// the Keys-tab "revoke this orphan" action can call it without dropping
// to a terminal. Only needs the bsky session — no private key required,
// no Yubikey interaction, so the API surface is intentionally small.

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevokeArgs {
    /// Canonical fingerprint of the record to revoke
    /// (`sha256:<lowercase-hex>`).
    fingerprint: String,
    /// Optional successor at-uri to set on the revoked record's
    /// `supersededBy` field. When `None`, the record is plain
    /// revoked without a successor pointer (useful when you don't
    /// have a replacement yet — orphan-cleanup case).
    superseded_by: Option<String>,
    data_dir: Option<String>,
}

#[derive(Serialize)]
struct RevokeResult {
    rkey: String,
}

#[tauri::command]
async fn kit_revoke(args: RevokeArgs) -> ApiResult<RevokeResult> {
    let dir = match resolve_dir(args.data_dir) {
        Ok(d) => d,
        Err(e) => return ApiResult::err(e),
    };
    let client = match AtprotoClient::load_session(&dir).await {
        Ok(c) => c,
        Err(e) => return ApiResult::err(format!("load session: {e}")),
    };
    let writer = provcheck_publish::RecordWriter::new(&client);

    // Find the record by fingerprint. Walk the user's published
    // records to pick out the matching rkey.
    let records = match writer.list_signing_keys().await {
        Ok(r) => r,
        Err(e) => return ApiResult::err(format!("list signing keys: {e}")),
    };
    let matching = records.iter().find(|(_, rec)| rec.fingerprint == args.fingerprint);
    let (uri, current) = match matching {
        Some(pair) => pair,
        None => {
            return ApiResult::err(format!(
                "no record with fingerprint {} found in your atproto repo",
                args.fingerprint
            ));
        }
    };
    let rkey = match uri.rkey() {
        Some(r) => r.to_string(),
        None => return ApiResult::err(format!("at-uri {} has no rkey", uri.as_str())),
    };

    // Mutate: set validUntil = now, optionally set supersededBy.
    let mut updated = current.clone();
    let now_iso = match OffsetDateTime::now_utc().format(&Rfc3339) {
        Ok(s) => s,
        Err(e) => return ApiResult::err(format!("format now(): {e}")),
    };
    updated.valid_until = Some(now_iso);
    if let Some(s) = args.superseded_by {
        updated.superseded_by = Some(s);
    }

    if let Err(e) = writer.update_signing_key(&rkey, &updated).await {
        return ApiResult::err(format!("update record on atproto: {e}"));
    }

    ApiResult::ok(RevokeResult { rkey })
}

// -------- kit_rotate ------------------------------------------------------
//
// Mint a fresh keypair on the recorded backend, publish it as a new active
// record, and revoke the previous record with a `supersededBy` link.
// Software-backend rotation only in v0.5.0 P4 — Yubikey rotation would
// need a separate `kit_rotate_yubikey` taking a fresh PIN through a
// callback, which the Keys-tab UI doesn't surface yet.

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateArgs {
    /// Optional label for the new record.
    label: Option<String>,
    data_dir: Option<String>,
}

#[derive(Serialize)]
struct RotateResult {
    new_fingerprint: String,
    new_at_uri: String,
    old_fingerprint: String,
}

#[tauri::command]
async fn kit_rotate(args: RotateArgs) -> ApiResult<RotateResult> {
    let dir = match resolve_dir(args.data_dir) {
        Ok(d) => d,
        Err(e) => return ApiResult::err(e),
    };
    let old = match load_locked(&dir) {
        Ok(l) => l,
        Err(e) => return ApiResult::err(format!("load current identity: {e}")),
    };

    // Refuse Yubikey rotation cleanly — the in-process flow can't
    // collect a fresh PIN through this API surface. Users must run
    // `provcheck-kit init --yubikey --force` from a terminal.
    if matches!(old.key_provider, KeyProviderKind::Yubikey { .. }) {
        return ApiResult::err(
            "GUI rotation of a Yubikey-backed identity isn't supported yet. \
             Run `provcheck-kit init --yubikey --force` from a terminal, \
             then come back here to publish + revoke."
                .to_string(),
        );
    }

    let client = match AtprotoClient::load_session(&dir).await {
        Ok(c) => c,
        Err(e) => return ApiResult::err(format!("load session: {e}")),
    };
    let writer = provcheck_publish::RecordWriter::new(&client);

    // Mint fresh software keypair.
    let kp = match provcheck_sign::cert::generate(&provcheck_sign::cert::SubjectInfo::default()) {
        Ok(kp) => kp,
        Err(e) => return ApiResult::err(format!("generate keypair: {e}")),
    };
    let new_fingerprint = kp.fingerprint.clone();
    let new_key_secret = SecretString::from(kp.key_pem.clone());

    // Store the new key under the SAME backend the old identity used
    // (Yubikey case is refused above, so this is keychain or age).
    let mut store_prompt =
        |_: provcheck_sign::providers::NewPassphrasePrompt| -> Result<SecretString, ProviderError> {
            Ok(SecretString::from(String::new()))
        };
    let store_result = match old.key_provider {
        KeyProviderKind::Keychain => provcheck_sign::providers::KeychainProvider::new()
            .store(&dir, &new_fingerprint, &new_key_secret, &mut store_prompt),
        KeyProviderKind::EncryptedFile => {
            return ApiResult::err(
                "GUI rotation of age-file-backed identities isn't wired yet. \
                 Use `provcheck-kit rotate` from a terminal."
                    .to_string(),
            );
        }
        KeyProviderKind::Yubikey { .. } => unreachable!("refused above"),
    };
    if let Err(e) = store_result {
        return ApiResult::err(format!("store new key in backend: {e}"));
    }

    // Persist the new public artefacts (overwrites identity.json).
    let now = OffsetDateTime::now_utc();
    let new_locked = provcheck_sign::types::LockedIdentity {
        chain_pem: kp.chain_pem,
        fingerprint: new_fingerprint.clone(),
        algorithm: kp.algorithm.clone(),
        did: old.did.clone(),
        handle: old.handle.clone(),
        created_at: now,
        key_provider: old.key_provider,
        recovery_recipients: old.recovery_recipients.clone(),
    };
    if let Err(e) = save_public_artefacts(&dir, &new_locked) {
        return ApiResult::err(format!("save new identity.json: {e}"));
    }

    // Publish the new record on atproto.
    let created_at_iso = match now.format(&Rfc3339) {
        Ok(s) => s,
        Err(e) => return ApiResult::err(format!("format created_at: {e}")),
    };
    let new_record = SigningKeyRecord {
        created_at: created_at_iso,
        fingerprint: new_fingerprint.clone(),
        algorithm: kp.algorithm,
        label: args.label,
        valid_from: None,
        valid_until: None,
        superseded_by: None,
    };
    let new_uri = match writer.publish_signing_key(&new_record).await {
        Ok(uri) => uri,
        Err(e) => return ApiResult::err(format!("publish new record: {e}")),
    };

    // Revoke the previous record IF it's still active on atproto.
    let existing_records = writer.list_signing_keys().await.unwrap_or_default();
    let old_fp = old.fingerprint.clone();
    if let Some((old_uri, old_rec)) = existing_records
        .iter()
        .find(|(_, r)| r.fingerprint == old_fp && r.valid_until.is_none())
    {
        if let Some(rkey) = old_uri.rkey() {
            let mut revoked = old_rec.clone();
            revoked.valid_until = Some(match OffsetDateTime::now_utc().format(&Rfc3339) {
                Ok(s) => s,
                Err(e) => return ApiResult::err(format!("format revoke timestamp: {e}")),
            });
            revoked.superseded_by = Some(new_uri.as_str().to_string());
            // Best-effort: a failure here leaves both records active
            // on atproto. The user can manually revoke later.
            let _ = writer.update_signing_key(rkey, &revoked).await;
        }
    }

    ApiResult::ok(RotateResult {
        new_fingerprint,
        new_at_uri: new_uri.as_str().to_string(),
        old_fingerprint: old_fp,
    })
}

// -------- kit_list_yubikeys -----------------------------------------------
//
// Enumerate connected Yubikeys. Used by the Keys-tab "Switch to
// Yubikey-backed identity" affordance to render the device-selection
// step (or skip it when only one device is connected).

#[derive(Serialize)]
struct YubikeyDeviceInfo {
    serial: u32,
}

#[tauri::command]
fn kit_list_yubikeys() -> ApiResult<Vec<YubikeyDeviceInfo>> {
    match provcheck_sign::providers::yubikey::list_connected() {
        Ok(serials) => ApiResult::ok(
            serials
                .into_iter()
                .map(|s| YubikeyDeviceInfo { serial: s })
                .collect(),
        ),
        Err(e) => ApiResult::err(format!("enumerate Yubikeys: {e}")),
    }
}

// -------- kit_sign --------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignArgs {
    file: String,
    /// When None → sidecar `<stem>.signed.<ext>` next to source.
    /// When Some → write to this path (must differ from `file` AND share extension).
    out: Option<String>,
    embed_identity: Option<bool>,
    /// One of "created" / "opened" / "edited" / "published" (or
    /// the canonical "c2pa." prefixed form). When None, the
    /// kit defaults to "published" if the source already has a
    /// C2PA manifest, "created" otherwise.
    action: Option<String>,
    /// When Some, mark the produced asset as AI-generated. The
    /// action assertion carries `digitalSourceType` =
    /// `trainedAlgorithmicMedia` (the IPTC NewsCodes term verifier
    /// tooling looks for), and the contained string lands on the
    /// action's `softwareAgent` field as the model/tool that
    /// produced the asset. None leaves the manifest unchanged.
    ai_artist_model: Option<String>,
    data_dir: Option<String>,
}

#[derive(Serialize)]
struct SignResultDto {
    output_path: String,
    manifest_bytes: usize,
    identity_embedded: Option<String>,
    /// The action label that ended up on the new manifest, e.g.
    /// "c2pa.published". Returned so the GUI can confirm it back
    /// to the user without re-deriving.
    action: String,
    /// Provenance of the source file, if it had any. Lets the GUI
    /// show "you just signed a derivative of …" in the done state.
    chained_from: Option<SourceProvenanceDto>,
}

/// Wire-friendly view of a source file's C2PA provenance. Mirrors
/// provcheck_sign::sign::SourceProvenance with explicit field
/// renames so the JS side has consistent camelCase.
#[derive(Serialize)]
struct SourceProvenanceDto {
    claim_generator: Option<String>,
    signer: Option<String>,
    title: Option<String>,
    label: String,
    format: Option<String>,
}

impl From<provcheck_sign::sign::SourceProvenance> for SourceProvenanceDto {
    fn from(s: provcheck_sign::sign::SourceProvenance) -> Self {
        Self {
            claim_generator: s.claim_generator,
            signer: s.signer,
            title: s.title,
            label: s.label,
            format: s.format,
        }
    }
}

/// Inspect a file for existing C2PA provenance. The GUI calls this
/// in the sign preview state to decide whether to show the "you'll
/// be adding to an existing chain" notice and to default the
/// action selector to Published.
#[tauri::command]
async fn kit_inspect_source(path: String) -> ApiResult<Option<SourceProvenanceDto>> {
    let p = PathBuf::from(path);
    ApiResult::ok(inspect_source(&p).map(Into::into))
}

#[tauri::command]
async fn kit_sign(args: SignArgs) -> ApiResult<SignResultDto> {
    let dir = match resolve_dir(args.data_dir) {
        Ok(d) => d,
        Err(e) => return ApiResult::err(e),
    };
    let locked = match load_locked(&dir) {
        Ok(l) => l,
        Err(e) => return ApiResult::err(format!("load identity: {e}")),
    };

    // Unlock — keychain backend has no passphrase prompt from our side
    // (OS handles it). EncryptedFile backend would need a passphrase UI
    // which is a follow-up — for v1 we only run the GUI flow against
    // keychain-backed identities.
    let mut prompt =
        |_: UnlockPrompt| -> Result<SecretString, ProviderError> {
            Ok(SecretString::from(String::new()))
        };
    let key_pem = match locked.key_provider {
        KeyProviderKind::Keychain => {
            match KeychainProvider::new().fetch(&dir, &locked.fingerprint, &mut prompt) {
                Ok(k) => k,
                Err(e) => return ApiResult::err(format!("fetch key: {e}")),
            }
        }
        KeyProviderKind::EncryptedFile => {
            return ApiResult::err(
                "GUI signing currently supports OS-keychain identities only. \
                 Use `provcheck-kit sign` from the CLI for age-file identities."
                    .to_string(),
            );
        }
        KeyProviderKind::Yubikey { .. } => {
            return ApiResult::err(
                "GUI signing of Yubikey-backed identities lands in v0.5.0 P3 + P4. \
                 For now, sign via `provcheck-kit sign` from a terminal — the kit \
                 prompts for the PIV PIN on each signature."
                    .to_string(),
            );
        }
    };
    let unlocked = UnlockedIdentity::new(locked.clone(), key_pem);

    let src = PathBuf::from(&args.file);
    let dst = match args.out.as_ref() {
        Some(p) => PathBuf::from(p),
        None => sidecar_signed_path(&src),
    };

    // Inspect the source for prior provenance so we can pick the
    // right default action AND echo the chain into the returned
    // SignResultDto for the GUI's done card.
    let provenance = inspect_source(&src);
    let action = match args.action.as_deref() {
        Some(s) => match SignAction::parse(s) {
            Some(a) => a,
            None => {
                return ApiResult::err(format!(
                    "action {s:?}: expected one of created/opened/edited/published"
                ));
            }
        },
        None => default_action_for(provenance.as_ref()),
    };

    let base_manifest = match default_manifest(&src, action, args.ai_artist_model.as_deref()) {
        Ok(m) => m,
        Err(e) => return ApiResult::err(e),
    };
    let embed = args.embed_identity.unwrap_or(true);
    let (manifest_json, embedded_did) = if embed {
        match locked.did.as_ref() {
            Some(did) => {
                let claim = IdentityClaim::new(did.clone(), locked.handle.clone());
                match embed_identity_assertion(&base_manifest, &claim) {
                    Ok(m) => (m, Some(did.clone())),
                    Err(e) => {
                        return ApiResult::err(format!("embed identity assertion: {e}"));
                    }
                }
            }
            None => {
                return ApiResult::err(
                    "embed-identity requires a DID — run kit_login first".to_string(),
                );
            }
        }
    } else {
        (base_manifest, None)
    };

    let result = match sign_asset(&unlocked, &src, &dst, &manifest_json) {
        Ok(r) => r,
        Err(e) => return ApiResult::err(format!("c2pa sign: {e}")),
    };

    ApiResult::ok(SignResultDto {
        output_path: result.output_path.to_string_lossy().into_owned(),
        manifest_bytes: result.manifest_bytes.len(),
        identity_embedded: embedded_did,
        action: action.as_c2pa_label().to_string(),
        chained_from: provenance.map(Into::into),
    })
}

fn sidecar_signed_path(src: &Path) -> PathBuf {
    let parent = src.parent();
    let stem = src
        .file_stem()
        .map(|s| s.to_owned())
        .unwrap_or_else(|| std::ffi::OsString::from("signed"));
    let ext = src.extension();
    let mut name = stem;
    name.push(".signed");
    if let Some(e) = ext {
        name.push(".");
        name.push(e);
    }
    match parent {
        Some(p) if !p.as_os_str().is_empty() => p.join(name),
        _ => PathBuf::from(name),
    }
}

fn default_manifest(
    asset: &Path,
    action: SignAction,
    ai_artist_model: Option<&str>,
) -> Result<String, String> {
    let format = format_from_extension(asset)
        .ok_or_else(|| "unrecognised file extension — custom manifest needed".to_string())?;
    let title = asset
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("untitled");
    let mut action_obj = serde_json::json!({"action": action.as_c2pa_label()});
    if let Some(model) = ai_artist_model {
        let trimmed = model.trim();
        // Mark the action as AI-generated regardless of whether the
        // model string is empty — the digitalSourceType is the
        // verifier-readable signal; softwareAgent is decoration that
        // only appears when the user gave us a name.
        action_obj["digitalSourceType"] = serde_json::Value::String(
            "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia".to_string(),
        );
        if !trimmed.is_empty() {
            action_obj["softwareAgent"] = serde_json::Value::String(trimmed.to_string());
        }
    }
    // Bind the claim_generator strings to CARGO_PKG_VERSION so they
    // stay in sync with the Cargo.toml + tauri.conf.json on every
    // release. Previously hardcoded to "0.3.1", which drifted four
    // versions before anyone noticed.
    const CG: &str = concat!("provcheck-app/", env!("CARGO_PKG_VERSION"));
    let v = serde_json::json!({
        "claim_generator": CG,
        "claim_generator_info": [{"name": "provcheck-app", "version": env!("CARGO_PKG_VERSION")}],
        "format": format,
        "title": title,
        "assertions": [
            {
                "label": "c2pa.actions.v2",
                "data": {"actions": [action_obj]}
            }
        ]
    });
    Ok(v.to_string())
}

fn format_from_extension(p: &Path) -> Option<&'static str> {
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

// ============================================================================
// main
// ============================================================================

fn main() {
    // resolve_recovery_recipients is unused in pass 1 but pulled in by the
    // backup module's surface — silence the dead-code warning. Drops naturally
    // when the backup UI lands.
    let _ = resolve_recovery_recipients as fn(&[provcheck_sign::types::RecoveryRecipient]) -> _;
    tauri::Builder::default()
        .setup(|app| {
            // Launch banner in the diagnostic log: version + the paths every
            // Backfire decision derives from.
            let res = app
                .path()
                .resource_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "unresolvable".into());
            let exe = std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "unknown".into());
            log_line(&format!(
                "launch: provcheck-app v{} exe={exe} resource_dir={res}",
                env!("CARGO_PKG_VERSION")
            ));
            // Self-heal any stale/broken Backfire code from a prior install so the
            // read path always runs the bundled (current) backfire.py.
            refresh_backfire_code(app.handle());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            verify_file,
            // v1.1.0: dedicated Watermark + Detect tabs.
            watermark_only,
            detect_only,
            // Experimental keyed-marks tab (Backfire + Mellin, both shell out
            // to their standalone BUSL tools; never linked).
            backfire_read,
            backfire_status,
            install_backfire,
            mellin_read,
            mellin_status,
            // Native "choose file" dialogs shared by the tabs.
            pick_image,
            pick_any_file,
            // Watermark-detection model management (download-on-demand weights).
            install_models,
            models_status,
            // v1.1.0: Tauri 2 webview sandboxes `<a href target="_blank">`
            // — brand links in the top bar were silent no-ops. This
            // command shells out to the platform URL handler via the
            // `open` crate. Called from a delegated JS click handler.
            open_url,
            kit_status,
            kit_init,
            kit_login,
            kit_logout,
            kit_remember_password,
            kit_recall_password,
            kit_forget_password,
            kit_publish,
            kit_revoke,
            kit_rotate,
            kit_list_yubikeys,
            kit_list,
            kit_sign,
            kit_inspect_source,
        ])
        .run(tauri::generate_context!())
        .expect("error while running provcheck-app");
}
