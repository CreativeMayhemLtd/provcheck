// Prevents the Windows console from appearing alongside the GUI.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use serde::Serialize;
use provcheck::prelude::*;
use provcheck_platform::{AttestationOptions, verify_with_attestation};

/// JSON-friendly wrapper around provcheck::Report.
///
/// `provcheck::Report` already derives Serialize, but we return
/// it through this wrapper anyway so the Tauri command's return type
/// never leaks a `Result<T, E>` where `T` is a foreign type — keeps
/// the frontend contract stable if the core type ever adds fields
/// we don't want to surface.
#[derive(Serialize)]
struct VerifyResponse {
    ok: bool,
    error: Option<String>,
    report: Option<Report>,
}

/// Verify a file with optional DID-anchored attestation.
///
/// Identity args are optional; when neither `handle` nor `did`
/// is provided we stay on the offline `verify()` path and the
/// returned `Report` carries `did_attestation: None`. When at
/// least one is provided we route through
/// `provcheck_platform::verify_with_attestation` — mirrors the
/// CLI dispatch at `provcheck-cli/src/main.rs:124-153`.
///
/// Watermark detectors run after the verify step on the
/// resulting `Report` regardless of which path produced it.
#[tauri::command]
fn verify_file(
    path: String,
    handle: Option<String>,
    did: Option<String>,
    require_attested: Option<bool>,
) -> VerifyResponse {
    let path = PathBuf::from(path);
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
            // Run each enabled watermark detector alongside the
            // C2PA verify and append its result to `report.watermarks`.
            // Failures here are informational — detector decoder
            // problems surface via the result's `message` field
            // rather than as an error. Adding a new FOSS detector
            // means appending another `if let Ok(...)` block here.
            if let Ok(w) = provcheck_watermark::detect(&path) {
                report.watermarks.push(w);
            }
            if let Ok(w) = provcheck_audioseal::detect(&path) {
                report.watermarks.push(w);
            }
            if let Ok(w) = provcheck_wavmark::detect(&path) {
                report.watermarks.push(w);
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
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![verify_file])
        .run(tauri::generate_context!())
        .expect("error while running provcheck-app");
}
