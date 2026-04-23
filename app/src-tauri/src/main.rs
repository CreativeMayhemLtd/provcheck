// Prevents the Windows console from appearing alongside the GUI.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use serde::Serialize;
use provcheck_core::prelude::*;

/// JSON-friendly wrapper around provcheck_core::Report.
///
/// `provcheck_core::Report` already derives Serialize, but we return
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

#[tauri::command]
fn verify_file(path: String) -> VerifyResponse {
    let path = PathBuf::from(path);
    match verify(&path) {
        Ok(report) => VerifyResponse {
            ok: true,
            error: None,
            report: Some(report),
        },
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
