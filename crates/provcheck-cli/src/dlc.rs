// SPDX-License-Identifier: Apache-2.0
//! provcheck's DLC management surface: inspect, unlock, and install the paid
//! keyed-watermarking pack (Backfire image + Mellin audio), gated on an
//! offline-verifiable **seat license** (`provcheck-dlc`).
//!
//! These are management commands that run and exit, exactly like
//! `--install-models` / `--install-backfire`; they never touch the C2PA verify
//! path. The pack the seat unlocks is the CM-signed payload of keyed tools the
//! `--mellin-read` / `--backfire-read` flags shell out to.
//!
//! The seat's durable identity — the `did:key` the license is bound to — is
//! sourced from `--seat-did` or `$PROVCHECK_SEAT_DID` for now. Auto-resolving it
//! from provcheck's own signing identity is the next step in the plan; until
//! then it is supplied explicitly, so the machinery is complete and the identity
//! source is the one thing left to swap.

use std::path::Path;
use std::process::ExitCode;

/// Resolve the seat identity from the flag, then the environment. A clear error
/// (not a panic) when neither is set — this is the seam the next step replaces.
fn seat_did(explicit: Option<&str>) -> Result<String, String> {
    if let Some(d) = explicit.filter(|d| !d.is_empty()) {
        return Ok(d.to_string());
    }
    match std::env::var("PROVCHECK_SEAT_DID") {
        Ok(d) if !d.is_empty() => Ok(d),
        _ => Err(
            "no seat identity. Pass --seat-did <did:key> or set PROVCHECK_SEAT_DID. \
             (Auto-sourcing the durable identity from your signing key is a later step.)"
                .to_string(),
        ),
    }
}

/// `--dlc-status`: list every known pack and whether this seat is licensed for it
/// and whether the payload is installed. Runs without a seat (everything shows
/// unlicensed) but notes how to name one.
pub fn status(seat: Option<&str>, quiet: bool) -> ExitCode {
    let home = match provcheck_dlc::default_home() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("provcheck: {e}");
            return ExitCode::from(2);
        }
    };
    // A seat is optional for a listing; with none, use a value that matches no
    // license so every pack reads unlicensed.
    let did = seat_did(seat).unwrap_or_else(|_| String::new());
    let rows = provcheck_dlc::dlc_status(&home, &did);
    if quiet {
        return ExitCode::SUCCESS;
    }
    if did.is_empty() {
        println!(
            "Seat: (none set — pass --seat-did <did:key> or PROVCHECK_SEAT_DID to see your entitlements)\n"
        );
    } else {
        println!("Seat: {did}\n");
    }
    for r in &rows {
        let lic = if !r.requires_license {
            "free"
        } else if r.licensed {
            "licensed"
        } else {
            "locked"
        };
        let inst = if r.installed {
            "installed"
        } else {
            "not installed"
        };
        println!("  {} [{}]  {} · {}", r.name, r.id, lic, inst);
        println!("      {}", r.summary);
        println!("      source: {}", r.default_source);
    }
    println!(
        "\nUnlock with:  provcheck --unlock-license <license.json> --seat-did <your did:key>\
         \nInstall with: provcheck --install-pack {} --seat-did <your did:key>",
        rows.first().map(|r| r.id.as_str()).unwrap_or("<pack-id>")
    );
    ExitCode::SUCCESS
}

/// `--unlock-license <FILE>`: store a seat license after verifying it is signed
/// by Creative Mayhem and bound to this seat.
pub fn unlock(file: &Path, seat: Option<&str>) -> ExitCode {
    let did = match seat_did(seat) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("provcheck: {e}");
            return ExitCode::from(2);
        }
    };
    let home = match provcheck_dlc::default_home() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("provcheck: {e}");
            return ExitCode::from(2);
        }
    };
    let json = match std::fs::read_to_string(file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("provcheck: could not read license {}: {e}", file.display());
            return ExitCode::from(2);
        }
    };
    match provcheck_dlc::dlc_unlock(&home, &json, &did) {
        Ok(st) => {
            println!("Unlocked '{}' for seat {did}.", st.name);
            if !st.installed {
                println!(
                    "Now install it:  provcheck --install-pack {} --seat-did {did}",
                    st.id
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("provcheck: license rejected: {e}");
            ExitCode::from(1)
        }
    }
}

/// `--install-pack <ID>`: pull the license-gated, signed pack into the seat's DLC
/// home. `source` overrides the catalog default (an https mirror, or a local /
/// UNC folder for offline installs).
pub fn install(product: &str, source: Option<&str>, seat: Option<&str>) -> ExitCode {
    let did = match seat_did(seat) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("provcheck: {e}");
            return ExitCode::from(2);
        }
    };
    let home = match provcheck_dlc::default_home() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("provcheck: {e}");
            return ExitCode::from(2);
        }
    };
    // Default to the catalog's mirror when no explicit source is given.
    let src = match source {
        Some(s) => s.to_string(),
        None => match provcheck_dlc::catalog()
            .into_iter()
            .find(|d| d.id == product)
        {
            Some(info) => info.default_source,
            None => {
                eprintln!("provcheck: unknown pack '{product}'");
                return ExitCode::from(2);
            }
        },
    };
    println!("Installing pack '{product}' from {src} ...");
    match provcheck_dlc::dlc_install(&home, product, &src, &did) {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("provcheck: install failed: {e}");
            ExitCode::from(1)
        }
    }
}
