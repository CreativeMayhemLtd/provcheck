// SPDX-License-Identifier: Apache-2.0
//! Offline-verify a signed DLC pack directory.
//!
//!   cargo run -p provcheck-dlc --example verify-pack -- <packdir> <issuer-did:key>
//!
//! Checks the detached `SHA256SUMS.sig` against the issuer's `did:key` and every
//! file's SHA-256 against the manifest — the exact check the app's license-gated
//! pull runs on download. Handy for proving a pack signed offline by
//! `dlc-issue pack-sign` is well-formed before publishing it to the mirror. Exit
//! 0 = verified, 1 = rejected, 2 = usage.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (dir, issuer) = match (args.first(), args.get(1)) {
        (Some(d), Some(i)) => (d.as_str(), i.as_str()),
        _ => {
            eprintln!("usage: verify-pack <packdir> <issuer-did:key>");
            return ExitCode::from(2);
        }
    };
    match provcheck_dlc::verify_pack_dir(std::path::Path::new(dir), issuer) {
        Ok(n) => {
            println!("pack OK: {n} file(s) verified against {issuer}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("pack REJECTED: {e}");
            ExitCode::from(1)
        }
    }
}
