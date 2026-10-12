// SPDX-License-Identifier: Apache-2.0
//! Golden cross-repo wire vectors. These are the EXACT bytes Lysn.fm's `lysn-dlc`
//! produces for a fixed issuer seed + fixed license fields, hardcoded here so a
//! drift on either side of the wire fails a test instead of silently breaking a
//! paid seat license. A mirrored pair of assertions lives in Lysn.fm's `lysn-dlc`.
//!
//! Regenerating (only ever needed if the wire format INTENTIONALLY changes, which
//! must be coordinated across both repos): run
//! `cargo test -p provcheck-dlc golden_ -- --nocapture`; the assertion failure
//! prints the actual value to paste back here and into `lysn-dlc`.

/// `did:key` for Ed25519 signing seed `[7u8; 32]` (the seed the license golden
/// tests sign with).
pub const ISSUER_DID_SEED7: &str = "did:key:z6MkvDqGT54cXesYGvABpF1UapVNwjCqRcafi4Px6Thv5T3Z";

/// base58btc signature over the golden license (issuer = seed 7, product =
/// `pro-watermarking`, subject = `did:key:zBuyer`, issued_at =
/// `2026-08-19T12:00:00Z`, no expiry).
pub const LICENSE_SIG_SEED7: &str =
    "V9kHQ5qxLNuFVBnWAHtSKwyztX8yz7QPgjNBREGkxaiujBAC9R5YyNFbKrDPhbpJrdofKr2W3uoLAUcMqqh1GLX";
