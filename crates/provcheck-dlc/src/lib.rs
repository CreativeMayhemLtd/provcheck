// SPDX-License-Identifier: Apache-2.0
//! # provcheck-dlc — the DLC framework
//!
//! provcheck's core is free and open (Apache-2.0). The keyed forensic
//! watermarking tools — **Backfire** (image) and **Mellin** (audio) — are
//! frontier tools Creative Mayhem sells as a paid, opt-in **DLC pack**. The
//! Apache binary never contains the pack; it is pulled on demand and gated on an
//! offline-verifiable **seat license**.
//!
//! This crate is the license VERIFIER and the pack PULLER, not the watermark IP
//! (that lives in the standalone, BUSL-licensed `backfire` tool and the
//! `provcheck-mellin` binary, which provcheck only ever shells out to across a
//! process boundary). It is therefore permissive-clean and safe to ship inside
//! the Apache-2.0 binary per `WATERMARK_LICENSE_POLICY.md`.
//!
//! ## Ported from Lysn.fm, byte-identical on the wire
//!
//! This is a faithful port of Lysn.fm's `lysn-dlc` (plus the minimal `lysn-sign`
//! / `lysn-jcs` it needs and the signed-pack pull from `lysn-desktop-core`). The
//! [`ProLicense`] wire format — its fields, the `lysn-prolicense/v1` domain tag,
//! the RFC 8785 canonicalization, and the did:key / base58 codecs — is identical
//! to Lysn.fm's, so ONE seat license, issued once by the offline `dlc-issue`
//! tool, verifies in BOTH the Lysn.fm desktop app and provcheck. The €10 buys a
//! seat = one durable identity; it is spent wherever the tools appear.
//!
//! **Cross-repo contract:** any change to the license bytes, the domain tags, the
//! codecs, or the JCS canonicalization is a wire-breaking change that MUST land
//! in both repos together. The golden tests (`golden_did_key_for_fixed_seed_*`,
//! `golden_signed_license_*`) lock the exact bytes; a mirrored pair lives in
//! Lysn.fm's `lysn-dlc`.
//!
//! ## What is and is not gated
//!
//! The seat license gates **installing the pack** (`dlc_install`): the CM-signed,
//! CM-approved payload of executable keyed tools is pulled only for a licensed
//! seat. Once installed, the tools themselves are governed by their own BUSL
//! terms (free for non-commercial use). Wiring the seat to provcheck's durable
//! identity, and the purchase→issue→redeem flow, are the next steps in the plan.

mod jcs;
mod license;
mod sign;

#[cfg(feature = "install")]
mod install;

#[cfg(test)]
pub(crate) mod testvectors;

// ── Public API ──────────────────────────────────────────────────────────────

pub use license::{
    DLC_MANIFEST_DOMAIN, DLC_PRO_WATERMARKING, DlcError, DlcInfo, LICENSE_ISSUER_DID, ProLicense,
    catalog,
};

// The signing primitive. `verify_sig` + the did:key codecs are what the license
// gate needs; `sign_bytes` + `DomainSigned::sign` are for the offline issuer and
// the tests. All faithful to `lysn-sign`.
pub use sign::{
    DomainSigned, SignError, did_key_from_verifying, sig_from_str, sig_to_str, sign_bytes,
    signing_bytes, verify_sig, verifying_from_did_key,
};

#[cfg(feature = "install")]
pub use install::{
    DlcStatus, default_home, dlc_install, dlc_pack_dir, dlc_status, dlc_unlock, verify_pack_dir,
};
