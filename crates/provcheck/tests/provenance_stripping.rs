//! Adversarial regression tests against a real provenance-stripping tool.
//!
//! These are the CI-side anchor for the survival matrix in
//! [`docs/provenance-stripping-survival.md`]. The premise, stated in
//! that document, is a non-negotiable invariant:
//!
//!   **provcheck must never report a stripped asset as verified.**
//!
//! Stripping provenance can defeat detection; it must never be able to
//! forge a passing verdict. To make that a standing regression guard
//! rather than a prose promise, we commit two tiny fixtures:
//!
//! - `signed.jpg` — a JPEG carrying an embedded C2PA manifest (signed
//!   by a throwaway provcheck-kit identity).
//! - `watermarks-remover-v0.5.0-stripped.jpg` — the exact byte output
//!   of running that signed JPEG through
//!   [watermarks-remover](https://github.com/guillaumemeyer/watermarks-remover)
//!   v0.5.0 `clean_image.py`. Its own report confirmed
//!   `still_has_c2pa: false`.
//!
//! The test asserts that provcheck sees a manifest on the first and
//! reports the second as unsigned and unverified. These call the
//! `verify()` library entry, which performs C2PA verification only (the
//! neural-watermark detectors live in the CLI layer), so the tests need
//! no ONNX Runtime and run clean in CI.
//!
//! Assertions are deliberately expiry-robust: we check manifest
//! presence and the never-verify invariant, not the throwaway cert's
//! trust chain, so a committed fixture cannot go flaky when its test
//! cert ages out.
//!
//! To refresh these fixtures against a newer watermarks-remover
//! release, see `scripts/provenance-strip-matrix.py`.

use std::path::PathBuf;

use provcheck::prelude::*;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("adversary")
        .join(name)
}

/// Baseline: the pre-strip asset carries a manifest provcheck can see.
/// (We assert manifest presence, not trust, so the throwaway signing
/// cert's validity window can never make this flaky.)
#[test]
fn signed_baseline_has_manifest() {
    let report = verify(&fixture("signed.jpg")).expect("verify returns Ok");
    assert!(
        !report.unsigned,
        "signed baseline must present a manifest (unsigned=false); got {report:?}"
    );
}

/// The invariant. A real provenance-stripper's output must never verify,
/// and must report as unsigned. If a future change ever let a
/// manifest-less file report `verified`, this fails loudly.
#[test]
fn adversary_stripped_asset_never_verifies() {
    let report =
        verify(&fixture("watermarks-remover-v0.5.0-stripped.jpg")).expect("verify returns Ok");
    assert!(
        !report.verified,
        "INVARIANT VIOLATED: a stripped asset reported verified; got {report:?}"
    );
    assert!(
        report.unsigned,
        "stripped asset must report unsigned=true; got {report:?}"
    );
}
