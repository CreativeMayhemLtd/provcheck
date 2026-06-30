//! Pin that the three v1.0 release-prep docs exist and cross-link
//! each other correctly. These docs cover task #155 in the v0.9.x
//! pre-release audit:
//!
//! 1. `docs/public-api-stability.md` — what's stable, what's not.
//! 2. `docs/semver-policy.md` — versioning rules.
//! 3. `docs/release-process.md` — mechanical release checklist.
//!
//! A future maintainer who deletes or renames one of these files
//! breaks the operator-facing release contract documented at
//! README + CONTRIBUTING; this test guards against silent
//! removal.

use std::path::Path;

fn workspace_root() -> &'static Path {
    // crates/provcheck/tests/v1_release_docs.rs → up three.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
}

fn doc(path: &str) -> std::path::PathBuf {
    workspace_root().join("docs").join(path)
}

#[test]
fn public_api_stability_doc_exists() {
    assert!(
        doc("public-api-stability.md").is_file(),
        "docs/public-api-stability.md must exist (v1.0 release-prep contract)"
    );
}

#[test]
fn semver_policy_doc_exists() {
    assert!(
        doc("semver-policy.md").is_file(),
        "docs/semver-policy.md must exist (v1.0 release-prep contract)"
    );
}

#[test]
fn release_process_doc_exists() {
    assert!(
        doc("release-process.md").is_file(),
        "docs/release-process.md must exist (v1.0 release-prep contract)"
    );
}

#[test]
fn public_api_stability_links_to_siblings() {
    // The three docs are deliberately cross-linked so any single
    // doc is a useful entry point to the other two. Pin so a
    // future rename of one of the files doesn't silently break
    // the navigation.
    let body = std::fs::read_to_string(doc("public-api-stability.md"))
        .expect("read public-api-stability.md");
    assert!(
        body.contains("semver-policy.md"),
        "public-api-stability.md must link to semver-policy.md"
    );
    assert!(
        body.contains("release-process.md"),
        "public-api-stability.md must link to release-process.md"
    );
}

#[test]
fn semver_policy_links_to_siblings() {
    let body =
        std::fs::read_to_string(doc("semver-policy.md")).expect("read semver-policy.md");
    assert!(
        body.contains("public-api-stability.md"),
        "semver-policy.md must link to public-api-stability.md"
    );
    assert!(
        body.contains("release-process.md"),
        "semver-policy.md must link to release-process.md"
    );
}

#[test]
fn release_process_links_to_siblings() {
    let body = std::fs::read_to_string(doc("release-process.md"))
        .expect("read release-process.md");
    assert!(
        body.contains("public-api-stability.md"),
        "release-process.md must link to public-api-stability.md"
    );
    assert!(
        body.contains("semver-policy.md"),
        "release-process.md must link to semver-policy.md"
    );
}

#[test]
fn release_process_names_the_release_matrix_glob() {
    // Pin that the doc references the actual release-yml glob,
    // not a stale wildcard. A future change to release.yml that
    // shifts the gate should be paired with a doc update.
    let body = std::fs::read_to_string(doc("release-process.md"))
        .expect("read release-process.md");
    assert!(
        body.contains("v*.*.0"),
        "release-process.md must reference the v*.*.0 release-matrix glob"
    );
}

#[test]
fn semver_policy_documents_msrv_bump_rule() {
    // The MSRV bump rule has a concrete numeric guarantee ("at
    // least 12 weeks old"). Pin that the doc carries it; without
    // a concrete threshold the rule is meaningless.
    let body =
        std::fs::read_to_string(doc("semver-policy.md")).expect("read semver-policy.md");
    assert!(
        body.contains("12 weeks") || body.contains("two stable Rust"),
        "semver-policy.md must document the MSRV bump time window"
    );
}

#[test]
fn public_api_stability_lists_every_publishable_crate() {
    // Every workspace crate that will publish to crates.io must
    // appear in the stability matrix; otherwise a downstream
    // consumer has no contract guidance for it.
    let body = std::fs::read_to_string(doc("public-api-stability.md"))
        .expect("read public-api-stability.md");
    for crate_name in [
        "provcheck",
        "provcheck-attestation-spec",
        "provcheck-cli",
        "provcheck-kit",
        "provcheck-sign",
        "provcheck-publish",
        "provcheck-watermark",
        "provcheck-audioseal",
        "provcheck-wavmark",
        "provcheck-image",
        "provcheck-video",
        "provcheck-synthid-text",
        "provcheck-weights",
        "provcheck-platform",
    ] {
        assert!(
            body.contains(crate_name),
            "public-api-stability.md must mention crate {crate_name}"
        );
    }
}
