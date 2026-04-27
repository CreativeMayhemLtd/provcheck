//! Integration tests for DID-anchored attestation.
//!
//! Most tests exercise [`provcheck_platform::check_attestation`]
//! directly — that's the layer where DID resolution, PDS access, and
//! fingerprint matching happen. A smaller smoke test goes through the
//! full [`provcheck_platform::verify_with_attestation`] pipeline
//! against a bogus DID to confirm the wiring is in place.
//!
//! Architecture note: tests deliberately *don't* try to feed mocked
//! URLs through the full `verify_with_attestation` path — those
//! overrides live on `AttestationConfig`, which `verify_with_attestation`
//! constructs internally. Mocked end-to-end coverage stays at the
//! `check_attestation` granularity, where it's both reliable and
//! exercised against the same network code the wrapper uses.

mod common;

use std::path::PathBuf;

use provcheck::report::AttestationStatus;
use provcheck::verification::VerifyOptions;
use provcheck_platform::{
    AttestationConfig, AttestationOptions, check_attestation, fingerprint_leaf_cert,
    verify_with_attestation,
};

use common::{MockServer, sign_with_fresh_chain, write_silent_wav};

// ---- Builders for mocked PDS responses -------------------------------------

/// Build a `did:web` identifier that points back to a localhost mock.
/// Per the did:web spec, port colons are encoded as `%3A`.
fn make_did_for_mock(server: &MockServer) -> String {
    format!("did:web:{}", server.addr().replace(':', "%3A"))
}

/// Minimal DID document with a single PDS service entry.
fn make_did_doc(did: &str, pds_endpoint: &str) -> String {
    serde_json::json!({
        "id": did,
        "service": [
            {
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": pds_endpoint
            }
        ]
    })
    .to_string()
}

/// Build a single `app.provcheck.signingKey` record entry.
fn make_record(
    fingerprint: &str,
    valid_from: Option<&str>,
    valid_until: Option<&str>,
) -> serde_json::Value {
    let mut value = serde_json::json!({
        "$type": "app.provcheck.signingKey",
        "createdAt": "2026-01-01T00:00:00Z",
        "fingerprint": fingerprint,
        "algorithm": "ES256",
    });
    if let Some(vf) = valid_from {
        value["validFrom"] = serde_json::Value::String(vf.to_string());
    }
    if let Some(vu) = valid_until {
        value["validUntil"] = serde_json::Value::String(vu.to_string());
    }
    serde_json::json!({
        "uri": "at://test/app.provcheck.signingKey/test",
        "cid": "bafyreitestcid",
        "value": value,
    })
}

fn make_list_records(records: Vec<serde_json::Value>) -> String {
    serde_json::json!({ "records": records }).to_string()
}

/// Common config that points all resolution at a localhost mock and
/// uses a fresh tempdir cache (or bypass) so tests don't pollute each
/// other.
fn mock_config(server: &MockServer, cache_dir: PathBuf, bypass_cache: bool) -> AttestationConfig {
    AttestationConfig {
        cache_dir: Some(cache_dir),
        bypass_cache,
        bsky_api_override: Some(server.base_url()),
        plc_directory_override: Some(server.base_url()),
        use_http_for_well_known: true,
    }
}

/// Sign a fresh WAV and compute the SHA-256 fingerprint of the leaf
/// cert that c2pa just embedded — this is what the mock should publish
/// to satisfy a Match.
fn signed_with_known_fingerprint() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    String, // fingerprint
    String, // chain pem
) {
    let tmp = tempfile::tempdir().expect("tmp");
    let src = tmp.path().join("src.wav");
    let dest = tmp.path().join("signed.wav");
    write_silent_wav(&src);
    let fixture = sign_with_fresh_chain(&src, &dest);
    let fp = fingerprint_leaf_cert(&fixture.chain_pem).expect("fingerprint");
    (tmp, dest, fp, fixture.chain_pem)
}

// ---- Tests against `check_attestation` directly ----------------------------

#[test]
fn match_via_did_web() {
    let (_tmp, _signed, fingerprint, chain_pem) = signed_with_known_fingerprint();
    let server = MockServer::start();
    let did = make_did_for_mock(&server);

    server.route_json(
        "/.well-known/did.json",
        make_did_doc(&did, &server.base_url()),
    );
    server.route_json(
        "/xrpc/com.atproto.repo.listRecords",
        make_list_records(vec![make_record(&fingerprint, None, None)]),
    );

    let cache = tempfile::tempdir().expect("cache tmp");
    let config = mock_config(&server, cache.path().to_path_buf(), false);

    // Use the chain we extracted ourselves — confirms our fingerprint
    // computation is reproducible (independent of c2pa's reader).
    let computed_fp = fingerprint_leaf_cert(&chain_pem).expect("fingerprint roundtrip");
    assert_eq!(computed_fp, fingerprint);

    let result = check_attestation(&fingerprint, None, Some(&did), &config);
    assert_eq!(result.status, AttestationStatus::Match, "got {result:?}");
    assert_eq!(
        result.matched_fingerprint.as_deref(),
        Some(fingerprint.as_str())
    );
    assert_eq!(result.did, did);
}

#[test]
fn mismatch_when_published_fingerprint_differs() {
    let (_tmp, _signed, fingerprint, _chain) = signed_with_known_fingerprint();
    let server = MockServer::start();
    let did = make_did_for_mock(&server);

    let other_fp = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    server.route_json(
        "/.well-known/did.json",
        make_did_doc(&did, &server.base_url()),
    );
    server.route_json(
        "/xrpc/com.atproto.repo.listRecords",
        make_list_records(vec![make_record(other_fp, None, None)]),
    );

    let cache = tempfile::tempdir().expect("cache tmp");
    let config = mock_config(&server, cache.path().to_path_buf(), false);

    let result = check_attestation(&fingerprint, None, Some(&did), &config);
    assert_eq!(result.status, AttestationStatus::Mismatch, "got {result:?}");
    assert_eq!(result.matched_fingerprint, None);
}

#[test]
fn not_published_when_no_records() {
    let (_tmp, _signed, fingerprint, _chain) = signed_with_known_fingerprint();
    let server = MockServer::start();
    let did = make_did_for_mock(&server);

    server.route_json(
        "/.well-known/did.json",
        make_did_doc(&did, &server.base_url()),
    );
    server.route_json(
        "/xrpc/com.atproto.repo.listRecords",
        make_list_records(vec![]),
    );

    let cache = tempfile::tempdir().expect("cache tmp");
    let config = mock_config(&server, cache.path().to_path_buf(), false);

    let result = check_attestation(&fingerprint, None, Some(&did), &config);
    assert_eq!(
        result.status,
        AttestationStatus::NotPublished,
        "got {result:?}"
    );
}

#[test]
fn require_attested_demotes_verified_for_bogus_did() {
    // Goes through the full verify_with_attestation pipeline. The DID
    // resolution will fail (no DNS for the bogus host), giving us
    // ResolutionFailed. With require_attested, that demotes verified
    // to false. Confirms the wiring at the platform-wrapper level
    // without needing test-only URL overrides on VerifyOptions.
    let tmp = tempfile::tempdir().expect("tmp");
    let src = tmp.path().join("src.wav");
    let signed = tmp.path().join("signed.wav");
    write_silent_wav(&src);
    let _fixture = sign_with_fresh_chain(&src, &signed);

    let verify_opts = VerifyOptions::default();
    let attest_opts = AttestationOptions {
        did: Some("did:web:does-not-exist.invalid.example".into()),
        require_attested: true,
        no_cache: true,
        ..Default::default()
    };
    let report = verify_with_attestation(&signed, &verify_opts, &attest_opts).expect("verify Ok");

    assert!(
        !report.verified,
        "require_attested + ResolutionFailed must demote verified — got {:?}",
        report
    );
    let att = report
        .did_attestation
        .as_ref()
        .expect("attestation present");
    assert_eq!(att.status, AttestationStatus::ResolutionFailed);
    assert_eq!(report.exit_code(), 1);
}

#[test]
fn handle_resolution_via_well_known() {
    let (_tmp, _signed, fingerprint, _chain) = signed_with_known_fingerprint();
    let server = MockServer::start();
    let did = make_did_for_mock(&server);

    // Handle resolution: GET http://<server>/.well-known/atproto-did
    // returns the DID. We can't customize the handle host (it's
    // baked into the URL), so we use the mock's address as the handle.
    let handle = server.addr().to_string();

    server.route_text("/.well-known/atproto-did", &did);
    server.route_json(
        "/.well-known/did.json",
        make_did_doc(&did, &server.base_url()),
    );
    server.route_json(
        "/xrpc/com.atproto.repo.listRecords",
        make_list_records(vec![make_record(&fingerprint, None, None)]),
    );

    let cache = tempfile::tempdir().expect("cache tmp");
    let config = mock_config(&server, cache.path().to_path_buf(), false);

    let result = check_attestation(&fingerprint, Some(&handle), None, &config);
    assert_eq!(result.status, AttestationStatus::Match, "got {result:?}");
    assert_eq!(result.handle.as_deref(), Some(handle.as_str()));
    assert_eq!(result.did, did);
}

#[test]
fn expired_record_ignored() {
    let (_tmp, _signed, fingerprint, _chain) = signed_with_known_fingerprint();
    let server = MockServer::start();
    let did = make_did_for_mock(&server);

    // Record matches the fingerprint but expired in 2020.
    server.route_json(
        "/.well-known/did.json",
        make_did_doc(&did, &server.base_url()),
    );
    server.route_json(
        "/xrpc/com.atproto.repo.listRecords",
        make_list_records(vec![make_record(
            &fingerprint,
            Some("2020-01-01T00:00:00Z"),
            Some("2020-12-31T23:59:59Z"),
        )]),
    );

    let cache = tempfile::tempdir().expect("cache tmp");
    let config = mock_config(&server, cache.path().to_path_buf(), false);

    let result = check_attestation(&fingerprint, None, Some(&did), &config);
    assert_eq!(
        result.status,
        AttestationStatus::NotPublished,
        "expired-only records should produce NotPublished, got {result:?}"
    );
}

#[test]
fn future_record_ignored() {
    let (_tmp, _signed, fingerprint, _chain) = signed_with_known_fingerprint();
    let server = MockServer::start();
    let did = make_did_for_mock(&server);

    // Record matches the fingerprint but doesn't take effect until 2099.
    server.route_json(
        "/.well-known/did.json",
        make_did_doc(&did, &server.base_url()),
    );
    server.route_json(
        "/xrpc/com.atproto.repo.listRecords",
        make_list_records(vec![make_record(
            &fingerprint,
            Some("2099-01-01T00:00:00Z"),
            None,
        )]),
    );

    let cache = tempfile::tempdir().expect("cache tmp");
    let config = mock_config(&server, cache.path().to_path_buf(), false);

    let result = check_attestation(&fingerprint, None, Some(&did), &config);
    assert_eq!(
        result.status,
        AttestationStatus::NotPublished,
        "future-only records should produce NotPublished, got {result:?}"
    );
}

#[test]
fn cache_hits_avoid_second_round_trip() {
    let (_tmp, _signed, fingerprint, _chain) = signed_with_known_fingerprint();
    let server = MockServer::start();
    let did = make_did_for_mock(&server);

    server.route_json(
        "/.well-known/did.json",
        make_did_doc(&did, &server.base_url()),
    );
    server.route_json(
        "/xrpc/com.atproto.repo.listRecords",
        make_list_records(vec![make_record(&fingerprint, None, None)]),
    );

    let cache = tempfile::tempdir().expect("cache tmp");
    // First call populates the cache.
    let config_first = mock_config(&server, cache.path().to_path_buf(), false);
    let result1 = check_attestation(&fingerprint, None, Some(&did), &config_first);
    assert_eq!(result1.status, AttestationStatus::Match);

    let count_after_first = server.request_count();
    assert!(
        count_after_first >= 2,
        "first call should hit DID doc + listRecords (got {count_after_first} requests)"
    );

    // Second call against the same cache dir should hit the cache —
    // expect zero additional network requests.
    let config_second = mock_config(&server, cache.path().to_path_buf(), false);
    let result2 = check_attestation(&fingerprint, None, Some(&did), &config_second);
    assert_eq!(result2.status, AttestationStatus::Match);

    let count_after_second = server.request_count();
    assert_eq!(
        count_after_second,
        count_after_first,
        "second call should be served entirely from cache, but observed {} extra requests",
        count_after_second - count_after_first
    );
}
