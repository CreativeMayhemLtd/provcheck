//! HTTP, DID resolution, and PDS record fetching for attestation.
//!
//! Pure sync (no tokio) over `ureq` + rustls. Supports `did:plc:*`
//! (via plc.directory) and `did:web:*` (via `.well-known/did.json`).
//! Handle resolution tries `.well-known/atproto-did` first (best for
//! domain-rooted handles), then falls back to the public bsky AppView
//! `com.atproto.identity.resolveHandle` XRPC call.
//!
//! Cache reads/writes go through [`crate::storage`]; transport URL
//! overrides for tests live on [`crate::attestation::AttestationConfig`].

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::attestation::AttestationConfig;
use crate::storage::{cache_read, cache_write};

const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const PUBLIC_BSKY: &str = "https://public.api.bsky.app";
const PLC_DIRECTORY: &str = "https://plc.directory";
const COLLECTION: &str = "app.provcheck.signingKey";

// ---------- typed PDS records -------------------------------------------

// `SigningKeyRecord` is the shared wire-format type in
// `provcheck-attestation-spec`. Re-export here so existing
// `crate::network::SigningKeyRecord` paths inside this crate keep
// working without churn during the refactor; downstream consumers
// should prefer the spec crate directly.
pub use provcheck_attestation_spec::SigningKeyRecord;

// ---------- handle resolution -------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct HandleCacheEntry {
    did: String,
}

/// Resolve a bsky / atproto handle to its DID. Tries
/// `.well-known/atproto-did` first (best for domain-rooted handles),
/// then `com.atproto.identity.resolveHandle` on the public AppView.
pub fn resolve_handle(handle: &str, config: &AttestationConfig) -> Result<String, String> {
    let handle = handle.trim_start_matches('@');

    if !config.bypass_cache {
        if let Some(cached) = cache_read::<HandleCacheEntry>(config, "handle", handle) {
            return Ok(cached.did);
        }
    }

    if let Ok(did) = try_well_known_handle(handle, config) {
        cache_write(
            config,
            "handle",
            handle,
            &HandleCacheEntry { did: did.clone() },
        );
        return Ok(did);
    }

    let base = config.bsky_api_override.as_deref().unwrap_or(PUBLIC_BSKY);
    let url = format!(
        "{base}/xrpc/com.atproto.identity.resolveHandle?handle={}",
        url_encode(handle)
    );
    let value = http_get_json(&url)?;
    let did = value
        .get("did")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "no 'did' field in resolveHandle response".to_string())?
        .to_string();

    cache_write(
        config,
        "handle",
        handle,
        &HandleCacheEntry { did: did.clone() },
    );
    Ok(did)
}

fn try_well_known_handle(handle: &str, config: &AttestationConfig) -> Result<String, String> {
    let scheme = if config.use_http_for_well_known {
        "http"
    } else {
        "https"
    };
    let url = format!("{scheme}://{handle}/.well-known/atproto-did");
    let body = http_get_text(&url)?;
    let did = body.trim();
    if !did.starts_with("did:") {
        return Err(format!("response was not a DID: {did:?}"));
    }
    Ok(did.to_string())
}

// ---------- DID document → PDS endpoint --------------------------------

#[derive(Debug, Deserialize)]
struct DidDocument {
    #[serde(default)]
    service: Vec<ServiceEntry>,
}

#[derive(Debug, Deserialize)]
struct ServiceEntry {
    #[serde(rename = "id", default)]
    id: String,
    #[serde(rename = "type", default)]
    service_type: String,
    #[serde(rename = "serviceEndpoint", default)]
    endpoint: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PdsCacheEntry {
    endpoint: String,
}

/// Resolve a DID to its PDS endpoint URL. Caches the result.
pub fn resolve_pds_endpoint(did: &str, config: &AttestationConfig) -> Result<String, String> {
    if !config.bypass_cache {
        if let Some(cached) = cache_read::<PdsCacheEntry>(config, "pds", did) {
            return Ok(cached.endpoint);
        }
    }

    let doc = fetch_did_document(did, config)?;

    // bsky convention: PDS service has id "#atproto_pds" and type
    // "AtprotoPersonalDataServer". Match the canonical pair first; fall
    // back to any service of the right type.
    let endpoint = doc
        .service
        .iter()
        .find(|s| s.id.ends_with("#atproto_pds") && !s.endpoint.is_empty())
        .or_else(|| {
            doc.service
                .iter()
                .find(|s| s.service_type == "AtprotoPersonalDataServer" && !s.endpoint.is_empty())
        })
        .map(|s| s.endpoint.trim_end_matches('/').to_string())
        .ok_or_else(|| "no PDS service entry in DID document".to_string())?;

    cache_write(
        config,
        "pds",
        did,
        &PdsCacheEntry {
            endpoint: endpoint.clone(),
        },
    );
    Ok(endpoint)
}

fn fetch_did_document(did: &str, config: &AttestationConfig) -> Result<DidDocument, String> {
    if let Some(rest) = did.strip_prefix("did:plc:") {
        if rest.is_empty() {
            return Err("empty did:plc identifier".into());
        }
        let base = config
            .plc_directory_override
            .as_deref()
            .unwrap_or(PLC_DIRECTORY);
        let url = format!("{base}/{did}");
        let value = http_get_json(&url)?;
        return serde_json::from_value(value).map_err(|e| format!("did:plc parse failed: {e}"));
    }

    if let Some(host) = did.strip_prefix("did:web:") {
        let scheme = if config.use_http_for_well_known {
            "http"
        } else {
            "https"
        };
        // Per did:web: a `:` (not %3A) in the suffix denotes a path
        // segment after the host. Ports must be %3A-encoded in the
        // DID, so a literal `:` only appears for path-style DIDs.
        let url = if host.contains(':') {
            let path = host.replace(':', "/");
            format!("{scheme}://{path}/did.json")
        } else {
            // Decode %3A back to : so a host:port works at the network
            // layer even when the DID encodes the port.
            let decoded = host.replace("%3A", ":");
            format!("{scheme}://{decoded}/.well-known/did.json")
        };
        let value = http_get_json(&url)?;
        return serde_json::from_value(value).map_err(|e| format!("did:web parse failed: {e}"));
    }

    Err(format!("unsupported DID method: {did}"))
}

// ---------- record listing ---------------------------------------------

#[derive(Debug, Deserialize)]
struct ListRecordsResponse {
    records: Vec<RecordEntry>,
    #[serde(default)]
    #[allow(dead_code)]
    cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RecordEntry {
    #[allow(dead_code)]
    uri: String,
    #[allow(dead_code)]
    cid: String,
    value: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct RecordsCacheEntry {
    records: Vec<SigningKeyRecord>,
}

/// Fetch all `app.provcheck.signingKey` records from a creator's PDS
/// for the given DID. Skips records that don't conform to the
/// lexicon. Caches the (full, decoded) list.
pub fn list_signing_keys(
    pds: &str,
    did: &str,
    config: &AttestationConfig,
) -> Result<Vec<SigningKeyRecord>, String> {
    let cache_key = format!("{did}__{COLLECTION}");
    if !config.bypass_cache {
        if let Some(cached) = cache_read::<RecordsCacheEntry>(config, "records", &cache_key) {
            return Ok(cached.records);
        }
    }

    let url = format!(
        "{}/xrpc/com.atproto.repo.listRecords?repo={}&collection={}&limit=100",
        pds.trim_end_matches('/'),
        url_encode(did),
        url_encode(COLLECTION)
    );
    let value = http_get_json(&url)?;
    let parsed: ListRecordsResponse =
        serde_json::from_value(value).map_err(|e| format!("listRecords parse failed: {e}"))?;

    let mut records = Vec::with_capacity(parsed.records.len());
    for r in parsed.records {
        if let Ok(rec) = serde_json::from_value::<SigningKeyRecord>(r.value) {
            records.push(rec);
        }
    }

    cache_write(
        config,
        "records",
        &cache_key,
        &RecordsCacheEntry {
            records: records.clone(),
        },
    );
    Ok(records)
}

// ---------- HTTP layer (sync, ureq + rustls) ---------------------------

fn http_get_json(url: &str) -> Result<serde_json::Value, String> {
    let mut response = ureq::get(url)
        .config()
        .timeout_global(Some(HTTP_TIMEOUT))
        .build()
        .call()
        .map_err(|e| format!("GET {url} failed: {e}"))?;

    response
        .body_mut()
        .read_json::<serde_json::Value>()
        .map_err(|e| format!("body read failed for {url}: {e}"))
}

fn http_get_text(url: &str) -> Result<String, String> {
    let mut response = ureq::get(url)
        .config()
        .timeout_global(Some(HTTP_TIMEOUT))
        .build()
        .call()
        .map_err(|e| format!("GET {url} failed: {e}"))?;

    response
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("body read failed for {url}: {e}"))
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            use std::fmt::Write;
            let _ = write!(out, "%{:02X}", b);
        }
    }
    out
}
