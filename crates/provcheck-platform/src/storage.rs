//! Filesystem cache for attestation lookups.
//!
//! DID documents and PDS record lists are cached as JSON envelopes
//! under a per-namespace subdirectory of the platform cache dir
//! (typically `~/.cache/provcheck/attestation/<namespace>/<key>.json`
//! on Linux, `%LOCALAPPDATA%\provcheck\attestation\...` on Windows).
//! Each envelope carries a Unix timestamp; reads past [`CACHE_TTL`]
//! return `None` and force a fresh fetch.
//!
//! Generic over the cached payload `T`. Callers in
//! [`crate::network`] use this with their own typed cache entries
//! (handle → DID, DID → PDS endpoint, DID → records).

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::attestation::AttestationConfig;

/// 24 hours. DID documents and PDS records are mutable but rarely so.
/// Pass `bypass_cache: true` on [`AttestationConfig`] to force a fresh
/// fetch (e.g., right after a key rotation).
pub const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Wraps a cached value with the time it was fetched. Stored as JSON
/// on disk.
#[derive(Debug, Serialize, Deserialize)]
pub struct CacheEnvelope<T> {
    pub fetched_at: u64,
    pub data: T,
}

/// Resolve the on-disk cache directory. Honors
/// `AttestationConfig::cache_dir` when set; otherwise falls back to
/// the platform default (`dirs::cache_dir()/provcheck/attestation`).
/// Returns `None` if neither is available — callers treat that as
/// "skip caching for this call".
pub fn resolve_cache_dir(config: &AttestationConfig) -> Option<PathBuf> {
    if let Some(d) = &config.cache_dir {
        return Some(d.clone());
    }
    let base = dirs::cache_dir()?;
    Some(base.join("provcheck").join("attestation"))
}

/// Build the on-disk path for `<namespace>/<sanitized-key>.json`.
pub fn cache_path(config: &AttestationConfig, namespace: &str, key: &str) -> Option<PathBuf> {
    let dir = resolve_cache_dir(config)?.join(namespace);
    Some(dir.join(format!("{}.json", sanitize_key(key))))
}

/// Replace any non-`[A-Za-z0-9_.-]` character with `_`, so DIDs (which
/// contain `:`) survive a round-trip through the filesystem.
pub fn sanitize_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    for c in key.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    out
}

/// Read a cached value if present and within [`CACHE_TTL`]. Returns
/// `None` for any failure (missing file, parse error, expired,
/// permission denied) — callers treat that uniformly as "cache miss".
pub fn cache_read<T: for<'de> Deserialize<'de>>(
    config: &AttestationConfig,
    namespace: &str,
    key: &str,
) -> Option<T> {
    let path = cache_path(config, namespace, key)?;
    let bytes = fs::read(&path).ok()?;
    let envelope: CacheEnvelope<T> = serde_json::from_slice(&bytes).ok()?;
    let fetched = UNIX_EPOCH.checked_add(Duration::from_secs(envelope.fetched_at))?;
    let age = SystemTime::now().duration_since(fetched).ok()?;
    if age > CACHE_TTL {
        return None;
    }
    Some(envelope.data)
}

/// Write a cached value with the current Unix timestamp. Best-effort:
/// any failure (no cache dir, mkdir failed, disk full) is silently
/// dropped — caching is opportunistic, not load-bearing.
pub fn cache_write<T: Serialize>(config: &AttestationConfig, namespace: &str, key: &str, data: &T) {
    let Some(path) = cache_path(config, namespace, key) else {
        return;
    };
    let Some(parent) = path.parent() else {
        return;
    };
    if fs::create_dir_all(parent).is_err() {
        return;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let envelope = CacheEnvelope {
        fetched_at: now,
        data,
    };
    if let Ok(bytes) = serde_json::to_vec_pretty(&envelope) {
        let _ = fs::write(&path, bytes);
    }
}

#[cfg(test)]
mod sanitize_key_tests {
    use super::sanitize_key;

    #[test]
    fn passthrough_for_alphanumeric() {
        assert_eq!(sanitize_key("abc123"), "abc123");
    }

    #[test]
    fn preserves_safe_punctuation() {
        // Dash, underscore, and dot are filesystem-safe and
        // common in DID method-specific identifiers.
        assert_eq!(sanitize_key("a-b_c.d"), "a-b_c.d");
    }

    #[test]
    fn replaces_did_colon() {
        // The motivating case: did:plc:abc123 must round-trip.
        // The `:` becomes `_`.
        assert_eq!(sanitize_key("did:plc:abc123"), "did_plc_abc123");
    }

    #[test]
    fn neutralises_path_traversal() {
        // An attacker-controlled key cannot escape the namespace
        // directory because '/' and '\\' are replaced with '_'.
        // Dots are preserved (DIDs commonly include them), so
        // '..' survives as literal dots, but no path separator
        // remains — meaning the result cannot be a directory
        // traversal token any filesystem will honour.
        assert_eq!(sanitize_key("../../etc/passwd"), ".._.._etc_passwd");
        assert_eq!(
            sanitize_key("..\\..\\Windows\\System32"),
            ".._.._Windows_System32"
        );
        // Confirm the load-bearing invariant: no path separators
        // appear in any sanitised string.
        for input in ["../../etc/passwd", "..\\..\\Windows\\System32"] {
            let out = sanitize_key(input);
            assert!(!out.contains('/'), "slash survived in {out}");
            assert!(!out.contains('\\'), "backslash survived in {out}");
        }
    }

    #[test]
    fn neutralises_null_byte() {
        // Null byte and other control bytes are also stripped.
        assert_eq!(sanitize_key("file\0name"), "file_name");
    }

    #[test]
    fn replaces_whitespace_and_special() {
        assert_eq!(sanitize_key("a b\tc\nd"), "a_b_c_d");
        assert_eq!(sanitize_key("a$b@c*d"), "a_b_c_d");
    }

    #[test]
    fn replaces_unicode_with_underscore() {
        // Non-ASCII characters are not in the allowlist.
        assert_eq!(sanitize_key("café"), "caf_");
    }

    #[test]
    fn empty_input_returns_empty() {
        assert_eq!(sanitize_key(""), "");
    }

    #[test]
    fn preserves_length() {
        let key = "did:plc:zaaa";
        assert_eq!(sanitize_key(key).len(), key.len());
    }
}
