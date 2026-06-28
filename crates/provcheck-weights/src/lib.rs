//! # provcheck-weights
//!
//! Downloadable-on-demand detector weights for provcheck. Each
//! family's pretrained model weights live as release assets on
//! the public mirror at
//! `https://github.com/CreativeMayhemLtd/provcheck/releases/tag/weights-v1`
//! rather than embedded into the binary via `include_bytes!()`.
//!
//! Replaces ~150 MB of bundled `.onnx` + `.nnef.tgz` files
//! (silentcipher 80 MB, audioseal 20 MB, wavmark 30 MB, TrustMark
//! 60 MB once added) with a slim FOSS core that pulls each
//! detector's weights from the public release on first use.
//!
//! ## Design
//!
//! - **Static manifest.** SHA256s are baked into the binary at
//!   compile time, so a tampered download is rejected before the
//!   bytes ever reach a detector. No MITM risk; no runtime
//!   manifest fetch.
//! - **OS-conventional cache.** Weights land in
//!   `dirs::cache_dir()/provcheck/weights/` —
//!   `~/.cache/provcheck/weights/` on Linux,
//!   `AppData\Local\provcheck\weights\` on Windows,
//!   `~/Library/Caches/provcheck/weights/` on macOS.
//! - **Lazy load.** Each detector's first call hits
//!   [`load_or_download`]; subsequent calls hit the cache.
//! - **Operator escape hatch.** The
//!   `PROVCHECK_WEIGHTS_CACHE_DIR` env var overrides the default
//!   cache location (useful for read-only filesystems and CI
//!   pre-populated mirrors).
//!
//! ## API
//!
//! Detector crates call:
//! ```ignore
//! let bytes = provcheck_weights::load_or_download("trustmark", "b-decoder")?;
//! // bytes is the full ONNX file, verified against the bundled SHA256
//! ```
//!
//! Operator-facing CLI calls:
//! ```ignore
//! provcheck_weights::status();      // what's installed
//! provcheck_weights::install_all(); // bulk pre-fetch
//! ```

use std::path::{Path, PathBuf};

mod cache;
mod download;
mod manifest;
mod verify;

pub use manifest::{MANIFEST, WeightEntry};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no entry in the bundled manifest for family={family:?} variant={variant:?}")]
    UnknownWeight {
        family: &'static str,
        variant: &'static str,
    },
    /// Weights not yet downloaded. The caller (CLI / GUI) should
    /// prompt the user to install via
    /// [`download`] rather than silently fetching them. Carries
    /// the entry so the prompt can show family, variant, size,
    /// and the public URL.
    ///
    /// "always respect the user" — v0.7 phase 8a design direction.
    #[error(
        "weights not installed for {family}/{variant} ({size_mb} MB) — \
         download via provcheck-weights::download or `provcheck-kit weights install {family}`"
    )]
    NotCached {
        family: &'static str,
        variant: &'static str,
        size_mb: u64,
    },
    #[error("cache directory not resolvable on this platform")]
    NoCacheDir,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("download failed: {0}")]
    Download(String),
    #[error(
        "sha256 mismatch for {filename}: expected {expected}, got {actual} — refusing to load tampered weights"
    )]
    Sha256Mismatch {
        filename: &'static str,
        expected: String,
        actual: String,
    },
}

/// Look up the manifest entry for `(family, variant)`, returning
/// the static metadata or [`Error::UnknownWeight`].
pub fn entry(family: &str, variant: &str) -> Result<&'static WeightEntry, Error> {
    MANIFEST
        .iter()
        .find(|e| e.family == family && e.variant == variant)
        .ok_or_else(|| Error::UnknownWeight {
            family: leak(family),
            variant: leak(variant),
        })
}

/// Return the cache path where the weight WOULD live (regardless
/// of whether it has been downloaded yet).
pub fn cache_path_for(entry: &WeightEntry) -> Result<PathBuf, Error> {
    let dir = cache::resolve_cache_dir().ok_or(Error::NoCacheDir)?;
    Ok(dir.join(entry.filename))
}

/// Return the cached weight path if present + SHA-valid; otherwise
/// return [`Error::NotCached`] WITHOUT initiating a download.
///
/// This is what detector crates (silentcipher, audioseal, wavmark,
/// image) call from their internal model loading. A missing weight
/// is surfaced cleanly so the CLI / GUI can prompt the user
/// rather than silently blocking for ~30s while a download
/// happens behind their back.
///
/// "always respect the user" — v0.7 phase 8a design direction.
pub fn load_if_cached(family: &str, variant: &str) -> Result<PathBuf, Error> {
    let entry = entry(family, variant)?;
    let path = cache_path_for(entry)?;
    if !path.exists() {
        return Err(Error::NotCached {
            family: entry.family,
            variant: entry.variant,
            size_mb: entry.size_bytes / (1024 * 1024),
        });
    }
    if !verify::file_sha256_matches(&path, &entry.sha256)? {
        // Stale or corrupted cache; remove + surface as NotCached
        // so the caller gets a clean "needs install" signal.
        let _ = std::fs::remove_file(&path);
        return Err(Error::NotCached {
            family: entry.family,
            variant: entry.variant,
            size_mb: entry.size_bytes / (1024 * 1024),
        });
    }
    Ok(path)
}

/// Explicitly download a weight. Called by the kit's
/// `weights install` subcommand and the GUI's install-modal
/// confirmation handler — both code paths that already have
/// user consent to perform the network operation.
///
/// Detector crates do NOT call this. They call [`load_if_cached`]
/// and surface the missing-weights error to the CLI / GUI.
pub fn download(family: &str, variant: &str) -> Result<PathBuf, Error> {
    let entry = entry(family, variant)?;
    let path = cache_path_for(entry)?;

    // Idempotent: if a valid cached copy already exists, skip the
    // network entirely.
    if path.exists() && verify::file_sha256_matches(&path, &entry.sha256)? {
        return Ok(path);
    }
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("download.tmp");
    download::download_to(entry.url, &tmp)?;
    if !verify::file_sha256_matches(&tmp, &entry.sha256)? {
        let _ = std::fs::remove_file(&tmp);
        return Err(Error::Sha256Mismatch {
            filename: entry.filename,
            expected: hex(&entry.sha256),
            actual: "(mismatch)".into(),
        });
    }
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

/// Delete a cached weight. Idempotent (returns Ok if the file is
/// already absent). Called by the kit's `weights uninstall`
/// subcommand.
pub fn uninstall(family: &str, variant: &str) -> Result<(), Error> {
    let entry = entry(family, variant)?;
    let path = cache_path_for(entry)?;
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

/// Convenience wrapper: load from cache, falling back to download
/// if absent. Reserved for explicit-consent contexts (e.g., the
/// `kit weights install` subcommand's body, the GUI's modal
/// confirmation handler). Detector crates use [`load_if_cached`]
/// instead so missing weights surface as a clean error rather
/// than a silent network operation.
pub fn load_or_download(family: &str, variant: &str) -> Result<PathBuf, Error> {
    match load_if_cached(family, variant) {
        Ok(p) => Ok(p),
        Err(Error::NotCached { .. }) => download(family, variant),
        Err(e) => Err(e),
    }
}

/// Return whether each manifest entry is currently cached + valid.
/// Operator-facing status surface for `kit weights status`.
pub fn status() -> Vec<WeightStatus> {
    MANIFEST
        .iter()
        .map(|entry| {
            let cached = match cache_path_for(entry) {
                Ok(p) => {
                    let exists = p.exists();
                    let valid = exists
                        && verify::file_sha256_matches(&p, &entry.sha256).unwrap_or(false);
                    WeightCacheState { exists, valid }
                }
                Err(_) => WeightCacheState {
                    exists: false,
                    valid: false,
                },
            };
            WeightStatus { entry, cached }
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct WeightStatus {
    pub entry: &'static WeightEntry,
    pub cached: WeightCacheState,
}

#[derive(Debug, Clone, Copy)]
pub struct WeightCacheState {
    pub exists: bool,
    pub valid: bool,
}

// NOTE: an `install_all()` bulk pre-fetch was deliberately removed
// from the public API per the v0.7 phase 8a design direction
// ("always respect the user"). The kit's `weights install`
// subcommand takes one family at a time. Operators who genuinely
// want everything installed can script it from `MANIFEST` directly,
// but the default flow does not push a download decision on the
// user.

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// `entry(...)`'s error path needs `&'static str` but the caller's
/// strings are borrowed. Leak the &str at the error boundary —
/// this only fires on a bug in the calling crate (asking for a
/// non-existent variant), so the bounded leak is acceptable.
fn leak(s: &str) -> &'static str {
    Box::leak(s.to_owned().into_boxed_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_has_trustmark_entries() {
        // v1 manifest ships TrustMark-B decoder + encoder.
        assert!(entry("trustmark", "b-decoder").is_ok());
        assert!(entry("trustmark", "b-encoder").is_ok());
    }

    #[test]
    fn unknown_weight_returns_typed_error() {
        let r = entry("nonexistent", "variant");
        assert!(matches!(r, Err(Error::UnknownWeight { .. })));
    }

    #[test]
    fn status_lists_every_manifest_entry() {
        let s = status();
        assert_eq!(s.len(), MANIFEST.len());
    }
}
