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

/// Load the weight bytes from cache, downloading + verifying first
/// if absent. The main entry point detector crates call from their
/// `model.rs` modules.
///
/// On success the file is guaranteed to exist on disk at the
/// returned path AND its bytes have been SHA256-verified against
/// the bundled manifest. The detector loads from the returned
/// path via `tract`'s `model_for_path` (or equivalent).
pub fn load_or_download(family: &str, variant: &str) -> Result<PathBuf, Error> {
    let entry = entry(family, variant)?;
    let path = cache_path_for(entry)?;

    if path.exists() {
        // Verify cached file is still intact. A flipped bit or a
        // truncated download from a previous run would surface here
        // before we hand the bytes to the detector.
        if verify::file_sha256_matches(&path, &entry.sha256)? {
            return Ok(path);
        }
        // Stale or corrupted cache. Remove + redownload.
        let _ = std::fs::remove_file(&path);
    }

    // Atomic download via temp file + rename so a partial download
    // never leaves a half-written file at the canonical path.
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

/// Pre-fetch every manifest entry. Operator-facing surface for
/// `kit weights install --all` (and the kit's offline-prep path).
pub fn install_all() -> Vec<(&'static WeightEntry, Result<PathBuf, Error>)> {
    MANIFEST
        .iter()
        .map(|e| (e, load_or_download(e.family, e.variant)))
        .collect()
}

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
