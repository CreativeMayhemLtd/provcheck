//! # provcheck-synthid-text
//!
//! [Google SynthID-text](https://github.com/google-deepmind/synthid-text)
//! detection for provcheck. Reads plain `.txt` / `.md` files and
//! attempts to detect Google's tournament-sampling-based LLM text
//! watermark.
//!
//! ## Status (v0.7 phase 7e scaffold)
//!
//! `detect()` returns `NotDetected` with a scaffold-pending
//! message. SynthID-text detection requires:
//!
//! 1. The tokenizer matching the LLM that produced the text.
//! 2. The watermark salt / depth / hash function used during
//!    generation.
//!
//! Without those parameters detection is undefined. The 7e
//! wiring phase will:
//!
//! - Land an `app.provcheck.synthid_config` C2PA assertion that
//!   creators can embed naming the tokenizer + salt they used,
//!   so the verifier can dispatch to the matching detector
//!   automatically.
//! - Ship a small set of preset configs for the major open-weight
//!   LLMs (Gemma, Llama, Qwen) so default detection works for
//!   the common ecosystem cases.
//!
//! ## License
//!
//! Per [`WATERMARK_LICENSE_POLICY.md`](../../WATERMARK_LICENSE_POLICY.md),
//! both code AND model weights must be permissively licensed.
//! Google's `synthid-text` library is Apache-2.0 on both
//! surfaces — no separate model weights to vet (the watermark is
//! a logit-bias scheme, not a learned classifier).

use std::path::Path;

pub use provcheck::prelude::{WatermarkBrand, WatermarkKind, WatermarkResult, WatermarkStatus};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("file not found or unreadable: {0}")]
    Io(#[from] std::io::Error),
}

/// Run SynthID-text detection on the file at `path`.
///
/// v0.7 phase 7e scaffold. Returns `NotDetected` with a
/// scaffold-pending message for any text extension; "not text"
/// for non-text files.
pub fn detect(path: &Path) -> Result<WatermarkResult, Error> {
    let _ = std::fs::metadata(path)?;
    if !looks_like_text(path) {
        return Ok(WatermarkResult {
            kind: WatermarkKind::SynthIdText,
            status: WatermarkStatus::NotDetected,
            detected: false,
            confidence: 0.0,
            payload: None,
            brand: None,
            message: Some("not text".into()),
            marked_regions: None,
        });
    }
    Ok(WatermarkResult {
        kind: WatermarkKind::SynthIdText,
        status: WatermarkStatus::NotDetected,
        detected: false,
        confidence: 0.0,
        payload: None,
        brand: None,
        message: Some(
            "synthid-text detector scaffold; tournament-sampling detection \
             (Apache-2.0 algorithm, ~200 LOC pure Rust) lands in v0.7.x — \
             requires the originating LLM's tokenizer + salt config either \
             via an `app.provcheck.synthid_config` C2PA assertion or via a \
             default preset for major open-weight LLMs"
                .into(),
        ),
        marked_regions: None,
    })
}

fn looks_like_text(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "txt" | "md" | "rst" | "text"
    )
}

/// v0.7 phase 7-pre audit #10: Send + Sync bound assertion.
#[cfg(test)]
mod _send_sync_assertions {
    fn assert_send_sync<T: Send + Sync>() {}
    #[test]
    fn key_public_types_are_send_sync() {
        assert_send_sync::<crate::WatermarkResult>();
        assert_send_sync::<crate::WatermarkBrand>();
        assert_send_sync::<crate::WatermarkKind>();
        assert_send_sync::<crate::WatermarkStatus>();
    }
}
