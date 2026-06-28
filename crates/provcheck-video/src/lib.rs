//! # provcheck-video
//!
//! Video-modality watermark detection for [`provcheck`]. v0.7
//! phase 7d **scaffold only** — the implementation strategy is
//! per-frame TrustMark-B detection (reusing the image crate's
//! decoder) plus temporal majority-vote across the recovered
//! brand ids.
//!
//! ## Strategy (target for the wiring phase)
//!
//! 1. Shell out to `ffmpeg` to extract frames at a configurable
//!    cadence (default: 1 frame / 2 seconds — enough redundancy
//!    for the majority vote without exploding wall clock).
//! 2. Run [`provcheck_image::detect`] on each frame in turn,
//!    collecting the recovered brand ids and confidences.
//! 3. Majority-vote the brand across detected frames; emit a
//!    single [`WatermarkResult`] with that brand and an aggregate
//!    confidence.
//!
//! ## Status (v0.7.0 ship)
//!
//! `detect()` returns `NotDetected` with a "video detector
//! scaffold; per-frame TrustMark + temporal vote lands in v0.7.x"
//! message. The crate scaffold exists so the verifier's dispatch
//! has a target to plumb against and the kit can dispatch
//! `--kind video` even before the inference is wired.
//!
//! `WatermarkKind::TrustMarkVideo` is the report-level
//! identifier; same Bayesian "Detected vs Degraded vs
//! NotDetected" classifier applies.

use std::path::Path;

pub use provcheck::prelude::{WatermarkBrand, WatermarkKind, WatermarkResult, WatermarkStatus};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("file not found or unreadable: {0}")]
    Io(#[from] std::io::Error),
}

/// Run video-modality watermark detection on the file at `path`.
///
/// v0.7 phase 7d scaffold. Returns `NotDetected` with a
/// scaffold-pending message for any video extension; "not video"
/// for non-video files.
pub fn detect(path: &Path) -> Result<WatermarkResult, Error> {
    let _ = std::fs::metadata(path)?;
    if !looks_like_video(path) {
        return Ok(WatermarkResult {
            kind: WatermarkKind::TrustMarkVideo,
            status: WatermarkStatus::NotDetected,
            detected: false,
            confidence: 0.0,
            payload: None,
            brand: None,
            message: Some("not video".into()),
            marked_regions: None,
        });
    }
    Ok(WatermarkResult {
        kind: WatermarkKind::TrustMarkVideo,
        status: WatermarkStatus::NotDetected,
        detected: false,
        confidence: 0.0,
        payload: None,
        brand: None,
        message: Some(
            "video detector scaffold; per-frame TrustMark + temporal vote lands in v0.7.x"
                .into(),
        ),
        marked_regions: None,
    })
}

fn looks_like_video(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "mp4" | "mov" | "mkv" | "webm" | "avi" | "m4v"
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
