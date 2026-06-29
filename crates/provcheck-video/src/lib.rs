//! # provcheck-video
//!
//! Video-modality watermark detection for [`provcheck`]. Per-frame
//! TrustMark-B inference plus temporal majority-vote across the
//! recovered brand ids.
//!
//! ## Strategy
//!
//! 1. Shell out to `ffmpeg` to extract one frame every
//!    [`SAMPLE_INTERVAL_SECS`] seconds (default 2), capped at
//!    [`MAX_FRAMES`], into a per-call temp directory.
//! 2. Run [`provcheck_image::detect`] on each frame. Each frame's
//!    detection produces a `WatermarkResult` carrying status,
//!    confidence, and (when BCH-5 recovers) brand id.
//! 3. Temporal aggregation:
//!    - Each frame is one vote per recovered brand id.
//!    - Aggregate confidence = mean of per-frame confidences.
//!    - Status = Detected if [`MIN_DETECTED_FRAMES`] frames recovered
//!      the same brand id, Degraded if at least one frame
//!      recovered ANY brand id below threshold, NotDetected
//!      otherwise.
//! 4. Cleanup: temp frames are removed regardless of result.
//!
//! ## Operator dependencies
//!
//! Requires `ffmpeg` on the host PATH. When it is missing, the
//! detector returns `NotDetected` with a clear "ffmpeg not on
//! PATH" message — same shape as other "this layer needs an
//! external tool" surfaces in the kit. The dispatch chain stays
//! intact; the verifier reports the absence rather than crashing.

use std::path::{Path, PathBuf};
use std::process::Command;

pub use provcheck::prelude::{WatermarkBrand, WatermarkKind, WatermarkResult, WatermarkStatus};

/// Interval between sampled frames, in seconds.
const SAMPLE_INTERVAL_SECS: u32 = 2;
/// Hard cap on per-call frame count to bound wall-clock on long videos.
const MAX_FRAMES: usize = 30;
/// Number of frames whose brand id must match for status=Detected.
const MIN_DETECTED_FRAMES: usize = 3;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("file not found or unreadable: {0}")]
    Io(#[from] std::io::Error),
    #[error("ffmpeg failed: {0}")]
    Ffmpeg(String),
}

/// Run video-modality watermark detection on the file at `path`.
pub fn detect(path: &Path) -> Result<WatermarkResult, Error> {
    let _ = std::fs::metadata(path)?;
    if !looks_like_video(path) {
        return Ok(not_video());
    }
    if !ffmpeg_on_path() {
        return Ok(missing_ffmpeg());
    }

    let tmp = make_tempdir()?;
    let frames = match extract_frames(path, &tmp) {
        Ok(f) => f,
        Err(e) => {
            cleanup_tempdir(&tmp);
            return Ok(WatermarkResult {
                kind: WatermarkKind::TrustMarkVideo,
                status: WatermarkStatus::NotDetected,
                detected: false,
                confidence: 0.0,
                payload: None,
                brand: None,
                message: Some(format!("ffmpeg frame extract failed: {e}")),
                marked_regions: None,
            });
        }
    };

    let mut per_frame_confs = Vec::new();
    let mut brand_votes: std::collections::HashMap<WatermarkBrand, usize> =
        std::collections::HashMap::new();
    let mut any_detected = false;

    for frame in &frames {
        let r = match provcheck_image::detect(frame) {
            Ok(r) => r,
            Err(_) => continue,
        };
        per_frame_confs.push(r.confidence);
        if let Some(brand) = r.brand {
            *brand_votes.entry(brand).or_insert(0) += 1;
        }
        if r.detected {
            any_detected = true;
        }
    }

    cleanup_tempdir(&tmp);

    if per_frame_confs.is_empty() {
        return Ok(WatermarkResult {
            kind: WatermarkKind::TrustMarkVideo,
            status: WatermarkStatus::NotDetected,
            detected: false,
            confidence: 0.0,
            payload: None,
            brand: None,
            message: Some(format!(
                "ffmpeg extracted {} frame(s) but the image detector \
                 errored on all of them — likely a TrustMark weight is \
                 not installed (run `provcheck-kit weights install trustmark`)",
                frames.len()
            )),
            marked_regions: None,
        });
    }

    let mean_conf =
        per_frame_confs.iter().copied().sum::<f32>() / per_frame_confs.len() as f32;

    let winner = brand_votes.iter().max_by_key(|(_, v)| **v);
    let (status, brand) = match winner {
        Some((brand, &count)) if count >= MIN_DETECTED_FRAMES => {
            (WatermarkStatus::Detected, Some(*brand))
        }
        Some((brand, _)) if any_detected => {
            (WatermarkStatus::Degraded, Some(*brand))
        }
        _ => (WatermarkStatus::NotDetected, None),
    };

    Ok(WatermarkResult {
        kind: WatermarkKind::TrustMarkVideo,
        status,
        detected: matches!(
            status,
            WatermarkStatus::Detected | WatermarkStatus::Degraded
        ),
        confidence: mean_conf,
        payload: None,
        brand,
        message: Some(format!(
            "per-frame TrustMark-B over {} sampled frame(s) at {}s interval; \
             {} frame(s) recovered a brand id; mean confidence {:.3}.",
            per_frame_confs.len(),
            SAMPLE_INTERVAL_SECS,
            brand_votes.values().sum::<usize>(),
            mean_conf
        )),
        marked_regions: None,
    })
}

fn not_video() -> WatermarkResult {
    WatermarkResult {
        kind: WatermarkKind::TrustMarkVideo,
        status: WatermarkStatus::NotDetected,
        detected: false,
        confidence: 0.0,
        payload: None,
        brand: None,
        message: Some("not video".into()),
        marked_regions: None,
    }
}

fn missing_ffmpeg() -> WatermarkResult {
    WatermarkResult {
        kind: WatermarkKind::TrustMarkVideo,
        status: WatermarkStatus::NotDetected,
        detected: false,
        confidence: 0.0,
        payload: None,
        brand: None,
        message: Some(
            "video detection requires `ffmpeg` on PATH; install via your \
             package manager (apt install ffmpeg / brew install ffmpeg / \
             winget install ffmpeg) and re-run."
                .into(),
        ),
        marked_regions: None,
    }
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

fn ffmpeg_on_path() -> bool {
    Command::new("ffmpeg")
        .arg("-version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn make_tempdir() -> Result<PathBuf, Error> {
    let base = std::env::temp_dir().join("provcheck-video-frames");
    std::fs::create_dir_all(&base)?;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = base.join(format!("call-{id:08x}"));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn cleanup_tempdir(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

fn extract_frames(src: &Path, dst: &Path) -> Result<Vec<PathBuf>, Error> {
    let pattern = dst.join("frame-%04d.png");
    let status = Command::new("ffmpeg")
        .args([
            "-hide_banner",
            "-loglevel",
            "error",
            "-i",
            &src.to_string_lossy(),
            "-vf",
            &format!("fps=1/{SAMPLE_INTERVAL_SECS}"),
            "-frames:v",
            &format!("{MAX_FRAMES}"),
            "-y",
            &pattern.to_string_lossy(),
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .status()
        .map_err(|e| Error::Ffmpeg(format!("spawn: {e}")))?;
    if !status.success() {
        return Err(Error::Ffmpeg(format!(
            "ffmpeg exited with status {status}"
        )));
    }
    let mut frames: Vec<PathBuf> = std::fs::read_dir(dst)?
        .filter_map(|r| r.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .map(|s| s.eq_ignore_ascii_case("png"))
                .unwrap_or(false)
        })
        .collect();
    frames.sort();
    Ok(frames)
}

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
