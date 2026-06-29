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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

pub use provcheck::prelude::{WatermarkBrand, WatermarkKind, WatermarkResult, WatermarkStatus};

/// Interval between sampled frames, in seconds.
const SAMPLE_INTERVAL_SECS: u32 = 2;
/// Hard cap on per-call frame count to bound wall-clock on long videos.
const MAX_FRAMES: usize = 30;
/// Number of frames whose brand id must match for status=Detected.
const MIN_DETECTED_FRAMES: usize = 3;
/// Minimum frames whose brand id must match for status=Degraded.
/// A single spurious 1-of-30 match no longer promotes to Degraded
/// per v0.9.0 audit §2.7.
const MIN_DEGRADED_FRAMES: usize = 2;
/// Wall-clock ffmpeg cap (input read budget), seconds. Per
/// v0.9.0 audit §3 prevents pathological input from chewing CPU
/// before the first sampled frame.
const FFMPEG_TIME_CAP_SECS: u32 = SAMPLE_INTERVAL_SECS * (MAX_FRAMES as u32);

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

    // v0.9.0 audit §2.5 + §3: tempfile::TempDir uses O_EXCL +
    // random suffix — no collision across concurrent processes,
    // no symlink-overwrite risk on shared /tmp, and Drop-on-panic
    // cleanup.
    let tmp: TempDir = match TempDir::with_prefix("provcheck-video-frames-") {
        Ok(t) => t,
        Err(e) => return Err(Error::Io(e)),
    };
    let frames = match extract_frames(path, tmp.path()) {
        Ok(f) => f,
        Err(e) => {
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
    // v0.9.0 audit §4: BTreeMap for deterministic tiebreak.
    let mut brand_votes: BTreeMap<WatermarkBrand, usize> = BTreeMap::new();

    for frame in &frames {
        let Ok(r) = provcheck_image::detect(frame) else {
            continue;
        };
        per_frame_confs.push(r.confidence);
        if let Some(brand) = r.brand {
            *brand_votes.entry(brand).or_insert(0) += 1;
        }
    }

    // tmp dropped here regardless of return path (including panics
    // inside the loop above).
    drop(tmp);

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
        // v0.9.0 audit §2.7: require >= MIN_DEGRADED_FRAMES, not
        // just any_detected. Prevents a 1-of-30 spurious frame
        // match from promoting to Degraded.
        Some((brand, &count)) if count >= MIN_DEGRADED_FRAMES => {
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

fn extract_frames(src: &Path, dst: &Path) -> Result<Vec<PathBuf>, Error> {
    let pattern = dst.join("frame-%04d.png");
    let status = Command::new("ffmpeg")
        .args([
            "-hide_banner",
            "-loglevel",
            "error",
            // v0.9.0 audit §3: wall-clock cap so a fuzzed
            // container can't chew CPU/RAM before the first
            // sampled frame lands.
            "-t",
            &format!("{FFMPEG_TIME_CAP_SECS}"),
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
mod tests {
    use super::*;

    #[test]
    fn key_public_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WatermarkResult>();
        assert_send_sync::<WatermarkBrand>();
        assert_send_sync::<WatermarkKind>();
        assert_send_sync::<WatermarkStatus>();
    }

    #[test]
    fn non_video_extension_returns_not_video() {
        let f = tempfile::Builder::new()
            .suffix(".txt")
            .tempfile()
            .expect("tempfile");
        let r = detect(f.path()).expect("detect");
        assert!(!r.detected);
        assert_eq!(r.message.as_deref(), Some("not video"));
    }

    #[test]
    fn video_extension_without_ffmpeg_surfaces_clear_hint() {
        // We can't UNINSTALL ffmpeg for the test, so this test
        // is best-effort: if ffmpeg is on PATH, the test exercises
        // the "ffmpeg failed on empty file" path instead, which
        // still surfaces a message. Both branches return
        // NotDetected without crashing.
        let f = tempfile::Builder::new()
            .suffix(".mp4")
            .tempfile()
            .expect("tempfile");
        // Empty file, no valid video container.
        let r = detect(f.path()).expect("detect");
        assert!(!r.detected);
        assert!(r.message.is_some());
    }
}
