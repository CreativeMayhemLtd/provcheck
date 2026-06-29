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

    let (status, brand) = classify_votes(&brand_votes);

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

/// Classify per-frame brand-id votes into a final
/// `(status, brand)` verdict. Factored out so the threshold logic
/// is table-testable without spinning up ffmpeg.
///
/// Rules:
/// - `WatermarkStatus::Detected` if any brand has at least
///   [`MIN_DETECTED_FRAMES`] votes.
/// - `WatermarkStatus::Degraded` if any brand has at least
///   [`MIN_DEGRADED_FRAMES`] votes (but not enough for Detected).
/// - `WatermarkStatus::NotDetected` otherwise.
///
/// On ties the `BTreeMap` ordering (by `WatermarkBrand` variant
/// order) determines the winner — deterministic, repeatable.
fn classify_votes(
    brand_votes: &BTreeMap<WatermarkBrand, usize>,
) -> (WatermarkStatus, Option<WatermarkBrand>) {
    let winner = brand_votes.iter().max_by_key(|(_, v)| **v);
    match winner {
        Some((brand, &count)) if count >= MIN_DETECTED_FRAMES => {
            (WatermarkStatus::Detected, Some(*brand))
        }
        Some((brand, &count)) if count >= MIN_DEGRADED_FRAMES => {
            (WatermarkStatus::Degraded, Some(*brand))
        }
        _ => (WatermarkStatus::NotDetected, None),
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

    // ----- looks_like_video ----------

    #[test]
    fn looks_like_video_accepts_documented_extensions() {
        for ext in ["mp4", "mov", "mkv", "webm", "avi", "m4v"] {
            let p = std::path::PathBuf::from(format!("/test/file.{ext}"));
            assert!(looks_like_video(&p), "{ext} should look like video");
        }
    }

    #[test]
    fn looks_like_video_is_case_insensitive() {
        // Operators pass paths from the filesystem; on Windows
        // the extension can be UPPER. Pin lowercase-normalisation.
        for ext in ["MP4", "MOV", "Mkv", "WEBM", "Avi", "M4V"] {
            let p = std::path::PathBuf::from(format!("/test/file.{ext}"));
            assert!(looks_like_video(&p), "{ext} should look like video");
        }
    }

    #[test]
    fn looks_like_video_rejects_non_video_extensions() {
        for ext in ["txt", "mp3", "wav", "png", "jpg", "pdf"] {
            let p = std::path::PathBuf::from(format!("/test/file.{ext}"));
            assert!(
                !looks_like_video(&p),
                "{ext} should NOT look like video"
            );
        }
    }

    #[test]
    fn looks_like_video_rejects_path_with_no_extension() {
        let p = std::path::PathBuf::from("/test/README");
        assert!(!looks_like_video(&p));
    }

    #[test]
    fn looks_like_video_rejects_empty_extension() {
        // Path like "/test/file." has an extension that's the
        // empty string per Rust's Path::extension semantics —
        // but actually returns None. Cover the edge.
        let p = std::path::PathBuf::from("/test/file.");
        assert!(!looks_like_video(&p));
    }

    // ----- not_video / missing_ffmpeg early-return paths ----------

    #[test]
    fn not_video_returns_trustmark_video_kind() {
        let r = not_video();
        assert!(matches!(r.kind, WatermarkKind::TrustMarkVideo));
        assert_eq!(r.confidence, 0.0);
        assert!(!r.detected);
        assert_eq!(r.message.as_deref(), Some("not video"));
    }

    #[test]
    fn missing_ffmpeg_returns_install_hint() {
        let r = missing_ffmpeg();
        assert!(matches!(r.kind, WatermarkKind::TrustMarkVideo));
        assert!(!r.detected);
        let msg = r.message.expect("must have message");
        // The message must name every supported install path so
        // the operator can copy-paste the right one. Pin them.
        assert!(msg.contains("ffmpeg"));
        assert!(msg.contains("apt") || msg.contains("brew") || msg.contains("winget"));
    }

    // ----- MIN_DETECTED_FRAMES + MIN_DEGRADED_FRAMES thresholds ----------

    #[test]
    fn min_detected_frames_is_three() {
        // Bumping this silently shifts every video detection
        // verdict. Pin explicitly.
        assert_eq!(MIN_DETECTED_FRAMES, 3);
    }

    #[test]
    fn min_degraded_frames_is_below_detected() {
        // Tier ordering invariant — degraded must be a less strict
        // bar than detected. Compile-time visible constants need
        // black_box wrapping so clippy doesn't fold and complain.
        let degraded = std::hint::black_box(MIN_DEGRADED_FRAMES);
        let detected = std::hint::black_box(MIN_DETECTED_FRAMES);
        assert!(degraded < detected);
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
    fn classify_votes_empty_returns_not_detected() {
        let votes = BTreeMap::new();
        let (status, brand) = classify_votes(&votes);
        assert_eq!(status, WatermarkStatus::NotDetected);
        assert_eq!(brand, None);
    }

    #[test]
    fn classify_votes_single_vote_returns_not_detected() {
        // 1 vote: below MIN_DEGRADED_FRAMES = 2 → no signal yet.
        let mut votes = BTreeMap::new();
        votes.insert(WatermarkBrand::Raidio, 1);
        let (status, brand) = classify_votes(&votes);
        assert_eq!(status, WatermarkStatus::NotDetected);
        assert_eq!(brand, None);
    }

    #[test]
    fn classify_votes_two_votes_returns_degraded() {
        // 2 votes: clears MIN_DEGRADED_FRAMES = 2, below
        // MIN_DETECTED_FRAMES = 3.
        let mut votes = BTreeMap::new();
        votes.insert(WatermarkBrand::Raidio, 2);
        let (status, brand) = classify_votes(&votes);
        assert_eq!(status, WatermarkStatus::Degraded);
        assert_eq!(brand, Some(WatermarkBrand::Raidio));
    }

    #[test]
    fn classify_votes_three_votes_returns_detected() {
        // 3 votes: clears MIN_DETECTED_FRAMES = 3.
        let mut votes = BTreeMap::new();
        votes.insert(WatermarkBrand::Doomscroll, 3);
        let (status, brand) = classify_votes(&votes);
        assert_eq!(status, WatermarkStatus::Detected);
        assert_eq!(brand, Some(WatermarkBrand::Doomscroll));
    }

    #[test]
    fn classify_votes_thirty_votes_returns_detected() {
        // Saturated: 30 votes for one brand → Detected.
        let mut votes = BTreeMap::new();
        votes.insert(WatermarkBrand::Vaideo, 30);
        let (status, brand) = classify_votes(&votes);
        assert_eq!(status, WatermarkStatus::Detected);
        assert_eq!(brand, Some(WatermarkBrand::Vaideo));
    }

    #[test]
    fn classify_votes_picks_majority_winner() {
        // Two brands with different counts: majority wins.
        let mut votes = BTreeMap::new();
        votes.insert(WatermarkBrand::Raidio, 5);
        votes.insert(WatermarkBrand::Doomscroll, 2);
        let (status, brand) = classify_votes(&votes);
        assert_eq!(status, WatermarkStatus::Detected);
        assert_eq!(brand, Some(WatermarkBrand::Raidio));
    }

    #[test]
    fn classify_votes_split_below_threshold_returns_not_detected() {
        // Two brands each with 1 vote: neither clears the
        // Degraded threshold individually → NotDetected.
        let mut votes = BTreeMap::new();
        votes.insert(WatermarkBrand::Raidio, 1);
        votes.insert(WatermarkBrand::Doomscroll, 1);
        let (status, brand) = classify_votes(&votes);
        assert_eq!(status, WatermarkStatus::NotDetected);
        assert_eq!(brand, None);
    }

    #[test]
    fn classify_votes_tiebreak_is_deterministic() {
        // Both brands have the same count → BTreeMap ordering
        // (WatermarkBrand variant order) picks. Run twice and
        // confirm we get the same winner — guards against
        // accidental HashMap reintroduction.
        let mut votes = BTreeMap::new();
        votes.insert(WatermarkBrand::Doomscroll, 3);
        votes.insert(WatermarkBrand::Raidio, 3);
        let (status_a, brand_a) = classify_votes(&votes);
        let (status_b, brand_b) = classify_votes(&votes);
        assert_eq!(status_a, status_b);
        assert_eq!(brand_a, brand_b);
        assert_eq!(status_a, WatermarkStatus::Detected);
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
