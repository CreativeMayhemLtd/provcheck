//! # provcheck-audioseal
//!
//! AudioSeal neural-watermark detection (and embedding) for
//! [`provcheck`]. Sibling crate to `provcheck-watermark` (silentcipher);
//! both push results into [`Report::watermarks`](provcheck::report::Report::watermarks)
//! so a single verify pass can report multiple independent detector
//! signals.
//!
//! ## License justification
//!
//! AudioSeal is a Meta FAIR research release (ICML 2024,
//! [arXiv:2401.17264](https://arxiv.org/abs/2401.17264)).
//!
//! - **Code:** [facebookresearch/audioseal](https://github.com/facebookresearch/audioseal)
//!   under the **MIT License** (Copyright © Meta Platforms, Inc.).
//! - **Model weights:** distributed via the [Hugging Face Hub at
//!   `facebook/audioseal`](https://huggingface.co/facebook/audioseal),
//!   relicensed to full MIT on 2024-04-02 (the README explicitly
//!   permits commercial use). Pre-relicense CC-BY-NC era weights
//!   would have been rejected.
//!
//! Both pieces compose cleanly with provcheck's Apache-2.0 workspace
//! license per `WATERMARK_LICENSE_POLICY.md`.
//!
//! ## Pipeline
//!
//! 1. [`audio`] decodes the input container via symphonia, downmixes
//!    to mono `f32`, and resamples to 16 kHz (AudioSeal's training
//!    rate).
//! 2. [`detect::detect`] zero-pads / chunks the waveform into
//!    `CHUNK_SAMPLES` windows, runs the detector ONNX on each in
//!    parallel via rayon, and aggregates per-sample presence into a
//!    detection probability + 16-bit message.
//! 3. [`brand::parse_brand`] maps the 16-bit big-endian message to a
//!    [`WatermarkBrand`] using the shared numeric registry
//!    (`docs/brand-registry.md`).
//! 4. The crate's top-level [`detect`] wraps all that into a
//!    [`WatermarkResult`].
//!
//! ## Chunking constraint
//!
//! AudioSeal's detector ONNX has a **fixed input length** baked in
//! at export time (`CHUNK_SAMPLES = 160_000` = 10 s @ 16 kHz). The
//! dynamic-axis export tract 0.21 can't handle the symbolic Pad
//! expressions that come from PyTorch's onnx exporter, so we sidestep
//! by chunking on the Rust side. Per-sample presence probabilities
//! drift by ~0.001 at chunk boundaries vs a hypothetical full-length
//! inference (vs ~2e-5 in the interior — measured during architecture
//! survey). Detection results aggregate across the file and are
//! insensitive to this; embedding is more sensitive — see
//! [`encode`].

use std::path::Path;

pub use provcheck::prelude::{WatermarkBrand, WatermarkKind, WatermarkResult, WatermarkStatus};

#[doc(hidden)]
pub mod audio;
mod brand;
#[doc(hidden)]
pub mod detect;
#[doc(hidden)]
pub mod encode;
#[doc(hidden)]
pub mod model;
pub mod registry;

/// Errors returned by [`detect`]. All non-fatal outcomes — "not
/// audio", decoder errors — are reported on the returned
/// [`WatermarkResult`] via its `message` field. `Error` is reserved
/// for genuinely exceptional cases (file not found, unreadable).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The target file could not be opened.
    #[error("file not found or unreadable: {0}")]
    Io(#[from] std::io::Error),
}

/// Run the AudioSeal detector on the file at `path`.
///
/// Returns a populated [`WatermarkResult`] regardless of whether the
/// file is audio. Callers should treat the `status` field as
/// load-bearing and the `message` field as informational (it carries
/// reasons like "not audio" or "decoder error").
///
/// Only returns `Err` on I/O failure (file missing, unreadable).
/// Non-audio input and decoder failures are reported as a
/// `WatermarkResult` with `status == NotDetected` and a descriptive
/// `message`, never as an `Err`.
pub fn detect(path: &Path) -> Result<WatermarkResult, Error> {
    // Preflight: file must exist. Lets us surface I/O errors cleanly.
    let _ = std::fs::metadata(path)?;

    if !looks_like_audio(path) {
        return Ok(not_detected("not audio"));
    }

    // 1. Decode container → mono 16 kHz waveform.
    let waveform = match audio::decode_to_mono_16k(path) {
        Ok(w) => w,
        Err(audio::AudioError::NotAudio) => return Ok(not_detected("not audio")),
        Err(audio::AudioError::Decode(msg)) => {
            return Ok(not_detected(&format!("decoder error: {msg}")));
        }
        Err(audio::AudioError::Resample(msg)) => {
            return Ok(not_detected(&format!("resample error: {msg}")));
        }
        Err(audio::AudioError::Io(e)) => return Err(Error::Io(e)),
    };

    // 2. Run chunked detector.
    let result = match detect::detect(&waveform) {
        Ok(r) => r,
        Err(e) => return Ok(not_detected(&format!("model error: {e}"))),
    };

    // 3. Brand classification + tiered status.
    let detection_probability = result.detection_probability;
    let status = classify(detection_probability);
    let detected = matches!(
        status,
        WatermarkStatus::Detected | WatermarkStatus::Degraded
    );
    let brand = if detection_probability >= CONFIDENCE_DEGRADED_THRESHOLD {
        brand::parse_brand(result.message)
    } else {
        // Below detection threshold: don't pretend to recognise a
        // brand from random-looking bits.
        None
    };
    let payload = if detected {
        Some(result.message.to_vec())
    } else {
        None
    };
    let marked_regions = if detected && !result.marked_regions.is_empty() {
        Some(result.marked_regions)
    } else {
        None
    };

    Ok(WatermarkResult {
        kind: WatermarkKind::AudioSeal,
        status,
        detected,
        confidence: detection_probability,
        payload,
        brand,
        message: None,
        marked_regions,
    })
}

/// Confidence at or above which detection reports as `Detected`.
const CONFIDENCE_DETECTED_THRESHOLD: f32 = 0.70;

/// Confidence at or above which detection reports as `Degraded`
/// (when not `Detected`). Below this reports as `NotDetected` even
/// if some samples appear marked.
const CONFIDENCE_DEGRADED_THRESHOLD: f32 = 0.50;

/// Three-tier classifier for the AudioSeal detection probability.
/// Mirrors silentcipher's classify for consistency in the report
/// rendering.
fn classify(confidence: f32) -> WatermarkStatus {
    if confidence >= CONFIDENCE_DETECTED_THRESHOLD {
        WatermarkStatus::Detected
    } else if confidence >= CONFIDENCE_DEGRADED_THRESHOLD {
        WatermarkStatus::Degraded
    } else {
        WatermarkStatus::NotDetected
    }
}

/// Build a `WatermarkResult` representing "nothing found, here's
/// why" without repeating the field-level defaults at every call
/// site.
fn not_detected(reason: &str) -> WatermarkResult {
    WatermarkResult {
        kind: WatermarkKind::AudioSeal,
        status: WatermarkStatus::NotDetected,
        detected: false,
        confidence: 0.0,
        payload: None,
        brand: None,
        message: Some(reason.into()),
        marked_regions: None,
    }
}

/// Cheap audio classifier by extension. Same allowlist as
/// `provcheck-watermark::looks_like_audio`. Saves loading a 33 MB
/// ONNX runtime when someone hands us a PNG.
fn looks_like_audio(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "mp3"
            | "mp4"
            | "wav"
            | "flac"
            | "aac"
            | "m4a"
            | "m4b"
            | "mov"
            | "ogg"
            | "oga"
            | "opus"
            | "wma"
            | "aiff"
            | "aif"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // ----- classify ----------

    #[test]
    fn classify_at_detected_threshold_is_detected() {
        assert!(matches!(
            classify(CONFIDENCE_DETECTED_THRESHOLD),
            WatermarkStatus::Detected
        ));
    }

    #[test]
    fn classify_at_degraded_threshold_is_degraded() {
        assert!(matches!(
            classify(CONFIDENCE_DEGRADED_THRESHOLD),
            WatermarkStatus::Degraded
        ));
    }

    #[test]
    fn classify_below_degraded_is_not_detected() {
        assert!(matches!(
            classify(CONFIDENCE_DEGRADED_THRESHOLD - 0.01),
            WatermarkStatus::NotDetected
        ));
    }

    #[test]
    fn classify_just_below_detected_is_degraded() {
        assert!(matches!(
            classify(CONFIDENCE_DETECTED_THRESHOLD - 0.01),
            WatermarkStatus::Degraded
        ));
    }

    // ----- looks_like_audio ----------

    #[test]
    fn looks_like_audio_accepts_documented_extensions() {
        for ext in [
            "mp3", "mp4", "wav", "flac", "aac", "m4a", "m4b", "mov", "ogg",
            "oga", "opus", "wma", "aiff", "aif",
        ] {
            let p = std::path::PathBuf::from(format!("/test/file.{ext}"));
            assert!(looks_like_audio(&p), "{ext} should look like audio");
        }
    }

    #[test]
    fn looks_like_audio_rejects_image_and_text_extensions() {
        for ext in ["png", "jpg", "gif", "txt", "md", "html"] {
            let p = std::path::PathBuf::from(format!("/test/file.{ext}"));
            assert!(
                !looks_like_audio(&p),
                "{ext} should NOT look like audio"
            );
        }
    }

    #[test]
    fn looks_like_audio_is_case_insensitive() {
        // Windows paths can be UPPER. Pin lowercase normalisation.
        for ext in ["WAV", "MP3", "FlAc"] {
            let p = std::path::PathBuf::from(format!("/test/file.{ext}"));
            assert!(looks_like_audio(&p), "{ext} should pass case-insensitive");
        }
    }

    #[test]
    fn looks_like_audio_rejects_no_extension() {
        let p = std::path::PathBuf::from("/test/README");
        assert!(!looks_like_audio(&p));
    }

    // ----- not_detected helper ----------

    #[test]
    fn not_detected_helper_sets_audioseal_kind_and_zero_confidence() {
        let r = not_detected("some reason");
        assert!(matches!(r.kind, WatermarkKind::AudioSeal));
        assert!(matches!(r.status, WatermarkStatus::NotDetected));
        assert_eq!(r.confidence, 0.0);
        assert!(!r.detected);
        assert!(r.payload.is_none());
        assert!(r.brand.is_none());
        assert!(r.marked_regions.is_none());
        assert_eq!(r.message.as_deref(), Some("some reason"));
    }

    #[test]
    fn missing_file_is_io_error() {
        let err = detect(Path::new("does_not_exist_audioseal_42.wav")).unwrap_err();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn non_audio_returns_not_audio() {
        let mut f = tempfile::Builder::new().suffix(".png").tempfile().unwrap();
        f.write_all(b"\x89PNG\r\n\x1a\n").unwrap();
        let r = detect(f.path()).unwrap();
        assert!(matches!(r.kind, WatermarkKind::AudioSeal));
        assert!(matches!(r.status, WatermarkStatus::NotDetected));
        assert_eq!(r.message.as_deref(), Some("not audio"));
    }

    #[test]
    fn fake_wav_short_returns_decoder_error_not_panic() {
        let mut f = tempfile::Builder::new().suffix(".wav").tempfile().unwrap();
        f.write_all(b"RIFF\0\0\0\0WAVEfake-not-real-data").unwrap();
        let r = detect(f.path()).unwrap();
        assert!(matches!(r.status, WatermarkStatus::NotDetected));
        let msg = r.message.unwrap_or_default();
        assert!(!msg.contains("pending"), "stale stub message: {msg}");
    }

    #[test]
    fn audio_extension_classifier_recognises_common() {
        for ext in ["mp3", "WAV", "Flac", "m4a", "ogg", "opus", "aif"] {
            let p = std::path::PathBuf::from(format!("sample.{ext}"));
            assert!(looks_like_audio(&p), "expected {ext} to be audio");
        }
    }

    #[test]
    fn non_audio_extensions_rejected() {
        for ext in ["png", "jpg", "txt", "pdf", "md", "exe"] {
            let p = std::path::PathBuf::from(format!("sample.{ext}"));
            assert!(!looks_like_audio(&p));
        }
    }

    #[test]
    fn classifier_buckets_match_thresholds() {
        assert_eq!(classify(0.99), WatermarkStatus::Detected);
        assert_eq!(classify(0.70), WatermarkStatus::Detected);
        assert_eq!(classify(0.69), WatermarkStatus::Degraded);
        assert_eq!(classify(0.50), WatermarkStatus::Degraded);
        assert_eq!(classify(0.49), WatermarkStatus::NotDetected);
    }
}

/// v0.7 phase 7-pre audit #10: Send + Sync bound assertion.
/// See `provcheck-watermark::_send_sync_assertions` for rationale.
#[cfg(test)]
mod _send_sync_assertions {
    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn key_public_types_are_send_sync() {
        assert_send_sync::<crate::WatermarkResult>();
        assert_send_sync::<crate::WatermarkBrand>();
        assert_send_sync::<crate::WatermarkKind>();
        assert_send_sync::<crate::WatermarkStatus>();
        assert_send_sync::<crate::encode::EmbedConfig>();
        assert_send_sync::<crate::encode::EncodeError>();
    }
}
