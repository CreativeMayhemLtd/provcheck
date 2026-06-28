//! # provcheck-wavmark
//!
//! WavMark neural-watermark detection (and embedding) for [`provcheck`].
//! Sibling crate to `provcheck-watermark` (silentcipher) and
//! `provcheck-audioseal`. Each detector pushes a result into
//! [`Report::watermarks`](provcheck::report::Report::watermarks) so a
//! single verify pass can report multiple independent detector signals.
//!
//! ## License justification
//!
//! WavMark is a 2023 academic release (paper
//! [arXiv:2308.12770](https://arxiv.org/abs/2308.12770), "WavMark:
//! Watermarking for Audio Generation").
//!
//! - **Code:** [wavmark/wavmark](https://github.com/wavmark/wavmark)
//!   under the **MIT License**.
//! - **Model weights:** distributed inside the [`wavmark` PyPI
//!   package](https://pypi.org/project/wavmark/), same MIT terms.
//!
//! Both pieces compose cleanly with provcheck's Apache-2.0 workspace
//! license per `WATERMARK_LICENSE_POLICY.md`.
//!
//! ## Pipeline
//!
//! 1. [`audio`] decodes via symphonia, downmixes to mono `f32`,
//!    resamples to 16 kHz (WavMark's training rate).
//! 2. [`detect::detect`] slides a 1-second window across the audio
//!    at 50 ms steps, runs the HiNet reverse-pass ONNX on each window,
//!    and keeps windows whose recovered first-16-bits exactly match
//!    WavMark's fix-pattern. Hit fraction is the detection signal.
//! 3. [`brand::parse_brand`] maps the recovered lower-16-bit custom
//!    payload to a [`WatermarkBrand`] via the shared numeric registry.
//!
//! ## STFT lives in Rust
//!
//! WavMark's PyTorch model uses
//! `torch.stft(..., return_complex=True)`, which `torch.onnx`'s
//! opset-17 STFT op rejects. The export at
//! `scripts/export-wavmark.py` keeps only the HiNet invertible-NN
//! block in ONNX; STFT, iSTFT, and the two Linear projections live
//! in [`stft`] and [`model`].

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
#[doc(hidden)]
pub mod stft;

/// Errors returned by [`detect`]. Non-fatal outcomes (not audio,
/// decoder errors) are reported on the returned [`WatermarkResult`]
/// via its `message` field. `Error` is reserved for genuinely
/// exceptional cases (file not found, unreadable).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("file not found or unreadable: {0}")]
    Io(#[from] std::io::Error),
}

/// Confidence at or above which detection reports as `Detected`.
/// Real marked WavMark content hits ~30–80 % of windows (every
/// ~50 ms position inside a marked stretch matches; boundaries and
/// unmarked tails miss). 0.05 is well above the
/// `1 / 2^16 = 1.5e-5` false-positive floor per window.
const CONFIDENCE_DETECTED_THRESHOLD: f32 = 0.05;

/// Confidence at or above which detection reports as `Degraded`.
/// Real marked content compressed through MP3 or pitched can drop to
/// ~1–4 % hit rate; we still want to surface that signal.
const CONFIDENCE_DEGRADED_THRESHOLD: f32 = 0.005;

/// Run the WavMark detector on the file at `path`.
pub fn detect(path: &Path) -> Result<WatermarkResult, Error> {
    let _ = std::fs::metadata(path)?;

    if !looks_like_audio(path) {
        return Ok(not_detected("not audio"));
    }

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

    let result = match detect::detect(&waveform) {
        Ok(r) => r,
        Err(e) => return Ok(not_detected(&format!("model error: {e}"))),
    };

    let confidence = result.detection_probability;
    let status = classify(confidence);
    let detected = matches!(
        status,
        WatermarkStatus::Detected | WatermarkStatus::Degraded
    );
    let brand = if detected && result.matched_windows > 0 {
        brand::parse_brand(result.payload)
    } else {
        None
    };
    let payload = if detected {
        Some(result.payload.to_vec())
    } else {
        None
    };
    let marked_regions = if detected && !result.marked_regions.is_empty() {
        Some(result.marked_regions)
    } else {
        None
    };

    Ok(WatermarkResult {
        kind: WatermarkKind::WavMark,
        status,
        detected,
        confidence,
        payload,
        brand,
        message: None,
        marked_regions,
    })
}

fn classify(confidence: f32) -> WatermarkStatus {
    if confidence >= CONFIDENCE_DETECTED_THRESHOLD {
        WatermarkStatus::Detected
    } else if confidence >= CONFIDENCE_DEGRADED_THRESHOLD {
        WatermarkStatus::Degraded
    } else {
        WatermarkStatus::NotDetected
    }
}

fn not_detected(reason: &str) -> WatermarkResult {
    WatermarkResult {
        kind: WatermarkKind::WavMark,
        status: WatermarkStatus::NotDetected,
        detected: false,
        confidence: 0.0,
        payload: None,
        brand: None,
        message: Some(reason.into()),
        marked_regions: None,
    }
}

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

    #[test]
    fn missing_file_is_io_error() {
        let err = detect(Path::new("does_not_exist_wavmark_42.wav")).unwrap_err();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn non_audio_returns_not_audio() {
        let mut f = tempfile::Builder::new().suffix(".png").tempfile().unwrap();
        f.write_all(b"\x89PNG\r\n\x1a\n").unwrap();
        let r = detect(f.path()).unwrap();
        assert!(matches!(r.kind, WatermarkKind::WavMark));
        assert!(matches!(r.status, WatermarkStatus::NotDetected));
        assert_eq!(r.message.as_deref(), Some("not audio"));
    }

    #[test]
    fn audio_extension_classifier_recognises_common() {
        for ext in ["mp3", "WAV", "Flac", "m4a", "ogg", "opus", "aif"] {
            let p = std::path::PathBuf::from(format!("sample.{ext}"));
            assert!(looks_like_audio(&p), "expected {ext} to be audio");
        }
    }

    #[test]
    fn classifier_buckets_match_thresholds() {
        assert_eq!(classify(0.99), WatermarkStatus::Detected);
        assert_eq!(classify(0.05), WatermarkStatus::Detected);
        assert_eq!(classify(0.049), WatermarkStatus::Degraded);
        assert_eq!(classify(0.005), WatermarkStatus::Degraded);
        assert_eq!(classify(0.004), WatermarkStatus::NotDetected);
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
