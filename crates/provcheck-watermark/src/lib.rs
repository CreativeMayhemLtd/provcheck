//! # provcheck-watermark
//!
//! Neural-watermark detection for [`provcheck`]. Detects the
//! sonic watermark embedded by Sony's silentcipher
//! ([sony/silentcipher](https://github.com/sony/silentcipher),
//! Interspeech 2024), which is what rAIdio.bot and doomscroll.fm
//! use to mark AI-generated audio. Independent of C2PA: the two
//! signals corroborate or contradict each other rather than
//! sharing a trust chain.
//!
//! ## Pipeline
//!
//! 1. [`audio`] decodes the input container (mp3 / wav / flac /
//!    m4a / ogg) via symphonia, downmixes to mono `f32`, and
//!    resamples to 44.1 kHz via rubato.
//! 2. [`stft`] applies the VCTK energy rescale, tail-pads the
//!    waveform, reflect-pads each end, frames at 2048-sample
//!    hops with a 4096-sample Hann window, takes the real FFT
//!    magnitude — producing the carrier tensor the decoder
//!    consumes.
//! 3. [`model`] runs the embedded ONNX decoder via tract.
//! 4. [`decode`] argmax-decodes the logit time series, votes
//!    per position across all tiles of the message, checks
//!    structural validity, and bit-packs the recovered 40 bits
//!    into 5 payload bytes.
//! 5. [`brand`] dispatches on the payload's schema byte to
//!    return the issuing product (rAIdio.bot, doomscroll.fm,
//!    vAIdeo.bot, or an `Unknown*` fallback) and classifies the
//!    confidence into Detected / Degraded / NotDetected.
//!
//! ## Brand-agnosticism
//!
//! Detection is brand-agnostic. The trained silentcipher
//! decoder recovers whatever 40 bits the embedder placed in the
//! file; the schema dispatch in [`brand`] only *labels* those
//! bits according to Creative Mayhem's tagged-union convention
//! (`schema=1` + 3-byte ASCII triplet). Any silentcipher-marked
//! file from a non-CM source still produces a green-status
//! result with `status: Detected` and the raw 5 bytes on
//! [`WatermarkResult::payload`]; only the [`WatermarkResult::brand`]
//! field falls back to `UnknownAscii` (schema 1 but unrecognised
//! triplet) or `UnknownSchema` (schema byte other than 1). What
//! this detector *cannot* see is watermarks from a different
//! family (AudioSeal, WavMark, etc.) — those need their own
//! decoders and would live in sibling crates that push another
//! entry into [`Report::watermarks`](provcheck::report::Report::watermarks).
//!
//! ## Eligibility for inclusion
//!
//! Detectors shipped inside provcheck must satisfy the workspace
//! license policy. See `WATERMARK_LICENSE_POLICY.md` at the
//! repository root for the full rule and the current pass/fail
//! survey of the major watermark families.
//!
//! ## Example
//!
//! ```no_run
//! use provcheck_watermark::detect;
//! use std::path::Path;
//!
//! let result = detect(Path::new("song.mp3"))?;
//! if result.detected {
//!     println!("silentcipher mark @ {:.0}%", result.confidence * 100.0);
//! }
//! # Ok::<(), provcheck_watermark::Error>(())
//! ```

use std::path::Path;

pub use provcheck::prelude::{
    WatermarkBrand, WatermarkKind, WatermarkResult, WatermarkStatus,
};

mod audio;
mod brand;
mod decode;
mod hparams;
mod model;
mod stft;

/// Errors returned by [`detect`]. All non-fatal outcomes —
/// "not audio", "decoder error" — are reported on the
/// returned [`WatermarkResult`] via its `message` field.
/// `Error` is reserved for genuinely exceptional cases (file
/// not found, unreadable).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The target file could not be opened.
    #[error("file not found or unreadable: {0}")]
    Io(#[from] std::io::Error),
}

/// Run the silentcipher detector on the file at `path`.
///
/// Returns a populated [`WatermarkResult`] regardless of whether
/// the file is audio. Callers should treat the `status` field
/// as load-bearing and the `message` field as informational
/// (it carries reasons like "not audio" or "decoder error").
///
/// Only returns `Err` on I/O failure (file missing,
/// unreadable). Non-audio input and decoder failures are
/// reported as a `WatermarkResult` with `status == NotDetected`
/// and a descriptive `message`, never as an `Err`.
pub fn detect(path: &Path) -> Result<WatermarkResult, Error> {
    // Preflight: file must exist. Lets us surface I/O errors
    // cleanly instead of muddling them with "not audio".
    let _ = std::fs::metadata(path)?;

    // Fast-path filter: avoid spinning up symphonia for files
    // with obviously non-audio extensions (PNG, MP4 video, MD,
    // etc.). Symphonia would reject them anyway; doing so here
    // saves the load-time cost.
    if !looks_like_audio(path) {
        return Ok(not_detected("not audio"));
    }

    // 1. Decode container → mono 44.1 kHz waveform.
    let waveform = match audio::decode_to_mono_44k1(path) {
        Ok(w) => w,
        Err(audio::AudioError::NotAudio) => {
            return Ok(not_detected("not audio"));
        }
        Err(audio::AudioError::Decode(msg)) => {
            return Ok(not_detected(&format!("decoder error: {msg}")));
        }
        Err(audio::AudioError::Resample(msg)) => {
            return Ok(not_detected(&format!("resample error: {msg}")));
        }
        Err(audio::AudioError::Io(e)) => return Err(Error::Io(e)),
    };

    // 2. STFT → carrier [1, 1, 2049, T].
    let (carrier, t_frames) = match stft::waveform_to_carrier(&waveform) {
        Ok(c) => c,
        Err(stft::StftError::Empty) => {
            return Ok(not_detected("audio decoded to zero samples"));
        }
        Err(stft::StftError::TooShort) => {
            return Ok(not_detected("audio shorter than minimum detection window"));
        }
    };

    // 3. Run the ONNX decoder → logits [1, 1, MESSAGE_DIM, T].
    let logits = match model::run(&carrier, t_frames) {
        Ok(l) => l,
        Err(e) => {
            return Ok(not_detected(&format!("model error: {e}")));
        }
    };

    // 4. Back-end decode → 5 payload bytes + confidence +
    //    structural-validity bit.
    let decoded = decode::decode_logits(&logits, t_frames);

    // 5. Schema-aware brand dispatch + tiered status.
    let status = brand::classify(decoded.valid, decoded.confidence);
    let detected = matches!(
        status,
        WatermarkStatus::Detected | WatermarkStatus::Degraded
    );
    let brand = if decoded.valid {
        brand::parse_brand(decoded.payload)
    } else {
        None
    };
    let payload = if decoded.valid {
        Some(decoded.payload.to_vec())
    } else {
        None
    };

    Ok(WatermarkResult {
        kind: WatermarkKind::SilentCipher,
        status,
        detected,
        confidence: decoded.confidence,
        payload,
        brand,
        message: None,
    })
}

/// Build a `WatermarkResult` representing "nothing found, here's
/// why" without repeating the field-level defaults at every call
/// site.
fn not_detected(reason: &str) -> WatermarkResult {
    WatermarkResult {
        kind: WatermarkKind::SilentCipher,
        status: WatermarkStatus::NotDetected,
        detected: false,
        confidence: 0.0,
        payload: None,
        brand: None,
        message: Some(reason.into()),
    }
}

/// Cheap audio classifier by file extension. Deliberately
/// loose — anything symphonia would later try to decode counts.
/// Symphonia's probe is the authoritative test for borderline
/// cases (raw streams, mislabelled extensions); this just keeps
/// us from loading a 9 MB ONNX runtime for obvious PNGs.
fn looks_like_audio(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "mp3" | "wav" | "flac" | "aac" | "m4a" | "ogg" | "oga" | "opus" | "wma" | "aiff" | "aif"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn audio_extension_sniff_recognises_common_formats() {
        for ext in ["mp3", "WAV", "Flac", "m4a", "ogg", "opus", "aif"] {
            let p = std::path::PathBuf::from(format!("sample.{}", ext));
            assert!(looks_like_audio(&p), "expected {} to be audio", ext);
        }
    }

    #[test]
    fn non_audio_extensions_are_rejected() {
        for ext in ["png", "jpg", "txt", "pdf", "md", "exe"] {
            let p = std::path::PathBuf::from(format!("sample.{}", ext));
            assert!(!looks_like_audio(&p), "expected {} to NOT be audio", ext);
        }
    }

    #[test]
    fn missing_extension_is_not_audio() {
        assert!(!looks_like_audio(std::path::Path::new("README")));
    }

    #[test]
    fn missing_file_is_io_error() {
        let err = detect(std::path::Path::new("does_not_exist_zzzzzz.wav")).unwrap_err();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn non_audio_returns_not_audio_message() {
        let mut f = tempfile::Builder::new().suffix(".png").tempfile().unwrap();
        f.write_all(b"\x89PNG\r\n\x1a\n").unwrap();
        let r = detect(f.path()).unwrap();
        assert!(!r.detected);
        assert!(matches!(r.status, WatermarkStatus::NotDetected));
        assert_eq!(r.confidence, 0.0);
        assert_eq!(r.message.as_deref(), Some("not audio"));
        assert!(matches!(r.kind, WatermarkKind::SilentCipher));
    }

    #[test]
    fn fake_wav_with_audio_extension_decodes_cleanly_to_not_detected() {
        // A file with `.wav` extension but no real wave data
        // makes it past the extension sniff but symphonia
        // rejects it. The detector should report not-detected
        // with a "not audio" / decoder-error message, never
        // panic or surface an I/O error.
        let mut f = tempfile::Builder::new().suffix(".wav").tempfile().unwrap();
        f.write_all(b"RIFF\0\0\0\0WAVEfmt notrealdataatall").unwrap();
        let r = detect(f.path()).unwrap();
        assert!(!r.detected);
        assert!(matches!(r.status, WatermarkStatus::NotDetected));
        // Message names a specific failure, not the silent
        // stub-pending sentinel from earlier in development.
        let msg = r.message.unwrap_or_default();
        assert!(
            !msg.contains("stub") && !msg.contains("pending"),
            "stale stub-pending sentinel in real-pipeline path: {}",
            msg
        );
    }
}
