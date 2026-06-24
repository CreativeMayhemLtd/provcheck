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

pub use provcheck::prelude::{WatermarkBrand, WatermarkKind, WatermarkResult, WatermarkStatus};

#[doc(hidden)]
pub mod audio;
mod brand;
#[doc(hidden)]
pub mod decode;
#[doc(hidden)]
pub mod encode;
#[doc(hidden)]
pub mod hparams;
#[doc(hidden)]
pub mod model;
#[doc(hidden)]
pub mod stft;

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
    //    Parallel-chunked with confidence-based early exit:
    //      a. process up to PARALLEL_BATCH chunks concurrently;
    //      b. after each batch, decode the partial logits;
    //      c. exit early if confidence >= EARLY_EXIT_THRESHOLD.
    //    Worst case (unmarked file) is the full traversal of the
    //    carrier — same wall-clock as v0.3.7's sequential chunk
    //    loop, possibly faster from rayon. Best case (clearly-
    //    marked file) terminates after 2-3 chunks (~10s of audio),
    //    which on a 60-minute episode is a 100x+ speedup.
    //
    //    Windowed inference (truncating tile count) was tried in
    //    v0.3.2-dev and reverted: silentcipher's per-position mode
    //    vote across tiles is the load-bearing noise-rejection step
    //    for marginal-SNR inputs (e.g. mixed-down voice tracks after
    //    MP3 encoding). Early exit is structurally different — we
    //    process MORE tiles only when needed, never fewer than the
    //    decoder needs to be confident.
    let decoded = match detect_chunked(&carrier, t_frames) {
        Ok(d) => d,
        Err(e) => {
            return Ok(not_detected(&format!("model error: {e}")));
        }
    };

    // 5. Schema-aware brand dispatch + tiered status. detect_chunked
    //    already ran the per-position mode vote so we just consume
    //    its output here.
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
    let marked_regions = if detected {
        let regs = regions_from_tile_quality(&decoded.tile_quality);
        if regs.is_empty() { None } else { Some(regs) }
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
        marked_regions,
    })
}

/// Per-tile match fraction threshold separating "this tile sits
/// inside a watermarked stretch" from "this tile is clean audio".
///
/// Random arg-max with no signal has expected match fraction
/// `1 / MESSAGE_DIM = 0.20`. A fully-marked tile rides near 1.0.
/// 0.55 leaves a comfortable margin above noise without rejecting
/// realistic mid-quality tiles (e.g. lossy-compressed audio that
/// still carries the mark at reduced fidelity).
const TILE_QUALITY_THRESHOLD: f32 = 0.55;

/// Minimum span duration (seconds) for a contiguous-hot-tile run
/// to be reported in `marked_regions`. Below this, single-tile
/// spikes are dropped as detection noise. One MESSAGE_LEN tile is
/// `21 * 2048 / 44_100 ≈ 0.975 s`, so 2 s ≈ 2 tiles.
const MIN_REGION_SECONDS: f32 = 2.0;

/// Walk per-tile quality and emit `(start_sec, end_sec)` spans
/// where the quality stays above [`TILE_QUALITY_THRESHOLD`] for at
/// least [`MIN_REGION_SECONDS`].
///
/// Tile-to-time mapping: tile `i` covers STFT frames
/// `[i * MESSAGE_LEN, (i+1) * MESSAGE_LEN)`. Each STFT frame is
/// `HOP` samples apart at `SAMPLE_RATE` Hz, so the tile boundaries
/// land at `i * MESSAGE_LEN * HOP / SAMPLE_RATE` seconds.
fn regions_from_tile_quality(tile_quality: &[f32]) -> Vec<(f32, f32)> {
    if tile_quality.is_empty() {
        return Vec::new();
    }
    let secs_per_tile =
        (hparams::MESSAGE_LEN as f32 * hparams::HOP as f32) / hparams::SAMPLE_RATE as f32;
    let mut regions = Vec::new();
    let mut start: Option<usize> = None;
    for (i, &q) in tile_quality.iter().enumerate() {
        let hot = q >= TILE_QUALITY_THRESHOLD;
        match (start, hot) {
            (None, true) => start = Some(i),
            (Some(s), false) => {
                let span_sec = (i - s) as f32 * secs_per_tile;
                if span_sec >= MIN_REGION_SECONDS {
                    regions.push((s as f32 * secs_per_tile, i as f32 * secs_per_tile));
                }
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        let end = tile_quality.len();
        let span_sec = (end - s) as f32 * secs_per_tile;
        if span_sec >= MIN_REGION_SECONDS {
            regions.push((s as f32 * secs_per_tile, end as f32 * secs_per_tile));
        }
    }
    regions
}

/// Confidence at or above which we trust the partial decode and
/// stop processing more chunks. Tuned well above the brand-classify
/// "Detected" threshold (0.70) so the wall-clock-fast path doesn't
/// risk downgrading a Detected verdict to Degraded as later tiles
/// come in.
const EARLY_EXIT_THRESHOLD: f32 = 0.85;

/// Minimum frames consumed before early-exit checks fire. Below
/// this, the per-position mode-vote doesn't have enough tile
/// redundancy for the confidence to be meaningful. 4 tiles is the
/// floor we accept; below that we let the loop run.
const EARLY_EXIT_MIN_FRAMES: usize = hparams::MESSAGE_LEN * 4;

/// Run the silentcipher decoder on a carrier tensor with chunked
/// inference, parallel batching, and confidence-based early exit.
///
/// Returns the decoded result whichever way the loop terminates —
/// either we hit the early-exit threshold partway through the
/// carrier, or we exhaust the whole carrier and decode the final
/// accumulated logits.
fn detect_chunked(
    carrier: &[f32],
    t_frames: usize,
) -> Result<decode::DecodeResult, model::ModelError> {
    use rayon::prelude::*;

    // Fan-out for parallel chunks within a single batch. Each chunk
    // peaks at ~1.5 GB of tract intermediates, so N chunks in
    // parallel ≈ N × 1.5 GB peak — we conservatively cap at 4 so
    // we stay under typical container memory ceilings.
    let parallel_batch: usize = std::thread::available_parallelism()
        .map(|n| (n.get() / 2).clamp(1, 4))
        .unwrap_or(2);

    let mut full_logits = vec![0.0_f32; hparams::MESSAGE_DIM * t_frames];
    let mut t_consumed: usize = 0;

    while t_consumed < t_frames {
        // Build this batch's chunk offsets + sizes.
        let mut batch: Vec<(usize, usize)> = Vec::with_capacity(parallel_batch);
        let mut t_cursor = t_consumed;
        for _ in 0..parallel_batch {
            if t_cursor >= t_frames {
                break;
            }
            let chunk_t = (t_frames - t_cursor).min(model::CHUNK_T_FRAMES);
            batch.push((t_cursor, chunk_t));
            t_cursor += chunk_t;
        }

        // Run the batch concurrently. Each thread independently
        // extracts its slice, runs tract, returns the chunk_logits.
        // tract's runnable model is Send+Sync (it's behind &), so
        // rayon can hand the same OnceLock-cached model to every
        // worker.
        let results: Result<Vec<(usize, usize, Vec<f32>)>, model::ModelError> = batch
            .par_iter()
            .map(|&(t_start, chunk_t)| {
                let chunk_carrier = model::extract_chunk(carrier, t_frames, t_start, chunk_t);
                let chunk_logits = model::run_chunk_owned(&chunk_carrier, chunk_t)?;
                Ok((t_start, chunk_t, chunk_logits))
            })
            .collect();
        let chunks = results?;

        // Scatter every chunk in this batch into full_logits and
        // advance the consumed counter to the highest t_start +
        // chunk_t. (Chunks within a batch are guaranteed
        // non-overlapping by construction.)
        for (t_start, chunk_t, chunk_logits) in chunks {
            model::scatter_chunk_logits(
                &chunk_logits,
                chunk_t,
                &mut full_logits,
                t_frames,
                t_start,
            );
            t_consumed = t_consumed.max(t_start + chunk_t);
        }

        // Early-exit check. Decode the partial logits — we need to
        // re-pack into a `[MESSAGE_DIM, t_consumed]` layout because
        // decode_logits's indexing depends on t_frames matching the
        // logits-buffer time axis.
        if t_consumed >= EARLY_EXIT_MIN_FRAMES && t_consumed < t_frames {
            let partial = pack_partial_logits(&full_logits, t_frames, t_consumed);
            let decoded = decode::decode_logits(&partial, t_consumed);
            if decoded.valid && decoded.confidence >= EARLY_EXIT_THRESHOLD {
                return Ok(decoded);
            }
        }
    }

    // Full traversal completed (or fast-path threshold never hit).
    // Decode against the full accumulated logits and return.
    Ok(decode::decode_logits(&full_logits, t_frames))
}

/// Extract a `[MESSAGE_DIM, t_consumed]` row-major buffer from the
/// pre-allocated `[MESSAGE_DIM, t_frames]` full_logits buffer. Only
/// the first `t_consumed` columns are populated in full_logits at
/// this point; the rest are zero. decode_logits's indexing requires
/// the layout's time axis to equal the t_frames argument it
/// receives, so we have to repack.
fn pack_partial_logits(full: &[f32], t_frames: usize, t_consumed: usize) -> Vec<f32> {
    let mut partial = vec![0.0_f32; hparams::MESSAGE_DIM * t_consumed];
    for dim in 0..hparams::MESSAGE_DIM {
        let src_off = dim * t_frames;
        let dst_off = dim * t_consumed;
        partial[dst_off..dst_off + t_consumed]
            .copy_from_slice(&full[src_off..src_off + t_consumed]);
    }
    partial
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
        marked_regions: None,
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
        f.write_all(b"RIFF\0\0\0\0WAVEfmt notrealdataatall")
            .unwrap();
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
