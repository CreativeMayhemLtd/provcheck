//! Watermark embedding — the producer side.
//!
//! Mirrors silentcipher's `encode_wav()` (server.py:272-348) end-to-end:
//!
//! 1. VCTK-rescale the input waveform.
//! 2. Forward STFT → (magnitude, phase, n_frames, n_samples_input).
//! 3. Build the message tensor from the 5-byte payload
//!    (`letters_encoding`).
//! 4. Compute the utterance-level normalisation scalar from the full
//!    carrier magnitude (one global `sqrt(mean(carrier²))`).
//! 5. Chunk through the encoder ONNX (`enc_c + dec_c` fused),
//!    capping per-call memory exactly like the decoder path.
//! 6. Multiply chunk outputs by the utterance scalar, negate
//!    (`ensure_negative_message`), and ReLU(`+ carrier`) to produce
//!    the modified magnitude `carrier_reconst`.
//! 7. Inverse STFT using `carrier_reconst` magnitude and the
//!    *original* phase.
//! 8. Undo the VCTK rescale.
//!
//! Steps 1, 2, 3, 4, 6, 7, 8 are pure Rust. Step 5 is the tract ONNX
//! inference. The Rust side carries the entire pipeline so the
//! caller hands in a `&[f32]` (mono 44.1 kHz PCM) and gets back a
//! watermarked `Vec<f32>` of the same length.
//!
//! License-policy note: the silentcipher encoder ONNX is exported
//! from Sony's MIT-licensed model at build time (see
//! `scripts/export-silentcipher-encoder.py`). License survey is in
//! `WATERMARK_LICENSE_POLICY.md`.

use std::sync::OnceLock;

#[cfg(not(feature = "cuda"))]
use tract_onnx::prelude::*;

use crate::hparams::{FREQ_BINS, MESSAGE_DIM, MESSAGE_LEN, N_FFT, VCTK_AVG_ENERGY, WIN};
use crate::model::CHUNK_T_FRAMES;
use crate::stft::{
    IstftStreamer, Spectrum, compute_n_frames, forward_stft_chunk,
    spectrum_to_waveform, streaming_utterance_norm, waveform_to_spectrum,
};

// v0.7 phase 8a: silentcipher encoder ONNX migrated from
// include_bytes!() to the provcheck-weights DLC pattern. First
// embed() lazily pulls from the public mirror's weights-v1
// release; subsequent calls hit the cache. Kit binary drops by
// ~2.1 MB.

/// `Encoder.linear` weights — shape `(MESSAGE_BAND_SIZE=1024, MESSAGE_DIM=5)`,
/// row-major as PyTorch dumps them. Used by [`transform_message`] to project
/// the 5-channel one-hot message tensor up to 1024 frequency bins; the
/// remaining 1025 bins are zero-padded. tract 0.21 can't analyse the
/// torch.nn.functional.pad node, so we do this step in Rust and ship the
/// weights as a separate binary blob.
const TRANSFORM_MESSAGE_WEIGHTS: &[u8] =
    include_bytes!("../models/silentcipher-encoder.transform_message.weights.bin");

/// `Encoder.linear` bias — shape `(MESSAGE_BAND_SIZE=1024,)`.
const TRANSFORM_MESSAGE_BIAS: &[u8] =
    include_bytes!("../models/silentcipher-encoder.transform_message.bias.bin");

/// Number of frequency bins the message gets projected into via the
/// encoder's linear layer before being zero-padded to `FREQ_BINS`.
const MESSAGE_BAND_SIZE: usize = 1024;

/// Default message SDR in dB. The silentcipher 44.1k checkpoint
/// trained at 47 dB (per `hparams.yaml`), which optimises for
/// inaudibility but does not survive lossy delivery codecs.
/// v0.5.2 lowers the default to 30 dB after the codec-survival
/// sweep in `docs/v0.5.2-codec-survival/` showed 30 dB retains
/// libmp3lame 192k detection at conf 0.95+ while still being
/// imperceptible on real-world content. Pass `--sdr-db 47` on
/// the CLI to restore v0.5.1 behaviour. Higher = quieter
/// watermark. AAC delivery is not survivable at any SDR; use
/// AudioSeal for AAC pipelines.
pub const DEFAULT_MESSAGE_SDR_DB: f32 = 30.0;

#[cfg(not(feature = "cuda"))]
type Runnable = TypedRunnableModel<TypedModel>;

/// v0.6.0 P4: CUDA backend via ort (onnxruntime-rs). Same ONNX
/// file; the session pins the CUDA execution provider so the
/// encoder runs on GPU when one is available, with a documented
/// fall-back to CPU EP otherwise. Wrapped in a `Mutex` because
/// `ort::Session::run` requires `&mut self`; CUDA serialises
/// inference on the single stream anyway so this does not give
/// up parallelism, it just makes the borrow-checker honest.
#[cfg(feature = "cuda")]
type Runnable = std::sync::Mutex<ort::session::Session>;

#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    #[error("encoder model load failed: {0}")]
    Load(String),
    #[error("encoder inference failed: {0}")]
    Inference(String),
    #[error("STFT failed: {0}")]
    Stft(#[from] crate::stft::StftError),
    #[error("input waveform is too short to embed (need at least one full window)")]
    TooShort,
    /// Caller passed mismatched left/right channel lengths to a
    /// stereo embed entry point. Distinct from `Inference` so
    /// callers can tell user-input bugs apart from model-internal
    /// failures. Added in the v0.9.0 audit pass.
    #[error("stereo embed: left ({left} samples) and right ({right} samples) have different lengths")]
    StereoLengthMismatch { left: usize, right: usize },
}

/// Embed configuration knobs threaded through the encode pipeline.
/// All fields are optional; `None` keeps the v0.6.0 P1 default
/// behaviour. v0.6.0 P3 phase 3d adds `max_parallel_chunks` so
/// memory-constrained operators can cap concurrent chunks below
/// the P1 detect-side cap of `min(cores/2, 4)`. Setting it to
/// `Some(1)` is the canonical "low memory" mode, peaking at one
/// tract intermediate buffer (~1.5 GB) instead of up to four.
#[derive(Debug, Default, Clone, Copy)]
pub struct EmbedConfig {
    /// Override the embed-side chunk parallelism cap. `None` uses
    /// the same auto-cap as the detect path. `Some(1)` forces
    /// sequential chunk processing (the v0.5.4 behaviour); higher
    /// values widen the rayon fan-out up to the chunk count.
    pub max_parallel_chunks: Option<usize>,
}

/// Embed a 5-byte payload into a mono 44.1 kHz f32 waveform.
///
/// Returns a watermarked waveform of the same length as the input.
///
/// The payload format is the same 5-byte tagged-union the detector
/// recovers: typically `[ASCII brand triplet, schema=1, reserved=0]`,
/// e.g. `[b'D', b'F', b'M', 0x01, 0x00]` for doomscroll.fm.
///
/// `message_sdr_db` controls the watermark's audibility ceiling.
/// Pass `None` for the model's training default (47 dB). Higher
/// values produce a quieter (more imperceptible) but more easily
/// damaged mark; lower values are more robust against compression.
pub fn embed(
    waveform: &[f32],
    payload: [u8; 5],
    message_sdr_db: Option<f32>,
) -> Result<Vec<f32>, EncodeError> {
    embed_with_config(waveform, payload, message_sdr_db, EmbedConfig::default())
}

/// Embed with explicit [`EmbedConfig`]. v0.6.0 P3 phase 3d entry.
/// Existing callers should keep using [`embed`]; pass an explicit
/// config only when overriding chunk parallelism for memory.
pub fn embed_with_config(
    waveform: &[f32],
    payload: [u8; 5],
    message_sdr_db: Option<f32>,
    config: EmbedConfig,
) -> Result<Vec<f32>, EncodeError> {
    if waveform.is_empty() {
        return Err(EncodeError::TooShort);
    }

    // 1. VCTK rescale. Remember the original power so we can de-rescale
    //    the watermarked output to the input's loudness.
    let original_power: f32 = waveform.iter().map(|s| s * s).sum::<f32>() / waveform.len() as f32;
    let rescale = if original_power > f32::EPSILON {
        (VCTK_AVG_ENERGY / original_power).sqrt()
    } else {
        1.0
    };
    let rescaled: Vec<f32> = waveform.iter().map(|s| s * rescale).collect();

    // 2. Forward STFT. Drop `rescaled` here so its `n_samples` worth of
    //    memory (~596 MB on a 56-minute mp3 at 44.1 kHz) doesn't sit
    //    next to the spectrogram during the chunk loop. The STFT keeps
    //    everything it needs in `spec`.
    let spec = waveform_to_spectrum(&rescaled)?;
    drop(rescaled);
    let n_frames = spec.n_frames;

    // 3. Message symbol stream — the small `[MESSAGE_DIM, n_frames]`
    //    one-hot tensor that gets projected up to `[FREQ_BINS, n_frames]`
    //    by `transform_message`. We do NOT precompute the projected
    //    full grid here; that was a ~595 MB allocation that scaled
    //    linearly with input length and was the dominant cause of the
    //    v0.3.8 embed-side OOM on multi-minute MP3s (public issue #17,
    //    fixed in v0.5.1). The projection lives inside the chunk loop
    //    instead, producing only `[FREQ_BINS, chunk_t]` per iteration.
    let msg_enc_5 = letters_encoding(payload, n_frames);

    // 4. Utterance-level normalisation scalar: sqrt(mean(carrier²))
    //    over the full magnitude grid. silentcipher applies this AFTER
    //    the dec_c output, so it must be computed from the full pre-
    //    inference carrier and applied to chunked outputs.
    let utterance_norm: f32 = {
        let mean_sq: f32 = spec.magnitude.iter().map(|m| m * m).sum::<f32>()
            / (FREQ_BINS as f32 * n_frames as f32);
        mean_sq.sqrt()
    };

    let sdr = message_sdr_db.unwrap_or(DEFAULT_MESSAGE_SDR_DB);

    // 5. Chunked ONNX inference, then post-process per chunk into the
    //    `carrier_reconst` buffer (magnitude after watermark embed).
    //    `transform_message_chunk` runs inline so the message projection
    //    never exists as a full-length tensor; only `chunk_t` columns
    //    of it are materialised at any time.
    //
    //    v0.6.0 P1: batches of up to `parallel_batch` chunks run
    //    concurrently via rayon. Each thread independently extracts
    //    its slice of the spectrogram, runs tract, and post-processes
    //    into a chunk-local buffer; the scatter into `carrier_reconst`
    //    happens sequentially after each batch because chunks within
    //    a batch are disjoint in time. Mirrors the detector's
    //    PARALLEL_BATCH pattern in `crates/provcheck-watermark/src/lib.rs`
    //    (`detect_chunked`). Empirical cap of 4 keeps peak memory
    //    bounded — each chunk peaks around 1.5 GB of tract intermediates,
    //    so 4-wide is safe on a 16 GB host and the doomscroll
    //    16 GB container we observed.
    use rayon::prelude::*;

    let auto_batch: usize = std::thread::available_parallelism()
        .map(|n| (n.get() / 2).clamp(1, 4))
        .unwrap_or(2);
    let parallel_batch: usize = config.max_parallel_chunks.unwrap_or(auto_batch).max(1);

    let model = model()?;
    let mut carrier_reconst = vec![0.0_f32; FREQ_BINS * n_frames];
    let mut t_consumed: usize = 0;

    while t_consumed < n_frames {
        // Build this batch's chunk offsets + sizes.
        let mut batch: Vec<(usize, usize)> = Vec::with_capacity(parallel_batch);
        let mut t_cursor = t_consumed;
        for _ in 0..parallel_batch {
            if t_cursor >= n_frames {
                break;
            }
            let chunk_t = (n_frames - t_cursor).min(CHUNK_T_FRAMES);
            batch.push((t_cursor, chunk_t));
            t_cursor += chunk_t;
        }

        // Run encoder + post-process in parallel. Each thread produces
        // a `[FREQ_BINS, chunk_t]` chunk-local buffer of reconst values
        // (laid out as `bin * chunk_t + t`). tract's runnable model is
        // `Send + Sync` behind `&`, so rayon can hand the same
        // OnceLock-cached model to every worker without contention on
        // its own state.
        let processed: Result<Vec<(usize, usize, Vec<f32>)>, EncodeError> = batch
            .par_iter()
            .map(|&(t_start, chunk_t)| {
                let carrier_chunk =
                    extract_carrier_chunk(&spec.magnitude, n_frames, t_start, chunk_t);
                let msg_chunk =
                    transform_message_chunk(&msg_enc_5, n_frames, t_start, chunk_t);
                let info_raw =
                    run_encoder_chunk(model, &carrier_chunk, &msg_chunk, sdr, chunk_t)?;

                let mut chunk_reconst = vec![0.0_f32; FREQ_BINS * chunk_t];
                for bin in 0..FREQ_BINS {
                    for t in 0..chunk_t {
                        let info = info_raw[bin * chunk_t + t] * utterance_norm;
                        // ensure_negative_message + relu(+ carrier).
                        let candidate = -info + carrier_chunk[bin * chunk_t + t];
                        chunk_reconst[bin * chunk_t + t] =
                            if candidate > 0.0 { candidate } else { 0.0 };
                    }
                }
                Ok((t_start, chunk_t, chunk_reconst))
            })
            .collect();
        let chunks = processed?;

        // Scatter every chunk in this batch into carrier_reconst.
        // Chunks within a batch are guaranteed non-overlapping by
        // construction (cursor advances by chunk_t each iteration).
        for (t_start, chunk_t, chunk_reconst) in chunks {
            for bin in 0..FREQ_BINS {
                let src_off = bin * chunk_t;
                let dst_off = bin * n_frames + t_start;
                carrier_reconst[dst_off..dst_off + chunk_t]
                    .copy_from_slice(&chunk_reconst[src_off..src_off + chunk_t]);
            }
            t_consumed = t_consumed.max(t_start + chunk_t);
        }
    }

    // 6. Inverse STFT — magnitude from carrier_reconst, phase from
    //    the original spectrum.
    let modified_spec = Spectrum {
        magnitude: carrier_reconst,
        phase: spec.phase,
        n_frames,
        n_samples_input: spec.n_samples_input,
    };
    let mut rescaled_out = spectrum_to_waveform(&modified_spec)?;

    // The iSTFT returns the tail-padded length. Trim back to the
    // caller's original length before de-rescaling.
    rescaled_out.truncate(waveform.len());

    // 7. De-rescale by undoing the VCTK rescale.
    let de_rescale = if original_power > f32::EPSILON {
        (original_power / VCTK_AVG_ENERGY).sqrt()
    } else {
        1.0
    };
    for s in rescaled_out.iter_mut() {
        *s *= de_rescale;
    }

    Ok(rescaled_out)
}

/// Chunk-fused streaming embed. Same semantics as [`embed_with_config`]
/// but the spectrogram is NEVER materialised in full: a two-pass
/// streaming design computes the global `utterance_norm` in pass 1
/// then processes one chunk at a time in pass 2, feeding each chunk's
/// reconstructed magnitude + phase frames directly into the streaming
/// iSTFT.
///
/// v0.6.0 P3 phase 3-fusion. Trades:
/// - ~10-20% extra wall clock (pass 1 + repeated forward STFTs per
///   chunk), in exchange for
/// - drops `spec.magnitude` (~600 MB on a 56-min episode),
/// - drops `spec.phase` (~600 MB),
/// - drops `carrier_reconst` (~600 MB),
/// - drops the full `rescaled_out` buffer in 3c (not yet).
///
/// Internally sequential — no chunk parallelism — so the
/// [`EmbedConfig`] `max_parallel_chunks` field is ignored. Use this
/// path when peak host RAM matters more than wall clock; use
/// [`embed_with_config`] when wall clock matters more.
/// Streaming variant of [`embed_with_config`]. NOTE: the
/// `EmbedConfig` parameter is currently ignored — the streaming
/// path's chunk-by-chunk shape makes the existing config knobs
/// (e.g. `max_parallel_chunks`) inapplicable. Future config knobs
/// specific to streaming (chunk size, ring-buffer depth) will
/// land here. Documented per v0.9.0 audit §3.
pub fn embed_streaming_with_config(
    waveform: &[f32],
    payload: [u8; 5],
    message_sdr_db: Option<f32>,
    _config: EmbedConfig,
) -> Result<Vec<f32>, EncodeError> {
    if waveform.is_empty() {
        return Err(EncodeError::TooShort);
    }
    // 1. VCTK rescale (identical to the materialised path).
    let original_power: f32 = waveform.iter().map(|s| s * s).sum::<f32>() / waveform.len() as f32;
    let rescale = if original_power > f32::EPSILON {
        (VCTK_AVG_ENERGY / original_power).sqrt()
    } else {
        1.0
    };
    let rescaled: Vec<f32> = waveform.iter().map(|s| s * rescale).collect();

    // 2. Derive padded-space dimensions without materialising the
    //    spectrum.
    let n_samples_input = rescaled.len() + (WIN - (rescaled.len() % WIN));
    let pad = N_FFT / 2;
    let padded_len = n_samples_input + 2 * pad;
    let n_frames = compute_n_frames(padded_len);
    if n_frames == 0 {
        return Err(EncodeError::TooShort);
    }

    // 3. Pass 1: streaming utterance_norm.
    let utterance_norm = streaming_utterance_norm(&rescaled)
        .map_err(|e| EncodeError::Inference(format!("streaming utterance_norm: {e}")))?;

    let msg_enc_5 = letters_encoding(payload, n_frames);
    let sdr = message_sdr_db.unwrap_or(DEFAULT_MESSAGE_SDR_DB);
    let model = model()?;

    // 4. Pass 2: chunk-fused embed + streaming iSTFT.
    let mut istft = IstftStreamer::new(n_frames, n_samples_input)
        .map_err(|e| EncodeError::Inference(format!("istft streamer: {e}")))?;
    let mut mag_frame = vec![0.0_f32; FREQ_BINS];
    let mut phase_frame = vec![0.0_f32; FREQ_BINS];
    let mut t_consumed: usize = 0;
    while t_consumed < n_frames {
        let chunk_t = (n_frames - t_consumed).min(CHUNK_T_FRAMES);
        let (carrier_chunk, phase_chunk) =
            forward_stft_chunk(&rescaled, n_samples_input, t_consumed, chunk_t)
                .map_err(|e| EncodeError::Inference(format!("forward_stft_chunk: {e}")))?;
        let msg_chunk = transform_message_chunk(&msg_enc_5, n_frames, t_consumed, chunk_t);
        let info_raw = run_encoder_chunk(model, &carrier_chunk, &msg_chunk, sdr, chunk_t)?;

        for t_local in 0..chunk_t {
            for bin in 0..FREQ_BINS {
                let info = info_raw[bin * chunk_t + t_local] * utterance_norm;
                let candidate = -info + carrier_chunk[bin * chunk_t + t_local];
                mag_frame[bin] = if candidate > 0.0 { candidate } else { 0.0 };
                phase_frame[bin] = phase_chunk[bin * chunk_t + t_local];
            }
            istft.push_frame(&mag_frame, &phase_frame);
        }
        t_consumed += chunk_t;
    }
    let mut rescaled_out = istft.finish();

    // 5. Trim + de-rescale (identical to the materialised path).
    rescaled_out.truncate(waveform.len());
    let de_rescale = if original_power > f32::EPSILON {
        (original_power / VCTK_AVG_ENERGY).sqrt()
    } else {
        1.0
    };
    for s in rescaled_out.iter_mut() {
        *s *= de_rescale;
    }
    Ok(rescaled_out)
}

/// Embed the same payload into both channels of a stereo signal.
///
/// silentcipher's encoder is mono-only by training-time
/// architecture; we orchestrate two independent embeds (L and R
/// with the same payload and SDR) so the resulting stereo file
/// detects on either single channel and on the mono downmix.
/// Returns `(marked_left, marked_right)`, each the same length as
/// the matching input channel. Errors if the two input channels
/// have different lengths.
pub fn embed_stereo(
    left: &[f32],
    right: &[f32],
    payload: [u8; 5],
    message_sdr_db: Option<f32>,
) -> Result<(Vec<f32>, Vec<f32>), EncodeError> {
    embed_stereo_with_config(left, right, payload, message_sdr_db, EmbedConfig::default())
}

/// Stereo embed with explicit [`EmbedConfig`]. Runs the two
/// per-channel mono embeds sequentially, threading the same config
/// through both. v0.6.0 P3 phase 3d entry.
pub fn embed_stereo_with_config(
    left: &[f32],
    right: &[f32],
    payload: [u8; 5],
    message_sdr_db: Option<f32>,
    config: EmbedConfig,
) -> Result<(Vec<f32>, Vec<f32>), EncodeError> {
    if left.len() != right.len() {
        return Err(EncodeError::StereoLengthMismatch {
            left: left.len(),
            right: right.len(),
        });
    }
    let l = embed_with_config(left, payload, message_sdr_db, config)?;
    let r = embed_with_config(right, payload, message_sdr_db, config)?;
    Ok((l, r))
}

/// Embed and self-test in one call: returns the marked waveform
/// AND the detector's confidence + payload-recovery verdict
/// against that very output.
///
/// Mirrors the kit's `--verify-after-embed` flag at the library
/// level so external Rust callers can opt into the same safety
/// guarantee without re-implementing the temp-file dance or the
/// threshold logic. No disk I/O happens — detection runs against
/// the in-memory marked waveform via
/// `crate::detect_from_mono_44k1`.
///
/// The returned [`provcheck::prelude::WatermarkResult`] carries
/// the confidence, the recovered payload (if any), the brand, and
/// the [`provcheck::prelude::WatermarkStatus`] tier
/// (Detected / Degraded / NotDetected). Threshold semantics live in
/// `provcheck::confidence` so callers can choose to fail the
/// pipeline on `< Detected` or accept `Degraded` etc.
///
/// v0.7 phase 7-pre audit #5.
pub fn embed_and_verify(
    waveform: &[f32],
    payload: [u8; 5],
    message_sdr_db: Option<f32>,
) -> Result<(Vec<f32>, provcheck::prelude::WatermarkResult), EncodeError> {
    let marked = embed(waveform, payload, message_sdr_db)?;
    let result = crate::detect_from_mono_44k1(&marked)
        .map_err(|e| EncodeError::Inference(format!("verify after embed: {e}")))?;
    Ok((marked, result))
}

#[cfg(test)]
mod embed_and_verify_tests {
    use super::*;

    #[test]
    fn empty_waveform_surfaces_too_short() {
        // Without weights installed we can't run the full embed,
        // but the TooShort guard fires BEFORE any model load, so
        // this test exercises the early-return path safely.
        let r = embed_and_verify(&[], [0u8; 5], None);
        assert!(matches!(r, Err(EncodeError::TooShort)));
    }

}

/// Build the message tensor that the encoder ONNX expects.
///
/// silentcipher's letters_encoding (model.py:62-81) takes a list of
/// 20 2-bit symbols (`binary_encode`d from the 5-byte payload), adds
/// 1 to put them in {1,2,3,4}, appends a terminator (0) to make 21,
/// and tiles that 21-symbol cycle across the full t_frames axis as
/// one-hot 5-vectors.
///
/// Output layout matches the ONNX input shape `[1, 1, 5, T]`,
/// flattened row-major as `[dim * T + t]` (the leading singleton
/// axes collapse).
pub fn letters_encoding(payload: [u8; 5], t_frames: usize) -> Vec<f32> {
    // 1. payload (5 bytes) → 20 2-bit symbols, MSB first.
    let mut symbols = [0u8; MESSAGE_LEN];
    for (byte_idx, byte) in payload.iter().enumerate() {
        for bit_pair in 0..4 {
            let shift = 6 - 2 * bit_pair;
            let sym = (byte >> shift) & 0b11;
            // +1 offset puts payload symbols in {1,2,3,4}; 0 is
            // reserved for the terminator at position 20.
            symbols[byte_idx * 4 + bit_pair] = sym + 1;
        }
    }
    symbols[MESSAGE_LEN - 1] = 0; // terminator

    // 2. One-hot encode + tile across time.
    let mut out = vec![0.0_f32; MESSAGE_DIM * t_frames];
    for t in 0..t_frames {
        let pos = t % MESSAGE_LEN;
        let sym = symbols[pos] as usize;
        out[sym * t_frames + t] = 1.0;
    }
    out
}

/// Extract a time-axis chunk from a `[FREQ_BINS, T]` row-major tensor.
fn extract_carrier_chunk(
    carrier: &[f32],
    t_frames: usize,
    t_start: usize,
    chunk_t: usize,
) -> Vec<f32> {
    let mut chunk = vec![0.0_f32; FREQ_BINS * chunk_t];
    for bin in 0..FREQ_BINS {
        let src_off = bin * t_frames + t_start;
        let dst_off = bin * chunk_t;
        chunk[dst_off..dst_off + chunk_t].copy_from_slice(&carrier[src_off..src_off + chunk_t]);
    }
    chunk
}

/// Project a chunk of the `[MESSAGE_DIM, n_frames]` one-hot message
/// tensor up to `[FREQ_BINS, chunk_t]`, applying the encoder's linear
/// layer plus zero-pad. Mirrors `silentcipher.model.Encoder.transform_message`
/// (model.py:36-40):
///
/// ```python
/// output = self.linear(msg.transpose(2, 3)).transpose(2, 3)
/// output = F.pad(output, (0, 0, 0, FREQ_BINS - MESSAGE_BAND_SIZE))
/// ```
///
/// The linear is `nn.Linear(MESSAGE_DIM=5, MESSAGE_BAND_SIZE=1024)`, so
/// weight is shape `(1024, 5)` and bias is shape `(1024,)`.
///
/// `msg_enc` is the full `[MESSAGE_DIM, n_frames]` tensor (small;
/// 5 * n_frames f32). The output covers only the time-window
/// `[t_start, t_start + chunk_t)` so callers can chunk the encoder
/// inference without ever materialising a full-length projected
/// tensor (`FREQ_BINS * n_frames` would be ~600 MB on a 56-minute
/// MP3, which is what blew up the v0.3.8 embed path).
fn transform_message_chunk(
    msg_enc: &[f32],
    n_frames: usize,
    t_start: usize,
    chunk_t: usize,
) -> Vec<f32> {
    debug_assert_eq!(msg_enc.len(), MESSAGE_DIM * n_frames);
    debug_assert!(t_start + chunk_t <= n_frames);

    // Decode the embedded weight + bias. PyTorch stores `Linear` weight
    // as `(out, in)` row-major: `weight[k, d] = bytes[(k * MESSAGE_DIM + d) * 4..]`.
    let weight: &[f32] = bytemuck_cast_f32(TRANSFORM_MESSAGE_WEIGHTS);
    let bias: &[f32] = bytemuck_cast_f32(TRANSFORM_MESSAGE_BIAS);
    debug_assert_eq!(weight.len(), MESSAGE_BAND_SIZE * MESSAGE_DIM);
    debug_assert_eq!(bias.len(), MESSAGE_BAND_SIZE);

    // Output layout matches the carrier chunk: row-major `[bin, t]`
    // flattened as `bin * chunk_t + t`, where `t` runs `0..chunk_t`.
    // Bins `MESSAGE_BAND_SIZE..FREQ_BINS` stay at zero (the F.pad).
    let mut padded = vec![0.0_f32; FREQ_BINS * chunk_t];
    for t_local in 0..chunk_t {
        let t = t_start + t_local;
        for k in 0..MESSAGE_BAND_SIZE {
            // sum_d weight[k, d] * msg_enc[d, t] + bias[k]
            let mut acc = bias[k];
            for d in 0..MESSAGE_DIM {
                acc += weight[k * MESSAGE_DIM + d] * msg_enc[d * n_frames + t];
            }
            padded[k * chunk_t + t_local] = acc;
        }
    }
    padded
}

/// Reinterpret a byte slice as an f32 slice without copying. Used to
/// access the embedded weight/bias blobs as native arrays.
fn bytemuck_cast_f32(bytes: &[u8]) -> &[f32] {
    debug_assert_eq!(
        bytes.len() % 4,
        0,
        "byte slice must be 4-byte aligned in length"
    );
    debug_assert_eq!(
        (bytes.as_ptr() as usize) % std::mem::align_of::<f32>(),
        0,
        "byte slice must be 4-byte aligned"
    );
    // SAFETY: the blob is a sequence of little-endian f32 values produced
    // by numpy.ndarray.tobytes() on a contiguous float32 array. Length is
    // a multiple of 4 (checked above) and the pointer alignment is checked
    // above. On the supported targets (x86_64 + aarch64) f32 has alignment
    // 4 so the static `include_bytes!` buffer satisfies the alignment.
    unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const f32, bytes.len() / 4) }
}

/// Single tract inference call against the encoder ONNX. Returns
/// the raw dec_c output `[1, 1, FREQ_BINS, chunk_t]` flattened as
/// `[bin * chunk_t + t]`.
#[cfg(not(feature = "cuda"))]
fn run_encoder_chunk(
    model: &Runnable,
    carrier: &[f32],
    msg_enc: &[f32],
    sdr_db: f32,
    chunk_t: usize,
) -> Result<Vec<f32>, EncodeError> {
    let carrier_tensor =
        tract_ndarray::Array4::from_shape_vec((1, 1, FREQ_BINS, chunk_t), carrier.to_vec())
            .map_err(|e| EncodeError::Inference(format!("carrier shape: {e}")))?;
    // msg_enc is already in `[FREQ_BINS, chunk_t]` layout — it's the
    // output of transform_message (linear 5→1024 + zero-pad to 2049).
    let msg_tensor =
        tract_ndarray::Array4::from_shape_vec((1, 1, FREQ_BINS, chunk_t), msg_enc.to_vec())
            .map_err(|e| EncodeError::Inference(format!("msg_enc shape: {e}")))?;
    let sdr_tensor = tract_ndarray::arr0(sdr_db);

    let inputs = tvec!(
        carrier_tensor.into_tvalue(),
        msg_tensor.into_tvalue(),
        sdr_tensor.into_tvalue(),
    );
    let outputs = model
        .run(inputs)
        .map_err(|e: TractError| EncodeError::Inference(e.to_string()))?;
    let out = outputs
        .into_iter()
        .next()
        .ok_or_else(|| EncodeError::Inference("model returned no outputs".into()))?;

    let shape: Vec<usize> = out.shape().to_vec();
    let layout_ok = matches!(
        &shape[..],
        [1, 1, b, t] if *b == FREQ_BINS && *t == chunk_t
    );
    if !layout_ok {
        return Err(EncodeError::Inference(format!(
            "expected [1, 1, {FREQ_BINS}, {chunk_t}], got {shape:?}"
        )));
    }
    let view = out
        .to_array_view::<f32>()
        .map_err(|e: TractError| EncodeError::Inference(e.to_string()))?;
    Ok(view.iter().copied().collect())
}

/// CUDA encoder inference via ort. Same input shapes as the tract
/// path; same output shape. The execution provider is fixed to
/// CUDA at session-build time (with CPU EP as the documented
/// fallback). Built behind `--features cuda`.
#[cfg(feature = "cuda")]
fn run_encoder_chunk(
    model: &Runnable,
    carrier: &[f32],
    msg_enc: &[f32],
    sdr_db: f32,
    chunk_t: usize,
) -> Result<Vec<f32>, EncodeError> {
    use ndarray::Array4;
    let carrier_arr = Array4::<f32>::from_shape_vec((1, 1, FREQ_BINS, chunk_t), carrier.to_vec())
        .map_err(|e| EncodeError::Inference(format!("carrier shape: {e}")))?;
    let msg_arr = Array4::<f32>::from_shape_vec((1, 1, FREQ_BINS, chunk_t), msg_enc.to_vec())
        .map_err(|e| EncodeError::Inference(format!("msg_enc shape: {e}")))?;
    let sdr_arr = ndarray::Array0::<f32>::from_elem((), sdr_db);

    let mut model = model.lock().map_err(|e| EncodeError::Inference(format!("ort session mutex poisoned: {e}")))?;
    let outputs = model
        .run(ort::inputs![
            "carrier_mag" => ort::value::TensorRef::from_array_view(carrier_arr.view()).map_err(|e| EncodeError::Inference(e.to_string()))?,
            "msg_enc_padded" => ort::value::TensorRef::from_array_view(msg_arr.view()).map_err(|e| EncodeError::Inference(e.to_string()))?,
            "message_sdr" => ort::value::TensorRef::from_array_view(sdr_arr.view()).map_err(|e| EncodeError::Inference(e.to_string()))?,
        ])
        .map_err(|e| EncodeError::Inference(e.to_string()))?;

    let out = outputs
        .get("message_info_raw")
        .ok_or_else(|| EncodeError::Inference("message_info_raw output missing".into()))?;
    let (shape, data) = out
        .try_extract_tensor::<f32>()
        .map_err(|e| EncodeError::Inference(e.to_string()))?;
    let shape_usize: Vec<usize> = shape.iter().map(|d| *d as usize).collect();
    let layout_ok = matches!(
        &shape_usize[..],
        [1, 1, b, t] if *b == FREQ_BINS && *t == chunk_t
    );
    if !layout_ok {
        return Err(EncodeError::Inference(format!(
            "expected [1, 1, {FREQ_BINS}, {chunk_t}], got {shape_usize:?}"
        )));
    }
    Ok(data.to_vec())
}

/// Build the runnable encoder ONNX model once and reuse for every
/// call. Same OnceLock pattern as the decoder model.
fn model() -> Result<&'static Runnable, EncodeError> {
    static MODEL: OnceLock<Runnable> = OnceLock::new();
    if let Some(m) = MODEL.get() {
        return Ok(m);
    }
    let m = build_model().map_err(EncodeError::Load)?;
    let _ = MODEL.set(m);
    Ok(MODEL.get().expect("just set"))
}

#[cfg(not(feature = "cuda"))]
fn build_model() -> Result<Runnable, String> {
    let path = provcheck_weights::load_if_cached("silentcipher", "encoder")
        .map_err(|e| format!("weights: {e}"))?;
    let file = std::fs::File::open(&path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    let model = tract_onnx::onnx()
        .model_for_read(&mut reader)
        .and_then(|m| m.into_optimized())
        .and_then(|m| m.into_runnable())
        .map_err(|e| e.to_string())?;
    Ok(model)
}

/// CUDA-backed encoder session. Loads ONNX once, pins CUDA EP at
/// session-build time. If the CUDA EP is not available on the
/// host (driver missing, runtime libs not installed) ort falls
/// back to CPU EP automatically — slower but functional. Document
/// the CUDA install path in `docs/v0.6.0-roadmap/p4-ort-cuda-backend-design.md`.
#[cfg(feature = "cuda")]
fn build_model() -> Result<Runnable, String> {
    use ort::execution_providers::CUDAExecutionProvider;
    use ort::session::Session;
    use ort::session::builder::GraphOptimizationLevel;
    let path = provcheck_weights::load_if_cached("silentcipher", "encoder")
        .map_err(|e| format!("weights: {e}"))?;
    // v0.7.x followup for public issue #32: `error_on_failure` flips
    // ort's CUDA EP from "silently fall back to CPU if the runtime
    // is missing" to "fail loudly", so we can surface a useful
    // diagnostic to the operator instead of letting them wait the
    // full embed wall-clock on a CPU path they thought was GPU.
    let cuda_ep = CUDAExecutionProvider::default()
        .with_device_id(0)
        .build()
        .error_on_failure();
    let session = match Session::builder()
        .map_err(|e| e.to_string())?
        .with_optimization_level(GraphOptimizationLevel::Level3)
        .map_err(|e| e.to_string())?
        .with_execution_providers([cuda_ep])
    {
        Ok(b) => {
            eprintln!(
                "provcheck-watermark: CUDA execution provider active (device 0). \
                 Embed will use GPU."
            );
            b.commit_from_file(&path).map_err(|e| e.to_string())?
        }
        Err(e) => {
            eprintln!(
                "provcheck-watermark: WARNING — `--features cuda` was built in, \
                 but the CUDA execution provider could not initialise: {e}. \
                 Falling back to CPU. Verify onnxruntime-gpu + CUDA 12.x + \
                 cuDNN are installed on this host; see \
                 docs/v0.6.0-roadmap/p4-cuda-implementation-notes.md."
            );
            Session::builder()
                .map_err(|e| e.to_string())?
                .with_optimization_level(GraphOptimizationLevel::Level3)
                .map_err(|e| e.to_string())?
                .commit_from_file(&path)
                .map_err(|e| e.to_string())?
        }
    };
    Ok(std::sync::Mutex::new(session))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letters_encoding_for_dfm_payload_matches_expected_symbols() {
        // DFM payload: 0x44, 0x46, 0x4d, 0x01, 0x00
        // Bytes → 2-bit symbols MSB-first:
        //   0x44 = 01000100 → [1, 0, 1, 0]
        //   0x46 = 01000110 → [1, 0, 1, 2]
        //   0x4d = 01001101 → [1, 0, 3, 1]
        //   0x01 = 00000001 → [0, 0, 0, 1]
        //   0x00 = 00000000 → [0, 0, 0, 0]
        // +1 offset: [2,1,2,1, 2,1,2,3, 2,1,4,2, 1,1,1,2, 1,1,1,1]
        // Terminator at end: [..., 0]
        let payload = [0x44, 0x46, 0x4d, 0x01, 0x00];
        let t_frames = MESSAGE_LEN; // exactly one tile so positions map directly
        let out = letters_encoding(payload, t_frames);

        let expected_symbols: [u8; MESSAGE_LEN] = [
            2, 1, 2, 1, 2, 1, 2, 3, 2, 1, 4, 2, 1, 1, 1, 2, 1, 1, 1, 1, 0,
        ];
        for (t, sym) in expected_symbols.iter().enumerate() {
            // Confirm one-hot at the expected dimension.
            for dim in 0..MESSAGE_DIM {
                let v = out[dim * t_frames + t];
                if dim == *sym as usize {
                    assert_eq!(v, 1.0, "expected 1 at dim={dim}, t={t}");
                } else {
                    assert_eq!(v, 0.0, "expected 0 at dim={dim}, t={t}");
                }
            }
        }
    }

    #[test]
    fn letters_encoding_output_size_matches_message_dim_times_t_frames() {
        // Wire-format invariant: output is exactly MESSAGE_DIM * T
        // f32s. ONNX session.run rejects mismatched input lengths.
        for t in [1, MESSAGE_LEN, 50, 100, 1000] {
            let out = letters_encoding([0u8; 5], t);
            assert_eq!(
                out.len(),
                MESSAGE_DIM * t,
                "t_frames={t} produced wrong-length output"
            );
        }
    }

    #[test]
    fn letters_encoding_is_one_hot_per_time_slot() {
        // Each time slot must have EXACTLY one 1.0 value across
        // the MESSAGE_DIM channels — that's what "one-hot" means.
        // Without this invariant the encoder's message tensor is
        // structurally invalid.
        let payload = [0x44, 0x46, 0x4d, 0x01, 0x00];
        let t_frames = 100;
        let out = letters_encoding(payload, t_frames);
        for t in 0..t_frames {
            let mut count = 0;
            for dim in 0..MESSAGE_DIM {
                if out[dim * t_frames + t] == 1.0 {
                    count += 1;
                } else {
                    assert_eq!(
                        out[dim * t_frames + t],
                        0.0,
                        "non-binary value at dim={dim} t={t}"
                    );
                }
            }
            assert_eq!(count, 1, "expected 1-hot at t={t}, got {count} hot");
        }
    }

    #[test]
    fn letters_encoding_terminator_at_position_20_is_dim_0() {
        // The terminator symbol is value 0, which lights up
        // dim 0 in the one-hot encoding.
        let payload = [0u8; 5];
        let out = letters_encoding(payload, MESSAGE_LEN);
        // Position 20 (terminator) — dim 0 should be hot.
        let t = MESSAGE_LEN - 1;
        // dim 0 at position t (terminator):
        assert_eq!(out[t], 1.0, "terminator dim mismatch");
        // All other dims at t=20 should be cold.
        for dim in 1..MESSAGE_DIM {
            assert_eq!(out[dim * MESSAGE_LEN + t], 0.0);
        }
    }

    #[test]
    fn letters_encoding_zero_payload_produces_all_dim_1_then_terminator() {
        // payload = 0x00 → bit pairs 00 → +1 = 1. All 20 payload
        // positions should be dim 1 hot.
        let payload = [0u8; 5];
        let out = letters_encoding(payload, MESSAGE_LEN);
        for t in 0..(MESSAGE_LEN - 1) {
            assert_eq!(
                out[MESSAGE_LEN + t],
                1.0,
                "expected dim 1 hot at t={t} for zero-payload"
            );
        }
    }

    #[test]
    fn letters_encoding_max_payload_produces_all_dim_4_then_terminator() {
        // payload = 0xFF → bit pairs 11 → +1 = 4. All 20 payload
        // positions should be dim 4 hot.
        let payload = [0xFFu8; 5];
        let out = letters_encoding(payload, MESSAGE_LEN);
        for t in 0..(MESSAGE_LEN - 1) {
            assert_eq!(
                out[4 * MESSAGE_LEN + t],
                1.0,
                "expected dim 4 hot at t={t} for 0xFF-payload"
            );
        }
    }

    #[test]
    fn letters_encoding_msb_first_per_byte() {
        // Byte 0x44 = 0b01000100. MSB-first 2-bit chunks:
        //   01, 00, 01, 00 → +1 → 2, 1, 2, 1.
        // So out[2*T+0]=1, out[1*T+1]=1, out[2*T+2]=1, out[1*T+3]=1.
        let payload = [0x44, 0, 0, 0, 0];
        let t = MESSAGE_LEN;
        let out = letters_encoding(payload, t);
        assert_eq!(out[2 * t], 1.0, "byte 0 pair 0: expected sym 2");
        assert_eq!(out[t + 1], 1.0, "byte 0 pair 1: expected sym 1");
        assert_eq!(out[2 * t + 2], 1.0, "byte 0 pair 2: expected sym 2");
        assert_eq!(out[t + 3], 1.0, "byte 0 pair 3: expected sym 1");
    }

    #[test]
    fn letters_encoding_short_t_frames_truncates_correctly() {
        // t_frames = 5 should cover the first 5 positions of the
        // 21-symbol cycle and nothing more. Output length must
        // be exactly MESSAGE_DIM * 5 regardless.
        let payload = [0u8; 5];
        let out = letters_encoding(payload, 5);
        assert_eq!(out.len(), MESSAGE_DIM * 5);
    }

    #[test]
    fn letters_encoding_tiles_across_longer_t_frames() {
        // With t_frames = 2*MESSAGE_LEN, position 0 should equal
        // position MESSAGE_LEN (start of second tile).
        let payload = [0x44, 0x46, 0x4d, 0x01, 0x00];
        let t_frames = 2 * MESSAGE_LEN;
        let out = letters_encoding(payload, t_frames);
        for dim in 0..MESSAGE_DIM {
            let a = out[dim * t_frames];
            let b = out[dim * t_frames + MESSAGE_LEN];
            assert_eq!(a, b, "tile-start mismatch at dim={dim}");
        }
    }

    /// Reference all-at-once projection. Used only in tests to verify
    /// `transform_message_chunk` produces identical numbers in chunked
    /// mode (the production code path).
    fn transform_message_full(msg_enc: &[f32], t_frames: usize) -> Vec<f32> {
        let weight: &[f32] = bytemuck_cast_f32(TRANSFORM_MESSAGE_WEIGHTS);
        let bias: &[f32] = bytemuck_cast_f32(TRANSFORM_MESSAGE_BIAS);
        let mut padded = vec![0.0_f32; FREQ_BINS * t_frames];
        for t in 0..t_frames {
            for k in 0..MESSAGE_BAND_SIZE {
                let mut acc = bias[k];
                for d in 0..MESSAGE_DIM {
                    acc += weight[k * MESSAGE_DIM + d] * msg_enc[d * t_frames + t];
                }
                padded[k * t_frames + t] = acc;
            }
        }
        padded
    }

    /// Chunked message projection must produce the same per-bin values
    /// as the all-at-once projection over the matching time window.
    /// Regression test for the v0.5.1 embed-OOM fix (public issue #17):
    /// if the per-chunk projection drifts from the original semantics,
    /// embedded watermarks would no longer round-trip through the
    /// detector.
    #[test]
    fn transform_message_chunk_matches_full_projection() {
        let payload = [0x44, 0x46, 0x4d, 0x01, 0x00];
        // Pick a t_frames that crosses several tile boundaries and is
        // not a multiple of an arbitrary chunk size.
        let n_frames = MESSAGE_LEN * 7 + 3;
        let msg_enc = letters_encoding(payload, n_frames);

        let full = transform_message_full(&msg_enc, n_frames);

        // Walk every reasonable chunk window and confirm the per-bin
        // values match. Cover the head, the tail (truncated final
        // chunk), and an interior window.
        for &(t_start, chunk_t) in &[
            (0_usize, 32_usize),
            (32, 32),
            (50, 17),
            (n_frames - 5, 5),
            (0, n_frames),
        ] {
            assert!(t_start + chunk_t <= n_frames, "test window out of range");
            let chunk = transform_message_chunk(&msg_enc, n_frames, t_start, chunk_t);
            for bin in 0..FREQ_BINS {
                for t_local in 0..chunk_t {
                    let from_chunk = chunk[bin * chunk_t + t_local];
                    let from_full = full[bin * n_frames + (t_start + t_local)];
                    let diff = (from_chunk - from_full).abs();
                    assert!(
                        diff < 1e-5,
                        "mismatch at bin={bin} t_local={t_local} t_start={t_start} chunk_t={chunk_t}: \
                         chunk={from_chunk} full={from_full} diff={diff}"
                    );
                }
            }
        }
    }
}
