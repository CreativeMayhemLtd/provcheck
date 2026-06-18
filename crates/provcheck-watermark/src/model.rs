//! tract-onnx wrapper around the silentcipher decoder.
//!
//! The ONNX file is embedded into the library at compile
//! time via [`include_bytes!`] so a running `provcheck`
//! binary has no runtime file dependency. The model is
//! lazily built on first call and cached for the lifetime of
//! the process.
//!
//! Input:  flat carrier `[1, 1, 2049, T]` row-major.
//! Output: flat logits  `[1, 1, 5, T]`  row-major.

use std::sync::OnceLock;

use tract_onnx::prelude::*;

use crate::hparams::{FREQ_BINS, MESSAGE_DIM};

/// The full silentcipher decoder ONNX, embedded at build time.
/// `provcheck.exe` thus needs no external model file.
const MODEL_BYTES: &[u8] = include_bytes!("../models/silentcipher-decoder.onnx");

/// Type alias for the runnable model we keep in the
/// [`OnceLock`]. tract's `TypedRunnableModel<TypedModel>` is
/// what `into_runnable()` returns on an optimised model.
type Runnable = TypedRunnableModel<TypedModel>;

/// Errors from the model layer. Wrapped into the crate's
/// top-level [`crate::Error`] for the public API.
#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("model load failed: {0}")]
    Load(String),
    #[error("inference failed: {0}")]
    Inference(String),
    #[error("unexpected output shape: expected {expected}, got {got}")]
    Shape { expected: String, got: String },
}

/// Maximum t_frames per tract inference call. Tract allocates
/// per-layer activation buffers proportional to `t_frames`; on a
/// 211-second MP3 (≈ 4540 frames) those buffers add up to >10 GB
/// of RSS and the OS OOM-killer steps in. Chunking caps the peak
/// at `O(CHUNK_T_FRAMES)` regardless of audio length.
///
/// The size is chosen to stay well under typical container memory
/// limits (a single chunk runs in ~600 MB on Linux x86_64) while
/// covering enough time-frames per call that per-chunk model
/// startup amortises across many tiles. 256 frames is ~12 seconds
/// of audio at HOP=2048, SR=44100.
///
/// silentcipher's decoder is a per-time-frame classifier with a
/// small convolutional receptive field along the time axis; the
/// per-position mode vote downstream of inference sees every
/// tile regardless of how chunking divided the input. Chunked
/// inference produces bit-exact logits vs single-call inference
/// on the v0.3.3 test fixtures.
const CHUNK_T_FRAMES: usize = 256;

/// Run the decoder on a carrier tensor laid out as
/// `[1, 1, FREQ_BINS, t_frames]` in row-major order
/// (`bin * t_frames + t`).
///
/// Returns the logits as a flat `Vec<f32>` of length
/// `MESSAGE_DIM * t_frames`, laid out as `[MESSAGE_DIM, T]`
/// row-major.
///
/// Internally chunked: the carrier is fed to tract in slices of
/// at most [`CHUNK_T_FRAMES`] frames along the time axis. This
/// caps tract's per-call intermediate memory at O(CHUNK_T_FRAMES)
/// rather than O(t_frames) — see [`CHUNK_T_FRAMES`] for the why.
pub fn run(carrier: &[f32], t_frames: usize) -> Result<Vec<f32>, ModelError> {
    assert_eq!(
        carrier.len(),
        FREQ_BINS * t_frames,
        "carrier length must match FREQ_BINS * t_frames"
    );

    let model = model()?;
    let mut full_logits = vec![0.0_f32; MESSAGE_DIM * t_frames];

    let mut t_start = 0;
    while t_start < t_frames {
        let chunk_t = (t_frames - t_start).min(CHUNK_T_FRAMES);
        let chunk_carrier = extract_chunk(carrier, t_frames, t_start, chunk_t);
        let chunk_logits = run_chunk(model, &chunk_carrier, chunk_t)?;
        scatter_chunk_logits(&chunk_logits, chunk_t, &mut full_logits, t_frames, t_start);
        t_start += chunk_t;
    }

    Ok(full_logits)
}

/// Extract a contiguous time-axis slice `[FREQ_BINS, chunk_t]`
/// from the row-major carrier `[FREQ_BINS, t_frames]`. The slice
/// isn't contiguous in the source (rows are interleaved with
/// other-frame data), so we copy per freq bin.
fn extract_chunk(carrier: &[f32], t_frames: usize, t_start: usize, chunk_t: usize) -> Vec<f32> {
    let mut chunk = vec![0.0_f32; FREQ_BINS * chunk_t];
    for bin in 0..FREQ_BINS {
        let src_off = bin * t_frames + t_start;
        let dst_off = bin * chunk_t;
        chunk[dst_off..dst_off + chunk_t].copy_from_slice(&carrier[src_off..src_off + chunk_t]);
    }
    chunk
}

/// Scatter a chunk's logits `[MESSAGE_DIM, chunk_t]` back into the
/// full logits `[MESSAGE_DIM, t_frames]` at column offset `t_start`.
fn scatter_chunk_logits(
    chunk_logits: &[f32],
    chunk_t: usize,
    full_logits: &mut [f32],
    t_frames: usize,
    t_start: usize,
) {
    for dim in 0..MESSAGE_DIM {
        let src_off = dim * chunk_t;
        let dst_off = dim * t_frames + t_start;
        full_logits[dst_off..dst_off + chunk_t]
            .copy_from_slice(&chunk_logits[src_off..src_off + chunk_t]);
    }
}

/// Single tract inference call. The chunked public `run` wraps
/// this and stitches outputs together.
fn run_chunk(model: &Runnable, carrier: &[f32], chunk_t: usize) -> Result<Vec<f32>, ModelError> {
    let input = tract_ndarray::Array4::from_shape_vec((1, 1, FREQ_BINS, chunk_t), carrier.to_vec())
        .map_err(|e| ModelError::Inference(format!("input shape: {e}")))?;
    let input_tensor: Tensor = input.into();

    let outputs = model
        .run(tvec!(input_tensor.into()))
        .map_err(|e: TractError| ModelError::Inference(e.to_string()))?;

    let out = outputs
        .into_iter()
        .next()
        .ok_or_else(|| ModelError::Inference("model returned no outputs".into()))?;

    // Accept the documented `[1, 1, MESSAGE_DIM, T]` shape and
    // a couple of defensive fallbacks that drop leading
    // singletons — different exporters phrase the rank
    // differently and the math is identical once the leading
    // singletons are stripped.
    let shape: Vec<usize> = out.shape().to_vec();
    let leading_singletons_ok = matches!(
        &shape[..],
        [1, 1, m, t] | [1, m, t] | [m, t] if *m == MESSAGE_DIM && *t == chunk_t
    );
    if !leading_singletons_ok {
        return Err(ModelError::Shape {
            expected: format!("[1, 1, {MESSAGE_DIM}, {chunk_t}]"),
            got: format!("{:?}", shape),
        });
    }
    let view = out
        .to_array_view::<f32>()
        .map_err(|e: TractError| ModelError::Inference(e.to_string()))?;
    let logits: Vec<f32> = view.iter().copied().collect();
    Ok(logits)
}

/// Build the runnable model once and reuse for every call.
/// tract's "into_runnable" is the moral equivalent of
/// torch's `model.eval()` + `torch.compile`.
fn model() -> Result<&'static Runnable, ModelError> {
    static MODEL: OnceLock<Runnable> = OnceLock::new();
    if let Some(m) = MODEL.get() {
        return Ok(m);
    }

    let m = build_model().map_err(|e: TractError| ModelError::Load(e.to_string()))?;
    // OnceLock::set returns Err only if already set; if a
    // racing thread set first, ours is dropped and we hand
    // back the existing one.
    let _ = MODEL.set(m);
    Ok(MODEL.get().expect("just set"))
}

fn build_model() -> TractResult<Runnable> {
    let mut cursor = std::io::Cursor::new(MODEL_BYTES);
    let model = tract_onnx::onnx()
        .model_for_read(&mut cursor)?
        .into_optimized()?
        .into_runnable()?;
    Ok(model)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip a carrier through extract+scatter and confirm
    /// values land at the right offsets, regardless of chunk size.
    /// The model isn't exercised here — only the chunking layout
    /// math, which is the part most likely to slip silently if
    /// `t_frames` indexing drifts.
    #[test]
    fn extract_then_scatter_preserves_layout_under_chunking() {
        let t_frames = 100;
        // Carrier with a unique value per (bin, t) so any misindex
        // shows up as a wrong number, not a zero.
        let carrier: Vec<f32> = (0..FREQ_BINS * t_frames).map(|i| i as f32).collect();
        // Synthesise per-chunk "logits" by treating extract_chunk as
        // if it were a model that emits MESSAGE_DIM logits per t,
        // each equal to bin 0 of that t. Then scatter and check
        // every value is in the right slot.
        for chunk_size in [16usize, 32, 64, 100, 128, 256] {
            let mut full_logits = vec![0.0_f32; MESSAGE_DIM * t_frames];
            let mut t_start = 0;
            while t_start < t_frames {
                let chunk_t = (t_frames - t_start).min(chunk_size);
                let chunk_carrier = extract_chunk(&carrier, t_frames, t_start, chunk_t);
                // Round-trip: every value in the chunk must match
                // the corresponding bin/t in the source.
                for bin in 0..FREQ_BINS {
                    for t in 0..chunk_t {
                        let got = chunk_carrier[bin * chunk_t + t];
                        let want = carrier[bin * t_frames + (t_start + t)];
                        assert_eq!(
                            got, want,
                            "chunk_size={chunk_size} bin={bin} t_start={t_start} t={t}"
                        );
                    }
                }
                // Build synthetic per-chunk logits where logit[dim,t] = t_start + t
                // so the scattered full_logits should equal the absolute frame
                // index at every (dim, t) cell.
                let chunk_logits: Vec<f32> = (0..MESSAGE_DIM)
                    .flat_map(|_dim| (0..chunk_t).map(|t| (t_start + t) as f32))
                    .collect();
                scatter_chunk_logits(&chunk_logits, chunk_t, &mut full_logits, t_frames, t_start);
                t_start += chunk_t;
            }
            // After all chunks scattered, every cell in full_logits
            // should hold its absolute t index.
            for dim in 0..MESSAGE_DIM {
                for t in 0..t_frames {
                    assert_eq!(
                        full_logits[dim * t_frames + t],
                        t as f32,
                        "chunk_size={chunk_size} dim={dim} t={t}"
                    );
                }
            }
        }
    }

    /// Specifically pin the load-bearing arithmetic at the chunk
    /// boundary: a t_frames that isn't a multiple of CHUNK_T_FRAMES
    /// must still cover every frame exactly once.
    #[test]
    fn chunking_covers_every_frame_exactly_once_on_ragged_inputs() {
        // 370 frames @ chunk=256 → chunks of [256, 114]
        let t_frames = 370;
        let mut covered = vec![0u32; t_frames];
        let mut t_start = 0;
        while t_start < t_frames {
            let chunk_t = (t_frames - t_start).min(CHUNK_T_FRAMES);
            for t in 0..chunk_t {
                covered[t_start + t] += 1;
            }
            t_start += chunk_t;
        }
        let unexpected: Vec<(usize, u32)> = covered
            .iter()
            .enumerate()
            .filter_map(|(i, &c)| if c != 1 { Some((i, c)) } else { None })
            .collect();
        assert!(
            unexpected.is_empty(),
            "every frame must be covered exactly once; mismatches: {unexpected:?}"
        );
    }
}
