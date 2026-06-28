//! tract-onnx wrappers around WavMark's HiNet forward + reverse
//! passes, plus the two Linear projections (`watermark_fc` and
//! `watermark_fc_back`) we couldn't keep in the ONNX.
//!
//! The ONNX export at `scripts/export-wavmark.py` carves WavMark's
//! `Model.encode` / `Model.decode` into three pieces:
//!
//! 1. STFT / iSTFT → handled in [`crate::stft`], because PyTorch's
//!    `return_complex=True` op can't round-trip through opset-17 ONNX.
//! 2. HiNet forward / reverse (the invertible neural network that
//!    actually mixes the watermark with the cover signal) → the two
//!    ONNX files embedded here.
//! 3. The two Linear projections that map the 32-bit message ↔ the
//!    16000-sample chunk → kept as plain weight + bias blobs and
//!    applied in Rust. These can't sit comfortably inside the HiNet
//!    ONNX because the input/output ranks don't match the HiNet's
//!    `[1, 2, t_frames, freq_bins]` rank.
//!
//! On-disk layout (relative to the crate root):
//! ```text
//! models/
//!   wavmark-encoder.onnx                   ─ HiNet forward
//!   wavmark-decoder.onnx                   ─ HiNet reverse
//!   wavmark-watermark_fc.weights.bin       ─ (16000, 32) f32
//!   wavmark-watermark_fc.bias.bin          ─ (16000,) f32
//!   wavmark-watermark_fc_back.weights.bin  ─ (32, 16000) f32
//!   wavmark-watermark_fc_back.bias.bin     ─ (32,) f32
//! ```

use std::sync::OnceLock;

use tract_onnx::prelude::*;

use crate::stft::StftConfig;

// v0.7 phase 8a: wavmark encoder + decoder + FC weights migrated
// from include_bytes!() to the provcheck-weights DLC pattern. Kit
// binary drops by ~16 MB. The tiny bias .bin files (64 KB
// fc.bias, 128 bytes fc_back.bias) stay embedded — too small to
// justify a download round trip.
const FC_BIAS: &[u8] = include_bytes!("../models/wavmark-watermark_fc.bias.bin");
const FC_BACK_BIAS: &[u8] = include_bytes!("../models/wavmark-watermark_fc_back.bias.bin");

/// Samples per WavMark chunk (16 kHz × 1 s).
pub const CHUNK_SAMPLES: usize = 16_000;

/// Total payload width: 16 fix-pattern bits + 16 custom payload bits.
pub const NUM_BITS: usize = 32;

/// Width of the fixed pattern at the head of the payload. The
/// detector calls a chunk "marked" iff the recovered first 16 bits
/// match WAVMARK_FIX_PATTERN within tolerance.
pub const FIX_PATTERN_LEN: usize = 16;

/// WavMark's hardcoded fix-pattern (first 16 bits of its 32-bit
/// payload). Lifted verbatim from the upstream package's
/// `wavmark/utils/wm_add_util.py::fix_pattern`. The package picked an
/// arbitrary non-periodic 16-bit sequence at training time and never
/// re-randomised it; every WavMark-marked file in the wild carries
/// this exact pattern.
pub const WAVMARK_FIX_PATTERN: [u8; FIX_PATTERN_LEN] =
    [1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0];

type Runnable = TypedRunnableModel<TypedModel>;

#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("model load failed: {0}")]
    Load(String),
    #[error("inference failed: {0}")]
    Inference(String),
    #[error("unexpected output shape: expected {expected}, got {got}")]
    Shape { expected: String, got: String },
}

/// `watermark_fc`: Linear(32 → 16000). Used to expand a 32-bit
/// message into a 16000-sample carrier before STFT during embed.
pub fn apply_watermark_fc(message: &[f32; NUM_BITS]) -> Vec<f32> {
    let weights = fc_weights();
    let bias = fc_bias();
    let mut out = vec![0.0_f32; CHUNK_SAMPLES];
    // PyTorch Linear: y = x @ W^T + b. Stored weight has shape
    // (out_features, in_features), so the dot product is over the
    // 32 in_features per row.
    for i in 0..CHUNK_SAMPLES {
        let row_off = i * NUM_BITS;
        let mut acc = bias[i];
        for j in 0..NUM_BITS {
            acc += weights[row_off + j] * message[j];
        }
        out[i] = acc;
    }
    out
}

/// `watermark_fc_back`: Linear(16000 → 32). Applied after the HiNet
/// reverse pass + iSTFT to map the recovered 16000-sample signal
/// back to a 32-bit message during detect. Returns the unclamped
/// 32-d output; caller clamps to `[-1, 1]` and thresholds at 0.5.
///
/// Takes a slice so the caller doesn't need to materialise a
/// `[f32; CHUNK_SAMPLES]` on the stack (64 KB on the stack can
/// overflow under rayon's default ~1 MB worker stacks).
pub fn apply_watermark_fc_back(signal: &[f32]) -> [f32; NUM_BITS] {
    assert_eq!(signal.len(), CHUNK_SAMPLES);
    let weights = fc_back_weights();
    let bias = fc_back_bias();
    let mut out = [0.0_f32; NUM_BITS];
    for i in 0..NUM_BITS {
        let row_off = i * CHUNK_SAMPLES;
        let mut acc = bias[i];
        for j in 0..CHUNK_SAMPLES {
            acc += weights[row_off + j] * signal[j];
        }
        out[i] = acc;
    }
    out
}

/// Run the HiNet forward pass (encoder ONNX). Inputs and outputs
/// are both in the permuted layout `[1, 2, t_frames, freq_bins]`.
///
/// Returns `(signal_marked_fft, msg_remain_fft)` flattened in the
/// same layout. Caller iSTFTs `signal_marked_fft` to recover the
/// marked waveform; `msg_remain_fft` is discarded for embed.
pub fn run_hinet_forward(
    signal_fft_pcfb: &[f32],
    message_fft_pcfb: &[f32],
    t_frames: usize,
    freq_bins: usize,
) -> Result<(Vec<f32>, Vec<f32>), ModelError> {
    let shape = (1, 2, t_frames, freq_bins);
    let expected_len = 2 * t_frames * freq_bins;
    assert_eq!(signal_fft_pcfb.len(), expected_len);
    assert_eq!(message_fft_pcfb.len(), expected_len);

    let model = encoder_model()?;
    let sig = tract_ndarray::Array4::from_shape_vec(shape, signal_fft_pcfb.to_vec())
        .map_err(|e| ModelError::Inference(format!("signal shape: {e}")))?;
    let msg = tract_ndarray::Array4::from_shape_vec(shape, message_fft_pcfb.to_vec())
        .map_err(|e| ModelError::Inference(format!("message shape: {e}")))?;

    let outputs = model
        .run(tvec!(Tensor::from(sig).into(), Tensor::from(msg).into()))
        .map_err(|e: TractError| ModelError::Inference(e.to_string()))?;

    let mut iter = outputs.into_iter();
    let sig_out = iter
        .next()
        .ok_or_else(|| ModelError::Inference("encoder: missing signal output".into()))?;
    let msg_out = iter
        .next()
        .ok_or_else(|| ModelError::Inference("encoder: missing message output".into()))?;

    check_shape("encoder.signal_marked_fft", &sig_out, [1, 2, t_frames, freq_bins])?;
    check_shape("encoder.msg_remain_fft", &msg_out, [1, 2, t_frames, freq_bins])?;

    let sig_view = sig_out
        .to_array_view::<f32>()
        .map_err(|e: TractError| ModelError::Inference(e.to_string()))?;
    let msg_view = msg_out
        .to_array_view::<f32>()
        .map_err(|e: TractError| ModelError::Inference(e.to_string()))?;
    Ok((
        sig_view.iter().copied().collect(),
        msg_view.iter().copied().collect(),
    ))
}

/// Run the HiNet reverse pass (decoder ONNX). Inputs match the
/// forward pass; in WavMark's `decode`, both inputs are the same
/// `signal_fft` tensor (the encoder embeds the watermark into the
/// signal, so during decode we feed the signal as the "watermark"
/// channel and let HiNet's reverse extract it). Outputs are
/// `(signal_residual_fft, message_recovered_fft)` — caller keeps
/// only the second.
pub fn run_hinet_reverse(
    signal_fft_pcfb: &[f32],
    watermark_fft_pcfb: &[f32],
    t_frames: usize,
    freq_bins: usize,
) -> Result<(Vec<f32>, Vec<f32>), ModelError> {
    let shape = (1, 2, t_frames, freq_bins);
    let expected_len = 2 * t_frames * freq_bins;
    assert_eq!(signal_fft_pcfb.len(), expected_len);
    assert_eq!(watermark_fft_pcfb.len(), expected_len);

    let model = decoder_model()?;
    let sig = tract_ndarray::Array4::from_shape_vec(shape, signal_fft_pcfb.to_vec())
        .map_err(|e| ModelError::Inference(format!("signal shape: {e}")))?;
    let wm = tract_ndarray::Array4::from_shape_vec(shape, watermark_fft_pcfb.to_vec())
        .map_err(|e| ModelError::Inference(format!("watermark shape: {e}")))?;

    let outputs = model
        .run(tvec!(Tensor::from(sig).into(), Tensor::from(wm).into()))
        .map_err(|e: TractError| ModelError::Inference(e.to_string()))?;

    let mut iter = outputs.into_iter();
    let sig_out = iter
        .next()
        .ok_or_else(|| ModelError::Inference("decoder: missing signal output".into()))?;
    let msg_out = iter
        .next()
        .ok_or_else(|| ModelError::Inference("decoder: missing watermark output".into()))?;

    check_shape("decoder.signal_out", &sig_out, [1, 2, t_frames, freq_bins])?;
    check_shape("decoder.watermark_out", &msg_out, [1, 2, t_frames, freq_bins])?;

    let sig_view = sig_out
        .to_array_view::<f32>()
        .map_err(|e: TractError| ModelError::Inference(e.to_string()))?;
    let msg_view = msg_out
        .to_array_view::<f32>()
        .map_err(|e: TractError| ModelError::Inference(e.to_string()))?;
    Ok((
        sig_view.iter().copied().collect(),
        msg_view.iter().copied().collect(),
    ))
}

/// Convert STFT output (layout `[freq_bins, t_frames, 2]` from
/// [`crate::stft::stft`]) into the HiNet's expected
/// `[1, 2, t_frames, freq_bins]` permutation.
pub fn permute_freq_time_to_channel_time_freq(
    spec_fbt2: &[f32],
    t_frames: usize,
    freq_bins: usize,
) -> Vec<f32> {
    let mut out = vec![0.0_f32; 2 * t_frames * freq_bins];
    // Output layout: [2, t_frames, freq_bins] row-major. Channel 0
    // holds reals at offsets [0, t_frames*freq_bins), channel 1
    // holds imaginaries at offsets [t_frames*freq_bins, 2*t_frames*freq_bins).
    let chan1_off = t_frames * freq_bins;
    for b in 0..freq_bins {
        for t in 0..t_frames {
            let src = b * t_frames * 2 + t * 2;
            let dst = t * freq_bins + b;
            out[dst] = spec_fbt2[src];
            out[chan1_off + dst] = spec_fbt2[src + 1];
        }
    }
    out
}

/// Inverse of [`permute_freq_time_to_channel_time_freq`]. Converts
/// HiNet output back to STFT layout for iSTFT.
pub fn permute_channel_time_freq_to_freq_time(
    spec_ctf: &[f32],
    t_frames: usize,
    freq_bins: usize,
) -> Vec<f32> {
    let mut out = vec![0.0_f32; freq_bins * t_frames * 2];
    let chan1_off = t_frames * freq_bins;
    for t in 0..t_frames {
        for b in 0..freq_bins {
            let src = t * freq_bins + b;
            let dst = b * t_frames * 2 + t * 2;
            out[dst] = spec_ctf[src];
            out[dst + 1] = spec_ctf[chan1_off + src];
        }
    }
    out
}

fn check_shape(
    label: &str,
    tensor: &tract_onnx::prelude::TValue,
    expected: [usize; 4],
) -> Result<(), ModelError> {
    let got = tensor.shape().to_vec();
    if got != expected {
        return Err(ModelError::Shape {
            expected: format!("{label} {expected:?}"),
            got: format!("{got:?}"),
        });
    }
    Ok(())
}

fn encoder_model() -> Result<&'static Runnable, ModelError> {
    static MODEL: OnceLock<Runnable> = OnceLock::new();
    if let Some(m) = MODEL.get() {
        return Ok(m);
    }
    let m = build_runnable_from_weights("encoder")
        .map_err(|e| ModelError::Load(format!("encoder: {e}")))?;
    let _ = MODEL.set(m);
    Ok(MODEL.get().expect("just set"))
}

fn decoder_model() -> Result<&'static Runnable, ModelError> {
    static MODEL: OnceLock<Runnable> = OnceLock::new();
    if let Some(m) = MODEL.get() {
        return Ok(m);
    }
    let m = build_runnable_from_weights("decoder")
        .map_err(|e| ModelError::Load(format!("decoder: {e}")))?;
    let _ = MODEL.set(m);
    Ok(MODEL.get().expect("just set"))
}

fn build_runnable_from_weights(variant: &str) -> Result<Runnable, String> {
    let path = provcheck_weights::load_or_download("wavmark", variant)
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

fn fc_weights() -> &'static [f32] {
    static W: OnceLock<Vec<f32>> = OnceLock::new();
    W.get_or_init(|| {
        load_f32_blob_from_weights("fc-weights", CHUNK_SAMPLES * NUM_BITS, "watermark_fc.weights")
    })
}

fn fc_bias() -> &'static [f32] {
    static B: OnceLock<Vec<f32>> = OnceLock::new();
    B.get_or_init(|| load_f32_blob(FC_BIAS, CHUNK_SAMPLES, "watermark_fc.bias"))
}

fn fc_back_weights() -> &'static [f32] {
    static W: OnceLock<Vec<f32>> = OnceLock::new();
    W.get_or_init(|| {
        load_f32_blob_from_weights(
            "fc-back-weights",
            NUM_BITS * CHUNK_SAMPLES,
            "watermark_fc_back.weights",
        )
    })
}

fn load_f32_blob_from_weights(variant: &str, expected_elems: usize, label: &str) -> Vec<f32> {
    let path = provcheck_weights::load_or_download("wavmark", variant)
        .unwrap_or_else(|e| panic!("{label}: weights load: {e}"));
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("{label}: read {}: {e}", path.display()));
    load_f32_blob(&bytes, expected_elems, label)
}

fn fc_back_bias() -> &'static [f32] {
    static B: OnceLock<Vec<f32>> = OnceLock::new();
    B.get_or_init(|| load_f32_blob(FC_BACK_BIAS, NUM_BITS, "watermark_fc_back.bias"))
}

fn load_f32_blob(bytes: &[u8], expected_elems: usize, label: &str) -> Vec<f32> {
    let expected_bytes = expected_elems * std::mem::size_of::<f32>();
    assert_eq!(
        bytes.len(),
        expected_bytes,
        "{label}: expected {expected_bytes} bytes for {expected_elems} f32, got {}",
        bytes.len()
    );
    let mut out = Vec::with_capacity(expected_elems);
    for chunk in bytes.chunks_exact(4) {
        out.push(f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }
    out
}

/// Encode pipeline (one chunk): message → carrier via Linear,
/// STFT both, run HiNet forward, iSTFT result → marked signal.
pub fn encode_chunk(signal: &[f32], message: &[f32; NUM_BITS]) -> Result<Vec<f32>, ModelError> {
    assert_eq!(signal.len(), CHUNK_SAMPLES);
    let cfg = StftConfig::WAVMARK;
    let t_frames = cfg.t_frames(CHUNK_SAMPLES);
    let freq_bins = cfg.freq_bins();

    let message_expand = apply_watermark_fc(message);
    let signal_fft = crate::stft::stft(signal, &cfg);
    let message_fft = crate::stft::stft(&message_expand, &cfg);

    let signal_fft_p = permute_freq_time_to_channel_time_freq(&signal_fft, t_frames, freq_bins);
    let message_fft_p = permute_freq_time_to_channel_time_freq(&message_fft, t_frames, freq_bins);

    let (signal_marked_fft_p, _) =
        run_hinet_forward(&signal_fft_p, &message_fft_p, t_frames, freq_bins)?;

    let signal_marked_fft =
        permute_channel_time_freq_to_freq_time(&signal_marked_fft_p, t_frames, freq_bins);
    Ok(crate::stft::istft(&signal_marked_fft, CHUNK_SAMPLES, &cfg))
}

/// Decode pipeline (one chunk): STFT signal, feed twice (both inputs)
/// to HiNet reverse, iSTFT the second output, apply Linear back,
/// clamp, return 32 floats in `[-1, 1]`. Caller thresholds at 0.5.
///
/// Takes a slice (not `&[f32; CHUNK_SAMPLES]`) so callers don't
/// have to materialise the 64 KB buffer on the stack.
pub fn decode_chunk(signal: &[f32]) -> Result<[f32; NUM_BITS], ModelError> {
    assert_eq!(signal.len(), CHUNK_SAMPLES);
    let cfg = StftConfig::WAVMARK;
    let t_frames = cfg.t_frames(CHUNK_SAMPLES);
    let freq_bins = cfg.freq_bins();

    let signal_fft = crate::stft::stft(signal, &cfg);
    let signal_fft_p = permute_freq_time_to_channel_time_freq(&signal_fft, t_frames, freq_bins);

    let (_, message_fft_p) =
        run_hinet_reverse(&signal_fft_p, &signal_fft_p, t_frames, freq_bins)?;

    let message_fft =
        permute_channel_time_freq_to_freq_time(&message_fft_p, t_frames, freq_bins);
    let message_expand = crate::stft::istft(&message_fft, CHUNK_SAMPLES, &cfg);

    let mut bits = apply_watermark_fc_back(&message_expand);
    for b in bits.iter_mut() {
        *b = b.clamp(-1.0, 1.0);
    }
    Ok(bits)
}
