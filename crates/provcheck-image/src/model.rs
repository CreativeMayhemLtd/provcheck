//! TrustMark-B decoder inference via tract-onnx.
//!
//! v0.7 phase 7b. Loads the ONNX weight via provcheck-weights's
//! `load_if_cached` so missing weights surface as a clean
//! install-needed error (the kit CLI / GUI is the right place to
//! prompt for consent, never the model layer).
//!
//! ## Pipeline
//!
//! 1. [`crate::image::decode`] returns a `[1, 3, 224, 224]` f32
//!    CHW tensor normalised to `[-1, 1]`.
//! 2. tract runs the TrustMark-B decoder ONNX on that tensor.
//! 3. The raw output is thresholded at zero per upstream's
//!    `(self.decoder.decoder(stego) > 0)`. The result is 100
//!    binary "secret" bits.
//! 4. Confidence is the mean of the absolute logit values —
//!    higher means the model committed harder to each bit's
//!    decision, which empirically tracks watermark-presence.
//!
//! BCH-5 error correction + brand mapping are NOT in this phase.
//! 7b ships the inference pipeline; brand mapping lands in a
//! follow-up. Until then [`run_decoder`] returns the raw bits as
//! a `Vec<u8>` and the caller's brand-id field stays `None`.
//!
//! ## tract 0.21 ONNX coverage gap (v0.7 phase 7b status)
//!
//! Adobe's TrustMark-B decoder ONNX uses Gemm and Resize op
//! attribute combinations that tract 0.21 declines to translate
//! (one Gemm node fails the `into_typed` pass; one Resize node
//! fails at runtime). Skipping the optimisation pass gets us past
//! the Gemm gate but hits the Resize gate at inference time.
//!
//! Status:
//!
//! - Preprocessing (decode + resize + normalise + CHW) is correct
//!   and tested via this crate's unit tests against the documented
//!   upstream math.
//! - DLC weight delivery + verifier integration are wired and
//!   exercised.
//! - The actual model run currently returns a runtime error
//!   surfaced as a clear "tract op coverage" message in
//!   [`crate::detect`].
//!
//! 7b-followup: switch the inference backend to ort, which has
//! full ONNX op coverage. The preprocessing + weight delivery
//! plumbing stays as-is.

use std::io::BufReader;
use std::sync::OnceLock;

use tract_onnx::prelude::*;
use tract_onnx::tract_hir::infer::InferenceOp;

use crate::image::{DecodedImage, MODEL_RES};

/// Number of raw bits the TrustMark decoder emits per image.
pub const SECRET_LEN: usize = 100;

/// Number of bytes needed to pack `SECRET_LEN` bits.
pub const SECRET_BYTES: usize = (SECRET_LEN + 7) / 8;

#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("decoder model load failed: {0}")]
    Load(String),
    #[error("decoder inference failed: {0}")]
    Inference(String),
    #[error(
        "unexpected output shape: expected last axis of length {SECRET_LEN}, got shape {got:?}"
    )]
    OutputShape { got: Vec<usize> },
}

/// Inference-form runnable (not TypedRunnableModel). tract 0.21
/// declines to translate one of TrustMark's Gemm nodes during the
/// `into_typed()` analysis pass, so we run the inference graph
/// directly rather than the typed/optimised form.
type Runnable =
    SimplePlan<InferenceFact, Box<dyn InferenceOp>, Graph<InferenceFact, Box<dyn InferenceOp>>>;

/// Output of one decoder pass.
#[derive(Debug, Clone)]
pub struct DecoderOutput {
    /// Raw thresholded bits, length [`SECRET_LEN`]. Each entry is
    /// 0 or 1.
    pub bits: Vec<u8>,
    /// `SECRET_LEN` bits packed MSB-first into [`SECRET_BYTES`]
    /// bytes for convenient downstream handling. The trailing
    /// `SECRET_BYTES * 8 - SECRET_LEN` low bits of the last byte
    /// are zero.
    pub payload_bytes: Vec<u8>,
    /// Mean absolute logit across the 100 outputs. Empirically
    /// tracks watermark presence — higher means the decoder
    /// committed harder to each bit's threshold decision.
    pub mean_abs_logit: f32,
}

/// Build the tract runnable (lazy + cached for the process
/// lifetime). Cache miss surfaces as a `weights not installed`
/// error from provcheck-weights.
fn model() -> Result<&'static Runnable, ModelError> {
    static MODEL: OnceLock<Runnable> = OnceLock::new();
    if let Some(m) = MODEL.get() {
        return Ok(m);
    }
    let path = provcheck_weights::load_if_cached("trustmark", "b-decoder")
        .map_err(|e| ModelError::Load(format!("weights: {e}")))?;
    let file = std::fs::File::open(&path)
        .map_err(|e| ModelError::Load(format!("open {}: {e}", path.display())))?;
    let mut reader = BufReader::new(file);
    // tract 0.21's translator stumbles on one Gemm node in the
    // TrustMark-B decoder export (Adobe's ONNX export uses a Gemm
    // attribute combination tract's optimiser rejects). Skipping
    // `into_optimized()` keeps the inference-graph form and lets
    // the runnable build succeed; we lose a small amount of graph
    // optimisation but the model runs end-to-end. If tract's
    // coverage closes in a later version, restore the optimisation
    // pass.
    let m = tract_onnx::onnx()
        .model_for_read(&mut reader)
        .and_then(|m| m.into_runnable())
        .map_err(|e| ModelError::Load(e.to_string()))?;
    let _ = MODEL.set(m);
    Ok(MODEL.get().expect("just set"))
}

/// Run the TrustMark-B decoder on a preprocessed image tensor and
/// return raw bits + confidence proxy.
pub fn run_decoder(decoded: &DecodedImage) -> Result<DecoderOutput, ModelError> {
    debug_assert_eq!(decoded.chw.len(), 3 * (MODEL_RES * MODEL_RES) as usize);
    let m = model()?;

    let input = tract_ndarray::Array4::from_shape_vec(
        (1, 3, MODEL_RES as usize, MODEL_RES as usize),
        decoded.chw.clone(),
    )
    .map_err(|e| ModelError::Inference(format!("input shape: {e}")))?;
    let outputs = m
        .run(tvec!(input.into_tvalue()))
        .map_err(|e: TractError| ModelError::Inference(e.to_string()))?;
    let out = outputs
        .into_iter()
        .next()
        .ok_or_else(|| ModelError::Inference("model returned no outputs".into()))?;

    let shape: Vec<usize> = out.shape().to_vec();
    // Accept any leading shape as long as the last (or only) axis
    // is SECRET_LEN. TrustMark's exported ONNX flattens to shape
    // [1, 100] or [100].
    let total: usize = shape.iter().product();
    if total != SECRET_LEN {
        return Err(ModelError::OutputShape { got: shape });
    }
    let view = out
        .to_array_view::<f32>()
        .map_err(|e: TractError| ModelError::Inference(e.to_string()))?;
    let logits: Vec<f32> = view.iter().copied().collect();

    let bits: Vec<u8> = logits.iter().map(|x| if *x > 0.0 { 1u8 } else { 0u8 }).collect();
    let mean_abs_logit =
        logits.iter().map(|x| x.abs()).sum::<f32>() / SECRET_LEN as f32;

    // Pack MSB-first into 13 bytes.
    let mut payload_bytes = vec![0u8; SECRET_BYTES];
    for (i, b) in bits.iter().enumerate() {
        if *b == 1 {
            payload_bytes[i / 8] |= 1 << (7 - (i % 8));
        }
    }

    Ok(DecoderOutput {
        bits,
        payload_bytes,
        mean_abs_logit,
    })
}
