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

/// Run the decoder on a carrier tensor laid out as
/// `[1, 1, FREQ_BINS, t_frames]` in row-major order
/// (`bin * t_frames + t`).
///
/// Returns the logits as a flat `Vec<f32>` of length
/// `MESSAGE_DIM * t_frames`, laid out as `[MESSAGE_DIM, T]`
/// row-major.
pub fn run(carrier: &[f32], t_frames: usize) -> Result<Vec<f32>, ModelError> {
    assert_eq!(
        carrier.len(),
        FREQ_BINS * t_frames,
        "carrier length must match FREQ_BINS * t_frames"
    );

    let model = model()?;

    // Build the tract input tensor. tract owns 4-D ndarray
    // construction via tract_ndarray; we go through that for a
    // tensor of shape [1, 1, FREQ_BINS, t_frames] from our
    // flat row-major carrier.
    let input =
        tract_ndarray::Array4::from_shape_vec((1, 1, FREQ_BINS, t_frames), carrier.to_vec())
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
        [1, 1, m, t] | [1, m, t] | [m, t] if *m == MESSAGE_DIM && *t == t_frames
    );
    if !leading_singletons_ok {
        return Err(ModelError::Shape {
            expected: format!("[1, 1, {MESSAGE_DIM}, {t_frames}]"),
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
