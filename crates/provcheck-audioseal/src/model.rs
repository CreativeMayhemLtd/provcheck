//! tract-onnx wrappers around AudioSeal's detector + generator.
//!
//! Both ONNX files are embedded into the library at compile time via
//! [`include_bytes!`] so a running `provcheck` binary has no runtime
//! file dependency. Each model is built lazily on first call and
//! cached for the lifetime of the process via separate `OnceLock`s.
//!
//! Critical shape constraint: tract 0.21 can't resolve the symbolic
//! Pad expressions PyTorch's onnx exporter emits for dynamic-length
//! SEANet inputs ("Undetermined symbol in expression: 16003 +
//! -1*<Sym0>"). The export script bakes a fixed input length into
//! both ONNX files; this module exposes [`CHUNK_SAMPLES`] so callers
//! know exactly what to pad or chunk to.

use std::sync::OnceLock;

use tract_onnx::prelude::*;

/// Detector ONNX. Two outputs (presence + 16-bit message).
const DETECTOR_BYTES: &[u8] = include_bytes!("../models/audioseal-detector.onnx");

/// Generator ONNX. Returns the watermark signal; caller computes
/// `marked = x + alpha * watermark`.
const GENERATOR_BYTES: &[u8] = include_bytes!("../models/audioseal-generator.onnx");

/// Fixed input length for both ONNX files. Audio shorter than this
/// must be zero-padded; longer audio must be chunked. Equal to
/// `SAMPLE_RATE * CHUNK_SECONDS = 16_000 * 10`. Matches
/// `export-audioseal.py`'s `T_FIXED`.
pub const CHUNK_SAMPLES: usize = 160_000;

/// Number of payload bits AudioSeal recovers per inference.
pub const NBITS: usize = 16;

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

/// Run the detector on a fixed-length `[1, 1, CHUNK_SAMPLES]` waveform
/// chunk. Returns `(presence, message)` where:
///   - `presence` is a `[1, 2, CHUNK_SAMPLES]` softmax (`(absent, present)`
///     probabilities per sample) flattened in row-major order
///     (`dim * CHUNK_SAMPLES + t`),
///   - `message` is a `[1, NBITS]` sigmoid (per-bit `P(bit == 1)`).
pub fn run_detector_chunk(carrier: &[f32]) -> Result<(Vec<f32>, Vec<f32>), ModelError> {
    assert_eq!(
        carrier.len(),
        CHUNK_SAMPLES,
        "carrier must be exactly CHUNK_SAMPLES; caller pads or chunks"
    );
    let model = detector_model()?;
    let x = tract_ndarray::Array3::from_shape_vec((1, 1, CHUNK_SAMPLES), carrier.to_vec())
        .map_err(|e| ModelError::Inference(format!("carrier shape: {e}")))?;
    let outputs = model
        .run(tvec!(Tensor::from(x).into()))
        .map_err(|e: TractError| ModelError::Inference(e.to_string()))?;

    let mut iter = outputs.into_iter();
    let presence = iter
        .next()
        .ok_or_else(|| ModelError::Inference("detector: missing presence output".into()))?;
    let message = iter
        .next()
        .ok_or_else(|| ModelError::Inference("detector: missing message output".into()))?;

    let presence_shape = presence.shape().to_vec();
    if presence_shape != [1, 2, CHUNK_SAMPLES] {
        return Err(ModelError::Shape {
            expected: format!("[1, 2, {CHUNK_SAMPLES}]"),
            got: format!("{presence_shape:?}"),
        });
    }
    let message_shape = message.shape().to_vec();
    if message_shape != [1, NBITS] {
        return Err(ModelError::Shape {
            expected: format!("[1, {NBITS}]"),
            got: format!("{message_shape:?}"),
        });
    }

    let presence_view = presence
        .to_array_view::<f32>()
        .map_err(|e: TractError| ModelError::Inference(e.to_string()))?;
    let message_view = message
        .to_array_view::<f32>()
        .map_err(|e: TractError| ModelError::Inference(e.to_string()))?;
    Ok((
        presence_view.iter().copied().collect(),
        message_view.iter().copied().collect(),
    ))
}

/// Run the generator on a fixed-length `[1, 1, CHUNK_SAMPLES]` waveform
/// + a 16-bit `[1, NBITS]` message tensor.
///
/// Returns the watermark signal `[1, 1, CHUNK_SAMPLES]` flattened —
/// caller composes `marked = x + alpha * watermark`.
pub fn run_generator_chunk(carrier: &[f32], msg: &[i64; NBITS]) -> Result<Vec<f32>, ModelError> {
    assert_eq!(
        carrier.len(),
        CHUNK_SAMPLES,
        "carrier must be exactly CHUNK_SAMPLES; caller pads or chunks"
    );
    let model = generator_model()?;
    let x = tract_ndarray::Array3::from_shape_vec((1, 1, CHUNK_SAMPLES), carrier.to_vec())
        .map_err(|e| ModelError::Inference(format!("carrier shape: {e}")))?;
    let m = tract_ndarray::Array2::from_shape_vec((1, NBITS), msg.to_vec())
        .map_err(|e| ModelError::Inference(format!("msg shape: {e}")))?;
    let outputs = model
        .run(tvec!(Tensor::from(x).into(), Tensor::from(m).into()))
        .map_err(|e: TractError| ModelError::Inference(e.to_string()))?;

    let out = outputs
        .into_iter()
        .next()
        .ok_or_else(|| ModelError::Inference("generator: missing watermark output".into()))?;

    let shape = out.shape().to_vec();
    if shape != [1, 1, CHUNK_SAMPLES] {
        return Err(ModelError::Shape {
            expected: format!("[1, 1, {CHUNK_SAMPLES}]"),
            got: format!("{shape:?}"),
        });
    }
    let view = out
        .to_array_view::<f32>()
        .map_err(|e: TractError| ModelError::Inference(e.to_string()))?;
    Ok(view.iter().copied().collect())
}

fn detector_model() -> Result<&'static Runnable, ModelError> {
    static MODEL: OnceLock<Runnable> = OnceLock::new();
    if let Some(m) = MODEL.get() {
        return Ok(m);
    }
    let m = build_runnable(DETECTOR_BYTES)
        .map_err(|e: TractError| ModelError::Load(format!("detector: {e}")))?;
    let _ = MODEL.set(m);
    Ok(MODEL.get().expect("just set"))
}

fn generator_model() -> Result<&'static Runnable, ModelError> {
    static MODEL: OnceLock<Runnable> = OnceLock::new();
    if let Some(m) = MODEL.get() {
        return Ok(m);
    }
    let m = build_runnable(GENERATOR_BYTES)
        .map_err(|e: TractError| ModelError::Load(format!("generator: {e}")))?;
    let _ = MODEL.set(m);
    Ok(MODEL.get().expect("just set"))
}

fn build_runnable(bytes: &[u8]) -> TractResult<Runnable> {
    let mut cursor = std::io::Cursor::new(bytes);
    let model = tract_onnx::onnx()
        .model_for_read(&mut cursor)?
        .into_optimized()?
        .into_runnable()?;
    Ok(model)
}
