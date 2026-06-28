//! TrustMark-B decoder inference via ort (onnxruntime 2.x).
//!
//! v0.7 phase 7b-followup. The original 7b commit wired the
//! preprocessing + DLC weight delivery + verifier integration but
//! tract 0.21's ONNX op coverage could not run Adobe's decoder
//! export (Gemm + Resize attribute combinations declined). This
//! follow-up swaps the inference call for ort, which has full
//! op coverage and runs the model as-is.
//!
//! ## Pipeline
//!
//! 1. [`crate::image::decode`] returns a `[1, 3, MODEL_RES, MODEL_RES]`
//!    f32 CHW tensor normalised to `[-1, 1]`.
//! 2. ort runs the TrustMark-B decoder ONNX on that tensor.
//! 3. The raw output is thresholded at zero per upstream's
//!    `(self.decoder.decoder(stego) > 0)`. Result: 100 bits.
//! 4. Confidence is the mean of the absolute logit values — higher
//!    means the model committed harder to each bit's decision, which
//!    empirically tracks watermark presence.
//!
//! BCH-5 error correction + brand mapping are NOT in this phase.
//! 7b ships the inference pipeline; brand mapping lands in a
//! follow-up. Until then [`run_decoder`] returns the raw bits as
//! a `Vec<u8>` and the caller's brand-id field stays `None`.

use std::io::BufReader;
use std::sync::{Mutex, OnceLock};

use ndarray::Array4;
use ort::session::Session;
use ort::value::TensorRef;

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

/// Build the ort session (lazy + cached for the process lifetime).
/// Wrapped in a Mutex because `Session::run` takes `&mut self`;
/// ORT serialises CPU inference on its own thread pool anyway, so
/// the mutex does not give up parallelism we were going to use.
fn model() -> Result<&'static Mutex<Session>, ModelError> {
    static MODEL: OnceLock<Mutex<Session>> = OnceLock::new();
    if let Some(m) = MODEL.get() {
        return Ok(m);
    }
    let path = provcheck_weights::load_if_cached("trustmark", "b-decoder")
        .map_err(|e| ModelError::Load(format!("weights: {e}")))?;
    let _ = BufReader::<std::fs::File>::with_capacity(0, std::fs::File::open(&path).map_err(
        |e| ModelError::Load(format!("open {}: {e}", path.display())),
    )?); // existence check
    let session = Session::builder()
        .map_err(|e| ModelError::Load(e.to_string()))?
        .commit_from_file(&path)
        .map_err(|e| ModelError::Load(format!("ort commit: {e}")))?;
    let _ = MODEL.set(Mutex::new(session));
    Ok(MODEL.get().expect("just set"))
}

/// Build the encoder ort session (lazy + cached). Mutex pattern
/// mirrors the decoder.
fn encoder_model() -> Result<&'static Mutex<Session>, ModelError> {
    static MODEL: OnceLock<Mutex<Session>> = OnceLock::new();
    if let Some(m) = MODEL.get() {
        return Ok(m);
    }
    let path = provcheck_weights::load_if_cached("trustmark", "b-encoder")
        .map_err(|e| ModelError::Load(format!("weights: {e}")))?;
    let session = Session::builder()
        .map_err(|e| ModelError::Load(e.to_string()))?
        .commit_from_file(&path)
        .map_err(|e| ModelError::Load(format!("ort commit: {e}")))?;
    let _ = MODEL.set(Mutex::new(session));
    Ok(MODEL.get().expect("just set"))
}

/// Run the TrustMark-B encoder on a 256×256 cover image plus a
/// 100-bit secret. Returns the stego image at 256×256 in
/// `[-1, 1]` CHW layout. Caller is responsible for the residual
/// + blend + resize-to-original-size dance per upstream
/// `trustmark.py`'s encoder path.
///
/// v0.7 phase 7c.
pub fn run_encoder(cover_chw: &[f32], secret_bits: &[u8; SECRET_LEN]) -> Result<Vec<f32>, ModelError> {
    debug_assert_eq!(cover_chw.len(), 3 * (MODEL_RES * MODEL_RES) as usize);
    let model = encoder_model()?;

    let cover_arr = Array4::<f32>::from_shape_vec(
        (1, 3, MODEL_RES as usize, MODEL_RES as usize),
        cover_chw.to_vec(),
    )
    .map_err(|e| ModelError::Inference(format!("cover shape: {e}")))?;

    let secret: Vec<f32> = secret_bits.iter().map(|&b| b as f32).collect();
    let secret_arr = ndarray::Array2::<f32>::from_shape_vec((1, SECRET_LEN), secret)
        .map_err(|e| ModelError::Inference(format!("secret shape: {e}")))?;

    let mut session = model
        .lock()
        .map_err(|e| ModelError::Inference(format!("ort encoder mutex poisoned: {e}")))?;
    let cover_tensor = TensorRef::from_array_view(cover_arr.view())
        .map_err(|e| ModelError::Inference(format!("cover tensor: {e}")))?;
    let secret_tensor = TensorRef::from_array_view(secret_arr.view())
        .map_err(|e| ModelError::Inference(format!("secret tensor: {e}")))?;
    let outputs = session
        .run(ort::inputs![cover_tensor, secret_tensor])
        .map_err(|e| ModelError::Inference(e.to_string()))?;
    let output = outputs
        .iter()
        .next()
        .ok_or_else(|| ModelError::Inference("encoder returned no outputs".into()))?
        .1;
    let (shape, data) = output
        .try_extract_tensor::<f32>()
        .map_err(|e| ModelError::Inference(e.to_string()))?;
    let total: usize = shape.iter().map(|d| *d as usize).product();
    let expected = 3 * (MODEL_RES * MODEL_RES) as usize;
    if total != expected {
        return Err(ModelError::OutputShape {
            got: shape.iter().map(|d| *d as usize).collect(),
        });
    }
    Ok(data.to_vec())
}

/// Run the TrustMark-B decoder on a preprocessed image tensor and
/// return raw bits + confidence proxy.
pub fn run_decoder(decoded: &DecodedImage) -> Result<DecoderOutput, ModelError> {
    debug_assert_eq!(decoded.chw.len(), 3 * (MODEL_RES * MODEL_RES) as usize);
    let model = model()?;

    let input = Array4::<f32>::from_shape_vec(
        (1, 3, MODEL_RES as usize, MODEL_RES as usize),
        decoded.chw.clone(),
    )
    .map_err(|e| ModelError::Inference(format!("input shape: {e}")))?;

    let mut session = model
        .lock()
        .map_err(|e| ModelError::Inference(format!("ort session mutex poisoned: {e}")))?;
    let input_tensor = TensorRef::from_array_view(input.view())
        .map_err(|e| ModelError::Inference(format!("input tensor: {e}")))?;
    let outputs = session
        .run(ort::inputs![input_tensor])
        .map_err(|e| ModelError::Inference(e.to_string()))?;

    // Output 0 holds the SECRET_LEN bit logits. Shape is typically
    // `[1, 100]` or `[100]`; we just check the total element count.
    let output = outputs
        .iter()
        .next()
        .ok_or_else(|| ModelError::Inference("model returned no outputs".into()))?
        .1;
    let (shape, data) = output
        .try_extract_tensor::<f32>()
        .map_err(|e| ModelError::Inference(e.to_string()))?;
    let shape_usize: Vec<usize> = shape.iter().map(|d| *d as usize).collect();
    let total: usize = shape_usize.iter().product();
    if total != SECRET_LEN {
        return Err(ModelError::OutputShape { got: shape_usize });
    }
    let logits: Vec<f32> = data.to_vec();

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
