//! Verify tract 0.21 can load + run AudioSeal's detector and
//! generator ONNXes. The detector uses LSTM (in SEANet's encoder)
//! plus ConvTranspose1d (in SEANetEncoderKeepDimension). The
//! generator additionally uses LSTM in the decoder. Both are
//! standard ONNX ops but tract's coverage is incomplete enough
//! to make this a real risk gate before we commit to the rest
//! of the pipeline.
//!
//! What this does
//! --------------
//! 1. Load detector ONNX, run on 1 second of synthetic audio
//!    (16000 samples). Confirm output shapes match expectations.
//! 2. Load generator ONNX, run on the same input + a random msg.
//!    Confirm watermark shape matches input shape.
//! 3. Print elapsed times so we know what scaling to expect for
//!    real-world clip lengths.
//!
//! Usage:
//!   cargo run --release -p provcheck-audioseal --example tract_probe

use std::time::Instant;

use tract_onnx::prelude::*;

// v0.7 phase 8a: weights moved to DLC. This example pulls them
// at runtime through provcheck-weights instead of via
// include_bytes!() on the now-deleted models/*.onnx files.

const SAMPLE_RATE: usize = 16_000;
const NBITS: usize = 16;
const CHUNK_SECONDS: usize = 10;
const FIXED_SAMPLES: usize = SAMPLE_RATE * CHUNK_SECONDS;

fn main() -> anyhow::Result<()> {
    eprintln!("== tract_probe ==");

    // 1. Detector
    eprintln!("[1/2] loading detector ONNX...");
    let t0 = Instant::now();
    let detector_path = provcheck_weights::load_or_download("audioseal", "detector")?;
    let mut cursor = std::io::BufReader::new(std::fs::File::open(&detector_path)?);
    let detector = tract_onnx::onnx()
        .model_for_read(&mut cursor)?
        .into_optimized()?
        .into_runnable()?;
    eprintln!("        load + optimize: {:.2?}", t0.elapsed());

    let samples = FIXED_SAMPLES; // tract-friendly fixed shape — caller chunks audio to fit
    let x = tract_ndarray::Array3::<f32>::zeros((1, 1, samples));
    let x_tensor: Tensor = x.into();

    eprintln!("[1/2] running detector on {samples} samples...");
    let t1 = Instant::now();
    let outputs = detector.run(tvec!(x_tensor.into()))?;
    eprintln!("        inference: {:.2?}", t1.elapsed());
    eprintln!("        outputs: {} tensors", outputs.len());
    for (i, out) in outputs.iter().enumerate() {
        eprintln!(
            "          [{i}] shape={:?} dt={:?}",
            out.shape(),
            out.datum_type()
        );
    }

    // 2. Generator
    eprintln!();
    eprintln!("[2/2] loading generator ONNX...");
    let t0 = Instant::now();
    let generator_path = provcheck_weights::load_or_download("audioseal", "generator")?;
    let mut cursor = std::io::BufReader::new(std::fs::File::open(&generator_path)?);
    let generator = tract_onnx::onnx()
        .model_for_read(&mut cursor)?
        .into_optimized()?
        .into_runnable()?;
    eprintln!("        load + optimize: {:.2?}", t0.elapsed());

    let x = tract_ndarray::Array3::<f32>::zeros((1, 1, samples));
    let msg = tract_ndarray::Array2::<i64>::from_shape_vec((1, NBITS), vec![1i64; NBITS])?;

    eprintln!("[2/2] running generator on {samples} samples + 16-bit msg...");
    let t1 = Instant::now();
    let outputs = generator.run(tvec!(Tensor::from(x).into(), Tensor::from(msg).into(),))?;
    eprintln!("        inference: {:.2?}", t1.elapsed());
    eprintln!("        outputs: {} tensors", outputs.len());
    for (i, out) in outputs.iter().enumerate() {
        eprintln!(
            "          [{i}] shape={:?} dt={:?}",
            out.shape(),
            out.datum_type()
        );
    }

    eprintln!();
    eprintln!("tract loaded + ran both ONNXes without errors.");
    Ok(())
}
