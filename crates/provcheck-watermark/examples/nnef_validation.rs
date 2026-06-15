//! Validation harness for the v0.3.2 NNEF pre-optimisation work.
//!
//! Times three operations on the silentcipher ONNX decoder:
//!
//! 1. Baseline: ONNX read → into_optimized → into_runnable.
//!    Measures the cost we're trying to eliminate.
//! 2. One-shot: ONNX read → into_optimized → write_to_tar.
//!    Cost paid ONCE at bake time; we commit the result.
//! 3. Fast path: NNEF read → into_runnable.
//!    What every cold process start would pay after the swap.
//!
//! Also verifies that both runnables produce identical outputs on
//! a zero-input carrier — if not, the round-trip is dropping
//! something and Plan A is dead.
//!
//! Run with:
//!   cargo run --release -p provcheck-watermark --example nnef_validation

use std::fs::File;
use std::io::BufWriter;
use std::time::Instant;

use tract_onnx::prelude::*;

const ONNX_PATH: &str = "crates/provcheck-watermark/models/silentcipher-decoder.onnx";
const NNEF_PATH: &str = "crates/provcheck-watermark/models/silentcipher-decoder.nnef.tgz";

const FREQ_BINS: usize = 2049;
const T_FRAMES: usize = 64;

fn main() -> anyhow::Result<()> {
    println!("== nnef_validation ==");

    // ---- 1. Baseline: ONNX → optimized → runnable ----
    let t0 = Instant::now();
    let mut f = File::open(ONNX_PATH)?;
    let onnx_runnable = tract_onnx::onnx()
        .model_for_read(&mut f)?
        .into_optimized()?
        .into_runnable()?;
    let baseline_secs = t0.elapsed().as_secs_f32();
    println!("[1] ONNX -> optimized -> runnable: {baseline_secs:.3}s");

    // ---- 2. One-shot bake: re-do optimization then write NNEF ----
    let t0 = Instant::now();
    let mut f = File::open(ONNX_PATH)?;
    let optimised: TypedModel = tract_onnx::onnx()
        .model_for_read(&mut f)?
        .into_optimized()?;
    let writer = BufWriter::new(File::create(NNEF_PATH)?);
    tract_nnef::nnef().write_to_tar(&optimised, writer)?;
    let bake_secs = t0.elapsed().as_secs_f32();
    let nnef_size = std::fs::metadata(NNEF_PATH)?.len();
    println!("[2] ONNX -> optimized -> write NNEF: {bake_secs:.3}s ({nnef_size} bytes)");

    // ---- 3. Fast path: NNEF → runnable ----
    let t0 = Instant::now();
    let mut f = File::open(NNEF_PATH)?;
    let nnef_runnable = tract_nnef::nnef()
        .model_for_read(&mut f)?
        .into_runnable()?;
    let fast_secs = t0.elapsed().as_secs_f32();
    println!("[3] NNEF -> runnable: {fast_secs:.3}s");

    // ---- 4. Output equivalence check ----
    let carrier: Vec<f32> = vec![0.0; FREQ_BINS * T_FRAMES];
    let input = tract_ndarray::Array4::from_shape_vec(
        (1, 1, FREQ_BINS, T_FRAMES),
        carrier,
    )?;
    let input_tensor: Tensor = input.into();

    let out_onnx = onnx_runnable.run(tvec!(input_tensor.clone().into()))?;
    let out_nnef = nnef_runnable.run(tvec!(input_tensor.into()))?;

    let onnx_first = out_onnx
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("onnx returned no outputs"))?;
    let nnef_first = out_nnef
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("nnef returned no outputs"))?;
    let onnx_view = onnx_first.to_array_view::<f32>()?;
    let nnef_view = nnef_first.to_array_view::<f32>()?;

    let mut max_diff: f32 = 0.0;
    for (a, b) in onnx_view.iter().zip(nnef_view.iter()) {
        max_diff = max_diff.max((a - b).abs());
    }
    println!("[4] max |onnx - nnef| over output: {max_diff:.3e}");

    println!();
    if fast_secs < baseline_secs * 0.5 {
        println!("VERDICT: Plan A viable.");
        println!("  Baseline:  {baseline_secs:.3}s");
        println!("  Fast path: {fast_secs:.3}s ({:.1}x speedup)",
            baseline_secs / fast_secs);
        if max_diff < 1e-3 {
            println!("  Outputs match within tolerance.");
        } else {
            println!("  WARNING: outputs diverge by {max_diff:.3e} — investigate before shipping.");
        }
    } else {
        println!("VERDICT: Plan A insufficient.");
        println!("  Fast path is not meaningfully faster than baseline.");
        println!("  Fall back to Plan B (on-disk runtime cache).");
    }

    Ok(())
}
