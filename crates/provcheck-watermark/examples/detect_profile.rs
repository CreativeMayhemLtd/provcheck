//! Profile each stage of the silentcipher detector on a real file.
//! Times decode → STFT → ONNX inference → backend decode separately
//! so we can point at the actual bottleneck instead of guessing.
//!
//! Run with:
//!   cargo run --release -p provcheck-watermark --example detect_profile -- <path>

use std::path::PathBuf;
use std::time::Instant;

use provcheck_watermark::audio;
use provcheck_watermark::decode;
use provcheck_watermark::model;
use provcheck_watermark::stft;

fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: detect_profile <audio-file>"))?;
    let path = PathBuf::from(path);
    println!("== detect_profile: {} ==", path.display());

    let total = Instant::now();

    // 1. Audio decode + resample to 44.1 kHz mono f32
    let t = Instant::now();
    let waveform = audio::decode_to_mono_44k1(&path)?;
    let decode_secs = t.elapsed().as_secs_f32();
    println!(
        "[1] decode + resample:    {decode_secs:6.3}s  ({} samples, {:.1}s of audio)",
        waveform.len(),
        waveform.len() as f32 / 44_100.0,
    );

    // 2. STFT → carrier
    let t = Instant::now();
    let (carrier, t_frames) = stft::waveform_to_carrier(&waveform)?;
    let stft_secs = t.elapsed().as_secs_f32();
    println!(
        "[2] STFT -> carrier:      {stft_secs:6.3}s  (t_frames = {t_frames}, carrier = {} f32s)",
        carrier.len()
    );

    // 3. ONNX inference
    let t = Instant::now();
    let logits = model::run(&carrier, t_frames)?;
    let model_secs = t.elapsed().as_secs_f32();
    println!(
        "[3] ONNX inference:       {model_secs:6.3}s  (logits = {} f32s)",
        logits.len()
    );

    // 4. Backend decode (argmax + voting + structural check)
    let t = Instant::now();
    let decoded = decode::decode_logits(&logits, t_frames);
    let decode_secs2 = t.elapsed().as_secs_f32();
    println!(
        "[4] backend decode:       {decode_secs2:6.3}s  (valid={}, confidence={:.2})",
        decoded.valid, decoded.confidence
    );

    let total_secs = total.elapsed().as_secs_f32();
    println!();
    println!("Total: {total_secs:.3}s");
    println!();
    println!("Breakdown by share of total:");
    let print = |name: &str, secs: f32| {
        println!(
            "  {name:<22} {:5.1}%  ({secs:.3}s)",
            secs / total_secs * 100.0
        );
    };
    print("decode + resample", decode_secs);
    print("STFT -> carrier", stft_secs);
    print("ONNX inference", model_secs);
    print("backend decode", decode_secs2);

    Ok(())
}
