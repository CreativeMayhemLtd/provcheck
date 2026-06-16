//! Validate that windowed inference produces the same detection
//! verdict as full inference, at a fraction of the time.
//!
//! For each given audio file, runs:
//!   1. Full inference (current behaviour).
//!   2. Windowed inference on the first N tiles of the carrier.
//!
//! Reports timing for both and asserts the verdict + brand agree.
//!
//! Run with:
//!   cargo run --release -p provcheck-watermark --example windowed_validate -- <path> [window_tiles]
//!
//! Default window_tiles = 10 (~10 seconds of audio at HOP=2048, SR=44100).

use std::path::PathBuf;
use std::time::Instant;

use provcheck_watermark::audio;
use provcheck_watermark::decode;
use provcheck_watermark::model;
use provcheck_watermark::stft;

// Match the existing hparams.
const FREQ_BINS: usize = 2049;
const MESSAGE_LEN: usize = 21; // frames per tile

fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: windowed_validate <audio-file> [window_tiles]"))?;
    let window_tiles: usize = std::env::args()
        .nth(2)
        .map(|s| s.parse().unwrap_or(10))
        .unwrap_or(10);
    let path = PathBuf::from(path);
    let window_frames = window_tiles * MESSAGE_LEN;

    println!("== windowed_validate ==");
    println!("file:          {}", path.display());
    println!("window_tiles:  {window_tiles} ({window_frames} frames)");
    println!();

    // Decode + STFT once. Cheap (<1% of total).
    let waveform = audio::decode_to_mono_44k1(&path)?;
    let (carrier, t_frames) = stft::waveform_to_carrier(&waveform)?;
    println!(
        "audio:         {:.1}s, t_frames={t_frames} (~{} tiles)",
        waveform.len() as f32 / 44_100.0,
        t_frames / MESSAGE_LEN
    );
    println!();

    // ---- 1. Full inference ----
    let t = Instant::now();
    let full_logits = model::run(&carrier, t_frames)?;
    let full_secs = t.elapsed().as_secs_f32();
    let full_decoded = decode::decode_logits(&full_logits, t_frames);
    println!(
        "[FULL    ] inference: {full_secs:6.3}s  valid={} confidence={:.3} payload={:02x?}",
        full_decoded.valid, full_decoded.confidence, full_decoded.payload
    );

    // ---- 2. Windowed inference ----
    let effective_window = window_frames.min(t_frames);
    let window_slice = &carrier[..effective_window * FREQ_BINS];
    let t = Instant::now();
    let win_logits = model::run(window_slice, effective_window)?;
    let win_secs = t.elapsed().as_secs_f32();
    let win_decoded = decode::decode_logits(&win_logits, effective_window);
    println!(
        "[WINDOWED] inference: {win_secs:6.3}s  valid={} confidence={:.3} payload={:02x?}",
        win_decoded.valid, win_decoded.confidence, win_decoded.payload
    );

    println!();
    let speedup = full_secs / win_secs.max(0.001);
    println!("speedup:       {speedup:.1}x");
    println!();
    println!("verdict agreement:");
    println!(
        "  valid:       full={} / window={}    {}",
        full_decoded.valid,
        win_decoded.valid,
        if full_decoded.valid == win_decoded.valid {
            "OK"
        } else {
            "DISAGREE"
        }
    );
    println!(
        "  payload:     full={:02x?} / window={:02x?}    {}",
        full_decoded.payload,
        win_decoded.payload,
        if full_decoded.payload == win_decoded.payload {
            "OK"
        } else {
            "DISAGREE"
        }
    );

    Ok(())
}
