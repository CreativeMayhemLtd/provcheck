//! Reproduce the v0.3.6 OOM bug on a synthetic carrier.
//!
//! On a 211s MP3, the watermark detector consumed ~11 GB RSS before
//! the kernel OOM-killed it. Doomscroll's bug report named the file
//! as 211s @ 44.1kHz; t_frames ≈ 4540. Building a synthetic carrier
//! of that size and feeding it through `model::run` should reproduce
//! the memory blowup without needing the actual MP3.
//!
//! Usage:
//!   cargo run --release -p provcheck-watermark --example memory_check -- [t_frames]
//!
//! Defaults to 4540 frames (≈ 211s of audio at HOP=2048, SR=44100).

use provcheck_watermark::model;

const FREQ_BINS: usize = 2049;

fn main() -> anyhow::Result<()> {
    let t_frames: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(4540);

    let audio_sec = t_frames as f32 * 2048.0 / 44100.0;
    let carrier_bytes = FREQ_BINS * t_frames * 4;
    eprintln!("== memory_check ==");
    eprintln!("t_frames:            {t_frames}");
    eprintln!("equivalent audio:    {audio_sec:.1} s");
    eprintln!("carrier (legit):     {} MB", carrier_bytes / 1024 / 1024);

    // Build a synthetic carrier with small positive magnitudes. The
    // actual values don't matter for memory profiling — only the
    // shape does. Use a deterministic pattern so reruns are
    // identical.
    let mut carrier = Vec::with_capacity(FREQ_BINS * t_frames);
    for i in 0..(FREQ_BINS * t_frames) {
        carrier.push(((i % 256) as f32) * 0.01);
    }

    eprintln!("running model::run …");
    let start = std::time::Instant::now();
    let logits = model::run(&carrier, t_frames)?;
    let elapsed = start.elapsed();

    eprintln!("logits len:          {}", logits.len());
    eprintln!("elapsed:             {:.2} s", elapsed.as_secs_f64());
    eprintln!();
    eprintln!("If this process completed under, say, 2 GB RSS,");
    eprintln!("the OOM hypothesis is wrong. If it exploded past");
    eprintln!("4-5 GB on a 211s-equivalent input, that's the bug.");
    Ok(())
}
