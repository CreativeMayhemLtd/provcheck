//! Empirically check each step of the silentcipher decoder
//! against what the expert's ranked debugging path says they
//! should be on a known-marked file.
//!
//! Print:
//!   1. mean(y²) before VCTK rescale, after VCTK rescale
//!      (after value should be ~0.0028372)
//!   2. carrier shape + spot-check values
//!   3. logits stats — min/max/mean per dim
//!   4. argmax predictions over first 3 tiles (63 frames)
//!   5. mode_per_pos and whether terminator (0) is present
//!
//! Run:
//!   cargo run --release -p provcheck-watermark --example decode_inspect -- <path>

use std::path::PathBuf;

use provcheck_watermark::audio;
use provcheck_watermark::model;
use provcheck_watermark::stft;

const FREQ_BINS: usize = 2049;
const MESSAGE_DIM: usize = 5;
const MESSAGE_LEN: usize = 21;
const VCTK_TARGET: f32 = 0.002_837_200_8;

fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: decode_inspect <audio-file>"))?;
    let path = PathBuf::from(path);

    println!("== decode_inspect: {} ==", path.display());
    println!();

    // 1. Audio decode
    let waveform = audio::decode_to_mono_44k1(&path)?;
    println!("[audio]");
    println!("  samples:       {}", waveform.len());
    println!("  duration:      {:.2}s", waveform.len() as f32 / 44_100.0);
    println!(
        "  abs-max:       {:.6}",
        waveform.iter().fold(0.0f32, |a, &s| a.max(s.abs()))
    );

    // 2. mean(y²) BEFORE rescale — this happens inside
    //    waveform_to_carrier, but we replicate it here so we can
    //    see the input energy independently.
    let mean_sq_pre: f32 = waveform.iter().map(|s| s * s).sum::<f32>() / waveform.len() as f32;
    println!("  mean(y²) pre:  {mean_sq_pre:.10}");
    println!(
        "  RMS pre:       {:.4} dBFS",
        20.0 * mean_sq_pre.sqrt().log10()
    );

    // What does the rescale produce?
    let scale = (VCTK_TARGET / mean_sq_pre).sqrt();
    let mean_sq_post: f32 = waveform
        .iter()
        .map(|s| (s * scale) * (s * scale))
        .sum::<f32>()
        / waveform.len() as f32;
    println!("  scale applied: {scale:.6}");
    println!("  mean(y²) post: {mean_sq_post:.10}  (target {VCTK_TARGET:.10})");
    let energy_ratio = mean_sq_post / VCTK_TARGET;
    println!(
        "  energy ratio:  {energy_ratio:.4}  {}",
        if (energy_ratio - 1.0).abs() < 1e-3 {
            "OK"
        } else {
            "BAD"
        }
    );
    println!();

    // 3. STFT → carrier
    let (carrier, t_frames) = stft::waveform_to_carrier(&waveform)?;
    println!("[carrier]");
    println!("  shape:         [1, 1, {FREQ_BINS}, {t_frames}]");
    let n_tiles_full = t_frames / MESSAGE_LEN;
    println!("  t_frames:      {t_frames} ({n_tiles_full} tiles)");
    // Spot-check: carrier statistics over the spectrogram.
    let carrier_mean: f32 = carrier.iter().sum::<f32>() / carrier.len() as f32;
    let carrier_max: f32 = carrier.iter().fold(0.0f32, |a, &v| a.max(v));
    let nonzero = carrier.iter().filter(|&&v| v > 1e-9).count();
    println!("  mean mag:      {carrier_mean:.6}");
    println!("  max mag:       {carrier_max:.4}");
    println!(
        "  nonzero bins:  {} / {} ({:.1}%)",
        nonzero,
        carrier.len(),
        100.0 * nonzero as f32 / carrier.len() as f32
    );
    println!();

    // 4. Inference
    let logits = model::run(&carrier, t_frames)?;
    println!("[logits]");
    println!("  layout:        [{MESSAGE_DIM}, {t_frames}] (flat = dim * T + t)");

    // Per-dim stats across all time frames.
    for d in 0..MESSAGE_DIM {
        let mut min = f32::INFINITY;
        let mut max = f32::NEG_INFINITY;
        let mut sum = 0.0f32;
        for t in 0..t_frames {
            let v = logits[d * t_frames + t];
            min = min.min(v);
            max = max.max(v);
            sum += v;
        }
        let mean = sum / t_frames as f32;
        println!("  dim {d}: min {min:8.3}  mean {mean:8.3}  max {max:8.3}");
    }
    println!();

    // 5. Argmax over first 3 tiles + per-position mode + terminator hunt.
    let inspect_tiles = 3.min(n_tiles_full);
    println!("[argmax — first {inspect_tiles} tiles]");
    let mut argmax = Vec::with_capacity(inspect_tiles * MESSAGE_LEN);
    for t in 0..inspect_tiles * MESSAGE_LEN {
        let mut best_d = 0;
        let mut best_v = logits[t];
        for d in 1..MESSAGE_DIM {
            let v = logits[d * t_frames + t];
            if v > best_v {
                best_v = v;
                best_d = d;
            }
        }
        argmax.push(best_d as u8);
    }
    for tile in 0..inspect_tiles {
        let row: Vec<String> = (0..MESSAGE_LEN)
            .map(|p| format!("{}", argmax[tile * MESSAGE_LEN + p]))
            .collect();
        println!("  tile {tile}: [{}]", row.join(" "));
    }

    // Count occurrences of each symbol overall — should not be
    // all 1..=4 (i.e. NEVER 0).
    let mut overall_counts = [0u32; MESSAGE_DIM];
    for t in 0..t_frames {
        let mut best_d = 0;
        let mut best_v = logits[t];
        for d in 1..MESSAGE_DIM {
            let v = logits[d * t_frames + t];
            if v > best_v {
                best_v = v;
                best_d = d;
            }
        }
        overall_counts[best_d] += 1;
    }
    println!();
    println!("[symbol frequency across all {t_frames} time frames]");
    for (d, &count) in overall_counts.iter().enumerate() {
        println!(
            "  symbol {d}: {:6} ({:5.1}%)",
            count,
            100.0 * count as f32 / t_frames as f32
        );
    }

    // Per-position mode across all tiles.
    let n_tiles = t_frames / MESSAGE_LEN;
    let mut full_argmax = Vec::with_capacity(t_frames);
    for t in 0..t_frames {
        let mut best_d = 0;
        let mut best_v = logits[t];
        for d in 1..MESSAGE_DIM {
            let v = logits[d * t_frames + t];
            if v > best_v {
                best_v = v;
                best_d = d;
            }
        }
        full_argmax.push(best_d as u8);
    }
    let mut mode_per_pos = [0u8; MESSAGE_LEN];
    let mut mode_count_per_pos = [0u32; MESSAGE_LEN];
    for p in 0..MESSAGE_LEN {
        let mut counts = [0u32; MESSAGE_DIM];
        for tile in 0..n_tiles {
            let v = full_argmax[tile * MESSAGE_LEN + p] as usize;
            counts[v] += 1;
        }
        let mut best = 0u8;
        let mut best_count = counts[0];
        for (v, &count) in counts.iter().enumerate().skip(1) {
            if count > best_count {
                best_count = count;
                best = v as u8;
            }
        }
        mode_per_pos[p] = best;
        mode_count_per_pos[p] = best_count;
    }
    println!();
    println!("[mode_per_pos across all {n_tiles} tiles]");
    let mode_row: Vec<String> = (0..MESSAGE_LEN)
        .map(|p| format!("{}", mode_per_pos[p]))
        .collect();
    println!("  symbols: [{}]", mode_row.join(" "));
    let conf_row: Vec<String> = (0..MESSAGE_LEN)
        .map(|p| {
            format!(
                "{:.0}%",
                100.0 * mode_count_per_pos[p] as f32 / n_tiles as f32
            )
        })
        .collect();
    println!("  conf:    [{}]", conf_row.join(" "));

    let term_pos = mode_per_pos.iter().position(|&s| s == 0);
    println!();
    match term_pos {
        Some(p) => println!("TERMINATOR FOUND at position {p}"),
        None => println!("TERMINATOR ABSENT  ← this is the sentinel cause"),
    }

    Ok(())
}
