//! Per-stage intermediate-value dumper for cross-implementation
//! comparison with the silentcipher Python reference.
//!
//! The Rust detector and a Python reference of the same model
//! produce different confidence on the same file (Rust ~24%,
//! Python ~95% on a known-marked voices-mixdown MP3). The pipeline
//! is structurally correct: the right message is recovered at
//! 14/21 positions. The gap is sub-LSB numerical accumulation
//! somewhere — either MP3 decoder, FFT precision, or window
//! values. To pin which stage diverges, we dump every
//! intermediate value to disk and the user diffs against a
//! Python dump of the same intermediates on the same file.
//!
//! Output: two files next to the input.
//!
//!   <input>.rust.json   — small metadata + summary stats
//!   <input>.rust.bin    — packed f32 dump:
//!       * audio samples (post-decode, pre-rescale): N_audio f32
//!       * audio samples (post-rescale):             N_audio f32
//!       * carrier (full STFT magnitudes):           2049 * T f32
//!       * logits (decoder output):                  5    * T f32
//!     followed by u8:
//!       * argmax sequence:                          T u8
//!       * mode_per_pos:                             21 u8
//!       * payload symbols (post-cyclic-roll):       20 u8
//!       * payload bytes:                            5  u8
//!
//! The Python-side comparison tool reads the .rust.json for
//! offsets and shapes, then reads the .rust.bin at those offsets
//! and compares against its own analogous arrays. The first
//! stage that diverges meaningfully (above f32 round-off) is the
//! bug.
//!
//! Run:
//!   cargo run --release -p provcheck-watermark --example decode_dump -- <path>

use std::fs::File;
use std::io::{BufWriter, Write};
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
        .ok_or_else(|| anyhow::anyhow!("usage: decode_dump <audio-file>"))?;
    let in_path = PathBuf::from(&path);
    let json_path = in_path.with_extension("rust.json");
    let bin_path = in_path.with_extension("rust.bin");

    eprintln!("== decode_dump: {} ==", in_path.display());

    // ---- decode + VCTK rescale ----
    let waveform_pre = audio::decode_to_mono_44k1(&in_path)?;
    let n_audio = waveform_pre.len();
    let mean_sq_pre: f32 =
        waveform_pre.iter().map(|s| s * s).sum::<f32>() / n_audio as f32;
    let scale = (VCTK_TARGET / mean_sq_pre).sqrt();
    let waveform_post: Vec<f32> = waveform_pre.iter().map(|s| s * scale).collect();
    let mean_sq_post: f32 =
        waveform_post.iter().map(|s| s * s).sum::<f32>() / n_audio as f32;

    // ---- STFT ----
    // We need the carrier on the POST-RESCALE waveform — that's
    // what waveform_to_carrier does internally. Re-run here so
    // the dumped audio (post-rescale) and the dumped carrier are
    // from consistent stages.
    let (carrier, t_frames) = stft::waveform_to_carrier(&waveform_pre)?;

    // ---- Inference ----
    let logits = model::run(&carrier, t_frames)?;

    // ---- Backend decode (mirror decode.rs logic so we can dump
    //      every intermediate). ----
    let mut argmax = Vec::with_capacity(t_frames);
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
        argmax.push(best_d as u8);
    }
    let n_tiles = t_frames / MESSAGE_LEN;
    let usable = n_tiles * MESSAGE_LEN;

    let mut mode_per_pos = [0u8; MESSAGE_LEN];
    for p in 0..MESSAGE_LEN {
        let mut counts = [0u32; MESSAGE_DIM];
        for tile in 0..n_tiles {
            counts[argmax[tile * MESSAGE_LEN + p] as usize] += 1;
        }
        let mut best = 0u8;
        let mut best_count = counts[0];
        for v in 1..MESSAGE_DIM {
            if counts[v] > best_count {
                best_count = counts[v];
                best = v as u8;
            }
        }
        mode_per_pos[p] = best;
    }

    let term_pos = mode_per_pos.iter().position(|&s| s == 0);
    let mut payload_symbols = [0u8; 20];
    let mut payload_bytes = [0u8; 5];
    let mut decode_ok = false;
    if let Some(end_char) = term_pos {
        let mut roll_idx = 0;
        for in_idx in (end_char + 1..MESSAGE_LEN).chain(0..end_char) {
            payload_symbols[roll_idx] = mode_per_pos[in_idx];
            roll_idx += 1;
        }
        let mut any_zero = false;
        for s in payload_symbols.iter_mut() {
            if *s == 0 {
                any_zero = true;
                break;
            }
            *s -= 1;
        }
        if !any_zero {
            for byte_idx in 0..5 {
                let base = byte_idx * 4;
                let a = payload_symbols[base];
                let b = payload_symbols[base + 1];
                let c = payload_symbols[base + 2];
                let d = payload_symbols[base + 3];
                payload_bytes[byte_idx] = (a << 6) | (b << 4) | (c << 2) | d;
            }
            decode_ok = true;
        }
    }
    let mut matches = 0u32;
    if usable > 0 {
        for tile in 0..n_tiles {
            for p in 0..MESSAGE_LEN {
                if argmax[tile * MESSAGE_LEN + p] == mode_per_pos[p] {
                    matches += 1;
                }
            }
        }
    }
    let confidence = if usable > 0 {
        matches as f32 / usable as f32
    } else {
        0.0
    };

    // ---- Write the binary dump ----
    let mut w = BufWriter::new(File::create(&bin_path)?);
    let mut offset: u64 = 0;

    let off_audio_pre = offset;
    for s in &waveform_pre {
        w.write_all(&s.to_le_bytes())?;
    }
    offset += (n_audio * 4) as u64;

    let off_audio_post = offset;
    for s in &waveform_post {
        w.write_all(&s.to_le_bytes())?;
    }
    offset += (n_audio * 4) as u64;

    let off_carrier = offset;
    for s in &carrier {
        w.write_all(&s.to_le_bytes())?;
    }
    offset += (carrier.len() * 4) as u64;

    let off_logits = offset;
    for s in &logits {
        w.write_all(&s.to_le_bytes())?;
    }
    offset += (logits.len() * 4) as u64;

    let off_argmax = offset;
    w.write_all(&argmax)?;
    offset += t_frames as u64;

    let off_mode_per_pos = offset;
    w.write_all(&mode_per_pos)?;
    offset += MESSAGE_LEN as u64;

    let off_payload_symbols = offset;
    w.write_all(&payload_symbols)?;
    offset += 20;

    let off_payload_bytes = offset;
    w.write_all(&payload_bytes)?;
    offset += 5;

    w.flush()?;
    let total_bytes = offset;

    // ---- Write the metadata JSON ----
    let json = serde_json::json!({
        "implementation": "provcheck-watermark v0.3.2 Rust port",
        "input_path": in_path.to_string_lossy(),
        "binary_dump_path": bin_path.to_string_lossy(),
        "binary_dump_bytes": total_bytes,
        "audio": {
            "n_samples": n_audio,
            "sample_rate": 44_100,
            "duration_sec": n_audio as f32 / 44_100.0,
            "mean_sq_pre_rescale":  mean_sq_pre,
            "mean_sq_post_rescale": mean_sq_post,
            "vctk_target_energy":   VCTK_TARGET,
            "vctk_energy_ratio":    mean_sq_post / VCTK_TARGET,
            "scale_factor":         scale,
        },
        "carrier": {
            "shape":    [1, 1, FREQ_BINS, t_frames],
            "layout":   "row-major, flat index = bin * T + t",
            "n_freq":   FREQ_BINS,
            "n_tiles_full":    t_frames / MESSAGE_LEN,
            "n_frames": t_frames,
        },
        "logits": {
            "shape":  [1, 1, MESSAGE_DIM, t_frames],
            "layout": "row-major, flat index = dim * T + t",
        },
        "decode": {
            "n_tiles":         n_tiles,
            "terminator_pos":  term_pos,
            "ok":              decode_ok,
            "confidence":      confidence,
            "payload_hex":     format!("{:02x?}", payload_bytes),
        },
        "binary_offsets": {
            "audio_pre_rescale":  { "offset": off_audio_pre,      "dtype": "f32_le", "count": n_audio       },
            "audio_post_rescale": { "offset": off_audio_post,     "dtype": "f32_le", "count": n_audio       },
            "carrier":            { "offset": off_carrier,        "dtype": "f32_le", "count": carrier.len() },
            "logits":             { "offset": off_logits,         "dtype": "f32_le", "count": logits.len()  },
            "argmax":             { "offset": off_argmax,         "dtype": "u8",     "count": t_frames      },
            "mode_per_pos":       { "offset": off_mode_per_pos,   "dtype": "u8",     "count": MESSAGE_LEN   },
            "payload_symbols":    { "offset": off_payload_symbols,"dtype": "u8",     "count": 20            },
            "payload_bytes":      { "offset": off_payload_bytes,  "dtype": "u8",     "count": 5             },
        }
    });
    std::fs::write(&json_path, serde_json::to_string_pretty(&json)?)?;

    eprintln!("wrote {}", json_path.display());
    eprintln!("wrote {} ({:.1} MiB)",
        bin_path.display(),
        total_bytes as f64 / (1024.0 * 1024.0));

    eprintln!();
    eprintln!("Summary:");
    eprintln!("  n_samples:     {n_audio}");
    eprintln!("  vctk ratio:    {:.4}", mean_sq_post / VCTK_TARGET);
    eprintln!("  t_frames:      {t_frames} ({n_tiles} tiles)");
    eprintln!(
        "  terminator:    {}",
        match term_pos { Some(p) => format!("found at {p}"), None => "NOT FOUND".into() }
    );
    eprintln!("  decode_ok:     {decode_ok}");
    eprintln!("  confidence:    {confidence:.4}");
    eprintln!("  payload:       {:02x?}", payload_bytes);

    Ok(())
}
