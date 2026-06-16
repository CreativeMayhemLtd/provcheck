//! Diff two `decode_dump` outputs and report which pipeline
//! stage first diverges meaningfully.
//!
//! The dump format (see decode_dump.rs):
//!   <stem>.<impl>.json  — metadata + binary offsets
//!   <stem>.<impl>.bin   — packed f32 + u8 arrays at those offsets
//!
//! Usage:
//!   cargo run --release -p provcheck-watermark --example decode_diff -- \
//!       <stem>.rust.json <stem>.python.json
//!
//! Reports per-stage L∞ (max abs diff), L2 (RMS diff), and
//! whether the diff is within reasonable f32 round-off tolerance.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use serde::Deserialize;

// Tolerances. f32 round-off is around 1e-7 relative for normal
// arithmetic; FFT accumulates more error proportional to log2(N).
// For N_FFT=4096, log2(N) ≈ 12, so we'd expect ~1e-6 relative
// error. Set thresholds generously.
const TOL_AUDIO:   f32 = 1e-5;  // post-decode samples differ on this scale = different MP3 decoder
const TOL_CARRIER: f32 = 1e-3;  // STFT magnitudes; depends on N_FFT precision
const TOL_LOGITS:  f32 = 1e-1;  // model output; neural networks accumulate error

#[derive(Deserialize)]
struct Dump {
    binary_dump_path: String,
    binary_offsets: BinaryOffsets,
    #[serde(default)]
    carrier: CarrierMeta,
    #[serde(default)]
    logits: LogitsMeta,
}

#[derive(Deserialize, Default)]
struct CarrierMeta {
    #[serde(default = "default_freq_bins")]
    n_freq: usize,
    #[serde(default)]
    n_frames: usize,
}

#[derive(Deserialize, Default)]
struct LogitsMeta {
    #[serde(default)]
    shape: Vec<usize>,
}

fn default_freq_bins() -> usize {
    2049
}

#[derive(Deserialize)]
struct BinaryOffsets {
    audio_pre_rescale:  ArraySpec,
    audio_post_rescale: ArraySpec,
    carrier:            ArraySpec,
    logits:             ArraySpec,
    argmax:             ArraySpec,
    mode_per_pos:       ArraySpec,
    payload_symbols:    ArraySpec,
    payload_bytes:      ArraySpec,
}

#[derive(Deserialize)]
struct ArraySpec {
    offset: u64,
    dtype:  String,
    count:  usize,
}

fn read_f32(f: &mut File, spec: &ArraySpec) -> anyhow::Result<Vec<f32>> {
    if spec.dtype != "f32_le" {
        anyhow::bail!("expected f32_le, got {}", spec.dtype);
    }
    f.seek(SeekFrom::Start(spec.offset))?;
    let mut buf = vec![0u8; spec.count * 4];
    f.read_exact(&mut buf)?;
    Ok(buf
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect())
}

fn read_u8(f: &mut File, spec: &ArraySpec) -> anyhow::Result<Vec<u8>> {
    if spec.dtype != "u8" {
        anyhow::bail!("expected u8, got {}", spec.dtype);
    }
    f.seek(SeekFrom::Start(spec.offset))?;
    let mut buf = vec![0u8; spec.count];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

struct Stats {
    n: usize,
    l_inf: f32,
    l2_rms: f32,
    first_div_idx: Option<usize>,
}

fn stats_f32(a: &[f32], b: &[f32], tol: f32) -> Stats {
    let n = a.len().min(b.len());
    let mut l_inf = 0.0f32;
    let mut sumsq = 0.0f64;
    let mut first_div_idx = None;
    for i in 0..n {
        let d = (a[i] - b[i]).abs();
        if d > l_inf {
            l_inf = d;
        }
        sumsq += (d as f64) * (d as f64);
        if first_div_idx.is_none() && d > tol {
            first_div_idx = Some(i);
        }
    }
    Stats {
        n,
        l_inf,
        l2_rms: (sumsq / n as f64).sqrt() as f32,
        first_div_idx,
    }
}

fn report(name: &str, stats: &Stats, tol: f32) {
    let status = if stats.l_inf <= tol { "OK" } else { "DIFF" };
    println!(
        "  {name:<24} n={:>10}  L∞={:.4e}  RMS={:.4e}  tol={:.0e}  {status}",
        stats.n, stats.l_inf, stats.l2_rms, tol
    );
    if let Some(i) = stats.first_div_idx {
        println!("    first divergence at index {i}");
    }
}

/// For a tensor laid out as `outer * inner_count + t`, compute the
/// RMS difference for each `outer` slice across all `inner_count`
/// time-frames and return the top-N worst-diverging outer indices
/// alongside their RMS, sorted descending.
fn worst_by_outer(
    a: &[f32],
    b: &[f32],
    outer: usize,
    inner: usize,
    top: usize,
) -> Vec<(usize, f32)> {
    let n = a.len().min(b.len());
    if n == 0 || outer * inner > n {
        return Vec::new();
    }
    let mut per_outer: Vec<(usize, f32)> = (0..outer)
        .map(|o| {
            let mut sumsq = 0.0f64;
            for t in 0..inner {
                let d = (a[o * inner + t] - b[o * inner + t]) as f64;
                sumsq += d * d;
            }
            (o, (sumsq / inner as f64).sqrt() as f32)
        })
        .collect();
    per_outer.sort_by(|(_, x), (_, y)| y.partial_cmp(x).unwrap_or(std::cmp::Ordering::Equal));
    per_outer.into_iter().take(top).collect()
}

/// Same shape, but report the worst inner-index (time-frame),
/// computed across all outer slices for that one t.
fn worst_by_inner(
    a: &[f32],
    b: &[f32],
    outer: usize,
    inner: usize,
    top: usize,
) -> Vec<(usize, f32)> {
    let n = a.len().min(b.len());
    if n == 0 || outer * inner > n {
        return Vec::new();
    }
    let mut per_inner: Vec<(usize, f32)> = (0..inner)
        .map(|t| {
            let mut sumsq = 0.0f64;
            for o in 0..outer {
                let d = (a[o * inner + t] - b[o * inner + t]) as f64;
                sumsq += d * d;
            }
            (t, (sumsq / outer as f64).sqrt() as f32)
        })
        .collect();
    per_inner.sort_by(|(_, x), (_, y)| y.partial_cmp(x).unwrap_or(std::cmp::Ordering::Equal));
    per_inner.into_iter().take(top).collect()
}

fn print_top(label: &str, worst: &[(usize, f32)]) {
    if worst.is_empty() {
        return;
    }
    let line: Vec<String> = worst
        .iter()
        .map(|(i, v)| format!("[{i}]={v:.3e}"))
        .collect();
    println!("    {label:<22} {}", line.join("  "));
}

fn report_u8(name: &str, a: &[u8], b: &[u8]) {
    let n = a.len().min(b.len());
    let mut diff = 0usize;
    let mut first_div = None;
    for i in 0..n {
        if a[i] != b[i] {
            diff += 1;
            if first_div.is_none() {
                first_div = Some(i);
            }
        }
    }
    let status = if diff == 0 { "OK" } else { "DIFF" };
    println!(
        "  {name:<24} n={n:>10}  diff_positions={diff}  ({:.1}%)  {status}",
        100.0 * diff as f32 / n as f32
    );
    if let Some(i) = first_div {
        println!("    first divergence at index {i}: rust={} python={}", a[i], b[i]);
    }
}

fn main() -> anyhow::Result<()> {
    let rust_json = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: decode_diff <rust.json> <python.json>"))?;
    let py_json = std::env::args()
        .nth(2)
        .ok_or_else(|| anyhow::anyhow!("usage: decode_diff <rust.json> <python.json>"))?;

    let rust: Dump = serde_json::from_str(&std::fs::read_to_string(&rust_json)?)?;
    let py: Dump = serde_json::from_str(&std::fs::read_to_string(&py_json)?)?;

    let mut rf = File::open(&rust.binary_dump_path)?;
    let mut pf = File::open(&py.binary_dump_path)?;

    println!("== decode_diff ==");
    println!("rust: {}", rust_json);
    println!("py:   {}", py_json);
    println!();

    // Stage 1: audio decoder output.
    let r_audio = read_f32(&mut rf, &rust.binary_offsets.audio_pre_rescale)?;
    let p_audio = read_f32(&mut pf, &py.binary_offsets.audio_pre_rescale)?;
    let s = stats_f32(&r_audio, &p_audio, TOL_AUDIO);
    println!("[STAGE 1: audio decode]");
    report("audio_pre_rescale", &s, TOL_AUDIO);

    // Stage 2: post-rescale audio.
    let r_audio = read_f32(&mut rf, &rust.binary_offsets.audio_post_rescale)?;
    let p_audio = read_f32(&mut pf, &py.binary_offsets.audio_post_rescale)?;
    let s = stats_f32(&r_audio, &p_audio, TOL_AUDIO);
    println!();
    println!("[STAGE 2: VCTK rescale]");
    report("audio_post_rescale", &s, TOL_AUDIO);

    // Stage 3: carrier (STFT output).
    let r_carrier = read_f32(&mut rf, &rust.binary_offsets.carrier)?;
    let p_carrier = read_f32(&mut pf, &py.binary_offsets.carrier)?;
    let s = stats_f32(&r_carrier, &p_carrier, TOL_CARRIER);
    println!();
    println!("[STAGE 3: STFT carrier]");
    report("carrier (full)", &s, TOL_CARRIER);
    // Carrier layout: bin * T + t. Use the dump that reports
    // n_freq + n_frames; both sides should agree, but if they
    // disagree, prefer the Rust side and report.
    let n_freq = rust.carrier.n_freq.max(py.carrier.n_freq).max(default_freq_bins());
    let t_frames_rust = rust.carrier.n_frames;
    let t_frames_py = py.carrier.n_frames;
    if t_frames_rust != t_frames_py && t_frames_rust != 0 && t_frames_py != 0 {
        println!(
            "    NOTE n_frames disagree: rust={t_frames_rust} python={t_frames_py} \
             — pipeline framing is misaligned, expect downstream noise"
        );
    }
    let t = t_frames_rust.min(t_frames_py).max(1);
    if s.l_inf > TOL_CARRIER {
        let worst_bins = worst_by_outer(&r_carrier, &p_carrier, n_freq, t, 5);
        let worst_times = worst_by_inner(&r_carrier, &p_carrier, n_freq, t, 5);
        println!("    (worst-diverging bins/frames — index=RMS)");
        print_top("worst freq bins:", &worst_bins);
        print_top("worst time frames:", &worst_times);
    }

    // Stage 4: logits (model output).
    let r_logits = read_f32(&mut rf, &rust.binary_offsets.logits)?;
    let p_logits = read_f32(&mut pf, &py.binary_offsets.logits)?;
    let s = stats_f32(&r_logits, &p_logits, TOL_LOGITS);
    println!();
    println!("[STAGE 4: model logits]");
    report("logits (full)", &s, TOL_LOGITS);
    if s.l_inf > TOL_LOGITS {
        // Logits laid out as dim * T + t with MESSAGE_DIM=5 dims.
        let message_dim = rust
            .logits
            .shape
            .get(2)
            .copied()
            .unwrap_or(5);
        let worst_dims = worst_by_outer(&r_logits, &p_logits, message_dim, t, message_dim);
        let worst_times = worst_by_inner(&r_logits, &p_logits, message_dim, t, 5);
        println!("    (per-dim and worst-frame breakdown)");
        print_top("per dim RMS:", &worst_dims);
        print_top("worst time frames:", &worst_times);
    }

    // Stage 5+: argmax + mode + payload (categorical comparisons).
    let r_argmax = read_u8(&mut rf, &rust.binary_offsets.argmax)?;
    let p_argmax = read_u8(&mut pf, &py.binary_offsets.argmax)?;
    println!();
    println!("[STAGE 5: argmax + decode]");
    report_u8("argmax", &r_argmax, &p_argmax);

    let r_mode = read_u8(&mut rf, &rust.binary_offsets.mode_per_pos)?;
    let p_mode = read_u8(&mut pf, &py.binary_offsets.mode_per_pos)?;
    report_u8("mode_per_pos", &r_mode, &p_mode);

    let r_sym = read_u8(&mut rf, &rust.binary_offsets.payload_symbols)?;
    let p_sym = read_u8(&mut pf, &py.binary_offsets.payload_symbols)?;
    report_u8("payload_symbols", &r_sym, &p_sym);

    let r_bytes = read_u8(&mut rf, &rust.binary_offsets.payload_bytes)?;
    let p_bytes = read_u8(&mut pf, &py.binary_offsets.payload_bytes)?;
    report_u8("payload_bytes", &r_bytes, &p_bytes);
    println!();
    println!("  rust payload: {:02x?}", r_bytes);
    println!("  py payload:   {:02x?}", p_bytes);

    Ok(())
}
