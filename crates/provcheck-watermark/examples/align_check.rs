//! One-shot alignment finder. Reads two decode_dump binaries
//! (rust + python), the audio_pre_rescale arrays only, and finds
//! the integer sample shift `k` that minimises the L2 difference
//! between `rust[k..k+n]` and `python[0..n]` (where n is set to
//! python's length, bounded by what's available on the rust side).
//!
//! If the audio is offset by encoder-delay samples (LAME priming),
//! this prints the offset directly. After the fix lands, the best
//! shift should be 0.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use serde::Deserialize;

#[derive(Deserialize)]
struct Dump {
    binary_dump_path: String,
    binary_offsets: BinaryOffsets,
}

#[derive(Deserialize)]
struct BinaryOffsets {
    audio_pre_rescale: ArraySpec,
}

#[derive(Deserialize)]
struct ArraySpec {
    offset: u64,
    count: usize,
}

fn read_f32(path: &str, spec: &ArraySpec) -> anyhow::Result<Vec<f32>> {
    let mut f = File::open(path)?;
    f.seek(SeekFrom::Start(spec.offset))?;
    let mut buf = vec![0u8; spec.count * 4];
    f.read_exact(&mut buf)?;
    Ok(buf
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect())
}

fn rmsd(a: &[f32], b: &[f32]) -> f64 {
    let n = a.len().min(b.len());
    let mut sumsq = 0.0f64;
    for i in 0..n {
        let d = (a[i] - b[i]) as f64;
        sumsq += d * d;
    }
    (sumsq / n as f64).sqrt()
}

fn main() -> anyhow::Result<()> {
    let rust_json = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: align_check <rust.json> <python.json>"))?;
    let py_json = std::env::args()
        .nth(2)
        .ok_or_else(|| anyhow::anyhow!("usage: align_check <rust.json> <python.json>"))?;

    let rust: Dump = serde_json::from_str(&std::fs::read_to_string(&rust_json)?)?;
    let py: Dump = serde_json::from_str(&std::fs::read_to_string(&py_json)?)?;

    let r_audio = read_f32(
        &rust.binary_dump_path,
        &rust.binary_offsets.audio_pre_rescale,
    )?;
    let p_audio = read_f32(&py.binary_dump_path, &py.binary_offsets.audio_pre_rescale)?;

    println!("rust len = {}", r_audio.len());
    println!("py len   = {}", p_audio.len());
    println!(
        "diff     = {} (rust - py)",
        r_audio.len() as i64 - p_audio.len() as i64
    );
    println!();

    let max_shift = (r_audio.len() as i64 - p_audio.len() as i64).clamp(0, 8_192) as usize;
    if max_shift == 0 {
        println!("rust is not longer than python — no positive-shift to try.");
        return Ok(());
    }

    println!("Searching shifts k ∈ [0, {max_shift}] (rust[k..k+n] vs python[..n])");
    println!();
    println!("  shift     RMSD          L∞");

    let n = p_audio.len();
    let mut best_k = 0usize;
    let mut best_rmsd = f64::INFINITY;
    for k in 0..=max_shift {
        if k + n > r_audio.len() {
            break;
        }
        let slice = &r_audio[k..k + n];
        let r = rmsd(slice, &p_audio);
        if r < best_rmsd {
            best_rmsd = r;
            best_k = k;
        }
        if k % 64 == 0 || k == max_shift {
            let l_inf = slice
                .iter()
                .zip(p_audio.iter())
                .map(|(a, b)| (a - b).abs())
                .fold(0.0f32, f32::max);
            println!("  {k:>5}   {r:.4e}    {l_inf:.4e}");
        }
    }

    println!();
    println!("BEST: shift = {best_k}, RMSD = {best_rmsd:.4e}");

    if best_rmsd < 1e-4 {
        println!();
        println!("=> Audio aligns near-perfectly at shift {best_k}.");
        println!("   Hypothesis: symphonia's MP3 path is yielding the LAME");
        println!("   encoder-delay samples (priming) that librosa trims.");
        println!("   Fix: read track.codec_params.delay and skip that many");
        println!("   samples from the start of the decoded mono buffer (and");
        println!("   trim track.codec_params.padding from the end).");
    } else {
        println!();
        println!("=> No clean integer-sample alignment. Misalignment is not");
        println!("   a simple LAME delay; could be channel-mix convention,");
        println!("   resample artefact, or codec-level numerical drift.");
    }

    Ok(())
}
