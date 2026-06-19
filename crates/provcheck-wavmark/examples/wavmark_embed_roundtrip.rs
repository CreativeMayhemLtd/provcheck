//! End-to-end embed → detect roundtrip on real audio.
//!
//! Usage:
//!   cargo run --release -p provcheck-wavmark --example wavmark_embed_roundtrip
//!
//! Pulls a real audio sample (defaults to examples/rAIdio.bot-sample.mp3),
//! embeds the Doomscroll brand, writes a WAV, then runs the detector on
//! the WAV and confirms the brand is recovered.

use std::path::{Path, PathBuf};
use std::time::Instant;

use provcheck_wavmark::{audio, encode, registry};

fn write_wav(path: &Path, samples: &[f32], sample_rate: u32) -> anyhow::Result<()> {
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate,
        bits_per_sample: 32,
        sample_format: hound::SampleFormat::Float,
    };
    let mut writer = hound::WavWriter::create(path, spec)?;
    for s in samples {
        writer.write_sample(*s)?;
    }
    writer.finalize()?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let input = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "examples/rAIdio.bot-sample.mp3".to_string());
    let input = PathBuf::from(input);
    println!("== wavmark_embed_roundtrip ==");
    println!("input: {}", input.display());

    let t0 = Instant::now();
    let waveform = audio::decode_to_mono_16k(&input)?;
    println!(
        "  decoded {} samples ({:.2} s @ 16 kHz mono) in {:.2?}",
        waveform.len(),
        waveform.len() as f32 / audio::SAMPLE_RATE as f32,
        t0.elapsed()
    );

    let brand_id = registry::BRAND_DOOMSCROLL;
    println!("  embedding brand id 0x{:02x} (Doomscroll)", brand_id);
    let t1 = Instant::now();
    let marked = encode::embed(&waveform, brand_id)?;
    println!("  embed wall-clock: {:.2?}", t1.elapsed());

    // Sanity stats on the marked-vs-input delta.
    let max_diff = marked
        .iter()
        .zip(waveform.iter())
        .map(|(a, b)| (a - b).abs())
        .fold(0.0_f32, f32::max);
    let rms_diff = (marked
        .iter()
        .zip(waveform.iter())
        .map(|(a, b)| {
            let d = a - b;
            (d * d) as f64
        })
        .sum::<f64>()
        / marked.len() as f64)
        .sqrt();
    let in_rms =
        (waveform.iter().map(|s| (s * s) as f64).sum::<f64>() / waveform.len() as f64).sqrt();
    let sdr_db = 20.0 * (in_rms / rms_diff.max(1e-30)).log10();
    println!(
        "  L∞ marked-vs-input = {max_diff:.6}  RMS diff = {rms_diff:.6}  SDR = {sdr_db:.1} dB"
    );

    let out_path = std::env::temp_dir().join("provcheck-wavmark-marked.wav");
    write_wav(&out_path, &marked, audio::SAMPLE_RATE)?;
    println!("  wrote: {}", out_path.display());

    let t2 = Instant::now();
    let result = provcheck_wavmark::detect(&out_path)?;
    println!("  detect wall-clock: {:.2?}", t2.elapsed());
    println!();
    println!("RESULT:");
    println!("  detected:   {}", result.detected);
    println!("  confidence: {:.4}", result.confidence);
    println!("  brand:      {:?}", result.brand);
    if let Some(p) = &result.payload {
        println!(
            "  payload:    {}",
            p.iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join("")
        );
    }
    if let Some(regions) = &result.marked_regions {
        println!("  marked_regions: {} region(s)", regions.len());
        for (i, (s, e)) in regions.iter().take(5).enumerate() {
            println!("    [{i}] {s:.2} → {e:.2} s");
        }
    }

    if matches!(
        result.brand,
        Some(provcheck_wavmark::WatermarkBrand::Doomscroll)
    ) {
        println!();
        println!("ROUND-TRIP OK: detector recovered Doomscroll.");
    } else {
        println!();
        println!(
            "ROUND-TRIP FAILED: expected Doomscroll, got {:?}",
            result.brand
        );
        std::process::exit(1);
    }
    Ok(())
}
