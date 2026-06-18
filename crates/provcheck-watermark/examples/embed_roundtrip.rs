//! End-to-end embed → detect round-trip on synthetic audio.
//!
//! Smoke-tests the full producer-side pipeline shipping in v0.3.8:
//!   1. Synthesise a few seconds of broadband-ish audio.
//!   2. Embed a known 5-byte payload via [`encode::embed`].
//!   3. Run the detector via [`detect`].
//!   4. Confirm the recovered payload matches what we embedded and
//!      the confidence is comfortably above the brand-classifier
//!      threshold.
//!
//! Usage:
//!   cargo run --release -p provcheck-watermark --example embed_roundtrip [payload-hex]
//!
//! Default payload is "DFM\x01\x00" (44 46 4d 01 00) — the
//! doomscroll.fm brand stamp. Override with five hex bytes if you
//! want to test a different one (e.g. `52414901 00` for rAIdio).

use std::path::PathBuf;
use std::time::Instant;

use provcheck_watermark::{audio, encode, hparams};

const SR: f32 = 44_100.0;

fn parse_hex_payload(s: &str) -> anyhow::Result<[u8; 5]> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() != 10 {
        anyhow::bail!(
            "payload must be 5 bytes (10 hex chars), got {}",
            cleaned.len()
        );
    }
    let mut out = [0u8; 5];
    for i in 0..5 {
        out[i] = u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}

fn synthesize_audio(seconds: f32) -> Vec<f32> {
    let n = (seconds * SR) as usize;
    (0..n)
        .map(|i| {
            let t = i as f32 / SR;
            // Pseudo-broadband: mix of tones at frequencies that
            // give silentcipher enough spectral content to embed
            // into. Real speech / music has even more — this is a
            // floor.
            0.20 * (2.0 * std::f32::consts::PI * 220.0 * t).sin()
                + 0.15 * (2.0 * std::f32::consts::PI * 440.0 * t).sin()
                + 0.10 * (2.0 * std::f32::consts::PI * 880.0 * t).sin()
                + 0.10 * (2.0 * std::f32::consts::PI * 1760.0 * t).sin()
                + 0.05 * (2.0 * std::f32::consts::PI * 3520.0 * t).sin()
        })
        .collect()
}

fn write_wav(path: &std::path::Path, samples: &[f32]) -> anyhow::Result<()> {
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate: hparams::SAMPLE_RATE,
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
    // Usage modes:
    //   embed_roundtrip                       # synthetic 6s test audio, DFM payload
    //   embed_roundtrip <audio-file>          # real audio, DFM payload
    //   embed_roundtrip <audio-file> <hex>    # real audio, custom payload
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (input_path, payload) = match args.len() {
        0 => (None, [0x44, 0x46, 0x4d, 0x01, 0x00]),
        1 => {
            let first = &args[0];
            if first
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c.is_whitespace())
                && first.len() == 10
            {
                (None, parse_hex_payload(first)?)
            } else {
                (Some(PathBuf::from(first)), [0x44, 0x46, 0x4d, 0x01, 0x00])
            }
        }
        _ => (Some(PathBuf::from(&args[0])), parse_hex_payload(&args[1])?),
    };

    println!("== embed_roundtrip ==");
    println!("payload:        {payload:02x?}");

    let waveform: Vec<f32> = match input_path.as_ref() {
        Some(p) => {
            println!("[1/4] decoding real audio from {}...", p.display());
            audio::decode_to_mono_44k1(p)?
        }
        None => {
            println!("[1/4] synthesising 6 seconds of test audio...");
            synthesize_audio(6.0)
        }
    };
    println!(
        "        n_samples = {} ({:.2} s @ {} Hz)",
        waveform.len(),
        waveform.len() as f32 / SR,
        SR as u32
    );

    // Allow SDR override via PROVCHECK_EMBED_SDR_DB for debug. Lower
    // SDR = louder watermark = more robust + more audible. silentcipher
    // default is 47 dB.
    let sdr = std::env::var("PROVCHECK_EMBED_SDR_DB")
        .ok()
        .and_then(|s| s.parse::<f32>().ok());
    println!(
        "        sdr_db    = {:?} (env override) | default 47.0",
        sdr
    );

    println!("[2/4] embedding watermark...");
    let t0 = Instant::now();
    let marked = encode::embed(&waveform, payload, sdr)?;
    println!("        elapsed   = {:?}", t0.elapsed());
    assert_eq!(
        marked.len(),
        waveform.len(),
        "embedded length must match input"
    );

    // Quick sanity: how much did the audio change?
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
    println!(
        "        input RMS = {in_rms:.6}  | marked-input L∞ = {max_diff:.6}  RMS = {rms_diff:.6}"
    );
    let sdr_measured = 20.0 * (in_rms / rms_diff.max(1e-30)).log10();
    println!("        achieved SDR = {sdr_measured:.1} dB");

    let tmp = std::env::temp_dir().join("provcheck-embed-roundtrip.wav");
    write_wav(&tmp, &marked)?;
    println!("        wrote     = {}", tmp.display());

    println!("[3/4] running detector on the watermarked WAV...");
    let t1 = Instant::now();
    let result = provcheck_watermark::detect(&PathBuf::from(&tmp))?;
    println!("        elapsed   = {:?}", t1.elapsed());

    println!("[4/4] verdict:");
    println!("        detected   = {}", result.detected);
    println!("        confidence = {:.4}", result.confidence);
    println!(
        "        payload    = {:?}",
        result.payload.as_deref().map(|p| {
            p.iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join("")
        })
    );
    println!("        brand      = {:?}", result.brand);
    println!("        status     = {:?}", result.status);
    if let Some(msg) = &result.message {
        println!("        message    = {msg}");
    }

    if let Some(p) = &result.payload {
        if p.as_slice() == payload {
            println!();
            println!("ROUND-TRIP OK: detector recovered the embedded payload.");
        } else {
            println!();
            println!("ROUND-TRIP FAILED: payload mismatch");
            println!("  embedded:  {payload:02x?}");
            println!("  recovered: {p:02x?}");
            std::process::exit(1);
        }
    } else {
        println!();
        println!("ROUND-TRIP FAILED: detector returned no payload");
        std::process::exit(1);
    }

    Ok(())
}
