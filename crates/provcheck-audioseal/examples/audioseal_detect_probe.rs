//! End-to-end probe: run the AudioSeal detector pipeline on a WAV
//! and print the recovered brand + bits + per-region info.
//!
//! Generate a marked fixture with
//! `scripts/audioseal-roundtrip-fixture.py` then run:
//!   cargo run --release -p provcheck-audioseal --example audioseal_detect_probe -- diagnose-audioseal-marked.wav

use std::path::PathBuf;
use std::time::Instant;

fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: audioseal_detect_probe <wav-path>"))?;
    let path = PathBuf::from(path);

    println!("== audioseal_detect_probe ==");
    println!("input: {}", path.display());

    let t0 = Instant::now();
    let result = provcheck_audioseal::detect(&path)?;
    println!("elapsed: {:.2?}", t0.elapsed());
    println!();
    println!("kind:        {:?}", result.kind);
    println!("status:      {:?}", result.status);
    println!("detected:    {}", result.detected);
    println!("confidence:  {:.4}", result.confidence);
    if let Some(payload) = &result.payload {
        println!(
            "payload:     {} ({} bytes)",
            payload
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(""),
            payload.len()
        );
    } else {
        println!("payload:     (none)");
    }
    println!("brand:       {:?}", result.brand);
    if let Some(msg) = &result.message {
        println!("message:     {msg}");
    }
    if let Some(regions) = &result.marked_regions {
        println!("marked_regions: {} region(s)", regions.len());
        for (s, e) in regions.iter().take(10) {
            println!("  {s:.2}s – {e:.2}s ({:.2}s)", e - s);
        }
        if regions.len() > 10 {
            println!("  …and {} more", regions.len() - 10);
        }
    } else {
        println!("marked_regions: None");
    }

    Ok(())
}
