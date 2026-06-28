// Standalone roundtrip smoke: encode then detect, verify brand survives.
// Compiled + run via `cargo run --release --example image_roundtrip
// --manifest-path crates/provcheck-image/Cargo.toml`.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let src = std::path::PathBuf::from(r"C:\Users\Administrator\AppData\Local\Temp\test.png");
    let dst = std::path::PathBuf::from(r"C:\Users\Administrator\AppData\Local\Temp\test-marked.png");
    let brand_id_5bit = 2; // BRAND_RAIDIO per audioseal::registry
    eprintln!("embedding brand_id={brand_id_5bit} into {} -> {}", src.display(), dst.display());
    provcheck_image::encode::embed(&src, &dst, brand_id_5bit)?;
    eprintln!("embed wrote {} bytes", std::fs::metadata(&dst)?.len());

    let report = provcheck_image::detect(&dst)?;
    eprintln!(
        "detect: status={:?} detected={} conf={:.4} brand={:?}",
        report.status, report.detected, report.confidence, report.brand
    );
    eprintln!("payload (first 13 bytes): {:02x?}", &report.payload.as_deref().unwrap_or(&[])[..13.min(report.payload.as_ref().map(|p| p.len()).unwrap_or(0))]);
    eprintln!("message: {}", report.message.unwrap_or_default());
    Ok(())
}
