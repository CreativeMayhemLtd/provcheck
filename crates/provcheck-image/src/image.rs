//! Image decode primitive — mirrors the audio sibling crates'
//! `audio.rs` pattern. v0.7 phase 7a scaffold; 7b wires the
//! actual TrustMark model against this.

use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    #[error("file is not a supported image container")]
    NotImage,
    #[error("image decode failed: {0}")]
    Decode(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Decoded image surface — RGB f32 normalised to `[0.0, 1.0]`,
/// laid out row-major as `[h * width * 3 + w * 3 + c]`.
///
/// v0.7 phase 7a scaffold. The exact tensor shape TrustMark
/// expects (CHW vs HWC, normalised mean/std) lands at 7b; the
/// public struct shape may shift then to match the model's
/// preferred input layout.
#[derive(Debug)]
pub struct DecodedImage {
    pub width: u32,
    pub height: u32,
    pub rgb: Vec<f32>,
}

/// Decode the file at `path` into a normalised RGB tensor.
///
/// v0.7 phase 7a scaffold: returns `NotImage` for unknown
/// extensions and a stubbed-shape decode for recognised ones.
/// 7b replaces the body with real `image` crate calls.
pub fn decode(path: &Path) -> Result<DecodedImage, ImageError> {
    let _ = std::fs::metadata(path)?;
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());
    match ext.as_deref() {
        Some("png" | "jpg" | "jpeg" | "webp" | "bmp" | "gif" | "tiff" | "tif") => {
            // Stub: real decode lands at 7b.
            Err(ImageError::Decode(
                "decode not yet wired (v0.7 phase 7a stub)".into(),
            ))
        }
        _ => Err(ImageError::NotImage),
    }
}
