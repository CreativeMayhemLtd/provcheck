//! Image decode + TrustMark preprocessing.
//!
//! v0.7 phase 7b inference: load via the `image` crate, resize
//! to the model's 224×224 input, normalise to `[-1, 1]`, and lay
//! out as a `[1, 3, 224, 224]` CHW f32 tensor flattened row-major.
//! Matches upstream TrustMark's `trustmark.py`:
//! `transforms.ToTensor()(stego_image).unsqueeze(0) * 2.0 - 1.0`.

use std::path::Path;

use image::imageops::FilterType;
use image::{GenericImageView, ImageReader};

/// TrustMark-B decoder ONNX input resolution. The upstream Python
/// `trustmark.py` documents `model_resolution_dec = 224` for the
/// post-torch-resize tensor, but Adobe's exported ONNX takes a
/// raw 256×256 input and applies an internal resize-to-the-model-
/// native-resolution as its first node. We feed 256 here to match
/// what the ONNX actually expects; the discrepancy with the
/// Python constant is a known upstream quirk. Live-smoke confirmed
/// against the real decoder on 2026-06-28.
pub(crate) const MODEL_RES: u32 = 256;

/// Max image dimension (width or height) we will decode. Crafted
/// PNG/TIFF / etc. can declare absurdly large dimensions; the
/// `image` crate honours them and allocates accordingly. Cap at
/// 8192 to bound peak memory at ~256 MB for any 4-byte/pixel
/// format. Creator outputs above this are out of scope for the
/// in-browser-marker use case. See v0.9.0 audit §2.3.
pub(crate) const MAX_IMAGE_DIM: u32 = 8192;
/// Max total allocation the image decoder is allowed to perform.
/// Belt-and-braces alongside `MAX_IMAGE_DIM` for formats with
/// variable bit depth or alpha planes.
pub(crate) const MAX_IMAGE_ALLOC: u64 = 256 * 1024 * 1024;

#[cfg(test)]
mod limit_tests {
    use super::*;

    #[test]
    fn max_image_dim_bounds_memory_estimate() {
        // Sanity-check: at MAX_IMAGE_DIM × MAX_IMAGE_DIM RGBA,
        // peak raw-pixel allocation should not exceed
        // MAX_IMAGE_ALLOC. If a future maintainer bumps either
        // cap without rebalancing, this test catches it.
        let pixels = u64::from(MAX_IMAGE_DIM) * u64::from(MAX_IMAGE_DIM);
        let rgba_bytes = pixels * 4;
        assert!(
            rgba_bytes <= MAX_IMAGE_ALLOC,
            "MAX_IMAGE_DIM ({MAX_IMAGE_DIM})² × 4 bytes/pixel = {rgba_bytes} \
             exceeds MAX_IMAGE_ALLOC ({MAX_IMAGE_ALLOC})"
        );
    }

    #[test]
    fn max_image_dim_is_high_enough_for_real_content() {
        // 4K UHD = 3840 × 2160. 8K UHD = 7680 × 4320. We need to
        // pass at least 4K cleanly. 8K is borderline (4320 vs cap
        // 8192 — clears with room). Capture this in a test so a
        // future maintainer doesn't drop the cap below real
        // creator output sizes. Constants are compile-time visible
        // so we read into a runtime variable to dodge the
        // constant-assertion lint.
        let cap = std::hint::black_box(MAX_IMAGE_DIM);
        assert!(cap >= 3840, "cap {cap} below 4K UHD width");
        assert!(cap >= 4320, "cap {cap} below 8K UHD height");
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    #[error("file is not a supported image container")]
    NotImage,
    #[error("image decode failed: {0}")]
    Decode(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Decoded image surface — RGB f32 normalised to `[-1, 1]`, laid
/// out as CHW (channels-first) in row-major order, batch axis
/// folded into the leading dimension. Shape conceptually
/// `[1, 3, MODEL_RES, MODEL_RES]`; flat-index
/// `c * MODEL_RES * MODEL_RES + y * MODEL_RES + x`.
#[derive(Debug)]
pub struct DecodedImage {
    pub width: u32,
    pub height: u32,
    /// Pre-resize source dimensions, kept for diagnostic reporting.
    /// The CHW tensor itself is always MODEL_RES × MODEL_RES.
    pub original_width: u32,
    pub original_height: u32,
    pub chw: Vec<f32>,
}

/// Decode `path` into a TrustMark-ready RGB tensor.
///
/// 1. Load via the `image` crate (PNG / JPEG / WebP per crate
///    Cargo.toml's features).
/// 2. Convert to 8-bit RGB.
/// 3. Resize to 224×224 with bilinear interpolation (upstream
///    uses `Image.BILINEAR`).
/// 4. Convert pixel bytes to f32, divide by 255, multiply by 2
///    and subtract 1 → range `[-1, 1]`.
/// 5. Re-layout HWC → CHW.
pub fn decode(path: &Path) -> Result<DecodedImage, ImageError> {
    let _ = std::fs::metadata(path)?;
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());
    if !matches!(
        ext.as_deref(),
        Some("png" | "jpg" | "jpeg" | "webp" | "bmp" | "gif" | "tiff" | "tif")
    ) {
        return Err(ImageError::NotImage);
    }

    let mut reader = ImageReader::open(path)
        .map_err(|e| ImageError::Decode(format!("open: {e}")))?
        .with_guessed_format()
        .map_err(|e| ImageError::Decode(format!("format probe: {e}")))?;
    // Decompression-bomb guard. A crafted PNG/TIFF can allocate
    // gigabytes before any size check fires. Cap dimensions to
    // 8192 × 8192 (~256 MB for 4-byte RGBA) and total alloc to
    // 256 MB — comfortably above any reasonable creator output,
    // comfortably below memory-pressure thresholds on modest
    // hosts. See v0.9.0 audit §2.3.
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_IMAGE_DIM);
    limits.max_image_height = Some(MAX_IMAGE_DIM);
    limits.max_alloc = Some(MAX_IMAGE_ALLOC);
    reader.limits(limits);
    let img = reader
        .decode()
        .map_err(|e| ImageError::Decode(format!("decode: {e}")))?;
    let (original_width, original_height) = img.dimensions();

    // Resize to 224×224 RGB8. Bilinear matches upstream's
    // Image.BILINEAR. The `image` crate's Triangle filter is the
    // bilinear analogue.
    let resized = img.resize_exact(MODEL_RES, MODEL_RES, FilterType::Triangle);
    let rgb = resized.to_rgb8();
    debug_assert_eq!(rgb.dimensions(), (MODEL_RES, MODEL_RES));

    // HWC u8 → CHW f32 in `[-1, 1]`. Loop layout matches
    // c*H*W + y*W + x.
    let area = (MODEL_RES * MODEL_RES) as usize;
    let mut chw = vec![0.0_f32; 3 * area];
    for (x, y, pixel) in rgb.enumerate_pixels() {
        let xi = x as usize;
        let yi = y as usize;
        let stride = MODEL_RES as usize;
        for c in 0..3 {
            let v = pixel[c] as f32 / 255.0; // [0, 1]
            chw[c * area + yi * stride + xi] = v * 2.0 - 1.0; // [-1, 1]
        }
    }

    Ok(DecodedImage {
        width: MODEL_RES,
        height: MODEL_RES,
        original_width,
        original_height,
        chw,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Generate a minimal 4×4 RGB PNG with a single channel pattern,
    /// decode it, and confirm: (a) the output tensor has the right
    /// shape `3 * MODEL_RES * MODEL_RES`, (b) values land in
    /// `[-1, 1]`, (c) the original-size fields are preserved.
    #[test]
    fn decode_normalises_to_minus_one_plus_one_in_chw_layout() {
        let mut png_bytes = Vec::<u8>::new();
        let img = image::RgbImage::from_fn(4, 4, |x, y| {
            image::Rgb([(x * 64) as u8, (y * 64) as u8, ((x + y) * 32) as u8])
        });
        image::DynamicImage::ImageRgb8(img)
            .write_to(
                &mut std::io::Cursor::new(&mut png_bytes),
                image::ImageFormat::Png,
            )
            .expect("encode png");
        let f = tempfile::Builder::new().suffix(".png").tempfile().expect("tempfile");
        f.as_file().write_all(&png_bytes).expect("write png");
        f.as_file().sync_all().expect("sync");

        let decoded = decode(f.path()).expect("decode");
        assert_eq!(decoded.width, MODEL_RES);
        assert_eq!(decoded.height, MODEL_RES);
        assert_eq!(decoded.original_width, 4);
        assert_eq!(decoded.original_height, 4);
        assert_eq!(decoded.chw.len(), 3 * (MODEL_RES * MODEL_RES) as usize);
        // Range check: every value MUST be in [-1, 1].
        for v in &decoded.chw {
            assert!(
                *v >= -1.0 && *v <= 1.0,
                "value {v} out of TrustMark expected range [-1, 1]"
            );
        }
    }
}
