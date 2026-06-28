//! TrustMark-B image embedding.
//!
//! v0.7 phase 7c. Mirrors upstream `trustmark.py`'s encoder path:
//!
//! 1. Resize the cover to the model's 256×256 input.
//! 2. Normalise to `[-1, 1]` CHW.
//! 3. Build a 100-bit secret tensor from the requested brand id.
//! 4. Run the TrustMark-B encoder → stego image at 256×256.
//! 5. Residual delta = stego - cover.
//! 6. Per-channel mean removal on the residual.
//! 7. Resize residual back to the original image dimensions.
//! 8. Blend: `output = clip(residual * WM_STRENGTH + cover_norm, -1, 1)`.
//! 9. Denormalise → 8-bit RGB → save as PNG.
//!
//! ## Payload format
//!
//! Phase 7c uses a **provcheck-internal** 100-bit payload format
//! (NOT TrustMark's BCH_5). The format is:
//!
//! | bits      | meaning                                         |
//! | --------- | ----------------------------------------------- |
//! | 0..8      | magic byte `0xA5` so a provcheck detector can   |
//! |           | distinguish provcheck-stamped marks from noise. |
//! | 8..13     | 5-bit brand id (BRAND_RAIDIO / BRAND_DOOMSCROLL |
//! |           | / BRAND_VAIDEO from the audio crate registry).  |
//! | 13..96    | zeros (reserved).                               |
//! | 96..100   | version `0b0000` — denotes "provcheck raw".     |
//! |           | TrustMark BCH_5 marks use `0b0001` here.        |
//!
//! The round-trip (provcheck encode → provcheck decode → same
//! brand) works today. Ecosystem interop with Adobe's Python
//! TrustMark requires real BCH-5 error correction; that lands as
//! a follow-up phase that swaps the secret-encoding step for
//! BCH(m=5, polynomial=137, t=5). The provcheck-internal format
//! today is forward-compatible: BCH-encoded marks will continue
//! to fall through the magic-byte check and decode via the
//! BCH path when it lands.

use std::path::Path;

use image::{ImageBuffer, Rgb, RgbImage};

use crate::image as imgmod;
use crate::model::{self, SECRET_LEN};

#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    #[error("image read failed: {0}")]
    Read(String),
    #[error("image write failed: {0}")]
    Write(String),
    #[error("encoder model error: {0}")]
    Model(#[from] model::ModelError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Embed config for shape parity with the audio crates'
/// `EmbedConfig`. v0.7 phase 7c. No knobs yet; future per-image
/// tuning (mark strength, residual blur radius, region mask) slots
/// in here.
#[derive(Debug, Default, Clone, Copy)]
pub struct EmbedConfig {}

/// Watermark strength multiplier applied to the residual before
/// adding it back to the cover. Upstream TrustMark uses `1.0` for
/// most variants (`1.25` for P). We track the default B/Q value.
const WM_STRENGTH: f32 = 1.0;

/// Magic byte at the head of provcheck-raw payloads. Distinguishes
/// a v0.7 provcheck-stamped mark from noise and from future BCH-5
/// marks (which use upstream's structure).
pub const PROVCHECK_RAW_MAGIC: u8 = 0xA5;

/// Pack a brand-id-5bit into the 100-bit provcheck-raw secret.
fn build_secret(brand_id_5bit: u8) -> [u8; SECRET_LEN] {
    let mut bits = [0u8; SECRET_LEN];
    // bits[0..8] = magic
    for i in 0..8 {
        if (PROVCHECK_RAW_MAGIC >> (7 - i)) & 1 == 1 {
            bits[i] = 1;
        }
    }
    // bits[8..13] = brand id, MSB first
    for i in 0..5 {
        if (brand_id_5bit >> (4 - i)) & 1 == 1 {
            bits[8 + i] = 1;
        }
    }
    // bits[13..96] zeros (already)
    // bits[96..100] version = 0b0000 (already)
    bits
}

/// Embed a brand-tagged TrustMark-B watermark into the image at
/// `src` and write the marked output to `dst`. v0.7 phase 7c.
pub fn embed(src: &Path, dst: &Path, brand_id_5bit: u8) -> Result<(), EncodeError> {
    embed_with_config(src, dst, brand_id_5bit, EmbedConfig::default())
}

/// [`embed`] with explicit [`EmbedConfig`]. Shape parity with the
/// audio crates' `embed_with_config`.
pub fn embed_with_config(
    src: &Path,
    dst: &Path,
    brand_id_5bit: u8,
    _config: EmbedConfig,
) -> Result<(), EncodeError> {
    // 1-2. Load + preprocess cover.
    let decoded = imgmod::decode(src)
        .map_err(|e| EncodeError::Read(format!("decode {}: {e}", src.display())))?;
    let orig_w = decoded.original_width;
    let orig_h = decoded.original_height;

    // 3. Build the 100-bit secret.
    let secret_bits = build_secret(brand_id_5bit);

    // 4. Run the encoder. Output is stego at 256×256 in [-1, 1] CHW.
    let stego_chw = model::run_encoder(&decoded.chw, &secret_bits)?;

    // 5. Residual delta = stego - cover (in normalised space).
    let mut residual: Vec<f32> = stego_chw
        .iter()
        .zip(decoded.chw.iter())
        .map(|(s, c)| s - c)
        .collect();

    // 6. Per-channel mean removal. Mirrors upstream:
    //    residual -= residual.mean(dim=(2,3), keepdim=True)
    let area = (imgmod::MODEL_RES * imgmod::MODEL_RES) as usize;
    for c in 0..3 {
        let offset = c * area;
        let mut sum = 0.0_f32;
        for i in 0..area {
            sum += residual[offset + i];
        }
        let mean = sum / area as f32;
        for i in 0..area {
            residual[offset + i] -= mean;
        }
    }

    // 7. Resize residual back to the ORIGINAL image dimensions via
    //    bilinear interpolation.
    let residual_resized =
        resize_residual_chw(&residual, imgmod::MODEL_RES, imgmod::MODEL_RES, orig_w, orig_h);

    // 8. Blend the residual into the original-sized cover. We need
    //    the cover at the original resolution in [-1, 1] CHW too.
    let cover_orig_chw = load_cover_chw_at_original_res(src, orig_w, orig_h)?;
    let mut out_chw = Vec::with_capacity(cover_orig_chw.len());
    for (r, c) in residual_resized.iter().zip(cover_orig_chw.iter()) {
        let blended = (r * WM_STRENGTH + c).clamp(-1.0, 1.0);
        out_chw.push(blended);
    }

    // 9. Denormalise CHW [-1, 1] → HWC u8 [0, 255] and save.
    let out_buf = chw_normalised_to_rgb_u8(&out_chw, orig_w, orig_h);
    out_buf
        .save(dst)
        .map_err(|e| EncodeError::Write(format!("save {}: {e}", dst.display())))?;
    Ok(())
}

/// Bilinear resize of a CHW float buffer from `(src_w, src_h)` to
/// `(dst_w, dst_h)`. Matches the `interpolate(mode='bilinear')` step
/// in upstream's residual pipeline. Output is row-major CHW.
fn resize_residual_chw(
    src_chw: &[f32],
    src_w: u32,
    src_h: u32,
    dst_w: u32,
    dst_h: u32,
) -> Vec<f32> {
    let src_w_usize = src_w as usize;
    let src_h_usize = src_h as usize;
    let dst_w_usize = dst_w as usize;
    let dst_h_usize = dst_h as usize;
    let src_area = src_w_usize * src_h_usize;
    let dst_area = dst_w_usize * dst_h_usize;
    let mut out = vec![0.0_f32; 3 * dst_area];

    for c in 0..3 {
        let src_off = c * src_area;
        let dst_off = c * dst_area;
        for dy in 0..dst_h_usize {
            let sy = (dy as f32 * src_h as f32 / dst_h as f32).clamp(0.0, (src_h - 1) as f32);
            let y0 = sy.floor() as usize;
            let y1 = (y0 + 1).min(src_h_usize - 1);
            let wy = sy - y0 as f32;
            for dx in 0..dst_w_usize {
                let sx = (dx as f32 * src_w as f32 / dst_w as f32).clamp(0.0, (src_w - 1) as f32);
                let x0 = sx.floor() as usize;
                let x1 = (x0 + 1).min(src_w_usize - 1);
                let wx = sx - x0 as f32;
                let v00 = src_chw[src_off + y0 * src_w_usize + x0];
                let v01 = src_chw[src_off + y0 * src_w_usize + x1];
                let v10 = src_chw[src_off + y1 * src_w_usize + x0];
                let v11 = src_chw[src_off + y1 * src_w_usize + x1];
                let v0 = v00 * (1.0 - wx) + v01 * wx;
                let v1 = v10 * (1.0 - wx) + v11 * wx;
                let v = v0 * (1.0 - wy) + v1 * wy;
                out[dst_off + dy * dst_w_usize + dx] = v;
            }
        }
    }
    out
}

/// Load the cover image at its ORIGINAL resolution, normalised to
/// `[-1, 1]` CHW. Used by the blend step. Reuses image-crate
/// decode + a smaller bespoke normalisation that does NOT resize.
fn load_cover_chw_at_original_res(
    src: &Path,
    orig_w: u32,
    orig_h: u32,
) -> Result<Vec<f32>, EncodeError> {
    let reader = image::ImageReader::open(src)
        .map_err(|e| EncodeError::Read(format!("open: {e}")))?
        .with_guessed_format()
        .map_err(|e| EncodeError::Read(format!("format: {e}")))?;
    let img = reader
        .decode()
        .map_err(|e| EncodeError::Read(format!("decode: {e}")))?;
    let rgb = img.to_rgb8();
    debug_assert_eq!(rgb.dimensions(), (orig_w, orig_h));
    let area = (orig_w * orig_h) as usize;
    let mut chw = vec![0.0_f32; 3 * area];
    let w = orig_w as usize;
    for (x, y, pixel) in rgb.enumerate_pixels() {
        let xi = x as usize;
        let yi = y as usize;
        for c in 0..3 {
            chw[c * area + yi * w + xi] = (pixel[c] as f32 / 255.0) * 2.0 - 1.0;
        }
    }
    Ok(chw)
}

/// CHW f32 in `[-1, 1]` → HWC u8 RGB image.
fn chw_normalised_to_rgb_u8(chw: &[f32], w: u32, h: u32) -> RgbImage {
    let area = (w * h) as usize;
    let mut out: RgbImage = ImageBuffer::new(w, h);
    for y in 0..h as usize {
        for x in 0..w as usize {
            let r = denorm(chw[y * w as usize + x]);
            let g = denorm(chw[area + y * w as usize + x]);
            let b = denorm(chw[2 * area + y * w as usize + x]);
            out.put_pixel(x as u32, y as u32, Rgb([r, g, b]));
        }
    }
    out
}

#[inline]
fn denorm(v: f32) -> u8 {
    (((v + 1.0) * 0.5).clamp(0.0, 1.0) * 255.0).round() as u8
}
