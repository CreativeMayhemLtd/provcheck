//! # provcheck-image
//!
//! Image-modality neural-watermark detection for [`provcheck`].
//! Sibling crate to `provcheck-watermark` (silentcipher),
//! `provcheck-audioseal`, and `provcheck-wavmark`. Each detector
//! pushes a result into
//! [`Report::watermarks`](provcheck::report::Report::watermarks)
//! so a single verify pass can report multiple independent
//! detector signals across modalities.
//!
//! ## Status
//!
//! v0.7 phase 7a: **scaffold only**. The chosen first family is
//! [TrustMark](https://github.com/adobe/TrustMark) (Adobe / CAI,
//! Apache-2.0 code and weights claimed). The ONNX backend wires
//! in at phase 7b; right now [`detect`] returns the
//! `NotDetected` stub for every input and [`encode::embed`]
//! returns [`EncodeError::NotYetImplemented`].
//!
//! See [`docs/v0.7.0-roadmap/7a-image-watermark-survey.md`](https://github.com/CreativeMayhemLtd/provcheck/blob/main/docs/v0.7.0-roadmap/7a-image-watermark-survey.md)
//! for the library-survey rationale.
//!
//! ## License posture
//!
//! Both the chosen family's code AND model weights must be
//! permissively licensed per the workspace
//! [`WATERMARK_LICENSE_POLICY.md`](https://github.com/CreativeMayhemLtd/provcheck/blob/main/WATERMARK_LICENSE_POLICY.md).
//! TrustMark's Apache-2.0 status is verified at 7b's wiring
//! commit; if it falls through the survey calls out DCT-DWT
//! classical methods as a no-weights-license-risk fallback.
//!
//! ## Pipeline (target shape for 7b)
//!
//! 1. [`image`] decodes the container (PNG, JPEG, WebP) via the
//!    `image` crate, normalises to an f32 tensor in the model's
//!    expected colourspace.
//! 2. [`detect::detect`] (7b) runs the TrustMark decoder ONNX
//!    via tract and recovers the 100-bit payload.
//! 3. [`brand`] (7b) dispatches on payload bytes the same way
//!    the audio side does — re-using
//!    [`provcheck::report::WatermarkBrand`].

use std::path::Path;

pub use provcheck::prelude::{WatermarkBrand, WatermarkKind, WatermarkResult, WatermarkStatus};

#[doc(hidden)]
pub mod image;
pub mod encode;
#[doc(hidden)]
pub mod model;
pub mod bch;

/// Errors returned by [`detect`]. Non-fatal outcomes (file is
/// not an image, decoder failure) are reported on the returned
/// [`WatermarkResult`]'s `message` field. `Error` is reserved
/// for genuinely exceptional cases (file not found, unreadable).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("file not found or unreadable: {0}")]
    Io(#[from] std::io::Error),
    /// Weight download / verify / cache failure surfaced through
    /// `provcheck-weights`. v0.7 phase 8a DLC wiring.
    #[error("weights: {0}")]
    Weights(#[from] provcheck_weights::Error),
}

/// Run image-modality watermark detection on the file at `path`.
///
/// v0.7 phase 7a scaffold: returns `NotDetected` with message
/// `"image detector not yet wired (v0.7 phase 7a stub)"` for every
/// input. Phase 7b lands the actual TrustMark inference.
///
/// The shape matches the audio sibling crates'
/// [`detect`](provcheck_watermark::detect) so the kit's dispatch
/// surface is uniform.
pub fn detect(path: &Path) -> Result<WatermarkResult, Error> {
    // Preflight: file must exist. Same convention as the audio crates.
    let _ = std::fs::metadata(path)?;

    // Fast-path: reject obviously-non-image extensions so the kit's
    // multi-detector run does not waste time spinning up an image
    // decoder on a WAV file.
    if !looks_like_image(path) {
        return Ok(WatermarkResult {
            kind: WatermarkKind::TrustMark,
            status: WatermarkStatus::NotDetected,
            detected: false,
            confidence: 0.0,
            payload: None,
            brand: None,
            message: Some("not image".into()),
            marked_regions: None,
        });
    }

    // v0.7 phase 8a "always respect the user": surface a clean
    // install-needed message if weights are absent. Detect / CLI
    // layer prompts for consent — never the model layer.
    match provcheck_weights::load_if_cached("trustmark", "b-decoder") {
        Ok(_) => {}
        Err(provcheck_weights::Error::NotCached {
            family,
            variant: _,
            size_mb,
        }) => {
            return Ok(WatermarkResult {
                kind: WatermarkKind::TrustMark,
                status: WatermarkStatus::NotDetected,
                detected: false,
                confidence: 0.0,
                payload: None,
                brand: None,
                message: Some(format!(
                    "image detector requires weights ({size_mb} MB): \
                     run `provcheck-kit weights install {family}`"
                )),
                marked_regions: None,
            });
        }
        Err(e) => return Err(Error::Weights(e)),
    }

    // v0.7 phase 7b: real TrustMark-B decoder inference.
    let decoded = image::decode(path).map_err(|e| match e {
        image::ImageError::NotImage => {
            // Caught above by `looks_like_image`, but defend.
            Error::Weights(provcheck_weights::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "decoder rejected as non-image",
            )))
        }
        image::ImageError::Decode(msg) => {
            Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, msg))
        }
        image::ImageError::Io(e) => Error::Io(e),
    })?;

    let result = match model::run_decoder(&decoded) {
        Ok(out) => out,
        Err(e) => {
            return Ok(WatermarkResult {
                kind: WatermarkKind::TrustMark,
                status: WatermarkStatus::NotDetected,
                detected: false,
                confidence: 0.0,
                payload: None,
                brand: None,
                message: Some(format!(
                    "TrustMark decoder runtime error: {e}. \
                     v0.7 phase 7b status: preprocessing + DLC weight delivery + \
                     verifier integration are wired, but tract 0.21's ONNX op coverage \
                     cannot run Adobe's decoder export (Gemm and Resize op attribute \
                     combinations declined). 7b-followup switches the backend to ort."
                )),
                marked_regions: None,
            });
        }
    };

    // v0.7 phase 7c: provcheck-internal "raw" payload format. If
    // the first byte matches `PROVCHECK_RAW_MAGIC` and the version
    // bits are `0b0000`, treat the next 5 bits as a brand id and
    // report Detected. TrustMark BCH-5 ecosystem interop ships as
    // a follow-up phase that swaps this magic-byte gate for the
    // proper finite-field decode.
    let (status, brand) = classify_bch5(&result.bits);
    Ok(WatermarkResult {
        kind: WatermarkKind::TrustMark,
        status,
        detected: matches!(
            status,
            WatermarkStatus::Detected | WatermarkStatus::Degraded
        ),
        confidence: result.mean_abs_logit,
        payload: Some(result.payload_bytes),
        brand,
        message: Some(format!(
            "TrustMark-B decoder ran; {} raw bits recovered, mean |logit| {:.3}. \
             BCH-5 shortened (96, 61, t=5) ecosystem-interop format. \
             Status NotDetected here means BCH could not correct the bit \
             pattern — either the image is unmarked, or the mark was degraded \
             beyond BCH's 5-bit correction capacity by a downstream transform. \
             High mean |logit| with NotDetected typically means a marked image \
             that lost too many bits to lossy re-encode or aggressive resize.",
            model::SECRET_LEN,
            result.mean_abs_logit
        )),
        marked_regions: None,
    })
}

/// Classify decoded bits via the BCH_5 shortened-codeword format.
/// Returns `(WatermarkStatus, Option<WatermarkBrand>)`.
///
/// Pipeline:
/// 1. Check the 4 version bits at positions [96..100] match
///    `0b0001` (BCH_5 marker).
/// 2. Reconstruct the full 127-bit BCH codeword from the 96-bit
///    shortened form by prepending 31 zero pads to the data
///    portion.
/// 3. Run BCH(127, 92, t=5) error correction.
/// 4. Check the magic byte at the head of the recovered data.
/// 5. Extract the brand id.
fn classify_bch5(bits: &[u8]) -> (WatermarkStatus, Option<WatermarkBrand>) {
    use crate::encode;
    if bits.len() < model::SECRET_LEN {
        return (WatermarkStatus::NotDetected, None);
    }
    // Version marker.
    if bits[96..100] != [0, 0, 0, 1] {
        return (WatermarkStatus::NotDetected, None);
    }

    // Layout in the 96-bit shortened codeword:
    //   bits[0..61]  = 61 data bits
    //   bits[61..96] = 35 ECC bits
    // Full BCH(127, 92) codeword layout per bch::encode:
    //   pos[0..35]  = parity
    //   pos[35..66] = SHORTEN_PAD zero bits
    //   pos[66..127] = 61 data bits
    let mut received = vec![0u8; crate::bch::N];
    for i in 0..35 {
        received[i] = bits[61 + i];
    }
    // pos[35..66] stays zero (the shortening pad).
    for i in 0..61 {
        received[66 + i] = bits[i];
    }

    let (data, _errs) = match crate::bch::decode(&received) {
        Ok(r) => r,
        Err(_) => return (WatermarkStatus::NotDetected, None),
    };
    // `data` is the 92-bit BCH input that was encoded. Strip the
    // 31 leading zero pads to get the 61 data bits.
    let payload = &data[31..];

    // Magic byte at the head.
    let mut magic = 0u8;
    for i in 0..8 {
        if payload[i] == 1 {
            magic |= 1 << (7 - i);
        }
    }
    if magic != encode::PROVCHECK_RAW_MAGIC {
        return (WatermarkStatus::NotDetected, None);
    }
    // Brand id at bits 8..13 of the recovered data.
    let mut brand_id = 0u8;
    for i in 0..5 {
        if payload[8 + i] == 1 {
            brand_id |= 1 << (4 - i);
        }
    }
    let brand = match brand_id {
        1 => Some(WatermarkBrand::Doomscroll),
        2 => Some(WatermarkBrand::Raidio),
        3 => Some(WatermarkBrand::Vaideo),
        _ => None,
    };
    (WatermarkStatus::Detected, brand)
}

fn looks_like_image(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "png" | "jpg" | "jpeg" | "webp" | "bmp" | "gif" | "tiff" | "tif"
    )
}

/// v0.7 phase 7-pre audit #10: Send + Sync bound assertion.
/// See `provcheck-watermark::_send_sync_assertions` for rationale.
#[cfg(test)]
mod _send_sync_assertions {
    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn key_public_types_are_send_sync() {
        assert_send_sync::<crate::WatermarkResult>();
        assert_send_sync::<crate::WatermarkBrand>();
        assert_send_sync::<crate::WatermarkKind>();
        assert_send_sync::<crate::WatermarkStatus>();
        assert_send_sync::<crate::encode::EmbedConfig>();
        assert_send_sync::<crate::encode::EncodeError>();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tempfile_with_ext(ext: &str, bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::Builder::new()
            .suffix(&format!(".{ext}"))
            .tempfile()
            .expect("create tempfile");
        f.write_all(bytes).expect("write tempfile");
        f
    }

    #[test]
    fn non_image_extension_is_rejected() {
        let f = tempfile_with_ext("wav", b"fake-wav-bytes");
        let r = detect(f.path()).expect("detect");
        assert!(!r.detected);
        assert_eq!(r.message.as_deref(), Some("not image"));
    }

    #[test]
    #[ignore = "requires network to download TrustMark weights from the public GH release"]
    fn image_extension_returns_weights_pending_stub() {
        let f = tempfile_with_ext("png", b"\x89PNG\r\n\x1a\nfake");
        let r = detect(f.path()).expect("detect");
        assert!(!r.detected);
        let msg = r.message.as_deref().unwrap_or("");
        assert!(
            msg.starts_with("image detector wiring pending"),
            "got message: {msg}"
        );
    }

    #[test]
    fn missing_file_is_io_error() {
        let r = detect(Path::new("/this/path/does/not/exist.png"));
        assert!(matches!(r, Err(Error::Io(_))));
    }
}
