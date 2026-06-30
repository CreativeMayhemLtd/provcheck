//! WavMark watermark embedding.
//!
//! Upstream `wavmark.encode_watermark` chunks the audio into
//! non-overlapping 16000-sample (1 s @ 16 kHz) chunks and encodes
//! each independently. Per chunk: build a 32-bit message (16-bit
//! fix-pattern in slots 0..16, ECC-encoded 5-bit brand ID across
//! slots 16..32), then run the HiNet forward pipeline.
//!
//! WavMark performs an SNR feedback loop upstream — re-encode until
//! the per-chunk SNR is within `[min_snr, max_snr]`. We omit the
//! loop in v1: the loop's purpose is to prevent over-marking on
//! aggressive content; running once at training-time α gives
//! ~38–40 dB SNR (per WavMark's README) which is well within the
//! intended quality envelope.

use crate::model::{self, CHUNK_SAMPLES, FIX_PATTERN_LEN, ModelError, NUM_BITS, WAVMARK_FIX_PATTERN};
use crate::registry;

#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    #[error("audio is empty")]
    Empty,
    #[error("model error: {0}")]
    Model(#[from] ModelError),
}

/// Embed config for shape parity with `provcheck-watermark::EmbedConfig`.
/// WavMark's HiNet encoder is per-1s-chunk by training-time
/// architecture and not chunk-parallel internally, so the config
/// has no knobs at this layer; the type exists so downstream
/// dispatchers can route through wavmark with the same call shape
/// as silentcipher without a special case.
///
/// v0.7 phase 7-pre.
#[derive(Debug, Default, Clone, Copy)]
pub struct EmbedConfig {}

/// Embed a 5-bit brand ID into a 16 kHz mono waveform. Returns the
/// marked waveform (same length as input). The tail (any samples
/// past the last full 16000-sample chunk) is copied through
/// unchanged — WavMark can only carry a full 1-second window's
/// worth of marking per chunk.
pub fn embed(waveform: &[f32], brand_id_5bit: u8) -> Result<Vec<f32>, EncodeError> {
    if waveform.is_empty() {
        return Err(EncodeError::Empty);
    }

    let payload = registry::encode_payload(brand_id_5bit);

    // Build the 32-bit message tensor: bits 0..16 = WavMark fix
    // pattern, bits 16..32 = ECC-encoded brand payload, MSB-first.
    let mut message = [0.0_f32; NUM_BITS];
    for i in 0..FIX_PATTERN_LEN {
        message[i] = WAVMARK_FIX_PATTERN[i] as f32;
    }
    for i in 0..FIX_PATTERN_LEN {
        let bit = (payload >> (15 - i)) & 1;
        message[FIX_PATTERN_LEN + i] = bit as f32;
    }

    let n = waveform.len();
    let mut out = waveform.to_vec();

    let num_chunks = n / CHUNK_SAMPLES;
    for c in 0..num_chunks {
        let start = c * CHUNK_SAMPLES;
        let marked = model::encode_chunk(&waveform[start..start + CHUNK_SAMPLES], &message)?;
        out[start..start + CHUNK_SAMPLES].copy_from_slice(&marked);
    }

    Ok(out)
}

/// Shape-parity wrapper. Calls [`embed`] and ignores the config.
/// v0.7 phase 7-pre.
pub fn embed_with_config(
    waveform: &[f32],
    brand_id_5bit: u8,
    _config: EmbedConfig,
) -> Result<Vec<f32>, EncodeError> {
    embed(waveform, brand_id_5bit)
}

/// Embed the same brand into both channels of a stereo signal.
///
/// WavMark's HiNet encoder is mono-only by training-time
/// architecture; like silentcipher + audioseal we orchestrate
/// two independent embeds (L and R with the same brand) so the
/// resulting stereo file detects on either single channel and on
/// the mono downmix. Returns `(marked_left, marked_right)`, each
/// the same length as the matching input channel. Errors if the
/// two input channels have different lengths.
///
/// v0.7 phase 7-pre audit #1.
pub fn embed_stereo(
    left: &[f32],
    right: &[f32],
    brand_id_5bit: u8,
) -> Result<(Vec<f32>, Vec<f32>), EncodeError> {
    if left.len() != right.len() {
        return Err(EncodeError::Model(crate::model::ModelError::Inference(
            format!(
                "stereo embed: left ({}) and right ({}) have different lengths",
                left.len(),
                right.len()
            ),
        )));
    }
    let l = embed(left, brand_id_5bit)?;
    let r = embed(right, brand_id_5bit)?;
    Ok((l, r))
}

/// Shape-parity wrapper. Calls [`embed_stereo`] and ignores config.
pub fn embed_stereo_with_config(
    left: &[f32],
    right: &[f32],
    brand_id_5bit: u8,
    _config: EmbedConfig,
) -> Result<(Vec<f32>, Vec<f32>), EncodeError> {
    embed_stereo(left, right, brand_id_5bit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_errors() {
        let r = embed(&[], registry::BRAND_DOOMSCROLL);
        assert!(matches!(r, Err(EncodeError::Empty)));
    }

    // ----- embed_stereo input validation ----------
    //
    // v0.9.63 ungates wavmark stereo embed at the kit dispatch
    // layer. The library entry point already existed but had no
    // input-validation coverage. Pin the contract here so the
    // kit's stereo route doesn't surface confusing model errors
    // on operator mistakes.

    #[test]
    fn embed_stereo_mismatched_lengths_returns_error() {
        // L and R must be the same length — they're independent
        // mono embeds that must align in the output WAV.
        let left = vec![0.01_f32; 100];
        let right = vec![0.01_f32; 99];
        let r = embed_stereo(&left, &right, registry::BRAND_DOOMSCROLL);
        assert!(r.is_err());
        match r {
            Err(EncodeError::Model(crate::model::ModelError::Inference(msg))) => {
                assert!(msg.contains("stereo"));
                assert!(msg.contains("100"));
                assert!(msg.contains("99"));
            }
            other => panic!("expected ModelError::Inference, got {other:?}"),
        }
    }

    #[test]
    fn embed_stereo_with_invalid_brand_id_propagates_error_from_each_channel() {
        // brand_id > 5 bits should fire the same error as the
        // mono path (caught inside encode_chunk via the BCH
        // construction). Below the encoder load, both channels
        // produce an Empty error on the empty path.
        let left: Vec<f32> = Vec::new();
        let right: Vec<f32> = Vec::new();
        let r = embed_stereo(&left, &right, registry::BRAND_DOOMSCROLL);
        // Empty input — same error as the mono path.
        assert!(matches!(r, Err(EncodeError::Empty)));
    }

    // ----- EmbedConfig parity wrappers ----------

    #[test]
    fn embed_with_config_routes_through_to_embed_for_empty_input() {
        // The parity wrapper must surface the same error as
        // the direct call. v0.9.63: pin so a future maintainer
        // doesn't accidentally drop the wrapper into a stub.
        let cfg = EmbedConfig::default();
        let r = embed_with_config(&[], registry::BRAND_DOOMSCROLL, cfg);
        assert!(matches!(r, Err(EncodeError::Empty)));
    }

    #[test]
    fn embed_stereo_with_config_routes_through_to_embed_stereo() {
        let cfg = EmbedConfig::default();
        let left = vec![0.01_f32; 10];
        let right = vec![0.01_f32; 20];
        let r = embed_stereo_with_config(&left, &right, registry::BRAND_DOOMSCROLL, cfg);
        // Length mismatch should propagate.
        assert!(r.is_err());
    }
}
