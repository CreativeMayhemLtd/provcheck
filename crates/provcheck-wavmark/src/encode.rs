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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_errors() {
        let r = embed(&[], registry::BRAND_DOOMSCROLL);
        assert!(matches!(r, Err(EncodeError::Empty)));
    }
}
