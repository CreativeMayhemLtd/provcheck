//! Watermark embedding — the producer side of AudioSeal.
//!
//! Pipeline (mirrors `AudioSealWM.forward`):
//!
//! 1. Decode + resample input to 16 kHz mono (caller).
//! 2. Encode 5-bit brand ID into 16-bit ECC-protected payload
//!    (3 repeated copies + 1 reserved bit) — see [`crate::registry`].
//! 3. Chunk waveform into [`CHUNK_SAMPLES`] windows; zero-pad the
//!    last chunk if needed.
//! 4. For each chunk: run generator ONNX → watermark signal.
//! 5. Concatenate watermark signals, trim padding tail.
//! 6. Compose `marked = x + alpha * watermark`.
//! 7. Caller resamples back to source SR + writes WAV.
//!
//! ## Chunk-boundary acoustics
//!
//! The per-chunk generator inference doesn't carry LSTM state across
//! chunk boundaries. The boundary L∞ measured during architecture
//! survey was 0.044 vs interior 0.0045 — roughly -27 dB. That's
//! borderline audible on quiet content; we apply a short
//! [`OVERLAP_SAMPLES`] linear crossfade between consecutive chunks'
//! watermark signals so any discontinuity is smeared over ~25 ms
//! rather than hitting as an instantaneous click.
//!
//! Crossfade math: for the overlap region we compute *both* the
//! previous chunk's tail and the new chunk's head (we run the
//! generator on a chunk that starts `OVERLAP_SAMPLES` early), then
//! linearly weight: fade-out the previous chunk's watermark from
//! 1.0 to 0.0 across the overlap, fade-in the new one from 0.0 to
//! 1.0, sum.

use crate::model::{self, CHUNK_SAMPLES, ModelError, NBITS};
use crate::registry;

/// Width of the linear-crossfade region at every chunk boundary
/// (in samples at 16 kHz). 25 ms is short enough that it doesn't
/// audibly smear transient content but long enough to hide a chunk-
/// boundary discontinuity from the listener.
pub const OVERLAP_SAMPLES: usize = 400;

#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    #[error("audio is empty")]
    Empty,
    #[error("model error: {0}")]
    Model(#[from] ModelError),
}

/// Default per-sample watermark amplitude. AudioSeal's
/// `Watermarker.forward` takes `alpha` as a multiplier on the
/// watermark signal before adding to the source: `marked = x + α*w`.
///
/// The upstream README's worked examples use `α = 1.0`, but the
/// codec-survival sweep in `docs/v0.5.2-codec-survival/` showed
/// that on real-world music content alpha=1.0 produces a mark
/// that sits below provcheck's 0.70 detected threshold even on
/// pristine PCM (~0.67 conf). v0.5.2 raises the default to 3.0
/// so the default behaviour reliably self-detects (~0.999 conf)
/// and survives both AAC 192k stereo and libmp3lame 192k mono
/// at conf 0.999. Pass `--alpha 1.0` to restore the v0.5.1
/// behaviour, or `--alpha 5.0` for cleaner brand-ID recovery
/// through AAC delivery.
pub const DEFAULT_ALPHA: f32 = 3.0;

/// Embed a 5-bit brand ID into a 16 kHz mono waveform. Returns the
/// marked waveform (same length as input). `alpha` scales the
/// watermark amplitude; pass `None` for [`DEFAULT_ALPHA`].
///
/// The waveform must already be at 16 kHz mono — the caller is
/// responsible for decode + resample (use [`crate::audio`]).
pub fn embed(
    waveform: &[f32],
    brand_id_5bit: u8,
    alpha: Option<f32>,
) -> Result<Vec<f32>, EncodeError> {
    if waveform.is_empty() {
        return Err(EncodeError::Empty);
    }
    let alpha = alpha.unwrap_or(DEFAULT_ALPHA);

    // Encode the brand ID into the 16-bit ECC-protected payload, then
    // unpack into the per-bit integer tensor the generator ONNX expects
    // (`msg` shape `[1, NBITS]`, dtype int64, big-endian MSB at index 0).
    let payload = registry::encode_payload(brand_id_5bit);
    let mut msg = [0i64; NBITS];
    for (i, slot) in msg.iter_mut().enumerate() {
        *slot = ((payload >> (15 - i)) & 1) as i64;
    }

    let n = waveform.len();

    // Build the full watermark signal by walking chunks. We run the
    // generator on a chunk that always covers
    // `[t_start, t_start + CHUNK_SAMPLES)` of the input — when the
    // remaining audio is shorter than CHUNK_SAMPLES the tail is zero-
    // padded. After inference we trim each chunk back to its valid
    // span and crossfade with the previous chunk's tail in the
    // overlap window.
    let mut wm = vec![0.0_f32; n];

    // For boundary crossfade we run successive chunks with a small
    // overlap. The first chunk starts at 0; subsequent chunks start
    // CHUNK_SAMPLES - OVERLAP_SAMPLES later than the previous, so
    // the overlap region is processed by both inferences.
    let stride = CHUNK_SAMPLES - OVERLAP_SAMPLES;
    let mut t_start: usize = 0;
    let mut chunk_idx: usize = 0;
    loop {
        if t_start >= n {
            break;
        }
        let valid_end = (t_start + CHUNK_SAMPLES).min(n);
        let valid_len = valid_end - t_start;

        // Pad chunk to CHUNK_SAMPLES with zeros if we're at the tail.
        let mut chunk = vec![0.0_f32; CHUNK_SAMPLES];
        chunk[..valid_len].copy_from_slice(&waveform[t_start..valid_end]);

        let chunk_wm = model::run_generator_chunk(&chunk, &msg)?;

        // Write into `wm`. The first chunk (chunk_idx == 0) writes
        // directly; subsequent chunks crossfade their head into the
        // existing tail of the previous chunk.
        if chunk_idx == 0 {
            wm[t_start..valid_end].copy_from_slice(&chunk_wm[..valid_len]);
        } else {
            let overlap_end = (t_start + OVERLAP_SAMPLES).min(valid_end);
            // Crossfade region: linear weighting.
            for i in t_start..overlap_end {
                let local = i - t_start; // 0..OVERLAP_SAMPLES
                let fade_in = (local as f32 + 1.0) / (OVERLAP_SAMPLES as f32 + 1.0);
                let fade_out = 1.0 - fade_in;
                let prev = wm[i];
                let new = chunk_wm[i - t_start];
                wm[i] = prev * fade_out + new * fade_in;
            }
            // Post-overlap region: just copy from new chunk.
            if overlap_end < valid_end {
                wm[overlap_end..valid_end]
                    .copy_from_slice(&chunk_wm[overlap_end - t_start..valid_len]);
            }
        }

        if valid_end == n {
            break;
        }
        t_start += stride;
        chunk_idx += 1;
    }

    // Compose `marked = x + alpha * wm`.
    let marked: Vec<f32> = waveform
        .iter()
        .zip(wm.iter())
        .map(|(x, w)| x + alpha * w)
        .collect();

    Ok(marked)
}

/// Convenience: rewind the brand registry to give the caller a
/// `marked` buffer for a named brand without having to thread the
/// 5-bit ID.
pub fn embed_brand(
    waveform: &[f32],
    brand_id_5bit: u8,
    alpha: Option<f32>,
) -> Result<Vec<f32>, EncodeError> {
    embed(waveform, brand_id_5bit, alpha)
}

/// Embed the same brand into both channels of a stereo signal.
///
/// AudioSeal's generator is mono-only by training-time
/// architecture; we orchestrate two independent embeds (L and R
/// with the same brand and alpha) so the resulting stereo file
/// detects on either single channel and on the mono downmix.
/// Returns `(marked_left, marked_right)`, each the same length as
/// the matching input channel. Errors if the two input channels
/// have different lengths.
pub fn embed_stereo(
    left: &[f32],
    right: &[f32],
    brand_id_5bit: u8,
    alpha: Option<f32>,
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
    let l = embed(left, brand_id_5bit, alpha)?;
    let r = embed(right, brand_id_5bit, alpha)?;
    Ok((l, r))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_errors() {
        let r = embed(&[], 0x01, None);
        assert!(matches!(r, Err(EncodeError::Empty)));
    }

    // We don't have a unit test that actually runs the ONNX without
    // an audio fixture; the gold-standard integration test lives at
    // examples/audioseal_embed_roundtrip.rs.
}
