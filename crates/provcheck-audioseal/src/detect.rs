//! Chunked AudioSeal detection.
//!
//! AudioSeal's detector ONNX has a fixed input length
//! (`CHUNK_SAMPLES = 160_000` = 10 seconds at 16 kHz). For audio
//! shorter than that we zero-pad to `CHUNK_SAMPLES`; for longer
//! audio we chunk into 10-second windows, run each independently,
//! and aggregate.
//!
//! Chunk boundary impact (per architecture survey, see
//! crate-level docs): per-sample presence probabilities drift by
//! ~0.001 around chunk boundaries vs a hypothetical full-length
//! inference, vs ~2e-5 in the interior. Both numbers are tiny;
//! aggregating across the full file washes them out. So we
//! parallelise chunks via rayon without overlap-and-fade.
//!
//! Aggregation rules:
//!
//! - **Presence**: per-sample probability of being watermarked is
//!   the softmax output channel 1 (channel 0 is absent). We
//!   concatenate per-chunk presence vectors then compute the
//!   detection probability = `count(presence > 0.5) / total`.
//!   That mirrors the upstream `detect_watermark`.
//! - **Message**: each chunk returns 16 mean-bit logits in [0, 1]
//!   (sigmoid output). We average per-bit across chunks then
//!   threshold at 0.5 to recover the 16-bit message.
//! - **Confidence (reported)**: `detection_probability`, the
//!   fraction of samples flagged. Same convention as silentcipher's
//!   per-position-mode-vote fraction.
//! - **`marked_regions`**: contiguous spans where the per-sample
//!   probability rises above 0.5 for at least
//!   [`MIN_REGION_SAMPLES`] consecutive samples. Below threshold
//!   regions or sub-threshold flickers are dropped.

use rayon::prelude::*;

use crate::model::{self, CHUNK_SAMPLES, ModelError, NBITS};

/// Threshold above which a per-sample probability is considered
/// "marked". Matches AudioSeal's upstream `detect_watermark`
/// default.
pub const PRESENCE_THRESHOLD: f32 = 0.5;

/// Minimum span length (in samples at 16 kHz) for a contiguous
/// above-threshold region to be reported in `marked_regions`. 16_000
/// samples = 1 second. Spans shorter than this are usually
/// classification noise, not real watermark presence.
pub const MIN_REGION_SAMPLES: usize = 16_000;

/// What the chunked detector returns. Convertible into a
/// `WatermarkResult` by the crate's top-level `detect`.
#[derive(Debug, Clone)]
pub struct DetectResult {
    /// Fraction of samples flagged as watermarked across the full
    /// audio. Range [0.0, 1.0].
    pub detection_probability: f32,
    /// Recovered 16-bit message as 2 bytes. Always present (the
    /// model always emits bits — they're only meaningful when
    /// `detection_probability` is high enough).
    pub message: [u8; 2],
    /// Per-bit averaged sigmoid output in [0.0, 1.0], pre-threshold.
    /// Useful for diagnostics; serialised for `--json` callers.
    pub bit_probabilities: [f32; NBITS],
    /// Marked time-spans in seconds (start, end). Aggregated from
    /// per-sample presence using `PRESENCE_THRESHOLD` +
    /// `MIN_REGION_SAMPLES`.
    pub marked_regions: Vec<(f32, f32)>,
}

/// Run the chunked detector on a 16 kHz mono waveform.
///
/// Chunking strategy:
///   - n_chunks = `ceil(samples / CHUNK_SAMPLES)`
///   - Each chunk is exactly `CHUNK_SAMPLES`; the last chunk is
///     zero-padded if `samples % CHUNK_SAMPLES != 0`.
///   - Chunks run in parallel via rayon. Each call to
///     `model::run_detector_chunk` is independent.
pub fn detect(waveform: &[f32]) -> Result<DetectResult, ModelError> {
    if waveform.is_empty() {
        return Ok(DetectResult {
            detection_probability: 0.0,
            message: [0, 0],
            bit_probabilities: [0.0; NBITS],
            marked_regions: Vec::new(),
        });
    }

    // Build chunk slices. Last chunk gets zero-padding to exactly
    // CHUNK_SAMPLES; we record `valid_samples` so the aggregation
    // can ignore the padded region.
    let chunks = chunk_waveform(waveform);

    // Run all chunks in parallel.
    type ChunkOutputs = (Vec<f32>, Vec<f32>, usize);
    let per_chunk: Result<Vec<ChunkOutputs>, ModelError> = chunks
        .par_iter()
        .map(|(chunk, valid)| {
            let (presence_flat, message_flat) = model::run_detector_chunk(chunk)?;
            Ok((presence_flat, message_flat, *valid))
        })
        .collect();
    let per_chunk = per_chunk?;

    // Concatenate per-sample present-probabilities across chunks,
    // truncating the padded tail of the final chunk.
    let total_valid: usize = per_chunk.iter().map(|(_, _, v)| *v).sum();
    let mut present_per_sample: Vec<f32> = Vec::with_capacity(total_valid);
    for (presence_flat, _, valid) in &per_chunk {
        // presence shape: [1, 2, CHUNK_SAMPLES] flattened as
        // dim * CHUNK_SAMPLES + t. Channel 1 is "present".
        let present_start = CHUNK_SAMPLES; // dim=1 offset
        present_per_sample.extend(presence_flat[present_start..present_start + *valid].iter());
    }

    // Aggregate.
    let detection_probability = if total_valid > 0 {
        let above: usize = present_per_sample
            .iter()
            .filter(|p| **p > PRESENCE_THRESHOLD)
            .count();
        above as f32 / total_valid as f32
    } else {
        0.0
    };

    // Per-bit average across chunks (weighted equally; each chunk
    // already averages its own samples internally before sigmoid).
    let mut bit_probabilities = [0.0_f32; NBITS];
    if !per_chunk.is_empty() {
        for (_, message_flat, _) in &per_chunk {
            for (i, &v) in message_flat.iter().take(NBITS).enumerate() {
                bit_probabilities[i] += v;
            }
        }
        for v in bit_probabilities.iter_mut() {
            *v /= per_chunk.len() as f32;
        }
    }
    let message = pack_bits(&bit_probabilities);

    // Build marked regions.
    let marked_regions = regions_above_threshold(&present_per_sample, crate::audio::SAMPLE_RATE);

    Ok(DetectResult {
        detection_probability,
        message,
        bit_probabilities,
        marked_regions,
    })
}

/// Split the waveform into `CHUNK_SAMPLES`-sized chunks, zero-padding
/// the last one if needed. Returns `(chunk_buffer, valid_sample_count)`.
fn chunk_waveform(waveform: &[f32]) -> Vec<(Vec<f32>, usize)> {
    let n = waveform.len();
    let mut chunks = Vec::with_capacity(n.div_ceil(CHUNK_SAMPLES));
    let mut t_start = 0;
    while t_start < n {
        let valid = (n - t_start).min(CHUNK_SAMPLES);
        let mut buf = vec![0.0_f32; CHUNK_SAMPLES];
        buf[..valid].copy_from_slice(&waveform[t_start..t_start + valid]);
        chunks.push((buf, valid));
        t_start += valid;
    }
    if chunks.is_empty() {
        // empty input — produce one zero-padded chunk so the caller
        // still gets a defined inference path. The aggregation
        // handles total_valid == 0.
        chunks.push((vec![0.0_f32; CHUNK_SAMPLES], 0));
    }
    chunks
}

/// Threshold the 16 per-bit probabilities and pack into 2 big-endian
/// bytes. Bit 0 of `bit_probabilities` is the MSB of byte 0.
fn pack_bits(bit_probabilities: &[f32; NBITS]) -> [u8; 2] {
    let mut packed = [0u8; 2];
    for (i, p) in bit_probabilities.iter().enumerate() {
        if *p > 0.5 {
            let byte_idx = i / 8;
            let bit_idx = 7 - (i % 8);
            packed[byte_idx] |= 1 << bit_idx;
        }
    }
    packed
}

/// Walk per-sample presence probabilities and return contiguous
/// `(start_sec, end_sec)` spans above `PRESENCE_THRESHOLD` lasting
/// at least `MIN_REGION_SAMPLES`. Times are in seconds at
/// `sample_rate`.
fn regions_above_threshold(presence: &[f32], sample_rate: u32) -> Vec<(f32, f32)> {
    let mut out = Vec::new();
    let sr = sample_rate as f32;
    let mut start: Option<usize> = None;
    for (i, &p) in presence.iter().enumerate() {
        let above = p > PRESENCE_THRESHOLD;
        match (start, above) {
            (None, true) => start = Some(i),
            (Some(s), false) => {
                if i - s >= MIN_REGION_SAMPLES {
                    out.push((s as f32 / sr, i as f32 / sr));
                }
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        let end = presence.len();
        if end - s >= MIN_REGION_SAMPLES {
            out.push((s as f32 / sr, end as f32 / sr));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- Threshold + constant pins ----------

    #[test]
    fn presence_threshold_is_half() {
        // 0.5 is the documented decision boundary for the
        // per-sample presence probability. Pin so a future
        // tuning pass leaves an explicit test update behind.
        assert_eq!(PRESENCE_THRESHOLD, 0.5);
    }

    #[test]
    fn min_region_samples_is_one_second_at_16khz() {
        // 16_000 samples @ 16 kHz = 1 second. Pin.
        assert_eq!(MIN_REGION_SAMPLES, 16_000);
    }

    // ----- pack_bits exhaustive bit-position coverage ----------
    //
    // pack_bits is the wire-format projection from per-bit
    // probabilities to the 16-bit AudioSeal payload. Every bit
    // position must land at the documented byte+bit slot.

    #[test]
    fn pack_each_bit_position_independently() {
        // For each i in 0..16, setting only bp[i] above 0.5 must
        // produce exactly one set bit at the documented position
        // (byte = i/8, bit = 7 - i%8).
        for i in 0..NBITS {
            let mut bp = [0.0_f32; NBITS];
            bp[i] = 1.0;
            let packed = pack_bits(&bp);
            let byte_idx = i / 8;
            let bit_idx = 7 - (i % 8);
            let expected = 1u8 << bit_idx;
            assert_eq!(
                packed[byte_idx], expected,
                "bit {i} should land at byte {byte_idx}, bit {bit_idx}"
            );
            // Other byte should be untouched.
            let other = 1 - byte_idx;
            assert_eq!(packed[other], 0, "byte {other} should be 0 when only bit {i} is set");
        }
    }

    #[test]
    fn pack_threshold_is_strictly_greater_than_half() {
        // `p > 0.5` is strict — exactly 0.5 must NOT set the
        // bit. Pin the strictness explicitly.
        let mut bp = [0.0_f32; NBITS];
        bp[0] = 0.5;
        assert_eq!(pack_bits(&bp), [0x00, 0x00]);
    }

    #[test]
    fn pack_just_above_half_sets_bit() {
        let mut bp = [0.0_f32; NBITS];
        bp[0] = 0.5001;
        assert_eq!(pack_bits(&bp), [0x80, 0x00]);
    }

    // ----- regions_above_threshold edge cases ----------

    #[test]
    fn regions_empty_presence_returns_empty() {
        let regions = regions_above_threshold(&[], 16_000);
        assert!(regions.is_empty());
    }

    #[test]
    fn regions_all_below_threshold_returns_empty() {
        // 4 seconds of zero presence.
        let presence = vec![0.0_f32; 64_000];
        let regions = regions_above_threshold(&presence, 16_000);
        assert!(regions.is_empty());
    }

    #[test]
    fn regions_unterminated_run_at_end_still_reported() {
        // A run that reaches the end of the buffer (no trailing
        // below-threshold sample to close it) must still appear
        // if its length is >= MIN_REGION_SAMPLES.
        let mut presence = vec![0.0_f32; 64_000];
        // Last 2 seconds (32_000 samples) all above threshold.
        for v in presence.iter_mut().skip(32_000) {
            *v = 0.9;
        }
        let regions = regions_above_threshold(&presence, 16_000);
        assert_eq!(regions.len(), 1);
        let (start, end) = regions[0];
        assert!((start - 2.0).abs() < 0.01, "got start={start}");
        assert!((end - 4.0).abs() < 0.01, "got end={end}");
    }

    #[test]
    fn regions_multiple_runs_each_reported() {
        // Two long runs separated by a gap.
        let mut presence = vec![0.0_f32; 96_000]; // 6 s @ 16 kHz
        // Region 1: 0-1.5s
        for v in presence.iter_mut().take(24_000) {
            *v = 0.9;
        }
        // Gap: 1.5-3s (silent)
        // Region 2: 3-4.5s
        for v in presence.iter_mut().take(72_000).skip(48_000) {
            *v = 0.9;
        }
        let regions = regions_above_threshold(&presence, 16_000);
        assert_eq!(regions.len(), 2);
    }

    #[test]
    fn pack_all_zero_bits_yields_zero_bytes() {
        let bp = [0.0_f32; NBITS];
        assert_eq!(pack_bits(&bp), [0x00, 0x00]);
    }

    #[test]
    fn pack_all_one_bits_yields_ff() {
        let bp = [1.0_f32; NBITS];
        assert_eq!(pack_bits(&bp), [0xff, 0xff]);
    }

    #[test]
    fn pack_msb_first_byte0() {
        // bit 0 (= MSB of byte 0) above threshold → 0x80, 0x00.
        let mut bp = [0.0_f32; NBITS];
        bp[0] = 1.0;
        assert_eq!(pack_bits(&bp), [0x80, 0x00]);
    }

    #[test]
    fn pack_doomscroll_id() {
        // ID 0x0001 → bit 15 only.
        let mut bp = [0.0_f32; NBITS];
        bp[15] = 1.0;
        assert_eq!(pack_bits(&bp), [0x00, 0x01]);
    }

    #[test]
    fn regions_skip_short_spikes() {
        // Single sample above threshold should NOT be reported.
        let mut presence = vec![0.0_f32; 100_000];
        presence[50_000] = 0.9;
        let regions = regions_above_threshold(&presence, 16_000);
        assert!(regions.is_empty(), "lone-sample spike must be filtered");
    }

    #[test]
    fn regions_report_one_second_run() {
        let mut presence = vec![0.0_f32; 64_000]; // 4 s @ 16 kHz
        for v in presence.iter_mut().take(32_000).skip(16_000) {
            *v = 0.9;
        }
        let regions = regions_above_threshold(&presence, 16_000);
        assert_eq!(regions.len(), 1);
        let (start, end) = regions[0];
        assert!((start - 1.0).abs() < 0.01);
        assert!((end - 2.0).abs() < 0.01);
    }

    #[test]
    fn chunking_covers_exact_multiple_of_chunk() {
        let n = CHUNK_SAMPLES * 2;
        let waveform = vec![0.0_f32; n];
        let chunks = chunk_waveform(&waveform);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].1, CHUNK_SAMPLES);
        assert_eq!(chunks[1].1, CHUNK_SAMPLES);
    }

    #[test]
    fn chunking_pads_last_short_chunk() {
        let n = CHUNK_SAMPLES + 50;
        let waveform = vec![1.0_f32; n];
        let chunks = chunk_waveform(&waveform);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].1, CHUNK_SAMPLES);
        assert_eq!(chunks[1].1, 50);
        // Second chunk's first 50 samples = 1.0, rest = 0.0 (padding)
        assert_eq!(chunks[1].0[0], 1.0);
        assert_eq!(chunks[1].0[49], 1.0);
        assert_eq!(chunks[1].0[50], 0.0);
    }
}
