//! WavMark detection via sliding-window decode.
//!
//! Mirrors the upstream `wm_decode_util.extract_watermark_v3_batch`:
//!
//!  1. Slide a 1-second window across the input at `SHIFT_STEP`
//!     samples per step (50 ms by default — half the upstream's
//!     `shift_range=0.1, shift_range_p=0.5`).
//!  2. For each window, run [`crate::model::decode_chunk`] to recover
//!     32 bits.
//!  3. Keep windows where the recovered first-16-bits **exactly**
//!     match [`crate::model::WAVMARK_FIX_PATTERN`]. Exact match is
//!     the upstream's correctness criterion; any partial match is a
//!     false positive ([per the README: probability of any
//!     unwatermarked window matching is `1 / 2^16 = 1.5e-5`]).
//!  4. Across the kept windows, average the lower-16-bit floats per
//!     position then threshold at 0.5 to recover the custom payload.
//!
//! Aggregation rules into a [`DetectResult`]:
//!
//! - `detection_probability` = `kept_windows / total_windows`. Range
//!   `[0, 1]`. Real marked content typically gives ~50–90 % — every
//!   ~50 ms window inside a marked stretch hits, but boundary
//!   windows straddling marked/unmarked regions miss.
//! - `payload` = the 2-byte aggregated lower-16-bits message. Only
//!   meaningful when at least one window hit.
//! - `marked_regions`: contiguous time spans (seconds) where windows
//!   are hitting at >= [`REGION_MIN_HIT_RATIO`] over a rolling
//!   neighbourhood, lasting at least [`MIN_REGION_SECONDS`].

use rayon::prelude::*;

use crate::audio::SAMPLE_RATE;
use crate::model::{self, CHUNK_SAMPLES, FIX_PATTERN_LEN, ModelError, NUM_BITS, WAVMARK_FIX_PATTERN};

/// Slide step in samples between successive detection windows.
/// Upstream Python: `int(0.1 * 16000 * 0.5) = 800` (50 ms).
pub const SHIFT_STEP: usize = 800;

/// Minimum span duration (seconds) for a contiguous-hit run to be
/// reported in `marked_regions`. Shorter runs are dropped as
/// detection noise.
pub const MIN_REGION_SECONDS: f32 = 1.0;

/// Per-second hit-density threshold to count a 1-second tile as
/// "inside a marked region". Empirically, a fully WavMark-marked
/// 60 s clip produces ~25 % overall hit rate = ~5 windows/second
/// (the rest fail strict 16-bit fix-pattern match around chunk
/// boundaries). A 10 % floor (~2 windows/second) reliably catches
/// real marked stretches while staying well above the 1.5e-5
/// false-positive rate per window.
pub const REGION_MIN_HIT_RATIO: f32 = 0.10;

#[derive(Debug, Clone)]
pub struct DetectResult {
    /// Fraction of windows whose recovered first-16-bits matched the
    /// WavMark fix-pattern exactly. Range `[0, 1]`.
    pub detection_probability: f32,
    /// Number of windows that hit. Useful for diagnostics.
    pub matched_windows: usize,
    /// Total windows considered.
    pub total_windows: usize,
    /// Aggregated 16-bit lower-payload bytes (big-endian).
    pub payload: [u8; 2],
    /// Marked time-spans in seconds (start, end).
    pub marked_regions: Vec<(f32, f32)>,
}

/// Run the WavMark detector on a 16 kHz mono waveform.
pub fn detect(waveform: &[f32]) -> Result<DetectResult, ModelError> {
    if waveform.len() < CHUNK_SAMPLES {
        return Ok(DetectResult {
            detection_probability: 0.0,
            matched_windows: 0,
            total_windows: 0,
            payload: [0, 0],
            marked_regions: Vec::new(),
        });
    }

    // Window start positions, equally spaced.
    let total_windows = (waveform.len() - CHUNK_SAMPLES) / SHIFT_STEP + 1;
    let positions: Vec<usize> = (0..total_windows).map(|i| i * SHIFT_STEP).collect();

    // Decode every window in parallel. Each emits 32 floats in
    // [-1, 1] (post-clamp). We keep the float vector so we can
    // average the lower-16 across hit windows for ECC-friendly
    // aggregation.
    let decoded: Result<Vec<(usize, [f32; NUM_BITS])>, ModelError> = positions
        .par_iter()
        .map(|&p| {
            let bits = model::decode_chunk(&waveform[p..p + CHUNK_SAMPLES])?;
            Ok((p, bits))
        })
        .collect();
    let decoded = decoded?;

    // Filter to exact-fix-pattern matches.
    let mut hits: Vec<(usize, [f32; NUM_BITS])> = decoded
        .into_iter()
        .filter(|(_, bits)| matches_fix_pattern(bits))
        .collect();
    hits.sort_by_key(|(p, _)| *p);

    let matched_windows = hits.len();
    let detection_probability = matched_windows as f32 / total_windows as f32;

    let payload = if hits.is_empty() {
        [0, 0]
    } else {
        aggregate_lower_payload(&hits)
    };

    let marked_regions = if hits.is_empty() {
        Vec::new()
    } else {
        contiguous_hit_regions(&hits, total_windows)
    };

    Ok(DetectResult {
        detection_probability,
        matched_windows,
        total_windows,
        payload,
        marked_regions,
    })
}

fn matches_fix_pattern(bits: &[f32; NUM_BITS]) -> bool {
    for i in 0..FIX_PATTERN_LEN {
        let bit = if bits[i] >= 0.5 { 1u8 } else { 0u8 };
        if bit != WAVMARK_FIX_PATTERN[i] {
            return false;
        }
    }
    true
}

/// Average the lower-16 float positions across all hit windows, then
/// threshold at 0.5 to recover the 16-bit custom payload as 2
/// big-endian bytes. Bit 16 of the 32-bit message is the MSB of byte 0.
fn aggregate_lower_payload(hits: &[(usize, [f32; NUM_BITS])]) -> [u8; 2] {
    let mut sums = [0.0_f32; FIX_PATTERN_LEN];
    for (_, bits) in hits {
        for (i, slot) in sums.iter_mut().enumerate() {
            *slot += bits[FIX_PATTERN_LEN + i];
        }
    }
    let n = hits.len() as f32;
    let mut packed = [0u8; 2];
    for (i, &sum) in sums.iter().enumerate() {
        let avg = sum / n;
        if avg >= 0.5 {
            let byte_idx = i / 8;
            let bit_idx = 7 - (i % 8);
            packed[byte_idx] |= 1 << bit_idx;
        }
    }
    packed
}

/// Bucket hit positions into 1-second tiles, then walk consecutive
/// high-density tiles to produce contiguous `(start_sec, end_sec)`
/// regions ≥ [`MIN_REGION_SECONDS`].
fn contiguous_hit_regions(
    hits: &[(usize, [f32; NUM_BITS])],
    _total_windows: usize,
) -> Vec<(f32, f32)> {
    let sr = SAMPLE_RATE as f32;
    if hits.is_empty() {
        return Vec::new();
    }
    let windows_per_sec = sr / SHIFT_STEP as f32;
    let min_hits_per_tile = (REGION_MIN_HIT_RATIO * windows_per_sec).ceil() as usize;

    // Bucket: tile_sec → count
    let last_sec = ((hits.last().unwrap().0 + CHUNK_SAMPLES) as f32 / sr) as usize;
    let n_tiles = last_sec + 1;
    let mut tile_counts = vec![0usize; n_tiles];
    for (pos, _) in hits {
        let center_sec = (*pos as f32 / sr) as usize;
        if center_sec < n_tiles {
            tile_counts[center_sec] += 1;
        }
    }

    // Walk tiles, glue consecutive high-density ones into regions.
    let mut regions = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in tile_counts.iter().enumerate() {
        let hot = *c >= min_hits_per_tile;
        match (start, hot) {
            (None, true) => start = Some(i),
            (Some(s), false) => {
                let len = i - s;
                if len as f32 >= MIN_REGION_SECONDS {
                    regions.push((s as f32, i as f32));
                }
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        let end = n_tiles;
        if (end - s) as f32 >= MIN_REGION_SECONDS {
            regions.push((s as f32, end as f32));
        }
    }
    regions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fix_pattern_matches_exact() {
        let mut bits = [0.0_f32; NUM_BITS];
        for (i, &p) in WAVMARK_FIX_PATTERN.iter().enumerate() {
            bits[i] = if p == 1 { 1.0 } else { 0.0 };
        }
        assert!(matches_fix_pattern(&bits));
    }

    #[test]
    fn fix_pattern_rejects_one_off_bit() {
        let mut bits = [0.0_f32; NUM_BITS];
        for (i, &p) in WAVMARK_FIX_PATTERN.iter().enumerate() {
            bits[i] = if p == 1 { 1.0 } else { 0.0 };
        }
        bits[3] = 1.0 - bits[3]; // flip one
        assert!(!matches_fix_pattern(&bits));
    }

    #[test]
    fn empty_signal_returns_zero_detection() {
        let r = detect(&[]).unwrap();
        assert_eq!(r.detection_probability, 0.0);
        assert_eq!(r.matched_windows, 0);
    }

    #[test]
    fn signal_shorter_than_chunk_returns_zero_detection() {
        let waveform = vec![0.0_f32; CHUNK_SAMPLES - 1];
        let r = detect(&waveform).unwrap();
        assert_eq!(r.detection_probability, 0.0);
    }
}
