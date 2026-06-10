//! STFT front-end: mono 44.1 kHz waveform → `carrier` tensor
//! of shape `[1, 1, 2049, T]` that the silentcipher ONNX
//! decoder consumes.
//!
//! Implements, in order, exactly the steps the production
//! Python pipeline runs:
//!
//! 1. **VCTK energy rescale.** Scale the waveform so its mean
//!    square equals [`VCTK_AVG_ENERGY`](crate::hparams::VCTK_AVG_ENERGY).
//!    Mandatory — the model was trained on speech rescaled this
//!    way and silently degrades without it.
//! 2. **Tail zero-pad** to a multiple of [`WIN`](crate::hparams::WIN).
//!    This is an explicit pad performed before the STFT call,
//!    distinct from the reflect-pad done by torch's
//!    `center=True` mode (which we replicate in step 3).
//! 3. **Reflect-pad** `N_FFT / 2` samples on each end. This is
//!    torch's `stft(center=True, pad_mode='reflect')` default.
//! 4. **Frame, window (Hann), real-FFT, magnitude.** No
//!    normalization. Magnitude is plain `sqrt(re² + im²)`; the
//!    epsilon-on-zero-bins trick in the Python is a
//!    gradient-flow artefact that has no effect on inference
//!    output.
//! 5. **Reshape** to `[1, 1, FREQ_BINS, T]`.

use realfft::RealFftPlanner;
use realfft::num_complex::Complex;

use crate::hparams::{FREQ_BINS, HOP, N_FFT, VCTK_AVG_ENERGY, WIN};

/// Build the carrier tensor `[1, 1, FREQ_BINS, T]` (flattened
/// in row-major order: `bin * T + t`) from a mono 44.1 kHz
/// waveform.
///
/// Returns `(carrier, n_frames)`. The carrier is owned because
/// tract takes an owned tensor; copying once at the boundary is
/// fine — `provcheck` verifies one file at a time and
/// silentcipher inputs are short.
///
/// Returns `Err` only if the waveform is too short to produce
/// at least one STFT frame. Empty input would mean upstream
/// audio decode produced nothing.
pub fn waveform_to_carrier(waveform: &[f32]) -> Result<(Vec<f32>, usize), StftError> {
    if waveform.is_empty() {
        return Err(StftError::Empty);
    }

    // 1. VCTK energy rescale (in place into a fresh buffer).
    let mut y = vctk_rescale(waveform);

    // 2. Tail zero-pad to a multiple of WIN.
    let tail = WIN - (y.len() % WIN);
    if tail != WIN {
        y.extend(std::iter::repeat_n(0.0_f32, tail));
    }

    // 3. Reflect-pad N_FFT/2 on each end (torch center=True).
    let pad = N_FFT / 2;
    let y_padded = reflect_pad(&y, pad);

    // 4. Frame, window, FFT, magnitude.
    let n_frames = compute_n_frames(y_padded.len());
    if n_frames == 0 {
        return Err(StftError::TooShort);
    }

    let window = hann_window(WIN);
    let mut planner = RealFftPlanner::<f32>::new();
    let r2c = planner.plan_fft_forward(N_FFT);
    let mut in_buf = r2c.make_input_vec();
    let mut out_buf: Vec<Complex<f32>> = r2c.make_output_vec();
    debug_assert_eq!(out_buf.len(), FREQ_BINS);

    // Carrier laid out as [bin][t] → flat index = bin * T + t.
    let mut carrier = vec![0.0_f32; FREQ_BINS * n_frames];

    for t in 0..n_frames {
        let start = t * HOP;
        // Window the frame into in_buf.
        for (i, w) in window.iter().enumerate().take(WIN) {
            // Safe by construction: reflect_pad + n_frames math
            // guarantees `start + i < y_padded.len()`.
            in_buf[i] = y_padded[start + i] * w;
        }
        // Zero any trailing samples in in_buf — only relevant
        // when WIN < N_FFT, which isn't our case (WIN == N_FFT),
        // but keeps the function correct if someone retunes.
        for slot in in_buf.iter_mut().take(N_FFT).skip(WIN) {
            *slot = 0.0;
        }

        r2c.process(&mut in_buf, &mut out_buf)
            .expect("realfft input/output sizes are fixed by the planner");

        // Magnitude into the carrier at column t.
        for (bin, c) in out_buf.iter().enumerate() {
            let mag = (c.re * c.re + c.im * c.im).sqrt();
            carrier[bin * n_frames + t] = mag;
        }
    }

    Ok((carrier, n_frames))
}

/// Errors from the STFT pipeline. All bubble up to the
/// detector as a `WatermarkResult::message` rather than an
/// `Error::Io`-like failure.
#[derive(Debug, thiserror::Error)]
pub enum StftError {
    #[error("waveform is empty")]
    Empty,
    #[error("audio is shorter than the minimum STFT window")]
    TooShort,
}

/// Rescale `y` so that `mean(y²) == VCTK_AVG_ENERGY`, matching
/// the Python encoder/decoder convention. If the input is
/// effectively silent (`mean(y²)` near zero) we return a copy
/// of the original — silent input can't carry a watermark and
/// downstream code will report not-detected naturally.
fn vctk_rescale(y: &[f32]) -> Vec<f32> {
    let n = y.len() as f32;
    let mean_sq = y.iter().map(|s| s * s).sum::<f32>() / n;
    if mean_sq <= f32::EPSILON {
        return y.to_vec();
    }
    let scale = (VCTK_AVG_ENERGY / mean_sq).sqrt();
    y.iter().map(|s| s * scale).collect()
}

/// Reflect-pad the waveform by `pad` samples on each side.
/// Matches torch's `pad_mode='reflect'`: the padded value at
/// position `-k` is `y[k]` and at position `len+k` is
/// `y[len-2-k]`. This requires `pad < y.len()`, which holds
/// trivially here because we always tail-pad to a multiple of
/// `WIN > 2 * pad` before this step.
fn reflect_pad(y: &[f32], pad: usize) -> Vec<f32> {
    let n = y.len();
    let mut out = Vec::with_capacity(n + 2 * pad);
    // Head reflection: y[pad], y[pad-1], ..., y[1] — i.e.
    // mirror around index 0 *without* duplicating y[0].
    for k in (1..=pad).rev() {
        out.push(y[k.min(n - 1)]);
    }
    out.extend_from_slice(y);
    // Tail reflection: y[n-2], y[n-3], ..., y[n-1-pad] —
    // mirror around index n-1 without duplicating y[n-1].
    for k in 1..=pad {
        let idx = n.saturating_sub(1).saturating_sub(k);
        out.push(y[idx]);
    }
    out
}

/// Number of STFT frames produced from a padded waveform of
/// length `len`. Mirrors librosa/torch's frame count math for
/// `center=True`: frames = 1 + (len - N_FFT) / HOP, floored,
/// but only counting frames that fit inside `len` without
/// running past the end.
fn compute_n_frames(len: usize) -> usize {
    if len < N_FFT {
        0
    } else {
        1 + (len - N_FFT) / HOP
    }
}

/// Standard Hann window of length `n`:
/// `w[i] = 0.5 * (1 - cos(2π i / (n-1)))`.
fn hann_window(n: usize) -> Vec<f32> {
    let denom = (n - 1) as f32;
    (0..n)
        .map(|i| 0.5 * (1.0 - (2.0 * std::f32::consts::PI * i as f32 / denom).cos()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hann_window_starts_and_ends_at_zero() {
        let w = hann_window(WIN);
        assert!(w[0].abs() < 1e-6);
        assert!(w[WIN - 1].abs() < 1e-6);
        assert!((w[WIN / 2] - 1.0).abs() < 1e-6);
    }

    #[test]
    fn reflect_pad_matches_numpy_semantics() {
        // numpy.pad([1,2,3,4,5], 2, mode='reflect') = [3,2,1,2,3,4,5,4,3]
        let y = [1.0_f32, 2.0, 3.0, 4.0, 5.0];
        let padded = reflect_pad(&y, 2);
        assert_eq!(padded, vec![3.0, 2.0, 1.0, 2.0, 3.0, 4.0, 5.0, 4.0, 3.0]);
    }

    #[test]
    fn vctk_rescale_hits_target_energy() {
        let y: Vec<f32> = (0..1000).map(|i| (i as f32 * 0.01).sin()).collect();
        let rescaled = vctk_rescale(&y);
        let mean_sq = rescaled.iter().map(|s| s * s).sum::<f32>() / rescaled.len() as f32;
        assert!(
            (mean_sq - VCTK_AVG_ENERGY).abs() < 1e-6,
            "expected {}, got {}",
            VCTK_AVG_ENERGY,
            mean_sq
        );
    }

    #[test]
    fn vctk_rescale_handles_silence() {
        let y = vec![0.0_f32; 1000];
        let rescaled = vctk_rescale(&y);
        // Silence stays silent; never NaN.
        assert!(rescaled.iter().all(|s| *s == 0.0));
    }

    #[test]
    fn frame_count_matches_torch_for_known_input() {
        // For a waveform of WIN samples, after reflect-pad of
        // N_FFT/2 on each side we have WIN + N_FFT samples total.
        // With WIN == N_FFT == 4096 and HOP == 2048, that's
        // 1 + (8192 - 4096) / 2048 = 1 + 2 = 3 frames.
        let pad = N_FFT / 2;
        let padded_len = WIN + 2 * pad;
        assert_eq!(compute_n_frames(padded_len), 3);
    }

    #[test]
    fn stft_produces_expected_carrier_shape() {
        // 30 s at 44.1 kHz = 1_323_000 samples; way more than a
        // window. The carrier should have FREQ_BINS rows and
        // some plausibly large number of time frames.
        let n_samples = 44_100 * 30;
        let waveform: Vec<f32> = (0..n_samples)
            .map(|i| 0.05 * (i as f32 * 0.01).sin())
            .collect();
        let (carrier, t) = waveform_to_carrier(&waveform).unwrap();
        assert!(t > 600, "expected ~650 frames for 30s, got {t}");
        assert_eq!(carrier.len(), FREQ_BINS * t);
        // Sanity: bin 0 (DC) should be near zero for a pure sine.
        let dc_max = (0..t).map(|i| carrier[i].abs()).fold(0.0, f32::max);
        let mid_max = (0..t)
            .map(|i| carrier[(FREQ_BINS / 4) * t + i].abs())
            .fold(0.0, f32::max);
        // DC mass should be much smaller than mid-band mass for
        // a sine that lives well above DC.
        assert!(
            mid_max > dc_max * 5.0 || mid_max > 1e-3,
            "FFT looks degenerate: dc_max={dc_max}, mid_max={mid_max}"
        );
    }
}
