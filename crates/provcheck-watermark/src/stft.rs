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

    // 2. Tail zero-pad. silentcipher's reference always pads —
    //    even when `y.len() % WIN == 0`, it appends a full WIN
    //    zeros (see `pad = win_len - x.shape[1] % win_len` in
    //    silentcipher/stft.py; remainder 0 → pad = win_len). Our
    //    v0.3.2 skipped the pad in that exact case, which only
    //    matters for inputs that are an exact multiple of WIN
    //    samples but counts as a real precision divergence vs
    //    the reference.
    let tail = WIN - (y.len() % WIN);
    y.extend(std::iter::repeat_n(0.0_f32, tail));

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
/// Frame count for an N-sample padded input under our HOP / N_FFT
/// scheme. Public so callers using the streaming primitives
/// directly (`forward_stft_chunk` + `IstftStreamer`) can size their
/// own pipelines without re-deriving the math.
pub fn compute_n_frames(len: usize) -> usize {
    if len < N_FFT {
        0
    } else {
        1 + (len - N_FFT) / HOP
    }
}

/// Periodic Hann window of length `n`:
/// `w[i] = 0.5 * (1 - cos(2π i / n))`.
///
/// Periodic (not symmetric). silentcipher's training pipeline
/// uses `torch.stft(..., window=torch.hann_window(n_fft))`, and
/// `torch.hann_window` defaults to `periodic=True` — which
/// divides by `n`, not `n - 1`. The two windows differ by a
/// small amount everywhere, but applied frame-by-frame the
/// resulting magnitudes shift just enough to push the decoder
/// into low-confidence territory on real inputs (the model was
/// trained on periodic-window magnitudes). Empirically caught
/// via examples/decode_inspect.rs: symmetric Hann gave ~24%
/// terminator confidence on a file where the Python reference
/// hits 95%.
/// Output of the embedding-side forward STFT. Carries both magnitude
/// and phase so the iSTFT can reconstruct the time-domain waveform
/// after the watermark encoder modifies the magnitude.
///
/// Layout: `[FREQ_BINS, n_frames]` row-major, same as the carrier
/// produced by [`waveform_to_carrier`].
///
/// `n_samples_input` is the length of the input passed to
/// [`waveform_to_spectrum`] AFTER the silentcipher tail-pad
/// (`pad = WIN - (raw_len % WIN)`). [`spectrum_to_waveform`] uses
/// it to undo the tail-pad on output. Caller is responsible for
/// remembering the pre-tail-pad length if VCTK de-rescale needs it.
pub struct Spectrum {
    pub magnitude: Vec<f32>,
    pub phase: Vec<f32>,
    pub n_frames: usize,
    pub n_samples_input: usize,
}

/// Forward STFT for the embedding path. Returns magnitude AND phase.
///
/// Differs from [`waveform_to_carrier`] in two ways:
///   1. NO VCTK rescale. Caller is expected to have already done it
///      (or to skip it deliberately). Embedding does its own VCTK
///      bookkeeping because it needs to undo the rescale after iSTFT.
///   2. Returns phase alongside magnitude. The decoder needs only
///      magnitude; the encoder pipeline needs phase to reconstruct.
///
/// v0.6.0 P3 phase 3a: drops the `y_padded` intermediate buffer
/// (~600 MB on a 56-minute 44.1 kHz episode). Each frame's samples
/// are computed on demand from the input `waveform` slice via
/// [`effective_sample`], which encodes the silentcipher tail-pad and
/// the reflect-pad-N/2 boundary inline rather than materialising
/// the padded buffer.
pub fn waveform_to_spectrum(waveform: &[f32]) -> Result<Spectrum, StftError> {
    if waveform.is_empty() {
        return Err(StftError::Empty);
    }
    let n_samples_input = waveform.len() + (WIN - (waveform.len() % WIN));
    let pad = N_FFT / 2;
    let padded_len = n_samples_input + 2 * pad;
    let n_frames = compute_n_frames(padded_len);
    if n_frames == 0 {
        return Err(StftError::TooShort);
    }

    let window = hann_window(WIN);
    let mut planner = RealFftPlanner::<f32>::new();
    let r2c = planner.plan_fft_forward(N_FFT);
    let mut in_buf = r2c.make_input_vec();
    let mut out_buf: Vec<Complex<f32>> = r2c.make_output_vec();

    let mut magnitude = vec![0.0_f32; FREQ_BINS * n_frames];
    let mut phase = vec![0.0_f32; FREQ_BINS * n_frames];

    for t in 0..n_frames {
        let start = t * HOP;
        for (i, w) in window.iter().enumerate().take(WIN) {
            in_buf[i] = effective_sample(start + i, waveform, n_samples_input, pad) * w;
        }
        for slot in in_buf.iter_mut().take(N_FFT).skip(WIN) {
            *slot = 0.0;
        }
        r2c.process(&mut in_buf, &mut out_buf)
            .expect("realfft sizes fixed by planner");

        for (bin, c) in out_buf.iter().enumerate() {
            magnitude[bin * n_frames + t] = (c.re * c.re + c.im * c.im).sqrt();
            phase[bin * n_frames + t] = c.im.atan2(c.re);
        }
    }

    Ok(Spectrum {
        magnitude,
        phase,
        n_frames,
        n_samples_input,
    })
}

/// Compute the sample value at index `i` in the conceptual padded
/// buffer (silentcipher tail-pad to multiple of `WIN`, then
/// reflect-pad `N_FFT/2` on each end) without materialising the
/// padded buffer in memory.
///
/// v0.6.0 P3 phase 3a foundation: replaces the ~600 MB `y_padded`
/// vector on a 56-minute 44.1 kHz episode with O(1) per-sample
/// addressing.
///
/// Mirrors [`reflect_pad`] (kept around for `waveform_to_carrier`
/// which still materialises in the detector path): head reflection
/// is `y[pad - i]` clamped to `[0, n_samples_input)`, mid is the
/// raw waveform (or zero in the tail-pad zone), tail reflection is
/// `y[2*n_samples_input - 2 - (i - pad)]` clamped to a valid index.
#[inline]
fn effective_sample(i: usize, waveform: &[f32], n_samples_input: usize, pad: usize) -> f32 {
    let n = n_samples_input;
    // Mid (the most common branch — hot path; check first).
    if i >= pad && i < pad + n {
        let src = i - pad;
        // src < waveform.len() returns the real sample;
        // src >= waveform.len() means we're in the silentcipher
        // tail-pad zone and the value is zero.
        return waveform.get(src).copied().unwrap_or(0.0);
    }
    if i < pad {
        // Head reflection: y[(pad - i).min(n-1)]
        let src = (pad - i).min(n.saturating_sub(1));
        return waveform.get(src).copied().unwrap_or(0.0);
    }
    // Tail reflection: y[2n - 2 - (i - pad)] clamped to [0, n).
    let off = i - pad;
    let src = (2 * n).saturating_sub(2).saturating_sub(off);
    waveform.get(src).copied().unwrap_or(0.0)
}

/// Inverse STFT — overlap-add reconstruction from magnitude + phase.
///
/// Under torch's `center=True` Hann + 50% overlap convention the COLA
/// condition isn't perfectly met for plain overlap-add, so we apply
/// the standard sum-of-squared-windows normalisation (torch.istft does
/// the same). The result round-trips a `waveform_to_spectrum` →
/// modify-mag-only → `spectrum_to_waveform` cycle to within f32
/// round-off in the interior, with edge artefacts confined to the
/// first/last few frames (which fall inside the silentcipher tail-pad
/// we trim). Returns a waveform of the same length the caller
/// originally fed into `waveform_to_spectrum` (minus the tail-pad).
/// The reflect-pad head/tail are also trimmed.
pub fn spectrum_to_waveform(spec: &Spectrum) -> Result<Vec<f32>, StftError> {
    if spec.n_frames == 0 {
        return Err(StftError::TooShort);
    }
    let mut streamer = IstftStreamer::new(spec.n_frames, spec.n_samples_input)?;
    let mut mag_frame = vec![0.0_f32; FREQ_BINS];
    let mut phase_frame = vec![0.0_f32; FREQ_BINS];
    for t in 0..spec.n_frames {
        for bin in 0..FREQ_BINS {
            mag_frame[bin] = spec.magnitude[bin * spec.n_frames + t];
            phase_frame[bin] = spec.phase[bin * spec.n_frames + t];
        }
        streamer.push_frame(&mag_frame, &phase_frame);
    }
    Ok(streamer.finish())
}

/// Streaming overlap-add iSTFT. Accepts magnitude + phase frames
/// one at a time and emits samples as they become final (no future
/// frame can contribute). Builds the output waveform incrementally
/// without holding a full `Spectrum` or any padded_len intermediate
/// buffer.
///
/// Memory: O(WIN) ring buffers (~32 KB) plus the output body
/// (trimmed_len samples) being accumulated. The body itself can be
/// removed in a future phase 3c by accepting a `Write` callback at
/// construction time.
///
/// Usage:
/// ```ignore
/// let mut s = IstftStreamer::new(n_frames, n_samples_input)?;
/// for (mag, phase) in frames {
///     s.push_frame(&mag, &phase);
/// }
/// let waveform = s.finish();
/// ```
pub struct IstftStreamer {
    window: Vec<f32>,
    c2r: std::sync::Arc<dyn realfft::ComplexToReal<f32>>,
    in_buf: Vec<Complex<f32>>,
    out_buf: Vec<f32>,
    n_fft_inv: f32,
    n_frames: usize,
    head_trim: usize,
    trimmed_len: usize,
    ring_sum: Vec<f32>,
    ring_norm: Vec<f32>,
    ring_start: usize,
    emitted: usize,
    frames_processed: usize,
    body: Vec<f32>,
}

impl IstftStreamer {
    pub fn new(n_frames: usize, n_samples_input: usize) -> Result<Self, StftError> {
        if n_frames == 0 {
            return Err(StftError::TooShort);
        }
        let window = hann_window(WIN);
        let mut planner = RealFftPlanner::<f32>::new();
        let c2r = planner.plan_fft_inverse(N_FFT);
        let in_buf: Vec<Complex<f32>> = c2r.make_input_vec();
        let out_buf = c2r.make_output_vec();
        let n_fft_inv = 1.0_f32 / (N_FFT as f32);
        let padded_len = (n_frames - 1) * HOP + N_FFT;
        let head_trim = N_FFT / 2;
        let trimmed_len = padded_len - 2 * head_trim;
        debug_assert_eq!(trimmed_len, n_samples_input);
        Ok(Self {
            window,
            c2r,
            in_buf,
            out_buf,
            n_fft_inv,
            n_frames,
            head_trim,
            trimmed_len,
            ring_sum: vec![0.0_f32; WIN],
            ring_norm: vec![0.0_f32; WIN],
            ring_start: 0,
            emitted: 0,
            frames_processed: 0,
            body: Vec::with_capacity(trimmed_len),
        })
    }

    /// Push one magnitude + phase frame (each of length `FREQ_BINS`).
    /// Internally runs an iFFT, accumulates into the ring, and emits
    /// `HOP` samples of finalised output.
    pub fn push_frame(&mut self, magnitude: &[f32], phase: &[f32]) {
        debug_assert_eq!(magnitude.len(), FREQ_BINS);
        debug_assert_eq!(phase.len(), FREQ_BINS);
        debug_assert!(self.frames_processed < self.n_frames);

        for (bin, slot) in self.in_buf.iter_mut().enumerate().take(FREQ_BINS) {
            let mag = magnitude[bin];
            let ph = phase[bin];
            *slot = Complex::new(mag * ph.cos(), mag * ph.sin());
        }
        self.in_buf[0].im = 0.0;
        self.in_buf[FREQ_BINS - 1].im = 0.0;
        self.c2r
            .process(&mut self.in_buf, &mut self.out_buf)
            .expect("realfft sizes fixed by planner");

        let frame_start = self.frames_processed * HOP;
        let align = frame_start - self.ring_start;
        debug_assert!(align + WIN <= self.ring_sum.len());
        for i in 0..WIN {
            let w = self.window[i];
            self.ring_sum[align + i] += self.out_buf[i] * w * self.n_fft_inv;
            self.ring_norm[align + i] += w * w;
        }

        // Emit first HOP samples of the ring (final after this frame).
        let mut pos = self.ring_start;
        for i in 0..HOP {
            Self::emit_one(
                self.ring_sum[i],
                self.ring_norm[i],
                &mut self.body,
                &mut pos,
                &mut self.emitted,
                self.head_trim,
                self.trimmed_len,
            );
        }
        self.ring_sum.copy_within(HOP..WIN, 0);
        self.ring_norm.copy_within(HOP..WIN, 0);
        for slot in &mut self.ring_sum[WIN - HOP..] {
            *slot = 0.0;
        }
        for slot in &mut self.ring_norm[WIN - HOP..] {
            *slot = 0.0;
        }
        self.ring_start += HOP;
        self.frames_processed += 1;
    }

    /// Flush the remaining ring buffer (the last frame's tail that
    /// no further frame would have contributed to) and return the
    /// reconstructed body waveform of length `n_samples_input`.
    pub fn finish(mut self) -> Vec<f32> {
        let mut pos = self.ring_start;
        for i in 0..(WIN - HOP) {
            Self::emit_one(
                self.ring_sum[i],
                self.ring_norm[i],
                &mut self.body,
                &mut pos,
                &mut self.emitted,
                self.head_trim,
                self.trimmed_len,
            );
        }
        self.body
    }

    #[inline]
    fn emit_one(
        sum_val: f32,
        norm_val: f32,
        body: &mut Vec<f32>,
        ring_pos: &mut usize,
        emitted: &mut usize,
        head_trim: usize,
        trimmed_len: usize,
    ) {
        let padded_pos = *ring_pos;
        *ring_pos += 1;
        if padded_pos < head_trim {
            return;
        }
        if *emitted >= trimmed_len {
            return;
        }
        let v = if norm_val > f32::EPSILON {
            sum_val / norm_val
        } else {
            sum_val
        };
        body.push(v);
        *emitted += 1;
    }
}

/// Compute magnitude + phase for a contiguous time slice of frames
/// `[t_start, t_start + chunk_t)` without materialising the full
/// spectrogram. Used by the v0.6.0 P3 chunk-fused embed path.
///
/// Returns `(magnitude, phase)`, each laid out as `[bin * chunk_t + t]`
/// of length `FREQ_BINS * chunk_t`.
///
/// `n_samples_input` is the silentcipher tail-padded length (the
/// same value that `waveform_to_spectrum` returns in its Spectrum).
/// Caller must pass the same value across all chunks of one pass so
/// the boundary reflection math agrees.
pub fn forward_stft_chunk(
    waveform: &[f32],
    n_samples_input: usize,
    t_start: usize,
    chunk_t: usize,
) -> Result<(Vec<f32>, Vec<f32>), StftError> {
    if waveform.is_empty() {
        return Err(StftError::Empty);
    }
    let pad = N_FFT / 2;
    let window = hann_window(WIN);
    let mut planner = RealFftPlanner::<f32>::new();
    let r2c = planner.plan_fft_forward(N_FFT);
    let mut in_buf = r2c.make_input_vec();
    let mut out_buf: Vec<Complex<f32>> = r2c.make_output_vec();

    let mut magnitude = vec![0.0_f32; FREQ_BINS * chunk_t];
    let mut phase = vec![0.0_f32; FREQ_BINS * chunk_t];

    for t_local in 0..chunk_t {
        let t = t_start + t_local;
        let start = t * HOP;
        for (i, w) in window.iter().enumerate().take(WIN) {
            in_buf[i] = effective_sample(start + i, waveform, n_samples_input, pad) * w;
        }
        for slot in in_buf.iter_mut().take(N_FFT).skip(WIN) {
            *slot = 0.0;
        }
        r2c.process(&mut in_buf, &mut out_buf)
            .expect("realfft sizes fixed by planner");
        for (bin, c) in out_buf.iter().enumerate() {
            magnitude[bin * chunk_t + t_local] = (c.re * c.re + c.im * c.im).sqrt();
            phase[bin * chunk_t + t_local] = c.im.atan2(c.re);
        }
    }
    Ok((magnitude, phase))
}

/// One-pass streaming computation of silentcipher's `utterance_norm`
/// = `sqrt(mean(magnitude²))` over the full spectrogram, without
/// materialising the spectrogram.
///
/// Used by the chunk-fused embed pass to obtain the global rescale
/// constant before the second pass produces output frames.
pub fn streaming_utterance_norm(waveform: &[f32]) -> Result<f32, StftError> {
    if waveform.is_empty() {
        return Err(StftError::Empty);
    }
    let n_samples_input = waveform.len() + (WIN - (waveform.len() % WIN));
    let pad = N_FFT / 2;
    let padded_len = n_samples_input + 2 * pad;
    let n_frames = compute_n_frames(padded_len);
    if n_frames == 0 {
        return Err(StftError::TooShort);
    }
    let window = hann_window(WIN);
    let mut planner = RealFftPlanner::<f32>::new();
    let r2c = planner.plan_fft_forward(N_FFT);
    let mut in_buf = r2c.make_input_vec();
    let mut out_buf: Vec<Complex<f32>> = r2c.make_output_vec();

    let mut sum_sq: f64 = 0.0;
    for t in 0..n_frames {
        let start = t * HOP;
        for (i, w) in window.iter().enumerate().take(WIN) {
            in_buf[i] = effective_sample(start + i, waveform, n_samples_input, pad) * w;
        }
        for slot in in_buf.iter_mut().take(N_FFT).skip(WIN) {
            *slot = 0.0;
        }
        r2c.process(&mut in_buf, &mut out_buf)
            .expect("realfft sizes fixed by planner");
        for c in &out_buf {
            let m = ((c.re * c.re + c.im * c.im) as f64).sqrt();
            sum_sq += m * m;
        }
    }
    let count = (FREQ_BINS * n_frames) as f64;
    Ok((sum_sq / count).sqrt() as f32)
}

fn hann_window(n: usize) -> Vec<f32> {
    let denom = n as f32;
    (0..n)
        .map(|i| 0.5 * (1.0 - (2.0 * std::f32::consts::PI * i as f32 / denom).cos()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hann_window_periodic_shape() {
        let w = hann_window(WIN);
        // Periodic Hann: w[0] is exactly zero. w[n-1] is small but
        // nonzero (the symmetric variant would force it to exactly
        // zero). w[n/2] is exactly 1 because cos(π) = -1.
        assert!(w[0].abs() < 1e-6, "w[0] = {}", w[0]);
        assert!(
            w[WIN - 1] > 0.0 && w[WIN - 1] < 1e-4,
            "w[WIN-1] should be small-but-nonzero (periodic), got {}",
            w[WIN - 1]
        );
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
    fn exact_window_multiple_input_still_tail_pads() {
        // silentcipher's stft.py computes
        // `pad = win_len - x.shape[1] % win_len`, which evaluates to
        // a full `win_len` of zeros when the remainder is 0. v0.3.2
        // skipped the pad in that exact case and quietly shifted
        // every downstream frame. This test fixes the invariant:
        // input length WIN must yield 5 frames (with-pad), not 3
        // (without-pad). The math:
        //   WIN samples → tail-pad WIN → 2*WIN → reflect-pad
        //   N_FFT/2 each side → 2*WIN + N_FFT samples →
        //   1 + (2*WIN + N_FFT - N_FFT) / HOP = 1 + 2*WIN/HOP = 5.
        let waveform: Vec<f32> = (0..WIN).map(|i| 0.05 * (i as f32 * 0.01).sin()).collect();
        let (_carrier, n_frames) = waveform_to_carrier(&waveform).unwrap();
        assert_eq!(
            n_frames, 5,
            "always-pad invariant broken: expected 5 frames for \
             exact-WIN input, got {n_frames}. silentcipher's stft.py \
             always pads, even when remainder is 0; do not 'optimise' \
             this away."
        );
    }

    #[test]
    fn spectrum_round_trips_within_f32_tolerance() {
        // Synthesise a few seconds of mixed sines; pass through
        // forward STFT + inverse STFT and confirm the body of the
        // signal reconstructs to within f32 round-off. Edge artefacts
        // near the head/tail of the reconstructed buffer are
        // expected for any windowed STFT — we only check the
        // interior, which is what the watermark embedder cares about.
        let n = WIN * 8; // 8 windows worth — plenty for overlap-add to stabilise
        let waveform: Vec<f32> = (0..n)
            .map(|i| {
                let t = i as f32 / 44_100.0;
                0.3 * (2.0 * std::f32::consts::PI * 440.0 * t).sin()
                    + 0.2 * (2.0 * std::f32::consts::PI * 1320.0 * t).sin()
            })
            .collect();

        let spec = waveform_to_spectrum(&waveform).expect("forward stft");
        let reconstructed = spectrum_to_waveform(&spec).expect("inverse stft");

        // Reconstructed should at least cover the original input
        // length; we ignore the silentcipher tail-pad samples.
        assert!(reconstructed.len() >= n, "reconstructed too short");

        // Interior region — skip first/last WIN samples to dodge
        // window-edge artefacts.
        let start = WIN;
        let end = n - WIN;
        let mut max_diff = 0.0_f32;
        let mut sum_sq_diff = 0.0_f64;
        let mut count = 0;
        for i in start..end {
            let d = (reconstructed[i] - waveform[i]).abs();
            if d > max_diff {
                max_diff = d;
            }
            sum_sq_diff += (d as f64) * (d as f64);
            count += 1;
        }
        let rmsd = (sum_sq_diff / count as f64).sqrt();
        let in_rms: f64 = (waveform[start..end]
            .iter()
            .map(|s| (*s as f64).powi(2))
            .sum::<f64>()
            / count as f64)
            .sqrt();
        let sdr_db = 20.0 * (in_rms / rmsd).log10();
        eprintln!("iSTFT round-trip: L∞ = {max_diff:.4e}, RMSD = {rmsd:.4e}, SDR = {sdr_db:.1} dB");
        assert!(
            max_diff < 1e-3,
            "iSTFT round-trip L∞ = {max_diff:.4e} (RMSD = {rmsd:.4e}); expected < 1e-3"
        );
    }

    /// v0.6.0 P3 phase 3a: confirm the streaming forward STFT
    /// produces bit-identical output to the materialised-buffer
    /// reference implementation. Tracks the regression risk of
    /// the `effective_sample` reflection-on-the-fly math.
    fn waveform_to_spectrum_reference(waveform: &[f32]) -> Result<Spectrum, StftError> {
        // Old, materialised-buffer path. Kept here as the test
        // oracle. If `effective_sample` ever drifts, this catches it.
        if waveform.is_empty() {
            return Err(StftError::Empty);
        }
        let n_samples_input = waveform.len() + (WIN - (waveform.len() % WIN));
        let mut y = Vec::with_capacity(n_samples_input);
        y.extend_from_slice(waveform);
        y.resize(n_samples_input, 0.0);
        let pad = N_FFT / 2;
        let y_padded = reflect_pad(&y, pad);
        let n_frames = compute_n_frames(y_padded.len());
        if n_frames == 0 {
            return Err(StftError::TooShort);
        }
        let window = hann_window(WIN);
        let mut planner = RealFftPlanner::<f32>::new();
        let r2c = planner.plan_fft_forward(N_FFT);
        let mut in_buf = r2c.make_input_vec();
        let mut out_buf: Vec<Complex<f32>> = r2c.make_output_vec();
        let mut magnitude = vec![0.0_f32; FREQ_BINS * n_frames];
        let mut phase = vec![0.0_f32; FREQ_BINS * n_frames];
        for t in 0..n_frames {
            let start = t * HOP;
            for (i, w) in window.iter().enumerate().take(WIN) {
                in_buf[i] = y_padded[start + i] * w;
            }
            for slot in in_buf.iter_mut().take(N_FFT).skip(WIN) {
                *slot = 0.0;
            }
            r2c.process(&mut in_buf, &mut out_buf)
                .expect("realfft sizes fixed by planner");
            for (bin, c) in out_buf.iter().enumerate() {
                magnitude[bin * n_frames + t] = (c.re * c.re + c.im * c.im).sqrt();
                phase[bin * n_frames + t] = c.im.atan2(c.re);
            }
        }
        Ok(Spectrum {
            magnitude,
            phase,
            n_frames,
            n_samples_input,
        })
    }

    #[test]
    fn forward_stft_chunk_matches_full_spectrum_slice() {
        // forward_stft_chunk computes the same (magnitude, phase)
        // values for frames [t_start, t_start + chunk_t) as
        // waveform_to_spectrum would over the full input. Bit-exact:
        // the FFT planner is deterministic and effective_sample is
        // pure.
        let n = WIN * 6 + 271;
        let waveform: Vec<f32> = (0..n)
            .map(|i| {
                let t = i as f32 / 44_100.0;
                0.25 * (2.0 * std::f32::consts::PI * 660.0 * t).sin()
                    + 0.15 * (2.0 * std::f32::consts::PI * 2200.0 * t).cos()
            })
            .collect();
        let full = waveform_to_spectrum(&waveform).expect("full");
        let chunk_t = 4;
        for t_start in [0_usize, 2, full.n_frames / 2, full.n_frames - chunk_t] {
            let (mag_chunk, phase_chunk) =
                forward_stft_chunk(&waveform, full.n_samples_input, t_start, chunk_t)
                    .expect("chunk");
            for t_local in 0..chunk_t {
                let t = t_start + t_local;
                for bin in 0..FREQ_BINS {
                    let m_full = full.magnitude[bin * full.n_frames + t];
                    let m_chunk = mag_chunk[bin * chunk_t + t_local];
                    assert_eq!(
                        m_full.to_bits(),
                        m_chunk.to_bits(),
                        "mag mismatch at bin={bin} t={t} (chunk t_start={t_start})"
                    );
                    let p_full = full.phase[bin * full.n_frames + t];
                    let p_chunk = phase_chunk[bin * chunk_t + t_local];
                    assert_eq!(
                        p_full.to_bits(),
                        p_chunk.to_bits(),
                        "phase mismatch at bin={bin} t={t}"
                    );
                }
            }
        }
    }

    #[test]
    fn streaming_utterance_norm_matches_full_spectrum() {
        // streaming_utterance_norm should produce a value within
        // numerical-precision tolerance of sqrt(mean(spec.magnitude²))
        // computed from the full spectrum. f64 accumulation in both
        // paths means the tolerance is very tight.
        let n = WIN * 5 + 99;
        let waveform: Vec<f32> = (0..n)
            .map(|i| {
                let t = i as f32 / 44_100.0;
                0.3 * (2.0 * std::f32::consts::PI * 440.0 * t).sin()
            })
            .collect();
        let full = waveform_to_spectrum(&waveform).expect("full");
        let stream_norm = streaming_utterance_norm(&waveform).expect("stream");
        let full_sum_sq: f64 = full.magnitude.iter().map(|x| (*x as f64).powi(2)).sum();
        let full_count = (FREQ_BINS * full.n_frames) as f64;
        let full_norm = (full_sum_sq / full_count).sqrt() as f32;
        let rel_err = (stream_norm - full_norm).abs() / full_norm.max(f32::EPSILON);
        assert!(
            rel_err < 1e-5,
            "stream={stream_norm} full={full_norm} rel_err={rel_err}"
        );
    }

    #[test]
    fn streaming_forward_stft_matches_materialised_reference() {
        // Multi-second mixed-sine input crossing several STFT frame
        // boundaries so the reflection math gets exercised at both
        // ends. The reference path materialises y_padded; the
        // production path uses effective_sample. They must produce
        // bit-identical f32 output (the same FFT planner and same
        // sample values feed the same realfft kernel).
        let n = WIN * 5 + 137; // off-window-multiple length forces tail-pad
        let waveform: Vec<f32> = (0..n)
            .map(|i| {
                let t = i as f32 / 44_100.0;
                0.3 * (2.0 * std::f32::consts::PI * 440.0 * t).sin()
                    + 0.2 * (2.0 * std::f32::consts::PI * 1320.0 * t).sin()
            })
            .collect();
        let prod = waveform_to_spectrum(&waveform).expect("prod");
        let refr = waveform_to_spectrum_reference(&waveform).expect("ref");
        assert_eq!(prod.n_frames, refr.n_frames);
        assert_eq!(prod.n_samples_input, refr.n_samples_input);
        assert_eq!(prod.magnitude.len(), refr.magnitude.len());
        for (i, (a, b)) in prod.magnitude.iter().zip(refr.magnitude.iter()).enumerate() {
            assert_eq!(
                a.to_bits(),
                b.to_bits(),
                "magnitude[{i}] differs: prod={a} ref={b}"
            );
        }
        for (i, (a, b)) in prod.phase.iter().zip(refr.phase.iter()).enumerate() {
            assert_eq!(
                a.to_bits(),
                b.to_bits(),
                "phase[{i}] differs: prod={a} ref={b}"
            );
        }
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
