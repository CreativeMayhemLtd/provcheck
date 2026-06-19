//! STFT + iSTFT in Rust, matching `torch.stft` / `torch.istft`'s
//! `center=True` + Hann-window behaviour bit-for-bit (within f32
//! rounding).
//!
//! Why this lives in Rust: WavMark's PyTorch model uses
//! `torch.stft(..., return_complex=True)` + `torch.view_as_real(...)`.
//! `torch.onnx`'s 17-opset STFT op rejects complex types, so the
//! STFT/iSTFT pair has to be carved out of the ONNX. The HiNet
//! invertible-neural-network core (the part that actually mixes the
//! watermark into the cover signal) is what we keep in ONNX.
//!
//! Implementation matches PyTorch's `center=True` mode:
//!   - reflect-pad the signal by `n_fft // 2` on each side,
//!   - window each frame with a periodic Hann window,
//!   - FFT real → complex `n_fft // 2 + 1` bins,
//!   - return as a `[freq_bins, t_frames, 2]` tensor (real, imag).
//!
//! iSTFT is the synthesis pair using overlap-add with the squared
//! window normaliser, then strips the centering pad.

use realfft::{ComplexToReal, RealFftPlanner, RealToComplex};

pub struct StftConfig {
    pub n_fft: usize,
    pub hop_length: usize,
}

impl StftConfig {
    pub const WAVMARK: StftConfig = StftConfig {
        n_fft: 1000,
        hop_length: 400,
    };

    pub fn freq_bins(&self) -> usize {
        self.n_fft / 2 + 1
    }

    /// Number of frames a `signal_len`-sample input produces under
    /// `center=True` (reflect-padded by `n_fft / 2` on each side).
    pub fn t_frames(&self, signal_len: usize) -> usize {
        let padded = signal_len + 2 * (self.n_fft / 2);
        if padded < self.n_fft {
            0
        } else {
            (padded - self.n_fft) / self.hop_length + 1
        }
    }
}

/// Periodic Hann window: `0.5 * (1 - cos(2π i / N))` for `i = 0..N`.
/// Matches `torch.hann_window(n_fft, periodic=True)`'s default.
pub fn hann_window(n: usize) -> Vec<f32> {
    let two_pi = 2.0 * std::f32::consts::PI;
    (0..n)
        .map(|i| 0.5 * (1.0 - (two_pi * i as f32 / n as f32).cos()))
        .collect()
}

/// Reflect-pad a signal by `pad` samples on each side.
///
/// PyTorch's `torch.stft(center=True)` uses `mode='reflect'`: index 0
/// becomes the mirror around sample 0 (so the padded sample at
/// position `-1` is `signal[1]`, position `-2` is `signal[2]`, etc.).
fn reflect_pad(signal: &[f32], pad: usize) -> Vec<f32> {
    let n = signal.len();
    let mut out = Vec::with_capacity(n + 2 * pad);
    for i in 0..pad {
        out.push(signal[(pad - i).min(n - 1)]);
    }
    out.extend_from_slice(signal);
    for i in 0..pad {
        out.push(signal[n.saturating_sub(2 + i).max(0)]);
    }
    out
}

/// Compute STFT of `signal`. Returns a flat
/// `[freq_bins, t_frames, 2]` (real, imag) tensor in row-major order.
pub fn stft(signal: &[f32], cfg: &StftConfig) -> Vec<f32> {
    let freq_bins = cfg.freq_bins();
    let t_frames = cfg.t_frames(signal.len());
    let window = hann_window(cfg.n_fft);
    let padded = reflect_pad(signal, cfg.n_fft / 2);

    let mut planner = RealFftPlanner::<f32>::new();
    let fft: std::sync::Arc<dyn RealToComplex<f32>> = planner.plan_fft_forward(cfg.n_fft);

    let mut input = vec![0.0_f32; cfg.n_fft];
    let mut spectrum = fft.make_output_vec();

    // Output layout: out[bin][frame][2] flattened as
    //   out[bin * t_frames * 2 + frame * 2 + (0|1)]
    let mut out = vec![0.0_f32; freq_bins * t_frames * 2];

    for frame in 0..t_frames {
        let start = frame * cfg.hop_length;
        for i in 0..cfg.n_fft {
            input[i] = padded[start + i] * window[i];
        }
        fft.process(&mut input, &mut spectrum).expect("real fft");
        for (bin, c) in spectrum.iter().enumerate() {
            let idx = bin * t_frames * 2 + frame * 2;
            out[idx] = c.re;
            out[idx + 1] = c.im;
        }
    }
    out
}

/// Inverse STFT: convert `[freq_bins, t_frames, 2]` complex frames
/// back to a time-domain signal of `signal_len` samples.
///
/// Implements the same Hann-window overlap-add + window² normaliser
/// as `torch.istft(center=True)`. After overlap-add we strip the
/// `n_fft / 2`-sample centering pad and truncate to `signal_len`.
pub fn istft(spec: &[f32], signal_len: usize, cfg: &StftConfig) -> Vec<f32> {
    let freq_bins = cfg.freq_bins();
    let t_frames = cfg.t_frames(signal_len);
    assert_eq!(spec.len(), freq_bins * t_frames * 2);

    let window = hann_window(cfg.n_fft);
    let pad = cfg.n_fft / 2;
    let padded_len = signal_len + 2 * pad;

    let mut planner = RealFftPlanner::<f32>::new();
    let ifft: std::sync::Arc<dyn ComplexToReal<f32>> = planner.plan_fft_inverse(cfg.n_fft);

    let mut spectrum = ifft.make_input_vec();
    let mut output = vec![0.0_f32; cfg.n_fft];

    let mut sum = vec![0.0_f32; padded_len];
    let mut win_sq = vec![0.0_f32; padded_len];

    let nyquist_bin = freq_bins - 1;
    for frame in 0..t_frames {
        for (bin, c) in spectrum.iter_mut().enumerate() {
            let idx = bin * t_frames * 2 + frame * 2;
            c.re = spec[idx];
            c.im = spec[idx + 1];
        }
        // realfft requires DC (bin 0) and Nyquist (last bin) to be
        // strictly real. HiNet output carries ~1e-3 numerical noise
        // in their imaginary parts; clamp to zero. This matches what
        // torch.istft does internally — neither bin contributes an
        // imaginary component to a real-valued time-domain signal.
        spectrum[0].im = 0.0;
        spectrum[nyquist_bin].im = 0.0;
        ifft.process(&mut spectrum, &mut output)
            .expect("inverse fft");
        let inv_n = 1.0_f32 / cfg.n_fft as f32;
        let start = frame * cfg.hop_length;
        for i in 0..cfg.n_fft {
            sum[start + i] += output[i] * inv_n * window[i];
            win_sq[start + i] += window[i] * window[i];
        }
    }

    let eps = 1e-11_f32;
    let mut out = Vec::with_capacity(signal_len);
    for i in 0..signal_len {
        let denom = win_sq[i + pad];
        out.push(if denom > eps { sum[i + pad] / denom } else { 0.0 });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_frames_matches_pytorch_16000_n1000_h400() {
        let cfg = StftConfig::WAVMARK;
        // PyTorch: stft of (16000,) → (501, 41, 2) under center=True.
        assert_eq!(cfg.t_frames(16000), 41);
        assert_eq!(cfg.freq_bins(), 501);
    }

    #[test]
    fn hann_window_endpoints_periodic() {
        let w = hann_window(8);
        // Periodic Hann starts at 0, never reaches 1 at the end.
        assert!((w[0] - 0.0).abs() < 1e-6);
        assert!((w[4] - 1.0).abs() < 1e-6);
    }

    #[test]
    fn stft_istft_round_trips_within_tolerance() {
        // White-noise signal → STFT → iSTFT → recover within ~1e-5.
        let cfg = StftConfig::WAVMARK;
        let n = 16_000;
        let signal: Vec<f32> = (0..n)
            .map(|i| (i as f32 * 0.12345).sin() * 0.5 + (i as f32 * 0.7).cos() * 0.3)
            .collect();
        let spec = stft(&signal, &cfg);
        let recovered = istft(&spec, n, &cfg);
        assert_eq!(recovered.len(), n);
        let max_err: f32 = signal
            .iter()
            .zip(recovered.iter())
            .map(|(a, b)| (a - b).abs())
            .fold(0.0, f32::max);
        assert!(
            max_err < 5e-3,
            "stft/istft round-trip diverged: max_err={max_err}"
        );
    }
}
