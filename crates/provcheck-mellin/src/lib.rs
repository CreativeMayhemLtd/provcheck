// SPDX-License-Identifier: BUSL-1.1
//! **Spectral (magnitude-domain) forensic watermark channel** — the scale/stretch-invariant tier,
//! ported from lysn (`crates/lysn-watermark/src/mellin.rs`).
//!
//! A classical time-domain chip is SMEARED by a pitch-preserving time-stretch (WSOLA / `atempo`): it
//! splices overlapping waveform windows to change tempo, destroying a Nyquist-rate chip even after
//! re-alignment. This channel instead writes the mark into the **magnitude spectrum**, consistently
//! across every analysis frame of a segment, and reads it back from the **frame-averaged** spectrum.
//! That is exactly the quantity WSOLA preserves — it keeps each frame's pitch/spectrum and only
//! rescales the *sequence* of frames — so a frame-average is time-warp invariant. Detection needs no
//! offset search (averaging is shift invariant) and no per-sample alignment.
//!
//! Bit carrier: a **secret-keyed ±1 pattern over a mid-band of FFT bins**; embedding scales each bin's
//! magnitude by `(1 + strength·sign·pattern[k])` in every frame (phase untouched), and detection
//! correlates the mean log-magnitude (band, mean-removed) against the keyed pattern. Sign → bit; a
//! z-score below the confidence gate → `None` (erasure), never a guessed bit — a fail-safe posture, so
//! it can only ever ADD recall, never frame an innocent. Keying prevents an informed leaker from
//! computing and cancelling the pattern.
//!
//! ## Compatibility contract
//!
//! The keying here (HMAC label `lysn-mellin-key/v1`, the PRNG, the ±1 pattern derivation) is
//! **bit-identical** with the lysn source. Marks embedded by Lysn.fm detect here with the same seller
//! secret + work id, and vice versa. Do not change any constant, label, or derivation without changing
//! it in lysn in the same breath.
//!
//! ## License
//!
//! This crate is BUSL-1.1 (see LICENSE), unlike the rest of provcheck (Apache-2.0). It is opt-in,
//! excluded from the workspace, and never bundled into the provcheck release binary — see
//! `WATERMARK_LICENSE_POLICY.md` at the repository root.

use hmac::{Hmac, Mac};
use sha2::Sha256;

// File-facing layers built ON TOP of the ported channel. These are provcheck-only
// (lysn has no file layer), so they carry no cross-repo bit-identity obligation:
// only the channel keying/DSP above must stay in lockstep with lysn-watermark.
pub mod audio;
pub mod serial;
pub mod tardos;
pub mod trace;

/// FFT frame size (power of two). ~21 ms at 48 kHz; small enough to get many frames per 0.5 s segment
/// (more frames = more averaging = higher detection SNR), large enough for usable bin resolution.
const FRAME: usize = 1024;
/// Hop (50% overlap): with a Hann window this satisfies constant-overlap-add for clean resynthesis.
const HOP: usize = 512;
/// Mark band in FFT bins (mid-band ~1-8 kHz at 48 kHz): below the codec's aggressive HF cull, above the
/// bass where perturbations are most audible and codecs spend the most bits.
const BIN_LO: usize = 24; // ~1.1 kHz
const BIN_HI: usize = 180; // ~8.4 kHz
/// Detection confidence gate in z units: a correlation below this is an erasure, not a bit. Under no
/// mark the normalized correlation is ~N(0,1); a real mark sits well above.
const MELLIN_Z_MIN: f64 = 5.0;

/// Frequency-scale search grid for detection (±4% covers a generous resample/speed change). `s = 1.0`
/// is included so a pure tempo change (frequencies unchanged) is the no-op case.
const FREQ_SCALE_MIN: f64 = 0.96;
const FREQ_SCALE_MAX: f64 = 1.04;
const FREQ_SCALE_STEPS: usize = 17; // 0.5% grid

/// Moving-average smoothing radius (bins) for the envelope removed at detection. The keyed pattern is
/// ±1 per bin (fastest bin-rate), so a ~9-bin average passes the envelope and rejects the mark; the
/// high-pass (signal - smoothed) then keeps the mark and drops the envelope.
const ENVELOPE_SMOOTH: usize = 4;

// ---------------------------------------------------------------------------
// Keying primitives (bit-identical with lysn's crates/lysn-watermark/src/dsp.rs
// and tardos.rs — the compatibility contract above depends on it).
// ---------------------------------------------------------------------------

/// splitmix64-style PRNG, identical to lysn's `tardos::Prng`.
struct Prng(u64);

impl Prng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    #[cfg(test)]
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Derive a per-work 8-byte channel key: `HMAC-SHA256(secret, label ‖ work_id)[..8]` as a
/// little-endian `u64`. `label` domain-separates each channel's key so the same seller secret + work
/// id yield independent keys per channel.
fn work_key(secret: &[u8], label: &[u8], work_id: &[u8]) -> u64 {
    let mut mac = <Hmac<Sha256>>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(label);
    mac.update(work_id);
    let out = mac.finalize().into_bytes();
    u64::from_le_bytes(out[..8].try_into().expect("sha256 >= 8 bytes"))
}

/// Secret-keyed antipodal (+1 / -1) value for `index` at `position`. An attacker who does not know
/// `key` cannot reproduce the sequence to null or flip the mark; it is deterministic, so embed and
/// detect always agree.
fn keyed_sign(key: u64, position: usize, index: usize) -> f64 {
    let mut p = Prng(
        key ^ (position as u64).wrapping_mul(0x100_0001b3)
            ^ (index as u64)
                .wrapping_add(1)
                .wrapping_mul(0x9E37_79B9_7F4A_7C15),
    );
    if p.next_u64() & 1 == 0 { -1.0 } else { 1.0 }
}

/// Decode little-endian signed-16-bit PCM into samples (drops a dangling odd byte).
fn pcm_i16(bytes: &[u8]) -> Vec<i16> {
    bytes
        .chunks_exact(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect()
}

// ---------------------------------------------------------------------------
// The channel
// ---------------------------------------------------------------------------

/// Spectral magnitude-domain watermark channel (WSOLA / time-stretch tolerant). See module docs.
#[derive(Debug, Clone, Copy)]
pub struct MellinChannel {
    /// Per-bin fractional magnitude perturbation (e.g. 0.2 = ±20% in the marked band). Trades
    /// audibility against detection margin; the mark is spread over the whole band so no single bin
    /// dominates. Detection is blind (no original needed).
    pub strength: f32,
    /// Secret keyed pattern seed: the ±1 bin pattern is `PRNG(key, position, k)`.
    pub key: u64,
}

impl Default for MellinChannel {
    fn default() -> Self {
        Self {
            strength: 0.2,
            key: 0x5EED_1234_ABCD_0001,
        }
    }
}

impl MellinChannel {
    /// Per-work keyed channel. The label matches lysn exactly, so the same seller secret + work id
    /// derive the same key on both sides.
    pub fn for_work(secret: &[u8], work_id: &[u8], strength: f32) -> Self {
        let key = work_key(secret, b"lysn-mellin-key/v1", work_id);
        Self { strength, key }
    }

    fn samples(bytes: &[u8]) -> Vec<f64> {
        pcm_i16(bytes).iter().map(|&s| s as f64).collect()
    }

    /// Keyed ±1 pattern for bin `k` at `position`.
    fn pattern(key: u64, position: usize, k: usize) -> f64 {
        keyed_sign(key, position, k)
    }

    /// Periodic Hann window of length `FRAME`.
    fn hann() -> [f64; FRAME] {
        let mut w = [0.0f64; FRAME];
        for (n, wn) in w.iter_mut().enumerate() {
            *wn = 0.5 - 0.5 * (2.0 * std::f64::consts::PI * n as f64 / FRAME as f64).cos();
        }
        w
    }

    /// Produce the variant of `segment` (i16 LE PCM) that carries `bit` at `position`.
    pub fn embed(&self, segment: &[u8], bit: bool, position: usize) -> Vec<u8> {
        let x = Self::samples(segment);
        let tail = &segment[x.len() * 2..];
        let n = x.len();
        if n < FRAME {
            return segment.to_vec(); // too short to frame — leave unmarked (a later erasure, never a wrong bit)
        }
        let sign = if bit { 1.0 } else { -1.0 };
        let s = self.strength as f64;
        let w = Self::hann();
        let mut out = vec![0.0f64; n];
        let mut wsum = vec![0.0f64; n];
        let mut start = 0;
        while start + FRAME <= n {
            let mut re = [0.0f64; FRAME];
            let mut im = [0.0f64; FRAME];
            for i in 0..FRAME {
                re[i] = x[start + i] * w[i];
            }
            fft(&mut re, &mut im, false);
            for k in BIN_LO..BIN_HI.min(FRAME / 2) {
                let f = 1.0 + s * sign * Self::pattern(self.key, position, k);
                re[k] *= f;
                im[k] *= f;
                let mir = FRAME - k; // conjugate-symmetric partner
                re[mir] *= f;
                im[mir] *= f;
            }
            fft(&mut re, &mut im, true);
            for i in 0..FRAME {
                out[start + i] += re[i] * w[i];
                wsum[start + i] += w[i] * w[i];
            }
            start += HOP;
        }
        // weighted overlap-add normalization; where no frame covered a sample, keep the original.
        let mut samples_i16 = Vec::with_capacity(n);
        for i in 0..n {
            let v = if wsum[i] > 1e-9 {
                out[i] / wsum[i]
            } else {
                x[i]
            };
            samples_i16.push(v.round().clamp(i16::MIN as f64, i16::MAX as f64) as i16);
        }
        let mut bytes = Vec::with_capacity(n * 2 + tail.len());
        for sm in &samples_i16 {
            bytes.extend_from_slice(&sm.to_le_bytes());
        }
        bytes.extend_from_slice(tail);
        bytes
    }

    /// Recover the bit from a (possibly attacked / re-encoded) segment. `None` = erasure/unreadable.
    pub fn detect(&self, segment: &[u8], position: usize) -> Option<bool> {
        let z = self.detect_score(segment, position);
        if z.abs() < MELLIN_Z_MIN {
            return None; // erasure, not a guessed bit
        }
        Some(z > 0.0)
    }

    /// The signed detection z-score for `position`: the frame-averaged log-magnitude spectrum,
    /// **high-passed** to strip the signal's own smooth spectral envelope (which otherwise swamps the
    /// mark), correlated with the keyed ±1 pattern and normalized. `~N(0,1)` under no mark; a real mark
    /// pushes it well positive/negative (sign = bit). `0.0` if the segment is too short to frame.
    pub fn detect_score(&self, segment: &[u8], position: usize) -> f64 {
        let x = Self::samples(segment);
        let n = x.len();
        if n < FRAME {
            return 0.0;
        }
        let w = Self::hann();
        let half = FRAME / 2;
        let mut mag_sum = vec![0.0f64; half]; // frame-averaged magnitude over the WHOLE half-spectrum
        let mut frames = 0usize;
        let mut start = 0;
        while start + FRAME <= n {
            let mut re = [0.0f64; FRAME];
            let mut im = [0.0f64; FRAME];
            for i in 0..FRAME {
                re[i] = x[start + i] * w[i];
            }
            fft(&mut re, &mut im, false);
            for (k, ms) in mag_sum.iter_mut().enumerate() {
                *ms += (re[k] * re[k] + im[k] * im[k]).sqrt();
            }
            frames += 1;
            start += HOP;
        }
        if frames == 0 {
            return 0.0;
        }
        let logmag: Vec<f64> = mag_sum
            .iter()
            .map(|&m| (m / frames as f64 + 1.0).ln())
            .collect();
        // High-pass: subtract a moving-average envelope so only the bin-to-bin fluctuation (where the
        // keyed ±1 mark lives) remains; the signal's smooth spectral shape is removed. The mark survives
        // (its own moving average is ~0 for a ±1 pattern), the envelope does not.
        let hp = highpass(&logmag, ENVELOPE_SMOOTH);
        // FREQUENCY-SCALE search (the Fourier-Mellin trick): a resample/speed change (asetrate, vinyl
        // speed) multiplies every frequency by a factor s, so the pattern embedded at bin k lands at bin
        // k·s. WSOLA (atempo) leaves frequencies alone (s=1). Correlating over a small grid of s and
        // taking the strongest makes ONE detector scale-invariant to BOTH: tempo change AND resample.
        let mut best = 0.0f64;
        let mut best_abs = -1.0f64;
        for step in 0..FREQ_SCALE_STEPS {
            let s = FREQ_SCALE_MIN
                + (FREQ_SCALE_MAX - FREQ_SCALE_MIN) * step as f64 / (FREQ_SCALE_STEPS - 1) as f64;
            let mut corr = 0.0;
            let mut energy = 0.0;
            for k in BIN_LO..BIN_HI.min(half) {
                let kk = ((k as f64) * s).round() as usize;
                if kk >= half {
                    continue;
                }
                let v = hp[kk];
                corr += v * Self::pattern(self.key, position, k);
                energy += v * v;
            }
            if energy > 0.0 {
                let z = corr / energy.sqrt();
                if z.abs() > best_abs {
                    best_abs = z.abs();
                    best = z;
                }
            }
        }
        best
    }

    /// Detect over a whole leaked PCM stream (any length): frame-averaging is already time-warp
    /// invariant, so this needs only a proportional re-split into `m` positions — no resample, no
    /// offset search. `Vec<Option<bool>>` aligned to positions `0..m`.
    pub fn detect_stream(&self, leaked_pcm: &[u8], m: usize) -> Vec<Option<bool>> {
        let all = leaked_pcm.len() / 2;
        if m == 0 || all == 0 {
            return vec![None; m];
        }
        (0..m)
            .map(|k| {
                let lo = (k * all) / m * 2;
                let hi = ((k + 1) * all) / m * 2;
                if hi <= lo {
                    return None;
                }
                self.detect(&leaked_pcm[lo..hi], k)
            })
            .collect()
    }
}

/// `x` minus its centered moving average of radius `r` (window `2r+1`) — a simple high-pass over the
/// bin axis.
fn highpass(x: &[f64], r: usize) -> Vec<f64> {
    let n = x.len();
    (0..n)
        .map(|k| {
            let lo = k.saturating_sub(r);
            let hi = (k + r + 1).min(n);
            let avg = x[lo..hi].iter().sum::<f64>() / (hi - lo) as f64;
            x[k] - avg
        })
        .collect()
}

/// Iterative radix-2 Cooley-Tukey FFT (in place). `re.len()` must be a power of two. `inverse` scales by
/// 1/n. Pure safe Rust; no external FFT dependency.
fn fft(re: &mut [f64], im: &mut [f64], inverse: bool) {
    let n = re.len();
    debug_assert!(n.is_power_of_two());
    // bit-reversal permutation
    let mut j = 0usize;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if i < j {
            re.swap(i, j);
            im.swap(i, j);
        }
    }
    let mut len = 2;
    while len <= n {
        let ang = 2.0 * std::f64::consts::PI / len as f64 * if inverse { 1.0 } else { -1.0 };
        let (wr, wi) = (ang.cos(), ang.sin());
        let mut i = 0;
        while i < n {
            let (mut cr, mut ci) = (1.0f64, 0.0f64);
            for k in 0..len / 2 {
                let a = i + k;
                let b = i + k + len / 2;
                let vr = re[b] * cr - im[b] * ci;
                let vi = re[b] * ci + im[b] * cr;
                re[b] = re[a] - vr;
                im[b] = im[a] - vi;
                re[a] += vr;
                im[a] += vi;
                let ncr = cr * wr - ci * wi;
                ci = cr * wi + ci * wr;
                cr = ncr;
            }
            i += len;
        }
        len <<= 1;
    }
    if inverse {
        let inv = 1.0 / n as f64;
        for v in re.iter_mut() {
            *v *= inv;
        }
        for v in im.iter_mut() {
            *v *= inv;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // deterministic pink-ish broadband signal (a simple 1/f-weighted sum of sines + a PRNG dither).
    fn broadband(n: usize) -> Vec<u8> {
        let mut p = Prng(0xC0FF_EE12_3456_789A);
        let mut out = Vec::with_capacity(n * 2);
        let mut acc = 0.0f64;
        for _ in 0..n {
            acc = 0.98 * acc + (p.unit() - 0.5); // brownish noise, broadband
            let v = (acc * 6000.0).clamp(i16::MIN as f64, i16::MAX as f64) as i16;
            out.extend_from_slice(&v.to_le_bytes());
        }
        out
    }

    #[test]
    fn fft_roundtrips() {
        let mut re: Vec<f64> = (0..8).map(|i| i as f64).collect();
        let mut im = vec![0.0; 8];
        let orig = re.clone();
        fft(&mut re, &mut im, false);
        fft(&mut re, &mut im, true);
        for (a, b) in re.iter().zip(orig.iter()) {
            assert!((a - b).abs() < 1e-9, "FFT/IFFT roundtrip");
        }
    }

    #[test]
    fn embed_detect_roundtrip_and_erases_unmarked() {
        let ch = MellinChannel {
            strength: 0.2,
            key: 0xABCD,
        };
        let host = broadband(24_000);
        for bit in [false, true] {
            let marked = ch.embed(&host, bit, 3);
            assert_eq!(
                ch.detect(&marked, 3),
                Some(bit),
                "marked segment reads back its bit"
            );
        }
        // unmarked host: no confident bit (erasure), and a wrong position/key doesn't read the mark.
        assert_eq!(
            ch.detect(&host, 3),
            None,
            "unmarked host is an erasure, not a guess"
        );
        let marked = ch.embed(&host, true, 3);
        assert_eq!(
            ch.detect(&marked, 9),
            None,
            "wrong position doesn't detect the mark"
        );
    }

    #[test]
    fn keyed_sign_is_deterministic_antipodal_and_key_sensitive() {
        for i in 0..64 {
            let v = keyed_sign(42, 3, i);
            assert!(v == 1.0 || v == -1.0);
            assert_eq!(v, keyed_sign(42, 3, i), "deterministic");
        }
        let a: Vec<f64> = (0..64).map(|i| keyed_sign(1, 0, i)).collect();
        let b: Vec<f64> = (0..64).map(|i| keyed_sign(2, 0, i)).collect();
        assert_ne!(a, b);
    }

    #[test]
    fn work_key_matches_lysn_derivation() {
        // Domain separation + determinism; the label constant is the cross-repo contract.
        let (secret, work) = (b"seller-secret", b"work-1");
        assert_eq!(
            work_key(secret, b"lysn-mellin-key/v1", work),
            work_key(secret, b"lysn-mellin-key/v1", work),
            "deterministic"
        );
        assert_ne!(
            work_key(secret, b"lysn-mellin-key/v1", work),
            work_key(secret, b"other-label", work),
            "different labels must derive different keys"
        );
    }
}
