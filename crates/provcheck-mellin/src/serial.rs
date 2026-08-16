//! Per-copy serial framing over the keyed Mellin channel.
//!
//! The channel ([`crate::MellinChannel`]) hides one bit per "position". This
//! layer spreads a fixed 64-bit **copy serial** across many positions with
//! repetition, so a single distributed copy can be individuated (and a leak
//! traced back to it) even after transcode: each repetition is read
//! independently and majority-voted, and a damaged position returns an erasure
//! ([`None`]) rather than a guessed bit, so noise costs confidence, never a
//! wrong accusation.
//!
//! Framing: `m = 64 * repeat` positions; position `k` carries serial bit
//! `k mod 64`. Embed and read must use the same `repeat`. Detection splits the
//! (possibly re-encoded) stream into `m` proportional chunks, so it tolerates
//! duration-preserving transcodes; it does not yet resync a trimmed clip.

use crate::MellinChannel;

/// Serial width in bits. A 64-bit copy id gives 2^64 distinguishable copies.
pub const SERIAL_BITS: usize = 64;

/// Default repetition factor (positions per serial bit). `m = 64 * repeat`.
pub const DEFAULT_REPEAT: usize = 8;

/// Outcome of reading a serial back from a stream.
#[derive(Debug, Clone, Copy)]
pub struct SerialReadout {
    /// Recovered 64-bit serial. Bits with no readable repetition are left 0;
    /// consult `bits_recovered` before trusting a full match.
    pub serial: u64,
    /// How many of the 64 bits had at least one non-erased repetition.
    pub bits_recovered: u32,
    /// Fraction of the `m` positions that read as an erasure.
    pub erasure_rate: f64,
    /// The weakest per-bit majority (fewest votes backing any recovered bit).
    /// A high value means every recovered bit had strong agreement.
    pub min_bit_votes: u32,
}

impl SerialReadout {
    /// True when every serial bit was recovered from at least one repetition.
    pub fn fully_recovered(&self) -> bool {
        self.bits_recovered as usize == SERIAL_BITS
    }
}

/// Number of channel positions used for a given repetition factor.
pub fn positions_for(repeat: usize) -> usize {
    SERIAL_BITS * repeat.max(1)
}

/// Samples per position below which detection erases too often to be reliable.
/// Each position needs several FFT frames (frame 1024, hop 512) to clear the
/// z-gate; ~4-5 frames is the practical floor for a robust read.
pub const MIN_SAMPLES_PER_POSITION: usize = 2560;

/// How many i16 samples each position gets for this geometry.
pub fn samples_per_position(pcm_samples: usize, repeat: usize) -> usize {
    // positions_for is always >= SERIAL_BITS (64), so the divisor is never zero.
    pcm_samples / positions_for(repeat)
}

/// Embed `serial` across `repeat * 64` positions of `pcm` (i16 LE mono).
/// Returns the marked PCM, same byte length as the input.
pub fn embed_serial(ch: &MellinChannel, pcm: &[u8], serial: u64, repeat: usize) -> Vec<u8> {
    let m = positions_for(repeat);
    let all = pcm.len() / 2; // whole i16 samples
    if m == 0 || all == 0 {
        return pcm.to_vec();
    }
    let mut out = Vec::with_capacity(pcm.len());
    for k in 0..m {
        let lo = (k * all) / m * 2;
        let hi = ((k + 1) * all) / m * 2;
        let seg = &pcm[lo..hi];
        let bit = (serial >> (k % SERIAL_BITS)) & 1 == 1;
        out.extend_from_slice(&ch.embed(seg, bit, k));
    }
    // Preserve any trailing odd byte the segmentation could not cover.
    out.extend_from_slice(&pcm[all * 2..]);
    out
}

/// Accumulated per-bit vote tallies, so several channels (or several passes)
/// can be combined before deciding. More surviving votes per bit means a more
/// reliable read through a lossy leak, which is why stereo (voting both
/// channels) beats mono.
#[derive(Debug, Clone)]
pub struct Tally {
    ones: [u32; SERIAL_BITS],
    zeros: [u32; SERIAL_BITS],
    erasures: usize,
    positions: usize,
}

impl Default for Tally {
    // Arrays longer than 32 do not derive Default; spell it out.
    fn default() -> Self {
        Self {
            ones: [0; SERIAL_BITS],
            zeros: [0; SERIAL_BITS],
            erasures: 0,
            positions: 0,
        }
    }
}

impl Tally {
    /// Fold one stream's per-position detections into the tally.
    pub fn add_stream(&mut self, ch: &MellinChannel, pcm: &[u8], repeat: usize) {
        let m = positions_for(repeat);
        for (k, b) in ch.detect_stream(pcm, m).iter().enumerate() {
            match b {
                Some(true) => self.ones[k % SERIAL_BITS] += 1,
                Some(false) => self.zeros[k % SERIAL_BITS] += 1,
                None => self.erasures += 1,
            }
        }
        self.positions += m;
    }

    /// Majority-vote each bit into a serial. A bit with no surviving vote is
    /// left 0 and not counted as recovered.
    pub fn decide(&self) -> SerialReadout {
        let mut serial = 0u64;
        let mut recovered = 0u32;
        let mut min_votes = u32::MAX;
        for j in 0..SERIAL_BITS {
            let (o, z) = (self.ones[j], self.zeros[j]);
            if o + z == 0 {
                continue; // fully erased bit: leave 0, do not count as recovered
            }
            if o > z {
                serial |= 1u64 << j;
            }
            recovered += 1;
            min_votes = min_votes.min(o.max(z));
        }
        SerialReadout {
            serial,
            bits_recovered: recovered,
            erasure_rate: if self.positions == 0 {
                0.0
            } else {
                self.erasures as f64 / self.positions as f64
            },
            min_bit_votes: if min_votes == u32::MAX { 0 } else { min_votes },
        }
    }
}

/// Read a serial back from a single (possibly re-encoded) stream.
pub fn read_serial(ch: &MellinChannel, pcm: &[u8], repeat: usize) -> SerialReadout {
    let mut t = Tally::default();
    t.add_stream(ch, pcm, repeat);
    t.decide()
}

/// Read a serial from a multi-channel file, voting every channel together.
/// Each channel carries the same keyed serial at the same positions, so
/// combining their votes roughly multiplies the surviving-vote budget by the
/// channel count.
pub fn read_serial_channels(
    ch: &MellinChannel,
    channels: &[Vec<u8>],
    repeat: usize,
) -> SerialReadout {
    let mut t = Tally::default();
    for pcm in channels {
        t.add_stream(ch, pcm, repeat);
    }
    t.decide()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic broadband host (LCG noise + a tone), long enough that
    /// every position gets several FFT frames. Self-contained: no crate
    /// internals, so the test documents the public framing API alone.
    fn host(samples: usize) -> Vec<u8> {
        let mut seed = 0xA11C_E00D_u64;
        let mut v = Vec::with_capacity(samples * 2);
        for n in 0..samples {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let noise = ((seed >> 33) as f64 / (1u64 << 31) as f64 - 1.0) * 0.3;
            let t = n as f64 / 44_100.0;
            let tone = 0.2 * (2.0 * std::f64::consts::PI * 220.0 * t).sin();
            let s = ((noise + tone).clamp(-1.0, 1.0) * 30_000.0) as i16;
            v.extend_from_slice(&s.to_le_bytes());
        }
        v
    }

    #[test]
    fn serial_round_trips_through_the_channel() {
        // ~30 s at 44.1 kHz: comfortably covers 64*8 positions with real frames.
        let pcm = host(1_323_000);
        let ch = MellinChannel::for_work(b"seller-secret", b"work-1", 0.25);
        let serial = 0xDEAD_BEEF_1234_5678u64;
        let marked = embed_serial(&ch, &pcm, serial, DEFAULT_REPEAT);
        let got = read_serial(&ch, &marked, DEFAULT_REPEAT);
        assert!(got.fully_recovered(), "all 64 bits should read: {got:?}");
        assert_eq!(got.serial, serial, "serial mismatch: {got:?}");
    }

    #[test]
    fn wrong_key_does_not_read_a_serial() {
        let pcm = host(1_323_000);
        let embedder = MellinChannel::for_work(b"seller-secret", b"work-1", 0.25);
        let marked = embed_serial(&embedder, &pcm, 0x0102_0304_0506_0708, DEFAULT_REPEAT);
        // A different work id derives a different channel key: the mark must not read.
        let attacker = MellinChannel::for_work(b"seller-secret", b"work-2", 0.25);
        let got = read_serial(&attacker, &marked, DEFAULT_REPEAT);
        assert_ne!(
            got.serial, 0x0102_0304_0506_0708,
            "wrong key read the serial: {got:?}"
        );
    }

    #[test]
    fn multi_channel_read_recovers_and_deepens_the_vote_budget() {
        // Two independent channels carrying the same keyed serial. Voting both
        // together should recover it, with more votes per bit than one channel.
        let ch = MellinChannel::for_work(b"seller-secret", b"work-1", 0.25);
        let serial = 0x00FF_00FF_0F0F_0F0Fu64;
        // ~32 s per channel keeps each position above the samples/position floor.
        let left = embed_serial(&ch, &host(1_400_000), serial, DEFAULT_REPEAT);
        let right = embed_serial(&ch, &host(1_400_000), serial, DEFAULT_REPEAT);

        let mono = read_serial(&ch, &left, DEFAULT_REPEAT);
        let stereo = read_serial_channels(&ch, &[left, right], DEFAULT_REPEAT);

        assert_eq!(stereo.serial, serial, "stereo read mismatch: {stereo:?}");
        assert!(
            stereo.fully_recovered(),
            "stereo should recover all bits: {stereo:?}"
        );
        assert!(
            stereo.min_bit_votes > mono.min_bit_votes,
            "two channels should back each bit with more votes ({} vs {})",
            stereo.min_bit_votes,
            mono.min_bit_votes
        );
    }
}
