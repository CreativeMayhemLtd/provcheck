// SPDX-License-Identifier: BUSL-1.1 OR LicenseRef-provcheck-mellin-Commercial
// Copyright (C) 2026 Creative Mayhem UG (haftungsbeschränkt)
//! Traitor tracing over audio: put a buyer's Tardos codeword into a file, and
//! recover the detected symbols from a leak to accuse.
//!
//! This is the bridge between the pure [`crate::tardos`] math and the
//! [`crate::MellinChannel`]. A codeword is one bit per position; here each
//! position is a proportional slice of the audio, and bit `j` is embedded at
//! channel position `j`. Detection splits the (re-encoded) leak the same way.
//! Unlike the fixed [`crate::serial`] serial, a trace codeword is as long as the
//! Tardos code needs ([`crate::tardos::required_length`]), so collusion
//! resistance scales with audio length: see [`capacity`].
//!
//! Embed and accuse must agree on `(secret, work_id, positions, colluders)` so
//! the bias vector and the channel key match on both sides. All provcheck-only;
//! the underlying keying stays bit-identical with the reference.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::MellinChannel;
use crate::tardos::{ScoredSuspect, TraceLedger, accuse, bias_vector, codeword_for, max_colluders};

/// Derive the per-work bias seed from the seller secret and work id, so the
/// Tardos bias vector is unguessable without the secret. Embed and accuse derive
/// it identically.
pub fn work_seed(secret: &[u8], work_id: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac takes any key");
    mac.update(b"lysn-mellin/work-seed");
    mac.update(work_id);
    mac.finalize().into_bytes().to_vec()
}

/// The largest coalition a given number of positions resists, at this population
/// and false-positive bound. Surfaces the honest capacity of short content.
pub fn capacity(positions: usize, population: usize, fp_log10: u32) -> usize {
    max_colluders(positions, population, fp_log10)
}

/// Embed a codeword into one mono PCM stream: bit `j` at proportional position
/// `j`. Returns the marked PCM, same byte length as the input.
pub fn embed_codeword(ch: &MellinChannel, pcm: &[u8], codeword: &[bool]) -> Vec<u8> {
    let m = codeword.len();
    let all = pcm.len() / 2;
    if m == 0 || all == 0 {
        return pcm.to_vec();
    }
    let mut out = Vec::with_capacity(pcm.len());
    for (k, &bit) in codeword.iter().enumerate() {
        let lo = (k * all) / m * 2;
        let hi = ((k + 1) * all) / m * 2;
        out.extend_from_slice(&ch.embed(&pcm[lo..hi], bit, k));
    }
    out.extend_from_slice(&pcm[all * 2..]);
    out
}

/// Detect the codeword symbols from a single stream over `positions` positions.
/// `None` is an erasure (a damaged position), which the accusation stage handles.
pub fn detect_codeword(ch: &MellinChannel, pcm: &[u8], positions: usize) -> Vec<Option<bool>> {
    ch.detect_stream(pcm, positions)
}

/// Detect the codeword symbols across every channel, voting each position. Each
/// channel carries the same codeword, so a per-position majority sharpens the
/// detected sequence; a tie or all-erased position stays an erasure (fail safe).
pub fn detect_codeword_channels(
    ch: &MellinChannel,
    channels: &[Vec<u8>],
    positions: usize,
) -> Vec<Option<bool>> {
    let mut ones = vec![0u32; positions];
    let mut zeros = vec![0u32; positions];
    for pcm in channels {
        for (k, b) in ch.detect_stream(pcm, positions).iter().enumerate() {
            match b {
                Some(true) => ones[k] += 1,
                Some(false) => zeros[k] += 1,
                None => {}
            }
        }
    }
    (0..positions)
        .map(|k| match ones[k].cmp(&zeros[k]) {
            std::cmp::Ordering::Greater => Some(true),
            std::cmp::Ordering::Less => Some(false),
            std::cmp::Ordering::Equal => None, // no votes, or a tie: erasure
        })
        .collect()
}

/// Convenience: build the bias vector and a buyer's codeword for a work.
pub fn buyer_codeword(
    secret: &[u8],
    work_id: &[u8],
    buyer: &str,
    positions: usize,
    colluders: usize,
) -> Vec<bool> {
    let seed = work_seed(secret, work_id);
    let biases = bias_vector(&seed, positions, colluders);
    let serial = crate::tardos::Serial::derive(secret, work_id, buyer.as_bytes());
    codeword_for(&serial, &biases)
}

/// Accuse from a detected symbol sequence against an enrolled ledger. Thin
/// wrapper that rebuilds the bias vector so callers pass the work params, not the
/// vector.
pub fn accuse_detected(
    detected: &[Option<bool>],
    secret: &[u8],
    work_id: &[u8],
    positions: usize,
    colluders: usize,
    ledger: &TraceLedger,
    fp_log10: u32,
) -> Vec<ScoredSuspect> {
    let seed = work_seed(secret, work_id);
    let biases = bias_vector(&seed, positions, colluders);
    accuse(detected, ledger, &biases, fp_log10)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tardos::TraceLedger;

    fn host(samples: usize) -> Vec<u8> {
        let mut seed = 0x51DE_C0DE_u64;
        let mut v = Vec::with_capacity(samples * 2);
        for n in 0..samples {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let noise = ((seed >> 33) as f64 / (1u64 << 31) as f64 - 1.0) * 0.3;
            let t = n as f64 / 44_100.0;
            let tone = 0.2 * (2.0 * std::f64::consts::PI * 200.0 * t).sin();
            let s = ((noise + tone).clamp(-1.0, 1.0) * 30_000.0) as i16;
            v.extend_from_slice(&s.to_le_bytes());
        }
        v
    }

    #[test]
    fn embed_codeword_traces_the_buyer_and_no_innocent() {
        // End-to-end audio path: embed a real buyer's codeword into audio, detect
        // it back, and confirm accusation names that buyer and no one else.
        let secret = b"seller-secret";
        let work_id = b"album-7";
        let (positions, colluders, fp_log10) = (200usize, 2usize, 6u32);

        // Enroll a small population; buyer "b3" is our real purchaser.
        let mut ledger = TraceLedger::new();
        for i in 0..20 {
            ledger.enroll(secret, work_id, &format!("b{i}"));
        }
        let buyer = "b3";

        // ~200 positions * ~2600 samples each keeps every position above the floor.
        let ch = MellinChannel::for_work(secret, work_id, 0.3);
        let pcm = host(positions * 2600);
        let codeword = buyer_codeword(secret, work_id, buyer, positions, colluders);
        let marked = embed_codeword(&ch, &pcm, &codeword);

        let detected = detect_codeword(&ch, &marked, positions);
        let observed = detected.iter().filter(|d| d.is_some()).count();
        assert!(
            observed >= 48,
            "need observed positions above the floor, got {observed}"
        );

        let suspects = accuse_detected(
            &detected, secret, work_id, positions, colluders, &ledger, fp_log10,
        );
        assert!(
            suspects.iter().any(|s| s.label == buyer),
            "the real buyer should be accused: {suspects:?}"
        );
        assert!(
            suspects.iter().all(|s| s.label == buyer),
            "no innocent should be accused: {suspects:?}"
        );
    }
}
