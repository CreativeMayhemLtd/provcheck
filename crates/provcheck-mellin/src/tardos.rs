// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-provcheck-mellin-Commercial
// Copyright (C) 2026 Creative Mayhem UG (haftungsbeschränkt)
//! Tardos collusion-resistant fingerprinting — the pure, hermetic core (no
//! media, no ML).
//!
//! This is the traitor-tracing math that makes per-copy fingerprinting *robust
//! against collusion*: several buyers comparing their copies to wash the mark
//! cannot erase every fingerprint, and the accusation stage still names at
//! least one of them while (the guarantee we hold hardest) never framing an
//! innocent. It is channel-independent: it works on **codewords** (one bit per
//! position, a position being a watermark-carrying unit) and a **detected**
//! symbol sequence extracted from a leak. Putting each bit into the audio is
//! the Mellin channel's job ([`crate::MellinChannel`]); mapping a codeword to
//! and from a file is [`crate::trace`]'s job.
//!
//! Guarantees (validated empirically by the tests, not just asserted):
//! - **No false accusation.** An innocent buyer's score has mean 0 and variance
//!   equal to the number of observed positions, asymptotically `~N(0, m_obs)`;
//!   with the threshold `sqrt(m_obs) * z(eps)` (Bonferroni-split over the
//!   population) the whole run's false-positive probability is bounded by
//!   `10^-fp_log10`. Below [`MIN_OBSERVED_POSITIONS`] the CLT no longer holds,
//!   so accusation refuses (fail safe: a miss, never a frame).
//! - **Soundness.** With enough positions ([`required_length`]) at least one
//!   real colluder scores above the threshold under standard fusion attacks.
//!
//! Everything is deterministic: biases derive from the work seed, codewords
//! from the pseudonymous [`Serial`], scoring is closed-form. Nothing here uses
//! an RNG (the tests supply one only to model the *attacker*).
//!
//! ## Compatibility contract
//!
//! The deterministic math here — the HMAC labels `lysn-tardos/bias` and
//! `lysn-tardos/codeword`, the bias distribution, the codeword rule, the
//! symmetric score, the threshold, and the Acklam quantile — is **bit-identical**
//! with lysn-watermark's `tardos.rs`. Given the same serial bytes and work seed,
//! a codeword generated in Lysn.fm scores here identically, and vice versa. The
//! enrollment types ([`Serial`], [`TraceLedger`]) are provcheck-only bookkeeping
//! and carry no cross-repo obligation. Do not change any label, constant, or
//! formula without changing lysn in the same breath.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

// ─────────────────────────────── deterministic bit sources ───────────────────────────────

/// HMAC(key, tag || idx) → the leading 8 bytes as a u64. The key + tag
/// domain-separate the two independent bit streams (per-work biases vs per-buyer
/// codewords) so they never correlate.
fn hmac_u64(key: &[u8], tag: &[u8], idx: u32) -> u64 {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac takes any key");
    mac.update(tag);
    mac.update(&idx.to_be_bytes());
    let out = mac.finalize().into_bytes();
    let mut b = [0u8; 8];
    b.copy_from_slice(&out[..8]);
    u64::from_be_bytes(b)
}

/// Map a keyed HMAC to a uniform `[0, 1)` deterministically.
fn hmac_unit(key: &[u8], tag: &[u8], idx: u32) -> f64 {
    // 53 bits of mantissa is all an f64 can hold; take the top 53.
    (hmac_u64(key, tag, idx) >> 11) as f64 / (1u64 << 53) as f64
}

// ─────────────────────────────── enrollment (provcheck-only) ───────────────────────────────

/// A buyer's pseudonymous fingerprint key. The codeword derives from these
/// bytes, so two systems that hold the same `Serial` produce the same codeword.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Serial(pub Vec<u8>);

impl Serial {
    /// Derive a per-buyer serial deterministically:
    /// `HMAC-SHA256(secret, work_id || buyer)`. The seller keeps `secret`; the
    /// same `(secret, work_id, buyer)` always yields the same serial, so a leak
    /// can be scored against a buyer reconstructed at trace time.
    pub fn derive(secret: &[u8], work_id: &[u8], buyer: &[u8]) -> Self {
        let mut mac = HmacSha256::new_from_slice(secret).expect("hmac takes any key");
        mac.update(work_id);
        mac.update(buyer);
        Serial(mac.finalize().into_bytes().to_vec())
    }
}

/// One enrolled buyer: their serial plus a human-facing label to report if
/// accused (a customer reference, order id, whatever the seller tracks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub serial: Serial,
    pub label: String,
}

/// The set of buyers a work was sold to, scored at trace time. Provcheck-only
/// bookkeeping; the tracing math never depends on its shape.
#[derive(Debug, Clone, Default)]
pub struct TraceLedger {
    entries: Vec<Entry>,
}

impl TraceLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enroll a buyer by deriving their serial from `(secret, work_id, buyer)`.
    pub fn enroll(&mut self, secret: &[u8], work_id: &[u8], buyer: &str) {
        self.entries.push(Entry {
            serial: Serial::derive(secret, work_id, buyer.as_bytes()),
            label: buyer.to_string(),
        });
    }

    /// Enroll a buyer with an already-derived serial (e.g. one supplied by an
    /// interoperating Lysn.fm pipeline).
    pub fn enroll_serial(&mut self, serial: Serial, label: impl Into<String>) {
        self.entries.push(Entry {
            serial,
            label: label.into(),
        });
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ─────────────────────────────────────── parameters ───────────────────────────────────────

/// The bias cutoff `t`: biases are drawn from `[t, 1-t]`. Classic Tardos uses
/// `t = 1/(300c)`; clamped so very small coalitions still get a sane spread.
fn cutoff(colluders: usize) -> f64 {
    (1.0 / (300.0 * colluders.max(1) as f64)).clamp(1e-6, 0.25)
}

/// Conservative code-length estimate for a target `(colluders, population n,
/// eps=10^-fp_log10)`. This is an ESTIMATE for capacity display; the accusation
/// threshold enforces the false-positive bound regardless. Constant `A` is
/// deliberately generous (symmetric Tardos needs ~`4*pi^2 c^2 ln(n/eps)`; we use
/// more headroom).
pub fn required_length(colluders: usize, population: usize, fp_log10: u32) -> usize {
    const A: f64 = 50.0;
    let c = colluders.max(1) as f64;
    let eps = 10f64.powi(-(fp_log10 as i32));
    let ln = ((population.max(1) as f64) / eps).ln().max(1.0);
    (A * c * c * ln).ceil() as usize
}

/// Inverse of [`required_length`]: the largest coalition a given number of
/// positions can resist at this population/eps. The honest capacity check —
/// short content has few positions and therefore low collusion resistance.
pub fn max_colluders(positions: usize, population: usize, fp_log10: u32) -> usize {
    const A: f64 = 50.0;
    let eps = 10f64.powi(-(fp_log10 as i32));
    let ln = ((population.max(1) as f64) / eps).ln().max(1.0);
    let c2 = positions as f64 / (A * ln);
    c2.sqrt().floor() as usize
}

// ─────────────────────────────── bias vector + codewords ───────────────────────────────

/// The per-work bias vector `p_j in [t, 1-t]`, arcsine-distributed (density
/// `1/(pi*sqrt(p(1-p)))`), derived deterministically from the work seed so
/// embed and accusation agree exactly. Same `(work_seed, positions, colluders)`
/// always yields the same vector.
pub fn bias_vector(work_seed: &[u8], positions: usize, colluders: usize) -> Vec<f64> {
    let t = cutoff(colluders);
    let theta_min = t.sqrt().asin();
    let theta_max = std::f64::consts::FRAC_PI_2 - theta_min;
    (0..positions)
        .map(|j| {
            let u = hmac_unit(work_seed, b"lysn-tardos/bias", j as u32);
            let theta = theta_min + u * (theta_max - theta_min);
            theta.sin().powi(2) // in [t, 1-t]
        })
        .collect()
}

/// A buyer's codeword: bit `j` is 1 with probability `p_j`, decided
/// deterministically from the buyer's [`Serial`]. Reproducible at accusation
/// time from the same serial.
pub fn codeword_for(serial: &Serial, biases: &[f64]) -> Vec<bool> {
    biases
        .iter()
        .enumerate()
        .map(|(j, &p)| hmac_unit(&serial.0, b"lysn-tardos/codeword", j as u32) < p)
        .collect()
}

// ─────────────────────────────── scoring + accusation ───────────────────────────────

/// Symmetric (Škorić) accusation score of one codeword against a detected symbol
/// sequence. `detected[j] == None` is an erasure (contributes nothing). For an
/// innocent buyer this has mean 0 and variance equal to the number of observed
/// positions, so it is `~N(0, m_obs)`.
pub fn score(detected: &[Option<bool>], codeword: &[bool], biases: &[f64]) -> f64 {
    let mut s = 0.0;
    for j in 0..biases.len().min(codeword.len()).min(detected.len()) {
        let Some(y) = detected[j] else { continue };
        let p = biases[j];
        let g1 = ((1.0 - p) / p).sqrt(); // matching a 1
        let g0 = (p / (1.0 - p)).sqrt(); // matching a 0
        s += match (y, codeword[j]) {
            (true, true) => g1,
            (true, false) => -g0,
            (false, false) => g0,
            (false, true) => -g1,
        };
    }
    s
}

/// A scored trace lead. **Evidence, not verdict** — a `score` above `threshold`
/// marks a suspect, but corroborate before acting.
#[derive(Debug, Clone, PartialEq)]
pub struct ScoredSuspect {
    pub label: String,
    pub score: f64,
    pub threshold: f64,
}

/// The accusation threshold for a run: `sqrt(m_obs) * z(1 - eps_per_buyer)`,
/// with `eps_per_buyer` Bonferroni-split across the enrolled population so the
/// WHOLE run's false-positive probability is bounded by `10^-fp_log10`.
/// Independent of code length — this is what guarantees no false accusal.
pub fn threshold(observed_positions: usize, population: usize, fp_log10: u32) -> f64 {
    // Cap fp_log10 so `-(… as i32)` can't overflow and 10^-fp can't underflow.
    let eps = 10f64.powi(-(fp_log10.min(300) as i32));
    let eps_per = (eps / population.max(1) as f64).clamp(f64::MIN_POSITIVE, 0.5);
    // Upper-tail quantile computed DIRECTLY from eps_per: z(1-a) = -z(a). Never
    // form `1 - eps_per` — for tiny eps_per it rounds to 1.0 (quantile +∞ ⇒
    // tracing silently disabled) and otherwise loses digits to cancellation.
    (observed_positions as f64).sqrt() * -normal_quantile(eps_per)
}

/// Below this many OBSERVED positions the score isn't yet normal (CLT), so the
/// `sqrt(m_obs)·z` threshold no longer bounds the false-positive rate. Refuse to
/// accuse on evidence that thin (fail safe: a miss, never a frame).
pub const MIN_OBSERVED_POSITIONS: usize = 48;

/// Score every enrolled buyer against the detected sequence and return those
/// above threshold, strongest first. `biases` must be the same vector used at
/// embed (`bias_vector` with the work's seed/params). `fp_log10` sets the
/// false-positive bound for the whole run.
pub fn accuse(
    detected: &[Option<bool>],
    ledger: &TraceLedger,
    biases: &[f64],
    fp_log10: u32,
) -> Vec<ScoredSuspect> {
    let m_obs = detected.iter().filter(|d| d.is_some()).count();
    if m_obs < MIN_OBSERVED_POSITIONS {
        return Vec::new(); // too few observed positions to bound false positives
    }
    let n = ledger.len().max(1);
    let th = threshold(m_obs, n, fp_log10);
    let mut out: Vec<ScoredSuspect> = ledger
        .entries()
        .iter()
        .filter_map(|e| {
            let cw = codeword_for(&e.serial, biases);
            let s = score(detected, &cw, biases);
            (s > th).then(|| ScoredSuspect {
                label: e.label.clone(),
                score: s,
                threshold: th,
            })
        })
        .collect();
    out.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}

// ─────────────────────────────── attacker model (marking assumption) ───────────────────────────────

/// A tiny deterministic PRNG (splitmix64). Used ONLY to model the attacker
/// (collusion strategy, channel noise) reproducibly — the tracing math itself
/// never uses randomness. Bit-identical with lysn's `tardos::Prng`.
#[derive(Debug, Clone)]
pub struct Prng(pub u64);

impl Prng {
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n.max(1) as u64) as usize
    }
}

/// How a coalition fuses their copies at a detectable position (one where their
/// bits differ). Under the **marking assumption**, positions where all colluders
/// agree are FORCED to that shared bit; only detectable positions are attackable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollusionStrategy {
    Majority,
    Minority,
    CoinFlip,
    AllZero,
    AllOne,
    Interleave,
}

/// The standard set of attack strategies, for sweeping in tests.
pub const ALL_STRATEGIES: [CollusionStrategy; 6] = [
    CollusionStrategy::Majority,
    CollusionStrategy::Minority,
    CollusionStrategy::CoinFlip,
    CollusionStrategy::AllZero,
    CollusionStrategy::AllOne,
    CollusionStrategy::Interleave,
];

/// Fuse a coalition's codewords into a detected symbol sequence under the
/// marking assumption. Forced positions (all agree) are emitted verbatim;
/// detectable positions follow `strategy`.
pub fn fuse(
    codewords: &[Vec<bool>],
    strategy: CollusionStrategy,
    rng: &mut Prng,
) -> Vec<Option<bool>> {
    if codewords.is_empty() {
        return Vec::new();
    }
    let m = codewords[0].len();
    (0..m)
        .map(|j| {
            let ones = codewords.iter().filter(|cw| cw[j]).count();
            if ones == codewords.len() {
                Some(true) // forced
            } else if ones == 0 {
                Some(false) // forced
            } else {
                match strategy {
                    CollusionStrategy::Majority => Some(ones * 2 >= codewords.len()),
                    CollusionStrategy::Minority => Some(ones * 2 < codewords.len()),
                    CollusionStrategy::AllZero => Some(false),
                    CollusionStrategy::AllOne => Some(true),
                    CollusionStrategy::CoinFlip => Some(rng.next_u64() & 1 == 1),
                    CollusionStrategy::Interleave => Some(codewords[rng.below(codewords.len())][j]),
                }
            }
        })
        .collect()
}

/// Apply channel noise: flip each observed symbol with probability `flip_prob`
/// (erasures stay erased). Models a robust-but-imperfect watermark channel that
/// survives re-encode with bit errors.
pub fn apply_noise(detected: &mut [Option<bool>], flip_prob: f64, rng: &mut Prng) {
    for b in detected.iter_mut().flatten() {
        if rng.unit() < flip_prob {
            *b = !*b;
        }
    }
}

// ─────────────────────────────── inverse normal CDF (Acklam) ───────────────────────────────

/// Inverse standard-normal CDF (Acklam's rational approximation, accurate to
/// ~1e-9). `p` in (0,1). Bit-identical with lysn.
fn normal_quantile(p: f64) -> f64 {
    const A: [f64; 6] = [
        -3.969_683_028_665_376e1,
        2.209_460_984_245_205e2,
        -2.759_285_104_469_687e2,
        1.383_577_518_672_69e2,
        -3.066_479_806_614_716e1,
        2.506_628_277_459_239e0,
    ];
    const B: [f64; 5] = [
        -5.447_609_879_822_406e1,
        1.615_858_368_580_409e2,
        -1.556_989_798_598_866e2,
        6.680_131_188_771_972e1,
        -1.328_068_155_288_572e1,
    ];
    const C: [f64; 6] = [
        -7.784_894_002_430_293e-3,
        -3.223_964_580_411_365e-1,
        -2.400_758_277_161_838e0,
        -2.549_732_539_343_734e0,
        4.374_664_141_464_968e0,
        2.938_163_982_698_783e0,
    ];
    const D: [f64; 4] = [
        7.784_695_709_041_462e-3,
        3.224_671_290_700_398e-1,
        2.445_134_137_142_996e0,
        3.754_408_661_907_416e0,
    ];
    let plow = 0.02425;
    let phigh = 1.0 - plow;
    if p <= 0.0 {
        return f64::NEG_INFINITY;
    }
    if p >= 1.0 {
        return f64::INFINITY;
    }
    if p < plow {
        let q = (-2.0 * p.ln()).sqrt();
        (((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
            / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1.0)
    } else if p <= phigh {
        let q = p - 0.5;
        let r = q * q;
        (((((A[0] * r + A[1]) * r + A[2]) * r + A[3]) * r + A[4]) * r + A[5]) * q
            / (((((B[0] * r + B[1]) * r + B[2]) * r + B[3]) * r + B[4]) * r + 1.0)
    } else {
        let q = (-2.0 * (1.0 - p).ln()).sqrt();
        -(((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
            / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"seller-trace-secret";

    fn enroll_population(n: usize) -> TraceLedger {
        let mut led = TraceLedger::new();
        for i in 0..n {
            led.enroll(SECRET, b"work", &format!("buyer{i}"));
        }
        led
    }

    #[test]
    fn threshold_is_finite_and_monotone_at_extremes() {
        // Regression: `1 - eps_per` rounding to 1.0 for tiny eps_per used to make
        // the threshold +∞ and silently disable ALL tracing. It must stay finite,
        // and a stricter fp must give a strictly higher bar.
        let m = 128;
        for &(fp, pop) in &[
            (6u32, 1usize),
            (12, 10_000),
            (15, 100),
            (18, 1),
            (300, 1_000_000),
        ] {
            let th = threshold(m, pop, fp);
            assert!(
                th.is_finite() && th > 0.0,
                "threshold finite & positive for fp={fp}, pop={pop}, got {th}"
            );
        }
        let th_max = threshold(m, 1, u32::MAX);
        assert!(
            th_max.is_finite() && th_max > 0.0,
            "no overflow panic at fp_log10 = u32::MAX"
        );
        assert!(
            threshold(m, 1, 12) > threshold(m, 1, 6),
            "stricter eps ⇒ higher threshold"
        );
        assert!(
            threshold(m, 1_000, 6) > threshold(m, 1, 6),
            "larger population ⇒ higher threshold"
        );
    }

    #[test]
    fn bias_and_codeword_are_deterministic() {
        let b1 = bias_vector(b"work-1", 128, 3);
        let b2 = bias_vector(b"work-1", 128, 3);
        assert_eq!(b1, b2, "bias vector is deterministic");
        assert!(
            b1.iter().all(|&p| p > 0.0 && p < 1.0),
            "biases strictly inside (0,1)"
        );
        let s = Serial::derive(SECRET, b"work", b"x");
        assert_eq!(
            codeword_for(&s, &b1),
            codeword_for(&s, &b1),
            "codeword is deterministic"
        );
    }

    #[test]
    fn tardos_golden_vector_matches_lysn() {
        // CROSS-REPO GOLDEN VECTOR. The bias distribution and codeword rule must
        // be bit-identical with lysn-watermark; these exact values must also be
        // asserted there. Independently verified against an HMAC-SHA256 reference.
        // Serial is a FIXED byte string (not derived) so the vector depends only on
        // the shared math, not either repo's enrollment scheme. Pin in BOTH repos.
        let biases = bias_vector(b"golden-seed", 8, 3);
        let expected_biases = [
            0.177776101,
            0.964041588,
            0.118869602,
            0.255585364,
            0.075223527,
            0.216557329,
            0.014092161,
            0.013582092,
        ];
        for (j, (&got, &want)) in biases.iter().zip(expected_biases.iter()).enumerate() {
            // Round to 9 dp: robust to platform ULP differences in sin/asin.
            let r = (got * 1e9).round() / 1e9;
            assert!((r - want).abs() < 1e-9, "bias[{j}] drift: {r} vs {want}");
        }
        let codeword = codeword_for(&Serial(b"golden-serial".to_vec()), &biases);
        assert_eq!(
            codeword,
            [false, true, false, false, true, false, false, false],
            "Tardos codeword golden vector changed — lysn interop broken"
        );
    }

    #[test]
    fn capacity_roundtrips() {
        let m = required_length(4, 1000, 6);
        assert!(
            max_colluders(m, 1000, 6) >= 4,
            "a code sized for c=4 resists at least 4"
        );
        assert!(
            max_colluders(50, 1000, 6) < max_colluders(5000, 1000, 6),
            "more positions => more resistance"
        );
    }

    #[test]
    fn innocent_scores_are_mean_zero_and_threshold_bounds_false_positives() {
        // The headline guarantee: with the threshold set for eps, an innocent is
        // accused at most eps of the time, whatever the colluding sequence is.
        let m = 2000;
        let biases = bias_vector(b"fp-work", m, 3);
        let fp_log10 = 2; // eps = 0.01, population 1 => 99th percentile
        let th = threshold(m, 1, fp_log10);
        let trials = 6000usize;
        let mut rng = Prng(0xDEAD_BEEF);
        let mut sum = 0.0;
        let mut exceed = 0usize;
        for t in 0..trials {
            let coalition: Vec<Vec<bool>> = (0..3)
                .map(|k| {
                    codeword_for(
                        &Serial::derive(
                            SECRET,
                            format!("cg{t}").as_bytes(),
                            format!("c{t}-{k}").as_bytes(),
                        ),
                        &biases,
                    )
                })
                .collect();
            let detected = fuse(&coalition, CollusionStrategy::Majority, &mut rng);
            let innocent = codeword_for(
                &Serial::derive(
                    SECRET,
                    format!("ig{t}").as_bytes(),
                    format!("innocent{t}").as_bytes(),
                ),
                &biases,
            );
            let s = score(&detected, &innocent, &biases);
            sum += s;
            if s > th {
                exceed += 1;
            }
        }
        let mean = sum / trials as f64;
        let fp_rate = exceed as f64 / trials as f64;
        assert!(mean.abs() < 1.5, "innocent score mean ~0 (got {mean:.3})");
        assert!(
            fp_rate <= 0.03,
            "false-positive rate {fp_rate:.4} exceeds bound (eps=0.01)"
        );
    }

    #[test]
    fn catches_at_least_one_colluder_and_frames_no_innocent() {
        // Soundness across coalition sizes and every attack strategy: the accused
        // set always contains a real colluder and never an innocent.
        let population = 60usize;
        let fp_log10 = 4; // eps = 1e-4
        for &c in &[2usize, 3] {
            let m = required_length(c, population, fp_log10);
            for &strat in &ALL_STRATEGIES {
                let trials = 40usize;
                let mut rng = Prng(0x1234_5678 ^ (c as u64) << 32 ^ strat as u64);
                for t in 0..trials {
                    let work = format!("work-{c}-{}-{t}", strat as u8);
                    let biases = bias_vector(work.as_bytes(), m, c);
                    let ledger = enroll_population(population);
                    let mut idx = Vec::new();
                    while idx.len() < c {
                        let k = rng.below(population);
                        if !idx.contains(&k) {
                            idx.push(k);
                        }
                    }
                    let coalition: Vec<Vec<bool>> = idx
                        .iter()
                        .map(|&k| codeword_for(&ledger.entries()[k].serial, &biases))
                        .collect();
                    let mut detected = fuse(&coalition, strat, &mut rng);
                    apply_noise(&mut detected, 0.02, &mut rng); // 2% channel bit-error
                    let accused = accuse(&detected, &ledger, &biases, fp_log10);
                    let colluder_labels: Vec<&String> =
                        idx.iter().map(|&k| &ledger.entries()[k].label).collect();
                    let caught = accused.iter().any(|a| colluder_labels.contains(&&a.label));
                    let framed = accused.iter().any(|a| !colluder_labels.contains(&&a.label));
                    assert!(
                        caught,
                        "c={c} strat={strat:?} trial={t}: no colluder caught"
                    );
                    assert!(
                        !framed,
                        "c={c} strat={strat:?} trial={t}: an innocent was framed"
                    );
                }
            }
        }
    }

    #[test]
    fn accuse_refuses_evidence_below_the_observed_floor() {
        let biases = bias_vector(b"floor-work", 8000, 3);
        let ledger = enroll_population(50);
        let target = codeword_for(&ledger.entries()[0].serial, &biases);
        let mut detected = vec![None; 8000];
        for (j, d) in detected
            .iter_mut()
            .enumerate()
            .take(MIN_OBSERVED_POSITIONS - 1)
        {
            *d = Some(target[j]);
        }
        assert!(
            accuse(&detected, &ledger, &biases, 6).is_empty(),
            "thin evidence => no accusation"
        );
        for (j, d) in detected.iter_mut().enumerate().take(300) {
            *d = Some(target[j]);
        }
        let accused = accuse(&detected, &ledger, &biases, 6);
        assert_eq!(
            accused.first().map(|a| a.label.clone()),
            Some(ledger.entries()[0].label.clone())
        );
        assert!(
            accused.iter().all(|a| a.label == ledger.entries()[0].label),
            "no innocent"
        );
    }
}
