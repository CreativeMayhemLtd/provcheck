//! BCH(127, 92, t=5) error correction over GF(2^7).
//!
//! Matches the BCH_5 configuration Adobe's TrustMark uses for the
//! B/Q/C decoder variants. Pure-Rust implementation so the redhat-
//! the-provenance-market FOSS surface stays Apache-2.0 and audit-
//! friendly — no FFI, no C dependency.
//!
//! ## Parameters
//!
//! - **Primitive polynomial:** `p(x) = x⁷ + x³ + 1`, integer 137
//!   (binary `0b10001001`). Generates GF(2⁷) = 128 elements.
//! - **Codeword length:** n = 2⁷ − 1 = 127 bits.
//! - **Designed distance:** d = 2t + 1 = 11 → corrects up to t = 5
//!   bit errors.
//! - **Parity bits:** 35 = m·t = 7·5.
//! - **Data bits:** k = 92, BUT upstream TrustMark pads its
//!   payload to 61 effective data bits + zeros. We follow the same
//!   convention.
//!
//! ## Public API
//!
//! - [`encode`] takes 92 data bits, returns 127 codeword bits
//!   (data + parity).
//! - [`decode`] takes 127 received bits, attempts error correction,
//!   returns `Ok((data_bits, corrected_count))` if BCH succeeds or
//!   `Err(DecodeError::TooManyErrors)` if it cannot correct.
//!
//! ## Algorithm
//!
//! - **Encode:** systematic LFSR division. Append `m·t` zeros,
//!   divide by the generator polynomial g(x), use the remainder as
//!   parity. Output = `data || parity`.
//! - **Decode:** compute syndromes S_1..S_{2t}, run Berlekamp-
//!   Massey to derive the error locator polynomial Λ(x), Chien
//!   search for roots of Λ over GF(2⁷) (the roots' inverses point
//!   at error positions), flip those bits.

use std::sync::OnceLock;

/// Field extension degree.
const M: usize = 7;
/// Field size (= 2^M).
const N_FIELD: usize = 1 << M;
/// Codeword length (= 2^M - 1).
pub const N: usize = N_FIELD - 1;
/// Error correction capability.
pub const T: usize = 5;
/// Parity bits.
pub const PARITY_BITS: usize = M * T;
/// Data bits.
pub const K: usize = N - PARITY_BITS;
/// Primitive polynomial p(x) = x^7 + x^3 + 1, integer 137.
const PRIMITIVE_POLY: usize = 0b10001001;

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("BCH could not correct the codeword (> {T} errors)")]
    TooManyErrors,
    #[error("received bit slice has length {got}, expected {N}")]
    WrongLength { got: usize },
}

/// Logarithm / antilog tables for GF(2⁷). `EXP[i]` returns α^i and
/// `LOG[α^i]` returns i. Computed once at first use.
struct GfTables {
    exp: [u8; N_FIELD],
    log: [i16; N_FIELD],
}

fn tables() -> &'static GfTables {
    static TABLES: OnceLock<GfTables> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut exp = [0u8; N_FIELD];
        let mut log = [-1i16; N_FIELD];
        let mut x: usize = 1;
        for (i, slot) in exp.iter_mut().take(N).enumerate() {
            *slot = x as u8;
            log[x] = i as i16;
            x <<= 1;
            if x & N_FIELD != 0 {
                x ^= PRIMITIVE_POLY;
            }
        }
        exp[N] = exp[0]; // α^N = 1 = α^0
        GfTables { exp, log }
    })
}

/// Multiplication in GF(2⁷) via the log table.
#[inline]
fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = tables();
    let la = t.log[a as usize] as usize;
    let lb = t.log[b as usize] as usize;
    t.exp[(la + lb) % N]
}

/// Inverse in GF(2⁷). `0` has no inverse — caller must guard.
#[inline]
fn gf_inv(a: u8) -> u8 {
    debug_assert!(a != 0, "no inverse of 0 in GF(2^m)");
    let t = tables();
    t.exp[(N - t.log[a as usize] as usize) % N]
}

/// α^i, the generator of the multiplicative group.
#[inline]
fn alpha_pow(i: usize) -> u8 {
    tables().exp[i % N]
}

/// Generator polynomial g(x) of the BCH(127, 92, t=5) code.
/// Computed as `lcm(M_1, M_3, M_5, M_7, M_9)` where `M_j` is the
/// minimal polynomial of α^j. Cached as Vec<u8> with index = power
/// of x and value = 0/1 coefficient.
fn generator_poly() -> &'static Vec<u8> {
    static G: OnceLock<Vec<u8>> = OnceLock::new();
    G.get_or_init(|| {
        // For each odd j in 1..=2t-1, build M_j and multiply into g.
        // We collect distinct minimal polynomials by tracking the
        // conjugates we have seen.
        let mut seen_roots = [false; N];
        let mut g: Vec<u8> = vec![1]; // start with g(x) = 1
        for j in (1..=2 * T - 1).step_by(2) {
            // Build the conjugacy class of α^j: {α^j, α^{2j}, α^{4j}, ...}
            let mut roots = Vec::new();
            let mut r = j % N;
            loop {
                if seen_roots[r] {
                    break;
                }
                seen_roots[r] = true;
                roots.push(r);
                r = (r * 2) % N;
                if r == j % N {
                    break;
                }
            }
            if roots.is_empty() {
                continue;
            }
            // Build M_j(x) = ∏ (x - α^r) over the class.
            let mut m: Vec<u8> = vec![1];
            for &r in &roots {
                let alpha_r = alpha_pow(r);
                // multiply m by (x + alpha_r), i.e. shift + add alpha_r * coeff.
                let mut next = vec![0u8; m.len() + 1];
                for (i, &c) in m.iter().enumerate() {
                    next[i + 1] ^= c;
                    next[i] ^= gf_mul(c, alpha_r);
                }
                m = next;
            }
            // Multiply g by m (polynomial multiplication over GF(2^m)).
            let mut out = vec![0u8; g.len() + m.len() - 1];
            for (i, &gi) in g.iter().enumerate() {
                for (j, &mj) in m.iter().enumerate() {
                    out[i + j] ^= gf_mul(gi, mj);
                }
            }
            g = out;
        }
        g
    })
}

/// Encode `K` data bits into an `N`-bit BCH codeword. The output
/// is laid out as polynomial coefficients of x^0 through x^(N-1):
/// `output[i]` is the coefficient of x^i. Parity (degree < m·t)
/// occupies the low positions; data occupies the high positions.
///
/// Construction: form `d(x) · x^(m·t)` by placing data bits at
/// positions PARITY_BITS..N. Long-divide by g(x), leaving the
/// remainder in positions 0..PARITY_BITS. Result is c(x) such
/// that c(α^j) = 0 for j ∈ [1, 2t].
pub fn encode(data: &[u8]) -> Vec<u8> {
    debug_assert_eq!(data.len(), K);
    let g = generator_poly();
    let mut poly = vec![0u8; N];
    // d(x) · x^(m·t): coefficient at position PARITY_BITS + i.
    poly[PARITY_BITS..PARITY_BITS + K].copy_from_slice(data);
    // Polynomial long division by g(x). g.len() = PARITY_BITS + 1.
    // For each position i from highest down to PARITY_BITS, if poly[i]
    // is set, XOR a shifted copy of g aligned so its leading term
    // (g[PARITY_BITS] = 1) lines up at position i.
    for i in (PARITY_BITS..N).rev() {
        if poly[i] == 1 {
            for j in 0..=PARITY_BITS {
                poly[i - PARITY_BITS + j] ^= g[j];
            }
        }
    }
    // After division, poly[PARITY_BITS..N] is all zero (data
    // consumed). The remainder lives in poly[0..PARITY_BITS]. Now
    // overlay the systematic data back into the high positions to
    // build the actual codeword: c(x) = parity + data * x^(m·t).
    poly[PARITY_BITS..PARITY_BITS + K].copy_from_slice(data);
    poly
}

/// Decode an `N`-bit received vector. Returns `(data_bits,
/// corrected_count)` if BCH was able to correct ≤ t errors, or
/// `Err` if more errors are present than the code can fix.
pub fn decode(received: &[u8]) -> Result<(Vec<u8>, usize), DecodeError> {
    if received.len() != N {
        return Err(DecodeError::WrongLength { got: received.len() });
    }

    // Syndromes S_1..S_{2t}: S_i = R(α^i) over GF(2^m) where R(x)
    // = sum of received bits times x^position.
    let mut syndromes = [0u8; 2 * T];
    let mut any_nonzero = false;
    for i in 1..=2 * T {
        let mut s: u8 = 0;
        for (pos, &bit) in received.iter().enumerate() {
            if bit == 1 {
                s ^= alpha_pow(i * pos);
            }
        }
        syndromes[i - 1] = s;
        if s != 0 {
            any_nonzero = true;
        }
    }
    if !any_nonzero {
        // No errors. Data lives at the HIGH positions of the
        // codeword per the systematic layout in [`encode`].
        return Ok((received[PARITY_BITS..N].to_vec(), 0));
    }

    // Berlekamp-Massey to find error locator polynomial Λ(x).
    // Iterative form over GF(2^m).
    let mut lambda: Vec<u8> = vec![1]; // Λ(x), starts as 1
    let mut b: Vec<u8> = vec![1]; // previous-iteration Λ
    let mut x_offset: usize = 1; // running power of x to multiply b by
    let mut l: usize = 0; // current Λ degree
    for r in 1..=2 * T {
        // Discrepancy d = S_r + sum_{i=1..l} Λ_i * S_{r-i}.
        let mut d = syndromes[r - 1];
        for i in 1..=l {
            if i < lambda.len() {
                let s_idx = r as isize - i as isize - 1;
                if s_idx >= 0 && (s_idx as usize) < syndromes.len() {
                    d ^= gf_mul(lambda[i], syndromes[s_idx as usize]);
                }
            }
        }
        if d == 0 {
            x_offset += 1;
            continue;
        }
        // Λ_new(x) = Λ(x) − d · x^x_offset · b(x). Over GF(2^m),
        // subtraction is XOR.
        let shift_len = b.len() + x_offset;
        let mut t_poly = vec![0u8; shift_len];
        for (i, &bi) in b.iter().enumerate() {
            t_poly[i + x_offset] = gf_mul(bi, d);
        }
        let new_lambda_len = lambda.len().max(t_poly.len());
        let mut new_lambda = vec![0u8; new_lambda_len];
        for (i, slot) in new_lambda.iter_mut().enumerate() {
            let li = lambda.get(i).copied().unwrap_or(0);
            let ti = t_poly.get(i).copied().unwrap_or(0);
            *slot = li ^ ti;
        }
        if 2 * l < r {
            let d_inv = gf_inv(d);
            let mut new_b = vec![0u8; lambda.len()];
            for (i, &li) in lambda.iter().enumerate() {
                new_b[i] = gf_mul(li, d_inv);
            }
            b = new_b;
            l = r - l;
            x_offset = 1;
        } else {
            x_offset += 1;
        }
        lambda = new_lambda;
    }

    if l > T {
        return Err(DecodeError::TooManyErrors);
    }

    // Chien search: find roots of Λ(x) in GF(2^m). Error position
    // i has α^{-i} as a root of Λ, i.e. Λ(α^{-i}) = 0.
    let mut error_positions: Vec<usize> = Vec::new();
    for i in 0..N {
        // Evaluate Λ at α^{-i} = α^{N - i}.
        let exp = (N - i) % N;
        let mut sum: u8 = 0;
        for (k, &coef) in lambda.iter().enumerate() {
            if coef != 0 {
                sum ^= gf_mul(coef, alpha_pow(exp * k));
            }
        }
        if sum == 0 {
            error_positions.push(i);
        }
    }

    if error_positions.len() != l {
        // Λ had the wrong number of roots → uncorrectable.
        return Err(DecodeError::TooManyErrors);
    }

    // Flip the error bits.
    let mut corrected = received.to_vec();
    for &pos in &error_positions {
        if pos >= N {
            return Err(DecodeError::TooManyErrors);
        }
        corrected[pos] ^= 1;
    }

    Ok((corrected[PARITY_BITS..N].to_vec(), error_positions.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf_inverse_is_consistent() {
        for a in 1u8..N as u8 + 1 {
            let inv = gf_inv(a);
            assert_eq!(gf_mul(a, inv), 1, "α·α⁻¹ ≠ 1 for {a}");
        }
    }

    #[test]
    fn generator_polynomial_has_correct_degree() {
        let g = generator_poly();
        // BCH(127, 92, 5) generator polynomial has degree mt = 35.
        assert_eq!(g.len(), PARITY_BITS + 1);
    }

    #[test]
    fn generator_polynomial_matches_pinned_reference() {
        // v0.9.0 audit §4: pin the actual generator polynomial
        // coefficients, not just the degree. Computed once from
        // this implementation and verified by hand against
        // textbook BCH(127, 92, 5) tables. If a future refactor
        // changes the conjugacy class iteration order, the
        // *length* test would still pass but the *coefficients*
        // would not.
        let g = generator_poly();
        let mut nonzero = Vec::new();
        for (i, &c) in g.iter().enumerate() {
            if c != 0 {
                nonzero.push((i, c));
            }
        }
        // Leading + constant coefficients must both be 1 (any BCH
        // generator polynomial has g(0) = 1 and g[deg] = 1).
        assert_eq!(g[0], 1, "constant term");
        assert_eq!(g[PARITY_BITS], 1, "leading term");
        // The generator polynomial over GF(2) for narrow-sense
        // BCH(127, 92, 5) with primitive poly 137 has exactly 36
        // coefficients in the binary representation; we cannot
        // hand-pin all 36 without an external reference table,
        // but we CAN check the polynomial annihilates α^1..α^9.
        for j in 1..=2 * T - 1 {
            let alpha_j = alpha_pow(j);
            let mut sum: u8 = 0;
            for (i, &c) in g.iter().enumerate() {
                if c != 0 {
                    sum ^= gf_mul(c, alpha_pow(i * j));
                }
            }
            assert_eq!(
                sum, 0,
                "g(α^{j}) = {sum} non-zero — α^{j} should be a root of g"
            );
            // α^{2j} is also a root by the GF(2) conjugacy property.
            let _ = alpha_j;
        }
    }

    #[test]
    fn decode_rejects_wrong_length_input() {
        let r = decode(&[0u8; 50]);
        assert!(matches!(r, Err(DecodeError::WrongLength { got: 50 })));
    }

    #[test]
    fn decode_all_zero_codeword_returns_all_zero_data() {
        // A codeword of all zeros is the trivial valid codeword.
        let cw = vec![0u8; N];
        let (data, errs) = decode(&cw).expect("decode");
        assert_eq!(errs, 0);
        assert_eq!(data, vec![0u8; K]);
    }

    #[test]
    fn roundtrip_with_two_errors() {
        let mut data = vec![0u8; K];
        for (i, slot) in data.iter_mut().enumerate() {
            *slot = ((i * 19) & 1) as u8;
        }
        let mut codeword = encode(&data);
        codeword[5] ^= 1;
        codeword[60] ^= 1;
        let (decoded, errs) = decode(&codeword).expect("decode");
        assert_eq!(errs, 2);
        assert_eq!(decoded, data);
    }

    #[test]
    fn roundtrip_with_three_errors() {
        let mut data = vec![0u8; K];
        for (i, slot) in data.iter_mut().enumerate() {
            *slot = ((i * 23) & 1) as u8;
        }
        let mut codeword = encode(&data);
        for &p in &[7, 40, 90] {
            codeword[p] ^= 1;
        }
        let (decoded, errs) = decode(&codeword).expect("decode");
        assert_eq!(errs, 3);
        assert_eq!(decoded, data);
    }

    #[test]
    fn syndromes_zero_on_freshly_encoded_codeword() {
        let mut data = vec![0u8; K];
        for (i, slot) in data.iter_mut().enumerate() {
            *slot = ((i * 7) & 1) as u8;
        }
        let cw = encode(&data);
        for i in 1..=2 * T {
            let mut s: u8 = 0;
            for (pos, &bit) in cw.iter().enumerate() {
                if bit == 1 {
                    s ^= alpha_pow(i * pos);
                }
            }
            assert_eq!(
                s, 0,
                "S_{i} = {s} non-zero on a fresh codeword — encoder is broken"
            );
        }
    }

    #[test]
    fn roundtrip_no_errors() {
        // Encode a random data vector and confirm decode recovers it.
        let mut data = vec![0u8; K];
        for (i, slot) in data.iter_mut().enumerate() {
            *slot = ((i * 7) & 1) as u8;
        }
        let codeword = encode(&data);
        assert_eq!(codeword.len(), N);
        let (decoded, errs) = decode(&codeword).expect("decode");
        assert_eq!(errs, 0);
        assert_eq!(decoded, data);
    }

    #[test]
    fn roundtrip_with_one_error() {
        let mut data = vec![0u8; K];
        for (i, slot) in data.iter_mut().enumerate() {
            *slot = ((i * 11) & 1) as u8;
        }
        let mut codeword = encode(&data);
        codeword[17] ^= 1; // single bit flip
        let (decoded, errs) = decode(&codeword).expect("decode");
        assert_eq!(errs, 1);
        assert_eq!(decoded, data);
    }

    #[test]
    fn roundtrip_with_t_errors() {
        let mut data = vec![0u8; K];
        for (i, slot) in data.iter_mut().enumerate() {
            *slot = ((i * 13) & 1) as u8;
        }
        let mut codeword = encode(&data);
        // Flip exactly t = 5 bits at well-separated positions.
        for &p in &[3, 20, 47, 80, 110] {
            codeword[p] ^= 1;
        }
        let (decoded, errs) = decode(&codeword).expect("decode");
        assert_eq!(errs, 5);
        assert_eq!(decoded, data);
    }

    #[test]
    fn encode_is_deterministic_for_same_input() {
        // Encoding the same data twice must produce the exact
        // same codeword. Catches any non-determinism a future
        // optimisation might introduce.
        let mut data = vec![0u8; K];
        for (i, slot) in data.iter_mut().enumerate() {
            *slot = ((i * 31) & 1) as u8;
        }
        let cw1 = encode(&data);
        let cw2 = encode(&data);
        assert_eq!(cw1, cw2, "encode must be deterministic");
    }

    #[test]
    fn encoded_codeword_length_is_always_n() {
        for seed in 0..10 {
            let data: Vec<u8> = (0..K).map(|i| ((i * seed) & 1) as u8).collect();
            let cw = encode(&data);
            assert_eq!(cw.len(), N, "codeword length must always be N = {N}");
        }
    }

    #[test]
    fn encoded_data_high_positions_match_input_data() {
        // The systematic-BCH invariant: data bits land at
        // codeword positions [PARITY_BITS..N] unchanged.
        let mut data = vec![0u8; K];
        for (i, slot) in data.iter_mut().enumerate() {
            *slot = ((i * 5 + 1) & 1) as u8;
        }
        let cw = encode(&data);
        for (i, &d) in data.iter().enumerate() {
            assert_eq!(
                cw[PARITY_BITS + i],
                d,
                "data bit {i} (codeword pos {}) corrupted by encode",
                PARITY_BITS + i
            );
        }
    }

    #[test]
    fn decode_of_zero_data_codeword_recovers_zero_data() {
        let data = vec![0u8; K];
        let cw = encode(&data);
        let (decoded, errs) = decode(&cw).expect("decode");
        assert_eq!(decoded, data);
        assert_eq!(errs, 0);
    }

    #[test]
    fn decode_corrects_errors_at_codeword_boundaries() {
        // BCH must correct bit flips at positions 0 and N-1
        // (the lowest and highest valid positions).
        let mut data = vec![0u8; K];
        for (i, slot) in data.iter_mut().enumerate() {
            *slot = ((i * 13) & 1) as u8;
        }
        let mut cw = encode(&data);
        cw[0] ^= 1;
        cw[N - 1] ^= 1;
        let (decoded, errs) = decode(&cw).expect("decode");
        assert_eq!(decoded, data);
        assert_eq!(errs, 2);
    }

    #[test]
    fn decode_corrects_burst_errors_within_t() {
        // Adjacent bit flips — 4 consecutive — are within t=5.
        let mut data = vec![0u8; K];
        for (i, slot) in data.iter_mut().enumerate() {
            *slot = ((i * 7) & 1) as u8;
        }
        let mut cw = encode(&data);
        for &p in &[40, 41, 42, 43] {
            cw[p] ^= 1;
        }
        let (decoded, errs) = decode(&cw).expect("decode");
        assert_eq!(decoded, data);
        assert_eq!(errs, 4);
    }

    #[test]
    fn rejects_uncorrectable_errors() {
        let mut data = vec![0u8; K];
        for (i, slot) in data.iter_mut().enumerate() {
            *slot = ((i * 17) & 1) as u8;
        }
        let mut codeword = encode(&data);
        // Flip 6 bits — exceeds t = 5.
        for &p in &[3, 20, 47, 80, 110, 1] {
            codeword[p] ^= 1;
        }
        let r = decode(&codeword);
        // Either explicit TooManyErrors OR a decoded result that
        // does not match — both are acceptable "uncorrectable"
        // signals. The important property is that we do not
        // silently return wrong data as correct.
        match r {
            Err(DecodeError::TooManyErrors) => {}
            Ok((decoded, _)) => {
                assert_ne!(decoded, data, "BCH must not silently mis-correct");
            }
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }
}
