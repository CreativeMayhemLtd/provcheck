//! WavMark's custom-payload brand registry.
//!
//! WavMark's 32-bit payload is split into:
//!   - **bits 0..16**: a hardcoded fix-pattern (the detection signal,
//!     see [`crate::model::WAVMARK_FIX_PATTERN`]). A chunk is "marked"
//!     iff the recovered first 16 bits exactly match this pattern.
//!   - **bits 16..32**: a custom 16-bit payload the encoder writes.
//!     We use the same 3-copy-5-bit ECC as `provcheck-audioseal` so a
//!     single decoder bit-flip in the lower-payload region still
//!     resolves to the correct brand. See
//!     `provcheck-audioseal::registry` for the layout rationale.
//!
//! Encoding the lower-16 payload:
//!
//! ```text
//!  bit:  15  14  13  12  11  10   9   8   7   6   5   4   3   2   1   0
//!       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//!       | R |       copy 3      |       copy 2      |       copy 1      |
//!       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! ```
//!
//! Doomscroll (`0x01` = `0b00001`): all three copies hold `00001`,
//! reserved bit = 0 → payload `0 00001 00001 00001` = `0x0421`.

pub const BRAND_DOOMSCROLL: u8 = 0x01;
pub const BRAND_RAIDIO: u8 = 0x02;
pub const BRAND_VAIDEO: u8 = 0x03;

pub const ID_MASK: u8 = 0x1F;

/// Encode a 5-bit brand ID into the 16-bit custom-payload region.
pub fn encode_payload(id: u8) -> u16 {
    debug_assert!(id <= ID_MASK, "id must fit in 5 bits");
    let id16 = (id & ID_MASK) as u16;
    id16 | (id16 << 5) | (id16 << 10)
}

/// Recover a 5-bit brand ID from the 16-bit custom-payload region by
/// bit-wise majority vote across the three repeated copies.
pub fn decode_payload(payload: u16) -> u8 {
    let copy1 = (payload & ID_MASK as u16) as u8;
    let copy2 = ((payload >> 5) & ID_MASK as u16) as u8;
    let copy3 = ((payload >> 10) & ID_MASK as u16) as u8;
    let mut result = 0u8;
    for i in 0..5 {
        let votes = ((copy1 >> i) & 1) + ((copy2 >> i) & 1) + ((copy3 >> i) & 1);
        if votes >= 2 {
            result |= 1 << i;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_doomscroll() {
        assert_eq!(encode_payload(BRAND_DOOMSCROLL), 0x0421);
    }

    #[test]
    fn encode_raidio() {
        // BRAND_RAIDIO = 0x02 = 0b00010. Three copies → 0b00010_00010_00010
        // with reserved bit 0 → 0x0842.
        assert_eq!(encode_payload(BRAND_RAIDIO), 0x0842);
    }

    #[test]
    fn encode_vaideo() {
        // BRAND_VAIDEO = 0x03 = 0b00011. Three copies → 0x0C63.
        assert_eq!(encode_payload(BRAND_VAIDEO), 0x0C63);
    }

    #[test]
    fn round_trip_all_ids() {
        for id in 0..=ID_MASK {
            assert_eq!(decode_payload(encode_payload(id)), id);
        }
    }

    #[test]
    fn tolerates_single_bit_flip() {
        let original = encode_payload(BRAND_DOOMSCROLL);
        for flip in 0..16 {
            let flipped = original ^ (1 << flip);
            assert_eq!(decode_payload(flipped), BRAND_DOOMSCROLL, "flip @ {flip}");
        }
    }

    #[test]
    fn tolerates_single_bit_flip_on_every_brand() {
        // Generalise to all three brands: any single-bit error
        // in the recovered 16-bit lower-payload region must be
        // corrected by majority vote across the three copies.
        for &id in &[BRAND_DOOMSCROLL, BRAND_RAIDIO, BRAND_VAIDEO] {
            let original = encode_payload(id);
            for flip in 0..16 {
                let flipped = original ^ (1 << flip);
                assert_eq!(
                    decode_payload(flipped),
                    id,
                    "brand 0x{id:02x} flip @ {flip} recovered wrong id"
                );
            }
        }
    }

    #[test]
    fn encoding_matches_audioseal_registry_for_same_brand() {
        // Cross-crate parity invariant: both crates document the
        // same 3-copy 5-bit ECC layout. A drift between the two
        // would mean an audioseal-marked stream couldn't be
        // re-tagged via wavmark and vice versa.
        for id in 0..=ID_MASK {
            assert_eq!(
                encode_payload(id),
                provcheck_audioseal::registry::encode_payload(id),
                "wavmark and audioseal must encode 0x{id:02x} identically"
            );
        }
    }

    #[test]
    fn reserved_bit_is_always_zero() {
        // Bit 15 is the reserved bit per the layout doc. Encode
        // must always leave it 0.
        for id in 0..=ID_MASK {
            let payload = encode_payload(id);
            assert_eq!(
                payload >> 15,
                0,
                "id 0x{id:02x}: reserved bit (15) must be 0, got payload 0x{payload:04x}"
            );
        }
    }

    #[test]
    fn id_mask_is_5_bits() {
        // ID_MASK constant must match the documented 5-bit space.
        assert_eq!(ID_MASK, 0x1F);
        assert_eq!(ID_MASK.count_ones(), 5);
    }

    #[test]
    fn decode_zero_payload_is_zero_id() {
        // All-zero payload → all-zero ID. This is the "no
        // signal" case after detection on unmarked content.
        assert_eq!(decode_payload(0), 0);
    }

    #[test]
    fn decode_handles_pessimal_two_bit_flip_in_one_copy() {
        // Two bit flips in the SAME copy still leave the other
        // two copies clean → majority vote recovers correctly.
        let original = encode_payload(BRAND_DOOMSCROLL);
        // Flip bits 0 and 4 (both in copy 1).
        let flipped = original ^ 0b10001;
        assert_eq!(decode_payload(flipped), BRAND_DOOMSCROLL);
    }
}
