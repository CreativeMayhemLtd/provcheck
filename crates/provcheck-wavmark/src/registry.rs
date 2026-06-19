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
}
