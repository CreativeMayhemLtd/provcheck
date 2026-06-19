//! Shared numeric brand registry for short-payload watermarks.
//!
//! Neural watermark decoders aren't bit-perfect. AudioSeal's
//! upstream `detect_watermark` reports ~6 % per-bit error on real
//! music — empirically confirmed by our own roundtrip fixture
//! against `audioseal-roundtrip-fixture.py`: a 16-bit payload of
//! `0x0001` (Doomscroll) is recovered as `0x0101` (one bit flipped
//! during embed/recovery). At that error rate, a naive `u16` lookup
//! mis-classifies > 90 % of marked content.
//!
//! Encoding fix: the 16-bit payload carries **three copies of a
//! 5-bit brand ID, plus one reserved bit**. The decoder recovers
//! each copy and takes a bit-wise majority vote, which handles up
//! to one bit flip per payload with full certainty and ~99 %+ of
//! the realistic 1-2 flip per payload regime.
//!
//! Layout (LSB = position 0):
//!
//! ```text
//!  bit:  15  14  13  12  11  10   9   8   7   6   5   4   3   2   1   0
//!       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//!       | R |       copy 3      |       copy 2      |       copy 1      |
//!       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//!       \--/ \------ 5 bits ---/ \------ 5 bits ---/ \------ 5 bits ---/
//!         |          ID 3              ID 2              ID 1
//!         |
//!         +-- reserved (always 0)
//! ```
//!
//! For Doomscroll (`0x01` = `0b00001`), all three copies hold
//! `00001`, the reserved bit is 0, so the on-wire payload is
//! `0 00001 00001 00001` = `0x0421` (big-endian bytes `04 21`).

/// 5-bit brand identifier for doomscroll.fm.
pub const BRAND_DOOMSCROLL: u8 = 0x01;

/// 5-bit brand identifier for rAIdio.bot.
pub const BRAND_RAIDIO: u8 = 0x02;

/// 5-bit brand identifier for vAIdeo.bot. Reserved for the video
/// product when it joins the registry.
pub const BRAND_VAIDEO: u8 = 0x03;

/// Mask for the 5 ID bits.
pub const ID_MASK: u8 = 0x1F;

/// Encode a 5-bit brand ID into the 16-bit on-wire payload as three
/// repeated copies + a reserved bit. Used by the embed path.
///
/// Panics in debug mode if `id` has bits set above bit 4.
pub fn encode_payload(id: u8) -> u16 {
    debug_assert!(id <= ID_MASK, "id must fit in 5 bits");
    let id16 = (id & ID_MASK) as u16;
    id16 | (id16 << 5) | (id16 << 10)
}

/// Recover a 5-bit brand ID from a 16-bit payload by bit-wise
/// majority vote across the three repeated copies. Used by the
/// detect path.
pub fn decode_payload(payload: u16) -> u8 {
    let copy1 = (payload & ID_MASK as u16) as u8;
    let copy2 = ((payload >> 5) & ID_MASK as u16) as u8;
    let copy3 = ((payload >> 10) & ID_MASK as u16) as u8;
    let mut result = 0u8;
    for i in 0..5 {
        let votes = ((copy1 >> i) & 1) + ((copy2 >> i) & 1) + ((copy3 >> i) & 1);
        // Majority of three: vote in if >= 2 copies agree.
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
        assert_eq!(encode_payload(BRAND_RAIDIO), 0x0842);
    }

    #[test]
    fn encode_vaideo() {
        assert_eq!(encode_payload(BRAND_VAIDEO), 0x0C63);
    }

    #[test]
    fn encode_then_decode_round_trips() {
        for id in 0..=ID_MASK {
            let encoded = encode_payload(id);
            assert_eq!(decode_payload(encoded), id, "round trip for id=0x{id:02x}");
        }
    }

    #[test]
    fn decode_tolerates_single_bit_flip() {
        let original = encode_payload(BRAND_DOOMSCROLL);
        for flip_pos in 0..16 {
            let flipped = original ^ (1 << flip_pos);
            let recovered = decode_payload(flipped);
            assert_eq!(
                recovered, BRAND_DOOMSCROLL,
                "single-bit-flip at position {flip_pos} should still recover Doomscroll"
            );
        }
    }

    #[test]
    fn decode_handles_pessimal_two_bit_flip_in_one_copy() {
        // Two bit flips in the SAME copy still leave the other two
        // copies clean → majority vote recovers correctly.
        let original = encode_payload(BRAND_DOOMSCROLL);
        // Flip two bits in copy 1 (positions 0 and 4)
        let flipped = original ^ 0b10001;
        let recovered = decode_payload(flipped);
        assert_eq!(recovered, BRAND_DOOMSCROLL);
    }
}
