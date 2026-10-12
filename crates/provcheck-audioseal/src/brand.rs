//! AudioSeal payload → brand dispatch.
//!
//! AudioSeal's 16-bit payload doesn't fit silentcipher's 40-bit
//! `[ASCII triplet, schema=1, reserved=0]` convention. The 16 bits
//! are an ECC-protected 5-bit brand ID — see [`crate::registry`] for
//! the layout and the majority-vote decoder. Parsing is two steps:
//! recover the 5-bit ID from the 16 bits, then look it up in the
//! shared registry.

use provcheck::prelude::WatermarkBrand;

use crate::registry::{self, BRAND_DOOMSCROLL, BRAND_RAIDIO, BRAND_VAIDEO};

/// Parse a 16-bit (big-endian) AudioSeal payload to a brand. Decodes
/// the payload's three repeated 5-bit copies by majority vote, then
/// dispatches to the brand registry. Always returns `Some` — the
/// `UnknownNumeric` variant is the fallback for IDs not yet in the
/// registry.
pub fn parse_brand(payload: [u8; 2]) -> Option<WatermarkBrand> {
    let payload_u16 = u16::from_be_bytes(payload);
    let id = registry::decode_payload(payload_u16);
    Some(match id {
        BRAND_DOOMSCROLL => WatermarkBrand::Doomscroll,
        BRAND_RAIDIO => WatermarkBrand::Raidio,
        BRAND_VAIDEO => WatermarkBrand::Vaideo,
        // Surface the recovered (post-ECC) ID, not the raw payload.
        other => WatermarkBrand::UnknownNumeric { id: other as u16 },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doomscroll_payload_maps_to_doomscroll() {
        // Doomscroll on-wire payload: 0x0421 (three copies of 0x01 + reserved)
        assert_eq!(parse_brand([0x04, 0x21]), Some(WatermarkBrand::Doomscroll));
    }

    #[test]
    fn raidio_payload_maps_to_raidio() {
        // Raidio on-wire payload: 0x0842
        assert_eq!(parse_brand([0x08, 0x42]), Some(WatermarkBrand::Raidio));
    }

    #[test]
    fn vaideo_payload_maps_to_vaideo() {
        // Vaideo on-wire payload: 0x0C63
        assert_eq!(parse_brand([0x0C, 0x63]), Some(WatermarkBrand::Vaideo));
    }

    #[test]
    fn one_bit_flip_in_doomscroll_payload_still_decodes() {
        // The 3-copy majority vote recovers the value after any single bit flip.
        let original = 0x0421_u16;
        for flip in 0..16 {
            let bytes = (original ^ (1 << flip)).to_be_bytes();
            assert_eq!(
                parse_brand(bytes),
                Some(WatermarkBrand::Doomscroll),
                "1-bit flip at position {flip} should still decode Doomscroll"
            );
        }
    }

    #[test]
    fn unknown_id_surfaces_id() {
        // 0x7FFF = three copies of the maximal 5-bit value (0x1F = 31), recovered as UnknownNumeric.
        let payload = 0x7FFF_u16.to_be_bytes();
        assert_eq!(
            parse_brand(payload),
            Some(WatermarkBrand::UnknownNumeric { id: 0x1F })
        );
    }
}
