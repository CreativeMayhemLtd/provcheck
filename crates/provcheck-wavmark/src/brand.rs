//! WavMark payload → brand dispatch.
//!
//! Takes the recovered 16-bit custom payload (the lower 16 bits of
//! WavMark's 32-bit payload) and dispatches to the shared numeric
//! brand registry. The upper 16 bits — the fix-pattern — are the
//! detection signal, not part of the brand decode.

use provcheck::prelude::WatermarkBrand;

use crate::registry::{self, BRAND_DOOMSCROLL, BRAND_RAIDIO, BRAND_VAIDEO};

/// Parse a 16-bit big-endian WavMark custom payload to a brand.
pub fn parse_brand(payload: [u8; 2]) -> Option<WatermarkBrand> {
    let payload_u16 = u16::from_be_bytes(payload);
    let id = registry::decode_payload(payload_u16);
    Some(match id {
        BRAND_DOOMSCROLL => WatermarkBrand::Doomscroll,
        BRAND_RAIDIO => WatermarkBrand::Raidio,
        BRAND_VAIDEO => WatermarkBrand::Vaideo,
        other => WatermarkBrand::UnknownNumeric { id: other as u16 },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doomscroll_payload_maps_to_doomscroll() {
        assert_eq!(parse_brand([0x04, 0x21]), Some(WatermarkBrand::Doomscroll));
    }

    #[test]
    fn raidio_payload_maps_to_raidio() {
        assert_eq!(parse_brand([0x08, 0x42]), Some(WatermarkBrand::Raidio));
    }
}
