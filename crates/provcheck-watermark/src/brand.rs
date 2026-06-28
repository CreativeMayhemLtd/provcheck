//! Schema-aware payload dispatch + brand registry.
//!
//! The 5-byte silentcipher payload is treated as a tagged
//! union keyed on `payload[3]` (the schema version byte). New
//! schema versions can repartition the remaining bytes; old
//! tooling continues to read the schema byte first and reports
//! `UnknownSchema` when it can't decode the rest.
//!
//! Schema 1 (production today): bytes 0..3 are an ASCII brand
//! triplet; byte 3 = 1; byte 4 = reserved (always 0).

use crate::hparams::{CONFIDENCE_DEGRADED_THRESHOLD, CONFIDENCE_DETECTED_THRESHOLD};
use provcheck::prelude::{WatermarkBrand, WatermarkStatus};

/// Index of the schema byte in the 5-byte payload.
const SCHEMA_BYTE_INDEX: usize = 3;

/// Schema 1's well-known brand-byte triplets.
const BRAND_RAI: [u8; 3] = [b'R', b'A', b'I'];
const BRAND_DFM: [u8; 3] = [b'D', b'F', b'M'];
const BRAND_VAI: [u8; 3] = [b'V', b'A', b'I'];

/// Schema 1 payload for the rAIdio.bot AI music brand.
/// 5-byte tagged union: `b"RAI" + schema=1 + reserved=0`.
/// v0.7 phase 7-pre — exposed as a public constant so downstream
/// callers do not have to hard-code the triplet themselves.
pub const PAYLOAD_RAIDIO: [u8; 5] = [b'R', b'A', b'I', 0x01, 0x00];

/// Schema 1 payload for the doomscroll.fm AI voice brand.
/// 5-byte tagged union: `b"DFM" + schema=1 + reserved=0`.
pub const PAYLOAD_DOOMSCROLL: [u8; 5] = [b'D', b'F', b'M', 0x01, 0x00];

/// Schema 1 payload for the vAIdeo.bot AI video brand.
/// 5-byte tagged union: `b"VAI" + schema=1 + reserved=0`.
pub const PAYLOAD_VAIDEO: [u8; 5] = [b'V', b'A', b'I', 0x01, 0x00];

/// Parse a 5-byte payload according to its embedded schema
/// version and return the matching [`WatermarkBrand`]. Always
/// returns `Some` — unknown brands and unknown schemas have
/// explicit fallback variants. The `Option` wrapper is left
/// for the call-site to use directly with
/// `WatermarkResult::brand: Option<WatermarkBrand>` without an
/// extra match — see [`crate::detect`].
pub fn parse_brand(payload: [u8; 5]) -> Option<WatermarkBrand> {
    let schema = payload[SCHEMA_BYTE_INDEX];
    match schema {
        1 => {
            let letters = [payload[0], payload[1], payload[2]];
            Some(brand_from_letters(letters))
        }
        other => Some(WatermarkBrand::UnknownSchema { schema: other }),
    }
}

/// Map an ASCII brand triplet to a known product, or report it
/// as `UnknownAscii`. Comparisons are case-sensitive — the
/// brand-byte registry is authoritative on case.
fn brand_from_letters(letters: [u8; 3]) -> WatermarkBrand {
    if letters == BRAND_RAI {
        WatermarkBrand::Raidio
    } else if letters == BRAND_DFM {
        WatermarkBrand::Doomscroll
    } else if letters == BRAND_VAI {
        WatermarkBrand::Vaideo
    } else {
        WatermarkBrand::UnknownAscii { letters }
    }
}

/// Three-tier classifier for a decoded watermark, combining
/// the back-end's structural-validity bit with the confidence
/// value:
///
/// - `valid == false`          → `NotDetected` regardless of confidence.
/// - `valid && conf >= 0.70`   → `Detected`.
/// - `valid && 0.50 <= conf`   → `Degraded`.
/// - `valid && conf < 0.50`    → `NotDetected` (false-positive guard).
pub fn classify(valid: bool, confidence: f32) -> WatermarkStatus {
    if !valid {
        return WatermarkStatus::NotDetected;
    }
    if confidence >= CONFIDENCE_DETECTED_THRESHOLD {
        WatermarkStatus::Detected
    } else if confidence >= CONFIDENCE_DEGRADED_THRESHOLD {
        WatermarkStatus::Degraded
    } else {
        WatermarkStatus::NotDetected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rai_payload_maps_to_raidio() {
        assert_eq!(
            parse_brand([82, 65, 73, 1, 0]),
            Some(WatermarkBrand::Raidio)
        );
    }

    #[test]
    fn dfm_payload_maps_to_doomscroll() {
        assert_eq!(
            parse_brand([68, 70, 77, 1, 0]),
            Some(WatermarkBrand::Doomscroll)
        );
    }

    #[test]
    fn vai_payload_maps_to_vaideo() {
        assert_eq!(
            parse_brand([86, 65, 73, 1, 0]),
            Some(WatermarkBrand::Vaideo)
        );
    }

    #[test]
    fn unknown_ascii_triplet_under_schema1_is_unknown_ascii() {
        let brand = parse_brand([b'X', b'Y', b'Z', 1, 0]).unwrap();
        assert_eq!(
            brand,
            WatermarkBrand::UnknownAscii {
                letters: [b'X', b'Y', b'Z']
            }
        );
    }

    #[test]
    fn unknown_schema_short_circuits_brand_lookup() {
        // Even if bytes 0..3 happen to be 'R','A','I', a non-1
        // schema means we don't know what they mean and must
        // report as UnknownSchema.
        let brand = parse_brand([82, 65, 73, 9, 0]).unwrap();
        assert_eq!(brand, WatermarkBrand::UnknownSchema { schema: 9 });
    }

    #[test]
    fn classify_buckets_match_thresholds() {
        assert_eq!(classify(true, 0.99), WatermarkStatus::Detected);
        assert_eq!(classify(true, 0.70), WatermarkStatus::Detected);
        assert_eq!(classify(true, 0.69), WatermarkStatus::Degraded);
        assert_eq!(classify(true, 0.50), WatermarkStatus::Degraded);
        assert_eq!(classify(true, 0.49), WatermarkStatus::NotDetected);
        assert_eq!(classify(false, 0.95), WatermarkStatus::NotDetected);
    }
}
