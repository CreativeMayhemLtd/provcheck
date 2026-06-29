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
#[allow(dead_code)]
pub const PAYLOAD_RAIDIO: [u8; 5] = [b'R', b'A', b'I', 0x01, 0x00];

/// Schema 1 payload for the doomscroll.fm AI voice brand.
/// 5-byte tagged union: `b"DFM" + schema=1 + reserved=0`.
#[allow(dead_code)]
pub const PAYLOAD_DOOMSCROLL: [u8; 5] = [b'D', b'F', b'M', 0x01, 0x00];

/// Schema 1 payload for the vAIdeo.bot AI video brand.
/// 5-byte tagged union: `b"VAI" + schema=1 + reserved=0`.
#[allow(dead_code)]
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

    // ----- Brand payload constants ----------
    //
    // Pin every PAYLOAD_* constant exactly. These are the
    // production payloads the embedder writes; a typo here
    // (e.g. a `b'V' -> b'B'` slip) silently breaks every
    // downstream verifier.

    #[test]
    fn payload_raidio_is_rai_schema1_reserved0() {
        assert_eq!(PAYLOAD_RAIDIO, [b'R', b'A', b'I', 0x01, 0x00]);
    }

    #[test]
    fn payload_doomscroll_is_dfm_schema1_reserved0() {
        assert_eq!(PAYLOAD_DOOMSCROLL, [b'D', b'F', b'M', 0x01, 0x00]);
    }

    #[test]
    fn payload_vaideo_is_vai_schema1_reserved0() {
        assert_eq!(PAYLOAD_VAIDEO, [b'V', b'A', b'I', 0x01, 0x00]);
    }

    #[test]
    fn payload_constants_round_trip_through_parse_brand() {
        // PAYLOAD_RAIDIO → parse_brand → Raidio. Symmetric for
        // each constant. Catches an accidental drift between
        // the PAYLOAD_* table and the parser's BRAND_* table.
        assert_eq!(parse_brand(PAYLOAD_RAIDIO), Some(WatermarkBrand::Raidio));
        assert_eq!(
            parse_brand(PAYLOAD_DOOMSCROLL),
            Some(WatermarkBrand::Doomscroll)
        );
        assert_eq!(parse_brand(PAYLOAD_VAIDEO), Some(WatermarkBrand::Vaideo));
    }

    #[test]
    fn payload_constants_all_use_schema_byte_one() {
        // The PAYLOAD_* table's [3] is the schema version. Pin
        // that every shipped constant lives in schema 1 (the
        // only currently-documented schema).
        for (name, payload) in [
            ("RAIDIO", PAYLOAD_RAIDIO),
            ("DOOMSCROLL", PAYLOAD_DOOMSCROLL),
            ("VAIDEO", PAYLOAD_VAIDEO),
        ] {
            assert_eq!(
                payload[SCHEMA_BYTE_INDEX], 1,
                "PAYLOAD_{name} must use schema version 1"
            );
        }
    }

    #[test]
    fn payload_constants_all_use_reserved_byte_zero() {
        // The reserved byte is documented as always-zero.
        for (name, payload) in [
            ("RAIDIO", PAYLOAD_RAIDIO),
            ("DOOMSCROLL", PAYLOAD_DOOMSCROLL),
            ("VAIDEO", PAYLOAD_VAIDEO),
        ] {
            assert_eq!(
                payload[4], 0,
                "PAYLOAD_{name} reserved byte must be 0"
            );
        }
    }

    #[test]
    fn schema_byte_index_is_three() {
        // The tagged-union key position. Pin so a future
        // schema-2 work doesn't accidentally shift it.
        assert_eq!(SCHEMA_BYTE_INDEX, 3);
    }

    // ----- parse_brand edge cases ----------

    #[test]
    fn parse_brand_lowercase_ascii_is_unknown_not_a_known_brand() {
        // Case-sensitive registry — "rai" is NOT Raidio.
        let r = parse_brand([b'r', b'a', b'i', 1, 0]);
        match r {
            Some(WatermarkBrand::UnknownAscii { letters }) => {
                assert_eq!(letters, [b'r', b'a', b'i']);
            }
            other => panic!("expected UnknownAscii, got {other:?}"),
        }
    }

    #[test]
    fn parse_brand_zero_schema_returns_unknown_schema() {
        // Schema 0 is reserved / not yet a real schema. Must
        // surface as UnknownSchema.
        let r = parse_brand([b'R', b'A', b'I', 0, 0]);
        assert_eq!(r, Some(WatermarkBrand::UnknownSchema { schema: 0 }));
    }

    #[test]
    fn parse_brand_max_schema_byte_returns_unknown_schema() {
        // 0xFF must not silently fall through to schema-1
        // behaviour.
        let r = parse_brand([b'R', b'A', b'I', 0xFF, 0]);
        assert_eq!(r, Some(WatermarkBrand::UnknownSchema { schema: 0xFF }));
    }

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
