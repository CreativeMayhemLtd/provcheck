// SPDX-License-Identifier: Apache-2.0
//! RFC 8785 JSON Canonicalization Scheme (JCS) — the deterministic bytes a
//! signature is computed over.
//!
//! **Ported verbatim from Lysn.fm's `lysn-jcs` crate.** A license signed by the
//! offline `dlc-issue` tool (Lysn.fm side) is only verifiable here if this
//! canonicalization produces byte-for-byte the same output. Do not "improve"
//! this module in isolation: any change is a wire-breaking change that must land
//! in `lysn-jcs` too, and the golden vectors in the tests below (shared with the
//! Lysn.fm crate) are what catch drift.
//!
//! The three rules that matter (RFC 8785 §3.2):
//! - **Object keys** are sorted by **UTF-16 code unit** order (not UTF-8 byte
//!   order — they differ for astral-plane characters).
//! - **Strings** use JCS escaping: `\" \\ \b \t \n \f \r`, `\u00XX` for other
//!   control chars, and raw UTF-8 for everything else (no `\/`, no gratuitous
//!   `\uXXXX`).
//! - **No insignificant whitespace**; array and object member order as given.
//!
//! LYSN records (including the license) carry **no JSON floats** — every quantity
//! is an integer or a string — so the ECMAScript shortest-float path is not
//! implemented; a non-integer number falls back to serde_json's formatting.

use serde_json::Value;

/// Canonicalize to UTF-8 bytes. This is the exact input (after the domain tag is
/// prepended) that the license signature is verified against.
pub fn canonicalize_bytes(value: &Value) -> Vec<u8> {
    canonicalize(value).into_bytes()
}

/// Canonicalize to a `String`. See the module note on floats.
pub fn canonicalize(value: &Value) -> String {
    let mut out = String::new();
    write_value(value, &mut out);
    out
}

fn write_value(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&number(n)),
        Value::String(s) => write_string(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, v) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(v, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by_key(|k| utf16(k));
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write_value(&map[*k], out);
            }
            out.push('}');
        }
    }
}

/// UTF-16 code units of a string (the JCS key-ordering key).
fn utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// Integer numbers exact; other numbers via serde_json's own formatting.
fn number(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    n.to_string()
}

/// RFC 8785 §3.2.2.2 string escaping.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0A}' => out.push_str("\\n"),
            '\u{0C}' => out.push_str("\\f"),
            '\u{0D}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

// ─────────────────────────────── tests ───────────────────────────────
// These mirror `lysn-jcs`'s own tests one-for-one. If any diverges, the two
// canonicalizers have drifted and cross-repo license verification is broken.

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_sorted_and_no_whitespace() {
        let v = json!({ "b": 1, "a": 2, "c": 3 });
        assert_eq!(canonicalize(&v), r#"{"a":2,"b":1,"c":3}"#);
    }

    #[test]
    fn nested_objects_and_arrays() {
        let v = json!({ "z": [3, 2, 1], "a": { "y": 1, "x": 2 } });
        assert_eq!(canonicalize(&v), r#"{"a":{"x":2,"y":1},"z":[3,2,1]}"#);
    }

    #[test]
    fn string_escaping_matches_jcs() {
        let v = json!({ "s": "a\"b\\c\nd\te\r\u{08}\u{0c}\u{01}" });
        let expected = "{\"s\":\"a\\\"b\\\\c\\nd\\te\\r\\b\\f\\u0001\"}";
        assert_eq!(canonicalize(&v), expected);
    }

    #[test]
    fn forward_slash_not_escaped() {
        let v = json!({ "uri": "https://a/b" });
        assert_eq!(canonicalize(&v), r#"{"uri":"https://a/b"}"#);
    }

    #[test]
    fn unicode_preserved_raw() {
        let v = json!({ "title": "Björk – Jóga" });
        assert_eq!(canonicalize(&v), "{\"title\":\"Björk – Jóga\"}");
    }

    #[test]
    fn utf16_ordering_for_astral_keys() {
        // U+1F600 (😀) is a UTF-16 surrogate pair starting 0xD83D; U+FFFF is
        // 0xFFFF. UTF-16 order puts 😀 first; UTF-8 byte order would not. JCS
        // mandates UTF-16.
        let v = json!({ "\u{FFFF}": 1, "😀": 2 });
        assert_eq!(canonicalize(&v), "{\"😀\":2,\"\u{FFFF}\":1}");
    }

    #[test]
    fn integers_exact() {
        let v = json!({ "n": 1499u64, "big": 9007199254740993u64, "neg": -42 });
        assert_eq!(
            canonicalize(&v),
            r#"{"big":9007199254740993,"n":1499,"neg":-42}"#
        );
    }

    #[test]
    fn idempotent() {
        let v = json!({ "b": [ { "d": 1, "c": 2 } ], "a": "x" });
        let once = canonicalize(&v);
        let twice: Value = serde_json::from_str(&once).unwrap();
        assert_eq!(canonicalize(&twice), once);
    }
}
