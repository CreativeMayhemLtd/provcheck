//! Static manifest baked into the binary at compile time.
//!
//! Each entry pairs a (family, variant) tuple with the URL on
//! `github.com/CreativeMayhemLtd/provcheck/releases/download/...`
//! and the SHA256 the bytes must hash to. Adding a weight = adding
//! a row here + uploading the corresponding asset to the matching
//! release tag on the public mirror.

/// One downloadable weight file.
#[derive(Debug, Clone, Copy)]
pub struct WeightEntry {
    /// Family identifier — matches the detector crate's family
    /// name (e.g. `"silentcipher"`, `"trustmark"`).
    pub family: &'static str,
    /// Variant within the family (e.g. `"b-decoder"` for TrustMark-B
    /// decoder, `"encoder"` for the silentcipher encoder).
    pub variant: &'static str,
    /// Filename used both in the cache directory AND as the
    /// release asset name on the public mirror. Identical so the
    /// URL pattern is predictable.
    pub filename: &'static str,
    /// Full download URL on
    /// `github.com/CreativeMayhemLtd/provcheck/releases/download/...`.
    pub url: &'static str,
    /// SHA256 of the file's bytes. Verified after download AND on
    /// every cache hit; a mismatch refuses the load.
    pub sha256: [u8; 32],
    /// Expected size in bytes (informational; operator-facing).
    pub size_bytes: u64,
}

/// The bundled v1 manifest. Bumping to v2 means a new release tag
/// (`weights-v2`) + a new manifest constant; binaries built
/// against v1 continue to pull from the immutable v1 release.
pub const MANIFEST: &[WeightEntry] = &[
    // Adobe TrustMark-B decoder. Released under MIT per
    // github.com/adobe/trustmark's repo-wide LICENSE (the weights
    // themselves do not carry a separate license file; the MIT
    // statement covers the artifact set). Originally hosted at
    // cai-watermark.adobe.net/watermarking/trustmark-models/ on
    // Adobe's S3; mirrored to our public GH release for stability
    // and SHA-pinned distribution. Source captured 2026-06-28.
    WeightEntry {
        family: "trustmark",
        variant: "b-decoder",
        filename: "trustmark-b-decoder-v1.onnx",
        url: "https://github.com/CreativeMayhemLtd/provcheck/releases/download/weights-v1/trustmark-b-decoder-v1.onnx",
        sha256: hex32!("d0e25bb6925f1b92c321996cf4ec4961f38de711099b9a289000db4fcd51aa8d"),
        size_bytes: 47_401_222,
    },
    // Adobe TrustMark-B encoder (matching pair for embed).
    WeightEntry {
        family: "trustmark",
        variant: "b-encoder",
        filename: "trustmark-b-encoder-v1.onnx",
        url: "https://github.com/CreativeMayhemLtd/provcheck/releases/download/weights-v1/trustmark-b-encoder-v1.onnx",
        sha256: hex32!("31e2fc73deba043de3b2ed0cbd4b0ec38fcc69dc112d3c4b6e52364a0921a65d"),
        size_bytes: 17_312_208,
    },
];

/// Compile-time hex string to `[u8; 32]`. Lets the manifest stay
/// readable while the actual constant is a fixed-size byte array.
macro_rules! hex32 {
    ($s:literal) => {{
        const fn parse(s: &str) -> [u8; 32] {
            let bytes = s.as_bytes();
            assert!(bytes.len() == 64, "sha256 hex must be 64 chars");
            let mut out = [0u8; 32];
            let mut i = 0;
            while i < 32 {
                out[i] = (hex_nibble(bytes[i * 2]) << 4) | hex_nibble(bytes[i * 2 + 1]);
                i += 1;
            }
            out
        }
        const fn hex_nibble(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => panic!("invalid hex char in sha256 literal"),
            }
        }
        parse($s)
    }};
}
pub(crate) use hex32;
