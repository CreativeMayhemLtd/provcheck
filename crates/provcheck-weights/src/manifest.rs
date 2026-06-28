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
    // Sony silentcipher encoder (MIT, weights via huggingface
    // sony/silentcipher). v0.6 included via include_bytes!();
    // migrated to DLC in the v0.7 phase 8a batch.
    WeightEntry {
        family: "silentcipher",
        variant: "encoder",
        filename: "silentcipher-encoder-v1.onnx",
        url: "https://github.com/CreativeMayhemLtd/provcheck/releases/download/weights-v1/silentcipher-encoder-v1.onnx",
        sha256: hex32!("d4f7b1992af8efda33f03b7e79b3f00293824ea0ca2462db484e1e30eea93061"),
        size_bytes: 2_170_740,
    },
    // Sony silentcipher decoder (detect path).
    WeightEntry {
        family: "silentcipher",
        variant: "decoder",
        filename: "silentcipher-decoder-v1.onnx",
        url: "https://github.com/CreativeMayhemLtd/provcheck/releases/download/weights-v1/silentcipher-decoder-v1.onnx",
        sha256: hex32!("6e433b5a1910e751adfa123c271ad48cb6fae39caf618db0000b0e0f3ee2288b"),
        size_bytes: 9_538_724,
    },
    // Meta AudioSeal detector (MIT since 2024-04-02 relicense).
    WeightEntry {
        family: "audioseal",
        variant: "detector",
        filename: "audioseal-detector-v1.onnx",
        url: "https://github.com/CreativeMayhemLtd/provcheck/releases/download/weights-v1/audioseal-detector-v1.onnx",
        sha256: hex32!("7dd84d2ba60207f05c657f9e01ec1fe9c59b37844410d68301d426179220936d"),
        size_bytes: 34_707_680,
    },
    // Meta AudioSeal generator (embed path).
    WeightEntry {
        family: "audioseal",
        variant: "generator",
        filename: "audioseal-generator-v1.onnx",
        url: "https://github.com/CreativeMayhemLtd/provcheck/releases/download/weights-v1/audioseal-generator-v1.onnx",
        sha256: hex32!("82cc3898553497429283ecdb662f785b5490a2680cba343451c8958d26a773e1"),
        size_bytes: 58_889_748,
    },
    // WavMark HiNet encoder (MIT, weights via PyPI `wavmark`).
    WeightEntry {
        family: "wavmark",
        variant: "encoder",
        filename: "wavmark-encoder-v1.onnx",
        url: "https://github.com/CreativeMayhemLtd/provcheck/releases/download/weights-v1/wavmark-encoder-v1.onnx",
        sha256: hex32!("cce4c7ee399c47e63f616ee82c574f9b8466ed789d5408cbc63529d526191e02"),
        size_bytes: 5_861_770,
    },
    // WavMark HiNet decoder (detect path).
    WeightEntry {
        family: "wavmark",
        variant: "decoder",
        filename: "wavmark-decoder-v1.onnx",
        url: "https://github.com/CreativeMayhemLtd/provcheck/releases/download/weights-v1/wavmark-decoder-v1.onnx",
        sha256: hex32!("78d101db31a180a6927a6170d9bbf4b22008554c50695a87f52440568831a4c7"),
        size_bytes: 5_861_768,
    },
    // WavMark forward FC weights (used by stft.rs's apply_watermark_fc).
    // The matching bias is small enough (64 KB) to keep embedded.
    WeightEntry {
        family: "wavmark",
        variant: "fc-weights",
        filename: "wavmark-watermark-fc-weights-v1.bin",
        url: "https://github.com/CreativeMayhemLtd/provcheck/releases/download/weights-v1/wavmark-watermark-fc-weights-v1.bin",
        sha256: hex32!("a493f449cb569af798a8d8d65b2b7bec3e7c126255868a125bae99f5bad1f881"),
        size_bytes: 2_048_000,
    },
    // WavMark inverse FC weights (apply_watermark_fc_back).
    WeightEntry {
        family: "wavmark",
        variant: "fc-back-weights",
        filename: "wavmark-watermark-fc-back-weights-v1.bin",
        url: "https://github.com/CreativeMayhemLtd/provcheck/releases/download/weights-v1/wavmark-watermark-fc-back-weights-v1.bin",
        sha256: hex32!("ce64d17d41d8827fefceda499c8fd4a3e8701e9c1a4ff73d362644bb2e31040e"),
        size_bytes: 2_048_000,
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
