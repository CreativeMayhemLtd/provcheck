# provcheck-mellin

Keyed spectral (Fourier-Mellin) forensic watermark channel: scale/stretch-invariant
embed and detect over i16 LE PCM. Ported from Lysn.fm's `lysn-watermark` crate
(`src/mellin.rs`) so the provenance suite can run seller-side forensic detection.

## This crate is opt-in, and it is NOT in the release binary

provcheck is Apache-2.0, and `WATERMARK_LICENSE_POLICY.md` requires everything
bundled into the binary to be permissively licensed. This crate is **BUSL-1.1**
(see `LICENSE`; it converts to Apache-2.0 on 2030-01-01), so it is excluded from
the workspace, never wired into the detector dispatch, and never shipped in the
`.exe`. Build it standalone:

```
cargo build --manifest-path crates/provcheck-mellin/Cargo.toml
cargo test  --manifest-path crates/provcheck-mellin/Cargo.toml
```

## Why it is different from the other detector families

The other families (silentcipher, AudioSeal, WavMark, TrustMark, SynthID-text)
are *blind public detectors*: anyone can run them on any file. This channel is
**secret-keyed**: embedding and detection require the seller's secret and the
work id (`MellinChannel::for_work`), because it exists to individuate copies and
trace leaks, not to label AI output. It therefore does not fit the
`detect(path) -> WatermarkResult` dispatch, and it must never frame an innocent:
a low-confidence read returns an erasure (`None`), never a guessed bit.

## Compatibility contract with Lysn.fm

The keying (HMAC label `lysn-mellin-key/v1`, the splitmix64-style PRNG, and the
keyed ±1 pattern) is bit-identical with `lysn-watermark`. Marks embedded by
Lysn.fm detect here with the same seller secret and work id, and vice versa. Any
change to a constant, label, or derivation must land in both repos together.
