# MP3 decoder alternatives — fallback plan if STAGE 1 diverges

This document captures the candidate replacements for symphonia's
MP3 path, in case `decode_diff` shows STAGE 1
(`audio_pre_rescale`) diverges from the Python reference past
`TOL_AUDIO` (1e-5).

Background: the Python reference reads the MP3 via `librosa.load`,
which on most systems delegates to `audioread` → `ffmpeg`'s
libavcodec MP3 decoder (the same `mp3float` codec used by every
ffmpeg-based pipeline). Our Rust pipeline uses `symphonia 0.5`'s
clean-room MP3 implementation. Symphonia and ffmpeg should agree
to within MP3 spec compliance (a few LSB in 16-bit space, ≈ 1.5e-5
in f32 [-1, 1]) — but if they don't, we have options.

## Candidates

| Crate | License | Backing | Maturity | Pros | Cons |
|---|---|---|---|---|---|
| **symphonia 0.5** *(current)* | MPL-2.0 | pure Rust | mature | already shipping; pure Rust; covers other formats too | clean-room decoder, may have small numerical differences vs ffmpeg's `mp3float` |
| **minimp3** Rust bindings (e.g. `minimp3` crate or `rust-minimp3`) | CC0 (C lib) + MIT (binding) | C library `minimp3.h` by lieff | mature, very widely used | small (~3kLoC), drop-in, agrees with reference MP3 spec at high precision | C build dependency; cross-compile for 3 OSes; static link CRT story |
| **puremp3** | MIT/Apache-2.0 | pure Rust port of minimp3 | less mature | pure Rust; same algorithm class as minimp3 | port quality unverified; less battle-tested |
| **ffmpeg** via `rsmpeg` / `ffmpeg-the-third` | LGPL or GPL (ffmpeg) + crate's own license | C library | mature | exact bit-for-bit match with Python reference | LGPL/GPL implications for distribution; heavy build; not Rust-native |

Notes:

- **License hard-filter**: per `WATERMARK_LICENSE_POLICY.md`, the
  detector pipeline must compose with Apache-2.0. MPL-2.0 (symphonia)
  is fine — it's file-level copyleft, doesn't infect our crate.
  CC0+MIT (minimp3) is fine. LGPL (ffmpeg) is workable if dynamically
  linked, but ships an extra runtime dep on every OS and complicates
  the GUI bundles. GPL (ffmpeg with `--enable-gpl`) is a hard reject.

- **Reference match priority**: if our goal is bit-exactness with
  Python's `librosa.load`, the order is `ffmpeg > minimp3 > symphonia
  > puremp3`. If our goal is FOSS-clean Rust-native, the order
  reverses.

## Decision tree (once decode_diff runs)

```
STAGE 1 L∞ < 1e-5
    → not the bug; symphonia stays
STAGE 1 L∞ ∈ [1e-5, 1e-3]
    → likely MP3 codec spec-level difference (mp3float vs symphonia)
    → first try: WAV the MP3 via ffmpeg manually, re-run decode_diff
      on the WAV → if STAGE 1 goes to 0, confirms symphonia's MP3
      path is the source
    → fix: swap to `minimp3` for MP3 specifically; keep symphonia
      for the other containers (it covers wav/flac/ogg/aac well)
STAGE 1 L∞ > 1e-3
    → something more structural (rate conversion, channel mixing,
      sample format). Audit symphonia's downmix and rubato's
      resampler before swapping decoders.
```

## What "swap to minimp3" actually looks like

If we go that route:

1. Add `minimp3 = "0.5"` (or whichever rust-binding crate proves
   most maintained at implementation time) to
   `provcheck-watermark/Cargo.toml`'s `[dependencies]`.
2. In `audio.rs::decode_to_mono_44k1`, detect MP3 by extension or
   magic-byte sniff and dispatch to a minimp3 branch; keep
   symphonia for everything else.
3. Mono-mix + 44.1kHz resample stay the same — those steps live
   downstream of the decoder.
4. Update `WATERMARK_LICENSE_POLICY.md` to record minimp3's licence
   (CC0 + binding's MIT).
5. CI matrix: confirm cross-compile works on Linux/macOS/Windows
   with the CRT-static setup in `.cargo/config.toml`.

## What "swap to ffmpeg" would actually look like (last resort)

Ships an extra dep on every OS (≈ 30MB GUI bundle increase via
`ffmpeg-next` static link, less via dynamic). License story is
LGPL — manageable but requires the GUI's third-party-notices to
include ffmpeg's notice file and a written-offer-for-source
clause. We'd only do this if minimp3 also disagrees with Python.

Note: this is the path of last resort because the GUI bundle size
inflation undoes the "small CLI" virtue, and the LGPL paperwork
is friction we'd rather avoid for a CLI that's meant to be easy
to ship.

## Sample precision targets

The watermark per-frame logit is sensitive to ≈ 1 LSB in 16-bit
audio (1.5e-5 in f32 [-1, 1]). decode_diff's `TOL_AUDIO = 1e-5`
is set just below that threshold so that any decoder difference
that would meaningfully shift downstream FFT bins shows up as
DIFF, not OK.
