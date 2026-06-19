v0.4.0: AudioSeal full (detect + embed)

The verifier and the kit gain a second neural-watermark family.
silentcipher's 40-bit ASCII triplet payload @ 44.1 kHz coexists
with AudioSeal's 16-bit ECC-protected brand ID @ 16 kHz. Both
detectors run side-by-side on every verify, and the kit's
`watermark` subcommand gets a `--kind` flag to pick which family
to embed.

This is a minor version bump because it adds a new public capability
(`provcheck-kit watermark --kind audioseal`), a new optional report
field (`marked_regions`), and a new enum variant on
`WatermarkBrand` (`UnknownNumeric`). The wire surface stays
backwards-compatible — old JSON parses against the new schema with
defaults filled in.

Wall-clock + memory on a 60-second sample (Windows release build):

  embed:  21.9 s (0.36x real-time)
  detect:  2.6 s (0.04x real-time)
  SDR:    44.1 dB on the marked output
  brand:  recovered correctly across 1-bit-flipped payloads

Why AudioSeal needed ECC, and what we built

AudioSeal's detector reports ~6 % per-bit error on real music. A
naive 16-bit brand lookup misclassifies most marked content — even
AudioSeal's own decoder sees ~15/16 bits per payload, not 16/16.

The fix: the 16-bit on-wire payload carries **three repeated
copies of a 5-bit brand ID plus one reserved bit**. The decoder
takes a bit-wise majority vote across the three copies; a single
bit flip is fully corrected, two-bit flips are mostly handled.
Empirically, real AudioSeal-marked content now decodes to the
right brand on every fixture we've tested.

The registry doc (`docs/brand-registry.md`) is the source of truth
for the brand IDs:

  0x01 = doomscroll.fm
  0x02 = rAIdio.bot
  0x03 = vAIdeo.bot

WavMark (which lands in v0.4.1) reuses the same registry by
encoding the lower 16 bits identically and reserving the upper 16
bits for per-family metadata.

What's actually new

- New `provcheck-audioseal` modules: `audio`, `detect`, `encode`,
  `model`, `brand`, `registry`. Each mirrors the structural shape
  of `provcheck-watermark`'s equivalents (audio decode → tract
  ONNX inference → bit decode → brand lookup → result). About
  1000 lines of focused Rust.

- Two new ONNX files embedded into the library via
  `include_bytes!`: `audioseal-detector.onnx` (33 MB) and
  `audioseal-generator.onnx` (56 MB). Exported by
  `scripts/export-audioseal.py` from Meta's MIT-licensed
  checkpoint. Fixed input shape (160_000 samples = 10 seconds at
  16 kHz) because tract 0.21 can't resolve the symbolic Pad
  expressions PyTorch emits for dynamic-length SEANet.

- New `kit watermark --kind audioseal` flag. Default stays
  silentcipher for backwards compatibility. Per-family flags:
    silentcipher: --payload <hex>  --sdr-db <db>
    audioseal:    --brand-id <id>  --alpha <strength>

- New `marked_regions` field on `WatermarkResult`:
  `Option<Vec<(f32, f32)>>` listing time-spans where the
  watermark is detected. AudioSeal populates this from
  per-sample presence probability; silentcipher leaves it as
  `None`. Renderers and JSON consumers see it iff present.

- New `UnknownNumeric { id: u16 }` variant on `WatermarkBrand`
  for short-payload detectors with unrecognised brand IDs.

- New `docs/brand-registry.md` describing the registry shape, the
  ECC layout, and the procedure for adding new brands.

- New scripts: `scripts/export-audioseal.py` (one-shot ONNX
  export), `scripts/audioseal-roundtrip-fixture.py` (generates
  test fixtures with controlled brand IDs).

- New examples: `tract_probe.rs` (verifies tract loads both
  ONNXes), `audioseal_detect_probe.rs` (end-to-end detect),
  `audioseal_embed_roundtrip.rs` (full embed → detect verify).

Architecture survey — what AudioSeal actually is

AudioSeal is fully convolutional, time-domain (NO STFT), trained at
16 kHz. SEANet encoder downsamples by 320× then runs through a
2-layer LSTM bottleneck; decoder mirrors. The detector uses
`SEANetEncoderKeepDimension` (encoder + ConvTranspose1d that
restores sample length) plus a final `Conv1d(32, 2 + 16, 1)` that
emits per-sample (`present_softmax`, `bit_logits`).

Empirical chunk-boundary check during survey (see the lib.rs
docstring): per-sample presence drifts by ~0.001 at chunk
boundaries vs interior 0.00002 — negligible for the detector
because message recovery averages across the whole file. On the
generator side the boundary L∞ is 0.044 (~ -27 dB), which we
smear with a 25 ms linear crossfade at every chunk boundary.

Binary size impact

provcheck.exe: +33 MB (detector ONNX)
provcheck-kit.exe: +89 MB (both ONNXes, since kit can sign + verify)

Sound rationale per the design discussion: detectors run in the
verifier; only the kit needs the generator. We could split via
cargo features but defer that to a future cycle — keeping the
build matrix simple ships v0.4.0 sooner.

Tests

29 watermark unit tests + 6 integration (silentcipher path unchanged).
33 audioseal unit tests (+33 new in registry, brand, detect, encode).
27 kit unit tests (+3 for the kind/brand-id parsing).
All workspace tests green; rustdoc compiles clean.

Wire format

`Report` JSON gains the optional `marked_regions` field on each
`WatermarkResult`. Old JSON parses against the new schema with
`marked_regions` defaulting to `None`. New JSON produced by v0.4.0
verifiers may include `marked_regions` for AudioSeal hits.

`WatermarkBrand` gains the `UnknownNumeric` variant. Old serde
deserializers that strictly enforce the enum membership will fail
on this variant; standard serde behaviour reports the variant
verbatim.

silentcipher's payload + brand encoding is unchanged.

Container update for downstream consumers

  ARG PROVCHECK_VERSION=v0.4.0

Doomscroll.fm specifically:

  # silentcipher (existing v0.3.x flow — unchanged)
  provcheck-kit watermark --kind silentcipher mixed.mp3 -o mixed-sc.wav

  # OR audioseal (new in v0.4.0)
  provcheck-kit watermark --kind audioseal --brand-id 1 mixed.mp3 -o mixed-as.wav

  # OR both — embed silentcipher first then audioseal on the WAV
  # (the two families are independent and don't interfere).

  provcheck mixed-as.wav  # reports both families if both are present

What's NOT in v0.4.0

- **WavMark**: same architecture work as AudioSeal but different
  parameters; will ship as v0.4.1 once we run through the same
  ONNX export + Rust pipeline build.
- **GUI display of `marked_regions`**: currently only the CLI
  surfaces the spans. GUI rendering lands in v0.4.2 alongside
  general v0.4.x polish.
- **Cargo-features split** for the binary size: deferred. The
  +33 MB / +89 MB hit is OK per the design discussion ("150mb is
  fine for this, this is a pretty necessary tool").
