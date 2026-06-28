# v0.7.0 phase 7-pre — Primitives audit + feature-completeness pass

Audit pass across every `provcheck-*` crate's public API surface,
performed before the v0.7.0 multimodal expansion phases (7a-7g)
land any new crates. The new modality crates inherit the audited
shape, so the primitives need to be coherent FIRST.

Direction from the project owner is on file: **FC > small**. It
is OK to grow the public surface area if completeness requires
it. The kit binary's "single 70 MB" property stays load-bearing;
the LIBRARY public surface area can grow to whatever feature-
completeness requires.

## Audit method

For every crate under `crates/`:

1. Snapshot every `pub fn`, `pub struct`, `pub enum`, `pub const`,
   `pub trait`, `pub type` by direct grep.
2. Cross-compare audio-watermark families (silentcipher,
   audioseal, wavmark) for shape consistency.
3. Identify primitives the kit reaches into via internal access
   that should be library-level instead.
4. Identify composite-operation gaps (`embed_and_sign`,
   `detect_and_classify`, `embed_and_verify`).
5. Identify error-variant coverage that surfaces opaque strings
   where a typed enum belongs.
6. Decide the trait-boundary question for v0.7 multimodal.

## Cross-crate parity matrix — audio watermark families

| Operation | provcheck-watermark (silentcipher) | provcheck-audioseal | provcheck-wavmark |
|---|---|---|---|
| `detect(path: &Path) -> Result<WatermarkResult, Error>` | ✓ | ✓ | ✓ |
| `decode_to_mono_*(path)` | ✓ (44k1) | ✓ (16k) | ✓ (16k) |
| `decode_to_stereo_*(path) -> StereoDecoded` | ✓ | ✓ | **✗** |
| `embed(&[f32], payload, ...) -> Result<Vec<f32>, EncodeError>` | ✓ | ✓ | ✓ |
| `embed_brand(&[f32], brand_id, ...)` | ✗ (uses `embed` with payload) | ✓ | ✗ (uses `embed` with brand_id_5bit) |
| `embed_stereo(left, right, payload, ...) -> Result<(L, R), EncodeError>` | ✓ | ✓ | **✗** |
| `embed_with_config(..., config: EmbedConfig)` | ✓ | **✗** | **✗** |
| `embed_stereo_with_config(...)` | ✓ | **✗** | **✗** |
| `embed_streaming_with_config(...)` | ✓ | **✗** | n/a (no chunked embed in wavmark) |
| `parse_brand(payload) -> Option<WatermarkBrand>` | ✓ (5-byte) | ✓ (2-byte) | ✓ (2-byte) |
| Public brand constants (`BRAND_DOOMSCROLL`, `BRAND_RAIDIO`, `BRAND_VAIDEO`) | **✗** | ✓ | ✓ |
| Public confidence thresholds (`CONFIDENCE_DETECTED_THRESHOLD`, `CONFIDENCE_DEGRADED_THRESHOLD`) | ✓ | **✗** | **✗** |
| `StereoDecoded` struct | ✓ | ✓ | **✗** |

**Asymmetries worth closing in 7-pre:**

1. **`provcheck-wavmark` is missing stereo support entirely.**
   No `decode_to_stereo_16k`, no `StereoDecoded`, no
   `embed_stereo`. The kit CLI's `--channels` flag can route a
   stereo input to wavmark today only by downmixing to mono
   first, which loses the L/R independence the other two
   families preserve. Add the three missing surfaces.

2. **`provcheck-audioseal` and `provcheck-wavmark` are missing
   `*_with_config`.** `EmbedConfig::max_parallel_chunks` is
   silentcipher-specific today (audioseal and wavmark are not
   chunk-parallel internally), but the kit's
   `--memory-budget` flag still routes through audioseal /
   wavmark for the other families. The flag is silently ignored
   in those code paths. Either:
   a. Add no-op `embed_with_config` stubs to audioseal + wavmark
      that accept and ignore the config, OR
   b. Document loudly in the kit that `--memory-budget` is
      silentcipher-only.

   Option (a) is more honest — keeps the kit dispatch shape
   uniform — and costs ~20 lines of wrapper code per crate.

3. **`provcheck-watermark` does not expose brand constants.**
   The 5-byte silentcipher payload format uses ASCII triplets
   (`b"DFM\x01\x00"`, `b"RAI\x01\x00"`, `b"VID\x01\x00"`) rather
   than a 5-bit id, so the constants would be `&[u8; 5]` arrays
   rather than `u8`. Add `PAYLOAD_DOOMSCROLL`, `PAYLOAD_RAIDIO`,
   `PAYLOAD_VAIDEO` to provcheck-watermark for shape parity. Kit
   already hard-codes these in `provcheck-kit/src/commands/mod.rs`.

4. **Confidence thresholds live only in `provcheck-watermark`.**
   `CONFIDENCE_DETECTED_THRESHOLD = 0.70` and
   `CONFIDENCE_DEGRADED_THRESHOLD = 0.50` are watermark-side
   semantics that audioseal and wavmark should inherit, not
   re-derive. Promote to `provcheck::confidence` (the verifier
   crate) since they describe report-level classification, not
   model-specific behaviour.

## Primitives the kit reaches into that should be library-level

The kit's `provcheck-kit/src/commands/mod.rs` hard-codes shape
that belongs in the libraries:

- **Payload literals** for the three brand triplets
  (`b"DFM\x01\x00"` etc.) live in the kit's CLI parser. Promote
  to `provcheck-watermark::brand` (companion to `parse_brand`).
- **`MemoryBudget` enum** in the kit duplicates configuration
  shape that `EmbedConfig` could carry. Today's `MemoryBudget`
  maps `default` / `low` / `streaming` to
  `max_parallel_chunks` + `is_streaming()`. After 7-pre, this
  belongs as a single `EmbedStrategy` enum on
  `provcheck-watermark::encode::EmbedConfig` so external callers
  (downstream Rust crates, the future serve worker's schema) can
  reuse the same enum without re-defining it.

## Composite operations missing across all three families

The kit shells out three separate calls today: `kit watermark`,
`kit sign`, `kit publish`. Each is a discrete CLI invocation
with its own process startup. For Rust callers, the composite
operations should exist as library primitives:

| Primitive | Wraps | Lives in |
|---|---|---|
| `embed_and_sign(asset, payload, identity)` | watermark + sign | new crate `provcheck-pipeline` OR top-level on `provcheck-kit` library surface |
| `detect_and_classify(path)` | verify + all detect family runs | `provcheck` (the verifier crate) |
| `embed_and_verify(asset, payload)` | embed + detect-after-embed self-test | `provcheck-watermark` (mirrors `--verify-after-embed`) |
| `publish_pipeline(asset, payload, identity, action)` | embed + sign + atproto record | foundation for v0.7.0 phase 7g `kit publish` |

`embed_and_verify` is the smallest and should land first; it
mirrors what the kit's `--verify-after-embed` flag already does
inside the kit's command handler. Promoting it to the library
gives external callers the same safety without re-implementing.

`publish_pipeline` is the foundation for 7g (unified
`kit publish`); land it as a primitive here so 7g is plumbing,
not new logic.

## Error variant coverage

Each crate has its own `Error` enum with consistent shape:
`Audio(AudioError) | Model(ModelError) | Encode(EncodeError) |
...`. Three asymmetries:

1. **`provcheck-publish::Error` does NOT wrap `SessionError` or
   `RecordsError` uniformly.** Today the publish entry point
   returns `Result<_, Error>` but internal calls return
   `SessionError` or `RecordsError`. The conversion goes through
   `?` with manual `From` impls in places. Add the `From` impls
   uniformly so callers can use `?` everywhere without thinking.

2. **`provcheck-sign::SignError` surfaces some failures as
   `Other(String)`.** Specifically the case where c2pa-rs returns
   a wrapped error during builder construction. Promote to typed
   variants (`SignError::C2paBuilder(...)`,
   `SignError::C2paClaim(...)`) so retry policy and operator
   error messages can distinguish them.

3. **`provcheck-platform::resolve_handle` returns `Result<String,
   String>` — typed Err belongs.** Same for `resolve_pds_endpoint`.
   These predate the rest of the crate's error discipline and
   should get their own `ResolveError` enum.

## Send / Sync / async consistency

| Crate | Detect path | Embed path | Sign / publish path |
|---|---|---|---|
| `provcheck-watermark` | sync, internally rayon | sync, internally rayon | n/a |
| `provcheck-audioseal` | sync, internally rayon | sync | n/a |
| `provcheck-wavmark` | sync, internally rayon | sync | n/a |
| `provcheck-sign` | n/a | n/a | sync |
| `provcheck-publish` | n/a | n/a | **async (tokio)** |
| `provcheck-kit` | dispatches sync to spawn_blocking | dispatches sync to spawn_blocking | async (tokio) |

Send / Sync stays implicit today and works because tract's
runnable model is `Send + Sync` behind `&`. The kit pattern of
`tokio::task::spawn_blocking` to call the sync detect / embed
from an async context is the right shape and should be
documented as the canonical bridge.

**Action:** add a `Send + Sync` bound assertion test in each
crate's `tests/api_shape.rs` so future refactors that
accidentally break the bound (e.g., introducing an `Rc`) get
caught at test time rather than at integration time. ~10 lines
per crate.

## Streaming primitive promotion from v0.6.0 P3

Phase 3a/3b shipped four primitives that are now public on
`provcheck-watermark`:

- `compute_n_frames(len)` — exposed for external callers sizing
  their own STFT pipelines.
- `forward_stft_chunk(waveform, n_samples_input, t_start,
  chunk_t)` — per-chunk forward STFT without materialising the
  full spectrum.
- `streaming_utterance_norm(waveform)` — global rescale scalar
  via a single streaming pass.
- `IstftStreamer { new, push_frame, finish }` — overlap-add
  iSTFT that accepts frames incrementally.

**Decision: leave these public.** They are useful for any
downstream caller building a custom STFT-shaped pipeline (which
is what every v0.7 multimodal family is), and the cost of
exposing them is one round of API stability commitment per
release.

audioseal and wavmark do NOT have streaming primitives today
because their internal architecture does not need them (the
models are small enough that the chunk-fused materialised path
fits in cheap memory). No action.

## Trait-boundary decision for v0.7 multimodal

Two options for v0.7's new modality crates
(`provcheck-image`, eventually `provcheck-video`,
`provcheck-text`):

**Option A: one crate per family, no shared trait.** Current
shape, extended. Each crate exposes its own `detect`, `embed`,
`embed_with_config`. Results funnel into `Report.watermarks` as
a tagged-union `WatermarkKind` (already a Vec, already
extensible). Composition lives in the verifier and kit code.

**Option B: shared `WatermarkFamily` trait.** Each crate
implements a trait like:

```rust
pub trait WatermarkFamily {
    type Payload;
    type Config;
    type Error;
    fn detect(path: &Path) -> Result<WatermarkResult, Self::Error>;
    fn embed(input: &[u8], payload: Self::Payload, config: Self::Config) -> Result<Vec<u8>, Self::Error>;
    fn modality() -> Modality;
}
```

The verifier could iterate `&dyn WatermarkFamily` for batch
detection.

**Recommendation: Option A. Stay disjoint.**

Reasoning:

- The three audio families have IDENTICAL signatures only in the
  obvious places (`detect(path)`, `embed(slice, payload)`). The
  payloads, configs, and errors are GENUINELY different: 5-byte
  ASCII triplet for silentcipher, 2-byte ECC for audioseal,
  4-byte for wavmark. A generic trait would force them through
  the same type erasure (`Box<dyn Any>`) which costs ergonomics
  without buying anything.
- v0.9's `Report.ai_classifier` is a SIBLING to
  `Report.watermarks`, not a watermark variant. A
  `WatermarkFamily` trait spanning it would conflate
  "this content was marked at generation time" with "this
  content looks AI-generated based on statistical features" —
  two semantically different claims.
- The image and video crates v0.7 will scaffold can borrow shape
  from the audio crates without inheriting a trait; the
  `WatermarkKind` enum in `provcheck` already tracks family
  identity at the report level, which is the only place the
  generic dispatch matters.
- Easy to add the trait later if a fifth family lands and the
  pattern is genuinely shared. Hard to remove it once added.

**Action:** document this decision in the audit doc (this doc),
no code change. The 7a image-survey phase can scaffold
`provcheck-image` with the same shape as the audio crates.

## Forward-compat for v0.9 / v1.0

Per the v0.7 roadmap's "Looking past v0.7" section, `Report` will
gain a sibling `ai_classifier` field in v0.9. The 7-pre audit's
trait-boundary decision (Option A above) already preserves this
because the trait is not added — watermark families stay in
`watermarks: Vec<WatermarkResult>` and the AI classifier lives in
a NEW field.

`Report` schema shape for v0.9 (sketch, not for landing in v0.7):

```rust
pub struct Report {
    // ... existing fields ...
    pub watermarks: Vec<WatermarkResult>,         // existing — Vec since v0.4.0
    pub ai_classifier: Option<AiClassifierResult>, // NEW in v0.9
}
```

The 7-pre audit explicitly does NOT add the field today
(empty-stub fields ship optimism, not contracts), but the trait
decision keeps the door open.

## Fix-in-this-release vs defer

| # | Item | Action | Effort | Release |
|---|---|---|---|---|
| 1 | `provcheck-wavmark` missing stereo (`decode_to_stereo_16k`, `StereoDecoded`, `embed_stereo`) | Add | 1-2 days | **v0.7 (this audit)** |
| 2 | `audioseal` + `wavmark` missing `embed_with_config` stubs | Add no-op wrappers accepting `EmbedConfig` | half a day | **v0.7 (this audit)** |
| 3 | `provcheck-watermark` missing public brand-payload constants | Add `PAYLOAD_DOOMSCROLL/RAIDIO/VAIDEO` | 1 hour | **v0.7 (this audit)** |
| 4 | Confidence thresholds promoted from `provcheck-watermark` to `provcheck::confidence` | Move + re-export | half a day | **v0.7 (this audit)** |
| 5 | `embed_and_verify` library primitive | Add to `provcheck-watermark` | 1 day | **v0.7 (this audit)** |
| 6 | `publish_pipeline` library primitive | Add to new `provcheck-pipeline` or top of `provcheck-kit::lib` | 2-3 days | **v0.7 (phase 7g foundation)** |
| 7 | `detect_and_classify` library primitive | Add to `provcheck` | 1 day | v0.7 if room, else v0.8 |
| 8 | `embed_and_sign` library primitive | Add to `provcheck-pipeline` | 1 day | v0.7 (depends on #6) |
| 9 | Promote `MemoryBudget` enum from kit to `provcheck-watermark::encode::EmbedStrategy` | Refactor | 1 day | v0.7 |
| 10 | Send + Sync bound assertion tests in every crate | Add `tests/api_shape.rs` | half a day | v0.7 |
| 11 | `provcheck-publish::Error` uniform `From` impls | Refactor | half a day | v0.7 |
| 12 | `provcheck-sign::SignError::Other(String)` → typed variants | Refactor | 1 day | v0.8 (cosmetic) |
| 13 | `provcheck-platform::resolve_handle` Result<String, String> → typed error | Refactor | half a day | v0.8 (cosmetic) |
| 14 | `WatermarkFamily` trait | Decided AGAINST | 0 | n/a |
| 15 | `Report.ai_classifier` field | Decided FOR but in v0.9 | 0 (here) | v0.9 |

**Total v0.7 fix-in-this-release effort: about 8-10 days.** All
the items above can land as their own commits in an "audit
series" between 7-pre and 7a. The image-survey phase (7a) starts
on the cleaned-up shape.

## Acceptance for 7-pre

- [x] This document lands at `docs/v0.7.0-roadmap/primitives-audit.md`.
- [ ] Items #1-#11 land as discrete commits in an audit series
      (each commit titled `v0.7 7-pre N/M: <item>` for tracking).
- [ ] `cargo test --release --workspace` stays green throughout
      the series.
- [ ] No breaking changes to the existing public API surface —
      the audit only ADDS primitives where they are missing or
      RE-EXPORTS them to a more honest location, it does NOT
      remove or restructure existing ones. Breaking changes
      surface as v0.8 candidates instead.
- [ ] Phase 7a (image survey) inherits the cleaned shape: the
      new `provcheck-image` crate scaffolds with `detect`,
      `embed`, `embed_with_config`, `decode_to_*`,
      `StereoDecoded`-equivalent, public family constants from
      day one rather than retrofitting.

## Related

- v0.7.0 roadmap parent: [`./README.md`](./README.md).
- Watermark license policy (gates every family added in 7a-7d):
  [`../../WATERMARK_LICENSE_POLICY.md`](../../WATERMARK_LICENSE_POLICY.md).
- v0.6.0 P3 streaming primitives this audit promoted: see the
  IstftStreamer + forward_stft_chunk additions in
  `crates/provcheck-watermark/src/stft.rs`.
