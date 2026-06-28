# v0.7.0 roadmap — multimodal expansion + cross-vendor detection

This directory is the **planning record** for v0.7.0, the
multimodal-expansion release. v0.6.0 closed the audio-only
throughput story (chunk-parallel embed, serve worker, streaming
embed design, CUDA backend design). v0.7.0 closes the
audio-only-modality story.

The work in this doc is scoped **clean-room**: feature gaps we
want to close, in our own terms, against FOSS-only model
candidates per `WATERMARK_LICENSE_POLICY.md`. No reverse
engineering of any other vendor's pipeline.

## Context

Two signals push toward multimodal expansion in mid-2026:

1. **Regulatory.** The EU AI Act Article 50 watermarking mandate
   takes effect 2026-08-02. The U.S. NO FAKES Act cleared Senate
   Judiciary unanimously on 2026-06-18 and references provenance
   tracking + watermark embedding as the trust mechanism. Neither
   text mandates a specific watermark technology, but both
   reference the multi-modality reality (voice, likeness, image).
2. **Competitive.** Commercial multimodal watermarkers ship four-
   modality coverage (audio, image, video, text), C2PA-bundled,
   behind hosted APIs. provcheck v0.6.0 ships audio-only, local-
   first, with C2PA as a separate kit step. The local-first +
   open-source positioning stays load-bearing; the multimodal gap
   does not.

v0.7.0 closes the modality gap without compromising the local-
first, no-API, single-binary stance. All four phases below ship
as Rust crates that compose into the existing kit + GUI; no
hosted service appears in the v0.7.0 surface.

## Goals

- **Image watermark embed + detect** ships in `provcheck-image`
  (new sibling crate to `provcheck-watermark`). Targets at least
  one FOSS-licensed model family with permissive code AND model
  weights.
- **Video watermark embed + detect** ships in `provcheck-video`.
  Likely composes image watermarking applied per frame plus
  temporal robustness adapter; concrete model family TBD.
- **Cross-vendor detection readers.** Detect at least one
  non-provcheck audio mark family (Google's SynthID-audio if
  ever opened; otherwise note the gap honestly). On the image
  side, support reading SynthID-image marks if the library opens
  during the v0.7.0 window.
- **Codec-robust silentcipher checkpoint** for audio. Adversarial
  fine-tune against AAC and the LAME / libmp3lame psychoacoustic
  paths so issue #23's "AAC unsupported for silentcipher" story
  inverts. Same payload format, same `provcheck.exe` detector,
  drop-in replacement at the model layer.
- **Unified `kit publish`** that fuses the
  watermark + sign + (optional) atproto record in one CLI
  invocation, matching the experience operators expect from a
  hosted-API competitor without becoming one.

## Phase-by-phase plan

### Phase 7-pre — Primitives audit + feature-completeness pass

**Effort:** 3-5 days.

**Why first:** the multimodal expansion phases (7a-7d) add new
crates that should inherit a coherent public API shape from the
existing audio crates. Auditing the primitives before scaffolding
new ones means the new crates land with the right shape instead
of inheriting churn or drift. Tracked as Task #147.

**Scope:**

- Cross-crate API parity. Audit whether `provcheck-watermark`'s
  `embed_stereo` / `embed_with_config` / `embed_stereo_with_config`
  pattern has matching siblings on `provcheck-audioseal` and
  `provcheck-wavmark`. Where the shape differs without a real
  reason, add the missing primitive.
- Public exposure. Walk every `pub fn` in every crate. Any helper
  the kit reaches into via internal access that should be
  library-level instead. Any primitive marked `pub(crate)` that
  external consumers (rAIdio.bot, doomscroll integrations) would
  benefit from. Promote.
- Composite operations. Add ergonomic combinators for the common
  composite paths: `embed_and_sign(asset, payload, identity)`,
  `detect_and_classify(path)`, `embed_and_verify(asset, payload)`.
  Each is a thin wrapper but landing them as primitives means
  external callers do not have to reinvent the orchestration.
- Error variant coverage. Anywhere a crate currently surfaces an
  opaque string error for a known structural failure, promote the
  variant to typed. The detect path's `decoder error: %s` is the
  prime example.
- Send/Sync/async consistency. Detect is sync; if the verifier
  ever spawns N detector calls in parallel (it does today via
  rayon), the public API should make the Send + Sync story
  explicit, not implicit. Same for the sign + publish path which
  is async via tokio.
- Streaming variants. Phase 3a/3b shipped `effective_sample` and
  a streaming overlap-add iSTFT as internal primitives. Decide
  whether to expose either at the public boundary so external
  callers can reuse them (e.g. for their own STFT-shaped
  pipelines).
- Trait boundaries for the multimodal expansion. Sketch the
  shape of a generic `WatermarkFamily` trait, OR commit to the
  current shape of "one crate per family, public detect/embed
  functions, results funnelled into `Report.watermarks`". Either
  is fine but the decision should be made before phase 7a
  scaffolds `provcheck-image`.

**Acceptance:**

- `docs/v0.7.0-roadmap/primitives-audit.md` lands enumerating
  every gap found, with a fix-in-this-release vs defer column.
- Each fix-in-this-release row lands as its own commit (so the
  history reads as a primitives-audit series rather than a single
  bundled refactor).
- `cargo test --release --workspace` stays green throughout.
- No breaking changes to the existing public API surface — the
  audit ADDS primitives where they are missing, it does not
  remove or restructure existing ones. Breaking changes get
  flagged as v0.8.0 candidates instead.

**Direction from project owner:** FC > small. It is OK to grow
the public surface area if completeness requires it. The
"single 70 MB binary" property stays load-bearing for the kit,
but the LIBRARY surface area can grow to whatever feature-
completeness requires.

### Phase 7a — Image watermark library survey + crate scaffold

**Effort:** 1 week (mostly survey, doc, license review).

**FOSS candidates worth scoring** (must satisfy
`WATERMARK_LICENSE_POLICY.md`: both code AND model weights
permissively licensed):

| Library | Code license | Weights license (claimed) | Notes |
|---|---|---|---|
| **TrustMark** (Adobe) | Apache-2.0 | Apache-2.0 (per Adobe's release) | Solid candidate; produced by Adobe's CAI team; explicitly designed for C2PA integration. Score first. |
| **StegaStamp** (Tancik et al, UC Berkeley) | MIT | Research-only on the original release | Needs FOSS retraining or weights-license clarification before adoption. |
| **HiDDeN** (Zhu et al, Stanford) | MIT (code) | Research code; weights situation unclear | Likely needs retraining from scratch. |
| **Stable Signature** (Meta / FAIR) | Possibly MIT, needs verify | Check against AudioSeal precedent (Meta did relicense AudioSeal to MIT, but per-model verification required) | Promising if license cleared. |
| **DCT-DWT classic methods** | varies | weights-free (algorithmic) | Cheap fallback. Lower robustness but no model-weights gating. |

Phase 7a output:

- `crates/provcheck-image/` scaffolded with the same shape as
  `provcheck-watermark`: `lib.rs` for the public `detect(path)`
  entry, `audio.rs`-equivalent for the image decode path (probably
  `image.rs` using the `image` crate), `embed.rs`, `model.rs`,
  `brand.rs`, `registry.rs`, `models/` for the ONNX/weights blob.
- A `WATERMARK_LICENSE_POLICY.md` update row per candidate scored.
- The doc names the chosen first family and explains why.

**Acceptance:**
- Scaffold compiles, public `detect` returns `WatermarkResult`
  with `status: NotDetected` (stub) for any input.
- License policy doc updated.
- No actual inference yet; that lands in 7b.

### Phase 7b — Image watermark detect

**Effort:** 1-2 weeks.

Wire the chosen family's ONNX (or pure-Rust equivalent) into
`provcheck-image::detect`. Same lazy-loaded `OnceLock` pattern
the audio crate uses. Surface the result in `Report.watermarks`
as a sibling to silentcipher / audioseal / wavmark entries; the
existing report-rendering code is already a Vec, so no schema
churn.

GUI integration: the verify pane's per-watermark row stays as-is;
image marks show up automatically. The GUI's existing
audio-input-only sniff (`looks_like_audio`) needs an
`looks_like_image` companion.

**Acceptance:**
- Real-image embed roundtrip test in
  `crates/provcheck-image/tests/integration.rs`. A test fixture
  with a known mark is detected with the expected payload.
- `provcheck path/to/image.png` reports the image-watermark detect
  alongside any audio path that fires (the existing detect path
  short-circuits on extension, so an image input skips the audio
  side cleanly).
- README codec/format matrix updated.

### Phase 7c — Image watermark embed

**Effort:** 1-2 weeks.

Add embed support to the chosen family via `provcheck-image::embed`.
Wire `provcheck-kit watermark --kind image` for the CLI surface.
The kit's existing channel/SDR/alpha flags are audio-specific;
image embed gets a new `--strength` knob analogous to
`--sdr-db`/`--alpha`.

**Acceptance:**
- Embed roundtrip test (embed a payload, write PNG/JPEG, detect,
  recover payload).
- Re-encode survival smoke test (PNG → JPEG quality 75 → detect
  conf >= 0.85) baked into the pre-push gate.

### Phase 7d — Video watermarking

**Effort:** 2-3 weeks.

Video is image applied per frame plus temporal coherence so the
mark survives frame re-encoding and frame drops. Two paths:

1. **Per-frame image mark + temporal voting at detect.** Simple,
   leans on phase 7b/7c. Conf is the per-frame mode-vote.
2. **Spatiotemporal video model.** Higher robustness but a larger
   model and a heavier compute story. Defer unless the per-frame
   approach falls below the 0.85 codec-survival threshold.

Start with (1). Move to (2) only if needed.

**Acceptance:**
- Embed a payload into an MP4, ffmpeg-transcode to h264 at CRF 23,
  detect at conf >= 0.85.
- Survives ffmpeg trim + concat (the analog of the silentcipher
  long-form OOM scenario for video).

### Phase 7e — SynthID-text reader

**Effort:** 1 week.

Google released `synthid-text` (Apache-2.0) for detecting text
watermarks they embed during LLM generation. Add as
`crates/provcheck-synthid-text/`. Same architecture as the audio
sibling crates: lazy-loaded model, public `detect`, surfaces in
`Report.watermarks`. SynthID-image and SynthID-audio remain
closed; document the gap honestly.

**Acceptance:**
- `provcheck path/to/llm-output.txt` reports synthid-text detect
  status alongside an empty audio/image side.

### Phase 7f — Codec-robust silentcipher checkpoint

**Effort:** 2-3 weeks of model retraining work + 1 week of
integration.

Public issue #23 cleared a real lesson: silentcipher at the
training-default SDR of 47 dB does not survive AAC, and even at
SDR 30 the mark sits at conf 0.92 on a clean WAV. The model was
trained without explicit AAC adversarial samples; that is fixable
without changing our public API.

Approach: take the silentcipher 44.1k checkpoint (Apache-2.0 model
weights per the original release), fine-tune against a mix of
clean PCM + AAC re-encoded targets + libmp3lame re-encoded
targets. The model architecture, payload, and inference path
stay identical; only the weights change. Drop-in replacement at
`crates/provcheck-watermark/models/silentcipher-encoder.onnx`.

The work itself is GPU fine-tuning, not Rust. Likely needs an
external collaborator with a model-training pipeline. Goal: same
training set silentcipher used, plus an adversarial loss term
that rewards detection after a randomised codec pass.

**Acceptance:**
- Same parity sweep harness as v0.5.2 shows post-AAC-192k detect
  conf >= 0.85 at SDR 30 dB.
- Pristine PCM detect conf does not regress below 0.95 at SDR 30.

### Phase 7g — Unified `kit publish`

**Effort:** 1 week.

Operator UX. Today, doomscroll's pipeline runs three CLI calls
per episode: `kit watermark`, then `kit sign`, then `kit publish`
(for the atproto record). v0.7.0 ships `kit publish-pipeline`
(name TBD) that does all three in one call with a shared input
file and a single config block.

This is pure plumbing. No new crypto, no new model, no new
storage. Reuses every function the kit already exposes.

**Acceptance:**
- `kit publish-pipeline in.mp3 -o out.wav --kind silentcipher` runs
  the watermark, signs the output, and publishes if `kit login`
  has a session. Each sub-step's existing flags are accepted via
  per-step prefix (e.g. `--sign-action published`).
- One-shot smoke roundtrip from input to atproto record visible
  via `kit list`.

## Sequencing

```
7-pre primitives audit ─┬─▶ 7a image survey  ─┬─▶ 7b image detect ─▶ 7c image embed ─┬─▶ 7d video
                        │                     │                                       │
                        ├─▶ 7e synthid-text   └─▶ 7f codec-robust audio (parallel)    │
                        │                                                              │
                        └─▶ 7g unified kit publish ◀────────────────────────────────────┘
```

- 7-pre primitives audit lands first; everything depends on its
  output (the audited public API surface). New crates in 7a
  inherit the cleaned-up shape rather than the pre-audit churn.
- 7a, 7e, 7f can start in parallel after 7-pre (different code
  paths, different skill sets).
- 7b depends on 7a's family choice.
- 7c depends on 7b's pipeline shape being right.
- 7d depends on 7c (per-frame approach reuses the image embed).
- 7g is the integration step that lights everything up; depends
  on 7c being callable from the kit and on the 7-pre audit's
  composite-operation primitives (specifically `embed_and_sign`,
  the foundation for `kit publish`).

Total wall clock if pipelined with a second pair of hands:
roughly 8-10 weeks. Single-maintainer serial: roughly 12-14
weeks.

## Out of scope for v0.7.0

- **Hosted API / SaaS.** Goes against the local-first positioning.
  If demand surfaces, `provcheck-kit serve` (v0.6.0 P2) plus the
  operator's own ingress is the answer.
- **SOC2 / GDPR / HIPAA certifications.** We are a builder tool,
  not a SaaS vendor. The compliance question for our users is
  "did the file leave my machine" and the answer is no by
  construction.
- **Text watermark embed.** Deferred to "Future-someday" below.
- **Adversarial-trained AudioSeal / WavMark checkpoints.** Same
  approach as 7g would work but the two families already survive
  AAC at alpha 3.0 / default settings respectively; the marginal
  value of retraining them is lower than silentcipher's.
- **SynthID-image / SynthID-audio readers.** Closed-source at
  the time of writing. Doc this as a known gap; add the readers
  if the upstream libraries open.
- **TrustMark embed if Adobe's model weights turn out to be
  research-only.** License policy gates apply. Skip the family
  rather than break the rule.

## Reviewer checklist for v0.7.0 PRs

When each phase lands, the reviewer should walk:

- [ ] License policy gate: every model family added has both code
      AND weights under MIT/Apache-2.0/BSD/ISC/CC0. Row added to
      `WATERMARK_LICENSE_POLICY.md`.
- [ ] Public `detect()` API surface of every new crate matches the
      audio crates' shape: `Result<WatermarkResult, Error>` with
      the same status/confidence/payload/brand semantics.
- [ ] The new family's brand registry uses the existing shared
      numeric registry (`docs/brand-registry.md`).
- [ ] GUI verify pane surfaces the new mark family automatically
      via the existing Vec-of-watermarks rendering.
- [ ] Pre-push regression gate gets a new survival smoke for the
      new family (image: PNG → JPEG; video: MP4 → h264 transcode;
      text: passthrough).
- [ ] Parity sweep extended to cover the new family vs whichever
      upstream Python reference exists.
- [ ] Codec-survival doc updated.

## Risks + open questions

1. **Image model weights license uncertainty.** TrustMark, Stable
   Signature, StegaStamp all have ambiguous weights-license
   situations on first read. Phase 7a's survey week is real
   research, not a checkbox.
2. **Per-frame video adequacy.** If the per-frame mode-vote does
   not survive ffmpeg transcode at CRF 23, we have to climb the
   model complexity ladder. Budget room for that.
3. **Codec-robust silentcipher retraining external dependency.**
   Phase 7g needs someone with a GPU training pipeline and access
   to silentcipher's original training set (VCTK + augmentation).
   That is a real procurement problem, not a coding problem.
4. **SynthID openness.** SynthID-text is open. SynthID-image and
   SynthID-audio are not, at the time of writing. The
   competitive read is that the gap is real; the engineering read
   is that nothing breaks if they stay closed.

## Composite competitive read

After v0.6.0 (audio throughput) and v0.7.0 (multimodal expansion),
provcheck's positioning vs hosted competitors:

| Capability | provcheck v0.7.0 (planned) | Hosted multimodal vendor (typical) |
|---|---|---|
| Audio watermark embed + detect | ✓ | ✓ |
| Image watermark embed + detect | ✓ | ✓ |
| Video watermark embed + detect | ✓ | ✓ |
| Text watermark detect | ✓ (SynthID) | ✓ |
| Text watermark embed | not in scope | ✓ |
| C2PA bundled in one call | ✓ (kit publish) | ✓ |
| atproto-bound creator identity | ✓ | ✗ |
| Yubikey HSM key custody | ✓ | typically ✗ |
| Local-first (file never leaves machine) | ✓ | ✗ (hosted API) |
| Open source (Apache-2.0) | ✓ | ✗ |
| SOC2 / GDPR / HIPAA certs | ✗ | ✓ |
| Hosted REST API | ✗ | ✓ |
| Cost | free | enterprise SaaS pricing |

The pitch after v0.7.0 stays consistent: every byte stays on the
operator's machine, every model and decoder is auditable Apache-
2.0 source, every signature ties back to the operator's atproto
identity, not a vendor's cert. The multimodal gap closes; the
local-first stance does not.

## Future-someday (post-v0.7.0)

Items intentionally not on the v0.7.0 roadmap but worth keeping
visible so they do not get re-litigated every quarter. These are
not commitments; they are "if the landscape changes, this is what
we'd do."

### FS-1 — Text watermark embed

**Why deferred:** the FOSS text-watermark landscape is thin in
mid-2026. The credible families (Kirchenbauer-style green-list
biasing, Aaronson distribution-shift schemes) require generator-
side coordination at LLM sampling time; provcheck's local-first
detection model does not fit the wire-protocol shape these
schemes need without becoming a hosted SaaS, which we explicitly
do not want to become.

**Revisit when:** either (a) a clean FOSS detector-only text-
watermark family ships with permissive code AND any required
weights, or (b) generator-side embedding becomes a thing we can
do as a library against a local LLM (e.g. llama.cpp + a watermark
layer) without requiring an inference service.

**Scope when it ships:** `provcheck-text` crate sibling to
`provcheck-image`, same public `detect()` shape, registry entries
for the text family's brand-id encoding. Embed surface in the kit
gated behind an `--llm-binding` flag because embedding requires
the upstream generator to cooperate.

### FS-2 — SynthID-image / SynthID-audio readers

**Why deferred:** closed-source at the time of v0.7.0 planning.
SynthID-text was opened by Google in 2024 (Apache-2.0); the image
and audio variants have not been.

**Revisit when:** Google opens either library, OR a clean-room
detector for either variant ships under a permissive license.

### FS-3 — Adversarial-trained AudioSeal / WavMark checkpoints

**Why deferred:** v0.7.0 phase 7f adversarially retrains
silentcipher because that is where the codec-survival gap is
sharpest. AudioSeal at alpha 3.0 already survives AAC; WavMark
already survives default-settings re-encode. The marginal value
of retraining either against codecs is real but small.

**Revisit when:** a production user reports an AAC failure on
AudioSeal or WavMark that isn't fixable with the alpha knob.

### FS-4 — Hosted API / SaaS

**Why deferred:** explicit non-goal of the project. Listed here
only so the question stops getting re-asked. The `kit serve`
worker mode (v0.6.0 P2) plus the operator's own ingress is the
answer for anyone who wants a managed-service shape.

**Revisit when:** never, unless project direction changes.

### FS-5 — SOC2 / GDPR / HIPAA certifications

**Why deferred:** we are not a SaaS vendor. The compliance
question for our users is "did the file leave my machine" and the
answer is no by construction. No certification body has a SKU
for "this CLI binary processes data locally."

**Revisit when:** never, unless project direction changes.

## Looking past v0.7

This roadmap covers v0.7 only. The sequence beyond it is:

- **v0.8.x — refinement.** Polish on what v0.7 ships: ergonomics,
  bug fixes from real-world v0.7 use, primitive cleanup that did
  not make the 7-pre audit cut, doc polish, performance work that
  needs a stable multimodal base. No major new families. Scope
  defined when v0.7 ships and the rough edges show themselves.

- **v0.9.x — staging release for AI content detection.** Adds the
  architectural slots (report schema fields, trait boundaries,
  CLI surface, GUI tab) that v1.0's AI detection add-on plugs
  into. No live classification yet. This is a contracts release;
  the model code and weights land in v1.0. Forward-compat note
  for the 7-pre primitives audit: `Report.ai_classifier` is a
  sibling to `Report.watermarks` rather than a stretched
  watermark variant, so the trait-boundary decision in 7-pre
  should accommodate that shape now.

- **v1.0.0 — full release with AI content detection as a paid DLC
  in the desktop app.** AI content classification, anti-spoofing,
  and deepfake detection ship as a downloadable-content add-on
  through the Tauri app's update channel. NOT bundled in the
  Apache-2.0 CLI binaries. The CLI stays free FOSS; the desktop
  app gains an optional paid layer for the detection capabilities.

This release sequence is a decision, not a survey; do not
re-propose AI content detection in v0.7 or v0.8. The
`WATERMARK_LICENSE_POLICY.md` FOSS-only gate continues to govern
the watermark detector families in the CLI; the v1.0 DLC sits
outside that surface.

## Related

- v0.6.0 roadmap parent: [`../v0.6.0-roadmap/`](../v0.6.0-roadmap/).
- v0.6.0 P3 streaming design: [`../v0.6.0-roadmap/p3-streaming-embed-design.md`](../v0.6.0-roadmap/p3-streaming-embed-design.md).
- v0.6.0 P4 ORT CUDA design: [`../v0.6.0-roadmap/p4-ort-cuda-backend-design.md`](../v0.6.0-roadmap/p4-ort-cuda-backend-design.md).
- Watermark license policy: [`../../WATERMARK_LICENSE_POLICY.md`](../../WATERMARK_LICENSE_POLICY.md) (load-bearing gate for every model family in this doc).
- v0.5.2 codec-survival findings: [`../v0.5.2-codec-survival/`](../v0.5.2-codec-survival/) (the prior art for 7g).
