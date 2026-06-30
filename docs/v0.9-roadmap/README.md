# v0.9 roadmap — AI-detection staging + ecosystem reach

Target release: v0.9. Staging release that lands the architectural
slots for v1.0's paid AI-detection DLC and broadens the FOSS surface
into ComfyUI + streaming deepfake detection.

## Strategic frame

Per [`project_redhat_provenance_market`](../../) in memory: v0.9 is
the staging release that wires up the architectural slots
v1.0 needs, while keeping every newly-added user-facing surface in
the FOSS core (Apache-2.0). The v1.0 paid DLC slots into the
detection-plumbing v0.9 stands up; nothing about v0.9 lives behind
a paywall.

## Phases (target)

### 9a — Detection slot architecture (FOSS plumbing) — SHIPPED across v0.9.71..73

The architectural slot that v1.0's AI-detection DLC will fill.
Pure plumbing in v0.9 — no classifier weights, no detection logic.
What landed:

- ✓ **v0.9.71**: `provcheck-detect` crate (FOSS Apache-2.0,
  `#![forbid(unsafe_code)]`, ships no model weights). Types:
  `DetectionFamily { Audio, Image, Video, Text }`,
  `DetectionStatus { Detected, Degraded, NotDetected,
  NotApplicable, Error }`,
  `DetectionResult { detector, family, status, detected,
  confidence, model_id, version, message }`, `DetectorError
  { ModelNotInstalled, Inference, Io }`. `Detector` trait
  (`Send + Sync`, object-safe so `Vec<Box<dyn Detector>>`
  works). `DetectorRegistry` (the dispatch layer: `register` +
  `run_all`, errors project onto `DetectionResult { status:
  Error, ... }`, never short-circuits).
- ✓ **v0.9.72**: Verifier dispatch wired through
  `provcheck::report::Report::detections: Vec<DetectionResult>`.
  The detectors themselves live in a `DetectorRegistry` the
  caller owns; the report carries the per-detector results.
  Empty for the core `verify_with_options` path; populated by
  callers that register detectors and call `run_all`. Backward-
  compat `serde(default)` so legacy Report JSON parses.
- ✓ **v0.9.73**: CLI surface — `provcheck --detect ai` flag
  parses, constructs `DetectorRegistry::new()`, reads the asset,
  runs `run_all` over the registry, pushes results into
  `report.detections`. The FOSS core registers ZERO detectors, so
  without an operator-supplied detector the flag is a documented
  no-op. The flag exists so operator scripts wired against a
  paid DLC pack or operator-supplied open-source wrapper crate
  can request the detection pass via a stable surface.
- ✓ **Documentation contract**: see
  [`../public-api-stability.md`](../public-api-stability.md) for
  the trait stability matrix and
  [`../semver-policy.md`](../semver-policy.md) for the wire-format
  rules every DLC pack consumes.

### 9b — Streaming deepfake detection (FOSS plumbing; detector models are paid DLC OR operator-supplied open source) — SHIPPED across v0.9.74..75

Per user direction 2026-06-28: "in v9 we want streaming detection
of deepfakes, for voice and video".

- ✓ **v0.9.74 + v0.9.75**: `provcheck-stream-detect` crate (FOSS
  Apache-2.0, `#![forbid(unsafe_code)]`, ships no model weights).
  Note the final name dropped "deepfake" since the trait the
  pipeline holds works for any AI-content detector, not just
  deepfake-specific ones. Audio half (v0.9.74): PCM chunk feeder
  via `AudioStreamingPipeline` + `AudioStreamConfig`
  (sample_rate, window_samples, hop_samples, history_capacity).
  Video half (v0.9.75): frame batch feeder via
  `VideoStreamingPipeline` + `VideoStreamConfig` (window_frames,
  hop_frames, history_capacity) + `VideoFrame` (pts_secs +
  opaque encoded bytes). Length-prefixed frame concatenation
  (big-endian u32 per frame) is the wire format detectors
  receive.
- Rolling-window detection confidence with configurable hop /
  window sizes.
- ⏳ GUI surface for live monitoring (microphone, screen
  capture, RTSP feed input adapters) — deferred to v1.x; the
  library API is the v0.9 deliverable, GUI integration is a
  desktop-app-specific wiring task that sits in front of the
  existing Tauri surface.
- ✓ Library API for callers that want to plug the detector into
  their own transport (Discord bot, broadcaster overlay, etc.) —
  the public crate IS the library API. Operators construct a
  `DetectorRegistry`, register their detector implementation,
  feed `AudioStreamingPipeline::feed` or
  `VideoStreamingPipeline::feed_frame`, and drain
  `WindowedVerdict`s.
- **Detector model arch + weights are NOT shipped by provcheck.**
  v0.9 ships the plumbing + a stub detector that returns "model
  not installed". Concrete detectors plug in via the
  `Detector` trait two ways:

  1. **Commercial paid-DLC detectors** (the high-margin upsell):
     Creative Mayhem ships commercial detector packs as paid DLC
     after v1.0. The first such pack is sourced from the
     doomscroll.fm pipeline and is NOT in this public repo at
     any version. Distribution + activation mechanism is itself
     part of the v1.0 paid surface.
  2. **Operator-supplied open-source detectors**: the `Detector`
     trait is public so an operator can implement it against
     any open-source detector available in the wild (e.g.
     existing FOSS audio-deepfake classifiers from research
     groups). provcheck does NOT ship those FOSS detectors
     either — the operator brings their own weights and
     implements the trait against them. The trait is the
     contract; the model is the operator's choice.

  Do not characterise the deepfake-detection capability as
  "free" or "shipped" anywhere in v1.0 copy. The plumbing is
  free; the detection is bring-your-own (paid DLC OR open-source
  third-party).

### 9c — ComfyUI node (FOSS, wires in v0.9) — SHIPPED across v0.9.0..77 + v0.9.80

Per user direction 2026-06-28: "we want to do a comfyui node
where the user can basically apply the app strings to their
outputs in comfyui and include this in the open source for 1.0.0".

- ✓ `python/comfyui-node/` package — scaffolded in v0.7.0, fully
  wired in v0.9.0 (subprocess call to `provcheck-kit stamp`,
  PNG tensor save / load).
- ✓ v0.9.77: audio variant (`StampAudioNode`) lands. AUDIO dict
  in → temp 16-bit PCM WAV → `provcheck-kit stamp` (auto-routes
  silentcipher) → WAV back → AUDIO dict out. Mono + stereo
  round-trip pinned by tests within int16 precision.
- ✓ v0.9.77: optional `sign: BOOLEAN` input on both nodes.
  Default `False` (watermark only). When `True`, the kit attempts
  C2PA signing with the local identity; sign failure → fail-closed
  passthrough with console warning.
- ✓ v0.9.77: optional `timeout_secs: INT` (5..600, default 120)
  on both nodes for slow-host operators.
- ✓ v0.9.77: GitHub Actions workflow (`comfyui-node.yml`) runs
  pytest matrix on Python 3.10 + 3.12. 22 tests cover wrapper
  failure modes + WAV round-trip.
- ✓ v0.9.80: three example workflow JSON files under
  `python/comfyui-node/workflows/` plus a README explaining how
  to use them. `stamp_image_minimal.json` (LoadImage → Stamp →
  PreviewImage), `stamp_audio_minimal.json` (LoadAudio →
  StampAudio → SaveAudio), `stamp_signed_image.json` (LoadImage
  → Stamp(sign=True) → SaveImage). All target ComfyUI's
  `version: 0.4` workflow schema.
- ✓ Brand-agnostic — works for any creator with their own atproto
  identity + signing key + brand registration. The README's
  `brand_id = 2` default is documented as an ergonomic choice,
  not a normative preference.
- ✓ Apache-2.0 alongside the rest of the FOSS surface.

### 9d — Codec-robust silentcipher checkpoint

Carried forward from v0.7 phase 7f. Requires an external GPU
collaborator with access to silentcipher's training pipeline to
fine-tune the encoder for AAC / Opus / low-bitrate MP3 survival.
Blocked on collaborator availability.

### 9e — Per-asset atproto record schema (deferred decision)

The ComfyUI node design surfaced the question of whether
provcheck wants per-asset atproto records (a Lexicon for
"this asset was stamped at this time by this DID with this
brand and this signature digest"). v0.9 is the natural release
to land this if we decide to.

Default position: NO per-asset record. The C2PA manifest already
carries the cryptographic identity claim + signed asset hash;
the atproto identity record is enough for the verifier to
cross-check. Adding a per-asset record:
- Inflates atproto PDS storage cost per creator linearly with
  output volume.
- Adds a write-path failure mode that the C2PA-only path does
  not have.
- Is not load-bearing for the verifier's cross-check.

Revisit in v0.9 if there is a concrete use case the C2PA + DID
combination cannot serve.

## Out of scope for v0.9 (lands in v1.0, OR is never shipped)

- **Paid DLC packaging + activation mechanism** for commercial
  detector packs (Creative Mayhem-distributed).
- **Commercial detector model packs** (paid DLC; sourced
  separately, not in this public repo).
- **Bundled FOSS deepfake detector models**: provcheck does NOT
  ship classifier weights for deepfake / anti-spoofing detection
  in either the FOSS core or the paid DLC layer. The FOSS layer
  ships the `Detector` trait + streaming intake; operators wire
  their own model in.

## Related memory

- [[release-roadmap-v07-to-v10]]
- [[redhat-provenance-market]]
- [[watermark-license-policy]] — applies to 9a, 9b, 9c
- [[rAIdio.bot lift authorisation is standing]] — 9c reference
