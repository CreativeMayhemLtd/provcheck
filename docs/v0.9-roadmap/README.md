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

### 9a — Detection slot architecture (FOSS plumbing)

The architectural slot that v1.0's AI-detection DLC will fill.
Pure plumbing in v0.9 — no classifier weights, no detection logic.
What lands:

- `provcheck-detect` crate with the trait + tagged-union types
  (`DetectionFamily { Image, Audio, Video, Text }`,
  `DetectionResult { confidence, family, model_id, version }`).
- Verifier dispatch: pluggable `Vec<Box<dyn Detector>>` slot in
  `provcheck::report::Report`.
- CLI surface: `provcheck --detect ai` flag toggles the detection
  pass; no-op stub today.
- Documentation contract: "where the paid DLC plugs in". Public
  spec so third-party detectors can implement the trait if they
  want to ship their own family.

### 9b — Streaming deepfake detection (FOSS scaffold)

Per user direction 2026-06-28: "in v9 we want streaming detection
of deepfakes, for voice and video".

- `provcheck-stream-deepfake` crate with the streaming intake
  pipeline (PCM chunk feeder for audio; frame batch feeder for
  video).
- Rolling-window detection confidence with configurable hop /
  window sizes.
- GUI surface for live monitoring (microphone, screen capture,
  RTSP feed input adapters).
- Library API for callers that want to plug the detector into
  their own transport (Discord bot, broadcaster overlay, etc.).
- **The actual classifier weights / model arch stays in v1.0's
  paid DLC.** v0.9 ships the plumbing + a stub detector that
  returns "model not installed" until the DLC unlocks it.

### 9c — ComfyUI node (FOSS, wires in v0.9)

Per user direction 2026-06-28: "we want to do a comfyui node
where the user can basically apply the app strings to their
outputs in comfyui and include this in the open source for 1.0.0".

- `python/comfyui-node/` package scaffolded today (v0.7.0).
- v0.9 wires the actual subprocess call to `provcheck-kit stamp`,
  handles tensor save / load, and ships example workflows.
- Brand-agnostic — works for any creator with their own atproto
  identity + signing key + brand registration.
- Apache-2.0 alongside the rest of the FOSS surface.

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

## Out of scope for v0.9 (lands in v1.0)

- Actual AI-detection classifier weights / model arch (paid DLC).
- Anti-spoofing + deepfake classification logic (paid DLC).
- DLC packaging + activation mechanism.

## Related memory

- [[release-roadmap-v07-to-v10]]
- [[redhat-provenance-market]]
- [[watermark-license-policy]] — applies to 9a, 9b, 9c
- [[rAIdio.bot lift authorisation is standing]] — 9c reference
