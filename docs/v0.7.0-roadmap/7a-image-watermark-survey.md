# v0.7.0 phase 7a — Image watermark library survey

Phase 7a is the FOSS-compatible library survey for the image
watermark family that v0.7.0 adds. Per the workspace
[`WATERMARK_LICENSE_POLICY.md`](../../WATERMARK_LICENSE_POLICY.md)
gate, **both** the model code AND the trained weights must be
permissively licensed (MIT, Apache-2.0, BSD, ISC, or CC0). Research-
only, "community license", CC-BY-NC, and other non-commercial
restrictions disqualify the family for inclusion.

This doc enumerates the candidates I am aware of, with the LAST
KNOWN claimed license status. Every "✓" below is treated as needing
verification at the upstream repo on the day the family is wired
in (7b); a row that passes survey here is not a green light to
ship without re-confirming the license on the wiring commit.

## Candidates

### TrustMark (Adobe / Content Authenticity Initiative)

- **Repository:** https://github.com/adobe/TrustMark
- **Paper:** Bui et al, "TrustMark: Universal Watermarking for
  Arbitrary Resolution Images" (arXiv:2311.18297, late 2023).
- **Code license (verified 2026-06-28):** **MIT**. The
  repository's blanket LICENSE statement, the README, and the
  package metadata all agree. My v0.7 phase 7a doc originally
  said Apache-2.0 — that was wrong; corrected at 7b.
- **Weights license (verified 2026-06-28):** **MIT** by the
  same blanket statement. The weights themselves do not carry a
  separate license file; the MIT statement covers the artifact
  set. Adobe hosts the `.ckpt` and `.onnx` files at
  `https://cai-watermark.adobe.net/watermarking/trustmark-models/`
  (migrated from Netlify in April 2026). We mirror to our public
  GH release at `weights-v1` for SHA-pinned distribution.
- **Architecture:** Encoder-decoder CNN; supports arbitrary image
  resolutions via patch-level processing. Built for C2PA-adjacent
  workflows specifically.
- **Payload:** 100 bits typical; smaller payloads land at higher
  robustness.
- **Robustness:** Designed against JPEG / WebP recompression,
  resize, crop, light filtering. Adobe published an empirical
  survival matrix in the paper.
- **Verdict (survey):** **First-choice candidate.** Apache-2.0 on
  both surfaces (subject to re-verification at 7b), explicitly
  designed for C2PA integration which matches provcheck's posture
  exactly, Adobe is a credible long-term maintainer.

### Stable Signature (Meta / FAIR)

- **Repository:** https://github.com/facebookresearch/stable_signature
- **Paper:** Fernandez et al, "The Stable Signature: Rooting
  Watermarks in Latent Diffusion Models" (ICCV 2023).
- **Claimed code license:** CC-BY-NC 4.0 (Meta's standard FAIR
  research-code license).
- **Claimed weights license:** CC-BY-NC 4.0.
- **Architecture:** Fine-tunes the VAE decoder of a latent
  diffusion model so generated images carry a watermark by
  construction. Cannot retrofit-watermark existing non-LDM
  images.
- **Verdict (survey):** **REJECTED.** CC-BY-NC fails the workspace
  license policy (the "NC" non-commercial clause). Documented
  here so future contributors can see the rejection rather than
  re-evaluating from scratch.

### StegaStamp (Tancik et al, UC Berkeley)

- **Repository:** https://github.com/tancik/StegaStamp
- **Paper:** Tancik et al, "StegaStamp: Invisible Hyperlinks in
  Physical Photographs" (CVPR 2020).
- **Claimed code license:** MIT (the code repository's LICENSE
  file).
- **Claimed weights license:** Unknown — the README does not
  explicitly state a weights license; the model checkpoint
  download links live on a Google Drive folder without a
  LICENSE.md adjacent to them. Could be research-only by default.
- **Architecture:** Encoder-decoder CNN trained against a
  differentiable physical-print simulator. Designed for printed
  photos that get recaptured by a camera, which is a stronger
  threat model than provcheck's normal JPEG/WebP-recompress
  case but produces a serviceable watermark either way.
- **Payload:** 100 bits typical.
- **Verdict (survey):** **HOLD pending weights-license
  clarification.** Code is MIT but weights status is the open
  question. Acceptable if upstream confirms permissive weights
  OR if we retrain from scratch on CC0/CC-BY data (large effort).
  Not first-choice.

### HiDDeN (Zhu et al, Stanford / Stanford-NLP)

- **Repository:** https://github.com/ando-khachatryan/HiDDeN
  (community-maintained reimpl of the Stanford paper).
- **Paper:** Zhu et al, "HiDDeN: Hiding Data With Deep Networks"
  (ECCV 2018).
- **Claimed code license:** MIT (for the community-maintained
  reimpl).
- **Claimed weights license:** No publicly released weights from
  the paper authors. Community reimplementations distribute
  trained weights with varying terms.
- **Architecture:** Encoder-decoder CNN with adversarial
  robustness training. The original paper's architecture is the
  canonical "deep-learning image watermark" baseline that newer
  families compare against.
- **Verdict (survey):** **HOLD — no canonical weights.** The
  family is the academic baseline but the lack of a
  publishable-as-FOSS weights checkpoint means we would need to
  retrain from scratch. Defer in favour of TrustMark which has
  released, permissively-licensed weights.

### DCT-DWT classical methods (algorithmic, no neural model)

- **Reference implementations:** widely available; common
  textbook algorithms.
- **Code license:** Public domain / various depending on the
  port chosen. We would write our own.
- **Weights license:** N/A (no trained weights — purely
  algorithmic).
- **Architecture:** Frequency-domain watermarking via DCT or
  DWT coefficients. Embedding bits as small perturbations to
  selected mid-frequency coefficients.
- **Robustness:** Solid against JPEG recompression at standard
  qualities, poor against geometric attacks (crop, rotate,
  resize).
- **Verdict (survey):** **FALLBACK only.** No model-weights
  licensing concern by construction. Robustness ceiling sits
  noticeably below TrustMark on real-world delivery pipelines.
  Acceptable as a backup family if TrustMark's weights-license
  re-verification at 7b fails.

## Selection for v0.7.0

**Chosen first family: TrustMark**, subject to license re-
verification at the 7b wiring commit.

Rationale:

1. **License posture matches.** Apache-2.0 on both code and
   weights (claimed) is the cleanest fit with the workspace
   license policy.
2. **Designed for C2PA integration.** Adobe's CAI team built
   TrustMark explicitly for the Content Authenticity Initiative
   ecosystem, which is the same standard provcheck verifies
   against. The pairing is intentional, not coincidental.
3. **Maintainer credibility.** Adobe-backed open-source models
   tend to stay maintained; orphaned research checkpoints have a
   higher abandonment rate.
4. **Robustness envelope matches our threat model.** TrustMark
   was trained against JPEG / WebP / resize / crop, which is
   exactly the delivery pipeline shape provcheck's image users
   will see (web upload, social media, CDN re-encode).

**Backup family (if TrustMark license re-verification fails at
7b): DCT-DWT classical method.** Lower robustness but zero
license risk. Phase 7b would scaffold the chosen family; if
license falls through during the 7b wiring commit we pivot to
DCT-DWT in the same PR rather than re-running the survey.

## Acceptance for 7a

This phase ships:

- This survey doc.
- A scaffolded `crates/provcheck-image/` crate with the
  cross-crate parity shape inherited from the 7-pre audit:
  - `pub fn detect(path: &Path) -> Result<WatermarkResult, Error>`
    returning the `NotDetected` stub until 7b lands inference.
  - `pub struct EmbedConfig {}` empty struct for shape parity.
  - `pub fn embed_with_config(...)` stub returning
    `EncodeError::NotYetImplemented`.
  - `audio.rs` equivalent named `image.rs` for the image-decode
    primitives (via the `image` crate).
  - Brand-payload constants matching the audio-crate convention.
- An update to `WATERMARK_LICENSE_POLICY.md` recording the
  TrustMark survey result.
- Workspace `Cargo.toml` includes the new crate.

Phase 7b is the wiring commit where the chosen family's ONNX (or
pure-Rust port) actually runs.

## Related

- v0.7.0 roadmap parent: [`./README.md`](./README.md).
- v0.7.0 primitives audit (the cross-crate parity this phase
  inherits): [`./primitives-audit.md`](./primitives-audit.md).
- Workspace license policy:
  [`../../WATERMARK_LICENSE_POLICY.md`](../../WATERMARK_LICENSE_POLICY.md).
