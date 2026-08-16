# Provenance-stripping survival

**Scope:** an honest, continuously-measured statement of how provcheck's
detection holds up against deliberate provenance-stripping tools, and,
just as importantly, where it does not. This is the adversarial companion
to [`audio-watermark-survival-range.md`](audio-watermark-survival-range.md):
that document measures survival against ordinary transcoding and
signal-processing; this one measures survival against software written
specifically to remove provenance.

## Why this document exists

provcheck is a detector and a verifier, not an embedder that promises its
marks are permanent. Anyone who tells you a watermark or a content
credential is unremovable is selling something. The honest position, and
the one that earns trust, is to name the leading adversary, test against
it in the open, and publish what survives and what does not.

That posture also happens to be the correct engineering strategy. No
single provenance layer is unbeatable, so provcheck runs several
independent layers (C2PA content credentials, invisible audio watermarks
across three detector families, invisible image watermarks, and
statistical text watermarks), and an adversary has to defeat every layer
that applies to a given asset to strip provenance completely. This
document tracks how that plays out against a real tool.

## The adversary we measure against

The reference adversary is
[guillaumemeyer/watermarks-remover](https://github.com/guillaumemeyer/watermarks-remover)
(MIT-licensed), currently the most prominent public provenance-stripping
project. It is candid about its own limits, which makes it a serious tool
to measure against rather than a marketing exercise. Its stated coverage
is four-layered:

1. **Invisible Unicode text hygiene:** strips zero-width, bidi, and
   tag-character carriers from generated text (deterministic).
2. **Statistical text watermarks:** best-effort removal of token-sampling
   schemes (SynthID-Text, KGW-family) by rewriting the text through an
   external LLM.
3. **File metadata cleaning:** strips C2PA manifests, EXIF, and XMP across
   PNG, JPEG, WebP, AVIF, HEIC, PDF, DOCX, and more.
4. **Pixel-domain image watermark removal (optional, external backends):**
   targets SynthID-image, StegaStamp, Tree-Ring, and StableSignature via
   diffusion-purification and regeneration harnesses.

Notably, it has **no audio capability**. It does not name TrustMark. We
measure against its released behaviour and refresh these results as it
ships new versions; the arms race runs in both directions, and this table
is the scoreboard.

## The one invariant that is not negotiable

Everything below is about how much of a mark survives an attack. Separate
from that, and never up for debate, is a correctness invariant:

> **provcheck must never report a stripped asset as verified.**

When a manifest is removed, provcheck reports the asset as unsigned or
lacking credentials, not as trusted. Stripping provenance can defeat
detection; it must never be able to forge a passing verdict. This
invariant is enforced by test (see "How this is tested" below) and is the
single most important property in the whole document.

## Survival matrix

Legend: ✓ = provcheck still detects the mark after the attack; ~ =
degraded (Status=Degraded reported); ✗ = mark does not survive the attack
(and provcheck honestly reports its absence); n/a = attack does not apply
to this modality; **measuring** = result under active measurement, not yet
asserted.

Measured against watermarks-remover v0.5.0 on 2026-08-16, provcheck
v1.1.11. The harness that produces this table is described under "How
this is tested".

| provcheck pillar | watermarks-remover capability that applies | Survives? | Notes |
|---|---|---|---|
| **Audio watermark** (silentcipher, AudioSeal, WavMark) | none (no audio support) | ✓ | **Measured.** The tool refuses to process audio at all ("bytes match no supported text, image or container format"), so it produces no output and the mark is untouched: provcheck still decodes silentcipher at confidence 0.984. The adversary cannot even engage. provcheck's strongest result. |
| **C2PA embedded manifest** (images, documents) | file metadata cleaning | ✗ | **Measured.** A signed JPEG (provcheck: verified) run through `clean_image.py` comes back with the manifest gone (their report: `still_has_c2pa: false`); provcheck then reports `verified: false, unsigned: true` and exits 1. The mark does not survive, and the **invariant holds** (no false verify). An honest boundary of embedded C2PA, not a provcheck defect. |
| **Image watermark** (TrustMark), metadata-strip tier | file metadata cleaning (default, no pixel backend) | ✓ | **Measured.** TrustMark lives in the pixels, so the default metadata clean leaves it byte-identical: provcheck's detection confidence is unchanged (12.5 before and after). Their common-case attack does not touch pixel watermarks. |
| **Image watermark** (TrustMark), pixel-domain tier | diffusion-purification / regeneration (optional external GPU backends) | ✗ | **Measured.** A single MarkDiffusion DiffusionPurification pass (Stable Diffusion 2.1-base, strength 0.3, 50 steps) washed the mark out: provcheck's detection confidence collapsed from 12.5 to 0.125 (not detected). This is the honest state of the art, not a provcheck defect: no pixel-domain watermark reliably survives a determined diffusion-regeneration adversary. It is exactly why provcheck does not rely on any single layer. Conditions matter (content, strength, step count); this is one measured point, not a universal guarantee. |
| **Statistical text watermark** (SynthID-text) | Unicode hygiene (Layer A) and LLM rewrite (Layer B) | measuring | SynthID-text is a token-sampling statistical mark, not a Unicode-carried one, so Layer A should not affect it; a full Layer-B rewrite changes the tokens and is expected to destroy the signal (at the cost of altering the text itself). Measured across both layers. |

## What we measured, and what is still measuring

**Measured (watermarks-remover v0.5.0, provcheck v1.1.11, 2026-08-16):**

- **Audio survives** because the adversary has no audio capability at all.
  Run against a silentcipher-marked WAV, the tool refused the file
  outright and produced no output; provcheck still decoded the mark at
  confidence 0.984. This is a property of the tool's scope, not a lucky
  robustness result, and it is provcheck's clearest differentiator.
- **Embedded C2PA does not survive a metadata wipe, and provcheck reports
  the loss honestly.** A signed JPEG verified, then had its manifest
  stripped by the tool, then reported as unsigned and unverified by
  provcheck (exit 1). This is expected and correct. provcheck verifies
  embedded manifests; it does not currently consume soft-binding or
  cloud-bound manifests, so the survival of soft-bound credentials is a
  separate, future question and is deliberately not claimed here.
- **TrustMark survives the tool's default (metadata-only) clean.** The
  cleaned image was byte-identical and provcheck's detection confidence
  was unchanged. The tool's common-case path does not touch pixels.

- **TrustMark does not survive the pixel-domain purification tier.** A
  Stable Diffusion 2.1 DiffusionPurification pass (strength 0.3, 50
  steps) dropped detection confidence from 12.5 to 0.125. This is the
  known limit of pixel watermarking against regeneration attacks, and it
  is the single strongest argument for running several independent
  provenance layers rather than trusting one. Conditions matter; treat
  this as one measured point, not a universal law.

**Under active measurement:**

- **SynthID-text survival** through Unicode hygiene and through rewrite
  (no in-repo text embedder yet, so this row is not yet reproducible).

We publish measured results, not hopeful ones. Rows stay marked
**measuring** until there is a reproducible fixture behind them.

**The takeaway across the matrix.** Three independent things had to be
true for provenance to fully survive this adversary, and no single layer
delivered all three: audio survived because the tool cannot touch it,
C2PA was removed but never faked a pass, and the image mark survived a
metadata wipe but not a diffusion regeneration. Layered detection is not
a nicety here; it is the only honest answer to a capable stripper.

## How this is tested

The measurement is not a one-off. It is wired into the test suite so that
watermarks-remover becomes a standing target to beat, and any regression
(theirs or ours) shows up:

- **Golden-fixture CI test (deterministic, runs in normal CI):**
  [`crates/provcheck/tests/provenance_stripping.rs`](../crates/provcheck/tests/provenance_stripping.rs)
  asserts provcheck's verdict on the tool's actual stripped output,
  captured at a pinned tool version and committed as a tiny fixture,
  including the non-negotiable "stripped asset never verifies" invariant.
  It calls the `verify()` library entry (C2PA-only, no ONNX Runtime), so
  it runs clean in CI without pulling in Python, Docker, or model
  weights.
- **Periodic live re-measurement (documented harness, not in CI):**
  [`scripts/provenance-strip-matrix.py`](../scripts/provenance-strip-matrix.py)
  runs the tool's current release against freshly generated
  provcheck-marked fixtures across every row and refreshes the golden
  set. This is where a new adversary release gets caught, and where the
  **measuring** rows above get their numbers.

## Honest boundaries

1. **Embedded C2PA is removable by design.** A content credential embedded
   as metadata can be stripped by wiping metadata. provcheck's job there
   is to detect the credential when present and to refuse to fake one when
   it is gone, not to make the credential unremovable.
2. **A full rewrite defeats a text watermark, because it is no longer the
   same text.** That is the honest limit of statistical text watermarking
   generally, not a provcheck-specific gap.
3. **Pixel-domain purification is a real and improving attack.** The image
   row is a genuine contest, which is exactly why it is measured openly
   rather than asserted.
4. **This is a moving target.** Both tools ship regularly. Treat this
   document as the current standing in an ongoing measurement, refreshed
   as the adversary evolves.
