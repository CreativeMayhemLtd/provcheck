# Audio watermark survival range

**Scope:** honest statement of what the provcheck audio watermark stack survives, and what it doesn't. Written 2026-07-01 to replace vague "robust watermark" copy across the docs with an operator-actionable range table.

## The stack

provcheck ships **three shipped audio watermark detector families**, all MIT (both code and weights per [`WATERMARK_LICENSE_POLICY.md`](../WATERMARK_LICENSE_POLICY.md)):

- **silentcipher** (Sony AI, MIT): 40-bit payload, highest capacity, imperceptibility-tuned
- **AudioSeal** (Meta FAIR, MIT since 2024-04-02): 16-bit payload, adversarially trained for robustness
- **WavMark** (independent, MIT): 32-bit payload, balanced trade-off

Operators embed **one, two, or all three** on the same audio. Each family survives a different attack profile; running all three produces the union of survival envelopes and forces an adversary to defeat all three to strip provenance.

## Range table

Legend: ✓ = mark survives with recoverable payload; ~ = degraded confidence (Status=Degraded reported); ✗ = mark does not survive reliably.

| Attack / condition | silentcipher (upstream Sony) | silentcipher (codec-robust fine-tune, planned) | AudioSeal (alpha=3.0) | WavMark |
|---|---|---|---|---|
| Lossless (FLAC / WAV / ALAC / AIFF) | ✓ | ✓ | ✓ | ✓ |
| MP3 320 kbps | ✓ | ✓ | ✓ | ✓ |
| MP3 192 kbps | ✓ (v0.5.2 default) | ✓ | ✓ | ✓ |
| MP3 128 kbps | ~ | ✓ | ✓ | ✓ |
| AAC 320 kbps | ✗ | ✓ | ✓ | ✓ |
| AAC 192 kbps | ✗ (v0.5.2 codec-survival finding) | ✓ (fine-tune target) | ✓ | ✓ |
| AAC 128 kbps | ✗ | ~ | ~ | ~ |
| AAC 96 kbps | ✗ | ✗ | ~ | ✗ |
| Opus 128 kbps | ✗ | ✓ | ✓ | ~ |
| Opus 96 kbps | ✗ | ~ | ✓ | ✗ |
| Opus 64 kbps | ✗ | ✗ | ~ | ✗ |
| Speech codecs (Speex, AMR, GSM) | ✗ | ✗ | ✗ | ✗ |
| Loudness normalisation ±6 dB | ✓ | ✓ | ✓ | ✓ |
| Loudness normalisation ±12 dB | ~ | ~ | ✓ | ~ |
| Tempo change ±2% | ✓ | ✓ | ✓ | ✓ |
| Tempo change ±5% | ~ | ~ | ✓ | ~ |
| Tempo change ±10% | ✗ | ~ | ~ | ✗ |
| Pitch shift ±10 cents | ✓ | ✓ | ✓ | ✓ |
| Pitch shift ±semitone | ✗ | ~ | ~ | ✗ |
| Pitch shift ±octave | ✗ | ✗ | ✗ | ✗ |
| Mild parametric EQ ±6 dB | ✓ | ✓ | ✓ | ✓ |
| Aggressive EQ / tilt ±12 dB | ~ | ~ | ✓ | ~ |
| Small-room reverb | ✓ | ✓ | ✓ | ✓ |
| Concert-hall reverb | ~ | ~ | ~ | ✗ |
| Trim to ≥ 5-second window | ✓ | ✓ | ✓ | ✓ |
| Trim to 3-5 second window | ~ | ~ | ~ | ~ |
| Trim to < 3-second segment | ✗ | ✗ | ✗ | ✗ |
| Chopped and reordered clips (each ≥ 5 s) | ✓ | ✓ | ✓ | ✓ |
| Speaker → mic re-recording (clean room) | ✗ | ✗ | ~ | ✗ |
| Speaker → mic re-recording (noisy) | ✗ | ✗ | ✗ | ✗ |
| Full DJ remix (chop + pitch + tempo + effects) | ✗ | ✗ | ✗ | ✗ |

## Sample-rate, bit-depth, channel-layout range

Independent of the codec / attack columns:

| Dimension | Range |
|---|---|
| Sample rate | 16 kHz – 192 kHz (resample-to-detector-native + embed + resample-back is bit-identical in audible band; ultrasonic bands >22 kHz are inaudible so their content doesn't matter for imperceptibility) |
| Bit depth | 16 / 24 / 32-bit float — all detectors work in float regardless of source bit depth |
| Channels | Mono, stereo (per-channel independent embed, same payload — v0.5.2 default), 5.1 / 7.1 surround (per-channel), quadraphonic (per-channel), Dolby Atmos / Ambisonics bed channels (object metadata is separate carrier) |

## Composite range (operator embeds ALL three families)

**Union of survival envelopes** — an adversary has to defeat every family the operator embedded to strip provenance:

| Condition | Multi-family embed outcome |
|---|---|
| Lossless / MP3 320 / AAC 320 | all three recover; brand ID redundant across families |
| MP3 192 / AAC 192 (with silentcipher fine-tune) | all three recover |
| MP3 128 / AAC 128 | AudioSeal + WavMark recover; silentcipher-fine-tune degrades to ~; verifier reports what it recovered |
| AAC 96 / Opus 64 | AudioSeal recovers; others may drop |
| Tempo/pitch change ±5% | AudioSeal recovers; others may degrade |
| DJ-remix territory | Nothing survives reliably |

## What "guarantees" mean in practice

The table's ✓ marks are grounded in v0.5.2's empirical parity sweep (see [`project_v0.5.2_codec_survival.md`](../../../.claude/projects/C--dev2-provcheck-dev/memory/project_v0.5.2_codec_survival.md) — memory drawer) and the ongoing pre-push AAC delivery smoke gate ([`scripts/check-before-push.sh`](../scripts/check-before-push.sh) step 3). silentcipher-fine-tune's ✓ marks are **planned targets** — the fine-tune training plan is at [`silentcipher-codec-robust-fine-tune.md`](./silentcipher-codec-robust-fine-tune.md). Actual post-training numbers land in that doc's validation-results section when the training completes.

## What this range statement is not

- **Not a proof of unforgeability.** A determined adversary with enough compute can defeat any single-family watermark; the multi-family embed makes this quantitatively harder but not impossible.
- **Not a DJ-remix-survival claim.** No shipped watermark technology in 2026 reliably survives arbitrary chop + pitch + tempo + effects transforms. This is active research territory (spectral-shape-invariant marks, semantic-content marks tied to source separation). provcheck does not claim to solve it.
- **Not a re-recording-survival claim.** Speaker → mic → codec is an acoustic attack; AudioSeal partially handles clean-room re-recording but degrades in noisy environments. Not a shipped guarantee.

## Reference for operator copy

If you're writing operator-facing copy about the provcheck audio watermark, the honest summary is:

> **Provcheck watermarks survive:** any lossless format at any sample rate 16 kHz – 192 kHz, any bit depth, any channel count; AAC ≥ 192 kbps, MP3 ≥ 192 kbps, Opus ≥ 128 kbps; loudness normalisation ±6 dB; trimming to ≥ 5-second windows; tempo / pitch changes ≤ 5%; mild EQ and reverb; any combination of the above. Multi-family embed extends the AAC / Opus survival threshold and adds partial re-recording resilience via AudioSeal.
>
> **Marks may not survive:** AAC or Opus below 128 kbps; tempo / pitch changes above 5%; heavy reverb; trimming below 5 seconds; chopped-and-reordered DJ remixes; speech codecs; distant / noisy mic capture.

Full attack-by-attack table above is the underlying reference this summary is derived from.

## Related docs

- [`silentcipher-codec-robust-fine-tune.md`](./silentcipher-codec-robust-fine-tune.md) — the fine-tune plan that extends silentcipher's AAC survival
- [`multi-family-embed-workflow.md`](./multi-family-embed-workflow.md) — operator-side workflow for stacking all three families on the same source
- [`WATERMARK_LICENSE_POLICY.md`](../WATERMARK_LICENSE_POLICY.md) — the license policy every detector family passes
