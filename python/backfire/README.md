# Backfire

**An imperceptible, keyed image watermark that AI provenance-stripping attacks *amplify* instead of remove.**

Part of the [provcheck](../../README.md) provenance suite. Apache-2.0 (this core tool).

## The problem it solves

Ordinary invisible image watermarks (TrustMark, StegaStamp, and friends) hide bits
in imperceptible pixel detail. A "regeneration" or "diffusion-purification" attack,
the kind shipped by the popular open-source provenance strippers, runs the image
through a diffusion model and projects it back onto the natural-image manifold,
discarding the off-manifold perturbation, i.e. the watermark. This is
[provably effective](https://arxiv.org/abs/2306.01953): in our own tests TrustMark's
detection confidence collapsed from 12.5 to 0.125 (the noise floor) under one such
attack.

## What Backfire does differently

Instead of hiding the mark where the purifier deletes it, Backfire **optimizes the
mark to be a fixed point of the purifier** — an attractor the diffusion process
reconstructs. Running a stripper's own purifier then makes the keyed serial read
*stronger*, not weaker. The attack backfires.

- **Imperceptible.** ~37 dB PSNR; visually identical to the original.
- **Keyed.** Carriers are HMAC-keyed, so only the key holder can write or read the
  mark. Wrong key reads nothing.
- **Survives the leading stripper.** After a real 50-step MarkDiffusion
  purification, the 8-bit keyed serial recovers with a mean ~91% bit accuracy
  across diverse images (see below), where a naive keyed mark collapses to a coin
  flip.

## Install

```
pip install -r requirements.txt          # embed needs torch + a diffusion model
# read needs only numpy + pillow
```

## Use

```
# stamp a keyed serial into an image (GPU; optimizes the poison mark)
python backfire.py embed photo.png -o photo.marked.png --key "my-secret-key" --serial 0xA5

# recover it (numpy only, no GPU, instant) -- exit 0 iff the serial reads
python backfire.py read photo.marked.png --key "my-secret-key" --expect 0xA5
```

`read` prints the recovered serial, a confidence, and whether the image is marked
with your key. Confidence is a decoy-normalized ratio (the real keyed carriers'
aligned energy over decoy keyed carriers): ~1.0 on an unmarked image or the wrong
key, and well above 1 when your mark is present (default threshold 1.25). In a
quick check: marked ~1.64 (with and without their attack) vs ~0.94 unmarked, ~0.57
wrong key.

## Measured robustness (2026-08-16, RTX 5090, vs the real MarkDiffusion purifier)

| condition | keyed serial recovery |
|---|---|
| no attack | ~100% |
| their 50-step purify @ strength 0.2 | ~100% |
| their 50-step purify @ strength 0.3 | ~88-100% |
| their 50-step purify @ strength 0.4 (aggressive) | ~75% |
| across 4 diverse images (mean, @0.3) | **~91%** |
| naive keyed mark, their attack (control) | ~56-62% (coin flip) |

## Honest limits (and the roadmap)

This FOSS core is a first real cut:

- **256 px**, one purifier backend (MarkDiffusion), one attack family.
- **8-bit keyed serial** (256 ids per key; the key is the primary identity).
- **Embed is slow** (~9 min/image on a 5090) because it optimizes per image; `read`
  is instant.
- Busy, high-frequency images are the hardest (~75% vs ~100% on smooth content).

The **pro tier** (BUSL, alongside provcheck's audio forensic layer) adds
error-correction for full recovery, higher-capacity payloads, collusion-resistant
traitor tracing (Tardos), and expectation-over-purifiers hardening across backends
(incl. CtrlRegen).

## Why it's free

Provenance marks only matter if they survive. A free tool that makes them
unstrippable, and turns the strippers' own attack into an amplifier, protects
everyone emitting provenance, from independent creators to the labs marking
AI-generated content under the EU AI Act. That is worth more open than closed.
