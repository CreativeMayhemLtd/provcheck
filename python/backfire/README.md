# Backfire

**An imperceptible, keyed image watermark that AI provenance-stripping attacks *amplify* instead of remove.**

Part of the [provcheck](../../README.md) provenance suite. Dual-licensed:
**AGPL-3.0-or-later** for open use, or a commercial license (see `LICENSING.md`).

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
mark to be a fixed point of the purifier**, an attractor the diffusion process
reconstructs. Running a stripper's own purifier then makes the keyed id read
*stronger*, not weaker. The attack backfires.

- **Imperceptible.** ~34 dB PSNR (configurable via `--target-psnr`); visually
  identical to the original. The mark shape is content-adaptive, then projected to
  an equal-energy PSNR floor so busy and smooth images alike get a reliable mark.
- **Keyed.** Carriers are HMAC-keyed, so only the key holder can write or read the
  mark. A wrong key reads nothing.
- **Trustworthy read.** Detection is decoy-normalized (real keyed carriers versus
  decoy keyed carriers), and every id bit must clear the decoy noise floor, so a
  marginal or wrong id is rejected rather than reported as valid.
- **Survives the leading stripper.** After a real 50-step MarkDiffusion
  purification the keyed id still reads, where a naive keyed mark collapses to a
  coin flip.

## What it stores

A **4-bit keyed id** (0 to 15) under a secret key. The key is the primary identity
(the keyspace is unbounded); the id is a per-copy index, for example which licensee
or which distribution got this copy. Reliability is bought with redundancy: each id
bit is repetition-coded across 8 of the 32 keyed carriers, and a read is only
reported `valid` when every one of the four bits clears the decoy noise floor by a
margin, so a marginal or wrong id is never reported as valid.

Higher-capacity payloads and error correction are the pro tier (see below).

## Install

```
pip install -r requirements.txt          # embed needs torch + a diffusion model
# read needs only numpy + pillow
```

## Use

```
# stamp a keyed id into an image (GPU; optimizes the poison mark)
python backfire.py embed photo.png -o photo.marked.png --key "my-secret-key" --serial 0x5

# recover it (numpy only, no GPU, instant) -- exit 0 iff the id reads and validates
python backfire.py read photo.marked.png --key "my-secret-key" --expect 0x5
```

To also resist a band-notch adaptive attacker (see limits below), embed with the
content-coupled carriers and the notch in the optimization loop, and read with the
same carrier mode:

```
python backfire.py embed photo.png -o photo.marked.png --key "my-secret-key" --serial 0x5 --carriers edge --notch-eot 1.5
python backfire.py read  photo.marked.png --key "my-secret-key" --carriers edge --expect 0x5
```

`read` prints the recovered id, a confidence, the weakest per-bit margin
(`min_bit_margin`), and `valid` (true when every id bit clears the decoy noise floor
by the margin threshold, default 1.5). Both numbers are decoy-normalized (the real
keyed carriers' aligned energy over decoy keyed carriers): near 1.0 on an unmarked
image or the wrong key, and well above the threshold when your mark is present.
Across 12 diverse images the certified marks sat at a weakest-bit margin averaging
3.4 before the attack and 5.8 after it (the purifier strengthens the mark), all clear
of the 1.5 threshold, while unmarked and wrong-key reads never cleared it (zero
false-valids, and no wrong id was ever accepted).

## Measured robustness (2026-08-17, RTX 5090, vs the real MarkDiffusion purifier)

Full-**id** recovery (the complete 4-bit id read back and margin-validated, not
per-bit accuracy), over 12 diverse real images, embed config: 240 iterations, EOT
over purify strengths 0.2 and 0.3, 4 noise draws, content-adaptive mark at a 34 dB
PSNR floor.

| condition | full-id recovered | mean PSNR |
|---|---|---|
| no attack (pre-purify) | 9/12 | 34.0 dB |
| their real 50-step purify @ strength 0.3 | 10/12 | (same image) |
| a **held-out** purifier (never optimized against) | 11/12 | (same image) |
| unmarked / wrong-key controls | 0 false-valids | n/a |

**Post-attack recovery (10/12) exceeds pre-attack recovery (9/12): the purifier is a
net amplifier across the set, not just survivable.** Both misses are correctly
rejected low-margin reads, never wrong ids: image 01 (a busy 1 MB PNG) never cleared
the 1.5 threshold pre or post, and image 04 validated at rest but the purifier
weakened it below threshold. Two images (06 and 07) were sub-threshold at rest and
the attack pushed them over into valid, the amplifier effect in its purest form.

**The amplification generalizes across purifiers.** Attacked by a *held-out*
diffusion purifier the mark was never optimized against (a different model), recovery
was 11/12, matching and slightly beating the in-training purifier (10/12); two images
that failed the in-training attack survived the held-out one. So the poison fixed
point is a general property of diffusion purification, not an artifact of one model:
the attack backfires whatever diffusion stripper is used. Optimizing against several
purifier backends at once (`--models a,b`) is available and pushed post-attack
recovery to 8/8 on an 8-image subset, but the held-out result shows it is a bonus, not
a requirement. For the one attack the pixel mark does not shrug off, a band-notch, see
the `--carriers edge --notch-eot` hardening under Honest limits.

## The text channel (a corroborating second id)

Alongside the pixel mark, Backfire can carry the same keyed id in the image's
metadata as a lightweight second channel (`backfire_text.py`). It is not robust on
its own; it exists to corroborate the pixel id and to catch signature-only strippers
that rewrite provenance blocks without touching neutral metadata.

```
# write the keyed id token into neutral PNG text fields
python backfire_text.py stamp photo.marked.png -o photo.final.png --key "my-secret-key" --serial 0x5 --smear 3

# recover / check it (exit 0 iff the token reads under the key)
python backfire_text.py verify photo.final.png --key "my-secret-key" --smear 3 --expect 0x5
```

How it works, and its honest scope:

- The id becomes a keyed token, `HMAC-SHA256(key, LABEL || id)` truncated, which is
  indistinguishable from random without the key.
- `--smear N` keystream-XORs the token across N neutral text fields (`Identifier`,
  `DocumentID`, `InstanceID`) so no single field looks like a payload; recovery tries
  all ids and only the right key reconstructs one.
- **Dies to a blanket metadata strip** (any tool that drops all text chunks removes
  it), so it is never the primary identity. It **survives signature-only strippers**
  that surgically remove known provenance (C2PA, XMP provenance blocks) while leaving
  ordinary metadata, and it **reads nothing under the wrong key**. Treat it as
  corroboration for the robust pixel id, not a replacement.

## Honest limits (and the roadmap)

This open core is a first real cut:

- **256 px**, one purifier backend (MarkDiffusion), one attack family (diffusion
  purification at strengths 0.2 to 0.4, which is what the leading open strippers
  ship). The amplification claim is scoped to purification-class strippers.
- **A band-aware adaptive attacker is partly, not fully, defended.** The default mark
  lives in a mid-frequency band, and an attacker who reads this source and suppresses
  that band can strip it (though only with a crude linear filter, not the diffusion
  purifiers the real strippers ship, and only by degrading the image to roughly 20 dB
  of clearly visible damage). The `--carriers edge --notch-eot` embed options harden
  against this: content-coupled carriers plus a band-notch term in the optimization
  loop keep the mark readable after a notch. On a 6-image test this raised post-notch
  survival from 0/6 to 3/6 with no loss of amplification (post-purify held at 5/6);
  the images that still fall are busy, high-frequency content that is energy-limited
  at 34 dB. Lowering `--target-psnr` to 31 dB (a little more mark energy) takes pre and
  post-purify recovery to 6/6 and roughly triples those images' notch margins (toward,
  though not yet over, the threshold), so a lower-PSNR robustness mode is the lever for
  busy content. Notch hardening is opt-in; the default remains the band mark.
- **4-bit keyed id** (16 ids per key; the key is the primary identity). Validity is
  a per-bit margin over the keyed decoy floor, not a cryptographic MAC: it rejects
  marginal and wrong-id reads, and a wrong key reads nothing, but the id is a
  per-copy index under a trusted key, not a signature.
- **Embed is slow** (~12 min/image on a 5090) because it optimizes per image; `read`
  is instant and needs no GPU.
- Busy, high-frequency images are the hardest; smooth content is the most reliable.

The **pro tier** (BUSL, alongside provcheck's audio forensic layer) adds
error-correction for full recovery, higher-capacity payloads, collusion-resistant
traitor tracing (Tardos), and expectation-over-purifiers hardening across backends
(incl. CtrlRegen).

## Why it's open

Provenance marks only matter if they survive. A tool that turns the leading
strippers' own purification attack into an amplifier protects everyone emitting
provenance, from independent creators to the labs marking AI-generated content under
the EU AI Act. Backfire is open under the AGPL so that improvements to that mechanism
stay in the open (see `LICENSING.md`); a commercial license is available for anyone
who needs to embed it without the AGPL's terms.
