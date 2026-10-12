# Backfire

**A keyed image watermark that AI provenance-stripping attacks amplify instead of remove.**

Experimental research from Creative Mayhem. Source-available and dual-licensed: Business Source License 1.1 (free for non-commercial use), or a commercial license.

## Why this exists

Creative Mayhem builds AI-generated content (rAIdio.bot, vAIdeo.bot, lysn.fm) and the provenance tooling meant to keep it accountable (provcheck). Attaching provenance is easy; making it survive the tools built to erase it is the hard and responsible part. Backfire is a first, honest attempt at a watermark that does not just resist a removal attack but turns it around. It is experimental, and we are releasing it in the open, limits and self-red-team included, because that is what is worth publishing.

## The attack, and the credit

Invisible watermarks hide bits in imperceptible pixel detail. A **regeneration** (diffusion-purification) attack removes them by running the image back through a diffusion model, which snaps it onto the natural-image manifold and drops the off-manifold perturbation, the watermark. This is published, proven work (Zhao et al., *Invisible Image Watermarks Are Provably Removable Using Generative AI*, NeurIPS 2024, [arXiv:2306.01953](https://arxiv.org/abs/2306.01953)), and open provenance-stripping tools make it practical.

We are genuinely glad that work is out in the open. Backfire exists *because* of it, and the paper's own conclusion points the way: it recommends shifting toward watermarks that keep the image semantically consistent, which is exactly the direction Backfire takes. To us at Creative Mayhem this is an interesting technical challenge that we are happy to take a look at.

## The idea

Instead of hiding the mark where the purifier deletes it, Backfire **optimizes the mark to be a fixed point of the purifier**, an attractor it reconstructs. So running the attack makes the keyed identifier read *stronger*. The attack backfires. That is the thesis, and the name.

## How it works

- **Keyed carriers.** HMAC-keyed frequency carriers; only the key holder can write or read, a wrong key reads nothing.
- **Fixed-point optimization.** Embed optimizes the mark by gradient descent *through* a differentiable diffusion purifier, so the purifier reinforces it. Slow, GPU-bound.
- **Keyed detection.** A keyed, decoy-normalized correlation. numpy only: no GPU, no weights. Anyone with the key verifies instantly.

## What we measured

All of it on the shipped mark (256 px, 30 dB), attacked and then read back through Backfire's own reader at its default threshold, so every number is what the tool actually reports, not a friendlier proxy. Measured over 200 COCO val2017 photos.

![Backfire image-mark survival across 200 photos: diffusion regeneration 99.5%, neural-codec re-encode 94 to 97.5% (iterated 86.5%), everyday handling 97 to 99%, zero false positives](repro/survival_200.png)

Every bar is recomputed from the raw per-image verdicts in [`repro/survival_200.jsonl`](repro/survival_200.jsonl); regenerate the chart with `python repro/plot_survival.py`.

- **It survives the real removal attack.** Against the published Zhao et al. WatermarkAttacker ([arXiv:2306.01953](https://arxiv.org/abs/2306.01953)), the keyed identifier reads back valid on 99.5% of 200 photos after the diffusion regeneration, on the matched model *and* a held-out one. That the mark reads *stronger* after the attack, the amplification Backfire is named for, is reproducible with `repro/demo_amplify.py`.
- **It survives a neural-codec re-encode too.** Against the same paper's VAE codec attacker, 94 to 97.5% survive across four compression models the mark was never tuned against; an iterated double-pass, the hardest case in the set, holds 86.5%, and we say so rather than drop it. So Backfire survives *both* removers behind the "provably removable" result, not just the diffusion one.
- **No false positives.** Zero valid reads over 200 unmarked images and every wrong-key read, at the default threshold. The reader normalizes each margin against a robust decoy noise floor, which holds the false-positive rate to zero over 1,000 unmarked images too (see `LIMITS.md`): the unmarked margin sits near the floor while a real mark clears it several times over. Failing safe is the point.
- **It shrugs off everyday handling.** JPEG 99.0% (quality 90) and 98.5% (quality 50), half-size downscale 98.0%, and blur 97.0%. It does *not* survive a hard crop, the carriers are position-locked; we disclose that rather than hide it.
- **Low visibility, content-dependent.** 30 dB PSNR: the mark hides in detailed images but shows as a faint texture on large flat regions, so it is subtle rather than strictly invisible, and we would rather say that than oversell it. A quieter mark trades survival for lower visibility; the embed also offers perceptual-mask and luminance-only modes (`--pmask`, `--luma`) and a content-adaptive mode (`--auto`) that reduce visibility further.
- **The frontier, and the seal that answers it.** The default invisible mark does not survive controllable regeneration from clean noise (for example CtrlRegen), which rebuilds the image from scratch rather than editing it, and an aggressive band-notch it detects rather than survives. The visible seal (`--level maximum`) is built for exactly that frontier: at a measured 30 dB, multi-band and luminance-only, it reads back on 98.4% of 1,600 images after CtrlRegen (95% CI [97.6, 98.9]) and 99.9% after a neural-codec strip, at zero false positives over 2,000 unmarked images. The trade is visibility, stated as a number and not asserted away (SSIM 0.79, LPIPS 0.20), and a scope limit: a heavy manual diffusion repaint still erodes it (80% at Stable Diffusion strength 0.20, 50.7% at 0.30). No watermark is unremovable; the invisible mark wins against the deployed strippers, and the seal extends that to the regenerator, each honest about its boundary. See `LIMITS.md`.

At larger scale, a 1,919-image run of the shipped invisible mark confirms the everyday battery: the keyed identifier reads back on 100% of images after JPEG (quality 90 down to 20), WebP, half-size resize, blur, sensor noise, grayscale, a crop with register, and a neural-codec strip, at zero false positives over 2,000 unmarked images. A fixed-strength Stable Diffusion img2img regeneration, a different attack from the purification stripper the amplification proof uses, recovers 97.8% at strength 0.10 and 89.6% at 0.20. The amplification and four-model codec figures above remain the 200-image battery, which that run did not reproduce at this scale.

## The weakness, and its answer

A sophisticated attacker who reads this source can strip the mark with an aggressive **band-notch**; we could not make the linear mark survive that, and we say so. But the notch is loud, it carves a spectral hole natural images lack, so `read` also runs a tamper tripwire. Across 300 clean images and 81 notch configurations (feathered evasions included), no notch both strips the mark and evades detection, at either resolution:

| attacker's move | the mark | the tripwire |
| --- | --- | --- |
| deployed diffusion stripper | **amplifies** | not needed |
| aggressive notch, to strip it | removed | **detected** |
| gentle notch, to stay quiet | **survives** | pointless |

Remove the mark or stay quiet. Not both.

## Reading and embedding options

Beyond the default keyed mark, a few opt-in knobs trade cost for robustness:

- **`--bands ab` (multi-band).** Carry the id in two frequency bands at once. A notch that strips one band leaves the other carrying the mark, so a single-band notch is *survived*, not merely detected. The default single-band mark reads with the widest margin; multi-band spends a little of it for notch survival.
- **`--register` (geometry recovery).** An opt-in reader that searches rotation and scale, so a mark survives a moderate rotation or rescale the position-locked base read would miss. It searches only the geometry, the detector and its noise floor are unchanged, so a recovered read keeps the same threshold meaning. (A hard crop is still not recovered.)
- **`--content-bind` (forgery resistance).** Derive the per-image carriers from a perceptual hash of the image, so a mark lifted from one image cannot be replayed or forged onto another: the wrong image yields the wrong carriers, and the read fails.
- **`--fast`.** A carrier-add mode that skips the diffusion optimization entirely, so it is instant, CPU-only, and needs no model. It survives ordinary handling (JPEG, resize) like any keyed band mark, but it does **not** self-amplify under a diffusion strip, that is the optimized default path. Use it as a fast provenance tier where amplification is not required.

## Honest limits

4-bit keyed identifier today (unbounded keyspace); minutes-per-image embed for the optimized mark (`read` is instant, and `--fast` embeds instantly without amplification); operates at 256 or 512 px (512 is Stable Diffusion's native resolution and needs a 16 GB-class GPU to embed); the mark is not crop-invariant (position-locked carriers; `--register` recovers a rotation or rescale, but not a crop); validated at research scale, not production millions; the amplification claim is scoped to purification-class strippers, and the notch boundary is detected, not survived. The default invisible mark does **not** survive controllable regeneration from clean noise (for example CtrlRegen), a newer and stronger attack that rebuilds the image instead of editing it; the opt-in visible seal (`--level maximum`) is built for that case and survives it at a measured cost in visibility (see `LIMITS.md`).

## Why we publish the whole method

By publishing it, we lose nothing and gain transparency. The secret that protects the technique is the user's key, not the algorithm. Showing exactly how Backfire works gives an attacker nothing without your key, and the one algorithm-level exception, the notch, ships with its own tripwire. The `read` portion of the app needs only numpy and pillow, so you can reproduce detection, the tripwire, and our stated limits yourself. `repro/` reproduces the amplification on a public sample image; we left the tools to check our work; we publish a reader, not the scrubber.

## License

Business Source License 1.1 (free for non-commercial use) OR a commercial license, copyright Creative Mayhem UG (haftungsbeschränkt). Commercial or for-profit production use requires a paid license from Creative Mayhem (licensing@creativemayhem.com). **Every released version automatically becomes open source (AGPL-3.0-or-later) four years after its first public distribution**, so nothing here stays closed forever. Use is also subject to `EULA.md` and, for any hosted offering, `TOS.md`. Standalone, and not bundled into the Apache-2.0 provcheck binary. Full terms in `LICENSING.md`.
