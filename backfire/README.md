# Backfire

**An imperceptible, keyed image watermark that AI provenance-stripping attacks amplify instead of remove.**

Experimental research from Creative Mayhem. Dual-licensed: AGPL-3.0-or-later, or a commercial license.

## Why this exists

Creative Mayhem builds AI-generated content (rAIdio.bot, vAIdeo.bot, lysn.fm) and the provenance tooling meant to keep it accountable (provcheck). Attaching provenance is easy; making it survive the tools built to erase it is the hard and responsible part. Backfire is a first, honest attempt at a watermark that does not just resist a removal attack but turns it around. It is experimental, and we are releasing it in the open, limits and self-red-team included, because that is what is worth publishing.

## The attack, and the credit

Invisible watermarks hide bits in imperceptible pixel detail. A **regeneration** (diffusion-purification) attack removes them by running the image back through a diffusion model, which snaps it onto the natural-image manifold and drops the off-manifold perturbation, the watermark. This is published, proven work (Zhao et al., *Invisible Image Watermarks Are Provably Removable Using Generative AI*, NeurIPS 2024, [arXiv:2306.01953](https://arxiv.org/abs/2306.01953)), and open tools such as [watermarks-remover](https://github.com/guillaumemeyer/watermarks-remover) make it practical.

We are genuinely glad that work is out in the open. Backfire exists *because* of it, and the paper's own conclusion points the way: it recommends shifting toward watermarks that keep the image semantically consistent, which is exactly the direction Backfire takes. To us at Creative Mayhem this is an interesting technical challenge that we are happy to take a look at.

## The idea

Instead of hiding the mark where the purifier deletes it, Backfire **optimizes the mark to be a fixed point of the purifier**, an attractor it reconstructs. So running the attack makes the keyed identifier read *stronger*. The attack backfires. That is the thesis, and the name.

## How it works

- **Keyed carriers.** HMAC-keyed frequency carriers; only the key holder can write or read, a wrong key reads nothing.
- **Fixed-point optimization.** Embed optimizes the mark by gradient descent *through* a differentiable diffusion purifier, so the purifier reinforces it. Slow, GPU-bound.
- **Keyed detection.** A keyed, decoy-normalized correlation. numpy only: no GPU, no weights. Anyone with the key verifies instantly.

## What we measured

- **It amplifies.** After a real diffusion purifier, the identifier reads back on 10 to 12 of 12 across our test sets, *more* than before the attack; on random real-world photos, all of them.
- **It generalizes.** Against a purifier it was never tuned on, still 11 of 12. A property of diffusion purification, not one model.
- **No false positives observed.** Across the sets we ran (our internal set and samples from COCO val2017), no false positive and no wrong identifier accepted. Failing safe is the point.
- **Invisible.** Around 34 dB PSNR.

## The weakness, and its answer

A sophisticated attacker who reads this source can strip the mark with an aggressive **band-notch**; we could not make the linear mark survive that, and we say so. But the notch is loud, it carves a spectral hole natural images lack, so `read` also runs a tamper tripwire. Across 300 clean images and 81 notch configurations (feathered evasions included), no notch both strips the mark and evades detection:

| attacker's move | the mark | the tripwire |
| --- | --- | --- |
| deployed diffusion stripper | **amplifies** | not needed |
| aggressive notch, to strip it | removed | **detected** |
| gentle notch, to stay quiet | **survives** | pointless |

Remove the mark or stay quiet. Not both.

## Honest limits

4-bit keyed identifier today (unbounded keyspace); minutes-per-image embed (`read` is instant); 256 px; validated at research scale, not production millions; the amplification claim is scoped to purification-class strippers, and the notch boundary is detected, not survived.

## Why we publish the whole method

By publishing it, we lose nothing and gain transparency. The secret that protects the technique is the user's key, not the algorithm. Showing exactly how Backfire works gives an attacker nothing without your key, and the one algorithm-level exception, the notch, ships with its own tripwire. The `read` portion of the app needs only numpy and pillow, so you can reproduce detection, the tripwire, and our stated limits yourself. `repro/` reproduces the amplification on a public sample image; we left the tools to check our work; we will not, however, provide a turnkey provenance stripper.

## License

AGPL-3.0-or-later OR a commercial license, copyright Creative Mayhem UG (haftungsbeschränkt). Standalone, and not bundled into the Apache-2.0 provcheck binary.
