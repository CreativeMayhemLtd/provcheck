# Backfire: honest limits

Backfire is experimental research. This document states, plainly, what it does not do and what we tried that did not work. We would rather you know the boundaries than discover them.

## Known limits

- **Capacity.** A 4-bit keyed identifier today (16 values per key). The key is the primary identity and the keyspace is unbounded, so this suits per-copy indexing (which licensee, which distribution), not arbitrary payloads.
- **Embed speed.** Minutes per image on a high-end GPU, because the mark is optimized per image against a differentiable purifier. `read` is instant, numpy-only, no GPU.
- **Resolution.** Validated at both 256 and 512 px. 512 is Stable Diffusion's native resolution and gives a cleaner regeneration; embedding there needs a 16 GB-class GPU.
- **Ordinary image handling.** The mark survives JPEG (quality 50 to 90), downscaling to half size, blur, and sensor noise, but it is **not crop-invariant**: the keyed carriers are position- and scale-locked, so a hard crop or large re-composition removes it. Re-mark after cropping.
- **Scale of validation.** Research-scale, not production millions. The current mark's survival battery (diffusion and neural-codec attacks, read through the shipped reader at its default threshold) ran over **200** photos; the amplification and generalization proof over **24**; false positives **zero** over the 200-image battery and over a separate **1,000** unmarked-image decoy-normalized test; the notch tripwire over **300** clean images with an 81-config notch grid. Consistent across our sets, but not a field study.
- **Attack scope.** The amplification claim is scoped to **purification-class strippers** (diffusion regeneration attacks), which are what is deployed. It is not a general robustness claim against every possible transform.
- **The adaptive attacker.** A sophisticated attacker who reads this source can strip the mark with an aggressive band-notch. That attack is **detected, not survived** (see the tamper tripwire). If your threat model includes an adversary who is willing to visibly degrade the image and does not care about leaving detectable tamper evidence, the mark itself will not stop them, though the tripwire will flag it.
- **Controllable regeneration from clean noise.** A newer and stronger class of attack (for example CtrlRegen) does not lightly edit the image the way a diffusion-purification stripper does. It regenerates the image from scratch from random noise, guided only by the image's edges and high-level semantics, and keeps almost none of the original pixels. Because Backfire's mark lives in the pixel and frequency structure this attack discards, it **erodes the mark, and a strong enough setting removes it**. This is a genuinely harder attack than the purification-class strippers Backfire amplifies, and we do not claim to survive it. We state it here rather than let you discover it.

## What large-scale validation changed

Two issues only surfaced once we tested at scale, and we fixed both rather than paper over them:

- **The validity threshold was too permissive.** The per-bit margin was normalized against a noise floor estimated from only four decoy values, which is occasionally small by chance. Reading 1,000 unmarked images surfaced a roughly 2 percent false-positive rate at the old threshold, at *both* resolutions, not the "none" a small sample had suggested. We replaced the noise floor with a robust estimate over all the decoy carriers: the unmarked-image margin now stays below 1.6 while a true mark clears 4, and the false-positive rate over 1,000 images is zero at the default threshold. Only the confidence margin changed; the recovered identifier did not.
- **The tamper tripwire threshold is resolution-aware.** Clean images read slightly higher on the notch statistic at 512 px than at 256, so the tripwire threshold sits at 1.45: above the clean tail at both sizes, and far below any mark-stripping notch (0 strip-and-evade gaps over an 81-config grid at each resolution).

## Where this is honest by construction

The security is in your key, not the algorithm, so publishing the full method costs nothing (Kerckhoffs's principle). The `read` path is numpy-only, so every claim here, the amplification, the tripwire, and these limits, is reproducible by you without trusting us. See `repro/`.
