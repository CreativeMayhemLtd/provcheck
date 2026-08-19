# Backfire: honest limits

Backfire is experimental research. This document states, plainly, what it does not do and what we tried that did not work. We would rather you know the boundaries than discover them.

## Known limits

- **Capacity.** A 4-bit keyed identifier today (16 values per key). The key is the primary identity and the keyspace is unbounded, so this suits per-copy indexing (which licensee, which distribution), not arbitrary payloads. Larger payloads with error correction are future work.
- **Embed speed.** Minutes per image on a high-end GPU, because the mark is optimized per image against a differentiable purifier. `read` is instant, numpy-only, no GPU.
- **Resolution.** Validated at both 256 and 512 px. 512 is Stable Diffusion's native resolution and gives a cleaner regeneration; embedding there needs a 16 GB-class GPU.
- **Ordinary image handling.** The mark survives JPEG (quality 50 to 90), downscaling to half size, blur, and sensor noise, but it is **not crop-invariant**: the keyed carriers are position- and scale-locked, so a hard crop or large re-composition removes it. Re-mark after cropping.
- **Scale of validation.** Research-scale, not production millions. Amplification and generalization were measured over **24** diverse COCO val2017 photos; false positives over **1,000** unmarked images; the notch tripwire over **300** clean images with an 81-config notch grid. Consistent across our sets, but not a field study.
- **Attack scope.** The amplification claim is scoped to **purification-class strippers** (diffusion regeneration attacks), which are what is deployed. It is not a general robustness claim against every possible transform.
- **The adaptive attacker.** A sophisticated attacker who reads this source can strip the mark with an aggressive band-notch. That attack is **detected, not survived** (see the tamper tripwire). If your threat model includes an adversary who is willing to visibly degrade the image and does not care about leaving detectable tamper evidence, the mark itself will not stop them, though the tripwire will flag it.

## What we tried against the notch that did not work

We spent real effort trying to make the linear mark *survive* an aggressive notch, and it does not. We are listing the dead ends so nobody has to rediscover them:

- **Notch in the optimization loop** (single band, then a distribution of bands): forces the attacker to a visibly-damaging notch, but never achieves robustness. The worst-case attacker cost plateaus around 24 dB.
- **Content-coupled / edge-masked carriers**: masking spreads the mark's energy back into the notchable mid-band.
- **Low-frequency / structural placement**: the low-frequency annulus has too few coefficients to carry a reliable keyed mark, and masking it (for imperceptibility) spreads it upward again.
- **The notch-then-restore "trap"**: it backfires. Notching first destroys the fixed-point structure, so a subsequent purify strips the mark rather than amplifying it. Notch-plus-purify is a *stronger* attack than either alone.
- **A learned non-linear codec** (to escape the linearity the notch exploits): did not converge to the poison-fixed-point property at honest imperceptibility in our experiments.

The conclusion we reached, and state openly: a keyed watermark of this class cannot win the *survival* fight against an aggressive-notch adaptive attacker. So Backfire does not pretend to. It wins where it can (purification-class strippers, which it amplifies), and where it cannot, it makes the attack **loud** (the tamper tripwire).

## What large-scale validation changed

Two issues only surfaced once we tested at scale, and we fixed both rather than paper over them:

- **The validity threshold was too permissive.** The per-bit margin was normalized against a noise floor estimated from only four decoy values, which is occasionally small by chance. Reading 1,000 unmarked images surfaced a roughly 2 percent false-positive rate at the old threshold, at *both* resolutions, not the "none" a small sample had suggested. We replaced the noise floor with a robust estimate over all the decoy carriers: the unmarked-image margin now stays below 1.6 while a true mark clears 4, and the false-positive rate over 1,000 images is zero at the default threshold. Only the confidence margin changed; the recovered identifier did not.
- **The tamper tripwire threshold is resolution-aware.** Clean images read slightly higher on the notch statistic at 512 px than at 256, so the tripwire threshold sits at 1.45: above the clean tail at both sizes, and far below any mark-stripping notch (0 strip-and-evade gaps over an 81-config grid at each resolution).

## Where this is honest by construction

The security is in your key, not the algorithm, so publishing the full method costs nothing (Kerckhoffs's principle). The `read` path is numpy-only, so every claim here, the amplification, the tripwire, and these limits, is reproducible by you without trusting us. See `repro/`.
