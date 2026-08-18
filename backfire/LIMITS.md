# Backfire: honest limits

Backfire is experimental research. This document states, plainly, what it does not do and what we tried that did not work. We would rather you know the boundaries than discover them.

## Known limits

- **Capacity.** A 4-bit keyed identifier today (16 values per key). The key is the primary identity and the keyspace is unbounded, so this suits per-copy indexing (which licensee, which distribution), not arbitrary payloads. Larger payloads with error correction are future work.
- **Embed speed.** Minutes per image on a high-end GPU, because the mark is optimized per image against a differentiable purifier. `read` is instant, numpy-only, no GPU.
- **Resolution.** Validated at 256 px.
- **Scale of validation.** Dozens to a few hundred images, not production millions. The amplification and generalization results are consistent across our sets and on random real-world photos, but they are research-scale, not a field study.
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

## Where this is honest by construction

The security is in your key, not the algorithm, so publishing the full method costs nothing (Kerckhoffs's principle). The `read` path is numpy-only, so every claim here, the amplification, the tripwire, and these limits, is reproducible by you without trusting us. See `repro/`.
