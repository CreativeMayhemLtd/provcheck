#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1 OR LicenseRef-Backfire-Commercial
# Copyright (C) 2026 Creative Mayhem UG (haftungsbeschränkt)
"""Backfire: a keyed image watermark that AI provenance-stripping attacks
*amplify* instead of remove.

Diffusion "purification" (regeneration) removes ordinary invisible
watermarks by projecting the image back onto the natural-image manifold. Backfire
instead optimizes the mark to be a fixed point / attractor of that very process,
so running a stripper's own purifier makes the keyed id read *stronger*.

The mark is optimized to be a fixed point of TWO regeneration attacks at once: a
diffusion purifier AND a learned neural codec (a VAE compression re-encode, the
Zhao VAEWMAttacker class). So it survives both a diffusion stripper and a
neural-codec re-encode, not just one. (Set --codec-eot 0 --codec-iter 0 for the
diffusion-only variant, which needs no compressai.)

  embed  optimize + write a marked image        (needs torch + a diffusion model + compressai)
  read   recover the keyed id from an image      (numpy only; fast, no GPU)

The read side never loads a model: detection is a keyed FFT correlation, so it is
cheap and portable. Carriers are HMAC-keyed and generated identically for embed
and read, so only the key holder can write or read the mark.
"""
import argparse, hmac, hashlib, json, sys
import numpy as np
from PIL import Image, ImageOps

# --- watermark geometry (must match between embed and read) ---
LO, HI = 6.0, 40.0                 # mid-frequency carrier band (radial px @ 256) = band A (default)
BAND_B = (44.0, 80.0)              # optional second (higher) band for multi-band redundancy: a mark
                                   # carried in A+B survives a notch that strips either single band
ID_BITS, ID_REPS = 4, 8            # 4-bit keyed id (16 per key; keyspace unbounded), 8 reps
NBITS = ID_BITS * ID_REPS          # 32 carriers, all id (reliability over capacity)

# Diffusion purifier proxy for the OPT-IN --diff-eot path. The default path is codec-only
# (--diff-eot 0, permissive compressai fixed point) and loads no diffusion model at all, so
# the tool ships without depending on any third-party diffusion weights. When you opt into the
# diffusion path (--diff-eot > 0) you bring your own SD-family weights via --model <hf repo id>
# or --weights-dir <local dir> (Stability withdrew the official SD-2.1 line from Hugging Face).
DEFAULT_MODEL = None
DEFAULT_REV = None

def _scaled_band(lo: float, hi: float, size: int):
    """Scale an @256 radial-bin band to `size` so the same *relative* frequency
    (cycles/pixel) is used at any resolution. size=256 returns (lo, hi) unchanged, so
    every 256px mark, golden vector, and test stays byte-identical."""
    s = size / 256.0
    return lo * s, hi * s

def _key_bytes(k: str, is_hex: bool) -> bytes:
    return bytes.fromhex(k) if is_hex else k.encode()

def _tardos_code(key: bytes, n_bits: int, size: int):
    """Lazy-load the Tardos collusion-tracing code (BUSL sibling module backfire/tardos.py) so the
    default 4-bit-serial paths never import it."""
    import os as _os, sys as _sys
    _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
    from tardos import TardosCode
    return TardosCode(key, n_bits=n_bits, size=size)

def _perceptual_hash(rgb):
    """Robust 64-bit average-hash: 8x8 grayscale, sign vs mean. Stable under jpeg/resize/blur/the mark
    itself, but image-distinct. Ties the mark to THIS image's content so a mark cannot be replayed to
    another image. NOTE: not geometry-invariant (a crop/rotate changes it) - content-bind currently
    targets the non-geometric forgery/replay threat; a geometry-invariant hash is the P5.3 upgrade."""
    small = np.asarray(Image.fromarray((rgb.mean(2) * 255).astype("uint8")).resize((8, 8))).astype(np.float32)
    bits = (small > small.mean()).astype(np.uint8).flatten()
    return np.packbits(bits).tobytes()

def _content_key(key: bytes, rgb):
    """Derive a per-image carrier key = HMAC(key, perceptual_hash(image)) for --content-bind. Each
    image's mark then uses distinct carriers, so replaying/forging a mark onto another image fails that
    image's content-derived carriers (validated: replay margin ~0.08). Closes the R4 stealing vector."""
    return hmac.new(key, b"backfire/content/" + _perceptual_hash(rgb), hashlib.sha256).digest()

def keyed_carriers(key: bytes, size: int, label: bytes = b"backfire/carrier", band=None):
    """Deterministic HMAC-keyed, band-limited carriers. numpy so embed and read
    produce byte-identical patterns from the same key. `label` domain-separates
    the real carriers from the decoy carriers used for detection normalization.
    `band` selects the radial frequency band (default = band A (LO,HI)); pass BAND_B for
    the second band. Callers that use both bands MUST domain-separate the labels so the
    two bands' carriers are cryptographically independent."""
    yy, xx = np.mgrid[0:size, 0:size].astype(np.float32)
    rad = np.sqrt((xx - size/2)**2 + (yy - size/2)**2)
    bl, bh = band if band is not None else (LO, HI)
    lo, hi = _scaled_band(bl, bh, size)
    band = ((rad > lo) & (rad < hi)).astype(np.float32)
    out = np.empty((NBITS, size, size), np.float32)
    for i in range(NBITS):
        seed = int.from_bytes(hmac.new(key, label + i.to_bytes(4, "big"),
                                       hashlib.sha256).digest()[:7], "big")
        n = np.random.default_rng(seed).standard_normal((size, size)).astype(np.float32)
        F = np.fft.fftshift(np.fft.fft2(n)) * band
        c = np.real(np.fft.ifft2(np.fft.ifftshift(F))).astype(np.float32)
        c -= c.mean(); out[i] = c / (np.linalg.norm(c) + 1e-8)
    return out

LO_EDGE, HI_EDGE = 3.0, 45.0        # mid-LOW band for the content-coupled carriers

def _edge_mask(lum, size):
    """Perceptual edge/contrast mask: gradient magnitude, blurred to dilate around
    edges, times a luminance term. High where a low-frequency perturbation hides."""
    gx = np.abs(np.diff(lum, axis=1, prepend=lum[:, :1]))
    gy = np.abs(np.diff(lum, axis=0, prepend=lum[:1, :]))
    fy = np.fft.fftfreq(size)[:, None]; fx = np.fft.fftfreq(size)[None, :]
    H = np.exp(-2 * (np.pi**2) * (2.0**2) * (fx**2 + fy**2)).astype(np.float32)
    g = np.real(np.fft.ifft2(np.fft.fft2(gx + gy) * H)).astype(np.float32)
    m = (0.15 + g) * (0.5 + 0.5 * lum)
    return (m / m.mean()).astype(np.float32)

def edge_carriers(key: bytes, size: int, lum, label: bytes = b"backfire/carrier"):
    """Content-coupled carriers: mid-LOW band keyed patterns modulated by the image's
    edge mask, so the mark rides on image structure (harder to notch out, survives
    blur). Deterministic from the image content, so a verifier reconstructs them from
    the image under test (the read path passes the image being checked as `lum`)."""
    yy, xx = np.mgrid[0:size, 0:size].astype(np.float32)
    rad = np.sqrt((xx - size/2)**2 + (yy - size/2)**2)
    lo, hi = _scaled_band(LO_EDGE, HI_EDGE, size)
    band = ((rad > lo) & (rad < hi)).astype(np.float32)
    M = _edge_mask(lum, size)
    out = np.empty((NBITS, size, size), np.float32)
    for i in range(NBITS):
        seed = int.from_bytes(hmac.new(key, label + i.to_bytes(4, "big"),
                                       hashlib.sha256).digest()[:7], "big")
        n = np.random.default_rng(seed).standard_normal((size, size)).astype(np.float32)
        F = np.fft.fftshift(np.fft.fft2(n)) * band
        c = np.real(np.fft.ifft2(np.fft.ifftshift(F))).astype(np.float32) * M
        c -= c.mean(); out[i] = c / (np.linalg.norm(c) + 1e-8)
    return out

def build_carriers(key, size, mode, lum, label=b"backfire/carrier", band=None):
    """Dispatch: band (default, image-independent) or edge (content-coupled). The
    edge label is domain-separated so the two modes are cryptographically distinct.
    `band` selects the frequency band for the band mode (default = band A (LO,HI))."""
    if mode == "edge":
        return edge_carriers(key, size, lum, label + b"/edge")
    return keyed_carriers(key, size, label, band)

def target_signs(key: bytes, idv: int):
    """Per-carrier +/-1 targets: ID_REPS carriers repetition-code each id bit."""
    s = np.empty(NBITS, np.float32)
    for i in range(NBITS):
        s[i] = 1.0 if (idv >> (i % ID_BITS)) & 1 else -1.0
    return s

def decode(img_gray, C, C_decoy):
    """Soft-vote each id bit, and score trust by the weakest bit's margin over the decoy
    noise floor. The noise floor is a robust null-scale estimate from ALL the decoy
    carriers (sqrt(ID_REPS) times the std of the decoy correlations), so a single
    chance-small decoy cannot inflate the margins. On unmarked or wrong-key images every
    bit's margin sits near or below 1; a genuinely marked image clears the floor on every
    bit by a wide margin. Returns (id, mean_margin, min_margin). This normalization only
    affects the margin; the recovered id is unchanged."""
    g = img_gray - img_gray.mean()
    corr = (C * g).sum((1, 2))
    dcorr = (C_decoy * g).sum((1, 2))
    votes = [float(corr[b:NBITS:ID_BITS].sum()) for b in range(ID_BITS)]
    # A bit-vote is a sum of ID_REPS carrier correlations, so under the null its scale is
    # sqrt(ID_REPS) * (per-carrier corr std). Estimating that std from all NBITS decoy
    # correlations is far more stable than the old mean of only ID_BITS decoy bit-sums,
    # which had a chance-small denominator ~2% of the time and produced false positives.
    dnoise = float(np.sqrt(ID_REPS) * dcorr.std()) + 1e-8
    idv = sum((1 << b) for b in range(ID_BITS) if votes[b] > 0)
    margins = [abs(v) / dnoise for v in votes]
    return idv, float(np.mean(margins)), float(min(margins))

def decode_keyed(img_gray, key: bytes, size: int, mode: str = "band"):
    # edge carriers are rebuilt from the image under test (img_gray); band carriers
    # are image-independent, so img_gray is ignored for band.
    return decode(img_gray, build_carriers(key, size, mode, img_gray, b"backfire/carrier"),
                  build_carriers(key, size, mode, img_gray, b"backfire/decoy"))

def decode_multiband(img_gray, key: bytes, size: int):
    """Combined band-A + band-B decode (P1 multi-band): sum each id bit's correlations across BOTH
    bands, normalize by the combined decoy floor. A mark carried in A+B reads here even after a notch
    strips one band (the surviving band carries it). Band B is domain-separated (label '/B' + BAND_B)
    so the two bands are keyed-independent. Backward-compat: a single-band-A mark still decodes (band B
    just contributes ~null); read it with the default single-band path for the identical legacy margin."""
    g = img_gray - img_gray.mean()
    CA = build_carriers(key, size, "band", img_gray, b"backfire/carrier")
    DA = build_carriers(key, size, "band", img_gray, b"backfire/decoy")
    CB = build_carriers(key, size, "band", img_gray, b"backfire/carrier/B", BAND_B)
    DB = build_carriers(key, size, "band", img_gray, b"backfire/decoy/B", BAND_B)
    corr = (CA * g).sum((1, 2)) + (CB * g).sum((1, 2))
    dcorr = np.concatenate([(DA * g).sum((1, 2)), (DB * g).sum((1, 2))])
    votes = [float(corr[b:NBITS:ID_BITS].sum()) for b in range(ID_BITS)]
    dnoise = float(np.sqrt(ID_REPS) * dcorr.std()) + 1e-8
    idv = sum((1 << b) for b in range(ID_BITS) if votes[b] > 0)
    margins = [abs(v) / dnoise for v in votes]
    return idv, float(np.mean(margins)), float(min(margins))

def _band_notch_np(rgb, size):
    """Numpy band-notch (suppress the LO..HI ring) for per-image robustness assessment."""
    yy, xx = np.mgrid[0:size, 0:size].astype(np.float32)
    rad = np.sqrt((xx - size/2)**2 + (yy - size/2)**2)
    lo, hi = _scaled_band(LO, HI, size)
    band = (rad > lo) & (rad < hi)
    out = np.empty_like(rgb)
    for c in range(rgb.shape[2]):
        F = np.fft.fftshift(np.fft.fft2(rgb[:, :, c])); F[band] = 0.0
        out[:, :, c] = np.real(np.fft.ifft2(np.fft.ifftshift(F)))
    return np.clip(out, 0, 1)

# A sophisticated attacker can strip the mark with an aggressive band-notch, but that
# notch is loud: it carves an anomalous suppressed ring into the FFT. Natural images have
# a smooth power-law radial spectrum, so a notch shows up as a localized dip far below
# trend. Every notch strong enough to strip the mark clears the threshold (measured over
# 300 clean COCO images: clean tops out near 1.15 at 256px and 1.39 at 512px, while
# mark-stripping notches read 4 and up), so the mark and this tripwire together leave the
# attacker no move that both removes the mark and stays quiet. 1.45 sits above the clean
# tail at both resolutions and well below every stripping notch (0 gaps over an 81-config
# feathered-notch grid at each size).
NOTCH_TAMPER_THRESHOLD = 1.45

def notch_tamper_stat(gray, size):
    """Deepest below-trend suppression in the radial power spectrum. > threshold means a
    band-notch was very likely applied (tamper evidence). numpy only."""
    yy, xx = np.mgrid[0:size, 0:size].astype(np.float32)
    rbin = np.sqrt((xx - size/2)**2 + (yy - size/2)**2).astype(np.int32)
    rmax = min(size // 2, 120)
    F = np.fft.fftshift(np.fft.fft2(gray)); p = F.real**2 + F.imag**2
    L = np.array([np.log(p[rbin == r].mean() + 1e-8) if (rbin == r).any() else 0.0 for r in range(rmax)])
    r = np.arange(1, rmax); y = L[1:rmax]; x = np.log(r)
    if x.size < 6:                                         # too few radial bins to fit a degree-4 trend
        return 0.0
    coef = np.polyfit(x, y, 4); base = np.polyval(coef, x)
    resid = y - base
    sd = float(np.std(resid))
    # Refit the trend without deep dips. On a near-flat spectrum (a solid or very
    # low-texture image) the first fit is already near-perfect, so sd is ~0 and
    # there are no dips to drop; keep every point then. Never let the mask collapse
    # below what a degree-4 fit needs, or np.polyfit raises on an empty vector.
    keep = resid > -sd if sd > 1e-9 else np.ones(resid.shape, dtype=bool)
    if int(keep.sum()) >= 6:
        coef = np.polyfit(x[keep], y[keep], 4); base = np.polyval(coef, x)
    dip = base - y
    return float(np.convolve(np.clip(dip, 0, None), np.ones(5) / 5, mode="same").max())

# ------------------------------- read (numpy) -------------------------------
# ---------------------------- geometry registration -------------------------
# The keyed carriers live at fixed FFT-band positions in the size x size read frame, so a
# rotation or a crop (a zoom) moves the mark off where the reader looks and the base read
# collapses. Because this mark's genuine margin (~9-10) towers over the wrong-key null (~1),
# we can RECOVER geometry at read time with a small search: rotate-back / re-pad over a grid,
# decode each candidate, and keep the strongest id-consistent one. Validated null-safe: over
# rotated/cropped corpora the wrong-key search max-margin stays ~1.0-1.5, far under threshold,
# so searching does NOT manufacture false positives. Coarse-to-fine keeps it ~90 decodes.
def register_search(rgb, key, sizes, carriers, expect, max_deg, max_pad):
    """Coarse-to-fine rotation x scale(pad) search over the standard read sizes. Returns
    (idv, conf, margin, size, angle, pad) for the best candidate: when `expect` is given,
    id-matching candidates win over non-matching, then by margin; otherwise the max-margin
    candidate. A rotated mark validates at neither size, so both are searched (like the base
    read). Only the geometry is searched, the detector and its null are unchanged, so a
    recovered read carries the same threshold meaning (validated null-safe). Band carriers are
    image-independent so they are built ONCE per size and reused across the grid (the search is
    ~100x cheaper than rebuilding per candidate); edge carriers are content-coupled so they are
    rebuilt per candidate."""
    def score(c):
        idv, _conf, margin = c
        return (1 if (expect is not None and idv == expect) else 0, margin)
    best = None; bs = ba = bp = None
    for size in sizes:
        if carriers == "band":
            C = build_carriers(key, size, "band", None, b"backfire/carrier")
            Cd = build_carriers(key, size, "band", None, b"backfire/decoy")
            decode_at = lambda gray, C=C, Cd=Cd: decode(gray, C, Cd)
        else:
            decode_at = lambda gray, size=size: decode_keyed(gray, key, size, carriers)
        def variant(A, P, size=size, decode_at=None):
            im = rgb
            if A != 0.0:
                im = im.rotate(A, resample=Image.BICUBIC, expand=False)
            if P > 0.0:
                w, h = im.size
                im = ImageOps.expand(im, border=(int(w * P), int(h * P), int(w * P), int(h * P)))
            gray = (np.asarray(im.resize((size, size)), np.float32) / 255.0).mean(2)
            return decode_at(gray)
        def grid_max(angles, pads, best, bs, ba, bp):
            for A in angles:
                for P in pads:
                    c = variant(A, P, decode_at=decode_at)
                    if best is None or score(c) > score(best):
                        best, bs, ba, bp = c, size, A, P
            return best, bs, ba, bp
        coarse_a = list(np.arange(-max_deg, max_deg + 1e-6, 2.0))
        # Scale-matched pad grid: a center-crop to fraction s needs pad (1/s - 1)/2, which is
        # nonlinear, so a LINEAR pad grid over-samples shallow crops and straddles specific mid
        # crops (the crop-90 dip: 72% recovery). Spacing the grid uniformly in SCALE hits every
        # crop level evenly and lifts mid-crop recovery to ~93% at no false-positive cost.
        s_min = 1.0 / (1.0 + 2.0 * max_pad)
        coarse_p = sorted(set([0.0] + [round((1.0 / s - 1.0) / 2.0, 4)
                                       for s in np.arange(1.0, s_min - 1e-6, -0.03)]))
        best, bs, ba, bp = grid_max(coarse_a, coarse_p, best, bs, ba, bp)
        fine_a = list(np.arange(ba - 1.5, ba + 1.5 + 1e-6, 0.5))
        fine_p = [round(x, 4) for x in np.arange(max(0.0, bp - 0.03), bp + 0.03 + 1e-6, 0.005)]
        best, bs, ba, bp = grid_max(fine_a, fine_p, best, bs, ba, bp)
    idv, conf, margin = best
    return idv, conf, margin, bs, round(ba, 2), round(bp, 3)

def read_cmd(a):
    key = _key_bytes(a.key, a.hexkey)
    rgb = Image.open(a.infile).convert("RGB")
    if getattr(a, "content_bind", False):   # P5: per-image carrier key -> mark can't be replayed/forged
        key = _content_key(key, np.asarray(rgb.resize((256, 256)), np.float32) / 255.0)
    # Try the requested size first, then the other standard resolution, so a mark
    # embedded at either 256 or 512 is found without the caller guessing. Stop at
    # the first size that validates; otherwise keep the requested size's result.
    sizes = [a.size] + [s for s in (512, 256) if s != a.size]
    best = None
    for size in sizes:
        gray = (np.asarray(rgb.resize((size, size)), np.float32) / 255.0).mean(2)
        if getattr(a, "bands", "a") == "ab" and a.carriers == "band":
            idv, conf, margin = decode_multiband(gray, key, size)   # combined band A+B (multi-band marks)
        else:
            idv, conf, margin = decode_keyed(gray, key, size, a.carriers)
        valid = bool(margin > a.threshold)   # every id bit must clear the decoy noise floor
        # The tamper tripwire is advisory: never let it kill the whole read. Any
        # failure degrades to 0.0 (no tamper detected) so read always emits JSON.
        try:
            tamper = notch_tamper_stat(gray, size)
        except Exception:
            tamper = 0.0
        if best is None or valid:
            best = (size, idv, conf, margin, valid, tamper)
        if valid:
            break
    size, idv, conf, margin, valid, tamper = best
    # Opt-in geometry recovery: only when the base read failed, so the default read path and its
    # cost stay exactly as before. A recovered read reports via="register" plus the angle/scale.
    via, reg_angle, reg_pad = "base", 0.0, 0.0
    if getattr(a, "register", False) and not valid:
        sizes_try = [a.size] + [s for s in (512, 256) if s != a.size]
        ridv, rconf, rmargin, rsize, rangle, rpad = register_search(
            rgb, key, sizes_try, a.carriers, a.expect, a.register_max_deg, a.register_max_pad)
        if rmargin > a.threshold and (a.expect is None or ridv == a.expect):
            size, idv, conf, margin, valid = rsize, ridv, rconf, rmargin, True
            tamper = 0.0   # notch tripwire is defined pre-geometry-correction; advisory only here
            via, reg_angle, reg_pad = "register", rangle, rpad
    out = {"id": idv, "id_hex": f"0x{idv:X}", "confidence": round(conf, 4),
           "min_bit_margin": round(margin, 4), "valid": valid, "size": size, "via": via,
           "match": (idv == a.expect) if a.expect is not None else None,
           "notch_tamper": {"stat": round(tamper, 3), "detected": tamper > a.notch_threshold}}
    if via == "register":
        out["register"] = {"rotation_deg": reg_angle, "pad_frac": reg_pad}
    print(json.dumps(out))
    if a.expect is not None:
        sys.exit(0 if (valid and idv == a.expect) else 1)

# ------------------------------- embed (torch) ------------------------------
# --- visibility <-> robustness SLIDER (preset over the existing energy/masking knobs) ---
# One control the UI exposes as a slider. Higher levels are more invisible (higher target PSNR + more
# perceptual masking); lower levels are louder and harder to remove. More masking at the invisible end buys
# imperceptibility; less masking at the robust end buys survival. The 'class' is the robustness class by
# design; exact per-level survival rates should be confirmed by a validation sweep before the UI presents
# them as promises.
LEVELS = {
    #  name        psnr  pmask  luma  codec_eot  bands  robustness class (user-facing)
    # Visibility descriptions are measured (looked at); survival is stated as a direction, not a rate.
    # The default embed path is the neural-codec fixed point: it SURVIVES a re-encode, it does not amplify.
    # Per-level survival rates come from the validation sweep; only 'maximum' has one at scale (see LIMITS.md).
    "invisible": (42.0, 0.35, True, 1.2, "a",  "Invisible. Survives everyday handling (recompression, resize, blur, light crop). Not built to survive AI regeneration."),
    "balanced":  (38.0, 0.25, True, 1.2, "a",  "Near-invisible. Everyday handling and standard re-encoding."),
    "durable":   (34.0, 0.15, True, 1.2, "a",  "Faint (slightly visible on smooth areas). Everyday handling plus heavier compression and re-encoding."),
    "robust":    (30.0, 0.08, True, 1.2, "a",  "Visibly textured. Aggressive handling and strong re-encode survival, including a light diffusion re-encode."),
    "maximum":   (30.0, 0.00, True, 1.2, "ab", "Visible seal (multi-band, luminance-only). The validated strip-proof config: built to survive AI regeneration (CtrlRegen) and neural-codec re-encoding at a visible cost. See LIMITS.md for measured survival and visibility."),
}
LEVEL_ORDER = ["invisible", "balanced", "durable", "robust", "maximum"]

def _apply_level(a):
    """If --level is set, override the energy/masking knobs from the preset (unless the user also passed the
    knob explicitly, which wins). Prints the resolved config + the honest robustness class."""
    lvl = getattr(a, "level", None)
    if not lvl:
        return
    psnr, pmask, luma, codec_eot, bands, klass = LEVELS[lvl]
    passed = getattr(a, "_explicit", set())
    if "target_psnr" not in passed: a.target_psnr = psnr
    if "pmask" not in passed: a.pmask = pmask
    if "luma" not in passed: a.luma = a.luma or luma
    if "codec_eot" not in passed: a.codec_eot = codec_eot
    if "bands" not in passed and hasattr(a, "bands"): a.bands = bands
    n = LEVEL_ORDER.index(lvl)
    bar = "".join("#" if i <= n else "-" for i in range(len(LEVEL_ORDER)))
    print(f"backfire: level={lvl}  [invisible {bar} robust]  target_psnr={a.target_psnr:.0f} pmask={a.pmask} luma={a.luma} bands={getattr(a, 'bands', 'a')}", file=sys.stderr, flush=True)
    print(f"backfire:   {klass}", file=sys.stderr, flush=True)

def embed_cmd(a):
    _apply_level(a)
    if not getattr(a, "tardos", False) and a.serial is None:
        sys.exit("backfire embed: --serial is required (or use --tardos --seat for a per-seat codeword)")
    if getattr(a, "fast", False):
        # FAST carrier-add mode (M1): no diffusion model, no optimization -> ~instant and CPU-portable
        # (numpy only). Adds the composite keyed mark (target_signs . carriers) projected to the target
        # PSNR; the decoder correlates against exactly that, so it self-reads with a wide margin. It
        # survives normal handling (JPEG/scale) like any keyed band mark, but does NOT self-amplify under
        # a diffusion strip -- that is the 'poison' optimization path below. Use for the fast provenance
        # tier and for non-poisoned frames in selective/N-frame keying.
        key = _key_bytes(a.key, a.hexkey)
        host_np = np.asarray(Image.open(a.infile).convert("RGB").resize((a.size, a.size)), np.float32) / 255.0
        if getattr(a, "content_bind", False):
            key = _content_key(key, np.asarray(Image.open(a.infile).convert("RGB").resize((256, 256)), np.float32) / 255.0)
        lum = host_np.mean(2)
        if getattr(a, "tardos", False):
            tc = _tardos_code(key, a.tardos_bits, a.size); C = tc.carriers(); ts = tc.target_signs(a.seat).astype(np.float32)
        elif getattr(a, "bands", "a") == "ab" and a.carriers == "band":
            CA = build_carriers(key, a.size, "band", lum, b"backfire/carrier")
            CB = build_carriers(key, a.size, "band", lum, b"backfire/carrier/B", BAND_B)
            C = np.concatenate([CA, CB], 0); _ts = target_signs(key, a.serial); ts = np.concatenate([_ts, _ts])
        else:
            C = build_carriers(key, a.size, a.carriers, lum); ts = target_signs(key, a.serial)
        mark = (ts[:, None, None] * C).sum(0)                       # composite keyed mark (H,W)
        target_rms = 10 ** (-a.target_psnr / 20.0)
        d = mark * (target_rms / max(float(np.sqrt((mark ** 2).mean())), 1e-12))   # project to target PSNR
        marked = np.clip(host_np + d[:, :, None], 0, 1)
        Image.fromarray((marked * 255).astype("uint8")).save(a.out)
        psnr = 10 * np.log10(1.0 / max(float(((marked - host_np) ** 2).mean()), 1e-12))
        g = marked.mean(2)
        if getattr(a, "tardos", False):
            sc = _tardos_code(key, a.tardos_bits, a.size).scores(g, [a.seat])[0]
            print(f"backfire: wrote {a.out} (FAST) PSNR={psnr:.1f}dB tardos seat={a.seat} self-score={sc:.1f}", file=sys.stderr, flush=True)
        elif getattr(a, "bands", "a") == "ab" and a.carriers == "band":
            idv, _c, margin = decode_multiband(g, key, a.size)
            print(f"backfire: wrote {a.out} (FAST) PSNR={psnr:.1f}dB self-read id=0x{idv:X} margin={margin:.2f}", file=sys.stderr, flush=True)
        else:
            idv, _c, margin = decode_keyed(g, key, a.size, a.carriers)
            print(f"backfire: wrote {a.out} (FAST) PSNR={psnr:.1f}dB self-read id=0x{idv:X} margin={margin:.2f}", file=sys.stderr, flush=True)
        return
    # Offline / local-weights containment (--weights-dir or --offline): forbid any network
    # fetch of the diffusion model. Set the HF offline env BEFORE importing diffusers/transformers
    # so the hub layer starts offline, and thread local_files_only through the model loads below.
    # This lets a sandbox guarantee the tool physically cannot reach the network for weights,
    # rather than merely being configured not to.
    import os as _os
    offline = bool(getattr(a, "offline", False) or getattr(a, "weights_dir", None))
    if offline:
        _os.environ["HF_HUB_OFFLINE"] = "1"
        _os.environ["TRANSFORMERS_OFFLINE"] = "1"
    # Self-heal for callers that scrub the environment (e.g. a sandbox/containment wrapper that
    # env_clear()s and re-adds a short allowlist). torch computes its dynamo/inductor cache path
    # via getpass.getuser(); with no USERNAME/USER/LOGNAME/LNAME it falls back to `import pwd`,
    # which does not exist on Windows and raises. That kills the lazy `import torch._dynamo` under
    # torch.optim.Adam and makes the embed unconstructible. Guarantee a username so a scrubbed-env
    # caller (this tool gets shelled by other software) does not crash on it.
    if not any(_os.environ.get(v) for v in ("LOGNAME", "USER", "LNAME", "USERNAME")):
        _os.environ["USERNAME"] = "backfire"
    import torch
    import torch.nn.functional as F
    # Diagnostic (not a fix): pre-load torch._dynamo here so that IF it fails, the real error
    # surfaces at its origin instead of resurfacing later as a misleading mega-cache "Artifact of
    # type=precompile already registered" double-registration under torch.optim.Adam (the first
    # failed import is evicted from sys.modules, the retry re-runs its module body). With the
    # username self-heal above this succeeds; backfire never calls torch.compile, so it is inert.
    try:
        import torch._dynamo  # noqa: F401
    except Exception:
        pass
    from diffusers import AutoencoderKL, UNet2DConditionModel, DDIMScheduler
    from transformers import CLIPTextModel, CLIPTokenizer
    dev = a.device
    def log(m): print(f"backfire: {m}", file=sys.stderr, flush=True)

    N_INFER = 20
    strengths = [float(s) for s in a.eot_strengths.split(",")]
    # One or more purifier backends. Default is the single model (unchanged behavior);
    # --models "id1,id2,..." optimizes the mark to be a fixed point of ALL of them, so
    # it generalizes past one backend. Cost scales ~linearly with the model count.
    if getattr(a, "weights_dir", None):
        model_ids = [a.weights_dir]      # local dir overrides --model/--models and implies offline
    else:
        model_ids = [m.strip() for m in a.models.split(",")] if a.models else [a.model]

    def build_purifier(model_id):
        # Pin the tested revision for the default mirror; a custom --model uses --revision
        # or main. Keeps the default reproducible now that the upstream weights are gone.
        rev = a.revision if a.revision else (DEFAULT_REV if model_id == DEFAULT_MODEL else None)
        log(f"loading diffusion purifier proxy: {model_id}{' @ ' + rev[:12] if rev else ''} ...")
        # force fp32 on every backend: some models (e.g. distilled ones) ship fp16
        # components, which mismatch the fp32 pipeline in cross-attention.
        # local_files_only=offline: when --offline/--weights-dir is set, from_pretrained never
        # touches the network and fails fast if a required file is not already local.
        vae = AutoencoderKL.from_pretrained(model_id, subfolder="vae", revision=rev, local_files_only=offline).to(dev).float().eval()
        unet = UNet2DConditionModel.from_pretrained(model_id, subfolder="unet", revision=rev, local_files_only=offline).to(dev).float().eval()
        tok = CLIPTokenizer.from_pretrained(model_id, subfolder="tokenizer", revision=rev, local_files_only=offline)
        txt = CLIPTextModel.from_pretrained(model_id, subfolder="text_encoder", revision=rev, local_files_only=offline).to(dev).float().eval()
        sched = DDIMScheduler.from_pretrained(model_id, subfolder="scheduler", revision=rev, local_files_only=offline)
        for m in (vae, unet, txt):
            for p in m.parameters(): p.requires_grad_(False)
        unet.enable_gradient_checkpointing()
        with torch.no_grad():
            ids = tok("", padding="max_length", max_length=tok.model_max_length, return_tensors="pt").input_ids.to(dev)
            null_emb = txt(ids)[0]
        SCALE = vae.config.scaling_factor
        sched.set_timesteps(N_INFER, device=dev)
        ts_by_s = {s: sched.timesteps[N_INFER - max(1, int(N_INFER*s)):] for s in strengths}
        def purify(x, noise, ts):
            lat = vae.encode(x*2-1).latent_dist.mean * SCALE
            z = sched.add_noise(lat, noise, ts[0].expand(lat.shape[0]))
            for t in ts:
                z = sched.step(unet(z, t, encoder_hidden_states=null_emb.expand(z.shape[0], -1, -1)).sample, t, z).prev_sample
            return (vae.decode(z/SCALE).sample + 1)/2
        return {"purify": purify, "ts_by_s": ts_by_s, "in_ch": unet.config.in_channels}

    # --diff-eot 0 => codec-only: never load a diffusion model (the license-clean path). Requires a codec term.
    if a.diff_eot <= 0 and a.codec_eot <= 0 and a.codec_iter <= 0:
        raise SystemExit("backfire: --diff-eot 0 needs a codec fixed point (--codec-eot/--codec-iter > 0), else no regeneration target")
    if a.diff_eot > 0 and not (a.weights_dir or a.models or a.model):
        raise SystemExit("backfire: --diff-eot > 0 needs SD-family weights you supply via --model <hf repo id> or --weights-dir <local dir>; the default codec-only path (--diff-eot 0) needs no diffusion model")
    purifiers = [build_purifier(mid) for mid in model_ids] if a.diff_eot > 0 else []
    lat_ch = purifiers[0]["in_ch"] if purifiers else 4
    if any(p["in_ch"] != lat_ch for p in purifiers):
        raise SystemExit("backfire: --models must share a latent channel count (SD-family)")

    # Neural-codec EOT (the 3.0 addition). Diffusion purification is not the only
    # regeneration attack: a learned compression autoencoder (the Zhao VAEWMAttacker class)
    # re-encodes the image through a trained bottleneck and drops off-manifold detail. We
    # add a lean codec ensemble (bmshj2018 quality 1 and 3) as extra fixed-point targets, so
    # the mark survives a neural-codec re-encode too, plus a focused ITERATED-codec term
    # (bmshj q1 applied twice) that buys down the one axis pure single-pass EOT leaves weak.
    # Off (0 weights) => no compressai needed and behavior is the diffusion-only 2.x mark.
    codecs = None
    if a.codec_eot > 0 or a.codec_iter > 0:
        from compressai.zoo import bmshj2018_factorized
        log("loading neural codec ensemble bmshj2018 q1,q3 (train-mode) ...")
        codecs = [bmshj2018_factorized(quality=q, pretrained=True).to(dev).float() for q in (1, 3)]
        for cm in codecs:
            for p in cm.parameters(): p.requires_grad_(False)
            cm.train()                              # train-mode: differentiable, no quantization round
        cq1 = codecs[0]
        def codec_single(x, cm):
            x512 = F.interpolate(x, (512, 512), mode="bilinear", align_corners=False)
            o = cm(x512)["x_hat"].clamp(0, 1)
            return F.interpolate(o, (a.size, a.size), mode="bilinear", align_corners=False)
        def codec_iterated(x):                      # the focused iterated term: q1 applied twice
            x512 = F.interpolate(x, (512, 512), mode="bilinear", align_corners=False)
            o = cq1(cq1(x512)["x_hat"].clamp(0, 1))["x_hat"].clamp(0, 1)
            return F.interpolate(o, (a.size, a.size), mode="bilinear", align_corners=False)

    key = _key_bytes(a.key, a.hexkey)
    host_np = np.asarray(Image.open(a.infile).convert("RGB").resize((a.size, a.size)), np.float32)/255.0
    if getattr(a, "content_bind", False):   # P5: derive a per-image carrier key from the clean host
        key = _content_key(key, np.asarray(Image.open(a.infile).convert("RGB").resize((256, 256)), np.float32)/255.0)
    host = torch.from_numpy(host_np).permute(2, 0, 1).unsqueeze(0).to(dev)
    # edge carriers are content-coupled (built from the host luminance); band ignores it.
    if getattr(a, "tardos", False):
        # P2: embed a per-seat Tardos collusion-tracing codeword instead of the 4-bit serial. n keyed
        # band carriers carry the codeword signs; the same EOT loss below optimizes them. Trace a
        # (possibly colluded) copy with the 'trace' subcommand.
        tc = _tardos_code(key, a.tardos_bits, a.size)
        C = torch.from_numpy(tc.carriers()).to(dev)
        tsign = torch.from_numpy(tc.target_signs(a.seat).astype(np.float32)).to(dev)
    elif getattr(a, "bands", "a") == "ab" and a.carriers == "band":
        # multi-band (P1): embed the same keyed id in band A AND a domain-separated band B, so a notch
        # of EITHER band leaves the other carrying the mark. Stacking the carriers + repeating the
        # target signs makes the whole EOT loss below optimize both bands at once, within the one
        # shared PSNR budget (the optimizer splits energy across bands).
        _lum = host_np.mean(2)
        CA = build_carriers(key, a.size, "band", _lum, b"backfire/carrier")
        CB = build_carriers(key, a.size, "band", _lum, b"backfire/carrier/B", BAND_B)
        C = torch.from_numpy(np.concatenate([CA, CB], 0)).to(dev)
        _ts = target_signs(key, a.serial)
        tsign = torch.from_numpy(np.concatenate([_ts, _ts])).to(dev)
    else:
        C = torch.from_numpy(build_carriers(key, a.size, a.carriers, host_np.mean(2))).to(dev)
        tsign = torch.from_numpy(target_signs(key, a.serial)).to(dev)
    def corrs(img):
        g = img.mean(1); g = g - g.mean((-1, -2), keepdim=True)
        return (C * g).sum((-1, -2))
    gtor = torch.Generator(dev).manual_seed(1234)
    lat_shape = (1, lat_ch, a.size//8, a.size//8)
    noises = [torch.randn(lat_shape, generator=gtor, device=dev) for _ in range(a.eot_noises)]

    # Content-adaptive strength: eps*tanh(w) sets the mark's *shape*; we then project
    # it to a fixed perturbation energy (a target PSNR floor). PSNR is a function of
    # perturbation RMS, so this gives every image the same GLOBAL mark energy regardless
    # of content, lifting busy/high-frequency images that otherwise under-use the budget.
    #
    # --pmask adds SPATIAL (perceptual / local-SNR) adaptivity on top: weight the mark by
    # the host's local texture (local luminance std) so energy concentrates where the eye
    # can't see it (detail) and is suppressed in flat regions (the visible-swirl areas),
    # at the SAME global RMS -> survival budget preserved, flat-region visibility cut.
    # floor keeps a minimum everywhere so the mark still covers flat content. 0 = off.
    g1 = host.mean(1, keepdim=True)
    mu = F.avg_pool2d(g1, 7, stride=1, padding=3)
    sig = (F.avg_pool2d(g1 * g1, 7, stride=1, padding=3) - mu * mu).clamp_min(0.0).sqrt()  # local luminance std
    if a.pmask > 0:
        sal = sig / sig.amax().clamp_min(1e-6)
        pmask = a.pmask + (1.0 - a.pmask) * sal        # in [pmask, 1]
    else:
        pmask = 1.0
    if a.auto:
        # Content-adaptive per-image energy computed UP FRONT from a perceptual (Noise
        # Visibility Function / JND) budget, so the mark is OPTIMIZED at this energy. Rescaling
        # a mark that was optimized at a different energy breaks the diffusion-fixed-point
        # survival (v1 bug: every auto mark came back "weak"). The JND budget is pure host math;
        # pmask is the shape proxy for the percentile normalization, so this needs no optimized
        # mark and can be calibrated offline. Flat images -> quiet (high dB), busy -> louder
        # (low dB, better survival), at constant visual invisibility.
        jnd = a.jnd_floor + a.jnd_gain * sig
        shp = pmask if a.pmask > 0 else torch.ones_like(g1)
        shp_rms = shp.pow(2).mean().clamp_min(1e-12).sqrt()
        p95 = torch.quantile((shp / jnd.clamp_min(1e-6)).flatten(), 0.95).clamp_min(1e-9)
        target_rms = float((a.jnd_target * shp_rms / p95).item())
        log(f"auto-psnr: content-adaptive energy = PSNR {-20.0 * np.log10(max(target_rms, 1e-12)):.1f}dB for this image")
    else:
        target_rms = 10 ** (-a.target_psnr / 20.0)
    def make_x(w):
        d = a.eps * torch.tanh(w) * pmask
        if a.luma:                                  # luminance-only: no chroma artifacts; the reader is luma-only anyway
            d = d.mean(1, keepdim=True).expand_as(d)
        d = d * (target_rms / d.pow(2).mean().clamp_min(1e-12).sqrt())
        return (host + d).clamp(0, 1)

    _iddesc = f"tardos seat {a.seat}" if getattr(a, "tardos", False) else f"id 0x{a.serial:X}"
    log(f"optimizing keyed poison ({_iddesc}, {a.iters} iters, target {a.target_psnr:.0f}dB, "
        f"EOT strengths {strengths} x {len(purifiers)} backend(s))...")
    # optional notch-in-the-loop: keep the mark readable after a band-notch, so the
    # optimizer parks energy the notch cannot reach (carrier placement alone does not
    # force this; the objective must).
    if a.notch_eot > 0:
        yy2, xx2 = np.mgrid[0:a.size, 0:a.size].astype(np.float32)
        rad2 = torch.from_numpy(np.sqrt((xx2 - a.size/2)**2 + (yy2 - a.size/2)**2).astype(np.float32)).to(dev)
        nrng = np.random.default_rng(1234)
        one = torch.tensor(1.0, device=dev)
        def dnotch(img, lo, hi, res):
            keep = torch.where((rad2 > lo) & (rad2 < hi), torch.tensor(res, device=dev), one)
            Fm = torch.fft.fftshift(torch.fft.fft2(img), dim=(-2, -1)) * keep
            return torch.real(torch.fft.ifft2(torch.fft.ifftshift(Fm, dim=(-2, -1))))
        nsc = a.size / 256.0                 # @256 band units, scaled to the embed resolution
        def sample_notch():  # a family of band-stops, not one fixed notch
            lo = float(nrng.uniform(3, 18)) * nsc; hi = lo + float(nrng.uniform(12, 44)) * nsc
            res = float(nrng.uniform(0.0, 0.3)); return lo, hi, res
    w = (0.01 * torch.randn_like(host)).requires_grad_(True)   # tiny nonzero: the RMS projection has no defined direction at w=0
    opt = torch.optim.Adam([w], lr=a.lr)
    eot_terms = [(pf, s, n) for pf in purifiers for s in strengths for n in noises]
    n_eot = len(eot_terms)
    for it in range(a.iters):
        opt.zero_grad()
        x = make_x(w)                              # graph: w -> x
        # Quantization-aware: round-trip the mark through 8-bit (straight-through
        # estimator, forward = quantize, backward = identity) so the mark is OPTIMIZED
        # to survive a PNG save. Without this, a quiet mark reads valid in float but
        # drops below threshold once written to 8-bit (the quantization tax hits quiet
        # marks hardest). All the EOT/read terms below now see the saved-file pixels.
        x = x + (torch.round(x.clamp(0.0, 1.0) * 255.0) / 255.0 - x).detach()
        # Accumulate gradients over the EOT purifier passes one at a time, freeing each
        # pass's autograd graph before building the next. Peak memory is ONE purifier
        # backprop, not all n_eot at once, which is what lets 512px embeds fit: the
        # differentiable purifier (not the mark) is the memory cost, and it scales with
        # the number of live EOT graphs. Math is identical to one stacked .mean().backward().
        xd = x.detach().requires_grad_(True)
        post = 0.0
        for pf, s, n in eot_terms:
            li = (corrs(pf["purify"](xd, n, pf["ts_by_s"][s])) * tsign).mean()
            (-a.diff_eot * li / n_eot).backward()  # d(-post/n_eot)/dxd, accumulated into xd.grad
            post += li.item() / n_eot
        if codecs is not None:                     # neural-codec EOT, accumulated one term at a time like the diffusion passes
            for cm in codecs:
                lc = (corrs(codec_single(xd, cm)) * tsign).mean()
                (-a.codec_eot * lc / len(codecs)).backward()
            lit = (corrs(codec_iterated(xd)) * tsign).mean()
            (-a.codec_iter * lit).backward()       # focused iterated-codec term, full weight
        extra = -a.direct * (corrs(xd) * tsign).mean()   # pre-attack readability term
        if a.notch_eot > 0:
            lo, hi, res = sample_notch()
            extra = extra - a.notch_eot * (corrs(dnotch(xd, lo, hi, res)) * tsign).mean()
        extra.backward()                           # accumulate the direct/notch grads into xd.grad
        x.backward(xd.grad)                         # propagate xd.grad through make_x back to w
        opt.step()
        if it % 40 == 0 or it == a.iters-1:
            log(f"  iter {it:4d}  E[post]={post:+.3f}")

    marked = make_x(w).detach()
    Image.fromarray((marked[0].permute(1, 2, 0).cpu().numpy() * 255).clip(0, 255).astype("uint8")).save(a.out)
    # Honest self-read + assess: reload the SAVED 8-bit file so every number reported is what
    # a downstream reader actually gets after the PNG round-trip, not the optimistic float mark.
    m_np = np.asarray(Image.open(a.out).convert("RGB"), np.float32) / 255.0
    marked = torch.from_numpy(m_np).permute(2, 0, 1).unsqueeze(0).to(dev)
    psnr = 10 * np.log10(1.0 / max(float(((m_np - host_np) ** 2).mean()), 1e-12))
    if getattr(a, "tardos", False):
        tc = _tardos_code(key, a.tardos_bits, a.size)
        sc = tc.scores(m_np.mean(2), [a.seat])[0]
        log(f"wrote {a.out}  PSNR={psnr:.1f}dB  tardos seat={a.seat} self-score={sc:.1f} (trace with the 'trace' subcommand)")
    else:
        if getattr(a, "bands", "a") == "ab" and a.carriers == "band":
            idv, conf, margin = decode_multiband(m_np.mean(2), key, a.size)
        else:
            idv, conf, margin = decode_keyed(m_np.mean(2), key, a.size, a.carriers)
        log(f"wrote {a.out}  PSNR={psnr:.1f}dB  self-read id=0x{idv:X} margin={margin:.2f}")

    assessment = None
    if a.assess:
        # Per-image confidence: measure this specific mark against the real threats,
        # rather than claiming a global constant. Reuses the loaded purifier (one draw
        # at the strongest trained strength) and a numpy band-notch.
        pf = purifiers[0]; s0 = strengths[-1]
        with torch.no_grad():
            pm = pf["purify"](marked, noises[0], pf["ts_by_s"][s0]).clamp(0, 1)
        p_id, _, p_m = decode_keyed(pm[0].permute(1, 2, 0).cpu().numpy().mean(2), key, a.size, a.carriers)
        n_id, _, n_m = decode_keyed(_band_notch_np(m_np, a.size).mean(2), key, a.size, a.carriers)
        p_ok = bool(p_id == a.serial and p_m > a.threshold)
        n_ok = bool(n_id == a.serial and n_m > a.threshold)
        rating = ("strong" if (p_ok and n_ok) else "amplifier-only" if p_ok else "weak")
        assessment = {"post_purify": {"valid": p_ok, "margin": round(p_m, 3)},
                      "post_notch": {"valid": n_ok, "margin": round(n_m, 3)}, "rating": rating}
        log(f"assess: purify={'OK' if p_ok else 'x'}({p_m:.2f}) notch={'OK' if n_ok else 'x'}({n_m:.2f}) -> {rating}")

    if getattr(a, "tardos", False):
        out = {"out": a.out, "tardos": True, "seat": a.seat, "tardos_bits": a.tardos_bits,
               "psnr_db": round(psnr, 2), "self_score": round(float(sc), 2)}
    else:
        out = {"out": a.out, "id_hex": f"0x{a.serial:X}", "psnr_db": round(psnr, 2),
               "self_read_ok": (idv == a.serial and margin > a.threshold)}
    if assessment: out["assess"] = assessment
    print(json.dumps(out))

def trace_cmd(a):
    """Tardos collusion tracing: scan seats 0..N-1 of a (possibly colluded) marked image and accuse the
    seat(s) whose codeword it carries. Numpy only, no GPU. Exit 0 iff --expect-seat is among the accused."""
    key = _key_bytes(a.key, a.hexkey)
    tc = _tardos_code(key, a.tardos_bits, a.size)
    gray = (np.asarray(Image.open(a.infile).convert("RGB").resize((a.size, a.size)), np.float32) / 255.0).mean(2)
    seats = list(range(a.seats))
    accused, scores = tc.accuse(gray, seats, k=a.k)
    top = int(np.argmax(scores)) if len(scores) else -1
    print(json.dumps({"accused": [int(s) for s in accused], "n_seats": a.seats,
                      "top_seat": top, "top_score": round(float(scores[top]), 3) if top >= 0 else 0.0,
                      "threshold_k": a.k}))
    if a.expect_seat is not None:
        sys.exit(0 if a.expect_seat in accused else 1)

def weights_pin_cmd(a):
    # Emit the exact diffusion model + revision + subfolders the OPT-IN --diff-eot > 0 embed would
    # load, as JSON, so a pack builder can mirror them into a content-addressed store and hand the
    # tool a local --weights-dir. There is no built-in default model, so --model is required here.
    if not a.model:
        raise SystemExit("backfire weights-pin: pass --model <hf repo id> (there is no built-in default; the codec-only path needs no diffusion weights)")
    rev = a.revision if a.revision else None
    print(json.dumps({
        "model": a.model,
        "revision": rev,
        "subfolders": ["vae", "unet", "tokenizer", "text_encoder", "scheduler"],
    }))

def main():
    ap = argparse.ArgumentParser(prog="backfire", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(required=True)
    e = sub.add_parser("embed", help="write a marked image (needs torch + a diffusion model)")
    e.add_argument("infile"); e.add_argument("-o", "--out", required=True)
    e.add_argument("--key", required=True); e.add_argument("--hexkey", action="store_true")
    e.add_argument("--serial", type=lambda x: int(x, 0), default=None, help="0..15 keyed id (4-bit); required unless --tardos")
    e.add_argument("--size", type=int, default=256); e.add_argument("--iters", type=int, default=240)
    e.add_argument("--fast", action="store_true", help="FAST carrier-add mode (M1): no model, no optimization, ~instant and CPU-portable. Survives normal handling (JPEG/scale) but does NOT self-amplify under a diffusion strip -- use for the fast provenance tier and non-poisoned frames in selective/N-frame keying.")
    e.add_argument("--eps", type=float, default=12/255, help="per-pixel bound on the mark's shape before energy projection")
    e.add_argument("--target-psnr", type=float, default=30.0, help="content-adaptive mark energy: projected PSNR floor")
    e.add_argument("--level", choices=LEVEL_ORDER, default=None, help="visibility<->robustness SLIDER preset (invisible|balanced|durable|robust|maximum): sets target-psnr, perceptual masking, and carrier bands together, from invisible/everyday-robust to a visible/strip-proof seal. 'maximum' is the validated multi-band seal (see LIMITS.md). An explicit --target-psnr/--pmask/--luma/--bands still overrides the preset. Run 'backfire levels' for the table.")
    e.add_argument("--pmask", type=float, default=0.0, help="perceptual / local-SNR mask floor (0=off, uniform energy). e.g. 0.2 concentrates the mark in textured regions and suppresses it in flat areas at the same global energy, cutting flat-region visibility without changing the survival budget")
    e.add_argument("--luma", action="store_true", help="constrain the mark to LUMINANCE (grayscale perturbation). The reader correlates luminance only, so chroma energy is invisible to detection but shows as visible color splotches; --luma moves all energy into luma, removing the color artifacts at no detection cost")
    e.add_argument("--auto", action="store_true", help="content-adaptive energy: set the mark strength PER IMAGE from a perceptual (Noise-Visibility-Function / JND) budget instead of a fixed --target-psnr. Flat images auto-get a quieter mark (higher effective dB), busy images a louder one (lower dB, better survival), at a constant low-visibility (perceptual) budget. Overrides --target-psnr for the final energy; reports the effective dB it chose")
    e.add_argument("--jnd-floor", type=float, default=0.006, help="(--auto) flat-region invisible perturbation amplitude in [0,1] units (~1.5/255)")
    e.add_argument("--jnd-gain", type=float, default=0.5, help="(--auto) how much local texture raises the invisible budget (masking gain on local luminance std)")
    e.add_argument("--jnd-target", type=float, default=1.0, help="(--auto) perceptual load headroom at the 95th percentile (1.0 = ride the JND; <1 = quieter/safer)")
    e.add_argument("--lr", type=float, default=4e-3)
    e.add_argument("--direct", type=float, default=1.0, help="pre-attack readability weight")
    e.add_argument("--eot-strengths", default="0.2,0.3"); e.add_argument("--eot-noises", type=int, default=4)
    e.add_argument("--codec-eot", type=float, default=1.2, help="neural-codec EOT weight (bmshj2018 q1,q3): makes the mark survive a learned VAE/neural-codec re-encode, not just diffusion. 0 = off (diffusion-only 2.x mark, no compressai needed)")
    e.add_argument("--codec-iter", type=float, default=0.5, help="focused iterated-codec term weight (bmshj q1 applied twice): buys down the repeated-compression axis. 0 = off")
    e.add_argument("--diff-eot", type=float, default=0.0, help="diffusion-purifier EOT weight. 0 = DEFAULT (license-clean): load no diffusion model, rely only on the permissive neural-codec fixed point (needs --codec-eot/--codec-iter > 0, which are on by default). > 0 = OPT IN to the SD-family fixed point too, which requires your own weights via --model / --weights-dir.")
    e.add_argument("--threshold", type=float, default=2.5, help="min per-bit margin for a valid read")
    e.add_argument("--carriers", choices=["band", "edge"], default="band", help="band (default) or content-coupled edge-masked mid-low carriers. edge is a documented dead end (see LIMITS.md): it did not improve notch survival; shipped only to reproduce that result")
    e.add_argument("--bands", choices=["a", "ab"], default="a", help="carrier bands to embed: 'a' = band A only (default, unchanged); 'ab' = multi-band A+B (survives a notch of either band; read back with 'read --bands ab')")
    e.add_argument("--content-bind", action="store_true", help="P5 forgery resistance: derive per-image carriers from a perceptual hash so the mark cannot be replayed/forged onto another image. Read back with 'read --content-bind'. Not geometry-invariant yet (targets the non-geometric replay threat)")
    e.add_argument("--tardos", action="store_true", help="embed a per-seat Tardos collusion-tracing codeword instead of the 4-bit serial (trace with the 'trace' subcommand). Fixes the serial's zero collusion resistance")
    e.add_argument("--seat", type=int, default=0, help="seat id (per-copy fingerprint) for --tardos")
    e.add_argument("--tardos-bits", type=int, default=1024, help="Tardos codeword length; larger bit budgets trace larger collusions (image capacity caps the practical regime at c<=3)")
    e.add_argument("--notch-eot", type=float, default=0.0, help="weight on staying readable after a band-notch (notch-in-the-loop). A documented dead end (see LIMITS.md): it never reached notch robustness; shipped only to reproduce that result, not recommended. 0 = off")
    e.add_argument("--assess", action="store_true", help="after embed, measure this mark's survival vs the purifier and a band-notch, and emit a per-image rating")
    e.add_argument("--model", default=DEFAULT_MODEL,
                   help="SD-family diffusion weights for the OPT-IN --diff-eot > 0 path (a Hugging Face "
                        "repo id you have rights to). Not used by the default codec-only path; bring your "
                        "own (Stability withdrew the official SD-2.1 weights).")
    e.add_argument("--revision", default=None,
                   help="pin a git revision for --model (optional; uses main if unset)")
    e.add_argument("--models", default=None, help="comma-separated diffusion backends for expectation-over-purifiers EOT (overrides --model; cost scales with count)")
    e.add_argument("--device", default="cuda")
    e.add_argument("--weights-dir", default=None,
                   help="local directory holding the diffusion model (vae/unet/tokenizer/text_encoder/scheduler subfolders). Overrides --model and implies --offline; run the embed from a pre-fetched, hash-pinned local copy with no network access")
    e.add_argument("--offline", action="store_true",
                   help="never reach the network for weights: sets HF_HUB_OFFLINE=1 and loads models local-only (from_pretrained local_files_only), failing fast if a required file is not already local, so a sandbox can guarantee the tool cannot fetch")
    e.set_defaults(func=embed_cmd)
    r = sub.add_parser("read", help="recover the keyed id (numpy only, no GPU)")
    r.add_argument("infile"); r.add_argument("--key", required=True); r.add_argument("--hexkey", action="store_true")
    r.add_argument("--size", type=int, default=512, help="resolution to read at; if it does not validate, the other of 256/512 is tried automatically")
    r.add_argument("--threshold", type=float, default=2.5)
    r.add_argument("--carriers", choices=["band", "edge"], default="band", help="must match how the image was embedded")
    r.add_argument("--bands", choices=["a", "ab"], default="a", help="carrier bands to read: 'a' = band A only (default, legacy, byte-identical); 'ab' = combined band A+B for multi-band marks (survives a notch of either band)")
    r.add_argument("--content-bind", action="store_true", help="read a content-bound mark (must match how it was embedded)")
    r.add_argument("--notch-threshold", type=float, default=NOTCH_TAMPER_THRESHOLD, help="band-notch tamper tripwire threshold (clean tail ~1.4, threshold 1.45; mark-stripping notches read 4+)")
    r.add_argument("--expect", type=lambda x: int(x, 0), default=None, help="exit 0 iff this id is read and valid")
    r.add_argument("--register", action="store_true", help="opt-in geometry recovery: if the base read fails, search a rotation x scale grid to recover a rotated or cropped mark (numpy only, ~90 extra decodes; null-safe, same threshold)")
    r.add_argument("--register-max-deg", type=float, default=12.0, help="max +/- rotation (deg) searched by --register")
    r.add_argument("--register-max-pad", type=float, default=0.20, help="max border-fraction (scale) searched by --register to undo a center-crop")
    r.set_defaults(func=read_cmd)
    t = sub.add_parser("trace", help="Tardos collusion tracing: accuse the seat(s) in a (possibly colluded) marked image (numpy only, no GPU)")
    t.add_argument("infile"); t.add_argument("--key", required=True); t.add_argument("--hexkey", action="store_true")
    t.add_argument("--seats", type=int, required=True, help="scan seats 0..N-1 for accusation")
    t.add_argument("--size", type=int, default=256); t.add_argument("--tardos-bits", type=int, default=1024)
    t.add_argument("--k", type=float, default=3.5, help="accusation threshold = pool mean + k*std (calibrated ~1e-3 FPR at k=3.5, bits>=1024)")
    t.add_argument("--expect-seat", type=int, default=None, help="exit 0 iff this seat is among the accused")
    t.set_defaults(func=trace_cmd)
    w = sub.add_parser("weights-pin", help="print the pinned diffusion model id + revision + subfolders as JSON, so a pack manifest can declare and pre-fetch the exact weights the embed loads (no model download; numpy/stdlib only)")
    w.add_argument("--model", default=DEFAULT_MODEL, help="SD-family repo id to report the pin for (required; there is no built-in default)")
    w.add_argument("--revision", default=None, help="git revision to report for --model (optional)")
    w.set_defaults(func=weights_pin_cmd)
    lv = sub.add_parser("levels", help="print the visibility<->robustness slider levels (name, target PSNR, robustness class) as JSON")
    lv.set_defaults(func=lambda a: print(json.dumps({"order": LEVEL_ORDER, "levels": {k: {"target_psnr": v[0], "pmask": v[1], "luma": v[2], "bands": v[4], "class": v[5]} for k, v in LEVELS.items()}}, indent=2)))
    a = ap.parse_args()
    # record which energy/masking knobs the user passed explicitly, so --level does not override them.
    # Match both `--flag value` (bare token) and `--flag=value` (single argv token) forms.
    _passed = lambda opt: any(t == opt or t.startswith(opt + "=") for t in sys.argv)
    a._explicit = {dest for opt, dest in (("--target-psnr", "target_psnr"), ("--pmask", "pmask"), ("--luma", "luma"), ("--codec-eot", "codec_eot"), ("--bands", "bands")) if _passed(opt)}
    a.func(a)

if __name__ == "__main__":
    main()
