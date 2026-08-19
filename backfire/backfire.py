#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1 OR LicenseRef-Backfire-Commercial
# Copyright (C) 2026 Creative Mayhem UG (haftungsbeschränkt)
"""Backfire: an imperceptible, keyed image watermark that AI provenance-stripping
attacks *amplify* instead of remove.

Diffusion "purification" (regeneration) provably removes ordinary invisible
watermarks by projecting the image back onto the natural-image manifold. Backfire
instead optimizes the mark to be a fixed point / attractor of that very process,
so running a stripper's own purifier makes the keyed id read *stronger*.

  embed  optimize + write a marked image        (needs torch + a diffusion model)
  read   recover the keyed id from an image      (numpy only; fast, no GPU)

The read side never loads a model: detection is a keyed FFT correlation, so it is
cheap and portable. Carriers are HMAC-keyed and generated identically for embed
and read, so only the key holder can write or read the mark.
"""
import argparse, hmac, hashlib, json, sys
import numpy as np
from PIL import Image

# --- watermark geometry (must match between embed and read) ---
LO, HI = 6.0, 40.0                 # mid-frequency carrier band (radial px @ 256)
ID_BITS, ID_REPS = 4, 8            # 4-bit keyed id (16 per key; keyspace unbounded), 8 reps
NBITS = ID_BITS * ID_REPS          # 32 carriers, all id (reliability over capacity)

# Diffusion purifier proxy. Stability withdrew the original SD-2.1 weights from Hugging
# Face (the whole 2.x line is gone, not merely gated), so there is no official checkpoint
# to point at. We develop against a complete community mirror of those weights, pinned to
# an exact revision for reproducibility. Override with --model / --revision.
DEFAULT_MODEL = "huanzi05/stable-diffusion-2-1-base"
DEFAULT_REV = "f71d7867a2745c420aa93441638b119c85995963"

def _scaled_band(lo: float, hi: float, size: int):
    """Scale an @256 radial-bin band to `size` so the same *relative* frequency
    (cycles/pixel) is used at any resolution. size=256 returns (lo, hi) unchanged, so
    every 256px mark, golden vector, and test stays byte-identical."""
    s = size / 256.0
    return lo * s, hi * s

def _key_bytes(k: str, is_hex: bool) -> bytes:
    return bytes.fromhex(k) if is_hex else k.encode()

def keyed_carriers(key: bytes, size: int, label: bytes = b"backfire/carrier"):
    """Deterministic HMAC-keyed, band-limited carriers. numpy so embed and read
    produce byte-identical patterns from the same key. `label` domain-separates
    the real carriers from the decoy carriers used for detection normalization."""
    yy, xx = np.mgrid[0:size, 0:size].astype(np.float32)
    rad = np.sqrt((xx - size/2)**2 + (yy - size/2)**2)
    lo, hi = _scaled_band(LO, HI, size)
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

def build_carriers(key, size, mode, lum, label=b"backfire/carrier"):
    """Dispatch: band (default, image-independent) or edge (content-coupled). The
    edge label is domain-separated so the two modes are cryptographically distinct."""
    if mode == "edge":
        return edge_carriers(key, size, lum, label + b"/edge")
    return keyed_carriers(key, size, label)

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
def read_cmd(a):
    key = _key_bytes(a.key, a.hexkey)
    rgb = Image.open(a.infile).convert("RGB")
    # Try the requested size first, then the other standard resolution, so a mark
    # embedded at either 256 or 512 is found without the caller guessing. Stop at
    # the first size that validates; otherwise keep the requested size's result.
    sizes = [a.size] + [s for s in (512, 256) if s != a.size]
    best = None
    for size in sizes:
        gray = (np.asarray(rgb.resize((size, size)), np.float32) / 255.0).mean(2)
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
    print(json.dumps({"id": idv, "id_hex": f"0x{idv:X}", "confidence": round(conf, 4),
                      "min_bit_margin": round(margin, 4), "valid": valid, "size": size,
                      "match": (idv == a.expect) if a.expect is not None else None,
                      "notch_tamper": {"stat": round(tamper, 3), "detected": tamper > a.notch_threshold}}))
    if a.expect is not None:
        sys.exit(0 if (valid and idv == a.expect) else 1)

# ------------------------------- embed (torch) ------------------------------
def embed_cmd(a):
    import torch
    from diffusers import AutoencoderKL, UNet2DConditionModel, DDIMScheduler
    from transformers import CLIPTextModel, CLIPTokenizer
    dev = a.device
    def log(m): print(f"backfire: {m}", file=sys.stderr, flush=True)

    N_INFER = 20
    strengths = [float(s) for s in a.eot_strengths.split(",")]
    # One or more purifier backends. Default is the single model (unchanged behavior);
    # --models "id1,id2,..." optimizes the mark to be a fixed point of ALL of them, so
    # it generalizes past one backend. Cost scales ~linearly with the model count.
    model_ids = [m.strip() for m in a.models.split(",")] if a.models else [a.model]

    def build_purifier(model_id):
        # Pin the tested revision for the default mirror; a custom --model uses --revision
        # or main. Keeps the default reproducible now that the upstream weights are gone.
        rev = a.revision if a.revision else (DEFAULT_REV if model_id == DEFAULT_MODEL else None)
        log(f"loading diffusion purifier proxy: {model_id}{' @ ' + rev[:12] if rev else ''} ...")
        # force fp32 on every backend: some models (e.g. distilled ones) ship fp16
        # components, which mismatch the fp32 pipeline in cross-attention.
        vae = AutoencoderKL.from_pretrained(model_id, subfolder="vae", revision=rev).to(dev).float().eval()
        unet = UNet2DConditionModel.from_pretrained(model_id, subfolder="unet", revision=rev).to(dev).float().eval()
        tok = CLIPTokenizer.from_pretrained(model_id, subfolder="tokenizer", revision=rev)
        txt = CLIPTextModel.from_pretrained(model_id, subfolder="text_encoder", revision=rev).to(dev).float().eval()
        sched = DDIMScheduler.from_pretrained(model_id, subfolder="scheduler", revision=rev)
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

    purifiers = [build_purifier(mid) for mid in model_ids]
    lat_ch = purifiers[0]["in_ch"]
    if any(p["in_ch"] != lat_ch for p in purifiers):
        raise SystemExit("backfire: --models must share a latent channel count (SD-family)")

    key = _key_bytes(a.key, a.hexkey)
    host_np = np.asarray(Image.open(a.infile).convert("RGB").resize((a.size, a.size)), np.float32)/255.0
    host = torch.from_numpy(host_np).permute(2, 0, 1).unsqueeze(0).to(dev)
    # edge carriers are content-coupled (built from the host luminance); band ignores it.
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
    # perturbation RMS, so this gives every image the same mark energy regardless of
    # content, lifting busy/high-frequency images that otherwise under-use the budget.
    target_rms = 10 ** (-a.target_psnr / 20.0)
    def make_x(w):
        d = a.eps * torch.tanh(w)
        d = d * (target_rms / d.pow(2).mean().clamp_min(1e-12).sqrt())
        return (host + d).clamp(0, 1)

    log(f"optimizing keyed poison (id 0x{a.serial:X}, {a.iters} iters, target {a.target_psnr:.0f}dB, "
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
        # Accumulate gradients over the EOT purifier passes one at a time, freeing each
        # pass's autograd graph before building the next. Peak memory is ONE purifier
        # backprop, not all n_eot at once, which is what lets 512px embeds fit: the
        # differentiable purifier (not the mark) is the memory cost, and it scales with
        # the number of live EOT graphs. Math is identical to one stacked .mean().backward().
        xd = x.detach().requires_grad_(True)
        post = 0.0
        for pf, s, n in eot_terms:
            li = (corrs(pf["purify"](xd, n, pf["ts_by_s"][s])) * tsign).mean()
            (-li / n_eot).backward()               # d(-post/n_eot)/dxd, accumulated into xd.grad
            post += li.item() / n_eot
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
    m_np = marked[0].permute(1, 2, 0).cpu().numpy()
    Image.fromarray((m_np*255).astype("uint8")).save(a.out)
    psnr = 10*np.log10(1.0/max(float(((marked-host)**2).mean()), 1e-12))
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

    out = {"out": a.out, "id_hex": f"0x{a.serial:X}", "psnr_db": round(psnr, 2),
           "self_read_ok": (idv == a.serial and margin > a.threshold)}
    if assessment: out["assess"] = assessment
    print(json.dumps(out))

def main():
    ap = argparse.ArgumentParser(prog="backfire", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(required=True)
    e = sub.add_parser("embed", help="write a marked image (needs torch + a diffusion model)")
    e.add_argument("infile"); e.add_argument("-o", "--out", required=True)
    e.add_argument("--key", required=True); e.add_argument("--hexkey", action="store_true")
    e.add_argument("--serial", type=lambda x: int(x, 0), required=True, help="0..15 keyed id (4-bit)")
    e.add_argument("--size", type=int, default=256); e.add_argument("--iters", type=int, default=240)
    e.add_argument("--eps", type=float, default=12/255, help="per-pixel bound on the mark's shape before energy projection")
    e.add_argument("--target-psnr", type=float, default=34.0, help="content-adaptive mark energy: projected PSNR floor")
    e.add_argument("--lr", type=float, default=4e-3)
    e.add_argument("--direct", type=float, default=0.7, help="pre-attack readability weight")
    e.add_argument("--eot-strengths", default="0.2,0.3"); e.add_argument("--eot-noises", type=int, default=4)
    e.add_argument("--threshold", type=float, default=2.5, help="min per-bit margin for a valid read")
    e.add_argument("--carriers", choices=["band", "edge"], default="band", help="band (default) or content-coupled edge-masked mid-low carriers. edge is a documented dead end (see LIMITS.md): it did not improve notch survival; shipped only to reproduce that result")
    e.add_argument("--notch-eot", type=float, default=0.0, help="weight on staying readable after a band-notch (notch-in-the-loop). A documented dead end (see LIMITS.md): it never reached notch robustness; shipped only to reproduce that result, not recommended. 0 = off")
    e.add_argument("--assess", action="store_true", help="after embed, measure this mark's survival vs the purifier and a band-notch, and emit a per-image rating")
    e.add_argument("--model", default=DEFAULT_MODEL,
                   help="diffusion purifier proxy. Stability withdrew the official SD-2.1 weights; "
                        "the default is a pinned community mirror of them (see --revision)")
    e.add_argument("--revision", default=None,
                   help="pin a model git revision. Defaults to the tested revision when --model is "
                        "the default mirror; ignored (uses main) for a custom --model")
    e.add_argument("--models", default=None, help="comma-separated diffusion backends for expectation-over-purifiers EOT (overrides --model; cost scales with count)")
    e.add_argument("--device", default="cuda")
    e.set_defaults(func=embed_cmd)
    r = sub.add_parser("read", help="recover the keyed id (numpy only, no GPU)")
    r.add_argument("infile"); r.add_argument("--key", required=True); r.add_argument("--hexkey", action="store_true")
    r.add_argument("--size", type=int, default=512, help="resolution to read at; if it does not validate, the other of 256/512 is tried automatically")
    r.add_argument("--threshold", type=float, default=2.5)
    r.add_argument("--carriers", choices=["band", "edge"], default="band", help="must match how the image was embedded")
    r.add_argument("--notch-threshold", type=float, default=NOTCH_TAMPER_THRESHOLD, help="band-notch tamper tripwire threshold (clean tail ~1.4, threshold 1.45; mark-stripping notches read 4+)")
    r.add_argument("--expect", type=lambda x: int(x, 0), default=None, help="exit 0 iff this id is read and valid")
    r.set_defaults(func=read_cmd)
    a = ap.parse_args(); a.func(a)

if __name__ == "__main__":
    main()
