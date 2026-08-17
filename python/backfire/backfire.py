#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Backfire-Commercial
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

def _key_bytes(k: str, is_hex: bool) -> bytes:
    return bytes.fromhex(k) if is_hex else k.encode()

def keyed_carriers(key: bytes, size: int, label: bytes = b"backfire/carrier"):
    """Deterministic HMAC-keyed, band-limited carriers. numpy so embed and read
    produce byte-identical patterns from the same key. `label` domain-separates
    the real carriers from the decoy carriers used for detection normalization."""
    yy, xx = np.mgrid[0:size, 0:size].astype(np.float32)
    rad = np.sqrt((xx - size/2)**2 + (yy - size/2)**2)
    band = ((rad > LO) & (rad < HI)).astype(np.float32)
    out = np.empty((NBITS, size, size), np.float32)
    for i in range(NBITS):
        seed = int.from_bytes(hmac.new(key, label + i.to_bytes(4, "big"),
                                       hashlib.sha256).digest()[:7], "big")
        n = np.random.default_rng(seed).standard_normal((size, size)).astype(np.float32)
        F = np.fft.fftshift(np.fft.fft2(n)) * band
        c = np.real(np.fft.ifft2(np.fft.ifftshift(F))).astype(np.float32)
        c -= c.mean(); out[i] = c / (np.linalg.norm(c) + 1e-8)
    return out

def target_signs(key: bytes, idv: int):
    """Per-carrier +/-1 targets: ID_REPS carriers repetition-code each id bit."""
    s = np.empty(NBITS, np.float32)
    for i in range(NBITS):
        s[i] = 1.0 if (idv >> (i % ID_BITS)) & 1 else -1.0
    return s

def decode(img_gray, C, C_decoy):
    """Soft-vote each id bit, and score trust by the weakest bit's margin over the
    decoy noise floor. A marginal or flipped bit (the false-valid failure mode) has
    a small margin and is rejected; a genuinely marked image clears the floor on
    every bit. Returns (id, mean_margin, min_margin). Margin ~1 means at the noise
    floor (unmarked or wrong key); well above 1 on every bit means marked."""
    g = img_gray - img_gray.mean()
    corr = (C * g).sum((1, 2))
    dcorr = (C_decoy * g).sum((1, 2))
    votes = [float(corr[b:NBITS:ID_BITS].sum()) for b in range(ID_BITS)]
    dnoise = float(np.abs([dcorr[b:NBITS:ID_BITS].sum() for b in range(ID_BITS)]).mean()) + 1e-8
    idv = sum((1 << b) for b in range(ID_BITS) if votes[b] > 0)
    margins = [abs(v) / dnoise for v in votes]
    return idv, float(np.mean(margins)), float(min(margins))

def decode_keyed(img_gray, key: bytes, size: int):
    return decode(img_gray, keyed_carriers(key, size),
                  keyed_carriers(key, size, b"backfire/decoy"))

# ------------------------------- read (numpy) -------------------------------
def read_cmd(a):
    img = np.asarray(Image.open(a.infile).convert("RGB").resize((a.size, a.size)), np.float32) / 255.0
    idv, conf, margin = decode_keyed(img.mean(2), _key_bytes(a.key, a.hexkey), a.size)
    valid = margin > a.threshold         # every id bit must clear the decoy noise floor
    print(json.dumps({"id": idv, "id_hex": f"0x{idv:X}", "confidence": round(conf, 4),
                      "min_bit_margin": round(margin, 4), "valid": valid,
                      "match": (idv == a.expect) if a.expect is not None else None}))
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
        log(f"loading diffusion purifier proxy: {model_id} ...")
        vae = AutoencoderKL.from_pretrained(model_id, subfolder="vae").to(dev).eval()
        unet = UNet2DConditionModel.from_pretrained(model_id, subfolder="unet").to(dev).eval()
        tok = CLIPTokenizer.from_pretrained(model_id, subfolder="tokenizer")
        txt = CLIPTextModel.from_pretrained(model_id, subfolder="text_encoder").to(dev).eval()
        sched = DDIMScheduler.from_pretrained(model_id, subfolder="scheduler")
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
    C = torch.from_numpy(keyed_carriers(key, a.size)).to(dev)
    tsign = torch.from_numpy(target_signs(key, a.serial)).to(dev)
    def corrs(img):
        g = img.mean(1); g = g - g.mean((-1, -2), keepdim=True)
        return (C * g).sum((-1, -2))

    host_np = np.asarray(Image.open(a.infile).convert("RGB").resize((a.size, a.size)), np.float32)/255.0
    host = torch.from_numpy(host_np).permute(2, 0, 1).unsqueeze(0).to(dev)
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
    w = (0.01 * torch.randn_like(host)).requires_grad_(True)   # tiny nonzero: the RMS projection has no defined direction at w=0
    opt = torch.optim.Adam([w], lr=a.lr)
    for it in range(a.iters):
        opt.zero_grad()
        x = make_x(w)
        post = torch.stack([(corrs(pf["purify"](x, n, pf["ts_by_s"][s]))*tsign).mean()
                            for pf in purifiers for s in strengths for n in noises]).mean()
        loss = -(post + a.direct*(corrs(x)*tsign).mean())
        loss.backward(); opt.step()
        if it % 40 == 0 or it == a.iters-1:
            log(f"  iter {it:4d}  E[post]={post.item():+.3f}")

    marked = make_x(w).detach()
    m_np = marked[0].permute(1, 2, 0).cpu().numpy()
    Image.fromarray((m_np*255).astype("uint8")).save(a.out)
    psnr = 10*np.log10(1.0/max(float(((marked-host)**2).mean()), 1e-12))
    idv, conf, margin = decode_keyed(m_np.mean(2), key, a.size)
    log(f"wrote {a.out}  PSNR={psnr:.1f}dB  self-read id=0x{idv:X} margin={margin:.2f}")
    print(json.dumps({"out": a.out, "id_hex": f"0x{a.serial:X}", "psnr_db": round(psnr, 2),
                      "self_read_ok": (idv == a.serial and margin > a.threshold)}))

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
    e.add_argument("--threshold", type=float, default=1.5, help="min per-bit margin for a valid read")
    e.add_argument("--model", default="huanzi05/stable-diffusion-2-1-base")
    e.add_argument("--models", default=None, help="comma-separated diffusion backends for expectation-over-purifiers EOT (overrides --model; cost scales with count)")
    e.add_argument("--device", default="cuda")
    e.set_defaults(func=embed_cmd)
    r = sub.add_parser("read", help="recover the keyed id (numpy only, no GPU)")
    r.add_argument("infile"); r.add_argument("--key", required=True); r.add_argument("--hexkey", action="store_true")
    r.add_argument("--size", type=int, default=256); r.add_argument("--threshold", type=float, default=1.5)
    r.add_argument("--expect", type=lambda x: int(x, 0), default=None, help="exit 0 iff this id is read and valid")
    r.set_defaults(func=read_cmd)
    a = ap.parse_args(); a.func(a)

if __name__ == "__main__":
    main()
