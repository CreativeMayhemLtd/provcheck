#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Backfire: an imperceptible, keyed image watermark that AI provenance-stripping
attacks *amplify* instead of remove.

Diffusion "purification" (regeneration) provably removes ordinary invisible
watermarks by projecting the image back onto the natural-image manifold. Backfire
instead optimizes the mark to be a fixed point / attractor of that very process,
so running a stripper's own purifier makes the keyed serial read *stronger*.

  embed  optimize + write a marked image        (needs torch + a diffusion model)
  read   recover the keyed serial from an image  (numpy only; fast, no GPU)

The read side never loads a model: detection is a keyed FFT correlation, so it is
cheap and portable. Carriers are HMAC-keyed and generated identically for embed
and read, so only the key holder can write or read the mark.
"""
import argparse, hmac, hashlib, json, sys
import numpy as np
from PIL import Image

# --- watermark geometry (must match between embed and read) ---
LO, HI = 6.0, 40.0                 # mid-frequency carrier band (radial px @ 256)
PAYLOAD_BITS = 8                   # keyed serial size (per-key index); pro tier raises this
REPS = 4                           # carrier repetitions per payload bit (soft-voted)
NBITS = PAYLOAD_BITS * REPS

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

def target_signs(serial: int):
    """Per-carrier +/-1 target from an 8-bit serial, repeated REPS times."""
    bits = np.array([(serial >> (j % PAYLOAD_BITS)) & 1 for j in range(NBITS)])
    return (bits * 2 - 1).astype(np.float32)

def _payload_softsums(corr):
    return np.array([corr[b::PAYLOAD_BITS].sum() for b in range(PAYLOAD_BITS)], np.float32)

def decode(img_gray, C, C_decoy):
    """Soft-vote the serial and a decoy-normalized confidence.

    The mark boosts the real keyed carriers' aligned energy far above what the
    same image gives on decoy keyed carriers (a different HMAC label). So
    confidence = mean|real payload soft-sum| / mean|decoy payload soft-sum| is
    ~1.0 on an unmarked image (both are just image content) and well above 1 when
    the mark is present, independent of image content."""
    g = img_gray - img_gray.mean()
    real = _payload_softsums((C * g).sum((1, 2)))
    decoy = _payload_softsums((C_decoy * g).sum((1, 2)))
    serial = 0
    for b in range(PAYLOAD_BITS):
        if real[b] > 0: serial |= (1 << b)
    conf = float(np.abs(real).mean() / (np.abs(decoy).mean() + 1e-8))
    return serial, conf

def decode_keyed(img_gray, key: bytes, size: int):
    return decode(img_gray, keyed_carriers(key, size),
                  keyed_carriers(key, size, b"backfire/decoy"))

# ------------------------------- read (numpy) -------------------------------
def read_cmd(a):
    img = np.asarray(Image.open(a.infile).convert("RGB").resize((a.size, a.size)), np.float32) / 255.0
    serial, conf = decode_keyed(img.mean(2), _key_bytes(a.key, a.hexkey), a.size)
    marked = conf > a.threshold
    print(json.dumps({"serial": serial, "serial_hex": f"0x{serial:02X}",
                      "confidence": round(conf, 4), "marked": marked,
                      "match": (serial == a.expect) if a.expect is not None else None}))
    if a.expect is not None:
        sys.exit(0 if (marked and serial == a.expect) else 1)

# ------------------------------- embed (torch) ------------------------------
def embed_cmd(a):
    import torch
    from diffusers import AutoencoderKL, UNet2DConditionModel, DDIMScheduler
    from transformers import CLIPTextModel, CLIPTokenizer
    dev = a.device
    def log(m): print(f"backfire: {m}", file=sys.stderr, flush=True)

    log("loading diffusion purifier proxy...")
    vae = AutoencoderKL.from_pretrained(a.model, subfolder="vae").to(dev).eval()
    unet = UNet2DConditionModel.from_pretrained(a.model, subfolder="unet").to(dev).eval()
    tok = CLIPTokenizer.from_pretrained(a.model, subfolder="tokenizer")
    txt = CLIPTextModel.from_pretrained(a.model, subfolder="text_encoder").to(dev).eval()
    sched = DDIMScheduler.from_pretrained(a.model, subfolder="scheduler")
    for m in (vae, unet, txt):
        for p in m.parameters(): p.requires_grad_(False)
    unet.enable_gradient_checkpointing()
    with torch.no_grad():
        ids = tok("", padding="max_length", max_length=tok.model_max_length, return_tensors="pt").input_ids.to(dev)
        null_emb = txt(ids)[0]
    SCALE = vae.config.scaling_factor
    N_INFER = 20; sched.set_timesteps(N_INFER, device=dev)
    strengths = [float(s) for s in a.eot_strengths.split(",")]
    ts_by_s = {s: sched.timesteps[N_INFER - max(1, int(N_INFER*s)):] for s in strengths}

    def purify(x, noise, ts):
        lat = vae.encode(x*2-1).latent_dist.mean * SCALE
        z = sched.add_noise(lat, noise, ts[0].expand(lat.shape[0]))
        for t in ts:
            z = sched.step(unet(z, t, encoder_hidden_states=null_emb.expand(z.shape[0], -1, -1)).sample, t, z).prev_sample
        return (vae.decode(z/SCALE).sample + 1)/2

    key = _key_bytes(a.key, a.hexkey)
    C = torch.from_numpy(keyed_carriers(key, a.size)).to(dev)
    tsign = torch.from_numpy(target_signs(a.serial)).to(dev)
    def corrs(img):
        g = img.mean(1); g = g - g.mean((-1, -2), keepdim=True)
        return (C * g).sum((-1, -2))

    host_np = np.asarray(Image.open(a.infile).convert("RGB").resize((a.size, a.size)), np.float32)/255.0
    host = torch.from_numpy(host_np).permute(2, 0, 1).unsqueeze(0).to(dev)
    gtor = torch.Generator(dev).manual_seed(1234)
    lat_shape = (1, unet.config.in_channels, a.size//8, a.size//8)
    noises = [torch.randn(lat_shape, generator=gtor, device=dev) for _ in range(a.eot_noises)]

    log(f"optimizing keyed poison (serial 0x{a.serial:02X}, {a.iters} iters, EOT strengths {strengths})...")
    w = torch.zeros_like(host, requires_grad=True); opt = torch.optim.Adam([w], lr=a.lr)
    for it in range(a.iters):
        opt.zero_grad()
        x = (host + a.eps*torch.tanh(w)).clamp(0, 1)
        post = torch.stack([(corrs(purify(x, n, ts_by_s[s]))*tsign).mean() for s in strengths for n in noises]).mean()
        loss = -(post + a.direct*(corrs(x)*tsign).mean())
        loss.backward(); opt.step()
        if it % 40 == 0 or it == a.iters-1:
            log(f"  iter {it:4d}  E[post]={post.item():+.3f}")

    marked = (host + a.eps*torch.tanh(w)).clamp(0, 1).detach()
    m_np = marked[0].permute(1, 2, 0).cpu().numpy()
    Image.fromarray((m_np*255).astype("uint8")).save(a.out)
    psnr = 10*np.log10(1.0/max(float(((marked-host)**2).mean()), 1e-12))
    serial, conf = decode_keyed(m_np.mean(2), key, a.size)
    log(f"wrote {a.out}  PSNR={psnr:.1f}dB  self-read serial=0x{serial:02X} conf={conf:.3f}")
    print(json.dumps({"out": a.out, "serial_hex": f"0x{a.serial:02X}", "psnr_db": round(psnr, 2), "self_read_ok": serial == a.serial}))

def main():
    ap = argparse.ArgumentParser(prog="backfire", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(required=True)
    e = sub.add_parser("embed", help="write a marked image (needs torch + a diffusion model)")
    e.add_argument("infile"); e.add_argument("-o", "--out", required=True)
    e.add_argument("--key", required=True); e.add_argument("--hexkey", action="store_true")
    e.add_argument("--serial", type=lambda x: int(x, 0), required=True, help="0..255 keyed serial")
    e.add_argument("--size", type=int, default=256); e.add_argument("--iters", type=int, default=220)
    e.add_argument("--eps", type=float, default=10/255); e.add_argument("--lr", type=float, default=4e-3)
    e.add_argument("--direct", type=float, default=0.5, help="pre-attack readability weight")
    e.add_argument("--eot-strengths", default="0.2,0.3"); e.add_argument("--eot-noises", type=int, default=3)
    e.add_argument("--model", default="huanzi05/stable-diffusion-2-1-base"); e.add_argument("--device", default="cuda")
    e.set_defaults(func=embed_cmd)
    r = sub.add_parser("read", help="recover the keyed serial (numpy only, no GPU)")
    r.add_argument("infile"); r.add_argument("--key", required=True); r.add_argument("--hexkey", action="store_true")
    r.add_argument("--size", type=int, default=256); r.add_argument("--threshold", type=float, default=1.25)
    r.add_argument("--expect", type=lambda x: int(x, 0), default=None, help="exit 0 iff this serial is read")
    r.set_defaults(func=read_cmd)
    a = ap.parse_args(); a.func(a)

if __name__ == "__main__":
    main()
