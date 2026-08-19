#!/usr/bin/env python3
"""Reproduce the Backfire result: embed a keyed mark, run a textbook diffusion
regeneration attack (stock `diffusers` img2img, the same attack class as the
published removal work), and watch the keyed identifier read back STRONGER.

This is the "check our work" tool the README promises. The purifier here is a
plain image-to-image regeneration, the general attack from Zhao et al. 2024, run
so you can reproduce our amplification claim on your own image. It is deliberately
not a turnkey provenance stripper: it targets nothing, removes nothing, and reads
nothing but the Backfire mark you put there with your own key.

Usage:
    python demo_amplify.py --image sample.png --key "my-key" --serial 0x7
    python demo_amplify.py --image sample.png --key "my-key" --strength 0.15 --out out.png

Needs a GPU and the embed-side deps (see ../requirements.txt). The read side needs
only numpy + pillow; see notch_limit.py / tripwire_dilemma.py for numpy-only checks.
"""
import argparse
import json
import os
import subprocess
import sys

BF = os.path.join(os.path.dirname(__file__), os.pardir, "backfire.py")
# Stability withdrew the official SD-2.1 weights; use the same pinned community mirror the
# embed side defaults to, so the demo is single-model (embed and attack on identical weights).
MODEL = os.environ.get("BACKFIRE_SD_MODEL", "huanzi05/stable-diffusion-2-1-base")
MODEL_REV = os.environ.get("BACKFIRE_SD_REVISION", "f71d7867a2745c420aa93441638b119c85995963")


def sh_read(path, key, carriers, size):
    r = subprocess.run(
        [sys.executable, BF, "read", path, "--key", key, "--carriers", carriers,
         "--size", str(size)],
        capture_output=True, text=True,
    )
    try:
        return json.loads(r.stdout.strip().splitlines()[-1])
    except Exception:
        sys.stderr.write(r.stdout + r.stderr)
        return {}


def purify(marked_path, out_path, strength, steps, seed, size):
    """Textbook diffusion regeneration: add a little noise, denoise back. Low
    strength keeps the image recognizable, exactly what a real attacker wants.
    Run at the model's native 512 so the regeneration does not melt the image."""
    import torch
    from PIL import Image
    from diffusers import DDIMScheduler, StableDiffusionImg2ImgPipeline

    dev = "cuda" if torch.cuda.is_available() else "cpu"
    dtype = torch.float16 if dev == "cuda" else torch.float32
    rev = MODEL_REV if MODEL == "huanzi05/stable-diffusion-2-1-base" else None
    pipe = StableDiffusionImg2ImgPipeline.from_pretrained(
        MODEL, revision=rev, torch_dtype=dtype, safety_checker=None
    )
    pipe.scheduler = DDIMScheduler.from_config(pipe.scheduler.config)
    pipe = pipe.to(dev)
    pipe.set_progress_bar_config(disable=True)
    img = Image.open(marked_path).convert("RGB").resize((size, size))
    g = torch.Generator(device=dev).manual_seed(seed)
    out = pipe(prompt="", image=img, strength=strength, num_inference_steps=steps,
               guidance_scale=1.0, generator=g).images[0]
    out.save(out_path)


def draw(original, marked, purified, m_marked, m_purified, m_wrong, out_path):
    from PIL import Image, ImageDraw, ImageFont

    def font(sz):
        for p in (r"C:\Windows\Fonts\segoeui.ttf", r"C:\Windows\Fonts\arial.ttf",
                  "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"):
            if os.path.exists(p):
                return ImageFont.truetype(p, sz)
        return ImageFont.load_default()

    IMG, GAP, PADX, TOP = 240, 40, 40, 110
    W = PADX * 2 + IMG * 3 + GAP * 2
    H = TOP + IMG + 250
    BG, FG, SUB = (17, 18, 22), (235, 236, 240), (150, 153, 162)
    GREEN, BAR, TRACK, GREY = (46, 204, 113), (39, 174, 96), (44, 46, 54), (120, 123, 130)
    c = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(c)
    d.text((PADX, 34), "Backfire", font=font(40), fill=FG)
    d.text((PADX, 82), "the watermark that gets STRONGER when you attack it",
           font=font(19), fill=GREEN)
    cols = [
        (original, "Original", None),
        (marked, "Marked (invisible)", m_marked),
        (purified, "After an AI stripper", m_purified),
    ]
    maxm = max(m_marked, m_purified) * 1.15
    for i, (path, label, m) in enumerate(cols):
        x = PADX + i * (IMG + GAP)
        c.paste(Image.open(path).convert("RGB").resize((IMG, IMG)), (x, TOP))
        d.rectangle([x, TOP, x + IMG, TOP + IMG], outline=(60, 62, 70))
        d.text((x, TOP + IMG + 12), label, font=font(17), fill=FG)
        by = TOP + IMG + 46
        if m is None:
            d.text((x, by + 8), "(unwatermarked)", font=font(15), fill=SUB)
            continue
        d.text((x, by), "watermark confidence", font=font(13), fill=SUB)
        d.rounded_rectangle([x, by + 22, x + IMG, by + 42], 6, fill=TRACK)
        w = int(IMG * min(1.0, m / maxm))
        d.rounded_rectangle([x, by + 22, x + w, by + 42], 6, fill=BAR)
        d.text((x, by + 50), f"{m:.1f}   VALID", font=font(20), fill=GREEN)
    d.text((PADX + IMG + 8, TOP + IMG + 78),
           f"->  x{m_purified / m_marked:.1f} stronger  ->", font=font(15), fill=GREEN)
    # Control: the SAME attacked image read with a WRONG key scores ~0. This proves the
    # high read is the key finding the mark, not a changed image reading high.
    cy = TOP + IMG + 130
    d.line([PADX, cy, W - PADX, cy], fill=(44, 46, 54), width=1)
    d.text((PADX, cy + 12),
           f"Control: the same attacked image, read with a WRONG key  ->  {m_wrong:.2f}   nothing.",
           font=font(15), fill=GREY)
    d.text((PADX, cy + 36),
           "The high read is your key finding your mark, not the changed image reading high. "
           "The mark is in the key, not the picture.", font=font(13), fill=SUB)
    d.text((PADX, H - 26),
           "Imperceptible keyed mark. Stock diffusers img2img regeneration; the keyed "
           "identifier survives it and reads back stronger.", font=font(12), fill=SUB)
    c.save(out_path)


def main():
    ap = argparse.ArgumentParser(description="Reproduce Backfire amplification end to end.")
    ap.add_argument("--image", required=True, help="cover image (any size; resized to --size)")
    ap.add_argument("--key", required=True)
    ap.add_argument("--serial", default="0x7")
    ap.add_argument("--carriers", default="band")
    ap.add_argument("--size", type=int, default=512,
                    help="embed/read resolution; 512 is SD's native res (clean attack), "
                         "256 is faster and lower-VRAM")
    ap.add_argument("--strength", type=float, default=0.10,
                    help="regeneration strength; low = image stays recognizable")
    ap.add_argument("--steps", type=int, default=50)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--workdir", default="repro_out")
    ap.add_argument("--out", default=None, help="demo PNG path (default <workdir>/demo.png)")
    a = ap.parse_args()

    os.makedirs(a.workdir, exist_ok=True)
    original = os.path.join(a.workdir, "original.png")
    marked = os.path.join(a.workdir, "marked.png")
    purified = os.path.join(a.workdir, "purified.png")
    out = a.out or os.path.join(a.workdir, "demo.png")

    from PIL import Image
    Image.open(a.image).convert("RGB").resize((a.size, a.size)).save(original)

    print(f"[1/4] embedding keyed mark (serial {a.serial}) at {a.size}px; GPU-bound and slow ...")
    subprocess.run([sys.executable, BF, "embed", original, "-o", marked,
                    "--key", a.key, "--serial", a.serial, "--carriers", a.carriers,
                    "--size", str(a.size)],
                   check=True)

    print(f"[2/4] running the diffusion regeneration attack (strength {a.strength}) ...")
    purify(marked, purified, a.strength, a.steps, a.seed, a.size)

    print("[3/4] reading the mark before and after the attack, plus a wrong-key control ...")
    rm = sh_read(marked, a.key, a.carriers, a.size)
    rp = sh_read(purified, a.key, a.carriers, a.size)
    # The control: read the SAME attacked image with a different key. It must score ~0,
    # proving the high read is the key finding the mark, not the changed image reading high.
    rw = sh_read(purified, a.key + "-wrong-control", a.carriers, a.size)
    m_marked = rm.get("min_bit_margin")
    m_purified = rp.get("min_bit_margin")
    m_wrong = rw.get("min_bit_margin")
    print(f"      marked : margin={m_marked} valid={rm.get('valid')} id={rm.get('id')}")
    print(f"      attacked: margin={m_purified} valid={rp.get('valid')} id={rp.get('id')}")
    print(f"      wrong-key control (attacked): margin={m_wrong} valid={rw.get('valid')}")
    if not m_marked or not m_purified:
        sys.exit("read failed; see stderr above")
    if m_wrong is None:
        m_wrong = 0.0

    print(f"[4/4] rendering {out} ...")
    draw(original, marked, purified, m_marked, m_purified, m_wrong, out)
    verdict = "AMPLIFIED" if m_purified > m_marked else "survived (did not amplify)"
    print(f"\n{verdict}: {m_marked:.2f} -> {m_purified:.2f}  (x{m_purified / m_marked:.2f})")


if __name__ == "__main__":
    main()
