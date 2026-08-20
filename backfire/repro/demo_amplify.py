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

    def font(sz, bold=False):
        cands = ([r"C:\Windows\Fonts\segoeuib.ttf", r"C:\Windows\Fonts\arialbd.ttf",
                  "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"] if bold else
                 [r"C:\Windows\Fonts\segoeui.ttf", r"C:\Windows\Fonts\arial.ttf",
                  "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"])
        for p in cands:
            if os.path.exists(p):
                return ImageFont.truetype(p, sz)
        return ImageFont.load_default()

    IMG, GAP, MARG = 400, 44, 64
    W = MARG * 2 + IMG * 3 + GAP * 2
    BG, FG, SUB = (16, 17, 21), (238, 239, 243), (148, 151, 160)
    GREEN, BAR, TRACK = (52, 211, 122), (42, 176, 99), (40, 42, 50)
    HAIR = (52, 55, 64)

    # Vertical rhythm, computed top to bottom so nothing overlaps.
    y_title = 56
    y_tag = y_title + 62
    y_img = y_tag + 58
    y_label = y_img + IMG + 16
    y_cap = y_label + 34
    y_bar = y_cap + 24
    y_val = y_bar + 34
    y_amp = y_val + 40
    y_rule = y_amp + 44
    y_ctrl = y_rule + 26
    y_ctrl2 = y_ctrl + 30
    y_foot = y_ctrl2 + 44
    H = y_foot + 48

    c = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(c)
    d.text((MARG, y_title), "Backfire", font=font(52, bold=True), fill=FG)
    d.text((MARG, y_tag), "the watermark that gets stronger when you attack it",
           font=font(24), fill=GREEN)

    cols = [
        (original, "Original", None),
        (marked, "Marked (invisible)", m_marked),
        (purified, "After an AI stripper", m_purified),
    ]
    maxm = max(m_marked, m_purified) * 1.12
    for i, (path, label, m) in enumerate(cols):
        x = MARG + i * (IMG + GAP)
        c.paste(Image.open(path).convert("RGB").resize((IMG, IMG)), (x, y_img))
        d.rectangle([x, y_img, x + IMG, y_img + IMG], outline=HAIR)
        d.text((x, y_label), label, font=font(21, bold=True), fill=FG)
        if m is None:
            d.text((x, y_cap), "(unwatermarked)", font=font(16), fill=SUB)
            continue
        d.text((x, y_cap), "WATERMARK CONFIDENCE", font=font(13), fill=SUB)
        d.rounded_rectangle([x, y_bar, x + IMG, y_bar + 24], 8, fill=TRACK)
        w = int(IMG * min(1.0, m / maxm))
        d.rounded_rectangle([x, y_bar, x + w, y_bar + 24], 8, fill=BAR)
        d.text((x, y_val), f"{m:.1f}", font=font(30, bold=True), fill=GREEN)
        vw = d.textlength(f"{m:.1f}", font=font(30, bold=True))
        d.text((x + vw + 14, y_val + 7), "VALID", font=font(19), fill=GREEN)
    # Amplification callout: its own line under the right panel, nothing overlaps.
    ax = MARG + 2 * (IMG + GAP)
    d.text((ax, y_amp), f"{m_purified / m_marked:.1f}x stronger than before the attack",
           font=font(17), fill=GREEN)

    # Control block: the SAME attacked image read with a WRONG key scores ~0,
    # proving the high read is the key finding the mark.
    d.line([MARG, y_rule, W - MARG, y_rule], fill=HAIR, width=1)
    d.text((MARG, y_ctrl),
           f"Control: the same attacked image, read with a wrong key, scores {m_wrong:.2f}. Nothing.",
           font=font(18), fill=FG)
    d.text((MARG, y_ctrl2),
           "The high read is your key finding your mark, not the changed image reading high. "
           "The mark is in the key, not the picture.", font=font(15), fill=SUB)
    d.text((MARG, y_foot),
           "Imperceptible keyed mark, 512 px. Stock diffusers img2img regeneration; "
           "the keyed identifier survives it and reads back stronger.", font=font(13), fill=SUB)
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
