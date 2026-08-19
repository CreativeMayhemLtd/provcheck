#!/usr/bin/env python3
"""Reproduce the tripwire dilemma (see ../README.md) on your own marked image.
The mark's weakness is an aggressive band-notch (notch_limit.py). The answer is that
the notch is loud: it carves a spectral hole natural images do not have, so `read`
scores a tamper tripwire. This shows both facts at once, numpy + pillow only, no GPU:

    python tripwire_dilemma.py --image marked.png --key "my-key"

    attacker's move            the mark        the tripwire
    diffusion stripper         amplifies       (not needed; see demo_amplify.py)
    aggressive notch, to strip removed          DETECTED
    do nothing / gentle        survives         quiet

Remove the mark or stay quiet, not both."""
import argparse
import os
import sys

import numpy as np
from PIL import Image

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))
import backfire as bf  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True, help="a Backfire-marked image")
    ap.add_argument("--key", required=True)
    ap.add_argument("--hexkey", action="store_true")
    ap.add_argument("--carriers", default="band")
    ap.add_argument("--size", type=int, default=512,
                    help="read resolution; must match the embed size (bundled sample is 512)")
    ap.add_argument("--valid-threshold", type=float, default=2.5)
    ap.add_argument("--tamper-threshold", type=float, default=bf.NOTCH_TAMPER_THRESHOLD)
    a = ap.parse_args()

    key = bf._key_bytes(a.key, a.hexkey)
    rgb = np.asarray(Image.open(a.image).convert("RGB").resize((a.size, a.size)), np.float32) / 255.0

    # Row 1: the marked image, untouched. Mark reads; tripwire quiet.
    _, _, m_clean = bf.decode_keyed(rgb.mean(2), key, a.size, a.carriers)
    t_clean = bf.notch_tamper_stat(rgb.mean(2), a.size)

    # Row 2: the attacker notches out the whole carrier band to strip the mark.
    notched = bf._band_notch_np(rgb, a.size)
    _, _, m_notch = bf.decode_keyed(notched.mean(2), key, a.size, a.carriers)
    t_notch = bf.notch_tamper_stat(notched.mean(2), a.size)

    def mk(m):
        return "reads" if m > a.valid_threshold else "STRIPPED"

    def tw(t):
        return "DETECTED" if t > a.tamper_threshold else "quiet"

    print(f"tamper threshold {a.tamper_threshold}   validity threshold {a.valid_threshold}\n")
    print(f"{'attacker move':26s}{'mark margin':>14s}{'tripwire stat':>16s}")
    print(f"{'marked, untouched':26s}{m_clean:11.3f} {mk(m_clean):>8s}{t_clean:11.3f} {tw(t_clean):>8s}")
    print(f"{'aggressive band-notch':26s}{m_notch:11.3f} {mk(m_notch):>8s}{t_notch:11.3f} {tw(t_notch):>8s}")

    stripped = m_notch <= a.valid_threshold
    caught = t_notch > a.tamper_threshold
    print()
    if stripped and caught:
        print("The notch removed the mark AND tripped the tamper detector. To strip the mark the")
        print("attacker has to carve a hole the detector sees; to stay quiet they have to leave the")
        print("mark. No single move does both. That is the dilemma.")
    elif not stripped:
        print("The notch did not fully strip the mark on this image; try a busier image.")
    else:
        print("Note: the notch stripped the mark without tripping the tripwire on this image.")


if __name__ == "__main__":
    main()
