#!/usr/bin/env python3
"""Reproduce Backfire's honest weakness (see ../LIMITS.md): a sophisticated attacker
who has read the source can strip the linear keyed mark with an aggressive band-notch.
We could not make the linear mark survive that, and this script proves it on your own
marked image. numpy + pillow only, no GPU.

    python notch_limit.py --image marked.png --key "my-key"

The answer to this weakness is the tripwire: run tripwire_dilemma.py next."""
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
    ap.add_argument("--threshold", type=float, default=2.5)
    ap.add_argument("--save-notched", default=None)
    a = ap.parse_args()

    key = bf._key_bytes(a.key, a.hexkey)
    rgb = np.asarray(Image.open(a.image).convert("RGB").resize((a.size, a.size)), np.float32) / 255.0

    _, _, m_before = bf.decode_keyed(rgb.mean(2), key, a.size, a.carriers)
    notched = bf._band_notch_np(rgb, a.size)
    _, _, m_after = bf.decode_keyed(notched.mean(2), key, a.size, a.carriers)

    if a.save_notched:
        Image.fromarray((notched * 255).astype(np.uint8)).save(a.save_notched)

    print(f"marked, before the notch : min-bit margin {m_before:.3f}  "
          f"({'VALID' if m_before > a.threshold else 'invalid'})")
    print(f"after an aggressive notch: min-bit margin {m_after:.3f}  "
          f"({'VALID' if m_after > a.threshold else 'STRIPPED'})")
    if m_after <= a.threshold:
        print("\nThe mark is gone. This is the limit we disclose in LIMITS.md: a linear keyed")
        print("mark cannot survive a notch that carves out its whole frequency band. But that")
        print("notch is loud. Run tripwire_dilemma.py to see it get caught.")
    else:
        print("\nThe notch did not strip the mark on this image (unusual); try a busier image.")


if __name__ == "__main__":
    main()
