#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1 OR LicenseRef-Backfire-Commercial
# Copyright (C) 2026 Creative Mayhem UG (haftungsbeschränkt)
"""M2 selective N-frame keying for video.

Instead of marking every frame (slow, and all-or-nothing to strip), mark a KEYED SUBSET: the key
picks which frames carry the mark, so an attacker cannot predict or selectively clean them, and the
cost drops by the subset fraction. Each marked frame carries the full keyed serial (simple redundancy);
a QUORUM read scans all frames and majority-votes the serial, so the id survives even after an H.264
re-encode drops or degrades some frames (per-frame survival through H.264 is proven: margin ~17->16).

Two selection modes:
  - every-Nth (keyed offset): mark frames off, off+N, off+2N, ...  (predictable cadence, keyed start)
  - keyed-random subset: mark ~density*n frames chosen by a keyed hash (unpredictable which frames)

This module is pure numpy + the shipped Backfire carrier-add reader; the per-frame mark reuses M1 fast
mode (instant, CPU) so a whole clip marks in ~realtime. Poison frames can be substituted on the keyed
subset for the boobytrap tier.
"""
import os, sys, hmac, hashlib
import numpy as np
from PIL import Image
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import backfire as bf


def keyed_subset(key: bytes, n_frames: int, density: float = 0.2, every: int | None = None):
    """Deterministically pick which frame indices to mark. `every` -> every-Nth with a keyed start
    offset; otherwise a keyed-random subset of ~density*n_frames. Unpredictable without the key."""
    if every and every > 0:
        off = int.from_bytes(hmac.new(key, b"backfire/frameoffset", hashlib.sha256).digest()[:2], "big") % every
        return list(range(off, n_frames, every))
    k = max(1, int(round(density * n_frames)))
    score = [int.from_bytes(hmac.new(key, b"backfire/frame/%d" % i, hashlib.sha256).digest()[:4], "big") for i in range(n_frames)]
    return sorted(sorted(range(n_frames), key=lambda i: score[i])[:k])


def fast_mark(rgb: np.ndarray, key: bytes, serial: int, size: int = 256, psnr: float = 30.0):
    """Apply the M1 fast carrier-add (bands ab) to one frame in-process (instant). rgb float[0,1] HxWx3
    at ANY resolution: the mark is computed in the `size`x`size` carrier space and its (signed, float)
    delta is resized to the frame's native resolution, so full-res / non-square video frames keep their
    resolution. The mid-band mark survives the resize round-trip (read resizes back). Returns the marked frame."""
    H, W = rgb.shape[:2]
    small = rgb if (H, W) == (size, size) else \
        np.asarray(Image.fromarray((rgb * 255).astype("uint8")).resize((size, size)), np.float32) / 255.0
    CA = bf.build_carriers(key, size, "band", small.mean(2), b"backfire/carrier")
    CB = bf.build_carriers(key, size, "band", small.mean(2), b"backfire/carrier/B", bf.BAND_B)
    C = np.concatenate([CA, CB], 0)
    ts = np.concatenate([bf.target_signs(key, serial)] * 2)
    mark = (ts[:, None, None] * C).sum(0)
    d = mark * (10 ** (-psnr / 20.0) / max(float(np.sqrt((mark ** 2).mean())), 1e-12))   # (size,size) signed delta
    if (H, W) != (size, size):    # resize the float delta to native res (mode 'F' keeps sign + precision)
        d = np.asarray(Image.fromarray(d.astype(np.float32), mode="F").resize((W, H), Image.BILINEAR), np.float32)
    return np.clip(rgb + d[:, :, None], 0, 1)


def read_frame(rgb: np.ndarray, key: bytes, size: int = 256, threshold: float = 2.5):
    """Read one frame (bands ab) at ANY resolution (resized into the carrier space). Returns (serial|None, margin, valid)."""
    H, W = rgb.shape[:2]
    g = rgb.mean(2) if (H, W) == (size, size) else \
        np.asarray(Image.fromarray((rgb * 255).astype("uint8")).resize((size, size)), np.float32).mean(2) / 255.0
    idv, _c, margin = bf.decode_multiband(g, key, size)
    return (idv, float(margin), bool(margin > threshold))


def quorum_read(frames, key: bytes, size: int = 256, threshold: float = 2.5):
    """Scan every frame, majority-vote the serial across valid reads. Recovers the id even if some
    marked frames were dropped/degraded by re-encoding. Returns a dict with the winning id, how many
    frames agreed, and their mean margin. Unmarked-only input yields id=None (no false positive)."""
    votes = {}
    valids = 0
    for f in frames:
        idv, margin, ok = read_frame(f, key, size, threshold)
        if ok:
            valids += 1
            votes.setdefault(idv, []).append(margin)
    if not votes:
        return {"id": None, "id_hex": None, "agree": 0, "valid_frames": 0, "mean_margin": 0.0}
    win = max(votes, key=lambda k: (len(votes[k]), sum(votes[k])))
    return {"id": win, "id_hex": f"0x{win:X}", "agree": len(votes[win]),
            "valid_frames": valids, "mean_margin": round(float(np.mean(votes[win])), 3)}


if __name__ == "__main__":
    # tiny self-demo on synthetic frames (no ffmpeg): keyed-subset mark + quorum read
    key = bf._key_bytes("testkey", False)
    rng = np.random.default_rng(0)
    frames = [np.clip(0.5 + 0.2 * rng.standard_normal((256, 256, 3)).astype(np.float32), 0, 1) for _ in range(30)]
    idx = keyed_subset(key, len(frames), every=5)
    for i in idx:
        frames[i] = fast_mark(frames[i], key, 0x7)
    print("marked frame indices:", idx)
    print("quorum:", quorum_read(frames, key))
