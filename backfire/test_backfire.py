#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Backfire-Commercial
# Copyright (C) 2026 Creative Mayhem UG (haftungsbeschränkt)
"""Unit tests for Backfire's read/decode path.

These cover everything that does not need a GPU or a diffusion model: keyed
carrier generation, the keyed id encoding, and the decoder's behaviour (id
recovery and the per-bit margin trust signal) on synthetically marked, unmarked,
and wrong-key images. The embed side (the torch optimization) is validated
separately by the image sweep, since it needs a model.

Run:  python test_backfire.py        (plain asserts, no deps beyond numpy)
  or:  pytest test_backfire.py
"""
import numpy as np
import backfire as bf

KEY = b"unit-test-key"
SIZE = 256
THRESH = 2.5      # default per-bit margin threshold for a valid read (robust noise floor)


def _synthetic_marked(key: bytes, idv: int, size: int = SIZE, amp: float = 0.03, seed: int = 0):
    """A gray host plus the exact composite mark the embedder aims for: the sum of
    target_signs * carriers. This is the noiseless ideal the optimizer converges
    toward, so the decoder must recover it cleanly with a wide margin."""
    rng = np.random.default_rng(seed)
    host = np.clip(0.5 + 0.03 * rng.standard_normal((size, size)).astype(np.float32), 0, 1)
    C = bf.keyed_carriers(key, size)
    signs = bf.target_signs(key, idv)
    mark = (signs[:, None, None] * C).sum(0)
    mark /= (np.abs(mark).max() + 1e-9)
    return np.clip(host + amp * mark, 0, 1)


def test_carriers_are_deterministic_and_keyed():
    a = bf.keyed_carriers(KEY, 64)
    b = bf.keyed_carriers(KEY, 64)
    assert np.array_equal(a, b), "same key must give byte-identical carriers"
    c = bf.keyed_carriers(b"other-key", 64)
    assert not np.allclose(a, c), "a different key must give different carriers"
    assert a.shape == (bf.NBITS, 64, 64)


def test_real_and_decoy_carriers_differ():
    real = bf.keyed_carriers(KEY, 64)
    decoy = bf.keyed_carriers(KEY, 64, b"backfire/decoy")
    assert not np.allclose(real, decoy), "decoy carriers must be domain-separated"


def test_full_id_roundtrip_all_ids():
    """Every 4-bit id must decode to itself with every bit well above the floor."""
    for idv in range(1 << bf.ID_BITS):
        marked = _synthetic_marked(KEY, idv)
        got, conf, margin = bf.decode_keyed(marked, KEY, SIZE)
        assert got == idv, f"id 0x{idv:X} decoded as 0x{got:X}"
        assert margin > THRESH, f"id 0x{idv:X} weakest-bit margin {margin:.2f} below threshold"


def test_unmarked_image_is_not_valid():
    rng = np.random.default_rng(1)
    host = np.clip(0.5 + 0.05 * rng.standard_normal((SIZE, SIZE)).astype(np.float32), 0, 1)
    _, conf, margin = bf.decode_keyed(host, KEY, SIZE)
    assert margin < THRESH, f"unmarked image margin {margin:.2f} should be near the floor"


def test_wrong_key_does_not_validate():
    marked = _synthetic_marked(KEY, 0x5)
    _, conf, margin = bf.decode_keyed(marked, b"attacker-guess", SIZE)
    assert margin < THRESH, f"a wrong key gave margin {margin:.2f}; must stay below threshold"


def test_margin_separates_marked_from_unmarked():
    """The whole point: the weakest-bit margin cleanly separates the two classes."""
    rng = np.random.default_rng(2)
    marked_margins, plain_margins = [], []
    for idv in range(16):
        marked_margins.append(bf.decode_keyed(_synthetic_marked(KEY, idv, seed=idv), KEY, SIZE)[2])
        host = np.clip(0.5 + 0.05 * rng.standard_normal((SIZE, SIZE)).astype(np.float32), 0, 1)
        plain_margins.append(bf.decode_keyed(host, KEY, SIZE)[2])
    assert min(marked_margins) > max(plain_margins), \
        f"classes overlap: marked min {min(marked_margins):.2f} vs unmarked max {max(plain_margins):.2f}"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failed += 1; print(f"FAIL {fn.__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    raise SystemExit(1 if failed else 0)
