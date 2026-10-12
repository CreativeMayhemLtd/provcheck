#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1 OR LicenseRef-Backfire-Commercial
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


def test_notch_tamper_stat_survives_degenerate_images():
    """Regression: a solid or near-flat image makes the radial power spectrum fit
    the degree-4 trend perfectly, so the dip-drop mask collapsed to empty and the
    refit `np.polyfit` raised "expected non-empty vector for x", killing the whole
    read. The stat must now return a finite number for these inputs, not crash."""
    for size in (256, 512):
        for img in (
            np.full((size, size), 0.5, np.float32),   # solid gray
            np.zeros((size, size), np.float32),        # solid black
            np.ones((size, size), np.float32),         # solid white
        ):
            stat = bf.notch_tamper_stat(img, size)
            assert isinstance(stat, float) and np.isfinite(stat) and stat >= 0.0, \
                f"degenerate {size}px image gave {stat!r}"


# ------------------------------- P1 multi-band -------------------------------
def _synthetic_multiband(key, idv, size=SIZE, amp=0.03, seed=0):
    """Host plus the ideal multi-band mark: target_signs * (band-A carriers + domain-separated band-B
    carriers). decode_multiband must recover it, and it must survive a notch of either band."""
    rng = np.random.default_rng(seed)
    host = np.clip(0.5 + 0.03 * rng.standard_normal((size, size)).astype(np.float32), 0, 1)
    CA = bf.build_carriers(key, size, "band", None, b"backfire/carrier")
    CB = bf.build_carriers(key, size, "band", None, b"backfire/carrier/B", bf.BAND_B)
    signs = bf.target_signs(key, idv)
    mark = (signs[:, None, None] * CA).sum(0) + (signs[:, None, None] * CB).sum(0)
    mark /= (np.abs(mark).max() + 1e-9)
    return np.clip(host + amp * mark, 0, 1)


def _notch(img, lo, hi, size=SIZE):
    yy, xx = np.mgrid[0:size, 0:size].astype(np.float32)
    rad = np.sqrt((xx - size/2)**2 + (yy - size/2)**2); m = (rad > lo) & (rad < hi)
    F = np.fft.fftshift(np.fft.fft2(img)); F[m] = 0.0
    return np.clip(np.real(np.fft.ifft2(np.fft.ifftshift(F))), 0, 1)


def test_multiband_roundtrip_and_notch_survival():
    marked = _synthetic_multiband(KEY, 0x7)
    got, _c, margin = bf.decode_multiband(marked, KEY, SIZE)
    assert got == 0x7 and margin > THRESH, f"clean multi-band read id 0x{got:X} margin {margin:.2f}"
    gotA, _c, mA = bf.decode_multiband(_notch(marked, 6, 40), KEY, SIZE)
    assert gotA == 0x7 and mA > THRESH, f"notch band A: id 0x{gotA:X} margin {mA:.2f} (should survive via B)"
    gotB, _c, mB = bf.decode_multiband(_notch(marked, 44, 80), KEY, SIZE)
    assert gotB == 0x7 and mB > THRESH, f"notch band B: id 0x{gotB:X} margin {mB:.2f} (should survive via A)"


def test_multiband_wrong_key_invalid():
    marked = _synthetic_multiband(KEY, 0x5)
    _i, _c, margin = bf.decode_multiband(marked, b"attacker-guess", SIZE)
    assert margin < THRESH, f"wrong-key multi-band margin {margin:.2f} must stay below threshold"


def test_multiband_is_additive_single_band_unchanged():
    """Backward-compat: a legacy single-band mark still reads via the default decode_keyed path."""
    marked = _synthetic_marked(KEY, 0x7)
    got, _c, margin = bf.decode_keyed(marked, KEY, SIZE)
    assert got == 0x7 and margin > THRESH


# ------------------------------- P2 Tardos -------------------------------
def _TC(key=KEY, n=512):
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from tardos import TardosCode
    return TardosCode(key, n_bits=n, size=SIZE)


def _tardos_marked(tc, seat, amp=0.05, seed=0):
    rng = np.random.default_rng(seed)
    host = np.clip(0.5 + 0.03 * rng.standard_normal((SIZE, SIZE)).astype(np.float32), 0, 1)
    C = tc.carriers()
    mark = (tc.target_signs(seat)[:, None, None] * C).sum(0)
    mark /= (np.abs(mark).max() + 1e-9)
    return np.clip(host + amp * mark, 0, 1)


def test_tardos_single_seat_trace():
    tc = _TC(); seats = list(range(300))
    acc, _s = tc.accuse(_tardos_marked(tc, 42, seed=1), seats)
    assert 42 in acc and set(acc) == {42}, f"single-seat trace accused {acc}"


def test_tardos_collusion_c2_traces_a_colluder():
    tc = _TC(); seats = list(range(300))
    avg = (_tardos_marked(tc, 10, seed=1) + _tardos_marked(tc, 20, seed=2)) / 2.0
    acc, _s = tc.accuse(avg, seats)
    assert set(acc) & {10, 20}, f"c=2 collusion traced no colluder: {acc}"
    assert not (set(acc) - {10, 20}), f"c=2 collusion falsely accused {set(acc) - {10, 20}}"


def test_tardos_wrong_key_no_accusation():
    tc, tc_wrong = _TC(), _TC(b"attacker-guess")
    acc, _s = tc_wrong.accuse(_tardos_marked(tc, 7, seed=3), list(range(300)))
    assert not acc, f"wrong-key falsely accused {acc}"


# ------------------------------- P5 content-bind (forgery resistance) -------------------------------
def _content_read(rgb, key):
    ck = bf._content_key(key, rgb)                    # reader derives the per-image key from the image
    C = bf.keyed_carriers(ck, SIZE); Cd = bf.keyed_carriers(ck, SIZE, b"backfire/decoy")
    g = rgb.mean(2); return bf.decode(g - g.mean(), C, Cd)


def _structured_host(seed):
    # low-frequency structure (gradient + sinusoids) so the coarse average-hash is STABLE under an
    # imperceptible mark -- the realistic case (a real photo, not pure noise).
    yy, xx = np.mgrid[0:SIZE, 0:SIZE].astype(np.float32) / SIZE
    rng = np.random.default_rng(seed)
    base = 0.35 + 0.3 * xx + 0.15 * np.sin(5 * yy + seed) + 0.1 * np.cos(3 * xx * (seed + 1)) \
        + 0.03 * rng.standard_normal((SIZE, SIZE))
    return np.clip(np.stack([base, base, base], -1), 0, 1).astype(np.float32)


def _content_marked(key, idv, seed, amp=0.03):
    host = _structured_host(seed)
    ck = bf._content_key(key, host)
    C = bf.keyed_carriers(ck, SIZE); signs = bf.target_signs(ck, idv)
    mark = (signs[:, None, None] * C).sum(0); mark /= (np.abs(mark).max() + 1e-9)
    return np.clip(host + amp * mark[:, :, None], 0, 1), host


def test_content_bind_reads_and_resists_replay():
    mA, hostA = _content_marked(KEY, 0x7, seed=1)
    got, _c, margin = _content_read(mA, KEY)
    assert got == 0x7 and margin > THRESH, f"genuine content-bound read id 0x{got:X} margin {margin:.2f}"
    # replay A's mark onto a DIFFERENT host -> its content key differs -> forgery must fail
    hostB = _structured_host(99)
    replay = np.clip(hostB + (mA - hostA), 0, 1)
    gi, _c, gm = _content_read(replay, KEY)
    assert not (gi == 0x7 and gm > THRESH), f"replay onto another image should fail content-bind (got id 0x{gi:X} margin {gm:.2f})"


# ------------------------------- M1 fast carrier-add mode -------------------------------
def test_fast_mode_cli_writes_a_readable_mark():
    """The --fast path (no model, no optimization, pure numpy) must write a mark the shipped reader
    validates. CPU-only smoke test of the CLI wiring; the carrier-add MATH is already covered by the
    synthetic roundtrip tests. Uses a structured host so the write/read round-trips deterministically."""
    import sys, os, json, subprocess, tempfile
    from PIL import Image as _Image
    d = tempfile.mkdtemp()
    src, out = os.path.join(d, "src.png"), os.path.join(d, "m.png")
    _Image.fromarray((_structured_host(3) * 255).astype(np.uint8)).save(src)
    here = os.path.dirname(os.path.abspath(__file__)); bf_py = os.path.join(here, "backfire.py")
    e = subprocess.run([sys.executable, bf_py, "embed", src, "-o", out, "--key", "testkey",
                        "--serial", "0x7", "--bands", "ab", "--fast"], capture_output=True, text=True)
    assert os.path.exists(out), f"--fast produced no file: {e.stderr[-300:]}"
    r = subprocess.run([sys.executable, bf_py, "read", out, "--key", "testkey", "--size", "256", "--bands", "ab"],
                       capture_output=True, text=True)
    j = json.loads(r.stdout.strip().splitlines()[-1])
    assert j.get("valid") and j.get("id_hex") == "0x7", f"fast mark did not read valid: {j}"


# ------------------------------- M2 selective N-frame keying -------------------------------
def test_video_keyed_subset_and_quorum():
    """Keyed subset selection is deterministic + keyed; marking the subset and quorum-reading recovers
    the serial (even with some marked frames dropped), and unmarked/wrong-key clips read nothing."""
    import video_keying as vk
    key = bf._key_bytes("testkey", False)
    a = vk.keyed_subset(key, 30, every=5); b = vk.keyed_subset(key, 30, every=5)
    assert a == b and all(0 <= i < 30 for i in a), "keyed_subset must be deterministic + in range"
    rng = np.random.default_rng(0)
    frames = [np.clip(0.5 + 0.2 * rng.standard_normal((256, 256, 3)).astype(np.float32), 0, 1) for _ in range(30)]
    idx = vk.keyed_subset(key, 30, density=0.25)
    for i in idx:
        frames[i] = vk.fast_mark(frames[i], key, 0x7)
    q = vk.quorum_read(frames, key)
    assert q["id"] == 0x7 and q["agree"] >= max(1, len(idx) // 2), f"quorum failed to recover the serial: {q}"
    # dropping half the marked frames still recovers via quorum
    surv = [frames[i] for i in range(len(frames)) if i not in idx[:len(idx) // 2]]
    assert vk.quorum_read(surv, key)["id"] == 0x7, "quorum should survive losing half the marked frames"
    # no false positive on unmarked, and a wrong key reads nothing
    clean = [np.clip(0.5 + 0.2 * rng.standard_normal((256, 256, 3)).astype(np.float32), 0, 1) for _ in range(10)]
    assert vk.quorum_read(clean, key)["id"] is None, "unmarked clip must not false-positive"
    assert vk.quorum_read(frames, bf._key_bytes("wrongkey", False))["id"] is None, "wrong key must read nothing"


# ------------------------------- register (geometry recovery) -------------------------------
def test_register_recovers_a_rotated_mark():
    """The opt-in --register reader must recover a keyed id from a ROTATED marked image that the base
    geometry-naive read misses. Synthetic band-A composite mark; no model needed."""
    from PIL import Image as _I
    g = _synthetic_marked(KEY, 0x7)                                  # (SIZE,SIZE) grayscale float
    rgb = _I.fromarray((np.stack([g] * 3, -1) * 255).astype(np.uint8))
    rot = rgb.rotate(6, resample=_I.BICUBIC, expand=False)
    grot = np.asarray(rot.resize((SIZE, SIZE)), np.float32).mean(2) / 255.0
    _i, _c, base_m = bf.decode_keyed(grot, KEY, SIZE, "band")
    assert base_m < THRESH, f"premise broken: base read survived rotation (margin {base_m:.2f})"
    idv, _conf, margin, _sz, _ang, _pad = bf.register_search(rot, KEY, [SIZE], "band", 0x7, 12, 0.1)
    assert idv == 0x7 and margin > THRESH, f"register failed to recover the rotated mark: id 0x{idv:X} margin {margin:.2f}"


# ------------------------------- M2 native-resolution video keying -------------------------------
def test_video_keying_native_resolution():
    """fast_mark/read must work at full, non-square video resolution (mark computed in carrier space,
    delta resized to native), not only 256x256."""
    import video_keying as vk
    key = bf._key_bytes("testkey", False)
    yy, xx = np.mgrid[0:480, 0:854].astype(np.float32)
    base = np.clip(0.4 + 0.3 * (xx / 854) + 0.1 * np.sin(6 * yy / 480), 0, 1).astype(np.float32)
    frame = np.stack([base] * 3, -1)
    marked = vk.fast_mark(frame, key, 0x7)
    assert marked.shape == frame.shape, f"native resolution not preserved: {marked.shape} vs {frame.shape}"
    idv, margin, ok = vk.read_frame(marked, key)
    assert ok and idv == 0x7, f"native-res mark did not read valid: id {idv} margin {margin:.2f}"


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
