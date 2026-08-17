#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Backfire-Commercial
"""Unit tests for the Backfire keyed text channel (backfire_text.py).

Covers the crypto/encoding core with no file I/O: token determinism and keying,
id recovery, wrong-key rejection, the smear split/reassemble roundtrip, and a
basic check that the token looks like noise (uniform byte distribution).

Run:  python test_backfire_text.py     or     pytest test_backfire_text.py
"""
import backfire_text as bt

KEY = b"unit-test-key"


def test_token_deterministic_and_keyed():
    for idv in range(16):
        assert bt.keyed_token(KEY, idv) == bt.keyed_token(KEY, idv)
        assert len(bt.keyed_token(KEY, idv)) == bt.TOKEN_BYTES
    # different ids -> different tokens; different key -> different tokens
    assert len({bt.keyed_token(KEY, i) for i in range(16)}) == 16
    diff = sum(bt.keyed_token(KEY, i) != bt.keyed_token(b"other", i) for i in range(16))
    assert diff == 16, "every token must change with the key"


def test_recover_id_roundtrip_all_ids():
    for idv in range(16):
        assert bt.recover_id(KEY, bt.keyed_token(KEY, idv)) == idv


def test_wrong_key_cannot_recover():
    # a token made under KEY should not resolve to any id under a different key
    hits = sum(bt.recover_id(b"attacker", bt.keyed_token(KEY, i)) is not None for i in range(16))
    assert hits == 0, f"wrong key recovered {hits}/16 ids; must be 0"


def test_smear_roundtrip():
    for smear in (1, 2, 3, 5):
        for idv in range(16):
            fields = bt.encode_fields(KEY, idv, smear)
            assert len(fields) == max(1, smear)
            tok = bt.decode_token(KEY, fields, smear)
            assert bt.recover_id(KEY, tok) == idv, f"smear={smear} id=0x{idv:X} failed roundtrip"


def test_smeared_shards_need_the_key():
    # with smear, each shard is keystream-masked; the wrong key reassembles to noise
    fields = bt.encode_fields(KEY, 0x9, 3)
    tok = bt.decode_token(b"wrong-key", fields, 3)
    assert bt.recover_id(KEY, tok) is None, "shards must be useless without the key"


def test_token_looks_like_noise():
    # aggregate many tokens; byte values should be roughly uniform over 0..255
    # (a crude randomness sanity check, not a formal test of the PRF)
    from collections import Counter
    c = Counter()
    for idv in range(16):
        for kb in range(64):
            c.update(bt.keyed_token(bytes([kb]) + KEY, idv))
    counts = [c.get(b, 0) for b in range(256)]
    total = sum(counts)
    # no byte value should dominate: max bucket well under 2x the uniform expectation
    assert max(counts) < 2.0 * (total / 256), "token bytes are not uniform enough to pass as noise"


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
