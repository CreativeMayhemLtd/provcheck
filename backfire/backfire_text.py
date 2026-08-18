#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Backfire-Commercial
# Copyright (C) 2026 Creative Mayhem UG (haftungsbeschränkt)
"""Backfire text channel: a keyed, noise-looking id token smeared into file metadata.

The pixel channel (backfire.py) is what survives diffusion-purification stripping.
This is a cheap *second* channel: a keyed HMAC of the id, written into the file's
text metadata. Because HMAC output is pseudorandom, the token is statistically
indistinguishable from random noise without the key, so:

  * nothing reading the file can tell it is a watermark (it looks like a random
    identifier, a UUID, a tracking blob),
  * nobody without the key can forge it or tell which id it encodes,
  * the key holder recovers the id by trying all 16 candidates and checking which
    one's HMAC matches (a keyed checksum, brute-forced over the tiny id space).

Honest scope: metadata is easy to strip wholesale, so this does NOT survive a
"remove all metadata" pass. Its value is (a) corroborating the pixel id when the
metadata is intact, and (b) evading strippers that only target *known* watermark
signatures (C2PA manifests, specific XMP tags) rather than blanket-wiping metadata,
since a keyed token carries no such signature. The robust channel is always the
pixels; this rides alongside.

  stamp   compute the keyed token for an id and write it into an image's metadata
  verify  read the token back and recover / check the id (try all 16 candidates)
  show    print the raw keyed token for a key+id (no file needed)

PNG only for now (matches backfire.py's output); other containers are future work.
"""
import argparse, hmac, hashlib, json, sys
from PIL import Image, PngImagePlugin

ID_BITS = 4                       # must match backfire.py's id space (0..15)
LABEL = b"backfire/textstamp/v1"
TOKEN_BYTES = 16                  # 128-bit keyed token
# Neutral, plausible metadata keys the smeared token hides behind. They read as
# ordinary identifiers, not "watermark". Order matters (reassembly uses it).
FIELDS = ["Identifier", "DocumentID", "InstanceID"]


def _key_bytes(k: str, is_hex: bool) -> bytes:
    return bytes.fromhex(k) if is_hex else k.encode()


def keyed_token(key: bytes, idv: int) -> bytes:
    """The keyed token for an id: HMAC-SHA256(key, LABEL || id) truncated. Pseudorandom
    and unforgeable without the key; reveals nothing about the id to a keyless reader."""
    h = hmac.new(key, LABEL + int(idv).to_bytes(1, "big"), hashlib.sha256).digest()
    return h[:TOKEN_BYTES]


def _keystream(key: bytes, n: int) -> bytes:
    """A keyed keystream so each smeared shard is independently noise (its bytes carry
    no fixed structure that would betray the split)."""
    out = b""
    i = 0
    while len(out) < n:
        out += hmac.new(key, b"backfire/textstamp/ks" + i.to_bytes(4, "big"), hashlib.sha256).digest()
        i += 1
    return out[:n]


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _as_uuid(b16: bytes) -> str:
    """Format 16 bytes as a UUID string so the token blends in as a generic id."""
    h = b16.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _from_uuid(s: str) -> bytes:
    return bytes.fromhex(s.replace("-", ""))


def encode_fields(key: bytes, idv: int, smear: int):
    """Return {field: value} to write. smear=1 -> one UUID field; smear>1 -> the
    keystream-masked token split across `smear` neutral fields (each looks random)."""
    tok = keyed_token(key, idv)
    if smear <= 1:
        return {FIELDS[0]: _as_uuid(tok)}
    masked = _xor(tok, _keystream(key, len(tok)))       # each shard is noise on its own
    parts = [masked[i::smear] for i in range(smear)]    # interleave so no shard is a prefix
    return {FIELDS[i % len(FIELDS)] + (f".{i}" if i >= len(FIELDS) else ""): parts[i].hex()
            for i in range(smear)}


def decode_token(key: bytes, fields: dict, smear: int):
    """Reassemble the token from metadata fields (inverse of encode_fields)."""
    if smear <= 1:
        v = fields.get(FIELDS[0])
        return _from_uuid(v) if v else None
    keys = [FIELDS[i % len(FIELDS)] + (f".{i}" if i >= len(FIELDS) else "") for i in range(smear)]
    parts = [bytes.fromhex(fields[k]) for k in keys if k in fields]
    if len(parts) != smear:
        return None
    total = sum(len(p) for p in parts)
    masked = bytearray(total)
    for i, p in enumerate(parts):
        masked[i::smear] = p
    return _xor(bytes(masked), _keystream(key, total))


def recover_id(key: bytes, token: bytes):
    """Brute-force the 4-bit id: return the id whose keyed token matches, else None."""
    if not token:
        return None
    for idv in range(1 << ID_BITS):
        if hmac.compare_digest(keyed_token(key, idv), token):
            return idv
    return None


# ------------------------------- CLI -------------------------------
def stamp_cmd(a):
    key = _key_bytes(a.key, a.hexkey)
    img = Image.open(a.infile)
    meta = PngImagePlugin.PngInfo()
    for k, v in (img.text.items() if hasattr(img, "text") else []):
        if k not in FIELDS:                     # preserve unrelated existing text
            meta.add_text(k, v)
    fields = encode_fields(key, a.serial, a.smear)
    for k, v in fields.items():
        meta.add_text(k, v)
    img.save(a.out, pnginfo=meta)
    print(json.dumps({"out": a.out, "id_hex": f"0x{a.serial:X}", "smear": a.smear,
                      "fields": list(fields.keys())}))


def verify_cmd(a):
    key = _key_bytes(a.key, a.hexkey)
    img = Image.open(a.infile)
    fields = dict(img.text) if hasattr(img, "text") else {}
    token = decode_token(key, fields, a.smear)
    idv = recover_id(key, token)
    ok = idv is not None and (a.expect is None or idv == a.expect)
    print(json.dumps({"id": idv, "id_hex": (f"0x{idv:X}" if idv is not None else None),
                      "token_present": token is not None, "valid": idv is not None,
                      "match": (idv == a.expect) if a.expect is not None else None}))
    if a.expect is not None:
        sys.exit(0 if ok else 1)


def show_cmd(a):
    key = _key_bytes(a.key, a.hexkey)
    tok = keyed_token(key, a.serial)
    print(json.dumps({"id_hex": f"0x{a.serial:X}", "token_hex": tok.hex(),
                      "uuid": _as_uuid(tok)}))


def main():
    ap = argparse.ArgumentParser(prog="backfire-text", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(required=True)
    s = sub.add_parser("stamp", help="write the keyed id token into an image's metadata")
    s.add_argument("infile"); s.add_argument("-o", "--out", required=True)
    s.add_argument("--key", required=True); s.add_argument("--hexkey", action="store_true")
    s.add_argument("--serial", type=lambda x: int(x, 0), required=True, help="0..15 keyed id")
    s.add_argument("--smear", type=int, default=1, help="split the token across N neutral fields")
    s.set_defaults(func=stamp_cmd)
    v = sub.add_parser("verify", help="recover / check the id from the token")
    v.add_argument("infile"); v.add_argument("--key", required=True); v.add_argument("--hexkey", action="store_true")
    v.add_argument("--smear", type=int, default=1); v.add_argument("--expect", type=lambda x: int(x, 0), default=None)
    v.set_defaults(func=verify_cmd)
    w = sub.add_parser("show", help="print the raw keyed token (no file)")
    w.add_argument("--key", required=True); w.add_argument("--hexkey", action="store_true")
    w.add_argument("--serial", type=lambda x: int(x, 0), required=True)
    w.set_defaults(func=show_cmd)
    a = ap.parse_args(); a.func(a)


if __name__ == "__main__":
    main()
