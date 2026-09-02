#!/usr/bin/env python3
"""Measure provcheck detection survival against a published
provenance-stripping tool, and refresh the committed golden fixtures.

This is the live re-measurement driver for the committed golden fixtures.
It is intentionally NOT run in
CI (it needs a checkout of the provenance-stripping tool and, for the pixel tier, GPU
ML backends). CI's deterministic anchor is
`crates/provcheck/tests/provenance_stripping.rs`, which runs against the
frozen fixtures this script produces.

What it does, per row:

  audio      generate a silentcipher-marked WAV, feed it to the tool
             (which has no audio path and refuses the file), confirm
             provcheck still decodes the mark.
  c2pa       sign a JPEG (embedded C2PA), strip it with the tool's
             clean_image.py, confirm provcheck reports it unsigned and
             NOT verified (the never-verify invariant), and refresh the
             committed signed/stripped golden fixtures.
  trustmark  embed TrustMark-B on a structured image, run the tool's
             default metadata clean, confirm the pixel mark survives.
             With --pixel, also run the optional diffusion-purification
             backend (GPU) and measure survival there.

Prerequisites:
  - Release binaries: `cargo build --release -p provcheck-cli -p provcheck-kit`.
  - A checkout of the provenance-stripping tool (--wr-dir or $STRIP_TOOL_DIR).
  - Python 3.10+ with Pillow and numpy for fixture synthesis.
  - Image rows need an ONNX Runtime 1.22.x DLL on --ort-dylib or
    $ORT_DYLIB_PATH (provcheck-image loads ort via load-dynamic; a
    mismatched onnxruntime.dll on PATH will otherwise be picked up).
  - The --pixel tier additionally needs the tool's CtrlRegen /
    MarkDiffusion backends set up per its own docs.

Usage:
  python scripts/provenance-strip-matrix.py \
      --wr-dir /path/to/strip-tool \
      --ort-dylib /path/to/onnxruntime.dll \
      [--pixel] [--refresh-fixtures] [--json result.json]
"""

from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import struct
import subprocess
import sys
import wave
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GOLDEN = REPO / "crates" / "provcheck" / "tests" / "fixtures" / "adversary"


def bin_path(name: str) -> Path:
    exe = name + (".exe" if os.name == "nt" else "")
    p = REPO / "target" / "release" / exe
    if not p.exists():
        sys.exit(f"missing binary: {p}\nbuild it: cargo build --release -p provcheck-cli -p provcheck-kit")
    return p


def run(cmd: list[str], env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, env=env)


def provcheck_report(pc: Path, target: Path, env: dict, no_watermark: bool) -> dict:
    cmd = [str(pc), "--json"]
    if no_watermark:
        cmd.append("--no-watermark")
    cmd.append(str(target))
    r = run(cmd, env=env)
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return {"_error": (r.stderr or r.stdout).strip()[:400]}


def wm(report: dict, kind: str) -> dict | None:
    for w in report.get("watermarks") or []:
        if w.get("kind") == kind:
            return w
    return None


def synth_wav(dest: Path) -> None:
    sr, dur = 44100, 6
    n = sr * dur
    dest.parent.mkdir(parents=True, exist_ok=True)
    with wave.open(str(dest), "w") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(sr)
        frames = bytearray()
        # broadband: pseudo-noise (LCG, no numpy dependency) plus tones,
        # so silentcipher has real spectral content to bind to.
        seed = 1234567
        for i in range(n):
            seed = (1103515245 * seed + 12345) & 0x7FFFFFFF
            noise = (seed / 0x7FFFFFFF - 0.5) * 0.30
            t = i / sr
            s = noise + 0.20 * math.sin(2 * math.pi * 220 * t) + 0.12 * math.sin(2 * math.pi * 523 * t)
            s = max(-1.0, min(1.0, s))
            frames += struct.pack("<h", int(s * 30000))
        w.writeframes(bytes(frames))


def synth_photo(dest: Path) -> None:
    from PIL import Image, ImageDraw

    dest.parent.mkdir(parents=True, exist_ok=True)
    w = h = 512
    img = Image.new("RGB", (w, h))
    px = img.load()
    for y in range(h):
        for x in range(w):
            px[x, y] = (
                int(128 + 120 * math.sin(x / 40)),
                int(128 + 120 * math.cos(y / 55)),
                int((x + y) / (w + h) * 255),
            )
    d = ImageDraw.Draw(img)
    d.ellipse([80, 80, 300, 300], fill=(230, 180, 60))
    d.rectangle([320, 300, 470, 470], fill=(40, 90, 180))
    d.line([0, 0, w, h], fill=(255, 255, 255), width=6)
    img.save(dest)


def row_audio(pc: Path, kit: Path, wr: Path, work: Path, env: dict) -> dict:
    src, marked = work / "audio.wav", work / "marked.wav"
    synth_wav(src)
    if marked.exists():
        marked.unlink()
    e = run([str(kit), "watermark", "--kind", "silentcipher", "--payload",
             "5241490100", "--sdr-db", "22", str(src), "-o", str(marked)])
    if not marked.exists():
        return {"row": "audio", "error": "embed failed", "detail": e.stderr[-300:]}
    base = wm(provcheck_report(pc, marked, env, no_watermark=False), "silent_cipher")
    # The tool has no audio path; clean_file.py refuses non text/image/container bytes.
    clean = run([sys.executable, str(wr / "service/scripts/clean_file.py"),
                 str(marked), "-o", str(work / "audio_cleaned.wav"), "--json"])
    refused = not (work / "audio_cleaned.wav").exists()
    post = wm(provcheck_report(pc, marked, env, no_watermark=False), "silent_cipher")
    return {
        "row": "audio",
        "tool_refused_audio": refused,
        "baseline": base and {"status": base.get("status"), "conf": base.get("confidence")},
        "post": post and {"status": post.get("status"), "conf": post.get("confidence")},
        "survives": bool(post and post.get("status") == "detected"),
    }


def row_c2pa(pc: Path, kit: Path, wr: Path, work: Path, env: dict, refresh: bool) -> dict:
    from PIL import Image

    orig, signed, stripped = work / "orig.jpg", work / "signed.jpg", work / "stripped.jpg"
    data = work / "kitdata"
    Image.new("RGB", (96, 96), (200, 40, 40)).save(orig, "JPEG", quality=90)
    if not (data / "keys").exists() and not (data).exists():
        run([str(kit), "init", "--data-dir", str(data)])
    else:
        run([str(kit), "init", "--data-dir", str(data)])
    run([str(kit), "sign", str(orig), "--data-dir", str(data), "-o", str(signed)])
    base = provcheck_report(pc, signed, env, no_watermark=True)
    run([sys.executable, str(wr / "service/scripts/clean_image.py"),
         str(signed), "-o", str(stripped), "--json"])
    post = provcheck_report(pc, stripped, env, no_watermark=True)
    invariant_ok = (post.get("verified") is False) and (post.get("unsigned") is True)
    if refresh and signed.exists() and stripped.exists():
        GOLDEN.mkdir(parents=True, exist_ok=True)
        shutil.copy(signed, GOLDEN / "signed.jpg")
        shutil.copy(stripped, GOLDEN / "stripped-v0.5.0.jpg")
    return {
        "row": "c2pa",
        "baseline": {"verified": base.get("verified"), "unsigned": base.get("unsigned")},
        "post": {"verified": post.get("verified"), "unsigned": post.get("unsigned")},
        "invariant_holds": invariant_ok,
        "survives": False,  # a metadata wipe removes an embedded manifest by design
    }


def row_trustmark(pc: Path, kit: Path, wr: Path, work: Path, env: dict, pixel: bool) -> dict:
    photo, tm = work / "photo.png", work / "tm.png"
    synth_photo(photo)
    run([str(kit), "watermark", "--kind", "image", str(photo), "-o", str(tm), "--overwrite"], env=env)
    base = wm(provcheck_report(pc, tm, env, no_watermark=False), "trust_mark")
    result = {"row": "trustmark",
              "baseline": base and {"status": base.get("status"), "conf": base.get("confidence")}}
    # metadata-only clean: expected to leave pixels untouched
    meta_out = work / "tm_metaclean.png"
    run([sys.executable, str(wr / "service/scripts/clean_image.py"),
         str(tm), "-o", str(meta_out), "--json"])
    meta = wm(provcheck_report(pc, meta_out, env, no_watermark=False), "trust_mark")
    result["metadata_strip"] = {
        "status": meta and meta.get("status"),
        "conf": meta and meta.get("confidence"),
        "survives": bool(meta and meta.get("status") == "detected"),
    }
    if pixel:
        # optional GPU tier: diffusion-purification regeneration
        px_out = work / "tm_pixel.png"
        e = run([sys.executable, str(wr / "service/scripts/clean_image.py"),
                 str(tm), "-o", str(px_out), "--remove-pixel", "diffusion", "--json"], env=env)
        if px_out.exists():
            px = wm(provcheck_report(pc, px_out, env, no_watermark=False), "trust_mark")
            result["pixel_strip"] = {
                "status": px and px.get("status"),
                "conf": px and px.get("confidence"),
                "survives": bool(px and px.get("status") == "detected"),
            }
        else:
            result["pixel_strip"] = {"error": "backend not available", "detail": e.stderr[-300:]}
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--wr-dir", default=os.environ.get("STRIP_TOOL_DIR"),
                    help="provenance-stripping-tool checkout root")
    ap.add_argument("--ort-dylib", default=os.environ.get("ORT_DYLIB_PATH"),
                    help="path to an ONNX Runtime 1.22.x DLL/so for the image rows")
    ap.add_argument("--work", default=None, help="scratch dir (default: a temp dir)")
    ap.add_argument("--pixel", action="store_true", help="also run the GPU diffusion-purification tier")
    ap.add_argument("--refresh-fixtures", action="store_true",
                    help="overwrite the committed golden C2PA fixtures with this run's output")
    ap.add_argument("--rows", default="audio,c2pa,trustmark",
                    help="comma-separated subset of rows to run")
    ap.add_argument("--json", dest="json_out", default=None, help="write full results JSON here")
    args = ap.parse_args()

    if not args.wr_dir:
        sys.exit("need --wr-dir (or $STRIP_TOOL_DIR): a provenance-stripping-tool checkout")
    wr = Path(args.wr_dir).resolve()
    pc, kit = bin_path("provcheck"), bin_path("provcheck-kit")

    env = dict(os.environ)
    if args.ort_dylib:
        env["ORT_DYLIB_PATH"] = str(Path(args.ort_dylib).resolve())

    import tempfile
    work = Path(args.work).resolve() if args.work else Path(tempfile.mkdtemp(prefix="strip-matrix-"))
    work.mkdir(parents=True, exist_ok=True)

    rows = [r.strip() for r in args.rows.split(",") if r.strip()]
    results = []
    if "audio" in rows:
        results.append(row_audio(pc, kit, wr, work, env))
    if "c2pa" in rows:
        results.append(row_c2pa(pc, kit, wr, work, env, args.refresh_fixtures))
    if "trustmark" in rows:
        results.append(row_trustmark(pc, kit, wr, work, env, args.pixel))

    print(json.dumps(results, indent=2))
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
