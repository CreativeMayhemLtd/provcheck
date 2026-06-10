#!/usr/bin/env python3
"""
Embed a silentcipher watermark into an audio file.

Run on a machine that has the upstream silentcipher Python
package installed (we don't have it locally in the Rust
workspace — same as the ONNX export, this is a handoff
script). Produces a marked WAV that the Rust verifier's
integration tests can decode end-to-end.

Why this script exists
----------------------
The provcheck verifier ships the silentcipher *decoder* as an
embedded ONNX. The matching *encoder* lives in the upstream
Python package (sony/silentcipher) and is what we need to
generate a positive-control test fixture.

Drop the resulting file at:

    crates/provcheck-watermark/tests/fixtures/silentcipher-marked.wav

then remove the `#[ignore]` attribute from
`real_watermarked_audio_is_detected` in
`crates/provcheck-watermark/tests/integration.rs`. After that,
`cargo test --workspace` will exercise the end-to-end pipeline
against a file with a known payload and confirm the recovered
bytes match.

Usage (the easy way)
--------------------
    pip install silentcipher        # if not already installed
    python scripts/embed-silentcipher.py path/to/any-clip.mp3

That's it. Defaults handle the rest:
    - Output: crates/provcheck-watermark/tests/fixtures/silentcipher-marked.wav
    - Payload: DFM  (doomscroll.fm — exercises the brand registry)
    - Duration: 15 s  (≈ 30 silentcipher tiles, robust mode-vote)
    - Model: 44.1 kHz variant (matches the decoder ONNX provcheck embeds)

Overrides if you want them
--------------------------
    --payload RAI               # different brand triplet
    --out /tmp/foo.wav          # different output path
    --duration-s 30             # longer / shorter clip
    --model-type 16_khz         # alternate silentcipher variant

Payload conventions
-------------------
The 5-byte payload is interpreted by provcheck's brand
dispatch (schema-1):
    byte 0..3 : ASCII brand triplet  (e.g. "DFM" → 68, 70, 77)
    byte 3    : schema version       (= 1)
    byte 4    : reserved             (= 0)

Pass `--payload DFM` to embed [68, 70, 77, 1, 0]. Provcheck
will then report:
    silentcipher: detected — doomscroll.fm (XX% confidence)
        payload: 44464d0100

Known FOSS brand triplets per WATERMARK_LICENSE_POLICY.md /
the brand registry in `provcheck/src/report.rs`:
    RAI → rAIdio.bot
    DFM → doomscroll.fm
    VAI → vAIdeo.bot

Any 3 ASCII chars work. Unknown triplets verify as
`unrecognized source "XYZ"` — useful for testing the
brand-agnostic path.
"""

import argparse
import sys
from pathlib import Path

# Heavy deps (silentcipher, librosa, soundfile, numpy) are
# imported lazily inside main() so `--help` works on a clean
# checkout. The fail-fast guards live there.


SAMPLE_RATE = 44_100

# Default output path: the canonical test fixture location, relative to
# the repo root (the script lives in repo-root/scripts/, so we walk up
# one directory). The integration test in
# crates/provcheck-watermark/tests/integration.rs reads from here.
DEFAULT_FIXTURE = (
    Path(__file__).resolve().parent.parent
    / "crates" / "provcheck-watermark" / "tests" / "fixtures"
    / "silentcipher-marked.wav"
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("input", type=Path,
                   help="Input audio (wav/mp3/flac/anything librosa can read).")
    p.add_argument("--out", "-o", dest="output", type=Path, default=DEFAULT_FIXTURE,
                   help=f"Output WAV path. Default: {DEFAULT_FIXTURE.relative_to(Path.cwd()) if DEFAULT_FIXTURE.is_relative_to(Path.cwd()) else DEFAULT_FIXTURE}")
    p.add_argument("--payload", "-p", default="DFM",
                   help="3 ASCII letters → schema-1 brand triplet. "
                        "Bytes 3 and 4 are auto-set to schema=1, reserved=0. "
                        "Default: DFM (doomscroll.fm — exercises the brand registry).")
    p.add_argument("--duration-s", "-d", type=float, default=15.0,
                   help="Truncate input to this many seconds before embedding. "
                        "Default: 15  (≈30 silentcipher tiles, robust mode-vote).")
    p.add_argument("--model-type", default="44_1_khz",
                   choices=["16_khz", "44_1_khz"],
                   help="Which silentcipher variant to load. Must match the "
                        "decoder ONNX that provcheck ships. Default: 44_1_khz.")
    return p.parse_args()


def encode_payload(letters: str) -> list[int]:
    if len(letters) != 3 or not letters.isascii():
        sys.exit(f"--payload must be exactly 3 ASCII characters, got: {letters!r}")
    return [ord(letters[0]), ord(letters[1]), ord(letters[2]), 1, 0]


def main() -> None:
    args = parse_args()
    payload_bytes = encode_payload(args.payload)
    print(f"payload: {payload_bytes}  ({args.payload!r} + schema=1 + reserved=0)")

    # Lazy imports — failing late means `--help` still works
    # on a machine that doesn't have silentcipher installed.
    try:
        import silentcipher  # type: ignore[import-not-found]
    except ImportError as e:
        sys.exit(
            f"silentcipher not installed: {e}\n"
            "Install with: pip install silentcipher"
        )
    try:
        import librosa  # type: ignore[import-not-found]
        import numpy as np  # type: ignore[import-not-found]
        import soundfile as sf  # type: ignore[import-not-found]
    except ImportError as e:
        sys.exit(
            f"required dep missing: {e}\n"
            "Install with: pip install librosa soundfile numpy"
        )

    print(f"loading model: silentcipher {args.model_type}")
    model = silentcipher.get_model(model_type=args.model_type, device="cpu")

    print(f"reading input: {args.input}")
    y, sr = librosa.load(str(args.input), sr=SAMPLE_RATE, mono=True)
    if args.duration_s and args.duration_s > 0:
        max_samples = int(args.duration_s * SAMPLE_RATE)
        if len(y) > max_samples:
            y = y[:max_samples]
            print(f"truncated to {args.duration_s} s")
        elif len(y) < max_samples:
            print(f"input is shorter than --duration-s ({len(y)/SAMPLE_RATE:.2f} s "
                  f"< {args.duration_s} s); embedding the full clip as-is")
    print(f"input shape: {y.shape}  ({len(y) / SAMPLE_RATE:.2f} s @ {SAMPLE_RATE} Hz mono)")

    print("embedding watermark...")
    # The exact API surface varies slightly across silentcipher versions:
    #   encode_wav(y, sr, message=...) → (marked_y, sdr)
    # If `message` doesn't accept a list of ints, try a str or `messages=[...]`
    # depending on the version installed. The script intentionally falls
    # back so it works against minor API drift.
    marked = None
    last_err = None
    for kw in [
        dict(message=payload_bytes),
        dict(messages=[payload_bytes]),
        dict(message=bytes(payload_bytes)),
    ]:
        try:
            result = model.encode_wav(y, sr=SAMPLE_RATE, **kw)
            # encode_wav typically returns (waveform, sdr_db) or a dict
            if isinstance(result, tuple):
                marked, sdr = result[0], result[1] if len(result) > 1 else None
            elif isinstance(result, dict) and "wav" in result:
                marked, sdr = result["wav"], result.get("sdr")
            else:
                marked, sdr = result, None
            print(f"encode_wav succeeded with kwargs {list(kw.keys())}; sdr={sdr}")
            break
        except (TypeError, ValueError, AttributeError) as e:
            last_err = e
            continue
    if marked is None:
        sys.exit(f"encode_wav failed under all candidate kwargs; last error: {last_err}")

    marked = np.asarray(marked, dtype=np.float32)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    sf.write(str(args.output), marked, SAMPLE_RATE)
    print(f"wrote: {args.output}  ({len(marked) / SAMPLE_RATE:.2f} s @ {SAMPLE_RATE} Hz)")
    print("done. Drop into crates/provcheck-watermark/tests/fixtures/ and "
          "remove the #[ignore] on real_watermarked_audio_is_detected.")


if __name__ == "__main__":
    main()
