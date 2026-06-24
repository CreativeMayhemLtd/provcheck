#!/usr/bin/env python3
"""
Parity harness: compare provcheck-watermark (Rust) embed against
upstream silentcipher (Python) embed across a sweep of SDR values.

Why this exists
---------------
v0.5.1's silentcipher embed produces marks that fail to survive lossy
re-encode (public issue #23). The 47 dB default SDR is at the
imperceptibility edge, so part of the gap is just "lower the SDR".
But before changing the default we want to confirm the Rust port is
faithful to the upstream Python implementation at the same nominal
SDR. If it is not, the SDR drop alone will not fully close the
margin gap.

What this produces
------------------
A table on stdout of detect confidence per (implementation, SDR),
plus sample-by-sample correlation of the two outputs at each SDR.
Optional AAC and MP3 re-encode survival columns when ffmpeg is on
PATH.

Run
---
    pip install silentcipher librosa soundfile numpy scipy
    python -c "from huggingface_hub import snapshot_download; snapshot_download('sony/silentcipher')"
    cargo build --release --bin provcheck-kit --bin provcheck
    python scripts/parity-vs-upstream.py examples/rAIdio.bot-sample.mp3

Pass --sdrs 25 30 35 40 47 to override the sweep. Pass
--out-dir <path> to keep the intermediate WAVs for inspection.

Sources and confidentiality
---------------------------
The reference is the upstream Python silentcipher library at the
44.1k snapshot we already use for our ONNX export. We do NOT read
or reference private downstream pipelines; the harness operates
only on the bundled examples/ fixtures and public-Hub weights.
"""

import argparse
import os
import shutil
import subprocess
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

DEFAULT_PAYLOAD_LETTERS = "DFM"
DEFAULT_PAYLOAD_BYTES = [0x44, 0x46, 0x4D, 0x01, 0x00]
DEFAULT_SDRS = [25.0, 30.0, 35.0, 40.0, 47.0]
DEFAULT_DURATION_S = 15.0
SAMPLE_RATE = 44_100


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("input", type=Path, help="Source audio (any librosa-readable format).")
    p.add_argument("--sdrs", type=float, nargs="+", default=DEFAULT_SDRS,
                   help=f"SDR values in dB to sweep. Default: {DEFAULT_SDRS}")
    p.add_argument("--duration-s", type=float, default=DEFAULT_DURATION_S,
                   help=f"Truncate input to this many seconds. Default: {DEFAULT_DURATION_S}")
    p.add_argument("--out-dir", type=Path,
                   default=REPO_ROOT / "target" / "parity-vs-upstream",
                   help="Directory for intermediate WAVs and the report. "
                        "Created if absent.")
    p.add_argument("--kit-binary", type=Path,
                   default=REPO_ROOT / "target" / "release" / "provcheck-kit.exe",
                   help="Path to provcheck-kit binary (release build).")
    p.add_argument("--verify-binary", type=Path,
                   default=REPO_ROOT / "target" / "release" / "provcheck.exe",
                   help="Path to provcheck binary (release build).")
    p.add_argument("--skip-codec", action="store_true",
                   help="Skip the AAC/MP3 re-encode survival pass, "
                        "even if ffmpeg is available.")
    return p.parse_args()


def load_silentcipher():
    """Load the upstream silentcipher 44.1k model, pointing at the
    HuggingFace cache. Re-implements scripts/export-silentcipher-
    encoder.py's `find_silentcipher_44k_cache` so this harness does
    not depend on the export step having been run."""
    import silentcipher
    candidates = [
        Path.home() / ".cache" / "huggingface" / "hub" / "models--sony--silentcipher",
    ]
    hf_home = os.environ.get("HF_HOME")
    if hf_home:
        candidates.append(Path(hf_home) / "hub" / "models--sony--silentcipher")
    for base in candidates:
        if not base.exists():
            continue
        snaps = list((base / "snapshots").glob("*/44_1_khz/73999_iteration"))
        if snaps:
            ckpt = str(snaps[0])
            cfg = str(snaps[0] / "hparams.yaml")
            return silentcipher.get_model(
                model_type="44.1k",
                ckpt_path=ckpt,
                config_path=cfg,
                device="cpu",
            )
    sys.exit(
        "silentcipher 44.1k weights not found in HF cache. Run:\n"
        "  python -c \"from huggingface_hub import snapshot_download; "
        "snapshot_download('sony/silentcipher')\""
    )


def python_embed(model, y, message_bytes, sdr_db):
    """Run upstream silentcipher.encode_wav at the given SDR.
    Returns a float32 numpy array at SAMPLE_RATE."""
    import numpy as np
    result = model.encode_wav(
        y,
        orig_sr=SAMPLE_RATE,
        message=message_bytes,
        message_sdr=sdr_db,
    )
    if isinstance(result, tuple):
        marked = result[0]
    elif isinstance(result, dict) and "wav" in result:
        marked = result["wav"]
    else:
        marked = result
    return np.asarray(marked, dtype=np.float32)


def rust_embed(kit_binary, input_path, output_path, payload_hex, sdr_db):
    """Call the Rust provcheck-kit watermark CLI at the given SDR."""
    cmd = [
        str(kit_binary), "watermark",
        str(input_path), "-o", str(output_path),
        "--payload", payload_hex,
        "--sdr-db", str(sdr_db),
        "--overwrite",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(
            f"provcheck-kit watermark failed (exit {res.returncode}):\n"
            f"stderr:\n{res.stderr}\nstdout:\n{res.stdout}"
        )


def rust_detect(verify_binary, wav_path):
    """Call provcheck --json and return the silentcipher confidence.
    Returns None if the verifier could not run or no watermark slot
    came back."""
    import json
    cmd = [str(verify_binary), "--json", str(wav_path)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"  [warn] verify failed for {wav_path.name}: {res.stderr.strip()}")
        return None
    try:
        report = json.loads(res.stdout)
    except json.JSONDecodeError:
        print(f"  [warn] verify output not JSON for {wav_path.name}")
        return None
    watermarks = report.get("watermarks") or []
    for w in watermarks:
        family = w.get("family") or w.get("kind") or ""
        if "silent" in family.lower():
            return float(w.get("confidence", w.get("conf", 0.0)))
    return None


def python_detect(model, wav_path):
    """Use upstream silentcipher.decode_wav on the given file.
    Returns confidence (float) or None if no payload recovered."""
    import librosa
    y, _ = librosa.load(str(wav_path), sr=SAMPLE_RATE, mono=True)
    try:
        result = model.decode_wav(y, SAMPLE_RATE, phase_shift_decoding=False)
    except AttributeError:
        return None
    if not isinstance(result, dict) or not result.get("status"):
        return None
    confs = result.get("confidences") or []
    return float(confs[0]) if confs else None


def correlate(a, b):
    """Sample-by-sample Pearson correlation, clipped to the shorter length."""
    import numpy as np
    n = min(len(a), len(b))
    if n < 2:
        return float("nan")
    a, b = a[:n], b[:n]
    am, bm = a.mean(), b.mean()
    num = ((a - am) * (b - bm)).sum()
    den = (((a - am) ** 2).sum() ** 0.5) * (((b - bm) ** 2).sum() ** 0.5)
    return float(num / den) if den > 0 else float("nan")


def spectral_diff(a, b, n_fft=4096, hop=2048):
    """Mean absolute magnitude-spectrogram difference."""
    import numpy as np
    import librosa
    n = min(len(a), len(b))
    A = np.abs(librosa.stft(a[:n], n_fft=n_fft, hop_length=hop))
    B = np.abs(librosa.stft(b[:n], n_fft=n_fft, hop_length=hop))
    return float(np.abs(A - B).mean())


def maybe_reencode(src_wav, dst_path, codec, bitrate, channels):
    """Run ffmpeg to re-encode src_wav into dst_path. Returns dst_path
    or None if ffmpeg is not available / the command failed."""
    if shutil.which("ffmpeg") is None:
        return None
    cmd = [
        "ffmpeg", "-y", "-loglevel", "error",
        "-i", str(src_wav),
        "-c:a", codec, "-b:a", bitrate,
        "-ar", "44100", "-ac", str(channels),
        str(dst_path),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"  [warn] ffmpeg {codec} failed: {res.stderr.strip()}")
        return None
    return dst_path


def main():
    args = parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    if not args.input.exists():
        sys.exit(f"input not found: {args.input}")
    if not args.kit_binary.exists():
        sys.exit(f"kit binary not found at {args.kit_binary} — run "
                 f"`cargo build --release --bin provcheck-kit` first")
    if not args.verify_binary.exists():
        sys.exit(f"verify binary not found at {args.verify_binary} — run "
                 f"`cargo build --release --bin provcheck` first")

    import librosa
    import soundfile as sf
    import numpy as np

    print(f"loading silentcipher 44.1k model (Python upstream)...")
    py_model = load_silentcipher()

    print(f"reading input: {args.input}")
    y, _ = librosa.load(str(args.input), sr=SAMPLE_RATE, mono=True)
    if args.duration_s and len(y) > int(args.duration_s * SAMPLE_RATE):
        y = y[: int(args.duration_s * SAMPLE_RATE)]
        print(f"truncated to {args.duration_s:.1f} s")

    truncated_path = args.out_dir / "input_44k1_mono.wav"
    sf.write(str(truncated_path), y, SAMPLE_RATE)

    payload_hex = "".join(f"{b:02x}" for b in DEFAULT_PAYLOAD_BYTES)
    print(f"payload: {DEFAULT_PAYLOAD_BYTES} (hex: {payload_hex})")
    print(f"sweep over SDR (dB): {args.sdrs}")

    do_codec = (not args.skip_codec) and (shutil.which("ffmpeg") is not None)
    print(f"codec re-encode pass: {'enabled' if do_codec else 'skipped (no ffmpeg)'}")
    print()

    rows = []
    for sdr in args.sdrs:
        print(f"---- SDR = {sdr} dB ----")
        py_wav = args.out_dir / f"python_marked_sdr{int(sdr)}.wav"
        rust_wav = args.out_dir / f"rust_marked_sdr{int(sdr)}.wav"

        print(f"  python embed -> {py_wav.name}")
        py_marked = python_embed(py_model, y, DEFAULT_PAYLOAD_BYTES, sdr)
        sf.write(str(py_wav), py_marked, SAMPLE_RATE)

        print(f"  rust embed   -> {rust_wav.name}")
        rust_embed(args.kit_binary, truncated_path, rust_wav, payload_hex, sdr)

        rust_marked, _ = librosa.load(str(rust_wav), sr=SAMPLE_RATE, mono=True)

        corr = correlate(py_marked, rust_marked)
        sdiff = spectral_diff(py_marked, rust_marked)

        py_conf_rust_detect = rust_detect(args.verify_binary, py_wav)
        rust_conf_rust_detect = rust_detect(args.verify_binary, rust_wav)
        py_conf_py_detect = python_detect(py_model, py_wav)
        rust_conf_py_detect = python_detect(py_model, rust_wav)

        row = {
            "sdr": sdr,
            "corr": corr,
            "spectral_diff": sdiff,
            "py_pristine_rust_detect": py_conf_rust_detect,
            "rust_pristine_rust_detect": rust_conf_rust_detect,
            "py_pristine_py_detect": py_conf_py_detect,
            "rust_pristine_py_detect": rust_conf_py_detect,
        }

        if do_codec:
            for codec, bitrate, ext, channels, key in [
                ("aac",         "192k", "m4a",  2, "aac192k_stereo"),
                ("libmp3lame",  "192k", "mp3",  1, "mp3_192k_mono"),
            ]:
                py_enc = args.out_dir / f"python_marked_sdr{int(sdr)}_{key}.{ext}"
                rust_enc = args.out_dir / f"rust_marked_sdr{int(sdr)}_{key}.{ext}"
                if maybe_reencode(py_wav, py_enc, codec, bitrate, channels):
                    row[f"py_{key}_rust_detect"] = rust_detect(args.verify_binary, py_enc)
                if maybe_reencode(rust_wav, rust_enc, codec, bitrate, channels):
                    row[f"rust_{key}_rust_detect"] = rust_detect(args.verify_binary, rust_enc)

        rows.append(row)
        print()

    # Report table.
    print()
    print("=" * 100)
    print("PARITY REPORT")
    print("=" * 100)
    print()
    print(f"input      : {args.input}")
    print(f"duration   : {len(y) / SAMPLE_RATE:.2f} s ({len(y)} samples)")
    print(f"payload    : {payload_hex}")
    print(f"sweep      : {args.sdrs} dB")
    print()

    def fmt_conf(v):
        if v is None:
            return "  ?  "
        return f"{v:.3f}"

    print(f"{'SDR':>5} {'corr':>6} {'sdiff':>9}   "
          f"{'py(R)':>6} {'rs(R)':>6}   "
          f"{'py(P)':>6} {'rs(P)':>6}")
    print(f"{'(dB)':>5} {'':>6} {'':>9}   "
          f"{'rDet':>6} {'rDet':>6}   "
          f"{'pDet':>6} {'pDet':>6}")
    print("-" * 65)
    for r in rows:
        print(
            f"{r['sdr']:>5.0f} "
            f"{r['corr']:>6.3f} "
            f"{r['spectral_diff']:>9.3e}   "
            f"{fmt_conf(r['py_pristine_rust_detect']):>6} "
            f"{fmt_conf(r['rust_pristine_rust_detect']):>6}   "
            f"{fmt_conf(r['py_pristine_py_detect']):>6} "
            f"{fmt_conf(r['rust_pristine_py_detect']):>6}"
        )

    if do_codec:
        print()
        print("Re-encode survival (Rust detector):")
        print(f"{'SDR':>5}   "
              f"{'py-aac':>7} {'rs-aac':>7}   "
              f"{'py-mp3':>7} {'rs-mp3':>7}")
        print("-" * 50)
        for r in rows:
            print(
                f"{r['sdr']:>5.0f}   "
                f"{fmt_conf(r.get('py_aac192k_stereo_rust_detect')):>7} "
                f"{fmt_conf(r.get('rust_aac192k_stereo_rust_detect')):>7}   "
                f"{fmt_conf(r.get('py_mp3_192k_mono_rust_detect')):>7} "
                f"{fmt_conf(r.get('rust_mp3_192k_mono_rust_detect')):>7}"
            )

    print()
    print("Legend: corr = Pearson sample correlation between python and rust outputs")
    print("        sdiff = mean abs magnitude-spectrogram diff (lower = closer)")
    print("        py(R)/rs(R) = pristine PCM confidence using rust detector")
    print("        py(P)/rs(P) = pristine PCM confidence using python detector")
    print()
    print(f"intermediate files: {args.out_dir}")


if __name__ == "__main__":
    main()
