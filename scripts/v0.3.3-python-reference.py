"""
v0.3.3 detection-gap investigation — Python reference decoder.

Runs the same silentcipher pipeline as provcheck's Rust port, using
standard Python tooling, and writes intermediates to disk in the
exact format the Rust side dumps. Pair with
`cargo run --example decode_diff` to pinpoint which stage diverges.

Why a fresh Python implementation instead of using silentcipher's
own code: we want to compare against a reference that uses the
SAME .onnx model file the Rust port ships, with the same STFT
parameters our hparams.json declares. That way the diff isolates
WHERE the numerical divergence happens without ambiguity about
which model checkpoint or which library version is in play.

Dependencies:
    pip install librosa numpy onnxruntime soundfile torch

(librosa for audio loading, torch for STFT — silentcipher trains
with torch.stft which has subtle differences vs librosa.stft's
default symmetric hann; using torch directly removes that as a
variable.)

Usage:
    python scripts/v0.3.3-python-reference.py <audio-file>

Writes alongside the input:
    <input>.python.json   — metadata + binary offsets
    <input>.python.bin    — packed f32 + u8 arrays
"""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import librosa
import numpy as np
import onnxruntime as ort
import torch


# Must match crates/provcheck-watermark/models/hparams.json AND the
# Rust constants in src/hparams.rs.
SAMPLE_RATE = 44_100
N_FFT = 4096
HOP = 2048
WIN_LEN = 4096
FREQ_BINS = 2049
MESSAGE_DIM = 5
MESSAGE_LEN = 21
VCTK_AVG_ENERGY = 0.002837200844477648

# Path to the ONNX model — same file the Rust port embeds via
# include_bytes!(). The script resolves it relative to the repo
# root assuming you run from the repo root (or pass --model).
MODEL_PATH = Path("crates/provcheck-watermark/models/silentcipher-decoder.onnx")


def vctk_rescale(y: np.ndarray) -> tuple[np.ndarray, float, float]:
    """Match provcheck-watermark/src/stft.rs vctk_rescale.

    Returns (y_post, mean_sq_pre, mean_sq_post).
    """
    n = float(y.shape[0])
    mean_sq_pre = float(np.sum(y * y) / n)
    if mean_sq_pre <= np.finfo(np.float32).eps:
        return y.copy(), mean_sq_pre, mean_sq_pre
    scale = float(np.sqrt(VCTK_AVG_ENERGY / mean_sq_pre))
    y_post = (y * scale).astype(np.float32)
    mean_sq_post = float(np.sum(y_post * y_post) / n)
    return y_post, mean_sq_pre, mean_sq_post


def stft_carrier(y_post: np.ndarray) -> tuple[np.ndarray, int]:
    """Match provcheck-watermark/src/stft.rs waveform_to_carrier.

    Pipeline:
      1. Tail-pad to multiple of WIN_LEN. Per silentcipher's stft.py
         this ALWAYS pads (including a full WIN_LEN when remainder
         is 0). Important detail — our Rust v0.3.2 skips the pad
         when remainder is 0, which is a bug we're tracking.
      2. torch.stft with periodic Hann window, n_fft=4096,
         hop=2048, center=True (default), pad_mode='reflect'
         (default), return_complex=True.
      3. magnitude = sqrt(re² + im²) — the eps-conditional trick
         in silentcipher's reference is functionally a no-op on
         the inference path.

    Returns (carrier flat row-major [bin * T + t], T).
    """
    x = torch.from_numpy(y_post).reshape(1, -1).float()
    # Always-pad (silentcipher convention). If x.shape[1] % WIN_LEN
    # is 0 we still pad WIN_LEN zeros.
    pad = WIN_LEN - (x.shape[1] % WIN_LEN)
    x = torch.nn.functional.pad(x, (0, pad))
    window = torch.hann_window(WIN_LEN, periodic=True)
    fft = torch.stft(
        x,
        n_fft=N_FFT,
        hop_length=HOP,
        win_length=WIN_LEN,
        window=window,
        center=True,
        pad_mode="reflect",
        return_complex=True,
        normalized=False,
    )
    # fft is [batch=1, freq_bins, frames]; magnitude.
    re = fft.real
    im = fft.imag
    squared = re * re + im * im
    additive_epsilon = (squared == 0).float() * 1e-24
    magnitude = torch.sqrt(squared + additive_epsilon) - torch.sqrt(additive_epsilon)
    mag = magnitude.squeeze(0).numpy().astype(np.float32)  # [freq_bins, T]
    t_frames = int(mag.shape[1])
    # Row-major flat: bin * T + t.
    carrier = mag.flatten(order="C")
    return carrier, t_frames


def run_model(carrier: np.ndarray, t_frames: int, model_path: Path) -> np.ndarray:
    """Run the ONNX decoder. Returns logits flat row-major [d * T + t]."""
    sess = ort.InferenceSession(str(model_path), providers=["CPUExecutionProvider"])
    inp_name = sess.get_inputs()[0].name
    # The Rust port builds shape [1, 1, FREQ_BINS, T] from a flat
    # row-major buffer with index = bin * T + t. Reshape matching.
    inp = carrier.reshape(1, 1, FREQ_BINS, t_frames).astype(np.float32)
    out = sess.run(None, {inp_name: inp})[0]  # shape [1, 1, MESSAGE_DIM, T]
    logits = out.squeeze().astype(np.float32)  # [MESSAGE_DIM, T]
    return logits.flatten(order="C")


def backend_decode(logits: np.ndarray, t_frames: int):
    """Match crates/provcheck-watermark/src/decode.rs decode_logits.

    Returns (argmax, mode_per_pos, payload_symbols, payload_bytes,
    decode_ok, confidence).
    """
    logits_2d = logits.reshape(MESSAGE_DIM, t_frames)
    argmax = np.argmax(logits_2d, axis=0).astype(np.uint8)
    n_tiles = t_frames // MESSAGE_LEN
    pred = argmax[: n_tiles * MESSAGE_LEN].reshape(n_tiles, MESSAGE_LEN)

    mode_per_pos = np.zeros(MESSAGE_LEN, dtype=np.uint8)
    for p in range(MESSAGE_LEN):
        counts = np.bincount(pred[:, p], minlength=MESSAGE_DIM)
        mode_per_pos[p] = int(np.argmax(counts))

    payload_symbols = np.zeros(MESSAGE_LEN - 1, dtype=np.uint8)
    payload_bytes = np.zeros(5, dtype=np.uint8)
    decode_ok = False
    term = np.where(mode_per_pos == 0)[0]
    if len(term) > 0:
        end_char = int(term.min())
        rolled = np.concatenate(
            [mode_per_pos[end_char + 1 :], mode_per_pos[:end_char]]
        )
        if not np.any(rolled == 0):
            payload_symbols = (rolled - 1).astype(np.uint8)
            for b in range(5):
                a = int(payload_symbols[b * 4 + 0])
                c = int(payload_symbols[b * 4 + 1])
                d = int(payload_symbols[b * 4 + 2])
                e = int(payload_symbols[b * 4 + 3])
                payload_bytes[b] = (a << 6) | (c << 4) | (d << 2) | e
            decode_ok = True

    matches = 0
    if n_tiles > 0:
        for tile in range(n_tiles):
            for p in range(MESSAGE_LEN):
                if pred[tile, p] == mode_per_pos[p]:
                    matches += 1
        confidence = matches / (n_tiles * MESSAGE_LEN)
    else:
        confidence = 0.0
    return argmax, mode_per_pos, payload_symbols, payload_bytes, decode_ok, confidence


def write_dump(input_path: Path, model_path: Path) -> None:
    # ---- Audio decode ----
    # librosa.load returns mono f32 at the requested sr. sr=44100
    # forces 44.1 kHz output regardless of source rate, matching
    # silentcipher's pipeline.
    y_pre, sr = librosa.load(str(input_path), sr=SAMPLE_RATE, mono=True)
    assert sr == SAMPLE_RATE
    y_pre = y_pre.astype(np.float32)
    n_audio = int(y_pre.shape[0])

    # ---- VCTK rescale ----
    y_post, mean_sq_pre, mean_sq_post = vctk_rescale(y_pre)

    # ---- STFT ----
    carrier, t_frames = stft_carrier(y_post)

    # ---- Model ----
    logits = run_model(carrier, t_frames, model_path)

    # ---- Backend decode ----
    (
        argmax,
        mode_per_pos,
        payload_symbols,
        payload_bytes,
        decode_ok,
        confidence,
    ) = backend_decode(logits, t_frames)

    # ---- Write binary dump ----
    json_path = input_path.with_suffix(".python.json")
    bin_path = input_path.with_suffix(".python.bin")
    bin_path.parent.mkdir(parents=True, exist_ok=True)

    offsets: dict[str, dict] = {}

    def append_f32(bf, arr, name):
        offsets[name] = {
            "offset": bf.tell(),
            "dtype": "f32_le",
            "count": int(arr.size),
        }
        bf.write(arr.astype(np.float32).tobytes())

    def append_u8(bf, arr, name):
        offsets[name] = {
            "offset": bf.tell(),
            "dtype": "u8",
            "count": int(arr.size),
        }
        bf.write(arr.astype(np.uint8).tobytes())

    with open(bin_path, "wb") as bf:
        append_f32(bf, y_pre, "audio_pre_rescale")
        append_f32(bf, y_post, "audio_post_rescale")
        append_f32(bf, carrier, "carrier")
        append_f32(bf, logits, "logits")
        append_u8(bf, argmax, "argmax")
        append_u8(bf, mode_per_pos, "mode_per_pos")
        append_u8(bf, payload_symbols, "payload_symbols")
        append_u8(bf, payload_bytes, "payload_bytes")
        total_bytes = bf.tell()

    metadata = {
        "implementation": "v0.3.3 python reference (torch.stft + onnxruntime)",
        "input_path": str(input_path),
        "binary_dump_path": str(bin_path),
        "binary_dump_bytes": total_bytes,
        "audio": {
            "n_samples": n_audio,
            "sample_rate": SAMPLE_RATE,
            "duration_sec": n_audio / SAMPLE_RATE,
            "mean_sq_pre_rescale": mean_sq_pre,
            "mean_sq_post_rescale": mean_sq_post,
            "vctk_target_energy": VCTK_AVG_ENERGY,
            "vctk_energy_ratio": mean_sq_post / VCTK_AVG_ENERGY,
        },
        "carrier": {
            "shape": [1, 1, FREQ_BINS, t_frames],
            "layout": "row-major, flat index = bin * T + t",
            "n_freq": FREQ_BINS,
            "n_frames": t_frames,
            "n_tiles_full": t_frames // MESSAGE_LEN,
        },
        "logits": {
            "shape": [1, 1, MESSAGE_DIM, t_frames],
            "layout": "row-major, flat index = dim * T + t",
        },
        "decode": {
            "n_tiles": int(t_frames // MESSAGE_LEN),
            "terminator_pos": int(np.where(mode_per_pos == 0)[0][0])
            if (mode_per_pos == 0).any()
            else None,
            "ok": bool(decode_ok),
            "confidence": float(confidence),
            "payload_hex": [int(b) for b in payload_bytes],
        },
        "binary_offsets": offsets,
    }
    with open(json_path, "w") as jf:
        json.dump(metadata, jf, indent=2)

    print(f"wrote {json_path}")
    print(f"wrote {bin_path} ({total_bytes / 1024 / 1024:.1f} MiB)")
    print()
    print("Summary:")
    print(f"  n_samples:     {n_audio}")
    print(f"  vctk ratio:    {mean_sq_post / VCTK_AVG_ENERGY:.4f}")
    print(f"  t_frames:      {t_frames} ({t_frames // MESSAGE_LEN} tiles)")
    print(
        f"  terminator:    "
        f"{'found at ' + str(int(np.where(mode_per_pos == 0)[0][0])) if (mode_per_pos == 0).any() else 'NOT FOUND'}"
    )
    print(f"  decode_ok:     {decode_ok}")
    print(f"  confidence:    {confidence:.4f}")
    print(f"  payload:       {[hex(int(b)) for b in payload_bytes]}")


def main() -> None:
    if len(sys.argv) < 2:
        print("usage: python v0.3.3-python-reference.py <audio-file> [--model PATH]")
        sys.exit(2)
    input_path = Path(sys.argv[1])
    model_path = MODEL_PATH
    for i, a in enumerate(sys.argv[2:], start=2):
        if a == "--model" and i + 1 < len(sys.argv):
            model_path = Path(sys.argv[i + 1])
    if not model_path.exists():
        print(f"fatal: model not found at {model_path}")
        print("Run from the repo root, or pass --model <path>")
        sys.exit(2)
    if not input_path.exists():
        print(f"fatal: input not found at {input_path}")
        sys.exit(2)
    write_dump(input_path, model_path)


if __name__ == "__main__":
    main()
