"""Diagnostic: mark synthetic audio with silentcipher's real encode_wav,
write to WAV, and tell the user what to run next.

If `provcheck` reports DETECTED on the file this script produces but
NOT on the file produced by my Rust embed pipeline (same input audio),
then my Rust embed has a bug. If neither detects, the synthetic audio
doesn't have enough spectral content for silentcipher to embed
reliably."""

import sys
import warnings
warnings.filterwarnings("ignore")

import numpy as np
import torch
import soundfile as sf
from pathlib import Path
import logging
logging.getLogger("pydub").setLevel(logging.ERROR)

import silentcipher

SR = 44100


def find_silentcipher_44k_cache():
    base = Path.home() / ".cache" / "huggingface" / "hub" / "models--sony--silentcipher"
    snaps = list((base / "snapshots").glob("*/44_1_khz/73999_iteration"))
    if not snaps:
        raise FileNotFoundError("silentcipher 44.1k weights not in HF cache")
    ckpt_dir = snaps[0]
    return str(ckpt_dir), str(ckpt_dir / "hparams.yaml")


def synthesize_audio(seconds=6.0):
    """Same waveform the Rust embed_roundtrip example uses."""
    n = int(seconds * SR)
    t = np.arange(n) / SR
    y = (
        0.20 * np.sin(2 * np.pi * 220.0 * t)
        + 0.15 * np.sin(2 * np.pi * 440.0 * t)
        + 0.10 * np.sin(2 * np.pi * 880.0 * t)
        + 0.10 * np.sin(2 * np.pi * 1760.0 * t)
        + 0.05 * np.sin(2 * np.pi * 3520.0 * t)
    ).astype(np.float32)
    return y


def main():
    print("[diag] loading silentcipher 44.1k model...")
    ckpt_dir, config_path = find_silentcipher_44k_cache()
    model = silentcipher.get_model(
        model_type="44.1k",
        ckpt_path=ckpt_dir,
        config_path=config_path,
        device="cpu",
    )

    print("[diag] synthesising 6s test audio (same as Rust embed_roundtrip)...")
    y = synthesize_audio()

    print("[diag] marking with silentcipher.encode_wav (DFM payload)...")
    payload = [0x44, 0x46, 0x4d, 0x01, 0x00]
    marked, sdr = model.encode_wav(y, SR, payload)
    print(f"[diag] silentcipher reported SDR: {sdr:.2f} dB")
    print(f"[diag] input  shape={y.shape},     range=[{y.min():.4f}, {y.max():.4f}]")
    print(f"[diag] marked shape={marked.shape}, range=[{marked.min():.4f}, {marked.max():.4f}]")

    py_out = Path("C:/dev2/provcheck-dev/diagnose-python-marked.wav")
    sf.write(str(py_out), marked, SR, subtype="FLOAT")
    print(f"[diag] wrote {py_out}")

    print()
    print("[diag] verify with silentcipher's own decoder (sanity check):")
    decoded = model.decode_wav(marked, SR, phase_shift_decoding=False)
    print(f"        {decoded}")

    print()
    print("==================================================")
    print("NEXT STEP — run the Rust detector on the Python-marked file:")
    print(f"  cargo run --release -p provcheck-cli -- {py_out}")
    print()
    print("Expected: detected = true, payload = 44 46 4d 01 00 (DFM)")
    print()
    print("If Rust detector DOES detect → my Rust embed has a bug, not the audio")
    print("If Rust detector does NOT detect → the synthetic audio is too simple")
    print("                                   OR my Rust detector has a bug too")
    print("==================================================")


if __name__ == "__main__":
    sys.exit(main() or 0)
