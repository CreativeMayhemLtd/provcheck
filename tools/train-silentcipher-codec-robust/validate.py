#!/usr/bin/env python3
"""Between-night validation for the silentcipher codec-robust fine-tune.

Usage:
    python validate.py --config configs/night2.yaml

Loads the latest checkpoint (or `best.pt`), runs a fixed 20-clip
validation set through real codec round-trips (AAC 128k/192k, Opus
96k/128k, MP3 192k, lossless regression guard), and prints a green /
amber / red banner with a per-codec detect-confidence table.

Design:
    - Real ffmpeg codec round-trips, not Encodec proxies. Encodec was
      the training-time proxy; here we validate against actual delivery
      codecs the operator's audience will hit.
    - Exit code: 0 on green or amber (operator decides), 1 on red.
    - Prints a `night2.yaml` config suggestion for the between-nights
      hand-off (halve LR if amber, restart from upstream if red).
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

import numpy as np
import torch
import torchaudio

# Local module import (train.py sibling).
sys.path.insert(0, str(Path(__file__).parent))
from train import Config, load_config, load_silentcipher  # noqa: E402


# ============================================================================
# Terminal helpers
# ============================================================================


def red(msg: str) -> None:
    print(f"\033[31m{msg}\033[0m", file=sys.stderr)


def yellow(msg: str) -> None:
    print(f"\033[33m{msg}\033[0m")


def green(msg: str) -> None:
    print(f"\033[32m{msg}\033[0m")


# ============================================================================
# Threshold ladders (from docs/silentcipher-codec-robust-fine-tune.md)
# ============================================================================

THRESHOLDS = {
    # (green_min, amber_min)  — below amber_min = red
    "aac_192k": (0.85, 0.70),
    "aac_128k": (0.70, 0.55),
    "opus_128k": (0.85, 0.70),
    "opus_96k": (0.70, 0.55),
    "mp3_192k": (0.95, 0.85),  # regression guard
    "lossless": (0.95, 0.85),  # regression guard
}


# ============================================================================
# Codec round-trip helpers (real ffmpeg)
# ============================================================================


def check_ffmpeg() -> bool:
    return shutil.which("ffmpeg") is not None


def codec_roundtrip(
    waveform: torch.Tensor,
    sample_rate: int,
    codec: str,
    tmpdir: Path,
) -> torch.Tensor:
    """Encode → decode via ffmpeg. Returns waveform at original sample rate."""
    src = tmpdir / "src.wav"
    torchaudio.save(str(src), waveform.cpu(), sample_rate)
    if codec == "aac_192k":
        out = tmpdir / "roundtrip.m4a"
        cmd = ["ffmpeg", "-y", "-loglevel", "error", "-i", str(src),
               "-c:a", "aac", "-b:a", "192k", str(out)]
    elif codec == "aac_128k":
        out = tmpdir / "roundtrip.m4a"
        cmd = ["ffmpeg", "-y", "-loglevel", "error", "-i", str(src),
               "-c:a", "aac", "-b:a", "128k", str(out)]
    elif codec == "opus_128k":
        out = tmpdir / "roundtrip.opus"
        cmd = ["ffmpeg", "-y", "-loglevel", "error", "-i", str(src),
               "-c:a", "libopus", "-b:a", "128k", str(out)]
    elif codec == "opus_96k":
        out = tmpdir / "roundtrip.opus"
        cmd = ["ffmpeg", "-y", "-loglevel", "error", "-i", str(src),
               "-c:a", "libopus", "-b:a", "96k", str(out)]
    elif codec == "mp3_192k":
        out = tmpdir / "roundtrip.mp3"
        cmd = ["ffmpeg", "-y", "-loglevel", "error", "-i", str(src),
               "-c:a", "libmp3lame", "-b:a", "192k", str(out)]
    elif codec == "lossless":
        # No-op: return the source through a WAV → WAV pass (guards
        # against accidental bit rot in the read/write path).
        wav, sr = torchaudio.load(str(src))
        return wav
    else:
        raise ValueError(f"unknown codec: {codec}")

    subprocess.run(cmd, check=True)
    # Decode back.
    wav, sr = torchaudio.load(str(out))
    if sr != sample_rate:
        wav = torchaudio.functional.resample(
            wav, orig_freq=sr, new_freq=sample_rate
        )
    return wav


# ============================================================================
# Validation clip loading
# ============================================================================


def load_validation_clips(cfg: Config, n: int = 20) -> list[torch.Tensor]:
    """Load 20 held-out clips from LibriSpeech test-clean."""
    root = Path.home() / ".cache" / "torch" / "hub" / "librispeech" / "test-clean"
    if not root.exists():
        raise RuntimeError(
            f"LibriSpeech test-clean not found at {root}. "
            f"Fetch via `python data/fetch_librispeech.py --split test`."
        )
    files = sorted(root.rglob("*.flac"))[:n]
    if len(files) < n:
        yellow(f"only {len(files)} clips available; expected {n}")
    clip_samples = int(cfg.clip_seconds * cfg.sample_rate)
    clips = []
    for f in files:
        wav, sr = torchaudio.load(str(f))
        if sr != cfg.sample_rate:
            wav = torchaudio.functional.resample(
                wav, orig_freq=sr, new_freq=cfg.sample_rate
            )
        if wav.shape[0] != cfg.channels:
            if cfg.channels == 1 and wav.shape[0] > 1:
                wav = wav.mean(dim=0, keepdim=True)
            elif cfg.channels == 2 and wav.shape[0] == 1:
                wav = wav.repeat(2, 1)
        # Trim / pad to clip_samples.
        if wav.shape[-1] >= clip_samples:
            wav = wav[..., :clip_samples]
        else:
            wav = torch.nn.functional.pad(wav, (0, clip_samples - wav.shape[-1]))
        clips.append(wav)
    return clips


# ============================================================================
# Detect confidence
# ============================================================================


def compute_conf(
    decoder: torch.nn.Module,
    marked_after_codec: torch.Tensor,
    original_payload: torch.Tensor,
    device: torch.device,
) -> float:
    """Return payload-recovery confidence in [0, 1]."""
    with torch.no_grad():
        wav = marked_after_codec.to(device).unsqueeze(0)  # [1, C, T]
        logits = decoder(wav)
        if logits.dim() == 3:
            logits = logits.mean(dim=1)
        probs = torch.sigmoid(logits).squeeze(0)  # [40]
        # Confidence = mean-per-bit correctness.
        correct = (probs > 0.5).float().eq(original_payload.to(device).float())
        return float(correct.float().mean().item())


# ============================================================================
# Report
# ============================================================================


def classify(codec: str, conf: float) -> str:
    green_min, amber_min = THRESHOLDS[codec]
    if conf >= green_min:
        return "GREEN"
    if conf >= amber_min:
        return "AMBER"
    return "RED"


def emit_banner_and_suggest(overall: str, per_codec: dict[str, float]) -> int:
    print()
    print("=" * 63)
    if overall == "GREEN":
        green(" GREEN — continue night 2 with same config")
    elif overall == "AMBER":
        yellow(" AMBER — suggest: halve lr AND halve msg_bce_weight_end,")
        yellow("         then continue night 2 from best.pt")
    else:
        red(" RED — do NOT continue night 2 from this checkpoint.")
        red("       suggest: restart from Sony upstream with Option B augmentation")
        red("       (edit night1.yaml augmentation.option to 'B' and re-run)")
    print("=" * 63)
    print()
    print(f"{'codec':<12} {'confidence':<12} {'threshold_g':<14} {'verdict':<10}")
    print("-" * 55)
    for codec, conf in per_codec.items():
        g, _ = THRESHOLDS[codec]
        verdict = classify(codec, conf)
        color = "\033[32m" if verdict == "GREEN" else (
            "\033[33m" if verdict == "AMBER" else "\033[31m"
        )
        print(f"{codec:<12} {conf:<12.4f} {g:<14.2f} {color}{verdict}\033[0m")
    print()

    return 0 if overall in ("GREEN", "AMBER") else 1


def overall_verdict(per_codec: dict[str, float]) -> str:
    verdicts = [classify(c, v) for c, v in per_codec.items()]
    if "RED" in verdicts:
        return "RED"
    if "AMBER" in verdicts:
        return "AMBER"
    return "GREEN"


# ============================================================================
# Main
# ============================================================================


def main() -> int:
    parser = argparse.ArgumentParser(description="between-night validation")
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args()

    if not args.config.exists():
        red(f"config not found: {args.config}")
        return 2

    cfg = load_config(args.config)

    if not check_ffmpeg():
        red("ffmpeg not on PATH — cannot run codec validation.")
        return 2

    best_pt = cfg.deliverable_dir / "best.pt"
    if not best_pt.exists():
        red(f"best.pt not found in {cfg.deliverable_dir}; run train.py first.")
        return 2

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    encoder, decoder = load_silentcipher(cfg, device)
    encoder.eval().to(device)
    decoder.eval().to(device)

    clips = load_validation_clips(cfg, n=20)
    codecs = list(THRESHOLDS.keys())

    per_codec_conf: dict[str, list[float]] = {c: [] for c in codecs}

    with tempfile.TemporaryDirectory() as td:
        tmpdir = Path(td)
        for i, clip in enumerate(clips):
            # Random 40-bit payload for this clip.
            payload = torch.randint(0, 2, (40,), dtype=torch.float32)
            # Embed.
            with torch.no_grad():
                marked = encoder(clip.to(device).unsqueeze(0),
                                 payload.to(device).unsqueeze(0)).squeeze(0)
            # Round-trip through each codec + detect.
            for codec in codecs:
                after = codec_roundtrip(marked.cpu(), cfg.sample_rate, codec, tmpdir)
                conf = compute_conf(decoder, after, payload, device)
                per_codec_conf[codec].append(conf)
            print(f"  clip {i + 1}/20 processed")

    per_codec_mean = {c: float(np.mean(v)) for c, v in per_codec_conf.items()}
    return emit_banner_and_suggest(overall_verdict(per_codec_mean), per_codec_mean)


if __name__ == "__main__":
    sys.exit(main())
