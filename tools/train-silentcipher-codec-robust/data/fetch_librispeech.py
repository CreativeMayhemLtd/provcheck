#!/usr/bin/env python3
"""Fetch LibriSpeech dev-clean (~350 MB) and test-clean (~350 MB).

Usage:
    python data/fetch_librispeech.py           # both splits (default)
    python data/fetch_librispeech.py --split dev
    python data/fetch_librispeech.py --split test

LibriSpeech (Panayotov et al. 2015) is licensed CC-BY-4.0. Attribution
required — see LICENSE-librispeech.README in the deliverable bundle.

Uses torchaudio.datasets.LIBRISPEECH which fetches from OpenSLR's
mirror. Downloads to `~/.cache/torch/hub/librispeech/` by default; the
train.py + validate.py loaders look there.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def fetch(split: str) -> None:
    import torchaudio

    root = Path.home() / ".cache" / "torch" / "hub" / "librispeech"
    root.mkdir(parents=True, exist_ok=True)

    print(f"fetching LibriSpeech {split}-clean into {root} …")
    torchaudio.datasets.LIBRISPEECH(
        root=str(root),
        url=f"{split}-clean",
        download=True,
    )
    print(f"  done: {split}-clean")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--split",
        choices=("dev", "test", "both"),
        default="both",
        help="which LibriSpeech split(s) to fetch",
    )
    args = parser.parse_args()

    if args.split in ("dev", "both"):
        fetch("dev")
    if args.split in ("test", "both"):
        fetch("test")

    print()
    print("LibriSpeech is licensed CC-BY-4.0. Attribution required.")
    print("Cite: Panayotov et al., 'Librispeech: an ASR corpus based on")
    print("      public domain audio books', ICASSP 2015.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
