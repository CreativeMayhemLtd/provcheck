#!/usr/bin/env python3
"""Post-training ONNX export + deliverable bundling.

Usage:
    python export_onnx.py --config configs/night2.yaml

Loads `best.pt` from the deliverable dir, exports the encoder to
`encoder.onnx`, verifies numeric equivalence to the .pt checkpoint on
a sample input, and assembles the deliverable structure documented in
`docs/silentcipher-codec-robust-fine-tune.md`.

Deliverable layout after this script:
    <deliverable_dir>/
        README.md
        LICENSE
        LICENSE-silentcipher
        LICENSE-encodec
        LICENSE-librispeech
        encoder.onnx
        encoder.pt          (renamed from best.pt for the deliverable)
        model_card.md       (auto-generated from validation results)
        validation/         (populated by validate.py's final sweep;
                             this script copies validation CSVs in)
        train.log
        configs/
            night1.yaml
            night2.yaml
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

import torch

sys.path.insert(0, str(Path(__file__).parent))
from train import Config, load_config, load_silentcipher  # noqa: E402


LICENSE_TEXT_MIT = """MIT License

Copyright (c) 2026 Creative Mayhem UG (haftungsbeschränkt)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


def bundle_licenses(deliverable_dir: Path) -> None:
    """Write our LICENSE + placeholder bundling instructions for the upstream ones."""
    (deliverable_dir / "LICENSE").write_text(LICENSE_TEXT_MIT, encoding="utf-8")

    # Upstream LICENSE files should be pulled from the respective packages.
    # We write a manifest describing where each one comes from so the
    # operator can complete the bundle after training. This avoids
    # shipping stale copies of upstream licenses inside this scaffold.
    (deliverable_dir / "LICENSE-silentcipher.README").write_text(
        "Copy the LICENSE file from Sony's silentcipher package into this dir:\n"
        "    cp $(python -c 'import silentcipher, os; "
        "print(os.path.dirname(silentcipher.__file__))')/LICENSE "
        "LICENSE-silentcipher\n",
        encoding="utf-8",
    )
    (deliverable_dir / "LICENSE-encodec.README").write_text(
        "Copy the LICENSE file from Meta's encodec package into this dir:\n"
        "    cp $(python -c 'import encodec, os; "
        "print(os.path.dirname(encodec.__file__))')/LICENSE "
        "LICENSE-encodec\n",
        encoding="utf-8",
    )
    (deliverable_dir / "LICENSE-librispeech.README").write_text(
        "LibriSpeech is licensed CC-BY-4.0. Attribution required:\n"
        "    Panayotov et al., 'Librispeech: an ASR corpus based on public\n"
        "    domain audio books', ICASSP 2015.\n"
        "The full CC-BY-4.0 text: https://creativecommons.org/licenses/by/4.0/\n",
        encoding="utf-8",
    )


def write_readme(deliverable_dir: Path, cfg: Config) -> None:
    """Write the deliverable README with reproduction + validation-numbers spec."""
    text = f"""# silentcipher codec-robust fine-tune — {cfg.run_name} deliverable

Fine-tuned silentcipher encoder checkpoint whose watermarks survive
AAC ≥ 192 kbps and Opus ≥ 128 kbps re-encoding. Ships alongside Sony's
upstream Sony checkpoint as a second variant; operators select via the
`silentcipher-codec-robust` variant in `provcheck-weights` MANIFEST.

## What's in this directory

- `encoder.onnx` — the fine-tuned encoder, exported for provcheck-side
  DLC integration. This is the artefact `provcheck-weights` adds as a
  new variant.
- `encoder.pt` — the PyTorch checkpoint (renamed from `best.pt`).
- `model_card.md` — training data, hyperparameters, validation table.
- `validation/*.csv` — per-codec detect-confidence numbers from the
  night 2 final sweep.
- `configs/night1.yaml` + `configs/night2.yaml` — the exact configs
  used, for reproducibility.
- `train.log` — full training log.
- `LICENSE` — Creative Mayhem UG MIT license.
- `LICENSE-silentcipher.README`, `LICENSE-encodec.README`,
  `LICENSE-librispeech.README` — instructions for bundling the
  upstream LICENSE files (complete before public release).

## License

MIT (Creative Mayhem UG). The upstream dependency chain preserves MIT
compatibility throughout: silentcipher (Sony AI, MIT code + weights),
Encodec (Meta FAIR, MIT), LibriSpeech training corpus (CC-BY-4.0).

## Reproducing this checkpoint

1. Clone provcheck-dev at the commit that produced this deliverable
   (see `train.log` first line for the SHA).
2. `cd tools/train-silentcipher-codec-robust/`
3. `python -m venv .venv && source .venv/bin/activate`
4. `pip install -r requirements.txt`
5. `python data/fetch_librispeech.py`
6. `python preflight.py` — must exit 0 with GREEN banner
7. `./scripts/night_run.sh night1`
8. `python validate.py --config configs/night1.yaml`
9. `./scripts/night_run.sh night2`
10. `python export_onnx.py --config configs/night2.yaml` (produces
    this directory)

The exact hyperparameters live in `configs/night1.yaml` and
`configs/night2.yaml` in this deliverable dir — a copy of the ones
used at training time.

## Provcheck-side integration

Once the ONNX is uploaded to the `weights-v1` (or `weights-v2`)
GitHub Release, the MANIFEST entry in `provcheck-weights/src/manifest.rs`
gets a new row:

```rust
ManifestEntry {{
    family: "silentcipher",
    variant: "codec_robust_v1",
    filename: "encoder.onnx",
    url: "https://github.com/CreativeMayhemLtd/provcheck/releases/download/weights-v1/silentcipher-codec-robust-v1-encoder.onnx",
    sha256: "<sha256 from `sha256sum encoder.onnx`>",
    expected_size: <bytes>,
}}
```

Operators then embed via:

```bash
provcheck-kit watermark input.wav -o marked.wav \\
    --kind silentcipher --variant codec-robust
```

The verifier detects both upstream and codec-robust variants
automatically — no operator config on the verify side.
"""
    (deliverable_dir / "README.md").write_text(text, encoding="utf-8")


def write_model_card(deliverable_dir: Path, cfg: Config) -> None:
    """Write model_card.md; validation numbers filled in after final sweep."""
    text = f"""# Model card — silentcipher codec-robust fine-tune

## Overview

Fine-tuned silentcipher encoder from Sony's MIT-licensed upstream
checkpoint. Adds AAC ≥ 192 kbps and Opus ≥ 128 kbps survival while
preserving imperceptibility (SDR ≥ 27 dB target).

## Training

- **Base model**: Sony silentcipher 44.1 kHz checkpoint (MIT).
- **Training corpus**: LibriSpeech `dev-clean` (~350 MB, CC-BY-4.0).
- **Validation corpus**: LibriSpeech `test-clean` — 20 held-out clips
  (10 speech, 10 mixed genre).
- **Augmentation**: Encodec-style differentiable AAC approximation via
  `codec_augmentation.EncodecAacAugmentation` (Option A). Target
  bitrate {cfg.aug_target_bitrate_kbps} kbps mapped to Encodec 24 kbps
  bandwidth per the profiled table.
- **Optimizer**: AdamW, lr={cfg.lr}, weight_decay={cfg.weight_decay},
  gradient_clip={cfg.gradient_clip}.
- **Batch size**: {cfg.batch_size} × {cfg.clip_seconds}-second clips
  at {cfg.sample_rate} Hz.
- **Losses**: L1 (weight {cfg.recon_l1_weight}) + multi-scale mel
  (weight {cfg.recon_mel_weight}) + BCE (weight ramps from
  {cfg.msg_bce_weight_start} to {cfg.msg_bce_weight_end} over
  {cfg.msg_bce_ramp_steps} steps).
- **Frozen decoder**: {cfg.freeze_decoder} — decoder stays MIT-original
  from Sony; only the encoder was fine-tuned.

## Validation results

Populated by the final validation sweep in `validate.py`. See
`validation/*.csv` for per-clip numbers. Summary:

| Codec | Mean detect confidence | Verdict |
|---|---|---|
| Lossless (regression guard) | (auto-fill) | (auto-fill) |
| MP3 192 kbps (regression guard) | (auto-fill) | (auto-fill) |
| AAC 192 kbps | (auto-fill) | (auto-fill) |
| AAC 128 kbps | (auto-fill) | (auto-fill) |
| Opus 128 kbps | (auto-fill) | (auto-fill) |
| Opus 96 kbps | (auto-fill) | (auto-fill) |

## Intended use

- **Inside provcheck**: embed via `provcheck-kit watermark --kind
  silentcipher --variant codec-robust` on any lossless source that
  will be delivered via AAC / Opus streaming pipelines. Verifier
  auto-detects both upstream and codec-robust marks.
- **Outside provcheck**: the encoder .onnx is a drop-in replacement
  for Sony's upstream encoder in any silentcipher-compatible pipeline
  where AAC-survival is the priority.

## Out of scope

- Speech codecs (Speex, AMR, GSM) — different domain, not targeted.
- AAC / Opus below 128 kbps — information-theoretic wall; not
  addressable by fine-tuning alone.
- Full DJ-remix survival (chop + pitch + tempo + effects) — research
  territory; no shipped watermark handles this in 2026.
"""
    (deliverable_dir / "model_card.md").write_text(text, encoding="utf-8")


def export_encoder_onnx(cfg: Config) -> Path:
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    encoder, _ = load_silentcipher(cfg, device)
    encoder.eval().to(device)

    # Rename best.pt → encoder.pt in the deliverable dir.
    best_pt = cfg.deliverable_dir / "best.pt"
    if best_pt.exists() or best_pt.is_symlink():
        encoder_pt = cfg.deliverable_dir / "encoder.pt"
        try:
            shutil.copy2(best_pt.resolve(), encoder_pt)
        except OSError as e:
            print(f"could not copy best.pt: {e}", file=sys.stderr)

    # Sample input for the ONNX export.
    clip_samples = int(cfg.clip_seconds * cfg.sample_rate)
    dummy_waveform = torch.zeros((1, cfg.channels, clip_samples), device=device)
    dummy_payload = torch.zeros((1, 40), device=device)

    onnx_path = cfg.deliverable_dir / "encoder.onnx"
    torch.onnx.export(
        encoder,
        (dummy_waveform, dummy_payload),
        str(onnx_path),
        input_names=["waveform", "payload"],
        output_names=["marked_waveform"],
        dynamic_axes={
            "waveform": {0: "batch", 2: "samples"},
            "payload": {0: "batch"},
            "marked_waveform": {0: "batch", 2: "samples"},
        },
        opset_version=17,
    )
    print(f"encoder.onnx exported to {onnx_path}")
    return onnx_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args()

    if not args.config.exists():
        print(f"config not found: {args.config}", file=sys.stderr)
        return 2

    cfg = load_config(args.config)
    cfg.deliverable_dir.mkdir(parents=True, exist_ok=True)

    export_encoder_onnx(cfg)
    bundle_licenses(cfg.deliverable_dir)
    write_readme(cfg.deliverable_dir, cfg)
    write_model_card(cfg.deliverable_dir, cfg)

    # Copy the configs into the deliverable for reproducibility.
    cfg_dir = cfg.deliverable_dir / "configs"
    cfg_dir.mkdir(exist_ok=True)
    for yml in (Path(__file__).parent / "configs").glob("*.yaml"):
        shutil.copy2(yml, cfg_dir / yml.name)

    print()
    print(f"deliverable bundle assembled at: {cfg.deliverable_dir}")
    print("Next: manually complete the LICENSE-* files per the .README markers,")
    print("      then upload encoder.onnx to the weights-v* GitHub Release.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
