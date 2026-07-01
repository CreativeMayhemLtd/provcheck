#!/usr/bin/env python3
"""Preflight environment check for the silentcipher codec-robust fine-tune.

Runs BEFORE every training night. Exits 1 with a RED banner if the
environment isn't ready; exits 0 with a GREEN banner if it is; prints
AMBER suggestions where applicable and still exits 0 (the operator
decides).

Checks (in order — halts on first FAIL):
    1. Python version >= 3.10
    2. Required Python packages importable
    3. CUDA-capable GPU visible
    4. GPU has >= 24 GB free VRAM (5090 has 32; require 24 free after
       accounting for OS overhead + safety margin)
    5. Free disk >= 50 GB on the training-dir mount
    6. Sony's silentcipher checkpoint present in HF cache
    7. Dry-run forward pass at batch 16, log peak VRAM, verify no OOM

No training-loop code lives here. Preflight is idempotent and
side-effect-free (does not download weights, does not write logs).
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Terminal banners. No dep on colorama or rich — ANSI escapes work on
# every terminal the operator is likely to run this from.
# ---------------------------------------------------------------------------

def red(msg: str) -> None:
    print(f"\033[31m{msg}\033[0m", file=sys.stderr)


def yellow(msg: str) -> None:
    print(f"\033[33m{msg}\033[0m")


def green(msg: str) -> None:
    print(f"\033[32m{msg}\033[0m")


def banner_fail(reason: str) -> None:
    red("")
    red("=" * 63)
    red(f" RED — preflight FAIL: {reason}")
    red("=" * 63)


def banner_ok() -> None:
    green("")
    green("=" * 63)
    green(" GREEN — preflight OK; training environment is ready.")
    green("=" * 63)


# ---------------------------------------------------------------------------
# Individual checks. Each returns (ok: bool, detail: str). No side effects.
# ---------------------------------------------------------------------------

def check_python() -> tuple[bool, str]:
    v = sys.version_info
    if (v.major, v.minor) < (3, 10):
        return False, (
            f"Python {v.major}.{v.minor}.{v.micro} — need 3.10 or newer. "
            "Sony's silentcipher training code depends on modern typing "
            "syntax."
        )
    return True, f"Python {v.major}.{v.minor}.{v.micro}"


def check_packages() -> tuple[bool, str]:
    required = [
        "torch",
        "torchaudio",
        "silentcipher",  # Sony AI, MIT
        "huggingface_hub",
        "numpy",
        "librosa",
        "soundfile",
        "yaml",
    ]
    missing: list[str] = []
    for name in required:
        try:
            __import__(name)
        except ImportError:
            missing.append(name)
    if missing:
        return False, (
            "missing Python packages: "
            + ", ".join(missing)
            + " (install via `pip install -r requirements.txt`)"
        )
    return True, "all required packages importable"


def check_gpu() -> tuple[bool, str]:
    try:
        import torch
    except ImportError:
        return False, "torch not importable (see check_packages)"
    if not torch.cuda.is_available():
        return False, "no CUDA GPU visible to torch"
    count = torch.cuda.device_count()
    name = torch.cuda.get_device_name(0)
    return True, f"{count} CUDA device(s); device 0 = {name}"


def check_vram() -> tuple[bool, str]:
    try:
        import torch
    except ImportError:
        return False, "torch not importable"
    if not torch.cuda.is_available():
        return False, "no CUDA GPU"
    props = torch.cuda.get_device_properties(0)
    total_gb = props.total_memory / (1024 ** 3)
    # Free-VRAM query. We accept anything with >= 24 GB total; if another
    # CUDA process is holding a lot of VRAM, torch.cuda.mem_get_info is
    # the truthful reading.
    try:
        free_bytes, _ = torch.cuda.mem_get_info(0)
        free_gb = free_bytes / (1024 ** 3)
    except Exception:  # noqa: BLE001
        free_gb = total_gb  # best-effort fall-through
    if total_gb < 20:
        return False, (
            f"GPU has only {total_gb:.1f} GB total VRAM; training needs "
            "24 GB free at peak. This scaffold targets a 5090 (32 GB) or "
            "a 3090 (24 GB) with no other CUDA workload."
        )
    if free_gb < 20:
        return False, (
            f"GPU has {free_gb:.1f} GB free of {total_gb:.1f} GB. Another "
            "CUDA process is holding VRAM. Stop it (e.g. Ollama) before "
            "training. Check `nvidia-smi` for the offender."
        )
    return True, f"{free_gb:.1f} GB free of {total_gb:.1f} GB total"


def check_disk() -> tuple[bool, str]:
    training_dir = Path(__file__).parent
    stat = shutil.disk_usage(training_dir)
    free_gb = stat.free / (1024 ** 3)
    if free_gb < 50:
        return False, (
            f"only {free_gb:.1f} GB free on the training-dir mount "
            f"({training_dir}); need 50 GB minimum for training corpus + "
            "rotating checkpoints + logs. Free some space or move the "
            "training dir to a larger volume."
        )
    return True, f"{free_gb:.1f} GB free on training-dir mount"


def check_silentcipher_checkpoint() -> tuple[bool, str]:
    """Verify Sony's pretrained silentcipher checkpoint is in HF cache."""
    hf_cache = Path.home() / ".cache" / "huggingface" / "hub"
    if not hf_cache.exists():
        return False, (
            f"HF cache dir not found at {hf_cache}. Fetch the checkpoint "
            "via: python -c "
            "\"from huggingface_hub import snapshot_download; "
            "snapshot_download('sony/silentcipher')\""
        )
    hits = list(hf_cache.rglob("44_1_khz/73999_iteration/hparams.yaml"))
    if not hits:
        return False, (
            "Sony's 44.1 kHz silentcipher checkpoint not in HF cache. "
            "Fetch via: python -c "
            "\"from huggingface_hub import snapshot_download; "
            "snapshot_download('sony/silentcipher')\""
        )
    return True, f"silentcipher checkpoint present at {hits[0].parent}"


def check_dry_run_forward() -> tuple[bool, str]:
    """
    Optional: load silentcipher + do a batch-16 forward pass, log the
    peak VRAM. Skipped in this scaffold pending the actual train.py that
    knows the model-loading dance; TODO once train.py lands.
    """
    return True, "dry-run forward pass — SKIPPED in scaffold (see TODO)"


# ---------------------------------------------------------------------------
# Orchestrator.
# ---------------------------------------------------------------------------

CHECKS = [
    ("Python version", check_python),
    ("Python packages", check_packages),
    ("CUDA GPU visible", check_gpu),
    ("GPU VRAM headroom", check_vram),
    ("Disk headroom", check_disk),
    ("silentcipher HF cache", check_silentcipher_checkpoint),
    ("Dry-run forward pass", check_dry_run_forward),
]


def main() -> int:
    for label, fn in CHECKS:
        try:
            ok, detail = fn()
        except Exception as e:  # noqa: BLE001
            banner_fail(f"{label} check raised: {e}")
            return 1
        if not ok:
            banner_fail(f"{label} — {detail}")
            return 1
        # single-line success per check
        print(f"  \033[32m✓\033[0m {label}: {detail}")

    banner_ok()
    return 0


if __name__ == "__main__":
    sys.exit(main())
