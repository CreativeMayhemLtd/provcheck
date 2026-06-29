"""StampNode — runs ``provcheck-kit stamp`` on every generated image.

ComfyUI passes images as ``torch.Tensor`` of shape
``[batch, H, W, channels]`` in ``[0, 1]``. The node:

1. Saves each batch element to a temp PNG.
2. Shells out to ``provcheck-kit stamp <tmp.png> -o <tmp_stamped.png>
   --brand-id <N>``.
3. Reads the stamped PNG back as a ``torch.Tensor`` and returns it.

The node fails closed: if ``provcheck-kit`` is missing from PATH,
or stamp fails on any frame, the node returns the input unchanged
and prints a clear diagnostic in the ComfyUI console — same
"degrade gracefully" pattern the verifier uses for missing
detectors. This keeps a creator's render queue from crashing when
the kit is not installed.

The node is brand-agnostic: the ``brand_id`` input picks one of
the registry brands (1 = doomscroll, 2 = rAIdio, 3 = vAIdeo, etc.).
A creator running their own pipeline picks the brand id matching
their atproto identity.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import numpy as np
import torch
from PIL import Image


def _kit_on_path() -> str | None:
    """Return the path to ``provcheck-kit`` if on PATH, else None."""
    return shutil.which("provcheck-kit") or shutil.which("provcheck-kit.exe")


def _tensor_to_png(t: torch.Tensor, out: Path) -> None:
    """t is HWC float in [0,1] -> PNG file."""
    arr = (t.detach().cpu().numpy() * 255.0).clip(0, 255).astype(np.uint8)
    Image.fromarray(arr).save(out, format="PNG")


def _png_to_tensor(path: Path) -> torch.Tensor:
    """PNG file -> HWC float tensor in [0,1]."""
    img = Image.open(path).convert("RGB")
    arr = np.array(img, dtype=np.float32) / 255.0
    return torch.from_numpy(arr)


def _stamp_one(kit: str, brand_id: int, src: Path, dst: Path) -> tuple[bool, str]:
    """Shell out to provcheck-kit. Returns (ok, message)."""
    try:
        proc = subprocess.run(
            [
                kit,
                "stamp",
                str(src),
                "-o",
                str(dst),
                "--brand-id",
                str(brand_id),
                "--no-sign",  # signing requires kit init; opt-in via separate node
                "--overwrite",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if proc.returncode != 0:
            return False, f"kit exit {proc.returncode}: {proc.stderr.strip()[:200]}"
        return True, "ok"
    except subprocess.TimeoutExpired:
        return False, "kit timed out (>120s)"
    except FileNotFoundError as e:
        return False, f"kit not executable: {e}"


class StampNode:
    """ComfyUI node — stamp generated images with a provcheck watermark.

    Inputs:
      ``image`` — IMAGE tensor batch from upstream.
      ``brand_id`` — 5-bit brand id (1..31). 1 = doomscroll,
        2 = rAIdio, 3 = vAIdeo, others = creator-registered.

    Output:
      ``stamped_image`` — same shape as input. Each batch frame
      has been stamped via ``provcheck-kit stamp`` (TrustMark-B
      watermark embedded). Frames that fail stamping pass through
      unchanged with a console warning — render does not crash.
    """

    @classmethod
    def INPUT_TYPES(cls):  # noqa: N802 — ComfyUI naming convention
        return {
            "required": {
                "image": ("IMAGE",),
                "brand_id": (
                    "INT",
                    {"default": 2, "min": 0, "max": 31, "step": 1},
                ),
            },
        }

    RETURN_TYPES = ("IMAGE",)
    RETURN_NAMES = ("stamped_image",)
    FUNCTION = "stamp"
    CATEGORY = "image/postprocessing"

    def stamp(self, image: torch.Tensor, brand_id: int):
        kit = _kit_on_path()
        if not kit:
            print(
                "[provcheck-comfyui] StampNode: provcheck-kit not on PATH; "
                "passing image through unchanged. Install: "
                "https://github.com/CreativeMayhemLtd/provcheck/releases/latest"
            )
            return (image,)

        # image is [B, H, W, C] in [0,1]
        batch = image.shape[0]
        out_frames = []
        with tempfile.TemporaryDirectory(prefix="provcheck-comfyui-") as td:
            tdpath = Path(td)
            for i in range(batch):
                src = tdpath / f"frame-{i:04d}.png"
                dst = tdpath / f"frame-{i:04d}.stamped.png"
                _tensor_to_png(image[i], src)
                ok, msg = _stamp_one(kit, brand_id, src, dst)
                if ok and dst.exists():
                    out_frames.append(_png_to_tensor(dst))
                else:
                    print(
                        f"[provcheck-comfyui] StampNode: frame {i} stamp "
                        f"failed ({msg}); passing through unchanged."
                    )
                    out_frames.append(image[i])
        stacked = torch.stack(out_frames, dim=0)
        print(
            f"[provcheck-comfyui] StampNode: stamped {batch} frame(s) "
            f"with brand_id={brand_id} via {os.path.basename(kit)}."
        )
        return (stacked,)
