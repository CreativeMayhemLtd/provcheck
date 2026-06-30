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
the registry brands. **The default of ``2`` reflects the public
mirror's published registry (RAIDIO); creators who registered
their own brand in their own atproto signing-key record pick
their own id.** No id is "preferred" — the node ships a default
for ergonomic reasons only.

C2PA signing: ``sign`` input is a bool, default ``False`` because
signing requires ``provcheck-kit init`` (a local signing identity)
to have been run upstream. When ``sign=True`` and the local
identity is missing, the kit errors out and the node falls back
to passthrough with a clear warning. ``sign=True`` does NOT
publish to atproto; that's a separate ``kit publish`` step
post-render.
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


# Default per-frame subprocess timeout (seconds). Operators can
# raise this via the ``timeout_secs`` node input when running on
# slow hosts (CPU-only TrustMark embed of a high-res image can
# legitimately take > 60 s).
DEFAULT_TIMEOUT_SECS = 120
MAX_TIMEOUT_SECS = 600


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


def _stamp_one(
    kit: str,
    brand_id: int,
    src: Path,
    dst: Path,
    sign: bool,
    timeout_secs: int,
) -> tuple[bool, str]:
    """Shell out to provcheck-kit stamp. Returns (ok, message).

    ``sign`` controls whether the C2PA signing step runs. When
    ``False`` the kit is invoked with ``--no-sign`` (watermark
    only). When ``True`` the kit attempts to sign with the local
    identity; if no identity is initialised the kit returns a
    non-zero exit and this function reports the failure so the
    caller can fall back to passthrough.
    """
    argv = [
        kit,
        "stamp",
        str(src),
        "-o",
        str(dst),
        "--brand-id",
        str(brand_id),
        "--overwrite",
    ]
    if not sign:
        argv.append("--no-sign")
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_secs,
        )
        if proc.returncode != 0:
            return False, f"kit exit {proc.returncode}: {proc.stderr.strip()[:200]}"
        return True, "ok"
    except subprocess.TimeoutExpired:
        return False, f"kit timed out (>{timeout_secs}s)"
    except FileNotFoundError as e:
        return False, f"kit not executable: {e}"


class StampNode:
    """ComfyUI node — stamp generated images with a provcheck watermark.

    Inputs:
      ``image`` — IMAGE tensor batch from upstream.
      ``brand_id`` — 5-bit brand id (0..31). Default 2 reflects
        the public mirror's RAIDIO registration; creators with
        their own atproto-published brand pick their own id.
      ``sign`` — when True, also run the C2PA signing step using
        the local identity. Requires ``provcheck-kit init`` to
        have been run. When False (default), watermark only.
      ``timeout_secs`` — per-frame subprocess timeout. Default
        120s; raise to 600s for slow hosts or high-res inputs.

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
            "optional": {
                "sign": ("BOOLEAN", {"default": False}),
                "timeout_secs": (
                    "INT",
                    {
                        "default": DEFAULT_TIMEOUT_SECS,
                        "min": 5,
                        "max": MAX_TIMEOUT_SECS,
                        "step": 5,
                    },
                ),
            },
        }

    RETURN_TYPES = ("IMAGE",)
    RETURN_NAMES = ("stamped_image",)
    FUNCTION = "stamp"
    CATEGORY = "image/postprocessing"

    def stamp(
        self,
        image: torch.Tensor,
        brand_id: int,
        sign: bool = False,
        timeout_secs: int = DEFAULT_TIMEOUT_SECS,
    ):
        # v0.9.0 audit §3: ComfyUI's INPUT_TYPES min/max is
        # client-side only. A malicious workflow JSON can pass any
        # int. Clamp defensively here BEFORE handing the value to
        # the kit subprocess.
        try:
            brand_id = max(0, min(31, int(brand_id)))
        except (TypeError, ValueError):
            brand_id = 2  # silent fall-back to RAIDIO default
        try:
            timeout_secs = max(5, min(MAX_TIMEOUT_SECS, int(timeout_secs)))
        except (TypeError, ValueError):
            timeout_secs = DEFAULT_TIMEOUT_SECS
        sign = bool(sign)

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
                ok, msg = _stamp_one(kit, brand_id, src, dst, sign, timeout_secs)
                if ok and dst.exists():
                    out_frames.append(_png_to_tensor(dst))
                else:
                    print(
                        f"[provcheck-comfyui] StampNode: frame {i} stamp "
                        f"failed ({msg}); passing through unchanged."
                    )
                    out_frames.append(image[i])
        stacked = torch.stack(out_frames, dim=0)
        mode = "signed + watermarked" if sign else "watermarked"
        print(
            f"[provcheck-comfyui] StampNode: {mode} {batch} frame(s) "
            f"with brand_id={brand_id} via {os.path.basename(kit)} "
            f"(timeout {timeout_secs}s/frame)."
        )
        return (stacked,)
