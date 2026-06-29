"""Stamp node — scaffold-only for v0.7.0.

The real implementation lands in v0.9 once the underlying
``provcheck-kit stamp`` CLI (v0.7.0) has had time to settle. See
``README.md`` for the target architecture.

The current node accepts an image input + brand id, returns the
input image unchanged, and prints a one-line console note
explaining that stamping is not yet wired.
"""

from __future__ import annotations


class StampNode:
    """ComfyUI node: stamp the input image with the provcheck app strings.

    v0.7.0 scaffold. Returns the input image unchanged.
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

    def stamp(self, image, brand_id: int):
        # v0.7.0 scaffold: pass-through with a console note. Real
        # wiring (subprocess call to `provcheck-kit stamp` with the
        # tensor saved to a temp PNG, then loaded back) ships in
        # v0.9 alongside the rest of the staging release.
        print(
            f"[provcheck-comfyui] StampNode invoked (brand_id={brand_id}); "
            f"v0.7.0 scaffold, returning input unchanged. Real wiring "
            f"in v0.9 (see python/comfyui-node/README.md)."
        )
        return (image,)
