"""Smoke tests for the provcheck-comfyui StampNode.

These are deliberately minimal — the bulk of the watermark
correctness is verified by the Rust crate's own tests. We test
the Python wrapper's failure modes here: missing kit, malformed
brand id, tensor shape preservation.

Run with: pytest python/comfyui-node/tests/
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

import numpy as np
import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "python" / "comfyui-node"))


@pytest.fixture
def small_tensor():
    """A 1-batch 8x8 RGB tensor in [0, 1] — enough to exercise the
    save/load roundtrip without forcing a long-running kit call."""
    import torch

    return torch.zeros((1, 8, 8, 3), dtype=torch.float32)


def test_passthrough_when_kit_missing(small_tensor):
    """When provcheck-kit isn't on PATH, the node returns the
    input unchanged and prints a console warning. This is the
    fail-closed behavior that keeps render queues from crashing
    when the kit isn't installed."""
    from provcheck_comfyui.stamp_node import StampNode

    node = StampNode()
    with mock.patch("provcheck_comfyui.stamp_node._kit_on_path", return_value=None):
        (out,) = node.stamp(small_tensor, brand_id=2)
    assert out.shape == small_tensor.shape
    import torch

    assert torch.allclose(out, small_tensor)


def test_brand_id_clamped_server_side(small_tensor):
    """Per the v0.9.0 audit §3 fix, the StampNode clamps brand_id
    defensively even when ComfyUI's INPUT_TYPES min/max would
    have caught it client-side. We can't easily inspect the
    clamped value without running the kit, but we can confirm
    that an out-of-range int doesn't raise."""
    from provcheck_comfyui.stamp_node import StampNode

    node = StampNode()
    with mock.patch("provcheck_comfyui.stamp_node._kit_on_path", return_value=None):
        node.stamp(small_tensor, brand_id=99999)
        node.stamp(small_tensor, brand_id=-7)
        node.stamp(small_tensor, brand_id=2)


def test_input_types_declares_required_fields():
    """ComfyUI loads INPUT_TYPES at registration. Verify it has
    the shape ComfyUI expects."""
    from provcheck_comfyui.stamp_node import StampNode

    spec = StampNode.INPUT_TYPES()
    assert "required" in spec
    assert "image" in spec["required"]
    assert "brand_id" in spec["required"]
    image_type, *_ = spec["required"]["image"]
    assert image_type == "IMAGE"


def test_node_metadata_present():
    """Node class metadata that ComfyUI introspects."""
    from provcheck_comfyui.stamp_node import StampNode

    assert StampNode.RETURN_TYPES == ("IMAGE",)
    assert StampNode.FUNCTION == "stamp"
    assert StampNode.CATEGORY == "image/postprocessing"
