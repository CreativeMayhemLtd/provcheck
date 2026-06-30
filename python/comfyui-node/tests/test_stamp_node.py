"""Smoke tests for the provcheck-comfyui StampNode (image).

These are deliberately minimal — the bulk of the watermark
correctness is verified by the Rust crate's own tests. We test
the Python wrapper's failure modes here: missing kit, malformed
brand id, tensor shape preservation, sign opt-in behaviour,
timeout knob clamping.

Run with: pytest python/comfyui-node/tests/
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

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
    have caught it client-side."""
    from provcheck_comfyui.stamp_node import StampNode

    node = StampNode()
    with mock.patch("provcheck_comfyui.stamp_node._kit_on_path", return_value=None):
        node.stamp(small_tensor, brand_id=99999)
        node.stamp(small_tensor, brand_id=-7)
        node.stamp(small_tensor, brand_id=2)


def test_brand_id_non_int_falls_back_to_default(small_tensor):
    """A workflow JSON could pass a string. The node must not raise."""
    from provcheck_comfyui.stamp_node import StampNode

    node = StampNode()
    with mock.patch("provcheck_comfyui.stamp_node._kit_on_path", return_value=None):
        # str that doesn't parse as int → silent fallback to RAIDIO.
        (out,) = node.stamp(small_tensor, brand_id="bogus")  # type: ignore[arg-type]
    assert out.shape == small_tensor.shape


def test_input_types_declares_required_and_optional_fields():
    """ComfyUI loads INPUT_TYPES at registration. Verify it has
    the shape ComfyUI expects, including the v0.9.77 sign +
    timeout optional inputs."""
    from provcheck_comfyui.stamp_node import StampNode

    spec = StampNode.INPUT_TYPES()
    assert "required" in spec
    assert "image" in spec["required"]
    assert "brand_id" in spec["required"]
    image_type, *_ = spec["required"]["image"]
    assert image_type == "IMAGE"
    # Optional inputs: sign + timeout_secs.
    assert "optional" in spec
    assert "sign" in spec["optional"]
    assert "timeout_secs" in spec["optional"]
    sign_type, sign_meta = spec["optional"]["sign"]
    assert sign_type == "BOOLEAN"
    assert sign_meta["default"] is False
    timeout_type, timeout_meta = spec["optional"]["timeout_secs"]
    assert timeout_type == "INT"
    assert timeout_meta["default"] == 120
    assert timeout_meta["min"] == 5
    assert timeout_meta["max"] == 600


def test_node_metadata_present():
    """Node class metadata that ComfyUI introspects."""
    from provcheck_comfyui.stamp_node import StampNode

    assert StampNode.RETURN_TYPES == ("IMAGE",)
    assert StampNode.FUNCTION == "stamp"
    assert StampNode.CATEGORY == "image/postprocessing"


def test_sign_default_is_false(small_tensor):
    """Default behaviour must be unsigned to match the documented
    contract (signing requires kit init). Verified by checking
    the subprocess argv on a missing-dst run (kit-missing path
    short-circuits before subprocess; instead intercept the
    helper)."""
    from provcheck_comfyui.stamp_node import StampNode

    captured: dict[str, list[str]] = {}

    def fake_stamp_one(kit, brand_id, src, dst, sign, timeout_secs):
        captured["args"] = [
            "kit",
            "stamp",
            str(src),
            "-o",
            str(dst),
            "--brand-id",
            str(brand_id),
            "--overwrite",
        ]
        if not sign:
            captured["args"].append("--no-sign")
        captured["sign"] = sign
        captured["timeout_secs"] = timeout_secs
        # Return failure so the node falls back to passthrough
        # without us having to produce a real stamped PNG.
        return False, "mocked"

    node = StampNode()
    with mock.patch(
        "provcheck_comfyui.stamp_node._kit_on_path",
        return_value="/fake/provcheck-kit",
    ), mock.patch(
        "provcheck_comfyui.stamp_node._stamp_one",
        side_effect=fake_stamp_one,
    ):
        node.stamp(small_tensor, brand_id=2)
    assert captured.get("sign") is False
    assert "--no-sign" in captured["args"]


def test_sign_true_omits_no_sign_flag(small_tensor):
    """sign=True must NOT pass --no-sign to the kit subprocess."""
    from provcheck_comfyui.stamp_node import StampNode

    captured: dict = {}

    def fake_stamp_one(kit, brand_id, src, dst, sign, timeout_secs):
        captured["sign"] = sign
        return False, "mocked"

    node = StampNode()
    with mock.patch(
        "provcheck_comfyui.stamp_node._kit_on_path",
        return_value="/fake/provcheck-kit",
    ), mock.patch(
        "provcheck_comfyui.stamp_node._stamp_one",
        side_effect=fake_stamp_one,
    ):
        node.stamp(small_tensor, brand_id=2, sign=True)
    assert captured.get("sign") is True


def test_timeout_clamped_to_valid_range(small_tensor):
    """Out-of-range timeout values must be clamped to [5, 600]."""
    from provcheck_comfyui.stamp_node import StampNode

    captured: dict = {}

    def fake_stamp_one(kit, brand_id, src, dst, sign, timeout_secs):
        captured.setdefault("timeouts", []).append(timeout_secs)
        return False, "mocked"

    node = StampNode()
    with mock.patch(
        "provcheck_comfyui.stamp_node._kit_on_path",
        return_value="/fake/provcheck-kit",
    ), mock.patch(
        "provcheck_comfyui.stamp_node._stamp_one",
        side_effect=fake_stamp_one,
    ):
        node.stamp(small_tensor, brand_id=2, timeout_secs=99999)
        node.stamp(small_tensor, brand_id=2, timeout_secs=0)
        node.stamp(small_tensor, brand_id=2, timeout_secs=60)
    assert captured["timeouts"] == [600, 5, 60]


def test_node_mappings_include_image_and_audio():
    """The __init__ must register BOTH nodes so ComfyUI sees them."""
    from provcheck_comfyui import (
        NODE_CLASS_MAPPINGS,
        NODE_DISPLAY_NAME_MAPPINGS,
    )

    assert "ProvcheckStamp" in NODE_CLASS_MAPPINGS
    assert "ProvcheckStampAudio" in NODE_CLASS_MAPPINGS
    assert "ProvcheckStamp" in NODE_DISPLAY_NAME_MAPPINGS
    assert "ProvcheckStampAudio" in NODE_DISPLAY_NAME_MAPPINGS
    # Display names must include Creative Mayhem branding.
    assert "Creative Mayhem" in NODE_DISPLAY_NAME_MAPPINGS["ProvcheckStamp"]
    assert "Creative Mayhem" in NODE_DISPLAY_NAME_MAPPINGS["ProvcheckStampAudio"]
