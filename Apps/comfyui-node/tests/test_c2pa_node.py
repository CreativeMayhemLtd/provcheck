"""Tests for the consolidated ProvcheckC2PANode (image/audio/video, read/write)."""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
PACK = REPO_ROOT / "Apps" / "comfyui-node"
sys.path.insert(0, str(PACK))


def _fake_kit(calls):
    """A stand-in for kit: 'stamp -o DST' copies SRC->DST (kit needs distinct paths);
    'sign' is a no-op on the existing file. Records argv into ``calls``."""
    import shutil

    def run(argv, timeout):
        calls.append(argv)
        if "stamp" in argv and "-o" in argv:
            src = argv[2]
            dst = argv[argv.index("-o") + 1]
            try:
                shutil.copyfile(src, dst)
            except OSError:
                return False, "copy failed"
        return True, "ok"

    return run


@pytest.fixture
def img():
    import torch

    return torch.zeros((1, 8, 8, 3), dtype=torch.float32)


@pytest.fixture
def aud():
    import torch

    return {"waveform": torch.zeros((1, 1, 1000), dtype=torch.float32), "sample_rate": 44100}


def test_input_types_and_metadata():
    from provcheck_comfyui.c2pa_node import ProvcheckC2PANode

    spec = ProvcheckC2PANode.INPUT_TYPES()
    assert spec["required"]["mode"][0] == ["write", "read"]
    assert spec["required"]["mode"][1]["default"] == "write"
    for k in ("image", "audio", "video"):
        assert k in spec["optional"], f"{k} input missing"
    for k in ("watermark", "c2pa_sign", "embed_identity", "record_provenance",
              "include_full_workflow", "brand_id", "timeout_secs"):
        assert "tooltip" in spec["optional"][k][1], f"{k} missing tooltip"
    assert ProvcheckC2PANode.RETURN_NAMES == ("image", "audio", "video", "report", "detected")
    assert ProvcheckC2PANode.OUTPUT_NODE is True
    assert "provcheck.ai" in ProvcheckC2PANode.DESCRIPTION
    # Backfire is noted in the info pane, not shipped as a fake node.
    assert "backfire" in ProvcheckC2PANode.DESCRIPTION.lower()


def test_nothing_connected():
    from provcheck_comfyui.c2pa_node import ProvcheckC2PANode

    res = ProvcheckC2PANode().run(mode="write")
    assert res["result"][:3] == (None, None, None)
    assert "connect" in res["result"][3]


def test_passthrough_when_kit_missing_write(img):
    from provcheck_comfyui.c2pa_node import ProvcheckC2PANode

    with mock.patch("provcheck_comfyui.c2pa_node._kit_on_path", return_value=None):
        res = ProvcheckC2PANode().run(mode="write", image=img)
    assert res["result"][0].shape == img.shape
    assert "not installed" in res["result"][3]


def test_nothing_to_do_when_both_off(img):
    from provcheck_comfyui.c2pa_node import ProvcheckC2PANode

    with mock.patch("provcheck_comfyui.c2pa_node._kit_on_path", return_value="/fake/kit"):
        res = ProvcheckC2PANode().run(mode="write", image=img, watermark=False, c2pa_sign=False)
    assert "nothing to do" in res["result"][3]


def test_image_watermark_only_returns_tensor(img):
    from provcheck_comfyui.c2pa_node import ProvcheckC2PANode

    with mock.patch("provcheck_comfyui.c2pa_node._kit_on_path", return_value="/fake/kit"), \
         mock.patch("provcheck_comfyui.c2pa_node._run", side_effect=_fake_kit([])):
        res = ProvcheckC2PANode().run(mode="write", image=img, watermark=True, c2pa_sign=False)
    assert res["result"][0].shape == img.shape
    assert "watermarked" in res["result"][3]
    assert res["ui"]["images"] == []  # watermark-only writes no output file


def test_image_sign_writes_file_and_argv(tmp_path, img):
    from provcheck_comfyui.c2pa_node import ProvcheckC2PANode

    calls = []

    with mock.patch("provcheck_comfyui.c2pa_node._kit_on_path", return_value="/fake/kit"), \
         mock.patch("provcheck_comfyui.c2pa_node._output_dir",
                    return_value=(tmp_path, "provcheck", "output")), \
         mock.patch("provcheck_comfyui.c2pa_node._run", side_effect=_fake_kit(calls)):
        res = ProvcheckC2PANode().run(mode="write", image=img, watermark=True,
                                      c2pa_sign=True, embed_identity=True)
    joined = [" ".join(c) for c in calls]
    assert any("stamp" in j and "--no-sign" in j for j in joined), "watermark step missing"
    assert any("sign" in j and "--embed-identity" in j for j in joined), "identity sign missing"
    assert res["ui"]["images"], "signed image not surfaced to UI"
    assert "signed" in res["result"][3]


def test_sign_provenance_passes_manifest(tmp_path, img):
    from provcheck_comfyui.c2pa_node import ProvcheckC2PANode

    calls = []

    with mock.patch("provcheck_comfyui.c2pa_node._kit_on_path", return_value="/fake/kit"), \
         mock.patch("provcheck_comfyui.c2pa_node._output_dir",
                    return_value=(tmp_path, "provcheck", "output")), \
         mock.patch("provcheck_comfyui.c2pa_node._run", side_effect=_fake_kit(calls)):
        ProvcheckC2PANode().run(mode="write", image=img, watermark=False, c2pa_sign=True,
                                record_provenance=True,
                                prompt={"1": {"class_type": "KSampler", "inputs": {"seed": 42}}})
    joined = [" ".join(c) for c in calls]
    assert any("sign" in j and "--manifest" in j for j in joined), "manifest not passed to sign"


def test_audio_write_returns_audio_dict(tmp_path, aud):
    from provcheck_comfyui.c2pa_node import ProvcheckC2PANode

    with mock.patch("provcheck_comfyui.c2pa_node._kit_on_path", return_value="/fake/kit"), \
         mock.patch("provcheck_comfyui.c2pa_node._output_dir",
                    return_value=(tmp_path, "provcheck", "output")), \
         mock.patch("provcheck_comfyui.c2pa_node._run", side_effect=_fake_kit([])):
        res = ProvcheckC2PANode().run(mode="write", audio=aud, watermark=True, c2pa_sign=False)
    out_audio = res["result"][1]
    assert isinstance(out_audio, dict) and "waveform" in out_audio
    assert out_audio["sample_rate"] == 44100
    assert "audio:" in res["result"][3]


def test_read_reports_detection(img):
    from provcheck_comfyui.c2pa_node import ProvcheckC2PANode

    fake = '{"watermarks":[{"detected":true,"kind":"image","confidence":0.9,"brand":{"code":"RAIDIO"}}]}'
    with mock.patch("provcheck_comfyui.c2pa_node._provcheck_on_path", return_value="/fake/provcheck"), \
         mock.patch("provcheck_comfyui.c2pa_node._run_capture", return_value=(True, fake)):
        res = ProvcheckC2PANode().run(mode="read", image=img)
    assert res["result"][4] is True
    assert "RAIDIO" in res["result"][3]


def test_read_passthrough_when_provcheck_missing(img):
    from provcheck_comfyui.c2pa_node import ProvcheckC2PANode

    with mock.patch("provcheck_comfyui.c2pa_node._provcheck_on_path", return_value=None):
        res = ProvcheckC2PANode().run(mode="read", image=img)
    assert res["result"][4] is False


def test_brand_id_clamped_and_nonint_safe(img):
    from provcheck_comfyui.c2pa_node import ProvcheckC2PANode

    node = ProvcheckC2PANode()
    with mock.patch("provcheck_comfyui.c2pa_node._kit_on_path", return_value=None):
        node.run(mode="write", image=img, brand_id=99999)
        node.run(mode="write", image=img, brand_id="bogus")  # type: ignore[arg-type]


def test_only_one_node_registered_with_help():
    from provcheck_comfyui import NODE_CLASS_MAPPINGS, NODE_DISPLAY_NAME_MAPPINGS

    assert list(NODE_CLASS_MAPPINGS) == ["ProvcheckC2PA"]
    assert "Creative Mayhem" in NODE_DISPLAY_NAME_MAPPINGS["ProvcheckC2PA"]
    docs = PACK / "provcheck_comfyui" / "web" / "docs"
    for key in NODE_CLASS_MAPPINGS:
        assert (docs / f"{key}.md").is_file(), f"missing help markdown for {key}"
