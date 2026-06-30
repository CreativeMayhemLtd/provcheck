"""Smoke tests for the provcheck-comfyui StampAudioNode.

Same shape as the image-node tests: cover the wrapper's failure
modes (missing kit, malformed AUDIO dict, malformed brand id,
timeout knob clamping, sign opt-in argv shape, WAV serialisation
round-trip). The audio-specific tests confirm the WAV round-trip
preserves shape + sample rate at int16 precision.

Run with: pytest python/comfyui-node/tests/
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "python" / "comfyui-node"))


@pytest.fixture
def small_audio():
    """A 1-batch mono 0.1-second audio clip at 44.1 kHz.

    Shape: [batch=1, channels=1, samples=4410].
    """
    import torch

    waveform = torch.zeros((1, 1, 4410), dtype=torch.float32)
    return {"waveform": waveform, "sample_rate": 44100}


@pytest.fixture
def stereo_audio():
    """A stereo clip: [batch=1, channels=2, samples=4410] at 44.1 kHz."""
    import torch

    waveform = torch.zeros((1, 2, 4410), dtype=torch.float32)
    return {"waveform": waveform, "sample_rate": 44100}


# ----- Fail-closed: missing kit -----

def test_passthrough_when_kit_missing(small_audio):
    from provcheck_comfyui.stamp_audio_node import StampAudioNode

    node = StampAudioNode()
    with mock.patch(
        "provcheck_comfyui.stamp_audio_node._kit_on_path",
        return_value=None,
    ):
        (out,) = node.stamp(small_audio, brand_id=2)
    # Same dict back.
    assert out is small_audio


# ----- Malformed AUDIO inputs -----

def test_passthrough_when_audio_is_not_a_dict():
    from provcheck_comfyui.stamp_audio_node import StampAudioNode

    node = StampAudioNode()
    bogus = "not-a-dict"
    with mock.patch(
        "provcheck_comfyui.stamp_audio_node._kit_on_path",
        return_value="/fake/kit",
    ):
        (out,) = node.stamp(bogus, brand_id=2)  # type: ignore[arg-type]
    assert out == "not-a-dict"


def test_passthrough_when_audio_missing_waveform_key():
    from provcheck_comfyui.stamp_audio_node import StampAudioNode

    node = StampAudioNode()
    bogus = {"sample_rate": 44100}
    with mock.patch(
        "provcheck_comfyui.stamp_audio_node._kit_on_path",
        return_value="/fake/kit",
    ):
        (out,) = node.stamp(bogus, brand_id=2)
    assert out is bogus


# ----- Brand-id clamping -----

def test_brand_id_clamped_server_side(small_audio):
    from provcheck_comfyui.stamp_audio_node import StampAudioNode

    node = StampAudioNode()
    with mock.patch(
        "provcheck_comfyui.stamp_audio_node._kit_on_path",
        return_value=None,
    ):
        node.stamp(small_audio, brand_id=99999)
        node.stamp(small_audio, brand_id=-7)
        node.stamp(small_audio, brand_id="bogus")  # type: ignore[arg-type]


# ----- INPUT_TYPES + metadata -----

def test_input_types_has_required_audio_and_brand_id():
    from provcheck_comfyui.stamp_audio_node import StampAudioNode

    spec = StampAudioNode.INPUT_TYPES()
    assert spec["required"]["audio"][0] == "AUDIO"
    assert spec["required"]["brand_id"][0] == "INT"
    assert "sign" in spec["optional"]
    assert "timeout_secs" in spec["optional"]


def test_node_metadata():
    from provcheck_comfyui.stamp_audio_node import StampAudioNode

    assert StampAudioNode.RETURN_TYPES == ("AUDIO",)
    assert StampAudioNode.FUNCTION == "stamp"
    assert StampAudioNode.CATEGORY == "audio/postprocessing"


# ----- WAV round-trip -----

def test_waveform_to_wav_and_back_round_trips_mono():
    import numpy as np
    import torch

    from provcheck_comfyui.stamp_audio_node import (
        _waveform_to_wav,
        _wav_to_waveform,
    )

    # A simple sine at 440 Hz, 0.1 s @ 44.1 kHz.
    sr = 44100
    samples = int(sr * 0.1)
    t = np.arange(samples) / sr
    waveform = torch.from_numpy(
        (0.5 * np.sin(2 * np.pi * 440 * t)).astype(np.float32)
    ).unsqueeze(0)  # [1, samples]

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "x.wav"
        _waveform_to_wav(waveform, sr, p)
        back, back_sr = _wav_to_waveform(p)

    assert back_sr == sr
    assert back.shape == waveform.shape
    # int16 round-trip is lossy in the LSB; tolerate within
    # 1/32768 + a small slack for numpy float32 imprecision.
    max_err = float((back - waveform).abs().max())
    assert max_err < 5e-4, f"round-trip error {max_err} too large"


def test_waveform_to_wav_and_back_round_trips_stereo():
    import numpy as np
    import torch

    from provcheck_comfyui.stamp_audio_node import (
        _waveform_to_wav,
        _wav_to_waveform,
    )

    sr = 44100
    samples = 2048
    t = np.arange(samples) / sr
    left = 0.3 * np.sin(2 * np.pi * 440 * t)
    right = 0.4 * np.sin(2 * np.pi * 880 * t)
    waveform = torch.from_numpy(
        np.stack([left, right]).astype(np.float32)
    )  # [2, samples]

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "x.wav"
        _waveform_to_wav(waveform, sr, p)
        back, back_sr = _wav_to_waveform(p)

    assert back_sr == sr
    assert back.shape == waveform.shape
    max_err = float((back - waveform).abs().max())
    assert max_err < 5e-4


def test_waveform_to_wav_clips_out_of_range_values():
    """Float input above 1.0 or below -1.0 must clip, not wrap."""
    import torch

    from provcheck_comfyui.stamp_audio_node import _waveform_to_wav, _wav_to_waveform

    sr = 44100
    waveform = torch.tensor([[2.0, -2.0, 1.5, -1.5, 0.5, 0.0]], dtype=torch.float32)
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "x.wav"
        _waveform_to_wav(waveform, sr, p)
        back, _ = _wav_to_waveform(p)
    # 2.0 → clipped to ~1.0 (int16 32767 / 32768 ≈ 0.99997).
    assert back[0, 0].item() > 0.99
    assert back[0, 1].item() < -0.99
    assert back[0, 2].item() > 0.99
    assert back[0, 3].item() < -0.99
    # 0.5 round-trips within precision.
    assert abs(back[0, 4].item() - 0.5) < 1e-3


# ----- Sign opt-in argv shape -----

def test_sign_default_passes_no_sign_flag(small_audio):
    from provcheck_comfyui.stamp_audio_node import StampAudioNode

    captured = {}

    def fake_stamp_one(kit, brand_id, src, dst, sign, timeout_secs):
        captured["sign"] = sign
        return False, "mocked"

    node = StampAudioNode()
    with mock.patch(
        "provcheck_comfyui.stamp_audio_node._kit_on_path",
        return_value="/fake/kit",
    ), mock.patch(
        "provcheck_comfyui.stamp_audio_node._stamp_one",
        side_effect=fake_stamp_one,
    ):
        node.stamp(small_audio, brand_id=2)
    assert captured["sign"] is False


def test_sign_true_does_not_pass_no_sign(small_audio):
    from provcheck_comfyui.stamp_audio_node import StampAudioNode

    captured = {}

    def fake_stamp_one(kit, brand_id, src, dst, sign, timeout_secs):
        captured["sign"] = sign
        return False, "mocked"

    node = StampAudioNode()
    with mock.patch(
        "provcheck_comfyui.stamp_audio_node._kit_on_path",
        return_value="/fake/kit",
    ), mock.patch(
        "provcheck_comfyui.stamp_audio_node._stamp_one",
        side_effect=fake_stamp_one,
    ):
        node.stamp(small_audio, brand_id=2, sign=True)
    assert captured["sign"] is True


# ----- Timeout clamping -----

def test_timeout_clamped_to_valid_range(small_audio):
    from provcheck_comfyui.stamp_audio_node import StampAudioNode

    captured = {}

    def fake_stamp_one(kit, brand_id, src, dst, sign, timeout_secs):
        captured.setdefault("timeouts", []).append(timeout_secs)
        return False, "mocked"

    node = StampAudioNode()
    with mock.patch(
        "provcheck_comfyui.stamp_audio_node._kit_on_path",
        return_value="/fake/kit",
    ), mock.patch(
        "provcheck_comfyui.stamp_audio_node._stamp_one",
        side_effect=fake_stamp_one,
    ):
        node.stamp(small_audio, brand_id=2, timeout_secs=99999)
        node.stamp(small_audio, brand_id=2, timeout_secs=0)
        node.stamp(small_audio, brand_id=2, timeout_secs=60)
    assert captured["timeouts"] == [600, 5, 60]


# ----- Sample rate preserved through round trip -----

def test_sample_rate_preserved_in_output_dict(small_audio):
    """When the kit fails (or is mocked-fail), the node passes
    through the input — including its sample_rate. Verifies the
    return shape matches ComfyUI's AUDIO type contract."""
    from provcheck_comfyui.stamp_audio_node import StampAudioNode

    node = StampAudioNode()
    with mock.patch(
        "provcheck_comfyui.stamp_audio_node._kit_on_path",
        return_value=None,
    ):
        (out,) = node.stamp(small_audio, brand_id=2)
    assert out["sample_rate"] == 44100
