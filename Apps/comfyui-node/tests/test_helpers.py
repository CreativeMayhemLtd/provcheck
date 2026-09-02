"""Tests for the shared internal helpers (provcheck_comfyui._helpers).

These cover the serialisation, report-parsing, and manifest-redaction behaviour that
used to live across the retired per-node test files, now that the node is a single
consolidated ProvcheckC2PA with the helpers factored into _helpers.py.
"""
from __future__ import annotations

import sys
import wave
from pathlib import Path

import numpy as np
import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
PACK = REPO_ROOT / "Apps" / "comfyui-node"
sys.path.insert(0, str(PACK))


# -- image round trip --------------------------------------------------------
def test_tensor_png_round_trip(tmp_path):
    import torch

    from provcheck_comfyui._helpers import _png_to_tensor, _tensor_to_png

    t = torch.rand((16, 24, 3), dtype=torch.float32)
    p = tmp_path / "x.png"
    _tensor_to_png(t, p)
    back = _png_to_tensor(p)
    assert back.shape == t.shape
    # 8-bit quantisation round-trip is within ~1/255
    assert torch.max(torch.abs(back - t)).item() < 0.01


# -- audio serialisation -----------------------------------------------------
@pytest.mark.parametrize("channels", [1, 2])
def test_waveform_to_wav_valid(tmp_path, channels):
    import torch

    from provcheck_comfyui._helpers import _waveform_to_wav

    wf = torch.zeros((channels, 8000), dtype=torch.float32)
    out = tmp_path / "a.wav"
    _waveform_to_wav(wf, 44100, out)
    with wave.open(str(out), "rb") as w:
        assert w.getnchannels() == channels
        assert w.getframerate() == 44100
        assert w.getsampwidth() == 2


def test_waveform_to_wav_clips_out_of_range(tmp_path):
    import torch

    from provcheck_comfyui._helpers import _waveform_to_wav

    wf = torch.full((1, 100), 5.0, dtype=torch.float32)  # way out of [-1,1]
    out = tmp_path / "clip.wav"
    _waveform_to_wav(wf, 22050, out)  # must not raise
    with wave.open(str(out), "rb") as w:
        raw = np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16)
    assert raw.max() <= 32767 and raw.min() >= -32768


# -- report parsing ----------------------------------------------------------
def test_parse_report_tolerant():
    from provcheck_comfyui._helpers import _parse_report

    assert _parse_report("") == {}
    assert _parse_report("not json") == {}
    assert _parse_report('banner line\n{"watermarks": []}')["watermarks"] == []


def test_first_detection_clamps_and_reads_brand():
    from provcheck_comfyui._helpers import _first_detection

    # TrustMark match score can exceed 1 -> clamp to 1.0
    det, brand, conf, summary = _first_detection(
        {"watermarks": [{"detected": True, "kind": "trust_mark", "confidence": 11.2,
                         "brand": {"code": "raidio"}}]})
    assert det is True and brand == "raidio" and conf == 1.0
    assert "raidio" in summary
    # nothing detected
    assert _first_detection({"watermarks": []})[0] is False
    assert _first_detection({})[0] is False


# -- manifest build + redaction ----------------------------------------------
MOCK_GRAPH = {
    "1": {"class_type": "CheckpointLoaderSimple", "inputs": {"ckpt_name": "C:/models/foo.safetensors"}},
    "2": {"class_type": "KSampler", "inputs": {"seed": 42, "steps": 20, "cfg": 7.0}},
    "3": {"class_type": "CLIPTextEncode", "inputs": {"text": "a cat"}},
    "5": {"class_type": "SomeCloudNode", "inputs": {"api_key": "sk-SECRET-123", "endpoint": "x"}},
}


def test_summarise_graph_curates_and_basenames():
    from provcheck_comfyui._helpers import _summarise_graph

    s = _summarise_graph(MOCK_GRAPH)
    assert s["model"] == "foo.safetensors"      # path reduced to basename
    assert s["seed"] == 42 and s["steps"] == 20
    assert s["prompts"] == ["a cat"]


def test_build_manifest_shape_and_full_redaction():
    from provcheck_comfyui._helpers import _build_manifest

    m = _build_manifest(MOCK_GRAPH, None, include_full=False)
    labels = [a["label"] for a in m["assertions"]]
    assert "c2pa.actions" in labels and "com.provcheck.generation" in labels
    gen = next(a["data"] for a in m["assertions"] if a["label"] == "com.provcheck.generation")
    assert "workflow_api" not in gen                       # curated default omits raw graph

    mfull = _build_manifest(MOCK_GRAPH, None, include_full=True)
    genf = next(a["data"] for a in mfull["assertions"] if a["label"] == "com.provcheck.generation")
    assert genf["workflow_api"]["5"]["inputs"]["api_key"] == "<redacted>"   # secret dropped even when included
    assert genf["workflow_api"]["1"]["inputs"]["ckpt_name"] == "foo.safetensors"  # path shortened
    # original graph untouched (deep copy)
    assert MOCK_GRAPH["5"]["inputs"]["api_key"] == "sk-SECRET-123"
