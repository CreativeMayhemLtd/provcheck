"""Internal helpers for the one provcheck ComfyUI node.

Serialisation (tensor <-> PNG, waveform -> 16-bit WAV), the ``provcheck --json``
report parser, the C2PA generation-provenance manifest builder with its secret/path
redaction, and PATH lookups for the CLIs. ``c2pa_node.ProvcheckC2PANode`` is the only
registered node; everything here is its internals. (The float-safe WAV *reader* lives
in c2pa_node, since the kit writes float32 WAV that the stdlib reader cannot parse.)
"""

from __future__ import annotations

import copy
import json
import shutil
import wave
from pathlib import Path

import numpy as np
import torch
from PIL import Image

DEFAULT_TIMEOUT_SECS = 120
MAX_TIMEOUT_SECS = 600
DEFAULT_SAMPLE_RATE = 44100

AI_SOURCE_TYPE = "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"

# Input keys whose VALUES must never be embedded (API keys, tokens, passwords).
_SECRET_KEYS = ("api_key", "apikey", "api-key", "token", "secret", "password",
                "passwd", "authorization", "auth")


# -- binaries on PATH --------------------------------------------------------
def _kit_on_path() -> str | None:
    """Path to ``provcheck-kit`` if on PATH, else None."""
    return shutil.which("provcheck-kit") or shutil.which("provcheck-kit.exe")


def _provcheck_on_path() -> str | None:
    """Path to the ``provcheck`` verifier if on PATH, else None."""
    return shutil.which("provcheck") or shutil.which("provcheck.exe")


# -- image: tensor <-> PNG ---------------------------------------------------
def _tensor_to_png(t: torch.Tensor, out: Path) -> None:
    """HWC float tensor in [0,1] -> PNG file."""
    arr = (t.detach().cpu().numpy() * 255.0).clip(0, 255).astype(np.uint8)
    Image.fromarray(arr).save(out, format="PNG")


def _png_to_tensor(path: Path) -> torch.Tensor:
    """PNG file -> HWC float tensor in [0,1]."""
    img = Image.open(path).convert("RGB")
    arr = np.array(img, dtype=np.float32) / 255.0
    return torch.from_numpy(arr)


# -- audio: [channels, samples] float -> 16-bit PCM WAV ----------------------
def _waveform_to_wav(waveform: torch.Tensor, sample_rate: int, out: Path) -> None:
    """Float [-1,1] -> int16 [-32768,32767] with clipping; multi-channel interleaved."""
    arr = waveform.detach().cpu().numpy()
    if arr.ndim == 1:
        arr = arr[np.newaxis, :]
    if arr.ndim != 2:
        raise ValueError(f"expected [channels, samples] tensor, got shape {arr.shape}")
    channels = arr.shape[0]
    interleaved = arr.T.astype(np.float32)
    int16 = np.clip(interleaved * 32767.0, -32768, 32767).astype(np.int16)
    with wave.open(str(out), "wb") as wf:
        wf.setnchannels(channels)
        wf.setsampwidth(2)
        wf.setframerate(int(sample_rate))
        wf.writeframes(int16.tobytes())


# -- provcheck --json report parsing -----------------------------------------
def _parse_report(stdout: str) -> dict:
    """Parse provcheck ``--json`` stdout into a dict; {} on any failure.

    provcheck exits non-zero for the UNSIGNED verdict (which a freshly generated
    frame always is), so the caller must NOT treat a non-zero exit as an error —
    the JSON on stdout is still the answer.
    """
    stdout = (stdout or "").strip()
    if not stdout:
        return {}
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        # Be forgiving if a banner precedes the JSON: take the last {...} block.
        start = stdout.find("{")
        end = stdout.rfind("}")
        if 0 <= start < end:
            try:
                return json.loads(stdout[start : end + 1])
            except json.JSONDecodeError:
                return {}
        return {}


def _first_detection(report: dict) -> tuple[bool, str, float, str]:
    """Return (detected, brand, confidence, summary) — highest-confidence detected mark.

    Detector confidence scales differ (silentcipher ~0..1; TrustMark's match score can
    exceed 1). Clamp to [0,1] so the node is consistent and matches the CLI display.
    """
    marks = report.get("watermarks") or []
    best = None
    for m in marks:
        if not isinstance(m, dict):
            continue
        if m.get("detected"):
            conf = min(1.0, max(0.0, float(m.get("confidence") or 0.0)))
            if best is None or conf > best[1]:
                brand = ""
                b = m.get("brand")
                if isinstance(b, dict):
                    brand = str(b.get("code") or "")
                elif isinstance(b, str):
                    brand = b
                best = (m.get("kind", "?"), conf, brand)
    if best is None:
        return False, "", 0.0, "no provcheck watermark detected"
    kind, conf, brand = best
    who = brand or "unknown-brand"
    return True, brand, conf, f"{kind}: detected — {who} ({conf * 100:.0f}% confidence)"


# -- C2PA generation-provenance manifest (curated + redacted) ----------------
def _looks_like_path(v) -> bool:
    return isinstance(v, str) and ("/" in v or "\\" in v) and len(v) > 3


def _basename(v: str) -> str:
    return v.replace("\\", "/").rsplit("/", 1)[-1]


def _redact_value(key: str, v):
    """Redact one input value for embedding: drop secrets, shorten paths."""
    if isinstance(key, str) and key.lower() in _SECRET_KEYS:
        return "<redacted>"
    if _looks_like_path(v):
        return _basename(v)
    return v


def _summarise_graph(prompt: dict | None) -> dict:
    """Best-effort curated summary of the common generation fields. Never raises;
    path values are reduced to basenames and secret-keyed inputs are dropped."""
    summary: dict = {}
    if not isinstance(prompt, dict):
        return summary
    prompts_text: list[str] = []
    for node in prompt.values():
        if not isinstance(node, dict):
            continue
        ct = str(node.get("class_type", ""))
        ins = node.get("inputs", {}) or {}
        if "CheckpointLoader" in ct and "ckpt_name" in ins and not isinstance(ins["ckpt_name"], list):
            summary.setdefault("model", _basename(str(ins["ckpt_name"])))
        if ct.startswith("KSampler") or ct == "SamplerCustom":
            for k in ("seed", "noise_seed", "steps", "cfg", "sampler_name", "scheduler", "denoise"):
                if k in ins and not isinstance(ins[k], list):
                    summary.setdefault("seed" if k == "noise_seed" else k, ins[k])
        if ct == "CLIPTextEncode":
            t = ins.get("text")
            if isinstance(t, str) and t.strip():
                prompts_text.append(t.strip())
        if "LoraLoader" in ct and "lora_name" in ins and not isinstance(ins["lora_name"], list):
            summary.setdefault("loras", []).append(_basename(str(ins["lora_name"])))
    if prompts_text:
        summary["prompts"] = prompts_text
    return summary


def _redact_graph(graph):
    """Deep-copy a workflow graph with secret-keyed inputs dropped and path values
    shortened to basenames, so the full-workflow opt-in still can't leak a key or the
    user's directory structure."""
    g = copy.deepcopy(graph)
    if isinstance(g, dict):
        for node in g.values():
            if isinstance(node, dict) and isinstance(node.get("inputs"), dict):
                node["inputs"] = {k: _redact_value(k, v) for k, v in node["inputs"].items()}
    return g


def _build_manifest(prompt: dict | None, extra_pnginfo: dict | None, include_full: bool) -> dict:
    """C2PA manifest: AI-generated marker + a curated generation summary. The raw
    (redacted) workflow is added only when include_full is set."""
    gen: dict = {"generator": "ComfyUI", "tool": "provcheck-comfyui"}
    gen.update(_summarise_graph(prompt))
    if include_full:
        if isinstance(prompt, dict):
            gen["workflow_api"] = _redact_graph(prompt)
        if isinstance(extra_pnginfo, dict) and "workflow" in extra_pnginfo:
            gen["workflow_ui"] = _redact_graph(extra_pnginfo["workflow"])
    return {
        "claim_generator": "ComfyUI + provcheck",
        "title": "AI-generated image (ComfyUI)",
        "assertions": [
            {"label": "c2pa.actions",
             "data": {"actions": [{"action": "c2pa.created", "softwareAgent": "ComfyUI",
                                   "digitalSourceType": AI_SOURCE_TYPE}]}},
            {"label": "com.provcheck.generation", "data": gen},
        ],
    }


def _output_dir(prefix: str):
    """(dir, name, type_tag) for a written file. Uses ComfyUI's output dir when
    available; falls back to the CWD so the node still works outside ComfyUI/tests."""
    try:
        import folder_paths  # provided by ComfyUI at runtime

        return Path(folder_paths.get_output_directory()), prefix, "output"
    except Exception:
        return Path.cwd(), prefix, "output"
