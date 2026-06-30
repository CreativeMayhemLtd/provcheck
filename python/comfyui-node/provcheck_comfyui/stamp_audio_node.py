"""StampAudioNode — runs ``provcheck-kit stamp`` on a ComfyUI AUDIO output.

ComfyUI's AUDIO type is a ``dict`` with two keys: ``waveform`` (a
``torch.Tensor`` of shape ``[batch, channels, samples]`` containing
float PCM in ``[-1.0, 1.0]``) and ``sample_rate`` (int Hz). This
node:

1. Saves each batch element to a temp WAV at the input's sample
   rate.
2. Shells out to ``provcheck-kit stamp <tmp.wav> -o
   <tmp_stamped.wav> --brand-id <N>``.
3. Reads the stamped WAV back as a tensor and returns the
   AUDIO dict downstream.

The kit auto-detects the modality from the file extension, so
the same ``stamp`` subcommand the image node uses handles audio
too — under the hood it routes through silentcipher (the default
audio family) and produces a marked WAV.

Same fail-closed posture as the image node: missing kit OR a kit
failure on any clip → pass through unchanged with a console
warning. The render queue never crashes.

WAV serialisation uses Python's stdlib ``wave`` module with
int16 quantisation. The kit re-reads via symphonia which handles
int16 WAV natively, so the round trip is lossless from the
detector's point of view — the watermark math is unaffected by
the int16 intermediate.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import wave
from pathlib import Path

import numpy as np
import torch


DEFAULT_TIMEOUT_SECS = 120
MAX_TIMEOUT_SECS = 600
DEFAULT_SAMPLE_RATE = 44100


def _kit_on_path() -> str | None:
    """Return the path to ``provcheck-kit`` if on PATH, else None."""
    return shutil.which("provcheck-kit") or shutil.which("provcheck-kit.exe")


def _waveform_to_wav(waveform: torch.Tensor, sample_rate: int, out: Path) -> None:
    """Write a [channels, samples] float tensor to a 16-bit PCM WAV.

    Float [-1, 1] is mapped to int16 [-32768, 32767] with clipping.
    Multi-channel input is interleaved per the WAV spec.
    """
    arr = waveform.detach().cpu().numpy()
    if arr.ndim == 1:
        arr = arr[np.newaxis, :]
    if arr.ndim != 2:
        raise ValueError(
            f"expected [channels, samples] tensor, got shape {arr.shape}"
        )
    channels = arr.shape[0]
    # Interleave: channels-first → samples-first via T.
    interleaved = arr.T.astype(np.float32)
    int16 = np.clip(interleaved * 32767.0, -32768, 32767).astype(np.int16)
    with wave.open(str(out), "wb") as wf:
        wf.setnchannels(channels)
        wf.setsampwidth(2)
        wf.setframerate(int(sample_rate))
        wf.writeframes(int16.tobytes())


def _wav_to_waveform(path: Path) -> tuple[torch.Tensor, int]:
    """Read a 16-bit PCM WAV back to [channels, samples] float tensor + sr.

    Multi-channel WAV is de-interleaved into separate channel rows.
    """
    with wave.open(str(path), "rb") as wf:
        channels = wf.getnchannels()
        sample_width = wf.getsampwidth()
        sample_rate = wf.getframerate()
        n_frames = wf.getnframes()
        raw = wf.readframes(n_frames)
    if sample_width != 2:
        raise ValueError(
            f"expected 16-bit WAV from kit output, got {sample_width * 8}-bit"
        )
    int16 = np.frombuffer(raw, dtype=np.int16)
    # De-interleave: WAV is samples-first within each frame.
    if channels > 1:
        int16 = int16.reshape(-1, channels).T
    else:
        int16 = int16[np.newaxis, :]
    float32 = int16.astype(np.float32) / 32768.0
    return torch.from_numpy(float32), sample_rate


def _stamp_one(
    kit: str,
    brand_id: int,
    src: Path,
    dst: Path,
    sign: bool,
    timeout_secs: int,
) -> tuple[bool, str]:
    """Shell out to provcheck-kit stamp on an audio file. Returns (ok, message)."""
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


class StampAudioNode:
    """ComfyUI node — stamp generated audio with a provcheck watermark.

    Inputs:
      ``audio`` — AUDIO dict from upstream
        (``{"waveform": tensor[B, C, samples], "sample_rate": int}``).
      ``brand_id`` — 5-bit brand id (0..31). Same registry as the
        image node; default 2 reflects the public mirror's RAIDIO
        registration.
      ``sign`` — when True, also run the C2PA signing step. Requires
        ``provcheck-kit init``. Default False (watermark only).
      ``timeout_secs`` — per-clip subprocess timeout. Default 120s.

    Output:
      ``stamped_audio`` — AUDIO dict with the same shape as input.
      Each batch element has been stamped via ``provcheck-kit
      stamp`` (silentcipher 40-bit ASCII payload at 44.1 kHz by
      default). Clips that fail pass through unchanged with a
      console warning.

    Behaviour notes:
      - The kit's stamp subcommand routes audio through
        silentcipher by default. If you need AudioSeal or WavMark
        specifically, use the kit's ``watermark --kind`` flag in
        a post-render pipeline step; this node uses the unified
        ``stamp`` surface for consistency with the image node.
      - Sample rate is preserved through the round-trip (the
        output AUDIO dict carries the same ``sample_rate`` as the
        input).
    """

    @classmethod
    def INPUT_TYPES(cls):  # noqa: N802
        return {
            "required": {
                "audio": ("AUDIO",),
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

    RETURN_TYPES = ("AUDIO",)
    RETURN_NAMES = ("stamped_audio",)
    FUNCTION = "stamp"
    CATEGORY = "audio/postprocessing"

    def stamp(
        self,
        audio: dict,
        brand_id: int,
        sign: bool = False,
        timeout_secs: int = DEFAULT_TIMEOUT_SECS,
    ):
        # Defensive clamping mirrors the image node — workflow
        # JSON can carry any int.
        try:
            brand_id = max(0, min(31, int(brand_id)))
        except (TypeError, ValueError):
            brand_id = 2
        try:
            timeout_secs = max(5, min(MAX_TIMEOUT_SECS, int(timeout_secs)))
        except (TypeError, ValueError):
            timeout_secs = DEFAULT_TIMEOUT_SECS
        sign = bool(sign)

        # Validate the AUDIO dict shape — the ComfyUI type system
        # only checks the type name, not the dict contents.
        if not isinstance(audio, dict):
            print(
                "[provcheck-comfyui] StampAudioNode: input is not an "
                "AUDIO dict; passing through unchanged."
            )
            return (audio,)
        waveform = audio.get("waveform")
        sample_rate = audio.get("sample_rate", DEFAULT_SAMPLE_RATE)
        if waveform is None or not hasattr(waveform, "shape"):
            print(
                "[provcheck-comfyui] StampAudioNode: AUDIO dict missing "
                "'waveform' tensor; passing through unchanged."
            )
            return (audio,)

        kit = _kit_on_path()
        if not kit:
            print(
                "[provcheck-comfyui] StampAudioNode: provcheck-kit not on "
                "PATH; passing audio through unchanged. Install: "
                "https://github.com/CreativeMayhemLtd/provcheck/releases/latest"
            )
            return (audio,)

        # waveform is [B, C, samples]. If 2D, treat as a single batch.
        wf = waveform
        if wf.ndim == 2:
            wf = wf.unsqueeze(0)
        if wf.ndim != 3:
            print(
                f"[provcheck-comfyui] StampAudioNode: unexpected waveform "
                f"shape {tuple(wf.shape)}; passing through unchanged."
            )
            return (audio,)

        batch = wf.shape[0]
        out_clips = []
        with tempfile.TemporaryDirectory(prefix="provcheck-comfyui-audio-") as td:
            tdpath = Path(td)
            for i in range(batch):
                src = tdpath / f"clip-{i:04d}.wav"
                dst = tdpath / f"clip-{i:04d}.stamped.wav"
                try:
                    _waveform_to_wav(wf[i], sample_rate, src)
                except Exception as e:  # noqa: BLE001
                    print(
                        f"[provcheck-comfyui] StampAudioNode: clip {i} "
                        f"WAV serialise failed ({e}); passing through."
                    )
                    out_clips.append(wf[i])
                    continue
                ok, msg = _stamp_one(kit, brand_id, src, dst, sign, timeout_secs)
                if ok and dst.exists():
                    try:
                        stamped, _sr = _wav_to_waveform(dst)
                        out_clips.append(stamped)
                    except Exception as e:  # noqa: BLE001
                        print(
                            f"[provcheck-comfyui] StampAudioNode: clip {i} "
                            f"WAV reload failed ({e}); passing through."
                        )
                        out_clips.append(wf[i])
                else:
                    print(
                        f"[provcheck-comfyui] StampAudioNode: clip {i} stamp "
                        f"failed ({msg}); passing through unchanged."
                    )
                    out_clips.append(wf[i])
        # Re-stack into [B, C, samples]. Channel counts must match
        # across clips; if a passthrough preserves the original
        # channel layout while a successful stamp changes it (e.g.
        # mono → stereo), torch.stack would raise. Guard with a
        # try/except and fall back to the original on shape
        # mismatch.
        try:
            stacked = torch.stack(out_clips, dim=0)
        except RuntimeError as e:
            print(
                f"[provcheck-comfyui] StampAudioNode: post-stamp shape "
                f"mismatch ({e}); returning original audio."
            )
            return (audio,)
        mode = "signed + watermarked" if sign else "watermarked"
        print(
            f"[provcheck-comfyui] StampAudioNode: {mode} {batch} clip(s) "
            f"with brand_id={brand_id} via {os.path.basename(kit)} "
            f"(timeout {timeout_secs}s/clip, sr {sample_rate} Hz)."
        )
        return ({"waveform": stacked, "sample_rate": int(sample_rate)},)
