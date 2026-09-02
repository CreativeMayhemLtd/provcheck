"""ProvcheckC2PANode — the one provcheck node. Image, audio, and video; read or write.

A single multifunction node. Wire in an image, an audio clip, a video, or any
combination, pick write or read, and it does the whole free provcheck pipeline for
each connected modality. Every option is a standard widget, so it can be typed OR
wired in from another node (the API + graph-flow workflow) — including the output
``filename_prefix``.

  mode = "write" (default): for each connected input, embed the free FOSS watermark
    (TrustMark on images, silentcipher on the audio track of audio/video) and/or
    C2PA-sign it with your local key + atproto/Bluesky identity, optionally recording
    the generation graph. Because a C2PA manifest lives in the file container (not a
    decoded tensor a downstream Save node would re-encode), the SIGNED FILE is written
    to ComfyUI's output directory; the passthrough outputs are for preview/chaining.

  mode = "read": detect and verify a provcheck watermark on each connected input.

Image and audio go through ``provcheck-kit`` directly (png -> TrustMark, wav ->
silentcipher). VIDEO is handled the correct, container-preserving way: the audio
track is split out via ComfyUI's own video API, watermarked, then recombined with the
original video frames and re-encoded, and the container is C2PA-signed. (Handing a
whole video file straight to the kit is NOT safe — the kit's audio watermarker writes
a bare WAV to the output path and drops the video, so we never do that.)

Fails closed: any missing tool or failed step leaves the inputs untouched with a
console note, so a render queue never crashes.

Creative Mayhem also makes **Backfire**, a keyed watermark that AI provenance-
stripping *amplifies instead of removes*. It is a commercial add-on, not part of this
free pack: https://provcheck.ai/backfire
"""

from __future__ import annotations

import json
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

import numpy as np
import torch

from ._helpers import (
    DEFAULT_SAMPLE_RATE,
    DEFAULT_TIMEOUT_SECS,
    MAX_TIMEOUT_SECS,
    _build_manifest,
    _first_detection,
    _kit_on_path,
    _output_dir,
    _parse_report,
    _png_to_tensor,
    _provcheck_on_path,
    _tensor_to_png,
    _waveform_to_wav,
)

BACKFIRE_URL = "https://provcheck.ai/backfire"


def _run(argv: list[str], timeout: int) -> tuple[bool, str]:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0:
            return False, f"exit {proc.returncode}: {proc.stderr.strip()[:200]}"
        return True, "ok"
    except subprocess.TimeoutExpired:
        return False, f"timed out (>{timeout}s)"
    except FileNotFoundError as e:
        return False, f"not executable: {e}"


def _run_capture(argv: list[str], timeout: int) -> tuple[bool, str]:
    """Return stdout for the read/verify path. A non-zero exit is the UNSIGNED
    verdict, not an error, so stdout is returned regardless."""
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return True, proc.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False, ""


def _read_wav_any(path: Path) -> tuple[np.ndarray, int]:
    """Read a WAV as float32 [channels, samples], handling PCM int16/int32 AND
    IEEE float32/64 AND WAVE_FORMAT_EXTENSIBLE.

    The kit writes its watermarked audio as float32 (extensible) WAV, which the
    stdlib ``wave`` module cannot parse — reading it with ``wave`` raises and would
    silently drop the watermark. This parser handles every format the kit emits.
    """
    data = Path(path).read_bytes()
    if data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        raise ValueError("not a RIFF/WAVE file")
    fmt_tag = channels = bits = 0
    sr = 0
    samples = b""
    pos = 12
    while pos + 8 <= len(data):
        cid = data[pos:pos + 4]
        csz = struct.unpack("<I", data[pos + 4:pos + 8])[0]
        body = data[pos + 8:pos + 8 + csz]
        if cid == b"fmt ":
            fmt_tag, channels, sr, _byte_rate, _block, bits = struct.unpack("<HHIIHH", body[:16])
            if fmt_tag == 0xFFFE and len(body) >= 40:  # WAVE_FORMAT_EXTENSIBLE
                fmt_tag = struct.unpack("<H", body[24:26])[0]  # real tag from SubFormat GUID
        elif cid == b"data":
            samples = body
        pos += 8 + csz + (csz & 1)  # chunks are word-aligned
    if not channels or not sr:
        raise ValueError("WAV missing fmt")
    if fmt_tag == 3 and bits == 32:
        arr = np.frombuffer(samples, dtype="<f4").astype(np.float32)
    elif fmt_tag == 3 and bits == 64:
        arr = np.frombuffer(samples, dtype="<f8").astype(np.float32)
    elif fmt_tag == 1 and bits == 16:
        arr = np.frombuffer(samples, dtype="<i2").astype(np.float32) / 32768.0
    elif fmt_tag == 1 and bits == 32:
        arr = np.frombuffer(samples, dtype="<i4").astype(np.float32) / 2147483648.0
    elif fmt_tag == 1 and bits == 24:
        raw = np.frombuffer(samples, dtype=np.uint8).reshape(-1, 3)
        as32 = (raw[:, 0].astype(np.int32) | (raw[:, 1].astype(np.int32) << 8)
                | (raw[:, 2].astype(np.int32) << 16))
        as32 = np.where(as32 & 0x800000, as32 - 0x1000000, as32)
        arr = as32.astype(np.float32) / 8388608.0
    else:
        raise ValueError(f"unsupported WAV format tag={fmt_tag} bits={bits}")
    if channels > 1:
        arr = arr.reshape(-1, channels).T  # de-interleave -> [channels, samples]
    else:
        arr = arr[np.newaxis, :]
    # .T leaves a non-contiguous view; ComfyUI's audio encoder needs C-contiguous.
    return np.ascontiguousarray(arr), int(sr)


def _load_video_libs():
    """ComfyUI runtime video helpers (lazy so the package imports without ComfyUI)."""
    from comfy_api.input_impl import VideoFromComponents, VideoFromFile
    from comfy_api.util import VideoComponents, VideoContainer

    return VideoFromFile, VideoFromComponents, VideoComponents, VideoContainer


class ProvcheckC2PANode:
    """ComfyUI node — the one provcheck node: image / audio / video, read or write."""

    DESCRIPTION = (
        "Free, open (Apache-2.0) provcheck for ComfyUI — one node for image, audio, and "
        "video. WRITE: embed the free watermark (TrustMark on images, silentcipher on the "
        "audio track of audio/video) and/or C2PA-sign with your local key + atproto/Bluesky "
        "identity, optionally recording the generation graph; the signed file is written to "
        "your output directory. READ: detect/verify a provcheck mark on each connected input. "
        "Wire in an image, audio, video, or any mix. Every option is a widget you can also "
        "wire in from another node, including the output filename. Creative Mayhem also makes "
        "Backfire, a keyed mark that AI stripping amplifies instead of removes (commercial "
        "add-on, not in this free pack): https://provcheck.ai/backfire . More: https://provcheck.ai"
    )

    @classmethod
    def INPUT_TYPES(cls):  # noqa: N802 — ComfyUI naming convention
        return {
            "required": {
                "mode": (["write", "read"], {
                    "default": "write",
                    "tooltip": "write = watermark and/or C2PA-sign each connected input (most "
                               "common). read = detect/verify an existing provcheck mark.",
                }),
            },
            "optional": {
                "image": ("IMAGE", {"tooltip": "Optional image batch to write to / read from."}),
                "audio": ("AUDIO", {"tooltip": "Optional audio to write to / read from."}),
                "video": ("VIDEO", {"tooltip": "Optional video. The watermark rides the audio "
                                    "track (frames are preserved); the container is C2PA-signed."}),
                "watermark": ("BOOLEAN", {"default": True,
                    "tooltip": "[write] Embed the free FOSS watermark (TrustMark image / "
                               "silentcipher audio)."}),
                "c2pa_sign": ("BOOLEAN", {"default": True,
                    "tooltip": "[write] C2PA-sign with your local signing key. The signed file "
                               "is written to your ComfyUI output directory."}),
                "embed_identity": ("BOOLEAN", {"default": True,
                    "tooltip": "[write] Embed your atproto/Bluesky identity (DID + handle) in the "
                               "manifest so a verifier sees who signed it. Needs kit login."}),
                "record_provenance": ("BOOLEAN", {"default": False,
                    "tooltip": "[write] Record a curated summary of the generation graph "
                               "(model, seed, sampler, prompts) into the signed manifest."}),
                "include_full_workflow": ("BOOLEAN", {"default": False,
                    "tooltip": "[write] With record_provenance: embed the FULL (redacted) "
                               "workflow, not just the summary. Off by default to avoid leaking "
                               "prompts/paths."}),
                "brand_id": ("INT", {"default": 2, "min": 0, "max": 31, "step": 1,
                    "tooltip": "[write] Your 5-bit brand id from the atproto brand registry "
                               "(0-31). Default 2 is the public rAIdio.bot id; use your own."}),
                "filename_prefix": ("STRING", {"default": "provcheck",
                    "tooltip": "[write, when a file is written] Output filename prefix for the "
                               "signed/watermarked files. Editable, and can be wired in from "
                               "another node (right-click -> Convert to input)."}),
                "timeout_secs": ("INT", {"default": DEFAULT_TIMEOUT_SECS, "min": 5,
                    "max": MAX_TIMEOUT_SECS, "step": 5,
                    "tooltip": "Per-item subprocess timeout in seconds."}),
            },
            "hidden": {"prompt": "PROMPT", "extra_pnginfo": "EXTRA_PNGINFO"},
        }

    RETURN_TYPES = ("IMAGE", "AUDIO", "VIDEO", "STRING", "BOOLEAN")
    RETURN_NAMES = ("image", "audio", "video", "report", "detected")
    FUNCTION = "run"
    CATEGORY = "provcheck"
    OUTPUT_NODE = True

    def run(self, mode: str = "write", image=None, audio=None, video=None,
            watermark: bool = True, c2pa_sign: bool = True, embed_identity: bool = True,
            record_provenance: bool = False, include_full_workflow: bool = False,
            brand_id: int = 2, filename_prefix: str = "provcheck",
            timeout_secs: int = DEFAULT_TIMEOUT_SECS, prompt=None, extra_pnginfo=None):
        try:
            brand_id = max(0, min(31, int(brand_id)))
        except (TypeError, ValueError):
            brand_id = 2
        try:
            timeout_secs = max(5, min(MAX_TIMEOUT_SECS, int(timeout_secs)))
        except (TypeError, ValueError):
            timeout_secs = DEFAULT_TIMEOUT_SECS
        prefix = str(filename_prefix).strip() or "provcheck"

        if image is None and audio is None and video is None:
            return {"ui": {"images": []},
                    "result": (None, None, None, "connect an image, audio, or video", False)}

        if str(mode) == "read":
            return self._read(image, audio, video, timeout_secs)
        return self._write(image, audio, video, watermark, c2pa_sign, embed_identity,
                           record_provenance, include_full_workflow, brand_id,
                           prefix, timeout_secs, prompt, extra_pnginfo)

    # -- read: detect / verify each connected modality --------------------------
    def _read(self, image, audio, video, timeout):
        prov = _provcheck_on_path()
        if not prov:
            print("[provcheck-comfyui] Provcheck(read): provcheck not on PATH; passing through.")
            return {"ui": {"images": []},
                    "result": (image, audio, video, "provcheck not installed", False)}
        reports, detected_any = [], False
        with tempfile.TemporaryDirectory(prefix="provcheck-read-") as td:
            tdp = Path(td)
            if image is not None:
                p = tdp / "frame.png"
                _tensor_to_png(image[0], p)
                det, s = self._read_file(prov, p, timeout)
                reports.append(f"image: {s}"); detected_any = detected_any or det
            if audio is not None:
                p = tdp / "clip.wav"
                if self._audio_to_wav(audio, p):
                    det, s = self._read_file(prov, p, timeout)
                    reports.append(f"audio: {s}"); detected_any = detected_any or det
            if video is not None:
                p = tdp / "vid.mp4"
                if self._video_to_mp4(video, p):
                    det, s = self._read_file(prov, p, timeout)
                    reports.append(f"video: {s}"); detected_any = detected_any or det
                else:
                    reports.append("video: could not materialise for read")
        report = "; ".join(reports) if reports else "nothing readable"
        print(f"[provcheck-comfyui] Provcheck(read): {report}")
        return {"ui": {"images": []}, "result": (image, audio, video, report, detected_any)}

    def _read_file(self, prov, path: Path, timeout) -> tuple[bool, str]:
        ok, out = _run_capture([prov, str(path), "--json"], timeout)
        det, _brand, _conf, summary = _first_detection(_parse_report(out))
        return det, summary

    # -- write: watermark and/or sign each connected modality -------------------
    def _write(self, image, audio, video, watermark, c2pa_sign, embed_identity,
               record_provenance, include_full, brand_id, prefix, timeout, prompt, extra_pnginfo):
        kit = _kit_on_path()
        if not kit:
            print("[provcheck-comfyui] Provcheck(write): provcheck-kit not on PATH; passing "
                  "through. Install: https://github.com/CreativeMayhemLtd/provcheck/releases/latest")
            return {"ui": {"images": []},
                    "result": (image, audio, video, "provcheck-kit not installed", False)}
        if not watermark and not c2pa_sign:
            return {"ui": {"images": []},
                    "result": (image, audio, video, "nothing to do (watermark + sign both off)", False)}

        manifest = _build_manifest(prompt, extra_pnginfo, bool(include_full)) if record_provenance else None
        out_dir, prefix, type_tag = _output_dir(prefix)
        out_dir.mkdir(parents=True, exist_ok=True)
        reports, ui_images = [], []
        out_image, out_audio, out_video = image, audio, video

        with tempfile.TemporaryDirectory(prefix="provcheck-write-") as td:
            tdp = Path(td)
            mpath = None
            if manifest is not None:
                mpath = tdp / "manifest.json"
                mpath.write_text(json.dumps(manifest), encoding="utf-8")

            if image is not None:
                out_image, r, ui = self._write_image(kit, image, watermark, c2pa_sign,
                                                      embed_identity, brand_id, mpath, timeout,
                                                      tdp, out_dir, prefix, type_tag)
                reports.append(f"image: {r}"); ui_images.extend(ui)
            if audio is not None:
                out_audio, r = self._write_audio(kit, audio, watermark, c2pa_sign,
                                                 embed_identity, brand_id, mpath, timeout,
                                                 tdp, out_dir, prefix)
                reports.append(f"audio: {r}")
            if video is not None:
                out_video, r = self._write_video(kit, video, watermark, c2pa_sign,
                                                 embed_identity, brand_id, mpath, timeout,
                                                 tdp, out_dir, prefix)
                reports.append(f"video: {r}")

        report = "; ".join(reports)
        print(f"[provcheck-comfyui] Provcheck(write): {report}. Files (if any) in {out_dir}. "
              "The signed FILE carries the manifest; passthrough outputs do not.")
        return {"ui": {"images": ui_images},
                "result": (out_image, out_audio, out_video, report, False)}

    def _write_image(self, kit, image, watermark, c2pa_sign, embed_identity, brand_id,
                     mpath, timeout, tdp, out_dir, prefix, type_tag):
        batch, out_frames, ui, ok_count = image.shape[0], [], [], 0
        for i in range(batch):
            persist = c2pa_sign
            src = tdp / f"img_src_{i:04d}.png"
            dst = (out_dir / f"{prefix}_{i:05d}.png") if persist else (tdp / f"img_out_{i:04d}.png")
            _tensor_to_png(image[i], src)
            ok, msg = self._two_step(kit, src, dst, brand_id, watermark, c2pa_sign,
                                     embed_identity, mpath, timeout)
            if ok and dst.exists():
                out_frames.append(_png_to_tensor(dst)); ok_count += 1
                if persist:
                    ui.append({"filename": dst.name, "subfolder": "", "type": type_tag})
            else:
                print(f"[provcheck-comfyui] image frame {i} failed ({msg}).")
                out_frames.append(image[i])
                if persist:
                    try:
                        dst.unlink(missing_ok=True)
                    except OSError:
                        pass
        r = (f"signed {ok_count}/{batch}" if c2pa_sign else f"watermarked {ok_count}/{batch}")
        return torch.stack(out_frames, 0), r, ui

    def _write_audio(self, kit, audio, watermark, c2pa_sign, embed_identity, brand_id,
                     mpath, timeout, tdp, out_dir, prefix):
        wf, sr = self._audio_fields(audio)
        if wf is None:
            return audio, "not a valid AUDIO input"
        if wf.ndim == 2:
            wf = wf.unsqueeze(0)
        batch, out_clips, ok_count = wf.shape[0], [], 0
        for i in range(batch):
            persist = c2pa_sign
            src = tdp / f"aud_src_{i:04d}.wav"
            dst = (out_dir / f"{prefix}_{i:05d}.wav") if persist else (tdp / f"aud_out_{i:04d}.wav")
            try:
                _waveform_to_wav(wf[i], sr, src)
            except Exception as e:  # noqa: BLE001
                print(f"[provcheck-comfyui] audio clip {i} serialise failed ({e}).")
                out_clips.append(wf[i]); continue
            ok, msg = self._two_step(kit, src, dst, brand_id, watermark, c2pa_sign,
                                     embed_identity, mpath, timeout)
            if ok and dst.exists():
                try:
                    arr, _ = _read_wav_any(dst)
                    out_clips.append(torch.from_numpy(arr)); ok_count += 1
                except Exception as e:  # noqa: BLE001
                    print(f"[provcheck-comfyui] audio clip {i} reload failed ({e}).")
                    out_clips.append(wf[i])
            else:
                print(f"[provcheck-comfyui] audio clip {i} failed ({msg}).")
                out_clips.append(wf[i])
        try:
            stacked = torch.stack(out_clips, 0)
        except RuntimeError:
            return audio, "post-process shape mismatch; returned original"
        r = (f"signed {ok_count}/{batch}" if c2pa_sign else f"watermarked {ok_count}/{batch}")
        return {"waveform": stacked, "sample_rate": sr}, r

    def _write_video(self, kit, video, watermark, c2pa_sign, embed_identity, brand_id,
                     mpath, timeout, tdp, out_dir, prefix):
        """Container-preserving: split audio via ComfyUI's video API, watermark it,
        recombine with the original frames, then C2PA-sign the container. We never
        hand the whole video to the kit (its audio watermarker would drop the video)."""
        try:
            VideoFromFile, VideoFromComponents, VideoComponents, VideoContainer = _load_video_libs()
        except Exception as e:  # noqa: BLE001
            print(f"[provcheck-comfyui] video: ComfyUI video API unavailable ({e}); passed through.")
            return video, "video API unavailable"
        try:
            comp = video.get_components()
        except Exception as e:  # noqa: BLE001
            return video, f"could not read video components ({e})"

        new_audio = comp.audio
        marked = False
        if watermark and comp.audio is not None:
            awf, asr = self._audio_fields(comp.audio)
            if awf is not None:
                wave2d = awf[0] if awf.ndim == 3 else awf
                src = tdp / "vtrack_in.wav"
                dst = tdp / "vtrack_wm.wav"
                try:
                    _waveform_to_wav(wave2d, asr, src)
                    ok, msg = _run([kit, "stamp", str(src), "-o", str(dst), "--brand-id",
                                    str(brand_id), "--overwrite", "--no-sign"], timeout)
                    if ok and dst.exists():
                        arr, _ = _read_wav_any(dst)
                        new_audio = {"waveform": torch.from_numpy(arr)[None, :, :], "sample_rate": asr}
                        marked = True
                    else:
                        print(f"[provcheck-comfyui] video audio watermark failed ({msg}).")
                except Exception as e:  # noqa: BLE001
                    print(f"[provcheck-comfyui] video audio watermark error ({e}).")

        out_path = out_dir / f"{prefix}_video.mp4"
        try:
            rebuilt = VideoFromComponents(VideoComponents(
                images=comp.images, frame_rate=comp.frame_rate, audio=new_audio,
                metadata=getattr(comp, "metadata", None)))
            rebuilt.save_to(str(out_path), format=VideoContainer.MP4)
        except Exception as e:  # noqa: BLE001
            return video, f"video rebuild failed ({e})"

        signed = False
        if c2pa_sign:
            argv = [kit, "sign", str(out_path)]
            if mpath is not None:
                argv += ["--manifest", str(mpath)]
            if embed_identity:
                argv.append("--embed-identity")
            ok, msg = _run(argv, timeout)
            signed = ok
            if not ok:
                print(f"[provcheck-comfyui] video sign failed ({msg}); left watermarked/unsigned.")
        r = ("signed" if signed else "watermarked" if marked else "rebuilt (no mark)")
        if marked:
            r += " + audio mark"
        return VideoFromFile(str(out_path)), r

    # -- shared kit two-step + serialisers --------------------------------------
    def _two_step(self, kit, src: Path, final: Path, brand_id, watermark, c2pa_sign,
                  embed_identity, mpath, timeout) -> tuple[bool, str]:
        """Watermark ``src`` into ``final`` then C2PA-sign ``final`` in place.

        The watermark step MUST use distinct input/output paths — the kit fails when
        asked to stamp a file onto itself (it reads the input while opening the same
        path for output). Signing IS safe in place (it does its own temp-rename).
        ``src`` and ``final`` must differ.
        """
        ok, msg = True, "ok"
        if watermark:
            ok, msg = _run([kit, "stamp", str(src), "-o", str(final), "--brand-id",
                            str(brand_id), "--overwrite", "--no-sign"], timeout)
        else:
            try:
                shutil.copyfile(src, final)
            except OSError as e:
                return False, f"copy failed ({e})"
        if ok and c2pa_sign:
            argv = [kit, "sign", str(final)]
            if mpath is not None:
                argv += ["--manifest", str(mpath)]
            if embed_identity:
                argv.append("--embed-identity")
            ok, msg = _run(argv, timeout)
        return ok, msg

    @staticmethod
    def _audio_fields(audio):
        if not isinstance(audio, dict):
            return None, DEFAULT_SAMPLE_RATE
        wf = audio.get("waveform")
        sr = int(audio.get("sample_rate", DEFAULT_SAMPLE_RATE))
        if wf is None or not hasattr(wf, "shape"):
            return None, sr
        return wf, sr

    def _audio_to_wav(self, audio, path: Path) -> bool:
        wf, sr = self._audio_fields(audio)
        if wf is None:
            return False
        if wf.ndim == 3:
            wf = wf[0]
        try:
            _waveform_to_wav(wf, sr, path)
            return True
        except Exception:  # noqa: BLE001
            return False

    def _video_to_mp4(self, video, path: Path) -> bool:
        """Materialise a VIDEO to an mp4 for reading. provcheck detects the audio-track
        watermark directly on the container (reading the extracted audio track loses it)."""
        try:
            _VFF, _VFC, _VC, VideoContainer = _load_video_libs()
            video.save_to(str(path), format=VideoContainer.MP4)
            return path.exists()
        except Exception as e:  # noqa: BLE001
            print(f"[provcheck-comfyui] video read materialise failed ({e}).")
            return False
