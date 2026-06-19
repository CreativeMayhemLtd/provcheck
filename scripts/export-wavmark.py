"""Export WavMark's encoder + decoder to ONNX for use by
provcheck-wavmark's Rust pipeline.

What this produces
------------------
- crates/provcheck-wavmark/models/wavmark-encoder.onnx
- crates/provcheck-wavmark/models/wavmark-decoder.onnx
- crates/provcheck-wavmark/models/wavmark.meta.json

What each ONNX does
-------------------
**Encoder** — `wavmark-encoder.onnx`
  Inputs:
    signal  : [1, 16000] float32 — 1 second of 16 kHz mono PCM
    message : [1, 32]    float32 — 32-bit message (0.0 / 1.0 floats)
  Output:
    marked  : [1, 16000] float32 — watermarked audio (replaces signal)

**Decoder** — `wavmark-decoder.onnx`
  Inputs:
    signal  : [1, 16000] float32 — candidate watermarked PCM
  Output:
    message : [1, 32] float32 — per-bit logits in [-1.0, +1.0];
                                 threshold at 0.0 (>= 0.5 in WavMark
                                 python; >= 0.0 here since logits are
                                 the pre-threshold values)

For the Rust side:
  - Decode + resample input to 16 kHz mono.
  - Detection: slide a 16000-sample window at 50 ms steps; on each
    window run the decoder ONNX → 32 bits; accept the window iff
    bits 0..16 exactly match WavMark's hardcoded fixed pattern;
    aggregate the lower-16 custom payload across exact-match
    windows by averaging then thresholding at 0.5.
  - Embedding: split audio into 16 000-sample chunks; for each
    chunk run the encoder ONNX with our 32-bit message
    (fix_pattern || ECC-encoded brand ID); concatenate.
  - Both ONNXes have FIXED input shape — no dynamic-axis exposure,
    so tract 0.21's symbolic Pad issue (seen in AudioSeal) doesn't
    apply here.

Run:
  pip install wavmark
  python scripts/export-wavmark.py
"""

import os
os.environ["NO_TORCH_COMPILE"] = "1"

import json
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
import logging
logging.getLogger("pydub").setLevel(logging.ERROR)

import numpy as np
import torch

import wavmark
from wavmark.utils.wm_add_util import fix_pattern as WAVMARK_FIX_PATTERN


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
OUT_DIR = REPO_ROOT / "crates" / "provcheck-wavmark" / "models"
ENCODER_PATH = OUT_DIR / "wavmark-encoder.onnx"
DECODER_PATH = OUT_DIR / "wavmark-decoder.onnx"
META_PATH = OUT_DIR / "wavmark.meta.json"

SAMPLE_RATE = 16_000
CHUNK_SAMPLES = 16_000  # WavMark Model.__init__ num_point
NUM_BIT = 32
FIX_PATTERN_LENGTH = 16
N_FFT = 1000
HOP_LENGTH = 400


class HinetForwardONNX(torch.nn.Module):
    """Forward (encode) pass of WavMark's HiNet — invertible neural
    network that mixes the cover signal with the watermark in STFT
    space.

    PyTorch's onnx exporter can't trace torch.stft with
    `return_complex=True` (the symbolic op rejects complex types in
    opset 17). WavMark uses `return_complex=True` + `view_as_real`
    so the STFT step has to live in Rust. We export only the HiNet
    block — STFT, iSTFT, and the two Linear projections (watermark_fc
    and watermark_fc_back) all run on the Rust side, with the linear
    weights shipped as sidecar binary blobs.

    Input layout (matches what Model.enc_dec computes after
    `permute(0, 3, 2, 1)`):
        signal_fft, watermark_fft : [1, 2, t_frames=41, freq_bins=501]
                                    (real, imag) channels first.

    Output: same shape; (signal_wmd_fft, msg_remain_fft).
    """

    def __init__(self, wm_model):
        super().__init__()
        self.hinet = wm_model.hinet

    def forward(self, signal_fft_pcfb, watermark_fft_pcfb):
        # _pcfb = permuted (b, 2, t_frames, freq_bins) layout
        signal2, watermark2 = self.hinet(signal_fft_pcfb, watermark_fft_pcfb, rev=False)
        return signal2, watermark2


class HinetReverseONNX(torch.nn.Module):
    """Reverse (decode) pass of WavMark's HiNet. Same I/O shape as
    forward; the rev=True flag inverts the coupling layers."""

    def __init__(self, wm_model):
        super().__init__()
        self.hinet = wm_model.hinet

    def forward(self, signal_fft_pcfb, watermark_fft_pcfb):
        signal2, watermark2 = self.hinet(signal_fft_pcfb, watermark_fft_pcfb, rev=True)
        return signal2, watermark2


def main():
    print("[export] loading WavMark model...")
    wm = wavmark.load_model()
    wm.eval()

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # ---- compute the STFT shape once ----
    # WavMark uses torch.stft with center=True, returning a complex tensor
    # of shape (batch, n_fft//2+1, t_frames). view_as_real → (batch, n_fft//2+1, t_frames, 2)
    # then permute(0, 3, 2, 1) → (batch, 2, t_frames, n_fft//2+1).
    freq_bins = N_FFT // 2 + 1
    signal_dummy = torch.randn(1, CHUNK_SAMPLES)
    with torch.no_grad():
        fft_dummy = wm.stft(signal_dummy)  # (1, freq_bins, t_frames, 2)
    t_frames = fft_dummy.shape[2]
    print(f"  STFT shape: (1, {freq_bins=}, {t_frames=}, 2)")

    # The HiNet ONNXes operate on the permuted layout:
    fft_perm_dummy = fft_dummy.permute(0, 3, 2, 1)
    print(f"  HiNet input shape (post-permute): {tuple(fft_perm_dummy.shape)}")

    # ---- decoder (HiNet reverse pass) ----
    print()
    print("[export] tracing + exporting hinet-reverse (decoder INN pass)...")
    rev = HinetReverseONNX(wm)
    rev.eval()

    with torch.no_grad():
        sig_out, wm_out = rev(fft_perm_dummy, fft_perm_dummy)
    print(f"  PyTorch reverse outputs: {tuple(sig_out.shape)}, {tuple(wm_out.shape)}")

    torch.onnx.export(
        rev,
        (fft_perm_dummy, fft_perm_dummy),
        str(DECODER_PATH),
        input_names=["signal_fft", "watermark_fft"],
        output_names=["signal_out", "watermark_out"],
        opset_version=17,
        do_constant_folding=True,
    )
    print(f"  wrote {DECODER_PATH.name} ({DECODER_PATH.stat().st_size / 1e6:.1f} MB)")

    import onnxruntime as ort
    sess = ort.InferenceSession(str(DECODER_PATH), providers=["CPUExecutionProvider"])
    onnx_out = sess.run(
        None,
        {"signal_fft": fft_perm_dummy.numpy(), "watermark_fft": fft_perm_dummy.numpy()},
    )
    diff_s = np.abs(onnx_out[0] - sig_out.numpy()).max()
    diff_w = np.abs(onnx_out[1] - wm_out.numpy()).max()
    print(f"  round-trip L∞: signal={diff_s:.4e}, watermark={diff_w:.4e}")
    assert diff_s < 1e-3 and diff_w < 1e-3, f"reverse divergence too large"

    # ---- encoder (HiNet forward pass) ----
    print()
    print("[export] tracing + exporting hinet-forward (encoder INN pass)...")
    fwd = HinetForwardONNX(wm)
    fwd.eval()

    msg_dummy = torch.randint(0, 2, (1, NUM_BIT), dtype=torch.float32)
    with torch.no_grad():
        # message → watermark_fc → message_expand → stft → message_fft (permuted)
        message_expand = wm.watermark_fc(msg_dummy)  # (1, 16000)
        message_fft = wm.stft(message_expand)  # (1, freq_bins, t_frames, 2)
        message_fft_perm = message_fft.permute(0, 3, 2, 1)

    with torch.no_grad():
        sig_out, msg_remain = fwd(fft_perm_dummy, message_fft_perm)
    print(f"  PyTorch forward outputs: {tuple(sig_out.shape)}, {tuple(msg_remain.shape)}")

    torch.onnx.export(
        fwd,
        (fft_perm_dummy, message_fft_perm),
        str(ENCODER_PATH),
        input_names=["signal_fft", "message_fft"],
        output_names=["signal_marked_fft", "msg_remain_fft"],
        opset_version=17,
        do_constant_folding=True,
    )
    print(f"  wrote {ENCODER_PATH.name} ({ENCODER_PATH.stat().st_size / 1e6:.1f} MB)")

    sess = ort.InferenceSession(str(ENCODER_PATH), providers=["CPUExecutionProvider"])
    onnx_out = sess.run(
        None,
        {"signal_fft": fft_perm_dummy.numpy(), "message_fft": message_fft_perm.numpy()},
    )
    diff_s = np.abs(onnx_out[0] - sig_out.numpy()).max()
    diff_m = np.abs(onnx_out[1] - msg_remain.numpy()).max()
    print(f"  round-trip L∞: signal_marked={diff_s:.4e}, msg_remain={diff_m:.4e}")
    assert diff_s < 1e-3 and diff_m < 1e-3, f"forward divergence too large"

    # ---- linear weights (sidecar binary blobs) ----
    print()
    print("[export] dumping watermark_fc + watermark_fc_back as binary sidecars...")
    fc_w_path = OUT_DIR / "wavmark-watermark_fc.weights.bin"
    fc_b_path = OUT_DIR / "wavmark-watermark_fc.bias.bin"
    fcb_w_path = OUT_DIR / "wavmark-watermark_fc_back.weights.bin"
    fcb_b_path = OUT_DIR / "wavmark-watermark_fc_back.bias.bin"

    # watermark_fc: Linear(32, 16000) — weight (16000, 32), bias (16000,)
    fc_w = wm.watermark_fc.weight.detach().cpu().numpy().astype(np.float32)
    fc_b = wm.watermark_fc.bias.detach().cpu().numpy().astype(np.float32)
    assert fc_w.shape == (CHUNK_SAMPLES, NUM_BIT)
    assert fc_b.shape == (CHUNK_SAMPLES,)
    fc_w_path.write_bytes(fc_w.tobytes())
    fc_b_path.write_bytes(fc_b.tobytes())
    print(
        f"  watermark_fc: weights {fc_w_path.name} ({fc_w_path.stat().st_size} bytes), "
        f"bias {fc_b_path.name} ({fc_b_path.stat().st_size} bytes)"
    )

    # watermark_fc_back: Linear(16000, 32) — weight (32, 16000), bias (32,)
    fcb_w = wm.watermark_fc_back.weight.detach().cpu().numpy().astype(np.float32)
    fcb_b = wm.watermark_fc_back.bias.detach().cpu().numpy().astype(np.float32)
    assert fcb_w.shape == (NUM_BIT, CHUNK_SAMPLES)
    assert fcb_b.shape == (NUM_BIT,)
    fcb_w_path.write_bytes(fcb_w.tobytes())
    fcb_b_path.write_bytes(fcb_b.tobytes())
    print(
        f"  watermark_fc_back: weights {fcb_w_path.name} ({fcb_w_path.stat().st_size} bytes), "
        f"bias {fcb_b_path.name} ({fcb_b_path.stat().st_size} bytes)"
    )

    # ---- metadata ----
    meta = {
        "family": "wavmark",
        "version": "32bits",
        "sample_rate": SAMPLE_RATE,
        "chunk_samples": CHUNK_SAMPLES,
        "num_bits": NUM_BIT,
        "fix_pattern_length": FIX_PATTERN_LENGTH,
        "fix_pattern": [int(b) for b in WAVMARK_FIX_PATTERN[:FIX_PATTERN_LENGTH]],
        "payload_bits_offset": FIX_PATTERN_LENGTH,
        "payload_bits_count": NUM_BIT - FIX_PATTERN_LENGTH,
        "n_fft": N_FFT,
        "hop_length": HOP_LENGTH,
        "freq_bins": freq_bins,
        "t_frames": t_frames,
        "license": "MIT",
        "model_source": "M4869/WavMark (Hugging Face)",
        "checkpoint": "step59000_snr39.99_pesq4.35_BERP_none0.30_mean1.81_std1.81.model.pkl",
    }
    META_PATH.write_text(json.dumps(meta, indent=2))
    print()
    print(f"[export] wrote {META_PATH.name}")
    print()
    print("EXPORT METADATA:")
    for k, v in meta.items():
        if isinstance(v, list) and len(v) > 8:
            print(f"  {k:24}  {v[:8]}...")
        else:
            print(f"  {k:24}  {v}")


if __name__ == "__main__":
    sys.exit(main() or 0)
