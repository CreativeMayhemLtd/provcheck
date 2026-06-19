"""Export AudioSeal's generator + detector to ONNX for use by
provcheck-audioseal's Rust pipeline.

What this produces
------------------
- crates/provcheck-audioseal/models/audioseal-detector.onnx  (~33 MB)
- crates/provcheck-audioseal/models/audioseal-generator.onnx (~56 MB)
- crates/provcheck-audioseal/models/audioseal.meta.json (model card +
  shape/sample-rate metadata for the Rust side)

What each ONNX does
-------------------
**Detector** — `audioseal-detector.onnx`
  Inputs:
    x : [1, 1, samples] float32 — raw 16 kHz mono PCM
  Outputs:
    result  : [1, 2, samples] float32 — softmax(present/absent) per sample
    message : [1, 16]        float32 — mean bit logits (sigmoid → bit probs)

**Generator** — `audioseal-generator.onnx`
  Inputs:
    x   : [1, 1, samples] float32 — raw 16 kHz mono PCM
    msg : [1, 16]         int64   — binary message {0, 1}
  Output:
    watermark : [1, 1, samples] float32 — watermark signal (add to x with alpha)

The Rust side does:
  - decode + resample to 16 kHz
  - (detect) chunked tract inference, scatter probs, aggregate
  - (embed) whole-file tract inference, marked = x + alpha * watermark
  - resample back to source SR if needed
  - write WAV (for embed)

The whole-file embed is required because chunking the generator produces
audible discontinuities at chunk boundaries (per L∞ test in survey:
boundary 0.044 vs interior 0.0045, 10x gap). Detector chunking is safe
(boundary 0.001 vs interior 0.00002, both tiny).

Run:
  pip install audioseal
  python scripts/export-audioseal.py
"""

import json
import os
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")

# Disable torch.compile — Python 3.12 doesn't support it, and we
# don't need it for export.
os.environ["NO_TORCH_COMPILE"] = "1"

import logging
logging.getLogger("pydub").setLevel(logging.ERROR)

import numpy as np
import torch
from audioseal import AudioSeal


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
OUT_DIR = REPO_ROOT / "crates" / "provcheck-audioseal" / "models"
DETECTOR_PATH = OUT_DIR / "audioseal-detector.onnx"
GENERATOR_PATH = OUT_DIR / "audioseal-generator.onnx"
META_PATH = OUT_DIR / "audioseal.meta.json"


# --- detector wrapper: trace-friendly forward ----------------------

class DetectorONNX(torch.nn.Module):
    """Wraps AudioSealDetector.forward for ONNX export. The model's
    own forward() does:
        result = self.detector(x)             # (b, 2+nbits, samples)
        result[:, :2, :] = softmax(result[:, :2, :], dim=1)
        message = sigmoid(result[:, 2:, :].mean(dim=-1))
        return result[:, :2, :], message

    We inline that to avoid in-place slice assignment (which tract
    can't analyse — same lesson as the silentcipher CarrierDecoder
    band-zero patch we already shipped)."""

    def __init__(self, detector):
        super().__init__()
        self.backbone = detector.detector  # Sequential[encoder, last_conv]

    def forward(self, x):
        # x: (1, 1, samples)
        raw = self.backbone(x)                       # (1, 2+nbits, samples)
        # split into the two heads instead of in-place mutation
        presence = torch.softmax(raw[:, :2, :], dim=1)        # (1, 2, samples)
        bits_raw = raw[:, 2:, :]                              # (1, nbits, samples)
        message = torch.sigmoid(bits_raw.mean(dim=-1))        # (1, nbits)
        return presence, message


# --- generator wrapper: trace-friendly forward ---------------------

class GeneratorONNX(torch.nn.Module):
    """Wraps AudioSealWM.get_watermark for ONNX export. Returns the
    watermark signal so the Rust side can `marked = x + alpha *
    watermark` outside the ONNX (skips alpha as an ONNX input — it's
    a scalar the caller controls).

    Skips the optional NormalizationProcessor (it's None on the 16-bit
    config and uses fold/unfold ops tract doesn't handle anyway)."""

    def __init__(self, generator):
        super().__init__()
        self.encoder = generator.encoder
        self.msg_processor = generator.msg_processor
        self.decoder = generator.decoder

    def forward(self, x, msg):
        # x:   (1, 1, samples) float32
        # msg: (1, nbits)       int64 of 0/1
        length = x.size(-1)
        hidden = self.encoder(x)                                # (1, dim, frames)
        # MsgProcessor expects int message; the Embedding lookup needs int64
        hidden = self.msg_processor(hidden, msg.long())
        watermark = self.decoder(hidden)[..., :length]
        return watermark


def main():
    print("[export] loading AudioSeal 16-bit detector + generator (cpu)...")
    det = AudioSeal.load_detector("audioseal_detector_16bits")
    gen = AudioSeal.load_generator("audioseal_wm_16bits")
    det.eval()
    gen.eval()

    SAMPLE_RATE = 16_000
    NBITS = 16
    # Fixed input size baked into the ONNX. tract 0.21 can't resolve
    # the symbolic Pad expression that pytorch's onnx exporter produces
    # for dynamic-length SEANet inputs ("Undetermined symbol in
    # expression: 16003 + -1*<Sym0>"). Fixing the input length to a
    # specific multiple of the encoder hop_length sidesteps that. The
    # Rust side chunks audio to fit; 10 seconds keeps chunks short
    # enough that embed-side LSTM boundary artifacts can be hidden
    # behind a small crossfade.
    CHUNK_SECONDS = 10
    T_FIXED = SAMPLE_RATE * CHUNK_SECONDS  # 160_000
    T_DUMMY = T_FIXED

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # ---- detector export ----
    print()
    print("[export] tracing + exporting detector...")
    dwrap = DetectorONNX(det)
    dwrap.eval()
    x_dummy = torch.randn(1, 1, T_DUMMY)

    with torch.no_grad():
        out_presence, out_msg = dwrap(x_dummy)
    print(
        f"  PyTorch detector output: presence={tuple(out_presence.shape)} "
        f"msg={tuple(out_msg.shape)}"
    )

    # NOTE: no dynamic_axes — tract 0.21's symbolic engine chokes on
    # the resulting Pad expression. Fixed-shape it is; caller chunks.
    torch.onnx.export(
        dwrap,
        (x_dummy,),
        str(DETECTOR_PATH),
        input_names=["x"],
        output_names=["presence", "message"],
        opset_version=13,
        do_constant_folding=True,
    )
    size_mb = DETECTOR_PATH.stat().st_size / (1024 * 1024)
    print(f"  wrote {DETECTOR_PATH.name} ({size_mb:.1f} MB)")

    # Round-trip verify detector
    import onnxruntime as ort
    sess = ort.InferenceSession(str(DETECTOR_PATH), providers=["CPUExecutionProvider"])
    onnx_out = sess.run(None, {"x": x_dummy.numpy()})
    diff_p = np.abs(onnx_out[0] - out_presence.numpy()).max()
    diff_m = np.abs(onnx_out[1] - out_msg.numpy()).max()
    print(f"  round-trip: presence L∞={diff_p:.4e}  message L∞={diff_m:.4e}")
    assert diff_p < 1e-3 and diff_m < 1e-3, f"detector divergence too large"

    # ---- generator export ----
    print()
    print("[export] tracing + exporting generator...")
    gwrap = GeneratorONNX(gen)
    gwrap.eval()
    msg_dummy = torch.randint(0, 2, (1, NBITS), dtype=torch.int64)

    with torch.no_grad():
        out_wm = gwrap(x_dummy, msg_dummy)
    print(f"  PyTorch generator output: watermark={tuple(out_wm.shape)}")

    # Same fixed-shape rationale as detector above.
    torch.onnx.export(
        gwrap,
        (x_dummy, msg_dummy),
        str(GENERATOR_PATH),
        input_names=["x", "msg"],
        output_names=["watermark"],
        opset_version=13,
        do_constant_folding=True,
    )
    size_mb = GENERATOR_PATH.stat().st_size / (1024 * 1024)
    print(f"  wrote {GENERATOR_PATH.name} ({size_mb:.1f} MB)")

    # Round-trip verify generator
    sess = ort.InferenceSession(str(GENERATOR_PATH), providers=["CPUExecutionProvider"])
    onnx_out = sess.run(None, {"x": x_dummy.numpy(), "msg": msg_dummy.numpy()})
    diff = np.abs(onnx_out[0] - out_wm.numpy()).max()
    print(f"  round-trip: watermark L∞={diff:.4e}")
    assert diff < 1e-3, f"generator divergence too large: {diff}"

    # ---- metadata ----
    meta = {
        "family": "audioseal",
        "version": "16bits",
        "sample_rate": SAMPLE_RATE,
        "nbits": NBITS,
        "input_channels": 1,
        "input_samples": T_FIXED,
        "chunk_seconds": CHUNK_SECONDS,
        "hop_length": int(gen.encoder.hop_length),
        "latent_dim": int(gen.encoder.dimension),
        "detector_output_dim": 32,
        "license": "MIT",
        "model_source": "facebook/audioseal (Hugging Face)",
        "detector_url": "https://huggingface.co/facebook/audioseal/resolve/main/detector_base.pth",
        "generator_url": "https://huggingface.co/facebook/audioseal/resolve/main/generator_base.pth",
    }
    META_PATH.write_text(json.dumps(meta, indent=2))
    print()
    print(f"[export] wrote {META_PATH.name}")
    print()
    print("EXPORT METADATA:")
    for k, v in meta.items():
        print(f"  {k:24}  {v}")


if __name__ == "__main__":
    sys.exit(main() or 0)
