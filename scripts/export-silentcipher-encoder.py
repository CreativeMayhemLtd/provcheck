"""Export silentcipher's encode pipeline (encoder + carrier_decoder + fusion)
as a single ONNX model for use by provcheck-watermark's Rust embedding path.

What this script produces
-------------------------
- crates/provcheck-watermark/models/silentcipher-encoder.onnx  (~10 MB)

What the ONNX model does
------------------------
Inputs (3):
  carrier_mag      : [1, 1, FREQ_BINS=2049, T] float32 — STFT magnitude (after VCTK rescale)
  msg_enc_padded   : [1, 1, FREQ_BINS=2049, T] float32 — the OUTPUT of
                     `enc_c.transform_message` already applied + the trailing
                     1025 freq bins zero-padded. Rust computes this directly
                     from letters_encoding + the linear weight (which we
                     also dump alongside) — see silentcipher-encoder.meta.json
                     for the weight + bias paths.
  message_sdr      : scalar float32 — target message SDR in dB (config default)

Output (1):
  message_info_raw : [1, 1, 2049, T] float32 — dec_c output, BEFORE encode_wav's
                     utterance-level normalization scaling + negate + relu

Internal graph (matches silentcipher's encode_wav lines 308-318):
  carrier_enc      = enc_c(carrier_mag)                                    # 32 channels
  msg_enc'         = enc_c.transform_message(msg_enc)                       # 32 channels
  merged_enc       = cat(carrier_enc, carrier_mag×32, msg_enc'×32, dim=1)   # 96 channels
  message_info_raw = dec_c(merged_enc, message_sdr)                         # 1 channel

Rust takes message_info_raw and finishes the embedding pipeline (mirrors
encode_wav lines 319-326 + 337):
  - utterance_level_normalization: scale by sqrt(mean(carrier_mag^2) over freq+time)
    NOTE: must be computed from the FULL carrier before any chunking — that's why
    this step is in Rust, not the ONNX.
  - ensure_negative_message: message_info = -message_info
  - carrier_reconst = relu(message_info + carrier_mag)
  - iSTFT(carrier_reconst, carrier_phase) → waveform

Pre/post processing stays in Rust:
  - Audio decode + resample to 44.1kHz
  - VCTK rescale
  - STFT (forward, get magnitude + phase)
  - letters_encoding (5 bytes → one-hot tile tensor)  ← port to Rust
  - utterance-level normalization scalar + negate + relu  ← post-ONNX
  - inverse STFT (overlap-add)                        ← port to Rust
  - VCTK de-rescale
  - Audio encode + resample back

Run:
  pip install silentcipher
  python scripts/export-silentcipher-encoder.py
"""

import os
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")

import numpy as np
import torch

# Suppress pydub's ffmpeg warning — we don't need ffmpeg for export
import logging
logging.getLogger("pydub").setLevel(logging.ERROR)

import silentcipher


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
OUT_PATH = REPO_ROOT / "crates" / "provcheck-watermark" / "models" / "silentcipher-encoder.onnx"


class EncodePipeline(torch.nn.Module):
    """Wraps the heavy enc_c + dec_c compute into a single forward()
    that can be traced for ONNX export.

    Doesn't include `enc_c.transform_message` — that step has an
    `F.pad` that tract 0.21 can't analyse (the pad-amount depends on
    a constant the optimiser can't trace through cleanly). Caller
    must do the linear projection + zero-pad in Rust before feeding
    `msg_enc_padded` into the ONNX. The weight + bias for that
    linear are dumped to a sidecar .npz so the Rust port is exact.

    Output is the raw dec_c output, BEFORE encode_wav's utterance-
    level normalisation + negate + relu — those happen in Rust
    because utterance-level normalisation needs the full
    (un-chunked) carrier to compute its scalar."""

    def __init__(self, model):
        super().__init__()
        self.enc_c = model.enc_c
        # We don't call dec_c.forward directly — its slice-assignment
        # to zero out high freq bins (`h[:, :, message_band_size:, :] = 0`)
        # traces to a Concat that tract 0.21 can't analyse. We inline
        # dec_c's logic in forward() using a multiplicative mask.
        self.dec_c_main = model.dec_c.main
        self.dec_c_no_normalization = bool(model.config.no_normalization)
        # Pre-baked band mask: ones over the first MESSAGE_BAND_SIZE freq
        # bins, zeros over the rest. Replaces the slice assignment in
        # dec_c.forward.
        FREQ_BINS = model.config.N_FFT // 2 + 1
        MESSAGE_BAND_SIZE = model.config.message_band_size
        band_mask = torch.cat(
            [
                torch.ones(MESSAGE_BAND_SIZE),
                torch.zeros(FREQ_BINS - MESSAGE_BAND_SIZE),
            ]
        ).view(1, 1, FREQ_BINS, 1)
        self.register_buffer("band_mask", band_mask)
        # Bake the relevant config invariants in as assertions so a
        # future model checkpoint with different flags fails loudly
        # at export time rather than silently producing a model with
        # the wrong post-processing math on the Rust side.
        assert not model.config.frame_level_normalization, (
            "this export assumes frame_level_normalization=False (prod 44.1k config)"
        )
        assert model.config.utterance_level_normalization, (
            "this export assumes utterance_level_normalization=True (prod 44.1k config)"
        )
        assert model.config.ensure_negative_message, (
            "this export assumes ensure_negative_message=True (prod 44.1k config)"
        )

    def forward(self, carrier, msg_enc_padded, message_sdr):
        # carrier: [1, 1, 2049, T]
        # msg_enc_padded: [1, 1, 2049, T] — already transformed + padded in Rust
        # message_sdr: scalar
        carrier_enc = self.enc_c(carrier)                     # [1, 32, 2049, T]
        merged_enc = torch.cat(
            (
                carrier_enc,
                carrier.repeat(1, 32, 1, 1),
                msg_enc_padded.repeat(1, 32, 1, 1),
            ),
            dim=1,
        )                                                     # [1, 96, 2049, T]

        # Inlined dec_c.forward (model.py:54-67). The slice-assignment
        # `h[:, :, message_band_size:, :] = 0` is replaced with a
        # multiplicative mask to keep tract happy.
        h = self.dec_c_main(merged_enc)
        h = torch.abs(h)                                       # ensure_negative_message
        h = h * self.band_mask                                 # zero out high bins
        if not self.dec_c_no_normalization:
            h = h / (torch.mean(h * h, dim=2, keepdim=True) ** 0.5) / (10.0 ** (message_sdr / 20.0))
        return h


def find_silentcipher_44k_cache():
    """Locate the silentcipher 44.1k snapshot in HuggingFace's hub
    cache. silentcipher.get_model() has hardcoded relative paths
    that don't work outside the package's source-tree; we point at
    the cache directly. Returns (ckpt_dir, config_path) or raises
    FileNotFoundError with a helpful message."""
    candidates = [
        Path.home() / ".cache" / "huggingface" / "hub" / "models--sony--silentcipher",
        Path(os.environ.get("HF_HOME", "")) / "hub" / "models--sony--silentcipher" if os.environ.get("HF_HOME") else None,
    ]
    candidates = [c for c in candidates if c is not None]
    for base in candidates:
        if not base.exists():
            continue
        snaps = list((base / "snapshots").glob("*/44_1_khz/73999_iteration"))
        if snaps:
            ckpt_dir = snaps[0]
            return str(ckpt_dir), str(ckpt_dir / "hparams.yaml")
    raise FileNotFoundError(
        "couldn't find silentcipher 44.1k weights in HF cache. "
        "Tried: " + ", ".join(str(c) for c in candidates) + ". "
        "Try `python -c 'from huggingface_hub import snapshot_download; snapshot_download(\"sony/silentcipher\")'`"
    )


def main():
    print(f"[export] locating silentcipher 44.1k weights...")
    ckpt_dir, config_path = find_silentcipher_44k_cache()
    print(f"[export] ckpt dir: {ckpt_dir}")
    print(f"[export] loading silentcipher (44.1k, cpu)...")
    model = silentcipher.get_model(
        model_type="44.1k",
        ckpt_path=ckpt_dir,
        config_path=config_path,
        device="cpu",
    )
    model.enc_c.eval()
    model.dec_c.eval()

    pipeline = EncodePipeline(model)
    pipeline.eval()

    # Synthetic input shapes. T_DUMMY just gives the tracer concrete
    # numbers; dynamic_axes below mark the time axis (and batch) as
    # variable so the exported ONNX accepts any audio length.
    FREQ_BINS = 2049
    MESSAGE_DIM = 5
    MESSAGE_BAND_SIZE = 1024
    T_DUMMY = 256

    carrier = torch.randn(1, 1, FREQ_BINS, T_DUMMY).abs()  # magnitudes are non-negative
    # ONNX expects msg_enc_padded — the output of transform_message
    # AFTER linear projection + zero-padding to FREQ_BINS. Use the
    # real Python implementation to produce it so the dummy matches
    # what Rust will produce at run time.
    msg_enc_pre = torch.zeros(1, 1, MESSAGE_DIM, T_DUMMY)
    msg_enc_pre[:, :, 0, :] = 1.0
    with torch.no_grad():
        msg_enc_padded = model.enc_c.transform_message(msg_enc_pre)
    assert msg_enc_padded.shape == (1, 1, FREQ_BINS, T_DUMMY), \
        f"unexpected transform_message output shape: {msg_enc_padded.shape}"
    message_sdr = torch.tensor(model.config.message_sdr, dtype=torch.float32)

    # Sanity check pre-export.
    print(f"[export] sanity-checking forward pass...")
    with torch.no_grad():
        out = pipeline(carrier, msg_enc_padded, message_sdr)
    assert out.shape == (1, 1, FREQ_BINS, T_DUMMY), f"unexpected output shape: {out.shape}"
    # message_info_raw is dec_c's output, which is abs'd internally
    # by dec_c when ensure_negative_message=True (model.py:60-61),
    # so it's non-negative coming out of ONNX. Rust negates it later.
    assert torch.all(out >= 0), "dec_c output should be non-negative (abs internal)"
    print(f"[export] forward pass OK — output shape {tuple(out.shape)}, range [{out.min().item():.4f}, {out.max().item():.4f}]")

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    print(f"[export] writing ONNX to {OUT_PATH}...")
    torch.onnx.export(
        pipeline,
        (carrier, msg_enc_padded, message_sdr),
        str(OUT_PATH),
        input_names=["carrier_mag", "msg_enc_padded", "message_sdr"],
        output_names=["message_info_raw"],
        dynamic_axes={
            "carrier_mag": {3: "t_frames"},
            "msg_enc_padded": {3: "t_frames"},
            "message_info_raw": {3: "t_frames"},
        },
        opset_version=17,
        do_constant_folding=True,
    )
    size_mb = OUT_PATH.stat().st_size / (1024 * 1024)
    print(f"[export] wrote {OUT_PATH.name} ({size_mb:.1f} MB)")

    # Round-trip verify via onnxruntime: compare exported ONNX
    # against the original PyTorch pipeline on the same random input.
    print(f"[export] round-trip verifying via onnxruntime...")
    import onnxruntime as ort
    sess = ort.InferenceSession(str(OUT_PATH), providers=["CPUExecutionProvider"])
    onnx_out = sess.run(
        None,
        {
            "carrier_mag": carrier.numpy(),
            "msg_enc_padded": msg_enc_padded.numpy(),
            "message_sdr": message_sdr.numpy(),
        },
    )[0]
    torch_out = out.numpy()
    abs_diff = np.abs(onnx_out - torch_out)
    print(f"[export] L∞={abs_diff.max():.4e}  RMS={np.sqrt(np.mean(abs_diff**2)):.4e}")
    assert abs_diff.max() < 1e-3, f"ONNX output diverges from PyTorch: L∞={abs_diff.max()}"
    print(f"[export] round-trip OK")

    # Also export a tiny metadata JSON for the Rust side.
    import json
    # Note: silentcipher's STFT class names the same attribute as
    # both `hop_length` (constructor arg) and `hop_len` (instance attr).
    # Use the instance attrs that actually exist on the loaded model.
    meta = {
        "model_type": "44.1k",
        "sample_rate": int(model.sr),
        "n_fft": int(model.stft.filter_length),
        "hop_length": int(model.stft.hop_len),
        "win_length": int(model.stft.win_len),
        "freq_bins": FREQ_BINS,
        "message_dim": MESSAGE_DIM,
        "message_len": int(model.config.message_len),
        "message_band_size": MESSAGE_BAND_SIZE,
        "message_sdr_default": float(model.config.message_sdr),
        "average_energy_vctk": float(model.average_energy_VCTK),
        "frame_level_normalization": bool(model.config.frame_level_normalization),
        "utterance_level_normalization": bool(model.config.utterance_level_normalization),
        "ensure_negative_message": bool(model.config.ensure_negative_message),
    }
    meta_path = OUT_PATH.with_suffix(".meta.json")
    meta_path.write_text(json.dumps(meta, indent=2))
    print(f"[export] wrote {meta_path.name}")

    # Dump the transform_message linear weights as a .bin so the
    # Rust port can reproduce the (linear → transpose → pad) step
    # without invoking the ONNX.
    weight_path = OUT_PATH.with_suffix(".transform_message.weights.bin")
    bias_path = OUT_PATH.with_suffix(".transform_message.bias.bin")
    lin = model.enc_c.linear
    assert lin.weight.shape == (MESSAGE_BAND_SIZE, MESSAGE_DIM), (
        f"unexpected linear weight shape: {tuple(lin.weight.shape)}"
    )
    assert lin.bias.shape == (MESSAGE_BAND_SIZE,)
    weight_path.write_bytes(lin.weight.detach().cpu().numpy().astype(np.float32).tobytes())
    bias_path.write_bytes(lin.bias.detach().cpu().numpy().astype(np.float32).tobytes())
    print(f"[export] wrote {weight_path.name} ({weight_path.stat().st_size} bytes)")
    print(f"[export] wrote {bias_path.name} ({bias_path.stat().st_size} bytes)")

    print()
    print("ENCODER METADATA:")
    for k, v in meta.items():
        print(f"  {k:36}  {v}")


if __name__ == "__main__":
    sys.exit(main() or 0)
