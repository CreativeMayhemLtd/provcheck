"""Generate a test fixture: real audio marked with AudioSeal carrying the
doomscroll brand ID (0x0001). Used by `provcheck-audioseal`'s
end-to-end test to verify the Rust detect pipeline recovers the
same brand the Python embed wrote.

Run:
  python scripts/audioseal-roundtrip-fixture.py [input.mp3]

Defaults to examples/rAIdio.bot-sample.mp3 (60 seconds of real audio).
"""

import os
os.environ["NO_TORCH_COMPILE"] = "1"

import sys
import warnings
warnings.filterwarnings("ignore")
import logging
logging.getLogger("pydub").setLevel(logging.ERROR)

from pathlib import Path
import numpy as np
import torch
import soundfile as sf
import librosa

from audioseal import AudioSeal

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_INPUT = REPO_ROOT / "examples" / "rAIdio.bot-sample.mp3"
OUTPUT_WAV = REPO_ROOT / "diagnose-audioseal-marked.wav"

# Brand IDs are 5-bit values; the on-wire payload encodes 3 copies
# for ECC. Doomscroll = 0x01 → payload = 0x0421 (see
# crates/provcheck-audioseal/src/registry.rs).
BRAND_ID_5BIT = 0x01  # Doomscroll


def encode_payload(id_5bit: int) -> int:
    """3 copies of the 5-bit ID + 1 reserved bit → 16-bit payload."""
    id_5bit &= 0x1F
    return id_5bit | (id_5bit << 5) | (id_5bit << 10)


def payload_to_bits(payload_u16: int) -> list[int]:
    """16-bit big-endian → 16-element bit list (MSB first)."""
    return [(payload_u16 >> (15 - i)) & 1 for i in range(16)]


def id_to_bits(id_u16: int) -> list[int]:
    """Legacy helper retained for compatibility — use payload_to_bits."""
    return payload_to_bits(id_u16)


def main():
    input_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_INPUT
    if not input_path.exists():
        print(f"fatal: {input_path} not found", file=sys.stderr)
        return 1

    print(f"[fixture] loading audio: {input_path}")
    y, sr = librosa.load(str(input_path), sr=16000, mono=True)
    print(f"          {len(y)} samples ({len(y)/sr:.2f} s @ {sr} Hz mono)")

    print(f"[fixture] loading AudioSeal generator + detector...")
    gen = AudioSeal.load_generator("audioseal_wm_16bits")
    det = AudioSeal.load_detector("audioseal_detector_16bits")
    gen.eval()
    det.eval()

    payload = encode_payload(BRAND_ID_5BIT)
    msg_bits = payload_to_bits(payload)
    print(
        f"[fixture] brand ID 0x{BRAND_ID_5BIT:02x} → payload 0x{payload:04x} → bits {msg_bits}"
    )
    msg = torch.tensor([msg_bits], dtype=torch.int32)

    x = torch.from_numpy(y).float().unsqueeze(0).unsqueeze(0)  # (1, 1, samples)
    with torch.no_grad():
        marked = gen(x, sample_rate=sr, message=msg, alpha=1.0)
    marked_np = marked.squeeze().numpy()
    print(f"[fixture] marked range: [{marked_np.min():.4f}, {marked_np.max():.4f}]")

    sf.write(str(OUTPUT_WAV), marked_np, sr, subtype="FLOAT")
    print(f"[fixture] wrote {OUTPUT_WAV} ({OUTPUT_WAV.stat().st_size} bytes)")

    print()
    print(f"[fixture] sanity-checking with AudioSeal's own detector...")
    with torch.no_grad():
        prob, recovered_bits = det.detect_watermark(
            marked, sample_rate=sr, detection_threshold=0.5, message_threshold=0.5
        )
    print(f"          detection probability: {prob.item():.4f}")
    print(f"          recovered bits: {recovered_bits[0].tolist()}")
    print(f"          embedded bits:  {msg_bits}")
    matches = sum(int(a == b) for a, b in zip(recovered_bits[0].tolist(), msg_bits))
    print(f"          matching bits: {matches} / 16")

    print()
    print("NEXT STEP — run the Rust detector on this WAV:")
    print(f"  cargo run --release --example audioseal_detect_probe -- {OUTPUT_WAV}")
    print("Expected: detected=true, brand=Doomscroll, confidence > 0.7")


if __name__ == "__main__":
    sys.exit(main() or 0)
