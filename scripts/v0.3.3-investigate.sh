#!/usr/bin/env bash
# v0.3.3-investigate.sh — drive the detection-gap diff on one file.
#
# Usage:
#   ./scripts/v0.3.3-investigate.sh path/to/audio-file.mp3
#
# Runs the Rust decode_dump, then either runs the Python reference
# dump (if Python deps are installed) or prints the command to run
# it manually. Finally, runs decode_diff against both dumps.

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <audio-file>" >&2
  exit 2
fi

INPUT="$1"
if [[ ! -f "$INPUT" ]]; then
  echo "fatal: $INPUT not found" >&2
  exit 2
fi

if [[ ! -d crates/provcheck-watermark ]]; then
  echo "fatal: run from the repo root (couldn't find crates/provcheck-watermark)" >&2
  exit 2
fi

stem="${INPUT%.*}"
rust_json="${stem}.rust.json"
python_json="${stem}.python.json"

echo "===== v0.3.3 detection-gap investigation: $INPUT ====="
echo

# ---- 1. Rust dump --------------------------------------------------------

echo "[1/3] Building + running Rust decode_dump…"
cargo run --release -p provcheck-watermark --example decode_dump -- "$INPUT"
echo

# ---- 2. Python dump ------------------------------------------------------

if [[ -f "$python_json" ]]; then
  echo "[2/3] Python dump already exists at $python_json — reusing."
elif command -v python >/dev/null && python -c "import torch, librosa, onnxruntime, numpy" 2>/dev/null; then
  echo "[2/3] Running Python reference dump…"
  python scripts/v0.3.3-python-reference.py "$INPUT"
elif command -v python3 >/dev/null && python3 -c "import torch, librosa, onnxruntime, numpy" 2>/dev/null; then
  echo "[2/3] Running Python reference dump (python3)…"
  python3 scripts/v0.3.3-python-reference.py "$INPUT"
else
  cat <<EOF
[2/3] Python deps not available. To produce the Python-side dump:

  pip install -r scripts/v0.3.3-python-reference.requirements.txt
  python scripts/v0.3.3-python-reference.py "$INPUT"

Then re-run this script — step 1 will be cached and step 3 will pick up.
EOF
  exit 0
fi
echo

# ---- 3. Diff -------------------------------------------------------------

if [[ ! -f "$rust_json" || ! -f "$python_json" ]]; then
  echo "fatal: one of $rust_json / $python_json doesn't exist; can't diff." >&2
  exit 1
fi

echo "[3/3] Running decode_diff…"
echo
cargo run --release --quiet -p provcheck-watermark --example decode_diff -- \
  "$rust_json" "$python_json"
echo

echo "Done. First DIFF stage is the bug. See docs/v0.3.3-detection-gap/README.md"
echo "for the candidate-cause mapping."
