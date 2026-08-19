#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1 OR LicenseRef-Backfire-Commercial
# Copyright (C) 2026 Creative Mayhem UG (haftungsbeschraenkt)
#
# setup_backfire.sh - one-command Backfire environment installer (Linux/macOS).
#
# Read tier (default): builds a self-contained virtualenv for Backfire's
# numpy-only READ path and smoke-tests a known marked image. Embed tier
# (--embed): additionally installs torch, diffusers, transformers, and
# pre-fetches the diffusion and TrustMark weights (multiple GB, for creators).
#
# Usage:
#   ./setup_backfire.sh           # read tier
#   ./setup_backfire.sh --embed   # + embed tier
#   ./setup_backfire.sh --force   # rebuild from scratch
#
# Exit codes: 0 success, 1 failure.
set -euo pipefail

EMBED=0; FORCE=0; QUIET=0
for a in "$@"; do
  case "$a" in
    --embed) EMBED=1 ;;
    --force) FORCE=1 ;;
    --quiet) QUIET=1 ;;
    *) echo "setup_backfire: unknown argument $a" >&2; exit 1 ;;
  esac
done

BACKFIRE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$BACKFIRE_DIR/pyembed"
PY="$VENV_DIR/bin/python3"
BACKFIRE_PY="$BACKFIRE_DIR/backfire.py"
SAMPLE="$BACKFIRE_DIR/repro/sample_marked.png"
READ_MARKER="$VENV_DIR/.read-ready"
EMBED_MARKER="$VENV_DIR/.embed-ready"

say()  { [ "$QUIET" -eq 1 ] || echo "$*"; }
step() { [ "$QUIET" -eq 1 ] || echo "==> $*"; }
die()  { echo "setup_backfire: $*" >&2; exit 1; }

[ -f "$BACKFIRE_PY" ] || die "backfire.py not found next to this script. Run it from inside the backfire folder."

SYS_PY=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1; then SYS_PY="$c"; break; fi
done
[ -n "$SYS_PY" ] || die "no system python3 found. Install Python 3 (e.g. via your package manager or python.org) and re-run."

if [ "$FORCE" -eq 1 ] && [ -d "$VENV_DIR" ]; then
  step "Force: removing existing environment"
  rm -rf "$VENV_DIR"
fi

if [ ! -x "$PY" ] || [ ! -f "$READ_MARKER" ]; then
  step "Creating a self-contained virtualenv for the Backfire read path"
  "$SYS_PY" -m venv "$VENV_DIR" || die "could not create a virtualenv (is the python3-venv package installed?)"
  step "Installing read dependencies (numpy, pillow)"
  "$PY" -m pip install --upgrade pip --quiet
  "$PY" -m pip install --quiet 'numpy>=1.24' 'pillow>=10' || die "installing numpy/pillow failed"
else
  step "Read environment already present (use --force to rebuild)"
fi

step "Smoke-testing the Backfire read path"
[ -f "$SAMPLE" ] || die "sample image missing ($SAMPLE)"
JSON_LINE="$("$PY" "$BACKFIRE_PY" read "$SAMPLE" --key backfire-demo-key 2>/dev/null | grep -v '^\s*$' | tail -n 1)"
VALID="$(printf '%s' "$JSON_LINE" | "$PY" -c 'import sys,json; print(json.load(sys.stdin).get("valid"))' 2>/dev/null || true)"
IDHEX="$(printf '%s' "$JSON_LINE" | "$PY" -c 'import sys,json; print(json.load(sys.stdin).get("id_hex"))' 2>/dev/null || true)"
[ "$VALID" = "True" ] || die "smoke test FAILED: expected a valid mark. Read output: $JSON_LINE"
[ "$IDHEX" = "0x7" ] || die "smoke test FAILED: expected id 0x7, got $IDHEX"
touch "$READ_MARKER"
say ""
say "Backfire read path is ready. Verified: sample_marked.png -> id $IDHEX, valid."

if [ "$EMBED" -eq 1 ]; then
  step "Embed tier: installing torch, diffusers, transformers (large download)"
  "$PY" -m pip install 'torch' 'diffusers>=0.27' 'transformers>=4.40' 'huggingface_hub' || die "installing embed dependencies failed"
  say "  Note: for GPU embed, install a CUDA torch build for your platform (see pytorch.org) into $VENV_DIR."
  step "Pre-fetching the diffusion purifier and TrustMark weights (several GB)"
  "$PY" - <<'PYEOF' || die "model pre-fetch failed (network or Hugging Face reachability)"
from huggingface_hub import snapshot_download
snapshot_download("huanzi05/stable-diffusion-2-1-base",
                  revision="f71d7867a2745c420aa93441638b119c85995963")
print("models fetched")
PYEOF
  touch "$EMBED_MARKER"
  say ""
  say "Backfire embed tier is ready (torch + diffusion weights installed)."
fi

say ""
say "Done. provcheck will now find this environment automatically."
exit 0
