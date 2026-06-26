#!/usr/bin/env bash
# check-before-push.sh — pre-push regression gate for provcheck.
#
# Runs in this order:
#   1. cargo test --release --workspace            (workspace-wide unit + integration)
#   2. scripts/parity-vs-upstream.py at SDR ∈ {30, 47}  (silentcipher embed parity vs upstream Python)
#   3. AAC delivery survival check for silentcipher + AudioSeal
#      (the public-issue #23 + #24 ground truth — guards both
#       embed margin AND the symphonia AAC decoder priming fix)
#
# Designed to be wired as `.git/hooks/pre-push` via the companion
# install line below. Any FAIL exits non-zero so the push aborts.
#
# Wall-clock: about 10 minutes on a warm cargo cache. Cold builds
# add 2-3 minutes. Skip with --skip-parity if you genuinely need to
# push and are confident the parity sweep is irrelevant to the
# change (e.g. doc-only edit).
#
# Bypass for emergencies: `git push --no-verify`. Use sparingly;
# every bypass should be noted in the commit body or release
# notes so a future investigator can correlate.
#
# Install:
#   ln -sf ../../scripts/check-before-push.sh .git/hooks/pre-push
#   chmod +x .git/hooks/pre-push
#
# Or run manually before a tag push:
#   scripts/check-before-push.sh

set -euo pipefail

SKIP_PARITY=0
for a in "$@"; do
    case "$a" in
        --skip-parity) SKIP_PARITY=1 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

red()    { printf "\033[31m%s\033[0m\n" "$*" >&2; }
green()  { printf "\033[32m%s\033[0m\n" "$*"; }
yellow() { printf "\033[33m%s\033[0m\n" "$*"; }

# ---- 1. Workspace cargo test --------------------------------------
yellow "[1/3] cargo test --release --workspace"
if ! cargo test --release --workspace 2>&1 | tail -40; then
    red "  FAIL: workspace tests"
    exit 1
fi
green "  OK"

# ---- 2. Parity sweep vs upstream Python silentcipher --------------
if [[ "$SKIP_PARITY" == "1" ]]; then
    yellow "[2/3] parity sweep SKIPPED (--skip-parity)"
else
    yellow "[2/3] parity sweep vs upstream Python (SDR 30 + 47)"

    # Skip silentcipher weights cleanly if they are not in HF cache.
    if ! python -c "from pathlib import Path; p = Path.home() / '.cache/huggingface/hub/models--sony--silentcipher'; import sys; sys.exit(0 if any(p.rglob('44_1_khz/73999_iteration/hparams.yaml')) else 1)" 2>/dev/null; then
        red "  FAIL: silentcipher 44.1k weights missing from HF cache."
        red "        Run: python -c \"from huggingface_hub import snapshot_download; snapshot_download('sony/silentcipher')\""
        red "        Or push with --skip-parity (then note in commit body)."
        exit 1
    fi
    if ! python -c "import silentcipher, librosa, soundfile, numpy" 2>/dev/null; then
        red "  FAIL: missing python deps. Run: pip install silentcipher librosa soundfile numpy"
        exit 1
    fi

    # Build the release CLI once so parity-vs-upstream uses fresh binaries.
    cargo build --release --bin provcheck-kit --bin provcheck >/dev/null 2>&1

    # Run a focused sweep (5s clip, SDR 30 + 47) and parse the conf
    # column for the rust-detect-rust row. The full script writes its
    # report to stdout; we tee to a log for inspection.
    LOG="target/check-before-push-parity.log"
    mkdir -p target
    if ! python scripts/parity-vs-upstream.py examples/rAIdio.bot-sample.mp3 \
            --duration-s 5 --sdrs 30 47 --skip-codec >"$LOG" 2>&1; then
        red "  FAIL: parity-vs-upstream.py crashed. See $LOG"
        exit 1
    fi

    # Extract the Python detector confidences (py(P)/rs(P)) from the
    # report table. Schema: "  30  0.999  0.999"-ish. Pull the rs(P)
    # column for the SDR 30 row and gate at >= 0.85.
    rust_at_30=$(awk '/^   30/ {print $(NF)}' "$LOG" | head -1)
    if [[ -z "$rust_at_30" ]] || ! python -c "import sys; v = float('$rust_at_30'); sys.exit(0 if v >= 0.85 else 1)" 2>/dev/null; then
        red "  FAIL: parity rust-embed-python-detect at SDR 30 conf=${rust_at_30:-?} < 0.85. See $LOG"
        exit 1
    fi
    green "  OK (rust@SDR30 conf=$rust_at_30 via python detector)"
fi

# ---- 3. AAC delivery survival (issues #23 + #24) ------------------
yellow "[3/3] AAC delivery survival smoke (issues #23 + #24)"
if ! command -v ffmpeg >/dev/null; then
    yellow "  ffmpeg not on PATH — skipping codec survival smoke"
    yellow "  (this gate cannot run; add ffmpeg if you want it enforced)"
else
    SCRATCH="$(mktemp -d)"
    trap 'rm -rf "$SCRATCH"' EXIT

    # Embed silentcipher into a 5s slice + AAC re-encode + detect.
    target/release/provcheck-kit watermark examples/rAIdio.bot-sample.mp3 \
        -o "$SCRATCH/sc_marked.wav" --no-verify-after-embed --overwrite >/dev/null 2>&1 || true
    # Truncate to 5s for speed.
    ffmpeg -y -loglevel error -i "$SCRATCH/sc_marked.wav" -t 5 "$SCRATCH/sc_5s.wav"
    ffmpeg -y -loglevel error -i "$SCRATCH/sc_5s.wav" -c:a aac -b:a 192k -ar 44100 -ac 2 "$SCRATCH/sc_aac.m4a"
    sc_conf=$(target/release/provcheck --json "$SCRATCH/sc_aac.m4a" 2>/dev/null | \
        python -c "import json,sys; r=json.load(sys.stdin); wm=[w for w in r['watermarks'] if w['kind']=='silent_cipher'][0]; print(wm['confidence'])")
    if ! python -c "import sys; sys.exit(0 if float('$sc_conf') >= 0.85 else 1)"; then
        red "  FAIL: silentcipher AAC 192k delivery conf=$sc_conf < 0.85 (issue #24 regression)"
        exit 1
    fi
    green "  silentcipher AAC 192k: conf=$sc_conf OK"

    # Embed audioseal at default alpha + AAC re-encode + detect.
    target/release/provcheck-kit watermark "$SCRATCH/sc_5s.wav" \
        -o "$SCRATCH/as_marked.wav" --kind audioseal --brand-id 1 --no-verify-after-embed --overwrite >/dev/null 2>&1
    ffmpeg -y -loglevel error -i "$SCRATCH/as_marked.wav" -c:a aac -b:a 192k -ar 44100 -ac 2 "$SCRATCH/as_aac.m4a"
    as_conf=$(target/release/provcheck --json "$SCRATCH/as_aac.m4a" 2>/dev/null | \
        python -c "import json,sys; r=json.load(sys.stdin); wm=[w for w in r['watermarks'] if w['kind']=='audio_seal'][0]; print(wm['confidence'])")
    if ! python -c "import sys; sys.exit(0 if float('$as_conf') >= 0.85 else 1)"; then
        red "  FAIL: audioseal AAC 192k delivery conf=$as_conf < 0.85 (issue #23 regression)"
        exit 1
    fi
    green "  audioseal AAC 192k:    conf=$as_conf OK"
fi

green ""
green "All pre-push checks passed."
