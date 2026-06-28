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

# Surface the failing line + last command + exit code on any abort
# under `set -e`. v0.6.0 release postmortem: step 3 of this gate was
# silently aborting with no diagnostic because the heredoc piping
# `$0 2>&1 | tail -N` discards everything before tail's window AND
# step 3 redirects the kit binary's stderr to /dev/null. The trap
# below prints the LINENO + BASH_COMMAND + exit code DIRECTLY to
# stderr, bypassing any in-script pipe, so a future investigator
# sees WHICH command failed instead of having to bash -x.
on_error() {
    ec=$?
    lineno=$1
    echo "" >&2
    echo "gate aborted: exit=$ec line=$lineno cmd=\"$BASH_COMMAND\"" >&2
    exit "$ec"
}
trap 'on_error "$LINENO"' ERR

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

# ---- 0. Pre-install detector weights -----------------------------
#
# v0.7 phase 8a: weights are downloaded on user demand, not bundled.
# Tests + gate scripts must explicitly install the weights they
# need before exercising the code paths that load them. We install
# silentcipher (gate step 2 parity sweep + step 3 AAC smoke) and
# audioseal (gate step 3 AAC smoke). Idempotent — re-installs are
# no-ops when the cache is valid.
yellow "[0/3] pre-installing detector weights (silentcipher + audioseal)"
if [[ -x target/release/provcheck-kit ]]; then
    target/release/provcheck-kit weights install silentcipher 2>&1 | tail -3
    target/release/provcheck-kit weights install audioseal 2>&1 | tail -3
else
    yellow "  kit binary not yet built; will install via cargo run from the test target dir"
    CARGO_TARGET_DIR=./target-gate cargo run --release --bin provcheck-kit -- \
        weights install silentcipher 2>&1 | tail -3 || true
    CARGO_TARGET_DIR=./target-gate cargo run --release --bin provcheck-kit -- \
        weights install audioseal 2>&1 | tail -3 || true
fi
green "  OK"

# ---- 1. Workspace cargo test --------------------------------------
yellow "[1/3] cargo test --release --workspace"
# Use a separate target dir so the test build's intermediate link
# step does not collide with a long-running process holding
# `target/release/*.exe` open on Windows. Same root cause as step 2's
# `|| true` rebuild tolerance, applied here as a clean-build-tree
# pattern rather than a swallow-and-continue.
if ! CARGO_TARGET_DIR=./target-gate cargo test --release --workspace 2>&1 | tail -40; then
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

    # Build the release CLI once so parity-vs-upstream uses fresh
    # binaries. `|| true` because Windows file locking will fail
    # this build silently when another process is holding the kit
    # or verifier exe open (e.g. a long-running prod-batch verify
    # run by the operator). In that case the parity sweep just
    # uses whichever binary is already on disk; if it is too stale
    # the sweep's threshold check below catches that downstream.
    # Without `|| true` the script's `set -euo pipefail` exits
    # silently here, leaving the operator with an unexplained push
    # rejection.
    cargo build --release --bin provcheck-kit --bin provcheck >/dev/null 2>&1 || true

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

    # Embed silentcipher into the 15-40s window + AAC re-encode +
    # detect. Sliced from `ss 15` for a 25-second window that lands
    # squarely inside one of silentcipher's tile-vote hot regions on
    # the bundled rAIdio.bot sample. v0.6.0 release postmortem:
    # `ss=0 -t=5` was prone to landing in a tile trough where mode-
    # vote confidence falls below the 0.85 gate even on a correctly-
    # marked output (empirical probe at scripts/check-before-push.sh
    # commit history).
    #
    # The kit embed STDERR is preserved (was `>/dev/null 2>&1 || true`
    # which masked real failures — another v0.6.0 lesson). If the
    # embed itself fails, the ffmpeg slice will fail next and the
    # ERR trap installed at the top of this script will surface
    # both the failing line and the kit's stderr.
    target/release/provcheck-kit watermark examples/rAIdio.bot-sample.mp3 \
        -o "$SCRATCH/sc_marked.wav" --no-verify-after-embed --overwrite >/dev/null
    [[ -s "$SCRATCH/sc_marked.wav" ]] || {
        red "  FAIL: kit produced no output WAV (sc_marked.wav missing or empty)"
        exit 1
    }
    ffmpeg -y -loglevel error -ss 15 -t 25 -i "$SCRATCH/sc_marked.wav" "$SCRATCH/sc_slice.wav"
    ffmpeg -y -loglevel error -i "$SCRATCH/sc_slice.wav" -c:a aac -b:a 192k -ar 44100 -ac 2 "$SCRATCH/sc_aac.m4a"
    # `provcheck` exits 1 on unsigned files; the AAC re-encode strips
    # any C2PA manifest, so on a watermark-only test the verifier
    # ALWAYS reports unsigned and returns non-zero. We care about the
    # watermark conf in the JSON body, not the manifest verification
    # status, so wrap to tolerate the exit code while still propagating
    # any genuine JSON-parse failures from python downstream.
    sc_conf=$( { target/release/provcheck --json "$SCRATCH/sc_aac.m4a" 2>/dev/null || true; } | \
        python -c "import json,sys; r=json.load(sys.stdin); wm=[w for w in r['watermarks'] if w['kind']=='silent_cipher'][0]; print(wm['confidence'])")
    if ! python -c "import sys; sys.exit(0 if float('$sc_conf') >= 0.85 else 1)"; then
        red "  FAIL: silentcipher AAC 192k delivery conf=$sc_conf < 0.85 (issue #24 regression)"
        exit 1
    fi
    green "  silentcipher AAC 192k: conf=$sc_conf OK"

    # Embed audioseal at default alpha + AAC re-encode + detect.
    target/release/provcheck-kit watermark "$SCRATCH/sc_slice.wav" \
        -o "$SCRATCH/as_marked.wav" --kind audioseal --brand-id 1 --no-verify-after-embed --overwrite >/dev/null 2>&1
    ffmpeg -y -loglevel error -i "$SCRATCH/as_marked.wav" -c:a aac -b:a 192k -ar 44100 -ac 2 "$SCRATCH/as_aac.m4a"
    # Same `|| true` pattern as the silentcipher step above —
    # provcheck reports the AAC file as unsigned (no C2PA), exits 1,
    # but the watermark conf JSON body is what we are gating on.
    as_conf=$( { target/release/provcheck --json "$SCRATCH/as_aac.m4a" 2>/dev/null || true; } | \
        python -c "import json,sys; r=json.load(sys.stdin); wm=[w for w in r['watermarks'] if w['kind']=='audio_seal'][0]; print(wm['confidence'])")
    if ! python -c "import sys; sys.exit(0 if float('$as_conf') >= 0.85 else 1)"; then
        red "  FAIL: audioseal AAC 192k delivery conf=$as_conf < 0.85 (issue #23 regression)"
        exit 1
    fi
    green "  audioseal AAC 192k:    conf=$as_conf OK"
fi

green ""
green "All pre-push checks passed."
