#!/usr/bin/env bash
# safe_stop.sh — request a graceful stop of the running training.
#
# The training loop checks for `stop.flag` at the repo root between
# steps. When present, it checkpoints and exits cleanly. NEVER kills
# the tmux session directly with `kill` or `tmux kill-session` — that
# risks leaving a half-written checkpoint on disk. Use this instead.
#
# Usage:
#     ./scripts/safe_stop.sh
#
# What it does:
#     1. Touches `<repo-root>/stop.flag`.
#     2. Prints when the training loop is expected to notice
#        (up to one training-step wallclock — usually a few seconds).
#     3. Optionally tails the training log so operator sees the
#        clean-exit lines when they land.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
FLAG_PATH="$REPO_ROOT/stop.flag"

green()  { printf "\033[32m%s\033[0m\n" "$*"; }
yellow() { printf "\033[33m%s\033[0m\n" "$*"; }

touch "$FLAG_PATH"
green "safe-stop signal written: $FLAG_PATH"
yellow "  The training loop checks for this between steps."
yellow "  Expect a clean exit within one step wallclock (usually a few"
yellow "  seconds). Tail the training log if you want to see the exit:"
yellow "    tail -f tools/train-silentcipher-codec-robust/train.log"

# The training script is expected to delete stop.flag on graceful exit
# so subsequent invocations don't inherit the signal.
