#!/usr/bin/env bash
# night_run.sh — orchestrator for one silentcipher codec-robust fine-
# tune night.
#
# Usage:
#     ./scripts/night_run.sh night1       # or night2
#
# What it does (each step gated on the previous succeeding):
#     1. Run preflight.py; halt on RED
#     2. Detach into tmux session "silentcipher-train" so a terminal
#        disconnect doesn't kill the run
#     3. Inside tmux: run train.py with the matching night YAML
#     4. On train.py exit (graceful OR SIGTERM OR done), run
#        validate.py against the latest checkpoint
#     5. Print a green/amber/red banner + suggestion for the next
#        night's config
#
# NOT wired in this scaffold: the actual invocation of train.py.
# train.py lands in a follow-up iteration commit. This script
# structure is the contract train.py will honour.
#
# Safe stop:
#     From any terminal on this host:
#         touch stop.flag
#     Next training step notices, checkpoints, exits gracefully.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$TOOL_DIR/../.." && pwd)"

# ---- Args --------------------------------------------------------------

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <night>" >&2
    echo "  night: night1 or night2" >&2
    exit 2
fi

NIGHT="$1"
CONFIG="$TOOL_DIR/configs/${NIGHT}.yaml"

if [[ ! -f "$CONFIG" ]]; then
    echo "error: config not found: $CONFIG" >&2
    exit 2
fi

# ---- Colour helpers ----------------------------------------------------

red()    { printf "\033[31m%s\033[0m\n" "$*" >&2; }
green()  { printf "\033[32m%s\033[0m\n" "$*"; }
yellow() { printf "\033[33m%s\033[0m\n" "$*"; }

# ---- Step 1 — Preflight ------------------------------------------------

green ""
green "[1/4] Preflight"

cd "$TOOL_DIR"
if ! python preflight.py; then
    red ""
    red "Preflight RED — training will not start."
    red "Fix the reported condition and re-run this script."
    exit 1
fi

# ---- Step 2 — tmux session ---------------------------------------------

green ""
green "[2/4] Starting tmux session 'silentcipher-train'"

if tmux has-session -t silentcipher-train 2>/dev/null; then
    yellow "tmux session 'silentcipher-train' already exists."
    yellow "  If a previous run is still active: attach with"
    yellow "    tmux attach -t silentcipher-train"
    yellow "  If it is stuck / dead: kill with"
    yellow "    tmux kill-session -t silentcipher-train"
    exit 1
fi

# ---- Step 3 — Run training ---------------------------------------------

green ""
green "[3/4] Launching train.py under tmux with config $NIGHT"

# STUB — train.py lands in a follow-up iteration commit. Uncomment the
# tmux + train.py invocation when it does:
#
#   tmux new-session -d -s silentcipher-train \
#       "cd '$TOOL_DIR' && python train.py --config '$CONFIG' 2>&1 | \
#        tee -a train.log; echo 'train.py exited'; sleep 5"
#
#   green "  Training running under tmux session 'silentcipher-train'."
#   green "  Attach to observe:  tmux attach -t silentcipher-train"
#   green "  Safe stop:          touch '$REPO_ROOT/stop.flag'"
#   green "  This script will wait for train.py to exit before running"
#   green "  the validation sweep."
#
#   # Wait for train.py to exit.
#   while tmux has-session -t silentcipher-train 2>/dev/null; do
#       sleep 30
#   done

yellow "train.py not yet in scaffold; skipping actual training run."
yellow "  Follow-up iteration commit lands train.py + un-comments the"
yellow "  tmux launcher above."
yellow "  When it lands, this script will:"
yellow "    a) start train.py in a tmux session"
yellow "    b) wait for it to exit"
yellow "    c) run validate.py"

# ---- Step 4 — Validation -----------------------------------------------

green ""
green "[4/4] Post-run validation"

# STUB — validate.py lands in a follow-up iteration commit.
#
# Uncomment when it lands:
#   python validate.py --config "$CONFIG"

yellow "validate.py not yet in scaffold; skipping validation."
yellow "  When it lands, it will:"
yellow "    a) load the latest checkpoint"
yellow "    b) run 20-sample codec-survival sweep"
yellow "    c) print green/amber/red banner + config suggestion"
yellow "    d) exit 0 on green, exit 0 with warning on amber, exit 1 on red"

green ""
green "night_run.sh $NIGHT complete."
