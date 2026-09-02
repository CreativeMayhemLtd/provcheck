#!/usr/bin/env bash
# publish-comfyui.sh — mirror the ComfyUI node pack out to the standalone repo.
#
# Source of truth is THIS repo (provcheck-dev) at Apps/comfyui-node/. The
# public distribution repo CreativeMayhemLtd/ComfyUI-Provcheck is a one-way
# mirror whose ROOT is the pack, so a ComfyUI user can:
#
#     cd ComfyUI/custom_nodes
#     git clone https://github.com/CreativeMayhemLtd/ComfyUI-Provcheck
#
# and it loads (and ComfyUI-Manager / the registry can discover it). Never edit
# the mirror by hand — edit Apps/comfyui-node/ here and re-run this.
#
# First-time setup (once): create the empty public repo, then run this script.
#     gh repo create CreativeMayhemLtd/ComfyUI-Provcheck --public \
#        --description "ComfyUI node for provcheck: free C2PA watermark (image/audio/video)"
#
# Usage:  scripts/publish-comfyui.sh [--push]
#   (no flag) stages the mirror and runs the OPSEC scrub, but does NOT push.
#   --push     also pushes to the ComfyUI-Provcheck remote after the scrub passes.
set -euo pipefail

SRC="Apps/comfyui-node"
REMOTE="https://github.com/CreativeMayhemLtd/ComfyUI-Provcheck.git"
MIRROR="${MIRROR_DIR:-$(git rev-parse --show-toplevel)/../ComfyUI-Provcheck-mirror}"
DENY="scripts/public-term-denylist.txt"
DO_PUSH=0; [ "${1:-}" = "--push" ] && DO_PUSH=1

[ -d "$SRC" ] || { echo "run from the provcheck-dev repo root ($SRC not found)"; exit 1; }

# --- fresh working copy of the mirror (clone if the repo exists, else init) ----
if [ ! -d "$MIRROR/.git" ]; then
    if git ls-remote "$REMOTE" >/dev/null 2>&1; then
        git clone "$REMOTE" "$MIRROR"
    else
        echo "note: $REMOTE not reachable yet — creating a local mirror to push later."
        mkdir -p "$MIRROR"; ( cd "$MIRROR" && git init -b main && git remote add origin "$REMOTE" )
    fi
fi

# --- replace the mirror's tracked content with the pack at root ---------------
find "$MIRROR" -mindepth 1 -maxdepth 1 -not -name .git -exec rm -rf {} +
cp -r "$SRC"/. "$MIRROR"/
# strip build junk that must never ship
find "$MIRROR" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "$MIRROR" -name '*.pyc' -delete 2>/dev/null || true
rm -rf "$MIRROR/.pytest_cache"

# --- OPSEC scrub: this is a PUBLIC repo outside the guard-public-push hook -----
if [ -f "$DENY" ]; then
    terms="$(grep -vE '^[[:space:]]*(#|$)' "$DENY" | tr -d '\r' | paste -sd '|' -)"
    hits="$(grep -rInEi -- "$terms" "$MIRROR" --exclude-dir=.git 2>/dev/null || true)"
    if [ -n "$hits" ]; then
        echo "REFUSING to publish — public-term-denylist hit in the ComfyUI mirror:"
        echo "$hits"
        exit 1
    fi
fi
echo "OPSEC scrub: clean."

# --- commit + (optional) push -------------------------------------------------
cd "$MIRROR"
git add -A
if git diff --cached --quiet; then echo "mirror already up to date; nothing to publish."; exit 0; fi
git commit -m "sync ComfyUI-Provcheck node pack" >/dev/null
echo "mirror staged and committed at: $MIRROR"
if [ "$DO_PUSH" = "1" ]; then
    git push -u origin main
    echo "pushed to $REMOTE"
else
    echo "dry run — re-run with --push (or: cd '$MIRROR' && git push -u origin main)"
fi
