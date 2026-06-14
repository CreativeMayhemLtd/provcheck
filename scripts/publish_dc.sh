#!/usr/bin/env bash
# publish_dc.sh — Drive a provcheck release from a prepared
# release-notes/<tag>/ directory through to the public mirror.
#
# Usage:
#   ./scripts/publish_dc.sh v0.3.1
#
# Expects, prepared in advance:
#   release-notes/<tag>/commit.md  — git commit message body
#   release-notes/<tag>/tag.md     — annotated tag message body
#   release-notes/<tag>/files.txt  — newline-separated paths to `git add`
#                                    (blank lines and # comments ignored)
#
# What it does (every step gated on the previous succeeding):
#   1. Validate the prep directory contents.
#   2. Stage every file listed in files.txt; show diff stat.
#   3. Confirm with the user before any git write happens.
#   4. Commit using commit.md (no GPG signing, no Co-Authored-By
#      trailer — the trailer rule is enforced by what claude puts
#      in commit.md, not by this script).
#   5. Push main.
#   6. Create the annotated tag using tag.md; push tag.
#   7. Watch the release workflow on the dev repo until it completes.
#   8. Download every artefact bundle to dist/.
#   9. Invoke scripts/publish-release.sh to mirror to the public
#      repo and cut the GitHub Release.
#
# The publish-release.sh step has its own confirmation prompt —
# that's the final out before anything goes public.
#
# Requirements:
#   * gh CLI authenticated (for run watch + artefact download)
#   * `public` git remote configured (publish-release.sh checks)
#   * Running from inside the provcheck-dev work tree

set -euo pipefail

# ---- 1. Arg + prep validation --------------------------------------------

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <tag>" >&2
  echo "example: $0 v0.3.1" >&2
  exit 2
fi

TAG="$1"
PREP_DIR="release-notes/$TAG"
REPO="CreativeMayhemLtd/provcheck-dev"
WORKFLOW="Build release binaries"

for f in commit.md tag.md files.txt; do
  if [[ ! -f "$PREP_DIR/$f" ]]; then
    echo "fatal: $PREP_DIR/$f not found." >&2
    echo "       The pre-release prep step must populate $PREP_DIR/{commit,tag}.md" >&2
    echo "       and files.txt before this script runs." >&2
    exit 2
  fi
done

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "fatal: must run from inside the provcheck-dev git tree." >&2
  exit 2
fi

if git rev-parse --verify --quiet "$TAG" >/dev/null; then
  echo "fatal: tag '$TAG' already exists locally." >&2
  echo "       To rebuild a release, delete the tag first:" >&2
  echo "       git tag -d $TAG && git push origin :refs/tags/$TAG" >&2
  exit 2
fi

# ---- 2. Show what's about to be staged + warn on unstaged drift ----------

echo "[publish_dc] $TAG — files from $PREP_DIR/files.txt:"
MISSING=0
while IFS= read -r f; do
  [[ -z "$f" || "$f" == \#* ]] && continue
  if [[ -e "$f" ]]; then
    echo "  + $f"
  else
    echo "  ! $f  (NOT FOUND on disk — will be skipped)"
    MISSING=1
  fi
done < "$PREP_DIR/files.txt"

if [[ $MISSING -eq 1 ]]; then
  echo
  echo "[publish_dc] WARNING: some listed files don't exist. Continuing will produce a partial commit." >&2
fi

# Show every modified file in the working tree, so the user notices
# anything in files.txt that ISN'T listed and decides whether that's
# intentional.
UNTRACKED_DIFF=$(git status --short || true)
if [[ -n "$UNTRACKED_DIFF" ]]; then
  echo
  echo "[publish_dc] Current working-tree state:"
  echo "$UNTRACKED_DIFF" | sed 's/^/    /'
fi

# ---- 3. Stage + confirm --------------------------------------------------

while IFS= read -r f; do
  [[ -z "$f" || "$f" == \#* ]] && continue
  [[ -e "$f" ]] && git add "$f"
done < "$PREP_DIR/files.txt"

echo
echo "[publish_dc] Staged for commit:"
git diff --cached --stat | sed 's/^/    /'

echo
read -r -p "[publish_dc] Stage looks right? Commit + push + tag + ship? [y/N] " confirm
if [[ "${confirm,,}" != "y" ]]; then
  echo "[publish_dc] aborted (no commit made)."
  exit 1
fi

# ---- 4. Commit -----------------------------------------------------------

echo
echo "[publish_dc] Committing…"
git commit -F "$PREP_DIR/commit.md"

# ---- 5. Push main --------------------------------------------------------

echo
echo "[publish_dc] Pushing main to origin…"
git push origin main

# ---- 6. Tag + push tag ---------------------------------------------------

echo
echo "[publish_dc] Tagging $TAG…"
git tag -a "$TAG" -F "$PREP_DIR/tag.md"
git push origin "$TAG"

# ---- 7. Watch the release workflow --------------------------------------

# GitHub needs a moment to register the push and start the workflow.
sleep 5

# Find the workflow run triggered by this tag push. We filter by
# workflow name + branch (which for a tag-triggered run is the tag
# name) and take the most recent one.
echo
echo "[publish_dc] Locating release workflow run for $TAG…"
RUN_ID=""
for attempt in 1 2 3 4 5; do
  RUN_ID=$(gh run list --repo "$REPO" --workflow "$WORKFLOW" \
    --branch "$TAG" --limit 1 --json databaseId --jq '.[0].databaseId' 2>/dev/null || true)
  if [[ -n "$RUN_ID" && "$RUN_ID" != "null" ]]; then
    break
  fi
  sleep 4
done

if [[ -z "$RUN_ID" || "$RUN_ID" == "null" ]]; then
  echo "fatal: couldn't find a workflow run for $TAG after 5 attempts." >&2
  echo "       Check https://github.com/$REPO/actions manually." >&2
  exit 1
fi

echo "[publish_dc] Watching run $RUN_ID (this typically takes ~26 minutes)…"
gh run watch "$RUN_ID" --repo "$REPO" --exit-status

# ---- 8. Download artefacts ----------------------------------------------

echo
echo "[publish_dc] Workflow green. Downloading artefacts to dist/…"
rm -rf dist
gh run download "$RUN_ID" --repo "$REPO" --dir dist

echo
echo "[publish_dc] dist/ contents:"
ls dist/ | sed 's/^/    /'

# ---- 9. Hand off to publish-release.sh ----------------------------------

echo
echo "[publish_dc] Mirroring to public repo + cutting GitHub Release…"

shopt -s nullglob globstar
ARTS=()
for pattern in \
  "dist/provcheck-$TAG-"*"/provcheck-$TAG-"*.zip \
  "dist/provcheck-$TAG-"*"/provcheck-$TAG-"*.tar.gz \
  "dist/provcheck-$TAG-"*/*.sha256 \
  "dist/provcheck-kit-$TAG-"*"/provcheck-kit-$TAG-"*.zip \
  "dist/provcheck-kit-$TAG-"*"/provcheck-kit-$TAG-"*.tar.gz \
  "dist/provcheck-kit-$TAG-"*/*.sha256 \
  "dist/provcheck-gui-$TAG-"*/*.exe \
  "dist/provcheck-gui-$TAG-"*/*.msi \
  "dist/provcheck-gui-$TAG-"*/*.deb \
  "dist/provcheck-gui-$TAG-"*/*.AppImage \
  "dist/provcheck-gui-$TAG-"*/*.dmg \
  "dist/provcheck-gui-$TAG-"*/*.sha256
do
  for f in $pattern; do
    ARTS+=("$f")
  done
done

if [[ ${#ARTS[@]} -eq 0 ]]; then
  echo "fatal: no artefacts matched the expected patterns in dist/" >&2
  echo "       Workflow may have produced unexpected names — inspect dist/ and run" >&2
  echo "       scripts/publish-release.sh manually." >&2
  exit 1
fi

scripts/publish-release.sh "$TAG" "${ARTS[@]}"

echo
echo "[publish_dc] Done. $TAG is live at https://github.com/CreativeMayhemLtd/provcheck/releases/tag/$TAG"
