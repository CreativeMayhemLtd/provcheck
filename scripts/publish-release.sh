#!/usr/bin/env bash
# publish-release.sh — manual-sync a release from the private dev repo
# (CreativeMayhemLtd/provcheck-dev) to the public release repo
# (CreativeMayhemLtd/provcheck), then cut a GitHub Release there.
#
# Usage:
#     scripts/publish-release.sh v0.3.0 \
#       dist/provcheck-v0.3.0-{windows,linux,macos}-*.{zip,tar.gz} \
#       dist/provcheck-kit-v0.3.0-{windows,linux,macos}-*.{zip,tar.gz} \
#       dist/provcheck-gui-v0.3.0-*.{exe,msi,deb,AppImage,dmg}
#
# From v0.3.0 onward, the release ships THREE binary surfaces:
#   * provcheck       — read-only verifier (the original CLI).
#   * provcheck-kit   — creator-side toolkit (mint identity, sign,
#                       atproto publish; v0.3.0+).
#   * provcheck-gui   — Tauri desktop app (verifier-only — kit GUI
#                       lands in a later release).
# Each ships as one archive per OS, with a matching .sha256 sidecar.
#
# What it does:
#   1. Sanity-checks that the tag exists locally and points at a
#      commit on main.
#   2. Pushes main + the tag to the `public` git remote.
#   3. Generates release notes from the commit log since the prior tag.
#   4. Calls `gh release create` on the public repo, attaching any
#      binary artefacts you pass on the command line.
#
# Requirements:
#   * `git remote show public` must exist and point at
#     https://github.com/CreativeMayhemLtd/provcheck
#     (run `git remote add public https://…` once if missing).
#   * `gh` CLI authed to github.com with `repo` scope.
#
# Deliberately simple — this is the manual-control release flow.
# CI automation arrives in Milestone 4; until then a human (you)
# reviews every public push. That's a feature, not a bug.

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <tag> [artefact...]" >&2
  echo "example: $0 v0.3.0 dist/provcheck-v0.3.0-*.{zip,tar.gz} \\" >&2
  echo "                   dist/provcheck-kit-v0.3.0-*.{zip,tar.gz}" >&2
  exit 2
fi

TAG="$1"
shift
ARTIFACTS=("$@")

REPO_PRIVATE="CreativeMayhemLtd/provcheck-dev"
REPO_PUBLIC="CreativeMayhemLtd/provcheck"

# --- 1. Preflight ---

echo "[1/5] Preflight …"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "fatal: must run from inside the provcheck-dev git tree." >&2
  exit 2
fi

if ! git remote get-url public >/dev/null 2>&1; then
  echo "fatal: 'public' remote not configured." >&2
  echo "  run: git remote add public https://github.com/${REPO_PUBLIC}.git" >&2
  exit 2
fi

PUBLIC_URL=$(git remote get-url public)
if [[ "$PUBLIC_URL" != *"$REPO_PUBLIC"* ]]; then
  echo "fatal: 'public' remote is $PUBLIC_URL, expected …/${REPO_PUBLIC}." >&2
  exit 2
fi

if ! git rev-parse --verify --quiet "$TAG" >/dev/null; then
  echo "fatal: tag '$TAG' not found locally. Create it first:" >&2
  echo "  git tag -a $TAG -m \"<release notes subject>\"" >&2
  exit 2
fi

# Make sure the tag is on main (or at least reachable from it).
if ! git merge-base --is-ancestor "$TAG" main; then
  echo "fatal: tag '$TAG' is not reachable from main." >&2
  echo "      Switch to main and make sure the release commit is merged." >&2
  exit 2
fi

for art in "${ARTIFACTS[@]}"; do
  if [[ ! -f "$art" ]]; then
    echo "fatal: artefact not found: $art" >&2
    exit 2
  fi
done

# Confirm — one chance to back out before we push to a PUBLIC repo.
echo
echo "  Tag:        $TAG"
echo "  From:       $REPO_PRIVATE"
echo "  To:         $REPO_PUBLIC"
echo "  Artefacts:  ${#ARTIFACTS[@]} file(s)"
for art in "${ARTIFACTS[@]}"; do echo "              - $art"; done
echo
read -r -p "Push and create public release? [y/N] " confirm
if [[ "${confirm,,}" != "y" ]]; then
  echo "aborted."
  exit 1
fi

# --- 2. Push main + tag to public ---

echo
echo "[2/5] Pushing main + tag to $REPO_PUBLIC …"
git push public main
git push public "$TAG"

# --- 3. Build release notes ---

echo
echo "[3/5] Building release notes …"

PRIOR_TAG=$(git describe --tags --abbrev=0 "$TAG^" 2>/dev/null || true)
NOTES_FILE=$(mktemp)
trap 'rm -f "$NOTES_FILE"' EXIT

{
  echo "## Changes"
  echo
  if [[ -n "$PRIOR_TAG" ]]; then
    git log --pretty=format:"- %s" "$PRIOR_TAG..$TAG"
  else
    # First release — summarise the initial drop.
    git log --pretty=format:"- %s" "$TAG"
  fi
  echo
  echo
  echo "## Downloads"
  echo
  echo "Platform binaries are attached to this release. Verify checksums"
  echo "against the SHA-256 values shown on the downloads page at"
  echo "[provcheck.ai](https://provcheck.ai) before running."
  echo
  echo "## Source"
  echo
  echo "Full source for this release is in this repo. Development happens"
  echo "in the private \`provcheck-dev\` repository; each release is a"
  echo "curated snapshot."
} > "$NOTES_FILE"

# --- 4. Create the GitHub Release ---

echo
echo "[4/5] Creating GitHub Release $TAG on $REPO_PUBLIC …"

GH_ARGS=(release create "$TAG"
  --repo "$REPO_PUBLIC"
  --title "$TAG"
  --notes-file "$NOTES_FILE"
)
for art in "${ARTIFACTS[@]}"; do
  GH_ARGS+=("$art")
done

# `gh` prefers $GITHUB_TOKEN over its keyring login. If the env var
# is stale (common when a local shell has an old PAT exported), every
# API call 401s even though the user is actually authed via the gh
# keyring. Clear it for this call so keyring auth takes over. Without
# this line, the v0.1.0 release cut 401'd at the final step.
GITHUB_TOKEN= gh "${GH_ARGS[@]}"

# --- 5. Refresh repo description + homepage + topics on both repos -----
#
# Keeps GitHub's front-page metadata in sync with the project's actual
# positioning. Without this, the repo description drifts (or stays
# empty) across releases and technical evaluators land on a stale page.
# Both repos are refreshed because the dev repo is a private mirror
# but is still indexed internally.

echo
echo "[5/5] Refreshing GitHub repo metadata on both repos …"

REPO_DESC="Local-first C2PA Content Credentials verifier + creator toolkit. Neural-watermark cross-check (silentcipher, AudioSeal, WavMark) and atproto-bound identity. CLI + GUI for Windows/Linux/macOS. Apache-2.0."
REPO_HOME="https://provcheck.ai"
REPO_TOPICS=(c2pa content-credentials provenance watermarking silentcipher audioseal wavmark atproto rust tauri desktop-app cli deepfake ai-provenance signing)

refresh_repo_metadata() {
  local repo="$1"
  local desc_prefix="$2"
  GITHUB_TOKEN= gh repo edit "$repo" \
    --description "${desc_prefix}${REPO_DESC}" \
    --homepage "$REPO_HOME" >/dev/null
  for t in "${REPO_TOPICS[@]}"; do
    GITHUB_TOKEN= gh repo edit "$repo" --add-topic "$t" >/dev/null 2>&1 || true
  done
  echo "  ${repo}: description + homepage + ${#REPO_TOPICS[@]} topics OK"
}

refresh_repo_metadata "$REPO_PUBLIC" ""
refresh_repo_metadata "CreativeMayhemLtd/provcheck-dev" "[DEV MIRROR] "

echo
echo "Done. Release live at: https://github.com/${REPO_PUBLIC}/releases/tag/${TAG}"
