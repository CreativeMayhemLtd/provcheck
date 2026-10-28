#!/usr/bin/env bash
# publish-crates.sh — ONE deterministic, fail-closed path to publish the Apache-2.0
# provcheck workspace to crates.io at the release version.
#
# This is the crates.io PEER of scripts/sign-and-publish-release.ps1: that script
# publishes signed BINARIES to the GitHub Release; this publishes the SOURCE crates
# to crates.io. It is LOCAL and operator-run (the token lives in ~/.cargo/credentials.toml,
# never in CI), and it slots into RELEASE_RUNBOOK.md as Step 9 — AFTER the tag is proven
# (matrix green, binaries signed), because a crates.io publish is PERMANENT (yank, never
# delete) and names + versions are claimed forever.
#
# Why a single command: crates.io re-rots to stale every release unless publishing is
# scripted into the runbook. `cargo publish --workspace` (stable since Rust 1.90; this
# MSRV is 1.91) publishes every publishable member in dependency order in one command,
# respects `publish = false`, and its verify makes `--workspace --dry-run` resolve
# bottom-up across not-yet-published siblings. cargo auto-waits on the index since 1.66.
#
# Usage:
#   scripts/publish-crates.sh [--tag vX.Y.0] [--dry-run] [--yes]
#     --tag     assert HEAD is exactly this release tag and its version matches (recommended)
#     --dry-run run the full gate + `cargo publish --workspace --dry-run` then STOP (no publish)
#     --yes     skip the confirmation prompt before the PERMANENT publish
#
# Fail-closed: any failed precondition aborts before anything reaches crates.io.
set -euo pipefail

TAG=""; DRY_RUN=0; ASSUME_YES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --tag) TAG="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) echo "unexpected arg: $1 (did you mean --tag $1 ?)" >&2; exit 2 ;;
  esac
done

die(){ printf '\033[31mpublish-crates: %s\033[0m\n' "$*" >&2; exit 1; }
step(){ printf '\033[33m== %s ==\033[0m\n' "$*"; }
ok(){ printf '\033[32m  %s\033[0m\n' "$*"; }

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"
command -v cargo >/dev/null || die "cargo not on PATH"
UA="provcheck-publish-gate (info@rAIdio.bot)"   # crates.io 403s requests without a descriptive UA

# ---- Step 1: preconditions (clean tree at the proven tag) -------------------
step "1. preconditions"
[ -z "$(git status --porcelain)" ] || die "working tree is dirty; publish only from the clean, tagged release tree."
VER="$(grep -m1 -E '^version = ' Cargo.toml | sed -E 's/version = "([^"]+)".*/\1/')"
[ -n "$VER" ] || die "could not read [workspace.package] version from Cargo.toml"
if [ -n "$TAG" ]; then
  [[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "tag must look like vX.Y.Z (got '$TAG')"
  [ "${TAG#v}" = "$VER" ] || die "tag $TAG does not match workspace version $VER"
  git rev-parse -q --verify "refs/tags/$TAG" >/dev/null || die "tag $TAG does not exist locally"
  [ "$(git rev-parse HEAD)" = "$(git rev-parse "refs/tags/$TAG^{commit}")" ] || die "HEAD is not at tag $TAG; checkout the tagged tree before publishing"
  ok "HEAD is at $TAG, workspace version $VER, tree clean"
else
  ok "workspace version $VER, tree clean (no --tag given; pass --tag vX.Y.Z to bind to the release tag)"
fi

# ---- Step 2: every intra-workspace dep carries a version + no BUSL leak ------
# crates.io refuses a `path` dependency that has no `version`. With the version
# hoisted into root [workspace.dependencies] as `{ version = .., path = .. }`,
# members reference them `{ workspace = true }` and no raw internal path dep should
# remain anywhere. Any internal `path = "(../|crates/)provcheck..."` line WITHOUT a
# version on it is the exact thing cargo will reject — catch it here, not mid-publish.
step "2. version-field + BUSL-leak gate"
# Derive the excluded (BUSL / crown-jewel) crate set from the root exclude = [...] so it
# cannot drift. These crates are workspace-excluded AND publish = false, so
# `cargo publish --workspace` never touches them and their internal path deps are
# irrelevant to crates.io (they are allowed to stay bare `{ path = ... }`). Assert each is
# publish = false as a second backstop; the Step-3 dry-run package list is the authoritative
# "no BUSL crate is published" check.
excl_line="$(grep -E '^[[:space:]]*exclude[[:space:]]*=' Cargo.toml || true)"
mapfile -t EXCLUDED < <(printf '%s\n' "$excl_line" | grep -oE '"[^"]+"' | tr -d '"')
[ "${#EXCLUDED[@]}" -gt 0 ] || die "parsed 0 excluded crates from Cargo.toml exclude=[...] (parser drift)"
for crate in "${EXCLUDED[@]}"; do
  m="$crate/Cargo.toml"; [ -f "$m" ] || continue
  grep -qE '^[[:space:]]*publish[[:space:]]*=[[:space:]]*false' "$m" \
    || die "$m is workspace-excluded but not marked publish = false (add it as a backstop)"
done
ok "${#EXCLUDED[@]} excluded crates all marked publish = false"
# crates.io refuses a `path` dependency that has no `version`. Check every PUBLISHABLE crate's
# internal path deps carry a version (members reference the hoisted root deps via
# `{ workspace = true }`, so none should remain). PRUNE the excluded crate dirs first: their
# path deps never reach crates.io, so a bare one there is not a publish blocker.
PRUNE="$(printf '/%s/|' "${EXCLUDED[@]}")"; PRUNE="${PRUNE%|}"
BARE_PATH="$(grep -rnE 'path[[:space:]]*=[[:space:]]*"(\.\./|crates/)provcheck' --include=Cargo.toml . | grep -vE 'version[[:space:]]*=' | grep -vE "$PRUNE" || true)"
if [ -n "$BARE_PATH" ]; then
  printf '%s\n' "$BARE_PATH" | sed 's/^/  MISSING version=: /' >&2
  die "internal path dependency with no version= in a publishable crate — cargo publish will reject it"
fi
ok "every publishable crate's internal path dep carries a version="

# ---- Step 3: full workspace dry-run (the real pre-publish gate) --------------
step "3. cargo publish --workspace --dry-run (compiles every crate; the gate)"
DRYLOG="$(mktemp)"
cargo publish --workspace --dry-run --jobs 8 2>&1 | tee "$DRYLOG" || { rm -f "$DRYLOG"; die "workspace dry-run FAILED — fix before publishing (nothing was published)"; }
# Authoritative publishable set = what cargo actually packaged.
mapfile -t PUBSET < <(grep -oE 'Packaging [a-z0-9-]+ v[0-9][^ ]*' "$DRYLOG" | awk '{print $2}' | sort -u)
rm -f "$DRYLOG"
[ "${#PUBSET[@]}" -gt 0 ] || die "dry-run packaged 0 crates — unexpected; refusing to continue"
# BUSL-leak assertion: no excluded crate name may appear in the packaged set.
for crate in "${EXCLUDED[@]}"; do
  name="$(basename "$crate")"
  for p in "${PUBSET[@]}"; do [ "$p" = "$name" ] && die "BUSL/excluded crate $name is in the publish set — ABORT"; done
done
ok "dry-run green: ${#PUBSET[@]} crates package cleanly, no excluded crate in the set"
printf '    %s\n' "${PUBSET[@]}"

if [ "$DRY_RUN" = "1" ]; then ok "--dry-run: gate passed, stopping before the permanent publish."; exit 0; fi

# ---- confirm before the PERMANENT publish -----------------------------------
echo
echo "  About to publish ${#PUBSET[@]} crates to crates.io at v$VER."
echo "  crates.io is APPEND-ONLY: versions and names are PERMANENT (yank, never delete)."
if [ "$ASSUME_YES" != "1" ]; then
  if [ -t 0 ]; then read -r -p "  proceed with the permanent publish? [y/N] " c; [ "${c,,}" = "y" ] || die "aborted."
  else die "non-interactive: pass --yes to proceed past this point."; fi
fi

# ---- Step 4: publish (dependency-ordered, index-aware) -----------------------
# NOTE: --workspace is NOT atomic. A mid-run failure leaves a partial publish;
# re-running resumes from the next unpublished crate (published ones are permanent
# and will be skipped as already-present).
step "4. cargo publish --workspace (permanent)"
cargo publish --workspace --jobs 8 || die "publish FAILED mid-run — published crates are permanent; re-run to resume from the next crate"
ok "cargo publish --workspace returned success"

# ---- Step 5: verify each crate+version resolves on crates.io -----------------
step "5. verify each crate resolves at v$VER on crates.io"
rc=0
for name in "${PUBSET[@]}"; do
  code="$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "https://crates.io/api/v1/crates/$name/$VER")"
  if [ "$code" = "200" ]; then ok "$name v$VER present"
  else echo "  NOT FOUND: $name v$VER (HTTP $code)" >&2; rc=1; fi
done
[ "$rc" = "0" ] || die "one or more crates did not resolve on crates.io (index lag or partial publish) — re-check before announcing"
echo
ok "DONE: ${#PUBSET[@]} crates live on crates.io at v$VER"
