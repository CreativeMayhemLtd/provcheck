#!/usr/bin/env bash
# refresh-sbom.sh -- regenerate the committed, normalized SBOM set.
#
# The repo carries a byte-reproducible SBOM for each shipping binary
# under sbom/. It is a pure function of Cargo.lock (see
# scripts/sbom-normalize.py for why it is reproducible), so it can be
# committed, diffed, and gate-checked. The pre-push gate
# (scripts/check-before-push.sh) regenerates into a temp dir and
# refuses the push if the result differs from what is committed, so
# the committed SBOM can never silently drift from the dependency
# graph. Because sbom/ is not in scripts/public-exclude.txt, the
# committed SBOM rides to the public mirror on every publish.
#
# Run this whenever Cargo.lock changes (a dependency bump, a new crate,
# a cargo update), then commit the sbom/ diff alongside the lockfile
# change. If deps did not change, this is a no-op and git shows nothing.
#
# Usage:
#   scripts/refresh-sbom.sh            # write into the committed sbom/ dir
#   scripts/refresh-sbom.sh <out_dir>  # write into <out_dir> (gate uses this)
#
# Requires cargo-sbom on PATH:  cargo install cargo-sbom --locked

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

OUT_DIR="${1:-sbom}"
NORMALIZE="$REPO_ROOT/scripts/sbom-normalize.py"

if ! command -v cargo-sbom >/dev/null 2>&1; then
  echo "fatal: cargo-sbom not on PATH. Install with: cargo install cargo-sbom --locked" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"

# binary (what users invoke) -> cargo package that builds it.
# provcheck-cli builds the `provcheck` binary; provcheck-kit builds
# `provcheck-kit`. The SBOM is named for the binary, not the crate.
declare -A BINARIES=(
  [provcheck]=provcheck-cli
  [provcheck-kit]=provcheck-kit
)

for binary in "${!BINARIES[@]}"; do
  package="${BINARIES[$binary]}"
  cdx="$OUT_DIR/${binary}.cdx.json"
  spdx="$OUT_DIR/${binary}.spdx.json"

  cargo sbom --cargo-package "$package" --output-format cyclone_dx_json_1_6 \
    | python "$NORMALIZE" > "$cdx"
  cargo sbom --cargo-package "$package" --output-format spdx_json_2_3 \
    | python "$NORMALIZE" > "$spdx"
done

# sha256 sidecars. The SBOM is reproducible, so the digest is a stable
# supply-chain anchor downstream consumers can pin against. Compute the
# sidecar with a bare filename (not the path) so `sha256sum -c` works
# from inside the output directory regardless of where the repo lives.
(
  cd "$OUT_DIR"
  for f in *.cdx.json *.spdx.json; do
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "$f" > "${f}.sha256"
    else
      shasum -a 256 "$f" > "${f}.sha256"
    fi
  done
)

echo "[refresh-sbom] wrote normalized SBOMs to $OUT_DIR/"
