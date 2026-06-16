#!/usr/bin/env bash
# generate-sbom.sh — emit Software Bill of Materials for provcheck binaries.
#
# Usage:
#   ./scripts/generate-sbom.sh <tag>  [out_dir]
#
# Examples:
#   ./scripts/generate-sbom.sh v0.3.5
#   ./scripts/generate-sbom.sh v0.3.5 dist/sbom
#
# Output (in ${out_dir:-target/sbom}):
#   provcheck-<tag>.cdx.json       # CycloneDX 1.6 — provcheck verifier CLI
#   provcheck-<tag>.spdx.json      # SPDX 2.3      — provcheck verifier CLI
#   provcheck-kit-<tag>.cdx.json   # CycloneDX 1.6 — provcheck-kit creator CLI
#   provcheck-kit-<tag>.spdx.json  # SPDX 2.3      — provcheck-kit creator CLI
#
# Scope:
#   - One SBOM per top-level binary, not per (binary × target).
#     The Cargo.lock-derived dependency graph is identical across
#     linux/macos/windows; target-conditional deps appear with
#     `condition` annotations in both formats. Downstream tools
#     (Dependency Track, Trivy, Grype, GitHub Advanced Security)
#     expect one SBOM per product and resolve target conditions
#     themselves.
#   - SBOMs are generated on the host platform of whichever runner
#     invokes the script. For the canonical SBOM shipped with each
#     release, this is the Linux x86_64 runner.
#
# Format choice rationale:
#   - **CycloneDX 1.6** is the OWASP-maintained format and is the
#     primary input for modern supply-chain security tools.
#   - **SPDX 2.3** is the ISO/IEC 5962:2021 standard and is what
#     compliance / procurement teams typically ask for.
#   We ship both because some consumers strongly prefer one or
#   the other; the marginal cost is minimal (cargo-sbom emits both).
#
# Requirements:
#   - `cargo-sbom` on PATH. Install via:
#       cargo install cargo-sbom
#   - Run from the repo root.

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <tag> [out_dir]" >&2
  echo "example: $0 v0.3.5" >&2
  exit 2
fi

TAG="$1"
OUT_DIR="${2:-target/sbom}"

if ! command -v cargo-sbom >/dev/null 2>&1; then
  echo "fatal: cargo-sbom not on PATH." >&2
  echo "       Install with: cargo install cargo-sbom" >&2
  exit 2
fi

if [[ ! -f Cargo.toml ]]; then
  echo "fatal: run from the repo root (no Cargo.toml in pwd)." >&2
  exit 2
fi

mkdir -p "$OUT_DIR"

echo "[generate-sbom] target dir: $OUT_DIR"
echo "[generate-sbom] cargo-sbom $(cargo sbom --version 2>/dev/null || echo unknown)"
echo

# Map binary → cargo package. Some workspaces ship a binary whose
# name differs from its crate; provcheck-cli builds the `provcheck`
# binary, provcheck-kit builds `provcheck-kit`. The SBOM uses the
# binary name (what end-users invoke), not the crate name.
declare -A BINARIES=(
  [provcheck]=provcheck-cli
  [provcheck-kit]=provcheck-kit
)

for binary in "${!BINARIES[@]}"; do
  package="${BINARIES[$binary]}"
  echo "[generate-sbom] $binary (package: $package)"

  cdx="$OUT_DIR/${binary}-${TAG}.cdx.json"
  spdx="$OUT_DIR/${binary}-${TAG}.spdx.json"

  cargo sbom --cargo-package "$package" \
    --output-format cyclone_dx_json_1_6 > "$cdx"
  echo "  + $cdx ($(wc -c < "$cdx") bytes)"

  cargo sbom --cargo-package "$package" \
    --output-format spdx_json_2_3 > "$spdx"
  echo "  + $spdx ($(wc -c < "$spdx") bytes)"
done

# sha256 sidecars — same convention as the binary archives.
echo
echo "[generate-sbom] sha256 sidecars"
cd "$OUT_DIR"
for f in *.cdx.json *.spdx.json; do
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" > "${f}.sha256"
  else
    shasum -a 256 "$f" > "${f}.sha256"
  fi
  echo "  + ${f}.sha256"
done
cd - >/dev/null

echo
echo "[generate-sbom] done."
