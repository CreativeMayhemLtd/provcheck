# Software Bill of Materials (SBOM)

Every provcheck release from v0.3.5 onward ships SBOMs alongside the
binaries. SBOMs are the industry-standard way to inventory the
dependencies of a piece of software — what's inside, where it came
from, under what licence. Supply-chain security tools (Dependency
Track, Trivy, Grype, Snyk, GitHub Advanced Security, Anchore, JFrog
Xray, Sonatype Lifecycle, etc.) consume SBOMs to surface known
CVEs and license compliance issues against a build.

## What we ship

Per release tag (`vX.Y.0` only — iteration tags do NOT ship release
artefacts), in two formats:

| File | Format | Standard | Tooling input |
|---|---|---|---|
| `provcheck-<tag>.cdx.json` | CycloneDX 1.6 | OWASP | Dependency Track, Snyk, Trivy, OWASP DT |
| `provcheck-<tag>.spdx.json` | SPDX 2.3 | ISO/IEC 5962:2021 | Compliance, procurement, GitHub Advanced Security |
| `provcheck-kit-<tag>.cdx.json` | CycloneDX 1.6 | OWASP | (same) |
| `provcheck-kit-<tag>.spdx.json` | SPDX 2.3 | ISO/IEC 5962:2021 | (same) |

Each file has a `.sha256` sidecar that matches the SHA-256 line shown
in the GitHub release page.

We ship both formats because some consumers strongly prefer one or
the other. The marginal cost is minimal — both come from the same
`cargo-sbom` invocation against the same `Cargo.lock`. They describe
the same dependency graph, just expressed in different schemas.

## Scope

**One SBOM per binary, not per (binary × target platform).** The
`Cargo.lock`-derived dependency graph is identical across Windows,
Linux, and macOS. Target-conditional dependencies (e.g. `keyring`
pulls in `secret-service` only on Linux, `windows-credentials` only
on Windows) appear in both SBOM formats with a `condition` annotation
that downstream tools resolve themselves.

Two SBOMs cover the entire CLI surface:

- `provcheck-<tag>.{cdx,spdx}.json` — the verifier CLI's tree
  (`provcheck`, `provcheck-platform`, `provcheck-watermark`, etc., plus
  their transitive deps).
- `provcheck-kit-<tag>.{cdx,spdx}.json` — the creator CLI's tree
  (`provcheck-kit`, `provcheck-sign`, `provcheck-publish`,
  `provcheck-attestation-spec`, plus transitive deps including
  `atrium-api`, `tokio`, `age`, `keyring`).

The Tauri GUI's SBOM is **not** currently shipped — that's a follow-up
that needs the npm-side (Vite / Tauri JS) tree merged with the Rust
side. If you need a GUI SBOM today, generate it locally:

```bash
cd app/src-tauri
cargo sbom --output-format cyclone_dx_json_1_6 > provcheck-gui-rust.cdx.json
cd ../
npm sbom --sbom-format=cyclonedx > provcheck-gui-frontend.cdx.json
```

## How to consume

### OWASP Dependency Track

```bash
curl -X PUT https://your-dt-server/api/v1/bom \
  -H "X-Api-Key: $DT_API_KEY" \
  -F "project=<your-project-id>" \
  -F "bom=@provcheck-vX.Y.Z.cdx.json"
```

### Trivy

```bash
trivy sbom provcheck-vX.Y.Z.cdx.json
```

### Grype

```bash
grype sbom:provcheck-vX.Y.Z.spdx.json
```

### GitHub Advanced Security

Upload the SPDX file to your repo's Dependency graph; GHAS uses it for
Dependabot alerts and license inventory.

### Read it by hand

CycloneDX components live under `.components[]`. Each has a `name`,
`version`, `purl` (Package URL identifier), and licence info:

```bash
jq '.components[] | {name, version, purl}' provcheck-vX.Y.Z.cdx.json
jq '.components[] | select(.licenses[]?.license.id == "GPL-3.0")' provcheck-vX.Y.Z.cdx.json
```

SPDX components live under `.packages[]`:

```bash
jq '.packages[] | {name, versionInfo, licenseConcluded}' provcheck-vX.Y.Z.spdx.json
```

## Verify SBOM integrity

```bash
sha256sum -c provcheck-vX.Y.Z.cdx.json.sha256
sha256sum -c provcheck-vX.Y.Z.spdx.json.sha256
```

The `.sha256` sidecars are produced inside the same workflow step that
emits the SBOM, on a GitHub Actions hosted runner. If you want
stronger supply-chain attestation (signed SBOM, SLSA provenance),
file an issue — Sigstore + SLSA L3 is on the roadmap but not in v0.9.x.

## Why we ship both CycloneDX *and* SPDX

CycloneDX is the OWASP-maintained format and the dominant input for
modern supply-chain security tools — most vulnerability scanners and
risk-management platforms speak CycloneDX natively or as their
preferred ingest.

SPDX is the ISO/IEC 5962:2021 standard and is what compliance and
procurement teams typically ask for in vendor questionnaires — it has
deeper roots in the FOSS legal-compliance world (created by the Linux
Foundation).

The two formats describe the same thing using different vocabularies.
Picking one means turning a downstream tool away; shipping both means
everyone's happy. Disk cost is ~500 KB per release.

## Reproducing the SBOMs locally

The same script CI uses lives at `scripts/generate-sbom.sh`:

```bash
cargo install cargo-sbom
./scripts/generate-sbom.sh vX.Y.Z my-out-dir
```

This produces the same files CI uploads. If a downstream tool reports
something surprising, regenerating locally is the first thing to try
— the SBOM is a function of `Cargo.lock` and the `cargo-sbom` version,
both of which are stable inputs.

## Caveat — what the SBOM does and doesn't cover

**Covered:** every Rust crate listed in `Cargo.lock`, its version, its
licence as declared in `Cargo.toml`, its source registry (crates.io
unless otherwise noted).

**Not covered:**

- The Rust toolchain itself (compiler, std library). These are pinned
  by the `rust-version` field in the workspace `Cargo.toml`.
- C system libraries linked at runtime (libc, libdl, libpthread).
  Static-CRT builds on Windows reduce this surface; Linux builds link
  against the host's glibc.
- The bundled neural-watermark model weights
  (`crates/provcheck-watermark/models/silentcipher-decoder.onnx`).
  These are committed in-tree and tracked in `WATERMARK_LICENSE_POLICY.md`,
  not the SBOM.
- Build-time dependencies that don't end up in the binary (procedural
  macros are listed in the SBOM with a `scope: optional` annotation;
  consumers can filter them out).

For full provenance of every byte in the binary, combine the SBOM
with the source archive available at
`https://github.com/CreativeMayhemLtd/provcheck/archive/<tag>.tar.gz`
— that's the canonical artefact for full-source review.
