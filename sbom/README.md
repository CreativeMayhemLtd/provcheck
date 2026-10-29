# Committed SBOMs

These files are the Software Bill of Materials for each shipping
provcheck binary, committed in-tree and kept in lockstep with
`Cargo.lock`.

| File | Binary | Format |
|---|---|---|
| `provcheck.cdx.json` | `provcheck` (verifier CLI) | CycloneDX 1.6 |
| `provcheck.spdx.json` | `provcheck` (verifier CLI) | SPDX 2.3 |
| `provcheck-kit.cdx.json` | `provcheck-kit` (creator CLI) | CycloneDX 1.6 |
| `provcheck-kit.spdx.json` | `provcheck-kit` (creator CLI) | SPDX 2.3 |

Each has a `.sha256` sidecar you can verify with `sha256sum -c *.sha256`.

## Do not hand-edit

They are generated. The two volatile fields `cargo-sbom` stamps (a
random UUID and a wall-clock timestamp) are pinned by
`scripts/sbom-normalize.py`, and every array is canonically sorted, so
the output is a byte-reproducible function of `Cargo.lock`. That is
what lets them be committed and machine-checked.

## Refreshing

When `Cargo.lock` changes (a dependency bump, a new crate, a
`cargo update`), regenerate and commit the diff in the same commit:

```bash
scripts/refresh-sbom.sh
```

If the dependency graph did not actually change, this is a no-op and
git shows nothing.

## Enforcement

The pre-push gate (`scripts/check-before-push.sh`) regenerates these
into a temp dir and refuses the push if the committed copy differs, so
the published SBOM can never silently drift from the binary. Because
this directory is not listed in `scripts/public-exclude.txt`, the
committed SBOM ships to the public mirror on every publish.

The release matrix additionally uploads tagged, release-scoped SBOMs
(`scripts/generate-sbom.sh`) to the GitHub Release page. See
`docs/sbom.md` for the full picture.
