# Committed SBOMs

These files are the Software Bill of Materials for each shipping
provcheck binary, committed in-tree and kept in lockstep with the
lockfiles they describe.

| File | Binary | Supply chain | Format |
|---|---|---|---|
| `provcheck.cdx.json` | `provcheck` (verifier CLI) | workspace `Cargo.lock` | CycloneDX 1.6 |
| `provcheck.spdx.json` | `provcheck` (verifier CLI) | workspace `Cargo.lock` | SPDX 2.3 |
| `provcheck-kit.cdx.json` | `provcheck-kit` (creator CLI) | workspace `Cargo.lock` | CycloneDX 1.6 |
| `provcheck-kit.spdx.json` | `provcheck-kit` (creator CLI) | workspace `Cargo.lock` | SPDX 2.3 |
| `gui-rust.cdx.json` | GUI (`provcheck-app`, Tauri) | `app/src-tauri/Cargo.lock` | CycloneDX 1.6 |
| `gui-rust.spdx.json` | GUI (`provcheck-app`, Tauri) | `app/src-tauri/Cargo.lock` | SPDX 2.3 |
| `gui-npm.cdx.json` | GUI build toolchain | `app/package-lock.json` | CycloneDX 1.6 |

Each has a `.sha256` sidecar you can verify with `sha256sum -c *.sha256`.

The GUI is a Tauri binary that lives outside the Rust workspace, so it
has two supply chains. The Rust half (`gui-rust.*`) is its own crate,
not a workspace member, so `cargo-sbom` is run from inside
`app/src-tauri`. The JavaScript half (`gui-npm.cdx.json`) is read
straight from `app/package-lock.json` by `scripts/sbom-npm.py` rather
than the stock `@cyclonedx/cyclonedx-npm`, so the gate stays hermetic
(no network and no third-party JavaScript executing on every push). Its
whole npm tree today is the Tauri CLI and its platform binaries (all
`Apache-2.0 OR MIT`); the frontend ships as a build-time bundle, so
there are no runtime npm dependencies. `gui-npm.cdx.json` is
CycloneDX-only because CycloneDX is the native npm SBOM format.

## Licensing

None of the shipping trees carry a sole-copyleft dependency. The GUI
Rust tree contains the usual dual/tri-licensed crates (`r-efi` is
`MIT OR Apache-2.0 OR LGPL-2.1-or-later`, `self_cell` is
`Apache-2.0 OR GPL-2.0`); a permissive option is always available and
elected, so there is no copyleft obligation, and there is no AGPL,
SSPL, or BUSL anywhere in the committed set.

## Do not hand-edit

They are generated. The two volatile fields `cargo-sbom` stamps (a
random UUID and a wall-clock timestamp) are pinned by
`scripts/sbom-normalize.py`, and every array is canonically sorted, so
the output is a byte-reproducible function of the lockfile. That is
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
