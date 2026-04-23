# scripts/

Maintenance scripts. None are required for building or running
provcheck — they exist for specific operator tasks.

## `make-unsigned-examples.py`

Regenerates the deliberately-unsigned audio + video samples in
`examples/`. Run from the repo root:

```bash
python scripts/make-unsigned-examples.py
```

Requires Python 3.8+ and ffmpeg on `PATH` (or set `$FFMPEG`).

## `publish-release.sh`

Manual-sync a release from the private dev repo
(`CreativeMayhemLtd/provcheck-dev`) to the public release repo
(`CreativeMayhemLtd/provcheck`), then cut a GitHub Release with
platform binaries attached.

```bash
scripts/publish-release.sh v0.1.0 \
  dist/provcheck-v0.1.0-windows-x86_64.zip \
  dist/provcheck-v0.1.0-macos-aarch64.tar.gz \
  dist/provcheck-v0.1.0-linux-x86_64.tar.gz
```

Preflight checks:
- `public` git remote must exist and point at
  `https://github.com/CreativeMayhemLtd/provcheck.git`
- `gh` CLI authed with `repo` scope
- Tag must exist locally and be reachable from `main`

Prompts once before the actual push so you can back out.

This is the **manual-control release flow** — every public push is
deliberate. CI automation (Milestone 4) replaces this, but until
then a human reviews every artefact that goes public. That's a
feature for a cryptographic-trust product, not a bug.
