v0.3.6: SBOMs land (v0.3.5 redo, with the CI fix)

This is the release that v0.3.5 was supposed to be. v0.3.5 was
tagged but its CI workflow exited 126 at the new build-sbom step —
the `scripts/generate-sbom.sh` script didn't have the +x bit set in
git's index, so `./scripts/generate-sbom.sh` on the Linux runner hit
'Permission denied'. The exec-bit fix is already on main (commit
65c57ab); v0.3.6 carries it from the start.

The user-facing payload is identical to what was specced for v0.3.5.
Full description below — only the version number changed.

SBOMs

provcheck and provcheck-kit each get four files per release:

  provcheck-<tag>.cdx.json      # CycloneDX 1.6 (OWASP)
  provcheck-<tag>.cdx.json.sha256
  provcheck-<tag>.spdx.json     # SPDX 2.3 (ISO/IEC 5962:2021)
  provcheck-<tag>.spdx.json.sha256
  # and the same four for provcheck-kit-<tag>.*

Tooling-ready for Dependency Track, Trivy, Grype, Snyk, GitHub
Advanced Security, and any supply-chain scanner that speaks either
format. Most modern scanners prefer CycloneDX; SPDX is what
compliance teams ask for in vendor questionnaires. We ship both
because the marginal cost is minimal — both come from one cargo-sbom
invocation against the same Cargo.lock.

Scope: one SBOM per binary, not per (binary × target). The
Cargo.lock dep graph is identical across the three OS targets;
target-conditional deps (keyring's secret-service on Linux,
windows-credentials on Windows, etc.) appear with `condition`
annotations in both formats. Downstream tools resolve those
themselves.

Not in this release: a Tauri GUI SBOM. That needs the npm/Vite
frontend tree merged with the Rust-side tree, which is a follow-up.
The Rust side of the GUI is generatable locally via `cargo sbom`
from `app/src-tauri/`; the doc has the commands.

Adds:
  scripts/generate-sbom.sh — reproducible local generation,
    now correctly marked executable in git's index
  .github/workflows/release.yml — new build-sbom job (Linux only,
    parallel with build / build-gui)
  docs/sbom.md — what we ship, why both formats, how to consume
    via the common scanners, what the SBOM does NOT cover
  README.md — pointer to the SBOM doc + updated release history

Release-script hardening

scripts/publish_dc.sh used `gh run watch --exit-status` to wait for
the CI workflow. A single HTTP 502 from
`api.github.com/.../actions/runs/.../jobs` mid-stream would make
`gh run watch` exit non-zero, `set -e` would abort the whole script,
and the ship ceremony would die — leaving the workflow running but
the publish flow gone. This bit during the v0.3.4 ship (twice in a
row, the same 502 from the same API endpoint). Replaced with an
`until` poll loop that survives the 502 by retrying. Same wall-clock
behaviour, far more robust.

Also extended the artifact glob in publish_dc.sh to include the new
`dist/provcheck-sbom-<tag>/*.cdx.json` + `.spdx.json` + `.sha256`
patterns so the new artifacts get attached to the public release.

Adjacent: Tauri version files (app/src-tauri/Cargo.toml,
tauri.conf.json, app/package.json) bumped to 0.3.6 in lockstep with
the workspace. The v0.3.4 workflow rename step is already
version-agnostic so a future drift can't recreate the bundle-name
wart, but lockstep avoids the question.

Test surface

193 workspace tests + 26 watermark unit tests + 6 integration tests,
all green. No CLI behaviour or wire-format changes.

Wire format

No changes. Drop-in upgrade for any 0.3.x consumer.

About v0.3.5

The tag exists on the private dev repo but its CI failed; no
artifacts were published to the public mirror. From a consumer's
perspective, v0.3.6 follows v0.3.4 directly. The website release
history can show this as a single v0.3.6 entry with a footnote, or
list v0.3.5 explicitly with "did not ship" — the maintainer's call.
