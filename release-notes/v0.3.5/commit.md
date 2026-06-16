v0.3.5: SBOMs + release-script hardening

Every release artifact now ships with a Software Bill of Materials in
both industry-standard formats (CycloneDX 1.6 + SPDX 2.3). Plus a
release-script fix so a single transient GitHub API hiccup can't
abort the ship ceremony anymore.

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
frontend tree merged with the Rust-side tree, which is a v0.3.6
follow-up. The Rust side of the GUI is generatable locally via
`cargo sbom` from `app/src-tauri/`; the doc has the commands.

Adds:
  scripts/generate-sbom.sh — reproducible local generation
  .github/workflows/release.yml — new build-sbom job (Linux only,
    parallel with build / build-gui)
  docs/sbom.md — what we ship, why both formats, how to consume
    via the common scanners, what the SBOM does NOT cover
  README.md — pointer to the SBOM doc

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
tauri.conf.json, app/package.json) bumped to 0.3.5 in lockstep with
the workspace. The v0.3.4 workflow rename step is already
version-agnostic so a future drift can't recreate the bundle-name
wart, but lockstep avoids the question.

Test surface

193 workspace tests + 26 watermark unit tests + 6 integration tests,
all green. No CLI behaviour or wire-format changes.

Wire format

No changes. Drop-in upgrade for any 0.3.x consumer.
