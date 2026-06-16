v0.3.5: SBOMs + release-script hardening

Every release artifact now ships with a Software Bill of Materials in
CycloneDX 1.6 + SPDX 2.3 — tooling-ready for Dependency Track,
Trivy, Grype, Snyk, GitHub Advanced Security, and the rest. One SBOM
per binary, sidecar files with .sha256 integrity checks. See
docs/sbom.md.

Release script hardened against GitHub API 502s. publish_dc.sh now
polls instead of streaming via `gh run watch --exit-status`, so a
single transient API blip can't abort the ship ceremony anymore.

No CLI behaviour or wire-format changes.
