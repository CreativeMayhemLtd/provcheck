v0.3.6: SBOMs land (v0.3.5 redo, with the CI fix)

Every release now ships a Software Bill of Materials in CycloneDX
1.6 + SPDX 2.3 per binary — tooling-ready for Dependency Track,
Trivy, Grype, Snyk, GitHub Advanced Security, and the rest. Sidecar
files with .sha256 integrity checks. See docs/sbom.md.

Release script hardened against transient GitHub API 502s.
publish_dc.sh now polls instead of streaming via
`gh run watch --exit-status`, so a single API blip can't abort the
ship ceremony anymore.

v0.3.5 was tagged but its CI failed at the new build-sbom step
(missing exec bit on the SBOM script). The exec-bit fix is in
v0.3.6 from the start. v0.3.5 never reached the public mirror.

No CLI behaviour or wire-format changes.
