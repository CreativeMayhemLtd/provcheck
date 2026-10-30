#!/usr/bin/env python3
"""sbom-npm.py -- emit a CycloneDX 1.6 SBOM from an npm package-lock.json.

The GUI (app/) is a Tauri application whose JavaScript supply chain lives
in app/package-lock.json. cargo-sbom cannot see it, and the standard npm
SBOM generator (@cyclonedx/cyclonedx-npm) would have to be fetched and
executed from the network on every pre-push gate run, which is the wrong
trust model for a security gate (arbitrary third-party JavaScript, a
network dependency, and non-reproducibility across tool versions).

A package-lock.json v2/v3 already fully describes the resolved dependency
tree: every package, its exact version, its registry URL, and a subresource
integrity hash. That is everything a bill of materials needs, so we read it
directly. No network, no external code, deterministic: same trust model as
scripts/sbom-normalize.py, which canonicalizes this output into the
byte-reproducible committed form.

Every locked package is emitted (including dev/build dependencies): for a
Tauri GUI the frontend ships as a bundle produced by the build toolchain,
so the build-time packages are the supply chain that matters. cargo-sbom
likewise emits the full dependency closure, so this keeps the two halves of
the GUI SBOM consistent.

Usage:
  python scripts/sbom-npm.py app/package-lock.json   # CycloneDX 1.6 -> stdout

Pipe through scripts/sbom-normalize.py to get the committed, reproducible
form (that filter pins the volatile serialNumber / timestamp and sorts
every array).
"""

import base64
import binascii
import json
import sys

# Subresource-integrity prefix -> CycloneDX hash algorithm name.
_ALG = {"sha512": "SHA-512", "sha384": "SHA-384", "sha256": "SHA-256", "sha1": "SHA-1"}


def _purl(name, version):
    """A package URL for an npm component. The scope separator in a scoped
    name (@scope/pkg) is percent-encoded per the purl spec; the version is
    appended verbatim."""
    enc = name.replace("@", "%40", 1) if name.startswith("@") else name
    return "pkg:npm/%s@%s" % (enc, version)


def _hashes(integrity):
    """Translate an SRI string (alg-<base64>) into CycloneDX hashes. The
    SRI digest is base64; CycloneDX wants the hex of the same bytes."""
    out = []
    for token in (integrity or "").split():
        if "-" not in token:
            continue
        alg, b64 = token.split("-", 1)
        name = _ALG.get(alg.lower())
        if not name:
            continue
        try:
            content = binascii.hexlify(base64.b64decode(b64)).decode("ascii")
        except (binascii.Error, ValueError):
            continue
        out.append({"alg": name, "content": content})
    return out


def _license(entry):
    """CycloneDX licenses from a lockfile 'license' field. An SPDX
    expression (contains OR / AND / WITH) uses the expression form; a bare
    identifier uses the id form."""
    lic = entry.get("license")
    if not isinstance(lic, str) or not lic:
        return None
    up = lic.upper()
    if " OR " in up or " AND " in up or " WITH " in up or "(" in lic:
        return [{"expression": lic}]
    return [{"license": {"id": lic}}]


def _component(name, version, entry, kind):
    comp = {
        "type": kind,
        "name": name,
        "version": version,
        "purl": _purl(name, version),
        "bom-ref": _purl(name, version),
    }
    hashes = _hashes(entry.get("integrity"))
    if hashes:
        comp["hashes"] = hashes
    lic = _license(entry)
    if lic:
        comp["licenses"] = lic
    return comp


def build(lock):
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        raise SystemExit("sbom-npm: unsupported lockfile (need packages map, lockfileVersion >= 2)")
    root = packages.get("", {})
    root_name = root.get("name") or lock.get("name") or "app"
    root_version = root.get("version") or lock.get("version") or "0.0.0"

    components = []
    for path, entry in packages.items():
        if not path:
            continue  # the root project is the metadata.component, not a component
        name = entry.get("name") or path.split("node_modules/")[-1]
        version = entry.get("version")
        if not version:
            continue  # a link/workspace stub with no resolved version is not a BOM component
        components.append(_component(name, version, entry, "library"))

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": root_name,
                "version": root_version,
                "purl": _purl(root_name, root_version),
                "bom-ref": _purl(root_name, root_version),
            }
        },
        "components": components,
    }


def main():
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r", encoding="utf-8") as fh:
            lock = json.load(fh)
    else:
        lock = json.load(sys.stdin)
    doc = build(lock)
    payload = json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    sys.stdout.buffer.write(payload.encode("utf-8"))


if __name__ == "__main__":
    main()
