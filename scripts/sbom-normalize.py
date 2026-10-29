#!/usr/bin/env python3
"""sbom-normalize.py -- make a cargo-sbom document byte-reproducible.

cargo-sbom introduces non-determinism in two ways. First, two volatile
fields: a random UUID identifier and a wall-clock creation timestamp.
Second, the component / package / relationship arrays are emitted in
hashmap iteration order, so the same dependency graph serializes in a
different element order on each run. Either one makes a committed SBOM
show a spurious diff on every regeneration, so neither could be
gate-checked against the dependency graph.

This filter removes both. The array order carries no meaning (these
are sets: components, packages, relationships, dependencies), so every
array is recursively sorted by its canonical serialization. The
dependency graph itself (components, versions, purls, licences,
relationships) is then a pure function of Cargo.lock and the
cargo-sbom version, so once the two volatile fields are pinned the
whole document becomes byte-reproducible:

  CycloneDX 1.6
    metadata.timestamp  -> fixed epoch sentinel (1970-01-01T00:00:00Z)
    serialNumber        -> urn:uuid derived from the content hash

  SPDX 2.3
    creationInfo.created -> fixed epoch sentinel (1970-01-01T00:00:00Z)
    documentNamespace    -> spdxdocs URL ending in the content hash uuid

The identifier is derived deterministically from a SHA-256 over the
document with the volatile fields stripped, so it stays unique per
dependency graph (it changes the moment a dependency changes) while
staying stable across regenerations of an unchanged graph. Output is
canonical JSON (sorted keys, two-space indent, trailing newline) so
`git diff` and the pre-push freshness check are meaningful.

Usage:
  python scripts/sbom-normalize.py <file.json>      # normalized -> stdout
  cargo sbom ... | python scripts/sbom-normalize.py  # stdin -> stdout
"""

import hashlib
import json
import sys

# Reproducible-builds sentinel: SOURCE_DATE_EPOCH = 0. A reader seeing
# this value knows the timestamp was deliberately pinned, not that the
# document was built in 1970.
EPOCH_SENTINEL = "1970-01-01T00:00:00Z"


def _canon(obj):
    """Recursively canonicalize: sort every array by its elements'
    canonical JSON so hashmap-order shuffling cannot change the output.

    SBOM arrays (components, packages, relationships, dependencies,
    licences, externalReferences) are semantically sets, so reordering
    them is lossless. Dict key order is handled at serialization time by
    sort_keys, so here we only need to order the lists.
    """
    if isinstance(obj, dict):
        return {k: _canon(v) for k, v in obj.items()}
    if isinstance(obj, list):
        items = [_canon(x) for x in obj]
        return sorted(items, key=lambda x: json.dumps(x, sort_keys=True, ensure_ascii=False))
    return obj


def _content_uuid(doc):
    """A stable UUID derived from the document minus its volatile fields.

    Unique per dependency graph, identical across regenerations of an
    unchanged graph. Formatted as a canonical 8-4-4-4-12 UUID string.
    """
    stripped = json.loads(json.dumps(doc))  # deep copy
    # Blank every field we are about to pin so the hash depends only on
    # the dependency graph, never on a prior invocation's random values.
    if "serialNumber" in stripped:
        stripped["serialNumber"] = ""
    meta = stripped.get("metadata")
    if isinstance(meta, dict):
        meta["timestamp"] = ""
    if "documentNamespace" in stripped:
        stripped["documentNamespace"] = ""
    ci = stripped.get("creationInfo")
    if isinstance(ci, dict):
        ci["created"] = ""
    blob = json.dumps(stripped, sort_keys=True, separators=(",", ":")).encode("utf-8")
    h = hashlib.sha256(blob).hexdigest()
    return "%s-%s-%s-%s-%s" % (h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])


def normalize(doc):
    doc = _canon(doc)
    uid = _content_uuid(doc)
    if doc.get("bomFormat") == "CycloneDX" or "specVersion" in doc:
        # CycloneDX 1.6.
        doc["serialNumber"] = "urn:uuid:" + uid
        meta = doc.setdefault("metadata", {})
        if isinstance(meta, dict):
            meta["timestamp"] = EPOCH_SENTINEL
    if "spdxVersion" in doc:
        # SPDX 2.3.
        name = doc.get("name", "sbom")
        doc["documentNamespace"] = "https://spdx.org/spdxdocs/%s-%s" % (name, uid)
        ci = doc.setdefault("creationInfo", {})
        if isinstance(ci, dict):
            ci["created"] = EPOCH_SENTINEL
    return doc


def main():
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    else:
        doc = json.load(sys.stdin)
    doc = normalize(doc)
    # Write raw UTF-8 bytes with LF, bypassing text-mode newline
    # translation. On Windows, sys.stdout in text mode would emit CRLF,
    # but .gitattributes pins these files to LF, so a CRLF working copy
    # would diff against the LF checkout and destabilize the sha256.
    payload = json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    sys.stdout.buffer.write(payload.encode("utf-8"))


if __name__ == "__main__":
    main()
