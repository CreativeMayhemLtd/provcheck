# `app.provcheck.signingKey` — atproto-anchored C2PA signing-key attestation

**Status:** v0.3 (provcheck v0.3.0). The wire format is stable; future
revisions will preserve backward compatibility unless explicitly noted.

**Audience:** Engineers building a publisher (signs media + writes
attestation records) or a verifier (reads media + checks attestation
records) against this spec. No prior provcheck knowledge required.

## 1. What this spec is for

Today, a C2PA-signed file proves that whoever held the signing
certificate's private key produced this content. It does **not** prove
that the holder is who they say they are. A creator can mint a cert
with `CN=Famous Studio` and sign anything; nothing in the C2PA layer
cross-checks that claim against an external identity.

`app.provcheck.signingKey` closes that gap by anchoring the signing
certificate to an atproto identity (a DID, optionally fronted by a
bsky handle). The creator publishes one atproto record per signing
certificate, carrying the certificate's SHA-256 fingerprint and a few
descriptive fields. A verifier:

1. Reads the C2PA manifest from the file.
2. Computes the fingerprint of the signing certificate.
3. Asks the creator's atproto repo for their `app.provcheck.signingKey`
   records.
4. Reports a match if the fingerprint appears in an active record.

A second lexicon, `app.provcheck.identity`, lets the publisher embed
the DID directly in the signed file as a C2PA assertion, so the
verifier can skip the "which handle?" UX step. The embedded claim is
a *hint*, never trust-anchoring on its own — the cross-check above is
still load-bearing.

The result is a cheap, federated, audit-friendly identity layer for
C2PA. No central trust list, no per-creator approvals, no
implementation lock-in: anyone implementing the lexicon correctly can
participate.

## 2. Wire format

### 2.1 `app.provcheck.signingKey` record

NSID: `app.provcheck.signingKey`. Record key: `any` (server-assigned).

```json
{
  "$type": "app.provcheck.signingKey",
  "createdAt": "2026-06-14T12:34:56.789Z",
  "fingerprint": "sha256:0123456789abcdef...0123456789abcdef",
  "algorithm": "ES256",
  "label": "studio mac",
  "validFrom": "2026-06-14T12:34:56.789Z",
  "validUntil": "2027-06-14T12:34:56.789Z",
  "supersededBy": "at://did:plc:abc.../app.provcheck.signingKey/3jzfci..."
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `createdAt` | datetime | yes | RFC 3339 timestamp the record was written. Default `validFrom` when that field is absent. |
| `fingerprint` | string | yes | Pattern `^sha256:[0-9a-f]{64}$`. See §3 for how it's computed. |
| `algorithm` | string | yes | JWS algorithm identifier. Known values: `ES256`, `ES384`, `ES512`, `PS256`, `PS384`, `PS512`, `RS256`, `RS384`, `RS512`, `Ed25519`. |
| `label` | string | no | Human-readable nickname. Up to 256 chars. No semantic meaning to the verifier. |
| `validFrom` | datetime | no | RFC 3339. When the record becomes active. Defaults to `createdAt` when absent. |
| `validUntil` | datetime | no | RFC 3339. When the record stops being active. Absent ⇒ open-ended. |
| `supersededBy` | at-uri | no | Informational pointer to a replacement record. Verifiers trust `validUntil` for the actual decision. |

Verifiers MUST reject records whose `algorithm` is not on the
known-values list above unless the verifier opts in explicitly to
broader algorithms. The algorithm field exists to let the verifier
reject signing keys that use algorithms it doesn't know how to check.

### 2.2 `app.provcheck.identity` assertion

This is a **C2PA assertion**, not an atproto record. It is embedded
in a signed asset's C2PA manifest under the label
`app.provcheck.identity`.

```json
{
  "did": "did:plc:abc...",
  "handle": "creator.bsky.social",
  "version": 1
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `did` | string | yes | DID format (`did:plc:...`, `did:web:...`). Source of truth for the identity. |
| `handle` | string | no | Display hint. Verifiers MUST NOT use this as the trust anchor; the DID is. |
| `version` | integer | no | Schema version. Currently always 1. |

Producers SHOULD emit `version: 1`. Verifiers MUST tolerate the
field's absence (treat as v1) and SHOULD reject versions they don't
recognise. The label string itself (`app.provcheck.identity`) is
part of the wire contract — verifiers walk C2PA assertions looking
for that exact label. (Note: c2pa-rs may append a `__<hash>`
disambiguation suffix to user-defined labels when serialising;
robust verifiers accept the bare label, the `__`-suffixed form,
and a `.<dot>`-suffixed form.)

## 3. Fingerprint algorithm

The `fingerprint` field is canonical:

```
fingerprint = "sha256:" + lowercase_hex(sha256(leaf_cert_der))
```

Where:

* `leaf_cert_der` is the DER encoding of the end-entity certificate
  (the first `CERTIFICATE` block in a conventional PEM chain).
* `sha256` is SHA-256.
* `lowercase_hex` is the lowercase hexadecimal representation of the
  resulting 32 bytes.

This is the hash of the **full leaf certificate**, not just its
public key. Two certificates with the same key but different
serials/extensions produce different fingerprints, by design — the
creator may want to publish each cert independently (e.g. when
re-issuing under a new CA).

Reference implementation:
[crates/provcheck-attestation-spec/src/lib.rs](../crates/provcheck-attestation-spec/src/lib.rs)
(`fingerprint_pem_chain`, `fingerprint_leaf_der`).

## 4. Verification flow

Given a signed file and (optionally) a creator identity:

1. **Parse the C2PA manifest** and validate the cryptographic
   signature using whichever C2PA implementation the verifier uses
   (c2pa-rs, c2pa-python, contentauthenticity.org SDK, etc.).
2. **Compute the signing certificate's fingerprint** per §3.
3. **Resolve the creator's identity**:
   * If the user supplied a handle: resolve it to a DID via the
     atproto handle-resolution flow (DNS TXT or `/.well-known/atproto-did`).
   * If the user supplied a DID: use it directly.
   * If the file embeds an `app.provcheck.identity` assertion AND
     the user opted in to "auto-identity": use the embedded DID.
     **Verifiers MUST NOT auto-use the embedded DID without an
     explicit user opt-in** — this prevents an attacker-controlled
     file from steering the verifier into trusting an arbitrary
     identity.
4. **Resolve the DID document**, then locate the PDS endpoint from
   it (via the service entry for `#atproto_pds`).
5. **Fetch records** from the PDS using
   `com.atproto.repo.listRecords` with collection
   `app.provcheck.signingKey`. Page through the cursor until
   exhausted.
6. **Filter for active records**: drop records where
   `validUntil` is set and ≤ `now`, and where `validFrom` is set
   and > `now`.
7. **Match the fingerprint** against the active set. A match means:
   "Attested by this DID." A non-match means "this signing cert is
   not on the creator's published list."

The verifier reports the outcome as one of:

* **Match** — fingerprint found in an active record.
* **Mismatch** — DID resolves; ≥1 active record exists; none match.
* **NotPublished** — DID resolves; no active records (the creator
  hasn't published any signing keys).
* **ResolutionFailed** — DID couldn't be resolved or PDS was
  unreachable.

## 5. Lifecycle

### 5.1 Publishing a new key

`com.atproto.repo.createRecord` with collection
`app.provcheck.signingKey` and the JSON above. The PDS assigns an
rkey; the resulting at-uri is the record's stable identifier.

The publisher should refuse to publish a duplicate fingerprint (two
records with identical `fingerprint` field) in the same repo without
explicit confirmation. Duplicates confuse verifiers and serve no
purpose — `kit publish` exits with a clear error and `--force` to
override.

### 5.2 Rotation

The publisher mints a fresh keypair (new fingerprint), then:

1. Publishes a new `signingKey` record for the new fingerprint.
2. Updates the old record (via `com.atproto.repo.putRecord` at the
   same rkey) to set `validUntil = now()` and
   `supersededBy = <new-record's at-uri>`.

The old record stays in the repo as a tombstone — important for
audit ("when did this key fall out of use? what replaced it?").
Verifiers continue to see the old record but treat it as inactive
because of `validUntil`.

If step 2 fails after step 1 succeeded, the publisher's atproto
state is briefly inconsistent: new record published, old record
still active. A robust publisher retries the revoke until it
succeeds, OR surfaces the inconsistency loudly so the operator can
finish it manually. Verifiers seeing both records active during
this window should treat the older `createdAt` as the trusted one
until the revoke completes (defensive: the new record could be an
unauthorised insertion).

### 5.3 Revocation

`com.atproto.repo.putRecord` at the existing rkey with
`validUntil = now()`. Optionally also set `supersededBy` if a
replacement record was published. The record stays in the repo.

**The audit trail this preserves**: anyone reading the repo later
sees the full history — when each key became active, when it was
retired, and what (if anything) replaced it.

### 5.4 Hard delete

`com.atproto.repo.deleteRecord` is supported but **NOT** the
recommended path. Use it only for orphaned records created in error
(e.g. a `rotate` that failed mid-flight and left a record nobody can
sign for); for normal lifecycle, prefer `validUntil` so the audit
trail stays intact.

## 6. Trust caveats

This is not a complete identity system. It is a *cross-check layer*
that composes with C2PA. It establishes:

* **What the cross-check proves on a match**: the holder of the
  atproto identity at the resolved DID, at some point, published
  this certificate's fingerprint and considers it theirs. The C2PA
  signature was produced by someone with the matching private key.
  If both are true, the signature was produced by someone the
  identity's owner authorised.

* **What it does NOT prove**:
  * That the file's content is authentic in any external sense —
    only that it was produced under a known key.
  * That the identity at the DID is the human or organisation the
    handle's name suggests — handles are user-controlled.
  * That the key wasn't compromised between publish and the file's
    signing — that's a key-security question, mitigated by
    `validUntil` and rotation.
  * That the verifier's view of "active records" matches reality
    at the time of signing — a rapid revoke + recheck can show
    different states. Use `validFrom` / `validUntil` to bracket
    the trust window.

* **Specifically about the embedded `app.provcheck.identity`
  assertion**: This is a self-asserted claim by the signer about
  whose identity they're signing under. An attacker can sign a file
  with any DID they want in the assertion. The verifier MUST cross-
  check the DID against the `signingKey` records before believing
  the claim. Without the cross-check, the assertion is a UX hint,
  not a trust signal.

## 7. Implementation cookbook

### 7.1 Building a verifier

Minimum viable verifier:

```
1. Open the file with your C2PA library; get the signing cert chain.
2. Compute fingerprint per §3.
3. Resolve user-supplied handle → DID, OR use the embedded
   app.provcheck.identity DID (with user opt-in).
4. GET https://plc.directory/{did}/data  (or the appropriate DID
   resolution endpoint for did:web).
5. From the DID doc, extract the atproto PDS endpoint.
6. GET {pds}/xrpc/com.atproto.repo.listRecords
       ?repo={did}&collection=app.provcheck.signingKey
   (page through cursor).
7. Filter records by validFrom/validUntil.
8. Compare fingerprints; emit Match / Mismatch / NotPublished.
```

The provcheck verifier ([crates/provcheck-platform](../crates/provcheck-platform/))
is a working reference implementation in ~1500 lines of Rust. It's
Apache-2.0-licensed and structured so the resolution / fetching /
matching layers can be picked up piecewise.

### 7.2 Building a publisher

Minimum viable publisher:

```
1. Mint or load a C2PA signing certificate (your existing
   c2pa-signing flow).
2. Authenticate to your atproto PDS (app password or OAuth).
3. POST {pds}/xrpc/com.atproto.repo.createRecord
   with collection=app.provcheck.signingKey and the JSON from §2.1.
4. On rotation, putRecord the old record with validUntil + supersededBy.
5. (Optional) During signing, embed the app.provcheck.identity
   assertion in the C2PA manifest so verifiers can auto-fill the
   identity.
```

The provcheck publisher ([crates/provcheck-publish](../crates/provcheck-publish/),
[crates/provcheck-kit](../crates/provcheck-kit/)) is Apache-2.0
Rust and exposes both a library API and a CLI that handles cert
custody, signing, and atproto record CRUD end-to-end.

## 8. Compatibility & versioning

* The wire format (§2) is the stable contract. Fields will not be
  renamed, retyped, or repurposed; new optional fields may be added.
* The fingerprint algorithm (§3) is locked. Any change is wire-
  breaking and would require a new lexicon ID (e.g.
  `app.provcheck.signingKey.v2`).
* Verifiers SHOULD ignore unknown fields they don't recognise;
  publishers MUST NOT rely on unknown fields being preserved by all
  PDSes (some normalise schemas).

## 9. References

* atproto repository operations:
  [com.atproto.repo.createRecord](https://atproto.com/specs/xrpc),
  [com.atproto.repo.listRecords](https://atproto.com/specs/xrpc),
  [com.atproto.repo.putRecord](https://atproto.com/specs/xrpc),
  [com.atproto.repo.deleteRecord](https://atproto.com/specs/xrpc).
* DID resolution: [W3C DID Core 1.0](https://www.w3.org/TR/did-core/),
  [did:plc method](https://github.com/did-method-plc/did-method-plc),
  [did:web method](https://w3c-ccg.github.io/did-method-web/).
* C2PA: [C2PA Technical Specification 2.1](https://c2pa.org/specifications/).
* JWS algorithm identifiers:
  [RFC 7518 §3.1](https://www.rfc-editor.org/rfc/rfc7518#section-3.1).
* Lexicon files:
  [lexicons/app/provcheck/signingKey.json](../lexicons/app/provcheck/signingKey.json),
  [lexicons/app/provcheck/identity.json](../lexicons/app/provcheck/identity.json).

## 10. Submitting feedback

The lexicons live in this repo. Open an issue or PR at
`https://github.com/CreativeMayhemLtd/provcheck` against the
`lexicons/` directory. Wire-breaking changes need a new lexicon ID;
additive changes can land under the existing one.
