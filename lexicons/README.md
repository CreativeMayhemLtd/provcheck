# provcheck atproto lexicons

This directory holds the atproto lexicon definitions used by
provcheck for DID-anchored identity attestation of C2PA signing
certificates.

## Files

* [`app/provcheck/signingKey.json`](app/provcheck/signingKey.json) —
  Record lexicon. A creator publishes one record per signing
  certificate; verifiers cross-check a C2PA signature's
  certificate fingerprint against the active set in the
  signer's atproto repo. NSID: `app.provcheck.signingKey`.

* [`app/provcheck/identity.json`](app/provcheck/identity.json) —
  C2PA assertion lexicon. Self-asserted DID embedded in a signed
  asset; verifiers use it as a *hint* to skip manual identity
  entry, then cross-check against the `signingKey` records.
  Assertion label: `app.provcheck.identity`. NOT trust-anchoring
  on its own.

## Spec

The full English writeup — fingerprint algorithm, verification
flow, rotation/revocation lifecycle, trust caveats, and
implementation cookbooks for both publisher and verifier — is in
[`docs/atproto-signing-key.md`](../docs/atproto-signing-key.md).

The reference Rust implementation:

* Verifier — [`crates/provcheck-platform/`](../crates/provcheck-platform/),
  [`crates/provcheck/`](../crates/provcheck/), and
  [`crates/provcheck-cli/`](../crates/provcheck-cli/).
* Publisher — [`crates/provcheck-publish/`](../crates/provcheck-publish/)
  (atproto session + record CRUD) and
  [`crates/provcheck-kit/`](../crates/provcheck-kit/) (the CLI
  that composes cert custody + C2PA signing + atproto publish).
* Wire-shape contract — [`crates/provcheck-attestation-spec/`](../crates/provcheck-attestation-spec/)
  (the shared Rust types both sides depend on).

## Status

Stable. Field names + types in both lexicons are part of the
v0.3 wire contract; future revisions preserve backward
compatibility unless explicitly noted.

## Submitting to lexicon.community

These lexicons are intended for submission to
[lexicon.community](https://lexicon.community/) once the v0.3
release lands and we have a stable upstream URL to reference.
The submission PR points back at provcheck.ai for documentation.
