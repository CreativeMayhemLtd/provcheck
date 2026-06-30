# Semver policy

How we version provcheck after v1.0.0.

## Versioning scheme

Standard semver: `MAJOR.MINOR.PATCH`.

- **MAJOR** (`v2.0.0`): a documented breaking change to anything
  in the **stable** column of
  [`public-api-stability.md`](./public-api-stability.md). Includes:
  - A public function signature change that breaks downstream code.
  - A public type losing a field or having a field renamed.
  - An enum variant being removed or having its serde tag changed.
  - An MSRV bump past two stable Rust releases (see MSRV section).
  - A CLI exit code being reassigned.
  - A wire-format byte layout change (PAYLOAD_*, BCH-5 magic, etc.).
- **MINOR** (`v1.X.0`): backwards-compatible additions to the
  stable surface. New subcommands, new flags, new functions, new
  enum variants on `#[non_exhaustive]` enums, new optional struct
  fields on serde-Default-enabled structs.
- **PATCH** (`vX.Y.Z` with Z > 0): bug fixes, documentation
  changes, test-coverage additions, internal refactors that
  don't touch the stable surface, dependency updates that don't
  bubble up to public types.

## Workspace-wide versioning

All workspace crates share a `version` field inherited from the
top-level `[workspace.package]` block. They release together; we
don't ship `provcheck-watermark v1.2.0` against `provcheck v1.0.0`.
This makes the cross-crate invariants we test (lexicon NSID,
wire-format constants, classify-threshold parity) trivially
upgradeable for downstream consumers.

## Pre-release tags

`vX.Y.Z` where `Z > 0` and the release matrix is skipped (the
`v*.*.0` glob filter in `.github/workflows/release.yml`):

- During development of vX.Y.0, we cut iteration tags freely
  (vX.Y.1, vX.Y.2, ..., as commit anchors for the test-coverage
  push). They don't fire the matrix, don't burn Actions minutes,
  and don't ship to crates.io.
- The actual release is always `vX.Y.0`; iteration tags are
  internal anchors.
- Operators MAY use a development iteration tag if they want a
  specific in-flight commit, but they should expect that semver
  guarantees only kick in at the `vX.Y.0` tags. Iteration tags are
  pre-release artefacts.

This matches the v0.9.0 → v0.9.69 iteration cycle we ran before
v1.0; see [`release-process.md`](./release-process.md) for the
mechanics.

## MSRV policy

The workspace `[workspace.package]` block pins `rust-version`. As
of v1.0 it is the version in `Cargo.toml`'s top-level
`workspace.package.rust-version` field.

**Bump rule**: we MAY bump MSRV in a minor release only when:

1. The new MSRV is at least 12 weeks old (i.e. two stable Rust
   releases have shipped past it).
2. The bump unlocks a feature we're actively using.
3. The bump is called out in the README changelog row.

We bump MSRV in a major release any time we need to. A pinned MSRV
older than 12 weeks is treated as a documentation bug in the patch
release stream.

## Breaking-change deprecation cycle

When we remove a public item in v1.x → v2.0:

1. In the last v1.x release before v2.0, the item gains
   `#[deprecated(since = "1.X.0", note = "use Y instead")]`.
2. The release notes (README changelog row + the v2.0 migration
   doc) name the deprecation and the replacement.
3. v2.0 removes the item.

Items added to a `#[non_exhaustive]` enum do NOT need this cycle;
that's what `#[non_exhaustive]` is for.

## Wire-format changes

Most "MAJOR" candidates are actually wire-format changes —
something whose bytes get stored in a C2PA manifest or an at-proto
record and whose meaning needs to round-trip across versions.

Categories:

1. **C2PA assertion content** (`app.provcheck.identity` body): wire
   format pinned by `provcheck-attestation-spec::IdentityClaim`.
   New fields land as `#[serde(default, skip_serializing_if = ...)]`.
   Removal of an existing field is a MAJOR change.
2. **at-proto record content** (`app.provcheck.signingKey` body):
   wire format pinned by `provcheck-attestation-spec::SigningKeyRecord`.
   Same rules: additive minor, removal major.
3. **Watermark payload bytes** (silentcipher 5-byte tagged union,
   audioseal / wavmark 16-bit 3-copy ECC, image BCH-5 100-bit
   secret): payload schema changes require a MAJOR bump. We
   reserve the schema byte at position [3] for silentcipher and
   the version bits at [96..100] for BCH-5 to let new schemas
   coexist with old ones during a migration; see the brand-registry
   doc for the mechanics.
4. **Cache layout on disk** (`provcheck-weights` cache, `kit` data
   dir): changes that invalidate existing operator state are MAJOR.
   Layout additions are minor.

## Patch-release scope

Patches MAY:
- Fix a documented behaviour bug (the function did X, docstring
  says Y — fixing the function so it does Y matches the contract).
- Tighten a security check (e.g. reject a previously-accepted
  malformed input).
- Update tolerated cargo-audit advisories in `SECURITY.md` (per
  the "tolerated transitive advisories" memory note).
- Update test fixtures to track newer upstream releases.

Patches MAY NOT:
- Change a documented function signature.
- Reassign a CLI exit code.
- Bump MSRV.
- Remove a `pub` item from a stable module.

## Yanking

We yank a release from crates.io only when:
- It introduces a security regression.
- It corrupts persistent operator state (a `kit` data-dir migration
  that loses keys, an at-proto record overwrite that nukes
  existing records).

We do NOT yank for:
- A non-corrupting bug.
- A confusing diagnostic message.
- A documentation gap.

For non-yanking cases, ship a patch.

## Reference

- [Public API stability](./public-api-stability.md) — what's in/out
  of the contract.
- [Release process](./release-process.md) — the mechanical gates.
- [SemVer specification](https://semver.org/) — the upstream spec
  this policy implements.
