# Public API stability — v1.0 contract

This file defines which Rust APIs ship under provcheck's semver
contract starting at v1.0.0, and which are explicitly **unstable**
or **internal**. The goal is to make breakage predictable: if you
depend on a crate from this workspace, you can read this file once
and know what we promise.

## tl;dr

| Crate                          | Public API stability       | What you can depend on              |
|--------------------------------|----------------------------|-------------------------------------|
| `provcheck`                    | **Stable**                 | `verify`, `verify_with_options`, `Report`, `WatermarkResult`, prelude |
| `provcheck-attestation-spec`   | **Stable**                 | Lexicon types + wire-format helpers |
| `provcheck-cli`                | **Stable** (binary surface)| Exit codes, JSON shape, flag names  |
| `provcheck-kit`                | **Binary stable**          | Subcommand surface + exit codes     |
| `provcheck-sign`               | **Library stable**         | Signing + persistence + backup APIs |
| `provcheck-publish`            | **Library stable**         | Records + session types             |
| `provcheck-watermark`          | Stable: `detect`, `embed`, `Report`-facing types. **Unstable**: STFT / encoder internals (`stft::*`, `encode::transform_message_chunk`, etc.) |
| `provcheck-audioseal`          | Stable: `detect`, `embed`. **Unstable**: model internals |
| `provcheck-wavmark`            | Stable: `detect`, `embed`. **Unstable**: model internals |
| `provcheck-image`              | Stable: `detect`, `embed`, `classify_bch5`. **Unstable**: ONNX model loading helpers |
| `provcheck-video`              | Stable: `detect`           | Per-frame TrustMark + temporal vote |
| `provcheck-synthid-text`       | Stable: `detect`           | Word-tokenizer + Bayesian z-score   |
| `provcheck-weights`            | Stable: `entry`, `load_if_cached`, `download`, `MANIFEST` | Cache layout, family/variant names |
| `provcheck-detect`             | **Stable** (trait + types). v1.0 plumbing — ships no model weights | `Detector` trait, `DetectorRegistry`, `DetectionFamily`, `DetectionStatus`, `DetectionResult`, `DetectorError` |
| `provcheck-platform`           | Stable: attestation entry points + `AttestationConfig` / `AttestationOptions` |

**Unstable / internal** items are either marked `#[doc(hidden)]`,
live in modules whose names start with `_`, or are documented as
"may break between minor releases" in their item docstring.

## What "stable" means for each crate

### Stable means

For an item marked stable, we promise:

1. **Function signatures don't change** in a v1.x release without
   a deprecation cycle (one minor release minimum).
2. **Public types don't lose fields** without a deprecation cycle.
3. **Enum variants don't get reordered** in a way that affects
   serde / wire-format readers.
4. **Documented behaviour holds**. If a docstring says
   "returns `Some` iff X", and X is true, the function returns
   `Some`. Bugs that violate the docstring are fixable in a patch.
5. **Error variants don't disappear**. New `#[non_exhaustive]`
   variants may be added in minor releases.

### Stable does NOT mean

1. **Wall-clock performance** is not part of the contract. A v1.x
   detector may run slower than v1.(x-1) under some workloads;
   regressions worth optimising land in patches but aren't
   semver-breaking.
2. **Detector confidence numbers** are not part of the contract.
   The `Detected` / `Degraded` / `NotDetected` bands are stable
   (gated by `provcheck::confidence::DETECTED_THRESHOLD`); the
   raw `confidence: f32` value is best-effort. A re-trained model
   shipped in v1.x may shift the absolute value.
3. **Operator-facing message strings** in `WatermarkResult::message`
   are best-effort. We pin some via regression tests when an
   operator workflow depends on the exact phrasing (e.g. the
   `kit login` hint in `SessionExpired`), but the general rule is
   that messages are informational, not API.

## Binary surface stability (the CLIs)

### `provcheck` CLI

Stable across v1.x:

- Positional arg: input file path.
- Documented flags: `--json`, `--trust-store`, `--require-trusted`,
  `--require-attested`, `--require-watermark`, `--no-watermark`,
  `--bsky-handle`, `--did`, `--auto-identity`,
  `--no-attestation-cache`, `--bsky-api`, `--no-fail-on-unsigned`.
- Exit codes (the load-bearing automation contract):
  - **0**: verified, or `--no-fail-on-unsigned` and unsigned
  - **1**: cryptographic failure OR gate (`--require-*`) demoted
  - **2**: usage error / file IO / malformed PEM / clap parse error
- JSON output shape: matches `provcheck::report::Report` serde
  (camelCase via serde rename, `skip_serializing_if = "Option::is_none"`
  for optional fields, `Vec::is_empty` for empty `watermarks` /
  `parents`).

### `provcheck-kit` CLI

Stable across v1.x:

- 18 documented subcommands: `init`, `status`, `login`, `logout`,
  `sign`, `publish`, `list`, `revoke`, `rotate`, `verify`,
  `export-backup`, `import-backup`, `unlock`, `lock`,
  `change-passphrase`, `add-recovery-recipient`,
  `list-recovery-recipients`, `remove-recovery-recipient`.
- Exit-code routing:
  - **0**: success
  - **1**: command-specific failure
  - **2**: usage error / clap parse error
  - **3**: atproto session expired (CLI suggests `kit login`)

Subcommands may gain new flags in minor releases. Flag removals
require a deprecation cycle.

## How to find the "unstable" boundary

Look for any of these signals:

- `#[doc(hidden)]` — explicitly internal, not part of the contract.
- Module name starts with `_` (e.g. `_send_sync_assertions`) —
  test-only or internal-helper module.
- A docstring containing the phrase **"may break between minor
  releases"** or **"unstable internal"** — explicit unstable marker.
- Items in `provcheck-{audioseal,wavmark,watermark}::model::*`
  and `provcheck-watermark::stft::*` past `compute_n_frames` —
  STFT / model-loading internals; tracked by tests but not part
  of the consumer contract.

## What we will NOT do

- Re-export third-party types in a way that locks our consumers
  to a specific upstream version. If we re-export `c2pa::SigningAlg`
  it's via the `parse_algorithm` helper, not as a `pub use`.
- Add `pub fn`s with name collisions that would break glob
  imports.
- Change the documented byte layouts of any wire-format constant:
  `PAYLOAD_RAIDIO` / `PAYLOAD_DOOMSCROLL` / `PAYLOAD_VAIDEO`
  (silentcipher), `BRAND_*` / encode-decode round-trip
  (audioseal / wavmark registries), `PROVCHECK_RAW_MAGIC` /
  `VERSION_BCH5` / `DATA_LEN` / `SECRET_LEN` (image BCH-5),
  `COLLECTION_NSID` / `IDENTITY_ASSERTION_LABEL` (lexicon).
  Pinned by tests across v0.9.x.

## Crates we MAY publish to crates.io

A `[publish = true]` Cargo.toml field is the marker for crates we
intend to push to crates.io once we ship v1.0:

- `provcheck` (the verifier library) — definitely
- `provcheck-attestation-spec` — definitely (downstream verifiers
  read it)
- `provcheck-cli` — yes, ships the `provcheck` binary
- `provcheck-kit` — yes, ships the `provcheck-kit` binary
- `provcheck-watermark`, `provcheck-audioseal`, `provcheck-wavmark`,
  `provcheck-image`, `provcheck-video`, `provcheck-synthid-text`
  — yes, for ecosystem integrators
- `provcheck-detect` — yes; the public Detector trait that
  operators implement against to wire in their own AI-content
  detector (commercial paid-DLC pack OR existing open-source
  third-party detector)
- `provcheck-platform`, `provcheck-sign`, `provcheck-publish`,
  `provcheck-weights` — yes; they're the load-bearing pieces

Crates intentionally NOT published:

- `provcheck-examples` — internal example harness only.

## When this contract changes

Bumping the major version (v2.0.0) is the only way to break any
"stable" guarantee above. Documented unstable items can change
in any release; we just won't surprise consumers about it.

See also: [`semver-policy.md`](./semver-policy.md),
[`release-process.md`](./release-process.md).
