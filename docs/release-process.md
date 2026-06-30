# Release process

The mechanical checklist for cutting a `vX.Y.0` release.

## Overview

A release is a tag (`vX.Y.0`) that fires the full release matrix
(Tauri x 3 OS + verifier + kit + SBOM + cargo audit). Per-run cost
is several hundred Actions unit-minutes — macOS bills at 10x.
This file lists every gate that must fire before pushing the tag.

The iteration tags (`vX.Y.Z` with Z > 0) explicitly skip the matrix
per the `v*.*.0` glob filter in `.github/workflows/release.yml`.
They exist as commit anchors during a pre-release cycle and do NOT
need to satisfy this checklist. See
[`semver-policy.md`](./semver-policy.md) for the categorisation.

## Cadence cap

**Max one `vX.Y.0` tag pushed per 24 hours.** Burning ~€25/week
of Actions credits in a single batch is what prompted this rule
(per the `feedback_release_cadence_budget` memory note from the
v0.4.x ship). Single-tag-per-day exceptions are reserved for:

- Production crashes
- Data-loss bugs
- Security regressions

Anything else waits.

## Pre-flight checklist

Before tagging, all of the following must be true:

### 1. Workspace builds clean

```bash
cargo build --release --workspace
RUSTFLAGS="-D warnings" cargo build --release --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All three silent.

### 2. Tests pass

```bash
cargo test --workspace --release
```

Plus the pre-push regression gate fires automatically via
`.git/hooks/pre-push` running `scripts/check-before-push.sh`:

- Full `cargo test --workspace`
- Parity sweep vs upstream Python silentcipher
- AAC delivery survival smoke (silentcipher + AudioSeal)

~10 minutes. Releases never bypass with `--no-verify`.

### 3. cargo audit clean against tolerated-list

```bash
cargo audit --ignore RUSTSEC-XXXX-YYYY --ignore RUSTSEC-XXXX-ZZZZ
```

The ignored advisories must match the **Tolerated transitive
advisories** table in `SECURITY.md`. Per the
`feedback_tolerated_advisories_watch` memory note: on each pass,
diff against the tolerated table — if any advisory has cleared
upstream, bump the dep and remove the row in the same commit
as the release.

### 4. README changelog row

Add the new row at the top of the changelog table in `README.md`,
under the existing v0.9.x rows. Format:

```markdown
| **vX.Y.0** | YYYY-MM-DD | **One-line headline.** Paragraph
describing the user-facing changes in the cadence the rest of the
table uses. Reference task #s and audit gates if relevant. |
```

The headline is what shows up in the GitHub release page summary.

### 5. Version bump

Three files need to change in lock-step:

- `Cargo.toml` `[workspace.package]` block — `version = "X.Y.0"`
- `app/src-tauri/Cargo.toml` `[package]` block — `version = "X.Y.0"`
- `app/src-tauri/tauri.conf.json` — `"version": "X.Y.0"`

The `app/src-tauri/` files live outside the workspace so they
don't inherit the workspace version; bumping the workspace alone
is not enough.

### 6. SBOMs

```bash
scripts/generate-sbom.sh vX.Y.0
```

Produces three sidecars per binary (verifier + kit):
- `*.cdx.json` (CycloneDX)
- `*.spdx.json` (SPDX)
- `*.sha256` (sha256 sidecar)

Attach to the release.

### 7. Clean-machine verify

Per the `feedback_clean_machine_gate` memory note: verify
`provcheck.exe` on a clean Windows target before tagging. Windows
Sandbox is the fast path (~3 minutes from URL to running
binary). The CRT-static config in `.cargo/config.toml` is what
makes this possible.

Document the verify in the tag annotation (e.g. "Clean-machine
verify: Windows Sandbox 2026-XX-XX, signed sample WAV reports
VERIFIED").

### 8. Public-API stability check

If anything in the **stable** column of
[`public-api-stability.md`](./public-api-stability.md) is changing,
this is a MAJOR (v2.0.0) release, not a minor (v1.X.0). Re-check
against [`semver-policy.md`](./semver-policy.md) before proceeding.

For a minor release, additions to the stable surface go in via
`#[non_exhaustive]` enums or `#[serde(default)]` struct fields.

## Tagging

```bash
git tag -a vX.Y.0 -m "vX.Y.0 — one-line headline"
git push origin main
git push origin vX.Y.0
```

The push to `vX.Y.0` fires:

1. **`.github/workflows/release.yml`** matrix:
   - Linux x86_64 verifier + kit
   - macOS arm64 verifier + kit + Tauri app
   - Windows x86_64 verifier + kit + Tauri app
2. **SBOM upload** to the GitHub release.
3. **cargo audit** workflow as a final guard against pushes that
   slipped past local audit.

Wait for the matrix to finish (~30-45 minutes) before publishing
the release.

## Publishing to crates.io

Once the matrix is green:

```bash
# Workspace order matters — leaves first.
for crate in \
  provcheck-attestation-spec \
  provcheck-weights \
  provcheck \
  provcheck-platform \
  provcheck-sign \
  provcheck-publish \
  provcheck-watermark \
  provcheck-audioseal \
  provcheck-wavmark \
  provcheck-image \
  provcheck-video \
  provcheck-synthid-text \
  provcheck-cli \
  provcheck-kit
do
  (cd crates/$crate && cargo publish --dry-run) || exit 1
done
```

If all `--dry-run`s pass, drop the flag and re-run. crates.io
enforces order (a crate can't publish until its `path =` deps
are already on crates.io); the loop above is the documented
dependency order.

### Not-published crates

- `provcheck-examples` — internal example harness, `publish = false`.

## Public mirror sync

The public mirror at `CreativeMayhemLtd/provcheck` gets the tag
pushed via:

```bash
git push public-mirror vX.Y.0
git push public-mirror main
```

(Assumes a `public-mirror` remote pointing at the public repo. Set
once via `git remote add public-mirror <url>` if absent.)

Strategic-relationship context (per memory note
`feedback_keep_relationship_context_out_of_artifacts`) is NEVER in
the public mirror's commit log. Run `git log -- origin/main..HEAD`
before the public push and scrub any commit that mentions
third-party connections (rAIdio.bot internals, doomscroll.fm
internals, founder intros, etc.).

## Post-release

1. **Issue tracker**: close any task milestones that the release
   closes. Push a comment on any public issue the release fixes
   (per the v0.5.2 / v0.5.3 model of acknowledging the reporter).
2. **Memory update**: write a project-memory entry in the form
   `project_vX.Y.0_shipped.md` summarising what shipped and any
   non-obvious gotchas. Add it to `MEMORY.md` as a one-line index
   entry. (This file is the auto-memory that the CLI reads at
   session start.)
3. **Lead-with-PR-check rule**: per
   `feedback_session_lead_with_pr_check`, the next session should
   start with `gh issue list` + `gh pr list` on both public and
   dev repos.

## Rollback

If a release ships and something serious shakes out within 24h:

- **Yank-worthy** (security regression, data-loss): yank the
  release on crates.io (`cargo yank --vers X.Y.0 <crate>` for each
  workspace crate), publish a fix patch (`vX.Y.1`).
- **Non-yankable** (confusing message, slow path, doc gap): just
  ship `vX.Y.1` with the fix. The single-tag-per-day cadence cap
  has an explicit production-crash exception that covers this.

Document the rollback in the next release's changelog row so
operators reading the table can see the history.

## House style for release commit messages

Per `feedback_style_guide`:
- No em-dashes (use comma, parenthesis, colon, semicolon, or
  sentence break).
- Oxford commas.
- No `Co-Authored-By: Claude` trailer (per
  `feedback_no_claude_coauthor_trailer`).

Example tag annotation:

```
vX.Y.0 — feature line A, feature line B, feature line C

Major: <breaking-change summary if any>
Minor: <new public API summary>
Internal: <test-coverage + refactor summary>

Clean-machine verify: Windows Sandbox YYYY-MM-DD on signed
sample WAV: VERIFIED.

cargo audit: 0 unhandled, N tolerated (see SECURITY.md).
SBOMs: attached.
```

## Reference

- [`public-api-stability.md`](./public-api-stability.md) — what's in
  the contract.
- [`semver-policy.md`](./semver-policy.md) — which version-component
  changes for which kind of change.
- [`sbom.md`](./sbom.md) — SBOM generation details.
- `SECURITY.md` (workspace root) — tolerated advisories table.
- `CONTRIBUTING.md` (workspace root) — pre-push gate + cadence rule.
