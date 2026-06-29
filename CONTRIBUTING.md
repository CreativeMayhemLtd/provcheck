# Contributing to provcheck

Thanks for digging in. This file documents the few conventions
that aren't obvious from the code.

## Pre-push gate

`scripts/check-before-push.sh` runs automatically via
`.git/hooks/pre-push` and exercises:

1. `cargo test --workspace` (every test in every crate).
2. Parity sweep vs upstream Python silentcipher.
3. AAC delivery survival smoke (silentcipher + AudioSeal).
4. Pre-installs detector weights for the gate harness so the
   tests can hit real model paths.

The gate runs in ~10 minutes. Don't bypass with `--no-verify`
unless you have a documented reason in the commit body. Releases
never bypass.

## cargo audit

Run with the same `--ignore` set the release workflow uses so
your local view matches CI:

```bash
cargo audit \
  --ignore RUSTSEC-2023-0071 \
  --ignore RUSTSEC-2024-0436 \
  --ignore RUSTSEC-2024-0370 \
  --ignore RUSTSEC-2026-0173 \
  --ignore RUSTSEC-2025-0136 \
  --ignore RUSTSEC-2026-0097
```

The ignored IDs mirror `SECURITY.md`'s tolerated table exactly.
If you see a new advisory not on the ignore list, you have two
choices: bump the dep that pulls in the advisory's crate, OR
add a row to SECURITY.md (and the workflow's `--ignore` list)
in the same commit, with a sentence explaining why it's
tolerated.

## House style

- No em-dashes anywhere (commit messages, code, docs, user-facing
  strings). Use commas, parentheses, colons, semicolons, or a
  sentence break instead.
- Oxford commas everywhere.
- Commit messages don't carry a `Co-Authored-By: Claude` trailer.

## Release cadence + tag conventions

**Two tag categories** — the release workflow distinguishes them
via glob filter on `.github/workflows/release.yml`:

- **`vX.Y.0` (major / minor release tags)** — fire the full
  release matrix (Tauri x 3 OS + verifier + kit + SBOM + cargo
  audit). Per-run cost is several hundred Actions unit-minutes
  (macOS is 10x billed). Max one of these per 24 hours. Single-
  tag-per-day exceptions reserved for production crashes or
  data-loss bugs; document in the tag annotation.

- **`vX.Y.Z` where Z > 0 (patch / iteration tags)** — do NOT
  fire the release matrix. These exist as commit anchors only.
  Use them freely during a pre-release iteration cycle (e.g.
  v0.9.1, v0.9.2, ... during a test-coverage push). They land
  in the dev repo, get test-coverage credit, but burn zero
  Actions minutes.

To **force a build** for a patch tag (e.g. you need release
artefacts for v0.9.5), trigger the workflow manually via the
`workflow_dispatch` input on the Actions UI and supply the tag
name. This is the explicit-opt-in escape hatch for one-off
patch ships.

The release matrix and ship-day gates (clean-machine verify,
README changelog row, SBOMs, cargo audit clean) still apply
to every `vX.Y.0` tag without exception.

## Style + clippy

CI runs `cargo clippy --workspace --all-targets -- -D warnings`.
Before pushing, run the same locally:

```bash
RUSTFLAGS="-D warnings" cargo build --release --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Both should be silent. Any `#[allow(...)]` needs a justifying
one-line comment above it.
