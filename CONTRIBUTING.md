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

## Release cadence

Max one `v*` tag pushed per 24 hours. The release workflow's
build matrix (Tauri x 3 OS + per-OS build minutes + macOS at 10x
billing) is expensive — batch your changes into one tag rather
than landing three patch tags in a row.

Single-tag-per-day exceptions are reserved for production
crashes or data-loss bugs. Document the exception in the tag's
annotation message.

## Style + clippy

CI runs `cargo clippy --workspace --all-targets -- -D warnings`.
Before pushing, run the same locally:

```bash
RUSTFLAGS="-D warnings" cargo build --release --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Both should be silent. Any `#[allow(...)]` needs a justifying
one-line comment above it.
