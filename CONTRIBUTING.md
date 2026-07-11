# Contributing to provcheck

Thanks for your interest in provcheck. This guide covers how to report
issues, propose changes, and get a pull request merged.

## Reporting a bug or requesting a feature

Open an issue on this repository. For a bug report, please include:

- what you ran (the command line, or a short code snippet),
- the input involved, and a small sample file if you can share one,
- what you expected to happen and what actually happened,
- your platform and the output of `provcheck --version`.

For a suspected **security vulnerability**, do not open a public issue.
Follow the private reporting process in [SECURITY.md](SECURITY.md).

## Proposing a change

1. Fork the repository and create a branch off `main`.
2. Make your change, with tests where it makes sense.
3. Open a pull request against `main` with a clear description of the
   what and the why.

Small, self-evident fixes (typos, docs, obvious bugs) are welcome as a
direct PR. For anything larger or design-affecting, open an issue first
so we can agree on the approach before you invest the effort.

## Building and testing

```bash
cargo build --workspace
cargo test --workspace
```

CI runs formatting, linting, and the test suite on Linux, macOS, and
Windows. Before you push, match what CI enforces:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
```

Both should be silent. Any `#[allow(...)]` needs a one-line comment
above it justifying the exception.

Some watermark integration tests need detector model weights, which are
downloaded on demand (`provcheck-kit weights install <family>`). Those
tests skip cleanly when the weights are not present, so a fresh clone
tests green without any extra setup.

## Dependency advisories

`cargo audit` runs in CI against a tolerated-advisory list. The
tolerated set, and the reasoning for each entry, is documented in
[SECURITY.md](SECURITY.md). If you hit a new advisory that is not
already tolerated there, either bump the dependency that pulls it in,
or add a row to SECURITY.md explaining why it is tolerated, in the same
pull request.

## House style

- No em-dashes anywhere: commit messages, code, docs, and user-facing
  strings. Use a comma, parentheses, a colon, a semicolon, or a
  sentence break instead.
- Oxford commas everywhere.
- Match the naming, comment density, and idioms of the surrounding
  code.

## License

provcheck's core crates are Apache-2.0. By contributing, you agree that
your contributions are licensed under the same terms. See
[LICENSE](LICENSE) and
[WATERMARK_LICENSE_POLICY.md](WATERMARK_LICENSE_POLICY.md) for the
details, including the permissive-license requirement for any new
watermark detector family.

Releases are cut by the maintainers.
