# Test fixtures

The integration test suite in `../integration.rs` exercises
`provcheck::verify` against synthesised fixtures generated at run-time
(no checked-in binaries), covering the outcome categories every
verifier must handle:

| Generated fixture          | Expected outcome                  |
|----------------------------|-----------------------------------|
| Silent WAV + ES256 cert    | `verified: true`, no errors       |
| Unsigned WAV               | `unsigned: true, verified: false` |
| Tampered (signed → flipped)| `verified: false`, validation_errors > 0 |
| Plain text file            | `unsigned: true`, format-not-supported |

The integration suite generates everything it needs at test time:
- Audio: 0.1-second silent WAV via `hound` — zero audio content, no
  copyright question, identical bytes across runs.
- Certs: ES256 CA + EE chain via `rcgen` — matches rAIdio.bot's
  per-install signing pattern.

There are no checked-in binary fixtures because nothing the test
suite needs has a meaningful "real-world" value that synthesis
can't reproduce.

The suite has 13 tests covering verify + unsigned + tampered +
non-media paths. Future fixture additions (real Adobe TrustMark
watermarked images, etc.) would land here as release-asset
downloads gated behind an `--ignored` test, not as checked-in
binaries.

If the integration suite ever genuinely needs a checked-in binary
fixture, the decision matrix is:
- Under 200 KB → commit as-is.
- 200 KB to 2 MB → commit with a clear justification in commit
  message.
- Over 2 MB → release-asset download with SHA-pinned manifest entry
  in `provcheck-weights` style.
