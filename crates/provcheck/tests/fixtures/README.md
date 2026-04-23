# Test fixtures

The integration test suite in `../integration.rs` (pending) exercises
`provcheck::verify` against a known set of files covering the
five outcome categories every verifier must handle:

| Fixture                    | Expected outcome                  |
|----------------------------|-----------------------------------|
| `signed-audio.wav`         | `verified: true`, no errors       |
| `signed-image.jpg`         | `verified: true`, no errors       |
| `unsigned.mp3`             | `unsigned: true, verified: false` |
| `tampered.wav`             | `verified: false`, signature mismatch |
| `missing-sidecar.mp3`      | `unsigned: true` (sidecar required, absent) |

Fixtures are generated from rAIdio.bot / vAIdeo.bot outputs where
possible (real C2PA manifests from the production signer) and are
committed to the repo when under 2 MB. Larger fixtures move to
Git LFS or to a release-asset download — decision deferred until
milestone 1 actually needs them.

**Currently empty.** Population is the first task of milestone 2.
