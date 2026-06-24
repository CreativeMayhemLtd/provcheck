# Follow-up: silentcipher reliability on C2PA-signed MP3s (resolved in v0.5.x)

This is a follow-up to the main
[v0.3.3 detection-gap investigation](./README.md). v0.3.3 closed the
bare-MP3 silentcipher accuracy gap (0.49 → 0.95 confidence on the
canonical test file). A separate but adjacent issue survived
v0.3.3 in production: the **same fix applied less cleanly when the
MP3 was wrapped in a C2PA manifest**, producing intermittent
detection at degraded confidence on signed files. This was
discovered fixed somewhere in the v0.5.x line during a downstream
cargo-install migration on 2026-06-24.

This doc records what we observed so the next person who runs into
a "v0.3.3 verifier on signed MP3" question has a single place to
read it, and so the regression-harness machinery in this directory
gains an additional fixture pattern (sign-then-verify, not just
bare-MP3 verify) for any future change that might reopen it.

## What we saw on v0.3.3 (post the detection-gap fix)

Reproducer protocol (run against a fresh doomscroll RANDOMTOONER
render, ~30 s mono MP3 with a known SilentCipher mark):

1. **Independent decoder on the unsigned file** (Sony silentcipher
   1.0.5 Python package directly, no C2PA involvement, via
   librosa.load): consistent `confidence ≈ 0.88`, payload
   `[68, 70, 77, 1, 0]` (`"DFM" + schema=1 + reserved=0`).

2. **Sign the file with `provcheck-kit 0.3.3`**: `ok: true`,
   manifest_bytes ≈ 13 KB. C2PA writes into the MP3 metadata frames
   — the audio data is byte-identical pre/post-sign (file size
   grows by exactly the manifest size).

3. **Independent decoder on the signed file**: same confidence
   (0.88), same payload — confirming the watermark survived signing
   cleanly in the PCM.

4. **`provcheck 0.3.3` verify on the signed file**: split outcome
   across the corpus, deterministic per-file:

   | Behaviour | Frequency on doomscroll voice-mixdown corpus |
   |---|---|
   | `silentcipher: detected — doomscroll.fm (XX%)` | ~50–60% of signed files |
   | `silentcipher: not detected` | ~40–50% of signed files |

   C2PA verification itself was unaffected — `[VERIFIED]` printed
   on every run regardless of the watermark outcome.

The miss was deterministic per-file (same file always missed; same
file always hit) but split across files from the same render
pipeline with no obvious audio-content predictor. Consistent with
a sample-alignment / decoder-priming issue inside the verifier's
C2PA-wrapped MP3 read path — same shape of bug as the v0.3.3
detection-gap fix, but on a different code path (the wrapped reader
rather than the bare reader).

## What we see on v0.5.3 against the same files

Tested 2026-06-24 on the Doomscroll 4090 host during the migration
from a baked v0.3.3 tarball to `cargo install --git --tag v0.5.3`.
Same shared cluster signing key, same MP3 source files:

| Aspect | v0.3.3 verifier | v0.5.3 verifier |
|---|---|---|
| v0.3.3-signed file, silentcipher confidence | **52 % (degraded)** | **94 %** |
| v0.5.3-signed file, silentcipher confidence | n/a | **93 %** |
| watermark time-range reporting | absent | `marked: 0:00–0:20` (new in v0.4.2) |
| audioseal / wavmark detectors | `n/a (impl pending)` | real `detected` / `not detected` |
| backwards-compat (v0.5.3 verifier on pure v0.3.3 file) | n/a | `[VERIFIED]`, identity intact, mark detected |

The marks were always at full strength in the audio — the v0.3.3
verifier just couldn't read them reliably through the C2PA wrapper.
v0.5.x resolves it. We didn't bisect the exact commit — the
recovery was observed in the wild on a downstream upgrade, not in
a targeted fuzz. Candidate causes from the v0.4.x → v0.5.x
shortlog that touched audio decode / priming:

- v0.3.3's bare-MP3 priming fix (`08a9bad`) — established the
  pattern but didn't generalise to wrapped reads.
- v0.4.x — multi-detector unification + symphonia-version updates
  in the watermark crates.
- v0.5.1 (`4fe6230`) — silentcipher embed memory rework that also
  touched the decode helper.
- v0.5.3 (`5168058`) — AAC-in-MP4/M4A `effective_priming()` helper
  added the "if codec is AAC and `codec_params.delay` is None,
  hardcode 1024" pattern. Same shape of fix as a hypothetical
  "if codec is MP3 and priming is missing, hardcode LAME default"
  would take — possible the wrapped read started routing through
  this path here.

## Regression-harness extension

The existing harness in this directory (`scripts/v0.3.3-investigate.sh`
+ the `decode_dump` / `decode_diff` / `align_check` example
binaries) fingerprints divergence per-stage on a bare audio input.
Any future change to the watermark crates' audio decode path
should ALSO run this end-to-end protocol against a C2PA-signed
input, since the wrapped read is what regressed in v0.3.3:

```bash
# Set up a fixture pair (run once, store outputs anywhere convenient)
SRC=path/to/known-marked-source.mp3
cp "$SRC" /tmp/bare.mp3
provcheck-kit sign /tmp/bare.mp3 --action created -o /tmp/signed.mp3

# Bare-MP3 regression check (the existing v0.3.3 protocol)
scripts/v0.3.3-investigate.sh /tmp/bare.mp3

# Signed-MP3 regression check (NEW — what this follow-up records)
provcheck --json /tmp/signed.mp3 \
  | jq '.watermarks[] | select(.kind == "silentcipher")'
# Expected: detected == true, confidence ≥ 0.85, payload matches
# the bare-MP3 reading from the harness.
```

A fixture corpus of ~10 signed MP3s spanning multiple render
sources and durations is sufficient to catch the split-outcome
shape of the v0.3.3 regression. If the wrapped read regresses
again, the per-file confidence will visibly bimodal-distribute
(some at 0.0, some at 0.5–0.9) rather than uniformly degrade.

## Why this is filed in `docs/`, not as a bug

There's nothing to fix in the current code — v0.5.3 reads the
signed corpus cleanly. The value is twofold:

1. **Closure on the v0.3.3 thread.** Anyone reading the main
   detection-gap README who later wonders "did the wrapped-read
   version of this ever get fixed" can find the answer here.
2. **Harness coverage.** Recording the signed-MP3 protocol
   alongside the bare-MP3 protocol means a future MP3-decode
   change can't silently regress C2PA-wrapped reads without
   tripping a documented check.

If the wrapped-read regression ever reproduces in a newer release,
this doc becomes the starting point: extend the per-stage
fingerprinting harness onto the wrapped reader, diff against the
bare reader's stage output on the same file, and look for the
divergence point.
