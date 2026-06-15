v0.3.2: responsive verify UI + GUI watermark toggle + bundle name fix

Fixes the user-facing "GUI verify hangs for 5+ minutes" complaint
from v0.3.1 on slower hardware. Two real fixes plus a release-page
cosmetic fix; one attempted optimisation reverted after empirical
testing.

## Why this is needed

A user dropped a doomscroll.fm-signed audio file on a v0.3.1 GUI
on a doomscroll-class box (mid-tier Ryzen, freshly booted) and
saw Windows tag the window "(Not Responding)" for over five
minutes before giving up. Two real problems compounded:

  * The silentcipher detector takes ~100s on a 60s audio file
    even on a fast dev box (it's single-threaded tract inference
    on an ONNX graph with no SIMD), so on slower hardware that
    naturally stretches to multiple minutes.

  * The Tauri verify_file command was synchronous, which pinned
    the backend message pump for the duration of the inference.
    Windows tags any window whose main thread stops pumping for
    more than ~5 seconds as "not responding". The result was
    arriving correctly but the user-visible behaviour was a hung
    window.

## What ships

### 1. verify_file is now async + spawn_blocking (app/src-tauri)

The Tauri command body runs inside `tauri::async_runtime::spawn_blocking`,
so the silentcipher inference happens on a worker thread instead
of the IPC dispatcher's thread. Windows no longer flags the window
as not-responding during long verify operations; the user can drag
the window around, the spinner keeps animating, and the result
arrives on the main thread when ready.

Validated locally: dropped a known-marked audio file on the GUI,
window stayed fully responsive throughout the ~10-second verify.
Previous v0.3.2-dev pass (sync command) saw the same window go
"(Not Responding)" for ~10 seconds.

### 2. GUI watermark toggle (app/dist + app/src-tauri)

Identity bar gains a "Run watermark detection" checkbox between
the bsky-handle input and the "Require attested" toggle, defaulted
ON. State persisted to localStorage. The verify_file Tauri
command gains a run_watermark: Option<bool> arg (defaults to true
when absent, so v0.3.1 callers continue to work). When false, the
silentcipher, audioseal, and wavmark detector calls are skipped
on the Rust side.

This is the user-facing kill switch for "I only care about the
C2PA signature, skip the slow watermark scan." A user who flips
the toggle off once never pays the watermark cost again on that
machine until they flip it back on.

### 3. GUI installer bundle naming (.github/workflows/release.yml)

The GitHub release page collapses asset lists past 10 entries
behind a "Show all N assets" expander; the existing Tauri-default
bundle names (provcheck_0.3.2_x64-setup.exe, etc.) sort *after*
the CLI tarballs (underscore > hyphen in ASCII) and end up below
the fold. Users landing on the page saw only CLI tarballs and
concluded there was no installer.

The Stage bundles step in the GUI build job now renames each
bundle to the canonical provcheck-gui-<tag>-<suffix> form before
upload — same prefix shape as the CLI artefacts, so they sort
alphabetically with everything else and stay above the fold.

The internal exe identity (Tauri's bundle metadata) is unchanged
— only the upload filename moves.

## What was tried and reverted

A windowed-inference optimisation was attempted: run the
silentcipher decoder on the first 10 tiles (~10s of audio)
instead of the full carrier. CLI timing on the dev box dropped
from 96s to 15s (a 6.3x speedup), and v0.3.2-dev shipped that
change for several days.

Empirical testing on a known-marked low-SNR file (a
voices_mixdown render that a Python reference decoder identifies
at 95% confidence) showed the windowed approach BREAKS detection
on exactly the regime users care about. The per-position
mode-vote across tiles is silentcipher's primary noise-rejection
mechanism. Cutting tile count from ~50 to 10 throws away the
redundancy that recovers signal from noise.

The full-carrier path is restored. The diagnostic examples that
identified this (examples/decode_inspect.rs and
examples/windowed_validate.rs) ship as part of this commit for
future regression investigation.

## What's NOT in v0.3.2 but is acknowledged

Independent of windowing, the Rust port of the silentcipher
decoder produces noisier logits than the Python reference on
the same input file. On the marked voices_mixdown file:

  * Python reference: 95% confidence, payload [0x44, 0x46, 0x4d, 0x01, 0x00]
    ("DFM" + schema 1) — Detected.
  * provcheck v0.3.2:  24% confidence on the terminator position —
    below the brand-classify threshold, reported as NotDetected.

The terminator IS found at the expected position; the per-tile
prediction is just noisy enough that the brand-classify gate
rejects the result. Both v0.3.0 and v0.3.1 had this same gap
(it's not a v0.3.2 regression). Fixing it is its own
investigation that needs to pin down whether the gap comes from:

  * tract numerical differences vs PyTorch's ONNX runner
  * an FFT normalisation detail we ported incorrectly
  * a model-input layout subtlety
  * something else

The `decode_inspect` example is the harness for that work — it
prints per-stage statistics that can be compared 1:1 against the
Python reference's stats. Out of scope for v0.3.2.

## Tooling

publish_dc.sh's glob array references the GUI bundles by file
extension (.exe, .msi, .deb, etc.), so it picks up the renamed
files automatically. No change needed in the publish step.

The same commit also carries the publish_dc.sh polish prepared
during the v0.3.1 cleanup session but never committed: tee the
script's stdout/stderr to publish_dc-<tag>.log in the repo root
(gitignored), add a loud STEP 9 banner before invoking
publish-release.sh so the user knows the next prompt is the
final-confirmation one, and wrap the publish-release.sh call
with `set +e` so a user-typed 'n' at its prompt is reported as
a clean bail-out rather than a fatal script abort.

## Test surface

Workspace: 201 unit + integration tests, zero failed, six ignored
(OS-keychain integration tests). One pre-existing test was
hardcoded against version 0.3.0; switched to env!(CARGO_PKG_VERSION)
so future bumps don't fail it.

Diagnostic examples that don't ship on the runtime path but live
in the source tree for future use:

  * crates/provcheck-watermark/examples/nnef_validation.rs
    Empirically demonstrates that tract 0.21's NNEF serialiser
    can't write the silentcipher model.

  * crates/provcheck-watermark/examples/detect_profile.rs
    Per-stage timing harness — how we found that ONNX inference
    is 99.8% of the cost.

  * crates/provcheck-watermark/examples/windowed_validate.rs
    Compares full vs windowed inference verdicts. Documents the
    test that surfaced the accuracy regression.

  * crates/provcheck-watermark/examples/decode_inspect.rs
    Per-stage statistical inspector — energy ratio after VCTK
    rescale, carrier shape, logit min/mean/max per dim, argmax
    distribution, mode_per_pos with confidence percentages,
    terminator position. The harness for the underlying
    detector-accuracy investigation.

To support these examples, the audio / model / stft / decode
modules in provcheck-watermark/src/lib.rs are now
#[doc(hidden)] pub instead of private. They don't appear in
rustdoc output and the public detect() API is unchanged.
