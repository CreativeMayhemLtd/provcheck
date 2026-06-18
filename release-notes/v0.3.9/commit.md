v0.3.9: detector early-exit + parallel chunks + CI fix

Two-part release: a wall-clock speedup for the watermark detector
that should have shipped in v0.3.8 alongside the embedding work, plus
a CI fix for a rustdoc trap that turned v0.3.8's CI red on every
platform.

Detector early-exit + parallel chunks

The v0.3.7 chunked detect was sequential (one chunk at a time) and
processed every chunk regardless of whether the watermark was
already confidently recovered. v0.3.9 changes both:

  - **Parallel chunks.** Up to `min(available_parallelism / 2, 4)`
    chunks process concurrently per batch via rayon. Each chunk
    still peaks at ~1.5 GB of tract intermediates, so the 4-chunk
    cap keeps batch peak around 6 GB — well under typical container
    memory ceilings.

  - **Confidence-based early exit.** After each batch the partial
    logits are decoded; if the per-position mode vote already
    reports confidence ≥ 0.85, the loop returns immediately. The
    0.85 threshold is well above the brand-classifier "Detected"
    tier (0.70) so a fast-path verdict can't downgrade as more
    tiles would have come in.

Empirical numbers on the v0.3.8 marked 60-second WAV
(Windows release build; Linux is typically 2-4x faster):

  v0.3.8 (sequential):              98.5 s detect wall-clock, 88% confidence
  v0.3.9 (parallel + early exit):   22.2 s detect wall-clock, 92% confidence
                                    => 4.4x speedup, no accuracy regression

Phase A was originally scoped for v0.3.8 alongside Phase B (the
embedding capability). It got dropped from v0.3.8 to focus on
shipping the embed pipeline; v0.3.9 ships it as intended.

CI fix — encode.rs:246 rustdoc trap

v0.3.8 shipped to the public mirror successfully (artifacts built,
binaries work) but its workspace CI run came back red on macos,
ubuntu, and windows. Cause: `transform_message`'s doc comment in
`crates/provcheck-watermark/src/encode.rs` contained two indented
lines of Python pseudocode

  ///     output = self.linear(msg.transpose(2, 3)).transpose(2, 3)
  ///     output = F.pad(output, ...)

which rustdoc interpreted as a Rust code block (4-space indent
inside a /// comment is the markdown "indented code block"
trigger) and tried to compile. Both lines failed with
`expected one of '!' or '::', found '='` because `output = ...`
isn't a valid Rust statement at file scope.

The local `cargo test --workspace` runs that gated v0.3.8 didn't
include doctests for the watermark crate by default (no
`#[cfg(doctest)]` attributes triggering a re-collect), so the
trap survived. v0.3.9 fences the pseudocode block as
`\`\`\`python` so rustdoc tags it as a foreign language and
skips compilation.

Implementation notes

`detect_chunked` is the new internal helper that runs the loop.
It uses the same `extract_chunk` / `scatter_chunk_logits` /
`run_chunk_owned` primitives v0.3.7 added to the `model` module
(those were made public-ish back then specifically so the lib
detect path could drive its own chunking).

The early-exit decode happens against a temporary
`pack_partial_logits()` buffer because `decode_logits`'s indexing
math depends on the buffer's time-axis dimension equaling the
`t_frames` argument it receives. Cost: O(MESSAGE_DIM * t_consumed)
copy per batch — at MESSAGE_DIM=5 and a typical 256-frame chunk,
that's ~5 KB of work — negligible vs the ~5-second tract inference
each chunk costs.

Test surface

29 watermark unit tests (was 27; +2 for chunk-scatter math).
6 watermark integration tests. Doctest now compiles clean
(the rustdoc fence). All workspace tests green.

Wire format

No CLI behaviour or wire-format changes. Detection produces the
same payload + brand verdict as v0.3.8 in less wall-clock time.

For doomscroll.fm

If you're verifying hour-long episodes as a QA gate, the speedup
is roughly:

  before: ~17 minutes wall-clock per hour of audio (linear-in-length)
  after:  ~4 minutes for a marked file with early exit firing
          ~5 minutes for a fully-traversed unmarked file (parallel only)

Container update: `ARG PROVCHECK_VERSION=v0.3.9`.
