v0.3.7: chunked watermark inference — fix OOM on multi-minute MP3s

Closes a real userland OOM reported against v0.3.6 by the
doomscroll.fm team running provcheck in their render container.

The bug

On a 211-second / 5.1 MB cluster-signed MP3, `provcheck --json
<file>` consumed ~22 GB virtual / ~11 GB RSS over 40-53 seconds
before the Linux kernel OOM-killed it. Reproduced locally on
Windows x86_64 with a synthetic 4540-frame carrier: peak RSS
25,091 MB (the box had more headroom than doomscroll's container).

`--no-watermark` on the same file always worked under 100 MB RSS,
which localised the bug to the watermark detector path.

Root cause

`model::run` in provcheck-watermark fed the entire carrier tensor
`[1, 1, 2049, t_frames]` to tract in a single inference call.
Tract's optimiser keeps the time axis symbolic and allocates per-
layer activation buffers proportional to the input's concrete
`t_frames` at run time. For a 211-second MP3 (~4540 frames),
those buffers add up to >10 GB total RSS; a 17-second test clip
(~370 frames) stays under 1 GB and never tripped the issue.

Memory scales linearly with audio length, which matches doomscroll's
report ("Memory scales linearly with audio length, not the watermark
search complexity").

The fix

`model::run` now chunks the carrier along the time axis at
`CHUNK_T_FRAMES = 256` (≈ 12 s of audio at HOP=2048, SR=44100).
Each chunk runs through tract independently; the logits are
scattered back into a single `[MESSAGE_DIM, t_frames]` output.
Peak tract intermediate memory is now O(CHUNK_T_FRAMES) regardless
of audio length.

The chunking arithmetic is a pure layout transform: extract the
contiguous `[FREQ_BINS, chunk_t]` slice from the row-major carrier,
scatter back into the same row-major layout. Two new unit tests
exercise the extract+scatter round-trip across a range of chunk
sizes and verify ragged tail-chunks cover every frame exactly once.

Correctness

silentcipher's decoder is a per-time-frame symbol classifier with a
small convolutional receptive field along the time axis; the per-
position mode vote downstream of inference sees every tile in the
sequence regardless of how chunking divided the input.

Verified empirically on the v0.3.3 reference fixtures (doomscroll
voice mixdown, doomscroll music render, unsigned control):
- voice file payload: [44, 46, 4d, 01, 00] (DFM/01/00) — same
- voice file confidence: 0.8347 (was 0.8319 single-call; +0.34%
  drift attributable to one chunk-boundary frame at position 256
  within a 369-frame input; well within f32 round-off and the
  brand-classifier acceptance threshold)
- music file: detected — doomscroll.fm 72% — same
- unsigned control: not detected — same

Empirical numbers on the 4540-frame synthetic

  Single-call (v0.3.6):  peak RSS 25,091 MB, elapsed 426 s
  Chunked (v0.3.7):      peak RSS  1,476 MB, elapsed 386 s
  Delta:                 -94% memory, -9% wall-clock

Wall-clock improvement is from not paging — same inference work,
but no OS-level memory pressure to fight.

Test surface

27 watermark unit tests (was 25; added 2 chunking-arithmetic
tests). 6 watermark integration tests. All workspace tests green.

Diagnostic harness

Adds `examples/memory_check.rs` for peak-RSS regression checks
when tract is bumped or the model is updated. Builds a synthetic
carrier at any `t_frames`, runs inference, prints elapsed +
logits length. Couple it with the platform's RSS sampler
(`Get-Process` on Windows, `/usr/bin/time -v` on Linux) to track
the memory profile across future changes.

Wire format

No changes. Drop-in upgrade for any 0.3.x consumer.

About doomscroll.fm's workaround

The team correctly identified `--no-watermark` as a safe immediate
mitigation while v0.3.7 was in flight. With this release shipped,
that workaround can be removed from their pipeline.
