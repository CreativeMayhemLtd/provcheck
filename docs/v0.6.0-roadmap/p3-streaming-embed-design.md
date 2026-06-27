# P3 design — streaming STFT embed

This document scopes the v0.6.0 P3 work (streaming STFT embed) before
the refactor starts. Goal: per-process peak RSS drops below 300 MB on
a 65-minute episode (currently 1.5-2 GB), without breaking output
bit-equivalence with the v0.6.0 P1+P2 baseline.

## Current memory profile, by allocation

After the v0.6.0 P1 chunk-parallel embed lands, the embed pipeline
on a 65-minute stereo episode peaks roughly here, in allocation
order:

| Buffer | Lifetime | Peak size on 65-min episode |
|---|---|---|
| Input PCM (per channel) | full embed | ~688 MB per channel × 2 = ~1.4 GB |
| Rescaled waveform | STFT window only | ~688 MB (dropped after STFT consumes it) |
| `spec.magnitude` (`FREQ_BINS × n_frames`) | full embed | ~700 MB |
| `spec.phase` (`FREQ_BINS × n_frames`) | full embed | ~700 MB |
| `msg_enc_5` (`MESSAGE_DIM × n_frames`) | full embed | ~1.7 MB (negligible) |
| Per-chunk `extract_carrier_chunk` | per chunk | ~17 MB |
| Per-chunk `transform_message_chunk` | per chunk | ~17 MB |
| Per-chunk `info_raw` (tract output) | per chunk | ~17 MB |
| Per-chunk `chunk_reconst` | per chunk | ~17 MB |
| Tract intermediates (per inference) | per inference | ~1.5 GB |
| `carrier_reconst` (full) | full embed | ~700 MB |
| iSTFT working buffer | iSTFT window | ~700 MB |
| Output waveform | full embed | ~688 MB |

The full-lifetime buffers (input PCM, `spec.magnitude`, `spec.phase`,
`carrier_reconst`) hold roughly 3.5 GB on a 65-minute stereo episode.
The transient peaks during STFT and iSTFT push it higher. The v0.5.1
OOM-fix cut the message-projection peak but did not touch the full-
length carrier and phase tensors.

To drop to a 300 MB ceiling we need to stream three things:

1. **Forward STFT**: emit (magnitude, phase) frames as the input
   waveform decoder yields them. Pass each frame into the chunk
   builder, NOT into a full-length spectrogram.
2. **Inverse STFT**: overlap-add chunk outputs into a ring buffer
   the size of the iSTFT window plus one hop. Flush samples as they
   become final.
3. **Output waveform**: write samples to disk as they become final
   from the iSTFT ring buffer. Do not buffer the whole output.

## Streaming chunk size

silentcipher's per-position mode vote at decode requires the decoder
to see all tiles, but the embedder can stream because each tile's
embed is independent at the symbol-stream level. The streaming-chunk
size must:

- Be a multiple of `CHUNK_T_FRAMES` (the existing per-chunk ONNX
  inference unit).
- Be at least one silentcipher tile wide so the message projection
  cycle is intact. One tile is `MESSAGE_LEN * HOP / SAMPLE_RATE
  ≈ 0.975 s` at 44.1 kHz; CHUNK_T_FRAMES corresponds to about
  ~5 seconds. So one chunk is already ~5 tiles wide; this constraint
  is satisfied trivially.
- Be small enough that the per-chunk peak (input frames + tract
  intermediates + chunk_reconst) stays under the 300 MB target.

Concretely: the streaming unit is one `CHUNK_T_FRAMES` chunk
(~5 sec of audio = ~10 MB of frames at f32). The streaming buffer
holds one chunk's worth of magnitude + phase + message frames =
~30 MB. tract's per-inference intermediates dominate; that's
already ~1.5 GB and is unchanged by streaming.

**This is the gotcha:** tract's per-chunk intermediate peak of
~1.5 GB is the floor. Streaming the input/output buffers drops the
full-lifetime ~3.5 GB to ~30 MB, but the per-chunk tract peak
stays. So the realistic target after P3 is roughly:

- Per-chunk tract intermediates: ~1.5 GB
- Streaming buffers (input + output + chunk extracts): ~50 MB
- Model + glue: ~100 MB

**Realistic peak: ~1.7 GB**, not 300 MB. The 300 MB number in the
v0.6.0 roadmap was aspirational and based on the spectrogram
buffers alone; it ignored tract's per-inference peak.

**Two options to actually hit 300 MB:**

A. Use the v0.6.0 P4 ORT backend. ORT with CUDA EP keeps the model
   on GPU memory, so host RAM only needs the chunk extracts and
   streaming buffers (~50 MB peak). The 300 MB target is hit
   trivially on a GPU host.

B. Stay on tract CPU, but cap concurrent chunks to 1 (no parallelism
   between chunks). With one chunk in flight at a time, only one
   tract intermediate buffer exists. Peak: ~1.5 GB + streaming
   buffers ~50 MB + model ~100 MB ≈ **1.65 GB**.

So the realistic v0.6.0 P3 target on CPU is ~1.7 GB peak (down from
~3.5 GB today), unlocking 4-wide concurrency on a 16 GB host
instead of 2-wide. On a CUDA host (post-P4) the same code path
drops to ~300 MB peak. The roadmap's `300 MB` cell was
aspirational for a single chunk, not a Ryzen-host-with-tract reality;
the doc is updated below to reflect the new number.

## Phase-by-phase plan

### Phase 3a — Streaming forward STFT

**Touchpoints:** `crates/provcheck-watermark/src/stft.rs`,
`crates/provcheck-watermark/src/encode.rs`.

Refactor `waveform_to_spectrum` from "consume slice, return
`Spectrum`" to a frame-emitting iterator. The streaming consumer in
encode.rs accumulates one chunk's worth of (magnitude, phase) frames,
hands them to the encoder, then discards them as the chunk loop
advances.

Risk: existing detection path also uses `waveform_to_carrier` (note
the name difference — detect uses just the magnitude). That path
must stay unchanged in v0.6.0 P3 because the detector's mode vote
requires full-length input. Either fork the API into
`stream_to_carrier_iter` for embed and keep the full-load
`waveform_to_carrier` for detect, or refactor the detector too.
**Decision: fork the API.** Touching detect for streaming is out
of scope for P3.

### Phase 3b — Streaming overlap-add iSTFT

**Touchpoints:** `stft.rs::spectrum_to_waveform`,
`crates/provcheck-watermark/src/encode.rs`.

Replace `spectrum_to_waveform` "consume full Spectrum, return full
waveform" with an overlap-add ring buffer that accepts (magnitude,
phase) per chunk and emits samples as they become final.

The overlap-add algorithm: for window size W = 4096 and hop H = 2048
(50% overlap), each chunk's iFFT produces W samples that overlap
the previous chunk's tail by W-H = 2048 samples. The ring buffer is
W samples wide, accumulating contributions from each chunk; samples
exit the buffer when their final value is locked (i.e. when the
next chunk no longer contributes to them).

Boundary correctness is the load-bearing concern. Test with the
existing real-audio embed roundtrip + a new test that compares
streaming output to non-streaming output sample-by-sample.

### Phase 3c — Streaming output

**Touchpoints:** `crates/provcheck-kit/src/commands/mod.rs`
(watermark subcommand, `write_wav`).

Replace the current "collect full waveform, then write WAV" with a
`hound::WavWriter` that accepts samples as they emerge from the
overlap-add buffer. Mostly mechanical.

For the stereo path: two writers (one per channel), interleaved
into the same WAV. hound's API supports per-sample writes so this
maps cleanly.

### Phase 3d — Cap concurrent chunks to 1 (CPU only)

**Touchpoints:** `crates/provcheck-watermark/src/encode.rs`.

The P1 chunk-parallel embed runs up to 4 chunks concurrently to
hit 2.5-3x throughput on Ryzen. Streaming gives us peak-RSS wins
ONLY when we reduce concurrent chunks to 1 (otherwise N tract
intermediates pile up).

Trade-off: P1 (4-wide tract) gives 2.5-3x throughput at ~1.5 GB
peak per chunk × 4 = ~6 GB total peak. P3 streaming with 1-wide
gives 1x throughput at ~1.7 GB total peak.

**Resolution:** add a `--memory-budget {default, low}` flag on
`kit watermark`. Default keeps P1's 4-wide parallelism. `low`
forces 1-wide streaming for memory-constrained hosts. Operators
running 16 GB Linux containers (doomscroll's case) pick `low` for
4-wide horizontal concurrency at the orchestrator level.

## Output bit-equivalence

The streaming refactor MUST produce output identical (within f32
precision) to v0.6.0 P2's output on the same input. The existing
`real_silentcipher_embed_roundtrips_to_detection` integration
test catches gross errors. P3 adds a new test:
`streaming_embed_matches_full_load_embed` — compares the streaming
path's output WAV against the full-load path's output WAV
sample-by-sample, asserting max abs diff < 1e-4 (the f32 noise
floor for overlap-add with 50% Hann).

## Test fixtures needed

P3 needs a representative input at scale for memory benchmarking:

- 5-minute stereo 44.1 kHz reference clip (already in fixtures).
- 30-minute stereo 44.1 kHz episode-shape clip (NEW). Build from
  concatenating the 5-minute clip 6 times if no licensed source is
  available; the streaming math is duration-invariant so any
  representative shape works.
- 65-minute stereo 44.1 kHz "world_news" shape (NEW). Same approach.

RSS profile per test fixture, captured via `ps -o rss` polling at
1 Hz during the embed.

## Effort estimate (revised)

Original v0.6.0 roadmap: 2-3 weeks for P3.

Revised after this design pass:

- 3a streaming forward STFT: ~5 days. The STFT loop is small but
  reflexive: the existing implementation pre-pads, windows, FFTs;
  streaming needs careful tail handling.
- 3b streaming overlap-add iSTFT: ~5 days. The ring buffer math is
  load-bearing; needs regression test against full-load output.
- 3c streaming output: ~1 day. Mostly mechanical.
- 3d concurrent-chunk cap + `--memory-budget` flag: ~2 days.
- Test fixtures + RSS benchmarking + regression: ~3 days.

Total: **~16 days = ~3 weeks** of focused single-maintainer work.
No change to the v0.6.0 roadmap's overall estimate, but the
breakdown is now concrete.

## Risks + open questions

1. **What does symphonia's decoder emit as a stream?** If the
   decoder loads the entire file into memory before yielding
   frames, P3a's streaming gain is illusory until we also stream
   the decoder. symphonia's API does support frame-by-frame
   decoding (`format.next_packet()` + `decoder.decode()`) which
   matches what we want. Confirm with a memory profile on a
   65-minute MP3 before starting 3a.
2. **iSTFT boundary phase coherence.** Each chunk's iFFT is
   independent. The Hann-windowed overlap-add stitches them but
   relies on the phase being continuous at chunk boundaries.
   silentcipher's per-chunk phase comes from the input STFT's
   phase tensor, which IS continuous, so this should be fine. But
   we need a regression test that catches phase discontinuities
   if they appear (compare downstream detect conf on streaming
   vs full-load).
3. **--memory-budget naming.** The flag could equivalently be
   `--low-memory` (boolean) or `--concurrent-chunks N` (integer).
   The integer form is more flexible (N=2 is intermediate) but
   the boolean is friendlier. **Decision: integer with a
   default that mirrors P1's existing rayon cap.** Easier to
   reason about for operators.

## Out of scope for P3 specifically

- Refactoring the detector (`crates/provcheck-watermark/src/lib.rs::
  detect_chunked`) to also stream. Detect requires all tiles for the
  mode vote; streaming it is a v0.7.x problem.
- Streaming on AudioSeal or WavMark. Both already have smaller
  per-process memory ceilings than silentcipher and are not the
  bottleneck. Defer until silentcipher streaming is proven.
- Adding `--memory-budget` to the `kit serve` request shape. The
  serve worker inherits the kit-level default; per-request override
  is a v0.6.1 polish.

## Sequencing with P4

P4 (ORT CUDA backend) and P3 (streaming embed) are independent
refactors. P3 should land first because:

- Streaming is a fix for the wrong place to allocate buffers, which
  is architectural and lives in the model-runtime-agnostic code
  paths. Doing it after P4 means redoing parts of it.
- P4 dramatically shrinks tract intermediates from RAM (because
  they move to GPU), which masks bad RAM usage patterns elsewhere.
  Land streaming first so the CPU path stays diagnosable.

## Reviewer checklist for the P3 PR(s)

When P3 lands, the reviewer should walk:

- [ ] `streaming_embed_matches_full_load_embed` test exists and passes.
- [ ] `real_silentcipher_embed_roundtrips_to_detection` still passes.
- [ ] Public API of `provcheck_watermark::embed` is unchanged
      (signature, return type, error variants).
- [ ] `--memory-budget` flag documented in `kit watermark --help`.
- [ ] RSS profile attached to the PR: 65-minute episode peak RSS
      under 1.8 GB on Ryzen + tract; under 400 MB on CUDA host with
      P4 enabled.
- [ ] No regression on `kit serve` smoke test (one request, then a
      second request reusing the model).
- [ ] No regression on the parity-vs-upstream sweep at SDR 30 + 47.

## Related

- v0.6.0 roadmap parent: [`../v0.6.0-roadmap/`](./).
- P1 chunk-parallel embed (already landed): commit `447c306`.
- P2 kit serve mode (already landed): commit `affad1f`.
- Memory: [[v0.5.1-shipped]] for prior art on chunked embed.
