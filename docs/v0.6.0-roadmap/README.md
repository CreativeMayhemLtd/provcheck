# v0.6.0 roadmap — throughput release

This directory is the **planning record** for v0.6.0, the watermark-
throughput release. It scopes four phases of work that together aim
to make watermark embed cease being the dominant pipeline bottleneck
for batch operators (doomscroll.fm being the canonical workload).

## Why v0.6.0 exists

Profile data from production (doomscroll.fm nightly pipeline,
2026-06-26):

- 9-13 podcast episodes per cycle, 15 min to 65 min each, stereo
  44.1 kHz MP3 input.
- v0.5.3 `provcheck-kit watermark` (silentcipher, default settings)
  takes about 70 minutes wall clock per 30-minute episode and over
  2h17m on a 65-minute "world_news" episode that exceeded the cap
  twice in observation.
- Per-process resident memory hovers at 1.5-2 GB; 2-wide parallelism
  is the stable ceiling on a 16 GB host before swap thrash and OOM
  kills appear.
- Watermark embed is now the dominant pipeline cost: a single cycle
  spends about 6 hours total on watermark embed alone, with
  assembly, C2PA, and uploads combined costing less than one
  episode's embed.

Architecture floor: silentcipher's fused `enc_c → concat × 32 →
dec_c` ONNX has dec_c (seven 2D convolutions over a
`[1, 96, 2049, T]` tensor) dominating cost at roughly 6 GFLOPS per
chunk. tract-onnx is at intra-op parallelism limits on this shape
past 2-3 threads. The per-mono-channel embed runs at ~1.05x real
time on a Ryzen and that is the steady-state floor for this model
on CPU. v0.5.2 stereo embed doubles wall clock by running L and R
independently as mono back-to-back.

## Goals

- **Target throughput on the existing CPU host:** 3-5x faster than
  v0.5.3 on the same machine without changing distribution model.
- **Target throughput on a CUDA-equipped workstation:** 30x faster
  than v0.5.3, taking the 65-minute episode from 2h17m to roughly
  2 minutes.
- **Memory ceiling lifted:** per-process peak under 300 MB
  regardless of episode length, so a 16 GB host can run 6+ wide
  without swap.
- **Default-distribution kit remains tract-only CPU and single
  binary.** GPU is a second binary in the release matrix, opt-in
  for operators who want the throughput.
- **End-user verifier is unchanged.** Detector path stays exactly
  as it is in v0.5.3; the v0.6.0 work is embed-side and operator-
  facing.

## Phases

### Phase 1 — Chunk-parallel embed

**Effort:** about 1 week of focused work.

**Why:** the detector already does this via `PARALLEL_BATCH` rayon
parallelism over `CHUNK_T_FRAMES`-sized windows and gets 3-4x on a
multi-core CPU. The embed-side chunk loop in
`crates/provcheck-watermark/src/encode.rs` is currently sequential
because the v0.5.1 OOM-fix landed without porting the parallelism
pattern. The fix is structural: process chunks concurrently via the
same `OnceLock`-cached tract model that the detect side already
shares safely across threads.

**Expected gain:** 2.5-3x on the existing Ryzen host. Stacks freely
with phases 2-4.

**Acceptance:**

- Output bit-equivalence to v0.5.3 on a representative input within
  the same 1e-5 tolerance the existing chunk-projection unit test
  enforces.
- All existing embed-roundtrip integration tests pass.
- Per-chunk parallelism gated by `std::thread::available_parallelism`
  with a sensible cap (probably 4 to match the detect side's
  empirical sweet spot).

**Risks:**

- tract's runnable model is `Send + Sync`, but tract intermediate
  buffers are not necessarily small. N chunks in parallel means N
  copies of per-chunk working memory; we already cap at 4 on the
  detect side for exactly this reason. The embed-side cap likely
  needs the same.

### Phase 2 — `provcheck-kit serve` mode

**Effort:** about 3-5 days.

**Why:** per-invocation model load costs roughly 3-5 seconds. At 9
episodes per nightly cycle that's 30-45 seconds, which is not the
dominant cost but is real. The bigger reason for serve mode is that
the doomscroll wrapper already structures embed as a per-file
subprocess call. A persistent worker process per concurrency slot
amortises model load to one-time and removes the per-file
process-startup cost (Python wrapper, fork, exec, dynamic linker).

**Surface (to be negotiated with the doomscroll team before
implementation):**

```
provcheck-kit serve [--protocol jsonl|socket] [--port N]
```

JSON-line on stdin/stdout is probably the right shape; matches how
the orchestrator structures its workers today, no auth surface to
worry about, no port conflicts. Unix socket is the alternative.

Per-request shape:

```jsonl
{"id": "...", "input": "/path/to/in.mp3", "output": "/path/to/out.wav", "kind": "silentcipher", "sdr_db": 30}
{"id": "...", "ok": true, "verify_conf": 0.94, "elapsed_s": 67.3}
```

**Acceptance:**

- Output bit-equivalent to one-shot `provcheck-kit watermark` on the
  same input.
- Crash isolation: a malformed input on one request does not bring
  down the worker. Errors surface via the response, not the exit
  code.
- Graceful shutdown on stdin close.

**Risks:**

- Model is held in memory across requests; if one request leaks
  somehow it accumulates. The detect path already runs a
  long-lived OnceLock model in tests with no observed leak, so the
  risk is low but real.

### Phase 3 — Streaming STFT embed

**Effort:** about 2-3 weeks.

**Why:** the v0.5.1 chunked refactor moved the ONNX call and the
message projection into per-chunk territory. What is still full-
length: the forward STFT (computed before the chunk loop), the
inverse STFT (fed the full `carrier_reconst` buffer), and the
rescaled waveform. For O(1) per-process memory the streaming
boundaries need to extend through these too.

**Approach:**

- Forward STFT: emit frames as the waveform decoder yields them,
  buffer enough for one chunk's worth, hand to the encoder.
- Inverse STFT: overlap-add buffer between consecutive output
  chunks; flush the tail after the last chunk.
- Tile-boundary awareness: silentcipher's per-position mode vote at
  decode requires the decoder to see all tiles, but the embedder
  can stream because each tile is independent at the symbol-stream
  level. The streaming-chunk size must be a multiple of the
  underlying tile structure to keep STFT alignment intact (one
  tile is `MESSAGE_LEN * HOP / SAMPLE_RATE ≈ 0.975 s`, so a 5 s
  streaming window is 5 tiles wide).

**Expected gain:** per-process peak drops from 1.5-2 GB to about
200 MB. The unlock that lets a 16 GB host run 4-6 wide without
swap.

**Acceptance:**

- Per-process peak measured via RSS-sampling under 300 MB on the
  65-minute episode test case.
- Output bit-equivalent (within 1e-4 floating-point tolerance, the
  iSTFT overlap-add has its own numeric noise floor) to v0.5.5
  non-streaming output on the same input.
- All existing embed-roundtrip integration tests pass.
- New streaming-specific regression test in
  `crates/provcheck-watermark/tests/` proving the boundary-buffer
  math is correct over multi-tile-spanning inputs.

**Risks:**

- iSTFT overlap-add at chunk boundaries can introduce audible
  artifacts if the window-add math is wrong. The existing v0.5.1
  embed regression test catches gross errors but a subtle 1e-4
  shift might still affect detection confidence at marginal SDR.
  Likely needs SDR-sweep regression validation.

### Phase 4 — ORT backend behind `--features cuda`

**Effort:** about 1-2 weeks.

**Why:** the architectural ceiling above. CPU silentcipher at 1x
real time per mono channel is the tract floor on this model. To
break the ceiling needs a different runtime. ORT (formerly
onnxruntime-rs) consumes the same `silentcipher-encoder.onnx` we
already export, supports CUDA EP for NVIDIA, DirectML EP for
Windows-any-GPU, CoreML EP for Apple Silicon, and CPU EP as
fallback. No PyTorch dependency. No Python.

**Distribution decision:**

- Default download stays `provcheck-kit` (tract, CPU, single
  binary, 70-90 MB) for end users and verifier-side workflows.
- New `provcheck-kit-cuda` target in the release matrix, with the
  ORT dynamic libs bundled or documented as install prerequisites.
  Builds for Linux x86_64 + Windows x86_64 with NVIDIA CUDA 12.x.
- macOS / Linux ARM get DirectML / CoreML EPs respectively, in a
  later phase if there's demand.

**Expected gain:** silentcipher embed drops from ~1x real time
(CPU) to ~30x real time (3090). The 65-minute episode goes from
2h17m to about 2 minutes. AudioSeal embed similar relative gain.
WavMark embed similar.

**Acceptance:**

- Bit-equivalent output to the tract path on the same model and
  inputs (within ORT's documented numeric tolerance vs tract,
  probably 1e-4).
- All existing watermark roundtrip integration tests pass under
  both backends.
- Release matrix builds `provcheck-kit-cuda` on Linux + Windows
  with smoke-test verification on a CUDA runner (or manually if no
  CUDA CI is available).
- Install docs cover CUDA 12.x runtime requirements per platform.

**Risks:**

- ORT 2.x's API has shifted across point releases. Pin and watch.
- CUDA driver/runtime version matrix is the real distribution
  headache; documented as a known limitation for the cuda target.
- DirectML EP is a different code path on Windows; either we
  promise CUDA-only on Windows or take the extra week to handle
  both. Likely CUDA-only for v0.6.0; DirectML deferred.

## Composite throughput projection

| Path | v0.5.3 | After P1 | After P1+P2 | After P1+P2+P3 | After P1+P2+P3+P4 |
|---|---|---|---|---|---|
| 30-min episode embed | ~70 min | ~25 min | ~24 min | ~24 min | ~1 min |
| 65-min episode embed | ~2h17m | ~50 min | ~48 min | ~48 min | ~2 min |
| Per-process peak RSS | 1.5-2 GB | 1.5-2 GB | 1.5-2 GB | 200-300 MB | 1-2 GB (GPU mem instead) |
| Concurrency on 16 GB host | 2 wide | 2 wide | 2 wide | 6 wide | N/A (GPU-bound) |
| 9-episode cycle total | ~6 h | ~2.5 h | ~2.4 h | ~50 min (parallel 6 wide) | ~10 min |

P4 is the dominant unlock for the doomscroll workload (CUDA host
available). P1 + P3 dominate for operators without GPU. P2 is small
in pure throughput terms but reshapes the pipeline integration to
make P3's concurrency unlock usable.

## Asks from the doomscroll team

To kick off this work the maintainer needs:

1. A 5-10 minute representative audio sample of the actual problem
   shape (the 65-min world_news episode is the canonical hard
   case). For regression test fixtures across phases 1 and 3.
2. An RSS curve over time during a current v0.5.3 embed run (just
   `ps aux` snapshots every 30 seconds into a CSV). For confirming
   the model-load tail and the steady-state floor.
3. Confirmation that `provcheck-kit serve` over JSON-line stdin/stdout
   is the right protocol shape, or push back with the wrapper's
   actual integration constraint.

## Sequencing

P1 and P2 can land in any order (independent). P3 depends on P1 for
the parallel chunk loop being in place; the streaming refactor
threads through that. P4 is independent of P1-P3 architecturally
but should land last so the regression suite has the new streaming
+ parallel paths to validate against.

A reasonable calendar:

- Week 1: P1 lands.
- Week 2: P2 lands.
- Weeks 3-5: P3 lands.
- Weeks 6-7: P4 lands.
- Week 8: release-prep (codec doc updates, README, SBOMs, clean-
  machine verify, GPU-target install docs, public release with
  changelog).

Total wall clock: 8 weeks, single maintainer. Compressible to 5-6
weeks with a second pair of hands or by deferring P3 to v0.6.1.

## Carried-over items

The following land in v0.5.4 (separately) before v0.6.0:

- The `--no-verify-after-embed` clap surface bug ([[v0.5.4-cleanup]]).
  Current help text claims the flag works but clap's ArgAction::Set
  only accepts `--verify-after-embed false`. v0.5.4 fixes the clap
  config.
- Dependabot triage backlog (Task #120). Roll the safe bumps in.

## What is NOT in v0.6.0

- Torch dependency back. Reaffirming: no. Per the doomscroll team's
  own brief, the kit's value over the Python reference is precisely
  not fighting the torch+silentcipher environment churn on the
  orchestrator host.
- Architectural redesign of the detector. The current detect path
  is already healthy for verifier-heavy use cases and for low-volume
  signers, which is most of the install base.
- Multi-GPU support. CUDA single-device is enough for v0.6.0; multi-
  GPU is a v0.7.x problem when one operator hits the ceiling.
- DirectML EP on Windows. Deferred behind CUDA EP because CUDA EP
  covers the load-bearing use case (NVIDIA workstations) and
  DirectML adds another week of work for marginal additional
  hardware coverage.

## Related

- v0.5.1 chunked OOM fix ([[v0.5.1-shipped]]) — the prior art for
  chunked embed.
- v0.5.2 codec-survival findings
  ([`docs/v0.5.2-codec-survival/`](../v0.5.2-codec-survival/)) —
  what regression tests need to keep working through the v0.6.0
  refactor.
- v0.5.3 AAC-in-MP4 detector fix ([[v0.5.3-shipped]]) — the prior
  art for symphonia-related decoder work, which is unaffected by
  v0.6.0 changes but borders them.
- Pre-push regression gate ([[pre-push-regression-gate]]) — the
  load-bearing safety net for the v0.6.0 refactor. Every phase
  push runs the full parity sweep + codec survival smoke.
