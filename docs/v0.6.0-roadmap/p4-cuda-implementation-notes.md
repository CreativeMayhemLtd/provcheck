# P4 implementation notes (vs the design doc)

The design doc at [`p4-ort-cuda-backend-design.md`](./p4-ort-cuda-backend-design.md)
scoped P4 as 8-11 days of work across four phases. The actual
single-day implementation made some pragmatic choices that
diverge from the design. Recording them here so the next person
through this code knows why.

## What landed

Single-feature-flag `cuda` on `provcheck-watermark` and `provcheck-kit`.
Default download unchanged: tract-only CPU single-binary. Building
with `--features cuda` produces a CUDA-enabled kit binary
(separately at `target-cuda/release/provcheck-kit.exe` when built
via `CARGO_TARGET_DIR=./target-cuda cargo build --release --features cuda`).

## Phase compression: 4a + 4b + 4c collapsed

The design doc scoped:
- 4a: Extract tract into a backend trait (~2 days).
- 4b: ORT CPU EP path (~2-3 days).
- 4c: CUDA EP wiring (~2-3 days).

The actual implementation just gated the two `model()` and
`run_encoder_chunk()` functions behind `#[cfg(feature = "cuda")]`
and `#[cfg(not(feature = "cuda"))]`. No backend trait. No CPU-EP-
first incremental approach. Direct jump to CUDA EP with ort's
`CUDAExecutionProvider::default().build()`.

Trade-off: lost the architectural cleanliness of a trait
abstraction (would have been useful for future DirectML / CoreML
EPs in v0.7.x). Gained the ability to ship the CUDA path the same
day the user asked for it. The trait extraction can land later as
a v0.6.1 refactor if a third backend ever appears.

## Singleton: Mutex&lt;Session&gt;, not bare Session

ort's `Session::run` requires `&mut self`. Our singleton model is
held in a `OnceLock` and accessed by `&Runnable`. To satisfy the
borrow checker without giving up the singleton, the CUDA
`Runnable` type is `Mutex<Session>`.

Performance impact: the Mutex serialises chunk inferences. CUDA
serialises operations on a single stream anyway, so this does not
give up parallelism we were going to use. The CPU path's
4-wide rayon parallelism (P1) is irrelevant here because the GPU
is the bottleneck and the CUDA EP single-stream model already
serialises.

## ORT version: 2.0.0-rc.10 (cargo resolved)

Cargo.toml asks for `2.0.0-rc.4`; cargo resolved to `rc.10`. The
API is similar across the rc series, with one breaking change we
hit: `from_array_view` takes `view()` directly (not `&view()`).
Pinning to `rc.10` explicitly would be sensible for the next
release-prep pass.

## Runtime: ORT shared libs NOT bundled

The `cuda` feature uses ort's `load-dynamic` mode. The CUDA-built
kit binary looks for `onnxruntime.dll` (and friends) at runtime
via the `ORT_DYLIB_PATH` env var.

Install path documented in the operator-facing README sidecar:

1. `pip install --user onnxruntime-gpu` (or unzip the wheel
   manually if Windows file locks bite, which they do).
2. `set ORT_DYLIB_PATH=<extracted>\onnxruntime\capi\onnxruntime.dll`
3. Ensure CUDA 12.x runtime + cuDNN are on `PATH`.

NVIDIA libraries are NOT redistributed in our release archives
(license terms). The operator installs them separately.

## Validated on Windows + 3090

Doomscroll's target host is Windows 11 + NVIDIA 3090. Dev
validation ran on the same combination:

- nvidia-smi reports driver 610.47, CUDA UMD 13.3
- CUDA toolkit 12.8 at `C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.8\`
- onnxruntime-gpu 1.27.0 (wheel) for the EP shared libs
- ort 2.0.0-rc.10 via cargo

5-second smoke test: 0.13× real-time.
56-min stereo episode: 0.12× real-time (394.8s embed wall clock).

Doomscroll's previous v0.5.4 baseline on the same shape of
content was around 2× real-time. So the CUDA path is roughly
**16-20× faster than v0.5.4** and **~4.4× faster than v0.6.0 P1
CPU**.

## Peak RSS still 6.7 GB on CUDA

The design doc predicted CUDA peak RSS around 300 MB (model
moves to GPU memory). Actual measurement on the 56-min episode
landed at 6.7 GB host RAM peak.

Where the host RAM goes:
- Full STFT magnitude tensor: ~700 MB
- Full STFT phase tensor: ~700 MB
- Carrier reconstruction buffer: ~700 MB
- Input PCM (one channel held while processing the other): ~600 MB
- Output buffers per channel (both held during stereo embed): ~1.2 GB
- ndarray + ort glue allocations during inference: ~1-2 GB

The 300 MB target requires P3 (streaming STFT) to land. P3 + P4
together would hit ~300-500 MB peak. With P3 unfinished, the
~7 GB CUDA peak is still a 40% reduction vs CPU's 11.5 GB peak.

## What the CPU build is unaffected by

The conditional compilation is strict. Without `--features cuda`:
- ort is NOT pulled in (dependency is optional).
- ndarray is NOT pulled in.
- The CUDA `run_encoder_chunk` and `build_model` bodies are
  excluded from the build entirely.
- The CPU rayon parallelism from P1 is exactly as in v0.6.0.

This is what lets us ship a single source tree with both backends
without complicating the default download.

## Open items / deferred

- Validate CUDA path against the parity-vs-upstream-Python harness
  at the same SDR sweep we use for CPU. CUDA output should be
  bit-identical to CPU within f32 round-off.
- Add CUDA target to the release matrix in
  `.github/workflows/release.yml`. The CUDA build needs a Windows
  runner with CUDA installed (or we cross-compile and let
  operators install the runtime themselves).
- README sidecar `README.cuda.md` with the install path
  documented for operators.
- Verify the AudioSeal and WavMark embed paths also benefit from
  CUDA. Their models are smaller; the speedup will be smaller
  but real.
- Detect-side ORT integration. Currently only the embed path uses
  ort. Verifier (`provcheck`) stays tract-only for the single-
  binary-no-CUDA story.

## Related

- Design doc: [`./p4-ort-cuda-backend-design.md`](./p4-ort-cuda-backend-design.md).
- P1 chunk-parallel embed (no change here): commit `447c306`.
- P2 kit serve (no change here): commit `affad1f`.
- P3 phase 3d `--memory-budget` flag: commit `dbf281a`.
- v0.5.4 baseline measurements: `scratchpad/rss-baselines/run1_default_56min.csv`.
- CUDA measurement: `scratchpad/rss-baselines/run3_cuda_56min.csv`.
