# P4 design — ORT backend behind `--features cuda`

This document scopes the v0.6.0 P4 work (ORT CUDA backend) before
the refactor starts. Goal: a second release-matrix target
`provcheck-kit-cuda` that runs silentcipher / AudioSeal / WavMark
inference on NVIDIA GPUs via the ORT runtime, delivering 30-100x
embed throughput over the tract CPU path on the same model files.

## Why ORT, not torch

P4 ships ONNX inference on GPU. Three runtime options exist; the
choice is the load-bearing decision:

| Option | Pros | Cons |
|---|---|---|
| **ort (onnxruntime-rs)** | Same ONNX files we export; CPU EP, CUDA EP, DirectML EP, CoreML EP; no Python dep; mature Rust bindings (`ort 2.x`). | ORT C++ shared libs (~100-300 MB on disk) bundled or installed alongside the binary. CUDA driver/runtime version matrix is a real headache for end users; this is documented as a known limitation for the `cuda` target. |
| **PyTorch + sidecar Python process** | Native silentcipher checkpoint, no ONNX re-export needed. | Drags Python + torch back into the orchestrator. The doomscroll team's brief explicitly NACKs this: getting rid of torch+silentcipher's environment churn was the whole point of the kit. |
| **wgpu compute shaders** | Cross-platform GPU via Vulkan/Metal/D3D, no CUDA dependency. | Months of work to implement transformer-shaped models correctly. Not validated against silentcipher. |

**Decision: ORT.** Same ONNX files we ship today, multiple EPs to
cover NVIDIA and (later) Apple Silicon / Windows-any-GPU, no
Python. CUDA EP only for v0.6.0; DirectML and CoreML deferred.

## Target architecture

### Default download stays unchanged

`provcheck-kit` (and `provcheck`, `provcheck-app`) continue to ship
as tract-only single binaries on Linux x86_64, macOS aarch64,
Windows x86_64. 70-90 MB. CPU only. This is the verifier-side path
and most operators' default. No regression.

### New `provcheck-kit-cuda` target

A second binary built with `--features cuda` enabled on the
`provcheck-watermark`, `provcheck-audioseal`, and `provcheck-wavmark`
crates. Replaces tract with ort + CUDA EP for the inference calls.
Linux x86_64 + Windows x86_64 only (the two platforms with mature
NVIDIA CUDA drivers); macOS gets CoreML EP in a v0.7.x release.

The GUI app stays tract-only. The Tauri release matrix is already
heavy (~25 EUR / week of GH Actions burn at our cadence per
`feedback_release_cadence_budget.md`); adding a CUDA GUI build is
not justified by the demand.

### Cargo feature flag

In `crates/provcheck-watermark/Cargo.toml`:

```toml
[features]
default = []
cuda = ["dep:ort"]

[dependencies]
tract-onnx.workspace = true
ort = { version = "2", optional = true, default-features = false, features = ["cuda"] }
```

Same shape in `provcheck-audioseal` and `provcheck-wavmark`.

In `crates/provcheck-kit/Cargo.toml` and similar:

```toml
[features]
default = []
cuda = ["provcheck-watermark/cuda", "provcheck-audioseal/cuda", "provcheck-wavmark/cuda"]
```

So `cargo build --release --features cuda` on the kit binary
propagates the flag into the watermark crates.

### Code-level conditional

In `crates/provcheck-watermark/src/model.rs` and `encode.rs`:

```rust
#[cfg(feature = "cuda")]
mod backend {
    pub use ort::session::Session;
    // ort-specific build_model, run_chunk_owned, etc.
}
#[cfg(not(feature = "cuda"))]
mod backend {
    pub use tract_onnx::prelude::TypedRunnableModel;
    // tract-specific path (existing code).
}
```

The public `pub fn embed(...)`, `pub fn detect(...)`, etc. stay
unchanged; the backend selection happens behind the
`mod backend` boundary. This keeps blast radius small and lets us
keep one set of tests for both backends.

Risk: the tract and ort APIs are different at the model-call level
(input/output tensor handling, error types). The cleanest pattern
is a thin internal trait `InferenceBackend` that both impls satisfy,
and the public functions take `&dyn InferenceBackend` or a generic.
Decide concretely during 4a below.

## Phase-by-phase plan

### Phase 4a — Backend trait + tract-only implementation

**Effort:** 2 days.

Extract the existing tract code from `model.rs` and `encode.rs` into
a `tract` backend module that implements a new `InferenceBackend`
trait. No behaviour change; this is pure refactor that lands in
v0.6.0 P4a. Tests pass unchanged.

**Acceptance:**
- All existing tests pass.
- `cargo build` (no features) produces the same binary size +/- 1%.

### Phase 4b — ORT backend (CPU EP)

**Effort:** 2-3 days.

Add the `ort` crate behind `--features cuda` (yes, the feature name
is "cuda" but we wire the CPU EP first because it's the smaller
delta and the CUDA EP layer adds on top of it). Implement
`InferenceBackend` for ORT.

The model files (silentcipher-encoder.onnx, audioseal-generator.onnx,
audioseal-detector.onnx, wavmark-hinet.onnx) load directly into ORT
via `Session::builder().with_model_from_memory(MODEL_BYTES)`.

**Acceptance:**
- `cargo build --features cuda` succeeds on Linux + Windows.
- All existing tests pass under `--features cuda` (ORT CPU EP).
- Output bit-equivalent to tract path within 1e-4 tolerance.

**Risk:** ORT's tensor input/output marshalling has different
ergonomics than tract's `Array4::from_shape_vec`. May need a thin
adapter layer.

### Phase 4c — CUDA EP wiring

**Effort:** 2-3 days.

Enable the CUDA EP in the ORT session builder. Requires the CUDA
runtime + cuDNN installed at runtime (the binary dlopens
libonnxruntime_providers_cuda.so or .dll).

**Acceptance:**
- `provcheck-kit-cuda watermark` on a Linux box with CUDA 12.x +
  cuDNN 8.x installed runs the inference on GPU.
- Embed wall-clock on a 5-minute clip drops from ~5 minutes (CPU)
  to ~10 seconds (3090 or equivalent).
- Falls back to CPU EP cleanly when CUDA libraries are not
  available (warning, then continues at CPU speed).

**Risk:** CUDA EP version-matrix grief is real. The doc ships a
known-good combo (CUDA 12.4 + cuDNN 8.9 + ORT 2.0.x), but operator
machines will not always match. Document the fallback path
explicitly.

### Phase 4d — Release matrix expansion

**Effort:** 2-3 days.

Update `.github/workflows/release.yml` to add two new targets:

- `provcheck-kit-v0.6.0-linux-x86_64-cuda.tar.gz`
- `provcheck-kit-v0.6.0-windows-x86_64-cuda.zip`

Each bundles:
- `provcheck-kit.exe` (or binary) built with `--features cuda`
- Documented runtime requirements in a `README.cuda.md` sidecar
- Optional: a small `cuda-deps-check` binary that probes the host
  for CUDA libs at install time

Add a smoke-test step that runs `provcheck-kit-cuda watermark`
against a 5-second fixture on the runner (the GH Actions Linux
runners do not have CUDA by default; the smoke test runs on CPU EP
fallback and asserts the binary works at all, just slower).

Real CUDA validation runs manually on the maintainer's box pre-
release. Document the manual gate as part of the v0.6.0 release
prep checklist.

**Acceptance:**
- Release matrix produces the two cuda targets.
- SBOMs generated for cuda targets too.
- `publish-release.sh` propagates cuda targets to the public mirror.

## Distribution decisions

### Binary size

Bundling ORT shared libs into the release archive adds roughly
100-300 MB depending on which providers are enabled. The CPU-only
ORT build is ~80 MB on Linux; adding CUDA provider blobs takes it
up.

**Decision:** ship the ORT shared libs as separate downloads from
the binary. The `provcheck-kit-cuda` archive contains the kit
binary + a `README.cuda.md` that points at the operator's package
manager (`apt install onnxruntime-cuda` on Debian-derivatives,
similar on RHEL, `winget install Microsoft.ONNX.Runtime` on
Windows). Reduces the per-release upload from ~250 MB to ~90 MB.

Trade-off: more friction at install time. Operators have to read
docs to get the deps right. Acceptable for a power-user target.

### License compliance

ORT itself is MIT-licensed (compatible with our Apache-2.0).
CUDA EP links against NVIDIA's proprietary CUDA libraries; the
license terms for redistribution are restrictive. We do NOT
redistribute the NVIDIA libraries; the operator installs them
separately. This keeps our release archives Apache-2.0 clean.

Document this prominently in `README.cuda.md` so operators
understand they're entering NVIDIA's license terms when they
install the CUDA runtime.

### Detector vs embedder coverage

P4 enables CUDA for BOTH embed and detect. The detect side already
has parallel chunk processing (`detect_chunked` in lib.rs); ORT
CUDA on detect gives 20-30x speedup on long files. Operators
running the verifier at scale (e.g. moderation pipelines) get the
same win.

The default `provcheck` (verifier) binary stays tract-only for the
single-binary-no-CUDA story. A separate `provcheck-cuda` could
ship as a parallel target if there is demand, but for v0.6.0 only
`provcheck-kit-cuda` ships.

## Composite throughput projection (revised)

Earlier roadmap doc estimated 30x speedup on a 3090 for
silentcipher embed. Refined estimate based on the silentcipher
model architecture (fused `enc_c + dec_c`, dominated by 2D conv on
[1, 96, 2049, T] tensors):

| Workload | tract CPU (Ryzen) | ORT CUDA (3090) | Speedup |
|---|---|---|---|
| silentcipher 5-min clip embed | ~5 minutes | ~10 seconds | ~30x |
| silentcipher 65-min episode embed | ~70 minutes | ~2 minutes | ~35x |
| AudioSeal 5-min clip embed | ~30 seconds | ~3 seconds | ~10x (smaller model) |
| WavMark 5-min clip embed | ~30 seconds | ~3 seconds | ~10x |
| silentcipher detect on 60-min file | ~30 seconds | ~3 seconds | ~10x |

The doomscroll team's 9-episode nightly cycle:

| Stage | tract CPU (v0.5.4 baseline) | P1+P2+P3d on CPU | P1+P2+P3d+P4 on CUDA |
|---|---|---|---|
| Total watermark wall clock | ~6 hours | ~2-2.5 hours | ~10-15 minutes |

P4 is the dominant unlock for operators with NVIDIA hardware.
Without P4, the v0.6.0 throughput improvement is roughly 2.5-3x
(P1+P2 alone, with P3d for memory cap). With P4 it is roughly
30-35x.

## Asks from the doomscroll team

To kick off P4 the maintainer needs:

1. Access to a CUDA-equipped Linux host for the validation gate at
   end of phase 4c.
2. Documentation of which CUDA driver version doomscroll's
   production container ships (CUDA 12.4? 12.6? 13.0?), so the
   shipped CUDA EP version matches.
3. Confirmation that "operator installs CUDA runtime separately
   from the kit archive" is the right friction point. The
   alternative is bundling everything for a larger archive.

## What is NOT in v0.6.0 P4

- DirectML EP on Windows (any-GPU coverage). Deferred behind the
  CUDA target because CUDA covers the load-bearing case (NVIDIA
  workstations) and DirectML adds another week.
- CoreML EP on macOS. Same reasoning; Apple Silicon support is a
  v0.7.x feature.
- TensorRT EP. Even faster than CUDA EP but requires per-model
  engine compilation that ages out across CUDA driver versions.
  Out of scope for v0.6.0.
- Multi-GPU support. CUDA single-device is enough; multi-GPU is a
  v0.7.x problem when one operator hits the ceiling.

## Sequencing with P3

P3 (streaming embed) lands before P4. Two reasons:

1. The streaming refactor lives in model-runtime-agnostic code
   paths (STFT, iSTFT, chunk loop coordination). Doing it after P4
   means redoing parts of it across both backends.
2. P4 dramatically shrinks tract intermediates' RAM share (because
   they move to GPU), which would mask bad RAM usage patterns
   elsewhere. Land streaming first so the CPU diagnostic path
   stays useful.

## Reviewer checklist for the P4 PR(s)

When P4 lands, the reviewer should walk:

- [ ] `InferenceBackend` trait exists and both `tract` and `ort`
      modules implement it cleanly.
- [ ] `cargo build` (no features) produces identical behaviour to
      v0.6.0 P3.
- [ ] `cargo build --features cuda` succeeds on Linux + Windows.
- [ ] All existing tests pass under both feature configurations.
- [ ] Embed roundtrip integration test passes under `--features cuda`
      with CPU EP fallback (no CUDA on the runner).
- [ ] Manual CUDA gate: maintainer runs `provcheck-kit-cuda
      watermark` on a CUDA host and confirms inference happens on
      GPU (via `nvidia-smi` profile sampling).
- [ ] Release matrix produces `provcheck-kit-cuda` targets for
      Linux + Windows.
- [ ] SBOMs include the cuda targets.
- [ ] `README.cuda.md` documents the runtime install path.
- [ ] License compliance: NVIDIA libraries are NOT redistributed
      in our archives; operator installs separately.

## Out of scope for P4 specifically

- Verifier (`provcheck`) does NOT get a CUDA target in v0.6.0.
  Only the kit (signing-side) does. Verifier CUDA is a v0.6.1
  follow-up if there is demand.
- Streaming + CUDA combined optimisations (e.g. moving STFT to GPU
  too) are a v0.7.x consideration.

## Effort total

Phases 4a (2d) + 4b (2-3d) + 4c (2-3d) + 4d (2-3d) = **8-11 days**
of focused single-maintainer work. Slightly longer than the
original 1-2 week estimate; the manual CUDA validation gate at end
of 4c adds calendar time even if it does not add coding time.

## Related

- v0.6.0 roadmap parent: [`./README.md`](./README.md).
- v0.6.0 P3 design: [`./p3-streaming-embed-design.md`](./p3-streaming-embed-design.md).
- P1 chunk-parallel embed (already landed): commit `447c306`.
- P2 kit serve mode (already landed): commit `affad1f`.
- P3 phase 3d (`--memory-budget` flag): landing in the current
  session as part of partial v0.6.0 progress.
