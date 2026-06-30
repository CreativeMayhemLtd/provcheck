# provcheck-comfyui

ComfyUI nodes that stamp generated outputs with provcheck app
strings: TrustMark-B watermark on images, silentcipher on audio,
optional C2PA Content Credentials signing, and (after upstream
`kit publish`) an atproto identity assertion in the signed
manifest. Inline with the generation graph.

**Scope:** v0.9 staging release of the provcheck v0.7 → v1.0
roadmap. This package is the public, brand-agnostic creator
surface — any creator with their own atproto identity + signing
key + brand registration can drop the package into their ComfyUI
`custom_nodes/` directory and stamp every output. Released under
Apache-2.0 alongside the rest of the FOSS provcheck core.

**Status (v0.9.84):** Fully wired for both image and audio,
example workflows shipped, pytest matrix in CI.
- **Stamp Image** (`ProvcheckStamp`): saves each tensor to a
  temp PNG, shells through `provcheck-kit stamp`, reads the
  stamped PNG back as a tensor. TrustMark-B watermark via the
  shipped FOSS DLC weights.
- **Stamp Audio** (`ProvcheckStampAudio`): saves each clip to a
  temp WAV (int16 PCM) at the input's `sample_rate`, shells
  through `provcheck-kit stamp` (auto-routes through silentcipher
  for audio), reads the stamped WAV back as a tensor.
- Both nodes fail closed when `provcheck-kit` is missing from
  PATH (passes input through with a console warning) so render
  queues do not crash.
- Both nodes clamp `brand_id` server-side as defence in depth
  against malformed workflow JSON.
- Both nodes accept an optional `sign` boolean (default `False`)
  to enable C2PA signing in the same shell-out. When `False`,
  the watermark embeds without engaging the local signing
  identity. When `True`, the kit attempts to sign; if no
  identity is initialised the kit errors and the node falls
  back to passthrough.
- Both nodes accept an optional `timeout_secs` input (default
  120, range 5–600) so operators on slow hosts can extend the
  per-frame / per-clip subprocess timeout.
- Three example workflows ship under `workflows/`
  (`stamp_image_minimal.json`, `stamp_audio_minimal.json`,
  `stamp_signed_image.json`). Drag-and-drop loadable; see
  `workflows/README.md`.
- 22 pytest tests cover all wrapper failure modes. CI workflow
  (`.github/workflows/comfyui-node.yml`) runs the matrix on
  Python 3.10 + 3.12 on every push that touches the package.

## Install

```bash
cd ~/ComfyUI/custom_nodes
git clone https://github.com/CreativeMayhemLtd/provcheck
ln -s provcheck/python/comfyui-node provcheck-comfyui
pip install -e ./provcheck-comfyui
```

Then in ComfyUI:
- Image: add the **"Stamp Image (provcheck • Creative Mayhem)"**
  node from the `image/postprocessing` category.
- Audio: add the **"Stamp Audio (provcheck • Creative Mayhem)"**
  node from the `audio/postprocessing` category.

## Architecture

Both nodes are intentionally thin Python wrappers around the
`provcheck-kit` CLI. The watermark math lives in the Rust crate;
the Python side just serialises tensors to disk, invokes the
kit, and re-loads the result.

**Image flow** (`StampNode`):
1. ComfyUI passes the generated image as a `torch.Tensor` of
   shape `[batch, height, width, channels]` in `[0, 1]`.
2. The node saves each tensor element to a temp PNG.
3. The node shells out to `provcheck-kit stamp <tmp.png> -o
   <tmp_stamped.png> --brand-id <N>` (plus `--no-sign` when
   `sign=False`).
4. The node loads the stamped PNG back as a torch tensor.
5. The node returns the stamped tensor downstream.

**Audio flow** (`StampAudioNode`):
1. ComfyUI passes the generated audio as an `AUDIO` dict:
   `{"waveform": tensor[B, C, samples], "sample_rate": int}` with
   float PCM in `[-1.0, 1.0]`.
2. The node saves each batch element to a temp 16-bit PCM WAV
   at the input's `sample_rate`.
3. The node shells out to `provcheck-kit stamp <tmp.wav> -o
   <tmp_stamped.wav> --brand-id <N>` (plus `--no-sign` when
   `sign=False`). The kit auto-routes audio through silentcipher.
4. The node loads the stamped WAV back as a tensor and re-stacks
   into the AUDIO dict.

`provcheck-kit` MUST be on the user's PATH for either node to do
work. Both nodes detect missing kit at first call and surface a
clear console message; the input passes through unchanged so the
render queue never crashes on a missing kit.

## Brand registry

`brand_id` is a 5-bit unsigned integer (0..31) matching the
signer's atproto-published brand registration record. The node
ships with `default=2` because the public mirror's published
registry uses id `2` for the rAIdio.bot brand, which is the most
common stamping target for casual installs. **The default is an
ergonomic choice, not a normative one.** Creators who registered
their own brand in their own atproto signing-key record pick
their own id — there is no "preferred" id in the protocol. See
`docs/brand-registry.md` in the workspace root for the published
list and how to register your own.

## What these nodes are NOT

- They are NOT bound to any specific brand. A creator running
  rAIdio.bot's pipeline uses the same nodes a creator running
  their own pipeline does. The brand id is a node input.
- They are NOT the AI-detection DLC (paid layer; v1.0). These
  are pure creator-side watermarking + signing. Free, open, no
  auth.
- They are NOT a per-asset atproto record publisher. The
  atproto identity assertion in the C2PA manifest is enough for
  the verifier to cross-check; per-asset records are an
  out-of-scope v1.0+ design decision.
- They are NOT a verifier. The `provcheck` CLI handles
  verification; if you need a verify-step node in a ComfyUI
  graph, file an issue.

## Example workflows

Three JSON workflows ship under `workflows/`:

- `stamp_image_minimal.json` — `LoadImage` → `ProvcheckStamp` → `PreviewImage`
- `stamp_audio_minimal.json` — `LoadAudio` → `ProvcheckStampAudio` → `SaveAudio`
- `stamp_signed_image.json` — `LoadImage` → `ProvcheckStamp(sign=True)` → `SaveImage`

Drag any of them onto the ComfyUI canvas to load. See
`workflows/README.md` for what you should expect to see in the
console + how to swap the placeholder inputs for your own files.

## Tests

```bash
pip install pytest
pytest python/comfyui-node/tests/
```

The test suite mocks `provcheck-kit` (no actual kit binary is
invoked), so it runs in CI without needing the full Rust build.
The end-to-end correctness of the watermark math is covered by
the Rust crate's own integration tests.

Coverage in v0.9.77:
- Image node: kit-missing passthrough, brand-id clamping,
  brand-id non-int fallback, INPUT_TYPES shape, sign default
  off, sign opt-in argv shape, timeout knob clamping, node
  metadata, node registration includes both image + audio.
- Audio node: kit-missing passthrough, malformed-dict
  passthrough, missing-waveform passthrough, brand-id clamping,
  INPUT_TYPES shape, metadata, WAV round-trip mono + stereo,
  WAV clipping on out-of-range float input, sign opt-in argv
  shape, timeout knob clamping, sample-rate preservation.
