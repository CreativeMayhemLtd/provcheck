# Example workflows

Three JSON workflow files you can drag-and-drop into ComfyUI:

| File | Graph | What it demos |
|---|---|---|
| `stamp_image_minimal.json` | `LoadImage` → `ProvcheckStamp` → `PreviewImage` | Smallest possible image-stamp workflow. Replace `example.png` with any image in your ComfyUI input directory. |
| `stamp_audio_minimal.json` | `LoadAudio` → `ProvcheckStampAudio` → `SaveAudio` | Smallest possible audio-stamp workflow. Replace `example.wav` with any clip in your ComfyUI input directory; SaveAudio writes the stamped WAV to the ComfyUI output directory. |
| `stamp_signed_image.json` | `LoadImage` → `ProvcheckStamp(sign=true)` → `SaveImage` | Image stamp **plus** C2PA signing. Requires `provcheck-kit init` to have been run upstream so the kit has a local signing identity. Sign failures (e.g. no identity set up) trigger the node's fail-closed passthrough: console warning + unsigned-but-watermarked output. |

## How to load a workflow

1. Open ComfyUI in your browser.
2. Drag the `.json` file from your file manager directly onto the
   ComfyUI canvas. ComfyUI parses the workflow and instantiates
   every node + connection.
3. Edit the `widgets_values` in the UI (e.g. swap `example.png`
   for an image you actually have, or change `brand_id` from 2
   to your registered brand id).
4. Click "Queue Prompt" to run.

## What you should see

- Console line from the node: e.g.
  `[provcheck-comfyui] StampNode: watermarked 1 frame(s) with
  brand_id=2 via provcheck-kit (timeout 120s/frame).`
- For `stamp_signed_image.json` the line should read
  `signed + watermarked 1 frame(s)`.
- For audio: same shape, but `clip(s)` instead of `frame(s)` and
  a sample-rate suffix.

If you see `passing image through unchanged` instead, check:

1. **Is `provcheck-kit` on PATH?** The node looks for it via
   `shutil.which`. Install via the release at
   <https://github.com/CreativeMayhemLtd/provcheck/releases/latest>
   and make sure the binary is on PATH (or symlink it).
2. **Is the input file actually loadable by the upstream node?**
   `LoadImage` / `LoadAudio` fail silently in some ComfyUI
   versions — check the ComfyUI console for upstream errors.
3. **For `stamp_signed_image.json`, has `kit init` been run?**
   The kit needs a local identity to sign. The node falls back
   to passthrough on sign failure, so a graph that "works" with
   `sign=false` will appear to do nothing when `sign=true` if
   the identity is missing.

## Brand id

All three workflows default to `brand_id = 2` (RAIDIO in the
public mirror's registry). Edit the `widgets_values` to use your
own registered brand id. See `docs/brand-registry.md` at the
workspace root for the published registry and the registration
process.

## Notes on workflow format

These JSON files target ComfyUI's `version: 0.4` workflow schema,
which is the format ComfyUI's "Save" button emits today. Older
ComfyUI builds might not load `version: 0.4` files — upgrade
ComfyUI before reporting a workflow-load failure as a node bug.

The `extra.provcheck_example` field is a human-readable note we
add so you can read the workflow's intent without firing up
ComfyUI. ComfyUI ignores fields under `extra` it doesn't know
about.
