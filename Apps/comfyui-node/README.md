# ComfyUI-Provcheck

**One ComfyUI node that watermarks and C2PA-signs your generated media —
image, audio, or video — right inside the graph.** Embed the free, open
watermark (TrustMark-B on images, silentcipher on the audio track of
audio/video), C2PA-sign with your atproto/Bluesky identity, optionally bake
the generation graph into the manifest, or flip to **read** mode to verify a
mark. Free and Apache-2.0.

- Node: **Provcheck (Free C2PA Watermark)** — category `provcheck`.
- One node, every modality, `write` or `read`.
- Fails closed: if the `provcheck` CLIs aren't installed it passes your media
  through untouched (with a console note) so a render never crashes.

---

## Install

Clone straight into your ComfyUI `custom_nodes/` and restart ComfyUI:

```bash
cd ComfyUI/custom_nodes
git clone https://github.com/CreativeMayhemLtd/ComfyUI-Provcheck
```

Or install from **ComfyUI-Manager** (search "Provcheck"). The Python deps
(`numpy`, `Pillow`, `torch`) already ship with ComfyUI, so a plain clone needs
nothing more.

**One extra requirement — the provcheck CLI.** The node is a thin wrapper; the
watermark and C2PA math live in the `provcheck` binaries. Put them on your PATH:

- `provcheck-kit` — needed to **write** (watermark / sign).
- `provcheck` — needed to **read** (verify).

Download from the [provcheck releases](https://github.com/CreativeMayhemLtd/provcheck/releases/latest)
and make sure the folder is on PATH (or drop the binaries next to your other
tools). Verify with `provcheck-kit --version`. If they aren't found, the node
still loads and simply passes media through.

To C2PA-**sign** you also need a one-time identity setup (see
[Signing setup](#signing-setup-one-time) below).

---

## Quick start (30 seconds, no account)

Free watermark, nothing to configure:

```
LoadImage ──▶ Provcheck (Free C2PA Watermark) ──▶ SaveImage
                mode: write
                watermark: on
                c2pa_sign: off
```

Wire your image into `image`, take the `image` output into `SaveImage`, set
`c2pa_sign` **off**, and run. The saved PNG carries the free TrustMark. Swap
`LoadImage`/`SaveImage` for `LoadAudio`/`SaveAudio` to watermark audio instead.

---

## Configuration — every input

The node has three **input sockets** (all optional — connect any one, or several
at once) and a set of **widgets**. Every widget can also be right-clicked →
*Convert to input* and driven from another node (a Primitive, an Int, a String,
etc.), for API/graph-flow pipelines.

### Inputs (sockets)

| Socket  | Type    | Notes |
|---------|---------|-------|
| `image` | IMAGE   | An image (or batch). Marked with TrustMark-B. |
| `audio` | AUDIO   | An audio clip. Marked with silentcipher on the waveform. |
| `video` | VIDEO   | A video. The mark rides the **audio track**; frames are preserved and the container is C2PA-signed. |

Connect whichever you have. Connect several and each is processed independently
in one run.

### Widgets

| Widget | Type / range | Default | What it does |
|--------|--------------|---------|--------------|
| `mode` | `write` \| `read` | `write` | **write** marks/signs. **read** verifies an existing mark and fills `report` + `detected`. |
| `watermark` | bool | `true` | *(write)* Embed the free FOSS watermark. |
| `c2pa_sign` | bool | `true` | *(write)* C2PA-sign the file with your local key. **Writes the signed file to your ComfyUI `output/` folder** (a manifest can't live in a tensor). Needs [signing setup](#signing-setup-one-time). |
| `embed_identity` | bool | `true` | *(write, with sign)* Put your atproto/Bluesky identity (DID + handle) in the manifest so a verifier sees **who** signed. |
| `record_provenance` | bool | `false` | *(write, with sign)* Bake a **curated** summary of the generation graph (model, seed, sampler, prompts) into the manifest. |
| `include_full_workflow` | bool | `false` | *(write, with provenance)* Embed the FULL (redacted) workflow, not just the summary. Off by default so prompts/paths don't leak. |
| `brand_id` | int, 0–31 | `2` | *(write)* Your 5-bit brand id from the atproto brand registry. `2` is the public rAIdio.bot id; use your own once registered. |
| `filename_prefix` | string | `provcheck` | *(write, when a file is written)* Output filename prefix. |
| `timeout_secs` | int, 5–600 | `120` | Per-item CLI timeout. Raise it on slow/CPU-only hosts or long clips. |

### Outputs

| Output | Type | Notes |
|--------|------|-------|
| `image` / `audio` / `video` | same as input | Passthrough for preview / chaining. **When signing, the passthrough tensor carries no manifest — the signed FILE in `output/` is the artifact.** |
| `report` | STRING | One line per modality (e.g. `image: signed 1/1`, or a read verdict). |
| `detected` | BOOLEAN | *(read)* True if any connected input carried a provcheck mark. |

---

## Recipes

Concrete configurations for common goals. "on/off" are the boolean widgets.

### 1. Free watermark only (no account)

> Goal: mark outputs with the open watermark, no signing, no setup.

```
Load{Image,Audio} ─▶ Provcheck ─▶ Save{Image,Audio}
   mode=write · watermark=on · c2pa_sign=off
```

Watermark-only returns the marked **tensor** on the matching output, so chain it
into a normal `SaveImage`/`SaveAudio`. Nothing lands in `output/` from the node
itself.

### 2. Easy C2PA sign (the headline)

> Goal: a signed file that proves who made it. Needs a one-time `provcheck-kit login`.

```
LoadImage ─▶ Provcheck ─▶ (done)
   mode=write · watermark=on · c2pa_sign=on · embed_identity=on · brand_id=<yours>
```

The node writes the **signed file to your ComfyUI `output/` directory itself**
(named `<filename_prefix>_00000.png`) — you do **not** need a `SaveImage` after
it for the signed artifact. Wire the `image` output into a `PreviewImage` if you
want to see it.

### 3. Full generation provenance

> Goal: signed, plus a tamper-evident record of how it was generated.

```
   mode=write · watermark=on · c2pa_sign=on · embed_identity=on
   record_provenance=on            (curated: model, seed, sampler, prompts)
   include_full_workflow=on/off    (on = whole redacted graph; off = summary)
```

Because the node runs *inside* ComfyUI it can attest the graph a post-hoc signer
can't. Secrets (`api_key`, `token`, …) are dropped and paths shortened to
basenames even with `include_full_workflow` on.

### 4. Verify / read a mark

> Goal: check whether media already carries a provcheck mark.

```
Load{Image,Audio,Video} ─▶ Provcheck ─▶ (report / detected)
   mode=read
```

Wire the `report` (STRING) into any text-preview node and branch on `detected`
(BOOLEAN). Read needs `provcheck` on PATH.

### 5. Video

> Goal: mark a generated video.

```
… ─▶ CreateVideo ─▶ Provcheck ─▶ (writes <prefix>_video.mp4 to output/)
   mode=write · watermark=on · c2pa_sign=on/off
```

The mark rides the **audio track** (silentcipher), so the video needs a few
seconds of audio to carry it reliably. Frames are preserved; the container is
C2PA-signed when `c2pa_sign` is on. Like image/audio signing, the marked mp4 is
written to `output/` by the node.

### 6. Brand it as your own / drive inputs from the board

> Goal: stamp with your registered brand, or feed settings from other nodes.

Set `brand_id` to your registered id. For an API/graph-flow pipeline, right-click
`brand_id` (or `filename_prefix`, or any widget) → **Convert to input**, then
wire an `Int` / `String` / `Primitive` node into it — e.g. derive
`filename_prefix` from a text node so every render is named from the prompt.

---

## Signing setup (one-time)

`c2pa_sign` needs a local signing identity. Once per machine:

```bash
provcheck-kit init                 # mint a local signing key
provcheck-kit login <handle>       # link your atproto/Bluesky handle
provcheck-kit publish              # anchor the key to your Bluesky DID
```

After that, `c2pa_sign=on` + `embed_identity=on` produces files a verifier can
trace to `@handle`. If no identity is set up, the sign step fails and the node
falls back to a watermark-only passthrough with a console warning (it never
crashes the render).

`brand_id` is a 5-bit id (0–31) matching your atproto-published brand record.
The default `2` is the public rAIdio.bot brand — an ergonomic default, not a
requirement. Register your own brand and use its id; see the brand-registry docs
in the [provcheck repo](https://github.com/CreativeMayhemLtd/provcheck).

---

## Modality notes & gotchas

- **Image needs ONNX Runtime 1.22.** TrustMark runs on ONNX Runtime; `provcheck-kit`
  needs a 1.22.x runtime (set `ORT_DYLIB_PATH` to it, or install it) to embed **and**
  `provcheck` needs it to detect. Missing/mismatched runtime = the image mark silently
  no-ops. Audio/video (silentcipher) don't need it.
- **Signing writes a file, not a tensor.** A C2PA manifest lives in the file
  container; a decoded ComfyUI tensor can't carry it. So when `c2pa_sign` is on,
  the signed file goes to `output/` and the passthrough output is just for preview.
- **Video re-encodes the audio.** The node splits the audio out, marks it, and
  recombines with the original frames; the audio track is re-encoded (AAC). The
  silentcipher mark survives ordinary AAC, but give it a few seconds of audio.
- **Fails closed everywhere.** Missing CLI, missing identity, a bad frame — the
  input passes through with a note. `brand_id` is clamped to 0–31 server-side.

---

## What this node is NOT

- It is NOT bound to any brand — `brand_id` is an input.
- It is NOT Backfire. Creative Mayhem's keyed **Backfire** mark (which AI
  stripping *amplifies* instead of removing) is a separate commercial add-on:
  <https://provcheck.ai/backfire>.

---

## Architecture

A thin Python wrapper around the `provcheck-kit` / `provcheck` CLIs. Each
modality is serialised to a file (image → PNG, audio → 16-bit WAV, video → MP4
via ComfyUI's video API), handed to the kit's two-step (`stamp --no-sign` to
watermark, then `sign`), and re-loaded. The kit auto-detects modality from the
extension. `provcheck_comfyui/` holds the node (`c2pa_node.py`) + its internals
(`_helpers.py`); the repo-root `__init__.py` is the ComfyUI clone entrypoint.

## Tests

```bash
pip install pytest
pytest        # from the repo root (or: pytest tests/)
```

The suite mocks the CLIs (no binary invoked), so it runs without the Rust build.
`test_helpers.py` covers serialisation, report parsing, and manifest redaction;
`test_c2pa_node.py` covers the node (image/audio write, read/verify, sign argv,
provenance manifest, brand clamp, fail-closed passthrough). The full
install→mark→verify integration gate lives in the provcheck repo at
`scripts/test-comfyui-install.sh`.
