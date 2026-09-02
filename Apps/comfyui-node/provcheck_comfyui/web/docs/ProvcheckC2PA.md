# Provcheck (Free C2PA Watermark)

The one provcheck node — **image, audio, and video, read or write**. Free and open
(Apache-2.0). Wire in any one modality or a mix; every option is a widget you can
type into **or** wire in from another node (right-click a widget → *Convert to
input*), for the API + graph-flow crowd.

## Mode

- **write** (default) — for each connected input, watermark and/or C2PA-sign it.
  This is what most people want: wire something in, get a signed, watermarked file.
- **read** — detect and verify an existing provcheck mark on each connected input,
  and report what it finds.

## Inputs (all optional — connect what you have)

- **image** — an image batch. Watermarked with the free **TrustMark-B** image mark.
- **audio** — an audio clip. Watermarked with **silentcipher** on the waveform.
- **video** — a video. The watermark rides the **audio track** (silentcipher) and the
  container is C2PA-signed. (Materialised to MP4 through ComfyUI's video API.)

## Write options

- **watermark** — embed the free FOSS watermark for each connected modality.
- **c2pa_sign** — C2PA-sign with your local signing key. The signed **file** is written
  to your ComfyUI output directory (a C2PA manifest lives in the file container, not in
  a decoded tensor a downstream Save node would re-encode — that is why signing writes
  the file itself).
- **embed_identity** — bake your atproto/Bluesky identity (DID + handle) into the
  manifest so a verifier sees who signed it. Needs a one-time `provcheck-kit login`.
- **record_provenance** — record a curated summary of the generation graph (model,
  seed, sampler, prompts) into the signed manifest. Because this node runs inside
  ComfyUI, it can attest the graph in a way a post-hoc signer cannot.
- **include_full_workflow** — with `record_provenance`, embed the FULL workflow, not
  just the summary. Off by default, and even when on it is redacted (secret-keyed
  inputs dropped, paths reduced to basenames).
- **brand_id** (0–31) — your 5-bit brand id from the atproto brand registry. Default
  `2` is the public rAIdio.bot id; register your own and use it.
- **filename_prefix** — output filename prefix for signed files.
- **timeout_secs** — per-item subprocess timeout.

## Outputs

- **image / audio / video** — the connected inputs, passed through for preview /
  chaining. When signing, the signed FILE in your output dir is the artifact (the
  passthrough carries no manifest).
- **report** — one line per modality (`image: signed 1/1`, `audio: watermarked 1/1`,
  or the read verdict).
- **detected** — read mode: True if any connected input carried a provcheck mark.

## Requirements

Needs `provcheck-kit` (write) / `provcheck` (read) on your PATH — install from the
[provcheck releases](https://github.com/CreativeMayhemLtd/provcheck/releases/latest).
If the tool is missing the node passes inputs through with a console note, so a render
queue never crashes. Identity signing also needs a one-time `provcheck-kit login`.

## Backfire (Pro, not in this pack)

Creative Mayhem also makes **Backfire**, a keyed watermark that AI provenance-stripping
*amplifies instead of removes* — it is optimized to be a fixed point of a diffusion
purifier, so running a stripper over it makes the keyed id read stronger. It is a
commercial add-on, not part of this free pack: <https://provcheck.ai/backfire>

Learn more: <https://provcheck.ai>
