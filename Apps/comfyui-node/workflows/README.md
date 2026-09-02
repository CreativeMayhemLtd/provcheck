# Example workflow

## `provcheck_doomscroll_demo.json`

A minimal, runnable demo of the **Provcheck (Free C2PA Watermark)** node on audio:

```
LoadAudio ──▶ Provcheck (write) ──┬──▶ SaveAudio
                                  ├──▶ PreviewAudio
                                  └──▶ Provcheck (read)   → report / detected
```

The write node embeds the free silentcipher audio watermark (`brand_id = 2`,
`c2pa_sign` off so it runs with no identity setup); SaveAudio writes the marked
file to your ComfyUI output directory; the second Provcheck node in **read** mode
verifies the mark in-graph.

### Run it

1. Put any audio clip in your ComfyUI `input/` directory named `doomscroll_clip.wav`
   (or open the workflow and point the `LoadAudio` node at a file you already have).
2. In ComfyUI, open `provcheck_doomscroll_demo.json` (Workflow → Open, or drag it
   onto the canvas).
3. Make sure `provcheck-kit` is on your PATH (else the node fail-closes to
   passthrough with a console note).
4. Run. The output FLAC in your `output/` directory carries the watermark; verify
   it with `provcheck <file>` or read the second node's `report`.

To also **C2PA-sign**, flip `c2pa_sign` on after a one-time `provcheck-kit login`.
To brand it for your own project, set `brand_id` to your registered id (the demo
uses the public rAIdio.bot id `2`). The node is content-agnostic — swap in any audio.

## Workflow format

The JSON targets ComfyUI's `version: 0.4` workflow schema (what ComfyUI's "Save"
button emits). Older ComfyUI builds may not load it — upgrade ComfyUI before
reporting a load failure as a node bug.
