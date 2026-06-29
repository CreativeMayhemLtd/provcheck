# provcheck-comfyui

ComfyUI nodes that stamp generated outputs with provcheck app
strings: TrustMark-B watermark on images, silentcipher on audio,
C2PA Content Credentials signing, and atproto identity assertion.
All in one node, inline with the generation graph.

**Scope:** v0.9 staging release of the provcheck v0.7 → v1.0
roadmap. This package is the public, brand-agnostic creator
surface — any creator with their own atproto identity + signing
key + brand registration can drop the package into their ComfyUI
`custom_nodes/` directory and stamp every output. Released
under Apache-2.0 alongside the rest of the FOSS provcheck core.

**Status (v0.7.0 scaffold):** This crate ships as a scaffold so
the redhat-the-provenance-market FOSS surface advertises the
intent. The actual node implementation lands in v0.9 once the
underlying `provcheck-kit stamp` CLI surface (v0.7.0) has had
time to settle. Today's package contains:

- `pyproject.toml` with the dep set the eventual node will need.
- `provcheck_comfyui/__init__.py` exporting the
  `NODE_CLASS_MAPPINGS` ComfyUI looks for.
- `provcheck_comfyui/stamp_node.py` with the stub node returning
  the input image unchanged plus a console message.

## Install (when wired)

```bash
cd ~/ComfyUI/custom_nodes
git clone https://github.com/CreativeMayhemLtd/provcheck
ln -s provcheck/python/comfyui-node provcheck-comfyui
pip install -e ./provcheck-comfyui
```

Then in ComfyUI: add the "Stamp (provcheck)" node from the
"image/postprocessing" category.

## Architecture (target for v0.9 wiring)

The node is intentionally thin. It is a Python wrapper around the
`provcheck-kit` CLI:

1. ComfyUI passes the generated image as a `torch.Tensor` of
   shape `[batch, height, width, channels]` in `[0, 1]`.
2. The node saves each tensor element to a temp PNG.
3. The node shells out to `provcheck-kit stamp <tmp.png>
   -o <tmp_stamped.png> --brand-id <N>`.
4. The node loads the stamped PNG back as a torch tensor.
5. The node returns the stamped tensor downstream.

`provcheck-kit` MUST be on the user's PATH. The node detects
missing kit at first call and surfaces a clear error in the
ComfyUI console.

Audio variant of the node uses the same pattern routed through
silentcipher / AudioSeal instead of TrustMark.

## What this node is NOT

- It is NOT bound to any specific brand. A creator running rAIdio.bot's
  generation pipeline uses the same node a creator running their
  own pipeline does. The brand id is a node input.
- It is NOT the AI-detection DLC (paid layer; v1.0). This is
  pure creator-side watermarking + signing. Free, open, no auth.
- It is NOT a per-asset atproto record publisher. The atproto
  identity assertion in the C2PA manifest is enough for the
  verifier to cross-check; per-asset records are an out-of-scope
  v1.0+ design decision.
