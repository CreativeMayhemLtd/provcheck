"""provcheck-comfyui: the ComfyUI node for provcheck.

Exposes ``NODE_CLASS_MAPPINGS`` + ``NODE_DISPLAY_NAME_MAPPINGS`` per the ComfyUI
custom-node contract. Loaded automatically when the package lives in
``custom_nodes/`` and is pip-installed.

ONE multifunction node — **Provcheck (Free C2PA Watermark)** (``ProvcheckC2PA``):
image, audio, and video, read or write. Wire in any one modality or a mix; in write
mode it watermarks (TrustMark on images, silentcipher on the audio track of
audio/video) and/or C2PA-signs with your atproto identity and optional generation
provenance; in read mode it detects/verifies a provcheck mark. Every option is a
widget that can also be wired in from another node.

The package is just this ``__init__``, ``c2pa_node`` (the node), and ``_helpers``
(serialisation, report parsing, and the C2PA manifest + redaction it builds on).
There is deliberately NO placeholder Backfire node — the paid Backfire mark is noted
in the node's info pane, not faked as a no-op node.

``WEB_DIRECTORY`` points ComfyUI at our static assets — the Creative Mayhem logo + a
JS extension that adds the logo to the node header and a single-line
"provcheck.ai · Creative Mayhem" link row.
"""

from .c2pa_node import ProvcheckC2PANode

NODE_CLASS_MAPPINGS = {
    "ProvcheckC2PA": ProvcheckC2PANode,
}

NODE_DISPLAY_NAME_MAPPINGS = {
    "ProvcheckC2PA": "Provcheck (Free C2PA Watermark) • Creative Mayhem",
}

# ComfyUI serves static files from this directory under /extensions/<package>/.
WEB_DIRECTORY = "./web"

__all__ = [
    "NODE_CLASS_MAPPINGS",
    "NODE_DISPLAY_NAME_MAPPINGS",
    "WEB_DIRECTORY",
    "ProvcheckC2PANode",
]
