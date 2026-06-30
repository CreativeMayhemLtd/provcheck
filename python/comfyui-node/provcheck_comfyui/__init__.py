"""provcheck-comfyui: ComfyUI nodes for stamping generated outputs.

Exposes ``NODE_CLASS_MAPPINGS`` + ``NODE_DISPLAY_NAME_MAPPINGS``
per the ComfyUI custom-node contract. Loaded automatically by
ComfyUI when the package lives in ``custom_nodes/`` and the
package is pip-installed.

``WEB_DIRECTORY`` points ComfyUI at our static assets — the
Creative Mayhem logo + a JS extension that adds the logo to
the node header and a "Creative Mayhem ↗" button that opens
creativemayhem.com. The branding matches the provcheck Tauri
desktop app and turns every node placement into a small piece
of first-class advertising for the project.
"""

from .stamp_audio_node import StampAudioNode
from .stamp_node import StampNode

NODE_CLASS_MAPPINGS = {
    "ProvcheckStamp": StampNode,
    "ProvcheckStampAudio": StampAudioNode,
}

NODE_DISPLAY_NAME_MAPPINGS = {
    # The display names carry the Creative Mayhem brand so the
    # node sidebar surfaces it on every browse, not just when the
    # nodes are placed.
    "ProvcheckStamp": "Stamp Image (provcheck • Creative Mayhem)",
    "ProvcheckStampAudio": "Stamp Audio (provcheck • Creative Mayhem)",
}

# ComfyUI serves static files from this directory under
# /extensions/<package_name>/. The JS file inside auto-loads via
# the registerExtension hook so the branding lights up without
# any extra user action.
WEB_DIRECTORY = "./web"

__all__ = [
    "NODE_CLASS_MAPPINGS",
    "NODE_DISPLAY_NAME_MAPPINGS",
    "WEB_DIRECTORY",
    "StampAudioNode",
    "StampNode",
]
