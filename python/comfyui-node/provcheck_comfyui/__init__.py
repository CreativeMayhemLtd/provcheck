"""provcheck-comfyui: ComfyUI nodes for stamping generated outputs.

Exposes ``NODE_CLASS_MAPPINGS`` + ``NODE_DISPLAY_NAME_MAPPINGS``
per the ComfyUI custom-node contract. Loaded automatically by
ComfyUI when the package lives in ``custom_nodes/`` and the
package is pip-installed.
"""

from .stamp_node import StampNode

NODE_CLASS_MAPPINGS = {
    "ProvcheckStamp": StampNode,
}

NODE_DISPLAY_NAME_MAPPINGS = {
    "ProvcheckStamp": "Stamp (provcheck)",
}

__all__ = ["NODE_CLASS_MAPPINGS", "NODE_DISPLAY_NAME_MAPPINGS"]
