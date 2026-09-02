"""ComfyUI custom-node entrypoint.

This directory is the ROOT of the standalone ComfyUI-Provcheck repo, which a user
clones straight into ``ComfyUI/custom_nodes/``. ComfyUI imports THIS ``__init__`` and
reads the node registration from it. The node code lives in the ``provcheck_comfyui``
subpackage; this re-exports its mappings and points ComfyUI at the web assets under it.
"""

try:
    # Normal path: ComfyUI imports this directory as a package.
    from .provcheck_comfyui import NODE_CLASS_MAPPINGS, NODE_DISPLAY_NAME_MAPPINGS
except ImportError:
    # Imported as a top-level module (e.g. pytest collecting the repo root): there is no
    # parent package for the relative import, so fall back to an absolute import.
    import os
    import sys

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from provcheck_comfyui import NODE_CLASS_MAPPINGS, NODE_DISPLAY_NAME_MAPPINGS

# ComfyUI serves this (relative to this dir) under /extensions/<node>/. The web assets
# live inside the subpackage.
WEB_DIRECTORY = "./provcheck_comfyui/web"

__all__ = ["NODE_CLASS_MAPPINGS", "NODE_DISPLAY_NAME_MAPPINGS", "WEB_DIRECTORY"]
