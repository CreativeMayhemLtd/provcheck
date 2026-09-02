// provcheck ComfyUI node UI extension.
//
// Adds the Creative Mayhem logo + link to the node header so the node
// visibly identifies its origin in the user's graph. The link is honest
// first-class advertising — clicking it opens creativemayhem.com in a new
// tab. Same branding style as the provcheck Tauri desktop app, applied to
// the ComfyUI surface.

import { app } from "/scripts/app.js";

// Resolve the logo relative to THIS script's served location, so it works
// whether the pack is pip-installed (/extensions/provcheck_comfyui/) or
// cloned into custom_nodes under any folder name.
const LOGO_URL = new URL("./img/logo.png", import.meta.url).href;
const HOME_URL = "https://creativemayhem.com";
const PROV_URL = "https://provcheck.ai";

app.registerExtension({
    name: "provcheck.branding",

    async beforeRegisterNodeDef(nodeType, nodeData) {
        // Apply the branding to the provcheck node.
        if (!nodeData.name || !nodeData.name.startsWith("Provcheck")) return;

        // Augment the node's title bar with a logo + link.
        const origDrawForeground = nodeType.prototype.onDrawForeground;
        nodeType.prototype.onDrawForeground = function (ctx) {
            if (origDrawForeground) origDrawForeground.apply(this, arguments);
            if (this.flags && this.flags.collapsed) return;

            // Cache the logo image on the node instance.
            if (!this._provcheckLogo) {
                const img = new Image();
                img.src = LOGO_URL;
                this._provcheckLogo = img;
            }
            const img = this._provcheckLogo;
            if (img.complete && img.naturalWidth > 0) {
                // Draw a 24x24 logo in the bottom-right corner.
                const size = 24;
                const pad = 6;
                const x = this.size[0] - size - pad;
                const y = this.size[1] - size - pad;
                ctx.save();
                ctx.globalAlpha = 0.85;
                ctx.drawImage(img, x, y, size, size);
                ctx.restore();
            }
        };

        // On node creation, attach a single-line link row with BOTH external
        // links: "provcheck.ai · Creative Mayhem", each independently clickable.
        const origNodeCreated = nodeType.prototype.onNodeCreated;
        nodeType.prototype.onNodeCreated = function () {
            if (origNodeCreated) origNodeCreated.apply(this, arguments);

            const mkLink = (label, url) => {
                const a = document.createElement("a");
                a.textContent = label;
                a.href = url;
                a.target = "_blank";
                a.rel = "noopener noreferrer";
                a.style.cssText =
                    "color:#5cc8ff;text-decoration:none;cursor:pointer;white-space:nowrap;";
                // Stop the click from being eaten by the canvas / node drag.
                a.addEventListener("pointerdown", (e) => e.stopPropagation());
                a.addEventListener("click", (e) => e.stopPropagation());
                return a;
            };

            if (this.addDOMWidget) {
                // One row, two links (preferred: a real DOM widget).
                const row = document.createElement("div");
                row.style.cssText =
                    "display:flex;gap:8px;align-items:center;justify-content:center;" +
                    "width:100%;font-size:11px;line-height:1.4;padding:2px 0;";
                const sep = document.createElement("span");
                sep.textContent = "·";
                sep.style.cssText = "opacity:0.5;";
                row.appendChild(mkLink("provcheck.ai ↗", PROV_URL));
                row.appendChild(sep);
                row.appendChild(mkLink("Creative Mayhem ↗", HOME_URL));
                this.addDOMWidget("provcheck_links", "provcheck_links", row, {
                    serialize: false,
                    hideOnZoom: false,
                });
            } else {
                // Fallback for older ComfyUI without DOM widgets: one button that
                // opens provcheck.ai (the primary), Creative Mayhem reachable from there.
                this.addWidget(
                    "button",
                    "provcheck.ai · Creative Mayhem ↗",
                    null,
                    () => { window.open(PROV_URL, "_blank"); },
                    { serialize: false },
                );
            }
        };
    },
});
