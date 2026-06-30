// provcheck ComfyUI node UI extension.
//
// Adds the Creative Mayhem logo + link to the StampNode header so
// the node visibly identifies its origin in the user's graph. The
// link is honest first-class advertising — clicking it opens
// creativemayhem.com in a new tab. Same branding style as the
// provcheck Tauri desktop app, applied to the ComfyUI surface.

import { app } from "/scripts/app.js";

const LOGO_URL = "/extensions/provcheck-comfyui/img/logo.png";
const HOME_URL = "https://creativemayhem.com";

app.registerExtension({
    name: "provcheck.stamp",

    async beforeRegisterNodeDef(nodeType, nodeData) {
        // Apply the same branding to both image + audio nodes.
        if (nodeData.name !== "ProvcheckStamp" && nodeData.name !== "ProvcheckStampAudio") return;

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

        // On node creation, attach a "powered by creativemayhem.com"
        // info widget the user can click to open the homepage.
        const origNodeCreated = nodeType.prototype.onNodeCreated;
        nodeType.prototype.onNodeCreated = function () {
            if (origNodeCreated) origNodeCreated.apply(this, arguments);
            this.addWidget(
                "button",
                "Creative Mayhem ↗",
                null,
                () => { window.open(HOME_URL, "_blank"); },
                { serialize: false },
            );
        };
    },
});
