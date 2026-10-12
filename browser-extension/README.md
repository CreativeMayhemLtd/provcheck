# provcheck browser extension (v1.5.0)

A privacy-respecting browser extension that inspects the media on a page for provenance and lets you
**filter what renders** — blur or hide images/videos by C2PA presence, AI-provenance markers, or a
keyword. It never alters the page's data or sends anything anywhere; it reads bytes locally and applies
a local visual filter (blur / hide) in your own browser.

## What it does
- **Detect C2PA.** Reads embedded C2PA manifests in-page with the official `c2pa` (WASM) SDK. Surfaces
  present/absent, the signer, and the assertion summary.
- **Grep for AI.** Reliable tier: C2PA AI-provenance assertions (`digitalSourceType: trainedAlgorithmic*`,
  generator actions) + keyword heuristics over alt-text/captions/manifest text. (Genuine watermark
  detection — SynthID / provcheck marks — stays in the desktop app; it needs detectors + keys and is not
  feasible in-browser. An optional in-browser ONNX AI-image classifier is a later stretch tier.)
- **Filter the render.** Rules: hide/blur when C2PA present (or absent), when an AI marker is present, or
  when a keyword matches. Local visual only — never modifies or re-uploads the media.

## Non-goals (honest scope)
- No in-browser provcheck/SynthID watermark detection (desktop/DLC path).
- No network calls, no telemetry, no page-data modification. Filtering is a local CSS overlay.

## Architecture (Manifest V3)
- `manifest.json` — MV3, `activeTab` + host permissions, content script + popup. Firefox variant via
  `browser_specific_settings`.
- `content.js` — scan `<img>`/`<video>`, apply the local blur/hide overlay per the rules, and for
  provenance rules ask the background worker to inspect each media URL. Re-scans on DOM mutations.
- `background.js` — service worker; fetches a media URL's bytes (host permissions read cross-origin bytes
  a content script cannot) and **byte-scans** for the C2PA JUMBF store + the standard AI assertion
  (`digitalSourceType: trainedAlgorithmicMedia`). Presence detection, cached per URL. Full WASM-SDK
  signature validation is a later polish, not needed for a blur/hide filter.
- `popup.html/js` — toggle the rules (C2PA present/absent, AI present, keyword) and the action (blur/hide),
  persisted via `chrome.storage`.

## Bricks
- B1 scaffold: manifest + popup + content-script skeleton. **[done]**
- B2 filter engine: blur/hide overlay + rule storage + keyword match over DOM/alt-text. **[done]**
- B3 C2PA/AI: background worker fetches bytes, byte-scans C2PA presence + the standard AI assertion;
  `known`-guarded so "C2PA absent" only fires on a confirmed absence. **[done]**
- B4 polish: icons (16/48/128); a **provenance badge** (hover tooltip verdict, so detection is visible,
  not only filtering); a **right-click "Inspect C2PA provenance"** context-menu that opens a panel with
  the media's C2PA summary (present/absent, AI-generated, producer/tool, standard assertion labels);
  loading/test notes. **[done]** Remaining store-listing + allowlist are packaging tasks.
- B5 (optional, later): full c2pa WASM SDK (signature validation + rich manifest view) and/or an
  in-browser ONNX AI-image classifier tier.

## Loading and testing
- **Chrome/Edge:** `chrome://extensions` -> Developer mode -> Load unpacked -> this folder. Open the
  popup, enable filtering, pick rules, and browse a page with C2PA-signed and AI images.
- **Firefox:** `about:debugging` -> This Firefox -> Load Temporary Add-on -> `manifest.json`. Note:
  older Firefox MV3 wants `"background": {"scripts": ["background.js"]}` instead of `service_worker`;
  the packaging step swaps that key for the Firefox build (a one-line transform, not a code change).
- Feature-complete for the spec (detect C2PA, grep AI, filter blur/hide by presence or keyword, show a
  badge). Not yet browser-load-verified in this environment (no browser available here) or store-listed.

## License
Apache-2.0: a public provcheck utility (C2PA reading + local render filtering), consistent with the
Apache core lineage. It contains no crown-jewel watermark method; the BUSL marking/tracing engines are
not part of this extension.
