# Provcheck AI Blur (browser extension, v1.4.1)

A privacy-respecting browser extension that inspects the media on a page for provenance signals and lets
you **filter what renders**: blur or hide images and videos by C2PA presence, AI-provenance markers,
YouTube's own AI self-disclosure, or a keyword. It never alters the page's data or sends anything
anywhere. It reads bytes locally and applies a local visual filter (blur or hide) in your own browser.

## What it does
- **Detect C2PA presence.** For media it can fetch as a real file, it byte-scans for the C2PA JUMBF store
  and reports present or absent. This is presence detection, not signature validation: it does not verify
  the cryptographic signature or read the signer. Full manifest validation (the official `c2pa` WASM SDK)
  is a planned later addition, not part of this build.
- **Flag AI.** Two signals, both honest about their source:
  - the standard C2PA assertion `digitalSourceType: trainedAlgorithmicMedia` (byte-scanned when the file
    is fetchable), and
  - YouTube's own "Altered or synthetic content" disclosure, read from the page (this is the uploader's
    self-declaration surfaced by YouTube, not a validated manifest).
- **Filter the render.** Rules: blur or hide when C2PA is present (or confirmed absent), when an AI marker
  is present, or when a keyword matches nearby text (alt, title, captions). Blurred media gets an
  **"AI Generated Content Detected"** banner (the caption states the actual reason per rule). The filter
  is a local CSS overlay only. It never modifies or re-uploads the media.
- **Show the verdict.** An optional hover badge and a right-click "Inspect C2PA provenance" panel show the
  byte-scan summary (present or absent, AI marker, recognizable producer and assertion strings), clearly
  labelled as a byte-scan summary rather than a validated manifest.

## Honest limits
- **It reads provenance and platform labels, not pixels.** It flags AI from a C2PA AI assertion or a
  platform's own label (YouTube), never by looking at the image itself. Unlabelled generator output with
  no provenance, which is most of what AI-art sites host, carries no signal and is not flagged. Pixel-based
  AI detection (an in-browser classifier) is a possible later tier, not part of this build.
- **Content a platform publishes without the AI mark the law requires.** Since 2 August 2026,
  **[EU AI Act Article 50](https://eur-lex.europa.eu/eli/reg/2024/1689/oj)** has required AI-generated
  image, audio, video, and text to carry an effective, machine-readable AI mark, and deployers to disclose
  deepfakes. A platform that ignores that obligation publishes AI content
  with no signal at all, so nothing, this extension included, can flag it. That gap is the platform's
  non-compliance with the law, not a limit of detection.
- **Presence, not validation.** It confirms a C2PA store is present and byte-scans for standard markers.
  It does not validate the signature or identify the signer.
- **Streamed and blob media cannot be read.** The scanner fetches real file bytes, so it cannot read a
  media stream delivered as a `blob:` URL, which is how players like YouTube deliver the playing video.
  On YouTube it therefore relies on the page's AI-disclosure label and on thumbnail and page images, not
  on the stream itself.
- **Platforms that re-encode strip provenance.** Sites that transcode uploads (YouTube among them) remove
  the C2PA manifest from the delivered copy, so a signed original can read as unsigned once re-encoded.
  This is exactly the gap that an in-media, transcode-surviving mark is meant to close; that watermark
  work lives in the desktop app, not here.
- **Thumbnails a site serves with the provenance stripped.** Many sites generate their own thumbnail or
  preview of an image and serve that re-encoded copy, with the C2PA manifest removed, even when the
  original was signed, and in a feed the thumbnail is often all you ever see. The extension scans the
  bytes actually served to your browser, so a stripped thumbnail reads as unsigned. The original file, not
  the site's thumbnail, is what carries the provenance.
- **Local only.** No network beyond fetching the media it inspects, no telemetry, and no modification of
  the page's data.

## How it works (Manifest V3)
- `manifest.json`: MV3, `activeTab` plus host permissions, a content script, a background service worker,
  and a popup.
- `content.js`: scans `<img>` and `<video>`, reads YouTube's AI-disclosure label when on YouTube, applies
  the local blur or hide overlay per the rules, draws the banner, and re-scans on DOM changes (throttled
  so a constantly mutating page cannot starve it).
- `background.js`: the service worker fetches a media URL's bytes (host permissions let it read
  cross-origin bytes a content script cannot) and byte-scans for the C2PA JUMBF store and the standard AI
  assertion. Results are cached per URL.
- `popup.html` and `popup.js`: toggle the rules (C2PA present or absent, AI present, keyword), the action
  (blur or hide), and the hover badge, persisted via `chrome.storage`.

## Loading and testing
- **Chrome, Edge, Brave (Chromium):** open `chrome://extensions`, enable Developer mode, choose Load
  unpacked, and select this folder. Open the popup, enable filtering, pick rules, and browse a page with
  C2PA-signed images, AI-labelled YouTube videos, or a keyword you set.
- **Firefox:** support is pending verification. Firefox's MV3 background model differs from Chromium's, so
  the packaging step needs to be confirmed on a current Firefox before Firefox is claimed as supported.

## License
Apache-2.0: a public provcheck utility for reading C2PA presence signals and applying a local render
filter, consistent with the Apache core lineage. It contains no watermark method and no signing or
tracing engine.
