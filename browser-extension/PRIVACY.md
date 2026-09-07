# Provcheck AI Blur: Privacy Policy

Last updated: 2026-09-07

Provcheck AI Blur is a local-only browser extension. It does not collect, transmit, sell, or share any personal
data. There are no analytics, no telemetry, and no servers operated by us that the extension talks to.

## What the extension handles, and where it stays

- **Your filter settings** (which rules are on, the action, the keyword, the badge toggle) are stored
  locally in your browser through the browser's own extension storage. They stay on your device. We do
  not sync, read, or receive them.
- **Media inspection.** To decide whether to blur or hide a piece of media, the extension fetches the
  bytes of images and videos that are already present on the page you are viewing, directly from that
  media's own host, and scans those bytes locally for provenance data (C2PA) and the standard AI-provenance
  assertion. Those requests go to the media's origin server, the same server your browser already loaded
  the media from. They do not go to us. Results are held in memory for the current session only and are
  never transmitted anywhere.
- **YouTube AI label.** On YouTube, the extension reads the page's own "Altered or synthetic content" AI
  label from the page you are viewing. This reading happens locally, in your browser.

## What the extension does not do

- It does not collect personal information, browsing history, account details, or credentials.
- It does not send any data to the extension's authors or to any third party.
- It does not sell or share data with anyone, because it collects none.
- It does not modify, upload, or re-transmit the media on the pages you visit. Filtering is a local visual
  overlay (blur or hide) applied only within your browser tab.
- It uses no cookies and performs no tracking.

## Permissions, and why each is needed

- **Access to the websites you visit (host permissions):** used only so the extension can fetch media
  bytes from the page's own hosts and scan them locally for provenance. No page content is sent anywhere.
- **storage:** to save your filter settings locally on your device.
- **activeTab and scripting:** to run the content script that applies the local blur or hide filter on the
  current tab.
- **contextMenus:** to add the right-click "Inspect C2PA provenance" option.

## Network activity

The only network requests the extension makes are to fetch the bytes of media already loaded on the page
you are viewing, from that media's own servers, for the sole purpose of scanning them locally for
provenance. The extension contacts no server operated by the authors.

## Data retention

The authors retain no data, because none is collected. Your settings remain in your browser until you
change them, clear them, or uninstall the extension.

## Children

The extension collects no data from anyone, including children.

## Changes to this policy

If this policy changes, the updated version will be published with a new "Last updated" date at the same
location as this document.

## Contact

Publisher: Creative Mayhem UG.
Questions about this policy: info@creativemayhem.com.
