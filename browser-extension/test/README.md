# provcheck extension tests

Headless tests for the extension. No browser required.

```
cd browser-extension/test
npm install
npm test
```

- `logic.test.js`: loads the real `content.js` and `background.js` into a `vm` context with mocked
  `chrome.*` and DOM, and asserts the detector and filter decision logic (C2PA presence, AI markers,
  YouTube AI self-disclosure, keyword, banner labels, and the orphaned-context guard).
- `integration.test.js`: loads the real `content.js` into a full DOM (jsdom) with a real
  `MutationObserver` and event loop, then drives it through live scenarios (a normal site, YouTube
  Shorts, a busy mutating feed, an extension reload that invalidates the context, and a background that
  stops responding) and **fails on any uncaught error the way Chrome would**. It also checks that
  `background.js` re-installs its context menu without a duplicate-id error on reload.

These run entirely in Node, so a change to the extension can be verified without loading it into a
browser. A real browser pass is still worthwhile before a release, but these catch the runtime errors.
