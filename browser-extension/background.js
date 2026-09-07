// provcheck background service worker: fetch a media URL's bytes (host permissions let us read
// cross-origin bytes a content script cannot) and detect C2PA provenance + an AI-provenance marker by
// scanning the file. This is PRESENCE detection (byte scan of the C2PA JUMBF store + the standard
// digitalSourceType assertion), not full signature validation -- adequate for a blur/hide filter, and
// honestly labelled as such. Results are cached per URL. No network beyond fetching the media itself.
"use strict";

const cache = new Map();      // url -> {c2pa, ai}
const MAX_BYTES = 8 * 1024 * 1024;   // cap: scan at most the first 8 MB of a file

// ASCII markers. C2PA data lives in a JUMBF box labelled "c2pa"; AI-generated media is declared by the
// standard assertion digitalSourceType = trainedAlgorithmicMedia (or compositeWithTrainedAlgorithmicMedia).
const C2PA_MARKERS = ["jumbf", "c2pa"];
const AI_MARKERS = ["trainedAlgorithmicMedia", "compositeWithTrainedAlgorithmicMedia"];

function findAscii(u8, s) {
  const n = s.length, L = u8.length - n;
  for (let i = 0; i <= L; i++) {
    let k = 0;
    while (k < n && u8[i + k] === s.charCodeAt(k)) k++;
    if (k === n) return i;
  }
  return -1;
}

function scan(buf) {
  const u8 = new Uint8Array(buf, 0, Math.min(buf.byteLength, MAX_BYTES));
  const c2pa = C2PA_MARKERS.every((m) => findAscii(u8, m) >= 0);   // both the box type and the c2pa label
  const ai = c2pa && AI_MARKERS.some((m) => findAscii(u8, m) >= 0);
  return { c2pa, ai };
}

async function inspect(url) {
  if (cache.has(url)) return cache.get(url);
  let res = { c2pa: false, ai: false, known: false };   // known=false -> fetch blocked, never act on "absent"
  try {
    const r = await fetch(url, { credentials: "omit" });
    if (r.ok) {
      const s = scan(await r.arrayBuffer());
      res = { c2pa: s.c2pa, ai: s.ai, known: true };
    }
  } catch (_e) {
    /* opaque/blocked fetch -> unknown, no filter */
  }
  cache.set(url, res);
  return res;
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === "inspect" && msg.url) {
    inspect(msg.url).then(sendResponse);
    return true;   // async response
  }
});

// --- richer manifest extraction for the right-click "Inspect C2PA provenance" panel ---
// Byte-scan the C2PA store for recognizable markers: standard assertion labels + known generator/tool
// strings. This is a readable summary, not the full validated manifest (that needs the c2pa WASM SDK,
// a later addition, not in this build).
const LABELS = ["c2pa.actions", "c2pa.hash.data", "c2pa.thumbnail", "stds.schema-org.CreativeWork",
  "c2pa.training-mining", "cawg.identity", "c2pa.metadata"];
const GEN_HINTS = ["Adobe", "Firefly", "Photoshop", "Lightroom", "Midjourney", "DALL", "OpenAI", "Gemini",
  "Imagen", "Leonardo", "Stability", "c2patool", "contentauth", "Truepic", "provcheck", "rAIdio", "Creative Mayhem"];

function extract(buf) {
  const u8 = new Uint8Array(buf, 0, Math.min(buf.byteLength, MAX_BYTES));
  const c2pa = C2PA_MARKERS.every((m) => findAscii(u8, m) >= 0);
  if (!c2pa) return { c2pa: false, ai: false, labels: [], gens: [], known: true };
  return {
    c2pa: true,
    ai: AI_MARKERS.some((m) => findAscii(u8, m) >= 0),
    labels: LABELS.filter((l) => findAscii(u8, l) >= 0),
    gens: GEN_HINTS.filter((g) => findAscii(u8, g) >= 0),
    known: true,
  };
}

async function inspectFull(url) {
  try {
    const r = await fetch(url, { credentials: "omit" });
    if (r.ok) return extract(await r.arrayBuffer());
  } catch (_e) {
    /* blocked fetch */
  }
  return { c2pa: false, ai: false, labels: [], gens: [], known: false };
}

// removeAll before create: on an extension reload onInstalled fires again, and a bare create() with the
// same id throws "Cannot create item with duplicate id" (and logs an unchecked lastError).
function installMenu() {
  try {
    chrome.contextMenus.removeAll(() => {
      void chrome.runtime.lastError;
      chrome.contextMenus.create({
        id: "provcheck-inspect",
        title: "Inspect C2PA provenance",
        contexts: ["image", "video"],
      });
      void chrome.runtime.lastError;
    });
  } catch (_e) {
    /* contextMenus unavailable */
  }
}
chrome.runtime.onInstalled.addListener(installMenu);
chrome.runtime.onStartup.addListener(installMenu);

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  try {
    if (info.menuItemId !== "provcheck-inspect" || !info.srcUrl || !tab) return;
    const data = await inspectFull(info.srcUrl);
    data.url = info.srcUrl;
    chrome.tabs.sendMessage(tab.id, { type: "showPanel", data }, () => { void chrome.runtime.lastError; });
  } catch (_e) {
    /* tab gone or no content script; nothing to do */
  }
});
