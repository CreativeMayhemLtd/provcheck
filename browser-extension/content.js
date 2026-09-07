// provcheck content script: scan page media and apply a LOCAL render filter (blur/hide) per the user's
// rules. It never modifies or re-uploads the media; it only toggles CSS on the elements in this tab.
// Live: keyword, blur/hide, C2PA-presence + AI-marker byte-scan, and YouTube's AI self-disclosure.
// Full C2PA manifest validation (the c2pa WASM SDK) is a later addition, not in this build.
"use strict";

const STYLE_ID = "provcheck-filter-style";
const TAG = "data-provcheck";

function ensureStyle() {
  if (document.getElementById(STYLE_ID)) return;
  const s = document.createElement("style");
  s.id = STYLE_ID;
  s.textContent =
    ".provcheck-blur{filter:blur(40px)!important;transition:filter .12s ease}" +
    ".provcheck-hide{visibility:hidden!important}" +
    ".provcheck-banner{position:fixed;z-index:2147483646;pointer-events:none;" +
    "background:rgba(180,69,58,.94);color:#fff;font:600 13px/1.3 system-ui,-apple-system,sans-serif;" +
    "padding:6px 12px;border-radius:6px;box-shadow:0 2px 10px rgba(0,0,0,.4);white-space:nowrap;" +
    "letter-spacing:.02em;max-width:90vw;text-align:center}";
  (document.head || document.documentElement).appendChild(s);
}

function nearbyText(el) {
  const bits = [el.alt, el.title, el.getAttribute && el.getAttribute("aria-label")];
  const fig = el.closest && el.closest("figure");
  if (fig) bits.push(fig.textContent);
  if (el.parentElement) bits.push(el.parentElement.getAttribute && el.parentElement.getAttribute("aria-label"));
  return bits.filter(Boolean).join(" ").toLowerCase();
}

// --- YouTube's own "Altered or synthetic content" AI self-declaration -------------------------
// Unlike the video stream's C2PA (a blob the byte-scanner cannot read, and which YouTube's re-encode
// usually strips), YouTube renders the uploader's AI disclosure as TEXT in the page. We read that text.
// This is a site heuristic matched by localized phrase, NOT a validated manifest -- reported as such.
const YT_AI_PHRASES = [
  "altered or synthetic content",             // en
  "veränderte oder synthetische inhalte",     // de
  "veranderte oder synthetische inhalte",     // de, umlaut-folded fallback
];
function isYouTube() {
  const h = location.hostname;
  return h === "youtube.com" || h.endsWith(".youtube.com") || h === "youtu.be" || h.endsWith(".youtu.be");
}
let ytAiFlag = false;
function youtubeAiDeclared() {
  if (!isYouTube()) return false;
  // 1) full-phrase text of the watch-page banner / mobile description region
  const scope =
    document.querySelector("#primary #below") ||
    document.querySelector("ytd-watch-metadata") ||
    document.querySelector("#primary") ||
    document.body;
  const txt = ((scope && (scope.innerText || scope.textContent)) || "").toLowerCase();
  if (YT_AI_PHRASES.some((p) => txt.includes(p))) return true;
  // 2) some chips carry the full phrase in their ACCESSIBLE label; matching the full phrase there is safe
  const labelled = document.querySelectorAll("[aria-label], [title]");
  for (const el of labelled) {
    const a = (((el.getAttribute && el.getAttribute("aria-label")) || "") + " " + (el.title || "")).toLowerCase();
    if (YT_AI_PHRASES.some((p) => a.includes(p))) return true;
  }
  // 3) YouTube's compact AI-disclosure chip (Shorts + feed) shows the bare text "AI". Match a LEAF element
  //    whose exact own-text is "AI". Host-gated to youtube, so a stray "AI" word elsewhere can't fire it.
  const all = document.querySelectorAll("*");
  for (let i = 0; i < all.length; i++) {
    const el = all[i];
    if (el.children && el.children.length > 1) continue;   // leaf-ish only; skip large containers
    let own = "";
    const kids = el.childNodes || [];
    for (let j = 0; j < kids.length; j++) if (kids[j].nodeType === 3) own += kids[j].nodeValue;
    if (own.trim() === "AI") return true;
  }
  return false;
}

// --- C2PA / AI detection via the background service worker (fetches bytes, byte-scans presence) ---
function mediaUrl(el) {
  const u = el.currentSrc || el.src || (el.getAttribute && el.getAttribute("src")) || "";
  return u && !u.startsWith("data:") ? u : "";
}
function inspectUrl(url) {
  return new Promise((resolve) => {
    if (!alive()) { resolve({ known: false }); return; }
    try {
      chrome.runtime.sendMessage({ type: "inspect", url }, (res) => {
        try { void chrome.runtime.lastError; } catch (_e) {}   // read it so Chrome does not log "Unchecked runtime.lastError"
        resolve(res || { known: false });
      });
    } catch (_e) {
      resolve({ known: false });   // "Extension context invalidated" mid-flight
    }
  });
}

// Returns a short reason LABEL (shown on the banner) when the element should be filtered, else "".
async function evaluate(el, rules) {
  if (rules.keyword) {
    const kw = rules.keyword.trim().toLowerCase();
    if (kw && nearbyText(el).includes(kw)) return "Filtered keyword: " + rules.keyword.trim();
  }
  // YouTube's own AI self-declaration (page-level), read from the DOM since the stream C2PA is unreadable
  if (rules.aiPresent && ytAiFlag && el.tagName === "VIDEO") return "AI Generated Content Detected";
  if (rules.c2paPresent || rules.c2paAbsent || rules.aiPresent) {
    const url = mediaUrl(el);
    if (url) {
      const r = await inspectUrl(url);
      if (rules.aiPresent && r.ai) return "AI Generated Content Detected";
      if (rules.c2paPresent && r.c2pa) return "C2PA Provenance Detected";
      if (rules.c2paAbsent && r.known && !r.c2pa) return "No C2PA Provenance";   // only a confirmed absence
    }
  }
  return "";
}

// label = reason string (truthy => filter this element), "" => clear it.
function apply(el, label, action) {
  el.classList.remove("provcheck-blur", "provcheck-hide");
  if (label && action === "hide") {
    el.classList.add("provcheck-hide");
    removeBanner(el);   // a hidden element gets no banner (nothing to caption)
  } else if (label) {
    el.classList.add("provcheck-blur");
    ensureBanner(el, label);
  } else {
    removeBanner(el);
  }
}

// --- "AI Generated Content Detected" style banner overlaid on blurred media -------------------
const banners = new Map();   // element -> its banner div
function bannerFits(el) {
  const r = el.getBoundingClientRect();
  return r.width >= 180 && r.height >= 120;   // skip tiny thumbnails/avatars, they would be swamped
}
function positionBanner(el, b) {
  const r = el.getBoundingClientRect();
  b.style.top = Math.max(8, r.top + 10) + "px";
  b.style.left = r.left + r.width / 2 + "px";
  b.style.transform = "translateX(-50%)";
}
function ensureBanner(el, label) {
  if (!bannerFits(el)) { removeBanner(el); return; }
  let b = banners.get(el);
  if (!b) {
    b = document.createElement("div");
    b.className = "provcheck-banner";
    document.documentElement.appendChild(b);
    banners.set(el, b);
  }
  b.textContent = label;
  positionBanner(el, b);
}
function removeBanner(el) {
  const b = banners.get(el);
  if (b) { b.remove(); banners.delete(el); }
}
function repositionBanners() {
  banners.forEach((b, el) => {
    if (!el.isConnected || !el.classList.contains("provcheck-blur")) { b.remove(); banners.delete(el); return; }
    positionBanner(el, b);
  });
}

function clearAll() {
  document.querySelectorAll(".provcheck-blur, .provcheck-hide").forEach((e) => {
    e.classList.remove("provcheck-blur", "provcheck-hide");
  });
  banners.forEach((b) => b.remove());
  banners.clear();
}

async function badge(el) {
  if (ytAiFlag && el.tagName === "VIDEO") {
    el.setAttribute("title", "provcheck: AI-declared (YouTube disclosure)");
    return;
  }
  const url = mediaUrl(el);
  if (!url) return;
  const r = await inspectUrl(url);
  if (!r.known) return;
  const v = r.ai ? "AI-generated (C2PA)" : r.c2pa ? "C2PA provenance present" : "no C2PA provenance";
  el.setAttribute("title", "provcheck: " + v);
}

let scanning = false;
async function scan(rules) {
  if (scanning) return;
  scanning = true;
  try {
    ensureStyle();
    ytAiFlag = youtubeAiDeclared();   // page-level YouTube AI disclosure, computed once per scan
    const els = [...document.querySelectorAll("img, video")];
    const action = rules.action || "blur";
    // FAST PATH: the page-level YouTube AI disclosure needs NO network, so blur videos instantly instead
    // of waiting behind the per-image byte fetches below (this is what caused the multi-second lag).
    if (rules.aiPresent && ytAiFlag) {
      for (const el of els) if (el.tagName === "VIDEO") apply(el, "AI Generated Content Detected", action);
    }
    // FULL PASS: byte-scan evaluation, now in PARALLEL (was sequential -> seconds on media-heavy pages).
    await Promise.all(els.map(async (el) => {
      try {
        apply(el, await evaluate(el, rules), action);
        if (rules.badge) await badge(el);   // provenance verdict as a hover tooltip
      } catch (_e) { /* one bad element must never abort the scan or bubble an uncaught error */ }
    }));
  } finally {
    scanning = false;
  }
}

// After the extension is reloaded/updated, content scripts already injected in open tabs are ORPHANED:
// their chrome.* calls throw "Extension context invalidated". Detect that and shut this instance down
// quietly (disconnect observers/listeners, drop banners) instead of spamming the tab with errors.
function alive() {
  try { return !!(chrome.runtime && chrome.runtime.id); } catch (_e) { return false; }
}
let torndown = false;
function onScroll() { try { repositionBanners(); } catch (_e) {} }
function onResize() { try { repositionBanners(); } catch (_e) {} }
function teardown() {
  if (torndown) return;
  torndown = true;
  try { mo.disconnect(); } catch (_e) {}
  try {
    window.removeEventListener("scroll", onScroll, true);
    window.removeEventListener("resize", onResize);
  } catch (_e) {}
  try { clearAll(); } catch (_e) {}
}

function loadRules(cb) {
  try {
    chrome.storage.local.get(["provcheckRules"], (r) => {
      try { void chrome.runtime.lastError; } catch (_e) {}
      cb((r && r.provcheckRules) || {});
    });
  } catch (_e) {
    teardown();   // context invalidated between scheduling and running
  }
}

function run() {
  if (!alive()) { teardown(); return; }
  loadRules((rules) => {
    try {
      if (rules.enabled) { const p = scan(rules); if (p && p.catch) p.catch(() => {}); }
      else clearAll();
    } catch (_e) {}
  });
}

// initial pass + react to rule changes + re-scan on DOM mutations (SPAs / infinite scroll). Every entry
// point below is wrapped so this content script can never surface an uncaught error into the host page,
// whether it is live or an orphan left by an extension reload.
run();
try {
  chrome.storage.onChanged.addListener((c) => { try { if (c && c.provcheckRules) run(); } catch (_e) {} });
} catch (_e) {}
// Throttle (leading + trailing, 500ms max) rather than a pure trailing debounce: a page that mutates
// continuously (YouTube) would keep resetting a debounce and starve the scan for seconds.
let lastRun = 0, pending = 0;
function schedule() {
  const since = Date.now() - lastRun;
  clearTimeout(pending);
  if (since >= 500) { lastRun = Date.now(); run(); }
  else { pending = setTimeout(() => { lastRun = Date.now(); run(); }, 500 - since); }
}
const mo = new MutationObserver(() => { try { schedule(); } catch (_e) {} });
mo.observe(document.documentElement, { childList: true, subtree: true });
// keep banners glued to their media as the page scrolls or resizes
window.addEventListener("scroll", onScroll, true);
window.addEventListener("resize", onResize);

// --- right-click "Inspect C2PA provenance" panel. Built with DOM nodes + textContent (no innerHTML),
//     so page-derived strings (producer/tool, assertion labels) can never be interpreted as markup. ---
function panelRow(box, text) {
  const r = document.createElement("div");
  r.style.margin = "3px 0";
  if (text != null) r.textContent = text;
  box.appendChild(r);
  return r;
}
function boldEl(text) { const b = document.createElement("b"); b.textContent = text; return b; }
function showPanel(d) {
  const old = document.getElementById("provcheck-panel");
  if (old) old.remove();
  const box = document.createElement("div");
  box.id = "provcheck-panel";
  box.style.cssText =
    "position:fixed;top:16px;right:16px;z-index:2147483647;max-width:340px;background:#fff;color:#1a1a1a;" +
    "border:1px solid #ccc;border-radius:8px;box-shadow:0 4px 18px rgba(0,0,0,.2);" +
    "font:13px system-ui,sans-serif;padding:12px 14px;line-height:1.5";
  const head = document.createElement("div");
  head.style.cssText = "display:flex;justify-content:space-between;align-items:center;margin-bottom:6px";
  head.appendChild(boldEl("provcheck"));
  const x = document.createElement("span");
  x.style.cssText = "cursor:pointer;color:#888;font-size:16px";
  x.textContent = "×";
  x.addEventListener("click", () => box.remove());
  head.appendChild(x);
  box.appendChild(head);
  if (!d.known) {
    panelRow(box).appendChild(boldEl("Could not read the image bytes"));
    box.lastChild.appendChild(document.createTextNode(" (blocked by the site)."));
  } else if (!d.c2pa) {
    panelRow(box).appendChild(boldEl("No C2PA provenance"));
    box.lastChild.appendChild(document.createTextNode(" found in this media."));
  } else {
    const r = panelRow(box);
    r.appendChild(boldEl("C2PA provenance present"));
    if (d.ai) {
      const ai = document.createElement("span");
      ai.style.color = "#b4453a";
      ai.textContent = " · AI-generated";
      r.appendChild(ai);
    }
    if (d.gens && d.gens.length) panelRow(box, "Producer/tool: " + d.gens.join(", "));
    if (d.labels && d.labels.length) panelRow(box, "Assertions: " + d.labels.join(", "));
    const note = panelRow(box, "Byte-scan summary, not a validated manifest.");
    note.style.color = "#888";
    note.style.fontSize = "11px";
  }
  document.documentElement.appendChild(box);
  setTimeout(() => { if (box.parentNode) box.remove(); }, 15000);
}
try {
  chrome.runtime.onMessage.addListener((msg) => {
    try { if (msg && msg.type === "showPanel") showPanel(msg.data); } catch (_e) {}
  });
} catch (_e) {}
