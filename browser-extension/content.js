// provcheck content script: scan page media and apply a LOCAL render filter (blur/hide) per the user's
// rules. It never modifies or re-uploads the media; it only toggles CSS on the elements in this tab.
// B1+B2: keyword rule + blur/hide are live. C2PA + AI rules are stubbed hooks (B3 wires the c2pa WASM SDK).
"use strict";

const STYLE_ID = "provcheck-filter-style";
const TAG = "data-provcheck";

function ensureStyle() {
  if (document.getElementById(STYLE_ID)) return;
  const s = document.createElement("style");
  s.id = STYLE_ID;
  s.textContent =
    ".provcheck-blur{filter:blur(18px)!important;transition:filter .12s ease}" +
    ".provcheck-hide{visibility:hidden!important}";
  (document.head || document.documentElement).appendChild(s);
}

function nearbyText(el) {
  const bits = [el.alt, el.title, el.getAttribute && el.getAttribute("aria-label")];
  const fig = el.closest && el.closest("figure");
  if (fig) bits.push(fig.textContent);
  if (el.parentElement) bits.push(el.parentElement.getAttribute && el.parentElement.getAttribute("aria-label"));
  return bits.filter(Boolean).join(" ").toLowerCase();
}

// --- C2PA / AI detection via the background service worker (fetches bytes, byte-scans presence) ---
function mediaUrl(el) {
  const u = el.currentSrc || el.src || (el.getAttribute && el.getAttribute("src")) || "";
  return u && !u.startsWith("data:") ? u : "";
}
function inspectUrl(url) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage({ type: "inspect", url }, (res) => resolve(res || { known: false }));
    } catch (_e) {
      resolve({ known: false });
    }
  });
}

async function evaluate(el, rules) {
  if (rules.keyword) {
    const kw = rules.keyword.trim().toLowerCase();
    if (kw && nearbyText(el).includes(kw)) return true;
  }
  if (rules.c2paPresent || rules.c2paAbsent || rules.aiPresent) {
    const url = mediaUrl(el);
    if (url) {
      const r = await inspectUrl(url);
      if (rules.c2paPresent && r.c2pa) return true;
      if (rules.c2paAbsent && r.known && !r.c2pa) return true;   // only act on a confirmed absence
      if (rules.aiPresent && r.ai) return true;
    }
  }
  return false;
}

function apply(el, hit, action) {
  el.classList.remove("provcheck-blur", "provcheck-hide");
  if (hit) el.classList.add(action === "hide" ? "provcheck-hide" : "provcheck-blur");
}

function clearAll() {
  document.querySelectorAll(".provcheck-blur, .provcheck-hide").forEach((e) => {
    e.classList.remove("provcheck-blur", "provcheck-hide");
  });
}

async function badge(el) {
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
    const els = document.querySelectorAll("img, video");
    for (const el of els) {
      apply(el, await evaluate(el, rules), rules.action || "blur");
      if (rules.badge) await badge(el);   // show the provenance verdict as a tooltip
    }
  } finally {
    scanning = false;
  }
}

function loadRules(cb) {
  chrome.storage.local.get(["provcheckRules"], (r) => cb((r && r.provcheckRules) || {}));
}

function run() {
  loadRules((rules) => (rules.enabled ? scan(rules) : clearAll()));
}

// initial pass + react to rule changes + re-scan on DOM mutations (SPAs / infinite scroll)
run();
chrome.storage.onChanged.addListener((c) => {
  if (c.provcheckRules) run();
});
let debounce;
const mo = new MutationObserver(() => {
  clearTimeout(debounce);
  debounce = setTimeout(run, 300);
});
mo.observe(document.documentElement, { childList: true, subtree: true });

// --- right-click "Inspect C2PA provenance" panel (fixed card, dynamic values escaped) ---
function esc(s) {
  return String(s).replace(/[<>&]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" }[c]));
}
function showPanel(d) {
  const old = document.getElementById("provcheck-panel");
  if (old) old.remove();
  const box = document.createElement("div");
  box.id = "provcheck-panel";
  box.style.cssText =
    "position:fixed;top:16px;right:16px;z-index:2147483647;max-width:340px;background:#fff;color:#1a1a1a;" +
    "border:1px solid #ccc;border-radius:8px;box-shadow:0 4px 18px rgba(0,0,0,.2);" +
    "font:13px system-ui,sans-serif;padding:12px 14px;line-height:1.5";
  const rows = [];
  if (!d.known) rows.push("<b>Could not read the image bytes</b> (blocked by the site).");
  else if (!d.c2pa) rows.push("<b>No C2PA provenance</b> found in this media.");
  else {
    rows.push("<b>C2PA provenance present</b>" + (d.ai ? " &middot; <span style='color:#b4453a'>AI-generated</span>" : ""));
    if (d.gens && d.gens.length) rows.push("Producer/tool: " + d.gens.map(esc).join(", "));
    if (d.labels && d.labels.length) rows.push("Assertions: " + d.labels.map(esc).join(", "));
    rows.push("<span style='color:#888;font-size:11px'>Byte-scan summary, not a validated manifest.</span>");
  }
  box.innerHTML =
    "<div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:6px'>" +
    "<b>provcheck</b><span id='provcheck-x' style='cursor:pointer;color:#888;font-size:16px'>&times;</span></div>" +
    rows.map((r) => "<div style='margin:3px 0'>" + r + "</div>").join("");
  document.documentElement.appendChild(box);
  document.getElementById("provcheck-x").addEventListener("click", () => box.remove());
  setTimeout(() => { if (box.parentNode) box.remove(); }, 15000);
}
chrome.runtime.onMessage.addListener((msg) => {
  if (msg && msg.type === "showPanel") showPanel(msg.data);
});
