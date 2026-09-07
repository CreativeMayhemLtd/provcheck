// Real-DOM integration test: load the actual content.js into jsdom (a real DOM + real MutationObserver +
// real event loop), drive it through live scenarios, and FAIL on any uncaught error the way Chrome would.
// This catches runtime bugs the vm mock cannot (invalidation, observer loops, banner DOM ops, etc.).
const { JSDOM, VirtualConsole } = require("jsdom");
const fs = require("fs");
const SRC = fs.readFileSync("C:\\dev2\\provcheck-extension-test\\content.js", "utf8");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let passed = 0, failed = 0;
const ck = (name, ok) => { console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}`); ok ? passed++ : failed++; };

// Faithful-ish chrome mock. Reproduces the two Chrome behaviors a naive mock hides:
//  - lastError is a GETTER; if it is set but never read during a callback, Chrome logs
//    "Unchecked runtime.lastError" (we push that as an error).
//  - opt.portClosed simulates the background not responding (cb(undefined) + lastError set).
function makeChrome(store, errors, opt = {}) {
  const changeListeners = [];
  const inspect = (url) => {
    if (/signed\b/.test(url)) return { c2pa: true, ai: false, known: true };
    if (/ai\b/.test(url)) return { c2pa: true, ai: true, known: true };
    if (/blocked\b/.test(url)) return { c2pa: false, ai: false, known: false };
    return { c2pa: false, ai: false, known: true };
  };
  let _lastError = null, _read = false;
  const runtime = {
    id: "testid",
    onMessage: { addListener() {} },
    sendMessage: (msg, cb) => {
      _lastError = opt.portClosed ? { message: "The message port closed before a response was received." } : null;
      _read = false;
      try {
        const res = opt.portClosed ? undefined : (msg && msg.type === "inspect" ? inspect(msg.url) : { known: false });
        cb(res);
      } catch (e) { errors.push("sendMessage cb threw: " + e.message); }
      if (_lastError && !_read) errors.push("Unchecked runtime.lastError: " + _lastError.message);
      _lastError = null;
    },
  };
  Object.defineProperty(runtime, "lastError", { get() { _read = true; return _lastError; }, configurable: true });
  return {
    _fireChange: (changes) => changeListeners.forEach((l) => l(changes, "local")),
    runtime,
    storage: {
      local: {
        get: (keys, cb) => { const out = {}; (Array.isArray(keys) ? keys : [keys]).forEach((k) => { if (k in store) out[k] = store[k]; }); cb(out); },
        set: (obj, cb) => { const ch = {}; Object.keys(obj).forEach((k) => { ch[k] = { oldValue: store[k], newValue: obj[k] }; store[k] = obj[k]; }); cb && cb(); changeListeners.forEach((l) => l(ch, "local")); },
      },
      onChanged: { addListener: (l) => changeListeners.push(l) },
    },
    contextMenus: { create() {}, onClicked: { addListener() {} } },
    tabs: { sendMessage() {} },
  };
}

function sizedImg(doc, id, src, alt) {
  const el = doc.createElement("img");
  el.id = id; if (src) el.setAttribute("src", src); if (alt) el.setAttribute("alt", alt);
  el.getBoundingClientRect = () => ({ width: 400, height: 300, top: 20, left: 20, right: 420, bottom: 320 });
  Object.defineProperty(el, "currentSrc", { value: src || "", configurable: true });
  return el;
}
function sizedVideo(doc) {
  const el = doc.createElement("video");
  el.getBoundingClientRect = () => ({ width: 400, height: 700, top: 0, left: 0, right: 400, bottom: 700 });
  Object.defineProperty(el, "currentSrc", { value: "blob:https://youtube.com/xyz", configurable: true });
  return el;
}

async function scenario(name, opts) {
  const { url, build, run } = opts;
  const errors = [];
  const vc = new VirtualConsole();
  vc.on("jsdomError", (e) => errors.push("jsdomError: " + (e.detail ? e.detail.message : e.message)));
  const dom = new JSDOM("<!DOCTYPE html><html><head></head><body></body></html>", {
    url, runScripts: "outside-only", pretendToBeVisual: true, virtualConsole: vc,
  });
  const win = dom.window;
  win.addEventListener("error", (e) => errors.push("window.error: " + (e.error ? e.error.message : e.message)));
  const store = {};
  const chrome = makeChrome(store, errors, opts.chromeOpt || {});
  win.chrome = chrome;
  build(win.document, chrome, store, win);
  try { win.eval(SRC); } catch (e) { errors.push("load: " + e.message); }
  await sleep(50);
  await run({ doc: win.document, chrome, store, win, errors });
  await sleep(50);
  ck(`[${name}] no uncaught errors`, errors.length === 0);
  if (errors.length) errors.slice(0, 6).forEach((e) => console.log("        > " + e));
  dom.window.close();
  return errors;
}

(async () => {
  // 1) Normal site: a C2PA-signed image blurs with the right banner; a plain image does not.
  await scenario("normal-site c2paPresent", {
    url: "https://example.com/",
    build: (doc) => {
      doc.body.appendChild(sizedImg(doc, "signed", "https://cdn/x/signed.png", "a photo"));
      doc.body.appendChild(sizedImg(doc, "plain", "https://cdn/x/plain.png", "a photo"));
    },
    run: async ({ doc, chrome }) => {
      chrome.storage.local.set({ provcheckRules: { enabled: true, c2paPresent: true, action: "blur", badge: true } });
      await sleep(120);
      ck("[normal-site] signed img blurred", doc.getElementById("signed").classList.contains("provcheck-blur"));
      ck("[normal-site] plain img not blurred", !doc.getElementById("plain").classList.contains("provcheck-blur"));
      const banner = doc.querySelector(".provcheck-banner");
      ck("[normal-site] banner present + captioned", !!banner && banner.textContent === "C2PA Provenance Detected");
    },
  });

  // 2) YouTube Shorts: an "AI" chip + a <video> -> the video blurs with the AI banner, fast (no fetch).
  await scenario("youtube shorts AI chip", {
    url: "https://www.youtube.com/shorts/abc123",
    build: (doc) => {
      const chip = doc.createElement("span"); chip.textContent = "AI"; doc.body.appendChild(chip);
      doc.body.appendChild(sizedVideo(doc));
    },
    run: async ({ doc, win }) => {
      win.chrome.storage.local.set({ provcheckRules: { enabled: true, aiPresent: true, action: "blur", badge: true } });
      await sleep(120);
      const v = doc.querySelector("video");
      ck("[youtube] video blurred via AI chip", v.classList.contains("provcheck-blur"));
      const banner = doc.querySelector(".provcheck-banner");
      ck("[youtube] AI banner present", !!banner && banner.textContent === "AI Generated Content Detected");
    },
  });

  // 3) Busy SPA: rapid DOM mutations must not throw and must keep filtering newly added media.
  await scenario("busy SPA mutations", {
    url: "https://www.linkedin.com/feed/",
    build: (doc) => { doc.body.appendChild(sizedImg(doc, "signed", "https://cdn/x/signed.png", "post")); },
    run: async ({ doc, win }) => {
      win.chrome.storage.local.set({ provcheckRules: { enabled: true, c2paPresent: true, action: "blur" } });
      await sleep(80);
      for (let i = 0; i < 20; i++) { const d = doc.createElement("div"); d.textContent = "churn " + i; doc.body.appendChild(d); await sleep(5); }
      const late = sizedImg(doc, "late", "https://cdn/x/signed.png", "late post");
      doc.body.appendChild(late);
      await sleep(700);   // let the throttle fire
      ck("[busy] late-added signed img blurred", doc.getElementById("late").classList.contains("provcheck-blur"));
    },
  });

  // 4) Extension reload -> context invalidated: further mutations must NOT throw; the script tears down.
  await scenario("extension-context invalidated", {
    url: "https://www.linkedin.com/feed/",
    build: (doc) => { doc.body.appendChild(sizedImg(doc, "signed", "https://cdn/x/signed.png", "post")); },
    run: async ({ doc, win }) => {
      win.chrome.storage.local.set({ provcheckRules: { enabled: true, c2paPresent: true, action: "blur" } });
      await sleep(80);
      delete win.chrome.runtime.id;   // simulate the extension being reloaded (context invalidated)
      // now hit every path that touches the (dead) context or the DOM: new media, churn, scroll/resize, a rule change
      doc.body.appendChild(sizedImg(doc, "afterkill", "https://cdn/x/signed.png", "post"));
      for (let i = 0; i < 10; i++) { const d = doc.createElement("div"); d.textContent = "post-reload " + i; doc.body.appendChild(d); await sleep(8); }
      win.dispatchEvent(new win.Event("scroll"));
      win.dispatchEvent(new win.Event("resize"));
      try { win.chrome.storage.local.set({ provcheckRules: { enabled: true, aiPresent: true, action: "hide" } }); } catch (_e) {}
      await sleep(300);
      ck("[invalidated] survived reload without throwing", true);   // the scenario-level error check is the real assert
    },
  });

  // 5) Background not responding: sendMessage callback fires with lastError set. The code MUST read
  //    lastError or Chrome logs "Unchecked runtime.lastError" (a real fresh-tab error our mock now models).
  await scenario("port-closed sendMessage (unchecked lastError)", {
    url: "https://news.example.com/",
    chromeOpt: { portClosed: true },
    build: (doc) => { for (let i = 0; i < 5; i++) doc.body.appendChild(sizedImg(doc, "img" + i, "https://cdn/x/pic" + i + ".png", "photo")); },
    run: async ({ win }) => {
      win.chrome.storage.local.set({ provcheckRules: { enabled: true, c2paPresent: true, aiPresent: true, action: "blur", badge: true } });
      await sleep(150);   // several inspect() round-trips, each returning a closed port
    },
  });

  // 6) background.js: onInstalled fires again on reload. A bare create() with a duplicate id errors;
  //    the fix must removeAll first and never leave an unchecked lastError.
  (function backgroundReinstall() {
    const vm = require("vm");
    const bgErrors = [];
    let created = 0, removedAll = 0, existingId = null;
    let _le = null, _read = false;
    const runtime = {
      _installed: null, _startup: null,
      onInstalled: { addListener: (fn) => { runtime._installed = fn; } },
      onStartup: { addListener: (fn) => { runtime._startup = fn; } },
      onMessage: { addListener() {} },
    };
    Object.defineProperty(runtime, "lastError", { get() { _read = true; return _le; }, configurable: true });
    const chrome = {
      runtime,
      contextMenus: {
        removeAll: (cb) => { removedAll++; existingId = null; _le = null; _read = false; cb && cb(); },
        create: (o) => {
          _read = false;
          if (existingId === o.id) { _le = { message: "Cannot create item with duplicate id " + o.id }; }
          else { existingId = o.id; created++; _le = null; }
          // Chrome surfaces create() failure via lastError; if unread, it logs.
          setTimeout(() => { if (_le && !_read) bgErrors.push("Unchecked: " + _le.message); }, 0);
        },
        onClicked: { addListener() {} },
      },
      tabs: { sendMessage() {} },
    };
    const ctx = { chrome, fetch: () => Promise.reject(new Error("no net")), Map, Uint8Array, Promise, setTimeout, console };
    vm.createContext(ctx);
    vm.runInContext(fs.readFileSync("C:\\dev2\\provcheck-extension-test\\background.js", "utf8"), ctx);
    runtime._installed && runtime._installed();   // first install
    runtime._installed && runtime._installed();   // reload -> onInstalled again
    return new Promise((r) => setTimeout(() => {
      ck("[background] menu re-install used removeAll (no duplicate-id)", removedAll >= 2 && created >= 2);
      ck("[background] no unchecked lastError on re-install", bgErrors.length === 0);
      if (bgErrors.length) bgErrors.forEach((e) => console.log("        > " + e));
      r();
    }, 20));
  })();
  await sleep(60);

  console.log(`\n  ${passed}/${passed + failed} integration checks passed`);
  process.exit(failed === 0 ? 0 : 1);
})().catch((e) => { console.log("HARNESS CRASH: " + e.stack); process.exit(2); });
