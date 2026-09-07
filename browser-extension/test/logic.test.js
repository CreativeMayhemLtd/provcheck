// Isolated logic test of the provcheck extension WITHOUT a browser: load the real background.js and
// content.js into a vm context with mocked chrome.*/DOM, then exercise the byte-scan detector
// (scan/extract) and the content-script filter decision (evaluate/apply/nearbyText). This verifies
// the code paths a full-browser test would, minus the extension runtime this env cannot start.
const vm = require("vm");
const fs = require("fs");
const path = require("path");
const EXT = "C:\\dev2\\provcheck-extension-test";

function buf(str) {
  // build an ArrayBuffer of latin1 bytes from a string (as the real fetched media bytes would be)
  const u8 = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) u8[i] = str.charCodeAt(i) & 0xff;
  return u8.buffer;
}

const results = [];
const ck = (name, ok) => results.push([name, !!ok]);

// ---------- background.js: byte-scan detector ----------
(() => {
  const ctx = {
    chrome: {
      runtime: { onMessage: { addListener() {} }, onInstalled: { addListener() {} }, onStartup: { addListener() {} }, lastError: null },
      contextMenus: { create() {}, onClicked: { addListener() {} }, },
      tabs: { sendMessage() {} },
    },
    fetch: () => Promise.reject(new Error("no network in logic test")),
    Map, Uint8Array, Promise, console,
  };
  vm.createContext(ctx);
  vm.runInContext(fs.readFileSync(path.join(EXT, "background.js"), "utf8"), ctx);

  // scan(): presence of BOTH jumbf + c2pa => c2pa true; AI marker only counts if c2pa true
  const plain = ctx.scan(buf("\x89PNG....ordinary pixels, no provenance box here...."));
  ck("bg.scan plain: c2pa=false", plain.c2pa === false);
  ck("bg.scan plain: ai=false", plain.ai === false);

  const signed = ctx.scan(buf("\x89PNG....jumbf....c2pa....c2pa.hash.data...."));
  ck("bg.scan signed: c2pa=true", signed.c2pa === true);
  ck("bg.scan signed: ai=false (no AI marker)", signed.ai === false);

  const ai = ctx.scan(buf("....jumbf....c2pa....digitalSourceType=trainedAlgorithmicMedia...."));
  ck("bg.scan AI: c2pa=true", ai.c2pa === true);
  ck("bg.scan AI: ai=true", ai.ai === true);

  // AI marker present but NO c2pa box => ai must stay false (guarded by c2pa &&)
  const aiNoBox = ctx.scan(buf("....trainedAlgorithmicMedia but no provenance store...."));
  ck("bg.scan AI-marker-without-c2pa: ai=false", aiNoBox.ai === false);

  // extract(): richer summary with assertion labels + generator hints
  const rich = ctx.extract(buf(
    "jumbf c2pa c2pa.actions stds.schema-org.CreativeWork Adobe Firefly trainedAlgorithmicMedia"));
  ck("bg.extract: c2pa=true", rich.c2pa === true);
  ck("bg.extract: ai=true", rich.ai === true);
  ck("bg.extract: labels include c2pa.actions", rich.labels.includes("c2pa.actions"));
  ck("bg.extract: labels include CreativeWork", rich.labels.includes("stds.schema-org.CreativeWork"));
  ck("bg.extract: gens include Adobe", rich.gens.includes("Adobe"));
  ck("bg.extract: gens include Firefly", rich.gens.includes("Firefly"));

  const extractPlain = ctx.extract(buf("no markers at all"));
  ck("bg.extract plain: c2pa=false, known=true", extractPlain.c2pa === false && extractPlain.known === true);
})();

// ---------- content.js: filter decision ----------
(() => {
  // per-url inspect results the mocked service worker returns
  const INSPECT = {
    "http://x/plain.png": { c2pa: false, ai: false, known: true },
    "http://x/signed.png": { c2pa: true, ai: false, known: true },
    "http://x/ai.png": { c2pa: true, ai: true, known: true },
    "http://x/blocked.png": { c2pa: false, ai: false, known: false },
  };
  function mkClassList() {
    const s = new Set();
    return { add: (...c) => c.forEach((x) => s.add(x)), remove: (...c) => c.forEach((x) => s.delete(x)),
      contains: (x) => s.has(x), _set: s };
  }
  function el({ src = "", alt = "", title = "" } = {}) {
    return {
      src, currentSrc: "", alt, title, tagName: "IMG", isConnected: true, classList: mkClassList(),
      getAttribute: (a) => (a === "src" ? src : a === "aria-label" ? "" : null),
      setAttribute() {}, closest: () => null, parentElement: null,
      getBoundingClientRect: () => ({ width: 400, height: 300, top: 10, left: 10 }),
    };
  }
  const noop = () => {};
  const ytState = { labelled: [], all: [] };   // querySelectorAll("[aria-label],[title]") and ("*")
  const appended = { last: null };             // last node appended to documentElement (the banner div)
  const ctx = {
    chrome: {
      storage: { local: { get: (k, cb) => cb({}) }, onChanged: { addListener: noop } },
      runtime: {
        id: "testid",   // present => alive(); absent would mean an orphaned context
        onMessage: { addListener: noop },
        sendMessage: (msg, cb) => cb(INSPECT[msg.url] || { known: false }),
      },
    },
    document: {
      getElementById: () => null,
      createElement: () => ({ id: "", textContent: "", style: {}, setAttribute: noop, appendChild: noop, addEventListener: noop, remove: noop }),
      head: { appendChild: noop }, documentElement: { appendChild: (n) => { appended.last = n; } },
      querySelectorAll: (sel) => (sel && sel.indexOf("aria-label") >= 0 ? ytState.labelled : sel === "*" ? ytState.all : []),
      querySelector: () => null, body: { innerText: "" },
    },
    location: { hostname: "example.com" },
    window: { addEventListener: noop, removeEventListener: noop },
    MutationObserver: function () { this.observe = noop; this.disconnect = noop; },
    setTimeout, clearTimeout, Promise, Map, console,
  };
  vm.createContext(ctx);
  vm.runInContext(fs.readFileSync(path.join(EXT, "content.js"), "utf8"), ctx);

  const run = (fn) => Promise.resolve(fn());
  const seq = [];

  // keyword rule via nearbyText(alt)
  seq.push(run(async () => {
    const hitCat = await ctx.evaluate(el({ alt: "a signed cat photo" }), { keyword: "cat" });
    const missCat = await ctx.evaluate(el({ alt: "a plain landscape" }), { keyword: "cat" });
    ck("content keyword 'cat': matches alt", Boolean(hitCat) === true);
    ck("content keyword 'cat': non-match is false", Boolean(missCat) === false);
  }));

  // c2paPresent
  seq.push(run(async () => {
    const s = await ctx.evaluate(el({ src: "http://x/signed.png" }), { c2paPresent: true });
    const p = await ctx.evaluate(el({ src: "http://x/plain.png" }), { c2paPresent: true });
    ck("content c2paPresent: signed hits", Boolean(s) === true);
    ck("content c2paPresent: plain misses", Boolean(p) === false);
  }));

  // aiPresent
  seq.push(run(async () => {
    const a = await ctx.evaluate(el({ src: "http://x/ai.png" }), { aiPresent: true });
    const s = await ctx.evaluate(el({ src: "http://x/signed.png" }), { aiPresent: true });
    ck("content aiPresent: AI img hits", Boolean(a) === true);
    ck("content aiPresent: signed-not-AI misses", Boolean(s) === false);
  }));

  // c2paAbsent only fires on a CONFIRMED absence (known=true, c2pa=false), never on a blocked fetch
  seq.push(run(async () => {
    const known = await ctx.evaluate(el({ src: "http://x/plain.png" }), { c2paAbsent: true });
    const blocked = await ctx.evaluate(el({ src: "http://x/blocked.png" }), { c2paAbsent: true });
    ck("content c2paAbsent: confirmed-absent hits", Boolean(known) === true);
    ck("content c2paAbsent: blocked fetch does NOT hit", Boolean(blocked) === false);
  }));

  // apply(): blur (+ banner) vs hide (no banner) vs clear
  seq.push(run(async () => {
    const e = el({});
    ctx.apply(e, "AI Generated Content Detected", "blur");
    ck("content apply blur: has provcheck-blur", e.classList.contains("provcheck-blur"));
    ck("content apply blur: banner captions with the label", appended.last && appended.last.textContent === "AI Generated Content Detected");
    ctx.apply(e, "AI Generated Content Detected", "hide");
    ck("content apply hide: has provcheck-hide", e.classList.contains("provcheck-hide"));
    ck("content apply hide: blur removed", !e.classList.contains("provcheck-blur"));
    ctx.apply(e, "", "blur");
    ck("content apply clear: no classes", !e.classList.contains("provcheck-blur") && !e.classList.contains("provcheck-hide"));
  }));

  // YouTube's own AI self-declaration detector (DOM text, localized, youtube-host-gated)
  ctx.location.hostname = "www.youtube.com";
  ctx.document.body = { innerText: "Description text ... Altered or synthetic content ... more" };
  ck("yt: EN 'Altered or synthetic content' detected", ctx.youtubeAiDeclared() === true);
  ctx.document.body = { innerText: "Beschreibung ... Veränderte oder synthetische Inhalte ... mehr" };
  ck("yt: DE 'Veränderte oder synthetische Inhalte' detected", ctx.youtubeAiDeclared() === true);
  ctx.document.body = { innerText: "just a normal cooking video with no disclosure" };
  ck("yt: no disclosure phrase => false", ctx.youtubeAiDeclared() === false);
  ctx.location.hostname = "example.com";
  ctx.document.body = { innerText: "Altered or synthetic content" };
  ck("yt: disclosure phrase off-youtube => false (host-gated)", ctx.youtubeAiDeclared() === false);
  // Shorts compact "AI" chip: no phrase in body text, but the full phrase is in the chip's aria-label
  ctx.location.hostname = "www.youtube.com";
  ctx.document.body = { innerText: "shorts feed, visible chip just says AI, no full phrase in text" };
  ytState.labelled = [{ getAttribute: (k) => (k === "aria-label" ? "Altered or synthetic content" : null), title: "" }];
  ck("yt: Shorts chip via aria-label detected", ctx.youtubeAiDeclared() === true);
  ytState.labelled = [{ getAttribute: () => null, title: "Play (k)" }];
  ck("yt: unrelated aria/title => false", ctx.youtubeAiDeclared() === false);
  // Shorts/feed compact chip: a leaf element whose exact own-text is "AI" (what is actually on screen)
  ctx.document.body = { innerText: "shorts feed, no full phrase anywhere" };
  ytState.labelled = [];
  ytState.all = [{ children: { length: 0 }, childNodes: [{ nodeType: 3, nodeValue: " AI " }] }];
  ck("yt: compact 'AI' chip (exact leaf text) detected", ctx.youtubeAiDeclared() === true);
  ytState.all = [{ children: { length: 0 }, childNodes: [{ nodeType: 3, nodeValue: "Email" }] }];
  ck("yt: 'Email' leaf not mistaken for AI chip", ctx.youtubeAiDeclared() === false);
  ytState.all = [];   // reset

  // orphaned-context guard: alive() tracks chrome.runtime.id; run() under an invalidated context tears down quietly
  ck("alive: true when runtime.id present", ctx.alive() === true);
  const savedId = ctx.chrome.runtime.id;
  delete ctx.chrome.runtime.id;
  ck("alive: false when context invalidated", ctx.alive() === false);
  let threw = false;
  try { ctx.run(); } catch (_e) { threw = true; }
  ck("run() under invalidated context does not throw", threw === false);
  ctx.chrome.runtime.id = savedId;

  return Promise.all(seq);
})().then(() => {
  let pass = 0;
  for (const [n, ok] of results) { console.log(`  ${ok ? "PASS" : "FAIL"}  ${n}`); if (ok) pass++; }
  console.log(`\n  ${pass}/${results.length} logic checks passed`);
  process.exit(pass === results.length ? 0 : 1);
});
