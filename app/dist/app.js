// provcheck GUI — vanilla JS + Tauri v2 IPC.
//
// Tauri v2 exposes `window.__TAURI__.core` when `withGlobalTauri`
// is true. Plugins like `dialog` are NOT auto-globalised in v2, so
// we keep the UI surface small: drag-drop is primary, "Choose file"
// uses a `<input type=file>` fallback.
//
// State machine:
//   empty  → drop/choose → loading → result
//   result → "Verify another" → empty

const TAURI = window.__TAURI__;
if (!TAURI || !TAURI.core || typeof TAURI.core.invoke !== "function") {
  // Running outside Tauri (plain browser) — fail loud in a visible
  // way rather than silently no-op on drops.
  document.body.innerHTML =
    '<pre style="padding:24px;color:#EF4444;font-family:monospace">' +
    "provcheck must be launched via provcheck-gui.exe\n" +
    "(The Tauri runtime was not detected.)" +
    "</pre>";
  throw new Error("no Tauri runtime");
}
const { invoke } = TAURI.core;

// ---- Frontend diagnostics --------------------------------------------------
// Every swallowed JS exception used to die invisibly, leaving spinners
// spinning with an idle backend and an empty log. Route them (and key flow
// traces) into the same provcheck.log the backend writes.
function uiLog(msg) {
  try {
    invoke("frontend_log", { msg: String(msg).slice(0, 500) });
  } catch {
    /* logging must never break the app */
  }
}
window.addEventListener("error", (e) => {
  uiLog(`window.onerror: ${e.message} @ ${e.filename || "?"}:${e.lineno || "?"}`);
});
window.addEventListener("unhandledrejection", (e) => {
  uiLog(`unhandledrejection: ${e.reason && e.reason.message ? e.reason.message : e.reason}`);
});

// Watchdog: no spinner is allowed to spin forever. Races a promise against a
// timeout so a never-settling invoke degrades into a visible error instead of
// an eternal loading state.
function raceTimeout(promise, ms) {
  return Promise.race([
    promise.then(
      (v) => ({ timedOut: false, value: v }),
      (e) => ({ timedOut: false, error: e })
    ),
    new Promise((res) => setTimeout(() => res({ timedOut: true }), ms)),
  ]);
}

// ---- DOM handles ---------------------------------------------------------

const $dropzone      = document.getElementById("dropzone");
const $loading       = document.getElementById("loading");
const $loadingFile   = document.getElementById("loading-file");
const $result        = document.getElementById("result");
const $verdict       = document.getElementById("verdict");
const $verdictIcon   = document.getElementById("verdict-icon");
const $verdictTitle  = document.getElementById("verdict-title");
const $verdictFile   = document.getElementById("verdict-file");
const $reason        = document.getElementById("reason");
const $reasonText    = document.getElementById("reason-text");
const $kvMain        = document.getElementById("kv-main");
const $kvClaims      = document.getElementById("kv-claims");
const $claimsHeading = document.getElementById("claims-heading");
const $watermarks     = document.getElementById("watermarks");
const $attestation    = document.getElementById("attestation");
const $attestationIcon  = document.getElementById("attestation-icon");
const $attestationTitle = document.getElementById("attestation-title");
const $attestationSub   = document.getElementById("attestation-sub");
const $attestationFp    = document.getElementById("attestation-fingerprint");
const $idHandle       = document.getElementById("identity-handle");
const $idRequire      = document.getElementById("identity-require-attested");
const $idWatermark    = document.getElementById("identity-run-watermark");
const $idAutofillHint = document.getElementById("identity-autofill-hint");
const $chooseBtn      = document.getElementById("choose-btn");
const $verifyAgain    = document.getElementById("verify-another");
const $copyJson       = document.getElementById("copy-json");
const $sampleRaidio     = document.getElementById("sample-raidio");
const $sampleDoomscroll = document.getElementById("sample-doomscroll");
const $footerHint     = document.getElementById("footer-hint");
const $footerActions  = document.getElementById("footer-actions");
const $aboutCard      = document.getElementById("about-card");

// v1.1.0 Watermark-tab handles. Own drop zone + own loading + own
// result surface, using the shared renderWatermarks() function
// with a target-element parameter (see the refactor below).
const $wmDropzone       = document.getElementById("wm-dropzone");
const $wmChooseBtn      = document.getElementById("wm-choose-btn");
const $wmLoading        = document.getElementById("wm-loading");
const $wmLoadingFile    = document.getElementById("wm-loading-file");
const $wmResult         = document.getElementById("wm-result");
const $wmResultFile     = document.getElementById("wm-result-file");
const $wmWatermarks     = document.getElementById("wm-watermarks");
const $wmAnother        = document.getElementById("wm-another");

let lastReport = null;
let lastFilePath = null;
// True while the identity field holds a value sourced from a file's identity
// assertion rather than the user's own typing. saveIdentity must never
// persist an autofilled value — the "never persists" promise in
// applyIdentityAutofill depends on it.
let idAutofilled = false;

// ---- State transitions ---------------------------------------------------

function showEmpty() {
  $dropzone.hidden = false;
  $loading.hidden = true;
  $result.hidden = true;
  $dropzone.classList.remove("drag-over");
  // Footer shows the sample-hint text in empty + loading states —
  // the action buttons only make sense once there's a result.
  $footerHint.hidden = false;
  $footerActions.hidden = true;
}

function showLoading(displayName) {
  $dropzone.hidden = true;
  $loading.hidden = false;
  $result.hidden = true;
  $loadingFile.textContent = displayName;
  // Warn about the slow path only when it applies: with watermark detection
  // on, audio/video inference legitimately takes minutes, and a bare spinner
  // is indistinguishable from a hang.
  const hintEl = document.getElementById("loading-hint");
  if (hintEl) hintEl.hidden = !($idWatermark && $idWatermark.checked);
  $footerHint.hidden = false;
  $footerActions.hidden = true;
}

function showResult(report, path) {
  $dropzone.hidden = true;
  $loading.hidden = true;
  $result.hidden = false;
  renderReport(report, path);
  // Swap footer content — buttons replace the sample-hint line so
  // they're always visible (not buried at the bottom of a scroll).
  $footerHint.hidden = true;
  $footerActions.hidden = false;
}

// ---- Rendering -----------------------------------------------------------

function renderReport(report, path) {
  lastReport = report;
  lastFilePath = path;

  let cls, icon, title;
  if (report.verified) {
    cls = "is-verified";
    icon = "\u2713";
    title = "Verified";
  } else if (report.unsigned) {
    cls = "is-unsigned";
    icon = "\u2014";
    title = "Unsigned";
  } else {
    cls = "is-invalid";
    icon = "\u2715";
    title = "Not verified";
  }
  $verdict.className = "verdict " + cls;
  $verdictIcon.textContent = icon;
  $verdictTitle.textContent = title;
  $verdictFile.textContent = path || "";

  if (report.failure_reason) {
    $reason.hidden = false;
    $reasonText.textContent = report.failure_reason;
  } else {
    $reason.hidden = true;
  }

  renderAttestation(report.did_attestation);
  renderWatermarks(report.watermarks);
  renderAboutCard(report, $aboutCard);
  applyIdentityAutofill(report.identity);

  $kvMain.innerHTML = "";
  const rows = [
    ["Signer", report.signer, false],
    ["Signed at", report.signed_at, false],
    ["Tool", report.claim_generator, false],
    ["Format", report.format, false],
    ["Manifest", report.active_manifest, true],
    [
      "Ingredients",
      report.ingredient_count > 0
        ? report.ingredient_count +
          " (derived content \u2014 this file was made by editing earlier signed files)"
        : null,
      false,
    ],
    [
      "Validation errors",
      report.validation_errors > 0 ? String(report.validation_errors) : null,
      false,
    ],
  ];
  for (const [label, value, mono] of rows) {
    if (value == null || value === "") continue;
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    if (mono) dd.classList.add("mono");
    dd.textContent = value;
    $kvMain.appendChild(dt);
    $kvMain.appendChild(dd);
  }

  $kvClaims.innerHTML = "";
  const hasClaims =
    report.assertions &&
    typeof report.assertions === "object" &&
    !Array.isArray(report.assertions) &&
    Object.keys(report.assertions).length > 0;
  $claimsHeading.hidden = !hasClaims;
  if (hasClaims) {
    for (const [label, value] of Object.entries(report.assertions)) {
      const dt = document.createElement("dt");
      dt.textContent = label;
      const dd = document.createElement("dd");
      dd.textContent = JSON.stringify(value, null, 2);
      $kvClaims.appendChild(dt);
      $kvClaims.appendChild(dd);
    }
  }
}

function renderAttestation(att) {
  // Four states keyed on DidAttestation.status — mirrors the
  // CLI Display impl in crates/provcheck/src/report.rs.
  // Hidden when offline-only (the user typed no handle/DID).
  if (!att || typeof att !== "object") {
    $attestation.hidden = true;
    return;
  }
  const status = att.status || "";
  const label = formatAttestationLabel(att);

  let cls, icon, title, sub;
  if (status === "match") {
    cls = "is-match";
    icon = "✓";
    title = "Attested by " + label;
    sub = att.message || "Signing certificate matches a key published under this identity.";
  } else if (status === "mismatch") {
    cls = "is-mismatch";
    icon = "✕";
    title = "Attestation mismatch for " + label;
    sub = att.message ||
      "Signing certificate does not match any key published under this identity.";
  } else if (status === "not_published") {
    cls = "is-not-published";
    icon = "—";
    title = "No keys published under " + label;
    sub = att.message ||
      "This identity exists but has not published any signingKey records.";
  } else {
    cls = "is-resolution-failed";
    icon = "?";
    title = "Could not resolve " + label;
    sub = att.message || "Identity resolution failed (handle/DID unreachable).";
  }

  $attestation.hidden = false;
  $attestation.className = "attestation-badge " + cls;
  $attestationIcon.textContent = icon;
  $attestationTitle.textContent = title;
  $attestationSub.textContent = sub;

  if (status === "match" && att.matched_fingerprint) {
    $attestationFp.hidden = false;
    $attestationFp.textContent = att.matched_fingerprint;
  } else {
    $attestationFp.hidden = true;
    $attestationFp.textContent = "";
  }
}

function formatAttestationLabel(att) {
  // Prefer @handle for readability, fall back to the DID, then
  // a generic placeholder so the UI never shows an empty label.
  if (att.handle) {
    return att.handle.startsWith("did:") ? att.handle : "@" + att.handle;
  }
  if (att.did) return att.did;
  return "this identity";
}

function renderWatermarks(list, target, opts) {
  // v1.1.0: `target` defaults to the Verify tab's $watermarks div,
  // but the Watermark tab passes $wmWatermarks so the same badge-
  // build logic renders in both places. `opts.detectionRan` is a
  // hint for the empty-state text — Verify tab passes the checkbox
  // state, Watermark tab always passes true (its whole purpose is
  // to run detection).
  target = target || $watermarks;
  const detectionRan = opts && "detectionRan" in opts
    ? opts.detectionRan
    : ($idWatermark && $idWatermark.checked);
  target.innerHTML = "";
  // One badge per detector that ran. Four per-badge states:
  //   detected   → green check, brand name + confidence %
  //   degraded   → amber check, brand name + "(degraded)" + %
  //   undetected → red x, "no mark detected"
  //   skipped    → dim dash, e.g. "not audio" or "model error"
  // Keyed forensic marks are invisible to every blind scan BY DESIGN: with
  // no secret there is nothing to detect. Say so, or a user who marked a
  // file with Backfire or Mellin concludes the scanner "misses" it.
  const appendKeyedNote = () => {
    const note = document.createElement("div");
    note.className = "watermarks-keyed-note";
    note.textContent =
      "Keyed marks (Backfire, Mellin) are not part of this scan. They can only be read with your key, on the Keyed marks tab.";
    target.appendChild(note);
  };
  if (!Array.isArray(list) || list.length === 0) {
    if (detectionRan) {
      target.hidden = false;
      const emptyEl = document.createElement("div");
      emptyEl.className = "watermarks-empty";
      emptyEl.textContent = "No watermarks detected by the detector families that ran.";
      target.appendChild(emptyEl);
      appendKeyedNote();
    } else {
      target.hidden = true;
    }
    return;
  }
  target.hidden = false;
  // Pick a shared timeline extent across all detectors so the
  // strips line up visually — if AudioSeal reports a mark at
  // 0:15–0:45 and WavMark at 0:10–0:50 on the same 60-second file,
  // both bars should use the same horizontal scale. We don't have
  // the file's total duration on the report, so we infer extent
  // from the last marked-region end across detectors and pad ~5%
  // so the trailing edge isn't flush against the right margin.
  let maxEnd = 0;
  for (const wm of list) {
    const regs = Array.isArray(wm.marked_regions) ? wm.marked_regions : [];
    for (const r of regs) {
      const end = Number(Array.isArray(r) ? r[1] : 0);
      if (end > maxEnd) maxEnd = end;
    }
  }
  const extent = maxEnd > 0 ? maxEnd * 1.05 : 0;
  for (const wm of list) {
    target.appendChild(buildWatermarkBadge(wm, extent));
  }
  appendKeyedNote();
}

function buildWatermarkBadge(wm, extent) {
  const detector =
    wm.kind === "silent_cipher" ? "silentcipher" : (wm.kind || "watermark");
  const msg = wm.message || "";
  const status = wm.status || (wm.detected ? "detected" : "not_detected");
  const pct = Math.round((Number(wm.confidence) || 0) * 100);
  const brandLabel = formatBrand(wm.brand);

  let cls, icon, title, sub;
  if (status === "detected") {
    cls = "is-detected";
    icon = "✓";
    title = detector + " · " + brandLabel;
    sub = pct + "% confidence";
  } else if (status === "degraded") {
    cls = "is-degraded";
    icon = "✓";
    title = detector + " · " + brandLabel;
    sub = pct + "% confidence; mark is degraded (partial corruption likely)";
  } else if (msg.length > 0) {
    cls = "is-skipped";
    icon = "—";
    title = detector + ": n/a";
    sub = msg;
  } else {
    cls = "is-undetected";
    icon = "✕";
    title = detector + ": no mark detected";
    sub = "";
  }

  const badge = document.createElement("div");
  badge.className = "watermark-badge " + cls;

  const iconEl = document.createElement("div");
  iconEl.className = "watermark-icon";
  iconEl.setAttribute("aria-hidden", "true");
  iconEl.textContent = icon;
  badge.appendChild(iconEl);

  const text = document.createElement("div");
  text.className = "watermark-text";
  const titleEl = document.createElement("p");
  titleEl.className = "watermark-title";
  titleEl.textContent = title;
  text.appendChild(titleEl);
  const subEl = document.createElement("p");
  subEl.className = "watermark-sub";
  subEl.textContent = sub;
  text.appendChild(subEl);

  const strip = buildMarkedTimeline(wm.marked_regions, extent);
  if (strip) text.appendChild(strip);

  badge.appendChild(text);
  return badge;
}

function buildMarkedTimeline(regions, extent) {
  if (!Array.isArray(regions) || regions.length === 0 || !extent || extent <= 0) {
    return null;
  }
  const strip = document.createElement("div");
  strip.className = "watermark-timeline";
  strip.setAttribute(
    "aria-label",
    "Watermark presence over time: " +
      regions.map((r) => formatTimecode(r[0]) + "–" + formatTimecode(r[1])).join(", ")
  );
  for (const r of regions) {
    const start = Math.max(0, Number(r[0]) || 0);
    const end = Math.max(start, Number(r[1]) || 0);
    if (end <= start) continue;
    const seg = document.createElement("div");
    seg.className = "watermark-timeline-seg";
    seg.style.left = ((start / extent) * 100).toFixed(2) + "%";
    seg.style.width = (((end - start) / extent) * 100).toFixed(2) + "%";
    seg.title = formatTimecode(start) + "–" + formatTimecode(end);
    strip.appendChild(seg);
  }
  return strip;
}

function formatTimecode(sec) {
  const s = Math.max(0, Math.floor(Number(sec) || 0));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const ss = s % 60;
  const pad = (n) => n.toString().padStart(2, "0");
  return h > 0 ? h + ":" + pad(m) + ":" + pad(ss) : m + ":" + pad(ss);
}

function formatBrand(brand) {
  // Serde tags WatermarkBrand with `{"code": "..."}`. Unknowns
  // carry extra fields (`letters` or `schema`). Detection is
  // brand-agnostic — any silentcipher mark from a non-CM source
  // still lights this badge green, just with an "unrecognized"
  // attribution.
  if (!brand || typeof brand !== "object") return "unrecognized source";
  switch (brand.code) {
    case "raidio":     return "rAIdio.bot";
    case "doomscroll": return "Doomscroll.FM";
    case "vaideo":     return "vAIdeo.bot";
    case "unknown_ascii": {
      const letters = Array.isArray(brand.letters) ? brand.letters : [];
      const ascii = letters.map((b) => String.fromCharCode(b)).join("");
      return "unrecognized source “" + ascii + "”";
    }
    case "unknown_schema":
      return "unrecognized payload schema (v" + (brand.schema ?? "?") + ")";
    default:
      return "unrecognized source";
  }
}

// ---- Actions -------------------------------------------------------------

async function verifyPath(path) {
  // One scan at a time per tab: model inference saturates the CPU, so a
  // second drop mid-scan halves both runs and doubles the wait.
  if (!$loading.hidden) {
    uiLog("verify: ignored, a verify is already running");
    return;
  }
  showLoading(prettyPath(path));
  // Read from the live input rather than localStorage so an
  // auto-filled value (which we deliberately don't persist) is
  // picked up by this run. localStorage and the live input agree
  // for typed values; they diverge only when applyIdentityAutofill
  // has populated the input from a prior file's identity
  // assertion.
  const rawHandle = $idHandle ? ($idHandle.value || "").trim() : "";
  const requireAttested = !!($idRequire && $idRequire.checked);
  // Single text input for both bsky handle and DID — sniff
  // the `did:` prefix to route correctly into the two
  // Tauri command args. Tauri auto-camelCases `require_attested`
  // → `requireAttested` on the JS side.
  const raw = rawHandle;
  const isDid = raw.startsWith("did:");
  const args = {
    path,
    handle: isDid ? null : (raw || null),
    did: isDid ? raw : null,
    requireAttested,
    runWatermark: !!($idWatermark && $idWatermark.checked),
  };
  uiLog(`verify: start ${prettyPath(path)}`);
  try {
    const resp = await invoke("verify_file", args);
    uiLog(`verify: settled ok=${!!(resp && resp.ok)}`);
    if (!resp.ok) {
      showResult(errorReport(resp.error || "Could not read file."), path);
      return;
    }
    showResult(resp.report, path);
  } catch (e) {
    uiLog(`verify: invoke rejected: ${e}`);
    showResult(errorReport("Internal error: " + (e && e.toString ? e.toString() : "unknown")), path);
  }
}

// ---- Watermark tab (v1.1.0) ----------------------------------------------

function showWmEmpty() {
  $wmDropzone.hidden = false;
  $wmLoading.hidden = true;
  $wmResult.hidden = true;
  $wmDropzone.classList.remove("drag-over");
}

function showWmLoading(displayName, families) {
  $wmDropzone.hidden = true;
  $wmLoading.hidden = false;
  $wmResult.hidden = true;
  $wmLoadingFile.textContent = displayName;
  // Say exactly what is running, not a canned "all six" line.
  const hintEl = document.getElementById("wm-loading-hint");
  if (hintEl) {
    const scope = Array.isArray(families) && families.length > 0
      ? `Scanning ${families.length} famil${families.length === 1 ? "y" : "ies"} (${families.join(", ")}).`
      : "Scanning all six detector families.";
    hintEl.textContent =
      scope + " Model inference is CPU-heavy on audio and video, so this can take a few minutes. Still working while this spins.";
  }
}

function showWmResult(report, path) {
  $wmDropzone.hidden = true;
  $wmLoading.hidden = true;
  $wmResult.hidden = false;
  $wmResultFile.textContent = prettyPath(path);
  // The Watermark tab's detection ALWAYS ran (that's the tab's job) —
  // pass detectionRan: true so the shared render function shows the
  // "no marks found" empty state instead of hiding the block.
  renderWatermarks(
    report && report.watermarks,
    $wmWatermarks,
    { detectionRan: true },
  );
}

// An error must render AS an error. Rendering it as the "no watermarks
// detected" empty state told the user their unreadable file was scanned
// clean, which is worse than a spinner dead end.
function showWmError(msg, path) {
  $wmDropzone.hidden = true;
  $wmLoading.hidden = true;
  $wmResult.hidden = false;
  $wmResultFile.textContent = prettyPath(path);
  $wmWatermarks.hidden = false;
  $wmWatermarks.innerHTML = "";
  const el = document.createElement("div");
  el.className = "watermarks-empty";
  el.textContent = "Could not scan this file: " + msg;
  $wmWatermarks.appendChild(el);
}

// The Watermark tab's family selector: which detector families to run.
const WM_FAMILIES_STORAGE = "provcheck.wm.families";
const $wmFamilies = document.getElementById("wm-families");

function wmSelectedFamilies() {
  if (!$wmFamilies) return null; // no selector rendered → scan everything
  return [...$wmFamilies.querySelectorAll("input[type=checkbox]:checked")].map(
    (c) => c.dataset.family
  );
}

if ($wmFamilies) {
  // Restore, then persist on every change.
  try {
    const saved = JSON.parse(localStorage.getItem(WM_FAMILIES_STORAGE) || "null");
    if (Array.isArray(saved)) {
      for (const c of $wmFamilies.querySelectorAll("input[type=checkbox]")) {
        c.checked = saved.includes(c.dataset.family);
      }
    }
  } catch {
    /* corrupt storage — keep defaults */
  }
  $wmFamilies.addEventListener("change", () => {
    try {
      localStorage.setItem(WM_FAMILIES_STORAGE, JSON.stringify(wmSelectedFamilies()));
    } catch {
      /* storage blocked */
    }
  });
}

async function watermarkPath(path) {
  if (!$wmLoading.hidden) {
    uiLog("watermark scan: ignored, a scan is already running");
    return;
  }
  const families = wmSelectedFamilies();
  if (families && families.length === 0) {
    showWmError("no detector families selected. Tick at least one above", path);
    return;
  }
  showWmLoading(prettyPath(path), families);
  uiLog(`watermark scan: start ${prettyPath(path)} families=${families ? families.join(",") : "all"}`);
  try {
    const resp = await invoke("watermark_only", { path, families });
    uiLog(`watermark scan: settled ok=${!!(resp && resp.ok)}`);
    if (!resp.ok) {
      showWmError(resp.error || "unreadable file", path);
      return;
    }
    showWmResult(resp.report, path);
  } catch (e) {
    uiLog(`watermark scan: invoke rejected: ${e}`);
    showWmError(String(e && e.message ? e.message : e), path);
  }
}

// ---- Identity (bsky handle / DID) persistence ----------------------------

const IDENTITY_STORAGE_KEY = "provcheck.identity";

function loadIdentity() {
  // localStorage is the only persistence layer here. Bsky
  // handles and DIDs are public identifiers — nothing secret
  // crosses this boundary.
  try {
    const raw = localStorage.getItem(IDENTITY_STORAGE_KEY);
    if (!raw) return { handle: "", requireAttested: false, runWatermark: true };
    const parsed = JSON.parse(raw);
    return {
      handle: typeof parsed.handle === "string" ? parsed.handle : "",
      requireAttested: !!parsed.requireAttested,
      // Default to true when the key isn't present (first-run, or
      // upgrading from v0.3.1). Users who want to skip the slow
      // watermark detection uncheck it once and it stays off.
      runWatermark: parsed.runWatermark !== false,
    };
  } catch {
    return { handle: "", requireAttested: false, runWatermark: true };
  }
}

function saveIdentity() {
  const payload = {
    // An autofilled handle (sourced from a file) is never persisted; only
    // what the user actually typed survives the session.
    handle: idAutofilled ? "" : (($idHandle && $idHandle.value) || "").trim(),
    requireAttested: !!($idRequire && $idRequire.checked),
    runWatermark: !!($idWatermark && $idWatermark.checked),
  };
  try {
    localStorage.setItem(IDENTITY_STORAGE_KEY, JSON.stringify(payload));
  } catch {
    /* storage full / disabled — silent no-op */
  }
}

function hydrateIdentityInputs() {
  const id = loadIdentity();
  if ($idHandle) $idHandle.value = id.handle || "";
  if ($idRequire) $idRequire.checked = !!id.requireAttested;
  if ($idWatermark) $idWatermark.checked = id.runWatermark !== false;
}

// Pre-fill the identity input from a file's app.provcheck.identity
// assertion, when the field is empty. Never persists to
// localStorage: the next session opens with whatever the user
// typed last, not a value sourced from a file that may not be
// around anymore. The user can override by typing — the input
// listener clears the autofill hint when they do.
function applyIdentityAutofill(claim) {
  if (!$idHandle || !$idAutofillHint) return;
  if (!claim || typeof claim !== "object") {
    $idAutofillHint.hidden = true;
    $idAutofillHint.textContent = "";
    return;
  }
  // Only populate when the field is genuinely empty — never
  // overwrite the user's input.
  const liveValue = ($idHandle.value || "").trim();
  if (liveValue !== "") {
    $idAutofillHint.hidden = true;
    return;
  }
  const filled = (claim.handle && claim.handle.trim()) || claim.did || "";
  if (!filled) {
    $idAutofillHint.hidden = true;
    return;
  }
  $idHandle.value = filled;
  idAutofilled = true;
  $idAutofillHint.textContent = "auto-filled from file";
  $idAutofillHint.hidden = false;
}

function errorReport(msg) {
  return {
    verified: false,
    unsigned: false,
    failure_reason: msg,
    active_manifest: null,
    signer: null,
    signed_at: null,
    claim_generator: null,
    assertions: {},
    ingredient_count: 0,
    format: null,
    validation_errors: 0,
    did_attestation: null,
    watermarks: [],
  };
}

function prettyPath(path) {
  if (!path) return "";
  const norm = path.replace(/\\/g, "/");
  const parts = norm.split("/");
  return parts[parts.length - 1] || path;
}

// ---- In-app dialogs (alert/confirm/prompt replacements) -------------------
// window.alert/confirm/prompt are NOT reliably implemented across Tauri
// webviews (WKWebView's confirm returns undefined, prompt is a no-op on some
// backends), which turned destructive-action confirmations into silent dead
// ends. Promise-based replacements over a plain DOM modal.
const $appDialog = document.getElementById("app-dialog");
const $appDialogMsg = document.getElementById("app-dialog-msg");
const $appDialogInput = document.getElementById("app-dialog-input");
const $appDialogOk = document.getElementById("app-dialog-ok");
const $appDialogCancel = document.getElementById("app-dialog-cancel");

function appDialog(message, { input = null, cancel = true } = {}) {
  return new Promise((resolve) => {
    $appDialogMsg.textContent = message;
    $appDialogInput.hidden = input === null;
    $appDialogInput.value = input || "";
    $appDialogCancel.hidden = !cancel;
    $appDialog.hidden = false;
    (input !== null ? $appDialogInput : $appDialogOk).focus();
    const done = (val) => {
      $appDialog.hidden = true;
      $appDialogOk.removeEventListener("click", ok);
      $appDialogCancel.removeEventListener("click", no);
      document.removeEventListener("keydown", key);
      resolve(val);
    };
    const ok = () => done(input !== null ? $appDialogInput.value : true);
    const no = () => done(input !== null ? null : false);
    const key = (e) => {
      if (e.key === "Escape") no();
      else if (e.key === "Enter" && input !== null) ok();
    };
    $appDialogOk.addEventListener("click", ok);
    $appDialogCancel.addEventListener("click", no);
    document.addEventListener("keydown", key);
  });
}
const appAlert = (msg) => appDialog(msg, { cancel: false }).then(() => undefined);
const appConfirm = (msg) => appDialog(msg);
const appPrompt = (msg, def = "") => appDialog(msg, { input: def });

// ---- File picker (hidden input, no plugin dep) ---------------------------

// Route a chosen/dropped absolute path to whichever tab is active.
function dispatchFile(path) {
  if (!path) return;
  const tab = activeTab();
  if (tab === "sign") {
    if (typeof window.signOnDrop === "function") window.signOnDrop(path);
  } else if (tab === "watermark") {
    watermarkPath(path);
  } else if (tab === "backfire") {
    // Keyed marks tab hosts two tools: audio files route to the Mellin
    // section, everything else reads the Backfire image mark. A dropped
    // WAV going to the image reader was a guaranteed dead end.
    if (/\.(wav|mp3|flac|m4a|aac|ogg|opus|aiff?)$/i.test(path)) {
      mellinPath(path);
    } else {
      backfirePath(path);
    }
  } else {
    // Detect and Keys own no drop surface, so the drop routes to Verify.
    // SURFACE the Verify pane too — a result rendering into a hidden tab
    // reads as "nothing happened".
    if (tab !== "verify") activateTab("verify");
    verifyPath(path);
  }
}

async function openFilePicker() {
  // Open a native dialog in Rust (the webview sandbox hides absolute paths from an
  // <input type=file>), then hand the path to the active tab. The picker MUST match
  // the tab: Verify/Watermark/Sign accept any file type (audio, video, image, text),
  // so they get the unfiltered dialog; only Backfire's own button is image-first,
  // and even that dialog carries an "All files" fallback. If the command is
  // unavailable, fall back to inviting the user to drag.
  const tab = activeTab();
  try {
    let path;
    if (tab === "backfire") {
      path = await invoke("pick_image");
    } else {
      const title =
        tab === "sign" ? "Choose a file to sign"
        : tab === "watermark" ? "Choose a file to scan for watermarks"
        : "Choose a file to verify";
      path = await invoke("pick_any_file", { title, kind: "media" });
    }
    if (path) dispatchFile(path);
  } catch {
    showReminderToDrag();
  }
}

function showReminderToDrag() {
  // Briefly swap the ACTIVE tab's dropzone copy to nudge toward drag-drop.
  // Targeting only the Verify dropzone made the nudge invisible from every
  // other tab (the element is hidden there).
  const dzMap = {
    verify: $dropzone,
    watermark: $wmDropzone,
    backfire: $bfDropzone,
    sign: document.getElementById("sign-dropzone"),
  };
  const dz = dzMap[activeTab()] || $dropzone;
  const inner = dz && dz.querySelector(".dropzone-inner h2");
  if (!inner) return;
  const original = inner.textContent;
  inner.textContent = "Drag the file onto the window";
  dz.classList.add("drag-over");
  setTimeout(() => {
    inner.textContent = original;
    dz.classList.remove("drag-over");
  }, 1600);
}

// ---- Wire-up -------------------------------------------------------------

$chooseBtn.addEventListener("click", openFilePicker);

$verifyAgain.addEventListener("click", showEmpty);

$copyJson.addEventListener("click", async () => {
  if (!lastReport) return;
  try {
    await navigator.clipboard.writeText(JSON.stringify(lastReport, null, 2));
    $copyJson.textContent = "Copied";
    setTimeout(() => ($copyJson.textContent = "Copy as JSON"), 1200);
  } catch {
    /* clipboard blocked — silent no-op */
  }
});

// Tauri 2 drag-drop: listen for the global event rather than the
// webview-bound helper (the helper requires an ESM import that our
// no-build-step setup can't provide). The payload shape is
//   { type: "enter"|"over"|"drop"|"leave", paths: [...], position }
//
// Dispatches based on which tab is active — Verify tab → verifyPath,
// Sign tab → showSignPreview. The two flows are independent.
TAURI.event.listen("tauri://drag-drop", (event) => {
  const p = event.payload;
  $dropzone.classList.remove("drag-over");
  if ($wmDropzone) $wmDropzone.classList.remove("drag-over");
  const $signDz = document.getElementById("sign-dropzone");
  if ($signDz) $signDz.classList.remove("drag-over");
  if ($bfDropzone) $bfDropzone.classList.remove("drag-over");
  if (!p || !Array.isArray(p.paths) || p.paths.length === 0) return;
  // Detect / Keys tabs own no dropzone, so dispatchFile falls back to Verify, the
  // most-generally-useful default when a file is dropped from an unfocused surface.
  dispatchFile(p.paths[0]);
});
TAURI.event.listen("tauri://drag-enter", () => {
  $dropzone.classList.add("drag-over");
  if ($wmDropzone) $wmDropzone.classList.add("drag-over");
  const $signDz = document.getElementById("sign-dropzone");
  if ($signDz) $signDz.classList.add("drag-over");
});
TAURI.event.listen("tauri://drag-over", () => {
  $dropzone.classList.add("drag-over");
  if ($wmDropzone) $wmDropzone.classList.add("drag-over");
  const $signDz = document.getElementById("sign-dropzone");
  if ($signDz) $signDz.classList.add("drag-over");
});
TAURI.event.listen("tauri://drag-leave", () => {
  $dropzone.classList.remove("drag-over");
  if ($wmDropzone) $wmDropzone.classList.remove("drag-over");
  const $signDz = document.getElementById("sign-dropzone");
  if ($signDz) $signDz.classList.remove("drag-over");
});

function activeTab() {
  // v1.1.0: extended for Watermark + Detect tabs. The Sign tab's
  // check remains structurally in place (an early `refreshSignTab`
  // caller relied on it). Detect tab is a static empty state that
  // doesn't consume dropped files, so it isn't a drop-dispatch
  // target — but the return value is still needed for tab-state
  // reads elsewhere.
  if (document.getElementById("tab-sign").classList.contains("is-active")) return "sign";
  if (document.getElementById("tab-watermark").classList.contains("is-active")) return "watermark";
  if (document.getElementById("tab-detect").classList.contains("is-active")) return "detect";
  if (document.getElementById("tab-keys").classList.contains("is-active")) return "keys";
  if (document.getElementById("tab-backfire").classList.contains("is-active")) return "backfire";
  return "verify";
}

// Footer example links — low-cost stub that explains where to grab
// the sample files. Proper bundled-resource wiring can land later.
function explainSample(productName, fileName) {
  showResult(
    {
      verified: false,
      unsigned: true,
      failure_reason:
        "The " +
        productName +
        " sample isn't bundled with the app. Download " +
        fileName +
        " from provcheck.ai and drag it into the window to verify it.",
      active_manifest: null,
      signer: null,
      signed_at: null,
      claim_generator: null,
      assertions: {},
      ingredient_count: 0,
      format: null,
      validation_errors: 0,
      did_attestation: null,
      watermarks: [],
    },
    fileName,
  );
}
$sampleRaidio.addEventListener("click", () => explainSample("rAIdio.bot", "rAIdio.bot-sample.mp3"));
$sampleDoomscroll.addEventListener("click", () => explainSample("Doomscroll.FM", "doomscroll.fm-sample.mp4"));
$sampleRaidio.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") explainSample("rAIdio.bot", "rAIdio.bot-sample.mp3");
});
$sampleDoomscroll.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") explainSample("Doomscroll.FM", "doomscroll.fm-sample.mp4");
});

// Identity inputs — hydrate from localStorage, persist on every change.
if ($idHandle) {
  $idHandle.addEventListener("input", () => {
    // User typing clears the "auto-filled from file" annotation —
    // the value is now their own (and may persist again).
    idAutofilled = false;
    if ($idAutofillHint) {
      $idAutofillHint.hidden = true;
      $idAutofillHint.textContent = "";
    }
    saveIdentity();
  });
  $idHandle.addEventListener("change", saveIdentity);
}
if ($idRequire) {
  $idRequire.addEventListener("change", saveIdentity);
}
if ($idWatermark) {
  $idWatermark.addEventListener("change", saveIdentity);
}
hydrateIdentityInputs();

// ============================================================================
// "About this file" card — friendly verify summary
// ============================================================================
//
// Walks report.assertions looking for user-relevant fields (URLs,
// product names, AI source type, license / compliance text) and
// renders them as a card above the raw KV details. The raw details
// stay reachable via the disclosure so engineers can still see the
// full manifest.

// Field-name aliases for the four scalar slots we surface.
const ABOUT_KEYS = {
  productName: ["productName", "product_name", "name", "title"],
  productType: ["productType", "product_type", "description", "summary"],
  modelName: ["modelName", "model_name", "modelFamily", "model_family", "model"],
  license: ["license", "modelLicense", "model_license", "licenseUrl", "license_url"],
  compliance: [
    "compliance",
    "euAiActCompliance",
    "eu_ai_act_compliance",
    "transparency",
    "transparencyNotice",
  ],
};

// AI source-type discriminators from c2pa.actions assertions. Per the
// C2PA spec these live in actions[].digitalSourceType.
const AI_SOURCE_TYPES = new Set([
  "trainedAlgorithmicMedia",
  "compositeTrainedAlgorithmicMedia",
  "algorithmicMedia",
  "compositeAlgorithmicMedia",
]);

function isUrl(s) {
  return typeof s === "string" && /^https?:\/\//i.test(s.trim());
}

function walkAssertions(assertions) {
  const out = {
    urls: new Set(),
    productName: null,
    productType: null,
    modelName: null,
    license: null,
    compliance: null,
    aiSource: null,
  };

  const visit = (val) => {
    if (val == null) return;
    if (typeof val === "string") {
      const trimmed = val.trim();
      if (isUrl(trimmed)) out.urls.add(trimmed);
      return;
    }
    if (Array.isArray(val)) {
      for (const v of val) visit(v);
      return;
    }
    if (typeof val !== "object") return;
    for (const [k, v] of Object.entries(val)) {
      // digitalSourceType is a C2PA standard field — surface its value
      // when it's one of the AI codes.
      if (k === "digitalSourceType" && typeof v === "string") {
        const cleaned = v.split("/").pop() || v;
        if (AI_SOURCE_TYPES.has(cleaned)) out.aiSource = cleaned;
      }
      // Scalar slots: first hit wins so the topmost / most prominent
      // assertion takes precedence.
      for (const [slot, aliases] of Object.entries(ABOUT_KEYS)) {
        if (!out[slot] && aliases.includes(k) && typeof v === "string" && v) {
          out[slot] = v;
        }
      }
      visit(v);
    }
  };
  visit(assertions);
  return out;
}

function renderAboutCard(report, cardEl) {
  if (!cardEl) return;
  const gridEl = cardEl.querySelector('[data-role="about-grid"]');
  const linksEl = cardEl.querySelector('[data-role="about-links"]');
  const linksListEl = cardEl.querySelector('[data-role="about-links-list"]');
  if (!gridEl || !linksEl || !linksListEl) return;

  // Hide outright on unsigned / failed-parse manifests — no assertions
  // to summarise.
  if (
    !report ||
    !report.assertions ||
    typeof report.assertions !== "object" ||
    Array.isArray(report.assertions) ||
    Object.keys(report.assertions).length === 0
  ) {
    cardEl.hidden = true;
    return;
  }
  const facts = walkAssertions(report.assertions);

  // Build the grid rows in display order. Pull a few signals from the
  // top-level report fields too (signer, tool from claim_generator) so
  // the card stands on its own without the raw KV.
  const rows = [];
  if (facts.productName) {
    rows.push({ label: "Made by", value: facts.productName, large: true });
  } else if (report.signer) {
    rows.push({ label: "Made by", value: report.signer, large: true });
  }
  if (facts.productType) {
    rows.push({ label: "About", value: facts.productType });
  }
  if (report.claim_generator || facts.modelName) {
    const bits = [];
    if (report.claim_generator) bits.push(report.claim_generator);
    if (facts.modelName) bits.push(facts.modelName);
    rows.push({
      label: "Made with",
      value: bits.join(" · "),
      ai: !!facts.aiSource,
    });
  } else if (facts.aiSource) {
    rows.push({ label: "Made with", value: "AI-generated", ai: true });
  }
  if (facts.license) {
    rows.push({ label: "License", value: facts.license });
  }
  if (facts.compliance) {
    rows.push({ label: "Compliance", value: facts.compliance });
  }

  // Identity claim (from app.provcheck.identity) — already shown by the
  // attestation badge when the cross-check ran, but the card surfaces
  // it standalone too when only the claim was found (no --auto-identity).
  if (
    report.identity &&
    typeof report.identity === "object" &&
    !report.did_attestation
  ) {
    const handle = report.identity.handle
      ? "@" + report.identity.handle
      : report.identity.did;
    rows.push({
      label: "Identity claim",
      value:
        handle +
        " (unverified; type it into the identity field above and re-verify to attest)",
    });
  }

  // Parent chain — when the file is a derivative (publisher
  // attestation, edit, etc.), surface the upstream creator. The
  // first parent is the direct upstream; if there are more, they're
  // deeper ancestors but still worth listing.
  if (Array.isArray(report.parents) && report.parents.length > 0) {
    for (let i = 0; i < report.parents.length; i++) {
      const p = report.parents[i];
      const label = i === 0 ? "Originally from" : "Earlier source";
      const bits = [];
      if (p.identity && p.identity.handle) {
        bits.push("@" + p.identity.handle);
      } else if (p.identity && p.identity.did) {
        bits.push(p.identity.did);
      }
      if (p.signer) bits.push(p.signer);
      if (p.claim_generator && !bits.includes(p.claim_generator)) {
        bits.push(p.claim_generator);
      }
      if (p.title && !bits.includes(p.title)) {
        bits.push(p.title);
      }
      const value = bits.length > 0 ? bits.join(" · ") : "(parent manifest, source unknown)";
      rows.push({ label, value });
    }
  }

  // Render.
  gridEl.innerHTML = "";
  for (const row of rows) {
    const k = document.createElement("div");
    k.className = "about-key";
    k.textContent = row.label;
    const v = document.createElement("div");
    v.className = "about-val";
    if (row.large) v.classList.add("is-large");
    v.textContent = row.value;
    if (row.ai) {
      const badge = document.createElement("span");
      badge.className = "badge-ai";
      badge.textContent = "AI-generated";
      v.appendChild(badge);
    }
    gridEl.appendChild(k);
    gridEl.appendChild(v);
  }

  // Links list — every URL found anywhere in the assertions, deduped.
  const urls = [...facts.urls].sort();
  if (urls.length > 0) {
    linksListEl.innerHTML = "";
    for (const u of urls) {
      const li = document.createElement("li");
      const a = document.createElement("a");
      a.href = u;
      a.textContent = u;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      li.appendChild(a);
      linksListEl.appendChild(li);
    }
    linksEl.hidden = false;
  } else {
    linksEl.hidden = true;
  }

  // If we found nothing at all, stay hidden so the card doesn't render
  // empty. Headline-rows alone is enough to show.
  cardEl.hidden = rows.length === 0 && urls.length === 0;
}

// Initial state.
showEmpty();

// ============================================================================
// SIGN TAB
// ============================================================================
//
// State machine, driven by `kit_status`:
//   no identity        → setup screen
//   identity, no sess  → connect screen
//   sess, no record    → publish screen
//   ready              → drop zone → preview → signing → done
//
// All backend calls go through Tauri `invoke`. No persistent state in JS
// beyond the last-known status snapshot and the currently-staged file
// path (when previewing a sign).

const SIGN_HANDLE_KEY = "provcheck.sign.handle";

const $tabVerifyBtn = document.getElementById("tab-verify-btn");
const $tabWatermarkBtn = document.getElementById("tab-watermark-btn");
const $tabDetectBtn = document.getElementById("tab-detect-btn");
const $tabKeysBtn = document.getElementById("tab-keys-btn");
const $tabSignBtn = document.getElementById("tab-sign-btn");
const $tabBackfireBtn = document.getElementById("tab-backfire-btn");
const $paneVerify = document.getElementById("tab-verify");
const $paneWatermark = document.getElementById("tab-watermark");
const $paneDetect = document.getElementById("tab-detect");
const $paneKeys = document.getElementById("tab-keys");
const $paneSign = document.getElementById("tab-sign");
const $paneBackfire = document.getElementById("tab-backfire");

// Backfire tab (experimental keyed image-watermark verify).
const $bfWarning = document.getElementById("bf-warning");
const $bfAck = document.getElementById("bf-ack");
const $bfKey = document.getElementById("bf-key");
const $bfSerial = document.getElementById("bf-serial");
const $bfCarriers = document.getElementById("bf-carriers");
const $bfDropzone = document.getElementById("bf-dropzone");
const $bfChooseBtn = document.getElementById("bf-choose-btn");
const $bfLoading = document.getElementById("bf-loading");
const $bfLoadingFile = document.getElementById("bf-loading-file");
const $bfResult = document.getElementById("bf-result");
const $bfVerdict = document.getElementById("bf-verdict");
const $bfResultTitle = document.getElementById("bf-result-title");
const $bfResultFile = document.getElementById("bf-result-file");
const $bfFields = document.getElementById("bf-fields");
const $bfAnother = document.getElementById("bf-another");
const $bfHint = document.getElementById("bf-hint");
const BF_HINT_DEFAULT = "Enter your key above first, then drop or choose an image. It reads automatically, and stays on your machine.";

const $signStripId = document.getElementById("sign-strip-id");
const $signStripSession = document.getElementById("sign-strip-session");
const $signLogoutBtn = document.getElementById("sign-logout-btn");

const $sLoading = document.getElementById("sign-loading");
const $sLoadingMsg = document.getElementById("sign-loading-msg");
const $sSetup = document.getElementById("sign-state-setup");
const $sConnect = document.getElementById("sign-state-connect");
const $sPublish = document.getElementById("sign-state-publish");
const $sStale = document.getElementById("sign-state-stale");
const $sError = document.getElementById("sign-state-error");
const $sErrorText = document.getElementById("sign-error-text");
const $sRetryBtn = document.getElementById("sign-retry-btn");
const $sStaleStatus = document.getElementById("sign-stale-status");
const $sStaleRecoveryCmd = document.getElementById("sign-stale-recovery-cmd");
const $sStaleSkipBtn = document.getElementById("sign-stale-skip-btn");
const $sReady = document.getElementById("sign-state-ready");

const $sInitBtn = document.getElementById("sign-init-btn");

const $sLoginForm = document.getElementById("sign-login-form");
const $sLoginHandle = document.getElementById("sign-login-handle");
const $sLoginPassword = document.getElementById("sign-login-password");
const $sLoginRemember = document.getElementById("sign-login-remember");
const $sLoginError = document.getElementById("sign-login-error");

const $sPublishForm = document.getElementById("sign-publish-form");
const $sPublishLabel = document.getElementById("sign-publish-label");
const $sPublishError = document.getElementById("sign-publish-error");
const $sSkipPublishBtn = document.getElementById("sign-skip-publish-btn");

const $sReadyEmpty = document.getElementById("sign-ready-empty");
const $sPreview = document.getElementById("sign-preview");
const $sSigning = document.getElementById("sign-signing");
const $sDone = document.getElementById("sign-done");
const $sPreviewHeading = document.getElementById("sign-preview-heading");
const $sPreviewPath = document.getElementById("sign-preview-path");
const $sPreviewIdentity = document.getElementById("sign-preview-identity");
const $sPreviewOutput = document.getElementById("sign-preview-output");
const $sChainNotice = document.getElementById("sign-chain-notice");
const $sChainSigner = document.getElementById("sign-chain-signer");
const $sChainToolLabel = document.getElementById("sign-chain-tool-label");
const $sChainTool = document.getElementById("sign-chain-tool");
const $sEmbedIdentity = document.getElementById("sign-embed-identity");
const $sAiArtist = document.getElementById("sign-ai-artist");
const $sAiModel = document.getElementById("sign-ai-model");
const $sAiModelField = document.getElementById("sign-ai-model-field");
const $sReplaceOriginal = document.getElementById("sign-replace-original");
const $sGoBtn = document.getElementById("sign-go-btn");
const $sCancelBtn = document.getElementById("sign-cancel-btn");
const $sGoError = document.getElementById("sign-go-error");
const $sDonePath = document.getElementById("sign-done-path");
const $sAboutCard = document.getElementById("sign-about-card");
const $sAnotherBtn = document.getElementById("sign-another-btn");
const $sVerifyBtn = document.getElementById("sign-verify-btn");

let signStatus = null;          // last KitStatus snapshot
let signStaged = null;          // { path, replaceOriginal, embed } when previewing

// ---- Keys tab element refs -------------------------------------------------
const $keysEmpty = document.getElementById("keys-empty-state");
const $keysKv = document.getElementById("keys-local-kv");
const $keysFingerprint = document.getElementById("keys-local-fingerprint");
const $keysAlgorithm = document.getElementById("keys-local-algorithm");
const $keysBackend = document.getElementById("keys-local-backend");
const $keysCreated = document.getElementById("keys-local-created");
const $keysDidLabel = document.getElementById("keys-local-did-label");
const $keysDid = document.getElementById("keys-local-did");
const $keysHandleLabel = document.getElementById("keys-local-handle-label");
const $keysHandle = document.getElementById("keys-local-handle");
const $keysYkDeviceLabel = document.getElementById("keys-local-yk-device-label");
const $keysYkDevice = document.getElementById("keys-local-yk-device");
const $keysYkPinLabel = document.getElementById("keys-local-yk-pin-label");
const $keysYkPin = document.getElementById("keys-local-yk-pin");
const $keysMismatch = document.getElementById("keys-mismatch-banner");
const $keysMismatchTitle = document.getElementById("keys-mismatch-title");
const $keysMismatchText = document.getElementById("keys-mismatch-text");
const $keysRotateBtn = document.getElementById("keys-rotate-btn");
const $keysSwitchYubikeyBtn = document.getElementById("keys-switch-yubikey-btn");
const $keysActionsError = document.getElementById("keys-actions-error");
const $keysActionsSuccess = document.getElementById("keys-actions-success");
const $keysRecordsTable = document.getElementById("keys-records-table");
const $keysRecordsTbody = document.getElementById("keys-records-tbody");
const $keysRecordsEmpty = document.getElementById("keys-records-empty");
const $keysRecordsNoSession = document.getElementById("keys-records-nosession");

let keysStatus = null;          // last KitStatus snapshot for the Keys tab
let keysRecords = [];           // last kit_list result (raw)
let signSkipPublish = false;    // user clicked "skip and sign locally"

// ---- Tab switching ---------------------------------------------------------

function activateTab(name) {
  const isVerify = name === "verify";
  const isWatermark = name === "watermark";
  const isDetect = name === "detect";
  const isKeys = name === "keys";
  const isSign = name === "sign";
  const isBackfire = name === "backfire";
  $tabVerifyBtn.classList.toggle("is-active", isVerify);
  $tabWatermarkBtn.classList.toggle("is-active", isWatermark);
  $tabDetectBtn.classList.toggle("is-active", isDetect);
  $tabKeysBtn.classList.toggle("is-active", isKeys);
  $tabSignBtn.classList.toggle("is-active", isSign);
  $tabBackfireBtn.classList.toggle("is-active", isBackfire);
  $tabVerifyBtn.setAttribute("aria-selected", String(isVerify));
  $tabWatermarkBtn.setAttribute("aria-selected", String(isWatermark));
  $tabDetectBtn.setAttribute("aria-selected", String(isDetect));
  $tabKeysBtn.setAttribute("aria-selected", String(isKeys));
  $tabSignBtn.setAttribute("aria-selected", String(isSign));
  $tabBackfireBtn.setAttribute("aria-selected", String(isBackfire));
  $paneVerify.classList.toggle("is-active", isVerify);
  $paneWatermark.classList.toggle("is-active", isWatermark);
  $paneDetect.classList.toggle("is-active", isDetect);
  $paneKeys.classList.toggle("is-active", isKeys);
  $paneSign.classList.toggle("is-active", isSign);
  $paneBackfire.classList.toggle("is-active", isBackfire);
  $paneVerify.hidden = !isVerify;
  $paneWatermark.hidden = !isWatermark;
  $paneDetect.hidden = !isDetect;
  $paneKeys.hidden = !isKeys;
  $paneSign.hidden = !isSign;
  $paneBackfire.hidden = !isBackfire;
  if (isKeys) refreshKeysTab();
  if (isSign) refreshSignTab();
  if (isWatermark && typeof refreshModelsStatus === "function") refreshModelsStatus();
}

$tabVerifyBtn.addEventListener("click", () => activateTab("verify"));
$tabWatermarkBtn.addEventListener("click", () => activateTab("watermark"));
$tabDetectBtn.addEventListener("click", () => activateTab("detect"));
$tabKeysBtn.addEventListener("click", () => activateTab("keys"));
$tabSignBtn.addEventListener("click", () => activateTab("sign"));
$tabBackfireBtn.addEventListener("click", () => activateTab("backfire"));

// Watermark-tab file-picker + reset buttons. Reuse Verify tab's
// openFilePicker (which nudges the user to drag on non-Tauri paths).
$wmChooseBtn.addEventListener("click", openFilePicker);
$wmAnother.addEventListener("click", showWmEmpty);

// ---- Backfire tab (experimental keyed image-watermark verify) ------------
// Shells out to the standalone BUSL-licensed backfire.py via the backfire_read command.
// A key is required (Backfire reads only a mark embedded with the same key).

const BF_KEY_STORAGE = "provcheck.backfire.key";
const BF_ACK_STORAGE = "provcheck.backfire.ack";

function bfShowEmpty() {
  $bfDropzone.hidden = false;
  $bfLoading.hidden = true;
  $bfResult.hidden = true;
}

function bfShowLoading(name) {
  $bfLoadingFile.textContent = name ? `Reading ${name}…` : "Reading Backfire mark…";
  $bfDropzone.hidden = true;
  $bfLoading.hidden = false;
  $bfResult.hidden = true;
}

function bfShowResult() {
  $bfDropzone.hidden = true;
  $bfLoading.hidden = true;
  $bfResult.hidden = false;
}

function bfRow(k, v) {
  const row = document.createElement("div");
  row.className = "bf-row";
  const ks = document.createElement("span");
  ks.className = "bf-row-k";
  ks.textContent = k;
  const vs = document.createElement("span");
  vs.className = "bf-row-v mono";
  vs.textContent = v;
  row.appendChild(ks);
  row.appendChild(vs);
  return row;
}

// Backfire is keyed — flag the missing key clearly instead of shelling out.
// Shared by backfirePath and the choose-button guard, so the user is warned
// BEFORE picking a file, not scolded after.
function bfWarnMissingKey() {
  $bfKey.classList.add("bf-field-error");
  $bfKey.focus();
  if ($bfHint) {
    $bfHint.textContent =
      "Enter your key above first. Backfire can only read a mark made with the same key.";
    $bfHint.classList.add("bf-hint-warn");
  }
  setTimeout(() => {
    $bfKey.classList.remove("bf-field-error");
    if ($bfHint) {
      $bfHint.textContent = BF_HINT_DEFAULT;
      $bfHint.classList.remove("bf-hint-warn");
    }
  }, 2600);
}

async function backfirePath(path) {
  const key = ($bfKey.value || "").trim();
  if (!key) {
    bfWarnMissingKey();
    return;
  }
  const serial = ($bfSerial.value || "").trim() || null;
  const carriers = $bfCarriers.value || "band";
  bfShowLoading(prettyPath(path));
  uiLog(`backfire read: start ${prettyPath(path)}`);
  const raced = await raceTimeout(invoke("backfire_read", { path, key, serial, carriers }), 120000);
  if (raced.timedOut) {
    uiLog("backfire read: TIMED OUT after 120s; invoke never settled");
    renderBackfireError(
      "The read timed out after 120 seconds without a response from the engine. See the log for details.",
      path
    );
    return;
  }
  if (raced.error !== undefined) {
    uiLog(`backfire read: invoke rejected: ${raced.error}`);
    renderBackfireError(String(raced.error && raced.error.message ? raced.error.message : raced.error), path);
    return;
  }
  const res = raced.value;
  uiLog(`backfire read: settled ok=${!!(res && res.ok)}`);
  if (!res || !res.ok) {
    renderBackfireError((res && res.error) || "Backfire read failed.", path);
    return;
  }
  renderBackfire(res.data, path);
}

function renderBackfire(bf, path) {
  bfShowResult();
  $bfResultFile.textContent = prettyPath(path);
  const valid = !!(bf && bf.valid === true);
  const tamper = !!(bf && bf.notch_tamper && bf.notch_tamper.detected === true);
  $bfVerdict.classList.remove("is-verified", "is-unsigned", "is-invalid");
  $bfVerdict.classList.add(valid ? "is-verified" : "is-unsigned");
  $bfResultTitle.textContent = valid ? "Backfire mark found" : "No valid Backfire mark";

  const idHex =
    bf && (bf.id_hex || (typeof bf.id === "number" ? "0x" + bf.id.toString(16).toUpperCase() : "—"));
  const margin = bf && bf.min_bit_margin != null ? String(bf.min_bit_margin) : "—";
  const stat = bf && bf.notch_tamper && bf.notch_tamper.stat != null ? bf.notch_tamper.stat : "—";

  $bfFields.replaceChildren();
  $bfFields.appendChild(bfRow("Identifier", valid ? idHex : "—"));
  $bfFields.appendChild(bfRow("Confidence (min-bit margin)", margin));
  $bfFields.appendChild(bfRow("Valid", valid ? "yes" : "no"));
  if (bf && bf.match != null) {
    $bfFields.appendChild(bfRow("Matches expected serial", bf.match ? "yes" : "no"));
  }
  $bfFields.appendChild(
    bfRow("Tamper tripwire", tamper ? `notch tamper detected (stat ${stat})` : `clean (stat ${stat})`),
  );
}

function renderBackfireError(msg, path) {
  bfShowResult();
  $bfResultFile.textContent = prettyPath(path);
  $bfVerdict.classList.remove("is-verified", "is-unsigned", "is-invalid");
  $bfVerdict.classList.add("is-invalid");
  $bfResultTitle.textContent = "Backfire could not run";
  $bfFields.replaceChildren(bfRow("Error", msg));
}

// Restore the acknowledge-once experimental warning. The Backfire KEY is a
// secret and is session-only: it is deliberately never persisted, and the
// removeItem below scrubs any key an earlier build may have left behind.
try {
  localStorage.removeItem(BF_KEY_STORAGE);
  if (localStorage.getItem(BF_ACK_STORAGE) === "1") $bfWarning.hidden = true;
} catch {
  /* storage blocked — show the warning */
}
$bfAck.addEventListener("click", () => {
  $bfWarning.hidden = true;
  try {
    localStorage.setItem(BF_ACK_STORAGE, "1");
  } catch {
    /* non-fatal */
  }
});
$bfChooseBtn.addEventListener("click", () => {
  // Validate the key BEFORE opening the picker — choosing a file and then
  // being scolded (and having the choice discarded) is a wasted round trip.
  if (!($bfKey.value || "").trim()) {
    bfWarnMissingKey();
    return;
  }
  openFilePicker();
});
$bfAnother.addEventListener("click", bfShowEmpty);

// Backfire "How it works" help modal.
const $bfHelpBtn = document.getElementById("bf-help-btn");
const $bfModal = document.getElementById("bf-modal");
const $bfModalClose = document.getElementById("bf-modal-close");
function bfOpenModal() { $bfModal.hidden = false; }
function bfCloseModal() { $bfModal.hidden = true; }
$bfHelpBtn.addEventListener("click", bfOpenModal);
$bfModalClose.addEventListener("click", bfCloseModal);
$bfModal.addEventListener("click", (e) => { if (e.target === $bfModal) bfCloseModal(); });
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !$bfModal.hidden) bfCloseModal();
});

// ---- Watermark-detection models (download-on-demand weights) -----------------
const $modelsBanner = document.getElementById("models-banner");
const $modelsStatusText = document.getElementById("models-status-text");
const $modelsInstallBtn = document.getElementById("models-install-btn");

async function refreshModelsStatus() {
  if (!$modelsBanner) return;
  try {
    const res = await invoke("models_status");
    if (res && res.ok && res.data) {
      const { installed, total } = res.data;
      if (installed >= total) {
        $modelsBanner.hidden = true;
      } else {
        $modelsBanner.hidden = false;
        $modelsStatusText.textContent =
          `${installed} of ${total} installed. Download the rest to enable image, audio, and video watermark detection (about 190 MB).`;
      }
    } else {
      // A status error must not hide the banner: a user with zero models on
      // this path would never see the Install button at all.
      $modelsBanner.hidden = false;
      $modelsStatusText.textContent =
        "Could not check model status: " + ((res && res.error) || "unknown error");
    }
  } catch (e) {
    $modelsBanner.hidden = false;
    $modelsStatusText.textContent =
      "Could not check model status: " + String(e && e.message ? e.message : e);
  }
}

async function installAllModels() {
  if (!$modelsInstallBtn) return;
  const orig = $modelsInstallBtn.textContent;
  $modelsInstallBtn.disabled = true;
  $modelsInstallBtn.textContent = "Installing…";
  $modelsStatusText.textContent = "Downloading models, this can take a minute…";
  try {
    const res = await invoke("install_models");
    $modelsStatusText.textContent =
      res && res.ok ? res.data || "Done." : (res && res.error) || "Install failed.";
  } catch (e) {
    $modelsStatusText.textContent = String(e && e.message ? e.message : e);
  } finally {
    $modelsInstallBtn.disabled = false;
    $modelsInstallBtn.textContent = orig;
    refreshModelsStatus();
  }
}

if ($modelsInstallBtn) $modelsInstallBtn.addEventListener("click", installAllModels);
refreshModelsStatus();

// ---- Backfire reader setup (auto-get the self-contained read environment) ----
const $bfInstallBanner = document.getElementById("bf-install-banner");
const $bfInstallStatus = document.getElementById("bf-install-status");
const $bfInstallBtn = document.getElementById("bf-install-btn");

// The banner is ALWAYS visible: it reports the reader's real state and the
// button always works as install-or-repair. Never hide it — a hidden control
// on a box that needs repair is a dead end.
async function refreshBackfireStatus() {
  if (!$bfInstallBanner) return;
  $bfInstallBanner.hidden = false;
  try {
    const ready = await invoke("backfire_status");
    $bfInstallStatus.textContent =
      ready === true
        ? "Ready. The reader ships inside the app; Install / Repair re-copies it if anything is broken."
        : "Not set up. Install / Repair copies the bundled reader into place; no downloads needed.";
  } catch (e) {
    $bfInstallStatus.textContent =
      "Status check failed: " + String(e && e.message ? e.message : e);
  }
}

async function installBackfire() {
  if (!$bfInstallBtn) return;
  const orig = $bfInstallBtn.textContent;
  $bfInstallBtn.disabled = true;
  $bfInstallBtn.textContent = "Working…";
  $bfInstallStatus.textContent = "Installing / repairing the Backfire reader…";
  try {
    const res = await invoke("install_backfire");
    $bfInstallStatus.textContent =
      res && res.ok ? res.data || "Done." : (res && res.error) || "Setup failed.";
  } catch (e) {
    $bfInstallStatus.textContent = String(e && e.message ? e.message : e);
  } finally {
    $bfInstallBtn.disabled = false;
    $bfInstallBtn.textContent = orig;
  }
}

if ($bfInstallBtn) $bfInstallBtn.addEventListener("click", installBackfire);
refreshBackfireStatus();

// ---- Mellin section (Keyed marks tab, audio-side keyed forensics) ---------
// Shells out to the standalone BUSL-licensed provcheck-mellin binary via the
// mellin_read command. Secret-keyed: needs the seller secret FILE (picked via
// a native dialog so we get a real path) and the work id. The secret path is
// held in JS memory only — never persisted, never logged.

const $mlStatus = document.getElementById("ml-status");
const $mlSecretBtn = document.getElementById("ml-secret-btn");
const $mlSecretPath = document.getElementById("ml-secret-path");
const $mlWorkId = document.getElementById("ml-workid");
const $mlSerial = document.getElementById("ml-serial");
const $mlChooseBtn = document.getElementById("ml-choose-btn");
const $mlZone = document.getElementById("ml-zone");
const $mlLoading = document.getElementById("ml-loading");
const $mlLoadingFile = document.getElementById("ml-loading-file");
const $mlResult = document.getElementById("ml-result");
const $mlVerdict = document.getElementById("ml-verdict");
const $mlResultTitle = document.getElementById("ml-result-title");
const $mlResultFile = document.getElementById("ml-result-file");
const $mlFields = document.getElementById("ml-fields");
const $mlAnother = document.getElementById("ml-another");
const $mlHint = document.getElementById("ml-hint");
const ML_HINT_DEFAULT = $mlHint ? $mlHint.textContent : "";
const ML_WORKID_STORAGE = "provcheck.mellin.workid";

let mlSecretFile = null; // absolute path, session-only

async function refreshMellinStatus() {
  if (!$mlStatus) return;
  try {
    const ready = await invoke("mellin_status");
    $mlStatus.textContent =
      ready === true
        ? "Ready. The tool ships inside the app; pick your secret file and work id to read."
        : "Not found. Reinstall provcheck, or set MELLIN_BIN to the provcheck-mellin binary.";
  } catch (e) {
    $mlStatus.textContent = "Status check failed: " + String(e && e.message ? e.message : e);
  }
}

function mlShowEmpty() {
  $mlZone.hidden = false;
  $mlLoading.hidden = true;
  $mlResult.hidden = true;
}

let mlWarnSticky = false;

function mlWarn(msg, sticky) {
  if (!$mlHint) return;
  $mlHint.textContent = msg;
  $mlHint.classList.add("bf-hint-warn");
  mlWarnSticky = !!sticky;
  if (!sticky) {
    setTimeout(() => {
      if (mlWarnSticky) return; // a sticky warning arrived meanwhile
      $mlHint.textContent = ML_HINT_DEFAULT;
      $mlHint.classList.remove("bf-hint-warn");
    }, 4000);
  }
}

function mlClearWarn() {
  mlWarnSticky = false;
  if (!$mlHint) return;
  $mlHint.textContent = ML_HINT_DEFAULT;
  $mlHint.classList.remove("bf-hint-warn");
}

async function mellinPath(path) {
  const workId = ($mlWorkId.value || "").trim();
  if (!mlSecretFile) {
    // A failed precondition must be IMPOSSIBLE to miss: scroll the section
    // into view, flag the control, and keep the warning up until resolved.
    // (The secret is deliberately never persisted, so it must be re-picked
    // after every launch — the exact state a returning tester is in.)
    $mlSecretBtn.scrollIntoView({ behavior: "smooth", block: "center" });
    $mlSecretPath.classList.add("bf-field-error");
    $mlSecretBtn.focus();
    mlWarn(
      "Choose your secret file first (it is never stored, so it resets on every app restart), then drop the audio again.",
      true
    );
    return;
  }
  if (!workId) {
    $mlWorkId.scrollIntoView({ behavior: "smooth", block: "center" });
    $mlWorkId.focus();
    mlWarn("Enter the work id the serial was embedded with, then drop the audio again.", true);
    return;
  }
  mlClearWarn();
  try {
    localStorage.setItem(ML_WORKID_STORAGE, workId);
  } catch {
    /* storage blocked — non-fatal */
  }
  const serial = ($mlSerial.value || "").trim() || null;
  $mlZone.hidden = true;
  $mlLoading.hidden = false;
  $mlResult.hidden = true;
  $mlLoadingFile.textContent = `Reading ${prettyPath(path)}…`;
  uiLog(`mellin read: start ${prettyPath(path)}`);
  const raced = await raceTimeout(
    invoke("mellin_read", {
      path,
      secretFile: mlSecretFile,
      workId,
      serial,
      repeat: null,
    }),
    120000
  );
  if (raced.timedOut) {
    uiLog("mellin read: TIMED OUT after 120s; invoke never settled");
    renderMellinError(
      "The read timed out after 120 seconds without a response from the engine. See the log for details.",
      path
    );
    return;
  }
  if (raced.error !== undefined) {
    uiLog(`mellin read: invoke rejected: ${raced.error}`);
    renderMellinError(String(raced.error && raced.error.message ? raced.error.message : raced.error), path);
    return;
  }
  const res = raced.value;
  uiLog(`mellin read: settled ok=${!!(res && res.ok)}`);
  if (!res || !res.ok) {
    renderMellinError((res && res.error) || "Mellin read failed.", path);
    return;
  }
  renderMellin(res.data, path);
}

function renderMellin(m, path) {
  $mlZone.hidden = true;
  $mlLoading.hidden = true;
  $mlResult.hidden = false;
  $mlResultFile.textContent = prettyPath(path);
  const full = !!(m && m.fully_recovered === true);
  $mlVerdict.classList.remove("is-verified", "is-unsigned", "is-invalid");
  $mlVerdict.classList.add(full ? "is-verified" : "is-unsigned");
  $mlResultTitle.textContent = full ? "Mellin serial recovered" : "No full Mellin serial";

  const bits = m && m.bits_recovered != null ? m.bits_recovered : 0;
  const votes = m && m.min_bit_votes != null ? m.min_bit_votes : 0;
  const erasure = m && m.erasure_rate != null ? (m.erasure_rate * 100).toFixed(1) + "%" : "—";

  $mlFields.replaceChildren();
  $mlFields.appendChild(bfRow("Serial", full ? m.serial : "—"));
  $mlFields.appendChild(bfRow("Bits recovered", `${bits}/64`));
  $mlFields.appendChild(bfRow("Erasure rate", erasure));
  $mlFields.appendChild(bfRow("Min bit votes", String(votes)));
  if (m && m.match != null) {
    $mlFields.appendChild(bfRow("Matches expected serial", m.match ? "yes" : "no"));
  }
}

function renderMellinError(msg, path) {
  $mlZone.hidden = true;
  $mlLoading.hidden = true;
  $mlResult.hidden = false;
  $mlResultFile.textContent = prettyPath(path);
  $mlVerdict.classList.remove("is-verified", "is-unsigned", "is-invalid");
  $mlVerdict.classList.add("is-invalid");
  $mlResultTitle.textContent = "Mellin could not run";
  $mlFields.replaceChildren(bfRow("Error", msg));
}

if ($mlSecretBtn) {
  $mlSecretBtn.addEventListener("click", async () => {
    try {
      const p = await invoke("pick_any_file", { title: "Choose the Mellin secret file", kind: null });
      if (p) {
        mlSecretFile = p;
        $mlSecretPath.textContent = prettyPath(p);
        $mlSecretPath.title = p;
        $mlSecretPath.classList.remove("bf-field-error");
        mlClearWarn();
      }
    } catch (e) {
      mlWarn("Could not open the file dialog: " + String(e && e.message ? e.message : e));
    }
  });
}
if ($mlChooseBtn) {
  $mlChooseBtn.addEventListener("click", async () => {
    try {
      const p = await invoke("pick_any_file", { title: "Choose an audio file to read", kind: "audio" });
      if (p) mellinPath(p);
    } catch (e) {
      mlWarn("Could not open the file dialog: " + String(e && e.message ? e.message : e));
    }
  });
}
if ($mlAnother) $mlAnother.addEventListener("click", mlShowEmpty);
try {
  const savedWorkId = localStorage.getItem(ML_WORKID_STORAGE);
  if (savedWorkId && $mlWorkId) $mlWorkId.value = savedWorkId;
} catch {
  /* storage blocked */
}
refreshMellinStatus();

// External-URL click interceptor. Tauri 2 sandboxes `target="_blank"`
// anchors, so provcheck.ai / creativemayhem.com links in the top bar
// (and any `[data-external]` link in the Detect tab or elsewhere) go
// nowhere by default. Delegate on document.body and IPC to the
// backend's open_url command, which shells out to the platform URL
// handler. Ignore modifier-clicks so a middle-click still no-ops
// rather than double-open.
document.body.addEventListener("click", (e) => {
  if (e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
  const a = e.target && e.target.closest ? e.target.closest("a[href]") : null;
  if (!a) return;
  const href = a.getAttribute("href") || "";
  if (!(href.startsWith("http://") || href.startsWith("https://"))) return;
  e.preventDefault();
  invoke("open_url", { url: href }).catch(() => {
    // Silent — the frontend has no meaningful recourse. The backend
    // logs the error via its Result return.
  });
});

// ---- State dispatch --------------------------------------------------------

function showSignState(name) {
  for (const el of [$sLoading, $sSetup, $sConnect, $sPublish, $sStale, $sError, $sReady]) {
    el.hidden = true;
  }
  if (name === "loading") $sLoading.hidden = false;
  else if (name === "setup") $sSetup.hidden = false;
  else if (name === "connect") $sConnect.hidden = false;
  else if (name === "publish") $sPublish.hidden = false;
  else if (name === "stale") $sStale.hidden = false;
  else if (name === "error") $sError.hidden = false;
  else if (name === "ready") {
    $sReady.hidden = false;
    resetReadySubstate();
  }
}

function resetReadySubstate() {
  $sReadyEmpty.hidden = false;
  $sPreview.hidden = true;
  $sSigning.hidden = true;
  $sDone.hidden = true;
}

function showReadySubstate(name) {
  $sReadyEmpty.hidden = name !== "empty";
  $sPreview.hidden = name !== "preview";
  $sSigning.hidden = name !== "signing";
  $sDone.hidden = name !== "done";
}

/// Refresh the Keys tab from kit_status + kit_list. Renders local
/// identity card, mismatch banner, and atproto records table.
async function refreshKeysTab() {
  $keysActionsError.hidden = true;
  $keysActionsSuccess.hidden = true;

  const statusRes = await invoke("kit_status", { dataDir: null });
  keysStatus = statusRes.ok ? statusRes.data : null;
  renderKeysLocalCard(keysStatus && keysStatus.identity);

  // Records: only fetch if we have a session.
  if (!keysStatus || !keysStatus.session) {
    keysRecords = [];
    $keysRecordsTable.hidden = true;
    $keysRecordsEmpty.hidden = true;
    $keysRecordsNoSession.hidden = false;
    renderKeysMismatchBanner(keysStatus && keysStatus.identity, []);
    return;
  }
  $keysRecordsNoSession.hidden = true;

  const listRes = await invoke("kit_list", { dataDir: null });
  if (!listRes.ok) {
    // A fetch failure must not render as "you have no records" — that tells
    // the user their published keys vanished. Show the error, and clear any
    // stale mismatch banner from the previous refresh.
    keysRecords = [];
    $keysRecordsTable.hidden = true;
    $keysRecordsEmpty.hidden = true;
    $keysMismatch.hidden = true;
    setKeysError(
      "Could not load your atproto records: " + (listRes.error || "unknown error")
    );
    return;
  }
  keysRecords = listRes.data || [];
  if (keysRecords.length === 0) {
    $keysRecordsTable.hidden = true;
    $keysRecordsEmpty.hidden = false;
  } else {
    $keysRecordsTable.hidden = false;
    $keysRecordsEmpty.hidden = true;
    renderKeysRecordsTable(keysStatus.identity, keysRecords);
  }
  renderKeysMismatchBanner(keysStatus.identity, keysRecords);
}

function renderKeysLocalCard(identity) {
  if (!identity) {
    $keysEmpty.hidden = false;
    $keysKv.hidden = true;
    return;
  }
  $keysEmpty.hidden = true;
  $keysKv.hidden = false;

  $keysFingerprint.textContent = identity.fingerprint || "—";
  $keysAlgorithm.textContent = identity.algorithm || "—";
  $keysCreated.textContent = identity.created_at || "—";

  // Backend display + Yubikey-specific extras.
  const backend = identity.backend || "—";
  if (backend === "yubikey") {
    $keysBackend.textContent = "Yubikey (PIV slot 0x" +
      (identity.yubikey_slot != null ? identity.yubikey_slot.toString(16) : "??") + ")";
    $keysYkDeviceLabel.hidden = false;
    $keysYkDevice.hidden = false;
    if (identity.yubikey_present === true) {
      $keysYkDevice.textContent = "Present (serial " + (identity.yubikey_serial ?? "?") + ")";
    } else if (identity.yubikey_present === false) {
      $keysYkDevice.textContent = "Not reachable (serial " + (identity.yubikey_serial ?? "?") + "; plug it in)";
    } else {
      $keysYkDevice.textContent = "—";
    }
    if (identity.pin_tries_remaining != null) {
      $keysYkPinLabel.hidden = false;
      $keysYkPin.hidden = false;
      $keysYkPin.textContent = identity.pin_tries_remaining + " of 3 remaining" +
        (identity.pin_tries_remaining === 1 ? " (one more failed try locks the PIN)" :
         identity.pin_tries_remaining === 0 ? "; locked, recover via ykman" : "");
    } else {
      $keysYkPinLabel.hidden = true;
      $keysYkPin.hidden = true;
    }
  } else {
    $keysBackend.textContent =
      backend === "keychain" ? "OS keychain"
      : backend === "encrypted_file" ? "Encrypted file (age)"
      : backend;
    $keysYkDeviceLabel.hidden = true;
    $keysYkDevice.hidden = true;
    $keysYkPinLabel.hidden = true;
    $keysYkPin.hidden = true;
  }

  if (identity.did) {
    $keysDidLabel.hidden = false;
    $keysDid.hidden = false;
    $keysDid.textContent = identity.did;
  } else {
    $keysDidLabel.hidden = true;
    $keysDid.hidden = true;
  }
  if (identity.handle) {
    $keysHandleLabel.hidden = false;
    $keysHandle.hidden = false;
    $keysHandle.textContent = "@" + identity.handle;
  } else {
    $keysHandleLabel.hidden = true;
    $keysHandle.hidden = true;
  }
}

function renderKeysMismatchBanner(identity, records) {
  $keysMismatch.hidden = true;
  if (!identity) return;
  const fp = identity.fingerprint;
  const localRecord = records.find((r) => r.fingerprint === fp);
  const orphanActive = records.find(
    (r) => r.status === "active" && r.fingerprint !== fp,
  );

  if (localRecord && localRecord.status === "active") {
    // Healthy state — no banner.
    return;
  }
  if (localRecord && localRecord.status === "superseded") {
    $keysMismatchTitle.textContent = "Your local key is superseded";
    $keysMismatchText.textContent =
      "This box's local key is no longer the active record on atproto. " +
      "Signatures made with it won't attest. Use Mint fresh + publish to " +
      "rotate, or Switch to Yubikey identity to mint on hardware.";
    $keysMismatch.hidden = false;
    return;
  }
  if (localRecord && localRecord.status === "revoked") {
    $keysMismatchTitle.textContent = "Your local key is revoked";
    $keysMismatchText.textContent =
      "This local key has been marked revoked on atproto. " +
      "Mint fresh + publish to recover.";
    $keysMismatch.hidden = false;
    return;
  }
  if (orphanActive) {
    $keysMismatchTitle.textContent = "Active record uses a key you don't have";
    $keysMismatchText.textContent =
      "An active record exists under your DID but uses a different key " +
      "than the one on this box. If you don't have that private key on " +
      "any other machine, revoke it (action below) then mint fresh.";
    $keysMismatch.hidden = false;
    return;
  }
  // Local fp not in records, no orphan active: first-publish state, no
  // banner. The Sign tab handles the publish flow.
}

function renderKeysRecordsTable(identity, records) {
  $keysRecordsTbody.innerHTML = "";
  const localFp = identity ? identity.fingerprint : null;
  for (const r of records) {
    const tr = document.createElement("tr");

    const statusTd = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = "keys-status-badge is-" + r.status;
    badge.textContent = r.status;
    statusTd.appendChild(badge);
    if (r.fingerprint === localFp) {
      const localTag = document.createElement("span");
      localTag.style.marginLeft = "8px";
      localTag.style.fontSize = "10.5px";
      localTag.style.color = "var(--text-muted)";
      localTag.textContent = "(this box)";
      statusTd.appendChild(localTag);
    }
    tr.appendChild(statusTd);

    const fpTd = document.createElement("td");
    fpTd.className = "mono";
    fpTd.textContent = r.fingerprint;
    tr.appendChild(fpTd);

    const createdTd = document.createElement("td");
    createdTd.textContent = (r.created_at || "").slice(0, 10);
    tr.appendChild(createdTd);

    const labelTd = document.createElement("td");
    labelTd.textContent = r.label || "—";
    tr.appendChild(labelTd);

    const actionsTd = document.createElement("td");
    actionsTd.className = "keys-row-actions";
    if (r.status === "active") {
      const revBtn = document.createElement("button");
      revBtn.type = "button";
      revBtn.className = "btn btn-ghost";
      revBtn.textContent = "Revoke";
      revBtn.addEventListener("click", () => handleRevoke(r));
      actionsTd.appendChild(revBtn);
    }
    tr.appendChild(actionsTd);

    $keysRecordsTbody.appendChild(tr);
  }
}

// ---- Keys tab actions (P6) -------------------------------------------------

function setKeysError(msg) {
  $keysActionsSuccess.hidden = true;
  if (!msg) {
    $keysActionsError.hidden = true;
    return;
  }
  $keysActionsError.hidden = false;
  $keysActionsError.textContent = msg;
}

function setKeysSuccess(msg) {
  $keysActionsError.hidden = true;
  if (!msg) {
    $keysActionsSuccess.hidden = true;
    return;
  }
  $keysActionsSuccess.hidden = false;
  $keysActionsSuccess.textContent = msg;
}

/// Revoke a record on atproto. confirm() prompts the user; on
/// acceptance we call kit_revoke and refresh the tab.
async function handleRevoke(record) {
  const isLocal = keysStatus &&
    keysStatus.identity &&
    keysStatus.identity.fingerprint === record.fingerprint;
  const msg = isLocal
    ? "Revoke YOUR OWN active key? Anyone you've signed for will see " +
      "your past signatures as 'signing key not currently attested.' " +
      "You'll want to mint fresh + publish a replacement immediately " +
      "after.\n\nFingerprint: " + record.fingerprint
    : "Revoke this record? " +
      "atproto will mark validUntil = now, and verifiers will treat " +
      "any future signatures by this key as not attested. The record " +
      "stays in atproto history as a tombstone (you can't un-revoke).\n\n" +
      "Fingerprint: " + record.fingerprint;
  if (!(await appConfirm(msg))) return;

  setKeysError(null);
  const res = await invoke("kit_revoke", {
    args: {
      fingerprint: record.fingerprint,
      supersededBy: null,
      dataDir: null,
    },
  });
  if (!res.ok) {
    setKeysError(res.error || "Revoke failed.");
    return;
  }
  setKeysSuccess("Record revoked (rkey " + res.data.rkey + ").");
  await refreshKeysTab();
}

/// Mint a fresh keypair on the current backend, publish it as the new
/// active record, and revoke the previous record. Software backend
/// only — Yubikey rotation drops to CLI.
$keysRotateBtn.addEventListener("click", async () => {
  if (!keysStatus || !keysStatus.identity) {
    setKeysError("No local identity to rotate from. Initialize one first.");
    return;
  }
  const backend = keysStatus.identity.backend;
  if (backend === "yubikey") {
    setKeysError(
      "Yubikey rotation needs an in-process PIN prompt the GUI doesn't " +
      "have yet. Run `provcheck-kit init --yubikey --force` from a terminal, " +
      "then come back here to revoke the old record.",
    );
    return;
  }
  if (backend === "encrypted_file") {
    setKeysError(
      "Age-file rotation needs an in-process passphrase prompt the GUI " +
      "doesn't have yet. Run `provcheck-kit rotate` from a terminal.",
    );
    return;
  }
  const label = await appPrompt(
    "Optional label for the new record (e.g. \"studio mac\"):",
    ""
  );
  if (label === null) return; // user cancelled

  if (!(await appConfirm(
    "Mint a fresh signing key and publish it?\n\n" +
    "This orphans the current key for anything signed with it going " +
    "forward (existing signatures stay valid until the old record's " +
    "validUntil is honored). The old record gets supersededBy linkage."
  ))) return;

  setKeysError(null);
  setKeysSuccess("Rotating…");
  $keysRotateBtn.disabled = true;
  try {
    const res = await invoke("kit_rotate", {
      args: { label: label || null, dataDir: null },
    });
    if (!res.ok) {
      setKeysError(res.error || "Rotate failed.");
      return;
    }
    setKeysSuccess(
      "Rotated. New fingerprint " + (res.data.new_fingerprint || "").slice(7, 15) +
      "… published; old record revoked."
    );
    await refreshKeysTab();
  } finally {
    $keysRotateBtn.disabled = false;
  }
});

/// "Switch to Yubikey identity" — opens guidance to drop to CLI for
/// the actual init (PIN prompt + management-key auth need a terminal).
$keysSwitchYubikeyBtn.addEventListener("click", async () => {
  setKeysError(null);
  setKeysSuccess(null);
  const listRes = await invoke("kit_list_yubikeys", {});
  const devices = listRes.ok ? (listRes.data || []) : [];
  let lines = [];
  if (devices.length === 0) {
    lines.push("No Yubikey detected.");
    lines.push("Plug one into a USB port and try again.");
  } else {
    lines.push("Detected " + devices.length + " Yubikey(s); serials: " +
      devices.map(d => d.serial).join(", "));
    lines.push("");
    lines.push("Switching to a Yubikey-backed identity needs a terminal " +
      "for the PIV PIN prompt. Run these from a terminal:");
    lines.push("");
    lines.push("    ykman piv access change-pin  # if still on factory default");
    lines.push("    provcheck-kit init --yubikey --force");
    lines.push("");
    lines.push("Then return here to publish the new fingerprint.");
  }
  await appAlert(lines.join("\n"));
});

async function refreshSignTab() {
  showSignState("loading");
  $sLoadingMsg.textContent = "Loading…";
  const res = await invoke("kit_status", { dataDir: null });
  if (!res.ok) {
    signStatus = null;
    paintStrip(null, null);
    // Never show "setup" here: a user who HAS an identity would be offered
    // a generate button that then refuses with force=true advice the GUI
    // cannot follow. Show the error and a Retry instead.
    $sErrorText.textContent = res.error || "Unknown error loading kit status.";
    showSignState("error");
    return;
  }
  signStatus = res.data;
  paintStrip(signStatus.identity, signStatus.session);

  if (!signStatus.identity) {
    signSkipPublish = false;
    showSignState("setup");
    return;
  }
  if (!signStatus.session) {
    signSkipPublish = false;
    const remembered = localStorage.getItem(SIGN_HANDLE_KEY);
    if (remembered && !$sLoginHandle.value) {
      $sLoginHandle.value = remembered;
    }
    // Fire-and-forget keychain recall — if we previously stashed a
    // password for this handle, the field pre-fills + the checkbox
    // flips to remembered. Doesn't block the state transition.
    if ($sLoginHandle.value) {
      tryRecallPasswordFor($sLoginHandle.value);
    }
    showSignState("connect");
    return;
  }

  // Session present. Check whether the local fingerprint is already an
  // active record in the user's repo.
  if (signSkipPublish) {
    showSignState("ready");
    return;
  }
  $sLoadingMsg.textContent = "Checking published keys…";
  showSignState("loading");
  const listRes = await invoke("kit_list", { dataDir: null });
  if (!listRes.ok) {
    // Couldn't reach atproto — degrade to "ready" so the user can at
    // least sign locally. The error is visible on the strip via
    // session presence.
    showSignState("ready");
    return;
  }
  const fp = signStatus.identity.fingerprint;
  const records = listRes.data || [];
  const localRecord = records.find((r) => r.fingerprint === fp);
  if (localRecord && localRecord.status === "active") {
    showSignState("ready");
    return;
  }
  if (localRecord) {
    // Local fingerprint IS in the user's repo but isn't active any more
    // — it's been superseded or revoked. Signatures made by this key
    // won't pass the verifier's `valid_until` check, so this is a
    // recovery state, not a publish state. Surface explicitly with
    // CLI guidance instead of looping into "Publish key" + a confusing
    // conflict error.
    renderStaleState(localRecord, records);
    showSignState("stale");
    return;
  }
  // No matching record at all — first publish from this device.
  showSignState("publish");
}

/// Populate the stale-state panel with the local record's status and
/// a copy-pasteable CLI recovery sequence. The exact sequence depends
/// on whether an "orphan active" record exists (an active record under
/// the user's DID whose private key the local box doesn't hold) — that
/// happens when a rotation on another machine produced the active key
/// and that machine's backup is now lost. The orphan needs revocation
/// before a clean rotate works.
function renderStaleState(localRecord, allRecords) {
  $sStaleStatus.textContent = localRecord.status; // "superseded" | "revoked"
  const localFp = localRecord.fingerprint;
  const orphanActive = allRecords.find(
    (r) => r.status === "active" && r.fingerprint !== localFp,
  );
  const lines = [];
  if (orphanActive) {
    lines.push("# the active atproto record uses a key this box does not hold;");
    lines.push("# revoke it first so no leaked copy can sign in your name");
    lines.push("provcheck-kit revoke " + orphanActive.fingerprint);
    lines.push("");
  }
  lines.push("# mint a fresh signing key on this box");
  lines.push("provcheck-kit init --force");
  lines.push("");
  lines.push("# publish the new fingerprint to atproto");
  lines.push("provcheck-kit publish");
  $sStaleRecoveryCmd.textContent = lines.join("\n");
}

function paintStrip(identity, session) {
  if (identity) {
    const shortFp = identity.fingerprint.startsWith("sha256:")
      ? identity.fingerprint.slice(7, 7 + 8) + "…"
      : identity.fingerprint.slice(0, 8) + "…";
    const handle = identity.handle ? "@" + identity.handle : "(no bsky handle)";
    $signStripId.textContent = handle + " · " + shortFp;
    $signStripId.classList.remove("is-empty");
  } else {
    $signStripId.textContent = "not set up";
    $signStripId.classList.add("is-empty");
  }
  if (session) {
    $signStripSession.textContent = "@" + session.handle;
    $signStripSession.classList.remove("is-empty");
    $signLogoutBtn.hidden = false;
  } else {
    $signStripSession.textContent = "disconnected";
    $signStripSession.classList.add("is-empty");
    $signLogoutBtn.hidden = true;
  }
}

// ---- Init flow -------------------------------------------------------------

if ($sRetryBtn) $sRetryBtn.addEventListener("click", refreshSignTab);

$sInitBtn.addEventListener("click", async () => {
  $sInitBtn.disabled = true;
  $sInitBtn.textContent = "Generating…";
  const res = await invoke("kit_init", { dataDir: null, force: false });
  $sInitBtn.disabled = false;
  $sInitBtn.textContent = "Generate signing key";
  if (!res.ok) {
    await appAlert("Failed to generate identity:\n" + (res.error || "unknown error"));
    return;
  }
  await refreshSignTab();
});

// ---- Login flow ------------------------------------------------------------

$sLoginForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  $sLoginError.hidden = true;
  const handle = $sLoginHandle.value.trim().replace(/^@/, "");
  const password = $sLoginPassword.value;
  if (!handle || !password) return;

  const btn = document.getElementById("sign-login-btn");
  btn.disabled = true;
  btn.textContent = "Connecting…";

  const res = await invoke("kit_login", {
    args: {
      handle,
      appPassword: password,
      pds: null,
      dataDir: null,
    },
  });

  btn.disabled = false;
  btn.textContent = "Connect";

  if (!res.ok) {
    $sLoginError.textContent = res.error || "Login failed.";
    $sLoginError.hidden = false;
    return;
  }

  localStorage.setItem(SIGN_HANDLE_KEY, handle);
  if ($sLoginRemember.checked) {
    // Stash the app password in the OS keychain so the next session
    // can pre-fill it. Soft failure: if the keychain refuses we
    // silently fall through — the user is logged in either way.
    try {
      await invoke("kit_remember_password", {
        args: { handle, appPassword: password },
      });
    } catch (_e) {
      // No surfacing — login already succeeded.
    }
  } else {
    // Explicit opt-out: if we previously stored a password for this
    // handle, clear it so the next login won't auto-fill.
    try {
      await invoke("kit_forget_password", { handle });
    } catch (_e) { /* noop */ }
  }
  $sLoginPassword.value = "";
  await refreshSignTab();
});

// When the handle field changes (typed or autofilled), try to recall
// a previously-stored app password from the keychain. Only fires
// when the password field is empty so we never overwrite a value the
// user is mid-typing. Setting the password also flips the
// "Remember me" checkbox on so the just-recalled credential stays
// stored after the next successful login.
async function tryRecallPasswordFor(handle) {
  const cleaned = (handle || "").trim().replace(/^@/, "");
  if (!cleaned) return;
  if ($sLoginPassword.value) return;
  try {
    // ApiResult serializes as {ok, error, data} — the recalled password is
    // res.data (this read res.value for a while, which silently killed the
    // prefill; the login still worked, the convenience did not).
    const res = await invoke("kit_recall_password", { handle: cleaned });
    if (res.ok && typeof res.data === "string" && res.data.length > 0) {
      $sLoginPassword.value = res.data;
      $sLoginRemember.checked = true;
    }
  } catch (_e) {
    // Soft failure — the user types their password normally.
  }
}

$sLoginHandle.addEventListener("change", () => {
  tryRecallPasswordFor($sLoginHandle.value);
});
$sLoginHandle.addEventListener("blur", () => {
  tryRecallPasswordFor($sLoginHandle.value);
});

$signLogoutBtn.addEventListener("click", async () => {
  if (!(await appConfirm("Disconnect this device's atproto session?"))) return;
  await invoke("kit_logout", { dataDir: null });
  await refreshSignTab();
});

// ---- Publish flow ----------------------------------------------------------

$sPublishForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  $sPublishError.hidden = true;
  const label = $sPublishLabel.value.trim();
  const btn = document.getElementById("sign-publish-btn");
  btn.disabled = true;
  btn.textContent = "Publishing…";

  const res = await invoke("kit_publish", {
    args: { label: label || null, dataDir: null },
  });

  btn.disabled = false;
  btn.textContent = "Publish key";

  if (!res.ok) {
    $sPublishError.textContent = res.error || "Publish failed.";
    $sPublishError.hidden = false;
    return;
  }

  $sPublishLabel.value = "";
  await refreshSignTab();
});

$sSkipPublishBtn.addEventListener("click", () => {
  signSkipPublish = true;
  showSignState("ready");
});

$sStaleSkipBtn.addEventListener("click", () => {
  signSkipPublish = true;
  showSignState("ready");
});

// ---- Sign flow -------------------------------------------------------------

window.signOnDrop = async function (path) {
  // Drag-drop dispatcher routes here when Sign tab is active.
  if (!signStatus || !signStatus.identity) {
    await appAlert("Set up an identity first before signing.");
    return;
  }
  if ($sReady.hidden) {
    // The user dropped while the ready screen isn't visible (e.g.
    // they're on the publish screen). Switch to ready first.
    showSignState("ready");
  }
  signStaged = {
    path,
    replaceOriginal: $sReplaceOriginal.checked,
    embed: $sEmbedIdentity.checked,
    aiArtist: $sAiArtist.checked,
    aiModel: $sAiModel.value.trim(),
    action: null,        // resolved after inspect_source returns
    provenance: null,    // SourceProvenanceDto when source is signed
  };
  const out = signStaged.replaceOriginal ? path : sidecarPath(path);
  $sPreviewPath.textContent = path;
  $sPreviewIdentity.textContent = signStatus.identity.handle
    ? "@" + signStatus.identity.handle
    : signStatus.identity.fingerprint;
  $sPreviewOutput.textContent = out;
  $sGoError.hidden = true;

  // Reset chain notice + action radios. Default both to the
  // unsigned-source state; we'll flip them based on inspect_source
  // when the call completes (a few hundred ms typically).
  $sChainNotice.hidden = true;
  $sPreviewHeading.textContent = "Ready to sign";
  setActionRadio("created");
  signStaged.action = "created";

  showReadySubstate("preview");

  // Inspect the source for prior provenance. Default action
  // changes based on whether the file already carries C2PA data.
  const inspect = await invoke("kit_inspect_source", { path });
  if (!inspect.ok || !inspect.data) {
    // Unsigned or unrecognised source — keep the "created"
    // default. Action picker stays available if the user
    // wants to override.
    return;
  }
  const prov = inspect.data;
  signStaged.provenance = prov;
  // Render the chain notice.
  $sChainSigner.textContent = prov.signer || prov.claim_generator || "(unknown signer)";
  if (prov.claim_generator) {
    $sChainTool.textContent = prov.claim_generator;
    $sChainToolLabel.hidden = false;
    $sChainTool.hidden = false;
  } else {
    $sChainToolLabel.hidden = true;
    $sChainTool.hidden = true;
  }
  $sChainNotice.hidden = false;
  $sPreviewHeading.textContent = "Ready to publish";
  // Default to "published" — the publisher-attestation case.
  setActionRadio("published");
  signStaged.action = "published";
};

function setActionRadio(value) {
  const radios = document.getElementsByName("sign-action");
  for (const r of radios) {
    r.checked = r.value === value;
  }
}

function getActionRadio() {
  const radios = document.getElementsByName("sign-action");
  for (const r of radios) {
    if (r.checked) return r.value;
  }
  return "created";
}

// Wire the action radios to update the staged action whenever
// the user picks one.
for (const r of document.getElementsByName("sign-action")) {
  r.addEventListener("change", () => {
    if (signStaged) signStaged.action = getActionRadio();
  });
}

function sidecarPath(p) {
  // Mirror the Rust-side sidecar_signed_path logic in display. `dot <= 0`
  // matches Rust's file_stem semantics: a dotfile like ".env" has no
  // extension, so it becomes ".env.signed", not ".signed.env".
  const norm = p.replace(/\\/g, "/");
  const slash = norm.lastIndexOf("/");
  const dir = slash >= 0 ? p.slice(0, slash + 1) : "";
  const name = slash >= 0 ? p.slice(slash + 1) : p;
  const dot = name.lastIndexOf(".");
  if (dot <= 0) return dir + name + ".signed";
  return dir + name.slice(0, dot) + ".signed" + name.slice(dot);
}

$sReplaceOriginal.addEventListener("change", () => {
  if (!signStaged) return;
  signStaged.replaceOriginal = $sReplaceOriginal.checked;
  $sPreviewOutput.textContent = signStaged.replaceOriginal
    ? signStaged.path
    : sidecarPath(signStaged.path);
});
$sEmbedIdentity.addEventListener("change", () => {
  if (!signStaged) return;
  signStaged.embed = $sEmbedIdentity.checked;
});
$sAiArtist.addEventListener("change", () => {
  $sAiModelField.hidden = !$sAiArtist.checked;
  if (signStaged) signStaged.aiArtist = $sAiArtist.checked;
});
$sAiModel.addEventListener("input", () => {
  if (signStaged) signStaged.aiModel = $sAiModel.value.trim();
});

$sCancelBtn.addEventListener("click", () => {
  signStaged = null;
  showReadySubstate("empty");
});

$sGoBtn.addEventListener("click", async () => {
  if (!signStaged) return;
  $sGoError.hidden = true;
  showReadySubstate("signing");

  const out = signStaged.replaceOriginal ? null : sidecarPath(signStaged.path);
  const res = await invoke("kit_sign", {
    args: {
      file: signStaged.path,
      out,
      // Explicit: out=null used to SILENTLY mean "sidecar", so the checked
      // "Replace the original" box wrote a sidecar while the preview claimed
      // in-place. The backend now implements real in-place replacement.
      replaceOriginal: !!signStaged.replaceOriginal,
      embedIdentity: signStaged.embed,
      action: signStaged.action || null,
      aiArtistModel: signStaged.aiArtist ? (signStaged.aiModel || "") : null,
      dataDir: null,
    },
  });

  if (!res.ok) {
    $sGoError.textContent = res.error || "Sign failed.";
    $sGoError.hidden = false;
    showReadySubstate("preview");
    return;
  }

  $sDonePath.textContent = res.data.output_path;
  signStaged = { ...signStaged, lastOutput: res.data.output_path };

  // Show DONE immediately — the About card below is decoration and must not
  // hold the user on the "Signing…" spinner. Skip the watermark detectors
  // outright (runWatermark: false): they added 10+ seconds of silentcipher
  // inference to every sign, for a card that never displays them.
  $sAboutCard.hidden = true;
  showReadySubstate("done");
  const verifyRes = await invoke("verify_file", {
    path: res.data.output_path,
    handle: null,
    did: null,
    requireAttested: false,
    runWatermark: false,
  });
  if (verifyRes.ok && verifyRes.report) {
    renderAboutCard(verifyRes.report, $sAboutCard);
  }
});

$sAnotherBtn.addEventListener("click", () => {
  signStaged = null;
  showReadySubstate("empty");
});

$sVerifyBtn.addEventListener("click", () => {
  // Switch to the Verify tab and queue a verify of the just-signed file.
  if (signStaged && signStaged.lastOutput) {
    const out = signStaged.lastOutput;
    activateTab("verify");
    verifyPath(out);
  }
});

