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

let lastReport = null;
let lastFilePath = null;

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

function renderWatermarks(list) {
  // One badge per detector that ran. Four per-badge states:
  //   detected   → green check, brand name + confidence %
  //   degraded   → amber check, brand name + "(degraded)" + %
  //   undetected → red x, "no mark detected"
  //   skipped    → dim dash, e.g. "not audio" or "model error"
  $watermarks.innerHTML = "";
  if (!Array.isArray(list) || list.length === 0) {
    $watermarks.hidden = true;
    return;
  }
  $watermarks.hidden = false;
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
    $watermarks.appendChild(buildWatermarkBadge(wm, extent));
  }
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
    sub = pct + "% confidence — mark is degraded (partial corruption likely)";
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
    case "doomscroll": return "doomscroll.fm";
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
  try {
    const resp = await invoke("verify_file", args);
    if (!resp.ok) {
      showResult(errorReport(resp.error || "Could not read file."), path);
      return;
    }
    showResult(resp.report, path);
  } catch (e) {
    showResult(errorReport("Internal error: " + (e && e.toString ? e.toString() : "unknown")), path);
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
    handle: ($idHandle && $idHandle.value || "").trim(),
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

// ---- File picker (hidden input, no plugin dep) ---------------------------

function openFilePicker() {
  // The webview sandbox hides full paths from File objects, so an
  // <input type=file> alone can't give us an absolute path to hand
  // to the Rust side. Fall back to inviting the user to drag:
  showReminderToDrag();
}

function showReminderToDrag() {
  // Briefly swap the dropzone copy to nudge toward drag-drop.
  const inner = $dropzone.querySelector(".dropzone-inner h2");
  if (!inner) return;
  const original = inner.textContent;
  inner.textContent = "Drag the file onto the window";
  $dropzone.classList.add("drag-over");
  setTimeout(() => {
    inner.textContent = original;
    $dropzone.classList.remove("drag-over");
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
  const $signDz = document.getElementById("sign-dropzone");
  if ($signDz) $signDz.classList.remove("drag-over");
  if (!p || !Array.isArray(p.paths) || p.paths.length === 0) return;
  if (activeTab() === "sign") {
    if (typeof window.signOnDrop === "function") window.signOnDrop(p.paths[0]);
  } else {
    verifyPath(p.paths[0]);
  }
});
TAURI.event.listen("tauri://drag-enter", () => {
  $dropzone.classList.add("drag-over");
  const $signDz = document.getElementById("sign-dropzone");
  if ($signDz) $signDz.classList.add("drag-over");
});
TAURI.event.listen("tauri://drag-over", () => {
  $dropzone.classList.add("drag-over");
  const $signDz = document.getElementById("sign-dropzone");
  if ($signDz) $signDz.classList.add("drag-over");
});
TAURI.event.listen("tauri://drag-leave", () => {
  $dropzone.classList.remove("drag-over");
  const $signDz = document.getElementById("sign-dropzone");
  if ($signDz) $signDz.classList.remove("drag-over");
});

function activeTab() {
  return document.getElementById("tab-sign").classList.contains("is-active")
    ? "sign"
    : "verify";
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
        " sample isn't installed alongside this build yet. Grab " +
        fileName +
        " from provcheck.ai (examples/ folder in the source tree) and drag it into the window.",
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
$sampleDoomscroll.addEventListener("click", () => explainSample("Doomscroll.fm", "doomscroll.fm-sample.mp4"));
$sampleRaidio.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") explainSample("rAIdio.bot", "rAIdio.bot-sample.mp3");
});
$sampleDoomscroll.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") explainSample("Doomscroll.fm", "doomscroll.fm-sample.mp4");
});

// Identity inputs — hydrate from localStorage, persist on every change.
if ($idHandle) {
  $idHandle.addEventListener("input", () => {
    // User typing clears the "auto-filled from file" annotation —
    // the value is now their own.
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
      value: handle + " (unverified — re-run with --auto-identity to attest)",
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
const $tabSignBtn = document.getElementById("tab-sign-btn");
const $paneVerify = document.getElementById("tab-verify");
const $paneSign = document.getElementById("tab-sign");

const $signStripId = document.getElementById("sign-strip-id");
const $signStripSession = document.getElementById("sign-strip-session");
const $signLogoutBtn = document.getElementById("sign-logout-btn");

const $sLoading = document.getElementById("sign-loading");
const $sLoadingMsg = document.getElementById("sign-loading-msg");
const $sSetup = document.getElementById("sign-state-setup");
const $sConnect = document.getElementById("sign-state-connect");
const $sPublish = document.getElementById("sign-state-publish");
const $sStale = document.getElementById("sign-state-stale");
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
let signSkipPublish = false;    // user clicked "skip and sign locally"

// ---- Tab switching ---------------------------------------------------------

function activateTab(name) {
  const isSign = name === "sign";
  $tabVerifyBtn.classList.toggle("is-active", !isSign);
  $tabSignBtn.classList.toggle("is-active", isSign);
  $tabVerifyBtn.setAttribute("aria-selected", String(!isSign));
  $tabSignBtn.setAttribute("aria-selected", String(isSign));
  $paneVerify.classList.toggle("is-active", !isSign);
  $paneSign.classList.toggle("is-active", isSign);
  $paneVerify.hidden = isSign;
  $paneSign.hidden = !isSign;
  if (isSign) refreshSignTab();
}

$tabVerifyBtn.addEventListener("click", () => activateTab("verify"));
$tabSignBtn.addEventListener("click", () => activateTab("sign"));

// ---- State dispatch --------------------------------------------------------

function showSignState(name) {
  for (const el of [$sLoading, $sSetup, $sConnect, $sPublish, $sStale, $sReady]) {
    el.hidden = true;
  }
  if (name === "loading") $sLoading.hidden = false;
  else if (name === "setup") $sSetup.hidden = false;
  else if (name === "connect") $sConnect.hidden = false;
  else if (name === "publish") $sPublish.hidden = false;
  else if (name === "stale") $sStale.hidden = false;
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

async function refreshSignTab() {
  showSignState("loading");
  $sLoadingMsg.textContent = "Loading…";
  const res = await invoke("kit_status", { dataDir: null });
  if (!res.ok) {
    signStatus = null;
    paintStrip(null, null);
    // Show setup as a graceful default; the real error is reported on
    // any subsequent action.
    showSignState("setup");
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
    lines.push("# active atproto record uses a key we don't hold locally —");
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

$sInitBtn.addEventListener("click", async () => {
  $sInitBtn.disabled = true;
  $sInitBtn.textContent = "Generating…";
  const res = await invoke("kit_init", { dataDir: null, force: false });
  $sInitBtn.disabled = false;
  $sInitBtn.textContent = "Generate signing key";
  if (!res.ok) {
    alert("Failed to generate identity:\n" + (res.error || "unknown error"));
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
    const res = await invoke("kit_recall_password", { handle: cleaned });
    if (res.ok && typeof res.value === "string" && res.value.length > 0) {
      $sLoginPassword.value = res.value;
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
  if (!confirm("Disconnect this device's atproto session?")) return;
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
    alert("Set up an identity first before signing.");
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
  // Mirror the Rust-side sidecar_signed_path logic in display.
  const norm = p.replace(/\\/g, "/");
  const slash = norm.lastIndexOf("/");
  const dir = slash >= 0 ? p.slice(0, slash + 1) : "";
  const name = slash >= 0 ? p.slice(slash + 1) : p;
  const dot = name.lastIndexOf(".");
  if (dot < 0) return dir + name + ".signed";
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

  // Verify the just-signed file in-process so we can render the
  // same "About this file" card the audience will see. Pure read,
  // no network (the local cert chain is self-signed; no attestation
  // unless the user asks).
  const verifyRes = await invoke("verify_file", {
    path: res.data.output_path,
    handle: null,
    did: null,
    requireAttested: false,
  });
  if (verifyRes.ok && verifyRes.report) {
    renderAboutCard(verifyRes.report, $sAboutCard);
  } else {
    $sAboutCard.hidden = true;
  }

  showReadySubstate("done");
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

