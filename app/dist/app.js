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
const $idAutofillHint = document.getElementById("identity-autofill-hint");
const $chooseBtn      = document.getElementById("choose-btn");
const $verifyAgain    = document.getElementById("verify-another");
const $copyJson       = document.getElementById("copy-json");
const $sampleRaidio     = document.getElementById("sample-raidio");
const $sampleDoomscroll = document.getElementById("sample-doomscroll");
const $footerHint     = document.getElementById("footer-hint");
const $footerActions  = document.getElementById("footer-actions");

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
  for (const wm of list) {
    $watermarks.appendChild(buildWatermarkBadge(wm));
  }
}

function buildWatermarkBadge(wm) {
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
  badge.appendChild(text);

  return badge;
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
    if (!raw) return { handle: "", requireAttested: false };
    const parsed = JSON.parse(raw);
    return {
      handle: typeof parsed.handle === "string" ? parsed.handle : "",
      requireAttested: !!parsed.requireAttested,
    };
  } catch {
    return { handle: "", requireAttested: false };
  }
}

function saveIdentity() {
  const payload = {
    handle: ($idHandle && $idHandle.value || "").trim(),
    requireAttested: !!($idRequire && $idRequire.checked),
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
TAURI.event.listen("tauri://drag-drop", (event) => {
  const p = event.payload;
  $dropzone.classList.remove("drag-over");
  if (p && Array.isArray(p.paths) && p.paths.length > 0) {
    verifyPath(p.paths[0]);
  }
});
TAURI.event.listen("tauri://drag-enter", () => $dropzone.classList.add("drag-over"));
TAURI.event.listen("tauri://drag-over", () => $dropzone.classList.add("drag-over"));
TAURI.event.listen("tauri://drag-leave", () => $dropzone.classList.remove("drag-over"));

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
hydrateIdentityInputs();

// Initial state.
showEmpty();
