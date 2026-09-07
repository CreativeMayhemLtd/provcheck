// provcheck popup: load/save the filter rules to chrome.storage.local. The content script reacts to
// storage changes, so edits apply live to the open tab.
"use strict";

const FIELDS = {
  enabled: "checkbox",
  c2paPresent: "checkbox",
  c2paAbsent: "checkbox",
  aiPresent: "checkbox",
  keyword: "text",
  action: "select",
  badge: "checkbox",
};
const DEFAULTS = { enabled: false, c2paPresent: false, c2paAbsent: false, aiPresent: false, keyword: "", action: "blur", badge: false };

function readForm() {
  const r = {};
  for (const [id, kind] of Object.entries(FIELDS)) {
    const el = document.getElementById(id);
    r[id] = kind === "checkbox" ? el.checked : el.value;
  }
  return r;
}

function writeForm(r) {
  const v = Object.assign({}, DEFAULTS, r || {});
  for (const [id, kind] of Object.entries(FIELDS)) {
    const el = document.getElementById(id);
    if (kind === "checkbox") el.checked = !!v[id];
    else el.value = v[id];
  }
}

function save() {
  chrome.storage.local.set({ provcheckRules: readForm() });
}

document.addEventListener("DOMContentLoaded", () => {
  chrome.storage.local.get(["provcheckRules"], (r) => writeForm(r && r.provcheckRules));
  for (const id of Object.keys(FIELDS)) {
    const el = document.getElementById(id);
    el.addEventListener("change", save);
    if (FIELDS[id] === "text") el.addEventListener("input", save);
  }
});
