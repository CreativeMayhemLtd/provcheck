// provcheck GUI internationalization: static and offline. Reads bundled catalogs (window.I18N, one entry
// per locale in the extension messages.json shape), picks the user's locale (an explicit override, then a
// stored preference, else English), fills [data-i18n] / [data-i18n-ph] / [data-i18n-title] markup, and
// exposes t(key, fallback, subs) for dynamic strings. English is the per-key fallback, so a missing
// translation never blanks. No network, no dependency.
//
// The locale is NEVER auto-detected from the OS/browser: navigator.language in a WebView reflects the
// Windows *regional format*, not the chosen UI language, so a machine set to English-UI in a German region
// reported "de-DE" and the GUI silently opened in German. English is the deterministic default; the user
// switches deliberately via the lang picker, and that choice persists in localStorage.
(function () {
  "use strict";
  var CAT = window.I18N || {};
  function pickLocale() {
    var langs = [];
    try { if (window.__I18N_LOCALE__) langs.push(window.__I18N_LOCALE__); } catch (e) {}
    try { var s = localStorage.getItem("provcheckLang"); if (s) langs.push(s); } catch (e) {}
    for (var i = 0; i < langs.length; i++) {
      var l = String(langs[i]).replace("-", "_");
      if (CAT[l]) return l;                 // exact, e.g. pt_BR / zh_CN
      var base = l.split("_")[0];
      if (CAT[base]) return base;           // base, e.g. de
    }
    return "en";                            // deterministic default; no OS/navigator auto-detection
  }
  var LOC = pickLocale();
  function entry(key) { return (CAT[LOC] && CAT[LOC][key]) || (CAT.en && CAT.en[key]) || null; }
  function subst(msg, e, subs) {
    if (subs == null) return msg;
    var arr = Array.isArray(subs) ? subs : [subs];
    if (e && e.placeholders) {
      for (var name in e.placeholders) {
        var idx = parseInt(String(e.placeholders[name].content).replace("$", ""), 10) - 1;
        msg = msg.replace(new RegExp("\\$" + name + "\\$", "gi"), arr[idx] != null ? arr[idx] : "");
      }
    } else {
      for (var i = 0; i < arr.length; i++) msg = msg.replace(new RegExp("\\$" + (i + 1), "g"), arr[i]);
    }
    return msg;
  }
  function t(key, fallback, subs) {
    var e = entry(key);
    var msg = e ? e.message : (fallback != null ? fallback : "");
    return subst(msg, e, subs);
  }
  function fill(root, attr, apply) {
    var els = (root || document).querySelectorAll("[" + attr + "]");
    for (var i = 0; i < els.length; i++) {
      var m = t(els[i].getAttribute(attr));
      if (m) apply(els[i], m);
    }
  }
  function localize(root) {
    fill(root, "data-i18n", function (el, m) { el.textContent = m; });
    fill(root, "data-i18n-ph", function (el, m) { el.setAttribute("placeholder", m); });
    fill(root, "data-i18n-title", function (el, m) { el.setAttribute("title", m); });
    fill(root, "data-i18n-aria", function (el, m) { el.setAttribute("aria-label", m); });
    try {
      document.documentElement.lang = LOC.replace("_", "-");
      if (["ar", "he", "fa", "ur"].indexOf(LOC) >= 0) document.documentElement.dir = "rtl";
    } catch (e) {}
    setupPicker();
  }
  // Native language names for the switcher. A locale present in the catalog but not
  // listed here still shows, labelled by its code.
  var NATIVE = {
    en: "English", es: "Español", fr: "Français", de: "Deutsch", it: "Italiano",
    pt_BR: "Português (Brasil)", nl: "Nederlands", pl: "Polski", ru: "Русский",
    uk: "Українська", tr: "Türkçe", cs: "Čeština", ro: "Română", hu: "Magyar",
    el: "Ελληνικά", sv: "Svenska", da: "Dansk", fi: "Suomi", no: "Norsk",
    ar: "العربية", he: "עברית", fa: "فارسی", hi: "हिन्दी", th: "ไทย",
    vi: "Tiếng Việt", id: "Bahasa Indonesia", ja: "日本語", ko: "한국어",
    zh_CN: "简体中文", zh_TW: "繁體中文"
  };
  // Populate and wire a <select id="lang-select"> if the page has one: choosing a
  // language stores the preference and reloads so every string re-renders. Idempotent.
  function setupPicker() {
    var sel = document.getElementById("lang-select");
    if (!sel || sel.getAttribute("data-ready")) return;
    sel.setAttribute("data-ready", "1");
    var order = Object.keys(NATIVE).filter(function (c) { return CAT[c]; });
    Object.keys(CAT).forEach(function (c) { if (order.indexOf(c) < 0) order.push(c); });
    for (var i = 0; i < order.length; i++) {
      var o = document.createElement("option");
      o.value = order[i];
      o.textContent = NATIVE[order[i]] || order[i];
      if (order[i] === LOC) o.selected = true;
      sel.appendChild(o);
    }
    sel.addEventListener("change", function () {
      try { localStorage.setItem("provcheckLang", sel.value); } catch (e) {}
      location.reload();
    });
  }
  window.provcheckI18n = { t: t, localize: localize, locale: LOC };
  window.t = t; // convenience for app.js dynamic strings
  // These scripts load at the end of <body>, so the markup above is already parsed: localize now, and
  // again on DOMContentLoaded as an idempotent safety net for anything not yet in the DOM.
  try { localize(); } catch (e) {}
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", function () { localize(); });
})();
