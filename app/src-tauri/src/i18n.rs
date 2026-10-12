//! GUI-output localization, built on fluent-rs via i18n-embed (same pattern as
//! provcheck-cli's brick C0).
//!
//! Fluent catalogs are embedded from `i18n/<lang>/provcheck_app.ftl` (the fl! macro
//! derives the domain from the package name, sanitizing `-` to `_`). English is the
//! fallback and source of truth: any message missing in the selected locale falls back
//! to English, so a partial translation never blanks a line. `init()` selects the user's
//! OS/desktop locale once at startup. Only complete user-facing sentences returned to the
//! GUI (ApiResult ok/err text) are localized; technical `{err}`/log-path diagnostics and
//! IPC error labels stay English, and the JSON envelope shape is unaffected.
use i18n_embed::{
    DesktopLanguageRequester, LanguageLoader,
    fluent::{FluentLanguageLoader, fluent_language_loader},
};
use once_cell::sync::Lazy;
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "i18n/"]
struct Localizations;

/// Process-wide fluent loader. The English fallback is loaded eagerly so the loader is
/// always usable; `init()` layers the requested locale on top.
pub static LOADER: Lazy<FluentLanguageLoader> = Lazy::new(|| {
    let loader = fluent_language_loader!();
    loader
        .load_fallback_language(&Localizations)
        .expect("embedded en fallback catalog must load");
    loader
});

/// Select the OS/desktop locale for GUI output. Call once, early in `main`. Never fails
/// hard: if the locale cannot be selected, output stays in the English fallback.
pub fn init() {
    let requested = DesktopLanguageRequester::requested_languages();
    let _ = i18n_embed::select(&*LOADER, &Localizations, &requested);
}
