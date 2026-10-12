//! Runtime-output localization (brick C0), built on fluent-rs via i18n-embed.
//!
//! Fluent catalogs are embedded from `i18n/<lang>/provcheck-cli.ftl`. English is the
//! fallback and source of truth: any message or argument missing in the selected locale
//! falls back to English, so a partial translation never blanks a line. `init()` selects
//! the user's OS/desktop locale once at startup. Only human-readable output is localized;
//! `--json` output and exit codes are unaffected, and clap `--help` stays English for now.
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

/// Select the OS/desktop locale for output. Call once, early in `main`. Never fails hard:
/// if the locale cannot be selected, output stays in the English fallback.
pub fn init() {
    let requested = DesktopLanguageRequester::requested_languages();
    let _ = i18n_embed::select(&*LOADER, &Localizations, &requested);
}

#[cfg(test)]
mod tests {
    use super::*;
    use i18n_embed_fl::fl;

    #[test]
    fn en_fallback_loads_and_reads() {
        // LOADER eagerly loads en; a known key resolves to its English text.
        assert_eq!(fl!(LOADER, "mellin-expected-match"), "expected: MATCH");
    }

    #[test]
    fn de_selection_localizes() {
        // Select German and confirm the fluent selection path (not just the fallback) works end to end.
        let de: unic_langid::LanguageIdentifier = "de".parse().expect("valid langid");
        let loader = fluent_language_loader!();
        loader
            .load_languages(&Localizations, &[de])
            .expect("de catalog must load");
        assert_eq!(fl!(loader, "mellin-expected-match"), "erwartet: TREFFER");
        // A message with an argument keeps the placeholder substitution.
        let s = fl!(loader, "mellin-erasures", pct = "12.5");
        assert!(s.contains("12.5"), "arg substituted: {s}");
    }
}
