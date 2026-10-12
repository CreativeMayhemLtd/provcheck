# Translations

The provcheck desktop GUI is localized into 30 languages. English (`en`) is the source of truth and the
per-key fallback: if any string is missing or wrong in another language, the app shows the English text
rather than a blank, so a partial or imperfect translation never breaks the interface.

The non-English strings were **machine-drafted**. They are a solid starting point, not a professional
localization, and some phrasing will be awkward, unnatural, or simply wrong. If you have hit a translation
that reads badly in your language, we are sorry. We shipped these so the tool would be usable in as many
languages as possible on day one, knowing we could not get every one of them right, and knowing some would
land poorly. That is on us, not on you.

**We do not speak most of these languages, so we depend on you.** If you are a native or fluent speaker and
you fix even a single awkward string, you are doing something we genuinely cannot do ourselves, and we are
grateful for it. A one-word fix is a completely valid pull request, and a welcome one. You are not
nitpicking; you are making the tool clearer and more respectful for everyone who shares your language.

## How the catalogs are built

- Per-language source lives in `locales/src/<lang>.json`, one file per locale, in the shape
  `{ "keyName": { "message": "translated text" }, ... }`. `en.json` is the canonical key set.
- `locales/catalogs.js` (the file the app actually loads) is **generated** from those sources. Do not hand
  edit `catalogs.js`; edit the `src/<lang>.json` file and regenerate:

  ```
  node locales/gen.js
  ```

  The generator fills any missing key from English, and warns if a translation dropped a `$1`/`$2`
  placeholder or left a string empty.

## Fixing or improving a translation

1. Open `locales/src/<lang>.json` (for example `locales/src/fr.json`).
2. Edit the `message` value for the key(s) you want to improve. Leave the key name unchanged.
3. Keep these intact:
   - Substitution tokens `$1` and `$2` (they are filled in at runtime with a filename, count, identifier,
     and so on). Their position may move to suit the target language's word order, but they must stay present.
   - Product and technical names, verbatim: `provcheck`, `C2PA`, `Content Credentials`, `atproto`, `Bsky`,
     `DID`, `Yubikey`, `Backfire`, `Mellin`, `idmark`, `silentcipher`, `AudioSeal`, `WavMark`, `TrustMark`,
     `SynthID`, and the like.
   - House style: no em-dashes (use commas, colons, or parentheses); Oxford commas in English.
4. Run `node locales/gen.js` and confirm it reports no warnings.
5. Open a PR. Please note in the description that you are a fluent or native speaker of the language.

## Adding a new language

1. Copy `locales/src/en.json` to `locales/src/<lang>.json` (use the BCP-47-ish code the app expects, for
   example `pt_BR`, `zh_CN`) and translate the `message` values.
2. Add the code to the `LANGS` array in `locales/gen.js`.
3. If the language is right-to-left, confirm it is covered by the RTL handling in `i18n.js`.
4. Run `node locales/gen.js` and open a PR.

Thank you, sincerely. A translation we got wrong is a small daily friction for everyone who reads it, and
when you fix it you remove that friction for people you will never meet. We could not reach your language
without you, and we are grateful you took the time.
