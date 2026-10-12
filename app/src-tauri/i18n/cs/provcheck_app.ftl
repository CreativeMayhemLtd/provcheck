# provcheck-app, GUI zprávy, čeština. Lokalizovány jsou pouze úplné věty pro uživatele
# vrácené do GUI jako text ApiResult ok/err; technické diagnostiky { $err }/cesty k logu
# a štítky chyb IPC zůstávají anglicky. Značky a technické výrazy (provcheck, provcheck-kit,
# Backfire, Mellin, C2PA, atproto, LOCALAPPDATA, BACKFIRE_PY, Yubikey, PIV PIN, DID, přepínače,
# názvy souborů) zůstávají doslovné v každém jazyce.

## Karta klíčovaného obrazového znaku Backfire (backfire_read + install_backfire).
backfire-read-needs-key = Pro čtení značky Backfire je vyžadován klíč.
backfire-folder-unresolved = Nepodařilo se najít zapisovatelnou složku Backfire (LOCALAPPDATA není nastaveno).
backfire-ready-bundled = Backfire je připraven (přiložená čtečka je přítomna). Zadejte klíč a přetáhněte obrázek.
backfire-files-missing = Soubory Backfire k instalaci nebyly nalezeny. Přeinstalujte provcheck, nebo nastavte BACKFIRE_PY.
backfire-ready = Backfire je připraven. Zadejte klíč a přetáhněte obrázek.

## Karta klíčovaných značek Mellin (mellin_read).
mellin-needs-secret-and-work-id = Pro čtení sériového čísla Mellin jsou vyžadovány soubor s tajným klíčem a ID zakázky.
mellin-secret-file-missing = Vybraný soubor s tajným klíčem neexistuje (nebo není čitelný).

## Karty Podepsat a Klíče: upozornění GUI na omezení funkcí vrácená jako chyby ApiResult.
identity-already-exists = v tomto datovém adresáři již existuje identita; předejte force=true k jejímu novému vygenerování (tím osiří všechny dříve zveřejněné záznamy atproto)
rotate-yubikey-unsupported = Rotace identity založené na Yubikey v GUI zatím není podporována. Spusťte `provcheck-kit init --yubikey --force` v terminálu a poté se sem vraťte pro zveřejnění a zneplatnění.
rotate-agefile-unsupported = Rotace identit založených na age-souboru v GUI zatím není zapojena. Použijte `provcheck-kit rotate` v terminálu.
sign-keychain-only = Podepisování v GUI aktuálně podporuje pouze identity z klíčenky OS. Pro identity založené na age-souboru použijte `provcheck-kit sign` z příkazové řádky.
sign-yubikey-unsupported = Podepisování identit založených na Yubikey v GUI přichází ve v0.5.0 P3 + P4. Prozatím podepisujte pomocí `provcheck-kit sign` z terminálu — kit si při každém podpisu vyžádá PIV PIN.
