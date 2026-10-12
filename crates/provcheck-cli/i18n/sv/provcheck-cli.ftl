# provcheck-cli körtidsutdata, svenska. Endast mänskligt läsbar utdata; --json-utdata
# och avslutningskoder lokaliseras aldrig. Platshållare { $name } fylls i vid
# anropsstället; lämna dem oförändrade i översättningar. Varumärkes- och tekniska
# termer (provcheck, C2PA, Backfire, Mellin, BUSL, Apache-2.0, JSON, PowerShell,
# bash, flaggor, filnamn) står kvar oöversatta på varje språk.

## Mellin-block för nyckelbaserad ljudforensik (print_mellin_human).
mellin-header = Mellin (experimentell, nyckelbaserat forensiskt ljudserienummer):
mellin-serial-full = serienummer:   { $serial } (alla 64 bitar återställda, minsta antal bitröster { $votes })
mellin-serial-partial = serienummer:   inte helt återställt ({ $bits }/64 bitar, minsta antal bitröster { $votes })
mellin-erasures = raderingar: { $pct }% av positionerna
mellin-expected-match = förväntat: TRÄFF
mellin-expected-no-match = förväntat: INGEN TRÄFF

## Backfire-block för nyckelbaserat bildvattenmärke (print_backfire_human).
backfire-header = Backfire (experimentell, nyckelbaserat bildvattenmärke):
backfire-mark-valid = markering:   GILTIG (id { $id }, marginal { $margin })
backfire-mark-none = markering:   inte upptäckt (marginal { $margin })
backfire-tamper-detected = manipulation: BAND-NOTCH UPPTÄCKT (stat { $stat }) -- bilden har med stor sannolikhet notch-attackerats
backfire-tamper-none = manipulation: ingen (band-notch-stat { $stat })

## Backfire-installation (--install-backfire).
backfire-folder-not-found = provcheck: kunde inte hitta backfire-mappen. Ange BACKFIRE_PY till backfire.py, eller kör från en mapp som innehåller backfire/backfire.py.
backfire-ps1-not-found = provcheck: setup_backfire.ps1 hittades inte i { $dir }
backfire-sh-not-found = provcheck: setup_backfire.sh hittades inte i { $dir }
backfire-setup-start = Backfire-läsmiljön ställs in (engångsåtgärd). Detta laddar ner en fristående Python.
backfire-setup-ready = Backfire är klart. Verifiera en markerad bild med:  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck: Backfire-installationen avslutades med status { $status }
backfire-setup-run-failed = provcheck: kunde inte köra Backfire-installationsskriptet ({ $err }). Det kräver PowerShell på Windows, eller bash på Linux/macOS.

## Modellinstallation (--install-models).
install-models-start = Installerar { $count } vattenmärkesdetekteringsmodellfil(er) ({ $mb } MB totalt).
install-models-item = { $family }/{ $variant } ({ $mb } MB) ...
install-models-ok = ok
install-models-item-failed = MISSLYCKADES: { $err }
install-models-done = Alla modeller installerade. Vattenmärkesdetektering är klar.
install-models-summary-failed = provcheck: { $count } modell(er) kunde inte installeras (se ovan).

## Huvudsökväg för verifiering: fel, meddelanden och tips.
require-attested-needs-identity = provcheck: --require-attested kräver --bsky-handle, --did eller --auto-identity
trust-store-read-failed = provcheck: kunde inte läsa trust store '{ $path }': { $err }
auto-identity-no-assertion = provcheck: --auto-identity begärdes, men filen saknar en app.provcheck.identity-assertion. Signera först med `provcheck-kit sign --embed-identity`, eller ange --bsky-handle / --did direkt.
backfire-needs-key = provcheck: --backfire-read kräver --backfire-key
backfire-experimental-notice = provcheck: Backfire är EXPERIMENTELL och BUSL-licensierad (gratis för icke-kommersiellt bruk), separat från Apache-2.0-kärnan. Den verifierar en nyckelbaserad markering du har bäddat in och flaggar band-notch-manipulation; robustheten varierar per bild.
backfire-read-failed = provcheck: backfire-läsning misslyckades: { $err }
mellin-needs-args = provcheck: --mellin-read kräver --mellin-secret-file och --mellin-work-id
mellin-experimental-notice = provcheck: Mellin är EXPERIMENTELL och BUSL-licensierad (gratis för icke-kommersiellt bruk), separat från Apache-2.0-kärnan. Den läser ett nyckelbaserat serienummer per kopia som du har bäddat in; utan din hemlighet och work-id finns inget att läsa.
mellin-read-failed = provcheck: mellin-läsning misslyckades: { $err }
json-serialize-failed = provcheck: misslyckades med att serialisera JSON: { $err }
hint-models-missing = [hint] { $count } vattenmärkesdetekteringsmodell(er) är inte installerade, så dessa rader visar "not installed". Aktivera all detektering med:  provcheck --install-models  (engångsåtgärd, { $mb } MB). C2PA-verifiering behöver dem inte.
hint-claims-identity = [hint] filen gör anspråk på identiteten { $who }. Kör igen med --auto-identity för att verifiera mot deras publicerade signeringsnyckelposter.
