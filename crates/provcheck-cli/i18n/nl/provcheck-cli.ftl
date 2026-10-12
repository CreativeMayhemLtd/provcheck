# provcheck-cli runtime-uitvoer, Nederlands. Alleen door mensen leesbare uitvoer;
# --json-uitvoer en afsluitcodes worden nooit gelokaliseerd. Plaatshouders { $name }
# worden op de aanroepplek ingevuld; laat ze ongewijzigd in vertalingen. Merk- en
# technische termen (provcheck, C2PA, Backfire, Mellin, BUSL, Apache-2.0, JSON,
# PowerShell, bash, flags, bestandsnamen) blijven in elke taal letterlijk staan.

## Mellin keyed-audio forensisch blok (print_mellin_human).
mellin-header = Mellin (experimenteel, keyed audio forensisch serienummer):
mellin-serial-full = serienummer:   { $serial } (alle 64 bits hersteld, minimum bit-stemmen { $votes })
mellin-serial-partial = serienummer:   niet volledig hersteld ({ $bits }/64 bits, minimum bit-stemmen { $votes })
mellin-erasures = wissingen: { $pct }% van de posities
mellin-expected-match = verwacht: OVEREENKOMST
mellin-expected-no-match = verwacht: GEEN OVEREENKOMST

## Backfire keyed-image watermerkblok (print_backfire_human).
backfire-header = Backfire (experimenteel, keyed image watermerk):
backfire-mark-valid = markering:   GELDIG (id { $id }, marge { $margin })
backfire-mark-none = markering:   niet gedetecteerd (marge { $margin })
backfire-tamper-detected = manipulatie: BAND-NOTCH GEDETECTEERD (stat { $stat }) -- de afbeelding is zeer waarschijnlijk notch-aangevallen
backfire-tamper-none = manipulatie: geen (band-notch stat { $stat })

## Backfire-installatie (--install-backfire).
backfire-folder-not-found = provcheck: kan de backfire-map niet vinden. Stel BACKFIRE_PY in op backfire.py, of voer uit vanuit een map die backfire/backfire.py bevat.
backfire-ps1-not-found = provcheck: setup_backfire.ps1 niet gevonden in { $dir }
backfire-sh-not-found = provcheck: setup_backfire.sh niet gevonden in { $dir }
backfire-setup-start = De Backfire-leesomgeving wordt ingericht (eenmalig). Dit downloadt een zelfstandige Python.
backfire-setup-ready = Backfire is gereed. Controleer een gemarkeerde afbeelding met:  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck: Backfire-installatie eindigde met status { $status }
backfire-setup-run-failed = provcheck: kon het Backfire-installatiescript niet uitvoeren ({ $err }). Hiervoor is PowerShell op Windows nodig, of bash op Linux/macOS.

## Modelinstallatie (--install-models).
install-models-start = { $count } watermerk-detectiemodelbestand(en) worden geïnstalleerd ({ $mb } MB totaal).
install-models-item = { $family }/{ $variant } ({ $mb } MB) ...
install-models-ok = ok
install-models-item-failed = MISLUKT: { $err }
install-models-done = Alle modellen geïnstalleerd. Watermerkdetectie is gereed.
install-models-summary-failed = provcheck: het installeren van { $count } model(len) is mislukt (zie hierboven).

## Hoofdpad voor verificatie: fouten, meldingen en tips.
require-attested-needs-identity = provcheck: --require-attested vereist --bsky-handle, --did of --auto-identity
trust-store-read-failed = provcheck: kan trust store '{ $path }' niet lezen: { $err }
auto-identity-no-assertion = provcheck: --auto-identity werd aangevraagd, maar het bestand bevat geen app.provcheck.identity-assertion. Onderteken eerst met `provcheck-kit sign --embed-identity`, of geef --bsky-handle / --did rechtstreeks op.
backfire-needs-key = provcheck: --backfire-read vereist --backfire-key
backfire-experimental-notice = provcheck: Backfire is EXPERIMENTEEL en BUSL-gelicentieerd (gratis voor niet-commercieel gebruik), los van de Apache-2.0-kern. Het verifieert een keyed markering die je hebt ingebed en signaleert band-notch manipulatie; de robuustheid verschilt per afbeelding.
backfire-read-failed = provcheck: backfire-lezen mislukt: { $err }
mellin-needs-args = provcheck: --mellin-read vereist --mellin-secret-file en --mellin-work-id
mellin-experimental-notice = provcheck: Mellin is EXPERIMENTEEL en BUSL-gelicentieerd (gratis voor niet-commercieel gebruik), los van de Apache-2.0-kern. Het leest een keyed serienummer per kopie dat je hebt ingebed; zonder jouw geheim en work-id is er niets om te lezen.
mellin-read-failed = provcheck: mellin-lezen mislukt: { $err }
json-serialize-failed = provcheck: JSON serialiseren mislukt: { $err }
hint-models-missing = [hint] { $count } watermerk-detectiemodel(len) zijn niet geïnstalleerd, dus deze regels tonen "not installed". Schakel volledige detectie in met:  provcheck --install-models  (eenmalig, { $mb } MB). C2PA-verificatie heeft ze niet nodig.
hint-claims-identity = [hint] bestand claimt identiteit { $who }. Voer opnieuw uit met --auto-identity om te verifiëren aan de hand van hun gepubliceerde ondertekeningssleutel-records.
