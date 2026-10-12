# provcheck-cli kjøretidsutdata, norsk bokmål. Kun menneskelesbar utdata; --json-utdata
# og avslutningskoder blir aldri lokalisert. Plassholdere { $name } fylles inn på
# kallestedet; la dem stå uendret i oversettelser. Merke- og tekniske termer
# (provcheck, C2PA, Backfire, Mellin, BUSL, Apache-2.0, JSON, PowerShell, bash, flagg,
# filnavn) forblir uoversatt på hvert språk.

## Mellin nøkkelbasert lydforensisk blokk (print_mellin_human).
mellin-header = Mellin (eksperimentell, nøkkelbasert forensisk lydserienummer):
mellin-serial-full = serienummer:   { $serial } (alle 64 bit gjenopprettet, minste antall bit-stemmer { $votes })
mellin-serial-partial = serienummer:   ikke fullstendig gjenopprettet ({ $bits }/64 bit, minste antall bit-stemmer { $votes })
mellin-erasures = slettinger: { $pct }% av posisjonene
mellin-expected-match = forventet: TREFF
mellin-expected-no-match = forventet: INGEN TREFF

## Backfire nøkkelbasert bildevannmerke-blokk (print_backfire_human).
backfire-header = Backfire (eksperimentell, nøkkelbasert bildevannmerke):
backfire-mark-valid = merke:   GYLDIG (id { $id }, margin { $margin })
backfire-mark-none = merke:   ikke oppdaget (margin { $margin })
backfire-tamper-detected = manipulasjon: BAND-NOTCH OPPDAGET (stat { $stat }) -- bildet er svært sannsynlig notch-angrepet
backfire-tamper-none = manipulasjon: ingen (band-notch-stat { $stat })

## Backfire-oppsett (--install-backfire).
backfire-folder-not-found = provcheck: fant ikke backfire-mappen. Sett BACKFIRE_PY til backfire.py, eller kjør fra en mappe som inneholder backfire/backfire.py.
backfire-ps1-not-found = provcheck: fant ikke setup_backfire.ps1 i { $dir }
backfire-sh-not-found = provcheck: fant ikke setup_backfire.sh i { $dir }
backfire-setup-start = Backfire-lesemiljøet settes opp (engangshandling). Dette laster ned en frittstående Python.
backfire-setup-ready = Backfire er klart. Verifiser et merket bilde med:  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck: Backfire-oppsettet avsluttet med status { $status }
backfire-setup-run-failed = provcheck: kunne ikke kjøre Backfire-oppsettskriptet ({ $err }). Det krever PowerShell på Windows, eller bash på Linux/macOS.

## Modellinstallasjon (--install-models).
install-models-start = Installerer { $count } vannmerke-deteksjonsmodellfil(er) ({ $mb } MB totalt).
install-models-item = { $family }/{ $variant } ({ $mb } MB) ...
install-models-ok = ok
install-models-item-failed = MISLYKTES: { $err }
install-models-done = Alle modeller installert. Vannmerke-deteksjon er klar.
install-models-summary-failed = provcheck: { $count } modell(er) kunne ikke installeres (se ovenfor).

## Hovedløype for verifisering: feil, meldinger og tips.
require-attested-needs-identity = provcheck: --require-attested krever --bsky-handle, --did eller --auto-identity
trust-store-read-failed = provcheck: kunne ikke lese trust store '{ $path }': { $err }
auto-identity-no-assertion = provcheck: --auto-identity ble forespurt, men filen inneholder ingen app.provcheck.identity-assertion. Signer først med `provcheck-kit sign --embed-identity`, eller oppgi --bsky-handle / --did direkte.
backfire-needs-key = provcheck: --backfire-read krever --backfire-key
backfire-experimental-notice = provcheck: Backfire er EKSPERIMENTELL og BUSL-lisensiert (gratis for ikke-kommersiell bruk), atskilt fra Apache-2.0-kjernen. Den verifiserer et nøkkelbasert merke du har bygd inn, og flagger band-notch-manipulasjon; robustheten varierer fra bilde til bilde.
backfire-read-failed = provcheck: backfire-lesing mislyktes: { $err }
mellin-needs-args = provcheck: --mellin-read krever --mellin-secret-file og --mellin-work-id
mellin-experimental-notice = provcheck: Mellin er EKSPERIMENTELL og BUSL-lisensiert (gratis for ikke-kommersiell bruk), atskilt fra Apache-2.0-kjernen. Den leser et nøkkelbasert serienummer per kopi som du har bygd inn; uten din hemmelighet og work-id er det ingenting å lese.
mellin-read-failed = provcheck: mellin-lesing mislyktes: { $err }
json-serialize-failed = provcheck: klarte ikke å serialisere JSON: { $err }
hint-models-missing = [hint] { $count } vannmerke-deteksjonsmodell(er) er ikke installert, så disse linjene viser "not installed". Aktiver full deteksjon med:  provcheck --install-models  (engangshandling, { $mb } MB). C2PA-verifisering trenger dem ikke.
hint-claims-identity = [hint] filen hevder identiteten { $who }. Kjør på nytt med --auto-identity for å verifisere mot deres publiserte signeringsnøkkel-oppføringer.
