# provcheck-cli's outputdata under kørsel, dansk. Kun menneskeligt læsbart output;
# --json-output og afslutningskoder lokaliseres aldrig. Pladsholdere { $name } udfyldes
# ved kaldestedet; lad dem stå uændret i oversættelser. Mærke- og tekniske termer
# (provcheck, C2PA, Backfire, Mellin, BUSL, Apache-2.0, JSON, PowerShell, bash, flags,
# filnavne) forbliver uoversatte på ethvert sprog.

## Mellin nøglebaseret lydforensisk blok (print_mellin_human).
mellin-header = Mellin (eksperimentel, nøglebaseret forensisk lydserienummer):
mellin-serial-full = serienummer:   { $serial } (alle 64 bit gendannet, mindste antal bit-stemmer { $votes })
mellin-serial-partial = serienummer:   ikke fuldt gendannet ({ $bits }/64 bit, mindste antal bit-stemmer { $votes })
mellin-erasures = sletninger: { $pct }% af positionerne
mellin-expected-match = forventet: MATCH
mellin-expected-no-match = forventet: INGEN MATCH

## Backfire nøglebaseret billedvandmærke-blok (print_backfire_human).
backfire-header = Backfire (eksperimentel, nøglebaseret billedvandmærke):
backfire-mark-valid = mærke:   GYLDIGT (id { $id }, margin { $margin })
backfire-mark-none = mærke:   ikke registreret (margin { $margin })
backfire-tamper-detected = manipulation: BAND-NOTCH REGISTRERET (stat { $stat }) -- billedet er højst sandsynligt notch-angrebet
backfire-tamper-none = manipulation: ingen (band-notch-stat { $stat })

## Backfire-opsætning (--install-backfire).
backfire-folder-not-found = provcheck: kunne ikke finde backfire-mappen. Sæt BACKFIRE_PY til backfire.py, eller kør fra en mappe, der indeholder backfire/backfire.py.
backfire-ps1-not-found = provcheck: setup_backfire.ps1 blev ikke fundet i { $dir }
backfire-sh-not-found = provcheck: setup_backfire.sh blev ikke fundet i { $dir }
backfire-setup-start = Backfire-læsemiljøet sættes op (engangshandling). Dette downloader en selvstændig Python.
backfire-setup-ready = Backfire er klar. Verificer et mærket billede med:  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck: Backfire-opsætningen afsluttede med status { $status }
backfire-setup-run-failed = provcheck: kunne ikke køre Backfire-opsætningsscriptet ({ $err }). Det kræver PowerShell på Windows eller bash på Linux/macOS.

## Modelinstallation (--install-models).
install-models-start = Installerer { $count } vandmærke-detektionsmodelfil(er) ({ $mb } MB i alt).
install-models-item = { $family }/{ $variant } ({ $mb } MB) ...
install-models-ok = ok
install-models-item-failed = MISLYKKEDES: { $err }
install-models-done = Alle modeller installeret. Vandmærke-detektion er klar.
install-models-summary-failed = provcheck: { $count } model(ler) kunne ikke installeres (se ovenfor).

## Hovedsti for verificering: fejl, meddelelser og tips.
require-attested-needs-identity = provcheck: --require-attested kræver --bsky-handle, --did eller --auto-identity
trust-store-read-failed = provcheck: kunne ikke læse trust store '{ $path }': { $err }
auto-identity-no-assertion = provcheck: --auto-identity blev anmodet, men filen indeholder ingen app.provcheck.identity-assertion. Signer først med `provcheck-kit sign --embed-identity`, eller angiv --bsky-handle / --did direkte.
backfire-needs-key = provcheck: --backfire-read kræver --backfire-key
backfire-experimental-notice = provcheck: Backfire er EKSPERIMENTEL og BUSL-licenseret (gratis til ikke-kommerciel brug), adskilt fra Apache-2.0-kernen. Den verificerer et nøglebaseret mærke, du har indlejret, og markerer band-notch-manipulation; robustheden varierer fra billede til billede.
backfire-read-failed = provcheck: backfire-læsning mislykkedes: { $err }
mellin-needs-args = provcheck: --mellin-read kræver --mellin-secret-file og --mellin-work-id
mellin-experimental-notice = provcheck: Mellin er EKSPERIMENTEL og BUSL-licenseret (gratis til ikke-kommerciel brug), adskilt fra Apache-2.0-kernen. Den læser et nøglebaseret serienummer pr. kopi, som du har indlejret; uden din hemmelighed og work-id er der intet at læse.
mellin-read-failed = provcheck: mellin-læsning mislykkedes: { $err }
json-serialize-failed = provcheck: kunne ikke serialisere JSON: { $err }
hint-models-missing = [hint] { $count } vandmærke-detektionsmodel(ler) er ikke installeret, så disse linjer viser "not installed". Aktiver fuld detektion med:  provcheck --install-models  (engangshandling, { $mb } MB). C2PA-verificering har ikke brug for dem.
hint-claims-identity = [hint] filen hævder identiteten { $who }. Kør igen med --auto-identity for at verificere mod deres offentliggjorte signeringsnøgle-registre.
