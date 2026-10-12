# provcheck-cli futásidejű kimenet, magyar. Csak ember által olvasható kimenet; a --json
# kimenet és a kilépési kódok soha nincsenek lokalizálva. A { $name } helyőrzőket a hívási
# helyen töltik ki; a fordításokban hagyd őket változatlanul. A márka- és technikai
# kifejezések (provcheck, C2PA, Backfire, Mellin, BUSL, Apache-2.0, JSON, PowerShell, bash,
# flagek, fájlnevek) minden nyelvben szó szerint maradnak.

## Mellin blokk (kulcsolt hangalapú kriminalisztikai sorszám) (print_mellin_human).
mellin-header = Mellin (kísérleti, kulcsolt hangalapú kriminalisztikai sorszám):
mellin-serial-full = sorszám:   { $serial } (mind a 64 bit visszaállítva, minimum bitszavazat { $votes })
mellin-serial-partial = sorszám:   nincs teljesen visszaállítva ({ $bits }/64 bit, minimum bitszavazat { $votes })
mellin-erasures = törlések: a pozíciók { $pct }%-a
mellin-expected-match = várt: EGYEZÉS
mellin-expected-no-match = várt: NINCS EGYEZÉS

## Backfire blokk (kulcsolt képi vízjel) (print_backfire_human).
backfire-header = Backfire (kísérleti, kulcsolt képi vízjel):
backfire-mark-valid = jelölés:   ÉRVÉNYES (id { $id }, tartalék { $margin })
backfire-mark-none = jelölés:   nem észlelhető (tartalék { $margin })
backfire-tamper-detected = manipuláció: SÁVKIVÁGÁS ÉSZLELVE (mutató { $stat }) -- a képet nagy valószínűséggel notch-támadás érte
backfire-tamper-none = manipuláció: nincs (sávkivágás-mutató { $stat })

## Backfire beállítás (--install-backfire).
backfire-folder-not-found = provcheck: nem található a backfire mappa. Állítsd be a BACKFIRE_PY változót a backfire.py fájlra, vagy futtasd olyan könyvtárból, amely tartalmazza a backfire/backfire.py fájlt.
backfire-ps1-not-found = provcheck: a setup_backfire.ps1 nem található itt: { $dir }
backfire-sh-not-found = provcheck: a setup_backfire.sh nem található itt: { $dir }
backfire-setup-start = A Backfire olvasási környezet beállítása folyamatban (egyszeri). Ez letölt egy önálló Python-telepítést.
backfire-setup-ready = A Backfire készen áll. Ellenőrizz egy megjelölt képet ezzel:  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck: a Backfire telepítés a { $status } állapottal lépett ki
backfire-setup-run-failed = provcheck: nem sikerült futtatni a Backfire telepítőszkriptet ({ $err }). PowerShell szükséges Windows alatt, vagy bash Linux/macOS alatt.

## Modelltelepítés (--install-models).
install-models-start = { $count } vízjel-felismerési modellfájl telepítése (összesen { $mb } MB).
install-models-item = { $family }/{ $variant } ({ $mb } MB) ...
install-models-ok = ok
install-models-item-failed = SIKERTELEN: { $err }
install-models-done = Minden modell telepítve. A vízjel-felismerés készen áll.
install-models-summary-failed = provcheck: { $count } modell telepítése sikertelen volt (lásd fent).

## Fő ellenőrzési útvonal: hibák, értesítések és tippek.
require-attested-needs-identity = provcheck: a --require-attested-hez szükség van --bsky-handle, --did vagy --auto-identity megadására
trust-store-read-failed = provcheck: nem sikerült beolvasni a(z) '{ $path }' megbízhatósági tárolót: { $err }
auto-identity-no-assertion = provcheck: a --auto-identity kérve volt, de a fájl nem tartalmaz app.provcheck.identity állítást. Előbb írd alá a `provcheck-kit sign --embed-identity` paranccsal, vagy add meg közvetlenül a --bsky-handle / --did kapcsolót.
backfire-needs-key = provcheck: a --backfire-read-hez szükség van --backfire-key megadására
backfire-experimental-notice = provcheck: a Backfire KÍSÉRLETI és BUSL licencű (ingyenes nem kereskedelmi felhasználásra), külön az Apache-2.0 magtól. Ellenőrzi az általad beágyazott kulcsolt jelölést, és jelzi a sávkivágásos manipulációt; a robusztusság képenként eltérő.
backfire-read-failed = provcheck: a backfire olvasása sikertelen: { $err }
mellin-needs-args = provcheck: a --mellin-read-hez szükség van --mellin-secret-file és --mellin-work-id megadására
mellin-experimental-notice = provcheck: a Mellin KÍSÉRLETI és BUSL licencű (ingyenes nem kereskedelmi felhasználásra), külön az Apache-2.0 magtól. Beolvassa az általad beágyazott, példányonkénti kulcsolt sorszámot; a titkod és a work id nélkül nincs mit beolvasni.
mellin-read-failed = provcheck: a mellin olvasása sikertelen: { $err }
json-serialize-failed = provcheck: a JSON szerializálása sikertelen: { $err }
hint-models-missing = [tipp] { $count } vízjel-felismerési modell nincs telepítve, ezért ezek a sorok "not installed" értéket mutatnak. Kapcsold be a teljes felismerést ezzel:  provcheck --install-models  (egyszeri, { $mb } MB). A C2PA-ellenőrzéshez nincs rájuk szükség.
hint-claims-identity = [tipp] a fájl { $who } identitást állít. Futtasd újra a --auto-identity kapcsolóval, hogy ellenőrizd a közzétett aláírókulcs-nyilvántartásuk alapján.
