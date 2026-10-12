# provcheck-app GUI üzenetek, magyar. Csak a GUI-nak ApiResult ok/err szövegként
# visszaadott, teljes, felhasználó felé irányuló mondatok vannak itt lokalizálva; a
# technikai { $err }/naplóútvonal diagnosztikák és az IPC hibacímkék angolul maradnak.
# A márka- és technikai kifejezések (provcheck, provcheck-kit, Backfire, Mellin, C2PA,
# atproto, LOCALAPPDATA, BACKFIRE_PY, Yubikey, PIV PIN, DID, flagek, fájlnevek) minden
# nyelvben szó szerint maradnak.

## Backfire kulcsolt kép fül (backfire_read + install_backfire).
backfire-read-needs-key = Egy Backfire jelölés olvasásához kulcs szükséges.
backfire-folder-unresolved = Nem sikerült meghatározni egy írható Backfire mappát (a LOCALAPPDATA nincs beállítva).
backfire-ready-bundled = A Backfire készen áll (a csomagolt olvasó jelen van). Add meg a kulcsot, és húzz be egy képet.
backfire-files-missing = A telepítendő Backfire fájlok nem találhatók. Telepítsd újra a provcheck-et, vagy állítsd be a BACKFIRE_PY változót.
backfire-ready = A Backfire készen áll. Add meg a kulcsot, és húzz be egy képet.

## Mellin kulcsolt jelölések fül (mellin_read).
mellin-needs-secret-and-work-id = Egy Mellin sorszám olvasásához titokfájl és work id szükséges.
mellin-secret-file-missing = A kiválasztott titokfájl nem létezik (vagy nem olvasható).

## Aláírás és Kulcsok fülek: GUI képességkorlát-értesítések ApiResult hibaként visszaadva.
identity-already-exists = ebben az adatkönyvtárban már létezik egy identitás; add meg a force=true értéket az újragenerálásához (ez árvává teszi a korábban közzétett atproto rekordokat)
rotate-yubikey-unsupported = A Yubikey-alapú identitás GUI-ból történő rotálása még nem támogatott. Futtasd a `provcheck-kit init --yubikey --force` parancsot egy terminálból, majd térj vissza ide a közzétételhez és visszavonáshoz.
rotate-agefile-unsupported = Az age-fájl-alapú identitások GUI-ból történő rotálása még nincs bekötve. Használd a `provcheck-kit rotate` parancsot egy terminálból.
sign-keychain-only = A GUI-aláírás jelenleg csak az OS-kulcstartó-alapú identitásokat támogatja. Az age-fájl-alapú identitásokhoz használd a `provcheck-kit sign` parancsot a CLI-ből.
sign-yubikey-unsupported = A Yubikey-alapú identitások GUI-aláírása a v0.5.0 P3 + P4 verzióban érkezik. Egyelőre írj alá a `provcheck-kit sign` paranccsal egy terminálból; a kit minden aláírásnál bekéri a PIV PIN-t.
