# provcheck-app GUI-meldingen, Nederlands. Alleen volledige, gebruikersgerichte zinnen die
# als ApiResult ok/err-tekst naar de GUI teruggaan, worden gelokaliseerd; technische
# { $err }/log-pad-diagnostiek en IPC-foutlabels blijven Engels. Merk- en technische
# termen (provcheck, provcheck-kit, Backfire, Mellin, C2PA, atproto, LOCALAPPDATA,
# BACKFIRE_PY, Yubikey, PIV PIN, DID, flags, bestandsnamen) blijven in elke taal
# letterlijk staan.

## Backfire keyed-image tab (backfire_read + install_backfire).
backfire-read-needs-key = Er is een sleutel nodig om een Backfire-markering te lezen.
backfire-folder-unresolved = Kan geen beschrijfbare Backfire-map vinden (LOCALAPPDATA niet ingesteld).
backfire-ready-bundled = Backfire is gereed (meegeleverde reader aanwezig). Voer een sleutel in en sleep een afbeelding hierheen.
backfire-files-missing = Backfire-bestanden voor installatie niet gevonden. Installeer provcheck opnieuw, of stel BACKFIRE_PY in.
backfire-ready = Backfire is gereed. Voer een sleutel in en sleep een afbeelding hierheen.

## Mellin keyed-marks tab (mellin_read).
mellin-needs-secret-and-work-id = Een geheim bestand en een work-id zijn nodig om een Mellin-serienummer te lezen.
mellin-secret-file-missing = Het gekozen geheime bestand bestaat niet (of is niet leesbaar).

## Sign- en Keys-tabs: GUI-functiebeperkingen die als ApiResult-fouten teruggaan.
identity-already-exists = er bestaat al een identiteit in deze datamap; geef force=true door om deze opnieuw te genereren (dit laat alle eerder gepubliceerde atproto-records verweesd achter)
rotate-yubikey-unsupported = GUI-rotatie van een op Yubikey gebaseerde identiteit wordt nog niet ondersteund. Voer `provcheck-kit init --yubikey --force` uit in een terminal, en kom dan hier terug om te publiceren en in te trekken.
rotate-agefile-unsupported = GUI-rotatie van op age-bestand gebaseerde identiteiten is nog niet aangesloten. Gebruik `provcheck-kit rotate` in een terminal.
sign-keychain-only = GUI-ondertekening ondersteunt momenteel alleen OS-keychain-identiteiten. Gebruik `provcheck-kit sign` vanaf de CLI voor age-bestand-identiteiten.
sign-yubikey-unsupported = GUI-ondertekening van op Yubikey gebaseerde identiteiten komt in v0.5.0 P3 + P4. Onderteken voorlopig via `provcheck-kit sign` in een terminal; de kit vraagt bij elke handtekening om de PIV PIN.
