# provcheck-app GUI-meddelanden, svenska. Endast fullständiga, användarriktade meningar
# som skickas tillbaka till GUI:t som ApiResult ok/err-text lokaliseras; teknisk
# { $err }/loggsökvägsdiagnostik och IPC-felbeteckningar förblir engelska. Varumärkes-
# och tekniska termer (provcheck, provcheck-kit, Backfire, Mellin, C2PA, atproto,
# LOCALAPPDATA, BACKFIRE_PY, Yubikey, PIV PIN, DID, flaggor, filnamn) står kvar
# oöversatta på varje språk.

## Backfire-flik för nyckelbaserad bild (backfire_read + install_backfire).
backfire-read-needs-key = En nyckel krävs för att läsa en Backfire-markering.
backfire-folder-unresolved = Kunde inte hitta en skrivbar Backfire-mapp (LOCALAPPDATA inte angiven).
backfire-ready-bundled = Backfire är klart (medföljande läsare finns). Ange en nyckel och släpp en bild.
backfire-files-missing = Backfire-filer för installation hittades inte. Installera om provcheck, eller ange BACKFIRE_PY.
backfire-ready = Backfire är klart. Ange en nyckel och släpp en bild.

## Mellin-flik för nyckelbaserade markeringar (mellin_read).
mellin-needs-secret-and-work-id = En hemlig fil och ett work-id krävs för att läsa ett Mellin-serienummer.
mellin-secret-file-missing = Den valda hemliga filen finns inte (eller går inte att läsa).

## Sign- och Keys-flikarna: begränsningar i GUI-funktionalitet som returneras som ApiResult-fel.
identity-already-exists = det finns redan en identitet i denna datakatalog; ange force=true för att generera om den (detta gör alla tidigare publicerade atproto-poster föräldralösa)
rotate-yubikey-unsupported = GUI-rotation av en Yubikey-baserad identitet stöds inte ännu. Kör `provcheck-kit init --yubikey --force` från en terminal, och kom sedan tillbaka hit för att publicera och återkalla.
rotate-agefile-unsupported = GUI-rotation av age-filbaserade identiteter är inte kopplat ännu. Använd `provcheck-kit rotate` från en terminal.
sign-keychain-only = GUI-signering stöder för närvarande endast OS-nyckelringsidentiteter. Använd `provcheck-kit sign` från CLI:t för age-filidentiteter.
sign-yubikey-unsupported = GUI-signering av Yubikey-baserade identiteter kommer i v0.5.0 P3 + P4. Signera tills vidare via `provcheck-kit sign` från en terminal; kitet frågar efter PIV PIN vid varje signering.
