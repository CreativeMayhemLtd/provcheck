# provcheck-app GUI-meddelelser, dansk. Kun fuldstændige, brugervendte sætninger, der
# returneres til GUI'en som ApiResult ok/err-tekst, lokaliseres; teknisk
# { $err }/log-sti-diagnostik og IPC-fejlbetegnelser forbliver engelske. Mærke- og
# tekniske termer (provcheck, provcheck-kit, Backfire, Mellin, C2PA, atproto,
# LOCALAPPDATA, BACKFIRE_PY, Yubikey, PIV PIN, DID, flags, filnavne) forbliver
# uoversatte på ethvert sprog.

## Backfire nøglebaseret billed-fane (backfire_read + install_backfire).
backfire-read-needs-key = Der kræves en nøgle for at læse et Backfire-mærke.
backfire-folder-unresolved = Kunne ikke finde en skrivbar Backfire-mappe (LOCALAPPDATA ikke angivet).
backfire-ready-bundled = Backfire er klar (medfølgende læser til stede). Indtast en nøgle, og træk et billede ind.
backfire-files-missing = Backfire-filer til installation blev ikke fundet. Geninstaller provcheck, eller angiv BACKFIRE_PY.
backfire-ready = Backfire er klar. Indtast en nøgle, og træk et billede ind.

## Mellin nøglebaserede mærker-fane (mellin_read).
mellin-needs-secret-and-work-id = Der kræves en hemmelig fil og et work-id for at læse et Mellin-serienummer.
mellin-secret-file-missing = Den valgte hemmelige fil findes ikke (eller kan ikke læses).

## Sign- og Keys-fanerne: GUI-funktionsbegrænsninger, der returneres som ApiResult-fejl.
identity-already-exists = der findes allerede en identitet i denne datamappe; angiv force=true for at gendanne den (dette gør alle tidligere offentliggjorte atproto-poster forældreløse)
rotate-yubikey-unsupported = GUI-rotation af en Yubikey-baseret identitet understøttes ikke endnu. Kør `provcheck-kit init --yubikey --force` fra en terminal, og kom derefter tilbage her for at offentliggøre og tilbagekalde.
rotate-agefile-unsupported = GUI-rotation af age-fil-baserede identiteter er ikke koblet til endnu. Brug `provcheck-kit rotate` fra en terminal.
sign-keychain-only = GUI-signering understøtter i øjeblikket kun OS-nøglering-identiteter. Brug `provcheck-kit sign` fra CLI'en til age-fil-identiteter.
sign-yubikey-unsupported = GUI-signering af Yubikey-baserede identiteter kommer i v0.5.0 P3 + P4. Signer indtil videre via `provcheck-kit sign` fra en terminal; kittet beder om PIV PIN ved hver signering.
