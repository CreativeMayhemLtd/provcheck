# provcheck-app GUI-meldinger, norsk bokmål. Kun fullstendige, brukervendte setninger som
# returneres til GUI-et som ApiResult ok/err-tekst, blir lokalisert; teknisk
# { $err }/loggbane-diagnostikk og IPC-feiletiketter forblir engelske. Merke- og
# tekniske termer (provcheck, provcheck-kit, Backfire, Mellin, C2PA, atproto,
# LOCALAPPDATA, BACKFIRE_PY, Yubikey, PIV PIN, DID, flagg, filnavn) forblir
# uoversatt på hvert språk.

## Backfire nøkkelbasert bilde-fane (backfire_read + install_backfire).
backfire-read-needs-key = En nøkkel kreves for å lese et Backfire-merke.
backfire-folder-unresolved = Fant ikke en skrivbar Backfire-mappe (LOCALAPPDATA ikke angitt).
backfire-ready-bundled = Backfire er klart (medfølgende leser til stede). Angi en nøkkel og slipp et bilde.
backfire-files-missing = Backfire-filer for installasjon ble ikke funnet. Installer provcheck på nytt, eller angi BACKFIRE_PY.
backfire-ready = Backfire er klart. Angi en nøkkel og slipp et bilde.

## Mellin nøkkelbaserte merker-fane (mellin_read).
mellin-needs-secret-and-work-id = En hemmelig fil og en work-id kreves for å lese et Mellin-serienummer.
mellin-secret-file-missing = Den valgte hemmelige filen finnes ikke (eller kan ikke leses).

## Sign- og Keys-fanene: GUI-funksjonsbegrensninger som returneres som ApiResult-feil.
identity-already-exists = det finnes allerede en identitet i denne datamappen; oppgi force=true for å regenerere den (dette gjør alle tidligere publiserte atproto-poster foreldreløse)
rotate-yubikey-unsupported = GUI-rotasjon av en Yubikey-basert identitet støttes ikke ennå. Kjør `provcheck-kit init --yubikey --force` fra en terminal, og kom deretter tilbake hit for å publisere og tilbakekalle.
rotate-agefile-unsupported = GUI-rotasjon av age-fil-baserte identiteter er ikke koblet til ennå. Bruk `provcheck-kit rotate` fra en terminal.
sign-keychain-only = GUI-signering støtter for øyeblikket kun OS-nøkkelring-identiteter. Bruk `provcheck-kit sign` fra CLI-en for age-fil-identiteter.
sign-yubikey-unsupported = GUI-signering av Yubikey-baserte identiteter kommer i v0.5.0 P3 + P4. Signer inntil videre via `provcheck-kit sign` fra en terminal; kittet spør om PIV PIN ved hver signering.
