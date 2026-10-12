# Messaggi GUI di provcheck-app, italiano. Vengono localizzate qui solo le frasi
# complete rivolte all'utente restituite alla GUI come testo ApiResult ok/err; le
# diagnostiche tecniche { $err }/percorso log e le etichette di errore IPC restano in
# inglese. I termini di marchio e tecnici (provcheck, provcheck-kit, Backfire, Mellin,
# C2PA, atproto, LOCALAPPDATA, BACKFIRE_PY, Yubikey, PIV PIN, DID, flags, nomi di file)
# restano testuali in ogni lingua.

## Scheda immagine con chiave di Backfire (backfire_read + install_backfire).
backfire-read-needs-key = E' richiesta una chiave per leggere un marchio Backfire.
backfire-folder-unresolved = Impossibile risolvere una cartella Backfire scrivibile (LOCALAPPDATA non impostata).
backfire-ready-bundled = Backfire e' pronto (lettore incluso presente). Inserisci una chiave e trascina un'immagine.
backfire-files-missing = File di Backfire non trovati per l'installazione. Reinstalla provcheck, oppure imposta BACKFIRE_PY.
backfire-ready = Backfire e' pronto. Inserisci una chiave e trascina un'immagine.

## Scheda marchi con chiave di Mellin (mellin_read).
mellin-needs-secret-and-work-id = Sono richiesti un file segreto e un work id per leggere un seriale Mellin.
mellin-secret-file-missing = Il file segreto scelto non esiste (o non e' leggibile).

## Schede Sign e Keys: avvisi sui limiti di capacita' della GUI restituiti come errori ApiResult.
identity-already-exists = esiste gia' un'identita' in questa directory dati; passa force=true per rigenerarla (questo rende orfani tutti i record atproto pubblicati in precedenza)
rotate-yubikey-unsupported = La rotazione da GUI di un'identita' basata su Yubikey non e' ancora supportata. Esegui `provcheck-kit init --yubikey --force` da un terminale, poi torna qui per pubblicare e revocare.
rotate-agefile-unsupported = La rotazione da GUI delle identita' basate su file age non e' ancora collegata. Usa `provcheck-kit rotate` da un terminale.
sign-keychain-only = La firma da GUI attualmente supporta solo identita' del portachiavi del sistema operativo. Usa `provcheck-kit sign` dalla CLI per le identita' basate su file age.
sign-yubikey-unsupported = La firma da GUI di identita' basate su Yubikey arrivera' in v0.5.0 P3 + P4. Per ora, firma tramite `provcheck-kit sign` da un terminale: il kit chiede il PIN PIV a ogni firma.
