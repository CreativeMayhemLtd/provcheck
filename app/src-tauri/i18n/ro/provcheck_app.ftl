# Mesaje GUI provcheck-app, română. Aici sunt localizate doar propozițiile complete
# orientate spre utilizator, returnate către GUI ca text ApiResult ok/err; diagnosticele
# tehnice { $err }/căi de jurnal și etichetele de eroare IPC rămân în engleză. Termenii de
# marcă și tehnici (provcheck, provcheck-kit, Backfire, Mellin, C2PA, atproto,
# LOCALAPPDATA, BACKFIRE_PY, Yubikey, PIV PIN, DID, flags, nume de fișiere) rămân
# identici în fiecare limbă.

## Fila de imagine codată cu cheie Backfire (backfire_read + install_backfire).
backfire-read-needs-key = Este necesară o cheie pentru a citi un marcaj Backfire.
backfire-folder-unresolved = Nu s-a putut determina un folder Backfire scriptibil (LOCALAPPDATA nesetat).
backfire-ready-bundled = Backfire este gata (cititorul inclus este prezent). Introdu o cheie și plasează o imagine.
backfire-files-missing = Fișierele Backfire pentru instalare nu au fost găsite. Reinstalează provcheck, sau setează BACKFIRE_PY.
backfire-ready = Backfire este gata. Introdu o cheie și plasează o imagine.

## Fila de marcaje codate cu cheie Mellin (mellin_read).
mellin-needs-secret-and-work-id = Sunt necesare un fișier secret și un id de lucrare pentru a citi un serial Mellin.
mellin-secret-file-missing = Fișierul secret ales nu există (sau nu este lizibil).

## Filele Semnare și Chei: notificări privind limitele de funcționalitate GUI, returnate ca erori ApiResult.
identity-already-exists = există deja o identitate în acest director de date; transmite force=true pentru a o regenera (aceasta orfelinizează orice înregistrări atproto publicate anterior)
rotate-yubikey-unsupported = Rotația prin GUI a unei identități bazate pe Yubikey nu este încă suportată. Rulează `provcheck-kit init --yubikey --force` dintr-un terminal, apoi revino aici pentru a publica și revoca.
rotate-agefile-unsupported = Rotația prin GUI a identităților bazate pe fișier age nu este încă conectată. Folosește `provcheck-kit rotate` dintr-un terminal.
sign-keychain-only = Semnarea prin GUI suportă în prezent doar identitățile bazate pe OS-keychain. Folosește `provcheck-kit sign` din CLI pentru identitățile cu fișier age.
sign-yubikey-unsupported = Semnarea prin GUI a identităților bazate pe Yubikey sosește în v0.5.0 P3 + P4. Deocamdată, semnează prin `provcheck-kit sign` dintr-un terminal; kitul solicită PIV PIN la fiecare semnătură.
