# provcheck-app GUI-Ausgabe, Deutsch. Nur vollstaendige, benutzerseitige Saetze, die als
# ApiResult ok/err an die GUI zurueckgehen, werden lokalisiert; technische
# { $err }/Log-Pfad-Diagnosen und IPC-Fehlerbezeichner bleiben Englisch. Marken- und
# Fachbegriffe (provcheck, provcheck-kit, Backfire, Mellin, C2PA, atproto, LOCALAPPDATA,
# BACKFIRE_PY, Yubikey, PIV-PIN, DID, Flags, Dateinamen) bleiben in jeder Sprache woertlich.

## Backfire-Tab (backfire_read + install_backfire).
backfire-read-needs-key = Zum Lesen einer Backfire-Markierung ist ein Schluessel erforderlich.
backfire-folder-unresolved = Es konnte kein beschreibbarer Backfire-Ordner ermittelt werden (LOCALAPPDATA nicht gesetzt).
backfire-ready-bundled = Backfire ist bereit (mitgelieferter Reader vorhanden). Gib einen Schluessel ein und ziehe ein Bild hinein.
backfire-files-missing = Die Backfire-Dateien fuer die Installation wurden nicht gefunden. Installiere provcheck neu, oder setze BACKFIRE_PY.
backfire-ready = Backfire ist bereit. Gib einen Schluessel ein und ziehe ein Bild hinein.

## Mellin-Tab (mellin_read).
mellin-needs-secret-and-work-id = Zum Lesen einer Mellin-Seriennummer sind eine Geheimnisdatei und eine Work-ID erforderlich.
mellin-secret-file-missing = Die gewaehlte Geheimnisdatei existiert nicht (oder ist nicht lesbar).

## Sign- und Keys-Tab: GUI-Funktionsgrenzen, die als ApiResult-Fehler zurueckgehen.
identity-already-exists = in diesem Datenverzeichnis existiert bereits eine Identitaet; uebergib force=true, um sie neu zu erzeugen (dies verwaist alle zuvor veroeffentlichten atproto-Datensaetze)
rotate-yubikey-unsupported = Die GUI-Rotation einer Yubikey-gestuetzten Identitaet wird noch nicht unterstuetzt. Fuehre `provcheck-kit init --yubikey --force` in einem Terminal aus, und komme dann hierher zurueck, um zu veroeffentlichen und zu widerrufen.
rotate-agefile-unsupported = Die GUI-Rotation von age-Datei-gestuetzten Identitaeten ist noch nicht angebunden. Verwende `provcheck-kit rotate` in einem Terminal.
sign-keychain-only = GUI-Signierung unterstuetzt derzeit nur OS-Keychain-Identitaeten. Verwende `provcheck-kit sign` in der CLI fuer age-Datei-Identitaeten.
sign-yubikey-unsupported = GUI-Signierung von Yubikey-gestuetzten Identitaeten kommt in v0.5.0 P3 + P4. Signiere vorerst ueber `provcheck-kit sign` in einem Terminal; das Kit fragt bei jeder Signatur nach der PIV-PIN.
