# provcheck-cli Laufzeitausgabe, Deutsch. Nur menschenlesbare Ausgabe; die --json-Ausgabe
# und Exit-Codes werden nie lokalisiert. Platzhalter { $name } werden an der Aufrufstelle
# gefuellt; in Uebersetzungen unveraendert lassen. Marken- und Fachbegriffe (provcheck,
# C2PA, Backfire, Mellin, BUSL, Apache-2.0, JSON, PowerShell, bash, Flags, Dateinamen)
# bleiben in jeder Sprache woertlich stehen.

## Mellin-Block (geschluesselte forensische Audio-Seriennummer).
mellin-header = Mellin (experimentell, geschluesselte forensische Audio-Seriennummer):
mellin-serial-full = Seriennummer:   { $serial } (alle 64 Bits wiederhergestellt, minimale Bit-Stimmen { $votes })
mellin-serial-partial = Seriennummer:   nicht vollstaendig wiederhergestellt ({ $bits }/64 Bits, minimale Bit-Stimmen { $votes })
mellin-erasures = Loeschungen: { $pct }% der Positionen
mellin-expected-match = erwartet: TREFFER
mellin-expected-no-match = erwartet: KEIN TREFFER

## Backfire-Block (geschluesseltes Bild-Wasserzeichen).
backfire-header = Backfire (experimentell, geschluesseltes Bild-Wasserzeichen):
backfire-mark-valid = Markierung:   GUELTIG (id { $id }, Marge { $margin })
backfire-mark-none = Markierung:   nicht erkannt (Marge { $margin })
backfire-tamper-detected = Manipulation: BAND-NOTCH ERKANNT (Wert { $stat }), das Bild wurde sehr wahrscheinlich mit einem Notch-Angriff bearbeitet
backfire-tamper-none = Manipulation: keine (Band-Notch-Wert { $stat })

## Backfire-Einrichtung (--install-backfire).
backfire-folder-not-found = provcheck: Der Backfire-Ordner konnte nicht gefunden werden. Setze BACKFIRE_PY auf backfire.py, oder starte aus einem Verzeichnis, das backfire/backfire.py enthaelt.
backfire-ps1-not-found = provcheck: setup_backfire.ps1 wurde in { $dir } nicht gefunden
backfire-sh-not-found = provcheck: setup_backfire.sh wurde in { $dir } nicht gefunden
backfire-setup-start = Die Backfire-Leseumgebung wird eingerichtet (einmalig). Dabei wird ein eigenstaendiges Python heruntergeladen.
backfire-setup-ready = Backfire ist bereit. Pruefe ein markiertes Bild mit:  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck: Backfire-Setup wurde mit Status { $status } beendet
backfire-setup-run-failed = provcheck: Das Backfire-Setup-Skript konnte nicht ausgefuehrt werden ({ $err }). Es benoetigt PowerShell unter Windows oder bash unter Linux/macOS.

## Modell-Installation (--install-models).
install-models-start = { $count } Modelldatei(en) zur Wasserzeichen-Erkennung werden installiert ({ $mb } MB insgesamt).
install-models-item = { $family }/{ $variant } ({ $mb } MB) ...
install-models-ok = ok
install-models-item-failed = FEHLGESCHLAGEN: { $err }
install-models-done = Alle Modelle installiert. Die Wasserzeichen-Erkennung ist bereit.
install-models-summary-failed = provcheck: { $count } Modell(e) konnten nicht installiert werden (siehe oben).

## Hauptpfad: Fehler, Hinweise und Tipps.
require-attested-needs-identity = provcheck: --require-attested benoetigt --bsky-handle, --did oder --auto-identity
trust-store-read-failed = provcheck: Trust-Store '{ $path }' konnte nicht gelesen werden: { $err }
auto-identity-no-assertion = provcheck: --auto-identity wurde angefordert, aber die Datei enthaelt keine app.provcheck.identity-Assertion. Signiere zuerst mit `provcheck-kit sign --embed-identity`, oder gib --bsky-handle / --did direkt an.
backfire-needs-key = provcheck: --backfire-read benoetigt --backfire-key
backfire-experimental-notice = provcheck: Backfire ist EXPERIMENTELL und BUSL-lizenziert (kostenlos fuer nicht-kommerzielle Nutzung), getrennt vom Apache-2.0-Kern. Es prueft eine geschluesselte Markierung, die du eingebettet hast, und meldet Band-Notch-Manipulationen; die Robustheit ist bildabhaengig.
backfire-read-failed = provcheck: Backfire-Lesen fehlgeschlagen: { $err }
mellin-needs-args = provcheck: --mellin-read benoetigt --mellin-secret-file und --mellin-work-id
mellin-experimental-notice = provcheck: Mellin ist EXPERIMENTELL und BUSL-lizenziert (kostenlos fuer nicht-kommerzielle Nutzung), getrennt vom Apache-2.0-Kern. Es liest eine geschluesselte Seriennummer pro Kopie, die du eingebettet hast; ohne dein Geheimnis und deine Work-ID gibt es nichts zu lesen.
mellin-read-failed = provcheck: Mellin-Lesen fehlgeschlagen: { $err }
json-serialize-failed = provcheck: JSON konnte nicht serialisiert werden: { $err }
hint-models-missing = [hint] { $count } Modell(e) zur Wasserzeichen-Erkennung sind nicht installiert, daher zeigen diese Zeilen "not installed". Aktiviere die vollstaendige Erkennung mit:  provcheck --install-models  (einmalig, { $mb } MB). Die C2PA-Verifizierung benoetigt sie nicht.
hint-claims-identity = [hint] Datei beansprucht Identitaet { $who }. Fuehre erneut mit --auto-identity aus, um sie gegen die veroeffentlichten Signaturschluessel-Datensaetze zu pruefen.
