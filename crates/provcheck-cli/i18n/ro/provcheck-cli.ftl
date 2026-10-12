# Ieșirea de execuție provcheck-cli, română. Doar ieșire lizibilă pentru oameni; ieșirea
# --json și codurile de ieșire nu sunt niciodată localizate. Marcatorii { $name } sunt
# completați la locul apelului; păstrează-i neschimbați în traduceri. Termenii de marcă
# și tehnici (provcheck, C2PA, Backfire, Mellin, BUSL, Apache-2.0, JSON, PowerShell, bash,
# flags, nume de fișiere) rămân identici în fiecare limbă.

## Blocul Mellin (serial forensic audio codat cu cheie) (print_mellin_human).
mellin-header = Mellin (experimental, serial forensic audio codat cu cheie):
mellin-serial-full = serial:   { $serial } (toți cei 64 de biți recuperați, voturi minime pe bit { $votes })
mellin-serial-partial = serial:   nu a fost recuperat complet ({ $bits }/64 biți, voturi minime pe bit { $votes })
mellin-erasures = ștergeri: { $pct }% din poziții
mellin-expected-match = așteptat: POTRIVIRE
mellin-expected-no-match = așteptat: FĂRĂ POTRIVIRE

## Blocul Backfire (filigran de imagine codat cu cheie) (print_backfire_human).
backfire-header = Backfire (experimental, filigran de imagine codat cu cheie):
backfire-mark-valid = marcaj:   VALID (id { $id }, marjă { $margin })
backfire-mark-none = marcaj:   nedetectat (marjă { $margin })
backfire-tamper-detected = alterare: BAND-NOTCH DETECTAT (statistică { $stat }) -- imaginea a fost foarte probabil supusă unui atac notch
backfire-tamper-none = alterare: niciuna (statistică band-notch { $stat })

## Configurare Backfire (--install-backfire).
backfire-folder-not-found = provcheck: nu s-a putut localiza folderul backfire. Setează BACKFIRE_PY la backfire.py, sau rulează dintr-un director care conține backfire/backfire.py.
backfire-ps1-not-found = provcheck: setup_backfire.ps1 nu a fost găsit în { $dir }
backfire-sh-not-found = provcheck: setup_backfire.sh nu a fost găsit în { $dir }
backfire-setup-start = Se configurează mediul de citire Backfire (o singură dată). Aceasta descarcă un Python autonom.
backfire-setup-ready = Backfire este gata. Verifică o imagine marcată cu:  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck: configurarea Backfire s-a încheiat cu starea { $status }
backfire-setup-run-failed = provcheck: nu s-a putut rula scriptul de configurare Backfire ({ $err }). Necesită PowerShell pe Windows, sau bash pe Linux/macOS.

## Instalarea modelelor (--install-models).
install-models-start = Se instalează { $count } fișier(e) de model de detectare a filigranului ({ $mb } MB în total).
install-models-item = { $family }/{ $variant } ({ $mb } MB) ...
install-models-ok = ok
install-models-item-failed = EȘUAT: { $err }
install-models-done = Toate modelele au fost instalate. Detectarea filigranului este gata.
install-models-summary-failed = provcheck: { $count } model(e) nu au putut fi instalate (vezi mai sus).

## Calea principală de verificare: erori, notificări și sugestii.
require-attested-needs-identity = provcheck: --require-attested necesită --bsky-handle, --did, sau --auto-identity
trust-store-read-failed = provcheck: nu s-a putut citi depozitul de încredere '{ $path }': { $err }
auto-identity-no-assertion = provcheck: s-a solicitat --auto-identity, dar fișierul nu conține nicio afirmație app.provcheck.identity. Semnează mai întâi cu `provcheck-kit sign --embed-identity`, sau transmite direct --bsky-handle / --did.
backfire-needs-key = provcheck: --backfire-read necesită --backfire-key
backfire-experimental-notice = provcheck: Backfire este EXPERIMENTAL și licențiat BUSL (gratuit pentru uz necomercial), separat de nucleul Apache-2.0. Verifică un marcaj codat cu cheie pe care l-ai încorporat și semnalează alterarea band-notch; robustețea variază de la o imagine la alta.
backfire-read-failed = provcheck: citirea backfire a eșuat: { $err }
mellin-needs-args = provcheck: --mellin-read necesită --mellin-secret-file și --mellin-work-id
mellin-experimental-notice = provcheck: Mellin este EXPERIMENTAL și licențiat BUSL (gratuit pentru uz necomercial), separat de nucleul Apache-2.0. Citește un serial codat cu cheie per copie pe care l-ai încorporat; fără secretul tău și id-ul lucrării nu este nimic de citit.
mellin-read-failed = provcheck: citirea mellin a eșuat: { $err }
json-serialize-failed = provcheck: serializarea JSON a eșuat: { $err }
hint-models-missing = [sugestie] { $count } model(e) de detectare a filigranului nu sunt instalate, deci acele linii afișează "not installed". Activează detectarea completă cu:  provcheck --install-models  (o singură dată, { $mb } MB). Verificarea C2PA nu are nevoie de ele.
hint-claims-identity = [sugestie] fișierul revendică identitatea { $who }. Rulează din nou cu --auto-identity pentru a verifica față de înregistrările publicate ale cheii lor de semnare.
