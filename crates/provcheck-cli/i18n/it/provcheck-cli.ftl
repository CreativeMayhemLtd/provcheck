# Output di runtime di provcheck-cli, italiano. Viene localizzato solo l'output
# leggibile da persone; l'output --json e i codici di uscita non vengono mai
# localizzati. I segnaposto { $name } vengono riempiti nel punto di chiamata; mantienili
# intatti nelle traduzioni. I termini di marchio e tecnici (provcheck, C2PA, Backfire,
# Mellin, BUSL, Apache-2.0, JSON, PowerShell, bash, flags, nomi di file) restano
# testuali in ogni lingua.

## Blocco forense audio con chiave di Mellin (print_mellin_human).
mellin-header = Mellin (sperimentale, seriale forense audio con chiave):
mellin-serial-full = seriale:   { $serial } (tutti i 64 bit recuperati, voti minimi di bit { $votes })
mellin-serial-partial = seriale:   non recuperato completamente ({ $bits }/64 bit, voti minimi di bit { $votes })
mellin-erasures = cancellazioni: { $pct }% delle posizioni
mellin-expected-match = atteso: CORRISPONDENZA
mellin-expected-no-match = atteso: NESSUNA CORRISPONDENZA

## Blocco filigrana immagine con chiave di Backfire (print_backfire_human).
backfire-header = Backfire (sperimentale, filigrana immagine con chiave):
backfire-mark-valid = marchio:   VALIDO (id { $id }, margine { $margin })
backfire-mark-none = marchio:   non rilevato (margine { $margin })
backfire-tamper-detected = manomissione: NOTCH DI BANDA RILEVATO (statistica { $stat }): l'immagine e' molto probabilmente stata attaccata con un notch
backfire-tamper-none = manomissione: nessuna (statistica notch di banda { $stat })

## Configurazione di Backfire (--install-backfire).
backfire-folder-not-found = provcheck: impossibile individuare la cartella backfire. Imposta BACKFIRE_PY su backfire.py, oppure esegui da una directory che contiene backfire/backfire.py.
backfire-ps1-not-found = provcheck: setup_backfire.ps1 non trovato in { $dir }
backfire-sh-not-found = provcheck: setup_backfire.sh non trovato in { $dir }
backfire-setup-start = Configurazione dell'ambiente di lettura Backfire in corso (una tantum). Questo scarica un Python autonomo.
backfire-setup-ready = Backfire e' pronto. Verifica un'immagine marchiata con:  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck: la configurazione di Backfire e' terminata con stato { $status }
backfire-setup-run-failed = provcheck: impossibile eseguire lo script di configurazione di Backfire ({ $err }). Richiede PowerShell su Windows, o bash su Linux/macOS.

## Installazione dei modelli (--install-models).
install-models-start = Installazione di { $count } file di modello per il rilevamento delle filigrane ({ $mb } MB totali).
install-models-item = { $family }/{ $variant } ({ $mb } MB) ...
install-models-ok = ok
install-models-item-failed = FALLITO: { $err }
install-models-done = Tutti i modelli sono stati installati. Il rilevamento delle filigrane e' pronto.
install-models-summary-failed = provcheck: { $count } modello/i non e' stato possibile installare (vedi sopra).

## Percorso principale di verifica: errori, avvisi e suggerimenti.
require-attested-needs-identity = provcheck: --require-attested richiede --bsky-handle, --did, o --auto-identity
trust-store-read-failed = provcheck: impossibile leggere il trust store '{ $path }': { $err }
auto-identity-no-assertion = provcheck: e' stato richiesto --auto-identity, ma il file non contiene alcuna asserzione app.provcheck.identity. Firma prima con `provcheck-kit sign --embed-identity`, oppure passa --bsky-handle / --did direttamente.
backfire-needs-key = provcheck: --backfire-read richiede --backfire-key
backfire-experimental-notice = provcheck: Backfire e' SPERIMENTALE e con licenza BUSL (gratuito per uso non commerciale), separato dal nucleo Apache-2.0. Verifica un marchio con chiave che hai incorporato e segnala manomissioni con notch di banda; la robustezza dipende dalla singola immagine.
backfire-read-failed = provcheck: lettura backfire fallita: { $err }
mellin-needs-args = provcheck: --mellin-read richiede --mellin-secret-file e --mellin-work-id
mellin-experimental-notice = provcheck: Mellin e' SPERIMENTALE e con licenza BUSL (gratuito per uso non commerciale), separato dal nucleo Apache-2.0. Legge un seriale con chiave per copia che hai incorporato; senza il tuo secret e il tuo work id non c'e' nulla da leggere.
mellin-read-failed = provcheck: lettura mellin fallita: { $err }
json-serialize-failed = provcheck: serializzazione JSON fallita: { $err }
hint-models-missing = [suggerimento] { $count } modello/i di rilevamento filigrana non sono installati, quindi quelle righe mostrano "not installed". Attiva il rilevamento completo con:  provcheck --install-models  (una tantum, { $mb } MB). La verifica C2PA non ne ha bisogno.
hint-claims-identity = [suggerimento] il file dichiara l'identita' { $who }. Riesegui con --auto-identity per verificarla rispetto ai suoi record di chiave di firma pubblicati.
