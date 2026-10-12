# Έξοδος εκτέλεσης του provcheck-cli, ελληνικά. Μόνο κείμενο αναγνώσιμο από άνθρωπο· η
# έξοδος --json και οι κωδικοί εξόδου δεν μεταφράζονται ποτέ. Οι δεσμευτές θέσης { $name }
# συμπληρώνονται στο σημείο κλήσης· διατήρησέ τους ακέραιους στις μεταφράσεις. Οι όροι
# επωνυμίας και οι τεχνικοί όροι (provcheck, C2PA, Backfire, Mellin, BUSL, Apache-2.0,
# JSON, PowerShell, bash, flags, ονόματα αρχείων) παραμένουν αυτούσιοι σε κάθε γλώσσα.

## Μπλοκ Mellin (κλειδωμένος εγκληματολογικός σειριακός ήχου) (print_mellin_human).
mellin-header = Mellin (πειραματικό, κλειδωμένος εγκληματολογικός σειριακός ήχου):
mellin-serial-full = σειριακός:   { $serial } (ανακτήθηκαν και τα 64 bit, ελάχιστες ψήφοι bit { $votes })
mellin-serial-partial = σειριακός:   δεν ανακτήθηκε πλήρως ({ $bits }/64 bit, ελάχιστες ψήφοι bit { $votes })
mellin-erasures = διαγραφές: { $pct }% των θέσεων
mellin-expected-match = αναμενόμενο: ΤΑΙΡΙΑΣΜΑ
mellin-expected-no-match = αναμενόμενο: ΧΩΡΙΣ ΤΑΙΡΙΑΣΜΑ

## Μπλοκ Backfire (κλειδωμένο υδατογράφημα εικόνας) (print_backfire_human).
backfire-header = Backfire (πειραματικό, κλειδωμένο υδατογράφημα εικόνας):
backfire-mark-valid = σήμανση:   ΕΓΚΥΡΗ (id { $id }, περιθώριο { $margin })
backfire-mark-none = σήμανση:   δεν εντοπίστηκε (περιθώριο { $margin })
backfire-tamper-detected = παραποίηση: ΕΝΤΟΠΙΣΤΗΚΕ ΑΠΟΚΟΠΗ ΖΩΝΗΣ (στατιστικό { $stat }) -- η εικόνα πολύ πιθανόν δέχτηκε επίθεση αποκοπής (notch)
backfire-tamper-none = παραποίηση: καμία (στατιστικό αποκοπής ζώνης { $stat })

## Ρύθμιση Backfire (--install-backfire).
backfire-folder-not-found = provcheck: δεν βρέθηκε ο φάκελος backfire. Όρισε το BACKFIRE_PY στο backfire.py, ή εκτέλεσε από κατάλογο που περιέχει το backfire/backfire.py.
backfire-ps1-not-found = provcheck: το setup_backfire.ps1 δεν βρέθηκε στο { $dir }
backfire-sh-not-found = provcheck: το setup_backfire.sh δεν βρέθηκε στο { $dir }
backfire-setup-start = Ρύθμιση του περιβάλλοντος ανάγνωσης Backfire (εφάπαξ). Αυτό κατεβάζει μια αυτόνομη εγκατάσταση Python.
backfire-setup-ready = Το Backfire είναι έτοιμο. Επαλήθευσε μια σημασμένη εικόνα με:  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck: η ρύθμιση του Backfire τερματίστηκε με κατάσταση { $status }
backfire-setup-run-failed = provcheck: δεν ήταν δυνατή η εκτέλεση του σεναρίου ρύθμισης Backfire ({ $err }). Χρειάζεται PowerShell σε Windows, ή bash σε Linux/macOS.

## Εγκατάσταση μοντέλων (--install-models).
install-models-start = Εγκατάσταση { $count } αρχείου(ων) μοντέλου ανίχνευσης υδατογραφήματος ({ $mb } MB συνολικά).
install-models-item = { $family }/{ $variant } ({ $mb } MB) ...
install-models-ok = ok
install-models-item-failed = ΑΠΕΤΥΧΕ: { $err }
install-models-done = Όλα τα μοντέλα εγκαταστάθηκαν. Η ανίχνευση υδατογραφήματος είναι έτοιμη.
install-models-summary-failed = provcheck: { $count } μοντέλο(α) απέτυχαν να εγκατασταθούν (δες παραπάνω).

## Κύρια διαδρομή επαλήθευσης: σφάλματα, ειδοποιήσεις και υποδείξεις.
require-attested-needs-identity = provcheck: το --require-attested χρειάζεται --bsky-handle, --did, ή --auto-identity
trust-store-read-failed = provcheck: δεν ήταν δυνατή η ανάγνωση του καταστήματος εμπιστοσύνης '{ $path }': { $err }
auto-identity-no-assertion = provcheck: ζητήθηκε --auto-identity, αλλά το αρχείο δεν φέρει διαβεβαίωση app.provcheck.identity. Υπόγραψε πρώτα με `provcheck-kit sign --embed-identity`, ή πέρασε απευθείας --bsky-handle / --did.
backfire-needs-key = provcheck: το --backfire-read χρειάζεται --backfire-key
backfire-experimental-notice = provcheck: Το Backfire είναι ΠΕΙΡΑΜΑΤΙΚΟ και έχει άδεια BUSL (δωρεάν για μη εμπορική χρήση), ξεχωριστό από τον πυρήνα Apache-2.0. Επαληθεύει μια κλειδωμένη σήμανση που ενσωμάτωσες και επισημαίνει παραποίηση αποκοπής ζώνης· η ανθεκτικότητα διαφέρει ανά εικόνα.
backfire-read-failed = provcheck: η ανάγνωση backfire απέτυχε: { $err }
mellin-needs-args = provcheck: το --mellin-read χρειάζεται --mellin-secret-file και --mellin-work-id
mellin-experimental-notice = provcheck: Το Mellin είναι ΠΕΙΡΑΜΑΤΙΚΟ και έχει άδεια BUSL (δωρεάν για μη εμπορική χρήση), ξεχωριστό από τον πυρήνα Apache-2.0. Διαβάζει έναν κλειδωμένο σειριακό ανά αντίγραφο που ενσωμάτωσες· χωρίς το μυστικό σου και το work id δεν υπάρχει τίποτα να διαβαστεί.
mellin-read-failed = provcheck: η ανάγνωση mellin απέτυχε: { $err }
json-serialize-failed = provcheck: αποτυχία σειριοποίησης JSON: { $err }
hint-models-missing = [υπόδειξη] { $count } μοντέλο(α) ανίχνευσης υδατογραφήματος δεν είναι εγκατεστημένα, γι' αυτό αυτές οι γραμμές δείχνουν "not installed". Ενεργοποίησε πλήρη ανίχνευση με:  provcheck --install-models  (εφάπαξ, { $mb } MB). Η επαλήθευση C2PA δεν τα χρειάζεται.
hint-claims-identity = [υπόδειξη] το αρχείο ισχυρίζεται ταυτότητα { $who }. Εκτέλεσε ξανά με --auto-identity για επαλήθευση έναντι των δημοσιευμένων εγγραφών κλειδιού υπογραφής τους.
