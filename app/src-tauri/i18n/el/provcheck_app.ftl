# Μηνύματα GUI του provcheck-app, ελληνικά. Μόνο πλήρεις προτάσεις προς τον χρήστη που
# επιστρέφονται στο GUI ως κείμενο ApiResult ok/err μεταφράζονται εδώ· τα τεχνικά
# διαγνωστικά { $err }/διαδρομής καταγραφής και οι ετικέτες σφαλμάτων IPC παραμένουν στα
# αγγλικά. Οι όροι επωνυμίας και οι τεχνικοί όροι (provcheck, provcheck-kit, Backfire,
# Mellin, C2PA, atproto, LOCALAPPDATA, BACKFIRE_PY, Yubikey, PIV PIN, DID, flags, ονόματα
# αρχείων) παραμένουν αυτούσιοι σε κάθε γλώσσα.

## Καρτέλα κλειδωμένης εικόνας Backfire (backfire_read + install_backfire).
backfire-read-needs-key = Απαιτείται κλειδί για την ανάγνωση μιας σήμανσης Backfire.
backfire-folder-unresolved = Δεν ήταν δυνατός ο προσδιορισμός εγγράψιμου φακέλου Backfire (το LOCALAPPDATA δεν έχει οριστεί).
backfire-ready-bundled = Το Backfire είναι έτοιμο (υπάρχει ενσωματωμένος αναγνώστης). Εισήγαγε ένα κλειδί και άφησε μια εικόνα.
backfire-files-missing = Δεν βρέθηκαν αρχεία Backfire προς εγκατάσταση. Επανεγκατέστησε το provcheck, ή όρισε το BACKFIRE_PY.
backfire-ready = Το Backfire είναι έτοιμο. Εισήγαγε ένα κλειδί και άφησε μια εικόνα.

## Καρτέλα κλειδωμένων σημάνσεων Mellin (mellin_read).
mellin-needs-secret-and-work-id = Απαιτούνται ένα αρχείο μυστικού και ένα work id για την ανάγνωση ενός σειριακού Mellin.
mellin-secret-file-missing = Το επιλεγμένο αρχείο μυστικού δεν υπάρχει (ή δεν είναι αναγνώσιμο).

## Καρτέλες Υπογραφής και Κλειδιών: ειδοποιήσεις ορίων δυνατοτήτων GUI που επιστρέφονται ως σφάλματα ApiResult.
identity-already-exists = υπάρχει ήδη μια ταυτότητα σε αυτόν τον κατάλογο δεδομένων· πέρασε force=true για αναδημιουργία (αυτό αφήνει ορφανές τυχόν προηγουμένως δημοσιευμένες εγγραφές atproto)
rotate-yubikey-unsupported = Η περιστροφή μέσω GUI μιας ταυτότητας βασισμένης σε Yubikey δεν υποστηρίζεται ακόμη. Εκτέλεσε `provcheck-kit init --yubikey --force` από τερματικό, και μετά επίστρεψε εδώ για δημοσίευση και ανάκληση.
rotate-agefile-unsupported = Η περιστροφή μέσω GUI ταυτοτήτων βασισμένων σε αρχείο age δεν έχει συνδεθεί ακόμη. Χρησιμοποίησε `provcheck-kit rotate` από τερματικό.
sign-keychain-only = Η υπογραφή μέσω GUI υποστηρίζει προς το παρόν μόνο ταυτότητες βασισμένες σε OS-keychain. Χρησιμοποίησε `provcheck-kit sign` από το CLI για ταυτότητες αρχείου age.
sign-yubikey-unsupported = Η υπογραφή μέσω GUI ταυτοτήτων βασισμένων σε Yubikey έρχεται στην v0.5.0 P3 + P4. Προς το παρόν, υπόγραψε μέσω `provcheck-kit sign` από τερματικό· το kit ζητά το PIV PIN σε κάθε υπογραφή.
