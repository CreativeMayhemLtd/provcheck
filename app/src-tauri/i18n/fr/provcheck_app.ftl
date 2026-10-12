# Messages GUI de provcheck-app, francais. Seules les phrases completes destinees a
# l'utilisateur, renvoyees a la GUI en texte ApiResult ok/err, sont localisees ici ; les
# diagnostics techniques { $err }/chemin de log et les libelles d'erreur IPC restent en
# anglais. Les termes de marque et techniques (provcheck, provcheck-kit, Backfire,
# Mellin, C2PA, atproto, LOCALAPPDATA, BACKFIRE_PY, Yubikey, PIV PIN, DID, flags, noms
# de fichiers) restent textuels dans chaque langue.

## Onglet image chiffree Backfire (backfire_read + install_backfire).
backfire-read-needs-key = Une cle est requise pour lire une marque Backfire.
backfire-folder-unresolved = Impossible de resoudre un dossier Backfire accessible en ecriture (LOCALAPPDATA non defini).
backfire-ready-bundled = Backfire est pret (lecteur integre present). Saisissez une cle et deposez une image.
backfire-files-missing = Fichiers Backfire introuvables pour l'installation. Reinstallez provcheck, ou definissez BACKFIRE_PY.
backfire-ready = Backfire est pret. Saisissez une cle et deposez une image.

## Onglet marques chiffrees Mellin (mellin_read).
mellin-needs-secret-and-work-id = Un fichier secret et un work id sont requis pour lire un numero de serie Mellin.
mellin-secret-file-missing = Le fichier secret choisi n'existe pas (ou n'est pas lisible).

## Onglets Sign et Keys : avis de limite de capacite de la GUI renvoyes comme erreurs ApiResult.
identity-already-exists = une identite existe deja dans ce repertoire de donnees ; passez force=true pour la regenerer (cela rend orphelins tous les enregistrements atproto publies precedemment)
rotate-yubikey-unsupported = La rotation depuis la GUI d'une identite adossee a une Yubikey n'est pas encore prise en charge. Executez `provcheck-kit init --yubikey --force` depuis un terminal, puis revenez ici pour publier et revoquer.
rotate-agefile-unsupported = La rotation depuis la GUI des identites adossees a un fichier age n'est pas encore cablee. Utilisez `provcheck-kit rotate` depuis un terminal.
sign-keychain-only = La signature depuis la GUI ne prend actuellement en charge que les identites du trousseau du systeme d'exploitation. Utilisez `provcheck-kit sign` depuis la CLI pour les identites adossees a un fichier age.
sign-yubikey-unsupported = La signature depuis la GUI des identites adossees a une Yubikey arrive en v0.5.0 P3 + P4. Pour l'instant, signez via `provcheck-kit sign` depuis un terminal : le kit demande le PIN PIV a chaque signature.
