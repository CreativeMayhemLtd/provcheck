# Sortie d'execution de provcheck-cli, francais. Seule la sortie lisible par un humain
# est localisee ; la sortie --json et les codes de sortie ne sont jamais localises. Les
# espaces reserves { $name } sont remplis au point d'appel ; conservez-les intacts dans
# les traductions. Les termes de marque et techniques (provcheck, C2PA, Backfire, Mellin,
# BUSL, Apache-2.0, JSON, PowerShell, bash, flags, noms de fichiers) restent textuels
# dans chaque langue.

## Bloc forensique audio chiffre de Mellin (print_mellin_human).
mellin-header = Mellin (experimental, numero de serie forensique audio chiffre) :
mellin-serial-full = numero de serie :   { $serial } (64 bits recuperes, votes de bit minimum { $votes })
mellin-serial-partial = numero de serie :   pas entierement recupere ({ $bits }/64 bits, votes de bit minimum { $votes })
mellin-erasures = effacements : { $pct }% des positions
mellin-expected-match = attendu : CORRESPOND
mellin-expected-no-match = attendu : NE CORRESPOND PAS

## Bloc de filigrane d'image chiffre de Backfire (print_backfire_human).
backfire-header = Backfire (experimental, filigrane d'image chiffre) :
backfire-mark-valid = marque :   VALIDE (id { $id }, marge { $margin })
backfire-mark-none = marque :   non detectee (marge { $margin })
backfire-tamper-detected = alteration : ENCOCHE DE BANDE DETECTEE (statistique { $stat }) : l'image a tres probablement subi une attaque par encoche
backfire-tamper-none = alteration : aucune (statistique d'encoche de bande { $stat })

## Configuration de Backfire (--install-backfire).
backfire-folder-not-found = provcheck : impossible de localiser le dossier backfire. Definissez BACKFIRE_PY vers backfire.py, ou lancez depuis un repertoire contenant backfire/backfire.py.
backfire-ps1-not-found = provcheck : setup_backfire.ps1 introuvable dans { $dir }
backfire-sh-not-found = provcheck : setup_backfire.sh introuvable dans { $dir }
backfire-setup-start = Configuration de l'environnement de lecture Backfire (une seule fois). Ceci telecharge un Python autonome.
backfire-setup-ready = Backfire est pret. Verifiez une image marquee avec :  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck : la configuration de Backfire s'est terminee avec le statut { $status }
backfire-setup-run-failed = provcheck : impossible d'executer le script de configuration Backfire ({ $err }). Il necessite PowerShell sous Windows, ou bash sous Linux/macOS.

## Installation des modeles (--install-models).
install-models-start = Installation de { $count } fichier(s) de modele de detection de filigrane ({ $mb } Mo au total).
install-models-item = { $family }/{ $variant } ({ $mb } Mo) ...
install-models-ok = ok
install-models-item-failed = ECHEC : { $err }
install-models-done = Tous les modeles sont installes. La detection de filigrane est prete.
install-models-summary-failed = provcheck : { $count } modele(s) n'ont pas pu etre installes (voir ci-dessus).

## Chemin principal de verification : erreurs, avis et conseils.
require-attested-needs-identity = provcheck : --require-attested necessite --bsky-handle, --did, ou --auto-identity
trust-store-read-failed = provcheck : impossible de lire le trust store '{ $path }' : { $err }
auto-identity-no-assertion = provcheck : --auto-identity a ete demande, mais le fichier ne porte aucune assertion app.provcheck.identity. Signez d'abord avec `provcheck-kit sign --embed-identity`, ou passez --bsky-handle / --did directement.
backfire-needs-key = provcheck : --backfire-read necessite --backfire-key
backfire-experimental-notice = provcheck : Backfire est EXPERIMENTAL et sous licence BUSL (gratuit pour un usage non commercial), separe du coeur Apache-2.0. Il verifie une marque chiffree que vous avez integree et signale les alterations par encoche de bande ; la robustesse depend de chaque image.
backfire-read-failed = provcheck : echec de la lecture backfire : { $err }
mellin-needs-args = provcheck : --mellin-read necessite --mellin-secret-file et --mellin-work-id
mellin-experimental-notice = provcheck : Mellin est EXPERIMENTAL et sous licence BUSL (gratuit pour un usage non commercial), separe du coeur Apache-2.0. Il lit un numero de serie chiffre par copie que vous avez integre ; sans votre secret et votre work id, il n'y a rien a lire.
mellin-read-failed = provcheck : echec de la lecture mellin : { $err }
json-serialize-failed = provcheck : echec de la serialisation JSON : { $err }
hint-models-missing = [conseil] { $count } modele(s) de detection de filigrane ne sont pas installes, ces lignes affichent donc "not installed". Activez toute la detection avec :  provcheck --install-models  (une seule fois, { $mb } Mo). La verification C2PA n'en a pas besoin.
hint-claims-identity = [conseil] le fichier revendique l'identite { $who }. Relancez avec --auto-identity pour la verifier par rapport a ses enregistrements de cle de signature publies.
