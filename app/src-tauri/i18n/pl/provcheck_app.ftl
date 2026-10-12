# provcheck-app, komunikaty GUI, polski. Lokalizowane są tylko pełne zdania zwracane do GUI
# jako tekst ok/err w ApiResult; techniczne diagnostyki { $err }/ścieżki dziennika oraz
# etykiety błędów IPC pozostają angielskie. Nazwy marek i terminy techniczne (provcheck,
# provcheck-kit, Backfire, Mellin, C2PA, atproto, LOCALAPPDATA, BACKFIRE_PY, Yubikey, PIV PIN,
# DID, flagi, nazwy plików) pozostają dosłowne w każdym języku.

## Zakładka klucza obrazu Backfire (backfire_read + install_backfire).
backfire-read-needs-key = Do odczytania znaku Backfire wymagany jest klucz.
backfire-folder-unresolved = Nie można ustalić zapisywalnego folderu Backfire (LOCALAPPDATA nie ustawione).
backfire-ready-bundled = Backfire jest gotowy (obecny dołączony czytnik). Wprowadź klucz i upuść obraz.
backfire-files-missing = Nie znaleziono plików Backfire do instalacji. Zainstaluj ponownie provcheck lub ustaw BACKFIRE_PY.
backfire-ready = Backfire jest gotowy. Wprowadź klucz i upuść obraz.

## Zakładka znaków kluczowanych Mellin (mellin_read).
mellin-needs-secret-and-work-id = Do odczytania numeru seryjnego Mellin wymagane są plik sekretu i identyfikator pracy.
mellin-secret-file-missing = Wybrany plik sekretu nie istnieje (lub nie jest czytelny).

## Zakładki Podpisz + Klucze: powiadomienia GUI o ograniczeniach funkcji zwracane jako błędy ApiResult.
identity-already-exists = w tym katalogu danych już istnieje tożsamość; przekaż force=true, aby ją ponownie wygenerować (to osieroca wszelkie wcześniej opublikowane rekordy atproto)
rotate-yubikey-unsupported = Rotacja tożsamości opartej na Yubikey w GUI nie jest jeszcze obsługiwana. Uruchom `provcheck-kit init --yubikey --force` w terminalu, a następnie wróć tutaj, aby opublikować i unieważnić.
rotate-agefile-unsupported = Rotacja tożsamości opartych na pliku age w GUI nie jest jeszcze podłączona. Użyj `provcheck-kit rotate` w terminalu.
sign-keychain-only = Podpisywanie w GUI obsługuje obecnie tylko tożsamości z pęku kluczy systemu operacyjnego. Użyj `provcheck-kit sign` z wiersza poleceń dla tożsamości opartych na pliku age.
sign-yubikey-unsupported = Podpisywanie w GUI tożsamości opartych na Yubikey pojawi się w v0.5.0 P3 + P4. Na razie podpisuj za pomocą `provcheck-kit sign` z terminala — kit poprosi o PIV PIN przy każdym podpisie.
