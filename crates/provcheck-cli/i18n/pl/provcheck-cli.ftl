# provcheck-cli, wynik działania w czasie wykonania, polski. Tylko czytelny dla człowieka
# tekst wyjściowy; wyjście --json i kody wyjścia nigdy nie są lokalizowane. Symbole zastępcze
# { $name } są wypełniane w miejscu wywołania; zachowaj je bez zmian w tłumaczeniach. Nazwy
# marek i terminy techniczne (provcheck, C2PA, Backfire, Mellin, BUSL, Apache-2.0, JSON,
# PowerShell, bash, flagi, nazwy plików) pozostają dosłowne w każdym języku.

## Blok kryminalistyczny Mellin dla klucza audio (print_mellin_human).
mellin-header = Mellin (eksperymentalne, kluczowany kryminalistyczny numer seryjny audio):
mellin-serial-full = numer seryjny:   { $serial } (wszystkie 64 bity odzyskane, minimalna liczba głosów bitowych { $votes })
mellin-serial-partial = numer seryjny:   nie odzyskano w pełni ({ $bits }/64 bitów, minimalna liczba głosów bitowych { $votes })
mellin-erasures = usunięcia: { $pct }% pozycji
mellin-expected-match = oczekiwano: ZGODNOŚĆ
mellin-expected-no-match = oczekiwano: BRAK ZGODNOŚCI

## Blok znaku wodnego obrazu Backfire (print_backfire_human).
backfire-header = Backfire (eksperymentalne, kluczowany znak wodny obrazu):
backfire-mark-valid = znak:   WAŻNY (id { $id }, margines { $margin })
backfire-mark-none = znak:   nie wykryto (margines { $margin })
backfire-tamper-detected = manipulacja: WYKRYTO BAND-NOTCH (statystyka { $stat }) -- obraz najprawdopodobniej został zaatakowany metodą notch
backfire-tamper-none = manipulacja: brak (statystyka band-notch { $stat })

## Konfiguracja Backfire (--install-backfire).
backfire-folder-not-found = provcheck: nie można zlokalizować folderu backfire. Ustaw BACKFIRE_PY na backfire.py lub uruchom z katalogu zawierającego backfire/backfire.py.
backfire-ps1-not-found = provcheck: nie znaleziono setup_backfire.ps1 w { $dir }
backfire-sh-not-found = provcheck: nie znaleziono setup_backfire.sh w { $dir }
backfire-setup-start = Konfigurowanie środowiska odczytu Backfire (jednorazowo). Spowoduje to pobranie samodzielnej instalacji Pythona.
backfire-setup-ready = Backfire jest gotowy. Zweryfikuj oznaczony obraz za pomocą:  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck: konfiguracja Backfire zakończyła się statusem { $status }
backfire-setup-run-failed = provcheck: nie udało się uruchomić skryptu konfiguracyjnego Backfire ({ $err }). Wymaga PowerShell w systemie Windows lub bash w Linux/macOS.

## Instalacja modeli (--install-models).
install-models-start = Instalowanie { $count } pliku(ów) modelu wykrywania znaków wodnych (łącznie { $mb } MB).
install-models-item = { $family }/{ $variant } ({ $mb } MB) ...
install-models-ok = ok
install-models-item-failed = NIEPOWODZENIE: { $err }
install-models-done = Wszystkie modele zainstalowane. Wykrywanie znaków wodnych jest gotowe.
install-models-summary-failed = provcheck: nie udało się zainstalować { $count } modelu/modeli (patrz powyżej).

## Główna ścieżka weryfikacji: błędy, powiadomienia i wskazówki.
require-attested-needs-identity = provcheck: --require-attested wymaga --bsky-handle, --did lub --auto-identity
trust-store-read-failed = provcheck: nie można odczytać magazynu zaufania '{ $path }': { $err }
auto-identity-no-assertion = provcheck: zażądano --auto-identity, ale plik nie zawiera asercji app.provcheck.identity. Najpierw podpisz za pomocą `provcheck-kit sign --embed-identity` lub podaj bezpośrednio --bsky-handle / --did.
backfire-needs-key = provcheck: --backfire-read wymaga --backfire-key
backfire-experimental-notice = provcheck: Backfire jest EKSPERYMENTALNY i licencjonowany na zasadach BUSL (bezpłatny do użytku niekomercyjnego), oddzielny od rdzenia Apache-2.0. Weryfikuje kluczowany znak, który osadziłeś, i zgłasza manipulacje band-notch; odporność zależy od obrazu.
backfire-read-failed = provcheck: odczyt backfire nie powiódł się: { $err }
mellin-needs-args = provcheck: --mellin-read wymaga --mellin-secret-file i --mellin-work-id
mellin-experimental-notice = provcheck: Mellin jest EKSPERYMENTALNY i licencjonowany na zasadach BUSL (bezpłatny do użytku niekomercyjnego), oddzielny od rdzenia Apache-2.0. Odczytuje kluczowany numer seryjny dla każdej kopii, który osadziłeś; bez twojego sekretu i identyfikatora pracy nie ma nic do odczytania.
mellin-read-failed = provcheck: odczyt mellin nie powiódł się: { $err }
json-serialize-failed = provcheck: nie udało się zserializować JSON: { $err }
hint-models-missing = [wskazówka] { $count } model(e/i) wykrywania znaków wodnych nie jest zainstalowanych, więc te wiersze pokazują "not installed". Włącz pełne wykrywanie za pomocą:  provcheck --install-models  (jednorazowo, { $mb } MB). Weryfikacja C2PA ich nie wymaga.
hint-claims-identity = [wskazówka] plik deklaruje tożsamość { $who }. Uruchom ponownie z --auto-identity, aby zweryfikować ją względem opublikowanych rekordów kluczy podpisujących.
