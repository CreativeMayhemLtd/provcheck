# provcheck-cli, výstup za běhu, čeština. Pouze čitelný textový výstup pro člověka;
# výstup --json a návratové kódy nejsou nikdy lokalizovány. Zástupné symboly { $name }
# jsou doplněny v místě volání; v překladech je zachovejte beze změny. Značky a technické
# výrazy (provcheck, C2PA, Backfire, Mellin, BUSL, Apache-2.0, JSON, PowerShell, bash,
# přepínače, názvy souborů) zůstávají doslovné v každém jazyce.

## Blok forenzního sériového čísla audia Mellin (print_mellin_human).
mellin-header = Mellin (experimentální, klíčované forenzní sériové číslo audia):
mellin-serial-full = sériové číslo:   { $serial } (všech 64 bitů obnoveno, minimální počet bitových hlasů { $votes })
mellin-serial-partial = sériové číslo:   nebylo plně obnoveno ({ $bits }/64 bitů, minimální počet bitových hlasů { $votes })
mellin-erasures = výmazy: { $pct }% pozic
mellin-expected-match = očekáváno: SHODA
mellin-expected-no-match = očekáváno: BEZ SHODY

## Blok klíčovaného obrazového vodoznaku Backfire (print_backfire_human).
backfire-header = Backfire (experimentální, klíčovaný obrazový vodoznak):
backfire-mark-valid = značka:   PLATNÁ (id { $id }, marže { $margin })
backfire-mark-none = značka:   nezjištěna (marže { $margin })
backfire-tamper-detected = neoprávněný zásah: ZJIŠTĚN BAND-NOTCH (statistika { $stat }) -- obrázek byl velmi pravděpodobně napaden metodou notch
backfire-tamper-none = neoprávněný zásah: žádný (statistika band-notch { $stat })

## Nastavení Backfire (--install-backfire).
backfire-folder-not-found = provcheck: nelze najít složku backfire. Nastavte BACKFIRE_PY na backfire.py, nebo spusťte z adresáře obsahujícího backfire/backfire.py.
backfire-ps1-not-found = provcheck: soubor setup_backfire.ps1 nebyl nalezen v { $dir }
backfire-sh-not-found = provcheck: soubor setup_backfire.sh nebyl nalezen v { $dir }
backfire-setup-start = Nastavuje se čtecí prostředí Backfire (jednorázově). Stáhne se samostatný Python.
backfire-setup-ready = Backfire je připraven. Ověřte označený obrázek pomocí:  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck: nastavení Backfire skončilo se stavem { $status }
backfire-setup-run-failed = provcheck: nepodařilo se spustit instalační skript Backfire ({ $err }). Vyžaduje PowerShell na Windows nebo bash na Linuxu/macOS.

## Instalace modelů (--install-models).
install-models-start = Instaluje se { $count } soubor(ů) modelu pro detekci vodoznaků (celkem { $mb } MB).
install-models-item = { $family }/{ $variant } ({ $mb } MB) ...
install-models-ok = ok
install-models-item-failed = SELHALO: { $err }
install-models-done = Všechny modely nainstalovány. Detekce vodoznaků je připravena.
install-models-summary-failed = provcheck: instalace { $count } modelu/modelů selhala (viz výše).

## Hlavní cesta ověření: chyby, upozornění a rady.
require-attested-needs-identity = provcheck: --require-attested vyžaduje --bsky-handle, --did nebo --auto-identity
trust-store-read-failed = provcheck: nelze číst úložiště důvěry '{ $path }': { $err }
auto-identity-no-assertion = provcheck: bylo požadováno --auto-identity, ale soubor neobsahuje tvrzení app.provcheck.identity. Nejprve podepište pomocí `provcheck-kit sign --embed-identity`, nebo zadejte přímo --bsky-handle / --did.
backfire-needs-key = provcheck: --backfire-read vyžaduje --backfire-key
backfire-experimental-notice = provcheck: Backfire je EXPERIMENTÁLNÍ a licencovaný pod BUSL (zdarma pro nekomerční použití), oddělený od jádra Apache-2.0. Ověřuje klíčovanou značku, kterou jste vložili, a hlásí manipulaci band-notch; odolnost závisí na konkrétním obrázku.
backfire-read-failed = provcheck: čtení backfire se nezdařilo: { $err }
mellin-needs-args = provcheck: --mellin-read vyžaduje --mellin-secret-file a --mellin-work-id
mellin-experimental-notice = provcheck: Mellin je EXPERIMENTÁLNÍ a licencovaný pod BUSL (zdarma pro nekomerční použití), oddělený od jádra Apache-2.0. Čte klíčované sériové číslo pro jednotlivou kopii, které jste vložili; bez vašeho tajného klíče a ID zakázky není co číst.
mellin-read-failed = provcheck: čtení mellin se nezdařilo: { $err }
json-serialize-failed = provcheck: serializace JSON se nezdařila: { $err }
hint-models-missing = [rada] { $count } model(ů) pro detekci vodoznaků není nainstalováno, proto tyto řádky zobrazují "not installed". Zapněte úplnou detekci pomocí:  provcheck --install-models  (jednorázově, { $mb } MB). Ověření C2PA je nepotřebuje.
hint-claims-identity = [rada] soubor deklaruje identitu { $who }. Spusťte znovu s --auto-identity a ověřte ji proti zveřejněným záznamům podpisových klíčů.
