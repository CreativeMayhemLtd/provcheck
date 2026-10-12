# provcheck-cli-ajonaikainen tuloste, suomi. Vain ihmisluettava tuloste; --json-tuloste
# ja poistumiskoodit eivät koskaan lokalisoidu. Paikkamerkit { $name } täytetään
# kutsukohdassa; pidä ne muuttumattomina käännöksissä. Tuotemerkki- ja tekniset termit
# (provcheck, C2PA, Backfire, Mellin, BUSL, Apache-2.0, JSON, PowerShell, bash, liput,
# tiedostonimet) pysyvät sanatarkkoina jokaisessa kielessä.

## Mellin-lohko (avainkoodattu forensinen äänisarjanumero) (print_mellin_human).
mellin-header = Mellin (kokeellinen, avainkoodattu forensinen äänisarjanumero):
mellin-serial-full = sarjanumero:   { $serial } (kaikki 64 bittiä palautettu, vähimmäisäänet per bitti { $votes })
mellin-serial-partial = sarjanumero:   ei täysin palautettu ({ $bits }/64 bittiä, vähimmäisäänet per bitti { $votes })
mellin-erasures = pyyhkiytymät: { $pct } % sijainneista
mellin-expected-match = odotettu: TÄSMÄÄ
mellin-expected-no-match = odotettu: EI TÄSMÄÄ

## Backfire-lohko (avainkoodattu kuvan vesileima) (print_backfire_human).
backfire-header = Backfire (kokeellinen, avainkoodattu kuvan vesileima):
backfire-mark-valid = merkki:   KELVOLLINEN (id { $id }, marginaali { $margin })
backfire-mark-none = merkki:   ei havaittu (marginaali { $margin })
backfire-tamper-detected = peukalointi: KAISTANESTOHYÖKKÄYS HAVAITTU (tunnusluku { $stat }) -- kuvaan on hyvin todennäköisesti kohdistunut notch-hyökkäys
backfire-tamper-none = peukalointi: ei havaittu (kaistanestotunnusluku { $stat })

## Backfire-asennus (--install-backfire).
backfire-folder-not-found = provcheck: backfire-kansiota ei löytynyt. Aseta BACKFIRE_PY osoittamaan tiedostoon backfire.py, tai suorita hakemistosta, joka sisältää tiedoston backfire/backfire.py.
backfire-ps1-not-found = provcheck: tiedostoa setup_backfire.ps1 ei löytynyt hakemistosta { $dir }
backfire-sh-not-found = provcheck: tiedostoa setup_backfire.sh ei löytynyt hakemistosta { $dir }
backfire-setup-start = Backfiren lukuympäristöä asennetaan (kertaluonteinen toimenpide). Tämä lataa itsenäisen Python-asennuksen.
backfire-setup-ready = Backfire on valmis. Tarkista merkitty kuva komennolla:  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck: Backfire-asennus päättyi tilaan { $status }
backfire-setup-run-failed = provcheck: Backfire-asennusskriptiä ei voitu suorittaa ({ $err }). Se tarvitsee PowerShellin Windowsissa tai bashin Linuxissa/macOS:ssa.

## Mallien asennus (--install-models).
install-models-start = Asennetaan { $count } vesileiman tunnistusmallitiedostoa (yhteensä { $mb } Mt).
install-models-item = { $family }/{ $variant } ({ $mb } Mt) ...
install-models-ok = ok
install-models-item-failed = EPÄONNISTUI: { $err }
install-models-done = Kaikki mallit asennettu. Vesileiman tunnistus on valmis.
install-models-summary-failed = provcheck: { $count } mallin asennus epäonnistui (katso yllä).

## Päävarmennuspolku: virheet, ilmoitukset ja vihjeet.
require-attested-needs-identity = provcheck: --require-attested tarvitsee parametrin --bsky-handle, --did tai --auto-identity
trust-store-read-failed = provcheck: luottotietovarastoa '{ $path }' ei voitu lukea: { $err }
auto-identity-no-assertion = provcheck: --auto-identity pyydettiin, mutta tiedostossa ei ole app.provcheck.identity-väitettä. Allekirjoita ensin komennolla `provcheck-kit sign --embed-identity`, tai anna --bsky-handle / --did suoraan.
backfire-needs-key = provcheck: --backfire-read tarvitsee parametrin --backfire-key
backfire-experimental-notice = provcheck: Backfire on KOKEELLINEN ja BUSL-lisensoitu (ilmainen ei-kaupalliseen käyttöön), erillään Apache-2.0-ytimestä. Se tarkistaa upottamasi avainkoodatun merkin ja merkitsee kaistanestopeukaloinnin; kestävyys vaihtelee kuvakohtaisesti.
backfire-read-failed = provcheck: backfiren luku epäonnistui: { $err }
mellin-needs-args = provcheck: --mellin-read tarvitsee parametrit --mellin-secret-file ja --mellin-work-id
mellin-experimental-notice = provcheck: Mellin on KOKEELLINEN ja BUSL-lisensoitu (ilmainen ei-kaupalliseen käyttöön), erillään Apache-2.0-ytimestä. Se lukee upottamasi avainkoodatun kappalekohtaisen sarjanumeron; ilman salaisuuttasi ja työtunnustasi ei ole mitään luettavaa.
mellin-read-failed = provcheck: mellinin luku epäonnistui: { $err }
json-serialize-failed = provcheck: JSON-muotoon sarjallistaminen epäonnistui: { $err }
hint-models-missing = [vihje] { $count } vesileiman tunnistusmallia ei ole asennettu, joten kyseiset rivit näyttävät "not installed". Ota kaikki tunnistus käyttöön komennolla:  provcheck --install-models  (kertaluonteinen, { $mb } Mt). C2PA-varmennus ei tarvitse niitä.
hint-claims-identity = [vihje] tiedosto väittää identiteetiksi { $who }. Suorita uudelleen parametrilla --auto-identity varmentaaksesi sen heidän julkaistuja allekirjoitusavaintietojaan vasten.
