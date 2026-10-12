# provcheck-app GUI-viestit, suomi. Vain täydelliset käyttäjälle näkyvät lauseet, jotka
# palautetaan GUI:lle ApiResult ok/err -tekstinä, lokalisoidaan tässä; tekniset
# { $err }/lokipolkudiagnostiikat ja IPC-virhetunnisteet pysyvät englanniksi. Tuotemerkki-
# ja tekniset termit (provcheck, provcheck-kit, Backfire, Mellin, C2PA, atproto,
# LOCALAPPDATA, BACKFIRE_PY, Yubikey, PIV PIN, DID, liput, tiedostonimet) pysyvät
# sanatarkkoina jokaisessa kielessä.

## Backfire-välilehti (avainkoodattu kuva) (backfire_read + install_backfire).
backfire-read-needs-key = Backfire-merkin lukeminen vaatii avaimen.
backfire-folder-unresolved = Kirjoitettavaa Backfire-kansiota ei voitu määrittää (LOCALAPPDATA asettamatta).
backfire-ready-bundled = Backfire on valmis (mukana toimitettu lukija läsnä). Syötä avain ja pudota kuva.
backfire-files-missing = Asennettavia Backfire-tiedostoja ei löytynyt. Asenna provcheck uudelleen tai aseta BACKFIRE_PY.
backfire-ready = Backfire on valmis. Syötä avain ja pudota kuva.

## Mellinin avainkoodattujen merkkien välilehti (mellin_read).
mellin-needs-secret-and-work-id = Mellin-sarjanumeron lukeminen vaatii salaisuustiedoston ja työtunnuksen.
mellin-secret-file-missing = Valittua salaisuustiedostoa ei ole olemassa (tai se ei ole luettavissa).

## Allekirjoitus- ja avainvälilehdet: GUI:n ominaisuusrajoitusilmoitukset ApiResult-virheinä.
identity-already-exists = tässä datahakemistossa on jo identiteetti; anna force=true luodaksesi sen uudelleen (tämä jättää aiemmin julkaistut atproto-tietueet orvoiksi)
rotate-yubikey-unsupported = Yubikey-pohjaisen identiteetin kierrättäminen GUI:sta ei ole vielä tuettu. Suorita `provcheck-kit init --yubikey --force` päätteestä, ja palaa sitten tänne julkaisemaan ja mitätöimään.
rotate-agefile-unsupported = Age-tiedostopohjaisten identiteettien kierrättäminen GUI:sta ei ole vielä kytketty. Käytä komentoa `provcheck-kit rotate` päätteestä.
sign-keychain-only = GUI-allekirjoitus tukee tällä hetkellä vain käyttöjärjestelmän avainnipun identiteettejä. Käytä komentoa `provcheck-kit sign` CLI:stä age-tiedostoidentiteeteille.
sign-yubikey-unsupported = Yubikey-pohjaisten identiteettien GUI-allekirjoitus tulee versiossa v0.5.0 P3 + P4. Allekirjoita toistaiseksi komennolla `provcheck-kit sign` päätteestä; kit kysyy PIV PIN -koodia jokaisen allekirjoituksen yhteydessä.
