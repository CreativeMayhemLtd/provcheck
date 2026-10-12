# Salida en tiempo de ejecucion de provcheck-cli, espanol. Solo se localiza la salida
# legible por humanos; la salida --json y los codigos de salida nunca se localizan. Los
# marcadores { $name } se completan en el punto de llamada; mantenlos intactos en las
# traducciones. Los terminos de marca y tecnicos (provcheck, C2PA, Backfire, Mellin, BUSL,
# Apache-2.0, JSON, PowerShell, bash, flags, nombres de archivo) permanecen textuales en
# cada idioma.

## Bloque forense de audio con clave de Mellin (print_mellin_human).
mellin-header = Mellin (experimental, serial forense de audio con clave):
mellin-serial-full = serial:   { $serial } (los 64 bits recuperados, votos minimos de bit { $votes })
mellin-serial-partial = serial:   no recuperado por completo ({ $bits }/64 bits, votos minimos de bit { $votes })
mellin-erasures = borrados: { $pct }% de las posiciones
mellin-expected-match = esperado: COINCIDE
mellin-expected-no-match = esperado: NO COINCIDE

## Bloque de marca de agua de imagen con clave de Backfire (print_backfire_human).
backfire-header = Backfire (experimental, marca de agua de imagen con clave):
backfire-mark-valid = marca:   VALIDA (id { $id }, margen { $margin })
backfire-mark-none = marca:   no detectada (margen { $margin })
backfire-tamper-detected = manipulacion: NOTCH DE BANDA DETECTADO (estadistico { $stat }): es muy probable que la imagen haya sido atacada con un notch
backfire-tamper-none = manipulacion: ninguna (estadistico de notch de banda { $stat })

## Configuracion de Backfire (--install-backfire).
backfire-folder-not-found = provcheck: no se pudo localizar la carpeta de backfire. Define BACKFIRE_PY apuntando a backfire.py, o ejecuta desde un directorio que contenga backfire/backfire.py.
backfire-ps1-not-found = provcheck: no se encontro setup_backfire.ps1 en { $dir }
backfire-sh-not-found = provcheck: no se encontro setup_backfire.sh en { $dir }
backfire-setup-start = Configurando el entorno de lectura de Backfire (una sola vez). Esto descarga un Python autocontenido.
backfire-setup-ready = Backfire esta listo. Verifica una imagen marcada con:  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck: la configuracion de Backfire termino con estado { $status }
backfire-setup-run-failed = provcheck: no se pudo ejecutar el script de configuracion de Backfire ({ $err }). Necesita PowerShell en Windows, o bash en Linux/macOS.

## Instalacion de modelos (--install-models).
install-models-start = Instalando { $count } archivo(s) de modelo de deteccion de marca de agua ({ $mb } MB en total).
install-models-item = { $family }/{ $variant } ({ $mb } MB) ...
install-models-ok = ok
install-models-item-failed = FALLO: { $err }
install-models-done = Todos los modelos instalados. La deteccion de marca de agua esta lista.
install-models-summary-failed = provcheck: { $count } modelo(s) no se pudieron instalar (ver arriba).

## Ruta principal de verificacion: errores, avisos y sugerencias.
require-attested-needs-identity = provcheck: --require-attested necesita --bsky-handle, --did, o --auto-identity
trust-store-read-failed = provcheck: no se pudo leer el trust store '{ $path }': { $err }
auto-identity-no-assertion = provcheck: se solicito --auto-identity, pero el archivo no lleva ninguna aserticion app.provcheck.identity. Firma primero con `provcheck-kit sign --embed-identity`, o pasa --bsky-handle / --did directamente.
backfire-needs-key = provcheck: --backfire-read necesita --backfire-key
backfire-experimental-notice = provcheck: Backfire es EXPERIMENTAL y tiene licencia BUSL (gratis para uso no comercial), separado del nucleo Apache-2.0. Verifica una marca con clave que hayas incrustado y senala manipulacion por notch de banda; la robustez es especifica por imagen.
backfire-read-failed = provcheck: fallo la lectura de backfire: { $err }
mellin-needs-args = provcheck: --mellin-read necesita --mellin-secret-file y --mellin-work-id
mellin-experimental-notice = provcheck: Mellin es EXPERIMENTAL y tiene licencia BUSL (gratis para uso no comercial), separado del nucleo Apache-2.0. Lee un serial con clave por copia que hayas incrustado; sin tu secreto y tu work id no hay nada que leer.
mellin-read-failed = provcheck: fallo la lectura de mellin: { $err }
json-serialize-failed = provcheck: no se pudo serializar el JSON: { $err }
hint-models-missing = [sugerencia] { $count } modelo(s) de deteccion de marca de agua no estan instalados, por lo que esas lineas muestran "not installed". Activa toda la deteccion con:  provcheck --install-models  (una sola vez, { $mb } MB). La verificacion C2PA no los necesita.
hint-claims-identity = [sugerencia] el archivo reclama la identidad { $who }. Vuelve a ejecutar con --auto-identity para verificarla contra sus registros de clave de firma publicados.
