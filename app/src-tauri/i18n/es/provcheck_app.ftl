# Mensajes de la GUI de provcheck-app, espanol. Solo se localizan aqui las oraciones
# completas orientadas al usuario devueltas a la GUI como texto ApiResult ok/err; los
# diagnosticos tecnicos { $err }/ruta de log y las etiquetas de error IPC permanecen en
# ingles. Los terminos de marca y tecnicos (provcheck, provcheck-kit, Backfire, Mellin,
# C2PA, atproto, LOCALAPPDATA, BACKFIRE_PY, Yubikey, PIV PIN, DID, flags, nombres de
# archivo) permanecen textuales en cada idioma.

## Pestana de imagen con clave de Backfire (backfire_read + install_backfire).
backfire-read-needs-key = Se requiere una clave para leer una marca de Backfire.
backfire-folder-unresolved = No se pudo resolver una carpeta de Backfire con permiso de escritura (LOCALAPPDATA no definido).
backfire-ready-bundled = Backfire esta listo (lector incluido presente). Ingresa una clave y suelta una imagen.
backfire-files-missing = No se encontraron archivos de Backfire para instalar. Reinstala provcheck, o define BACKFIRE_PY.
backfire-ready = Backfire esta listo. Ingresa una clave y suelta una imagen.

## Pestana de marcas con clave de Mellin (mellin_read).
mellin-needs-secret-and-work-id = Se requieren un archivo secreto y un work id para leer un serial de Mellin.
mellin-secret-file-missing = El archivo secreto elegido no existe (o no se puede leer).

## Pestanas Sign y Keys: avisos de limite de capacidad de la GUI devueltos como errores ApiResult.
identity-already-exists = ya existe una identidad en este directorio de datos; pasa force=true para regenerarla (esto deja huerfanos los registros atproto publicados previamente)
rotate-yubikey-unsupported = La rotacion desde la GUI de una identidad respaldada por Yubikey todavia no es compatible. Ejecuta `provcheck-kit init --yubikey --force` desde una terminal, y luego regresa aqui para publicar y revocar.
rotate-agefile-unsupported = La rotacion desde la GUI de identidades respaldadas por archivo age todavia no esta conectada. Usa `provcheck-kit rotate` desde una terminal.
sign-keychain-only = La firma desde la GUI actualmente solo admite identidades del llavero del sistema operativo. Usa `provcheck-kit sign` desde la CLI para identidades respaldadas por archivo age.
sign-yubikey-unsupported = La firma desde la GUI de identidades respaldadas por Yubikey llega en v0.5.0 P3 + P4. Por ahora, firma via `provcheck-kit sign` desde una terminal: el kit pide el PIN de PIV en cada firma.
