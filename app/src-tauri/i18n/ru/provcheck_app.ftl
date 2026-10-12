# provcheck-app, сообщения GUI, русский. Локализуются только полные предложения для
# пользователя, возвращаемые в GUI как текст ApiResult ok/err; технические диагностики
# { $err }/пути журнала и метки ошибок IPC остаются на английском. Названия брендов и
# технические термины (provcheck, provcheck-kit, Backfire, Mellin, C2PA, atproto,
# LOCALAPPDATA, BACKFIRE_PY, Yubikey, PIV PIN, DID, флаги, имена файлов) остаются
# дословными на любом языке.

## Вкладка ключевого водяного знака изображения Backfire (backfire_read + install_backfire).
backfire-read-needs-key = Для чтения метки Backfire требуется ключ.
backfire-folder-unresolved = Не удалось определить доступную для записи папку Backfire (LOCALAPPDATA не задана).
backfire-ready-bundled = Backfire готов (встроенное средство чтения присутствует). Введите ключ и перетащите изображение.
backfire-files-missing = Файлы Backfire для установки не найдены. Переустановите provcheck, либо задайте BACKFIRE_PY.
backfire-ready = Backfire готов. Введите ключ и перетащите изображение.

## Вкладка ключевых меток Mellin (mellin_read).
mellin-needs-secret-and-work-id = Для чтения серийного номера Mellin требуются файл секрета и идентификатор работы.
mellin-secret-file-missing = Выбранный файл секрета не существует (или недоступен для чтения).

## Вкладки Подписать и Ключи: уведомления GUI об ограничениях функциональности, возвращаемые как ошибки ApiResult.
identity-already-exists = в этом каталоге данных уже существует личность; передайте force=true, чтобы перегенерировать её (это лишает привязки все ранее опубликованные записи atproto)
rotate-yubikey-unsupported = Ротация личности на основе Yubikey в GUI пока не поддерживается. Запустите `provcheck-kit init --yubikey --force` в терминале, а затем вернитесь сюда, чтобы опубликовать и отозвать.
rotate-agefile-unsupported = Ротация личностей на основе age-файла в GUI пока не подключена. Используйте `provcheck-kit rotate` в терминале.
sign-keychain-only = Подписание в GUI в настоящее время поддерживает только личности из связки ключей ОС. Используйте `provcheck-kit sign` из командной строки для личностей на основе age-файла.
sign-yubikey-unsupported = Подписание личностей на основе Yubikey в GUI появится в v0.5.0 P3 + P4. Пока подписывайте через `provcheck-kit sign` в терминале — kit будет запрашивать PIV PIN при каждой подписи.
