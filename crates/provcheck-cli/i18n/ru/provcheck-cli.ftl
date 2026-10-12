# provcheck-cli, вывод во время выполнения, русский. Только текст, предназначенный для
# чтения человеком; вывод --json и коды завершения никогда не локализуются. Заполнители
# { $name } подставляются в месте вызова; сохраняйте их без изменений в переводах. Названия
# брендов и технические термины (provcheck, C2PA, Backfire, Mellin, BUSL, Apache-2.0, JSON,
# PowerShell, bash, флаги, имена файлов) остаются дословными на любом языке.

## Блок криминалистического серийного номера Mellin для аудио (print_mellin_human).
mellin-header = Mellin (экспериментальный, ключевой криминалистический серийный номер аудио):
mellin-serial-full = серийный номер:   { $serial } (все 64 бита восстановлены, минимальное число битовых голосов { $votes })
mellin-serial-partial = серийный номер:   восстановлен не полностью ({ $bits }/64 бит, минимальное число битовых голосов { $votes })
mellin-erasures = стирания: { $pct }% позиций
mellin-expected-match = ожидается: СОВПАДЕНИЕ
mellin-expected-no-match = ожидается: НЕТ СОВПАДЕНИЯ

## Блок ключевого водяного знака изображения Backfire (print_backfire_human).
backfire-header = Backfire (экспериментальный, ключевой водяной знак изображения):
backfire-mark-valid = метка:   ДЕЙСТВИТЕЛЬНА (id { $id }, запас { $margin })
backfire-mark-none = метка:   не обнаружена (запас { $margin })
backfire-tamper-detected = вмешательство: ОБНАРУЖЕН BAND-NOTCH (статистика { $stat }) -- изображение, весьма вероятно, подверглось атаке notch
backfire-tamper-none = вмешательство: нет (статистика band-notch { $stat })

## Настройка Backfire (--install-backfire).
backfire-folder-not-found = provcheck: не удалось найти папку backfire. Установите BACKFIRE_PY в backfire.py, либо запустите из каталога, содержащего backfire/backfire.py.
backfire-ps1-not-found = provcheck: setup_backfire.ps1 не найден в { $dir }
backfire-sh-not-found = provcheck: setup_backfire.sh не найден в { $dir }
backfire-setup-start = Настройка среды чтения Backfire (однократно). Будет загружен автономный Python.
backfire-setup-ready = Backfire готов. Проверьте помеченное изображение с помощью:  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck: настройка Backfire завершилась со статусом { $status }
backfire-setup-run-failed = provcheck: не удалось запустить скрипт настройки Backfire ({ $err }). Требуется PowerShell в Windows или bash в Linux/macOS.

## Установка моделей (--install-models).
install-models-start = Установка { $count } файла(ов) модели обнаружения водяных знаков (всего { $mb } МБ).
install-models-item = { $family }/{ $variant } ({ $mb } МБ) ...
install-models-ok = ok
install-models-item-failed = ОШИБКА: { $err }
install-models-done = Все модели установлены. Обнаружение водяных знаков готово.
install-models-summary-failed = provcheck: не удалось установить { $count } модель(и) (см. выше).

## Основной путь проверки: ошибки, уведомления и подсказки.
require-attested-needs-identity = provcheck: --require-attested требует --bsky-handle, --did или --auto-identity
trust-store-read-failed = provcheck: не удалось прочитать хранилище доверия '{ $path }': { $err }
auto-identity-no-assertion = provcheck: запрошен --auto-identity, но файл не содержит утверждения app.provcheck.identity. Сначала подпишите с помощью `provcheck-kit sign --embed-identity`, либо укажите --bsky-handle / --did напрямую.
backfire-needs-key = provcheck: --backfire-read требует --backfire-key
backfire-experimental-notice = provcheck: Backfire является ЭКСПЕРИМЕНТАЛЬНЫМ и лицензирован по BUSL (бесплатен для некоммерческого использования), отдельно от ядра Apache-2.0. Он проверяет ключевую метку, которую вы внедрили, и обнаруживает вмешательство band-notch; устойчивость зависит от конкретного изображения.
backfire-read-failed = provcheck: чтение backfire не удалось: { $err }
mellin-needs-args = provcheck: --mellin-read требует --mellin-secret-file и --mellin-work-id
mellin-experimental-notice = provcheck: Mellin является ЭКСПЕРИМЕНТАЛЬНЫМ и лицензирован по BUSL (бесплатен для некоммерческого использования), отдельно от ядра Apache-2.0. Он читает ключевой серийный номер для каждой копии, который вы внедрили; без вашего секрета и идентификатора работы читать нечего.
mellin-read-failed = provcheck: чтение mellin не удалось: { $err }
json-serialize-failed = provcheck: не удалось сериализовать JSON: { $err }
hint-models-missing = [подсказка] { $count } модель(и) обнаружения водяных знаков не установлены, поэтому эти строки показывают "not installed". Включите полное обнаружение с помощью:  provcheck --install-models  (однократно, { $mb } МБ). Проверка C2PA их не требует.
hint-claims-identity = [подсказка] файл заявляет личность { $who }. Запустите снова с --auto-identity, чтобы проверить её по опубликованным записям ключей подписи.
