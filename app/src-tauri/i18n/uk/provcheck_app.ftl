# provcheck-app, повідомлення GUI, українська. Локалізуються лише повні речення для
# користувача, що повертаються до GUI як текст ApiResult ok/err; технічні діагностики
# { $err }/шляхи журналу та мітки помилок IPC залишаються англійською. Назви брендів і
# технічні терміни (provcheck, provcheck-kit, Backfire, Mellin, C2PA, atproto, LOCALAPPDATA,
# BACKFIRE_PY, Yubikey, PIV PIN, DID, прапорці, імена файлів) залишаються дослівними в
# кожній мові.

## Вкладка ключованого водяного знака зображення Backfire (backfire_read + install_backfire).
backfire-read-needs-key = Для читання знака Backfire потрібен ключ.
backfire-folder-unresolved = Не вдалося визначити придатну для запису папку Backfire (LOCALAPPDATA не встановлено).
backfire-ready-bundled = Backfire готовий (наявний вбудований засіб читання). Введіть ключ і перетягніть зображення.
backfire-files-missing = Файли Backfire для встановлення не знайдено. Перевстановіть provcheck, або встановіть BACKFIRE_PY.
backfire-ready = Backfire готовий. Введіть ключ і перетягніть зображення.

## Вкладка ключованих знаків Mellin (mellin_read).
mellin-needs-secret-and-work-id = Для читання серійного номера Mellin потрібні файл секрету та ідентифікатор роботи.
mellin-secret-file-missing = Обраний файл секрету не існує (або є нечитабельним).

## Вкладки Підписати та Ключі: повідомлення GUI про обмеження функцій, що повертаються як помилки ApiResult.
identity-already-exists = у цьому каталозі даних уже існує особистість; передайте force=true, щоб перегенерувати її (це залишить без прив'язки всі раніше опубліковані записи atproto)
rotate-yubikey-unsupported = Ротація особистості на основі Yubikey в GUI ще не підтримується. Запустіть `provcheck-kit init --yubikey --force` у терміналі, а потім поверніться сюди, щоб опублікувати та відкликати.
rotate-agefile-unsupported = Ротація особистостей на основі age-файлу в GUI ще не підключена. Використайте `provcheck-kit rotate` у терміналі.
sign-keychain-only = Підписування в GUI наразі підтримує лише особистості зі сховища ключів ОС. Використайте `provcheck-kit sign` з CLI для особистостей на основі age-файлу.
sign-yubikey-unsupported = Підписування особистостей на основі Yubikey в GUI з'явиться у v0.5.0 P3 + P4. Наразі підписуйте через `provcheck-kit sign` у терміналі — kit запитуватиме PIV PIN при кожному підписі.
