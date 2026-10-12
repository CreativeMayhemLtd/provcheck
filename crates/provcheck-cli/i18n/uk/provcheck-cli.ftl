# provcheck-cli, вивід під час виконання, українська. Лише текст, призначений для читання
# людиною; вивід --json і коди завершення ніколи не локалізуються. Заповнювачі { $name }
# підставляються в місці виклику; зберігайте їх без змін у перекладах. Назви брендів і
# технічні терміни (provcheck, C2PA, Backfire, Mellin, BUSL, Apache-2.0, JSON, PowerShell,
# bash, прапорці, імена файлів) залишаються дослівними в кожній мові.

## Блок криміналістичного серійного номера Mellin для аудіо (print_mellin_human).
mellin-header = Mellin (експериментальний, ключований криміналістичний серійний номер аудіо):
mellin-serial-full = серійний номер:   { $serial } (усі 64 біти відновлено, мінімальна кількість бітових голосів { $votes })
mellin-serial-partial = серійний номер:   відновлено не повністю ({ $bits }/64 бітів, мінімальна кількість бітових голосів { $votes })
mellin-erasures = стирання: { $pct }% позицій
mellin-expected-match = очікується: ЗБІГ
mellin-expected-no-match = очікується: НЕМАЄ ЗБІГУ

## Блок ключованого водяного знака зображення Backfire (print_backfire_human).
backfire-header = Backfire (експериментальний, ключований водяний знак зображення):
backfire-mark-valid = знак:   ДІЙСНИЙ (id { $id }, запас { $margin })
backfire-mark-none = знак:   не виявлено (запас { $margin })
backfire-tamper-detected = втручання: ВИЯВЛЕНО BAND-NOTCH (статистика { $stat }) -- зображення, найімовірніше, зазнало атаки notch
backfire-tamper-none = втручання: немає (статистика band-notch { $stat })

## Налаштування Backfire (--install-backfire).
backfire-folder-not-found = provcheck: не вдалося знайти папку backfire. Встановіть BACKFIRE_PY на backfire.py, або запустіть з каталогу, що містить backfire/backfire.py.
backfire-ps1-not-found = provcheck: setup_backfire.ps1 не знайдено в { $dir }
backfire-sh-not-found = provcheck: setup_backfire.sh не знайдено в { $dir }
backfire-setup-start = Налаштування середовища читання Backfire (одноразово). Це завантажить автономний Python.
backfire-setup-ready = Backfire готовий. Перевірте позначене зображення за допомогою:  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck: налаштування Backfire завершилося зі статусом { $status }
backfire-setup-run-failed = provcheck: не вдалося запустити скрипт налаштування Backfire ({ $err }). Потрібен PowerShell у Windows або bash у Linux/macOS.

## Встановлення моделей (--install-models).
install-models-start = Встановлення { $count } файлу(ів) моделі виявлення водяних знаків (загалом { $mb } МБ).
install-models-item = { $family }/{ $variant } ({ $mb } МБ) ...
install-models-ok = ok
install-models-item-failed = ПОМИЛКА: { $err }
install-models-done = Усі моделі встановлено. Виявлення водяних знаків готове.
install-models-summary-failed = provcheck: не вдалося встановити { $count } модель(і) (див. вище).

## Основний шлях перевірки: помилки, повідомлення та підказки.
require-attested-needs-identity = provcheck: --require-attested потребує --bsky-handle, --did або --auto-identity
trust-store-read-failed = provcheck: не вдалося прочитати сховище довіри '{ $path }': { $err }
auto-identity-no-assertion = provcheck: було запитано --auto-identity, але файл не містить твердження app.provcheck.identity. Спочатку підпишіть за допомогою `provcheck-kit sign --embed-identity`, або вкажіть безпосередньо --bsky-handle / --did.
backfire-needs-key = provcheck: --backfire-read потребує --backfire-key
backfire-experimental-notice = provcheck: Backfire є ЕКСПЕРИМЕНТАЛЬНИМ і ліцензований за BUSL (безкоштовний для некомерційного використання), окремо від ядра Apache-2.0. Він перевіряє ключований знак, який ви вбудували, і виявляє втручання band-notch; стійкість залежить від конкретного зображення.
backfire-read-failed = provcheck: читання backfire не вдалося: { $err }
mellin-needs-args = provcheck: --mellin-read потребує --mellin-secret-file і --mellin-work-id
mellin-experimental-notice = provcheck: Mellin є ЕКСПЕРИМЕНТАЛЬНИМ і ліцензований за BUSL (безкоштовний для некомерційного використання), окремо від ядра Apache-2.0. Він читає ключований серійний номер для кожної копії, який ви вбудували; без вашого секрету та ідентифікатора роботи читати нічого.
mellin-read-failed = provcheck: читання mellin не вдалося: { $err }
json-serialize-failed = provcheck: не вдалося серіалізувати JSON: { $err }
hint-models-missing = [підказка] { $count } модель(і) виявлення водяних знаків не встановлено, тому ці рядки показують "not installed". Увімкніть повне виявлення за допомогою:  provcheck --install-models  (одноразово, { $mb } МБ). Перевірка C2PA їх не потребує.
hint-claims-identity = [підказка] файл заявляє особу { $who }. Запустіть знову з --auto-identity, щоб перевірити її за опублікованими записами ключів підпису.
