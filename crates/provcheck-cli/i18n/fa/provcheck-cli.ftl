# خروجی زمان اجرای provcheck-cli، فارسی (مرجع: انگلیسی). فقط خروجی قابل خواندن برای انسان
# ترجمه می‌شود؛ خروجی --json و کدهای خروج هرگز بومی‌سازی نمی‌شوند. جای‌نگهدارهای { $name }
# در محل فراخوانی پر می‌شوند؛ آن‌ها را در ترجمه‌ها دست‌نخورده نگه دارید. اصطلاحات تجاری و فنی
# (provcheck، C2PA، Backfire، Mellin، BUSL، Apache-2.0، JSON، PowerShell، bash، flags، نام
# فایل‌ها) در هر زبان بدون تغییر باقی می‌مانند.

## بلوک قضایی صوتی کلیددار Mellin (print_mellin_human).
mellin-header = Mellin (آزمایشی، شماره سریال قضایی صوتی کلیددار):
mellin-serial-full = سریال:   { $serial } (هر 64 بیت بازیابی شد، حداقل رأی بیت { $votes })
mellin-serial-partial = سریال:   به‌طور کامل بازیابی نشد ({ $bits }/64 بیت، حداقل رأی بیت { $votes })
mellin-erasures = پاک‌شدگی: { $pct }% از موقعیت‌ها
mellin-expected-match = مورد انتظار: تطابق
mellin-expected-no-match = مورد انتظار: عدم تطابق

## بلوک واترمارک تصویر کلیددار Backfire (print_backfire_human).
backfire-header = Backfire (آزمایشی، واترمارک تصویر کلیددار):
backfire-mark-valid = نشان:   معتبر (شناسه { $id }، حاشیه { $margin })
backfire-mark-none = نشان:   شناسایی نشد (حاشیه { $margin })
backfire-tamper-detected = دستکاری: شکاف باند (band-notch) شناسایی شد (آماره { $stat }) -- به احتمال زیاد تصویر مورد حمله شکاف باند قرار گرفته است
backfire-tamper-none = دستکاری: هیچ (آماره شکاف باند { $stat })

## راه‌اندازی Backfire (--install-backfire).
backfire-folder-not-found = provcheck: پوشه backfire یافت نشد. BACKFIRE_PY را روی backfire.py تنظیم کنید، یا از دایرکتوری حاوی backfire/backfire.py اجرا کنید.
backfire-ps1-not-found = provcheck: setup_backfire.ps1 در { $dir } یافت نشد
backfire-sh-not-found = provcheck: setup_backfire.sh در { $dir } یافت نشد
backfire-setup-start = محیط خواندن Backfire در حال راه‌اندازی است (یک‌بار). این کار یک پایتون مستقل را دانلود می‌کند.
backfire-setup-ready = Backfire آماده است. یک تصویر نشان‌دار را با این دستور تأیید کنید:  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck: راه‌اندازی Backfire با وضعیت { $status } پایان یافت
backfire-setup-run-failed = provcheck: اجرای اسکریپت راه‌اندازی Backfire ممکن نشد ({ $err }). به PowerShell در Windows یا bash در Linux/macOS نیاز دارد.

## نصب مدل‌ها (--install-models).
install-models-start = در حال نصب { $count } فایل مدل تشخیص واترمارک (مجموعاً { $mb } مگابایت).
install-models-item = { $family }/{ $variant } ({ $mb } مگابایت) ...
install-models-ok = انجام شد
install-models-item-failed = ناموفق: { $err }
install-models-done = همه مدل‌ها نصب شدند. تشخیص واترمارک آماده است.
install-models-summary-failed = provcheck: نصب { $count } مدل ناموفق بود (به بالا مراجعه کنید).

## مسیر اصلی تأیید: خطاها، اعلان‌ها و راهنمایی‌ها.
require-attested-needs-identity = provcheck: --require-attested به --bsky-handle، --did یا --auto-identity نیاز دارد
trust-store-read-failed = provcheck: خواندن مخزن اعتماد '{ $path }' ممکن نشد: { $err }
auto-identity-no-assertion = provcheck: --auto-identity درخواست شد اما فایل حاوی هیچ ادعای app.provcheck.identity نیست. ابتدا با `provcheck-kit sign --embed-identity` امضا کنید، یا --bsky-handle / --did را مستقیماً وارد کنید.
backfire-needs-key = provcheck: --backfire-read به --backfire-key نیاز دارد
backfire-experimental-notice = provcheck: Backfire آزمایشی و دارای مجوز BUSL است (رایگان برای استفاده غیرتجاری)، جدا از هسته Apache-2.0. این ابزار نشان کلیدداری را که جاسازی کرده‌اید تأیید می‌کند و دستکاری شکاف باند را گزارش می‌دهد؛ استحکام آن به تصویر بستگی دارد.
backfire-read-failed = provcheck: خواندن backfire ناموفق بود: { $err }
mellin-needs-args = provcheck: --mellin-read به --mellin-secret-file و --mellin-work-id نیاز دارد
mellin-experimental-notice = provcheck: Mellin آزمایشی و دارای مجوز BUSL است (رایگان برای استفاده غیرتجاری)، جدا از هسته Apache-2.0. این ابزار شماره سریال کلیددار هر نسخه را که جاسازی کرده‌اید می‌خواند؛ بدون کلید مخفی و شناسه کار شما چیزی برای خواندن وجود ندارد.
mellin-read-failed = provcheck: خواندن mellin ناموفق بود: { $err }
json-serialize-failed = provcheck: سریال‌سازی JSON ناموفق بود: { $err }
hint-models-missing = [راهنمایی] { $count } مدل تشخیص واترمارک نصب نشده‌اند، بنابراین این خطوط "not installed" را نشان می‌دهند. تشخیص کامل را با این دستور فعال کنید:  provcheck --install-models  (یک‌بار، { $mb } مگابایت). تأیید C2PA به آن‌ها نیازی ندارد.
hint-claims-identity = [راهنمایی] فایل ادعای هویت { $who } را دارد. برای تأیید آن در برابر سوابق کلید امضای منتشرشده، دوباره با --auto-identity اجرا کنید.
