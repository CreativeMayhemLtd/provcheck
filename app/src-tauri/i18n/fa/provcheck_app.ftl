# پیام‌های رابط کاربری provcheck-app، فارسی (مرجع: انگلیسی). فقط جملات کامل رو به کاربر که
# به‌صورت متن ApiResult ok/err به رابط کاربری بازمی‌گردند در اینجا بومی‌سازی می‌شوند؛ تشخیص‌های
# فنی { $err }/مسیر لاگ و برچسب‌های خطای IPC به انگلیسی باقی می‌مانند. اصطلاحات تجاری و فنی
# (provcheck، provcheck-kit، Backfire، Mellin، C2PA، atproto، LOCALAPPDATA، BACKFIRE_PY،
# Yubikey، PIV PIN، DID، flags، نام فایل‌ها) در هر زبان بدون تغییر باقی می‌مانند.

## تب تصویر کلیددار Backfire (backfire_read + install_backfire).
backfire-read-needs-key = برای خواندن نشان Backfire به یک کلید نیاز است.
backfire-folder-unresolved = پوشه قابل نوشتن Backfire قابل شناسایی نبود (LOCALAPPDATA تنظیم نشده است).
backfire-ready-bundled = Backfire آماده است (خواننده همراه موجود است). یک کلید وارد کنید و یک تصویر را رها کنید.
backfire-files-missing = فایل‌های Backfire برای نصب یافت نشدند. provcheck را دوباره نصب کنید، یا BACKFIRE_PY را تنظیم کنید.
backfire-ready = Backfire آماده است. یک کلید وارد کنید و یک تصویر را رها کنید.

## تب نشان‌های کلیددار Mellin (mellin_read).
mellin-needs-secret-and-work-id = برای خواندن شماره سریال Mellin به یک فایل مخفی و یک شناسه کار نیاز است.
mellin-secret-file-missing = فایل مخفی انتخاب‌شده وجود ندارد (یا قابل خواندن نیست).

## تب‌های امضا و کلیدها: اعلان‌های محدودیت قابلیت رابط کاربری که به‌صورت خطاهای ApiResult بازمی‌گردند.
identity-already-exists = هویتی از قبل در این دایرکتوری داده وجود دارد؛ برای بازسازی آن force=true را ارسال کنید (این کار همه سوابق atproto منتشرشده پیشین را یتیم می‌کند)
rotate-yubikey-unsupported = چرخش هویت مبتنی بر Yubikey از طریق رابط کاربری هنوز پشتیبانی نمی‌شود. `provcheck-kit init --yubikey --force` را از یک ترمینال اجرا کنید، سپس برای انتشار و ابطال به اینجا بازگردید.
rotate-agefile-unsupported = چرخش هویت‌های مبتنی بر فایل age از طریق رابط کاربری هنوز متصل نشده است. از `provcheck-kit rotate` در یک ترمینال استفاده کنید.
sign-keychain-only = امضای رابط کاربری در حال حاضر فقط از هویت‌های زنجیره کلید سیستم‌عامل پشتیبانی می‌کند. برای هویت‌های فایل age از `provcheck-kit sign` در خط فرمان استفاده کنید.
sign-yubikey-unsupported = امضای رابط کاربری برای هویت‌های مبتنی بر Yubikey در v0.5.0 P3 + P4 ارائه می‌شود. فعلاً از طریق `provcheck-kit sign` در یک ترمینال امضا کنید؛ ابزار در هر امضا PIV PIN را درخواست می‌کند.
