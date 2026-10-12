# رسائل واجهة provcheck-app، بالعربية (المصدر: الإنجليزية). تُترجم هنا فقط الجمل الكاملة
# الموجهة للمستخدم والتي تعود إلى الواجهة كنص ApiResult ok/err؛ تبقى تشخيصات
# { $err }/مسار السجل وتسميات أخطاء IPC التقنية بالإنجليزية. المصطلحات التجارية والتقنية
# (provcheck، provcheck-kit، Backfire، Mellin، C2PA، atproto، LOCALAPPDATA، BACKFIRE_PY،
# Yubikey، PIV PIN، DID، flags، أسماء الملفات) تبقى كما هي في كل لغة.

## تبويب Backfire المُرمّز للصورة (backfire_read + install_backfire).
backfire-read-needs-key = يلزم مفتاح لقراءة علامة Backfire.
backfire-folder-unresolved = تعذر تحديد مجلد Backfire قابل للكتابة (LOCALAPPDATA غير مضبوط).
backfire-ready-bundled = Backfire جاهز (القارئ المرفق موجود). أدخل مفتاحًا وأفلت صورة.
backfire-files-missing = لم يُعثر على ملفات Backfire لتثبيتها. أعد تثبيت provcheck، أو اضبط BACKFIRE_PY.
backfire-ready = Backfire جاهز. أدخل مفتاحًا وأفلت صورة.

## تبويب علامات Mellin المُرمّزة (mellin_read).
mellin-needs-secret-and-work-id = يلزم ملف سرّي ومعرّف عمل لقراءة رقم Mellin التسلسلي.
mellin-secret-file-missing = الملف السرّي المحدد غير موجود (أو غير قابل للقراءة).

## تبويبا التوقيع والمفاتيح: إشعارات حدود قدرات الواجهة التي تعود كأخطاء ApiResult.
identity-already-exists = توجد هوية بالفعل في دليل البيانات هذا؛ مرّر force=true لإعادة إنشائها (هذا يجعل جميع سجلات atproto المنشورة سابقًا يتيمة)
rotate-yubikey-unsupported = تدوير هوية مدعومة بـ Yubikey عبر الواجهة غير مدعوم بعد. شغّل `provcheck-kit init --yubikey --force` من طرفية، ثم عد إلى هنا للنشر والإبطال.
rotate-agefile-unsupported = تدوير الهويات المدعومة بملف age عبر الواجهة غير مفعّل بعد. استخدم `provcheck-kit rotate` من طرفية.
sign-keychain-only = يدعم التوقيع عبر الواجهة حاليًا هويات سلسلة مفاتيح نظام التشغيل فقط. استخدم `provcheck-kit sign` من سطر الأوامر لهويات ملف age.
sign-yubikey-unsupported = يصل التوقيع عبر الواجهة للهويات المدعومة بـ Yubikey في الإصدار v0.5.0 P3 + P4. حاليًا، وقّع عبر `provcheck-kit sign` من طرفية؛ تطلب الأداة رمز PIV PIN عند كل توقيع.
