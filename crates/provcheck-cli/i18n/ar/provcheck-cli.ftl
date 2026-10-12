# مخرجات وقت التشغيل لـ provcheck-cli، بالعربية (المصدر: الإنجليزية). النص القابل للقراءة
# البشرية فقط؛ مخرجات --json ورموز الخروج لا تُترجم أبدًا. يتم ملء العناصر النائبة
# { $name } عند نقاط الاستدعاء؛ احتفظ بها كما هي في الترجمات. المصطلحات التجارية والتقنية
# (provcheck، C2PA، Backfire، Mellin، BUSL، Apache-2.0، JSON، PowerShell، bash، flags، أسماء
# الملفات) تبقى كما هي في كل لغة.

## كتلة Mellin الجنائية الصوتية المُرمّزة (print_mellin_human).
mellin-header = Mellin (تجريبي، رقم تسلسلي جنائي صوتي مُرمّز):
mellin-serial-full = الرقم التسلسلي:   { $serial } (تم استرداد جميع البتات الـ64، الحد الأدنى لأصوات البتات { $votes })
mellin-serial-partial = الرقم التسلسلي:   لم يُسترد بالكامل ({ $bits }/64 بت، الحد الأدنى لأصوات البتات { $votes })
mellin-erasures = المحو: { $pct }% من المواضع
mellin-expected-match = المتوقع: تطابق
mellin-expected-no-match = المتوقع: لا تطابق

## كتلة علامة Backfire المائية المُرمّزة للصورة (print_backfire_human).
backfire-header = Backfire (تجريبي، علامة مائية مُرمّزة للصورة):
backfire-mark-valid = العلامة:   صالحة (المعرّف { $id }، الهامش { $margin })
backfire-mark-none = العلامة:   غير مكتشفة (الهامش { $margin })
backfire-tamper-detected = العبث: تم اكتشاف قطع نطاق (band-notch) (إحصائية { $stat }) -- من المرجح جدًا أن الصورة تعرضت لهجوم قطع نطاق
backfire-tamper-none = العبث: لا يوجد (إحصائية قطع النطاق { $stat })

## إعداد Backfire (--install-backfire).
backfire-folder-not-found = provcheck: تعذر تحديد موقع مجلد backfire. اضبط BACKFIRE_PY على backfire.py، أو شغّل الأمر من دليل يحتوي على backfire/backfire.py.
backfire-ps1-not-found = provcheck: لم يُعثر على setup_backfire.ps1 في { $dir }
backfire-sh-not-found = provcheck: لم يُعثر على setup_backfire.sh في { $dir }
backfire-setup-start = يجري إعداد بيئة قراءة Backfire (لمرة واحدة). يقوم هذا بتنزيل Python مستقل بذاته.
backfire-setup-ready = Backfire جاهز. تحقق من صورة مُعلَّمة باستخدام:  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck: خرج إعداد Backfire بالحالة { $status }
backfire-setup-run-failed = provcheck: تعذر تشغيل نص إعداد Backfire ({ $err }). يتطلب PowerShell على Windows، أو bash على Linux/macOS.

## تثبيت النماذج (--install-models).
install-models-start = جارٍ تثبيت { $count } من ملفات نماذج اكتشاف العلامات المائية (بإجمالي { $mb } ميغابايت).
install-models-item = { $family }/{ $variant } ({ $mb } ميغابايت) ...
install-models-ok = تم
install-models-item-failed = فشل: { $err }
install-models-done = تم تثبيت جميع النماذج. اكتشاف العلامات المائية جاهز الآن.
install-models-summary-failed = provcheck: فشل تثبيت { $count } من النماذج (انظر أعلاه).

## مسار التحقق الرئيسي: الأخطاء والإشعارات والتلميحات.
require-attested-needs-identity = provcheck: يتطلب --require-attested وجود --bsky-handle أو --did أو --auto-identity
trust-store-read-failed = provcheck: تعذرت قراءة مخزن الثقة '{ $path }': { $err }
auto-identity-no-assertion = provcheck: تم طلب --auto-identity لكن الملف لا يحمل تأكيد app.provcheck.identity. وقّع أولاً باستخدام `provcheck-kit sign --embed-identity`، أو مرّر --bsky-handle / --did مباشرةً.
backfire-needs-key = provcheck: يتطلب --backfire-read وجود --backfire-key
backfire-experimental-notice = provcheck: Backfire تجريبي ومرخّص بموجب BUSL (مجاني للاستخدام غير التجاري)، منفصل عن نواة Apache-2.0. يتحقق من علامة مُرمّزة قمت بتضمينها ويشير إلى العبث بقطع النطاق؛ المتانة تختلف حسب الصورة.
backfire-read-failed = provcheck: فشلت قراءة backfire: { $err }
mellin-needs-args = provcheck: يتطلب --mellin-read وجود --mellin-secret-file و --mellin-work-id
mellin-experimental-notice = provcheck: Mellin تجريبي ومرخّص بموجب BUSL (مجاني للاستخدام غير التجاري)، منفصل عن نواة Apache-2.0. يقرأ رقمًا تسلسليًا مُرمّزًا لكل نسخة قمت بتضمينه؛ بدون سرّك ومعرّف العمل الخاص بك لا يوجد شيء لقراءته.
mellin-read-failed = provcheck: فشلت قراءة mellin: { $err }
json-serialize-failed = provcheck: فشل تسلسل JSON: { $err }
hint-models-missing = [تلميح] { $count } من نماذج اكتشاف العلامات المائية غير مثبتة، لذا تظهر هذه الأسطر "not installed". فعّل الاكتشاف الكامل باستخدام:  provcheck --install-models  (لمرة واحدة، { $mb } ميغابايت). التحقق من C2PA لا يحتاج إليها.
hint-claims-identity = [تلميح] يدّعي الملف هوية { $who }. أعد التشغيل مع --auto-identity للتحقق منها مقابل سجلات مفتاح التوقيع المنشورة.
