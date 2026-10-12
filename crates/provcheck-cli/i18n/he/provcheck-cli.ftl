# פלט זמן ריצה של provcheck-cli, עברית (המקור: אנגלית). רק פלט קריא לבני אדם מתורגם;
# פלט --json וקודי יציאה לעולם אינם מתורגמים. מציין המיקום { $name } מתמלא בנקודת הקריאה;
# יש להשאיר אותו כמות שהוא בתרגומים. מונחים מסחריים וטכניים (provcheck, C2PA, Backfire,
# Mellin, BUSL, Apache-2.0, JSON, PowerShell, bash, flags, שמות קבצים) נשארים כלשונם בכל שפה.

## בלוק פורנזי אודיו ממופתח של Mellin (print_mellin_human).
mellin-header = Mellin (ניסיוני, מספר סידורי פורנזי ממופתח לאודיו):
mellin-serial-full = מספר סידורי:   { $serial } (כל 64 הביטים שוחזרו, מינימום הצבעות ביט { $votes })
mellin-serial-partial = מספר סידורי:   לא שוחזר במלואו ({ $bits }/64 ביטים, מינימום הצבעות ביט { $votes })
mellin-erasures = מחיקות: { $pct }% מהמיקומים
mellin-expected-match = צפוי: התאמה
mellin-expected-no-match = צפוי: אין התאמה

## בלוק סימן מים ממופתח לתמונה של Backfire (print_backfire_human).
backfire-header = Backfire (ניסיוני, סימן מים ממופתח לתמונה):
backfire-mark-valid = סימן:   תקף (מזהה { $id }, שוליים { $margin })
backfire-mark-none = סימן:   לא זוהה (שוליים { $margin })
backfire-tamper-detected = חבלה: זוהתה חריצת פס (band-notch) (סטטיסטיקה { $stat }) -- סביר מאוד שהתמונה הותקפה בחריצת פס
backfire-tamper-none = חבלה: אין (סטטיסטיקת חריצת פס { $stat })

## התקנת Backfire (--install-backfire).
backfire-folder-not-found = provcheck: לא ניתן לאתר את תיקיית backfire. הגדירו את BACKFIRE_PY לקובץ backfire.py, או הריצו מתוך ספרייה המכילה backfire/backfire.py.
backfire-ps1-not-found = provcheck: setup_backfire.ps1 לא נמצא ב-{ $dir }
backfire-sh-not-found = provcheck: setup_backfire.sh לא נמצא ב-{ $dir }
backfire-setup-start = סביבת הקריאה של Backfire מוגדרת כעת (חד פעמי). פעולה זו מורידה Python עצמאי.
backfire-setup-ready = Backfire מוכן. ניתן לאמת תמונה מסומנת באמצעות:  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck: התקנת Backfire הסתיימה עם סטטוס { $status }
backfire-setup-run-failed = provcheck: לא ניתן להריץ את סקריפט ההתקנה של Backfire ({ $err }). נדרש PowerShell ב-Windows, או bash ב-Linux/macOS.

## התקנת מודלים (--install-models).
install-models-start = מתקין { $count } קובצי מודל לזיהוי סימני מים (סה"כ { $mb } MB).
install-models-item = { $family }/{ $variant } ({ $mb } MB) ...
install-models-ok = בוצע
install-models-item-failed = נכשל: { $err }
install-models-done = כל המודלים הותקנו. זיהוי סימני מים מוכן.
install-models-summary-failed = provcheck: { $count } מודלים נכשלו בהתקנה (ראו למעלה).

## נתיב האימות הראשי: שגיאות, הודעות ורמזים.
require-attested-needs-identity = provcheck: --require-attested דורש --bsky-handle, --did או --auto-identity
trust-store-read-failed = provcheck: לא ניתן לקרוא את מאגר האמון '{ $path }': { $err }
auto-identity-no-assertion = provcheck: --auto-identity התבקש אך הקובץ אינו נושא הצהרת app.provcheck.identity. חתמו תחילה עם `provcheck-kit sign --embed-identity`, או העבירו --bsky-handle / --did ישירות.
backfire-needs-key = provcheck: --backfire-read דורש --backfire-key
backfire-experimental-notice = provcheck: Backfire הוא ניסיוני ובעל רישיון BUSL (חינמי לשימוש לא מסחרי), נפרד מליבת Apache-2.0. הוא מאמת סימן ממופתח שהטמעתם ומדווח על חבלת חריצת פס; העמידות משתנה לפי תמונה.
backfire-read-failed = provcheck: קריאת backfire נכשלה: { $err }
mellin-needs-args = provcheck: --mellin-read דורש --mellin-secret-file ו--mellin-work-id
mellin-experimental-notice = provcheck: Mellin הוא ניסיוני ובעל רישיון BUSL (חינמי לשימוש לא מסחרי), נפרד מליבת Apache-2.0. הוא קורא מספר סידורי ממופתח לכל עותק שהטמעתם; ללא הסוד ומזהה העבודה שלכם אין מה לקרוא.
mellin-read-failed = provcheck: קריאת mellin נכשלה: { $err }
json-serialize-failed = provcheck: סריאליזציה של JSON נכשלה: { $err }
hint-models-missing = [רמז] { $count } מודלים לזיהוי סימני מים אינם מותקנים, ולכן השורות הללו מציגות "not installed". הפעילו זיהוי מלא באמצעות:  provcheck --install-models  (חד פעמי, { $mb } MB). אימות C2PA אינו זקוק להם.
hint-claims-identity = [רמז] הקובץ טוען לזהות { $who }. הריצו מחדש עם --auto-identity כדי לאמת מול רשומות מפתח החתימה המפורסמות.
