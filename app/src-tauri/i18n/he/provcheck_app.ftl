# הודעות ממשק provcheck-app, עברית (המקור: אנגלית). רק משפטים מלאים הפונים למשתמש
# המוחזרים לממשק כטקסט ApiResult ok/err מתורגמים כאן; אבחוני { $err }/נתיב היומן הטכניים
# ותוויות שגיאת IPC נשארים באנגלית. מונחים מסחריים וטכניים (provcheck, provcheck-kit,
# Backfire, Mellin, C2PA, atproto, LOCALAPPDATA, BACKFIRE_PY, Yubikey, PIV PIN, DID, flags,
# שמות קבצים) נשארים כלשונם בכל שפה.

## לשונית התמונה הממופתחת של Backfire (backfire_read + install_backfire).
backfire-read-needs-key = נדרש מפתח כדי לקרוא סימן Backfire.
backfire-folder-unresolved = לא ניתן היה לאתר תיקיית Backfire הניתנת לכתיבה (LOCALAPPDATA לא מוגדר).
backfire-ready-bundled = Backfire מוכן (הקורא המצורף קיים). הזינו מפתח וגררו תמונה.
backfire-files-missing = קובצי Backfire להתקנה לא נמצאו. התקינו מחדש את provcheck, או הגדירו BACKFIRE_PY.
backfire-ready = Backfire מוכן. הזינו מפתח וגררו תמונה.

## לשונית הסימנים הממופתחים של Mellin (mellin_read).
mellin-needs-secret-and-work-id = נדרשים קובץ סוד ומזהה עבודה כדי לקרוא מספר סידורי של Mellin.
mellin-secret-file-missing = קובץ הסוד שנבחר אינו קיים (או אינו קריא).

## לשוניות חתימה ומפתחות: הודעות מגבלת יכולת הממשק המוחזרות כשגיאות ApiResult.
identity-already-exists = כבר קיימת זהות בספריית הנתונים הזו; העבירו force=true כדי ליצור אותה מחדש (פעולה זו הופכת את כל רשומות ה-atproto שפורסמו בעבר ליתומות)
rotate-yubikey-unsupported = סיבוב זהות המבוססת על Yubikey דרך הממשק אינו נתמך עדיין. הריצו `provcheck-kit init --yubikey --force` מטרמינל, ואז חזרו לכאן כדי לפרסם ולבטל.
rotate-agefile-unsupported = סיבוב זהויות המבוססות על קובץ age דרך הממשק עדיין לא חובר. השתמשו ב-`provcheck-kit rotate` מטרמינל.
sign-keychain-only = חתימה דרך הממשק תומכת כרגע רק בזהויות מחזיק המפתחות של מערכת ההפעלה. השתמשו ב-`provcheck-kit sign` משורת הפקודה עבור זהויות קובץ age.
sign-yubikey-unsupported = חתימה דרך הממשק לזהויות המבוססות על Yubikey תגיע בגרסה v0.5.0 P3 + P4. בינתיים, חתמו דרך `provcheck-kit sign` מטרמינל; הכלי מבקש את קוד ה-PIV PIN בכל חתימה.
