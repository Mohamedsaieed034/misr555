-- قاعدة بيانات المستخدمين المشتركة (Cloudflare D1)
-- شغّل هذا الملف مرة واحدة فقط عند إعداد قاعدة البيانات لأول مرة.

CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    fullname TEXT NOT NULL,
    pass_hash TEXT NOT NULL,
    pass_salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'طالب',
    current_level INTEGER NOT NULL DEFAULT 1,
    nav_visibility TEXT NOT NULL DEFAULT '{}',
    allowed_ips TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ملاحظة: هذا الملف لا يزرع حساب مدير افتراضي بكلمة مرور معروفة مسبقاً،
-- لأن أي قيمة مكتوبة هنا ستكون مرئية لأي شخص يفتح هذا الملف على GitHub.
-- بعد إنشاء القاعدة، استخدم زر "تهيئة أول حساب مدير" داخل التطبيق
-- (يظهر فقط إذا كانت قاعدة البيانات فارغة تماماً) لإنشاء أول حساب بأمان.

-- بيانات مشتركة عامة (بيانات التأمين، بيانات الأدوية) — مخزَّنة كـ JSON لكل مفتاح
CREATE TABLE IF NOT EXISTS app_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- سجل نتائج الاختبارات (كل محاولة اختبار من أي مستخدم ومن أي جهاز)
CREATE TABLE IF NOT EXISTS quiz_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student TEXT NOT NULL,
    level TEXT NOT NULL,
    score INTEGER NOT NULL,
    total INTEGER NOT NULL,
    percent INTEGER NOT NULL,
    date_time TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- سجل نشاط النظام (كل حدث من أي مستخدم ومن أي جهاز)
CREATE TABLE IF NOT EXISTS history_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    user TEXT NOT NULL,
    text TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

