import { verifyToken, getAuthPayloadFromRequest, jsonResponse } from '../../_lib/auth.js';

// المفاتيح المسموح بها والمستخدمة من الواجهة الأمامية
const ALLOWED_KEYS = ['insuranceSettings', 'allStagesMeds'];
// المفاتيح التي يمكن لأي مستخدم مسجّل دخول تعديلها (وليس المدير فقط)،
// لأن شاشة "التطوير الدوائي" متاحة افتراضياً لكل الأدوار
const OPEN_WRITE_KEYS = ['allStagesMeds'];

async function requireAuth(request, env) {
    const token = getAuthPayloadFromRequest(request);
    const payload = await verifyToken(env, token);
    return payload; // null إن لم يكن صالحاً
}

export async function onRequestGet({ request, env, params }) {
    const auth = await requireAuth(request, env);
    if (!auth) return jsonResponse({ error: 'unauthorized' }, 401);

    const key = params.key;
    if (!ALLOWED_KEYS.includes(key)) return jsonResponse({ error: 'invalid_key' }, 400);

    const row = await env.DB.prepare('SELECT value FROM app_state WHERE key = ?').bind(key).first();
    return jsonResponse({ value: row ? JSON.parse(row.value) : null });
}

export async function onRequestPut({ request, env, params }) {
    const auth = await requireAuth(request, env);
    if (!auth) return jsonResponse({ error: 'unauthorized' }, 401);

    const key = params.key;
    if (!ALLOWED_KEYS.includes(key)) return jsonResponse({ error: 'invalid_key' }, 400);

    // شاشة إعدادات التعاقدات (بيانات التأمين) مقصورة على المدير فقط، مطابقةً لقفل الشاشة بالواجهة
    if (!OPEN_WRITE_KEYS.includes(key) && auth.role !== 'مدير') return jsonResponse({ error: 'unauthorized' }, 401);

    let body;
    try { body = await request.json(); } catch (e) { return jsonResponse({ error: 'invalid_body' }, 400); }

    await env.DB.prepare(
        'INSERT INTO app_state (key, value, updated_at) VALUES (?, ?, datetime(\'now\')) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at'
    ).bind(key, JSON.stringify(body)).run();

    return jsonResponse({ ok: true });
}
