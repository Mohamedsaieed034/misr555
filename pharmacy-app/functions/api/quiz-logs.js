import { verifyToken, getAuthPayloadFromRequest, jsonResponse } from '../_lib/auth.js';

async function requireAuth(request, env) {
    const token = getAuthPayloadFromRequest(request);
    return await verifyToken(env, token);
}

export async function onRequestGet({ request, env }) {
    const auth = await requireAuth(request, env);
    if (!auth) return jsonResponse({ error: 'unauthorized' }, 401);

    const { results } = await env.DB.prepare('SELECT student, level, score, total, percent, date_time as dateTime FROM quiz_logs ORDER BY id DESC LIMIT 500').all();
    return jsonResponse({ logs: results });
}

export async function onRequestPost({ request, env }) {
    const auth = await requireAuth(request, env);
    if (!auth) return jsonResponse({ error: 'unauthorized' }, 401);

    let body;
    try { body = await request.json(); } catch (e) { return jsonResponse({ error: 'invalid_body' }, 400); }
    const { student, level, score, total, percent, dateTime } = body;
    if (!student || !level || score == null || total == null || percent == null || !dateTime) {
        return jsonResponse({ error: 'missing_fields' }, 400);
    }

    await env.DB.prepare(
        'INSERT INTO quiz_logs (student, level, score, total, percent, date_time) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(student, String(level), score, total, percent, dateTime).run();

    return jsonResponse({ ok: true });
}
