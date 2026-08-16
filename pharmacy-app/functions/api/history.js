import { verifyToken, getAuthPayloadFromRequest, jsonResponse } from '../_lib/auth.js';

async function requireAuth(request, env) {
    const token = getAuthPayloadFromRequest(request);
    return await verifyToken(env, token);
}

export async function onRequestGet({ request, env }) {
    const auth = await requireAuth(request, env);
    if (!auth) return jsonResponse({ error: 'unauthorized' }, 401);

    const { results } = await env.DB.prepare('SELECT timestamp, user, text FROM history_log ORDER BY id DESC LIMIT 50').all();
    return jsonResponse({ history: results });
}

export async function onRequestPost({ request, env }) {
    const auth = await requireAuth(request, env);
    if (!auth) return jsonResponse({ error: 'unauthorized' }, 401);

    let body;
    try { body = await request.json(); } catch (e) { return jsonResponse({ error: 'invalid_body' }, 400); }
    const { timestamp, user, text } = body;
    if (!timestamp || !user || !text) return jsonResponse({ error: 'missing_fields' }, 400);

    await env.DB.prepare('INSERT INTO history_log (timestamp, user, text) VALUES (?, ?, ?)').bind(timestamp, user, text).run();

    // تقليم السجل للاحتفاظ بآخر 500 حدث فقط
    await env.DB.prepare('DELETE FROM history_log WHERE id NOT IN (SELECT id FROM history_log ORDER BY id DESC LIMIT 500)').run();

    return jsonResponse({ ok: true });
}
