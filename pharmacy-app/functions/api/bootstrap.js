import { generateSalt, hashPassword, jsonResponse } from '../_lib/auth.js';

// نقطة نهاية خاصة لإنشاء أول حساب مدير فقط، وتعمل فقط إذا كانت قاعدة البيانات فارغة تماماً.
// بعد إنشاء أول حساب، تتوقف هذه النقطة عن العمل تلقائياً ولا يمكن استخدامها مرة أخرى.

export async function onRequestGet({ env }) {
    const row = await env.DB.prepare('SELECT COUNT(*) as c FROM users').first();
    return jsonResponse({ needsBootstrap: row.c === 0 });
}

export async function onRequestPost({ request, env }) {
    const row = await env.DB.prepare('SELECT COUNT(*) as c FROM users').first();
    if (row.c > 0) return jsonResponse({ error: 'already_bootstrapped' }, 403);

    let body;
    try { body = await request.json(); } catch (e) { return jsonResponse({ error: 'invalid_body' }, 400); }
    const { username, fullname, password } = body;
    if (!username || !fullname || !password || password.length < 8) {
        return jsonResponse({ error: 'invalid_fields', detail: 'يجب توفير اسم مستخدم واسم كامل وكلمة مرور 8 خانات على الأقل' }, 400);
    }

    const salt = generateSalt();
    const hash = await hashPassword(password, salt);
    const navVisibility = JSON.stringify({ dash: true, users: true, medGuide: true, medDev: true, insGuide: true, sett: true, contracts: true });

    await env.DB.prepare(
        'INSERT INTO users (username, fullname, pass_hash, pass_salt, role, current_level, nav_visibility, allowed_ips) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(username, fullname, hash, salt, 'مدير', 1, navVisibility, '[]').run();

    return jsonResponse({ ok: true });
}
