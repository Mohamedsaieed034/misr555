import { generateSalt, hashPassword, verifyToken, getAuthPayloadFromRequest, jsonResponse } from '../../_lib/auth.js';

async function requireManager(request, env) {
    const token = getAuthPayloadFromRequest(request);
    const payload = await verifyToken(env, token);
    if (!payload || payload.role !== 'مدير') return null;
    return payload;
}

export async function onRequestGet({ request, env }) {
    const auth = await requireManager(request, env);
    if (!auth) return jsonResponse({ error: 'unauthorized' }, 401);

    const { results } = await env.DB.prepare('SELECT username, fullname, role, current_level, nav_visibility, allowed_ips FROM users').all();
    const users = results.map(r => ({
        username: r.username, fullname: r.fullname, role: r.role, currentLevel: r.current_level,
        navVisibility: JSON.parse(r.nav_visibility || '{}'), allowedIPs: JSON.parse(r.allowed_ips || '[]')
    }));
    return jsonResponse({ users });
}

export async function onRequestPost({ request, env }) {
    const auth = await requireManager(request, env);
    if (!auth) return jsonResponse({ error: 'unauthorized' }, 401);

    let body;
    try { body = await request.json(); } catch (e) { return jsonResponse({ error: 'invalid_body' }, 400); }
    const { username, fullname, password, role, navVisibility, allowedIPs } = body;
    if (!username || !fullname || !password || !role) return jsonResponse({ error: 'missing_fields' }, 400);

    const existing = await env.DB.prepare('SELECT username FROM users WHERE username = ?').bind(username).first();
    if (existing) return jsonResponse({ error: 'username_taken' }, 409);

    const finalVis = { ...navVisibility };
    if (role !== 'مدير') { finalVis.users = false; finalVis.sett = false; finalVis.contracts = false; }

    const salt = generateSalt();
    const hash = await hashPassword(password, salt);

    await env.DB.prepare(
        'INSERT INTO users (username, fullname, pass_hash, pass_salt, role, current_level, nav_visibility, allowed_ips) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(username, fullname, hash, salt, role, 1, JSON.stringify(finalVis), JSON.stringify(allowedIPs || [])).run();

    return jsonResponse({ ok: true });
}
