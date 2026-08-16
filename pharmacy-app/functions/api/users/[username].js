import { generateSalt, hashPassword, verifyToken, getAuthPayloadFromRequest, jsonResponse } from '../../_lib/auth.js';

async function requireManager(request, env) {
    const token = getAuthPayloadFromRequest(request);
    const payload = await verifyToken(env, token);
    if (!payload || payload.role !== 'مدير') return null;
    return payload;
}

export async function onRequestPut({ request, env, params }) {
    const auth = await requireManager(request, env);
    if (!auth) return jsonResponse({ error: 'unauthorized' }, 401);

    const targetUsername = params.username;
    const existing = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(targetUsername).first();
    if (!existing) return jsonResponse({ error: 'not_found' }, 404);

    let body;
    try { body = await request.json(); } catch (e) { return jsonResponse({ error: 'invalid_body' }, 400); }
    const { fullname, password, role, currentLevel, navVisibility, allowedIPs } = body;

    const finalRole = role || existing.role;
    const finalVis = { ...(navVisibility || JSON.parse(existing.nav_visibility || '{}')) };
    if (finalRole !== 'مدير') { finalVis.users = false; finalVis.sett = false; finalVis.contracts = false; }

    let passHash = existing.pass_hash, passSalt = existing.pass_salt;
    if (password) {
        passSalt = generateSalt();
        passHash = await hashPassword(password, passSalt);
    }

    await env.DB.prepare(
        'UPDATE users SET fullname = ?, pass_hash = ?, pass_salt = ?, role = ?, current_level = ?, nav_visibility = ?, allowed_ips = ? WHERE username = ?'
    ).bind(
        fullname || existing.fullname, passHash, passSalt, finalRole,
        currentLevel || existing.current_level, JSON.stringify(finalVis), JSON.stringify(allowedIPs || []), targetUsername
    ).run();

    return jsonResponse({ ok: true });
}

export async function onRequestDelete({ request, env, params }) {
    const auth = await requireManager(request, env);
    if (!auth) return jsonResponse({ error: 'unauthorized' }, 401);

    const targetUsername = params.username;
    const managerCountRow = await env.DB.prepare("SELECT COUNT(*) as c FROM users WHERE role = 'مدير'").first();
    const target = await env.DB.prepare('SELECT role FROM users WHERE username = ?').bind(targetUsername).first();
    if (!target) return jsonResponse({ error: 'not_found' }, 404);
    if (target.role === 'مدير' && managerCountRow.c <= 1) return jsonResponse({ error: 'cannot_delete_last_manager' }, 400);

    await env.DB.prepare('DELETE FROM users WHERE username = ?').bind(targetUsername).run();
    return jsonResponse({ ok: true });
}
