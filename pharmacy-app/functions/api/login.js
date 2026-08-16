import { verifyPassword, issueToken, jsonResponse, getClientIP } from '../_lib/auth.js';

export async function onRequestPost({ request, env }) {
    let body;
    try { body = await request.json(); } catch (e) { return jsonResponse({ error: 'invalid_body' }, 400); }

    const { username, password } = body;
    if (!username || !password) return jsonResponse({ error: 'missing_fields' }, 400);

    const row = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
    if (!row) return jsonResponse({ error: 'invalid_credentials' }, 401);

    const ok = await verifyPassword(password, row.pass_salt, row.pass_hash);
    if (!ok) return jsonResponse({ error: 'invalid_credentials' }, 401);

    // التحقق الحقيقي من عنوان IP — يتم على الخادم باستخدام العنوان الذي يراه Cloudflare فعلياً،
    // وليس عنواناً يبلغ عنه المتصفح، لذا لا يمكن تجاوزه من كونسول المطور.
    const allowedIPs = JSON.parse(row.allowed_ips || '[]').filter(Boolean);
    if (allowedIPs.length > 0) {
        const clientIP = getClientIP(request);
        if (!allowedIPs.includes(clientIP)) {
            return jsonResponse({ error: 'ip_not_allowed', yourIp: clientIP }, 403);
        }
    }

    const user = {
        username: row.username,
        fullname: row.fullname,
        role: row.role,
        currentLevel: row.current_level,
        navVisibility: JSON.parse(row.nav_visibility || '{}'),
        allowedIPs: allowedIPs
    };
    const token = await issueToken(env, { username: row.username, role: row.role });
    return jsonResponse({ user, token });
}
