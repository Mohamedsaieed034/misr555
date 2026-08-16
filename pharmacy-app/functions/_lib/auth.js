// مكتبة مشتركة: تجزئة كلمات المرور، وإصدار/التحقق من رموز الجلسة (tokens)
// تُستخدم من كل نقاط الـ API. لا يتم استيرادها من المتصفح مطلقاً.

function bufToHex(buf) {
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}
function hexToBuf(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    return bytes.buffer;
}

export function generateSalt() {
    const arr = new Uint8Array(16);
    crypto.getRandomValues(arr);
    return bufToHex(arr.buffer);
}

// PBKDF2-SHA256 حقيقي بدل تخزين كلمة المرور كنص صريح
export async function hashPassword(password, saltHex) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: hexToBuf(saltHex), iterations: 100000, hash: 'SHA-256' },
        keyMaterial, 256
    );
    return bufToHex(bits);
}

export async function verifyPassword(password, saltHex, expectedHashHex) {
    const computed = await hashPassword(password, saltHex);
    // مقارنة بزمن ثابت لتقليل هجمات القياس الزمني
    if (computed.length !== expectedHashHex.length) return false;
    let diff = 0;
    for (let i = 0; i < computed.length; i++) diff |= computed.charCodeAt(i) ^ expectedHashHex.charCodeAt(i);
    return diff === 0;
}

async function hmac(secret, data) {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
    return bufToHex(sig);
}

function b64url(str) {
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return atob(str);
}

// إصدار رمز جلسة موقّع (مشابه لفكرة JWT المبسطة) صالح لمدة 12 ساعة
export async function issueToken(env, payloadObj) {
    const payload = { ...payloadObj, exp: Date.now() + 12 * 60 * 60 * 1000 };
    const payloadStr = b64url(JSON.stringify(payload));
    const sig = await hmac(env.APP_JWT_SECRET, payloadStr);
    return `${payloadStr}.${sig}`;
}

export async function verifyToken(env, token) {
    if (!token) return null;
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const [payloadStr, sig] = parts;
    const expectedSig = await hmac(env.APP_JWT_SECRET, payloadStr);
    if (sig !== expectedSig) return null;
    let payload;
    try { payload = JSON.parse(b64urlDecode(payloadStr)); } catch (e) { return null; }
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload;
}

export function getAuthPayloadFromRequest(request) {
    return request.headers.get('Authorization')?.replace(/^Bearer\s+/i, '') || null;
}

export function jsonResponse(obj, status = 200) {
    return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
}

export function getClientIP(request) {
    return request.headers.get('CF-Connecting-IP') || 'unknown';
}
