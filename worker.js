// ARYAN AI GATEWAY — by ARYAN DIGITAL SOLUTIONS
// Single-file Cloudflare Worker: dashboard UI + backend + Gemini proxy.
// Needs ONE KV binding named DB. Optional secret: MASTER_KEY.
const enc = new TextEncoder(), dec = new TextDecoder();
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const rnd = n => hex(crypto.getRandomValues(new Uint8Array(n)));
const sha = async s => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const J = (o, s = 200, h = {}) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...h } });

async function pw(p, salt) {
  const k = await crypto.subtle.importKey('raw', enc.encode(p), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256' }, k, 256));
}
async function ck(env) {
  let m = env.MASTER_KEY;
  if (!m) { m = await env.DB.get('sys:mk'); if (!m) { m = rnd(32); await env.DB.put('sys:mk', m); } }
  return crypto.subtle.importKey('raw', await crypto.subtle.digest('SHA-256', enc.encode(m)), 'AES-GCM', false, ['encrypt', 'decrypt']);
}
async function encr(env, t) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return b64(iv) + '.' + b64(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await ck(env), enc.encode(t)));
}
async function decr(env, s) {
  const [a, b] = s.split('.');
  return dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(a) }, await ck(env), unb64(b)));
}
async function gList(key) {
  const r = await fetch('https://generativelanguage.googleapis.com/v1beta/models?pageSize=100', { headers: { 'x-goog-api-key': key } });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error((d.error && d.error.message) || 'Invalid key (' + r.status + ')');
  return (d.models || []).map(m => String(m.name || '').replace('models/', '')).filter(n => /^gemini-/.test(n) && !/embed|aqa|imagen|tts/.test(n));
}
const status = a => a.revoked ? 'revoked' : (a.expiresAt && Date.now() > a.expiresAt) ? 'expired' : !a.enabled ? 'disabled' : 'active';
const pub = a => { const { tokHash, mk, mc, dk, ...r } = a; return { ...r, status: status(a), dc: a.dk === new Date().toISOString().slice(0, 10) ? a.dc : 0 }; };
function norm(b) {
  const n = x => Math.max(0, parseInt(x) || 0);
  return { name: String(b.name || '').trim().slice(0, 80), app: String(b.app || '').trim().slice(0, 80), maxReq: n(b.maxReq), rpm: n(b.rpm), daily: n(b.daily), model: String(b.model || 'any'), enabled: b.enabled !== false };
}
function expiry(b) {
  const P = { '1h': 3600e3, '24h': 864e5, '7d': 6048e5, '30d': 2592e6 };
  if (P[b.exp]) return Date.now() + P[b.exp];
  if (b.exp === 'custom') { const t = Date.parse(b.custom); return t > Date.now() ? t : null; }
  return undefined;
}
async function logReq(env, a, x) {
  try {
    const t = Date.now(), k = 'log:' + String(9e12 - t).padStart(13, '0') + rnd(3);
    await env.DB.put(k, JSON.stringify({ t, api: a.name, ...x }), { expirationTtl: 604800 });
  } catch (e) { /* logging must never break a request */ }
}
async function getApi(env, id) { return JSON.parse(await env.DB.get('api:' + id) || 'null'); }
const putApi = (env, a) => env.DB.put('api:' + a.id, JSON.stringify(a));
const getMain = async env => JSON.parse(await env.DB.get('main') || 'null');

async function gateway(req, env) {
  const cors = { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'authorization,content-type,x-app-name', 'access-control-allow-methods': 'POST,OPTIONS' };
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
  const e = (m, s) => J({ error: m }, s, cors);
  const t = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '').trim();
  if (!t) return e('Missing token', 401);
  const id = await env.DB.get('tok:' + await sha(t));
  const a = id && await getApi(env, id);
  if (!a) return e('Invalid token', 401);
  const t0 = Date.now();
  const done = async (c, m, x = {}) => { await logReq(env, a, { code: c, msg: m, ms: Date.now() - t0, ...x }); return e(m, c); };
  const st = status(a);
  if (st !== 'active') return done(403, 'API is ' + st);
  const app = req.headers.get('x-app-name');
  if (app && a.app && app !== a.app) return done(403, 'Application not permitted');
  let b; try { b = await req.json(); } catch { return e('Invalid JSON body', 400); }
  const m = await getMain(env);
  if (!m) return e('Gateway not connected to Gemini', 503);
  const model = b.model || (a.model !== 'any' ? a.model : m.model);
  if (a.model !== 'any' && model !== a.model) return done(403, 'Model not allowed for this token');
  const now = Date.now(), mk = Math.floor(now / 60000), dk = new Date(now).toISOString().slice(0, 10);
  if (a.mk !== mk) { a.mk = mk; a.mc = 0; }
  if (a.dk !== dk) { a.dk = dk; a.dc = 0; }
  if (a.maxReq && a.requests >= a.maxReq) return done(429, 'Maximum requests reached');
  if (a.rpm && a.mc >= a.rpm) return done(429, 'Rate limit exceeded');
  if (a.daily && a.dc >= a.daily) return done(429, 'Daily limit reached');
  const body = {};
  if (b.contents) body.contents = b.contents;
  else if (b.prompt) body.contents = [{ role: 'user', parts: [{ text: String(b.prompt) }] }];
  else return done(400, 'Send "prompt" or "contents"');
  if (b.system) body.systemInstruction = { parts: [{ text: String(b.system) }] };
  if (b.generationConfig) body.generationConfig = b.generationConfig;
  const key = await decr(env, m.enc);
  const r = await fetch('https://generativelanguage.googleapis.com/v1beta/models/' + encodeURIComponent(model) + ':generateContent', { method: 'POST', headers: { 'content-type': 'application/json', 'x-goog-api-key': key }, body: JSON.stringify(body) });
  const d = await r.json().catch(() => ({}));
  a.requests++; a.mc++; a.dc++; a.lastUsed = now;
  if (!r.ok) { await putApi(env, a); return done(502, (d.error && d.error.message) || 'Upstream error', { model }); }
  const u = d.usageMetadata || {};
  a.tokens += u.totalTokenCount || 0;
  await putApi(env, a);
  await logReq(env, a, { code: 200, msg: 'OK', model, tokens: u.totalTokenCount || 0, ms: Date.now() - t0 });
  const text = ((d.candidates && d.candidates[0] && d.candidates[0].content && d.candidates[0].content.parts) || []).map(p => p.text || '').join('');
  return J({ text, model, usage: { promptTokens: u.promptTokenCount || 0, completionTokens: u.candidatesTokenCount || 0, totalTokens: u.totalTokenCount || 0 } }, 200, cors);
}

async function admin(req, env, url) {
  const p = url.pathname, M = req.method;
  const ck_ = (req.headers.get('cookie') || '').match(/sid=([a-f0-9]+)/);
  const authed = async () => !!(ck_ && await env.DB.get('sess:' + await sha(ck_[1])));
  const adm = JSON.parse(await env.DB.get('admin') || 'null');
  if (p === '/admin/status') return J({ setup: !!adm, authed: await authed() });
  if (M !== 'GET' && req.headers.get('x-req') !== '1') return J({ error: 'Bad request' }, 400);
  const body = (M === 'GET' || M === 'DELETE') ? {} : await req.json().catch(() => ({}));
  const startSession = async () => {
    const sid = rnd(32);
    await env.DB.put('sess:' + await sha(sid), '1', { expirationTtl: 604800 });
    return { 'set-cookie': 'sid=' + sid + '; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=604800' };
  };
  if (p === '/admin/setup' && M === 'POST') {
    if (adm) return J({ error: 'Already set up' }, 400);
    if (String(body.password || '').length < 8) return J({ error: 'Password must be 8+ characters' }, 400);
    const salt = rnd(16);
    await env.DB.put('admin', JSON.stringify({ salt, hash: await pw(body.password, salt) }));
    return J({ ok: 1 }, 200, await startSession());
  }
  if (p === '/admin/login' && M === 'POST') {
    if (!adm) return J({ error: 'Not set up' }, 400);
    const ip = req.headers.get('cf-connecting-ip') || 'x', rk = 'rl:' + ip;
    const n = parseInt(await env.DB.get(rk) || '0');
    if (n >= 5) return J({ error: 'Too many attempts. Try again in 15 minutes.' }, 429);
    if (await pw(String(body.password || ''), adm.salt) !== adm.hash) {
      await env.DB.put(rk, String(n + 1), { expirationTtl: 900 });
      return J({ error: 'Wrong password' }, 401);
    }
    return J({ ok: 1 }, 200, await startSession());
  }
  if (!(await authed())) return J({ error: 'Unauthorized' }, 401);
  if (p === '/admin/logout') {
    if (ck_) await env.DB.delete('sess:' + await sha(ck_[1]));
    return J({ ok: 1 }, 200, { 'set-cookie': 'sid=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0' });
  }
  if (p === '/admin/main') {
    const m = await getMain(env);
    if (M === 'GET') return J({ connected: !!m, model: m && m.model, models: m ? [...new Set([m.model, ...(m.models || [])])] : [], at: m && m.at });
    if (M === 'DELETE') { await env.DB.delete('main'); return J({ ok: 1 }); }
    if (M === 'POST') {
      const key = String(body.key || '').trim();
      let nm = m ? { ...m } : null;
      if (key) {
        let models = (m && m.models) || [];
        if (body.validate) { try { models = await gList(key); } catch (x) { return J({ error: x.message }, 400); } }
        nm = { enc: await encr(env, key), models, at: Date.now(), model: (m && m.model) || 'gemini-3.8-flash' };
      }
      if (!nm) return J({ error: 'Paste your Gemini API key first' }, 400);
      if (body.model) nm.model = String(body.model);
      await env.DB.put('main', JSON.stringify(nm));
      return J({ ok: 1, connected: true, model: nm.model, models: nm.models });
    }
  }
  if (p === '/admin/main/test' && M === 'POST') {
    let key = String(body.key || '').trim();
    const m = await getMain(env);
    if (!key && m) key = await decr(env, m.enc);
    if (!key) return J({ error: 'No key to test' }, 400);
    try { const models = await gList(key); return J({ ok: 1, count: models.length }); } catch (x) { return J({ error: x.message }, 400); }
  }
  if (p === '/admin/logs') {
    if (M === 'GET') {
      const l = await env.DB.list({ prefix: 'log:', limit: 60 });
      return J({ logs: (await Promise.all(l.keys.map(k => env.DB.get(k.name, 'json')))).filter(Boolean) });
    }
    if (M === 'DELETE') {
      const l = await env.DB.list({ prefix: 'log:', limit: 1000 });
      await Promise.all(l.keys.map(k => env.DB.delete(k.name)));
      return J({ ok: 1 });
    }
  }
  if (p === '/admin/apis') {
    if (M === 'GET') {
      const l = await env.DB.list({ prefix: 'api:' });
      const all = (await Promise.all(l.keys.map(k => env.DB.get(k.name, 'json')))).filter(Boolean);
      return J({ apis: all.map(pub).sort((a, b) => b.created - a.created) });
    }
    if (M === 'POST') {
      const f = norm(body), ex = expiry(body);
      if (!f.name) return J({ error: 'API Name required' }, 400);
      if (!ex) return J({ error: 'Choose a valid expiry (custom date must be in the future)' }, 400);
      const id = rnd(8), token = 'agw_' + rnd(24);
      const a = { id, ...f, expiresAt: ex, revoked: false, requests: 0, tokens: 0, lastUsed: null, created: Date.now(), tokHash: await sha(token) };
      await putApi(env, a); await env.DB.put('tok:' + a.tokHash, id);
      return J({ api: pub(a), token });
    }
  }
  const mm = p.match(/^\/admin\/apis\/([a-f0-9]+)(?:\/(\w+))?$/);
  if (mm) {
    const a = await getApi(env, mm[1]);
    if (!a) return J({ error: 'Not found' }, 404);
    const act = mm[2];
    if (M === 'DELETE') { await env.DB.delete('api:' + a.id); await env.DB.delete('tok:' + a.tokHash); return J({ ok: 1 }); }
    if (M === 'PUT') {
      const f = norm(body); if (!f.name) return J({ error: 'API Name required' }, 400);
      const ex = expiry(body);
      if (ex === null) return J({ error: 'Invalid expiry' }, 400);
      Object.assign(a, f); if (ex) a.expiresAt = ex;
      await putApi(env, a); return J({ api: pub(a) });
    }
    if (M === 'POST' && act === 'revoke') { a.revoked = true; await putApi(env, a); return J({ ok: 1 }); }
    if (M === 'POST' && act === 'toggle') {
      if (a.revoked) return J({ error: 'Revoked APIs cannot be enabled. Generate a new token instead.' }, 400);
      a.enabled = !a.enabled; await putApi(env, a); return J({ ok: 1 });
    }
    if (M === 'POST' && act === 'regen') {
      await env.DB.delete('tok:' + a.tokHash);
      const token = 'agw_' + rnd(24); a.tokHash = await sha(token); a.revoked = false;
      await putApi(env, a); await env.DB.put('tok:' + a.tokHash, a.id);
      return J({ token });
    }
  }
  return J({ error: 'Not found' }, 404);
}

export default {
  async fetch(req, env) {
    try {
      if (!env.DB) return new Response('KV binding "DB" missing. Add a KV namespace binding named DB in Worker Settings > Bindings.', { status: 500 });
      const url = new URL(req.url);
      if (url.pathname.startsWith('/v1/')) return await gateway(req, env);
      if (url.pathname.startsWith('/admin/')) return await admin(req, env, url);
      return new Response(HTML, { headers: { 'content-type': 'text/html;charset=utf-8', 'cache-control': 'no-store', 'x-frame-options': 'DENY' } });
    } catch (x) { return J({ error: 'Server error: ' + x.message }, 500); }
  }
};

const HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ARYAN AI GATEWAY</title><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Space+Grotesk:wght@400;500;700&display=swap" rel="stylesheet"><style>
:root{--bg:#05060a;--c:#0c0e16;--b:#2a3050;--t:#f1f3ff;--m:#8790b3;--a:#a855f7;--a2:#22d3ee;--pk:#ff2e93;--g:#00ff9d;--r:#ff3b5c;--y:#ffb020;--mono:'JetBrains Mono',ui-monospace,Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;color:var(--t);font:14px/1.55 'Space Grotesk',system-ui,-apple-system,Segoe UI,sans-serif;min-height:100vh;background:radial-gradient(900px 500px at 88% -10%,#a855f744,transparent),radial-gradient(800px 460px at -8% 8%,#22d3ee2e,transparent),radial-gradient(700px 400px at 50% 120%,#ff2e9326,transparent),var(--bg);background-attachment:fixed}
body::before{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;background-image:linear-gradient(#ffffff09 1px,transparent 1px),linear-gradient(90deg,#ffffff09 1px,transparent 1px);background-size:44px 44px;-webkit-mask-image:radial-gradient(circle at 50% 0,#000 15%,transparent 75%);mask-image:radial-gradient(circle at 50% 0,#000 15%,transparent 75%)}
body::after{content:"";position:fixed;inset:0;pointer-events:none;z-index:50;background:repeating-linear-gradient(0deg,#0000 0 2px,#00000026 2px 3px);opacity:.35}
#app{position:relative;z-index:1}
header{display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between;padding:12px 22px;border-bottom:1px solid #a855f733;background:#06070bd9;position:sticky;top:0;backdrop-filter:blur(14px);z-index:5;box-shadow:0 1px 34px #a855f71f}
.bw{display:flex;align-items:center;gap:12px}
.logo{width:40px;height:40px;clip-path:polygon(50% 0,93% 25%,93% 75%,50% 100%,7% 75%,7% 25%);background:linear-gradient(135deg,var(--a2),var(--a) 55%,var(--pk));display:flex;align-items:center;justify-content:center;font-weight:800;font-size:18px;color:#fff;animation:glow 3s ease-in-out infinite}.logo.s{width:36px;height:36px;font-size:16px}
.brand b{font-size:16px;letter-spacing:2.4px;background:linear-gradient(90deg,var(--a2),#fff,var(--pk),var(--a2));background-size:250% 100%;-webkit-background-clip:text;background-clip:text;color:transparent;animation:sh 7s linear infinite}.brand small{display:block;color:var(--m);font:10px var(--mono);letter-spacing:2.4px}
nav{display:flex;gap:6px;overflow-x:auto;max-width:100%;padding:3px}
nav button{background:none;border:1px solid transparent;color:var(--m);padding:8px 13px;border-radius:8px;cursor:pointer;font:600 11.5px var(--mono);letter-spacing:.7px;text-transform:uppercase;white-space:nowrap;transition:.15s}
nav button:hover{color:#fff;background:#ffffff0d}nav button.on{color:#fff;border-color:#a855f7aa;background:#a855f722;box-shadow:0 0 18px #a855f755 inset,0 0 14px #a855f733}
main{max-width:1140px;margin:0 auto;padding:26px 18px 70px}
h2{margin:0;font-size:23px;letter-spacing:.3px}.ph h2::before{content:"// ";color:var(--a2);font-family:var(--mono)}.sub{margin:3px 0 0;color:var(--m);font-size:13px}
.ph{display:flex;flex-wrap:wrap;gap:10px;justify-content:space-between;align-items:center;margin-bottom:18px}
.tg{font:10.5px var(--mono);letter-spacing:2.4px;color:var(--a2)}
.pill{display:inline-flex;align-items:center;background:#0c0e16;border:1px solid var(--b);padding:7px 14px;border-radius:8px;font:12px var(--mono);color:var(--m)}.pill.ok{color:#b8ffe0;border-color:#00ff9d55;background:#00ff9d10;box-shadow:0 0 18px #00ff9d22}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));gap:13px;margin-bottom:16px}
.card{position:relative;overflow:hidden;background:linear-gradient(160deg,#151a33e6,#0a0c16f2);border:1px solid var(--b);border-radius:14px;padding:18px;box-shadow:0 0 0 1px #ffffff05 inset,0 14px 44px #000b}
.card::before{content:"";position:absolute;left:0;right:0;top:0;height:1px;background:linear-gradient(90deg,transparent,var(--a2),var(--a),var(--pk),transparent);opacity:.8}
.stat{display:flex;align-items:center;gap:14px;transition:.2s}.stat:hover{transform:translateY(-3px);border-color:#a855f799;box-shadow:0 0 30px #a855f744,0 14px 44px #000b}
.stat i{font-style:normal;width:44px;height:44px;border-radius:11px;display:flex;align-items:center;justify-content:center;font-size:19px;flex:none;box-shadow:0 0 20px -4px currentColor}
.stat small{color:var(--m);display:block;font:11px var(--mono);text-transform:uppercase;letter-spacing:1px}.stat b{font:700 25px var(--mono);line-height:1.25;background:linear-gradient(90deg,#fff,#d6c8ff);-webkit-background-clip:text;background-clip:text;color:transparent}
.ep{margin-bottom:16px;display:grid;gap:6px}
label{display:block;color:var(--m);font:11px var(--mono);text-transform:uppercase;letter-spacing:1px;margin:15px 0 6px}
input,select{width:100%;background:#05060b;border:1px solid var(--b);color:var(--t);padding:12px 13px;border-radius:10px;font:14px inherit;transition:.15s}
input:focus,select:focus{outline:none;border-color:var(--a2);box-shadow:0 0 0 3px #22d3ee26,0 0 22px #22d3ee22}
.row{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:0 16px}.btns{display:flex;flex-wrap:wrap;gap:10px;margin-top:22px}
button.bt{background:#12162a;border:1px solid var(--b);color:var(--t);padding:10px 17px;border-radius:10px;cursor:pointer;font:600 12.5px var(--mono);letter-spacing:.4px;transition:.15s}
button.bt:hover{border-color:var(--a2);background:#171c36;box-shadow:0 0 18px #22d3ee33}button.bt:active{transform:scale(.97)}
button.p{background:linear-gradient(90deg,var(--a),var(--pk));border:0;color:#fff;box-shadow:0 0 24px #a855f766;animation:pulse 3s ease-in-out infinite}button.p:hover{filter:brightness(1.12);background:linear-gradient(90deg,var(--a),var(--pk));box-shadow:0 0 34px #ff2e9399}
button.d{color:#ff8fa3}button.d:hover{border-color:var(--r);box-shadow:0 0 18px #ff3b5c44}button.sm{padding:6px 10px;font-size:11px;border-radius:7px}
.tw{overflow-x:auto;padding:6px 14px}table{width:100%;border-collapse:collapse;min-width:820px}
th,td{text-align:left;padding:13px 8px;border-bottom:1px solid #1d2240;font-size:13px;vertical-align:middle}th{color:var(--a2);font:600 10.5px var(--mono);text-transform:uppercase;letter-spacing:1.1px;opacity:.85}
tbody tr{transition:.15s}tbody tr:hover{background:#a855f70d}tbody tr:last-child td{border-bottom:0}.empty td{text-align:center;color:var(--m);padding:36px 8px}
.tag{padding:3px 10px;border-radius:6px;font:600 11px var(--mono);text-transform:uppercase;letter-spacing:.6px}.tag.active{background:#00ff9d18;color:var(--g);box-shadow:0 0 12px #00ff9d2a}.tag.expired,.tag.revoked{background:#ff3b5c1a;color:var(--r);box-shadow:0 0 12px #ff3b5c2a}.tag.disabled{background:#ffb0201a;color:var(--y)}
.bar{height:4px;background:#ffffff14;border-radius:9px;margin-top:5px;min-width:70px;overflow:hidden}.bar span{display:block;height:100%;background:linear-gradient(90deg,var(--a2),var(--a),var(--pk));box-shadow:0 0 10px var(--a)}.bar.big{height:9px;margin:0}
.tb{display:grid;grid-template-columns:minmax(80px,150px) 1fr 54px;gap:14px;align-items:center;margin-top:12px;font-size:13px}.tb b{font:600 13px var(--mono);text-align:right}
.act{white-space:nowrap}.act button{margin:2px 4px 2px 0}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--r);margin-right:9px;box-shadow:0 0 8px var(--r)}.dot.on{background:var(--g);box-shadow:0 0 12px var(--g);animation:bl 1.6s infinite}
.pr{position:relative}.pr button{position:absolute;right:6px;top:6px}
.ov{position:fixed;inset:0;background:#000d;backdrop-filter:blur(5px);display:flex;align-items:center;justify-content:center;padding:16px;z-index:20;animation:f .18s}.ov .card{max-width:600px;width:100%;animation:u .25s}
code,pre{font:12px/1.6 var(--mono);background:#04050a;border:1px solid var(--b);border-radius:10px;padding:12px;display:block;word-break:break-all;white-space:pre-wrap;color:#b8f3ff;margin:6px 0}
#toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#0c0e16;border:1px solid var(--g);padding:11px 20px;border-radius:10px;display:none;z-index:60;max-width:90%;font:13px var(--mono);box-shadow:0 0 30px #00ff9d33,0 10px 30px #000c}#toast.bad{border-color:var(--r);box-shadow:0 0 30px #ff3b5c44,0 10px 30px #000c}
.auth{max-width:410px;margin:9vh auto;text-align:center}.auth .logo{margin:0 auto 14px;width:68px;height:68px;font-size:30px}.auth .bw{justify-content:center}.auth label,.auth h2{text-align:left}.auth .btns button{width:100%}.m{color:var(--m)}
@keyframes f{from{opacity:0}}@keyframes u{from{opacity:0;transform:translateY(16px) scale(.98)}}@keyframes sh{to{background-position:250% 0}}@keyframes bl{50%{opacity:.35}}
@keyframes glow{50%{filter:drop-shadow(0 0 14px #a855f7) drop-shadow(0 0 22px #22d3ee66)}}@keyframes pulse{50%{box-shadow:0 0 38px #a855f7aa}}
@media(max-width:720px){main{padding:16px 12px 60px}h2{font-size:19px}.tw{overflow:visible;background:none;border:0;padding:0;box-shadow:none}.tw::before{display:none}table,thead,tbody,tr,td{display:block;min-width:0}thead{display:none}tbody tr{background:linear-gradient(160deg,#151a33e6,#0a0c16f2);border:1px solid var(--b);border-radius:14px;padding:6px 14px;margin-bottom:12px}td{border:0!important;display:flex;justify-content:space-between;align-items:center;gap:14px;padding:8px 0;text-align:right}td::before{content:attr(data-l);color:var(--m);font:11px var(--mono);text-transform:uppercase;text-align:left;flex:none}td.act{flex-wrap:wrap;justify-content:flex-start}td.act::before{display:none}.empty td{display:block;text-align:center}.empty td::before{display:none}.bar{margin-left:auto}.tb{grid-template-columns:90px 1fr 44px}}
</style></head><body><div id="app"></div><div id="toast"></div><script>
var $=function(s){return document.querySelector(s)},S={view:'dash',apis:[],edit:null,main:null};
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function api(p,m,b){return fetch(p,{method:m||'GET',headers:{'content-type':'application/json','x-req':'1'},body:b?JSON.stringify(b):undefined}).then(function(r){return r.json().catch(function(){return{}}).then(function(d){if(!r.ok)throw new Error(d.error||('Error '+r.status));return d})})}
function toast(t,bad){var e=$('#toast');e.textContent=t;e.className=bad?'bad':'';e.style.display='block';clearTimeout(toast.t);toast.t=setTimeout(function(){e.style.display='none'},3500)}
function fd(d){return d?new Date(d).toLocaleString():'—'}
function fail(e){toast(e.message,1)}
function brand(){return '<div class="bw"><div class="logo s">A</div><div class="brand"><b>ARYAN AI GATEWAY</b><small>ARYAN DIGITAL SOLUTIONS</small></div></div>'}
async function boot(){var s=await api('/admin/status');if(!s.authed)return authView(s.setup);shell();go(S.view)}
function authView(setup){$('#app').innerHTML='<div class="auth card"><div class="logo">A</div><div class="brand" style="margin-bottom:6px"><b>ARYAN AI GATEWAY</b><small>ARYAN DIGITAL SOLUTIONS</small></div><div class="tg" style="margin-top:18px">// SECURE ACCESS TERMINAL</div><h2 style="margin-top:6px">'+(setup?'Admin Login':'Create Admin Password')+'</h2><p class="m">'+(setup?'':'First-time setup. Choose a strong password (8+ characters).')+'</p><label>Password</label><input id="pw" type="password" autocomplete="current-password"><div class="btns"><button class="bt p" id="go">'+(setup?'Login':'Create & Continue')+'</button></div></div>';
function sub(){api(setup?'/admin/login':'/admin/setup','POST',{password:$('#pw').value}).then(boot).catch(fail)}
$('#go').onclick=sub;$('#pw').onkeydown=function(e){if(e.key==='Enter')sub()}}
function shell(){$('#app').innerHTML='<header>'+brand()+'<nav id="nav"></nav></header><main id="main"></main>'}
function nav(){var t=[['dash','◧ Dashboard'],['main','⚙ Main API'],['create',S.edit?'✎ Edit API':'＋ Create API'],['logs','▤ Logs'],['integ','⌘ Integrate']];$('#nav').innerHTML=t.map(function(x){return '<button class="'+(S.view===x[0]?'on':'')+'" data-a="go" data-v="'+x[0]+'">'+x[1]+'</button>'}).join('')+'<button data-a="out">⎋ Logout</button>'}
function out(){api('/admin/logout','POST',{}).then(boot)}
function go(v){if(v!=='create')S.edit=null;S.view=v;nav();({dash:dash,main:mainView,create:form,logs:logs,integ:integ})[v]().catch(fail)}
async function dash(){var r=await Promise.all([api('/admin/apis'),api('/admin/main')]),d=r[0],mn=r[1];S.apis=d.apis;var A=d.apis,c=function(s){return A.filter(function(a){return a.status===s}).length},req=0,tok=0;A.forEach(function(a){req+=a.requests;tok+=a.tokens});
var st=function(i,l,v,col){return '<div class="card stat"><i style="background:'+col+'22;color:'+col+'">'+i+'</i><div><small>'+l+'</small><b>'+v+'</b></div></div>'};
var top=A.slice().sort(function(x,y){return y.requests-x.requests}).slice(0,5),mx=Math.max(1,top.length?top[0].requests:1);
var chart=A.length?'<div class="card" style="margin-bottom:16px"><small class="m" style="font-family:var(--mono);letter-spacing:1px">TOP APIS · REQUESTS</small>'+top.map(function(a){return '<div class="tb"><span>'+esc(a.name)+'</span><div class="bar big"><span style="width:'+Math.round(a.requests*100/mx)+'%"></span></div><b>'+a.requests+'</b></div>'}).join('')+'</div>':'';
var rows=A.map(function(a){var pc=a.maxReq?Math.min(100,Math.round(a.requests*100/a.maxReq)):0;return '<tr><td data-l="API"><b>'+esc(a.name)+'</b><br><span class="m">'+esc(a.app||'—')+' · '+esc(a.model)+'</span></td><td data-l="Status"><span class="tag '+a.status+'">'+a.status+'</span></td><td data-l="Requests"><span>'+a.requests+(a.maxReq?' / '+a.maxReq+'<div class="bar"><span style="width:'+pc+'%"></span></div>':'')+'</span></td><td data-l="Tokens">'+a.tokens.toLocaleString()+'</td><td data-l="Expires">'+fd(a.expiresAt)+'</td><td data-l="Last used">'+fd(a.lastUsed)+'</td><td data-l="Actions" class="act"><button class="bt sm" data-a="edit" data-id="'+a.id+'">Edit</button><button class="bt sm" data-a="tg" data-id="'+a.id+'">'+(a.enabled?'Disable':'Enable')+'</button><button class="bt sm" data-a="rg" data-id="'+a.id+'">New Token</button><button class="bt sm d" data-a="rv" data-id="'+a.id+'">Revoke</button><button class="bt sm d" data-a="dl" data-id="'+a.id+'">Delete</button></td></tr>'}).join('');
$('#main').innerHTML='<div class="ph"><div><h2>Dashboard</h2><p class="sub">Manage your gateway, tokens and usage</p></div><span class="pill'+(mn.connected?' ok':'')+'"><span class="dot'+(mn.connected?' on':'')+'"></span>'+(mn.connected?'Gemini · '+esc(mn.model):'Gemini not connected')+'</span></div>'
+'<div class="grid">'+st('▦','All APIs',A.length,'#8b6cff')+st('●','Active',c('active'),'#22c55e')+st('◷','Expired',c('expired'),'#ef4444')+st('⇄','Requests',req.toLocaleString(),'#38bdf8')+st('◈','Tokens used',tok.toLocaleString(),'#f59e0b')+'</div>'
+chart+'<div class="card ep"><small class="m">Gateway endpoint</small><code>POST '+esc(location.origin)+'/v1/generate</code><small class="m">Header: Authorization: Bearer YOUR_TOKEN · Body: {"prompt":"Hello"}</small></div>'
+'<div class="card tw"><table><thead><tr><th>API</th><th>Status</th><th>Requests</th><th>Tokens</th><th>Expires</th><th>Last Used</th><th>Actions</th></tr></thead><tbody>'+(rows||'<tr class="empty"><td colspan="7">No APIs yet. Open <b>Create New API</b> to make your first one.</td></tr>')+'</tbody></table></div>'}
function tg(i){api('/admin/apis/'+i+'/toggle','POST',{}).then(dash).catch(fail)}
function rv(i){if(confirm('Revoke this API permanently? Its token will stop working.'))api('/admin/apis/'+i+'/revoke','POST',{}).then(dash).catch(fail)}
function dl(i){if(confirm('Delete this API?'))api('/admin/apis/'+i,'DELETE').then(dash).catch(fail)}
function rg(i){if(confirm('Generate a new token? The old token stops working.'))api('/admin/apis/'+i+'/regen','POST',{}).then(function(d){showTok(d.token)}).catch(fail)}
function edit(i){S.edit=S.apis.filter(function(a){return a.id===i})[0];go('create')}
function showTok(t){var o=document.createElement('div');o.className='ov';var u=location.origin+'/v1/generate';
o.innerHTML='<div class="card"><h2>Your API Token</h2><p class="m">Copy it now. For security it is shown only once.</p><code id="tk">'+esc(t)+'</code><div class="btns"><button class="bt p" id="cp">Copy Token</button><button class="bt" id="cl">Done</button></div><p class="m" style="margin-top:14px">Use it like this:</p><pre>POST '+esc(u)+'&#10;Authorization: Bearer '+esc(t)+'&#10;Content-Type: application/json&#10;&#10;{&quot;prompt&quot;:&quot;Hello&quot;}</pre></div>';
document.body.appendChild(o);$('#cp').onclick=function(){navigator.clipboard.writeText(t).then(function(){toast('Copied')})};$('#cl').onclick=function(){o.remove();go('dash')}}
async function form(){var m=await api('/admin/main'),e=S.edit,v=function(k,d){return e?esc(e[k]):d};
var mo='<option value="any"'+(e&&e.model==='any'?' selected':'')+'>Any model</option>'+m.models.map(function(x){return '<option'+((e?e.model===x:x===m.model)?' selected':'')+'>'+esc(x)+'</option>'}).join('');
$('#main').innerHTML='<div class="ph"><div><h2>'+(e?'Edit API':'Create New API')+'</h2><p class="sub">Set limits, expiry and the model this token may use</p></div></div><div class="card"><div class="row"><div><label>API Name</label><input id="n" value="'+v('name','')+'"></div><div><label>Application Name</label><input id="ap" value="'+v('app','')+'" placeholder="Sent as X-App-Name header (optional)"></div>'
+'<div><label>Expiration</label><select id="ex">'+(e?'<option value="keep">Keep current ('+esc(fd(e.expiresAt))+')</option>':'')+'<option value="1h">1 hour</option><option value="24h"'+(e?'':' selected')+'>24 hours</option><option value="7d">7 days</option><option value="30d">30 days</option><option value="custom">Custom date</option></select><input id="cu" type="datetime-local" style="display:none;margin-top:6px"></div>'
+'<div><label>Maximum Requests (0 = unlimited)</label><input id="mr" type="number" min="0" value="'+v('maxReq',0)+'"></div><div><label>Requests Per Minute (0 = unlimited)</label><input id="rp" type="number" min="0" value="'+v('rpm',60)+'"></div><div><label>Daily Usage Limit (0 = unlimited)</label><input id="dy" type="number" min="0" value="'+v('daily',0)+'"></div>'
+'<div><label>Allowed Gemini Model</label><select id="md">'+mo+'</select></div><div><label>Status</label><select id="en"><option value="1">Enabled</option><option value="0"'+(e&&!e.enabled?' selected':'')+'>Disabled</option></select></div></div>'
+'<div class="btns"><button class="bt p" id="sv">'+(e?'Save Changes':'Create API')+'</button>'+(e?'<button class="bt" id="cn">Cancel</button>':'')+'</div>'+(m.connected?'':'<p class="m">Tip: connect your Gemini key in "Main API" first.</p>')+'</div>';
$('#ex').onchange=function(){$('#cu').style.display=this.value==='custom'?'block':'none'};
if(e)$('#cn').onclick=function(){go('dash')};
$('#sv').onclick=function(){var b={name:$('#n').value,app:$('#ap').value,exp:$('#ex').value,custom:$('#cu').value?new Date($('#cu').value).toISOString():'',maxReq:$('#mr').value,rpm:$('#rp').value,daily:$('#dy').value,model:$('#md').value,enabled:$('#en').value==='1'};
(e?api('/admin/apis/'+e.id,'PUT',b):api('/admin/apis','POST',b)).then(function(d){if(e){toast('Saved');go('dash')}else showTok(d.token)}).catch(fail)}}
async function mainView(){var m=await api('/admin/main');S.main=m;
$('#main').innerHTML='<div class="ph"><div><h2>Main API Settings</h2><p class="sub">Your Gemini key is stored encrypted on the server and never sent to the browser</p></div></div><div class="card"><p><span class="dot'+(m.connected?' on':'')+'"></span><b>'+(m.connected?'Connected':'Not connected')+'</b></p>'
+(m.connected?'<p class="m">Connected model: <b style="color:#fff">'+esc(m.model)+'</b> · '+m.models.length+' models available · Connected '+esc(fd(m.at))+'</p>':'')
+'<label>Gemini API Key '+(m.connected?'(stored encrypted on the server — paste a new one to replace it)':'')+'</label><div class="pr"><input id="k" type="password" autocomplete="off" placeholder="'+(m.connected?'••••••••••••••••':'Paste your Gemini API key')+'"><button class="bt sm" id="sh">Show</button></div>'
+(m.connected&&m.models.length?'<label>Default Gemini model</label><select id="dm">'+m.models.map(function(x){return '<option'+(x===m.model?' selected':'')+'>'+esc(x)+'</option>'}).join('')+'</select>':'')
+'<div class="btns"><button class="bt p" id="c1">Connect API</button><button class="bt" id="c2">Test Connection</button><button class="bt" id="c3">Save API</button><button class="bt d" id="c4">Disconnect API</button></div></div>';
$('#sh').onclick=function(){var k=$('#k');k.type=k.type==='password'?'text':'password';this.textContent=k.type==='password'?'Show':'Hide'};
var dm=function(){return $('#dm')?$('#dm').value:''};
$('#c1').onclick=function(){api('/admin/main','POST',{key:$('#k').value,model:dm(),validate:true}).then(function(){toast('Connected to Gemini');mainView()}).catch(fail)};
$('#c2').onclick=function(){api('/admin/main/test','POST',{key:$('#k').value}).then(function(d){toast('Connection OK — '+d.count+' models')}).catch(fail)};
$('#c3').onclick=function(){api('/admin/main','POST',{key:$('#k').value,model:dm()}).then(function(){toast('Saved');mainView()}).catch(fail)};
$('#c4').onclick=function(){if(confirm('Disconnect? All tokens will stop working until you reconnect.'))api('/admin/main','DELETE').then(function(){toast('Disconnected');mainView()}).catch(fail)}}
async function logs(){var d=await api('/admin/logs');
var rows=d.logs.map(function(l){var ok=l.code===200;return '<tr><td data-l="Time">'+fd(l.t)+'</td><td data-l="API"><b>'+esc(l.api)+'</b></td><td data-l="Result"><span class="tag '+(ok?'active':'revoked')+'">'+l.code+'</span></td><td data-l="Model">'+esc(l.model||'—')+'</td><td data-l="Tokens">'+(l.tokens||0)+'</td><td data-l="Speed">'+(l.ms||0)+' ms</td><td data-l="Message">'+esc(l.msg)+'</td></tr>'}).join('');
$('#main').innerHTML='<div class="ph"><div><h2>Request Logs</h2><p class="sub">Latest 60 requests, kept for 7 days</p></div><button class="bt d" data-a="clr">Clear logs</button></div><div class="card tw"><table><thead><tr><th>Time</th><th>API</th><th>Result</th><th>Model</th><th>Tokens</th><th>Speed</th><th>Message</th></tr></thead><tbody>'+(rows||'<tr class="empty"><td colspan="7">No requests yet. Logs appear when your apps call the gateway.</td></tr>')+'</tbody></table></div>'}
async function integ(){var u=esc(location.origin)+'/v1/generate',q='&quot;';
var c1='curl -X POST '+u+' -H '+q+'Authorization: Bearer YOUR_TOKEN'+q+' -H '+q+'Content-Type: application/json'+q+' -d &#39;{'+q+'prompt'+q+':'+q+'Hello'+q+'}&#39;';
var c2=['const r = await fetch('+q+u+q+', {','  method: '+q+'POST'+q+',','  headers: {','    '+q+'Authorization'+q+': '+q+'Bearer YOUR_TOKEN'+q+',','    '+q+'Content-Type'+q+': '+q+'application/json'+q+'','  },','  body: JSON.stringify({ prompt: '+q+'Hello'+q+' })','});','const data = await r.json();','console.log(data.text);'].join('&#10;');
var c3=['import requests','r = requests.post('+q+u+q+',','    headers={'+q+'Authorization'+q+': '+q+'Bearer YOUR_TOKEN'+q+'},','    json={'+q+'prompt'+q+': '+q+'Hello'+q+'})','print(r.json()['+q+'text'+q+'])'].join('&#10;');
var c4='{'+q+'text'+q+': '+q+'Hi! How can I help?'+q+', '+q+'model'+q+': '+q+'gemini-3.8-flash'+q+', '+q+'usage'+q+': {'+q+'totalTokens'+q+': 12}}';
var blk=function(t,c,cp){return '<div class="card" style="margin-bottom:14px"><div class="ph" style="margin-bottom:6px"><b>'+t+'</b>'+(cp?'<button class="bt sm" data-a="cpy">Copy</button>':'')+'</div><pre>'+c+'</pre></div>'};
$('#main').innerHTML='<div class="ph"><div><h2>Integration Guide</h2><p class="sub">Use your token from any app. Your Gemini key never leaves the server.</p></div></div>'
+'<div class="card" style="margin-bottom:14px"><span class="tg">ENDPOINT</span><code>POST '+u+'</code><p class="m" style="margin:8px 0 0">Send header <b>Authorization: Bearer YOUR_TOKEN</b>. If you set an Application Name, also send header <b>X-App-Name</b> with the same value. Body can be <b>prompt</b> (text), or <b>contents</b>, <b>system</b>, <b>generationConfig</b>, <b>model</b> (optional).</p></div>'
+blk('cURL',c1,1)+blk('JavaScript',c2,1)+blk('Python',c3,1)+blk('Response',c4,0)
+'<div class="card"><span class="tg">ERROR CODES</span><p class="m" style="margin:8px 0 0">401 invalid token · 403 disabled, revoked, expired, wrong app or model · 429 request, rate or daily limit reached · 502 Gemini returned an error · 503 gateway not connected to Gemini</p></div>'}
document.addEventListener('click',function(e){var t=e.target.closest('[data-a]');if(!t)return;var a=t.dataset.a,i=t.dataset.id;if(a==='go')go(t.dataset.v);else if(a==='out')out();else if(a==='edit')edit(i);else if(a==='tg')tg(i);else if(a==='rg')rg(i);else if(a==='rv')rv(i);else if(a==='dl')dl(i);else if(a==='clr'){if(confirm('Clear all logs?'))api('/admin/logs','DELETE').then(logs).catch(fail)}else if(a==='cpy'){navigator.clipboard.writeText(t.closest('.card').querySelector('pre').textContent).then(function(){toast('Copied')})}});
boot().catch(fail);
</script></body></html>`;
