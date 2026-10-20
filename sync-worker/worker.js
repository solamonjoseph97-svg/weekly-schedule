// Hourline sync service — Cloudflare Worker + D1.
//
// Security model
// - Identity: Google sign-in (OpenID Connect id_token, RS256, verified against Google's keys; audience, issuer,
//   expiry and a one-time nonce are all checked). We keep only Google's opaque account id ("sub").
// - At rest: every schedule is encrypted with AES-256-GCM using a per-account key derived (HKDF-SHA-256) from
//   DATA_KEY, a secret that lives only in Worker settings, never in the database. The account id is bound in as
//   additional data, so ciphertext can't be swapped between accounts. A copy of the database alone is unreadable.
// - Sessions: HMAC-SHA-256 signed, 180-day expiry, revocable ("sign out everywhere" bumps a per-account version).
// - No emails or schedule contents are stored in plain text or written to logs.
// - Only the app's own origin may call the API from a browser (CORS), and sign-in attempts are rate-limited.
//
// Settings (Worker → Settings → Variables and secrets):
//   GOOGLE_CLIENT_ID (text), APP_ORIGIN (text), SESSION_SECRET (secret), DATA_KEY (secret)
// Binding: D1 database as DB (tables: schema.sql).

const GOOGLE_AUTH = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_JWKS = "https://www.googleapis.com/oauth2/v3/certs";
const SESSION_DAYS = 180, LOGIN_TTL_MS = 10 * 60 * 1000, MAX_DOC = 1_500_000;

const enc = new TextEncoder(), dec = new TextDecoder();
const b64u = buf => { let s = ""; const a = new Uint8Array(buf); for (let i = 0; i < a.length; i += 0x8000) s += String.fromCharCode(...a.subarray(i, i + 0x8000)); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), c => c.charCodeAt(0));
const esc = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const SEC = { "strict-transport-security": "max-age=63072000; includeSubDomains", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "x-frame-options": "DENY", "cache-control": "no-store" };
function cors(env, req) {
  const o = req.headers.get("origin") || "";
  const allowed = (env.APP_ORIGIN || "").split(",").map(s => s.trim()).filter(Boolean);
  return allowed.includes(o) ? { "access-control-allow-origin": o, "access-control-allow-methods": "GET,PUT,POST,DELETE,OPTIONS", "access-control-allow-headers": "authorization,content-type", "access-control-max-age": "86400", vary: "origin" } : {};
}
const json = (obj, status, h) => new Response(JSON.stringify(obj), { status: status || 200, headers: { "content-type": "application/json", ...SEC, ...h } });
const page = (title, body, status) => new Response(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><style>body{font:16px -apple-system,system-ui,sans-serif;max-width:420px;margin:15vh auto;padding:0 20px;text-align:center;color:#14181d}h1{font-size:22px}p{color:#5d6670}</style>${body}`,
  { status: status || 200, headers: { "content-type": "text/html; charset=utf-8", ...SEC, "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" } });

// ---- keys ----
const keyCache = new Map();
async function hmacKey(env) { return crypto.subtle.importKey("raw", enc.encode(env.SESSION_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]); }
async function dataKey(env, sub) {
  if (keyCache.has(sub)) return keyCache.get(sub);
  const ikm = await crypto.subtle.importKey("raw", enc.encode(env.DATA_KEY), "HKDF", false, ["deriveKey"]);
  const k = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: enc.encode("schedule-io/data/v1"), info: enc.encode(sub) }, ikm, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  if (keyCache.size > 500) keyCache.clear();
  keyCache.set(sub, k); return k;
}
async function seal(env, sub, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(sub) }, await dataKey(env, sub), enc.encode(JSON.stringify(obj)));
  return "v1." + b64u(iv) + "." + b64u(ct);
}
async function open(env, sub, box) {
  const [v, iv, ct] = String(box).split(".");
  if (v !== "v1") throw new Error("unknown format");
  return JSON.parse(dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64u(iv), additionalData: enc.encode(sub) }, await dataKey(env, sub), unb64u(ct))));
}

// ---- sessions: base64url(json).base64url(hmac); payload {sub, email, ver, exp} ----
async function makeSession(env, sub, email, ver) {
  const body = b64u(enc.encode(JSON.stringify({ sub, email, ver, exp: Date.now() + SESSION_DAYS * 864e5 })));
  return body + "." + b64u(await crypto.subtle.sign("HMAC", await hmacKey(env), enc.encode(body)));
}
async function accountVer(env, sub) { const r = await env.DB.prepare("SELECT ver FROM accounts WHERE sub = ?").bind(sub).first(); return r ? r.ver : 0; }
async function readSession(env, req) {
  const m = /^Bearer ([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/.exec(req.headers.get("authorization") || "");
  if (!m) return null;
  try {
    if (!(await crypto.subtle.verify("HMAC", await hmacKey(env), unb64u(m[2]), enc.encode(m[1])))) return null;
    const s = JSON.parse(dec.decode(unb64u(m[1])));
    if (!(s.exp > Date.now()) || !s.sub) return null;
    if ((s.ver || 0) !== (await accountVer(env, s.sub))) return null; // revoked by "sign out everywhere"
    return s;
  } catch { return null; }
}

// ---- Google id_token verification ----
let jwksCache = { at: 0, keys: [] };
async function googleKeys(env) {
  if (Date.now() - jwksCache.at < 3600e3 && jwksCache.keys.length) return jwksCache.keys;
  const r = await fetch(env.GOOGLE_JWKS_URL || GOOGLE_JWKS);
  jwksCache = { at: Date.now(), keys: (await r.json()).keys || [] };
  return jwksCache.keys;
}
async function verifyIdToken(env, token, nonce) {
  const [h, p, sig] = String(token || "").split(".");
  if (!h || !p || !sig) throw new Error("malformed token");
  const header = JSON.parse(dec.decode(unb64u(h))), claims = JSON.parse(dec.decode(unb64u(p)));
  if (header.alg !== "RS256") throw new Error("bad alg");
  let jwk = (await googleKeys(env)).find(k => k.kid === header.kid);
  if (!jwk) { jwksCache.at = 0; jwk = (await googleKeys(env)).find(k => k.kid === header.kid); }
  if (!jwk) throw new Error("unknown key");
  const key = await crypto.subtle.importKey("jwk", { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  if (!(await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, unb64u(sig), enc.encode(h + "." + p)))) throw new Error("bad signature");
  const issOk = ["accounts.google.com", "https://accounts.google.com"].includes(claims.iss) || (env.GOOGLE_ISS && claims.iss === env.GOOGLE_ISS);
  if (!issOk) throw new Error("bad issuer");
  if (claims.aud !== env.GOOGLE_CLIENT_ID) throw new Error("wrong client");
  if (!(claims.exp * 1000 > Date.now())) throw new Error("expired");
  if (!nonce || claims.nonce !== nonce) throw new Error("nonce mismatch");
  if (!claims.sub) throw new Error("no subject");
  return claims;
}

// ---- simple rate limit for sign-in endpoints (per isolate; pair with a Cloudflare rate-limit rule) ----
const hits = new Map();
function limited(req, max) {
  const ip = req.headers.get("cf-connecting-ip") || "local", now = Date.now(), w = hits.get(ip) || [];
  const recent = w.filter(t => now - t < 60000); recent.push(now); hits.set(ip, recent);
  if (hits.size > 5000) hits.clear();
  return recent.length > max;
}
const validState = s => /^[A-Za-z0-9_-]{22,64}$/.test(s || "");

export default {
  async fetch(req, env) {
    const url = new URL(req.url), path = url.pathname, ch = cors(env, req);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: { ...ch, ...SEC } });
    try {
      if (path === "/auth/start" && req.method === "GET") {
        if (limited(req, 30)) return page("Slow down", "<h1>Too many attempts</h1><p>Wait a minute and try again.</p>", 429);
        const state = url.searchParams.get("state");
        if (!validState(state)) return page("Sign-in error", "<h1>Something went wrong</h1><p>Go back to Hourline and try again.</p>", 400);
        const q = new URLSearchParams({ client_id: env.GOOGLE_CLIENT_ID, redirect_uri: url.origin + "/auth/callback", response_type: "id_token", response_mode: "form_post", scope: "openid email", nonce: state, state, prompt: "select_account" });
        return new Response(null, { status: 302, headers: { location: (env.GOOGLE_AUTH_URL || GOOGLE_AUTH) + "?" + q, ...SEC } });
      }
      if (path === "/auth/callback" && req.method === "POST") {
        if (limited(req, 30)) return page("Slow down", "<h1>Too many attempts</h1><p>Wait a minute and try again.</p>", 429);
        const f = await req.formData(), state = f.get("state");
        if (f.get("error") || !validState(state)) return page("Sign-in cancelled", "<h1>Sign-in cancelled</h1><p>You can close this and return to Hourline.</p>", 400);
        const c = await verifyIdToken(env, f.get("id_token"), state);
        const session = await makeSession(env, c.sub, c.email || "", await accountVer(env, c.sub));
        await env.DB.prepare("DELETE FROM logins WHERE created < ?").bind(Date.now() - LOGIN_TTL_MS).run();
        await env.DB.prepare("INSERT OR IGNORE INTO logins (state, session, created) VALUES (?, ?, ?)").bind(state, session, Date.now()).run();
        const origins = (env.APP_ORIGIN || "").split(",").map(o => o.trim()).filter(Boolean);
        return page("Signed in", `<h1>You're signed in</h1><p>${esc(c.email || "")}</p><p>Return to Hourline. Your devices will start syncing.</p><script>try{window.opener&&${JSON.stringify(origins)}.forEach(function(o){window.opener.postMessage({sioSignedIn:1},o)})}catch(e){}setTimeout(function(){try{window.close()}catch(e){}},1200)</script>`);
      }
      if (path === "/auth/claim" && req.method === "GET") {
        const state = url.searchParams.get("state");
        if (!validState(state)) return json({ error: "bad state" }, 400, ch);
        const row = await env.DB.prepare("SELECT session, created FROM logins WHERE state = ?").bind(state).first();
        if (!row || Date.now() - row.created > LOGIN_TTL_MS) return json({ pending: true }, 202, ch);
        await env.DB.prepare("DELETE FROM logins WHERE state = ?").bind(state).run(); // one-time pickup
        return json({ session: row.session }, 200, ch);
      }
      // Everything below needs a valid session.
      const s = await readSession(env, req);
      if (path === "/auth/signout-all" && req.method === "POST") {
        if (!s) return json({ error: "signed out" }, 401, ch);
        await env.DB.prepare("INSERT INTO accounts (sub, ver) VALUES (?, 1) ON CONFLICT(sub) DO UPDATE SET ver = ver + 1").bind(s.sub).run();
        return json({ ok: true }, 200, ch);
      }
      if (path === "/data") {
        if (!s) return json({ error: "signed out" }, 401, ch);
        if (req.method === "GET") {
          const row = await env.DB.prepare("SELECT rev, doc, updated FROM docs WHERE sub = ?").bind(s.sub).first();
          return json(row ? { rev: row.rev, doc: await open(env, s.sub, row.doc), updated: row.updated } : { rev: 0, doc: null }, 200, ch);
        }
        if (req.method === "PUT") {
          const text = await req.text();
          if (text.length > MAX_DOC) return json({ error: "too large" }, 413, ch);
          const { baseRev, doc } = JSON.parse(text);
          if (!doc || typeof doc !== "object" || !Number.isInteger(baseRev) || baseRev < 0) return json({ error: "bad request" }, 400, ch);
          const box = await seal(env, s.sub, doc), now = Date.now();
          // Compare-and-swap on rev: only write if nothing changed since this device last pulled.
          const r = baseRev
            ? await env.DB.prepare("UPDATE docs SET doc = ?, rev = rev + 1, updated = ? WHERE sub = ? AND rev = ?").bind(box, now, s.sub, baseRev).run()
            : await env.DB.prepare("INSERT OR IGNORE INTO docs (sub, rev, doc, updated) VALUES (?, 1, ?, ?)").bind(s.sub, box, now).run();
          if (!r.meta.changes) {
            const row = await env.DB.prepare("SELECT rev, doc FROM docs WHERE sub = ?").bind(s.sub).first();
            return json({ error: "conflict", rev: row ? row.rev : 0, doc: row ? await open(env, s.sub, row.doc) : null }, 409, ch);
          }
          return json({ rev: baseRev ? baseRev + 1 : 1, updated: now }, 200, ch);
        }
        if (req.method === "DELETE") { // "Delete my cloud data": removes the schedule and signs out every device
          await env.DB.prepare("DELETE FROM docs WHERE sub = ?").bind(s.sub).run();
          await env.DB.prepare("INSERT INTO accounts (sub, ver) VALUES (?, 1) ON CONFLICT(sub) DO UPDATE SET ver = ver + 1").bind(s.sub).run();
          return json({ ok: true }, 200, ch);
        }
      }
      if (path === "/" || path === "/health") return json({ ok: true, service: "schedule-io-sync" }, 200, ch);
      return json({ error: "not found" }, 404, ch);
    } catch (e) {
      if (path === "/auth/callback") return page("Sign-in error", "<h1>Sign-in didn't work</h1><p>Return to Hourline and try again.</p>", 400);
      return json({ error: "server error" }, 500, ch);
    }
  }
};
