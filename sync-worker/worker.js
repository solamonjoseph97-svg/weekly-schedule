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
//   Optional: DATA_KEY_OLD (secret, only while rotating DATA_KEY), LOCKDOWN (text "1" = emergency stop),
//   ANTHROPIC_API_KEY (secret, turns on Ella smart conversation and the event finder), ELLA_DAILY (text, messages per account per day, default 40)
//   EVENTS_DAILY (text, event searches per account per day, default 5), WEB_SEARCH_TOOL (text, default web_search_20250305)
//   GEOCODE_URL (text, reverse-geocoding endpoint, default OpenStreetMap Nominatim), GEOCODE_OFF (text "1" = no addresses on check-in proof)
// Binding: D1 database as DB (tables: schema.sql). Teams: teams, members, snaps. Notifications: push, conf, nudge_use; partners (created on
// first use, also in schema.sql). Cron Trigger every minute sends due notifications (wrangler.toml [triggers]).

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
async function dataKey(secret, sub) {
  const id = secret.length + ":" + secret.slice(0, 6) + ":" + sub; // cache per (key, account) so a rotated key never reuses a stale entry
  if (keyCache.has(id)) return keyCache.get(id);
  const ikm = await crypto.subtle.importKey("raw", enc.encode(secret), "HKDF", false, ["deriveKey"]);
  const k = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: enc.encode("schedule-io/data/v1"), info: enc.encode(sub) }, ikm, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  if (keyCache.size > 500) keyCache.clear();
  keyCache.set(id, k); return k;
}
async function seal(env, sub, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(sub) }, await dataKey(env.DATA_KEY, sub), enc.encode(JSON.stringify(obj)));
  return "v1." + b64u(iv) + "." + b64u(ct);
}
// Key rotation: set the new key as DATA_KEY and the previous one as DATA_KEY_OLD. Each schedule still under the old key
// is re-encrypted with the new key the next time that account syncs. Keep DATA_KEY_OLD set until accounts have had time to
// sync (a schedule that was never re-encrypted can't be read once DATA_KEY_OLD is removed; that account would start fresh).
async function openWith(secret, sub, iv, ct) {
  return JSON.parse(dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64u(iv), additionalData: enc.encode(sub) }, await dataKey(secret, sub), unb64u(ct))));
}
async function open(env, sub, box) {
  const [v, iv, ct] = String(box).split(".");
  if (v !== "v1") throw new Error("unknown format");
  try { return { doc: await openWith(env.DATA_KEY, sub, iv, ct), stale: false }; }
  catch (e) { if (!env.DATA_KEY_OLD) throw e; }
  return { doc: await openWith(env.DATA_KEY_OLD, sub, iv, ct), stale: true };
}

// ---- teams: a member's device publishes a filtered copy of their schedule for their team lead ----
// Each copy is encrypted with a key unique to the team (HKDF info "team:<id>"), with team and member bound in as
// additional data. Every request re-checks membership in the database; removing someone deletes their copy at once.
const MAX_SNAP = 400_000, MAX_TEAMS_OWNED = 5, MAX_MEMBERS = 500;
const teamIdOk = t => /^tm_[A-Za-z0-9_-]{16,40}$/.test(t || "");
const rnd = n => b64u(crypto.getRandomValues(new Uint8Array(n)));
const sha256 = async t => b64u(await crypto.subtle.digest("SHA-256", enc.encode(t)));
async function sealT(env, team, sub, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(team + "|" + sub) }, await dataKey(env.DATA_KEY, "team:" + team), enc.encode(JSON.stringify(obj)));
  return "v1." + b64u(iv) + "." + b64u(ct);
}
async function openT(env, team, sub, box) {
  const [v, iv, ct] = String(box).split(".");
  if (v !== "v1") throw new Error("unknown format");
  const tryKey = async secret => JSON.parse(dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64u(iv), additionalData: enc.encode(team + "|" + sub) }, await dataKey(secret, "team:" + team), unb64u(ct))));
  try { return { doc: await tryKey(env.DATA_KEY), stale: false }; } catch (e) { if (!env.DATA_KEY_OLD) throw e; }
  return { doc: await tryKey(env.DATA_KEY_OLD), stale: true };
}
// Check-in proof (team members): a live camera photo and where it was taken, sealed per member like snaps.
// Only the team lead can read them. Photos and places are deleted after PROOF_DAYS, when the member leaves, or with their data.
const PROOF_DAYS = 30, PROOF_MAX = 600_000, PROOF_KEY = /^[A-Za-z0-9_-]{1,60}\|\d{4}-\d{2}-\d{2}$/;
let proofReady = false;
async function proofInit(env) { if (proofReady) return;
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS proofs (id TEXT PRIMARY KEY, team TEXT NOT NULL, sub TEXT NOT NULL, k TEXT NOT NULL, at INTEGER NOT NULL, meta TEXT NOT NULL, photo TEXT, created INTEGER NOT NULL)").run();
  await env.DB.prepare("CREATE UNIQUE INDEX IF NOT EXISTS proofs_one ON proofs (team, sub, k)").run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS proofs_age ON proofs (created)").run(); proofReady = true; }
// Turns a check-in's coordinates into a readable place ("The Domain, 11410 Century Oaks Ter, Austin") for the lead.
// Uses OpenStreetMap's Nominatim from the server (only the coordinates are sent, never who you are), cached ~11 m apart.
// GEOCODE_URL can point at another provider later; GEOCODE_OFF=1 turns it off.
async function placeName(env, lat, lng) {
  if (env.GEOCODE_OFF === "1") return "";
  const k = lat.toFixed(4) + "," + lng.toFixed(4);
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS geo_cache (k TEXT PRIMARY KEY, place TEXT NOT NULL, at INTEGER NOT NULL)").run();
  const hit = await env.DB.prepare("SELECT place FROM geo_cache WHERE k = ?").bind(k).first(); if (hit) return hit.place;
  try {
    const u = new URL(env.GEOCODE_URL || "https://nominatim.openstreetmap.org/reverse"); u.searchParams.set("format", "jsonv2"); u.searchParams.set("lat", String(lat)); u.searchParams.set("lon", String(lng)); u.searchParams.set("zoom", "18"); u.searchParams.set("addressdetails", "1");
    const ctl = new AbortController(), tm = setTimeout(() => ctl.abort(), 3500);
    const r = await fetch(u, { headers: { "user-agent": "Hourline/1.0 (+https://hourline.io)", "accept-language": "en" }, signal: ctl.signal }); clearTimeout(tm);
    if (!r.ok) return "";
    const j = await r.json(), a = j.address || {};
    const name = j.name && !/^\d/.test(j.name) ? j.name : (a.shop || a.amenity || a.building || a.office || a.leisure || "");
    const street = [a.house_number, a.road].filter(Boolean).join(" "), city = a.city || a.town || a.village || a.suburb || a.county || "";
    const place = [name, street, [city, a.state ? (a["ISO3166-2-lvl4"] || "").split("-")[1] || a.state : ""].filter(Boolean).join(", ")].filter(Boolean).join(" · ").slice(0, 140);
    if (place) await env.DB.prepare("INSERT INTO geo_cache (k, place, at) VALUES (?, ?, ?) ON CONFLICT(k) DO NOTHING").bind(k, place, Date.now()).run();
    return place;
  } catch { return ""; }
}
async function proofRoutes(env, req, s, id, me, parts, ch) {
  const M = req.method, lead = me.role === "lead", now = Date.now(); await proofInit(env);
  if (parts.length === 4 && M === "PUT") { // a member saves the proof for one check-in (re-taking replaces it)
    if (lead) return json({ error: "forbidden" }, 403, ch);
    if (limited(req, 30, "proof")) return json({ error: "slow down" }, 429, ch);
    const k = decodeURIComponent(parts[3]); if (!PROOF_KEY.test(k)) return json({ error: "bad request" }, 400, ch);
    const t = await req.text(); if (t.length > PROOF_MAX) return json({ error: "too large" }, 413, ch);
    let b; try { b = JSON.parse(t); } catch { return json({ error: "bad request" }, 400, ch); }
    const at = +b.at, photo = typeof b.photo === "string" ? b.photo : "";
    if (!Number.isFinite(at) || at > now + 5 * 60000 || at < now - 3 * 864e5) return json({ error: "bad time" }, 400, ch);
    if (photo && !/^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/.test(photo)) return json({ error: "bad photo" }, 400, ch);
    const num = (v, lo, hi) => Number.isFinite(+v) && +v >= lo && +v <= hi ? Math.round(+v * 1e6) / 1e6 : null;
    const lat = num(b.lat, -90, 90), lng = num(b.lng, -180, 180), acc = num(b.acc, 0, 100000);
    const place = lat != null && lng != null ? await placeName(env, lat, lng) : "";
    const meta = { at, title: String(b.title || "").slice(0, 60), place, lat: lat != null && lng != null ? lat : null, lng: lat != null && lng != null ? lng : null, acc: lat != null ? acc : null,
      why: photo ? "" : String(b.why || "no photo").slice(0, 60), locWhy: lat != null ? "" : String(b.locWhy || "no location").slice(0, 60), photo: !!photo };
    const ex = await env.DB.prepare("SELECT id FROM proofs WHERE team = ? AND sub = ? AND k = ?").bind(id, s.sub, k).first();
    const pid = ex ? ex.id : "pf_" + rnd(16);
    await env.DB.prepare("INSERT INTO proofs (id, team, sub, k, at, meta, photo, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(team, sub, k) DO UPDATE SET at = excluded.at, meta = excluded.meta, photo = excluded.photo, created = excluded.created")
      .bind(pid, id, s.sub, k, at, await sealT(env, id, s.sub, meta), photo ? await sealT(env, id, s.sub, { photo }) : null, now).run();
    return json({ id: pid }, 200, ch);
  }
  if (!lead) return json({ error: "forbidden" }, 403, ch);
  if (parts.length === 3 && M === "GET") { // lead: proof details for the last N days (no photos, just what each check-in carried)
    const days = Math.min(PROOF_DAYS, Math.max(1, +new URL(req.url).searchParams.get("days") || 7));
    const rows = (await env.DB.prepare("SELECT p.id AS id, p.sub AS sub, p.k AS k, p.meta AS meta, m.mid AS mid FROM proofs p JOIN members m ON m.team = p.team AND m.sub = p.sub WHERE p.team = ? AND p.created > ? ORDER BY p.at DESC LIMIT 2000").bind(id, now - days * 864e5).all()).results || [];
    const out = [];
    for (const r of rows) { try { out.push({ id: r.id, mid: r.mid, k: r.k, ...(await openT(env, id, r.sub, r.meta)).doc }); } catch { } }
    return json({ proofs: out }, 200, ch);
  }
  if (parts.length === 5 && parts[4] === "photo" && M === "GET") { // lead: one photo
    const r = await env.DB.prepare("SELECT sub, photo FROM proofs WHERE team = ? AND id = ?").bind(id, parts[3]).first();
    if (!r || !r.photo) return json({ error: "not found" }, 404, ch);
    try { return json({ photo: (await openT(env, id, r.sub, r.photo)).doc.photo }, 200, { ...ch, "cache-control": "no-store" }); } catch { return json({ error: "not found" }, 404, ch); }
  }
  return json({ error: "not found" }, 404, ch);
}
async function memberOf(env, team, sub) { return env.DB.prepare("SELECT role, mid FROM members WHERE team = ? AND sub = ?").bind(team, sub).first(); }
async function dropTeam(env, team) {
  await env.DB.prepare("DELETE FROM snaps WHERE team = ?").bind(team).run();
  await proofInit(env); await env.DB.prepare("DELETE FROM proofs WHERE team = ?").bind(team).run();
  await env.DB.prepare("DELETE FROM members WHERE team = ?").bind(team).run();
  await env.DB.prepare("DELETE FROM teams WHERE id = ?").bind(team).run();
}
async function teams(env, req, s, path, ch) {
  const parts = path.split("/").filter(Boolean), M = req.method, now = Date.now();
  const body = async () => { const t = await req.text(); if (t.length > MAX_SNAP) throw Object.assign(new Error("too large"), { status: 413 }); return t ? JSON.parse(t) : {}; };
  if (parts.length === 1 && M === "GET") { // my teams
    const r = await env.DB.prepare("SELECT m.team AS id, m.role AS role, m.mid AS mid, t.name AS name FROM members m JOIN teams t ON t.id = m.team WHERE m.sub = ?").bind(s.sub).all();
    return json({ teams: r.results || [] }, 200, ch);
  }
  if (parts.length === 1 && M === "POST") { // create a team; the creator is its lead
    if (limited(req, 20, "teams")) return json({ error: "slow down" }, 429, ch);
    const b = await body(), name = String(b.name || "").trim().slice(0, 40) || "Team";
    const owned = await env.DB.prepare("SELECT COUNT(*) AS n FROM teams WHERE owner = ?").bind(s.sub).first();
    if (owned && owned.n >= MAX_TEAMS_OWNED) return json({ error: "team limit" }, 403, ch);
    const id = "tm_" + rnd(18), invite = rnd(24), mid = "mb_" + rnd(12);
    await env.DB.prepare("INSERT INTO teams (id, owner, name, invite_hash, created) VALUES (?, ?, ?, ?, ?)").bind(id, s.sub, name, await sha256(invite), now).run();
    await env.DB.prepare("INSERT INTO members (team, sub, mid, role, joined) VALUES (?, ?, ?, 'lead', ?)").bind(id, s.sub, mid, now).run();
    return json({ id, invite, mid, name, role: "lead" }, 200, ch);
  }
  if (parts.length === 2 && parts[1] === "join" && M === "POST") {
    if (limited(req, 20, "teams")) return json({ error: "slow down" }, 429, ch);
    const b = await body(), id = String(b.team || ""), inv = String(b.invite || "");
    const t = teamIdOk(id) && inv.length >= 20 ? await env.DB.prepare("SELECT id, name, invite_hash FROM teams WHERE id = ?").bind(id).first() : null;
    if (!t || (await sha256(inv)) !== t.invite_hash) return json({ error: "invite not valid" }, 403, ch);
    const had = await memberOf(env, id, s.sub);
    if (had) return json({ id, name: t.name, role: had.role, mid: had.mid }, 200, ch);
    const n = await env.DB.prepare("SELECT COUNT(*) AS n FROM members WHERE team = ?").bind(id).first();
    if (n && n.n >= MAX_MEMBERS) return json({ error: "team full" }, 403, ch);
    const mid = "mb_" + rnd(12);
    await env.DB.prepare("INSERT INTO members (team, sub, mid, role, joined) VALUES (?, ?, ?, 'member', ?)").bind(id, s.sub, mid, now).run();
    return json({ id, name: t.name, role: "member", mid }, 200, ch);
  }
  const id = parts[1];
  if (!teamIdOk(id)) return json({ error: "not found" }, 404, ch);
  const me = await memberOf(env, id, s.sub);
  if (!me) return json({ error: "not found" }, 404, ch); // never reveal whether a team exists to outsiders
  const lead = me.role === "lead";
  if (parts[2] === "proofs") return proofRoutes(env, req, s, id, me, parts, ch);
  if (parts.length === 2 && M === "GET") { // lead only: every member's latest shared copy
    if (!lead) return json({ error: "forbidden" }, 403, ch);
    const t = await env.DB.prepare("SELECT name FROM teams WHERE id = ?").bind(id).first();
    const ms = (await env.DB.prepare("SELECT m.sub AS sub, m.mid AS mid, m.role AS role, m.joined AS joined, s.doc AS doc, s.updated AS updated FROM members m LEFT JOIN snaps s ON s.team = m.team AND s.sub = m.sub WHERE m.team = ?").bind(id).all()).results || [];
    const out = [];
    for (const m of ms) {
      if (m.sub === s.sub) continue;
      let doc = null;
      if (m.doc) { try { const o = await openT(env, id, m.sub, m.doc); doc = o.doc; if (o.stale) await env.DB.prepare("UPDATE snaps SET doc = ? WHERE team = ? AND sub = ? AND updated = ?").bind(await sealT(env, id, m.sub, doc), id, m.sub, m.updated).run(); } catch { doc = null; } }
      out.push({ mid: m.mid, role: m.role, joined: m.joined, updated: m.updated || null, doc });
    }
    return json({ id, name: t ? t.name : "Team", members: out }, 200, ch);
  }
  if (parts.length === 3 && parts[2] === "snap" && M === "PUT") { // a member publishes their shared copy
    if (limited(req, 30, "snap")) return json({ error: "slow down" }, 429, ch);
    const b = await body();
    if (!b.doc || typeof b.doc !== "object") return json({ error: "bad request" }, 400, ch);
    await env.DB.prepare("INSERT INTO snaps (team, sub, doc, updated) VALUES (?, ?, ?, ?) ON CONFLICT(team, sub) DO UPDATE SET doc = excluded.doc, updated = excluded.updated").bind(id, s.sub, await sealT(env, id, s.sub, b.doc), now).run();
    return json({ updated: now }, 200, ch);
  }
  if (parts.length === 3 && parts[2] === "snap" && M === "DELETE") { // stop sharing, stay on the team
    await env.DB.prepare("DELETE FROM snaps WHERE team = ? AND sub = ?").bind(id, s.sub).run();
    return json({ ok: true }, 200, ch);
  }
  if (parts.length === 3 && parts[2] === "nudge" && M === "POST") { // lead: "time to check in" on members' lock screens
    if (!lead) return json({ error: "forbidden" }, 403, ch);
    if (limited(req, 8, "nudge")) return json({ error: "slow down" }, 429, ch);
    const b = await body();
    const mids = Array.isArray(b.mids) ? [...new Set(b.mids.map(String))] : [];
    if (!mids.length || mids.length > NUDGE_BATCH) return json({ error: "bad request" }, 400, ch);
    await pushInit(env); await nudgeInit(env);
    const day = new Date(now).toISOString().slice(0, 10);
    await env.DB.prepare("DELETE FROM nudge_use WHERE day < ?").bind(day).run();
    const t = await env.DB.prepare("SELECT name FROM teams WHERE id = ?").bind(id).first();
    // Fixed wording: a lead can't put their own text on someone's lock screen. No schedule details are included.
    const msg = { title: String(t && t.name || "Your team").slice(0, 40), body: "Your team lead is asking for today's check-in. Tap to check in.", url: "/app/#checkin", tag: "nudge" };
    const out = { sent: [], none: [], capped: [] };
    for (const mid of mids) {
      const m = await env.DB.prepare("SELECT sub FROM members WHERE team = ? AND mid = ?").bind(id, mid).first();
      if (!m || m.sub === s.sub) continue;
      const used = await env.DB.prepare("SELECT n FROM nudge_use WHERE team = ? AND sub = ? AND day = ?").bind(id, m.sub, day).first();
      if (used && used.n >= NUDGE_DAILY) { out.capped.push(mid); continue; }
      const devs = (await env.DB.prepare("SELECT id, box FROM push WHERE sub = ? ORDER BY updated DESC LIMIT ?").bind(m.sub, NUDGE_DEVICES).all()).results || [];
      let n = 0;
      for (const d of devs) {
        let doc; try { doc = (await open(env, m.sub, d.box)).doc; } catch { continue; }
        let st = 0; try { st = await sendPush(env, doc, msg); } catch { st = 0; }
        if (st === 404 || st === 410) await env.DB.prepare("DELETE FROM push WHERE id = ?").bind(d.id).run();
        else if (st >= 200 && st < 300) n++;
      }
      if (!n) { out.none.push(mid); continue; } // no phone with notifications on: the app offers a text instead
      await env.DB.prepare("INSERT INTO nudge_use (team, sub, day, n) VALUES (?, ?, ?, 1) ON CONFLICT(team, sub, day) DO UPDATE SET n = n + 1").bind(id, m.sub, day).run();
      out.sent.push(mid);
    }
    return json(out, 200, ch);
  }
  if (parts.length === 3 && parts[2] === "invite" && M === "POST") { // lead: new invite code; old links stop working
    if (!lead) return json({ error: "forbidden" }, 403, ch);
    const invite = rnd(24);
    await env.DB.prepare("UPDATE teams SET invite_hash = ? WHERE id = ?").bind(await sha256(invite), id).run();
    return json({ invite }, 200, ch);
  }
  if (parts.length === 3 && parts[2] === "name" && M === "PUT") {
    if (!lead) return json({ error: "forbidden" }, 403, ch);
    const b = await body();
    await env.DB.prepare("UPDATE teams SET name = ? WHERE id = ?").bind(String(b.name || "").trim().slice(0, 40) || "Team", id).run();
    return json({ ok: true }, 200, ch);
  }
  if (parts.length === 4 && parts[2] === "members" && M === "DELETE") { // lead removes someone, or a member leaves
    const target = await env.DB.prepare("SELECT sub, role FROM members WHERE team = ? AND mid = ?").bind(id, parts[3]).first();
    if (!target) return json({ error: "not found" }, 404, ch);
    const self = target.sub === s.sub;
    if (!(self || lead) || (self && lead)) return json({ error: "forbidden" }, 403, ch); // a lead deletes the team instead
    await env.DB.prepare("DELETE FROM snaps WHERE team = ? AND sub = ?").bind(id, target.sub).run();
    await proofInit(env); await env.DB.prepare("DELETE FROM proofs WHERE team = ? AND sub = ?").bind(id, target.sub).run();
    await env.DB.prepare("DELETE FROM members WHERE team = ? AND sub = ?").bind(id, target.sub).run();
    return json({ ok: true }, 200, ch);
  }
  if (parts.length === 2 && M === "DELETE") { // lead deletes the team and every shared copy in it
    if (!lead) return json({ error: "forbidden" }, 403, ch);
    await dropTeam(env, id);
    return json({ ok: true }, 200, ch);
  }
  return json({ error: "not found" }, 404, ch);
}

// ---- accountability partners (one way): the owner shares chosen categories with one partner per invite link ----
// The partner sees only what the owner's app sends (same shape as a team copy); the owner never sees anything of the
// partner's. Invite links work once. Names and the shared copy are sealed per partner link, like team copies.
const MAX_PARTNERS = 5, MAX_WATCHING = 20, partnerIdOk = id => /^pt_[A-Za-z0-9_-]{20,40}$/.test(id || "");
let partnersReady = false;
async function partnersInit(env) {
  if (partnersReady) return;
  for (const q of ["CREATE TABLE IF NOT EXISTS partners (id TEXT PRIMARY KEY, owner TEXT NOT NULL, viewer TEXT, invite_hash TEXT, names TEXT, doc TEXT, updated INTEGER, created INTEGER NOT NULL)",
    "CREATE INDEX IF NOT EXISTS partners_by_owner ON partners (owner)", "CREATE INDEX IF NOT EXISTS partners_by_viewer ON partners (viewer)"]) await env.DB.prepare(q).run();
  partnersReady = true;
}
const pName = v => String(v || "").trim().slice(0, 40);
async function pNames(env, r) { if (!r.names) return {}; try { return (await openT(env, r.id, "names", r.names)).doc || {}; } catch { return {}; } }
async function partners(env, req, s, path, ch) {
  await partnersInit(env);
  const parts = path.split("/").filter(Boolean), M = req.method, now = Date.now();
  const body = async () => { const t = await req.text(); if (t.length > MAX_SNAP) throw Object.assign(new Error("too large"), { status: 413 }); return t ? JSON.parse(t) : {}; };
  if (parts.length === 1 && M === "GET") {
    const mine = (await env.DB.prepare("SELECT id, viewer, names, created FROM partners WHERE owner = ?").bind(s.sub).all()).results || [];
    const shared = (await env.DB.prepare("SELECT id, owner, names, doc, updated FROM partners WHERE viewer = ?").bind(s.sub).all()).results || [];
    const out = { mine: [], shared: [] };
    for (const r of mine) out.mine.push({ id: r.id, accepted: !!r.viewer, partner: r.viewer ? pName((await pNames(env, r)).viewer) : "", created: r.created });
    for (const r of shared) {
      let doc = null;
      if (r.doc) { try { const o = await openT(env, r.id, r.owner, r.doc); doc = o.doc; if (o.stale) await env.DB.prepare("UPDATE partners SET doc = ? WHERE id = ? AND updated = ?").bind(await sealT(env, r.id, r.owner, doc), r.id, r.updated).run(); } catch { doc = null; } }
      out.shared.push({ id: r.id, name: pName((await pNames(env, r)).owner), updated: r.updated || null, doc });
    }
    return json(out, 200, ch);
  }
  if (parts.length === 1 && M === "POST") { // owner makes an invite link
    if (limited(req, 20, "partners")) return json({ error: "slow down" }, 429, ch);
    const b = await body();
    const n = await env.DB.prepare("SELECT COUNT(*) AS n FROM partners WHERE owner = ?").bind(s.sub).first();
    if (n && n.n >= MAX_PARTNERS) return json({ error: "partner limit" }, 403, ch);
    const id = "pt_" + rnd(18), invite = rnd(24);
    await env.DB.prepare("INSERT INTO partners (id, owner, invite_hash, names, created) VALUES (?, ?, ?, ?, ?)").bind(id, s.sub, await sha256(invite), await sealT(env, id, "names", { owner: pName(b.name) }), now).run();
    return json({ id, invite }, 200, ch);
  }
  if (parts.length === 2 && parts[1] === "accept" && M === "POST") {
    if (limited(req, 20, "partners")) return json({ error: "slow down" }, 429, ch);
    const b = await body(), id = String(b.id || ""), inv = String(b.invite || "");
    const r = partnerIdOk(id) ? await env.DB.prepare("SELECT * FROM partners WHERE id = ?").bind(id).first() : null;
    if (r && r.viewer === s.sub) return json({ id, name: pName((await pNames(env, r)).owner) }, 200, ch); // already accepted
    if (!r || r.viewer || !r.invite_hash || inv.length < 20 || (await sha256(inv)) !== r.invite_hash) return json({ error: "invite not valid" }, 403, ch);
    if (r.owner === s.sub) return json({ error: "own invite" }, 400, ch);
    const w = await env.DB.prepare("SELECT COUNT(*) AS n FROM partners WHERE viewer = ?").bind(s.sub).first();
    if (w && w.n >= MAX_WATCHING) return json({ error: "partner limit" }, 403, ch);
    const names = { ...(await pNames(env, r)), viewer: pName(b.name) };
    const u = await env.DB.prepare("UPDATE partners SET viewer = ?, invite_hash = NULL, names = ? WHERE id = ? AND viewer IS NULL").bind(s.sub, await sealT(env, id, "names", names), id).run();
    if (!u.meta.changes) return json({ error: "invite not valid" }, 403, ch);
    return json({ id, name: pName(names.owner) }, 200, ch);
  }
  const id = parts[1];
  const r = partnerIdOk(id) ? await env.DB.prepare("SELECT id, owner, viewer FROM partners WHERE id = ?").bind(id).first() : null;
  if (!r || (r.owner !== s.sub && r.viewer !== s.sub)) return json({ error: "not found" }, 404, ch);
  if (parts.length === 3 && parts[2] === "snap" && M === "PUT") { // owner publishes what this partner may see
    if (r.owner !== s.sub) return json({ error: "forbidden" }, 403, ch);
    if (limited(req, 30, "psnap")) return json({ error: "slow down" }, 429, ch);
    const b = await body();
    if (!b.doc || typeof b.doc !== "object") return json({ error: "bad request" }, 400, ch);
    await env.DB.prepare("UPDATE partners SET doc = ?, updated = ? WHERE id = ?").bind(await sealT(env, id, r.owner, b.doc), now, id).run();
    return json({ updated: now }, 200, ch);
  }
  if (parts[2] === "snaps") return partnerSnaps(env, req, s, r, parts, ch);
  if (parts.length === 2 && M === "DELETE") { // owner stops sharing, or the partner stops watching
    await env.DB.prepare("DELETE FROM partners WHERE id = ?").bind(id).run();
    await psInit(env); await env.DB.prepare("DELETE FROM psnaps WHERE pid = ?").bind(id).run();
    return json({ ok: true }, 200, ch);
  }
  return json({ error: "not found" }, 404, ch);
}

// ---- check-in snaps to an accountability partner (the owner opts in per partner) ----
// The owner's app sends the check-in photo (with an optional sticker) to partners it chose; the partner can react once
// (🔥 👏 💪 😂 🎯). Sealed per partner link, deleted after 30 days or when either side stops. Pushes use fixed wording.
const PS_REACT = ["🔥", "👏", "💪", "😂", "🎯"];
let psReady = false;
async function psInit(env) { if (psReady) return;
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS psnaps (id TEXT PRIMARY KEY, pid TEXT NOT NULL, k TEXT NOT NULL, at INTEGER NOT NULL, meta TEXT NOT NULL, photo TEXT NOT NULL, react TEXT, created INTEGER NOT NULL)").run();
  await env.DB.prepare("CREATE UNIQUE INDEX IF NOT EXISTS psnaps_one ON psnaps (pid, k)").run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS psnaps_age ON psnaps (created)").run(); psReady = true; }
async function pushTo(env, sub, msg) { // best effort, newest 3 devices
  try { await pushInit(env); const devs = (await env.DB.prepare("SELECT id, box FROM push WHERE sub = ? ORDER BY updated DESC LIMIT 3").bind(sub).all()).results || [];
    for (const d of devs) { let doc; try { doc = (await open(env, sub, d.box)).doc; } catch { continue; } let st = 0; try { st = await sendPush(env, doc, msg); } catch { } if (st === 404 || st === 410) await env.DB.prepare("DELETE FROM push WHERE id = ?").bind(d.id).run(); } } catch { }
}
async function partnerSnaps(env, req, s, r, parts, ch) {
  await psInit(env); const M = req.method, now = Date.now(), owner = r.owner === s.sub, viewer = r.viewer === s.sub;
  if (parts.length === 4 && M === "PUT") { // owner sends a snap for one check-in
    if (!owner) return json({ error: "forbidden" }, 403, ch);
    if (!r.viewer) return json({ error: "not accepted" }, 409, ch);
    if (limited(req, 40, "psnap")) return json({ error: "slow down" }, 429, ch);
    const k = decodeURIComponent(parts[3]); if (!PROOF_KEY.test(k)) return json({ error: "bad request" }, 400, ch);
    const t = await req.text(); if (t.length > PROOF_MAX) return json({ error: "too large" }, 413, ch);
    let b; try { b = JSON.parse(t); } catch { return json({ error: "bad request" }, 400, ch); }
    const at = +b.at, photo = String(b.photo || "");
    if (!Number.isFinite(at) || at > now + 5 * 60000 || at < now - 3 * 864e5) return json({ error: "bad time" }, 400, ch);
    if (!/^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/.test(photo)) return json({ error: "bad photo" }, 400, ch);
    const meta = { at, title: String(b.title || "").slice(0, 60), sticker: String(b.sticker || "").slice(0, 30), place: String(b.place || "").slice(0, 80), v: ["ok", "review"].includes(b.v) ? b.v : "" };
    const ex = await env.DB.prepare("SELECT id FROM psnaps WHERE pid = ? AND k = ?").bind(r.id, k).first(), sid = ex ? ex.id : "ps_" + rnd(16);
    await env.DB.prepare("INSERT INTO psnaps (id, pid, k, at, meta, photo, react, created) VALUES (?, ?, ?, ?, ?, ?, NULL, ?) ON CONFLICT(pid, k) DO UPDATE SET at = excluded.at, meta = excluded.meta, photo = excluded.photo, created = excluded.created")
      .bind(sid, r.id, k, at, await sealT(env, r.id, r.owner, meta), await sealT(env, r.id, r.owner, { photo }), now).run();
    const nm = pName((await pNames(env, await env.DB.prepare("SELECT id, names FROM partners WHERE id = ?").bind(r.id).first())).owner) || "Your partner";
    if (!ex) await pushTo(env, r.viewer, { title: `📸 ${nm}`.slice(0, 60), body: "Sent a check-in snap. Tap to see it and react.", url: "/app/#snaps", tag: "ps-" + r.id.slice(3, 15) });
    return json({ id: sid }, 200, ch);
  }
  if (parts.length === 3 && M === "GET") { // both sides: the last 30 days (no photo data), newest first
    const rows = (await env.DB.prepare("SELECT id, k, meta, react FROM psnaps WHERE pid = ? AND created > ? ORDER BY at DESC LIMIT 60").bind(r.id, now - PROOF_DAYS * 864e5).all()).results || [];
    const out = []; for (const x of rows) { try { out.push({ id: x.id, k: x.k, react: x.react || "", ...(await openT(env, r.id, r.owner, x.meta)).doc }); } catch { } }
    return json({ snaps: out }, 200, ch);
  }
  if (parts.length === 5 && parts[4] === "photo" && M === "GET") { // viewer (or the owner) opens one
    const x = await env.DB.prepare("SELECT photo FROM psnaps WHERE pid = ? AND id = ?").bind(r.id, parts[3]).first();
    if (!x) return json({ error: "not found" }, 404, ch);
    try { return json({ photo: (await openT(env, r.id, r.owner, x.photo)).doc.photo }, 200, { ...ch, "cache-control": "no-store" }); } catch { return json({ error: "not found" }, 404, ch); }
  }
  if (parts.length === 5 && parts[4] === "react" && M === "POST") { // viewer reacts (can change it)
    if (!viewer) return json({ error: "forbidden" }, 403, ch);
    if (limited(req, 60, "preact")) return json({ error: "slow down" }, 429, ch);
    let b = {}; try { b = JSON.parse(await req.text() || "{}"); } catch { }
    if (!PS_REACT.includes(b.e)) return json({ error: "bad reaction" }, 400, ch);
    const x = await env.DB.prepare("SELECT react FROM psnaps WHERE pid = ? AND id = ?").bind(r.id, parts[3]).first(); if (!x) return json({ error: "not found" }, 404, ch);
    await env.DB.prepare("UPDATE psnaps SET react = ? WHERE pid = ? AND id = ?").bind(b.e, r.id, parts[3]).run();
    if (!x.react) { const nm = pName((await pNames(env, await env.DB.prepare("SELECT id, names FROM partners WHERE id = ?").bind(r.id).first())).viewer) || "Your partner";
      await pushTo(env, r.owner, { title: `${b.e} ${nm}`.slice(0, 60), body: "Reacted to your check-in snap.", url: "/app/", tag: "pr-" + parts[3].slice(3, 15) }); }
    return json({ ok: true }, 200, ch);
  }
  return json({ error: "not found" }, 404, ch);
}

// ---- sessions: base64url(json).base64url(hmac); payload {sub, email, ver, exp} ----
// ---- push notifications (Web Push, RFC 8291 + VAPID RFC 8292) ----
// Each device sends its own list of upcoming alerts (time + short title/body) for the next week; the minute timer
// (Cron Trigger) sends whatever is due. The device's push address and its alert list are sealed with the account key,
// like schedules. Only the next alert time is stored in the clear, so the timer can find due rows. Message contents are
// encrypted again for the device itself, so Apple, Google and Mozilla relay them without being able to read them.
// The signing key (VAPID) is created on first use and stored sealed, so there's no extra secret to set up.
const PUSH_HOSTS = /(^|\.)(fcm\.googleapis\.com|android\.googleapis\.com|push\.apple\.com|push\.services\.mozilla\.com|notify\.windows\.com)$/;
const MAX_Q = 80, MAX_DEVICES = 10, PUSH_AHEAD = 8 * 864e5, PUSH_LATE = 15 * 60000, PUSH_IDLE = 30 * 864e5;
const PUSH_URL = /^\/app\/(#[a-z]{1,20})?$/, PUSH_TAG = /^[A-Za-z0-9_@|.-]{0,60}$/;
let pushReady = false, VK = null;
async function pushInit(env) {
  if (pushReady) return;
  for (const q of ["CREATE TABLE IF NOT EXISTS push (id TEXT PRIMARY KEY, sub TEXT NOT NULL, box TEXT NOT NULL, next_at INTEGER, updated INTEGER NOT NULL)",
    "CREATE INDEX IF NOT EXISTS push_next ON push (next_at)", "CREATE INDEX IF NOT EXISTS push_by_sub ON push (sub)",
    "CREATE TABLE IF NOT EXISTS conf (k TEXT PRIMARY KEY, v TEXT NOT NULL)"]) await env.DB.prepare(q).run();
  pushReady = true;
}
async function vapidKeys(env) {
  if (VK) return VK;
  await pushInit(env);
  let row = await env.DB.prepare("SELECT v FROM conf WHERE k = 'vapid'").first();
  if (!row) {
    const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const pub = b64u(await crypto.subtle.exportKey("raw", kp.publicKey)), jwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
    await env.DB.prepare("INSERT OR IGNORE INTO conf (k, v) VALUES ('vapid', ?)").bind(await seal(env, "vapid", { pub, jwk })).run();
    row = await env.DB.prepare("SELECT v FROM conf WHERE k = 'vapid'").first(); // another request may have won the race: use theirs
  }
  let doc; try { doc = (await open(env, "vapid", row.v)).doc; }
  catch { await env.DB.prepare("DELETE FROM conf WHERE k = 'vapid'").run(); VK = null; return vapidKeys(env); } // data key was replaced: make a new signing key
  VK = { pub: doc.pub, key: await crypto.subtle.importKey("jwk", doc.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]) };
  return VK;
}
const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
async function hkdf(salt, ikm, info, len) {
  const k = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, k, len * 8));
}
async function encryptPush(t, text) { // RFC 8291, aes128gcm, single record
  const ua = unb64u(t.p256dh), auth = unb64u(t.auth);
  const eph = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPub = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", ua, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, eph.privateKey, 256));
  const ikm = await hkdf(auth, shared, cat(enc.encode("WebPush: info\0"), ua, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16), nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);
  const key = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, cat(enc.encode(text), new Uint8Array([2]))));
  const hdr = new Uint8Array(21); hdr.set(salt, 0); new DataView(hdr.buffer).setUint32(16, 4096); hdr[20] = 65;
  return cat(hdr, asPub, ct);
}
async function sendPush(env, t, msg) {
  const V = await vapidKeys(env), aud = new URL(t.ep).origin;
  const h = b64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" }))), p = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: "https://hourline.io" })));
  const sig = b64u(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, V.key, enc.encode(h + "." + p)));
  const body = await encryptPush(t, JSON.stringify({ title: msg.title, body: msg.body, url: msg.url || "/app/", tag: msg.tag || "" }));
  const r = await fetch(t.ep, { method: "POST", body, headers: { authorization: `vapid t=${h}.${p}.${sig}, k=${V.pub}`, "content-encoding": "aes128gcm", "content-type": "application/octet-stream", ttl: "900", urgency: "high" } });
  return r.status;
}
function pushTarget(env, b) {
  const s = b && b.sub, ep = s && String(s.endpoint || ""), k = s && s.keys || {};
  let u; try { u = new URL(ep); } catch { return null; }
  const test = env.PUSH_TEST_ORIGIN && u.origin === env.PUSH_TEST_ORIGIN; // local test harness only
  if (!test && (u.protocol !== "https:" || !PUSH_HOSTS.test(u.hostname))) return null; // only real push services: never an arbitrary URL
  if (ep.length > 1000) return null;
  try { if (unb64u(String(k.p256dh || "")).length !== 65 || unb64u(String(k.auth || "")).length !== 16) return null; } catch { return null; }
  return { ep, p256dh: String(k.p256dh), auth: String(k.auth) };
}
function pushQueue(q, now) {
  if (!Array.isArray(q) || q.length > MAX_Q) return null;
  const out = [];
  for (const x of q) {
    if (!x || !Number.isInteger(x.at) || typeof x.title !== "string" || typeof (x.body || "") !== "string") return null;
    if (x.title.length > 60 || (x.body || "").length > 140 || (x.url && !PUSH_URL.test(x.url)) || !PUSH_TAG.test(x.tag || "")) return null;
    if (x.at > now + PUSH_AHEAD) return null;
    if (x.at > now - 60000) out.push({ at: x.at, title: x.title, body: x.body || "", url: x.url || "/app/", tag: x.tag || "" });
  }
  return out.sort((a, b) => a.at - b.at);
}
const nextAt = q => q.length ? q[0].at : null;
// Leader nudges: at most NUDGE_DAILY per member per team per day, NUDGE_BATCH members per request (keeps each request
// well under Cloudflare's outgoing-request limit; the app sends larger teams in batches), newest NUDGE_DEVICES phones each.
const NUDGE_DAILY = 2, NUDGE_BATCH = 15, NUDGE_DEVICES = 3;
let nudgeReady = false;
async function nudgeInit(env) { if (nudgeReady) return; await env.DB.prepare("CREATE TABLE IF NOT EXISTS nudge_use (team TEXT NOT NULL, sub TEXT NOT NULL, day TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (team, sub, day))").run(); nudgeReady = true; }
async function pushRoutes(env, req, s, path, ch) {
  await pushInit(env);
  const now = Date.now(), b = await req.json().catch(() => null), t = pushTarget(env, b);
  if (!t) return json({ error: "bad subscription" }, 400, ch);
  const id = "p_" + await sha256("push:" + t.ep);
  if (path === "/push" && req.method === "PUT") { // turn on / refresh this device's alert list
    if (limited(req, 30, "push")) return json({ error: "slow down" }, 429, ch);
    const q = pushQueue(b.q, now);
    if (!q) return json({ error: "bad alerts" }, 400, ch);
    const n = await env.DB.prepare("SELECT COUNT(*) AS n FROM push WHERE sub = ? AND id != ?").bind(s.sub, id).first();
    if (n && n.n >= MAX_DEVICES) return json({ error: "too many devices" }, 409, ch);
    const own = await env.DB.prepare("SELECT sub FROM push WHERE id = ?").bind(id).first();
    if (own && own.sub !== s.sub) await env.DB.prepare("DELETE FROM push WHERE id = ?").bind(id).run(); // device changed accounts
    const box = await seal(env, s.sub, { ...t, q });
    await env.DB.prepare("INSERT INTO push (id, sub, box, next_at, updated) VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET box = excluded.box, next_at = excluded.next_at, updated = excluded.updated")
      .bind(id, s.sub, box, nextAt(q), now).run();
    return json({ ok: true, queued: q.length }, 200, ch);
  }
  if (path === "/push/off" && req.method === "POST") {
    await env.DB.prepare("DELETE FROM push WHERE id = ? AND sub = ?").bind(id, s.sub).run();
    return json({ ok: true }, 200, ch);
  }
  if (path === "/push/test" && req.method === "POST") { // "Send a test" in Settings
    if (limited(req, 5, "ptest")) return json({ error: "slow down" }, 429, ch);
    const row = await env.DB.prepare("SELECT sub FROM push WHERE id = ? AND sub = ?").bind(id, s.sub).first();
    if (!row) return json({ error: "not turned on" }, 404, ch);
    const st = await sendPush(env, t, { title: "Hourline", body: "Notifications are on. This is how block starts will look.", url: "/app/", tag: "test" });
    if (st === 404 || st === 410) { await env.DB.prepare("DELETE FROM push WHERE id = ?").bind(id).run(); return json({ error: "expired" }, 410, ch); }
    return json({ ok: st >= 200 && st < 300, status: st }, 200, ch);
  }
  return json({ error: "not found" }, 404, ch);
}
// Runs every minute (wrangler.toml [triggers]). Sends due alerts, drops expired devices and ones idle for 30 days.
async function runPush(env, now = Date.now()) {
  if (env.LOCKDOWN === "1" || env.LOCKDOWN === "true") return { sent: 0 };
  await pushInit(env);
  await env.DB.prepare("DELETE FROM push WHERE updated < ?").bind(now - PUSH_IDLE).run();
  const rows = (await env.DB.prepare("SELECT id, sub, box, updated FROM push WHERE next_at IS NOT NULL AND next_at <= ? ORDER BY next_at LIMIT 300").bind(now).all()).results || [];
  let sent = 0, dropped = 0;
  for (const r of rows) {
    let doc;
    try { doc = (await open(env, r.sub, r.box)).doc; } catch { await env.DB.prepare("DELETE FROM push WHERE id = ?").bind(r.id).run(); dropped++; continue; }
    const due = doc.q.filter(x => x.at <= now && now - x.at < PUSH_LATE).slice(-2), rest = doc.q.filter(x => x.at > now);
    let gone = false;
    for (const m of due) {
      let st = 0; try { st = await sendPush(env, doc, m); } catch { st = 0; }
      if (st === 404 || st === 410) { gone = true; break; }
      if (st >= 200 && st < 300) sent++;
    }
    if (gone) { await env.DB.prepare("DELETE FROM push WHERE id = ?").bind(r.id).run(); dropped++; continue; }
    // Only write back if the device didn't send a fresh list meanwhile.
    await env.DB.prepare("UPDATE push SET box = ?, next_at = ? WHERE id = ? AND updated = ?").bind(await seal(env, r.sub, { ...doc, q: rest }), nextAt(rest), r.id, r.updated).run();
  }
  return { sent, dropped, rows: rows.length };
}


// ---- Ella smart conversation (optional). The app answers most things on the device; only questions it can't handle come here.
// Needs ANTHROPIC_API_KEY (secret). Limits: 40 messages per account per day (ELLA_DAILY to change), 20 a minute per IP,
// small inputs. Nothing about the conversation is stored: only a per-day message count.
const ELLA_TONES = { friendly: "friendly and direct", respect: "direct and respectful", kind: "kind and gentle but still direct", neutral: "neutral and factual", strict: "strict, demanding, no excuses", cold: "blunt and cold, very few words", brutal: "brutally honest and direct, meant to shock someone out of apathy (attack excuses, never the person)" };
let ellaReady = false;
// the API wants user first and roles alternating: drop leading replies, join back-to-back turns from the same side
function ellaTurns(list) { const out = []; for (const m of list) { if (!out.length && m.role !== "user") continue; const last = out[out.length - 1]; if (last && last.role === m.role) last.content += "\n" + m.content; else out.push({ ...m }); } return out; }
async function ellaInit(env) { if (ellaReady) return; await env.DB.prepare("CREATE TABLE IF NOT EXISTS ella_use (sub TEXT NOT NULL, day TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (sub, day))").run(); ellaReady = true; }
async function ellaRoute(env, req, s, ch) {
  if (!env.ANTHROPIC_API_KEY) return json({ error: "not set up" }, 503, ch);
  if (limited(req, 20, "ella")) return json({ error: "slow down" }, 429, ch);
  const text = await req.text(); if (text.length > 12000) return json({ error: "too large" }, 413, ch);
  let b; try { b = JSON.parse(text); } catch { return json({ error: "bad request" }, 400, ch); }
  const q = String(b && b.q || "").trim().slice(0, 300); if (!q) return json({ error: "bad request" }, 400, ch);
  const hist = (Array.isArray(b.hist) ? b.hist : []).slice(-8).map(t => ({ role: t && t.r === "u" ? "user" : "assistant", content: String(t && t.t || "").slice(0, 400) })).filter(t => t.content);
  const ctx = JSON.stringify(b.ctx || {}).slice(0, 5000), tone = ELLA_TONES[b.tone] || ELLA_TONES.friendly;
  await ellaInit(env);
  const day = new Date().toISOString().slice(0, 10), max = +env.ELLA_DAILY || 40;
  const row = await env.DB.prepare("SELECT n FROM ella_use WHERE sub = ? AND day = ?").bind(s.sub, day).first();
  if (row && row.n >= max) return json({ error: "daily limit" }, 429, ch);
  await env.DB.prepare("INSERT INTO ella_use (sub, day, n) VALUES (?, ?, 1) ON CONFLICT(sub, day) DO UPDATE SET n = n + 1").bind(s.sub, day).run();
  await env.DB.prepare("DELETE FROM ella_use WHERE day < ?").bind(new Date(Date.now() - 3 * 864e5).toISOString().slice(0, 10)).run();
  const system = `You are Ella (short for Candela), a productivity and sales coach inside Hourline, a scheduling app for insurance and sales agents. Personality: ${tone}.
Rules: Reply in at most 3 short sentences (under 60 words). Plain text, no markdown, no lists. Use the user's data below when relevant; never invent numbers, names or appointments.
Stay on coaching: schedules, habits, prospecting, follow-ups, goals, motivation, sales conversations. For anything else (medical, legal, tax, investment advice, politics, personal crises), say briefly that you're a productivity coach and suggest the right kind of professional; if someone mentions self-harm or crisis, gently point them to 988 (US) or local emergency services.
You can't take actions from here; if they want to book, add a prospect or change a setting, tell them the exact phrase to say, e.g. "book an appointment with Sam Friday at 3".
Never shame the person. Never claim to be human.
User data (JSON): ${ctx}`;
  let r;
  try {
    r = await fetch(env.ANTHROPIC_URL || "https://api.anthropic.com/v1/messages", { method: "POST", headers: { "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json" },
      body: JSON.stringify({ model: env.ELLA_MODEL || "claude-haiku-5-5", max_tokens: 220, system, messages: ellaTurns([...hist, { role: "user", content: q }]) }) });
  } catch { return json({ error: "ai unavailable" }, 502, ch); }
  if (!r.ok) return json({ error: "ai unavailable" }, 502, ch);
  const out = await r.json().catch(() => null), reply = out && Array.isArray(out.content) ? out.content.filter(c => c.type === "text").map(c => c.text).join(" ").trim().slice(0, 600) : "";
  return json(reply ? { text: reply, left: Math.max(0, max - ((row ? row.n : 0) + 1)) } : { error: "ai unavailable" }, reply ? 200 : 502, ch);
}

// Ella's event finder: in-person networking events near a city, found with the AI's web search tool.
// Privacy: only the city/region the person typed is sent (no name, schedule, prospects or location coordinates).
// Results are cached per city + window for 12 hours and shared (they hold no personal data). Searches are limited per account.
let evReady = false;
async function evInit(env) { if (evReady) return;
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS events_cache (k TEXT PRIMARY KEY, at INTEGER NOT NULL, body TEXT NOT NULL)").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS events_use (sub TEXT NOT NULL, day TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (sub, day))").run(); evReady = true; }
const EV_CITY = /^[A-Za-z][A-Za-z .,'-]{1,59}$/, EV_HHMM = /^([01]\d|2[0-3]):[0-5]\d$/, EV_ISO = /^\d{4}-\d{2}-\d{2}$/;
const EV_FOCUS = { general: "business networking events, mixers and professional meetups", insurance: "business networking, chamber of commerce, small-business owner, real-estate, financial-services and community events where an insurance or financial agent can meet prospects", sales: "business networking, sales, entrepreneur and small-business events" };
function evClean(list, from, to) {
  const out = [];
  for (const x of Array.isArray(list) ? list : []) {
    if (!x || typeof x !== "object") continue;
    const title = String(x.title || "").trim().slice(0, 90), date = String(x.date || "");
    if (!title || !EV_ISO.test(date) || date < from || date > to) continue;
    let url = String(x.url || "").trim(); try { const u = new URL(url); if (u.protocol !== "https:") url = ""; else url = u.href.slice(0, 300); } catch { url = ""; }
    if (!url) continue; // no real https event page = can't be checked, so it isn't shown
    out.push({ title, date, start: EV_HHMM.test(x.start) ? x.start : "", end: EV_HHMM.test(x.end) ? x.end : "", venue: String(x.venue || "").slice(0, 80), address: String(x.address || "").slice(0, 120),
      cost: String(x.cost || "").slice(0, 30), url, why: String(x.why || "").slice(0, 140) });
    if (out.length >= 12) break;
  }
  return out.sort((a, b) => (a.date + a.start).localeCompare(b.date + b.start));
}
async function eventsRoute(env, req, s, ch) {
  if (!env.ANTHROPIC_API_KEY) return json({ error: "not set up" }, 503, ch);
  if (limited(req, 10, "events")) return json({ error: "slow down" }, 429, ch);
  const text = await req.text(); if (text.length > 2000) return json({ error: "too large" }, 413, ch);
  let b; try { b = JSON.parse(text); } catch { return json({ error: "bad request" }, 400, ch); }
  const city = String(b && b.city || "").trim().replace(/\s+/g, " "), region = String(b && b.region || "").trim().slice(0, 40), focus = EV_FOCUS[b && b.focus] ? b.focus : "insurance";
  const days = [7, 14, 30].includes(+(b && b.days)) ? +b.days : 14, tz = /^[A-Za-z_]+\/[A-Za-z_]+$/.test(b && b.tz || "") ? b.tz : "America/Chicago";
  if (!EV_CITY.test(city) || (region && !EV_CITY.test(region))) return json({ error: "bad city" }, 400, ch);
  await evInit(env);
  const from = new Date().toISOString().slice(0, 10), to = new Date(Date.now() + days * 864e5).toISOString().slice(0, 10);
  const key = [city.toLowerCase(), region.toLowerCase(), focus, days, from].join("|");
  const hit = await env.DB.prepare("SELECT at, body FROM events_cache WHERE k = ?").bind(key).first();
  if (hit && Date.now() - hit.at < 12 * 3600e3) return json({ events: JSON.parse(hit.body), cached: true }, 200, ch);
  const day = from, max = +env.EVENTS_DAILY || 5;
  const row = await env.DB.prepare("SELECT n FROM events_use WHERE sub = ? AND day = ?").bind(s.sub, day).first();
  if (row && row.n >= max) return json({ error: "daily limit" }, 429, ch);
  await env.DB.prepare("INSERT INTO events_use (sub, day, n) VALUES (?, ?, 1) ON CONFLICT(sub, day) DO UPDATE SET n = n + 1").bind(s.sub, day).run();
  await env.DB.prepare("DELETE FROM events_use WHERE day < ?").bind(new Date(Date.now() - 3 * 864e5).toISOString().slice(0, 10)).run();
  await env.DB.prepare("DELETE FROM events_cache WHERE at < ?").bind(Date.now() - 2 * 864e5).run();
  const place = city + (region ? ", " + region : "");
  const system = `You find real, upcoming, in-person events for a sales professional. Use web search. Only include events you found on a real web page with a specific date between ${from} and ${to} in or near ${place}. Never invent events, dates, venues or links.
Reply with ONLY a JSON array (no prose, no markdown), up to 10 items, each: {"title":"","date":"YYYY-MM-DD","start":"HH:MM" (24h, or ""),"end":"HH:MM" or "","venue":"","address":"","cost":"Free" or price or "","url":"https link to the event page","why":"one short sentence on why it's good for meeting prospects"}. If you find nothing, reply [].`;
  let r;
  try {
    r = await fetch(env.ANTHROPIC_URL || "https://api.anthropic.com/v1/messages", { method: "POST", headers: { "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json" },
      body: JSON.stringify({ model: env.EVENTS_MODEL || env.ELLA_MODEL || "claude-haiku-5-5", max_tokens: 1800, system,
        tools: [{ type: env.WEB_SEARCH_TOOL || "web_search_20250305", name: "web_search", max_uses: 4, user_location: { type: "approximate", city, ...(region ? { region } : {}), country: "US", timezone: tz } }],
        messages: [{ role: "user", content: `Find ${EV_FOCUS[focus]} in ${place} from ${from} to ${to}. Prefer Eventbrite, Meetup, chamber of commerce and venue pages.` }] }) });
  } catch { return json({ error: "ai unavailable" }, 502, ch); }
  if (!r.ok) return json({ error: "ai unavailable" }, 502, ch);
  const out = await r.json().catch(() => null), txt = out && Array.isArray(out.content) ? out.content.filter(c => c.type === "text").map(c => c.text).join("\n") : "";
  const m = txt.match(/\[[\s\S]*\]/); let list = []; try { list = m ? JSON.parse(m[0]) : []; } catch { list = []; }
  const events = evClean(list, from, to);
  await env.DB.prepare("INSERT INTO events_cache (k, at, body) VALUES (?, ?, ?) ON CONFLICT(k) DO UPDATE SET at = excluded.at, body = excluded.body").bind(key, Date.now(), JSON.stringify(events)).run();
  return json({ events, left: Math.max(0, max - ((row ? row.n : 0) + 1)) }, 200, ch);
}

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
function limited(req, max, bucket = "auth") { // separate counters per kind of request
  const ip = (req.headers.get("cf-connecting-ip") || "local") + "|" + bucket, now = Date.now(), w = hits.get(ip) || [];
  const recent = w.filter(t => now - t < 60000); recent.push(now); hits.set(ip, recent);
  if (hits.size > 5000) hits.clear();
  return recent.length > max;
}
const validState = s => /^[A-Za-z0-9_-]{22,64}$/.test(s || "");

export default {
  async fetch(req, env) {
    const url = new URL(req.url), path = url.pathname, ch = cors(env, req);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: { ...ch, ...SEC } });
    // Emergency switch: set LOCKDOWN = 1 in Worker settings to stop all sign-ins and data access at once (the app keeps working
    // offline on each device; nothing is lost). Remove it to turn sync back on.
    if (env.LOCKDOWN === "1" || env.LOCKDOWN === "true") {
      if (path === "/" || path === "/health") return json({ ok: true, lockdown: true }, 200, ch);
      return path.startsWith("/auth/") && req.method !== "GET" || path === "/auth/start"
        ? page("Sync paused", "<h1>Sync is paused</h1><p>Hourline sync is temporarily turned off. Your schedule is safe on your device. Try again later.</p>", 503)
        : json({ error: "sync paused" }, 503, ch);
    }
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
          if (!row) return json({ rev: 0, doc: null }, 200, ch);
          let o; try { o = await open(env, s.sub, row.doc); } catch { return json({ rev: row.rev, doc: null, unreadable: true }, 200, ch); } // key was replaced: device re-uploads its copy
          if (o.stale) await env.DB.prepare("UPDATE docs SET doc = ? WHERE sub = ? AND rev = ?").bind(await seal(env, s.sub, o.doc), s.sub, row.rev).run(); // re-encrypt under the new key
          return json({ rev: row.rev, doc: o.doc, updated: row.updated }, 200, ch);
        }
        if (req.method === "PUT") {
          if (limited(req, 60, "data")) return json({ error: "slow down" }, 429, ch);
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
            let cdoc = null; if (row) try { cdoc = (await open(env, s.sub, row.doc)).doc; } catch { cdoc = null; }
            return json({ error: "conflict", rev: row ? row.rev : 0, doc: cdoc }, 409, ch);
          }
          return json({ rev: baseRev ? baseRev + 1 : 1, updated: now }, 200, ch);
        }
        if (req.method === "DELETE") { // "Delete my cloud data": removes the schedule and signs out every device
          await env.DB.prepare("DELETE FROM docs WHERE sub = ?").bind(s.sub).run();
          const owned = (await env.DB.prepare("SELECT id FROM teams WHERE owner = ?").bind(s.sub).all()).results || [];
          for (const t of owned) await dropTeam(env, t.id);
          await env.DB.prepare("DELETE FROM snaps WHERE sub = ?").bind(s.sub).run();
          await proofInit(env); await env.DB.prepare("DELETE FROM proofs WHERE sub = ?").bind(s.sub).run();
          await env.DB.prepare("DELETE FROM members WHERE sub = ?").bind(s.sub).run();
          await pushInit(env); await env.DB.prepare("DELETE FROM push WHERE sub = ?").bind(s.sub).run();
          await ellaInit(env); await env.DB.prepare("DELETE FROM ella_use WHERE sub = ?").bind(s.sub).run();
          await evInit(env); await env.DB.prepare("DELETE FROM events_use WHERE sub = ?").bind(s.sub).run();
          await nudgeInit(env); await env.DB.prepare("DELETE FROM nudge_use WHERE sub = ?").bind(s.sub).run();
          await partnersInit(env); await psInit(env); await env.DB.prepare("DELETE FROM psnaps WHERE pid IN (SELECT id FROM partners WHERE owner = ? OR viewer = ?)").bind(s.sub, s.sub).run();
          await partnersInit(env); await env.DB.prepare("DELETE FROM partners WHERE owner = ? OR viewer = ?").bind(s.sub, s.sub).run();
          await env.DB.prepare("INSERT INTO accounts (sub, ver) VALUES (?, 1) ON CONFLICT(sub) DO UPDATE SET ver = ver + 1").bind(s.sub).run();
          return json({ ok: true }, 200, ch);
        }
      }
      if (path === "/partners" || path.startsWith("/partners/")) {
        if (!s) return json({ error: "signed out" }, 401, ch);
        return await partners(env, req, s, path, ch);
      }
      if (path === "/teams" || path.startsWith("/teams/")) {
        if (!s) return json({ error: "signed out" }, 401, ch);
        return await teams(env, req, s, path, ch);
      }
      if (path === "/ella" && req.method === "POST") { if (!s) return json({ error: "signed out" }, 401, ch); return await ellaRoute(env, req, s, ch); }
      if (path === "/events" && req.method === "POST") { if (!s) return json({ error: "signed out" }, 401, ch); return await eventsRoute(env, req, s, ch); }
      if (path === "/push/key" && req.method === "GET") return json({ key: (await vapidKeys(env)).pub }, 200, ch);
      if (path === "/push" || path.startsWith("/push/")) {
        if (!s) return json({ error: "signed out" }, 401, ch);
        return await pushRoutes(env, req, s, path, ch);
      }
      if (path === "/" || path === "/health") // setup check: says only whether each setting exists, never its value
        return json({ ok: true, service: "schedule-io-sync", setup: { db: !!env.DB, google: !!env.GOOGLE_CLIENT_ID, origin: !!env.APP_ORIGIN, session: !!env.SESSION_SECRET, data: !!env.DATA_KEY, push: !!globalThis.crypto?.subtle } }, 200, ch);
      return json({ error: "not found" }, 404, ch);
    } catch (e) {
      if (e && e.status === 413) return json({ error: "too large" }, 413, ch);
      console.error("server error", req.method, path.replace(/\/teams\/[^/]+/, "/teams/:id"), e && e.name, String(e && e.message || "").slice(0, 200)); // no user data
      if (path.startsWith("/push")) return json({ error: "server error", code: String(e && e.name || "") + ": " + String(e && e.message || "").slice(0, 120) }, 500, ch);
      if (path === "/auth/callback") return page("Sign-in error", "<h1>Sign-in didn't work</h1><p>Return to Hourline and try again.</p>", 400);
      return json({ error: "server error" }, 500, ch);
    }
  },
  async scheduled(ev, env, ctx) { ctx.waitUntil(runPush(env)); // every minute: send due notifications
    if (new Date().getUTCMinutes() === 7) ctx.waitUntil((async () => { await proofInit(env); await env.DB.prepare("DELETE FROM proofs WHERE created < ?").bind(Date.now() - PROOF_DAYS * 864e5).run();
      await psInit(env); await env.DB.prepare("DELETE FROM psnaps WHERE created < ?").bind(Date.now() - PROOF_DAYS * 864e5).run(); })()); } // hourly: proofs past 30 days
};
