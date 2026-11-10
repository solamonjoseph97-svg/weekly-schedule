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
//   GCAL_OPEN (text "1" once Google approves the calendar permissions; until then only ADMIN_EMAILS and GCAL_TESTERS see Connect Google Calendar)
//   ADMIN_EMAILS (text, comma-separated Google emails that can read problem reports; defaults to the owner)
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

// ---- teams: a member's device publishes a filtered copy of their schedule for their team lead, and for any teammates they pick ----
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
// Sharing with teammates: each shared copy lists which teammates (by member id) may read it, besides the lead, and each
// member's display name is kept sealed so teammates can be shown by name. Added columns, created on first use.
let shareReady = false;
async function shareInit(env) { if (shareReady) return;
  for (const q of ["ALTER TABLE snaps ADD COLUMN readers TEXT", "ALTER TABLE members ADD COLUMN nbox TEXT", "ALTER TABLE members ADD COLUMN upline TEXT", "ALTER TABLE members ADD COLUMN level INTEGER", "ALTER TABLE members ADD COLUMN pbox TEXT", "ALTER TABLE teams ADD COLUMN cbox TEXT"]) { try { await env.DB.prepare(q).run(); } catch (e) { /* already there */ } }
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS tpart (team TEXT NOT NULL, a TEXT NOT NULL, b TEXT NOT NULL, state TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY (team, a, b))").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS rcodes (team TEXT NOT NULL, mid TEXT NOT NULL, hash TEXT NOT NULL, created INTEGER NOT NULL, PRIMARY KEY (team, mid))").run();
  shareReady = true; }
// The team is a tree: each member's upline is who recruited them (the lead when unknown). Anyone with recruits leads
// that branch: every upline sees their whole branch's shared copies. Peers see each other only as accepted partners.
const LEVELS = [30, 40, 50, 60, 70];
// A Marketing Director (70% and up) is released from their upline: nobody above them sees them or their branch, or
// changes their level; they lead their own branch and set their own percentage above 70.
// The team lead has no upline: their level starts unset and they set it themselves (it isn't assumed to be 70).
const RELEASE = 70;
function treeOf(ms) { // ms: [{mid, role, upline, level}] -> parent map with the lead as root, cycles and strays re-parented to the lead
  const root = (ms.find(m => m.role === "lead") || {}).mid, ids = new Set(ms.map(m => m.mid)), par = {}, rel = new Set(ms.filter(m => m.role !== "lead" && (+m.level || 0) >= RELEASE).map(m => m.mid));
  for (const m of ms) par[m.mid] = m.mid === root ? null : (m.upline && ids.has(m.upline) && m.upline !== m.mid ? m.upline : root);
  for (const m of ms) { let x = par[m.mid], n = 0; while (x && n < 600) { if (x === m.mid) { par[m.mid] = root; break; } x = par[x]; n++; } }
  return { root, par, rel };
}
// is `up` above `mid` with nobody released in between (a released MD is out of reach of everyone above them)
const isAbove = (T, up, mid) => { let cur = mid, n = 0; while (n++ < 600) { if (T.rel.has(cur)) return false; const p = T.par[cur]; if (!p) return false; if (p === up) return true; cur = p; } return false; };
async function partnersOf(env, team, mid) { const r = (await env.DB.prepare("SELECT a, b, state FROM tpart WHERE team = ? AND (a = ? OR b = ?)").bind(team, mid, mid).all()).results || [];
  const o = {}; for (const x of r) { const other = x.a === mid ? x.b : x.a; o[other] = x.state === "yes" ? "yes" : x.a === mid ? "out" : "in"; } return o; }
const PHOTO_MAX = 90_000; // a small JPEG or WebP as a data URL; the app shrinks pictures before sending
const photoOk = v => typeof v === "string" && v.length <= PHOTO_MAX && /^data:image\/(jpeg|webp|png);base64,[A-Za-z0-9+/=]+$/.test(v);
const readersOf = r => { try { const a = JSON.parse(r || "[]"); return Array.isArray(a) ? a.map(String) : []; } catch { return []; } };
async function dropTeam(env, team) {
  await env.DB.prepare("DELETE FROM snaps WHERE team = ?").bind(team).run();
  await boardInit(env); await env.DB.prepare("DELETE FROM boards WHERE team = ?").bind(team).run();
  await proofInit(env); await env.DB.prepare("DELETE FROM proofs WHERE team = ?").bind(team).run();
  await env.DB.prepare("DELETE FROM members WHERE team = ?").bind(team).run();
  await shareInit(env); await env.DB.prepare("DELETE FROM tpart WHERE team = ?").bind(team).run(); await env.DB.prepare("DELETE FROM rcodes WHERE team = ?").bind(team).run();
  await tmetInit(env); await env.DB.prepare("DELETE FROM tmetrics WHERE team = ?").bind(team).run();
  await rcInit(env); for (const t of ["recruits", "comps", "cscores"]) await env.DB.prepare(`DELETE FROM ${t} WHERE team = ?`).bind(team).run();
  await bkInit(env); for (const t of ["avail", "bkg"]) await env.DB.prepare(`DELETE FROM ${t} WHERE team = ?`).bind(team).run();
  await env.DB.prepare("DELETE FROM teams WHERE id = ?").bind(team).run();
}
const MAX_BOARD = 2000; let boardReady = false;
// team metrics: the lead sets the team's; any upline can set their own branch's. A member uses the nearest set above them
// (or their own, if they lead a branch), stopping at a released Marketing Director, who sets their branch's.
let tmetReady = false;
async function tmetInit(env) { if (tmetReady) return; await env.DB.prepare("CREATE TABLE IF NOT EXISTS tmetrics (team TEXT NOT NULL, mid TEXT NOT NULL, box TEXT NOT NULL, updated INTEGER NOT NULL, PRIMARY KEY (team, mid))").run(); tmetReady = true; }
// recruits: "Got coded ($199 paid)", approved by the nearest Marketing Director above the recruiter (or the team lead),
// or by whoever runs a recruit competition the recruiter is in. Sealed; a phone already approved on this team is flagged.
// competitions: top finishers / hit the goal / team goal, on one team number (or approved recruits, counted here, not by the phone).
// booking time: your uplines, your downline and your accountability partners can ask for time on your calendar, inside the hours you set.
// avail: your hours plus busy times only (never titles), sealed. bookings: a request, counter-offers, accept / decline / cancel, sealed.
let bkReady = false;
async function bkInit(env) { if (bkReady) return;
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS avail (team TEXT NOT NULL, mid TEXT NOT NULL, box TEXT NOT NULL, updated INTEGER NOT NULL, PRIMARY KEY (team, mid))").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS bkg (team TEXT NOT NULL, id TEXT NOT NULL, a TEXT NOT NULL, b TEXT NOT NULL, state TEXT NOT NULL, turn TEXT, box TEXT NOT NULL, day TEXT NOT NULL, created INTEGER NOT NULL, updated INTEGER NOT NULL, PRIMARY KEY (team, id))").run();
  bkReady = true; }
const BK_KINDS = ["checkin", "threeway", "training", "field", "strategy", "other"], BK_HOW = ["phone", "video", "person"];
const hhmmOk = v => /^([01]\d|2[0-3]):[0-5]\d$/.test(String(v || ""));
function cleanHours(h) { if (!h || typeof h !== "object") return null; const days = (Array.isArray(h.days) ? h.days : []).map(Number).filter(d => d >= 0 && d <= 6);
  if (!hhmmOk(h.from) || !hhmmOk(h.to) || h.to <= h.from) return null; return { days: [...new Set(days)].sort(), from: h.from, to: h.to, open: h.open !== false }; }
let rcReady = false;
async function rcInit(env) { if (rcReady) return;
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS recruits (team TEXT NOT NULL, id TEXT NOT NULL, by_mid TEXT NOT NULL, approver TEXT NOT NULL, state TEXT NOT NULL, box TEXT NOT NULL, phash TEXT, created INTEGER NOT NULL, decided INTEGER, PRIMARY KEY (team, id))").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS comps (team TEXT NOT NULL, id TEXT NOT NULL, owner TEXT NOT NULL, box TEXT NOT NULL, starts TEXT NOT NULL, ends TEXT NOT NULL, created INTEGER NOT NULL, PRIMARY KEY (team, id))").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS cscores (team TEXT NOT NULL, comp TEXT NOT NULL, mid TEXT NOT NULL, value REAL NOT NULL, updated INTEGER NOT NULL, PRIMARY KEY (team, comp, mid))").run();
  rcReady = true; }
const PRIZE_PHOTO_MAX = 160_000;
const prizePhotoOk = v => typeof v === "string" && v.length <= PRIZE_PHOTO_MAX && /^data:image\/(jpeg|webp|png);base64,[A-Za-z0-9+/=]+$/.test(v);
const isoDay = v => /^\d{4}-\d{2}-\d{2}$/.test(String(v || "")) ? String(v) : "";
function descendants(T, all, mid) { const out = new Set([mid]); let grew = true; while (grew) { grew = false; for (const m of all) if (!out.has(m.mid) && out.has(T.par[m.mid]) && !T.rel.has(m.mid)) { out.add(m.mid); grew = true; } } return out; }
function recruitApprover(T, byMid) { // nearest released MD strictly above, else the team lead
  let cur = T.par[byMid], n = 0; while (cur && n++ < 600) { if (T.rel.has(cur)) return cur; if (!T.par[cur]) return cur; cur = T.par[cur]; }
  return T.root; }
function cleanComp(b) {
  const name = String(b.name || "").trim().slice(0, 50), metric = String(b.metric || "").trim().slice(0, 30), kind = ["rank", "mark", "team"].includes(b.kind) ? b.kind : "";
  if (!name || !metric || !kind) return null;
  const goal = Math.max(0, Math.min(1e9, +b.goal || 0)); if (kind !== "rank" && !(goal > 0)) return null;
  const winners = Math.max(0, Math.min(50, Math.round(+b.winners || 0)));
  const prizes = (Array.isArray(b.prizes) ? b.prizes : []).slice(0, 10).map(x => String(x || "").trim().slice(0, 80));
  if (kind === "rank" && !prizes.filter(Boolean).length) return null;
  const starts = isoDay(b.starts), ends = isoDay(b.ends); if (!starts || !ends || ends < starts) return null;
  const scope = b.scope === "pick" ? "pick" : "tree", pick = scope === "pick" ? (Array.isArray(b.pick) ? b.pick : []).map(String).slice(0, 300) : [];
  const unit = b.unit === "money" ? "money" : "count";
  return { name, metric, kind, goal, winners, prizes, starts, ends, scope, pick, unit, photo: prizePhotoOk(b.photo) ? b.photo : "" };
}
const MET_FEEDS = ["", "met", "call", "text", "convo", "appt", "pres", "sale", "none"];
function cleanMetrics(a) {
  if (!Array.isArray(a) || a.length > 12) return null; const out = [], seen = new Set();
  for (const x of a) {
    if (!x || typeof x !== "object") return null; const name = String(x.name || "").trim().slice(0, 30); if (!name || seen.has(name.toLowerCase())) return null; seen.add(name.toLowerCase());
    const target = Math.max(0, Math.min(1e7, Math.round(+x.target || 0))), unit = x.unit === "money" ? "money" : "count", feed = MET_FEEDS.includes(String(x.feed || "")) ? String(x.feed || "") : "";
    const m = { name, target, unit, feed };
    if (x.comp && typeof x.comp === "object") { const ct = Math.max(0, Math.min(1e8, Math.round(+x.comp.target || 0))), prize = String(x.comp.prize || "").trim().slice(0, 80), ends = /^\d{4}-\d{2}-\d{2}$/.test(String(x.comp.ends || "")) ? String(x.comp.ends) : ""; if (ct > 0) m.comp = { target: ct, prize, ends }; }
    out.push(m);
  }
  return out;
}
async function boardInit(env) { if (boardReady) return; await env.DB.prepare("CREATE TABLE IF NOT EXISTS boards (team TEXT PRIMARY KEY, doc TEXT NOT NULL, updated INTEGER NOT NULL)").run(); boardReady = true; }
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
    let recruiter = null;
    if (t && (await sha256(inv)) !== t.invite_hash) { await shareInit(env); const rc = await env.DB.prepare("SELECT r.mid AS mid FROM rcodes r JOIN members m ON m.team = r.team AND m.mid = r.mid WHERE r.team = ? AND r.hash = ?").bind(id, await sha256(inv)).first(); recruiter = rc ? rc.mid : null; }
    if (!t || ((await sha256(inv)) !== t.invite_hash && !recruiter)) return json({ error: "invite not valid" }, 403, ch);
    const had = await memberOf(env, id, s.sub);
    if (had) return json({ id, name: t.name, role: had.role, mid: had.mid }, 200, ch);
    const n = await env.DB.prepare("SELECT COUNT(*) AS n FROM members WHERE team = ?").bind(id).first();
    if (n && n.n >= MAX_MEMBERS) return json({ error: "team full" }, 403, ch);
    const mid = "mb_" + rnd(12);
    await env.DB.prepare("INSERT INTO members (team, sub, mid, role, joined) VALUES (?, ?, ?, 'member', ?)").bind(id, s.sub, mid, now).run();
    // the invite link can say who shared it: they become the new member's upline (checked: must be on this team)
    const by = recruiter || String(b.by || ""); if (by) { await shareInit(env); const up = await env.DB.prepare("SELECT mid FROM members WHERE team = ? AND mid = ?").bind(id, by).first(); if (up) await env.DB.prepare("UPDATE members SET upline = ?, level = 30 WHERE team = ? AND sub = ?").bind(up.mid, id, s.sub).run(); }
    return json({ id, name: t.name, role: "member", mid }, 200, ch);
  }
  const id = parts[1];
  if (!teamIdOk(id)) return json({ error: "not found" }, 404, ch);
  const me = await memberOf(env, id, s.sub);
  if (!me) return json({ error: "not found" }, 404, ch); // never reveal whether a team exists to outsiders
  const lead = me.role === "lead";
  if (parts[2] === "proofs") return proofRoutes(env, req, s, id, me, parts, ch);
  if (parts.length === 3 && parts[2] === "roster" && M === "GET") { // any member: the team tree with names, photos, levels and (if they chose) phone/email
    await shareInit(env);
    const ms = (await env.DB.prepare("SELECT m.sub AS sub, m.mid AS mid, m.role AS role, m.nbox AS nbox, m.pbox AS pbox, m.upline AS upline, m.level AS level, m.joined AS joined, s.readers AS readers FROM members m LEFT JOIN snaps s ON s.team = m.team AND s.sub = m.sub WHERE m.team = ?").bind(id).all()).results || [];
    const T = treeOf(ms), P = await partnersOf(env, id, me.mid), t = await env.DB.prepare("SELECT name, cbox FROM teams WHERE id = ?").bind(id).first();
    let crest = ""; if (t && t.cbox) { try { crest = (await openT(env, id, "crest", t.cbox)).doc.image || ""; } catch { crest = ""; } }
    const out = [];
    for (const m of ms) {
      let pr = {}; if (m.pbox) { try { pr = (await openT(env, id, m.sub, m.pbox)).doc || {}; } catch { pr = {}; } }
      let name = String(pr.name || ""); if (!name && m.nbox) { try { name = String((await openT(env, id, m.sub, m.nbox)).doc.name || ""); } catch { name = ""; } }
      const mine = m.sub === s.sub, above = isAbove(T, me.mid, m.mid);
      out.push({ mid: m.mid, role: m.role, upline: T.par[m.mid], released: T.rel.has(m.mid), level: m.level || (m.role === "lead" ? null : 30), name: name.slice(0, 40), photo: photoOk(pr.photo) ? pr.photo : "",
        phone: String(pr.phone || "").slice(0, 24), email: String(pr.email || "").slice(0, 80), joined: m.joined || null, me: mine,
        partner: mine ? "" : P[m.mid] || "", canSee: !mine && (above || P[m.mid] === "yes" || readersOf(m.readers).includes(me.mid)),
        canEdit: mine ? (m.role === "lead" || T.rel.has(m.mid)) : above, sharesWithMe: !mine && (above || P[m.mid] === "yes" || readersOf(m.readers).includes(me.mid)) });
    }
    return json({ team: { name: t ? t.name : "Team", crest }, root: T.root, me: me.mid, members: out }, 200, ch);
  }
  if (parts.length === 3 && parts[2] === "recruit" && M === "POST") { // any member: a personal invite; whoever joins with it is placed under them. A new one replaces the old.
    if (limited(req, 10, "recruit")) return json({ error: "slow down" }, 429, ch);
    await shareInit(env); const code = rnd(24);
    await env.DB.prepare("INSERT INTO rcodes (team, mid, hash, created) VALUES (?, ?, ?, ?) ON CONFLICT(team, mid) DO UPDATE SET hash = excluded.hash, created = excluded.created").bind(id, me.mid, await sha256(code), now).run();
    return json({ invite: code }, 200, ch);
  }
  if (parts.length === 3 && parts[2] === "profile" && M === "PUT") { // my card: name, photo, and phone/email only if I chose to show them
    if (limited(req, 30, "profile")) return json({ error: "slow down" }, 429, ch);
    await shareInit(env); const b = await body();
    if (b.photo && !photoOk(b.photo)) return json({ error: "photo too large" }, 413, ch);
    const pr = { name: String(b.name || "").trim().slice(0, 40), photo: b.photo || "", phone: String(b.phone || "").replace(/[^0-9+()\- .]/g, "").slice(0, 24), email: /^[^@\s]{1,64}@[^@\s]{1,80}$/.test(String(b.email || "")) ? String(b.email).slice(0, 80) : "" };
    await env.DB.prepare("UPDATE members SET pbox = ?, nbox = ? WHERE team = ? AND sub = ?").bind(await sealT(env, id, s.sub, pr), pr.name ? await sealT(env, id, s.sub, { name: pr.name }) : null, id, s.sub).run();
    return json({ ok: true }, 200, ch);
  }
  if (parts.length === 3 && parts[2] === "crest" && M === "PUT") { // lead: team picture and name
    if (!lead) return json({ error: "forbidden" }, 403, ch);
    await shareInit(env); const b = await body();
    if (b.image && !photoOk(b.image)) return json({ error: "photo too large" }, 413, ch);
    if (b.image !== undefined) await env.DB.prepare("UPDATE teams SET cbox = ? WHERE id = ?").bind(b.image ? await sealT(env, id, "crest", { image: b.image }) : null, id).run();
    const nm = String(b.name || "").trim().slice(0, 40); if (nm) await env.DB.prepare("UPDATE teams SET name = ? WHERE id = ?").bind(nm, id).run();
    return json({ ok: true }, 200, ch);
  }
  if (parts.length === 4 && parts[2] === "members" && M === "PUT") { // an upline sets a downline member's contract level, or moves them under someone in their branch
    await shareInit(env); const b = await body();
    const ms = (await env.DB.prepare("SELECT mid, role, upline, level FROM members WHERE team = ?").bind(id).all()).results || [], T = treeOf(ms), tg = ms.find(m => m.mid === parts[3]);
    if (!tg) return json({ error: "not found" }, 404, ch);
    if (tg.mid === me.mid) { // the team lead has no upline, so they set their own level (any, 30 and up); a released MD sets their own, 70 and up
      const lv = Math.round(+b.level), lo = tg.role === "lead" ? 30 : RELEASE; if (!(tg.role === "lead" || T.rel.has(tg.mid)) || b.upline !== undefined || !(lv >= lo && lv <= 150)) return json({ error: "forbidden" }, 403, ch);
      await env.DB.prepare("UPDATE members SET level = ? WHERE team = ? AND mid = ?").bind(lv, id, tg.mid).run(); return json({ ok: true }, 200, ch); }
    if (tg.role === "lead") return json({ error: "not found" }, 404, ch);
    if (!isAbove(T, me.mid, tg.mid)) return json({ error: "forbidden" }, 403, ch);
    if (b.level !== undefined) { const lv = Math.round(+b.level); if (!(lv >= 30 && lv <= 150)) return json({ error: "bad level" }, 400, ch);
      await env.DB.prepare("UPDATE members SET level = ? WHERE team = ? AND mid = ?").bind(lv, id, tg.mid).run(); }
    if (b.upline !== undefined) { const nu = String(b.upline);
      if (!ms.some(m => m.mid === nu) || nu === tg.mid || isAbove(T, tg.mid, nu)) return json({ error: "bad upline" }, 400, ch); // not themselves, not someone under them
      if (!(nu === me.mid || isAbove(T, me.mid, nu))) return json({ error: "forbidden" }, 403, ch); // only within your own branch
      await env.DB.prepare("UPDATE members SET upline = ? WHERE team = ? AND mid = ?").bind(nu, id, tg.mid).run(); }
    return json({ ok: true }, 200, ch);
  }
  if (parts[2] === "partners" && parts.length >= 4) { // accountability partners inside a team: ask, accept, end
    await shareInit(env); const other = parts[3];
    const o = await env.DB.prepare("SELECT mid FROM members WHERE team = ? AND mid = ?").bind(id, other).first();
    if (!o || other === me.mid) return json({ error: "not found" }, 404, ch);
    const ab = await env.DB.prepare("SELECT a, b, state FROM tpart WHERE team = ? AND ((a = ? AND b = ?) OR (a = ? AND b = ?))").bind(id, me.mid, other, other, me.mid).first();
    if (parts.length === 4 && M === "POST") { // ask (or, if they already asked me, this accepts)
      if (limited(req, 20, "tpart")) return json({ error: "slow down" }, 429, ch);
      if (ab && ab.state === "yes") return json({ state: "yes" }, 200, ch);
      if (ab && ab.a === other) { await env.DB.prepare("UPDATE tpart SET state = 'yes', at = ? WHERE team = ? AND a = ? AND b = ?").bind(now, id, other, me.mid).run(); return json({ state: "yes" }, 200, ch); }
      if (!ab) await env.DB.prepare("INSERT INTO tpart (team, a, b, state, at) VALUES (?, ?, ?, 'req', ?)").bind(id, me.mid, other, now).run();
      return json({ state: "out" }, 200, ch);
    }
    if (parts.length === 5 && parts[4] === "accept" && M === "POST") {
      if (!ab || ab.a !== other || ab.state !== "req") return json({ error: "no request" }, 404, ch);
      await env.DB.prepare("UPDATE tpart SET state = 'yes', at = ? WHERE team = ? AND a = ? AND b = ?").bind(now, id, other, me.mid).run();
      return json({ state: "yes" }, 200, ch);
    }
    if (parts.length === 4 && M === "DELETE") { // decline, cancel or end: either side, any time
      await env.DB.prepare("DELETE FROM tpart WHERE team = ? AND ((a = ? AND b = ?) OR (a = ? AND b = ?))").bind(id, me.mid, other, other, me.mid).run();
      return json({ state: "" }, 200, ch);
    }
    return json({ error: "not found" }, 404, ch);
  }
  if (parts.length === 3 && parts[2] === "shared" && M === "GET") { // any member: the copies teammates chose to share with me
    await shareInit(env);
    const ms = (await env.DB.prepare("SELECT m.sub AS sub, m.mid AS mid, m.role AS role, s.doc AS doc, s.updated AS updated, s.readers AS readers FROM members m JOIN snaps s ON s.team = m.team AND s.sub = m.sub WHERE m.team = ?").bind(id).all()).results || [];
    const all = (await env.DB.prepare("SELECT mid, role, upline, level FROM members WHERE team = ?").bind(id).all()).results || [], T = treeOf(all), P = await partnersOf(env, id, me.mid);
    const out = [];
    for (const m of ms) {
      if (m.sub === s.sub) continue;
      const why = isAbove(T, me.mid, m.mid) ? "upline" : P[m.mid] === "yes" ? "partner" : readersOf(m.readers).includes(me.mid) ? "shared" : "";
      if (!why) continue;
      let doc = null; try { doc = (await openT(env, id, m.sub, m.doc)).doc; } catch { doc = null; }
      out.push({ mid: m.mid, role: m.role, updated: m.updated || null, doc, why });
    }
    return json({ members: out }, 200, ch);
  }
  if (parts.length === 2 && M === "GET") { // lead only: every member's latest shared copy
    if (!lead) return json({ error: "forbidden" }, 403, ch);
    const t = await env.DB.prepare("SELECT name FROM teams WHERE id = ?").bind(id).first();
    const ms = (await env.DB.prepare("SELECT m.sub AS sub, m.mid AS mid, m.role AS role, m.joined AS joined, s.doc AS doc, s.updated AS updated FROM members m LEFT JOIN snaps s ON s.team = m.team AND s.sub = m.sub WHERE m.team = ?").bind(id).all()).results || [];
    const out = [];
    await shareInit(env);
    const all = (await env.DB.prepare("SELECT mid, role, upline, level FROM members WHERE team = ?").bind(id).all()).results || [], T = treeOf(all);
    for (const m of ms) {
      if (m.sub === s.sub || !isAbove(T, me.mid, m.mid)) continue; // a released MD's branch is theirs, not the lead's
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
    await shareInit(env);
    // who besides the lead may read it: teammates by member id, checked against the team now (unknown ids are dropped)
    let readers = [];
    if (Array.isArray(b.to) && b.to.length) {
      const want = [...new Set(b.to.map(String))].slice(0, MAX_MEMBERS), ok = new Set(((await env.DB.prepare("SELECT mid FROM members WHERE team = ? AND sub != ?").bind(id, s.sub).all()).results || []).map(x => x.mid));
      readers = want.filter(m => ok.has(m));
    }
    await env.DB.prepare("INSERT INTO snaps (team, sub, doc, updated, readers) VALUES (?, ?, ?, ?, ?) ON CONFLICT(team, sub) DO UPDATE SET doc = excluded.doc, updated = excluded.updated, readers = excluded.readers").bind(id, s.sub, await sealT(env, id, s.sub, b.doc), now, JSON.stringify(readers)).run();
    const nm = String(b.name || "").trim().slice(0, 40);
    if (nm) await env.DB.prepare("UPDATE members SET nbox = ? WHERE team = ? AND sub = ?").bind(await sealT(env, id, s.sub, { name: nm }), id, s.sub).run();
    return json({ updated: now, readers }, 200, ch);
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
  if (parts.length === 3 && parts[2] === "board") { // weekly draw notice: the lead writes it, every member reads it. Prize wording, team total, last winner's name; nothing per member but that
    await boardInit(env);
    if (M === "GET") {
      const row = await env.DB.prepare("SELECT doc, updated FROM boards WHERE team = ?").bind(id).first();
      if (!row) return json({ board: null }, 200, ch);
      try { return json({ board: (await openT(env, id, "board", row.doc)).doc, updated: row.updated }, 200, ch); } catch (e) { return json({ board: null }, 200, ch); }
    }
    if (M === "PUT") {
      if (!lead) return json({ error: "forbidden" }, 403, ch);
      const b = await body();
      if (!b.board || typeof b.board !== "object" || Array.isArray(b.board)) return json({ error: "bad request" }, 400, ch);
      if (JSON.stringify(b.board).length > MAX_BOARD) return json({ error: "too large" }, 413, ch);
      await env.DB.prepare("INSERT INTO boards (team, doc, updated) VALUES (?, ?, ?) ON CONFLICT(team) DO UPDATE SET doc = excluded.doc, updated = excluded.updated").bind(id, await sealT(env, id, "board", b.board), now).run();
      return json({ ok: true }, 200, ch);
    }
    return json({ error: "not found" }, 404, ch);
  }
  if (parts[2] === "avail" || parts[2] === "bookings") {
    await shareInit(env); await bkInit(env);
    const all = (await env.DB.prepare("SELECT sub, mid, role, upline, level, nbox, pbox FROM members WHERE team = ?").bind(id).all()).results || [], T = treeOf(all), P = await partnersOf(env, id, me.mid);
    const nameOf = async mid => { const m = all.find(x => x.mid === mid); if (!m) return "Teammate"; let nm = ""; if (m.pbox) { try { nm = String((await openT(env, id, m.sub, m.pbox)).doc.name || ""); } catch (e) { } } if (!nm && m.nbox) { try { nm = String((await openT(env, id, m.sub, m.nbox)).doc.name || ""); } catch (e) { } } return nm.slice(0, 40) || "Teammate"; };
    const mayBook = to => to !== me.mid && all.some(x => x.mid === to) && (isAbove(T, to, me.mid) || isAbove(T, me.mid, to) || P[to] === "yes"); // your uplines, your downline, and your partners
    const today = new Date(now).toISOString().slice(0, 10);
    if (parts[2] === "avail") {
      if (parts.length === 3 && M === "PUT") { // my hours + busy times for the next few weeks
        if (limited(req, 60, "avail")) return json({ error: "slow down" }, 429, ch);
        const b = await body(), hours = cleanHours(b.hours); if (!hours) return json({ error: "bad hours" }, 400, ch);
        const busy = {}; let n = 0; for (const [d, arr] of Object.entries(b.busy && typeof b.busy === "object" ? b.busy : {})) { if (!isoDay(d) || !Array.isArray(arr) || n > 60) continue; n++;
          busy[d] = arr.slice(0, 60).map(x => [Math.max(0, Math.min(1440, Math.round(+x[0] || 0))), Math.max(0, Math.min(1440, Math.round(+x[1] || 0)))]).filter(x => x[1] > x[0]); }
        await env.DB.prepare("INSERT INTO avail (team, mid, box, updated) VALUES (?, ?, ?, ?) ON CONFLICT(team, mid) DO UPDATE SET box = excluded.box, updated = excluded.updated").bind(id, me.mid, await sealT(env, id, "avail|" + me.mid, { hours, busy }), now).run();
        return json({ ok: true }, 200, ch);
      }
      if (parts.length === 3 && M === "GET") { // who I can book, and my own hours
        const rows = (await env.DB.prepare("SELECT mid, box FROM avail WHERE team = ?").bind(id).all()).results || [], out = []; let mine = null;
        for (const r of rows) { let d; try { d = (await openT(env, id, "avail|" + r.mid, r.box)).doc; } catch (e) { continue; }
          if (r.mid === me.mid) mine = d.hours; else if (mayBook(r.mid) && d.hours.open) out.push({ mid: r.mid, name: await nameOf(r.mid), why: P[r.mid] === "yes" ? "partner" : isAbove(T, r.mid, me.mid) ? "upline" : "downline" }); }
        return json({ hours: mine, canBook: out }, 200, ch);
      }
      if (parts.length === 4 && M === "GET") { // their open hours and busy times (no titles); only for people I may book
        const to = parts[3]; if (!mayBook(to)) return json({ error: "forbidden" }, 403, ch);
        const r = await env.DB.prepare("SELECT box, updated FROM avail WHERE team = ? AND mid = ?").bind(id, to).first(); if (!r) return json({ hours: null, busy: {} }, 200, ch);
        let d; try { d = (await openT(env, id, "avail|" + to, r.box)).doc; } catch (e) { return json({ hours: null, busy: {} }, 200, ch); }
        if (!d.hours.open) return json({ hours: null, busy: {}, closed: true }, 200, ch);
        const held = (await env.DB.prepare("SELECT box FROM bkg WHERE team = ? AND (a = ? OR b = ?) AND state IN ('pending','accepted') AND day >= ?").bind(id, to, to, today).all()).results || [];
        const busy = JSON.parse(JSON.stringify(d.busy || {}));
        for (const h of held) { try { const x = (await openT(env, id, "bkg", h.box)).doc; (busy[x.date] = busy[x.date] || []).push([x.start, x.start + x.dur]); } catch (e) { } }
        return json({ hours: d.hours, busy, updated: r.updated, name: await nameOf(to) }, 200, ch);
      }
      return json({ error: "not found" }, 404, ch);
    }
    // bookings
    const clean = b => { const date = isoDay(b.date), start = Math.round(+b.start), dur = Math.round(+b.dur);
      if (!date || !(start >= 0 && start < 1440) || !(dur >= 5 && dur <= 240) || start + dur > 1440) return null;
      const kind = BK_KINDS.includes(b.kind) ? b.kind : "other"; return { date, start, dur, kind, label: String(b.label || "").trim().slice(0, 40), note: String(b.note || "").trim().slice(0, 300), how: BK_HOW.includes(b.how) ? b.how : "phone", link: cleanLink(b.link) }; };
    const subOf = mid => (all.find(x => x.mid === mid) || {}).sub;
    const nice = x => { const d = new Date(x.date + "T12:00:00Z"), h = Math.floor(x.start / 60), m = x.start % 60; return `${d.toLocaleDateString("en-US", { weekday: "short", month: "short", day: "numeric", timeZone: "UTC" })} ${(h % 12) || 12}:${String(m).padStart(2, "0")} ${h < 12 ? "AM" : "PM"}`; };
    if (parts.length === 3 && M === "POST") {
      if (limited(req, 30, "bookings")) return json({ error: "slow down" }, 429, ch);
      const b = await body(), to = String(b.to || ""); if (!mayBook(to)) return json({ error: "forbidden" }, 403, ch);
      const x = clean(b); if (!x || x.date < today) return json({ error: "bad time" }, 400, ch);
      const open = await env.DB.prepare("SELECT COUNT(*) AS n FROM bkg WHERE team = ? AND a = ? AND state = 'pending'").bind(id, me.mid).first(); if (open && open.n >= 20) return json({ error: "too many open requests" }, 409, ch);
      const bid = "bk_" + rnd(12), doc = { ...x, ...(x.link ? { linkBy: me.mid } : {}), hist: [{ by: me.mid, date: x.date, start: x.start, at: now }] };
      await env.DB.prepare("INSERT INTO bkg (team, id, a, b, state, turn, box, day, created, updated) VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)").bind(id, bid, me.mid, to, to, await sealT(env, id, "bkg", doc), x.date, now, now).run();
      const s2 = subOf(to); if (s2) await pushTo(env, s2, { title: `${await nameOf(me.mid)} wants time with you`.slice(0, 60), body: `${nice(x)} · tap to accept or suggest another time`, url: "/app/#bookings", tag: "bk-" + bid.slice(3) });
      return json({ id: bid, state: "pending" }, 200, ch);
    }
    if (parts.length === 3 && M === "GET") {
      const rows = (await env.DB.prepare("SELECT id, a, b, state, turn, box, day, created, updated FROM bkg WHERE team = ? AND (a = ? OR b = ?)").bind(id, me.mid, me.mid).all()).results || [], out = [];
      const old = new Date(now - 30 * 864e5).toISOString().slice(0, 10);
      for (const r of rows) { if (r.day < old) continue; let d; try { d = (await openT(env, id, "bkg", r.box)).doc; } catch (e) { continue; }
        const other = r.a === me.mid ? r.b : r.a; out.push({ id: r.id, mine: r.a === me.mid, other, otherName: await nameOf(other), state: r.state, myTurn: r.turn === me.mid, ...d, updated: r.updated }); }
      out.sort((x, y) => (x.date + String(x.start).padStart(4, "0")).localeCompare(y.date + String(y.start).padStart(4, "0")));
      return json({ bookings: out }, 200, ch);
    }
    if (parts.length === 4 && M === "POST") {
      const r = await env.DB.prepare("SELECT id, a, b, state, turn, box FROM bkg WHERE team = ? AND id = ?").bind(id, parts[3]).first();
      if (!r || (r.a !== me.mid && r.b !== me.mid)) return json({ error: "not found" }, 404, ch);
      const b = await body(), act = String(b.action || ""), other = r.a === me.mid ? r.b : r.a; let d; try { d = (await openT(env, id, "bkg", r.box)).doc; } catch (e) { return json({ error: "not found" }, 404, ch); }
      let state = r.state, turn = r.turn, msg = null, linkChanged = false;
      // either side can add or swap the meeting link when they accept or suggest a time (or set it on an accepted one); "" clears it
      if (b.link !== undefined && act !== "cancel" && act !== "decline") { const l = cleanLink(b.link); if (b.link !== "" && !l) return json({ error: "bad link" }, 400, ch); if (l !== (d.link || "")) { d.link = l; d.linkBy = l ? me.mid : ""; linkChanged = true; } }
      if (act === "link") { if (r.state !== "accepted" && r.state !== "pending") return json({ error: "closed" }, 409, ch); if (linkChanged && d.link) msg = [`${await nameOf(me.mid)} added a video link`, `${nice(d)} · tap to see it`]; }
      else if (act === "cancel") { if (!["pending", "accepted"].includes(r.state)) return json({ error: "closed" }, 409, ch); state = "cancelled"; turn = null; d.reason = String(b.reason || "").trim().slice(0, 140); msg = [`${await nameOf(me.mid)} cancelled`, nice(d)]; }
      else { if (r.state !== "pending" || r.turn !== me.mid) return json({ error: "not your turn" }, 409, ch);
        if (act === "accept") { state = "accepted"; turn = null; msg = [`${await nameOf(me.mid)} accepted`, `${nice(d)} is on both calendars`]; }
        else if (act === "decline") { state = "declined"; turn = null; d.reason = String(b.reason || "").trim().slice(0, 140); msg = [`${await nameOf(me.mid)} can't make it`, d.reason || nice(d)]; }
        else if (act === "counter") { const x = clean({ ...d, link: d.link, date: b.date, start: b.start, dur: b.dur || d.dur }); if (!x || x.date < today) return json({ error: "bad time" }, 400, ch);
          d.date = x.date; d.start = x.start; d.dur = x.dur; d.reason = String(b.reason || "").trim().slice(0, 140); (d.hist = d.hist || []).push({ by: me.mid, date: x.date, start: x.start, at: now }); d.hist = d.hist.slice(-12);
          turn = other; msg = [`${await nameOf(me.mid)} suggested another time`, `${nice(d)}${d.reason ? " · " + d.reason : ""}`]; }
        else return json({ error: "bad action" }, 400, ch); }
      d.last = me.mid;
      await env.DB.prepare("UPDATE bkg SET state = ?, turn = ?, box = ?, day = ?, updated = ? WHERE team = ? AND id = ?").bind(state, turn, await sealT(env, id, "bkg", d), d.date, now, id, r.id).run();
      const s2 = subOf(other); if (s2 && msg) await pushTo(env, s2, { title: msg[0].slice(0, 60), body: msg[1].slice(0, 120), url: "/app/#bookings", tag: "bk-" + r.id.slice(3) });
      return json({ ok: true, state }, 200, ch);
    }
    return json({ error: "not found" }, 404, ch);
  }
  if (parts[2] === "recruits" || parts[2] === "comps") {
    await shareInit(env); await rcInit(env);
    const all = (await env.DB.prepare("SELECT sub, mid, role, upline, level, nbox, pbox FROM members WHERE team = ?").bind(id).all()).results || [], T = treeOf(all);
    const nameOf = {}; for (const m of all) { let nm = ""; if (m.pbox) { try { nm = String((await openT(env, id, m.sub, m.pbox)).doc.name || ""); } catch (e) { } } if (!nm && m.nbox) { try { nm = String((await openT(env, id, m.sub, m.nbox)).doc.name || ""); } catch (e) { } } nameOf[m.mid] = nm.slice(0, 40) || "Teammate"; }
    const today = new Date(now).toISOString().slice(0, 10);
    const compRows = async () => { const rows = (await env.DB.prepare("SELECT id, owner, box, starts, ends, created FROM comps WHERE team = ?").bind(id).all()).results || [], out = [];
      for (const r of rows) { try { const c = (await openT(env, id, "comp|" + r.id, r.box)).doc; out.push({ id: r.id, owner: r.owner, created: r.created, ...c }); } catch (e) { } } return out; };
    const inComp = c => { const base = c.scope === "pick" ? new Set([c.owner, ...c.pick.filter(x => all.some(m => m.mid === x))]) : descendants(T, all, c.owner); return base; };
    const recruitComps = async () => (await compRows()).filter(c => c.metric === "__recruits" && c.starts <= today && today <= c.ends);
    if (parts[2] === "recruits") {
      if (parts.length === 3 && M === "POST") {
        if (limited(req, 20, "recruits")) return json({ error: "slow down" }, 429, ch);
        const b = await body(), name = String(b.name || "").trim().slice(0, 60), phone = String(b.phone || "").replace(/[^0-9]/g, "").slice(-10);
        if (!name || b.coded !== true) return json({ error: "a recruit needs a name and to be coded" }, 400, ch);
        const photo = prizePhotoOk(b.photo) ? b.photo : "", note = String(b.note || "").trim().slice(0, 200), rid = "rc_" + rnd(12);
        let approver = lead ? me.mid : recruitApprover(T, me.mid);
        const phash = phone.length >= 7 ? await sha256(id + "|" + phone) : null;
        const dup = phash ? !!(await env.DB.prepare("SELECT 1 FROM recruits WHERE team = ? AND phash = ? AND state = 'yes'").bind(id, phash).first()) : false;
        const auto = lead; // the lead's own recruits need no one else's approval
        await env.DB.prepare("INSERT INTO recruits (team, id, by_mid, approver, state, box, phash, created, decided) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(id, rid, me.mid, approver, auto && !dup ? "yes" : "pending", await sealT(env, id, "recruit|" + rid, { name, phone, note, photo, coded: true, pid: String(b.pid || "").slice(0, 40) }), phash, now, auto && !dup ? now : null).run();
        return json({ id: rid, state: auto && !dup ? "yes" : "pending", approver, approverName: nameOf[approver] || "your team lead", dup }, 200, ch);
      }
      if (parts.length === 3 && M === "GET") {
        const rows = (await env.DB.prepare("SELECT id, by_mid, approver, state, box, phash, created, decided FROM recruits WHERE team = ?").bind(id).all()).results || [];
        const rcs = await recruitComps(), mine = [], toApprove = [], counts = {}, approvedP = new Set(rows.filter(r => r.state === "yes" && r.phash).map(r => r.phash));
        for (const r of rows) {
          if (r.state === "yes") counts[r.by_mid] = (counts[r.by_mid] || 0) + 1;
          const canApprove = r.state === "pending" && (r.approver === me.mid || rcs.some(c => c.owner === me.mid && inComp(c).has(r.by_mid))) && r.by_mid !== me.mid;
          if (r.by_mid !== me.mid && !canApprove) continue;
          let d = {}; try { d = (await openT(env, id, "recruit|" + r.id, r.box)).doc || {}; } catch (e) { continue; }
          const item = { id: r.id, state: r.state, name: d.name, phone: d.phone, note: d.note, photo: d.photo || "", pid: d.pid || "", by: r.by_mid, byName: nameOf[r.by_mid], approverName: nameOf[r.approver] || "", created: r.created, decided: r.decided, back: d.back || "" };
          if (r.by_mid === me.mid) mine.push(item);
          if (canApprove) toApprove.push({ ...item, dup: !!(r.phash && approvedP.has(r.phash)) });
        }
        return json({ mine, toApprove, counts }, 200, ch);
      }
      if (parts.length === 4 && M === "POST") {
        const r = await env.DB.prepare("SELECT id, by_mid, approver, state, box FROM recruits WHERE team = ? AND id = ?").bind(id, parts[3]).first(); if (!r) return json({ error: "not found" }, 404, ch);
        const rcs = await recruitComps(), can = r.state === "pending" && r.by_mid !== me.mid && (r.approver === me.mid || rcs.some(c => c.owner === me.mid && inComp(c).has(r.by_mid)));
        if (!can) return json({ error: "forbidden" }, 403, ch);
        const b = await body(), yes = b.decision === "yes";
        let d = {}; try { d = (await openT(env, id, "recruit|" + r.id, r.box)).doc || {}; } catch (e) { }
        if (!yes) d.back = String(b.note || "").trim().slice(0, 200);
        await env.DB.prepare("UPDATE recruits SET state = ?, decided = ?, box = ? WHERE team = ? AND id = ?").bind(yes ? "yes" : "no", now, await sealT(env, id, "recruit|" + r.id, d), id, r.id).run();
        return json({ ok: true, state: yes ? "yes" : "no" }, 200, ch);
      }
      if (parts.length === 4 && M === "DELETE") { // take back your own pending request
        const r = await env.DB.prepare("SELECT by_mid, state FROM recruits WHERE team = ? AND id = ?").bind(id, parts[3]).first();
        if (!r || r.by_mid !== me.mid || r.state === "yes") return json({ error: "not found" }, 404, ch);
        await env.DB.prepare("DELETE FROM recruits WHERE team = ? AND id = ?").bind(id, parts[3]).run(); return json({ ok: true }, 200, ch);
      }
      return json({ error: "not found" }, 404, ch);
    }
    // competitions
    const canRun = lead || T.rel.has(me.mid) || all.some(m => m.mid !== me.mid && T.par[m.mid] === me.mid);
    if (parts.length === 3 && M === "GET") {
      const cs = await compRows(), sc = (await env.DB.prepare("SELECT comp, mid, value, updated FROM cscores WHERE team = ?").bind(id).all()).results || [];
      const rrows = (await env.DB.prepare("SELECT by_mid, decided FROM recruits WHERE team = ? AND state = 'yes'").bind(id).all()).results || [];
      const out = [];
      for (const c of cs) {
        const ppl = inComp(c); if (!ppl.has(me.mid)) continue;
        const endMs = Date.parse(c.ends + "T23:59:59Z") + 864e5, startMs = Date.parse(c.starts + "T00:00:00Z") - 864e5; // a day of slack either side for time zones
        if (now > endMs + 30 * 864e5) continue; // finished more than a month ago
        const rows = [...ppl].map(mid => { let v = 0, u = 0;
          if (c.metric === "__recruits") { const mine = rrows.filter(r => r.by_mid === mid && r.decided >= startMs && r.decided <= endMs); v = mine.length; u = mine.reduce((a, r) => Math.max(a, r.decided), 0); }
          else { const x = sc.find(z => z.comp === c.id && z.mid === mid); if (x) { v = x.value; u = x.updated; } }
          return { mid, name: nameOf[mid] || "Teammate", value: v, updated: u, me: mid === me.mid }; });
        out.push({ ...c, pick: undefined, mine: c.owner === me.mid, ownerName: nameOf[c.owner] || "", rows, status: today > c.ends ? "ended" : today < c.starts ? "soon" : "running" });
      }
      out.sort((a, b) => (a.status === "ended") - (b.status === "ended") || (a.ends < b.ends ? -1 : 1));
      return json({ comps: out, canRun }, 200, ch);
    }
    if (parts.length === 3 && M === "POST") {
      if (!canRun) return json({ error: "forbidden" }, 403, ch);
      if (limited(req, 20, "comps")) return json({ error: "slow down" }, 429, ch);
      const c = cleanComp(await body()); if (!c) return json({ error: "bad competition" }, 400, ch);
      const n = await env.DB.prepare("SELECT COUNT(*) AS n FROM comps WHERE team = ?").bind(id).first(); if (n && n.n >= 40) return json({ error: "too many competitions" }, 409, ch);
      const cid = "cp_" + rnd(12); c.owner = me.mid;
      await env.DB.prepare("INSERT INTO comps (team, id, owner, box, starts, ends, created) VALUES (?, ?, ?, ?, ?, ?, ?)").bind(id, cid, me.mid, await sealT(env, id, "comp|" + cid, c), c.starts, c.ends, now).run();
      return json({ id: cid }, 200, ch);
    }
    const cid = parts[3], row = cid ? await env.DB.prepare("SELECT id, owner, box FROM comps WHERE team = ? AND id = ?").bind(id, cid).first() : null;
    if (!row) return json({ error: "not found" }, 404, ch);
    if (parts.length === 4 && (M === "PUT" || M === "DELETE")) {
      if (row.owner !== me.mid) return json({ error: "forbidden" }, 403, ch);
      if (M === "DELETE") { await env.DB.prepare("DELETE FROM comps WHERE team = ? AND id = ?").bind(id, cid).run(); await env.DB.prepare("DELETE FROM cscores WHERE team = ? AND comp = ?").bind(id, cid).run(); return json({ ok: true }, 200, ch); }
      const c = cleanComp(await body()); if (!c) return json({ error: "bad competition" }, 400, ch); c.owner = me.mid;
      await env.DB.prepare("UPDATE comps SET box = ?, starts = ?, ends = ? WHERE team = ? AND id = ?").bind(await sealT(env, id, "comp|" + cid, c), c.starts, c.ends, id, cid).run();
      return json({ ok: true }, 200, ch);
    }
    if (parts.length === 5 && parts[4] === "score" && M === "PUT") { // a participant reports their own total for this one number
      let c; try { c = (await openT(env, id, "comp|" + cid, row.box)).doc; } catch (e) { return json({ error: "not found" }, 404, ch); }
      c.owner = row.owner; if (!inComp(c).has(me.mid) || c.metric === "__recruits") return json({ error: "forbidden" }, 403, ch);
      if (today > c.ends || today < c.starts) return json({ error: "not running" }, 409, ch);
      const v = Math.max(0, Math.min(1e9, +(await body()).value || 0));
      await env.DB.prepare("INSERT INTO cscores (team, comp, mid, value, updated) VALUES (?, ?, ?, ?, ?) ON CONFLICT(team, comp, mid) DO UPDATE SET value = excluded.value, updated = CASE WHEN excluded.value <> cscores.value THEN excluded.updated ELSE cscores.updated END").bind(id, cid, me.mid, v, now).run();
      return json({ ok: true }, 200, ch);
    }
    return json({ error: "not found" }, 404, ch);
  }
  if (parts.length === 3 && parts[2] === "metrics") {
    await shareInit(env); await tmetInit(env);
    const all = (await env.DB.prepare("SELECT mid, role, upline, level FROM members WHERE team = ?").bind(id).all()).results || [], T = treeOf(all);
    const leadsBranch = all.some(m => m.mid !== me.mid && (T.par[m.mid] === me.mid)); // has anyone directly under them
    if (M === "GET") {
      const rows = (await env.DB.prepare("SELECT mid, box, updated FROM tmetrics WHERE team = ?").bind(id).all()).results || [], by = {};
      for (const r of rows) { try { by[r.mid] = { metrics: (await openT(env, id, "metrics|" + r.mid, r.box)).doc, updated: r.updated }; } catch (e) { } }
      // nearest set: me (only if I lead a branch), then each upline, stopping at a released MD
      let use = null, from = null, cur = me.mid, n = 0;
      if ((leadsBranch || T.rel.has(cur) || cur === T.root) && by[cur]) { use = by[cur]; from = cur; }
      // walk up; a released MD's branch never inherits from above the MD
      while (!use && !T.rel.has(cur) && n++ < 600) { const p = T.par[cur]; if (!p) break; if (by[p]) { use = by[p]; from = p; } cur = p; }
      return json({ metrics: use ? use.metrics : null, from, updated: use ? use.updated : 0, mine: by[me.mid] ? by[me.mid].metrics : null, canEdit: lead || leadsBranch || T.rel.has(me.mid) }, 200, ch);
    }
    if (M === "PUT") {
      if (!(lead || leadsBranch || T.rel.has(me.mid))) return json({ error: "forbidden" }, 403, ch);
      const b = await body();
      if (b.metrics === null) { await env.DB.prepare("DELETE FROM tmetrics WHERE team = ? AND mid = ?").bind(id, me.mid).run(); return json({ ok: true }, 200, ch); }
      const ms = cleanMetrics(b.metrics); if (!ms) return json({ error: "bad metrics" }, 400, ch);
      await env.DB.prepare("INSERT INTO tmetrics (team, mid, box, updated) VALUES (?, ?, ?, ?) ON CONFLICT(team, mid) DO UPDATE SET box = excluded.box, updated = excluded.updated").bind(id, me.mid, await sealT(env, id, "metrics|" + me.mid, ms), now).run();
      return json({ ok: true, metrics: ms }, 200, ch);
    }
    return json({ error: "not found" }, 404, ch);
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
    await shareInit(env);
    const tm = await env.DB.prepare("SELECT mid, upline FROM members WHERE team = ? AND sub = ?").bind(id, target.sub).first();
    if (tm) { await env.DB.prepare("UPDATE members SET upline = ? WHERE team = ? AND upline = ?").bind(tm.upline || null, id, tm.mid).run(); // their recruits move up to their upline
      await env.DB.prepare("DELETE FROM tpart WHERE team = ? AND (a = ? OR b = ?)").bind(id, tm.mid, tm.mid).run();
      await env.DB.prepare("DELETE FROM rcodes WHERE team = ? AND mid = ?").bind(id, tm.mid).run(); await tmetInit(env); await env.DB.prepare("DELETE FROM tmetrics WHERE team = ? AND mid = ?").bind(id, tm.mid).run(); }
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
// a meeting link (Zoom, Teams, Meet…): https only, no user:password inside, no spaces, at most 300 characters. Anything else = no link.
function cleanLink(v) { const s = String(v == null ? "" : v).trim(); if (!s || s.length > 300 || /\s/.test(s)) return ""; try { const u = new URL(s); if (u.protocol !== "https:" || u.username || u.password || !u.hostname.includes(".")) return ""; return u.href; } catch { return ""; } }
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
  const body = await encryptPush(t, JSON.stringify({ title: msg.title, body: msg.body, url: msg.url || "/app/", tag: msg.tag || "", ...(msg.join ? { join: msg.join } : {}) }));
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
    if (x.join !== undefined && x.join !== "" && !cleanLink(x.join)) return null;
    if (x.at > now - 60000) out.push({ at: x.at, title: x.title, body: x.body || "", url: x.url || "/app/", tag: x.tag || "", ...(x.join ? { join: cleanLink(x.join) } : {}) });
  }
  return out.sort((a, b) => a.at - b.at);
}
const nextAt = q => q.length ? q[0].at : null;
// ---- live calendar feed: Apple, Google and Outlook subscribe to one private link and stay current ----
// The owner's app sends the events it wants shown (work blocks; personal only if they choose), already turned into exact
// times. They're sealed per account. The link holds a long random secret; the database keeps only its hash, so a copy of the
// database can't be turned into working links. Reset makes a new secret and the old link stops at once.
const FEED_MAX = 1500, FEED_BYTES = 450_000, FEED_ID = /^[A-Za-z0-9_|.-]{1,80}$/;
let feedReady = false;
async function feedInit(env) { if (feedReady) return; await env.DB.prepare("CREATE TABLE IF NOT EXISTS feeds (id TEXT PRIMARY KEY, sub TEXT NOT NULL UNIQUE, box TEXT NOT NULL, updated INTEGER NOT NULL)").run(); feedReady = true; }
function feedClean(list, now) {
  if (!Array.isArray(list) || list.length > FEED_MAX) return null;
  const out = [], lo = now - 62 * 864e5, hi = now + 400 * 864e5;
  for (const x of list) {
    if (!x || typeof x !== "object" || !FEED_ID.test(String(x.id || ""))) return null;
    const s = Math.round(+x.s), e = Math.round(+x.e);
    if (!(s >= lo && s <= hi && e > s && e - s <= 864e5)) return null;
    const t = String(x.t || "").trim().slice(0, 90) || "Busy";
    out.push({ id: String(x.id), s, e, t, ...(x.c ? { c: String(x.c).slice(0, 30) } : {}), ...(cleanLink(x.l) ? { l: cleanLink(x.l) } : {}) });
  }
  return out;
}
const icsText = t => String(t).replace(/\\/g, "\\\\").replace(/;/g, "\\;").replace(/,/g, "\\,").replace(/\r?\n/g, "\\n");
const icsTime = ms => new Date(ms).toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
function icsFold(line) { const b = enc.encode(line); if (b.length <= 75) return line; const out = []; let cur = "", n = 0;
  for (const ch of line) { const k = enc.encode(ch).length; if (n + k > (out.length ? 74 : 75)) { out.push(cur); cur = ""; n = 0; } cur += ch; n += k; } out.push(cur); return out.join("\r\n "); }
function feedIcs(doc, now) {
  const L = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Hourline//Feed//EN", "CALSCALE:GREGORIAN", "METHOD:PUBLISH", "X-WR-CALNAME:" + icsText(doc.name || "Hourline"), "REFRESH-INTERVAL;VALUE=DURATION:PT30M", "X-PUBLISHED-TTL:PT30M"], stamp = icsTime(now);
  for (const x of doc.ev || []) {
    const desc = [x.c ? x.c : "", x.l ? `Join: ${x.l}` : "", "Open in Hourline: https://hourline.io/app/"].filter(Boolean).join("\n");
    L.push("BEGIN:VEVENT", "UID:" + x.id.replace(/\|/g, "-") + "@hourline.io", "DTSTAMP:" + stamp, "DTSTART:" + icsTime(x.s), "DTEND:" + icsTime(x.e), "SUMMARY:" + icsText(x.t),
      ...(x.l ? ["LOCATION:" + icsText(x.l), "URL:" + x.l] : []), "DESCRIPTION:" + icsText(desc), "TRANSP:OPAQUE", "END:VEVENT");
  }
  L.push("END:VCALENDAR");
  return L.map(icsFold).join("\r\n") + "\r\n";
}
async function feedRoutes(env, req, s, path, ch) {
  await feedInit(env);
  const now = Date.now(), row = await env.DB.prepare("SELECT id, box, updated FROM feeds WHERE sub = ?").bind(s.sub).first();
  const urlOf = tok => "https://api.hourline.io/cal/" + tok + ".ics";
  if (path === "/feed" && req.method === "GET") {
    if (!row) return json({ on: false }, 200, ch);
    const d = (await open(env, s.sub, row.box)).doc; return json({ on: true, url: urlOf(d.tok), updated: row.updated, n: (d.ev || []).length }, 200, ch);
  }
  if (path === "/feed" && req.method === "PUT") {
    if (limited(req, 30, "feed")) return json({ error: "slow down" }, 429, ch);
    const raw = await req.text(); if (raw.length > FEED_BYTES) return json({ error: "too big" }, 413, ch);
    let b; try { b = JSON.parse(raw); } catch { return json({ error: "bad json" }, 400, ch); }
    const ev = feedClean(b && b.ev, now); if (!ev) return json({ error: "bad events" }, 400, ch);
    const name = String(b.name || "").trim().slice(0, 40);
    let tok;
    if (row) { try { tok = (await open(env, s.sub, row.box)).doc.tok; } catch (e) { tok = null; } }
    if (!tok) tok = rnd(24);
    const id = "f_" + await sha256("feed:" + tok), box = await seal(env, s.sub, { tok, name: name ? "Hourline · " + name : "Hourline", ev });
    if (row && row.id !== id) await env.DB.prepare("DELETE FROM feeds WHERE sub = ?").bind(s.sub).run();
    await env.DB.prepare("INSERT INTO feeds (id, sub, box, updated) VALUES (?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET box = excluded.box, updated = excluded.updated").bind(id, s.sub, box, now).run();
    return json({ ok: true, url: urlOf(tok), n: ev.length }, 200, ch);
  }
  if (path === "/feed/reset" && req.method === "POST") {
    if (!row) return json({ error: "not on" }, 404, ch);
    const d = (await open(env, s.sub, row.box)).doc, tok = rnd(24), id = "f_" + await sha256("feed:" + tok);
    await env.DB.prepare("DELETE FROM feeds WHERE sub = ?").bind(s.sub).run();
    await env.DB.prepare("INSERT INTO feeds (id, sub, box, updated) VALUES (?, ?, ?, ?)").bind(id, s.sub, await seal(env, s.sub, { ...d, tok }), now).run();
    return json({ ok: true, url: urlOf(tok) }, 200, ch);
  }
  if (path === "/feed" && req.method === "DELETE") { await env.DB.prepare("DELETE FROM feeds WHERE sub = ?").bind(s.sub).run(); return json({ ok: true }, 200, ch); }
  return json({ error: "not found" }, 404, ch);
}
// ---- public booking page: hourline.io/b/<handle> ----
// The owner's app sends the page settings plus busy times only (start/end, never titles), sealed with the owner's key.
// Anyone can open the page and book an open time without an account. Each booking is sealed with the owner's key; the
// guest gets a private link to see or cancel it. Emails go through Resend only when RESEND_API_KEY is set.
let bpReady = false;
async function bpInit(env) { if (bpReady) return;
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS bpages (handle TEXT PRIMARY KEY, sub TEXT NOT NULL UNIQUE, box TEXT NOT NULL, updated INTEGER NOT NULL)").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS bbook (id TEXT PRIMARY KEY, handle TEXT NOT NULL, sub TEXT NOT NULL, s INTEGER NOT NULL, e INTEGER NOT NULL, box TEXT NOT NULL, state TEXT NOT NULL, tok TEXT NOT NULL, ip TEXT NOT NULL, created INTEGER NOT NULL)").run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS bbook_h ON bbook (handle, s)").run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS bbook_sub ON bbook (sub, s)").run();
  bpReady = true; }
const BP_RESERVED = new Set(["app", "api", "admin", "privacy", "terms", "book", "booking", "b", "p", "login", "signin", "signup", "settings", "help", "support", "about", "pricing", "blog", "team", "teams", "hourline", "www", "mail", "static", "assets", "fonts", "marketing", "index", "cal", "feed", "join", "invite", "home", "security", "status", "legal", "contact"]);
const bpHandleOk = h => typeof h === "string" && /^[a-z0-9](?:[a-z0-9-]{1,28})[a-z0-9]$/.test(h) && !h.includes("--") && !BP_RESERVED.has(h);
const BP_LOOKS = ["night", "grid", "split", "clean"], BP_HOW = ["video", "phone", "person"], BP_THEMES = ["classic", "floral", "forest"], BP_PAYWHEN = ["all", "eve", "wkd"];
// the owner's own pictures: a small face photo and a wider cover, shrunk on their phone before upload; JPEG or WebP only
const bpPic = (v, max) => typeof v === "string" && v.length <= max && /^data:image\/(jpeg|webp);base64,[A-Za-z0-9+/=]+$/.test(v) ? v : "";
const BP_PHOTO_MAX = 60_000, BP_COVER_MAX = 160_000;
// what a time costs: the owner can charge every time, or only evenings and weekends (5 pm on, Sat, Sun), or only weekends, in the page's time zone
function bpPriceAt(m, start, tz) { const p = m.price || 0; if (!p || !m.payWhen || m.payWhen === "all") return p;
  const d = new Date(start + bpOff(start, tz) * 6e4), wd = d.getUTCDay(), wknd = wd === 0 || wd === 6;
  return m.payWhen === "wkd" ? (wknd ? p : 0) : (wknd || d.getUTCHours() >= 17 ? p : 0); }
const bpStr = (v, n) => String(v == null ? "" : v).replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, n);
const bpTz = z => { try { new Intl.DateTimeFormat("en-US", { timeZone: String(z) }); return String(z).slice(0, 60); } catch { return "America/Chicago"; } };
function bpUrl(v) { const s = String(v || "").trim(); if (!s || s.length > 200) return ""; try { const u = new URL(/^https?:\/\//i.test(s) ? s : "https://" + s); return u.protocol === "https:" && !u.username && !u.password && u.hostname.includes(".") ? u.href : ""; } catch { return ""; } }
function bpClean(b, now) {
  if (!b || typeof b !== "object") return null;
  const look = b.look && typeof b.look === "object" ? b.look : {};
  const pr = b.profile && typeof b.profile === "object" ? b.profile : {};
  const hours = {}; if (b.hours && typeof b.hours === "object") for (const [k, v] of Object.entries(b.hours)) if (/^[0-6]$/.test(k) && Array.isArray(v) && v.length === 2 && v.every(x => typeof x === "number" && x >= 0 && x <= 24) && v[0] < v[1]) hours[k] = [Math.round(v[0] * 2) / 2, Math.round(v[1] * 2) / 2];
  const meetings = (Array.isArray(b.meetings) ? b.meetings : []).slice(0, 8).map((m, i) => ({
    id: /^[a-z0-9]{1,12}$/.test(String(m && m.id)) ? String(m.id) : "m" + i, on: m && m.on !== false,
    title: bpStr(m && m.title, 60) || "Meeting", len: [15, 30, 45, 60, 90].includes(+(m && m.len)) ? +m.len : 30, sub: bpStr(m && m.sub, 160),
    how: (Array.isArray(m && m.how) ? m.how : ["video"]).filter(x => BP_HOW.includes(x)).slice(0, 3), before: bpStr(m && m.before, 240),
    q: bpStr(m && m.q, 120), qreq: !!(m && m.qreq), notice: [0, 120, 1440].includes(+(m && m.notice)) ? +m.notice : 120,
    ahead: [14, 30, 90].includes(+(m && m.ahead)) ? +m.ahead : 30, max: Math.max(1, Math.min(12, Math.round(+(m && m.max) || 4))),
    link: cleanLink(m && m.link), place: bpStr(m && m.place, 200),
    price: Math.max(0, Math.min(100_000_00, Math.round(+(m && m.price) || 0))), currency: "usd",
    payWhen: BP_PAYWHEN.includes(m && m.payWhen) ? m.payWhen : "all", dep: !!(m && m.dep) })).map(m => ({ ...m, price: m.price && m.price < 100 ? 0 : m.price })).filter(m => m.title);
  if (!meetings.length) return null;
  const busy = (Array.isArray(b.busy) ? b.busy : []).filter(x => Array.isArray(x) && x.length === 2 && Number.isFinite(x[0]) && Number.isFinite(x[1]) && x[1] > x[0] && x[1] > now - 864e5 && x[0] < now + 100 * 864e5 && x[1] - x[0] <= 3 * 864e5).slice(0, 1500).map(x => [Math.round(x[0]), Math.round(x[1])]);
  return {
    look: { name: BP_LOOKS.includes(look.name) ? look.name : "night", accent: /^#[0-9a-f]{6}$/i.test(look.accent || "") ? String(look.accent).toLowerCase() : "#2f5bff", photo: look.photo !== false, pattern: ["solid", "dots", "grid", "lines", "fade"].includes(look.pattern) ? look.pattern : "solid",
      theme: BP_THEMES.includes(look.theme) ? look.theme : "classic", cover: bpPic(look.cover, BP_COVER_MAX) },
    profile: { name: bpStr(pr.name, 60) || "Hourline user", intro: bpStr(pr.intro, 240), cred: bpStr(pr.cred, 120), photo: bpPic(pr.photo, BP_PHOTO_MAX),
      links: (Array.isArray(pr.links) ? pr.links : []).slice(0, 3).map(l => ({ k: bpStr(l && l.k, 20), url: bpUrl(l && l.url) })).filter(l => l.k && l.url) },
    tz: bpTz(b.tz), hours, meetings, busy, buffer: [0, 5, 10, 15, 30].includes(+b.buffer) ? +b.buffer : 15, thanks: bpStr(b.thanks, 300), notify: b.notify !== false };
}
const bpDtf = {};
function bpOff(ms, z) { const f = bpDtf[z] || (bpDtf[z] = new Intl.DateTimeFormat("en-US", { timeZone: z, hourCycle: "h23", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }));
  const p = {}; for (const x of f.formatToParts(new Date(ms))) p[x.type] = x.value; return (Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour % 24, +p.minute) - Math.floor(ms / 6e4) * 6e4) / 6e4; }
function bpWall(y, mo, d, mins, z) { const g = Date.UTC(y, mo, d, 0, mins); const t = g - bpOff(g, z) * 6e4; return g - bpOff(t, z) * 6e4; }
function bpLocalDay(ms, z) { const t = ms + bpOff(ms, z) * 6e4, d = new Date(t); return { y: d.getUTCFullYear(), mo: d.getUTCMonth(), d: d.getUTCDate(), dow: d.getUTCDay(), key: d.toISOString().slice(0, 10) }; }
function bpSlots(cfg, m, booked, now) { // open start times for one kind of meeting, grouped by local day
  const out = [], len = m.len * 6e4, buf = cfg.buffer * 6e4, step = (m.len === 15 ? 15 : 30) * 6e4, earliest = now + m.notice * 6e4;
  const blocks = [...cfg.busy, ...booked.map(x => [x.s - buf, x.e + buf])];
  const perDay = {}; for (const x of booked) { const k = bpLocalDay(x.s, cfg.tz).key; perDay[k] = (perDay[k] || 0) + 1; }
  const first = bpLocalDay(now, cfg.tz);
  for (let i = 0; i <= m.ahead && out.length < 45; i++) {
    const base = Date.UTC(first.y, first.mo, first.d + i), dd = new Date(base), dow = dd.getUTCDay(), key = dd.toISOString().slice(0, 10), h = cfg.hours[dow];
    if (!h || (perDay[key] || 0) >= m.max) continue;
    const times = [];
    for (let mins = h[0] * 60; mins + m.len <= h[1] * 60; mins += step / 6e4) {
      const s = bpWall(dd.getUTCFullYear(), dd.getUTCMonth(), dd.getUTCDate(), mins, cfg.tz), e = s + len;
      if (s < earliest) continue;
      if (blocks.some(([a, b]) => s < b && e > a)) continue;
      times.push(s); if (times.length >= 24) break;
    }
    if (times.length) out.push({ day: key, times });
  }
  return out;
}
async function bpLoad(env, handle) { const row = await env.DB.prepare("SELECT sub, box FROM bpages WHERE handle = ?").bind(handle).first(); if (!row) return null;
  try { return { sub: row.sub, cfg: (await open(env, row.sub, row.box)).doc }; } catch { return null; } }
async function bpBooked(env, handle, now) { return (await env.DB.prepare("SELECT s, e FROM bbook WHERE handle = ? AND (state = 'ok' OR (state = 'hold' AND created > ?)) AND e > ?").bind(handle, now - HOLD_MS, now - 864e5).all()).results || []; }
function bpWhen(ms, z) { try { return new Intl.DateTimeFormat("en-US", { timeZone: z, weekday: "long", month: "long", day: "numeric", hour: "numeric", minute: "2-digit", timeZoneName: "short" }).format(new Date(ms)); } catch { return new Date(ms).toUTCString(); } }
async function bpMail(env, to, subject, text, replyTo) { // best effort; never blocks a booking
  if (!env.RESEND_API_KEY || !to) return false;
  try { const ac = new AbortController(), t = setTimeout(() => ac.abort(), 6000);
    const r = await fetch(env.RESEND_URL || "https://api.resend.com/emails", { method: "POST", signal: ac.signal, headers: { authorization: "Bearer " + env.RESEND_API_KEY, "content-type": "application/json" },
      body: JSON.stringify({ from: env.MAIL_FROM || "Hourline <bookings@hourline.io>", to: [to], subject: subject.slice(0, 160), text, ...(replyTo ? { reply_to: replyTo } : {}) }) });
    clearTimeout(t); return r.ok; } catch { return false; } }
const bpEmailOk = v => /^[^\s@<>"]{1,64}@[^\s@<>"]{1,180}\.[a-z]{2,}$/i.test(String(v || ""));
// ---- getting paid for bookings: Stripe Connect (each owner's own Stripe account; Hourline never touches card details) ----
// Off until STRIPE_SECRET_KEY is set. Guests pay on Stripe's checkout page; the time is held 15 minutes while they pay and the
// booking only becomes final when Stripe's signed webhook says it's paid (STRIPE_WEBHOOK_SECRET). Money goes to the owner's
// connected account; PLATFORM_FEE_BPS (default 0) is Hourline's cut, in hundredths of a percent.
let payReady = false;
async function payInit(env) { if (payReady) return;
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS bpay (sub TEXT PRIMARY KEY, acct TEXT NOT NULL, ready INTEGER NOT NULL, updated INTEGER NOT NULL)").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS bpaid (booking TEXT PRIMARY KEY, sess TEXT NOT NULL, pi TEXT, amount INTEGER NOT NULL, currency TEXT NOT NULL, state TEXT NOT NULL, updated INTEGER NOT NULL)").run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS bpaid_sess ON bpaid (sess)").run();
  payReady = true; }
const HOLD_MS = 15 * 60000;
function stripeForm(obj, pre = "", out = []) {
  for (const [k, v] of Object.entries(obj)) { if (v == null) continue; const key = pre ? `${pre}[${k}]` : k;
    if (typeof v === "object") stripeForm(v, key, out); else out.push(encodeURIComponent(key) + "=" + encodeURIComponent(String(v))); }
  return out.join("&"); }
async function stripe(env, method, path, params, idem) {
  const r = await fetch((env.STRIPE_API || "https://api.stripe.com") + path, { method, headers: { authorization: "Bearer " + env.STRIPE_SECRET_KEY, "content-type": "application/x-www-form-urlencoded", "stripe-version": "2024-06-20", ...(idem ? { "idempotency-key": idem } : {}) }, body: method === "GET" ? undefined : stripeForm(params || {}) });
  const j = await r.json().catch(() => ({})); if (!r.ok) { const e = new Error((j.error && j.error.message) || "stripe error"); e.status = r.status; throw e; } return j; }
async function payAcct(env, sub) { await payInit(env); return await env.DB.prepare("SELECT acct, ready FROM bpay WHERE sub = ?").bind(sub).first(); }
async function payRoutes(env, req, s, path, ch) { // owner: GET /bpage/pay, POST /bpage/pay/connect, POST /bpage/pay/off
  await payInit(env);
  const on = !!env.STRIPE_SECRET_KEY, row = await payAcct(env, s.sub);
  if (path === "/bpage/pay" && req.method === "GET") {
    if (!on) return json({ enabled: false, connected: !!row, ready: false }, 200, ch);
    if (row && !row.ready) { try { const a = await stripe(env, "GET", "/v1/accounts/" + row.acct); const ready = a.charges_enabled ? 1 : 0; if (ready !== row.ready) await env.DB.prepare("UPDATE bpay SET ready = ?, updated = ? WHERE sub = ?").bind(ready, Date.now(), s.sub).run(); return json({ enabled: true, connected: true, ready: !!ready }, 200, ch); } catch { } }
    return json({ enabled: true, connected: !!row, ready: !!(row && row.ready) }, 200, ch);
  }
  if (path === "/bpage/pay/connect" && req.method === "POST") {
    if (!on) return json({ error: "payments not set up yet" }, 503, ch);
    if (limited(req, 5, "payconnect")) return json({ error: "slow down" }, 429, ch);
    let acct = row && row.acct;
    if (!acct) { const a = await stripe(env, "POST", "/v1/accounts", { type: "express", country: "US", ...(bpEmailOk(s.email) ? { email: s.email } : {}), capabilities: { card_payments: { requested: true }, transfers: { requested: true } }, business_profile: { product_description: "Meetings booked through Hourline" }, metadata: { hourline: "1" } }, "acct-" + await sha256("acct:" + s.sub));
      acct = a.id; await env.DB.prepare("INSERT INTO bpay (sub, acct, ready, updated) VALUES (?, ?, 0, ?) ON CONFLICT(sub) DO UPDATE SET acct = excluded.acct, updated = excluded.updated").bind(s.sub, acct, Date.now()).run(); }
    const back = (env.APP_ORIGIN || "https://hourline.io") + "/app/#pay-back";
    const link = await stripe(env, "POST", "/v1/account_links", { account: acct, refresh_url: back, return_url: back, type: "account_onboarding" });
    return json({ url: link.url }, 200, ch);
  }
  if (path === "/bpage/pay/off" && req.method === "POST") { await env.DB.prepare("DELETE FROM bpay WHERE sub = ?").bind(s.sub).run(); return json({ ok: true }, 200, ch); }
  return json({ error: "not found" }, 404, ch);
}
async function payCheckout(env, { handle, m, id, tok, email, acct, ownerName }) { // a Stripe checkout page for one held booking
  const site = env.APP_ORIGIN || "https://hourline.io", fee = Math.floor(m.price * Math.max(0, Math.min(3000, +env.PLATFORM_FEE_BPS || 0)) / 10000);
  const sess = await stripe(env, "POST", "/v1/checkout/sessions", { mode: "payment", customer_email: email, expires_at: Math.floor((Date.now() + 31 * 60000) / 1000),
    line_items: { 0: { quantity: 1, price_data: { currency: m.currency, unit_amount: m.price, product_data: { name: `${m.dep ? "Deposit: " : ""}${m.title} with ${ownerName}`.slice(0, 120) } } } },
    payment_intent_data: { transfer_data: { destination: acct }, ...(fee ? { application_fee_amount: fee } : {}), metadata: { booking: id, handle } },
    metadata: { booking: id, handle }, success_url: `${site}/b/${handle}?b=${tok}&paid=1`, cancel_url: `${site}/b/${handle}?b=${tok}&unpaid=1` }, "cs-" + id);
  await env.DB.prepare("INSERT INTO bpaid (booking, sess, amount, currency, state, updated) VALUES (?, ?, ?, ?, 'open', ?)").bind(id, sess.id, m.price, m.currency, Date.now()).run();
  return sess.url;
}
async function payRefund(env, bookingId) { // best effort; full refund including Hourline's fee
  if (!env.STRIPE_SECRET_KEY) return false; await payInit(env);
  const p = await env.DB.prepare("SELECT pi, state FROM bpaid WHERE booking = ?").bind(bookingId).first(); if (!p || p.state !== "paid" || !p.pi) return false;
  try { await stripe(env, "POST", "/v1/refunds", { payment_intent: p.pi, reverse_transfer: true, refund_application_fee: true }, "rf-" + bookingId);
    await env.DB.prepare("UPDATE bpaid SET state = 'refunded', updated = ? WHERE booking = ?").bind(Date.now(), bookingId).run(); return true; } catch { return false; } }
async function stripeSigOk(env, raw, header) {
  if (!env.STRIPE_WEBHOOK_SECRET || !header) return false;
  const parts = Object.fromEntries(String(header).split(",").map(x => x.split("=")).filter(x => x.length === 2).map(([k, v]) => [k.trim(), v.trim()]));
  const t = +parts.t; if (!t || Math.abs(Date.now() / 1000 - t) > 300) return false;
  const k = await crypto.subtle.importKey("raw", enc.encode(env.STRIPE_WEBHOOK_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = [...new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(t + "." + raw)))].map(b => b.toString(16).padStart(2, "0")).join("");
  const sigs = String(header).split(",").filter(x => x.trim().startsWith("v1=")).map(x => x.trim().slice(3));
  return sigs.some(v => v.length === mac.length && v.split("").reduce((a, c, i) => a | (c.charCodeAt(0) ^ mac.charCodeAt(i)), 0) === 0);
}
async function stripeWebhook(env, req, ctx) {
  const raw = await req.text(); if (raw.length > 200000) return new Response("too big", { status: 413 });
  if (!(await stripeSigOk(env, raw, req.headers.get("stripe-signature")))) return new Response("bad signature", { status: 400 });
  let ev; try { ev = JSON.parse(raw); } catch { return new Response("bad json", { status: 400 }); }
  await payInit(env); await bpInit(env); const o = ev.data && ev.data.object || {}, now = Date.now();
  if (ev.type === "account.updated" && o.id) { await env.DB.prepare("UPDATE bpay SET ready = ?, updated = ? WHERE acct = ?").bind(o.charges_enabled ? 1 : 0, now, o.id).run(); }
  if ((ev.type === "checkout.session.completed" || ev.type === "checkout.session.async_payment_succeeded") && o.payment_status === "paid") {
    const p = await env.DB.prepare("SELECT booking, state FROM bpaid WHERE sess = ?").bind(String(o.id)).first();
    if (p && p.state !== "paid") {
      await env.DB.prepare("UPDATE bpaid SET state = 'paid', pi = ?, updated = ? WHERE booking = ?").bind(String(o.payment_intent || ""), now, p.booking).run();
      const b = await env.DB.prepare("SELECT id, handle, sub, s, e, box, state FROM bbook WHERE id = ?").bind(p.booking).first();
      if (b && (b.state === "hold" || b.state === "expired")) {
        const clash = (await env.DB.prepare("SELECT COUNT(*) AS n FROM bbook WHERE handle = ? AND state = 'ok' AND s < ? AND e > ? AND id != ?").bind(b.handle, b.e, b.s, b.id).first()).n;
        if (clash) { await env.DB.prepare("UPDATE bbook SET state = 'cancelled' WHERE id = ?").bind(b.id).run(); await payRefund(env, b.id); } // paid too late and someone else took it: refund
        else { await env.DB.prepare("UPDATE bbook SET state = 'ok' WHERE id = ?").bind(b.id).run(); const job = bpConfirmed(env, b, ctx); if (ctx && ctx.waitUntil) ctx.waitUntil(job); else await job; }
      }
    }
  }
  if (ev.type === "checkout.session.expired") {
    const p = await env.DB.prepare("SELECT booking FROM bpaid WHERE sess = ?").bind(String(o.id)).first();
    if (p) { await env.DB.prepare("UPDATE bpaid SET state = 'expired', updated = ? WHERE booking = ? AND state = 'open'").bind(now, p.booking).run(); await env.DB.prepare("UPDATE bbook SET state = 'expired' WHERE id = ? AND state = 'hold'").bind(p.booking).run(); }
  }
  return new Response("ok", { status: 200 });
}
async function bpConfirmed(env, b, ctx) { // emails + a push for a booking that's final (free right away, paid once Stripe says so)
  let doc = b.doc, cfg = b.cfg;
  try { if (!doc) doc = (await open(env, b.sub, b.box)).doc; if (!cfg) { const pg = await bpLoad(env, b.handle); cfg = pg && pg.cfg; } } catch { return; }
  if (!doc || !cfg) return;
  const m = cfg.meetings.find(x => x.id === doc.m) || { link: "", place: "", before: "" }, owner = cfg.profile.name, first = doc.name.split(" ")[0], when = bpWhen(b.s, cfg.tz);
  const manage = "https://hourline.io/b/" + b.handle + "?b=" + doc.tok, how = doc.how, phone = doc.phone;
  const where = how === "phone" ? "By phone. " + owner + " will call " + (phone || "you") + "." : how === "person" ? (m.place ? "In person: " + m.place : "In person. " + owner + " will send the address.") : (m.link ? "Video call: " + m.link : owner + " will send a video link.");
  const paidLine = doc.price ? `\nPaid: ${(doc.price / 100).toFixed(2)} ${String(doc.currency || "usd").toUpperCase()}\n` : "";
  await Promise.all([bpMail(env, doc.email, `You're booked with ${owner}: ${doc.title}, ${when}`, `Hi ${first},\n\nYou're booked.\n\n${doc.title} (${doc.len} min) with ${owner}\n${when}\n${where}\n${paidLine}${m.before ? "\nBefore we meet: " + m.before + "\n" : ""}${cfg.thanks ? "\n" + cfg.thanks.replace(/\{first name\}/gi, first) + "\n" : ""}\nNeed to change or cancel? ${manage}\n\nSent by Hourline for ${owner}. Reply to this email to reach ${owner}.`, cfg.email || null),
    cfg.notify && cfg.email ? bpMail(env, cfg.email, `New booking: ${doc.name}, ${doc.title}, ${when}`, `${doc.name} booked ${doc.title} (${doc.len} min)\n${when}\nHow: ${how}${paidLine}\nEmail: ${doc.email}${phone ? "\nPhone: " + phone : ""}${doc.q ? "\n" + doc.q + " " + (doc.answer || "(no answer)") : ""}${doc.note ? "\nNote: " + doc.note : ""}\n\nIt's on your week in Hourline.`, doc.email) : Promise.resolve(false),
    pushTo(env, b.sub, { title: "New booking", body: `${doc.name} · ${doc.title} · ${when}`, url: "/app/#bookings", tag: "bk" + b.id })]);
}
async function bpPublic(env, req, path, ch, ctx) { // GET /p/<handle>, POST /p/<handle>/book, GET|POST /p/<handle>/b/<tok>[/cancel]
  await bpInit(env);
  const parts = path.split("/").filter(Boolean), handle = String(parts[1] || "").toLowerCase(), now = Date.now();
  if (!bpHandleOk(handle)) return json({ error: "not found" }, 404, ch);
  if (limited(req, 90, "bp")) return json({ error: "slow down" }, 429, ch);
  const pg = await bpLoad(env, handle); if (!pg) return json({ error: "not found" }, 404, ch);
  const cfg = pg.cfg;
  if (parts.length === 2 && req.method === "GET") {
    const booked = await bpBooked(env, handle, now), pa = env.STRIPE_SECRET_KEY ? await payAcct(env, pg.sub) : null;
    return json({ handle, look: cfg.look, profile: cfg.profile, tz: cfg.tz, thanks: "", made: true,
      pay: !!(pa && pa.ready), meetings: cfg.meetings.filter(m => m.on).map(m => ({ id: m.id, title: m.title, len: m.len, sub: m.sub, how: m.how, before: m.before, q: m.q, qreq: m.qreq, price: m.price || 0, currency: m.currency || "usd", payWhen: m.payWhen || "all", dep: !!m.dep, days: bpSlots(cfg, m, booked, now) })) }, 200, { ...ch, "cache-control": "no-store" });
  }
  if (parts.length === 3 && parts[2] === "book" && req.method === "POST") {
    if (limited(req, 6, "bpbook")) return json({ error: "slow down" }, 429, ch);
    let b; try { const raw = await req.text(); if (raw.length > 6000) return json({ error: "too big" }, 413, ch); b = JSON.parse(raw); } catch { return json({ error: "bad json" }, 400, ch); }
    if (b && b.hp) return json({ ok: true }, 200, ch); // a robot filled the hidden field: pretend it worked, save nothing
    const m = cfg.meetings.find(x => x.on && x.id === String(b && b.m)); if (!m) return json({ error: "no such meeting" }, 400, ch);
    const name = bpStr(b.name, 80), email = bpStr(b.email, 200).toLowerCase(), phone = bpStr(b.phone, 30).replace(/[^0-9+()\- .]/g, ""), answer = bpStr(b.answer, 300), note = bpStr(b.note, 600);
    const how = BP_HOW.includes(b.how) && m.how.includes(b.how) ? b.how : m.how[0] || "video";
    if (!name || !bpEmailOk(email)) return json({ error: "name and email needed" }, 400, ch);
    if (m.qreq && m.q && !answer) return json({ error: "answer needed" }, 400, ch);
    const ip = await sha256("bpip:" + (req.headers.get("cf-connecting-ip") || "local") + ":" + handle);
    const mine = await env.DB.prepare("SELECT COUNT(*) AS n FROM bbook WHERE handle = ? AND ip = ? AND created > ?").bind(handle, ip, now - 864e5).first();
    if (mine && mine.n >= 3) return json({ error: "too many bookings today" }, 429, ch);
    const start = Math.round(+b.s), booked = await bpBooked(env, handle, now);
    if (!bpSlots(cfg, m, booked, now).some(d => d.times.includes(start))) return json({ error: "taken" }, 409, ch);
    const price = bpPriceAt(m, start, cfg.tz), paid = price > 0; let acct = null;
    if (paid) { const pa = env.STRIPE_SECRET_KEY ? await payAcct(env, pg.sub) : null; if (!pa || !pa.ready) return json({ error: "payments not ready" }, 402, ch); acct = pa.acct; }
    const id = "bk_" + rnd(9), tok = rnd(18), end = start + m.len * 6e4;
    const doc = { m: m.id, title: m.title, len: m.len, how, name, email, phone, answer, q: m.q, note, created: now, tok, ...(paid ? { price, currency: m.currency, ...(m.dep ? { dep: true } : {}) } : {}) };
    await env.DB.prepare("INSERT INTO bbook (id, handle, sub, s, e, box, state, tok, ip, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(id, handle, pg.sub, start, end, await seal(env, pg.sub, doc), paid ? "hold" : "ok", await sha256("bptok:" + tok), ip, now).run();
    const clash = (await bpBooked(env, handle, now)).filter(x => start < x.e && end > x.s).length; // two people at the same instant: the second one loses
    if (clash > 1) { const first = await env.DB.prepare("SELECT id FROM bbook WHERE handle = ? AND state = 'ok' AND s < ? AND e > ? ORDER BY created, id LIMIT 1").bind(handle, end, start).first();
      if (first && first.id !== id) { await env.DB.prepare("DELETE FROM bbook WHERE id = ?").bind(id).run(); return json({ error: "taken" }, 409, ch); } }
    if (paid) { let url; try { url = await payCheckout(env, { handle, m: { ...m, price }, id, tok, email, acct, ownerName: cfg.profile.name }); } catch { await env.DB.prepare("DELETE FROM bbook WHERE id = ?").bind(id).run(); return json({ error: "payment page failed" }, 502, ch); }
      return json({ ok: true, pay: url, manage: tok, s: start, e: end, title: m.title, price, currency: m.currency }, 200, ch); }
    const job = bpConfirmed(env, { id, handle, sub: pg.sub, s: start, e: end, doc, cfg }, ctx); if (ctx && ctx.waitUntil) ctx.waitUntil(job); else await job;
    const when = bpWhen(start, cfg.tz);
    return json({ ok: true, s: start, e: end, title: m.title, len: m.len, how, when, thanks: cfg.thanks.replace(/\{first name\}/gi, name.split(" ")[0]), link: how === "video" ? m.link : "", place: how === "person" ? m.place : "", manage: tok, mailed: !!env.RESEND_API_KEY }, 200, ch);
  }
  if (parts.length >= 4 && parts[2] === "b") {
    const tok = String(parts[3] || ""); if (!/^[A-Za-z0-9_-]{20,40}$/.test(tok)) return json({ error: "not found" }, 404, ch);
    const row = await env.DB.prepare("SELECT id, s, e, box, state FROM bbook WHERE handle = ? AND tok = ?").bind(handle, await sha256("bptok:" + tok)).first();
    if (!row) return json({ error: "not found" }, 404, ch);
    const d = (await open(env, pg.sub, row.box)).doc;
    if (parts.length === 4 && req.method === "GET") return json({ title: d.title, len: d.len, s: row.s, e: row.e, when: bpWhen(row.s, cfg.tz), state: row.state === "hold" && now - (d.created || 0) > HOLD_MS ? "expired" : row.state, name: d.name.split(" ")[0], price: d.price || 0, currency: d.currency || "usd" }, 200, ch);
    if (parts.length === 5 && parts[4] === "cancel" && req.method === "POST") {
      let refunded = false;
      if (row.state === "hold") await env.DB.prepare("UPDATE bbook SET state = 'cancelled' WHERE id = ?").bind(row.id).run();
      if (row.state === "ok") { await env.DB.prepare("UPDATE bbook SET state = 'cancelled' WHERE id = ?").bind(row.id).run();
        if (d.price && row.s - now > 864e5) refunded = await payRefund(env, row.id); // paid: refunded when cancelled more than a day ahead
        const when = bpWhen(row.s, cfg.tz), jobs = [cfg.notify && cfg.email ? bpMail(env, cfg.email, `Cancelled: ${d.name}, ${d.title}, ${when}`, `${d.name} cancelled ${d.title} on ${when}. The time is open again on your booking page.`, d.email) : Promise.resolve(false),
          pushTo(env, pg.sub, { title: "Booking cancelled", body: `${d.name} · ${d.title} · ${when}`, url: "/app/#bookings", tag: "bk" + row.id })];
        if (ctx && ctx.waitUntil) ctx.waitUntil(Promise.all(jobs)); else await Promise.all(jobs); }
      return json({ ok: true, state: "cancelled", refunded }, 200, ch);
    }
  }
  return json({ error: "not found" }, 404, ch);
}
async function bpOwner(env, req, s, path, ch, ctx) { // the owner's app: claim a link, save the page, see and cancel bookings
  await bpInit(env);
  const now = Date.now(), M = req.method, row = await env.DB.prepare("SELECT handle, box, updated FROM bpages WHERE sub = ?").bind(s.sub).first();
  if (path === "/bpage" && M === "GET") { if (!row) return json({ on: false, pics: true }, 200, ch); let o = null; try { o = (await open(env, s.sub, row.box)).doc; } catch { }
    return json({ on: true, handle: row.handle, url: "https://hourline.io/b/" + row.handle, updated: row.updated, pics: true, hasPhoto: !!(o && o.profile && o.profile.photo), hasCover: !!(o && o.look && o.look.cover) }, 200, ch); }
  if (path === "/bpage/check" && M === "GET") { const h = String(new URL(req.url).searchParams.get("h") || "").toLowerCase(); if (!bpHandleOk(h)) return json({ ok: false, why: "format" }, 200, ch);
    const t = await env.DB.prepare("SELECT sub FROM bpages WHERE handle = ?").bind(h).first(); return json({ ok: !t || t.sub === s.sub }, 200, ch); }
  if (path === "/bpage" && M === "PUT") {
    if (limited(req, 30, "bpput")) return json({ error: "slow down" }, 429, ch);
    const raw = await req.text(); if (raw.length > 450_000) return json({ error: "too big" }, 413, ch);
    let b; try { b = JSON.parse(raw); } catch { return json({ error: "bad json" }, 400, ch); }
    const h = String(b && b.handle || (row && row.handle) || "").toLowerCase(); if (!bpHandleOk(h)) return json({ error: "bad link name" }, 400, ch);
    const cfg = bpClean(b, now); if (!cfg) return json({ error: "bad page" }, 400, ch);
    // pictures live on the server only (they'd bloat the synced schedule): a save that doesn't mention a picture keeps the one already there; "" removes it
    if (row) { let old = null; try { old = (await open(env, s.sub, row.box)).doc; } catch { }
      if (old) { if (!(b.profile && typeof b.profile === "object" && "photo" in b.profile)) cfg.profile.photo = bpPic(old.profile && old.profile.photo, BP_PHOTO_MAX); if (!(b.look && typeof b.look === "object" && "cover" in b.look)) cfg.look.cover = bpPic(old.look && old.look.cover, BP_COVER_MAX); } }
    if (cfg.notify && bpEmailOk(s.email)) cfg.email = String(s.email).toLowerCase();
    const taken = await env.DB.prepare("SELECT sub FROM bpages WHERE handle = ?").bind(h).first(); if (taken && taken.sub !== s.sub) return json({ error: "taken" }, 409, ch);
    if (row && row.handle !== h) { await env.DB.prepare("DELETE FROM bpages WHERE sub = ?").bind(s.sub).run(); await env.DB.prepare("UPDATE bbook SET handle = ? WHERE sub = ?").bind(h, s.sub).run(); }
    await env.DB.prepare("INSERT INTO bpages (handle, sub, box, updated) VALUES (?, ?, ?, ?) ON CONFLICT(handle) DO UPDATE SET box = excluded.box, updated = excluded.updated").bind(h, s.sub, await seal(env, s.sub, cfg), now).run();
    return json({ ok: true, handle: h, url: "https://hourline.io/b/" + h, mail: !!env.RESEND_API_KEY, pics: true }, 200, ch);
  }
  if (path === "/bpage" && M === "DELETE") { await env.DB.prepare("DELETE FROM bpages WHERE sub = ?").bind(s.sub).run(); await env.DB.prepare("DELETE FROM bbook WHERE sub = ?").bind(s.sub).run(); return json({ ok: true }, 200, ch); }
  if (path === "/bpage/bookings" && M === "GET") {
    const rows = (await env.DB.prepare("SELECT id, s, e, box, state, created FROM bbook WHERE sub = ? AND e > ? ORDER BY s LIMIT 300").bind(s.sub, now - 30 * 864e5).all()).results || [];
    const out = []; for (const r of rows) { try { const d = (await open(env, s.sub, r.box)).doc; if (r.state === "hold" && now - r.created > HOLD_MS) continue; out.push({ id: r.id, s: r.s, e: r.e, state: r.state, created: r.created, title: d.title, len: d.len, how: d.how, name: d.name, email: d.email, phone: d.phone, q: d.q, answer: d.answer, note: d.note, ...(d.price ? { price: d.price, currency: d.currency } : {}) }); } catch { } }
    return json({ bookings: out }, 200, ch);
  }
  const mc = path.match(/^\/bpage\/bookings\/(bk_[A-Za-z0-9_-]{8,20})\/cancel$/);
  if (mc && M === "POST") {
    const r = await env.DB.prepare("SELECT id, s, box, state FROM bbook WHERE id = ? AND sub = ?").bind(mc[1], s.sub).first(); if (!r) return json({ error: "not found" }, 404, ch);
    if (r.state === "ok" || r.state === "hold") { await env.DB.prepare("UPDATE bbook SET state = 'cancelled' WHERE id = ?").bind(r.id).run(); await payRefund(env, r.id);
      const d = (await open(env, s.sub, r.box)).doc, pgc = row ? (await open(env, s.sub, row.box)).doc : null, who = pgc ? pgc.profile.name : "Your host";
      const j = bpMail(env, d.email, `Cancelled: ${d.title} with ${who}`, `Hi ${d.name.split(" ")[0]},\n\n${who} had to cancel ${d.title} on ${bpWhen(r.s, pgc ? pgc.tz : "America/Chicago")}.${row ? "\n\nPick a new time: https://hourline.io/b/" + row.handle : ""}\n\nSent by Hourline for ${who}.`, pgc && pgc.email || null);
      if (ctx && ctx.waitUntil) ctx.waitUntil(j); else await j; }
    return json({ ok: true }, 200, ch);
  }
  return json({ error: "not found" }, 404, ch);
}
// ---- reading someone's other calendar by its link (Google secret address, iCloud public link, Outlook ICS link) ----
// The app can't read those addresses itself (the calendar sites don't allow it from a web page), so the server fetches
// the file and hands back the text. Nothing is stored. Only public https addresses on standard port 443: no IP
// addresses, no local or internal names, at most 3 redirects (each checked), 10 seconds and 5 MB.
const ICS_MAX = 5_000_000;
function icsUrlOk(raw) {
  let u; try { u = new URL(String(raw || "").trim().replace(/^webcal:/i, "https:")); } catch { return null; }
  if (u.protocol !== "https:" || u.username || u.password || (u.port && u.port !== "443")) return null;
  const h = u.hostname.toLowerCase();
  if (!h.includes(".") || /^[\d.]+$/.test(h) || h.includes(":") || h.startsWith("[") || /(^|\.)(localhost|local|internal|intranet|lan|home|corp|arpa)$/.test(h) || h.endsWith(".hourline.io") || h === "hourline.io") return null;
  if (u.href.length > 1000) return null;
  return u;
}
async function icsFetchRoute(env, req, s, ch) {
  if (limited(req, 20, "icsfetch")) return json({ error: "slow down" }, 429, ch);
  const b = await req.json().catch(() => null); let u = icsUrlOk(b && b.url); if (!u) return json({ error: "bad link" }, 400, ch);
  const ctl = new AbortController(), timer = setTimeout(() => ctl.abort(), 10000);
  try {
    let r, hops = 0;
    for (;;) {
      r = await fetch(u.href, { method: "GET", redirect: "manual", signal: ctl.signal, headers: { accept: "text/calendar, text/plain;q=0.8, */*;q=0.1", "user-agent": "Hourline calendar import (+https://hourline.io)" } });
      if (r.status >= 300 && r.status < 400 && r.headers.get("location")) { if (++hops > 3) return json({ error: "too many redirects" }, 400, ch); u = icsUrlOk(new URL(r.headers.get("location"), u).href); if (!u) return json({ error: "bad link" }, 400, ch); continue; }
      break;
    }
    if (!r.ok) return json({ error: "calendar said " + r.status }, 400, ch);
    if (+(r.headers.get("content-length") || 0) > ICS_MAX) return json({ error: "too big" }, 413, ch);
    const rd = r.body.getReader(); let got = 0; const parts = [];
    for (;;) { const { done, value } = await rd.read(); if (done) break; got += value.length; if (got > ICS_MAX) { try { await rd.cancel(); } catch { } return json({ error: "too big" }, 413, ch); } parts.push(value); }
    const all = new Uint8Array(got); let o = 0; for (const p of parts) { all.set(p, o); o += p.length; }
    const text = new TextDecoder("utf-8", { fatal: false }).decode(all);
    if (!/^\s*BEGIN:VCALENDAR/i.test(text.slice(0, 500))) return json({ error: "not a calendar" }, 400, ch);
    return json({ text }, 200, { ...ch, "cache-control": "no-store" });
  } catch (e) { return json({ error: "couldn't reach that calendar" }, 502, ch); }
  finally { clearTimeout(timer); }
}
// ---- Google Calendar, read-only (plan Phase 3b) ----
// Only when the person taps Connect: Google asks them to allow reading their events and calendar list. Nothing can be
// created, changed or deleted. The long-lived permission (refresh token) is sealed with the person's key; events are read
// when the app asks and handed straight back, never stored here. Disconnect deletes the permission and asks Google to revoke it.
const GCAL_SCOPES = "https://www.googleapis.com/auth/calendar.events.readonly https://www.googleapis.com/auth/calendar.calendarlist.readonly";
const GCAL_TOKEN = "https://oauth2.googleapis.com/token", GCAL_API = "https://www.googleapis.com/calendar/v3";
let gcalReady = false;
async function gcalInit(env) { if (gcalReady) return;
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS gcal (sub TEXT PRIMARY KEY, box TEXT NOT NULL, updated INTEGER NOT NULL)").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS gcal_state (id TEXT PRIMARY KEY, sub TEXT NOT NULL, box TEXT NOT NULL, created INTEGER NOT NULL)").run(); gcalReady = true; }
const gcalCb = env => (env.GCAL_REDIRECT || "https://api.hourline.io/gcal/callback");
async function gcalAccess(env, sub) {
  const row = await env.DB.prepare("SELECT box FROM gcal WHERE sub = ?").bind(sub).first(); if (!row) return null;
  const d = (await open(env, sub, row.box)).doc;
  const r = await fetch(env.GCAL_TOKEN_URL || GCAL_TOKEN, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ client_id: env.GOOGLE_CLIENT_ID, client_secret: String(env.GOOGLE_CLIENT_SECRET || "").trim(), refresh_token: d.rt, grant_type: "refresh_token" }) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) { if (j.error === "invalid_grant") await env.DB.prepare("DELETE FROM gcal WHERE sub = ?").bind(sub).run(); return null; }
  return j.access_token;
}
function gcalLink(ev) {
  const v = ((ev.conferenceData && ev.conferenceData.entryPoints) || []).find(x => x.entryPointType === "video");
  return cleanLink(ev.hangoutLink || (v && v.uri) || "") || "";
}
async function gcalRoutes(env, req, s, path, ch) {
  await gcalInit(env);
  if (!env.GOOGLE_CLIENT_SECRET) return json({ error: "not set up" }, 503, ch);
  const now = Date.now();
  // Until Google approves the calendar permissions, only the owner (ADMIN_EMAILS) and GCAL_TESTERS can start a connection; GCAL_OPEN = "1" opens it to everyone.
  const allowed = env.GCAL_OPEN === "1" || isAdmin(env, s) || String(env.GCAL_TESTERS || "").toLowerCase().split(",").map(x => x.trim()).filter(Boolean).includes(String(s.email || "").toLowerCase());
  if (path === "/gcal/begin" && req.method === "POST") { // the app gets a one-time Google consent link
    if (!allowed) return json({ error: "not available yet" }, 403, ch);
    if (limited(req, 10, "gcal")) return json({ error: "slow down" }, 429, ch);
    const state = rnd(24), verifier = rnd(48), challenge = b64u(await crypto.subtle.digest("SHA-256", enc.encode(verifier)));
    await env.DB.prepare("DELETE FROM gcal_state WHERE created < ?").bind(now - 15 * 60000).run();
    await env.DB.prepare("INSERT INTO gcal_state (id, sub, box, created) VALUES (?, ?, ?, ?)").bind("g_" + await sha256("gstate:" + state), s.sub, await seal(env, s.sub, { verifier }), now).run();
    const q = new URLSearchParams({ client_id: env.GOOGLE_CLIENT_ID, redirect_uri: gcalCb(env), response_type: "code", scope: GCAL_SCOPES, access_type: "offline", prompt: "consent", include_granted_scopes: "false", state, code_challenge: challenge, code_challenge_method: "S256", login_hint: String(s.email || "") });
    return json({ url: (env.GOOGLE_AUTH_URL || GOOGLE_AUTH) + "?" + q }, 200, ch);
  }
  if (path === "/gcal" && req.method === "GET") { const row = await env.DB.prepare("SELECT updated FROM gcal WHERE sub = ?").bind(s.sub).first(); return json({ on: !!row, since: row ? row.updated : 0, allowed }, 200, ch); }
  if (path === "/gcal/off" && req.method === "POST") {
    const row = await env.DB.prepare("SELECT box FROM gcal WHERE sub = ?").bind(s.sub).first();
    if (row) { try { const d = (await open(env, s.sub, row.box)).doc; await fetch((env.GCAL_REVOKE_URL || "https://oauth2.googleapis.com/revoke") + "?token=" + encodeURIComponent(d.rt), { method: "POST" }); } catch (e) { } }
    await env.DB.prepare("DELETE FROM gcal WHERE sub = ?").bind(s.sub).run(); return json({ ok: true }, 200, ch);
  }
  if (path === "/gcal/calendars" && req.method === "POST") {
    if (limited(req, 30, "gcal")) return json({ error: "slow down" }, 429, ch);
    const at = await gcalAccess(env, s.sub); if (!at) return json({ error: "not connected" }, 409, ch);
    const r = await fetch(GCAL_API + "/users/me/calendarList?minAccessRole=freeBusyReader&maxResults=50&fields=items(id,summary,summaryOverride,primary,backgroundColor,accessRole,selected)", { headers: { authorization: "Bearer " + at } });
    if (!r.ok) return json({ error: "google said " + r.status }, 502, ch);
    const j = await r.json(); return json({ calendars: (j.items || []).slice(0, 50).map(c => ({ id: String(c.id).slice(0, 200), name: String(c.summaryOverride || c.summary || "Calendar").slice(0, 60), primary: !!c.primary, color: /^#[0-9a-f]{6}$/i.test(c.backgroundColor || "") ? c.backgroundColor : "", on: c.selected !== false })) }, 200, ch);
  }
  if (path === "/gcal/events" && req.method === "POST") {
    if (limited(req, 30, "gcal")) return json({ error: "slow down" }, 429, ch);
    const b = await req.json().catch(() => null); const cals = Array.isArray(b && b.cals) ? b.cals.map(String).filter(x => x.length <= 200).slice(0, 10) : [];
    const from = Math.max(now - 14 * 864e5, +b.from || now), to = Math.min(now + 120 * 864e5, +b.to || now + 84 * 864e5);
    if (!cals.length || !(to > from)) return json({ error: "bad request" }, 400, ch);
    const at = await gcalAccess(env, s.sub); if (!at) return json({ error: "not connected" }, 409, ch);
    const out = [];
    for (const cal of cals) {
      let page = "", n = 0;
      do {
        const q = new URLSearchParams({ singleEvents: "true", orderBy: "startTime", timeMin: new Date(from).toISOString(), timeMax: new Date(to).toISOString(), maxResults: "2500", fields: "nextPageToken,items(id,iCalUID,summary,status,transparency,start,end,location,hangoutLink,conferenceData/entryPoints,recurringEventId,originalStartTime,attendees(self,responseStatus),eventType)", ...(page ? { pageToken: page } : {}) });
        const r = await fetch(GCAL_API + "/calendars/" + encodeURIComponent(cal) + "/events?" + q, { headers: { authorization: "Bearer " + at } });
        if (!r.ok) { if (r.status === 404 || r.status === 403) break; return json({ error: "google said " + r.status }, 502, ch); }
        const j = await r.json(); page = j.nextPageToken || "";
        for (const ev of j.items || []) {
          if (ev.status === "cancelled") continue;
          const allDay = !!(ev.start && ev.start.date), s0 = allDay ? Date.parse(ev.start.date + "T00:00:00") : Date.parse(ev.start && ev.start.dateTime), e0 = allDay ? Date.parse(ev.end.date + "T00:00:00") : Date.parse(ev.end && ev.end.dateTime);
          if (!(s0 > 0 && e0 >= s0)) continue;
          const me = (ev.attendees || []).find(a => a.self), declined = me && me.responseStatus === "declined";
          const uid = String(ev.iCalUID || ev.id).slice(0, 200), orig = ev.recurringEventId && ev.originalStartTime ? (ev.originalStartTime.dateTime ? Date.parse(ev.originalStartTime.dateTime) : ev.originalStartTime.date) : null;
          out.push({ key: (orig != null ? uid + "|" + orig : uid).slice(0, 240), uid, title: String(ev.summary || "Busy").slice(0, 90), s: s0, e: e0, allDay, ...(allDay ? { day: ev.start.date, dayEnd: ev.end.date } : {}),
            free: ev.transparency === "transparent" || !!declined || ev.eventType === "workingLocation", series: !!ev.recurringEventId, loc: String(ev.location || "").slice(0, 300), url: gcalLink(ev), desc: "", cal });
          if (out.length >= 3000) break;
        }
      } while (page && ++n < 4 && out.length < 3000);
    }
    return json({ events: out }, 200, { ...ch, "cache-control": "no-store" });
  }
  return json({ error: "not found" }, 404, ch);
}
async function gcalCallback(env, req, url) {
  const back = (ok, why) => new Response(null, { status: 302, headers: { ...SEC, location: (env.APP_ORIGIN || "https://hourline.io") + "/app/#" + (ok ? "gcal-ok" : "gcal-" + why) } });
  if (limited(req, 20, "gcalcb")) return back(false, "slow");
  await gcalInit(env);
  const state = url.searchParams.get("state") || "", code = url.searchParams.get("code") || "";
  if (!/^[A-Za-z0-9_-]{32}$/.test(state)) return back(false, "bad");
  const id = "g_" + await sha256("gstate:" + state), row = await env.DB.prepare("SELECT sub, box, created FROM gcal_state WHERE id = ?").bind(id).first();
  await env.DB.prepare("DELETE FROM gcal_state WHERE id = ?").bind(id).run(); // one use only
  if (!row || Date.now() - row.created > 15 * 60000) return back(false, "expired");
  if (url.searchParams.get("error") || !code) return back(false, "denied");
  const granted = (url.searchParams.get("scope") || "").split(" ");
  const { verifier } = (await open(env, row.sub, row.box)).doc;
  const r = await fetch(env.GCAL_TOKEN_URL || GCAL_TOKEN, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ code, client_id: env.GOOGLE_CLIENT_ID, client_secret: String(env.GOOGLE_CLIENT_SECRET || "").trim(), redirect_uri: gcalCb(env), grant_type: "authorization_code", code_verifier: verifier }) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.refresh_token) { // say which part Google refused (Google's error code only; never the secret or the code)
    const e = String(j.error || ""), d = String(j.error_description || "").slice(0, 120);
    console.log(JSON.stringify({ gcal: "token-refused", status: r.status, error: e, desc: d }));
    return back(false, e === "invalid_client" || e === "unauthorized_client" ? "client" : e === "invalid_grant" ? (/redirect/i.test(d) ? "redirect" : "grant") : e === "redirect_uri_mismatch" ? "redirect" : r.ok ? "norefresh" : "failed"); }
  const sc = String(j.scope || granted.join(" "));
  if (!sc.includes("calendar.events.readonly")) { try { await fetch((env.GCAL_REVOKE_URL || "https://oauth2.googleapis.com/revoke") + "?token=" + encodeURIComponent(j.refresh_token), { method: "POST" }); } catch (e) { } return back(false, "scope"); }
  await env.DB.prepare("INSERT INTO gcal (sub, box, updated) VALUES (?, ?, ?) ON CONFLICT(sub) DO UPDATE SET box = excluded.box, updated = excluded.updated").bind(row.sub, await seal(env, row.sub, { rt: j.refresh_token, scope: sc.slice(0, 400) }), Date.now()).run();
  return back(true);
}
async function feedPublic(env, req, tok) {
  const H = { ...SEC, "content-type": "text/calendar; charset=utf-8", "cache-control": "private, max-age=300", "x-robots-tag": "noindex, nofollow", "content-disposition": 'inline; filename="hourline.ics"' };
  if (limited(req, 60, "cal")) return new Response("slow down", { status: 429, headers: { ...SEC, "content-type": "text/plain" } });
  if (!/^[A-Za-z0-9_-]{32}$/.test(tok)) return new Response("not found", { status: 404, headers: { ...SEC, "content-type": "text/plain" } });
  await feedInit(env);
  const row = await env.DB.prepare("SELECT sub, box FROM feeds WHERE id = ?").bind("f_" + await sha256("feed:" + tok)).first();
  if (!row) return new Response("not found", { status: 404, headers: { ...SEC, "content-type": "text/plain" } });
  let d; try { d = (await open(env, row.sub, row.box)).doc; } catch (e) { return new Response("not found", { status: 404, headers: { ...SEC, "content-type": "text/plain" } }); }
  if (d.tok !== tok) return new Response("not found", { status: 404, headers: { ...SEC, "content-type": "text/plain" } });
  return new Response(feedIcs(d, Date.now()), { status: 200, headers: H });
}
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
You coach on schedules, habits, prospecting, follow-ups, goals, motivation and sales conversations, and you also answer everyday general-knowledge questions briefly and accurately. If you are not sure of a fact, say so. For medical, legal, tax or investment questions give only general information and suggest the right professional; for a personal crisis, be kind and point them to real help (in the US, call or text 988).
You can't take actions from here; if they want to book, add a prospect or change a setting, tell them the exact phrase to say, e.g. "book an appointment with Sam Friday at 3".
Never shame the person. Never claim to be human.
User data (JSON): ${ctx}`;
  let r;
  try {
    r = await fetch(env.ANTHROPIC_URL || "https://api.anthropic.com/v1/messages", { method: "POST", headers: { "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json" },
      body: JSON.stringify({ model: env.ELLA_MODEL || "claude-haiku-5-5", max_tokens: 220, system, messages: ellaTurns([...hist, { role: "user", content: q }]) }) });
  } catch { return json({ error: "ai unavailable", code: 0 }, 502, ch); }
  if (!r.ok) { console.error("ella upstream", r.status); return json({ error: "ai unavailable", code: r.status }, 502, ch); } // status only (401 = bad key, 404 = model name, 429/529 = busy)
  const out = await r.json().catch(() => null), reply = out && Array.isArray(out.content) ? out.content.filter(c => c.type === "text").map(c => c.text).join(" ").trim().slice(0, 600) : "";
  return json(reply ? { text: reply, left: Math.max(0, max - ((row ? row.n : 0) + 1)) } : { error: "ai unavailable" }, reply ? 200 : 502, ch);
}

// ---- problem reports ("Report a problem" in the app). Anyone can send one (signed in or not), at most 5 per 10 minutes
// per address. The text, contact and technical details are encrypted at rest; only an admin (ADMIN_EMAILS, comma list)
// can read them. Admins get a push when one arrives. Kept 180 days. "Delete my cloud data" removes a person's reports.
// The technical triage fields (area, app version, device, error messages: no names, contact or schedule content) are kept
// readable in "meta" so the builder (and Claude, through the Cloudflare connector) can triage without decrypting anything.
let fbReady = false;
async function fbInit(env) { if (fbReady) return;
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS feedback (id TEXT PRIMARY KEY, at INTEGER NOT NULL, sub TEXT NOT NULL, box TEXT NOT NULL, done INTEGER NOT NULL DEFAULT 0, meta TEXT NOT NULL DEFAULT '{}')").run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS feedback_at ON feedback (at)").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS admins (sub TEXT PRIMARY KEY, seen INTEGER NOT NULL)").run(); fbReady = true; }
// ---- admin: who is on Hourline ----
// One row per account: the sign-in email (encrypted at rest), first and last time the app talked to the server, and a
// pause switch. Nothing from anyone's schedule, prospects, goals or notes: those stay encrypted and are never read here.
// A paused account can't sync or use team features until it's resumed; nothing is deleted, and the app keeps working
// on the phone. Admins (ADMIN_EMAILS) can't be paused.
let peopleReady = false; const peopleMem = new Map();
async function peopleInit(env) { if (peopleReady) return; await env.DB.prepare("CREATE TABLE IF NOT EXISTS seen (sub TEXT PRIMARY KEY, box TEXT NOT NULL, first INTEGER NOT NULL, last INTEGER NOT NULL, paused INTEGER NOT NULL DEFAULT 0)").run(); peopleReady = true; }
async function peopleTouch(env, s) { // returns true when this account is paused
  const now = Date.now(), c = peopleMem.get(s.sub); if (c && now - c.at < 60_000) return c.paused;
  await peopleInit(env);
  const row = await env.DB.prepare("SELECT last, paused FROM seen WHERE sub = ?").bind(s.sub).first();
  if (!row) await env.DB.prepare("INSERT INTO seen (sub, box, first, last, paused) VALUES (?, ?, ?, ?, 0) ON CONFLICT(sub) DO NOTHING").bind(s.sub, await seal(env, "people", { email: String(s.email || "").toLowerCase().slice(0, 200) }), now, now).run();
  else if (now - row.last > 3600_000) await env.DB.prepare("UPDATE seen SET last = ?, box = ? WHERE sub = ?").bind(now, await seal(env, "people", { email: String(s.email || "").toLowerCase().slice(0, 200) }), s.sub).run(); // re-sealed each time, so a rotated key keeps it readable
  const paused = !!(row && row.paused) && !isAdmin(env, s);
  if (peopleMem.size > 5000) peopleMem.clear(); peopleMem.set(s.sub, { at: now, paused }); return paused;
}
// flat price per plan (no per-seat add-ons). founding = what the first 25 paying teams pay, locked for 24 months. An estimate for the admin view: billing isn't built yet.
const planFor = n => n <= 5 ? { plan: "Solo", price: 39, founding: 29 } : n <= 15 ? { plan: "Team", price: 129, founding: 99 } : n <= 40 ? { plan: "Agency", price: 299, founding: 199 } : { plan: "Organization", price: null, founding: null };
async function peopleRoutes(env, req, s, path, ch) {
  if (!s) return json({ error: "signed out" }, 401, ch);
  if (!isAdmin(env, s)) return json({ error: "not allowed" }, 403, ch);
  await peopleInit(env); const M = req.method, now = Date.now();
  if (path === "/admin/people" && M === "GET") {
    const rows = (await env.DB.prepare("SELECT sub, box, first, last, paused FROM seen ORDER BY last DESC LIMIT 2000").all()).results || [];
    const mem = (await env.DB.prepare("SELECT m.sub AS sub, m.role AS role, m.team AS team, t.name AS name FROM members m JOIN teams t ON t.id = m.team").all()).results || [];
    let pages = []; try { pages = (await env.DB.prepare("SELECT sub, handle FROM bpages").all()).results || []; } catch { }
    const size = {}; for (const m of mem) size[m.team] = (size[m.team] || 0) + 1;
    const bySub = {}; for (const m of mem) (bySub[m.sub] = bySub[m.sub] || []).push({ name: String(m.name || "").slice(0, 60), role: m.role, seats: size[m.team] });
    const pg = {}; for (const p of pages) pg[p.sub] = p.handle;
    const people = []; for (const r of rows) { let email = ""; try { email = (await open(env, "people", r.box)).doc.email || ""; } catch { }
      people.push({ id: r.sub, email, first: r.first, last: r.last, paused: !!r.paused, teams: bySub[r.sub] || [], page: pg[r.sub] || "", admin: adminList(env).includes(email) }); }
    const teamRows = (await env.DB.prepare("SELECT id, name, created FROM teams").all()).results || [];
    const teams = teamRows.map(t => ({ name: String(t.name || "").slice(0, 60), seats: size[t.id] || 0, created: t.created, ...planFor(size[t.id] || 0) })).sort((a, b) => b.seats - a.seats);
    const act = d => rows.filter(r => now - r.last < d * 864e5).length;
    return json({ people, teams, totals: { all: rows.length, day: act(1), week: act(7), month: act(30), new7: rows.filter(r => now - r.first < 7 * 864e5).length, paused: rows.filter(r => r.paused).length, teams: teams.length,
      mrr: teams.reduce((a, t) => a + (t.price || 0), 0), mrrFounding: teams.reduce((a, t) => a + (t.founding || 0), 0) } }, 200, { ...ch, "cache-control": "no-store" });
  }
  const m = path.match(/^\/admin\/people\/([A-Za-z0-9_.:|@-]{1,128})$/);
  if (m && M === "POST") { let b = {}; try { b = await req.json(); } catch { }
    const row = await env.DB.prepare("SELECT box FROM seen WHERE sub = ?").bind(m[1]).first(); if (!row) return json({ error: "not found" }, 404, ch);
    let email = ""; try { email = (await open(env, "people", row.box)).doc.email || ""; } catch { }
    if (b && b.paused && adminList(env).includes(email)) return json({ error: "admins can't be paused" }, 400, ch);
    await env.DB.prepare("UPDATE seen SET paused = ? WHERE sub = ?").bind(b && b.paused ? 1 : 0, m[1]).run(); peopleMem.delete(m[1]);
    return json({ ok: true, paused: !!(b && b.paused) }, 200, ch); }
  return json({ error: "not found" }, 404, ch);
}
const adminList = env => String(env.ADMIN_EMAILS || "solamonjoseph97@gmail.com").toLowerCase().split(",").map(x => x.trim()).filter(Boolean);
const isAdmin = (env, s) => !!(s && s.email && adminList(env).includes(String(s.email).toLowerCase()));
async function feedbackRoutes(env, req, s, path, ch) {
  await fbInit(env); const M = req.method;
  if (path === "/feedback" && M === "POST") {
    if (limited(req, 5, "fb")) return json({ error: "slow down" }, 429, ch);
    const text = await req.text(); if (text.length > 8000) return json({ error: "too large" }, 413, ch);
    let b; try { b = JSON.parse(text); } catch { return json({ error: "bad request" }, 400, ch); }
    const msg = String(b && b.text || "").trim().slice(0, 2000); if (msg.length < 3) return json({ error: "bad request" }, 400, ch);
    const area = String(b.area || "").replace(/[^a-z-]/g, "").slice(0, 20), contact = String(b.contact || "").trim().slice(0, 120);
    let diag = {}; try { diag = JSON.parse(JSON.stringify(b.diag || {}).slice(0, 3000)); } catch { diag = {}; }
    const id = "fb_" + rnd(12), at = Date.now();
    const meta = JSON.stringify({ area, v: String(diag.v || "").slice(0, 30), sw: String(diag.sw || "").slice(0, 12), ua: String(diag.ua || "").slice(0, 180), home: !!diag.homeScreen, notif: String(diag.notifications || "").slice(0, 10), sync: !!diag.sync, team: String(diag.team || "").slice(0, 10), errors: Array.isArray(diag.errors) ? diag.errors.slice(-5).map(e => ({ t: String(e && e.t || "").slice(0, 16), m: String(e && e.m || "").slice(0, 140), l: +(e && e.l) || 0 })) : [] });
    await env.DB.prepare("INSERT INTO feedback (id, at, sub, box, done, meta) VALUES (?, ?, ?, ?, 0, ?)").bind(id, at, s ? s.sub : "", await seal(env, "feedback", { text: msg, area, contact, diag, email: s ? s.email || "" : "" }), meta).run();
    const admins = (await env.DB.prepare("SELECT sub FROM admins").all()).results || [];
    for (const a of admins) await pushTo(env, a.sub, { title: "New problem report", body: (area ? area + ": " : "") + msg.slice(0, 100), url: "/app/#reports", tag: "fb-" + id });
    return json({ ok: true, id }, 200, ch);
  }
  if (!s) return json({ error: "signed out" }, 401, ch);
  if (!isAdmin(env, s)) return json({ error: "not allowed" }, 403, ch);
  await env.DB.prepare("INSERT INTO admins (sub, seen) VALUES (?, ?) ON CONFLICT(sub) DO UPDATE SET seen = excluded.seen").bind(s.sub, Date.now()).run();
  if (path === "/admin/feedback" && M === "GET") {
    const rows = (await env.DB.prepare("SELECT id, at, done, box FROM feedback ORDER BY at DESC LIMIT 100").all()).results || [];
    const out = [];for (const r of rows) { try { const d = (await open(env, "feedback", r.box)).doc; out.push({ id: r.id, at: r.at, done: !!r.done, ...d }); } catch { } }
    return json({ items: out }, 200, ch);
  }
  const m = path.match(/^\/admin\/feedback\/(fb_[A-Za-z0-9_-]{8,30})$/);
  if (m && M === "POST") { let b = {}; try { b = await req.json(); } catch { }
    await env.DB.prepare("UPDATE feedback SET done = ? WHERE id = ?").bind(b && b.done ? 1 : 0, m[1]).run(); return json({ ok: true }, 200, ch); }
  return json({ error: "not found" }, 404, ch);
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
  async fetch(req, env, ctx) {
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
      if (s && await peopleTouch(env, s)) return json({ error: "paused" }, 403, ch); // an admin paused this account; nothing is deleted
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
          await feedInit(env); await env.DB.prepare("DELETE FROM feeds WHERE sub = ?").bind(s.sub).run();
          await bpInit(env); await env.DB.prepare("DELETE FROM bpages WHERE sub = ?").bind(s.sub).run(); await env.DB.prepare("DELETE FROM bbook WHERE sub = ?").bind(s.sub).run(); await payInit(env); await env.DB.prepare("DELETE FROM bpay WHERE sub = ?").bind(s.sub).run();
          await gcalInit(env); { const g = await env.DB.prepare("SELECT box FROM gcal WHERE sub = ?").bind(s.sub).first(); if (g) { try { const d = (await open(env, s.sub, g.box)).doc; await fetch("https://oauth2.googleapis.com/revoke?token=" + encodeURIComponent(d.rt), { method: "POST" }); } catch (e) { } } }
          await env.DB.prepare("DELETE FROM gcal WHERE sub = ?").bind(s.sub).run(); await env.DB.prepare("DELETE FROM gcal_state WHERE sub = ?").bind(s.sub).run();
          await ellaInit(env); await env.DB.prepare("DELETE FROM ella_use WHERE sub = ?").bind(s.sub).run();
          await evInit(env); await env.DB.prepare("DELETE FROM events_use WHERE sub = ?").bind(s.sub).run();
          await nudgeInit(env); await env.DB.prepare("DELETE FROM nudge_use WHERE sub = ?").bind(s.sub).run();
          await fbInit(env); await env.DB.prepare("DELETE FROM feedback WHERE sub = ?").bind(s.sub).run();
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
      if (path === "/feedback" || path === "/admin/feedback" || path.startsWith("/admin/feedback/")) return await feedbackRoutes(env, req, s, path, ch);
      if (path === "/admin/people" || path.startsWith("/admin/people/")) return await peopleRoutes(env, req, s, path, ch);
      if (path === "/push/key" && req.method === "GET") return json({ key: (await vapidKeys(env)).pub }, 200, ch);
      if (req.method === "GET" && path.startsWith("/cal/") && path.endsWith(".ics")) return await feedPublic(env, req, path.slice(5, -4));
      if (path === "/gcal/callback" && req.method === "GET") return await gcalCallback(env, req, url);
      if (path.startsWith("/p/")) return await bpPublic(env, req, path, ch, ctx);
      if (path === "/stripe/webhook" && req.method === "POST") return await stripeWebhook(env, req, ctx);
      if (path === "/bpage/pay" || path.startsWith("/bpage/pay/")) { if (!s) return json({ error: "signed out" }, 401, ch); return await payRoutes(env, req, s, path, ch); }
      if (path === "/bpage" || path.startsWith("/bpage/")) { if (!s) return json({ error: "signed out" }, 401, ch); return await bpOwner(env, req, s, path, ch, ctx); }
      if (path === "/gcal" || path.startsWith("/gcal/")) { if (!s) return json({ error: "signed out" }, 401, ch); return await gcalRoutes(env, req, s, path, ch); }
      if (path === "/ics/fetch" && req.method === "POST") { if (!s) return json({ error: "signed out" }, 401, ch); return await icsFetchRoute(env, req, s, ch); }
      if (path === "/feed" || path === "/feed/reset") { if (!s) return json({ error: "signed out" }, 401, ch); return await feedRoutes(env, req, s, path, ch); }
      if (path === "/push" || path.startsWith("/push/")) {
        if (!s) return json({ error: "signed out" }, 401, ch);
        return await pushRoutes(env, req, s, path, ch);
      }
      if (path === "/" || path === "/health") // setup check: says only whether each setting exists, never its value
        return json({ ok: true, service: "schedule-io-sync", setup: { db: !!env.DB, google: !!env.GOOGLE_CLIENT_ID, origin: !!env.APP_ORIGIN, session: !!env.SESSION_SECRET, data: !!env.DATA_KEY, push: !!globalThis.crypto?.subtle, ai: !!env.ANTHROPIC_API_KEY, gcal: !!env.GOOGLE_CLIENT_SECRET } }, 200, ch);
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
      await psInit(env); await env.DB.prepare("DELETE FROM psnaps WHERE created < ?").bind(Date.now() - PROOF_DAYS * 864e5).run();
      await fbInit(env); await env.DB.prepare("DELETE FROM feedback WHERE at < ?").bind(Date.now() - 180 * 864e5).run(); })()); } // hourly: proofs past 30 days
};
