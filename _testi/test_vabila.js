#!/usr/bin/env node
/**
 * Test vabil v ekipo (migracija 013). Zagon (lokalno, PG16 na 5433, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres@localhost:5433/outly?host=/tmp/pg" node _testi/test_vabila.js
 *
 * Skripta sama dvigne lokalni JWKS streznik (port 3999), podpise ES256 zetone
 * in zazene backend na portu 3112 s SUPABASE_URL=http://127.0.0.1:3999.
 * Resend ni nastavljen (RESEND_API_KEY prazen) -> maili se ne posiljajo.
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3112, JWKS_PORT = 3999;
const BASE = `http://127.0.0.1:${PORT}`;

// --- kljuc + JWKS ---
const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-1";
const jwksServer = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify({ keys: [{ ...jwk, kid: KID, alg: "ES256", use: "sig" }] }));
});

function b64u(o) { return Buffer.from(typeof o === "string" ? o : JSON.stringify(o)).toString("base64url"); }
function zeton(email, sub) {
  const now = Math.floor(Date.now() / 1000);
  const h = b64u({ alg: "ES256", typ: "JWT", kid: KID });
  const p = b64u({ iss: `http://127.0.0.1:${JWKS_PORT}/auth/v1`, aud: "authenticated", sub, email, exp: now + 3600, iat: now,
    user_metadata: { email_verified: true, username: email.split("@")[0].replace(/[^a-z0-9_]/gi, "") } });
  const sig = crypto.sign("sha256", Buffer.from(h + "." + p), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return h + "." + p + "." + sig.toString("base64url");
}
function uuid(n) { return `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`; }

let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }

async function api(method, path, token, body) {
  const r = await fetch(BASE + path, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  // cista miza
  await pool.query("TRUNCATE club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");

  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  const T = {
    lastnik: zeton("lastnik@outly.si", uuid(1)),
    ana: zeton("ana@outly.si", uuid(2)),
    bor: zeton("bor@outly.si", uuid(3)),
    drugi: zeton("drugi@outly.si", uuid(4)),
  };
  // Prvi klic ustvari lokalne vrstice.
  for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
  const me = await api("GET", "/me", T.ana);
  assert(me.body.pending_invites === 0, "/me vraca pending_invites = 0", me.body.pending_invites);

  // Lastnik: role business + klub. Drugi: lastnik drugega kluba.
  await pool.query("UPDATE users SET role='business' WHERE email IN ('lastnik@outly.si','drugi@outly.si')");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana')");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='drugi@outly.si'), 'Drugi Klub', 'Maribor')");

  console.log("\n# Vabilo");
  let r = await api("POST", "/business/team", T.lastnik, { email: "ana@outly.si", role: "manager" });
  assert(r.status === 201, "POST /business/team -> 201 (vabilo)", r.body);
  assert(Array.isArray(r.body.invites) && r.body.invites.length === 1 && r.body.invites[0].role === "manager", "odgovor vsebuje invites[1] manager", r.body.invites);
  assert(r.body.members.length === 1 && r.body.members[0].role === "owner", "members se samo lastnik (clan NI dodan neposredno)", r.body.members);
  const inviteId = r.body.invites[0].id;

  r = await api("POST", "/business/team", T.lastnik, { email: "ana@outly.si", role: "doorman" });
  assert(r.status === 409 && r.body.error === "already_invited", "drugo vabilo istemu -> 409 already_invited", r.body);
  r = await api("POST", "/business/team", T.lastnik, { email: "drugi@outly.si", role: "doorman" });
  assert(r.status === 409 && r.body.error === "is_owner", "lastnik drugega kluba -> 409 is_owner", r.body);
  r = await api("POST", "/business/team", T.lastnik, { email: "nihce@outly.si", role: "doorman" });
  assert(r.status === 404 && r.body.error === "no_account", "brez racuna -> 404 no_account", r.body);
  r = await api("POST", "/business/team", T.ana, { email: "bor@outly.si", role: "doorman" });
  assert(r.status === 403, "ana (se ni clanica) ne more vabiti -> 403", r.status);

  console.log("\n# Uporabnik vidi vabilo");
  r = await api("GET", "/me", T.ana);
  assert(r.body.pending_invites === 1 && r.body.club_role === null, "/me: pending_invites=1, club_role null", r.body);
  r = await api("GET", "/me/invites", T.ana);
  assert(r.status === 200 && r.body.invites.length === 1 && r.body.invites[0].club_name === "Pure Club" && r.body.invites[0].invited_by_username, "GET /me/invites: Pure Club, manager, vabitelj", r.body);
  r = await api("GET", "/me/invites", T.bor);
  assert(r.body.invites.length === 0, "bor nima vabil");

  console.log("\n# Tuje vabilo");
  r = await api("POST", `/me/invites/${inviteId}/accept`, T.bor);
  assert(r.status === 404, "bor ne more sprejeti Aninega vabila -> 404", r.status);
  r = await api("POST", `/me/invites/${inviteId}/decline`, T.bor);
  assert(r.status === 404, "bor ne more zavrniti Aninega vabila -> 404", r.status);

  console.log("\n# Vabilo drugega kluba + sprejem");
  r = await api("POST", "/business/team", T.drugi, { email: "ana@outly.si", role: "doorman" });
  assert(r.status === 201, "drugi klub povabi Ano kot vratarko", r.status);
  const invite2 = r.body.invites[0].id;
  r = await api("GET", "/me", T.ana);
  assert(r.body.pending_invites === 2, "/me: pending_invites=2", r.body.pending_invites);

  r = await api("POST", `/me/invites/${inviteId}/accept`, T.ana);
  assert(r.status === 200 && r.body.club && r.body.club.name === "Pure Club" && r.body.role === "manager", "accept -> klub Pure Club, vloga manager", r.body);
  r = await api("GET", "/me", T.ana);
  assert(r.body.club_role === "manager" && r.body.pending_invites === 0, "/me: club_role manager, pending_invites 0 (drugo vabilo zavrnjeno)", r.body);
  const st = await pool.query("SELECT id, status FROM club_invites ORDER BY id");
  assert(st.rows[0].status === "accepted" && st.rows[1].status === "declined", "statusa: accepted, declined", st.rows);
  r = await api("POST", `/me/invites/${inviteId}/accept`, T.ana);
  assert(r.status === 404, "ponovni accept -> 404", r.status);
  r = await api("POST", `/me/invites/${invite2}/accept`, T.ana);
  assert(r.status === 404, "accept ze zavrnjenega -> 404", r.status);

  r = await api("GET", "/business/team", T.lastnik);
  assert(r.body.members.length === 2 && r.body.members[1].role === "manager" && r.body.invites.length === 0, "ekipa: lastnik + manager, brez cakajocih", r.body);

  console.log("\n# Manager vabi vratarja, preklic");
  r = await api("POST", "/business/team", T.ana, { email: "bor@outly.si", role: "manager" });
  assert(r.status === 403, "manager ne sme vabiti managerja -> 403", r.status);
  r = await api("POST", "/business/team", T.ana, { email: "bor@outly.si", role: "doorman" });
  assert(r.status === 201 && r.body.invites.length === 1, "manager povabi vratarja -> 201", r.body);
  const invite3 = r.body.invites[0].id;
  r = await api("DELETE", `/business/team/invites/${invite3}`, T.ana);
  assert(r.status === 200 && r.body.invites.length === 0, "manager preklice vabilo vratarju -> 200, invites []", r.body);
  r = await api("GET", "/me/invites", T.bor);
  assert(r.body.invites.length === 0, "bor po preklicu nima vabil");
  r = await api("DELETE", `/business/team/invites/${invite3}`, T.ana);
  assert(r.status === 404, "preklic ze preklicanega -> 404", r.status);

  console.log("\n# Zavrnitev");
  r = await api("POST", "/business/team", T.lastnik, { email: "bor@outly.si", role: "doorman" });
  const invite4 = r.body.invites[0].id;
  r = await api("POST", `/me/invites/${invite4}/decline`, T.bor);
  assert(r.status === 200 && r.body.invites.length === 0, "bor zavrne -> 200, invites []", r.body);
  r = await api("GET", "/business/team", T.lastnik);
  assert(r.body.invites.length === 0 && r.body.members.length === 2, "po zavrnitvi: brez cakajocih, 2 clana", r.body);
  r = await api("POST", "/business/team", T.lastnik, { email: "bor@outly.si", role: "doorman" });
  assert(r.status === 201, "po zavrnitvi ga lahko povabi znova -> 201", r.status);

  console.log("\n# Clan ne more sprejeti se enega vabila; lastnik ne more");
  r = await api("POST", "/business/team", T.drugi, { email: "ana@outly.si", role: "doorman" });
  assert(r.status === 409 && r.body.error === "already_member", "Ana je ze clanica -> 409 already_member", r.body);
  r = await api("POST", "/business/team", T.drugi, { email: "lastnik@outly.si", role: "doorman" });
  assert(r.status === 409 && r.body.error === "is_owner", "lastnika ne more povabiti -> 409 is_owner", r.body);

  console.log("\n# Odstranitev clana in /me/invites brez zetona");
  const anaId = (await pool.query("SELECT id FROM users WHERE email='ana@outly.si'")).rows[0].id;
  r = await api("DELETE", `/business/team/${anaId}`, T.lastnik);
  assert(r.status === 200 && r.body.members.length === 1 && Array.isArray(r.body.invites), "DELETE clana vrne members + invites", r.body);
  r = await api("GET", "/me/invites");
  assert(r.status === 401, "GET /me/invites brez zetona -> 401", r.status);
  r = await api("POST", "/me/invites/abc/accept", T.ana);
  assert(r.status === 400, "accept z neveljavnim id -> 400", r.status);

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  if (/error|Error/.test(log) && !/Resend/.test(log)) { console.log("\n--- log streznika ---\n" + log); }
  srv.kill(); jwksServer.close(); await pool.end();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
