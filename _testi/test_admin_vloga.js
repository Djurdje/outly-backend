#!/usr/bin/env node
/**
 * PATCH /admin/api/users/:id, sprememba vloge z dnevnikom admin dejanj (U3, #328, 23. 10. 2026). Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres@localhost:5432/outly" node _testi/test_admin_vloga.js
 * Vzorec kot test_finance_admin.js: lokalni JWKS (3448), backend na svojem portu (3447).
 *
 * Kaj dokazuje:
 *  1. admin spremeni vlogo z `reason` -> 200 (oblika odgovora kot prej) + natanko ena vrstica admin_dejanja: dejanje `user.role`, cilj_tip `user`,
 *     cilj_id = id, prej/potem `{ role }` (brez e-naslova), razlog, admin_user_id = admin; vloga v bazi je nova.
 *  2. sprememba brez `reason` -> vrstica z razlogom NULL; presezek (500 znakov) je v redu, 501 -> 400 in NIC se ne spremeni (ne vloga, ne vrstica).
 *  3. enaka vloga (brez spremembe), unlock in emailVerified NE pustijo vrstice user.role.
 *  4. neveljaven `reason` (ni niz) -> 400; neveljavna vloga -> 400; neobstojec uporabnik -> 404 brez vrstice; admin si ne vzame lastne vloge -> 400 brez vrstice.
 *  5. ne-admin (user, business, backup) in brez zetona: 403 / 401, vloga ostane, vrstice ni.
 *  6. sprememba vloge in vrstica sta v ISTI transakciji: ce vpis v dnevnik pade (trigger), vloga ostane stara.
 *  7. GET /admin/api/users in admin dnevnik ostaneta enake oblike (polja kot prej).
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3447, JWKS_PORT = 3448;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-1";
const jwksServer = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url.startsWith("/auth/v1/user")) { try { const t = JSON.parse(Buffer.from(String(req.headers.authorization).split(".")[1], "base64url")); return res.end(JSON.stringify({ id: t.sub, email: t.email, email_confirmed_at: "2026-01-01T00:00:00Z" })); } catch (_) { res.statusCode = 401; return res.end("{}"); } }
  if (req.url.startsWith("/auth/v1/settings")) return res.end(JSON.stringify({ mailer_autoconfirm: false, external: { anonymous_users: false } }));
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
  return { status: r.status, body: j, text: t };
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE admin_dejanja, omejitve, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, creator_applications, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  try {
    const T = {
      admin: zeton("admin@outly.si", uuid(1)),
      cilj: zeton("cilj@outly.si", uuid(2)),
      navaden: zeton("navaden@outly.si", uuid(3)),
      lastnik: zeton("lastnik@outly.si", uuid(4)),
      kopija: zeton("kopija@outly.si", uuid(5)),
    };
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    await pool.query("UPDATE users SET role='backup' WHERE email='kopija@outly.si'");
    const id = async (email) => (await pool.query("SELECT id FROM users WHERE email=$1", [email])).rows[0].id;
    const adminId = await id("admin@outly.si"), ciljId = await id("cilj@outly.si"), navadenId = await id("navaden@outly.si");
    const vloga = async (i) => (await pool.query("SELECT role FROM users WHERE id=$1", [i])).rows[0].role;
    const vrstice = async () => (await pool.query("SELECT * FROM admin_dejanja WHERE dejanje='user.role' ORDER BY id")).rows;

    console.log("\n# Sprememba vloge z razlogom");
    let r = await api("PATCH", `/admin/api/users/${ciljId}`, T.admin, { role: "business", reason: "  odobren organizator  " });
    assert(r.status === 200 && r.body.role === "business" && r.body.email === "cilj@outly.si" && r.body.id === ciljId, "admin: user -> business = 200, odgovor ima id/email/role", r.body);
    const oblika = Object.keys(r.body).sort().join();
    assert(["id", "email", "username", "role", "email_verified"].every(k => k in r.body), "odgovor ostane iste oblike (obstoječa polja uporabnika)", oblika);
    assert(await vloga(ciljId) === "business", "vloga v bazi je nova");
    let v = await vrstice();
    assert(v.length === 1, "natanko ena vrstica user.role", v.length);
    assert(v[0] && v[0].cilj_tip === "user" && v[0].cilj_id === String(ciljId) && v[0].admin_user_id === adminId, "vrstica: cilj_tip user, cilj_id = id, admin_user_id = admin", v[0]);
    assert(v[0] && JSON.stringify(v[0].prej) === '{"role":"user"}' && JSON.stringify(v[0].potem) === '{"role":"business"}', "vrstica: prej/potem = { role } (brez e-naslova)", v[0] && [v[0].prej, v[0].potem]);
    assert(v[0] && v[0].razlog === "odobren organizator", "vrstica: razlog (obrezan)", v[0] && v[0].razlog);
    assert(!JSON.stringify(v[0]).includes("@"), "vrstica ne vsebuje e-naslova");

    console.log("\n# Brez razloga, meje razloga");
    r = await api("PATCH", `/admin/api/users/${ciljId}`, T.admin, { role: "user" });
    v = await vrstice();
    assert(r.status === 200 && v.length === 2 && v[1].razlog === null && v[1].prej.role === "business" && v[1].potem.role === "user", "brez reason: 200, vrstica z razlogom NULL", v[1]);
    r = await api("PATCH", `/admin/api/users/${ciljId}`, T.admin, { role: "admin", reason: "x".repeat(500) });
    v = await vrstice();
    assert(r.status === 200 && v.length === 3 && v[2].razlog.length === 500, "reason 500 znakov = 200, shranjen cel", [r.status, v.length]);
    r = await api("PATCH", `/admin/api/users/${ciljId}`, T.admin, { role: "user", reason: "x".repeat(501) });
    assert(r.status === 400, "reason 501 znakov -> 400", r.status);
    assert(await vloga(ciljId) === "admin" && (await vrstice()).length === 3, "400 zaradi razloga: vloga in dnevnik nespremenjena");
    r = await api("PATCH", `/admin/api/users/${ciljId}`, T.admin, { role: "user", reason: 5 });
    assert(r.status === 400, "reason ni niz -> 400", r.status);
    r = await api("PATCH", `/admin/api/users/${ciljId}`, T.admin, { role: "user", reason: { a: 1 } });
    assert(r.status === 400, "reason objekt -> 400", r.status);
    // razlog je obvezen (vsaj 3 znaki po trim) za novo vlogo admin/backup in odvzem vloge admin (N1); ostale spremembe brez razloga
    const brezSpremembe = async (ime) => assert(await vloga(ciljId) === "admin" && (await vrstice()).length === 3, ime + ": vloga in dnevnik nespremenjena");
    for (const [ime, telo] of [["admin → user brez reason", { role: "user" }], ["admin → user, reason samo presledki", { role: "user", reason: "   " }], ["admin → business, reason 2 znaka", { role: "business", reason: " ab " }], ["admin → backup, reason null", { role: "backup", reason: null }]]) {
      r = await api("PATCH", `/admin/api/users/${ciljId}`, T.admin, telo);
      assert(r.status === 400 && r.body && r.body.error === "reason_required", ime + " -> 400 reason_required", [r.status, r.body]);
      await brezSpremembe(ime);
    }
    r = await api("PATCH", `/admin/api/users/${ciljId}`, T.admin, { role: "user", reason: " abc " });
    v = await vrstice();
    assert(r.status === 200 && v.length === 4 && v[3].razlog === "abc" && v[3].prej.role === "admin", "admin → user z 3 znaki razloga = 200, razlog obrezan", v[3]);
    for (const [ime, telo] of [["user → admin brez reason", { role: "admin" }], ["user → backup, reason presledki", { role: "backup", reason: "   " }], ["user → admin, reason 2 znaka", { role: "admin", reason: "ab" }]]) {
      r = await api("PATCH", `/admin/api/users/${ciljId}`, T.admin, telo);
      assert(r.status === 400 && r.body && r.body.error === "reason_required" && await vloga(ciljId) === "user" && (await vrstice()).length === 4, ime + " -> 400 reason_required, nič spremenjeno", [r.status, r.body]);
    }
    r = await api("PATCH", `/admin/api/users/${ciljId}`, T.admin, { role: "business", reason: "   " });
    v = await vrstice();
    assert(r.status === 200 && v.length === 5 && v[4].razlog === null, "user → business, reason samo presledki -> 200, razlog NULL (neobvezen)", v[4]);
    r = await api("PATCH", `/admin/api/users/${ciljId}`, T.admin, { role: "user" });
    v = await vrstice();
    assert(r.status === 200 && v.length === 6 && v[5].razlog === null, "business → user brez reason = 200", v[5]);
    r = await api("PATCH", `/admin/api/users/${adminId}`, T.admin, { role: "admin" });
    assert(r.status === 200 && (await vrstice()).length === 6, "admin → admin (brez spremembe) brez reason = 200, brez vrstice");

    console.log("\n# Brez spremembe vloge ni vrstice");
    const pred = (await vrstice()).length;
    r = await api("PATCH", `/admin/api/users/${ciljId}`, T.admin, { role: "user", reason: "enako" });
    assert(r.status === 200 && r.body.role === "user" && (await vrstice()).length === pred, "enaka vloga: 200, brez nove vrstice");
    await pool.query("UPDATE users SET failed_login_count=3, locked_until=NOW() + INTERVAL '1 hour', email_verified=false WHERE id=$1", [navadenId]);
    r = await api("PATCH", `/admin/api/users/${navadenId}`, T.admin, { unlock: true });
    assert(r.status === 200 && r.body.failed_login_count === 0 && r.body.locked_until === null, "unlock deluje kot prej", r.body);
    r = await api("PATCH", `/admin/api/users/${navadenId}`, T.admin, { emailVerified: true, reason: "ročno" });
    assert(r.status === 200 && r.body.email_verified === true, "emailVerified deluje kot prej (reason ni obvezen ne prepovedan)", r.body);
    assert((await vrstice()).length === pred, "unlock in emailVerified ne pustita vrstice user.role");

    console.log("\n# Napake");
    r = await api("PATCH", `/admin/api/users/${ciljId}`, T.admin, { role: "superadmin" });
    assert(r.status === 400, "neveljavna vloga -> 400", r.status);
    r = await api("PATCH", `/admin/api/users/999999`, T.admin, { role: "business", reason: "nima ga" });
    assert(r.status === 404, "neobstojec uporabnik -> 404", r.status);
    r = await api("PATCH", `/admin/api/users/${adminId}`, T.admin, { role: "user", reason: "sam sebi" });
    assert(r.status === 400 && await vloga(adminId) === "admin", "admin si ne vzame lastne vloge -> 400, vloga ostane", r.status);
    r = await api("PATCH", `/admin/api/users/abc`, T.admin, { role: "user" });
    assert(r.status === 400, "neveljaven id -> 400", r.status);
    r = await api("PATCH", `/admin/api/users/${ciljId}`, T.admin, {});
    assert(r.status === 400, "prazno telo -> 400", r.status);
    assert((await vrstice()).length === pred, "nobena napaka ni pustila vrstice");

    console.log("\n# Ne-admin");
    for (const [ime, t, st] of [["user", T.navaden, 403], ["business", T.lastnik, 403], ["backup", T.kopija, 403], ["brez zetona", null, 401]]) {
      r = await api("PATCH", `/admin/api/users/${ciljId}`, t, { role: "admin", reason: "poskus" });
      assert(r.status === st, `${ime}: PATCH vloge -> ${st}`, r.status);
    }
    assert(await vloga(ciljId) === "user" && (await vrstice()).length === pred, "ne-admin: vloga ostane, vrstice ni");

    console.log("\n# Ista transakcija");
    await pool.query(`CREATE OR REPLACE FUNCTION test_pad_dnevnika() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'dnevnik pade'; END $$`);
    await pool.query("CREATE TRIGGER test_pad_dnevnika BEFORE INSERT ON admin_dejanja FOR EACH ROW EXECUTE FUNCTION test_pad_dnevnika()");
    r = await api("PATCH", `/admin/api/users/${ciljId}`, T.admin, { role: "business", reason: "mora propasti" });
    assert(r.status === 500, "padel vpis v dnevnik -> 500", r.status);
    assert(await vloga(ciljId) === "user", "vloga ostane stara (UPDATE in dnevnik v isti transakciji)");
    await pool.query("DROP TRIGGER test_pad_dnevnika ON admin_dejanja");
    await pool.query("DROP FUNCTION test_pad_dnevnika()");
    r = await api("PATCH", `/admin/api/users/${ciljId}`, T.admin, { role: "business", reason: "zdaj gre" });
    assert(r.status === 200 && await vloga(ciljId) === "business" && (await vrstice()).length === pred + 1, "po popravku trigerja spet dela");

    console.log("\n# Branje ostane enako");
    r = await api("GET", "/admin/api/users?q=cilj", T.admin);
    assert(r.status === 200 && Array.isArray(r.body) && r.body.length === 1 && r.body[0].role === "business" && "club_count" in r.body[0], "GET /admin/api/users: seznam z club_count", r.body);
    r = await api("GET", `/admin/api/events`, T.admin);
    assert(r.status === 200, "GET /admin/api/events nespremenjen", r.status);
  } finally {
    console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
    const napake = log.split("\n").filter(l => /TypeError|Unhandled/i.test(l));
    if (napake.length) console.log("\nLog backenda (sumljivo):\n" + napake.join("\n"));
    srv.kill(); jwksServer.close(); await pool.end().catch(() => {});
  }
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
