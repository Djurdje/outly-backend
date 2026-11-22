#!/usr/bin/env node
/**
 * Samodejno sledenje uradnemu profilu Outly (DECISIONS 2026-11-22; migracija 077).
 *  - NOV uporabnik (vrstica v `users` nastane ob prvem klicu z Supabasovim zetonom) sledi vsem klubom z is_official = TRUE,
 *    ki niso skriti in niso demo; samo ob nastanku (kdor odsledi, ga ne prijavi nic znova);
 *  - napaka pri sledenju ne podre prvega klica; brez uradnega kluba prvi klic dela;
 *  - migracija 077 doda sledenje obstojecim racunom, brez obvestil; ponovni zagon ne naredi nic.
 * Zagon: DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_samodejno_sledenje.js
 * Vzorec kot test_vabila.js: lokalni JWKS (6460), backend na 6461.
 */
const crypto = require("crypto");
const http = require("http");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 6461, JWKS_PORT = 6460;
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
async function api(method, path_, token, body) {
  const r = await fetch(BASE + path_, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, club_event_notifications, club_follows, club_invites, club_members, event_favorites, friendships, friend_requests, ticket_transfers, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }
  const stSledenj = async (email) => (await pool.query("SELECT COUNT(*)::int AS n FROM club_follows f JOIN users u ON u.id=f.user_id WHERE u.email=$1", [email])).rows[0].n;
  const stSledilcev = async (id) => (await pool.query("SELECT COUNT(*)::int AS n FROM club_follows WHERE club_id=$1", [id])).rows[0].n;

  try {
    console.log("\n# Brez uradnega kluba prvi klic dela");
    const T = {};
    T.lastnik = zeton("lastnik@outly.si", uuid(1));
    let r = await api("GET", "/me", T.lastnik);
    assert(r.status === 200, "prvi klic brez uradnega kluba -> 200", r.body);
    assert((await stSledenj("lastnik@outly.si")) === 0, "brez uradnega kluba ni vrstic club_follows");

    // klubi: 1 uradni, 2 navaden, 3 uradni skrit, 4 uradni demo
    const idLastnik = (await pool.query("SELECT id FROM users WHERE email='lastnik@outly.si'")).rows[0].id;
    await pool.query("UPDATE users SET role='business' WHERE id=$1", [idLastnik]);
    await pool.query(`INSERT INTO clubs (owner_user_id, name, city, is_official, hidden, is_demo) VALUES
      ($1, 'Outly', 'Ljubljana', TRUE, FALSE, FALSE),
      ($1, 'Navaden klub', 'Ljubljana', FALSE, FALSE, FALSE),
      ($1, 'Skriti uradni', 'Maribor', TRUE, TRUE, FALSE),
      ($1, 'Demo uradni', 'Maribor', TRUE, FALSE, TRUE)`, [idLastnik]);

    console.log("\n# Novi racun sledi uradnemu profilu");
    T.ana = zeton("ana@outly.si", uuid(2));
    r = await api("GET", "/me", T.ana);
    assert(r.status === 200, "prvi klic nove uporabnice -> 200", r.body);
    r = await api("GET", "/clubs/1", T.ana);
    assert(r.status === 200 && r.body.is_following === true, "ana sledi uradnemu klubu (is_following)", r.body.is_following);
    assert((await stSledilcev(1)) === 1, "uradni klub ima 1 sledilca (ana)");
    r = await api("GET", "/clubs/2", T.ana);
    assert(r.body.is_following === false, "navadnemu klubu ne sledi", r.body.is_following);
    assert((await stSledilcev(3)) === 0 && (await stSledilcev(4)) === 0, "skritemu in demo uradnemu klubu ne sledi");
    r = await api("GET", "/me/clubs/following", T.ana);
    assert(r.status === 200 && r.body.ids.length === 1 && r.body.ids[0] === 1, "GET /me/clubs/following = samo uradni klub", r.body);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM club_event_notifications")).rows[0].n === 0, "sledenje ne ustvari obvestil");

    console.log("\n# Odsledenje velja (ne ob prijavi, ne ob GET /me)");
    r = await api("DELETE", "/clubs/1/follow", T.ana);
    assert(r.status === 200 && r.body.following === false, "unfollow -> 200", r.body);
    await api("GET", "/me", T.ana);
    const T2 = zeton("ana@outly.si", uuid(2));   // nova prijava, isti racun
    r = await api("GET", "/me", T2);
    assert(r.status === 200, "ponovna prijava -> 200", r.body);
    r = await api("GET", "/clubs/1", T2);
    assert(r.body.is_following === false, "po unfollow in ponovni prijavi ne sledi vec", r.body.is_following);
    assert((await stSledilcev(1)) === 0, "uradni klub ima 0 sledilcev");

    console.log("\n# Napaka pri sledenju ne podre prvega klica");
    await pool.query("ALTER TABLE club_follows RENAME TO club_follows_x");
    try {
      T.bor = zeton("bor@outly.si", uuid(3));
      r = await api("GET", "/me", T.bor);
      assert(r.status === 200 && r.body.email === "bor@outly.si", "prvi klic ob pokvarjenem sledenju -> 200", r);
      assert((await pool.query("SELECT COUNT(*)::int AS n FROM users WHERE email='bor@outly.si'")).rows[0].n === 1, "uporabnik je nastal");
    } finally {
      await pool.query("ALTER TABLE club_follows_x RENAME TO club_follows");
    }
    assert(/\[sledenje\]|samodejno sledenje/i.test(log), "napaka je zabelezena (console.error)");
    r = await api("GET", "/me", T.bor);
    assert(r.status === 200, "naslednji klic dela", r.body);
    assert((await stSledenj("bor@outly.si")) === 0, "bor ni (vec) prijavljen samodejno: samo ob nastanku");

    console.log("\n# Migracija 077 za obstojece racune");
    const sql = fs.readFileSync(path.join(__dirname, "..", "db", "migracije", "077_sledenje_uradnemu_profilu.sql"), "utf8");
    await pool.query("INSERT INTO users (email, username, email_verified) VALUES ('stari1@outly.si','stari1',true), ('stari2@outly.si','stari2',true)");
    await pool.query("INSERT INTO club_event_notifications (user_id, event_id) SELECT 1, 1 WHERE FALSE");
    const pred = (await pool.query("SELECT COUNT(*)::int AS n FROM club_follows")).rows[0].n;
    const nUsers = (await pool.query("SELECT COUNT(*)::int AS n FROM users")).rows[0].n;
    await pool.query(sql);
    const po = (await pool.query("SELECT COUNT(*)::int AS n FROM club_follows WHERE club_id=1")).rows[0].n;
    assert(po === nUsers, `vsi racuni (${nUsers}) sledijo uradnemu klubu`, po);
    assert((await stSledilcev(2)) === 0 && (await stSledilcev(3)) === 0 && (await stSledilcev(4)) === 0, "migracija ne dodaja navadnemu, skritemu, demo");
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM club_event_notifications")).rows[0].n === 0, "migracija ne ustvari obvestil");
    const zdaj = (await pool.query("SELECT COUNT(*)::int AS n FROM club_follows")).rows[0].n;
    await pool.query(sql);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM club_follows")).rows[0].n === zdaj, "ponovni zagon migracije ne naredi nic");
    assert(pred === 0, "pred migracijo je bil club_follows prazen", pred);

    console.log("\n# Migracija brez uradnega kluba uspe");
    await pool.query("UPDATE clubs SET is_official = FALSE");
    await pool.query("TRUNCATE club_follows");
    await pool.query(sql);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM club_follows")).rows[0].n === 0, "brez uradnega kluba migracija ne naredi nic");
  } finally {
    srv.kill();
    jwksServer.close();
    await pool.end();
  }
  console.log(`\n${ok} ok, ${fail} napak`);
  if (fail) { console.log(log.split("\n").slice(-20).join("\n")); process.exit(1); }
})().catch((e) => { console.error(e); process.exit(1); });
