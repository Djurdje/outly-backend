#!/usr/bin/env node
/**
 * Naslov dogodka najvec 200 znakov (Martin 23. 10. 2026; pregled #330 K1: 95 000-znakovni naslov). Meja `NASLOV_NAJVEC` v index.js,
 * steje se po trim() v Unicode znakih ([...s].length; emoji = 1 znak, ne 2 enoti UTF-16).
 * Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_naslov_dogodka.js
 * Vzorec kot test_admin_podvoji.js: lokalni JWKS, backend na svojem portu, TRUNCATE na zacetku.
 *
 *  N1  POST /events (lastnik): 200 znakov 201; 201 -> 400 (golo besedilo, kot ostale napake te poti); 200 emojijev 201; 201 emojijev 400;
 *      presledki okrog se ne stejejo (shranjen naslov ostane, kot je bil poslan — kot doslej)
 *  N2  POST /admin/api/events (admin): 201 -> 400, 200 -> 201
 *  N3  PATCH /events/:id na obstojecem dogodku s 300-znakovnim naslovom (vstavljen s SQL): brez title 200 in naslov nespremenjen (tudi v GET);
 *      isti (nespremenjen) 300-znakovni naslov v telesu 200 (obrazca iOS/splet posljeta vsa polja); nov 300-znakovni 400 in nic spremenjeno; 200 emojijev 200
 *  N4  PATCH /events/:id kot admin (urejevalnik panela): 201 -> 400
 *  N5  POST /admin/api/events/:id/duplicate: 200-znakovni naslov se kopira nespremenjen; star 300-znakovni (emojiji) se v kopiji obreze na 200 znakov
 *      brez razpolovljenega emojija; izvor ostane
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 6271, JWKS_PORT = 6272;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-naslov";
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
const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra).slice(0, 300) : ""); } }
async function api(method, path, token, telo) {
  const r = await fetch(BASE + path, { method, headers: { ...(token ? { authorization: "Bearer " + token } : {}), ...(telo !== undefined ? { "content-type": "application/json" } : {}) },
    body: telo === undefined ? undefined : JSON.stringify(telo) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, text: t };
}
const znakov = (s) => [...s].length;
const EMOJI = "\u{1F600}";   // 2 enoti UTF-16, 1 znak

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE admin_dejanja, omejitve, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, club_tables, events, clubs, creator_applications, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test",
    STRIPE_SECRET_KEY: "", TEST_PLACILA: "", ADMIN_NADZOR_PREDPOMNILNIK_MS: "0" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  try {
    const T = { admin: zeton("admin@outly.si", uuid(1)), lastnik: zeton("lastnik@outly.si", uuid(2)) };
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    const lastnikId = (await pool.query("SELECT id FROM users WHERE email='lastnik@outly.si'")).rows[0].id;
    const K = (await pool.query("INSERT INTO clubs (owner_user_id, name) VALUES ($1, 'Klub Naslov') RETURNING id", [lastnikId])).rows[0].id;
    const zac = new Date(Date.now() + 10 * 864e5).toISOString();
    const naslovV = async (id) => (await pool.query("SELECT title FROM events WHERE id = $1", [id])).rows[0].title;
    const steviloDogodkov = async () => Number((await pool.query("SELECT count(*)::int AS n FROM events")).rows[0].n);

    console.log("N1 POST /events");
    let x = await api("POST", "/events", T.lastnik, { clubId: K, title: "a".repeat(200), startAt: zac, status: "draft" });
    assert(x.status === 201, "200 znakov: 201", x.body);
    let pred = await steviloDogodkov();
    x = await api("POST", "/events", T.lastnik, { clubId: K, title: "a".repeat(201), startAt: zac, status: "draft" });
    assert(x.status === 400, "201 znakov: 400", x.status);
    assert(typeof x.body === "string" && /Title is too long \(max 200 characters\)/.test(x.text), "sporocilo: golo besedilo »Title is too long (max 200 characters).«", x.text);
    assert((await steviloDogodkov()) === pred, "201 znakov: nic ustvarjeno");
    x = await api("POST", "/events", T.lastnik, { clubId: K, title: EMOJI.repeat(200), startAt: zac, status: "draft" });
    assert(x.status === 201, "200 emojijev (400 enot UTF-16): 201", x.body);
    x = await api("POST", "/events", T.lastnik, { clubId: K, title: EMOJI.repeat(201), startAt: zac, status: "draft" });
    assert(x.status === 400, "201 emojijev: 400", x.status);
    const sPresledki = "   " + "b".repeat(200) + " \n\t ";
    x = await api("POST", "/events", T.lastnik, { clubId: K, title: sPresledki, startAt: zac, status: "draft" });
    assert(x.status === 201, "200 znakov + presledki okrog: 201 (presledki se ne stejejo)", x.body);
    x = await api("POST", "/events", T.lastnik, { clubId: K, title: " " + "b".repeat(201) + " ", startAt: zac, status: "draft" });
    assert(x.status === 400, "201 znakov + presledki okrog: 400", x.status);
    x = await api("POST", "/events", T.lastnik, { clubId: K, title: "a".repeat(95000), startAt: zac, status: "draft" });
    assert(x.status === 400, "95 000 znakov (#330 K1): 400", x.status);

    console.log("N2 POST /admin/api/events");
    pred = await steviloDogodkov();
    x = await api("POST", "/admin/api/events", T.admin, { clubId: K, title: "c".repeat(201), startAt: zac });
    assert(x.status === 400 && /Title is too long/.test(x.text), "admin 201 znakov: 400", { s: x.status, t: x.text });
    assert((await steviloDogodkov()) === pred, "admin 201: nic ustvarjeno");
    x = await api("POST", "/admin/api/events", T.admin, { clubId: K, title: "c".repeat(200), startAt: zac });
    assert(x.status === 201, "admin 200 znakov: 201", x.body);

    console.log("N3 PATCH /events/:id na obstojecem dolgem naslovu");
    const dolg = "S".repeat(300);
    const staro = (await pool.query("INSERT INTO events (club_id, title, start_at, status) VALUES ($1, $2, $3, 'published') RETURNING id", [K, dolg, zac])).rows[0].id;
    x = await api("PATCH", `/events/${staro}`, T.lastnik, { description: "nov opis" });
    assert(x.status === 200, "PATCH brez title na 300-znakovnem naslovu: 200", x.body);
    assert((await naslovV(staro)) === dolg, "naslov nespremenjen (300 znakov)");
    x = await api("GET", `/events/${staro}`);
    assert(x.status === 200 && x.body.title === dolg, "GET /events/:id vrne 300-znakovni naslov nespremenjen", x.status);
    x = await api("PATCH", `/events/${staro}`, T.lastnik, { title: dolg, description: "se en opis" });
    assert(x.status === 200, "PATCH z nespremenjenim 300-znakovnim naslovom (obrazec poslje vsa polja): 200", x.body);
    x = await api("PATCH", `/events/${staro}`, T.lastnik, { title: "N".repeat(300), description: "ne sme" });
    assert(x.status === 400 && /Title is too long/.test(x.text), "PATCH z novim 300-znakovnim naslovom: 400", { s: x.status, t: x.text });
    assert((await naslovV(staro)) === dolg, "po 400 naslov nespremenjen");
    assert((await pool.query("SELECT description FROM events WHERE id = $1", [staro])).rows[0].description === "se en opis", "po 400 tudi opis nespremenjen");
    x = await api("PATCH", `/events/${staro}`, T.lastnik, { title: "  " + EMOJI.repeat(200) + "  " });
    assert(x.status === 200, "PATCH 200 emojijev s presledki: 200", x.body);
    x = await api("PATCH", `/events/${staro}`, T.lastnik, { title: "d".repeat(201) });
    assert(x.status === 400, "PATCH 201 znakov: 400", x.status);

    console.log("N4 PATCH /events/:id kot admin");
    x = await api("PATCH", `/events/${staro}`, T.admin, { title: "e".repeat(201) });
    assert(x.status === 400 && /Title is too long/.test(x.text), "admin PATCH 201 znakov: 400", { s: x.status, t: x.text });
    x = await api("PATCH", `/events/${staro}`, T.admin, { title: "e".repeat(200) });
    assert(x.status === 200, "admin PATCH 200 znakov: 200", x.body);

    console.log("N5 POST /admin/api/events/:id/duplicate");
    const t200 = "f".repeat(200);
    const iz200 = (await pool.query("INSERT INTO events (club_id, title, start_at, status) VALUES ($1, $2, $3, 'published') RETURNING id", [K, t200, zac])).rows[0].id;
    const novZac = new Date(Date.now() + 20 * 864e5).toISOString();
    x = await api("POST", `/admin/api/events/${iz200}/duplicate`, T.admin, { startAt: novZac });
    assert(x.status === 201 && x.body.events && x.body.events.length === 1, "podvajanje 200-znakovnega naslova: 201", x.body);
    if (x.status === 201) assert((await naslovV(x.body.events[0].id)) === t200, "kopija ima isti 200-znakovni naslov");
    const dolgEmoji = EMOJI.repeat(300);
    const iz300 = (await pool.query("INSERT INTO events (club_id, title, start_at, status) VALUES ($1, $2, $3, 'published') RETURNING id", [K, dolgEmoji, zac])).rows[0].id;
    x = await api("POST", `/admin/api/events/${iz300}/duplicate`, T.admin, { startAt: novZac, ponovi: "weekly", n: 2 });
    assert(x.status === 201 && x.body.events && x.body.events.length === 2, "podvajanje starega 300-znakovnega naslova: 201 (ne pade)", x.body);
    if (x.status === 201) {
      for (const e of x.body.events) {
        const t = await naslovV(e.id);
        assert(znakov(t) === 200 && t === EMOJI.repeat(200), `kopija #${e.id}: naslov obrezan na 200 znakov, emoji cel`, { znakov: znakov(t), enot: t.length });
      }
    }
    assert((await naslovV(iz300)) === dolgEmoji, "izvor obdrzi 300-znakovni naslov");
  } catch (e) {
    fail++; console.log("  ✗ izjema", e && e.stack);
  } finally {
    srv.kill(); jwksServer.close(); await pool.end();
  }
  if (fail) console.log(log.slice(-3000));
  console.log(`\n${ok} ok, ${fail} napak`);
  process.exit(fail ? 1 : 0);
})();
