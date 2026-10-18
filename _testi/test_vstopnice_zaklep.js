#!/usr/bin/env node
/**
 * Test: SEZNAM VSTOPNIC PRI ZAKLEPU TABELE (#277 N1, 503 search_timeout, I45). Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_vstopnice_zaklep.js
 * Vzorec kot test_vstopnice_seznam.js: lokalni JWKS (5786), backend na svojem portu (5785) s PG_POOL_MAX=1 (ena povezava glavnega poola),
 * TRUNCATE na zacetku. Druga seja drzi LOCK TABLE tickets IN ACCESS EXCLUSIVE MODE (kot migracija ob deployu).
 * Test caka na POGOJ (zahtevek ceka na zaklep v pg_stat_activity; zahtevek je pri zaklepu starejsi od 3,5 s po uri BAZE), ne na stensko uro;
 * meja 3 s (SET LOCAL statement_timeout) je v kodi, test meri samo izid.
 *  1  ovojnica ob zaklepu: 503 { error: "search_timeout", message } z Retry-After; sporocilo je nevtralno (brez »shorter search«, ker q lahko manjka)
 *  2  povezava je vrnjena (PG_POOL_MAX=1): po sprostitvi zaklepa ovojnica spet 200; po 503 ni seje »idle in transaction«
 *  3  SET LOCAL ne uide: golo polje (brez ovojnice) na ISTI povezavi cez 3 s cakanja na zaklep NE dobi 57014 in uspe (200)
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Client } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 5785, JWKS_PORT = 5786;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-vstopnice-zaklep";
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
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
const cakaj = (ms) => new Promise(r => setTimeout(r, ms));
async function pocakaj(pogoj, ms = 30000) {   // ms je samo zgornja meja za primer napake
  const konec = Date.now() + ms;
  while (Date.now() < konec) { if (await pogoj()) return true; await cakaj(50); }
  return false;
}
async function api(p, token) {
  const r = await fetch(BASE + p, { headers: { authorization: "Bearer " + token } });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, retryAfter: r.headers.get("retry-after") };
}

let srv = null;
(async () => {
  const q = new Client({ connectionString: DB }), L = new Client({ connectionString: DB });
  await q.connect(); await L.connect();
  await q.query("TRUNCATE omejitve, guest_list_members, guest_lists, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), PG_POOL_MAX: "1", SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await cakaj(100); } }
  let drziZaklep = false;
  try {
    const T = zeton("lastnik@outly.si", "00000000-0000-4000-8000-000000000001");
    let r = await api("/me", T);
    assert(r.status === 200, "GET /me", r.body);
    await q.query("UPDATE users SET role='business'");
    await q.query("INSERT INTO clubs (owner_user_id, name, city) VALUES (1, 'Pure Club', 'Ljubljana')");
    const ev = (await q.query("INSERT INTO events (club_id, title, start_at, ticket_price_cents) VALUES (1, 'E', NOW() + interval '1 day', 1000) RETURNING id")).rows[0].id;
    await q.query(`INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, paid_at)
                   SELECT 'R' || lpad(g::text, 5, '0'), 1, $1, 1, 1, 1000, 1000, 'paid', 'a@b.si', NOW() FROM generate_series(1, 5) g`, [ev]);
    await q.query("INSERT INTO tickets (order_id, event_id) SELECT id, event_id FROM orders");
    const lastni = [(await q.query("SELECT pg_backend_pid() AS p")).rows[0].p, (await L.query("SELECT pg_backend_pid() AS p")).rows[0].p];
    const zahtevekCaka = async (starejsiOdSekund = 0) => (await q.query(
      `SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND pid <> ALL($1::int[]) AND wait_event_type = 'Lock'
         AND query LIKE '%t.order_id, t.event_id%' AND now() - query_start > make_interval(secs => $2::float8)`, [lastni, starejsiOdSekund])).rows[0].n > 0;

    r = await api(`/business/events/${ev}/tickets?limit=10`, T);
    assert(r.status === 200 && r.body.tickets.length === 5, "osnova (brez zaklepa): ovojnica 200", r.status);

    console.log("\n# 1. Ovojnica ob zaklepu tabele: 503 search_timeout");
    await L.query("BEGIN; LOCK TABLE tickets IN ACCESS EXCLUSIVE MODE"); drziZaklep = true;
    r = await api(`/business/events/${ev}/tickets?limit=10`, T);   // vrne sele po meji v kodi (3 s)
    assert(r.status === 503 && r.body && r.body.error === "search_timeout" && typeof r.body.message === "string", "503 { error: search_timeout, message }", r);
    assert(r.retryAfter === "5", "Retry-After: 5", r.retryAfter);
    assert(!/shorter search/i.test(r.body.message) && !/\bq\b/.test(r.body.message), "sporocilo je nevtralno (klic brez q ne dobi namiga o iskanju)", r.body.message);
    r = await api(`/business/events/${ev}/tickets?limit=10&q=R0`, T);
    assert(r.status === 503 && r.body.error === "search_timeout", "isto z q", r.status);

    console.log("\n# 2. Povezava je vrnjena (PG_POOL_MAX=1)");
    const viseca = (await q.query(`SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND pid <> ALL($1::int[]) AND state LIKE 'idle in transaction%'`, [lastni])).rows[0].n;
    assert(viseca === 0, "po 503 ni seje »idle in transaction«", viseca);
    await L.query("COMMIT"); drziZaklep = false;
    r = await api(`/business/events/${ev}/tickets?limit=10`, T);
    assert(r.status === 200 && r.body.counts.all === 5, "po sprostitvi zaklepa ovojnica spet 200 (edina povezava poola je prosta)", r.status);
    r = await api(`/business/events/${ev}/tickets?limit=10&q=R0`, T);
    assert(r.status === 200 && r.body.total === 5, "isto z q", r.status);

    console.log("\n# 3. SET LOCAL ne uide: golo polje na isti povezavi ne dobi 57014");
    await L.query("BEGIN; LOCK TABLE tickets IN ACCESS EXCLUSIVE MODE"); drziZaklep = true;
    const golo = api(`/business/events/${ev}/tickets`, T);
    // zaklep sprostimo, ko zahtevek po uri baze ze vec kot 3,5 s caka (cez mejo 3 s ovojnice); brez statement_timeout mora golo polje uspeti
    const dolgo = await pocakaj(() => zahtevekCaka(3.5));
    assert(dolgo, "golo polje caka na zaklep dlje od 3,5 s (ni prekinjeno z 57014)");
    await L.query("COMMIT"); drziZaklep = false;
    r = await golo;
    assert(r.status === 200 && Array.isArray(r.body) && r.body.length === 5, "golo polje po sprostitvi zaklepa: 200 in 5 vrstic (brez statement_timeout)", { status: r.status, body: r.body });
    assert(!/57014|statement timeout/i.test(log.split("\n").slice(-30).join("\n").replace(/iskanje je preseglo statement_timeout/g, "")), "dnevnik: brez 57014 pri golem polju");
  } catch (e) {
    fail++; console.error("NAPAKA TESTA:", e);
  } finally {
    if (drziZaklep) await L.query("ROLLBACK").catch(() => {});
    srv.kill(); jwksServer.close(); await q.end(); await L.end();
    if (fail) console.log("\n--- dnevnik streznika ---\n" + log.split("\n").slice(-40).join("\n"));
    console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
    process.exit(fail ? 1 : 0);
  }
})();
