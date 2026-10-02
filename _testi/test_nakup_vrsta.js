#!/usr/bin/env node
/**
 * Vrsta nakupov (issue #89): semafor v POST /events/:id/orders (index.js: nakupDovoljenje / nakupVstopi / nakupIzstopi).
 * Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL=postgres://postgres:postgres@localhost:5432/outly node _testi/test_nakup_vrsta.js
 *
 * Nakup "obesimo" tako, da test sam drzi zaklep vrstice dogodka (SELECT ... FOR UPDATE v lastni transakciji):
 * sprozilec orders_rezerviraj ob INSERT-u caka na isti zaklep, nakup pa med tem drzi dovoljenje in povezavo.
 * Vsak scenarij dvigne svoj backend z nizkimi mejami iz okolja (NAKUP_VZPOREDNO, NAKUP_CAKANJE_MS, PG_POOL_MAX ...):
 *   S1  vrsta: 503 Retry-After po izteku cakanja; odjemalec, ki odide med cakanjem, NE kupi (duh); sprostitev dovoljenja;
 *       "razprodano" zavrne 409 pred semaforjem in ga sprememba capacity takoj pozabi.
 *   S2  pool.connect pade (PG_POOL_MAX=2, kratek PG_CONNECT_TIMEOUT_MS): 503 Retry-After (ne 500), dovoljenje se sprosti.
 *   S3  lock_timeout nakupne transakcije (NAKUP_DB_TIMEOUT_MS): 503 Retry-After, dovoljenje se sprosti.
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const JWKS_PORT = 3993;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-vrsta";
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
const spi = (ms) => new Promise(r => setTimeout(r, ms));

let BASE = "", ipStevec = 0;
async function api(method, path, token, body, signal) {
  const t0 = performance.now();
  try {
    const r = await fetch(BASE + path, {
      method,
      headers: { "content-type": "application/json", "x-forwarded-for": `10.9.${(++ipStevec >> 8) & 255}.${(ipStevec & 255) + 1}`, ...(token ? { authorization: "Bearer " + token } : {}) },
      body: body ? JSON.stringify(body) : undefined, signal: signal || AbortSignal.timeout(30000),
    });
    const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
    return { status: r.status, body: j, retryAfter: r.headers.get("retry-after"), ms: performance.now() - t0 };
  } catch (e) { return { status: e.name === "AbortError" ? "prekinjeno" : "omrezje", body: String(e.message), ms: performance.now() - t0 }; }
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));

  let srv = null, log = "";
  async function zagon(port, okolje) {
    BASE = `http://127.0.0.1:${port}`;
    srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test", ...okolje }, stdio: ["ignore", "pipe", "pipe"] });
    srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
    for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); return; } catch { await spi(100); } }
  }
  async function ustavi() { if (!srv) return; const s = srv; srv = null; await new Promise(r => { s.once("exit", r); s.kill(); }); }

  const U = {};
  const uporabnik = (ime, n) => (U[ime] = zeton(`${ime}@outly.si`, uuid(n)));
  uporabnik("lastnik", 1);
  ["a", "b", "c", "d", "e", "f", "g", "h"].forEach((x, i) => uporabnik("kupec_" + x, 10 + i));
  ["p1", "p2", "p3", "q1", "q2", "q3", "r1", "r2", "r3", "z"].forEach((x, i) => uporabnik("kupec_" + x, 30 + i));

  // Zaklep vrstice dogodka: nakup, ki zeli vstaviti narocilo za ta dogodek, obvisi v sprozilcu, dokler ne sprostimo.
  async function zakleni(dogodek) {
    const c = await pool.connect();
    await c.query("BEGIN"); await c.query("SELECT id FROM events WHERE id=$1 FOR UPDATE", [dogodek]);
    return { sprosti: async () => { await c.query("ROLLBACK"); c.release(); } };
  }
  const steviloNarocil = async (ime) => (await pool.query("SELECT COUNT(*)::int AS n FROM orders o JOIN users u ON u.id=o.user_id WHERE u.email=$1", [`${ime}@outly.si`])).rows[0].n;

  // ---------------------------------------------------------------- S1
  console.log("# S1: vrsta (NAKUP_VZPOREDNO=1, NAKUP_CAKANJE_MS=1500)");
  await zagon(3141, { NAKUP_VZPOREDNO: "1", NAKUP_CAKANJE_MS: "1500" });
  for (const k of Object.keys(U)) { const r = await api("GET", "/me", U[k]); if (r.status !== 200) assert(false, `GET /me ${k}`, r.body); }
  await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Vrsta Club', 'Ljubljana')");
  const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
  const dogodek = async (naslov, kapaciteta) => (await pool.query(
    "INSERT INTO events (club_id, title, start_at, status, ticket_price_cents, capacity, min_age) VALUES (1,$1,$2,'published',1000,$3,0) RETURNING id", [naslov, cezDan, kapaciteta])).rows[0].id;
  const E = await dogodek("E zaklenjen", 1000), F = await dogodek("F capacity 1", 1), H = await dogodek("H capacity 1", 1);

  console.log("\n## 503 po izteku cakanja");
  let lk = await zakleni(E);
  const A1 = api("POST", `/events/${E}/orders`, U.kupec_a, { quantity: 1 });   // drzi edino dovoljenje, obvisi na zaklepu
  await spi(300);
  const B = await api("POST", `/events/${E}/orders`, U.kupec_b, { quantity: 1 });
  assert(B.status === 503, "cakalec, ki ne dobi dovoljenja v NAKUP_CAKANJE_MS -> 503", B);
  assert(B.retryAfter === "5", "503 ima Retry-After", B.retryAfter);
  assert(B.ms >= 1400 && B.ms < 4000, "503 pride po ~1,5 s cakanja", B.ms);
  await lk.sprosti();
  const a1 = await A1;
  assert(a1.status === 201, "nakup, ki je drzal dovoljenje, se po sprostitvi zaklepa uspesno konca (201)", a1);
  assert(await steviloNarocil("kupec_b") === 0, "kupec, ki je dobil 503, nima narocila");

  console.log("\n## odjemalec odide med cakanjem -> ne kupi (duh)");
  lk = await zakleni(E);
  const A2 = api("POST", `/events/${E}/orders`, U.kupec_c, { quantity: 1 });
  await spi(300);
  const D = api("POST", `/events/${E}/orders`, U.kupec_d, { quantity: 1 });                       // normalen cakalec (pozitivna kontrola)
  await spi(50);
  const ac = new AbortController();
  const C = api("POST", `/events/${E}/orders`, U.kupec_e, { quantity: 1 }, ac.signal);            // odide
  await spi(200);
  ac.abort();
  const c = await C;
  assert(c.status === "prekinjeno", "odjemalec je prekinil zahtevek med cakanjem", c);
  await spi(150);
  await lk.sprosti();
  const [a2, d] = await Promise.all([A2, D]);
  assert(a2.status === 201 && d.status === 201, "ostala dva nakupa (drzalec in normalen cakalec) uspeta", [a2.status, d.status]);
  await spi(500);   // brez popravka bi duh pridobil dovoljenje in kupil
  assert(await steviloNarocil("kupec_e") === 0, "prekinjeni cakalec NIMA narocila (ni duha)");

  console.log("\n## dovoljenje se sprosti (nic ne uhaja)");
  const t = await api("POST", `/events/${E}/orders`, U.kupec_f, { quantity: 1 });
  assert(t.status === 201 && t.ms < 1000, "naslednji nakup gre takoj skozi (201, brez cakanja na dovoljenje)", t);

  console.log("\n## razprodano: 409 pred semaforjem");
  let r = await api("POST", `/events/${H}/orders`, U.kupec_a, { quantity: 1 });
  assert(r.status === 201, "H capacity 1: prvi kupec 201", r);
  r = await api("POST", `/events/${H}/orders`, U.kupec_b, { quantity: 1 });
  assert(r.status === 409 && /0 tickets left/.test(String(r.body)), "H razprodan: 409 (zapomni si razprodano)", r);
  lk = await zakleni(E);
  const A3 = api("POST", `/events/${E}/orders`, U.kupec_g, { quantity: 1 });                       // spet drzi edino dovoljenje
  await spi(300);
  const hitro = await api("POST", `/events/${H}/orders`, U.kupec_h, { quantity: 1 });
  assert(hitro.status === 409 && hitro.ms < 300, "razprodan dogodek dobi 409 takoj, ceprav je dovoljenje zasedeno (ne caka v vrsti)", hitro);
  const zaklenjen = api("POST", `/events/${E}/orders`, U.kupec_p1, { quantity: 1 });               // nerazprodan dogodek ISTEGA dovoljenja caka
  await lk.sprosti();
  const [a3, zk] = await Promise.all([A3, zaklenjen]);
  assert(a3.status === 201 && zk.status === 201, "nerazprodan dogodek se po sprostitvi normalno proda", [a3.status, zk.status]);

  console.log("\n## sprememba capacity takoj pozabi razprodano");
  r = await api("POST", `/events/${F}/orders`, U.kupec_a, { quantity: 1 });
  assert(r.status === 201, "F capacity 1: prvi kupec 201", r);
  r = await api("POST", `/events/${F}/orders`, U.kupec_b, { quantity: 1 });
  assert(r.status === 409, "F razprodan: 409", r);
  r = await api("PATCH", `/events/${F}`, U.lastnik, { capacity: 5 });
  assert(r.status === 200, "lastnik poveca capacity na 5", r);
  r = await api("POST", `/events/${F}/orders`, U.kupec_b, { quantity: 1 });
  assert(r.status === 201, "takoj po povecanju capacity nakup spet uspe (razprodano je pozabljeno)", r);
  await ustavi();

  // ---------------------------------------------------------------- S2
  console.log("\n# S2: pool.connect pade (PG_POOL_MAX=2, PG_CONNECT_TIMEOUT_MS=300, NAKUP_VZPOREDNO=3)");
  await zagon(3142, { PG_POOL_MAX: "2", PG_CONNECT_TIMEOUT_MS: "300", NAKUP_VZPOREDNO: "3", NAKUP_CAKANJE_MS: "2000" });
  const E2 = await dogodek("E2 zaklenjen", 1000);
  const skupaj = { 201: 0, 503: 0, drugo: [] }, kroge = [];
  for (const [k, ime] of [[1, "p"], [2, "q"], [3, "r"]]) {
    const lk2 = await zakleni(E2);
    // Trije hkrati: dva zasedeta obe povezavi (obviseta na zaklepu), tretji ne dobi povezave -> 503.
    const ps = [1, 2, 3].map(i => api("POST", `/events/${E2}/orders`, U[`kupec_${ime}${i}`], { quantity: 1 }));
    await spi(900);
    await lk2.sprosti();
    const rez = await Promise.all(ps);
    const kr = { 201: 0, 503: 0 };
    for (const x of rez) {
      if (x.status === 201) { skupaj[201]++; kr[201]++; }
      else if (x.status === 503) { skupaj[503]++; kr[503]++; if (x.retryAfter !== "5") skupaj.drugo.push(["brez Retry-After", x]); }
      else skupaj.drugo.push(x.status);
    }
    kroge.push(kr);
  }
  console.log(`  (3 kroga po 3 nakupe: ${JSON.stringify(kroge)})`);
  assert(skupaj.drugo.length === 0, "nobenega 500/401/omrezne napake, vsak 503 ima Retry-After", skupaj.drugo);
  // Ce bi neuspeh pool.connect ohranil dovoljenje, bi ze v 2. krogu en nakup cakal na dovoljenje namesto na povezavo
  // (omejitev dovoljenj bi skrila naslednje neuspehe): vsak krog mora dati tocno en 503 in dva 201.
  assert(kroge.every(k => k[503] === 1 && k[201] === 2), "v vsakem od treh krogov tocno 1 x 503 (brez povezave) in 2 x 201 - dovoljenje se po neuspehu sprosti", kroge);
  const zadnji = await api("POST", `/events/${E2}/orders`, U.kupec_z, { quantity: 1 });
  assert(zadnji.status === 201 && zadnji.ms < 1000, "po neuspehih gre nakup takoj skozi", zadnji);
  await ustavi();

  // ---------------------------------------------------------------- S3
  console.log("\n# S3: lock_timeout nakupne transakcije (NAKUP_DB_TIMEOUT_MS=600, NAKUP_VZPOREDNO=1)");
  await zagon(3143, { NAKUP_DB_TIMEOUT_MS: "600", NAKUP_VZPOREDNO: "1" });
  const E3 = await dogodek("E3 zaklenjen", 1000);
  lk = await zakleni(E3);
  const z1 = await api("POST", `/events/${E3}/orders`, U.kupec_a, { quantity: 1 });
  assert(z1.status === 503 && z1.retryAfter === "5", "nakup, ki predolgo caka na zaklep -> 503 Retry-After (ne 500, ne vise)", z1);
  assert(z1.ms >= 500 && z1.ms < 5000, "503 pride po ~NAKUP_DB_TIMEOUT_MS", z1.ms);
  await lk.sprosti();
  const z2 = await api("POST", `/events/${E3}/orders`, U.kupec_b, { quantity: 1 });
  assert(z2.status === 201 && z2.ms < 1000, "po lock_timeout se dovoljenje in povezava sprostita (naslednji nakup 201)", z2);
  const naE3 = (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1", [E3])).rows[0].n;
  assert(naE3 === 1, "na E3 je samo ena narocilo (nakup, ki je padel na lock_timeout, narocila nima)", naE3);
  await ustavi();

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  const napake = log.split("\n").filter(l => /TypeError|Unhandled|ReferenceError/i.test(l));
  if (napake.length) { console.log("\nLog backenda (sumljivo):\n" + napake.slice(0, 20).join("\n")); }
  jwksServer.close(); await pool.end();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
