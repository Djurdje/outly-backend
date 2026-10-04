#!/usr/bin/env node
/**
 * Neujet `await pool.connect()` pred `try` (issue #129): Express 4 zavrnjene obljube asinhronih rocnikov ne ujame, zato je
 * "timeout exceeded when trying to connect" ob zasicenem poolu postal unhandled rejection in Node 22 je KONCAL CEL PROCES
 * (tudi sken vstopnic na vratih). Pricakovano: proces prezivi, odgovor je 503 + Retry-After: 5 (napaka povezave) ali 500
 * (vse drugo), nikoli izhod procesa ali dvojen odgovor.
 * Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL=postgres://postgres:postgres@localhost:5432/outly node _testi/test_connect_napaka.js
 *
 *   S1  tocen scenarij iz issuea: PG_POOL_MAX=2, PG_CONNECT_TIMEOUT_MS=100, 400 vzporednih
 *       POST /me/friends/requests/999/accept -> proces zivi, odgovori 404/503, vsak 503 ima Retry-After 5.
 *   S2  vsako mesto s `await pool.connect()` pred `try` (admin: approve, POST/PATCH clubs, export; transfer vstopnice,
 *       sprejem vabila, PUT /business/vip, PUT /business/events/:id/vip) pod isto zasicenostjo -> proces zivi, brez 500.
 *   S3c DETERMINISTICNO: napaka baze (57014) v `await` pred `try` -> 503 + Retry-After, dnevnik [rocnik] (S1/S2 sta odvisna od casovanja).
 *   S3  `await` pred `try`, ki pade z NE-povezavno napako (pool.query z 22003 v staPrijatelja) -> 500 (ne izhod procesa).
 *   S4  skenPool (PG_SKEN_POOL_MAX=1, kratek timeout): 300 vzporednih skenov -> proces zivi, /clubs po koncu 200.
 *   S4b sken poti: stavek prekinjen (57014) -> 503 + Retry-After (NE 500), S4c enota odgovoriNaNapako, S5 transfer z user_id izven int4 -> 400 (issue #132).
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const JWKS_PORT = 3961;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-connect";
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
async function api(method, path, token, body) {
  try {
    const r = await fetch(BASE + path, {
      method,
      headers: { "content-type": "application/json", "x-forwarded-for": `10.8.${(++ipStevec >> 8) & 255}.${(ipStevec & 255) + 1}`, ...(token ? { authorization: "Bearer " + token } : {}) },
      body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(60000),
    });
    const t = await r.text();
    return { status: r.status, body: t, retryAfter: r.headers.get("retry-after") };
  } catch (e) { return { status: "omrezje", body: String(e.message) }; }
}
const steje = (rez) => rez.reduce((m, r) => (m[r.status] = (m[r.status] || 0) + 1, m), {});

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await pool.query("TRUNCATE omejitve");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));

  let srv = null, log = "", umrl = null;
  async function zagon(port, okolje) {
    BASE = `http://127.0.0.1:${port}`; log = ""; umrl = null;
    srv = spawn("node", ["index.js"], { env: { ...process.env, REZERVACIJE_CISCENJE_MS: "0", PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test", JAVNI_PREDPOMNILNIK_MS: "0", ...okolje }, stdio: ["ignore", "pipe", "pipe"] });
    srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
    srv.on("exit", (code, sig) => { umrl = { code, sig }; });
    for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); return; } catch { await spi(100); } }
  }
  async function ustavi() { if (!srv) return; const s = srv; srv = null; if (umrl) return; await new Promise(r => { s.once("exit", r); s.kill(); }); }
  const zivo = async () => { await spi(300); if (umrl) return false; const r = await api("GET", "/clubs"); return r.status === 200; };

  const U = {};
  [["ana", 1], ["admin", 2], ["lastnik", 3], ["bor", 4]].forEach(([ime, n]) => { U[ime] = zeton(`${ime}@outly.si`, uuid(n)); });

  // Priprava (brez obremenitve): uporabniki, admin, klub z dogodkom, vabilo.
  await zagon(3962, {});
  for (const k of Object.keys(U)) { const r = await api("GET", "/me", U[k]); if (r.status !== 200) assert(false, `priprava GET /me ${k}`, r); }
  await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
  await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Connect Club', 'Ljubljana')");
  await pool.query("INSERT INTO events (club_id, title, start_at, status, ticket_price_cents, capacity, min_age) VALUES (1,'E',$1,'published',1000,100,0)", [new Date(Date.now() + 86400000).toISOString()]);
  await ustavi();

  // ---------------------------------------------------------------- S1
  console.log("# S1: scenarij iz issuea (PG_POOL_MAX=2, PG_CONNECT_TIMEOUT_MS=100, 400 x POST /me/friends/requests/999/accept)");
  await zagon(3962, { PG_POOL_MAX: "2", PG_CONNECT_TIMEOUT_MS: "100" });
  // Opomba: ali zavrnitev pool.connect res pride do rocnika, ali pa vsi 503 nastanejo ze v iskanju uporabnika (avtentikacija,
  // requireAuth tudi porabi povezavo iz istega poola), je odvisno od casovanja (CPU, CI) - zato tu NE trdimo dnevnika [rocnik].
  // To trditev determinirano drzi S3c; S1 in S2 sta testa PREZIVETJA procesa pod navalo (na stari kodi izstopi s kodo 1).
  let rez = await Promise.all(Array.from({ length: 400 }, () => api("POST", "/me/friends/requests/999/accept", U.ana)));
  let st = steje(rez);
  console.log("  (statusi:", JSON.stringify(st), ")");
  await spi(300);
  assert(!umrl, "proces po 400 vzporednih zahtevkih ZIVI (ni izstopil)", umrl);
  assert(Object.keys(st).every(k => k === "404" || k === "503"), "vsak odgovor je 404 (ni prosnje) ali 503 (pool zaseden): brez 500 in prekinjenih zvez", st);
  assert((st["503"] || 0) > 0, "scenarij je res zasitil pool (vsaj en 503)", st);
  assert(rez.filter(r => r.status === 503).every(r => r.retryAfter === "5"), "vsak 503 ima Retry-After: 5");
  assert(await zivo(), "po navali GET /clubs -> 200");
  await ustavi();

  // ---------------------------------------------------------------- S2
  console.log("\n# S2: vsa mesta z `await pool.connect()` pred `try` pod zasicenim poolom");
  await zagon(3962, { PG_POOL_MAX: "2", PG_CONNECT_TIMEOUT_MS: "100" });
  const poti = [
    ["admin: odobritev prosnje", "POST", "/admin/api/creator-applications/999/approve", U.admin, {}],
    ["admin: nov klub", "POST", "/admin/api/clubs", U.admin, { ownerEmail: "bor@outly.si", name: "X" }],
    ["admin: urejanje kluba", "PATCH", "/admin/api/clubs/999", U.admin, { name: "Y" }],
    ["admin: izvoz", "GET", "/admin/api/export", U.admin, null],
    ["prenos vstopnice (e-naslov)", "POST", "/tickets/999/transfer", U.ana, { email: "bor@outly.si" }],
    ["sprejem vabila", "POST", "/me/invites/999/accept", U.ana, {}],
    ["PUT /business/vip", "PUT", "/business/vip", U.lastnik, { plan: null, tables: [], packages: [] }],
    ["PUT /business/events/:id/vip", "PUT", "/business/events/1/vip", U.lastnik, { enabled: true }],
    ["sprejem prosnje za prijateljstvo", "POST", "/me/friends/requests/999/accept", U.ana, {}],
  ];
  const vsi = await Promise.all(poti.flatMap(([ime, m, p, t, b]) => Array.from({ length: 80 }, () => api(m, p, t, b).then(r => ({ ime, ...r })))));
  console.log("  (statusi:", JSON.stringify(steje(vsi)), ")");
  await spi(300);
  assert(!umrl, "proces po 720 vzporednih zahtevkih na 9 poti ZIVI", umrl);
  for (const [ime] of poti) {
    const r = vsi.filter(x => x.ime === ime), s = steje(r);
    assert(!r.some(x => x.status === 500 || x.status === "omrezje"), `${ime}: brez 500 in prekinjenih zvez`, s);
    assert(r.filter(x => x.status === 503).every(x => x.retryAfter === "5"), `${ime}: vsak 503 ima Retry-After: 5`);
  }
  assert(await zivo(), "po navali GET /clubs -> 200");
  await ustavi();

  // ---------------------------------------------------------------- S3
  console.log("\n# S3: `await` pred `try` pade z napako, ki NI povezava (55P03 lock_timeout, razred 55) -> 500, proces zivi");
  // Prej je to dal user_id izven int4 (22003 v staPrijatelja); od #132 je to 400 (glej S5), zato ista pot (`staPrijatelja` pred
  // `try` v prenosu vstopnice) zdaj pade na zaklepu tabele friendships z lock_timeout: SQLSTATE 55P03 NI v razredih 08/53/57.
  await zagon(3962, { PGOPTIONS: "-c lock_timeout=300" });
  const borId3 = (await pool.query("SELECT id FROM users WHERE email='bor@outly.si'")).rows[0].id;
  const zk3 = await pool.connect();
  await zk3.query("BEGIN"); await zk3.query("LOCK TABLE friendships IN ACCESS EXCLUSIVE MODE");
  let r = await api("POST", "/tickets/1/transfer", U.ana, { user_id: borId3 });
  assert(r.status === 500, "prenos vstopnice: napaka, ki ni povezava (55P03, staPrijatelja pred try) -> 500 (ne izhod procesa, ne 503)", r);
  await spi(300);
  assert(!umrl, "proces po napaki ZIVI", umrl);
  assert(log.includes("[rocnik] nepricakovana napaka (POST /tickets/1/transfer)"), "napaka je zapisana s potjo in skladom ([rocnik] nepricakovana napaka)");
  await zk3.query("ROLLBACK"); zk3.release();
  const slabJson = await fetch(BASE + "/me", { method: "PATCH", headers: { "content-type": "application/json", authorization: "Bearer " + U.ana }, body: "{pokvarjen" }).catch(() => ({ status: "omrezje" }));
  assert(slabJson.status === 400, "pokvarjen JSON ostane 400 (napaka body-parserja gre skozi privzeti obravnavalnik, ne 500/503)", slabJson.status);
  assert(await zivo(), "GET /clubs -> 200");
  await ustavi();

  // ---------------------------------------------------------------- S3c
  console.log("\n# S3c: DETERMINISTICNO: napaka povezave/baze (57014 statement_timeout, razred 57) v `await` pred `try` -> 503 + dnevnik [rocnik]");
  // Avtentikacija uspe (tabela users ni zaklenjena), `staPrijatelja` (pool.query PRED try v prenosu vstopnice) pa obvisi na zaklepu
  // tabele friendships, dokler Postgres ne prekine stavka (PGOPTIONS statement_timeout). Isti mehanizem kot zavrnjen pool.connect
  // pred try (zavrnjena obljuba pred try), a brez odvisnosti od casovanja.
  await zagon(3962, { PGOPTIONS: "-c statement_timeout=400" });
  const borId = (await pool.query("SELECT id FROM users WHERE email='bor@outly.si'")).rows[0].id;
  const zk = await pool.connect();
  await zk.query("BEGIN"); await zk.query("LOCK TABLE friendships IN ACCESS EXCLUSIVE MODE");
  let t0 = Date.now();
  r = await api("POST", "/tickets/1/transfer", U.ana, { user_id: borId });
  assert(r.status === 503 && r.retryAfter === "5", "prenos vstopnice: stavek pred try prekinjen (57014) -> 503 + Retry-After 5 (NE izhod procesa, NE 500)", r);
  assert(Date.now() - t0 >= 300, "odgovor je prisel po statement_timeout (zaklep je res drzal)", Date.now() - t0);
  assert(log.includes("[rocnik] zacasna napaka povezave z bazo (POST /tickets/1/transfer)"), "napaka je sla prek obravnavalnika napak (dnevnik [rocnik] z metodo in potjo)");
  await spi(300);
  assert(!umrl, "proces ZIVI", umrl);
  await zk.query("ROLLBACK"); zk.release();
  r = await api("POST", "/tickets/1/transfer", U.ana, { user_id: borId });
  assert(r.status === 404, "po sprostitvi zaklepa isti klic -> 404 (nista prijatelja), spet normalno", r);
  assert(await zivo(), "GET /clubs -> 200");
  await ustavi();

  // Enota: obravnavalnik napak ne pise dvojnega odgovora in prevaja napake.
  console.log("\n# S3b: napakaRocnik (enota)");
  const { napakaRocnik } = require("../asinhroni_rocniki");
  const lazni = (headersSent) => { const r = { headersSent, koda: null, glave: {}, telo: null,
    status(k) { this.koda = k; return this; }, set(k, v) { this.glave[k] = v; return this; }, send(t) { this.telo = t; return this; } }; return r; };
  const tiho = console.error; console.error = () => {};
  try {
    let n = null, res = lazni(true); napakaRocnik(new Error("timeout exceeded when trying to connect"), {}, res, e => { n = e; });
    assert(res.koda === null && res.telo === null && n, "odgovor ze poslan: nic ne pise, napako preda Expressu (zapre povezavo)");
    res = lazni(false); n = null; napakaRocnik(new Error("timeout exceeded when trying to connect"), {}, res, e => { n = e; });
    assert(res.koda === 503 && res.glave["Retry-After"] === "5" && n === null, "napaka povezave -> 503 + Retry-After 5");
    res = lazni(false); n = null; napakaRocnik(Object.assign(new Error("x"), { code: "ECONNRESET" }), {}, res, e => { n = e; });
    assert(res.koda === 503, "ECONNRESET -> 503");
    res = lazni(false); n = null; napakaRocnik(Object.assign(new Error("value out of range"), { code: "22003" }), {}, res, e => { n = e; });
    assert(res.koda === 500 && res.telo === "Server error.", "22003 -> 500");
    res = lazni(false); n = null; napakaRocnik(new TypeError("x is not a function"), {}, res, e => { n = e; });
    assert(res.koda === 500, "TypeError -> 500 (programska napaka ni 503)");
    res = lazni(false); n = null; napakaRocnik(Object.assign(new Error("too large"), { status: 413 }), {}, res, e => { n = e; });
    assert(res.koda === null && n && n.status === 413, "4xx (body-parser) preda privzetemu obravnavalniku");
  } finally { console.error = tiho; }

  // ---------------------------------------------------------------- S4
  console.log("\n# S4: skenPool (PG_SKEN_POOL_MAX=1, PG_SKEN_CONNECT_TIMEOUT_MS=100), 300 vzporednih skenov");
  await zagon(3962, { PG_SKEN_POOL_MAX: "1", PG_SKEN_CONNECT_TIMEOUT_MS: "100" });
  const serial = "00000000-0000-4000-8000-0000000000aa";
  rez = await Promise.all(Array.from({ length: 300 }, () => api("POST", "/business/tickets/scan", U.lastnik, { serial })));
  st = steje(rez);
  console.log("  (statusi:", JSON.stringify(st), ")");
  await spi(300);
  assert(!umrl, "proces po 300 vzporednih skenih ZIVI", umrl);
  assert(rez.every(x => typeof x.status === "number"), "vsak zahtevek dobi odgovor (brez prekinjenih zvez)", st);
  assert(rez.filter(x => x.status === 503).every(x => x.retryAfter === "5"), "vsak 503 ima Retry-After: 5");
  assert(rez.every(x => x.status === 404 || x.status === 503), "brez 500: vsak odgovor je 404 (neznana vstopnica) ali 503 (pool zaseden), issue #132", st);
  assert(await zivo(), "po navali GET /clubs -> 200");
  await ustavi();

  // ---------------------------------------------------------------- S4b
  // Issue #132: lasten `catch (e) { ...; return res.status(500) }` skenskih poti je napako povezave/baze vrnil kot 500.
  // DETERMINISTICNO (brez casovanja in brez stetja 503): tabelo `tickets` zaklenemo, PGOPTIONS statement_timeout prekine stavek
  // skena s 57014 (razred 57 = jeNapakaPovezave) -> pricakujemo 503 + Retry-After 5, nikoli 500. Vsaka pot skena mora imeti
  // svoj stavek, ki zadene `tickets` PO preverjanju kluba (zaklep tickets ne vpliva na avtentikacijo in iskanje kluba).
  console.log("\n# S4b: sken poti, stavek nad `tickets` prekinjen (57014) -> 503 + Retry-After 5, NE 500 (#132)");
  await zagon(3962, { PGOPTIONS: "-c statement_timeout=400" });
  {
    const zkt = await pool.connect();
    await zkt.query("BEGIN"); await zkt.query("LOCK TABLE tickets IN ACCESS EXCLUSIVE MODE");
    const skenPoti = [
      ["POST /business/tickets/scan", "POST", "/business/tickets/scan", { serial }],
      ["POST /business/tickets/scan-batch", "POST", "/business/tickets/scan-batch", { scans: [{ client_scan_id: "s4b-1", device_id: "dev-s4b", serial }] }],
      ["GET /business/events/1/scan-list", "GET", "/business/events/1/scan-list", null],
    ];
    for (const [ime, m, pot, telo] of skenPoti) {
      const r4 = await api(m, pot, U.lastnik, telo);
      assert(r4.status === 503 && r4.retryAfter === "5", `${ime}: stavek prekinjen (57014) -> 503 + Retry-After 5 (NE 500)`, r4);
    }
    const rKljuc = await api("GET", "/business/scan-key", U.lastnik);
    assert(rKljuc.status === 200, "GET /business/scan-key ne rabi tickets: 200 tudi med zaklepom", rKljuc);
    await spi(300);
    assert(!umrl, "proces ZIVI", umrl);
    await zkt.query("ROLLBACK"); zkt.release();
    const rPo = await api("POST", "/business/tickets/scan", U.lastnik, { serial });
    assert(rPo.status === 404, "po sprostitvi zaklepa sken neznane vstopnice -> 404 (normalno delovanje)", rPo);
  }
  await ustavi();

  // Enota: pomocnik odgovoriNaNapako (503 + Retry-After za napake povezave, sicer 500; odgovor ze poslan ne pise dvojnega).
  console.log("\n# S4c: odgovoriNaNapako (enota)");
  {
    const { odgovoriNaNapako } = require("../napaka_povezave");
    const lazni2 = (headersSent) => ({ headersSent, koda: null, glave: {}, telo: null,
      status(k) { this.koda = k; return this; }, set(k, v) { this.glave[k] = v; return this; },
      send(t) { this.telo = t; return this; }, json(t) { this.telo = t; return this; } });
    const tiho2 = console.error; console.error = () => {};
    try {
      let res = lazni2(false); odgovoriNaNapako(res, Object.assign(new Error("canceling statement due to statement timeout"), { code: "57014" }), "scan");
      assert(res.koda === 503 && res.glave["Retry-After"] === "5" && res.telo && res.telo.error === "service_unavailable", "57014 -> 503 + Retry-After 5 + {error:service_unavailable}", res);
      res = lazni2(false); odgovoriNaNapako(res, new Error("timeout exceeded when trying to connect"), "scan");
      assert(res.koda === 503 && res.glave["Retry-After"] === "5", "izcrpan pool (napaka brez kode) -> 503");
      res = lazni2(false); odgovoriNaNapako(res, Object.assign(new Error("value out of range"), { code: "22003" }), "scan");
      assert(res.koda === 500 && res.telo && res.telo.error === "server_error" && !res.glave["Retry-After"], "22003 -> 500 brez Retry-After");
      res = lazni2(false); odgovoriNaNapako(res, new TypeError("x"), "scan");
      assert(res.koda === 500, "TypeError -> 500 (programska napaka ni 503)");
      res = lazni2(true); odgovoriNaNapako(res, new Error("timeout exceeded when trying to connect"), "scan");
      assert(res.koda === null && res.telo === null, "odgovor ze poslan: ne pise dvojnega");
    } finally { console.error = tiho2; }
  }

  // ---------------------------------------------------------------- S5
  // Issue #132 (drugi del): user_id izven int4 je dal 22003 -> 500; veljavno je samo 400 (neveljaven id).
  console.log("\n# S5: POST /tickets/:id/transfer z user_id izven int4 -> 400 (NE 500)");
  await zagon(3962, {});
  for (const uid of ["99999999999", 2147483648, 9223372036854775807n.toString(), 2147483647, 999]) {
    const rt = await api("POST", "/tickets/1/transfer", U.ana, { user_id: uid });
    const pricakovano = (String(uid) === "2147483647" || String(uid) === "999") ? 404 : 400;
    assert(rt.status === pricakovano, `user_id ${uid} -> ${pricakovano} (${pricakovano === 400 ? "izven int4" : "veljaven int4, nista prijatelja"})`, rt);
  }
  // events.id je int4: id dogodka izven int4 v scan-list je dal 22003 -> 500 (pregled #136); veljavno je 400.
  const rSl = await api("GET", "/business/events/99999999999/scan-list", U.lastnik);
  assert(rSl.status === 400, "GET /business/events/99999999999/scan-list -> 400 (izven int4, NE 500)", rSl);
  assert(await zivo(), "GET /clubs -> 200");
  await ustavi();

  await pool.end();
  jwksServer.close();
  console.log(`\n${ok} ok, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
