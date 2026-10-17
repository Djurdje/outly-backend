#!/usr/bin/env node
/**
 * Sken na vratih ne sme viseti za zaklepom (pregled 17. 10. 2026, S1; I16). Migracija ob deployu (ACCESS EXCLUSIVE na tickets
 * do 120 s) ali dolga transakcija, ki drzi vrstico vstopnice, je sken v teku zadrzala, dokler zaklep ni popustil. Pricakovano:
 * skenPool ima casovni meji (`lock_timeout` = PG_SKEN_LOCK_TIMEOUT_MS, `statement_timeout` = PG_SKEN_STATEMENT_TIMEOUT_MS),
 * sken dobi HITRO 503 + Retry-After 5 (kot ob nedosegljivi bazi), telefon preklopi na sken brez povezave.
 * Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL=postgres://postgres:postgres@localhost:5432/outly node _testi/test_sken_zaklep.js
 *
 *   Z1  LOCK TABLE tickets IN ACCESS EXCLUSIVE MODE v odprti transakciji -> POST /business/tickets/scan 503 + Retry-After 5
 *       v < meja + 1 s (55P03); scan-list in scan-batch enako; po ROLLBACK sken uspe (200 ok). Na stari kodi sken VISI -> PADE.
 *   Z2  isto z izklopljenim lock_timeout (PG_SKEN_LOCK_TIMEOUT_MS=0): statement_timeout (57014) -> 503 v < meja + 1 s.
 *   Z3  zaklep VRSTICE vstopnice (SELECT ... FOR UPDATE): SELECT skena ni blokiran, UPDATE caka -> 503 (55P03), ne visi in ne 500.
 *   Z4  scan-batch, zaklenjenih vec vrstic: element na zaklenjeni vrstici -> "error" (odjemalec ga obdrzi), proste -> "ok";
 *       po prvi zacasni napaki in izteku roka paketa (SKEN_BATCH_ROK_MS) ostali elementi -> "error" brez cakanja.
 *   Z5  najvecji dogodek (20 000 vstopnic): HLADEN prvi scan-list (nov proces backenda = nove povezave z bazo, kot po deployu) in
 *       scan-batch z najvecjim paketom (500) pod privzetimi mejami -> 200. Backend tu tece prek prisluskovalnega posrednika
 *       (TCP med backendom in Postgresom): ujame zagonske parametre povezav (skenPool posilja jit=off, lock_timeout, statement_timeout)
 *       in PRAVI stavek scan-list (sporocilo Parse). Ta stavek z EXPLAIN (ANALYZE) na novi seji: z jit=off ima vsaj 10x rezerve do 2 s,
 *       z jit=on (privzeto PG16) samo izpis (strosek plana preseze jit_above_cost). CI 17. 10. 2026: prvi scan-list 5000 vstopnic 3,5 s (JIT) -> 503 pri meji 2 s.
 *   Z6  hkratni scan-list: najvec max(1, PG_SKEN_POOL_MAX - 1) hkrati, ostali takoj 503; sken med njimi uspe (povezava ostane).
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3431, JWKS_PORT = 3432;   // posrednik Z5: 3435
const BASE = `http://127.0.0.1:${PORT}`;
// Privzeti meji v index.js (preverjamo privzeto vedenje, ne nastavljenega).
const LOCK_MS = 1000, STMT_MS = 5000, SEZNAM_MS = 10000;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-zaklep";
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
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra).slice(0, 400) : ""); } }

// Vsak klic ima trd odjemalski rok: sken, ki visi, je "visi" (ne caka v nedogled).
async function api(method, path, token, body, rokMs = 15000) {
  const t0 = Date.now();
  try {
    const r = await fetch(BASE + path, {
      method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) },
      body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(rokMs),
    });
    const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
    return { status: r.status, body: j, retryAfter: r.headers.get("retry-after"), ms: Date.now() - t0 };
  } catch (e) { return { status: "visi", body: String(e.message), ms: Date.now() - t0 }; }
}

// Prisluskovalni posrednik (Z5): TCP med backendom in Postgresom, bere SAMO sporocila odjemalca (protokol v3): zagonski paket
// (parametri povezave), Parse in Query (besedilo stavka). Promet posreduje nespremenjen. Gostitelj ostane "localhost" (SSL izklopljen).
const net = require("net");
const posrednik = { zagoni: [], stavki: [] };
function zazeniPosrednika(port) {
  const u = new URL(DB);
  const srvP = net.createServer((odj) => {
    const gor = net.connect(Number(u.port || 5432), u.hostname);
    let buf = Buffer.alloc(0), zagon = true;
    odj.on("data", (d) => {
      gor.write(d);
      buf = Buffer.concat([buf, d]);
      for (;;) {
        if (zagon) {
          if (buf.length < 8) break;
          const n = buf.readInt32BE(0); if (buf.length < n) break;
          if (buf.readInt32BE(4) === 196608) {   // protokol 3.0: pari kljuc\0vrednost\0
            const deli = buf.subarray(8, n).toString("utf8").split("\0"); const par = {};
            for (let i = 0; i + 1 < deli.length; i += 2) if (deli[i]) par[deli[i]] = deli[i + 1];
            posrednik.zagoni.push(par); zagon = false;
          }
          buf = buf.subarray(n); continue;
        }
        if (buf.length < 5) break;
        const n = buf.readInt32BE(1); if (buf.length < n + 1) break;
        if (buf[0] === 0x50) {   // 'P' Parse: ime\0 stavek\0 ...
          const telo = buf.subarray(5, n + 1); const z = telo.indexOf(0);
          posrednik.stavki.push(telo.subarray(z + 1, telo.indexOf(0, z + 1)).toString("utf8"));
        } else if (buf[0] === 0x51) {   // 'Q' preprost stavek (brez parametrov): stavek\0
          posrednik.stavki.push(buf.subarray(5, n).toString("utf8"));
        }
        buf = buf.subarray(n + 1);
      }
    });
    gor.on("data", (d) => odj.write(d));
    const zapri = () => { odj.destroy(); gor.destroy(); };
    odj.on("error", zapri); gor.on("error", zapri); odj.on("close", zapri); gor.on("close", zapri);
  });
  return new Promise((r) => srvP.listen(port, "127.0.0.1", () => {
    const v = new URL(DB); v.hostname = "localhost"; v.port = String(port);
    r({ url: v.toString(), zapri: () => new Promise((z) => srvP.close(z)) });
  }));
}

let srv = null, log = "";
(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, table_service, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));

  async function zagon(okolje = {}) {
    log = "";
    srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test", REZERVACIJE_CISCENJE_MS: "0", ...okolje }, stdio: ["ignore", "pipe", "pipe"] });
    srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
    for (let i = 0; i < 100; i++) { try { await fetch(BASE + "/"); return; } catch { await new Promise(r => setTimeout(r, 100)); } }
    throw new Error("backend se ni zagnal");
  }
  async function ustavi() { if (!srv) return; const s = srv; srv = null; if (s.exitCode !== null) return; await new Promise(r => { s.once("exit", r); s.kill(); }); }

  await zagon();
  const T = { lastnik: zeton("lastnik@outly.si", uuid(1)), ana: zeton("ana@outly.si", uuid(2)) };
  for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
  await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Zaklep Klub', 'Ljubljana')");
  const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
  let r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Zaklep", startAt: cezDan, ticketPriceCents: 0, capacity: 20000, minAge: 0 });
  assert(r.status === 201, "dogodek ustvarjen", r.body);
  const dog = r.body.id;
  r = await api("POST", `/events/${dog}/orders`, T.ana, { quantity: 8 });
  assert(r.status === 201 && r.body.tickets && r.body.tickets.length === 8, "ana dobi 8 brezplacnih vstopnic", r.body);
  const anine = r.body.tickets.map(t => t.serial);
  // Vrata so odprta: dogodek se je zacel pred uro, vstopnice so nastale pred dnevi.
  await pool.query("UPDATE tickets SET created_at = NOW() - INTERVAL '2 days'");
  await pool.query("UPDATE events SET start_at = NOW() - INTERVAL '1 hour' WHERE id=$1", [dog]);

  // Druga povezava, ki drzi zaklep; sprosti se v finally, da test ne pusti visece transakcije.
  async function zZaklepom(sql, params, fn) {
    const c = await pool.connect();
    try { await c.query("BEGIN"); await c.query(sql, params); return await fn(); }
    finally { await c.query("ROLLBACK").catch(() => {}); c.release(); }
  }
  const meja503 = (x, meja) => x.status === 503 && x.retryAfter === "5" && x.ms < meja + 1000;

  // ---------------------------------------------------------------- Z1
  console.log(`\n# Z1: ACCESS EXCLUSIVE na tickets (migracija ob deployu) -> sken 503 v < ${LOCK_MS} ms + 1 s, ne visi`);
  await zZaklepom("LOCK TABLE tickets IN ACCESS EXCLUSIVE MODE", [], async () => {
    const s = await api("POST", "/business/tickets/scan", T.lastnik, { serial: anine[0] }, LOCK_MS + 4000);
    assert(meja503(s, LOCK_MS), `POST /business/tickets/scan med zaklepom -> 503 + Retry-After 5 v ${s.ms} ms (NE visi, NE 500)`, s);
    const lp = api("GET", `/business/events/${dog}/scan-list`, T.lastnik, null, LOCK_MS + 4000);
    const l = await lp;
    assert(meja503(l, LOCK_MS), `GET scan-list med zaklepom -> 503 v ${l.ms} ms (lock_timeout velja tudi v transakciji seznama)`, l);
    const b = await api("POST", "/business/tickets/scan-batch", T.lastnik, { scans: [{ client_scan_id: "z1-1", device_id: "dev-z1", serial: anine[1] }] }, LOCK_MS + 4000);
    assert(meja503(b, LOCK_MS), `POST scan-batch med zaklepom -> 503 v ${b.ms} ms`, b);
    const z = await api("GET", "/healthz");
    assert(z.status === 200, "GET /healthz med zaklepom tickets -> 200 (instanca je zdrava)", z);
  });
  r = await api("POST", "/business/tickets/scan", T.lastnik, { serial: anine[0] });
  assert(r.status === 200 && r.body.result === "ok", "po sprostitvi zaklepa sken uspe (200 ok)", r);
  assert(/zacasna napaka povezave z bazo \(POST \/business\/tickets\/scan\)/.test(log) && !/nepricakovana napaka \(POST \/business\/tickets\/scan\)/.test(log),
    "dnevnik: zacasna napaka (503), ne nepricakovana (500)");
  await ustavi();

  // ---------------------------------------------------------------- Z2
  console.log(`\n# Z2: brez lock_timeout (PG_SKEN_LOCK_TIMEOUT_MS=0) ujame statement_timeout (57014) -> 503 v < ${STMT_MS} ms + 1 s`);
  await zagon({ PG_SKEN_LOCK_TIMEOUT_MS: "0" });
  await zZaklepom("LOCK TABLE tickets IN ACCESS EXCLUSIVE MODE", [], async () => {
    const s = await api("POST", "/business/tickets/scan", T.lastnik, { serial: anine[2] }, STMT_MS + 4000);
    assert(meja503(s, STMT_MS) && s.ms >= STMT_MS - 200, `sken med zaklepom -> 503 po statement_timeout (${s.ms} ms)`, s);
  });
  r = await api("POST", "/business/tickets/scan", T.lastnik, { serial: anine[2] });
  assert(r.status === 200 && r.body.result === "ok", "po sprostitvi sken uspe", r);
  await ustavi();

  // ---------------------------------------------------------------- Z3
  console.log("\n# Z3: zaklep VRSTICE vstopnice (dolga transakcija) -> UPDATE skena 503 (55P03), ne visi");
  await zagon();
  await zZaklepom("SELECT id FROM tickets WHERE serial = $1 FOR UPDATE", [anine[3]], async () => {
    const s = await api("POST", "/business/tickets/scan", T.lastnik, { serial: anine[3] }, LOCK_MS + 4000);
    assert(meja503(s, LOCK_MS), `sken zaklenjene vstopnice -> 503 + Retry-After 5 v ${s.ms} ms`, s);
    const d = await api("POST", "/business/tickets/scan", T.lastnik, { serial: anine[4] });
    assert(d.status === 200 && d.body.result === "ok", "druga (prosta) vstopnica se med tem skenira normalno", d);
  });
  r = await api("POST", "/business/tickets/scan", T.lastnik, { serial: anine[3] });
  assert(r.status === 200 && r.body.result === "ok", "po sprostitvi zaklepa vrstice sken uspe", r);
  await ustavi();

  // ---------------------------------------------------------------- Z4
  console.log("\n# Z4: scan-batch, zaklenjene vrstice: element -> error, proste -> ok, paket ne visi cez rok paketa");
  await zagon({ SKEN_BATCH_ROK_MS: "500" });
  const zaklenjene = [anine[5], anine[6], anine[1]];
  await zZaklepom("SELECT id FROM tickets WHERE serial = ANY($1::uuid[]) FOR UPDATE", [zaklenjene], async () => {
    // prosta, zaklenjena, zaklenjena, zaklenjena: prosta -> ok; prva zaklenjena caka lock_timeout (1 s) -> error; po roku paketa (0,5 s)
    // ostali dve -> error BREZ cakanja. Brez roka bi paket trajal ~3 x lock_timeout.
    const b = await api("POST", "/business/tickets/scan-batch", T.lastnik, { scans: [
      { client_scan_id: "z4-2", device_id: "dev-z4", serial: anine[7] },
      { client_scan_id: "z4-1", device_id: "dev-z4", serial: anine[5] },
      { client_scan_id: "z4-3", device_id: "dev-z4", serial: anine[6] },
      { client_scan_id: "z4-4", device_id: "dev-z4", serial: anine[1] },
    ] }, 10000);
    const res = b.body && b.body.results;
    assert(b.status === 200 && res && res.length === 4, `paket -> 200 v ${b.ms} ms`, b);
    assert(res && res.map(x => x.result).join() === "ok,error,error,error", "prosta -> ok, zaklenjena -> error, zaklenjeni po roku -> error", res);
    assert(b.ms < LOCK_MS * 2, `paket ni cakal na vsako zaklenjeno vrstico posebej (${b.ms} ms < ${LOCK_MS * 2})`, b.ms);
  });
  r = await api("POST", "/business/tickets/scan-batch", T.lastnik, { scans: [
    { client_scan_id: "z4-1", device_id: "dev-z4", serial: anine[5] }, { client_scan_id: "z4-3", device_id: "dev-z4", serial: anine[6] },
    { client_scan_id: "z4-4", device_id: "dev-z4", serial: anine[1] }] });
  assert(r.status === 200 && r.body.results.every(x => x.result === "ok"), "ponovljen paket po sprostitvi -> vse ok", r.body);
  await ustavi();

  // ---------------------------------------------------------------- Z5
  console.log("\n# Z5: najvecji dogodek (20 000 vstopnic): hladen prvi scan-list, scan-batch (500), pravi stavek brez JIT");
  // 9996 kupcev x 2 vstopnici neposredno v bazi (+ 8 aninih = 20 000 = kapaciteta). Vsaka vstopnica ima svojega imetnika (JOIN users).
  await pool.query(`INSERT INTO users (email, username, email_verified) SELECT 'k' || g || '@test.si', 'kupec' || g, true FROM generate_series(1, 9996) g`);
  await pool.query(`INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, paid_at)
    SELECT 'ZK' || u.id, u.id, $1, 1, 2, 1500, 3000, 'paid', u.email, NOW() FROM users u WHERE u.email LIKE 'k%@test.si'`, [dog]);
  await pool.query(`INSERT INTO tickets (order_id, event_id, created_at) SELECT o.id, o.event_id, NOW() - INTERVAL '2 days' FROM orders o, generate_series(1, 2) WHERE o.public_ref LIKE 'ZK%'`);
  await pool.query("ANALYZE tickets; ANALYZE orders; ANALYZE users");
  const st = (await pool.query("SELECT count(*)::int AS n FROM tickets WHERE event_id=$1", [dog])).rows[0].n;
  assert(st === 20000, `dogodek ima ${st} vstopnic`);
  // Nov proces backenda: skenPool odpre NOVE povezave (nov streznik Postgresa na povezavo, brez nalozenega JIT/katalogov) = hladno kot po deployu.
  const pos = await zazeniPosrednika(3435);
  await zagon({ DATABASE_URL: pos.url });
  const casi = [];
  for (let i = 0; i < 5; i++) {
    const l = await api("GET", `/business/events/${dog}/scan-list`, T.lastnik, null, 30000);
    if (i === 0) {
      assert(l.status === 200 && l.body.tickets && l.body.tickets.length === st, `HLADEN prvi scan-list (20 000) -> 200, ${l.body && l.body.tickets && l.body.tickets.length} vstopnic`, { status: l.status, ms: l.ms });
      // Pod staro mejo stavka (2 s), ki jo je CI s JIT presegel ze pri 5000 vstopnicah; celoten HTTP zahtevek, ne le stavek.
      // Rezerva: lokalno (4 CPU) hladno 220-270 ms (brez JIT) proti 677 ms z JIT; na CI ~2-3x pocasneje. Ta meja je casovna in ohlapna;
      // deterministicni preverbi JIT sta spodaj (zagonski paket jit=off, EXPLAIN pravega stavka brez JIT).
      assert(l.ms < 2000, `hladen prvi scan-list (20 000) v ${l.ms} ms < 2000 ms`, l.ms);
    } else assert(l.status === 200, `scan-list ${i + 1}. klic -> 200`, { status: l.status });
    casi.push(l.ms);
  }
  console.log(`  (scan-list 20 000 vstopnic: hladno ${casi[0]} ms, nato ${casi.slice(1).join(", ")} ms)`);
  const serijski = (await pool.query("SELECT serial FROM tickets t JOIN orders o ON o.id=t.order_id WHERE o.public_ref LIKE 'ZK%' ORDER BY t.id LIMIT 500")).rows.map(x => x.serial);
  const b = await api("POST", "/business/tickets/scan-batch", T.lastnik, { scans: serijski.map((s, i) => ({ client_scan_id: "z5-" + i, device_id: "dev-z5", serial: s })) }, 60000);
  assert(b.status === 200 && b.body.results.length === 500 && b.body.results.every(x => x.result === "ok"), `scan-batch 500 -> 200, vse ok (${b.ms} ms)`, { status: b.status, napake: b.body && b.body.results && b.body.results.filter(x => x.result !== "ok").length });
  const b2 = await api("POST", "/business/tickets/scan-batch", T.lastnik, { scans: serijski.map((s, i) => ({ client_scan_id: "z5-" + i, device_id: "dev-z5", serial: s })) }, 60000);
  assert(b2.status === 200 && b2.body.results.every(x => x.result === "ok"), `ponovitev paketa 500 (idempotentno) -> vse ok (${b2.ms} ms)`);
  console.log(`  (scan-batch 500: ${b.ms} ms, ponovitev ${b2.ms} ms)`);
  // PRAVI stavek scan-list (ujet v Z1) v bazi, vsakic na NOVI povezavi (hladna seja): z jit=on (privzeto) in jit=off (kot skenPool).
  async function razlozi(jit) {
    const { Client } = require("pg");
    const c = new Client({ connectionString: DB, options: `-c jit=${jit}` });
    await c.connect();
    try {
      const t0 = Date.now();
      const r = await c.query(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${stavekSeznama}`, [dog]);
      const n = r.rows[0]["QUERY PLAN"][0];
      return { ms: n["Execution Time"], skupaj: Date.now() - t0, strosek: n.Plan["Total Cost"], jit: n.JIT ? n.JIT.Timing.Total : null };
    } finally { await c.end(); }
  }
  // Zagonski parametri povezav skenPool (prepoznane po lock_timeout) in pravi stavek scan-list, kot ju je poslal backend.
  const skenZagoni = posrednik.zagoni.filter(p => p.lock_timeout === String(LOCK_MS));
  assert(skenZagoni.length > 0 && skenZagoni.every(p => /(^|\s)-c jit=off(\s|$)/.test(p.options || "") && p.statement_timeout === String(STMT_MS)),
    `povezave skenPool: jit=off, lock_timeout ${LOCK_MS}, statement_timeout ${STMT_MS} (zagonski paket)`, skenZagoni);
  const stavekSeznama = posrednik.stavki.find(q => /FROM tickets t JOIN orders o/.test(q) && /WHERE t\.event_id = \$1/.test(q) && /ORDER BY t\.id/.test(q) && /holder_username/.test(q));
  assert(!!stavekSeznama, "pravi stavek scan-list ujet (Parse)");
  assert(posrednik.stavki.includes(`BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout = ${SEZNAM_MS}`),
    `scan-list v transakciji z SET LOCAL statement_timeout = ${SEZNAM_MS} (BEGIN in SET v enem Query = ena krozna pot)`);
  // iOS hitra pot (scan-batch z 1 elementom): brez transakcije (BEGIN/SET/COMMIT bi bile dodatne krozne poti pod rokom 2 s).
  posrednik.stavki.length = 0;
  const vecSer = (await pool.query("SELECT serial FROM tickets t JOIN orders o ON o.id=t.order_id WHERE o.public_ref LIKE 'ZK%' ORDER BY t.id OFFSET 500 LIMIT 1")).rows[0].serial;
  const en = await api("POST", "/business/tickets/scan-batch", T.lastnik, { scans: [{ client_scan_id: "z5-en", device_id: "dev-z5", serial: vecSer }] });
  assert(en.status === 200 && en.body.results[0].result === "ok", "scan-batch z 1 elementom -> ok", en.body);
  assert(!posrednik.stavki.some(q => /^\s*(BEGIN|COMMIT|SET)/i.test(q)), "scan-batch z 1 elementom brez BEGIN/SET/COMMIT", posrednik.stavki.filter(q => /^\s*(BEGIN|COMMIT|SET)/i.test(q)));
  if (stavekSeznama) {
    const zJit = await razlozi("on"), brezJit = await razlozi("off");
    const pragJit = Number((await pool.query("SHOW jit_above_cost")).rows[0].jit_above_cost);
    console.log(`  (pravi stavek scan-list, hladna seja: jit=on ${zJit.ms.toFixed(1)} ms (JIT ${zJit.jit === null ? "ni" : (typeof zJit.jit === "number" ? zJit.jit.toFixed(1) : JSON.stringify(zJit.jit)) + " ms"}), ` +
      `jit=off ${brezJit.ms.toFixed(1)} ms; strosek plana ${Math.round(zJit.strosek)}, jit_above_cost ${pragJit})`);
    assert(brezJit.jit === null, "z jit=off (kot skenPool) stavek scan-list ne prevaja JIT");
    assert(brezJit.ms * 10 < 2000, `pravi stavek scan-list (20 000, jit=off) ima vsaj 10x rezerve do 2 s (${brezJit.ms.toFixed(1)} ms x 10 < 2000 ms)`);
    assert(brezJit.ms * 10 < SEZNAM_MS, `... in do meje seznama ${SEZNAM_MS} ms`);
  }
  await ustavi();
  await pos.zapri();

  // ---------------------------------------------------------------- Z6
  console.log("\n# Z6: hkratni scan-list ne zasedejo vseh povezav skenPool (PG_SKEN_POOL_MAX 3 -> najvec 2 seznama), sken uspe");
  // Seznama obvisita na zaklepu ticket_transfers (drugi stavek scan-list; sken veljavne vstopnice te tabele ne bere) z lock_timeout 3 s.
  await zagon({ PG_SKEN_LOCK_TIMEOUT_MS: "3000" });
  const ser6 = (await pool.query("SELECT serial FROM tickets t JOIN orders o ON o.id=t.order_id WHERE o.public_ref LIKE 'ZK%' AND t.status='valid' ORDER BY t.id LIMIT 1")).rows[0].serial;
  await zZaklepom("LOCK TABLE ticket_transfers IN ACCESS EXCLUSIVE MODE", [], async () => {
    const dva = [1, 2].map(() => api("GET", `/business/events/${dog}/scan-list`, T.lastnik, null, 10000));
    let cakata = 0;
    for (const doKdaj = Date.now() + 5000; cakata < 2 && Date.now() < doKdaj;) {
      cakata = (await pool.query("SELECT count(*)::int AS n FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query LIKE '%FROM ticket_transfers tt%' AND pid <> pg_backend_pid()")).rows[0].n;
      if (cakata < 2) await new Promise(r => setImmediate(r));
    }
    assert(cakata === 2, "dva scan-list drzita povezavi skenPool (cakata na zaklep)", cakata);
    // Tretji: z mejo takoj 503; brez nje bi zasedel zadnjo povezavo (cakal na zaklep) in sken bi po 2,5 s dobil 503.
    let tretjiKonec = false;
    const tretjiP = api("GET", `/business/events/${dog}/scan-list`, T.lastnik, null, 10000).then(x => { tretjiKonec = true; return x; });
    for (const doKdaj = Date.now() + 5000; !tretjiKonec && cakata < 3 && Date.now() < doKdaj;) {
      cakata = (await pool.query("SELECT count(*)::int AS n FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query LIKE '%FROM ticket_transfers tt%' AND pid <> pg_backend_pid()")).rows[0].n;
      if (cakata < 3) await new Promise(r => setImmediate(r));
    }
    const s6 = await api("POST", "/business/tickets/scan", T.lastnik, { serial: ser6 }, 5000);
    const tretji = await tretjiP;
    assert(tretji.status === 503 && tretji.retryAfter === "5" && tretji.ms < 1000, `tretji hkratni scan-list -> TAKOJ 503 + Retry-After 5 (${tretji.ms} ms, brez vrste)`, tretji);
    assert(s6.status === 200 && s6.body.result === "ok", `sken med dvema visecima scan-list -> 200 ok (${s6.ms} ms; povezava ostane skenu)`, s6);
    await Promise.all(dva);
  });
  r = await api("GET", `/business/events/${dog}/scan-list`, T.lastnik, null, 10000);
  assert(r.status === 200, "po sprostitvi scan-list spet 200 (stevec hkratnih se je vrnil)", { status: r.status });
  assert(/scan-list zavrnjen: ze 2 hkrati/.test(log), "dnevnik: zavrnjen scan-list (meja hkratnih)");
  await ustavi();

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  const sumljivo = log.split("\n").filter(l => /TypeError|Unhandled|ReferenceError/i.test(l));
  if (sumljivo.length) console.log("\nLog backenda (sumljivo):\n" + sumljivo.slice(0, 20).join("\n"));
  jwksServer.close(); await pool.end();
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); if (srv) srv.kill(); process.exit(1); });
