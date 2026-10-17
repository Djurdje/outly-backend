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
 *   Z5  velik dogodek (5000 vstopnic): scan-list in scan-batch z najvecjim paketom (500) pod privzetima mejama -> 200, izmerjen cas.
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3431, JWKS_PORT = 3432;
const BASE = `http://127.0.0.1:${PORT}`;
// Privzeti meji v index.js (preverjamo privzeto vedenje, ne nastavljenega).
const LOCK_MS = 1000, STMT_MS = 2000;

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
    const l = await api("GET", `/business/events/${dog}/scan-list`, T.lastnik, null, LOCK_MS + 4000);
    assert(meja503(l, LOCK_MS), `GET scan-list med zaklepom -> 503 v ${l.ms} ms`, l);
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
  console.log("\n# Z5: velik dogodek (5000 vstopnic): scan-list in scan-batch (500) pod privzetima mejama");
  // 2500 kupcev x 2 vstopnici neposredno v bazi (nakup prek API-ja bi trajal minute). Vsaka vstopnica ima svojega imetnika (JOIN users).
  await pool.query(`INSERT INTO users (email, username, email_verified) SELECT 'k' || g || '@test.si', 'kupec' || g, true FROM generate_series(1, 2500) g`);
  await pool.query(`INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, paid_at)
    SELECT 'ZK' || u.id, u.id, $1, 1, 2, 1500, 3000, 'paid', u.email, NOW() FROM users u WHERE u.email LIKE 'k%@test.si'`, [dog]);
  await pool.query(`INSERT INTO tickets (order_id, event_id, created_at) SELECT o.id, o.event_id, NOW() - INTERVAL '2 days' FROM orders o, generate_series(1, 2) WHERE o.public_ref LIKE 'ZK%'`);
  await pool.query("ANALYZE tickets; ANALYZE orders; ANALYZE users");
  const st = (await pool.query("SELECT count(*)::int AS n FROM tickets WHERE event_id=$1", [dog])).rows[0].n;
  assert(st >= 5000, `dogodek ima ${st} vstopnic`);
  await zagon();
  const casi = [];
  for (let i = 0; i < 5; i++) {
    const l = await api("GET", `/business/events/${dog}/scan-list`, T.lastnik, null, 30000);
    if (i === 0) assert(l.status === 200 && l.body.tickets.length === st, `scan-list (5000) -> 200, ${l.body.tickets && l.body.tickets.length} vstopnic`, { status: l.status });
    casi.push(l.ms);
  }
  console.log(`  (scan-list 5000 vstopnic: ${casi.join(", ")} ms)`);
  const serijski = (await pool.query("SELECT serial FROM tickets t JOIN orders o ON o.id=t.order_id WHERE o.public_ref LIKE 'ZK%' ORDER BY t.id LIMIT 500")).rows.map(x => x.serial);
  const b = await api("POST", "/business/tickets/scan-batch", T.lastnik, { scans: serijski.map((s, i) => ({ client_scan_id: "z5-" + i, device_id: "dev-z5", serial: s })) }, 60000);
  assert(b.status === 200 && b.body.results.length === 500 && b.body.results.every(x => x.result === "ok"), `scan-batch 500 -> 200, vse ok (${b.ms} ms)`, { status: b.status, napake: b.body && b.body.results && b.body.results.filter(x => x.result !== "ok").length });
  const b2 = await api("POST", "/business/tickets/scan-batch", T.lastnik, { scans: serijski.map((s, i) => ({ client_scan_id: "z5-" + i, device_id: "dev-z5", serial: s })) }, 60000);
  assert(b2.status === 200 && b2.body.results.every(x => x.result === "ok"), `ponovitev paketa 500 (idempotentno) -> vse ok (${b2.ms} ms)`);
  console.log(`  (scan-batch 500: ${b.ms} ms, ponovitev ${b2.ms} ms)`);
  // Najdaljsi posamezen stavek na skenPool: scan-list, merjen v bazi (brez HTTP in JSON).
  const ex = await pool.query(`EXPLAIN (ANALYZE, FORMAT JSON) SELECT t.serial, t.status, t.used_at, (o.table_id IS NOT NULL) AS is_vip, o.table_label,
      COALESCE(hu.username, 'x') AS holder_username, EXISTS (SELECT 1 FROM spori sp WHERE sp.order_id = o.id) AS d
    FROM tickets t JOIN orders o ON o.id = t.order_id LEFT JOIN users hu ON hu.id = COALESCE(t.holder_user_id, o.user_id) WHERE t.event_id = $1 ORDER BY t.id`, [dog]);
  const stavekMs = ex.rows[0]["QUERY PLAN"][0]["Execution Time"];
  console.log(`  (stavek scan-list v bazi: ${stavekMs.toFixed(1)} ms; meja statement_timeout ${STMT_MS} ms)`);
  assert(stavekMs * 10 < STMT_MS, `stavek scan-list ima vsaj 10x rezerve do statement_timeout (${stavekMs.toFixed(1)} ms x 10 < ${STMT_MS} ms)`);
  await ustavi();

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  const sumljivo = log.split("\n").filter(l => /TypeError|Unhandled|ReferenceError/i.test(l));
  if (sumljivo.length) console.log("\nLog backenda (sumljivo):\n" + sumljivo.slice(0, 20).join("\n"));
  jwksServer.close(); await pool.end();
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); if (srv) srv.kill(); process.exit(1); });
