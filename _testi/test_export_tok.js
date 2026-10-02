#!/usr/bin/env node
/**
 * Test izvoza v toku (GET /admin/api/export, issue #23). Zagon (lokalno, PG16,
 * prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_export_tok.js
 * Vzorec kot test_finance_admin.js: lokalni JWKS (3999), backend na svojem portu (3124).
 *
 * Kaj dokazuje:
 *  1. Oblika izhoda je ENAKA staremu izvozu: odgovor je bajt za bajtom enak
 *     JSON.stringify(...) objekta, ki ga zgradi stara (ne-tokovna) koda
 *     (referencna izvedba je v tem testu). Obstojece kopije in obnovi_izvoz.js
 *     berejo to obliko.
 *  2. Poraba pomnilnika procesa ne raste z velikostjo baze: 300.000 vstopnic
 *     (> 80 MB JSON), kopica strezniskega procesa je omejena na 48 MB; po
 *     ogrevanju z majhnim izvozom veliki izvoz doda vrhu RSS
 *     strezniskega procesa (VmHWM iz /proc) < 50 MB in manj kot pol velikosti
 *     odgovora. Stara koda zgradi cel odgovor v pomnilniku (issue #23: 56 MB
 *     odgovora = RSS +170 MB), zato ta preverba na njej pade.
 *  3. Prekinitev odjemalca sredi izvoza sprosti povezavo iz poola (po 15
 *     prekinitvah, vec kot je povezav v poolu, strezniku se vedno dela, v bazi
 *     ni "idle in transaction").
 *  4. Dostop je nespremenjen: brez zetona 401, navaden uporabnik/business 403.
 */
process.env.TZ = "Europe/Ljubljana"; // date_of_birth mora ostati niz YYYY-MM-DD tudi v pasu z odmikom
const crypto = require("crypto");
const http = require("http");
const fs = require("fs");
const { spawn } = require("child_process");
const { Pool, types: pgTipi } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3124, JWKS_PORT = 3999;
const BASE = `http://127.0.0.1:${PORT}`;
const ST_NAROCIL = Number(process.env.EXPORT_TEST_NAROCIL || 100000); // x 3 vstopnice = 300.000 vstopnic (issue #23 meri 120.000 = 56 MB)

// Enako kot index.js: BIGINT kot stevilo
pgTipi.setTypeParser(20, (v) => (v === null ? null : parseInt(v, 10)));

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
async function api(method, path, token) {
  const r = await fetch(BASE + path, { method, headers: token ? { authorization: "Bearer " + token } : {} });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}
function vrhRssMB(pid) {
  const m = /VmHWM:\s+(\d+) kB/.exec(fs.readFileSync(`/proc/${pid}/status`, "utf8"));
  return m ? Number(m[1]) / 1024 : NaN;
}
// Referencna (stara, ne-tokovna) izvedba izvoza: ta test jo hrani, da primerja izhod bajt za bajtom.
async function referencniIzvoz(pool, exportedAt, postgres) {
  const c = await pool.connect();
  try {
    await c.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    const t = await c.query(
      `SELECT table_name FROM information_schema.tables
       WHERE table_schema='public' AND table_type='BASE TABLE' AND table_name <> 'omejitve' ORDER BY table_name`);
    const tipiIzvoza = { getTypeParser: (oid, fmt) => (oid === 1082 ? (v) => v : pgTipi.getTypeParser(oid, fmt)) };
    const tables = {};
    for (const { table_name } of t.rows) {
      const r = await c.query({ text: `SELECT * FROM "${table_name.replace(/"/g, '""')}"`, types: tipiIzvoza });
      tables[table_name] = { count: r.rowCount, columns: r.fields.map((f) => f.name), rows: r.rows };
    }
    const s = await c.query(`SELECT sequencename AS name, last_value FROM pg_sequences WHERE schemaname='public' ORDER BY sequencename`);
    await c.query("COMMIT");
    return JSON.stringify({ exported_at: exportedAt, postgres, tables, sequences: s.rows });
  } finally { c.release(); }
}
// Prebere telo kot tok kosov (brez res.json), da test sam ne povzroca vrha v strezniku.
async function izvozKosi(token) {
  const r = await fetch(BASE + "/admin/api/export", { headers: { authorization: "Bearer " + token } });
  const kosi = [];
  for await (const k of r.body) kosi.push(Buffer.from(k));
  return { status: r.status, tip: r.headers.get("content-type"), telo: Buffer.concat(kosi), ste_kosov: kosi.length };
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, creator_applications, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  // Strezniku omejimo kopico V8 na 48 MB: tokovni izvoz mora v njej zdrzati odgovor > 100 MB (ne-tokovna koda
  // zgradi cel odgovor v kopici in pade z "heap out of memory"), poleg tega RSS ne zraste zaradi leno
  // sprozenega GC (brez omejitve zraste ~70 MB, tudi ce kopica ni vecja).
  // Casovne omejitve izvoza so v testu kratke (privzeto 60 s / 120 s): drain 3 s, idle-in-transaction 30 s.
  let srv = null, log = "";
  function zazeniStreznik(okolje) {
    srv = spawn("node", ["--max-old-space-size=48", "index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test", TZ: "Europe/Ljubljana", EXPORT_DRAIN_TIMEOUT_MS: "3000", EXPORT_IDLE_TX_MS: "30000", ...(okolje || {}) }, stdio: ["ignore", "pipe", "pipe"] });
    srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  }
  async function pocakajStreznik() { for (let i = 0; i < 80; i++) { try { await fetch(BASE + "/"); return; } catch { await new Promise(r => setTimeout(r, 100)); } } }
  async function ponovniZagon(okolje) {
    const s = srv;
    if (s.exitCode === null) await new Promise(r => { s.once("exit", r); s.kill(); });
    zazeniStreznik(okolje); await pocakajStreznik();
  }
  zazeniStreznik();
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  const T = {
    admin: zeton("admin@outly.si", uuid(1)),
    lastnik: zeton("lastnik@outly.si", uuid(2)),
    navaden: zeton("navaden@outly.si", uuid(3)),
  };
  for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
  await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
  await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");

  console.log("\n# Seme (netrivialni podatki + majhen posnetek vstopnic)");
  // Posebni znaki, unicode, narekovaji, backslash, nova vrstica, JSONB, polje, DATE, prazna tabela med drugimi.
  await pool.query(
    `UPDATE users SET date_of_birth = DATE '1999-12-31', genres = '{house,"drum & bass","z \\"narekovaji\\""}',
       username = 'ž"č\\š''-😀', phone = '+38640123456', country = 'SI' WHERE email='navaden@outly.si'`);
  await pool.query(
    `INSERT INTO clubs (owner_user_id, name, city, description, floor_plan) VALUES
       ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure "Club" \\ Ž', 'Ljubljana', E'vrstica 1\\nvrstica 2\\t\\u2028 konec', $1::jsonb)`,
    [JSON.stringify({ width: 10, height: 10, elements: [{ type: "bar", x: 0, y: 0, w: 2, h: 1 }], opomba: "č š ž    " })]);
  await pool.query(
    `INSERT INTO events (club_id, title, start_at, ticket_price_cents, capacity) VALUES (1, 'Veliki dogodek', NOW() + INTERVAL '7 days', 1000, 500000)`);
  // Brez sprozilcev (zaloga se ne steje), da seme ni pocasno; poslovna logika se tu ne preizkusa.
  async function dosejVstopnice(odNarocila, doNarocila) {
    const seed = await pool.connect();
    try {
      await seed.query("SET session_replication_role = replica");
      await seed.query(
        `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, paid_at, buyer_email)
         SELECT 'ref-' || g, 3, 1, 1, 3, 1000, 3000, 'paid', NOW(), 'navaden@outly.si' FROM generate_series($1::int, $2::int) g`, [odNarocila, doNarocila]);
      await seed.query(
        `INSERT INTO tickets (order_id, event_id, holder_user_id)
         SELECT o.id, 1, 3 FROM orders o, generate_series(1, 3) k WHERE o.id >= $1`, [odNarocila]);
    } finally { seed.release(); }
  }
  const MALO = 3000; // najprej majhen posnetek (ogrevanje procesa), sele nato velik
  await dosejVstopnice(1, MALO);
  console.log("\n# Dostop");
  let r = await api("GET", "/admin/api/export", null);
  assert(r.status === 401, "izvoz brez zetona -> 401", r.status);
  r = await api("GET", "/admin/api/export", T.navaden);
  assert(r.status === 403, "izvoz navaden uporabnik -> 403", r.status);
  r = await api("GET", "/admin/api/export", T.lastnik);
  assert(r.status === 403, "izvoz business vloga -> 403", r.status);

  console.log("\n# Oblika izhoda (majhen izvoz, primerjava z staro izvedbo)");
  // MALO narocil = MALO*3 vstopnic: oba stevila sta CELOSTEVILSKI veckratnik velikosti kosa (500), kar je
  // robni primer (zadnji FETCH vrne 0 vrstic, brez odvecne vejice); users (3 vrstice) in prazne tabele so nepolni kosi.
  const mali = await izvozKosi(T.admin);
  assert(mali.status === 200, "admin izvoz -> 200", mali.status);
  assert(/^application\/json/.test(mali.tip || ""), "Content-Type je application/json", mali.tip);
  let izvoz; try { izvoz = JSON.parse(mali.telo.toString("utf8")); } catch (e) { izvoz = null; }
  assert(izvoz !== null, "odgovor je veljaven JSON");
  if (izvoz) {
    assert(Object.keys(izvoz).join(",") === "exported_at,postgres,tables,sequences", "kljuci najvisje ravni po vrstnem redu", Object.keys(izvoz));
    assert(izvoz.tables.tickets.count === MALO * 3 && izvoz.tables.tickets.rows.length === MALO * 3, "tickets: count in stevilo vrstic se ujemata (veckratnik kosa)", izvoz.tables.tickets.count);
    assert(izvoz.tables.users.count === 3 && izvoz.tables.users.rows.length === 3, "users: nepolni kos (3 vrstice)", izvoz.tables.users.count);
    assert(izvoz.tables.ticket_transfers.count === 0 && izvoz.tables.ticket_transfers.rows.length === 0 && Array.isArray(izvoz.tables.ticket_transfers.columns) && izvoz.tables.ticket_transfers.columns.length > 0, "prazna tabela: count 0, rows [], columns se vedno navedeni", izvoz.tables.ticket_transfers);
    assert(izvoz.tables.users.rows.some((u) => u.date_of_birth === "1999-12-31"), "date_of_birth je niz YYYY-MM-DD (ne premaknjen za dan)");
    assert(izvoz.tables.users.rows.some((u) => u.username === 'ž"č\\š\'-😀'), "unicode, narekovaji in backslash prezivijo");
    assert(izvoz.tables.clubs.rows[0].floor_plan && izvoz.tables.clubs.rows[0].floor_plan.width === 10, "JSONB je objekt");
    const refTelo = await referencniIzvoz(pool, izvoz.exported_at, izvoz.postgres);
    const enako = Buffer.compare(mali.telo, Buffer.from(refTelo, "utf8")) === 0;
    assert(enako, "odgovor je BAJT ZA BAJTOM enak izhodu stare (ne-tokovne) izvedbe", { dolzina_tok: mali.telo.length, dolzina_ref: Buffer.byteLength(refTelo) });
    const tabele = (await pool.query(`SELECT COUNT(*)::int AS n FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE' AND table_name <> 'omejitve'`)).rows[0].n;
    assert(Object.keys(izvoz.tables).length === tabele, `izvoz vsebuje vseh ${tabele} tabel`, Object.keys(izvoz.tables).length);
  }

  console.log("\n# Poraba pomnilnika (baza zraste ~35x)");
  // Vrh RSS (VmHWM) le narasca, zato merimo, koliko vrha doda sele veliki izvoz povrh vrha malega (proces je ogret).
  // Tokovna koda doda nekaj deset MB (GC), ne-tokovna ~5x velikost odgovora.
  await dosejVstopnice(MALO + 1, ST_NAROCIL);
  const stVse = (await pool.query("SELECT COUNT(*)::int AS n FROM tickets")).rows[0].n;
  assert(stVse === ST_NAROCIL * 3, `v bazi je ${ST_NAROCIL * 3} vstopnic`, stVse);
  const hwm0 = vrhRssMB(srv.pid);
  const t0 = Date.now();
  const iz = await izvozKosi(T.admin);
  const ms = Date.now() - t0;
  const hwm1 = vrhRssMB(srv.pid);
  const velikostMB = iz.telo.length / 1048576;
  const rast = hwm1 - hwm0;
  console.log(`    odgovor ${velikostMB.toFixed(1)} MB v ${iz.ste_kosov} kosih, ${ms} ms; vrh RSS strezniskega procesa ${hwm0.toFixed(0)} -> ${hwm1.toFixed(0)} MB (+${rast.toFixed(0)})`);
  assert(iz.status === 200, "veliki izvoz -> 200", iz.status);
  assert(velikostMB > 80, "odgovor je velik (> 80 MB), test je smiseln", velikostMB);
  assert(iz.telo.subarray(0, 13).toString() === '{"exported_at' && iz.telo.subarray(-2).toString() === "]}", "veliki odgovor se zacne in konca kot JSON objekt");
  assert(iz.telo.includes(`"tickets":{"count":${ST_NAROCIL * 3},`), "veliki izvoz navaja count vstopnic", ST_NAROCIL * 3);
  assert(rast < 50, `veliki izvoz doda manj kot 50 MB vrha RSS povrh majhnega (+${rast.toFixed(0)} MB pri ${velikostMB.toFixed(0)} MB odgovora)`, { rast, velikostMB });
  assert(rast < velikostMB / 2, "rast vrha RSS je manjsa od pol velikosti odgovora (ne raste linearno z bazo)", { rast, velikostMB });

  console.log("\n# Prekinitev odjemalca sprosti povezavo");
  // Pool ima najvec 10 povezav: 15 prekinitev bi ga izpraznilo, ce bi prekinjen izvoz povezavo obdrzal.
  for (let i = 0; i < 15; i++) {
    const ac = new AbortController();
    try {
      const rr = await fetch(BASE + "/admin/api/export", { headers: { authorization: "Bearer " + T.admin }, signal: ac.signal });
      const rd = rr.body.getReader();
      await rd.read(); // prvi kos je prisel, izvoz je sredi poti
      ac.abort();
    } catch (_) { /* AbortError je pricakovan */ }
  }
  let obvisele = -1;
  for (let i = 0; i < 100; i++) { // povezave se sprostijo v nekaj 100 ms (strežnik dokonča tekoči FETCH)
    obvisele = (await pool.query(`SELECT COUNT(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND state LIKE 'idle in transaction%' AND pid <> pg_backend_pid()`)).rows[0].n;
    if (obvisele === 0) break;
    await new Promise((r) => setTimeout(r, 100));
  }
  assert(obvisele === 0, "po prekinitvah ni povezav 'idle in transaction'", obvisele);
  r = await api("GET", "/clubs");
  assert(r.status === 200, "/clubs po 15 prekinitvah -> 200 (pool ni izpraznjen)", r.status);
  r = await api("GET", "/admin/api/summary", T.admin);
  assert(r.status === 200, "/admin/api/summary po prekinitvah -> 200", r.status);
  const iz2 = await izvozKosi(T.admin);
  assert(iz2.status === 200 && iz2.telo.length > 1000000, "poln izvoz po prekinitvah se vedno deluje", iz2.status);

  // ------------------------------------------------------------------------------------------------
  // Pomocniki za bralca, ki ga nadziramo (bere sele, ko mu recemo)
  function pocasniBralec() {
    return new Promise((resolve, reject) => {
      const req = http.get(BASE + "/admin/api/export", { headers: { authorization: "Bearer " + T.admin } }, (res) => {
        res.pause(); // ne bere: socket se napolni in strežnik čaka na 'drain'
        let bajtov = 0, napaka = null;
        const izid = new Promise((done) => {
          res.on("data", (d) => { bajtov += d.length; });
          res.on("error", (e) => { napaka = e.code || e.message; });
          res.on("close", () => done({ complete: res.complete, bajtov, napaka }));
        });
        resolve({ res, izid, status: res.statusCode });
      });
      req.on("error", (e) => reject(e));
    });
  }
  const cakaj = (ms) => new Promise((r) => setTimeout(r, ms));
  // Povezave, ki jih drzi izvoz: 'idle in transaction' (REPEATABLE READ), zadnja poizvedba je FETCH/DECLARE/SELECT COUNT.
  const mirujocaTx = async () => (await pool.query(
    `SELECT pid, state, query FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid() AND state LIKE 'idle in transaction%'`)).rows;
  async function cakajNaMirujocoTx(msMax) {
    for (let t = 0; t < msMax; t += 100) { const v = await mirujocaTx(); if (v.length) return v; await cakaj(100); }
    return [];
  }
  async function cakajBrezMirujocihTx(msMax) {
    for (let t = 0; t < msMax; t += 100) { if ((await mirujocaTx()).length === 0) return true; await cakaj(100); }
    return false;
  }
  const streznikZiv = () => srv.exitCode === null && srv.signalCode === null;

  console.log("\n# Baza sredi izvoza prekine povezavo (pg_terminate_backend) -> streznik preziv");
  await ponovniZagon();
  let b = await pocasniBralec();
  assert(b.status === 200, "pocasni bralec dobi glave izvoza (200)", b.status);
  await cakaj(1000); // streznik napolni socket in caka na 'drain'; transakcija izvoza miruje
  let tx = await cakajNaMirujocoTx(5000);
  assert(tx.length === 1, "izvoz drzi natanko eno transakcijo (idle in transaction)", tx);
  if (tx.length) await pool.query("SELECT pg_terminate_backend($1)", [tx[0].pid]);
  b.res.resume();
  let izid = await Promise.race([b.izid, cakaj(15000).then(() => "casovna omejitev")]);
  assert(izid !== "casovna omejitev" && izid.complete === false, "odjemalec dobi PREKINJEN (nepopoln) odgovor", izid);
  await cakaj(300);
  assert(streznikZiv(), "strezniski proces se je po prekinitvi povezave izvoza ziv", { exitCode: srv.exitCode, signalCode: srv.signalCode });
  assert(!/Unhandled 'error' event/.test(log), "v logu ni 'Unhandled error event'", log.split("\n").filter((l) => /Unhandled/.test(l)).slice(0, 2));
  if (streznikZiv()) {
    r = await api("GET", "/clubs");
    assert(r.status === 200, "/clubs po prekinitvi povezave izvoza -> 200", r.status);
    r = await api("GET", "/admin/api/summary", T.admin);
    assert(r.status === 200, "/admin/api/summary (pool dela naprej) -> 200", r.status);
    assert(await cakajBrezMirujocihTx(3000), "po prekinitvi ni povezav 'idle in transaction'");
    const iz3 = await izvozKosi(T.admin);
    assert(iz3.status === 200 && iz3.telo.length > 1000000 && iz3.telo.subarray(-2).toString() === "]}", "poln izvoz po prekinitvi povezave se vedno deluje", iz3.status);
  }

  console.log("\n# Pocasen bralec (ne bere, ne zapre) -> po meji drain se transakcija sprosti, migracija se izvede");
  await ponovniZagon(); // EXPORT_DRAIN_TIMEOUT_MS=3000, EXPORT_IDLE_TX_MS=30000
  b = await pocasniBralec();
  await cakaj(1000);
  tx = await cakajNaMirujocoTx(5000);
  assert(tx.length === 1, "pocasni bralec: izvoz drzi transakcijo", tx);
  // bottle_packages je abecedno prva tabela, ki jo izvoz prebere: zaklep (AccessShareLock) drzi do konca transakcije,
  // tudi ko je kurzor ze pri kasnejsi tabeli.
  async function alter(lockTimeout, sql) {
    const c = await pool.connect();
    try {
      await c.query("BEGIN");
      await c.query(`SET LOCAL lock_timeout = '${lockTimeout}'`);
      await c.query(sql);
      await c.query("COMMIT");
      return { ok: true };
    } catch (e) { await c.query("ROLLBACK").catch(() => {}); return { ok: false, koda: e.code }; }
    finally { c.release(); }
  }
  let al = await alter("500ms", "ALTER TABLE bottle_packages ADD COLUMN _test_tok integer");
  assert(al.ok === false && al.koda === "55P03", "dokler bralec miruje, ALTER TABLE caka na zaklep (lock_timeout 55P03)", al);
  const tAlter = Date.now();
  al = await alter("12s", "ALTER TABLE bottle_packages ADD COLUMN _test_tok integer");
  const alMs = Date.now() - tAlter;
  assert(al.ok === true && alMs < 10000, `po meji drain (3 s) se ALTER TABLE izvede (${alMs} ms)`, { al, alMs });
  if (al.ok) await pool.query("ALTER TABLE bottle_packages DROP COLUMN _test_tok");
  assert(await cakajBrezMirujocihTx(3000), "pocasni bralec: po meji ni povezav 'idle in transaction'");
  b.res.resume();
  izid = await Promise.race([b.izid, cakaj(15000).then(() => "casovna omejitev")]);
  assert(izid !== "casovna omejitev" && izid.complete === false, "pocasni bralec dobi prekinjen odgovor", izid);
  assert(streznikZiv(), "strezniski proces je ziv");
  if (streznikZiv()) { r = await api("GET", "/clubs"); assert(r.status === 200, "/clubs po sprostitvi pocasnega bralca -> 200", r.status); }

  console.log("\n# Varovalo idle_in_transaction_session_timeout (drain meja je dolga, Postgres sam prekine)");
  await ponovniZagon({ EXPORT_DRAIN_TIMEOUT_MS: "60000", EXPORT_IDLE_TX_MS: "2000" });
  b = await pocasniBralec();
  await cakaj(500);
  tx = await cakajNaMirujocoTx(5000);
  assert(tx.length === 1, "izvoz drzi transakcijo, preden izteče idle meja", tx);
  assert(await cakajBrezMirujocihTx(8000), "Postgres po idle meji (2 s) sam prekine transakcijo izvoza");
  b.res.resume();
  izid = await Promise.race([b.izid, cakaj(15000).then(() => "casovna omejitev")]);
  assert(izid !== "casovna omejitev" && izid.complete === false, "odjemalec dobi prekinjen odgovor", izid);
  await cakaj(300);
  assert(streznikZiv(), "strezniski proces je ziv po prekinitvi zaradi idle meje");
  assert(!/Unhandled 'error' event/.test(log), "v logu ni 'Unhandled error event'");
  if (streznikZiv()) {
    r = await api("GET", "/clubs");
    assert(r.status === 200, "/clubs po idle prekinitvi -> 200", r.status);
    // normalen izvoz ne sme biti prekinjen zaradi idle meje (transakcija med izvozom ne miruje dolgo)
    const iz4 = await izvozKosi(T.admin);
    assert(iz4.status === 200 && iz4.telo.subarray(-2).toString() === "]}", "poln izvoz s hitrim bralcem uspe tudi z idle mejo 2 s", iz4.status);
  }

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  const napake = log.split("\n").filter(l => /error|TypeError|Unhandled/i.test(l) && !/Server error\./.test(l) && !/Resend/i.test(l));
  if (napake.length) console.log("\nLog backenda (sumljivo):\n" + napake.join("\n"));
  srv.kill(); jwksServer.close();
  await pool.query("TRUNCATE omejitve, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, creator_applications, users RESTART IDENTITY CASCADE");
  await pool.end();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
