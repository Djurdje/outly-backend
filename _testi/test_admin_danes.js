#!/usr/bin/env node
/**
 * GET /admin/api/danes: nadzorna plosca »Danes« (#326, 23. 10. 2026; admin_nadzor.js). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres@localhost:5432/outly" node _testi/test_admin_danes.js
 * Vzorec kot test_admin_vloga.js: lokalni JWKS (6104), strezniki na portih 6103 (brez predpomnilnika), 6105 (predpomnilnik 1,5 s), 6106 (privzeto trajanje).
 *
 * Kaj dokazuje:
 *  1. oblika odgovora { cas, prodaja: { danes, dni7, testno_danes }, nocoj, racuni, opozorila_rdeca }.
 *  2. pravi in testni promet LOCENO (SQL_TESTNO_NAROCILO, I39: lazni nacin test_… in Stripe sandbox cs_test_…); guest lista ne steje nikamor; v celoti vrnjeno
 *     (refunded), neplacano (pending/failed/cancelled) in jutrisnje narocilo ne steje; delno vrnjeno steje v celoti; VIP miza steje v narocila in bruto, ne v vstopnice;
 *     »7 dni« = danes in prejsnjih 6 ljubljanskih dni (7 dni nazaj ze ne).
 *  3. nocoj: samo objavljeni dogodki z oknom skena danes (zacetek med -12 h in +24 h ali v teku), skriti klub, osnutek, dogodek cez 3 dni in vceraj koncan so izven;
 *     vstopi (skupaj) in vstopi_15min iz tickets.used_at; prodaja tece / ustavljena / razprodano / zaprta; polja natanko po dogovoru.
 *  4. racuni: izdani_danes (po izdan_at v ljubljanskem dnevu), caka, napaka; opozorila_rdeca = rdeca opozorila iz /opozorila.
 *  5. ljubljanski »danes«: za poljubne trenutke (vkljub poletni in zimski uri, dan s 23 in 25 urami) se meja dneva ujema z neodvisnim izracunom v JS (Intl, Europe/Ljubljana):
 *     narocilo ob 23:30 UTC je poleti (UTC+2) in pozimi (UTC+1) ze naslednji dan; »danes« se ne ravna po UTC.
 *  6. predpomnilnik: drugi klic znotraj trajanja ne vidi novega narocila (isti `cas`); po izteku ga vidi; privzeto trajanje je dolgo (vsaj nekaj sekund); sočasni klici so ena poizvedba.
 *  7. 403 (user, business, backup), 401 brez zetona; samo branje.
 */
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const http = require("http");
const { spawn } = require("child_process");
const pg = require("pg");
pg.types.setTypeParser(20, (v) => (v === null ? null : parseInt(v, 10)));   // kot index.js: BIGINT -> stevilo
const { Pool, Client } = pg;

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 6103, JWKS_PORT = 6104, PORT_PRED = 6105, PORT_PRIVZETO = 6106;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-danes";
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
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
const pocakaj = (ms) => new Promise(r => setTimeout(r, ms));
async function api(port, p, token) {
  const r = await fetch(`http://127.0.0.1:${port}${p}`, { headers: token ? { authorization: "Bearer " + token } : {} });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, text: t, glave: r.headers };
}
function zazeni(port, okolje) {
  const proc = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test",
    STRIPE_SECRET_KEY: "", STRIPE_WEBHOOK_SECRET: "", TEST_PLACILA: "", ...okolje }, stdio: ["ignore", "pipe", "pipe"] });
  const o = { proc, log: "" };
  proc.stdout.on("data", d => o.log += d); proc.stderr.on("data", d => o.log += d);
  return o;
}
async function cakajStreznik(port) { for (let i = 0; i < 80; i++) { try { await fetch(`http://127.0.0.1:${port}/`); return true; } catch { await pocakaj(100); } } return false; }

// SQL pogoj testnega narocila mora biti natanko tisti iz index.js (isti vir resnice, I39): test ga prebere iz izvorne kode.
const SQL_TESTNO_ZAPIS = "(COALESCE(o.stripe_payment_intent_id LIKE 'test\\\\_%', FALSE) OR COALESCE(o.stripe_checkout_session_id LIKE 'cs\\\\_test\\\\_%', FALSE))";   // kot v izvorni kodi (znaki \\)
const SQL_TESTNO = new Function("return `" + SQL_TESTNO_ZAPIS + "`")();                                                                                                              // kot ga vidi baza
const indexKoda = fs.readFileSync(path.join(__dirname, "..", "index.js"), "utf8");

// Neodvisen izracun ljubljanskega dne v JS (Intl): 'YYYY-MM-DD'.
const ljDan = (d) => new Intl.DateTimeFormat("sv-SE", { timeZone: "Europe/Ljubljana", year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date(d));
const danMinus = (niz, n) => { const d = new Date(niz + "T12:00:00Z"); d.setUTCDate(d.getUTCDate() - n); return d.toISOString().slice(0, 10); };

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE racuni, vracila, spori, admin_dejanja, omejitve, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, creator_applications, users RESTART IDENTITY CASCADE");
  const brezSprozilcev = new Client({ connectionString: DB });
  await brezSprozilcev.connect();
  await brezSprozilcev.query("SET session_replication_role = replica");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const A = zazeni(PORT, { ADMIN_NADZOR_PREDPOMNILNIK_MS: "0" });
  const B = zazeni(PORT_PRED, { ADMIN_NADZOR_PREDPOMNILNIK_MS: "3000" });
  const C = zazeni(PORT_PRIVZETO, {});
  const vsi = [A, B, C];
  for (const [p] of [[PORT], [PORT_PRED], [PORT_PRIVZETO]]) await cakajStreznik(p);

  try {
    assert(indexKoda.includes("const SQL_TESTNO_NAROCILO = `" + SQL_TESTNO_ZAPIS + "`;"), "test uporablja isti pogoj testnega naročila kot index.js (SQL_TESTNO_NAROCILO)");
    const T = {
      admin: zeton("admin@outly.si", uuid(1)), navaden: zeton("navaden@outly.si", uuid(2)), lastnik: zeton("lastnik@outly.si", uuid(3)), kopija: zeton("kopija@outly.si", uuid(4)),
    };
    for (const k of Object.keys(T)) { const r = await api(PORT, "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    await pool.query("UPDATE users SET role='backup' WHERE email='kopija@outly.si'");
    const kupecId = (await pool.query("SELECT id FROM users WHERE email='navaden@outly.si'")).rows[0].id;

    let moj = 100;
    const klub = async (ime, hidden = false) => {
      const n = moj++;
      const u = (await pool.query("INSERT INTO users (email, username, role) VALUES ($1, $2, 'business') RETURNING id", [`lastnik${n}@primer.si`, `lastnik${n}`])).rows[0].id;
      return (await pool.query("INSERT INTO clubs (owner_user_id, name, hidden) VALUES ($1, $2, $3) RETURNING id", [u, ime, hidden])).rows[0].id;
    };
    const K1 = await klub("Klub Eden"), K_SKRIT = await klub("Klub Skrit", true);
    const dogodek = async (klubId, naslov, polja = {}) => {
      const e = { status: "published", start: "-2 hours", end: "4 hours", price: 1500, capacity: 100, paused: false, open: null, close: null, ...polja };
      return (await pool.query(
        `INSERT INTO events (club_id, title, status, start_at, end_at, ticket_price_cents, capacity, sales_paused, poster_url, sales_open_at, sales_close_at)
         VALUES ($1, $2, $3, NOW() + $4::interval, CASE WHEN $5::text IS NULL THEN NULL ELSE NOW() + $5::interval END, $6, $7, $8, 'https://x.test/p.jpg',
                 CASE WHEN $9::text IS NULL THEN NULL ELSE NOW() + $9::interval END, CASE WHEN $10::text IS NULL THEN NULL ELSE NOW() + $10::interval END) RETURNING id`,
        [klubId, naslov, e.status, e.start, e.end, e.price, e.capacity, e.paused, e.open, e.close])).rows[0].id;
    };
    const E = {};
    E.tece = await dogodek(K1, "Tece zdaj");                                                   // v teku, prodaja nikoli ni bila ustavljena, a zacel se je -> zaprta
    E.pozneje = await dogodek(K1, "Zacne se kasneje", { start: "3 hours", end: "9 hours" });   // prodaja tece
    E.ustavljena = await dogodek(K1, "Ustavljena", { start: "20 hours", end: "26 hours", paused: true });
    E.razprodano = await dogodek(K1, "Razprodano", { start: "5 hours", end: "11 hours", capacity: 2 });
    E.zunanja = await dogodek(K1, "Zunanja prodaja", { start: "6 hours", end: "12 hours", price: null, capacity: null });
    E.okno = await dogodek(K1, "Okno prodaje zaprto", { start: "7 hours", end: "13 hours", close: "-1 hour" });
    E.kmalu23 = await dogodek(K1, "Cez 23 h 50 min", { start: "23 hours 50 minutes", end: "30 hours" });
    E.cez25 = await dogodek(K1, "Cez 25 h", { start: "25 hours", end: "30 hours" });
    E.cez3dni = await dogodek(K1, "Cez 3 dni", { start: "3 days", end: "3 days 6 hours", capacity: null });
    E.vceraj = await dogodek(K1, "Vceraj koncan", { start: "-20 hours", end: "-14 hours" });
    E.pred13h = await dogodek(K1, "Pred 13 h brez konca", { start: "-13 hours", end: null });
    E.vTeku = await dogodek(K1, "V teku od vceraj (do jutri)", { start: "-30 hours", end: "10 hours" });
    E.osnutek = await dogodek(K1, "Osnutek nocoj", { status: "draft" });
    E.skrit = await dogodek(K_SKRIT, "Skriti klub nocoj");
    await pool.query("UPDATE events SET sold_count = 40 WHERE id = $1", [E.tece]);
    await pool.query("UPDATE events SET sold_count = 2 WHERE id = $1", [E.razprodano]);

    // --- vstopnice (vstopi): na dogodku »tece« 5 vstopov (2 pred 3 min, 1 pred 14 min, 2 pred 20 min), 1 veljavna, 1 void; na »pozneje« en vstop pred 1 min ---
    let ref = 1;
    const narocilo = async (eventId, klubId, polja = {}) => {
      const o = { status: "paid", created: "0", qty: 1, price: 1500, pi: null, session: null, refunded: 0, listId: null, tableId: null, userId: kupecId, ...polja };
      return (await pool.query(
        `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, created_at, paid_at,
                             stripe_payment_intent_id, stripe_checkout_session_id, refunded_cents, guest_list_id, table_id, table_label, table_seats)
         VALUES ($1, $2, $3::int, $4::int, $5::int, $6::int, $5::int * $6::int, $7, 'kupec@primer.si', $8::timestamptz, $8::timestamptz, $9, $10, $11, $12, $13, $14, $15) RETURNING id`,
        ["OUT-DA-" + (ref++), o.userId, eventId, klubId, o.qty, o.price, o.status, o.created, o.pi, o.session, o.refunded, o.listId, o.tableId, o.tableId ? "M1" : null, o.tableId ? 4 : null])).rows[0].id;
    };
    const dalec = new Date(Date.now() - 40 * 864e5).toISOString();
    const nVstop = await narocilo(E.tece, K1, { qty: 8, created: dalec });
    const nVstop2 = await narocilo(E.pozneje, K1, { qty: 2, created: dalec });
    const vstopnica = (orderId, eventId, status, usedPred) => pool.query(
      `INSERT INTO tickets (order_id, event_id, status, used_at) VALUES ($1, $2, $3, CASE WHEN $4::text IS NULL THEN NULL ELSE NOW() - $4::interval END)`, [orderId, eventId, status, usedPred]);
    for (const m of ["3 minutes", "2 minutes", "14 minutes", "20 minutes", "40 minutes"]) await vstopnica(nVstop, E.tece, "used", m);
    await vstopnica(nVstop, E.tece, "valid", null); await vstopnica(nVstop, E.tece, "void", null);
    await vstopnica(nVstop2, E.pozneje, "used", "1 minute");
    await pool.query("UPDATE events SET sold_count = 40 WHERE id = $1", [E.tece]);

    // --- naročila glede na ljubljanski koledar (meje iz baze: isti izracun kot v strezniku, a neodvisno napisan) ---
    const lj = async (dniOdmik, interval) => (await pool.query(
      `SELECT (((date_trunc('day', NOW() AT TIME ZONE 'Europe/Ljubljana') + $1::interval) AT TIME ZONE 'Europe/Ljubljana') + $2::interval) AS t`, [dniOdmik, interval])).rows[0].t;
    const cDanes = await lj("0 days", "10 minutes");
    const cDanesKonec = await lj("1 day", "-1 minute");
    const cVceraj = await lj("0 days", "-1 minute");
    const cJutri = await lj("1 day", "1 minute");
    const c6 = await lj("-6 days", "1 hour");
    const c7 = await lj("-7 days", "23 hours");
    const listaId = (await pool.query("INSERT INTO guest_lists (event_id, host_user_id, spots) VALUES ($1, $2, 5) RETURNING id", [E.cez3dni, kupecId])).rows[0].id;
    const kupec = (polja) => narocilo(E.cez3dni, K1, polja);
    await kupec({ qty: 2, created: cDanes });                                                     // pravo, danes: 2 vstopnici, 3000
    await kupec({ qty: 1, created: cDanesKonec, status: "partially_refunded", refunded: 500 });   // delno vrnjeno, 23:59 danes: steje v celoti, 1500
    await kupec({ qty: 1, created: cDanes, status: "refunded", refunded: 1500 });                 // v celoti vrnjeno: ne steje
    await kupec({ qty: 1, created: cDanes, status: "cancelled" });
    await kupec({ qty: 1, created: cDanes, status: "failed" });
    await kupec({ qty: 1, created: cDanes, status: "pending" });
    await kupec({ qty: 1, price: 0, created: cDanes, listId: listaId, userId: kupecId });            // guest lista (total 0): ne steje nikamor
    await kupec({ qty: 3, created: cDanes, pi: "test_abcdef" });                                  // lazni nacin: testno, 4500
    await kupec({ qty: 1, created: cDanes, session: "cs_test_xyz", pi: "pi_sandbox" });          // Stripe sandbox: testno, 1500
    await kupec({ qty: 1, created: cDanes, pi: "pi_prava", session: "cs_live_prava" });           // pravo (live seja): danes 1500
    await kupec({ qty: 1, created: cVceraj });                                                   // vceraj 23:59: samo 7 dni
    await kupec({ qty: 1, created: c6 });                                                        // pred 6 dnevi: se v 7 dneh
    await kupec({ qty: 5, created: c7 });                                                        // pred 7 dnevi: izven
    await kupec({ qty: 1, created: cJutri });                                                    // jutri: nikjer
    await kupec({ qty: 1, created: cVceraj, pi: "test_vceraj" });                                // testno vceraj: nikjer (testno_danes je samo danes)
    // VIP miza danes: steje v narocila in bruto, ne v vstopnice
    const miza = (await pool.query("INSERT INTO club_tables (club_id, label, x, y, w, h, seats, price_cents) VALUES ($1, 'M1', 1, 1, 1, 1, 4, 2500) RETURNING id", [K1])).rows[0].id;
    await kupec({ qty: 1, price: 2500, created: cDanes, tableId: miza });
    // dogodka samo z VIP mizami (brez vstopnice): prodaja miz tece, ko se zacet - zaprta (ne »zaprta« zaradi manjkajoce cene vstopnice)
    E.vip = await dogodek(K1, "Samo VIP", { start: "8 hours", end: "14 hours", price: null, capacity: null });
    E.vipZacet = await dogodek(K1, "Samo VIP zacet", { start: "-1 hour", end: "5 hours", price: null, capacity: null });
    await pool.query("UPDATE events SET vip_enabled = TRUE WHERE id = ANY($1)", [[E.vip, E.vipZacet]]);
    // PRICAKOVANO: danes: 4 narocila (3000 + 1500 delno vrnjeno + 1500 live + 2500 miza); bruto 3000 + 1500 + 1500 + 2500 = 8500; vstopnice 2 + 1 + 1 = 4
    //              7 dni: + vceraj (1500, 1) + pred 6 dnevi (1500, 1) = 6 narocil; bruto 11500; vstopnice 6
    //              testno_danes: 2 narocili, 6000, 4 vstopnice

    // --- racuni ---
    const nR = [];
    for (let i = 0; i < 7; i++) nR.push(await narocilo(E.cez3dni, K1, { qty: 1, created: dalec }));
    const racun = async (orderId) => (await brezSprozilcev.query("INSERT INTO racuni (order_id, vrsta, znesek_cents) VALUES ($1, 'racun', 1500) RETURNING id", [orderId])).rows[0].id;
    const potrjen = (id, kdaj) => brezSprozilcev.query(
      `UPDATE racuni SET stanje = 'potrjen', eor = gen_random_uuid(), potrjen_at = NOW(), prostor = 'A001', naprava = '1', leto = 2026, stevilka = 5000 + id, izdan_at = $2::timestamptz WHERE id = $1`, [id, kdaj]);
    const r1 = await racun(nR[0]), r2 = await racun(nR[1]), r3 = await racun(nR[2]), r4 = await racun(nR[3]), r5 = await racun(nR[4]), r6 = await racun(nR[5]);
    await potrjen(r1, cDanes); await potrjen(r2, cDanesKonec); await potrjen(r3, cVceraj);       // izdana: danes 2, vceraj 1
    await brezSprozilcev.query("UPDATE racuni SET stanje = 'napaka' WHERE id = $1", [r4]);        // napaka 1
    // r5, r6: caka (2) + en racun cakajoc > 1 h za opozorila (ni pomembno za »danes«)
    await brezSprozilcev.query("UPDATE racuni SET created_at = NOW() - INTERVAL '2 hours' WHERE id = $1", [r5]);

    console.log("\n# Oblika in vloge");
    let r = await api(PORT, "/admin/api/danes", T.admin);
    assert(r.status === 200, "admin: 200", r.status);
    const d = r.body;
    assert(r.glave.get("cache-control") === "no-store", "Cache-Control: no-store");
    assert(JSON.stringify(Object.keys(d).sort()) === JSON.stringify(["cas", "nocoj", "opozorila_rdeca", "prodaja", "racuni"]), "najvisja polja: cas, prodaja, nocoj, racuni, opozorila_rdeca", Object.keys(d));
    assert(JSON.stringify(Object.keys(d.prodaja).sort()) === JSON.stringify(["danes", "dni7", "testno_danes"]), "prodaja: danes, dni7, testno_danes", Object.keys(d.prodaja));
    for (const k of ["danes", "dni7", "testno_danes"]) assert(JSON.stringify(Object.keys(d.prodaja[k]).sort()) === JSON.stringify(["bruto_cents", "narocila", "vstopnice"]) && Object.values(d.prodaja[k]).every(Number.isInteger), `prodaja.${k}: narocila, bruto_cents, vstopnice (cela stevila)`, d.prodaja[k]);
    assert(Math.abs(new Date(d.cas).getTime() - Date.now()) < 60000, "cas = zdaj (ISO)", d.cas);
    for (const [ime, t, status] of [["user", T.navaden, 403], ["business", T.lastnik, 403], ["backup", T.kopija, 403], ["brez zetona", null, 401]]) {
      const x = await api(PORT, "/admin/api/danes", t);
      assert(x.status === status, `${ime}: GET /admin/api/danes -> ${status}`, x.status);
    }

    console.log("\n# Prodaja: pravi in testni promet loceno");
    assert(JSON.stringify(d.prodaja.danes) === JSON.stringify({ narocila: 4, bruto_cents: 8500, vstopnice: 4 }), "danes (pravi): 4 narocila, 8500 c, 4 vstopnice (guest lista, vrnjeno, neplacano, jutri ne steje)", d.prodaja.danes);
    assert(JSON.stringify(d.prodaja.dni7) === JSON.stringify({ narocila: 6, bruto_cents: 11500, vstopnice: 6 }), "7 dni (pravi): 6 narocil, 11500 c, 6 vstopnic (pred 7 dnevi izven)", d.prodaja.dni7);
    assert(JSON.stringify(d.prodaja.testno_danes) === JSON.stringify({ narocila: 2, bruto_cents: 6000, vstopnice: 4 }), "testno danes: lazni nacin (test_) + Stripe sandbox (cs_test_): 2 narocili, 6000 c, 4 vstopnice", d.prodaja.testno_danes);
    assert(!JSON.stringify(d.prodaja.danes).includes("test"), "pravi promet brez testnega (loceno)");

    console.log("\n# Nocoj");
    const nocoj = d.nocoj;
    const idji = nocoj.map(e => e.id);
    // pred13h: zacetek pred 13 h, brez konca -> privzeto trajanje 12 h -> konec pred 1 h: izven; vTeku (zacel -30 h, konec +10 h): v teku -> noter
    const pricakovano = [E.vTeku, E.tece, E.pozneje, E.razprodano, E.zunanja, E.okno, E.ustavljena, E.kmalu23, E.vip, E.vipZacet];
    assert(JSON.stringify([...idji].sort((a, b) => a - b)) === JSON.stringify([...pricakovano].sort((a, b) => a - b)), "nocoj: natanko dogodki z oknom skena danes", { dobljeno: idji, pricakovano });
    assert(!idji.includes(E.cez25) && !idji.includes(E.cez3dni) && !idji.includes(E.vceraj) && !idji.includes(E.osnutek) && !idji.includes(E.skrit) && !idji.includes(E.pred13h), "izven: cez 25 h, cez 3 dni, vceraj koncan, osnutek, skriti klub, pred 13 h brez konca (12 h trajanje je mimo)");
    assert(JSON.stringify(idji) === JSON.stringify([...nocoj].sort((a, b) => new Date(a.start_at) - new Date(b.start_at)).map(e => e.id)), "razvrsceno po zacetku");
    assert(nocoj.every(e => JSON.stringify(Object.keys(e).sort()) === JSON.stringify(["id", "kapaciteta", "klub", "naslov", "prodaja", "prodano", "start_at", "vstopi", "vstopi_15min"])), "polja nocojsnjega dogodka natanko po dogovoru", Object.keys(nocoj[0] || {}));
    const po = (id) => nocoj.find(e => e.id === id);
    assert(po(E.tece).naslov === "Tece zdaj" && po(E.tece).klub === "Klub Eden" && po(E.tece).prodano === 40 && po(E.tece).kapaciteta === 100, "dogodek tece: naslov, klub, prodano 40, kapaciteta 100", po(E.tece));
    assert(po(E.tece).vstopi === 5 && po(E.tece).vstopi_15min === 3, "vstopi: 5 skupaj (veljavna in void ne), 3 v zadnjih 15 min (3, 2 in 14 min)", [po(E.tece).vstopi, po(E.tece).vstopi_15min]);
    assert(po(E.pozneje).vstopi === 1 && po(E.pozneje).vstopi_15min === 1 && po(E.vTeku).vstopi === 0 && po(E.vTeku).vstopi_15min === 0, "vstopi drugih dogodkov: 1/1 in 0/0");
    assert(po(E.tece).prodaja === "zaprta", "prodaja: zacet dogodek = zaprta", po(E.tece).prodaja);
    assert(po(E.pozneje).prodaja === "tece", "prodaja: prihajajoc dogodek s prodajo = tece", po(E.pozneje).prodaja);
    assert(po(E.ustavljena).prodaja === "ustavljena", "prodaja: sales_paused = ustavljena");
    assert(po(E.razprodano).prodaja === "razprodano", "prodaja: sold_count >= capacity = razprodano");
    assert(po(E.zunanja).prodaja === "zaprta" && po(E.zunanja).kapaciteta === null, "prodaja: brez cene (zunanja) = zaprta, kapaciteta null");
    assert(po(E.okno).prodaja === "zaprta", "prodaja: okno prodaje zaprto = zaprta");
    assert(po(E.vip).prodaja === "tece" && po(E.vipZacet).prodaja === "zaprta", "prodaja: dogodek samo z VIP mizami: tece (ne zaprta zaradi manjkajoce cene vstopnice); ko se zacne: zaprta", [po(E.vip).prodaja, po(E.vipZacet).prodaja]);
    assert(po(E.kmalu23).prodaja === "tece", "dogodek cez 23 h 50 min je se nocoj in tece");
    assert(po(E.tece).start_at === new Date(po(E.tece).start_at).toISOString(), "start_at je ISO");

    console.log("\n# Racuni in rdeca opozorila");
    assert(JSON.stringify(d.racuni) === JSON.stringify({ izdani_danes: 2, caka: 2, napaka: 1 }), "racuni: 2 izdana danes (vceraj ne), 2 cakata, 1 napaka", d.racuni);
    const op = await api(PORT, "/admin/api/opozorila", T.admin);
    assert(d.opozorila_rdeca === op.body.stevci.rdece && d.opozorila_rdeca >= 1, "opozorila_rdeca = rdeca opozorila iz /opozorila (vsaj racun v napaki)", [d.opozorila_rdeca, op.body.stevci.rdece]);
    assert(!r.text.includes("@") && !r.text.includes("kupec") && !r.text.includes("primer.si"), "odgovor brez e-naslovov in kupcev");

    console.log("\n# Samo branje");
    const pred = JSON.stringify((await pool.query("SELECT (SELECT COUNT(*) FROM events) e, (SELECT COUNT(*) FROM orders) o, (SELECT COUNT(*) FROM tickets) t, (SELECT COUNT(*) FROM racuni) r, (SELECT SUM(sold_count) FROM events) s")).rows[0]);
    for (let i = 0; i < 3; i++) await api(PORT, "/admin/api/danes", T.admin);
    const potem = JSON.stringify((await pool.query("SELECT (SELECT COUNT(*) FROM events) e, (SELECT COUNT(*) FROM orders) o, (SELECT COUNT(*) FROM tickets) t, (SELECT COUNT(*) FROM racuni) r, (SELECT SUM(sold_count) FROM events) s")).rows[0]);
    assert(pred === potem, "klici ne spremenijo baze", [pred, potem]);

    console.log("\n# Ljubljanski »danes« po neodvisnem izracunu (poletni in zimski cas, menjava ure)");
    // Narocila vsako uro (UTC) v letu 2031 (nikjer v ostalem testu): okoli menjave ure 30. 3. in 26. 10. ter navadnega poletja/zime.
    const ZAC_LETO = Date.UTC(2031, 0, 1);
    const obdobja = [[Date.UTC(2031, 2, 26), Date.UTC(2031, 3, 3)], [Date.UTC(2031, 9, 22), Date.UTC(2031, 9, 30)], [Date.UTC(2031, 6, 10), Date.UTC(2031, 6, 18)], [Date.UTC(2031, 0, 10), Date.UTC(2031, 0, 18)]];
    const vstavljeni = [];
    for (const [od, do_] of obdobja) for (let t = od; t < do_; t += 3600e3) vstavljeni.push(t);
    for (const dodatno of [Date.UTC(2031, 6, 15, 23, 30), Date.UTC(2031, 0, 15, 23, 30), Date.UTC(2031, 6, 15, 21, 59, 59), Date.UTC(2031, 6, 15, 22, 0, 0)]) if (!vstavljeni.includes(dodatno)) vstavljeni.push(dodatno);
    const eventLj = E.cez3dni;
    const vrstice = vstavljeni.map((t, i) => [`OUT-LJ-${i}`, new Date(t).toISOString()]);
    await brezSprozilcev.query(
      `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, created_at, paid_at)
       SELECT r.ref, NULL, $1, $2, 1, 1000, 1000, 'paid', 'lj@primer.si', r.t::timestamptz, r.t::timestamptz
         FROM unnest($3::text[], $4::text[]) AS r(ref, t)`, [eventLj, K1, vrstice.map(v => v[0]), vrstice.map(v => v[1])]);
    // Ker streznik uporablja uro baze, trenutke iz leta 2031 preizkusimo neposredno z isto funkcijo (admin_nadzor.danesNaCas) na isti bazi.
    const { ustvari } = require("../admin_nadzor");
    const usmerjevalnik = { get() {} };
    const nic = () => null;
    const modul = ustvari({ pool, router: usmerjevalnik, SQL_TESTNO_NAROCILO: SQL_TESTNO, razlogNerazpolozljivosti: nic, nacinPlacilaZ: nic, sqlKlubStripePripravljen: () => "NULL::boolean AS club_stripe_ready, NULL::jsonb AS club_seller_raw",
      VIP_OD_CENTOV: "NULL", odgovoriNaNapako: nic, env: { ADMIN_NADZOR_PREDPOMNILNIK_MS: "0" } });
    const vzorci = [
      Date.UTC(2031, 6, 16, 8, 0), Date.UTC(2031, 6, 15, 23, 30), Date.UTC(2031, 6, 15, 22, 0), Date.UTC(2031, 6, 15, 21, 59, 59), Date.UTC(2031, 0, 16, 8, 0), Date.UTC(2031, 0, 15, 23, 30), Date.UTC(2031, 0, 15, 23, 0), Date.UTC(2031, 0, 15, 22, 59, 59),
      Date.UTC(2031, 2, 29, 12, 0), Date.UTC(2031, 2, 30, 0, 30), Date.UTC(2031, 2, 29, 23, 0), Date.UTC(2031, 2, 30, 21, 59), Date.UTC(2031, 2, 30, 22, 0), Date.UTC(2031, 2, 31, 12, 0),
      Date.UTC(2031, 9, 25, 12, 0), Date.UTC(2031, 9, 25, 22, 0), Date.UTC(2031, 9, 26, 0, 30), Date.UTC(2031, 9, 26, 22, 59), Date.UTC(2031, 9, 26, 23, 0), Date.UTC(2031, 9, 27, 12, 0),
    ];
    let napacni = 0;
    for (const zdaj of vzorci) {
      const dan = ljDan(zdaj), od7 = danMinus(dan, 6);
      const pric = { danes: vstavljeni.filter(t => ljDan(t) === dan).length, dni7: vstavljeni.filter(t => ljDan(t) >= od7 && ljDan(t) <= dan).length };
      const izr = await modul.danesNaCas(new Date(zdaj));
      const dob = { danes: izr.prodaja.danes.narocila, dni7: izr.prodaja.dni7.narocila };
      const dobro = pric.danes === dob.danes && pric.dni7 === dob.dni7 && izr.prodaja.danes.bruto_cents === pric.danes * 1000 && izr.prodaja.dni7.bruto_cents === pric.dni7 * 1000
        && izr.prodaja.danes.vstopnice === pric.danes && new Date(izr.cas).getTime() === zdaj;
      if (!dobro) { napacni++; console.log("  ✗ zdaj", new Date(zdaj).toISOString(), "(Lj dan", dan + ")", "pricakovano", pric, "dobljeno", dob); }
    }
    assert(napacni === 0, `${vzorci.length} trenutkov (poletje, zima, menjava ure 30. 3. in 26. 10.): »danes« in »7 dni« se ujemata z Intl(Europe/Ljubljana)`);
    // izrecni primeri iz naloge: narocilo ob 23:30 UTC je ze naslednji dan v Ljubljani
    const iz1 = await modul.danesNaCas(new Date(Date.UTC(2031, 6, 15, 23, 30)));   // Lj: 16. 7. 01:30 (UTC+2)
    const iz2 = await modul.danesNaCas(new Date(Date.UTC(2031, 0, 15, 23, 30)));   // Lj: 16. 1. 00:30 (UTC+1)
    const iz3 = await modul.danesNaCas(new Date(Date.UTC(2031, 6, 15, 21, 59, 59))); // Lj: 15. 7. 23:59:59
    const dnevi = (iz) => iz.prodaja.danes.narocila;
    const stJul16 = vstavljeni.filter(t => ljDan(t) === "2031-07-16").length, stJan16 = vstavljeni.filter(t => ljDan(t) === "2031-01-16").length, stJul15 = vstavljeni.filter(t => ljDan(t) === "2031-07-15").length;
    assert(dnevi(iz1) === stJul16 && dnevi(iz2) === stJan16 && dnevi(iz3) === stJul15, "poleti 23:30 UTC = 16. 7.; pozimi 23:30 UTC = 16. 1.; 21:59:59 UTC poleti = se 15. 7. (UTC-dan bi dal drugace)", [dnevi(iz1), stJul16, dnevi(iz2), stJan16, dnevi(iz3), stJul15]);
    const meja = await modul.danesNaCas(new Date(Date.UTC(2031, 6, 15, 22, 0, 0)));   // 00:00 Lj 16. 7.
    assert(dnevi(meja) === stJul16, "natanko opolnoci po ljubljansko (22:00 UTC poleti) se dan zacne", [dnevi(meja), stJul16]);
    const dan23 = await modul.danesNaCas(new Date(Date.UTC(2031, 2, 30, 12, 0)));   // 30. 3. 2031: dan s 23 urami
    const dan25 = await modul.danesNaCas(new Date(Date.UTC(2031, 9, 26, 12, 0)));   // 26. 10. 2031: dan s 25 urami
    assert(dnevi(dan23) === 23 && dnevi(dan25) === 25, "dan menjave ure ima 23 oziroma 25 narocil (po eno na uro)", [dnevi(dan23), dnevi(dan25)]);

    console.log("\n# Predpomnilnik (trajanje 3 s; preverba po STANJU, ne po uri: ob pocasnem racunalniku se poskus ponovi)");
    const tokB = T.admin;
    const stDanes = (x) => x.body.prodaja.danes.narocila;
    const getB = (p) => api(PORT_PRED, p, tokB);
    // Svez izracun: pocakaj, da se `cas` spremeni (predpomnilnik je potekel in se je izracunalo na novo).
    async function svezDanes() {
      let prej = (await getB("/admin/api/danes")).body.cas;
      for (let i = 0; i < 80; i++) { await pocakaj(250); const r = await getB("/admin/api/danes"); if (r.body.cas !== prej) return r; prej = r.body.cas; }
      throw new Error("predpomnilnik danes ni potekel v 20 s");
    }
    let uspelo = false, osnova = 0;
    for (let poskus = 1; poskus <= 5 && !uspelo; poskus++) {
      const b1 = await svezDanes();                  // izracunano ravnokar: predpomnilnik velja ~3 s od razresitve
      const t0 = Date.now();
      await narocilo(E.cez3dni, K1, { qty: 1, created: cDanes });
      const b2 = await getB("/admin/api/danes");
      const socasni = await Promise.all([1, 2, 3, 4, 5].map(() => getB("/admin/api/danes")));
      if (Date.now() - t0 > 1500) { console.log(`  (poskus ${poskus}: pocasno racunalnik, ${Date.now() - t0} ms; ponavljam)`); continue; }
      uspelo = true; osnova = stDanes(b1);
      assert(b2.status === 200 && stDanes(b2) === stDanes(b1) && b2.body.cas === b1.body.cas, "predpomnilnik: drugi klic znotraj trajanja ne vidi novega narocila (isti cas)", [stDanes(b1), stDanes(b2)]);
      assert(socasni.every(x => x.body.cas === b1.body.cas && stDanes(x) === stDanes(b1)), "5 socasnih klicev = ista poizvedba (isti cas)");
    }
    assert(uspelo, "predpomnilnik: preverba uspela v 5 poskusih");
    let vidi = false;
    for (let i = 0; i < 80 && !vidi; i++) { const x = await getB("/admin/api/danes"); vidi = stDanes(x) > osnova; if (!vidi) await pocakaj(250); }
    assert(vidi, "po izteku predpomnilnika (stanje, ne ura) klic vidi novo narocilo");
    // opozorila: isti vzorec
    const stOp = async () => (await getB("/admin/api/opozorila")).body.items.length;
    let opUspelo = false, opOsnova = 0;
    for (let poskus = 1; poskus <= 5 && !opUspelo; poskus++) {
      await pocakaj(3300);                           // predpomnilnik (3 s od razresitve) je zagotovo potekel (daljse cakanje ne moti, krajse bi)
      const n1 = await stOp();                      // svez izracun (predpomnilnik je zagotovo potekel)
      const t0 = Date.now();
      await pool.query("INSERT INTO events (club_id, title, status, start_at, end_at, poster_url, ticket_price_cents, capacity) VALUES ($1, $2, 'published', NOW() + INTERVAL '2 days', NOW() + INTERVAL '3 days', '', 1000, 10)", [K1, "Brez plakata predpomnilnik " + poskus]);
      const n2 = await stOp();
      if (Date.now() - t0 > 1500) continue;
      opUspelo = true; opOsnova = n1;
      assert(n2 === n1, "opozorila: drugi klic znotraj trajanja je predpomnjen", [n1, n2]);
    }
    assert(opUspelo, "opozorila: preverba predpomnilnika uspela");
    let opVidi = false;
    for (let i = 0; i < 80 && !opVidi; i++) { opVidi = (await stOp()) > opOsnova; if (!opVidi) await pocakaj(250); }
    assert(opVidi, "opozorila: po izteku predpomnilnika (stanje, ne ura) klic vidi nov dogodek brez plakata");
    await pool.query("DELETE FROM events WHERE title LIKE 'Brez plakata predpomnilnik%'");
    // brez nastavljenega trajanja (privzeto 10 s): klica 2 s narazen sta ista poizvedba (ce racunalnik ni bil > 7 s pocasnejsi)
    const tC = Date.now();
    const c1 = await api(PORT_PRIVZETO, "/admin/api/danes", tokB);
    await pocakaj(2000);
    const c2 = await api(PORT_PRIVZETO, "/admin/api/danes", tokB);
    if (Date.now() - tC < 8000) assert(c2.body.cas === c1.body.cas, "privzeto trajanje predpomnilnika je daljse od 2 s (10 s)", [c1.body.cas, c2.body.cas]);
    else assert(true, "privzeto trajanje: preskoceno (racunalnik je bil prepocasen za casovno preverbo)");
    // brez predpomnilnika (strezniki A) vsak klic bere bazo
    const a1 = await api(PORT, "/admin/api/danes", T.admin);
    const a2 = await api(PORT, "/admin/api/danes", T.admin);
    assert(a1.body.cas !== a2.body.cas, "ADMIN_NADZOR_PREDPOMNILNIK_MS=0: brez predpomnilnika");

    console.log("\n# Zanesljivost: 57014 -> 503, vracanje povezave, semafor (najvec ena povezava)");
    const aktivne = async () => (await pool.query("SELECT COUNT(*)::int AS n FROM pg_stat_activity WHERE application_name = 'admin_nadzor'")).rows[0].n;
    const zakleni = async () => { const k = new Client({ connectionString: DB }); await k.connect(); await k.query("BEGIN"); await k.query("LOCK TABLE racuni IN ACCESS EXCLUSIVE MODE"); return k; };
    // 1. poizvedba obvisi na zaklepu (statement_timeout 2 s steje tudi cakanje na zaklep) -> 57014 -> 503 + Retry-After, povezava se vrne
    let kl = await zakleni();
    for (const pot of ["/admin/api/opozorila", "/admin/api/racuni", "/admin/api/danes"]) {
      const t0 = Date.now();
      const x = await api(PORT, pot, T.admin);
      const dt = Date.now() - t0;
      assert(x.status === 503 && x.body.error === "admin_busy" && x.glave.get("retry-after") === "5", `${pot}: poizvedba preseze 2 s -> 503 admin_busy + Retry-After 5`, [x.status, x.body, x.glave.get("retry-after")]);
      assert(dt >= 1800, `${pot}: 503 sele po statement_timeout (${dt} ms)`);
    }
    await kl.query("ROLLBACK"); await kl.end();
    await pocakaj(200);
    assert(await aktivne() === 0, "po 57014 ni odprte transakcije admin_nadzor (ROLLBACK, povezava vrnjena)");
    const povrnjeno = [];
    for (const pot of ["/admin/api/opozorila", "/admin/api/racuni", "/admin/api/danes", "/admin/api/summary"]) povrnjeno.push((await api(PORT, pot, T.admin)).status);
    assert(povrnjeno.every(c => c === 200), "po zaklepu vsi klici spet 200 (semafor in povezava sta sproscena)", povrnjeno);
    const zdravje = await api(PORT, "/healthz", null);
    assert(zdravje.status === 200, "/healthz 200 (pool ni izcrpan)", zdravje.status);
    // 2. semafor: hkratni /danes + /opozorila + /racuni + /summary, medtem ko prva poizvedba caka na zaklep: najvec ENA povezava admin_nadzor
    kl = await zakleni();
    let najvec = 0, videno = 0, tece = true;
    const vzorcevalec = (async () => { while (tece) { const n = await aktivne(); najvec = Math.max(najvec, n); if (n > 0) videno++; await pocakaj(15); } })();
    const poti = ["/admin/api/danes", "/admin/api/opozorila", "/admin/api/racuni", "/admin/api/racuni?stanje=caka", "/admin/api/summary", "/admin/api/opozorila"];
    const odgovori = Promise.all(poti.map(pot => api(PORT, pot, T.admin)));
    await pocakaj(700);
    await kl.query("ROLLBACK"); await kl.end();
    const izidi = await odgovori;
    tece = false; await vzorcevalec;
    assert(videno > 0, "vzorcevalec je videl povezavo admin_nadzor (preverba ni prazna)", videno);
    assert(najvec === 1, "semafor: v pg_stat_activity najvec ENA povezava admin_nadzor hkrati (6 vzporednih klicev)", najvec);
    assert(izidi.every(x => x.status === 200 || (x.status === 503 && x.body.error === "admin_busy")), "izidi: 200 ali 503 admin_busy", izidi.map(x => x.status));
    assert(izidi.filter(x => x.status === 200).length >= 3, "vsaj trije klici (summary in cakajoci po sprostitvi) uspejo", izidi.map(x => x.status));
    assert(await aktivne() === 0, "po koncu ni odprte transakcije admin_nadzor");
    // 3. cakajoci drugacen izracun: ce povezava ostane zasedena dlje kot 2 s, dobi 503 admin_busy + Retry-After (enota: lazen pool, ki nikoli ne odgovori)
    {
      const rute = {};
      const obesen = { connect: async () => ({ on() {}, off() {}, release() {}, query: () => new Promise(() => {}) }) };
      const modul3 = ustvari({ pool: obesen, router: { get: (p, h) => { rute[p] = h; } }, SQL_TESTNO_NAROCILO: SQL_TESTNO, razlogNerazpolozljivosti: () => null, nacinPlacilaZ: () => null,
        sqlKlubStripePripravljen: () => "NULL::boolean AS club_stripe_ready, NULL::jsonb AS club_seller_raw", VIP_OD_CENTOV: "NULL", odgovoriNaNapako: (res) => res.status(500).json({}), env: { ADMIN_NADZOR_PREDPOMNILNIK_MS: "0" } });
      const lazniRes = () => { const r = { glave: {}, kod: null, telo: null, set(k, v) { r.glave[String(k).toLowerCase()] = v; return r; }, status(c) { r.kod = c; return r; }, json(b) { r.telo = b; return r; } }; return r; };
      assert(typeof modul3.rdeceStevilo === "function" && modul3.rdeceStevilo() === null, "rdeceStevilo() brez izracuna je null (ne sprozi izracuna, ne caka)");
      void rute["/opozorila"]({ query: {} }, lazniRes());   // zasede edino povezavo in ne vrne nikoli
      await pocakaj(50);
      const r2 = lazniRes(), t1 = Date.now();
      await rute["/racuni"]({ query: {} }, r2);
      const dt1 = Date.now() - t1;
      assert(r2.kod === 503 && r2.telo.error === "admin_busy" && r2.glave["retry-after"] === "5" && dt1 >= 1800 && dt1 < 3500, "zaseden semafor: drugacen izracun po ~2 s dobi 503 admin_busy + Retry-After", [r2.kod, r2.telo, r2.glave, dt1]);
      const r3 = lazniRes(), t2 = Date.now();
      await rute["/danes"]({ query: {} }, r3);
      assert(r3.kod === 503 && r3.telo.error === "admin_busy" && Date.now() - t2 < 5500, "zaseden semafor: tudi /danes konca z 503 admin_busy (ne obvisi)", [r3.kod, Date.now() - t2]);
    }

    console.log("\n# Dnevnik streznika");
    for (const [ime, s] of [["A", A], ["B", B], ["C", C]]) {
      assert(!/TypeError|ReferenceError|Unhandled|error: /i.test(s.log), `dnevnik strezniika ${ime} brez napak`, s.log.split("\n").filter(l => /Error|Unhandled|error:/i.test(l)).slice(0, 3));
    }
  } catch (e) {
    fail++; console.log("  ✗ izjema:", e && e.stack || e);
  } finally {
    for (const s of vsi) s.proc.kill();
    jwksServer.close();
    await brezSprozilcev.end().catch(() => {});
    await pool.end().catch(() => {});
  }
  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  process.exit(fail ? 1 : 0);
})();
