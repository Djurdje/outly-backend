#!/usr/bin/env node
/**
 * Test "rezervacija mize po telefonu" (migracija 032, invarianta I13 razsirjena, DECISIONS 4. 10. 2026).
 * Zagon (lokalno, PG16, baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_rezervacija_telefon.js
 * Vzorec kot test_vip.js: lokalni JWKS, backend kot otrok proces na svojem portu (3129, drugi proces 3130, tretji 3131).
 * Pokriva: vloge (vratar 403, tuj klub 404), validacijo (ime 1-60, opomba 0-200), obliko odgovora (`hold` pri vsaki mizi),
 * 409 pri prodani/placilo-v-teku/ze rezervirani mizi, nakup rezervirane mize 409, javni GET (available false, NIKOLI imena gosta),
 * DELETE sprosti mizo (nakup spet 201, tudi ko je predpomnilnik "razprodano" pravkar zavrnil nakup), idempotenco (I18),
 * hkratnost (nakup + rezervacija iste mize -> natanko eden zmaga, vec krogov, en in dva procesa), pospravljanje starih
 * rezervacij, da rezervacija NI prodaja (GET /business/sales, /admin/api/finance), da ne nastanejo vstopnice.
 * Nakup (omejevalnik "nakup", 20/uro na IP) dobi pri vsakem klicu svoj naslov prek X-Forwarded-For (trust proxy 1).
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3129, PORT_B = 3130, PORT_C = 3131, JWKS_PORT = 3970;
const BASE = `http://127.0.0.1:${PORT}`;
const BASE_B = `http://127.0.0.1:${PORT_B}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-rez";
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
let ipStevec = 0;
const novIp = () => `10.30.${(++ipStevec >> 8) & 255}.${(ipStevec & 255) + 1}`;
async function apiNa(base, method, p, token, body, glave) {
  const r = await fetch(base + p, { method, headers: { "content-type": "application/json", "x-forwarded-for": novIp(), ...(token ? { authorization: "Bearer " + token } : {}), ...(glave || {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, besedilo: t, h: Object.fromEntries(r.headers) };
}
const api = (method, p, token, body, glave) => apiNa(BASE, method, p, token, body, glave);

const procesi = [];
let log = "";
async function zazeni(port, okolje = {}) {
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test", ...okolje }, stdio: ["ignore", "pipe", "pipe"] });
  srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 100; i++) { try { await fetch(`http://127.0.0.1:${port}/`); break; } catch { await new Promise(r => setTimeout(r, 100)); } }
  procesi.push(srv);
  return srv;
}
function ustavi(srv) { return new Promise(r => { if (srv.exitCode !== null) return r(); srv.once("exit", r); srv.kill(); }); }
const spi = (ms) => new Promise(r => setTimeout(r, ms));

(async () => {
  const pool = new Pool({ connectionString: DB });
  const TRUNC = "TRUNCATE omejitve, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE";
  await pool.query(TRUNC);
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srvA = await zazeni(PORT);
  const srvB = await zazeni(PORT_B);

  const KUPCEV = 10;
  const T = {
    lastnik: zeton("lastnik@outly.si", uuid(1)),
    manager: zeton("manager@outly.si", uuid(2)),
    doorman: zeton("doorman@outly.si", uuid(3)),
    ana: zeton("ana@outly.si", uuid(4)),
    drugi: zeton("drugi@outly.si", uuid(5)),
    admin: zeton("admin@outly.si", uuid(6)),
  };
  const kupci = Array.from({ length: KUPCEV }, (_, i) => zeton(`kupec${i}@outly.si`, uuid(100 + i)));
  for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
  for (const t of kupci) await api("GET", "/me", t);
  await pool.query("UPDATE users SET role='business' WHERE email IN ('lastnik@outly.si','drugi@outly.si')");
  await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
  // Miza s paketom pijace zahteva datum rojstva (>= 18, #102).
  await pool.query("UPDATE users SET date_of_birth = (CURRENT_DATE - INTERVAL '30 years')::date WHERE email IN ('ana@outly.si') OR email LIKE 'kupec%@outly.si'");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana')");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='drugi@outly.si'), 'Drugi Klub', 'Maribor')");
  await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, (SELECT id FROM users WHERE email='manager@outly.si'), 'manager')");
  await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, (SELECT id FROM users WHERE email='doorman@outly.si'), 'doorman')");
  const uid = async (email) => (await pool.query("SELECT id FROM users WHERE email=$1", [email])).rows[0].id;

  async function dogodek(klub, naslov, pomik, polja = {}) {
    const r = await pool.query(
      `INSERT INTO events (club_id, title, poster_url, start_at, end_at, status, ticket_price_cents, capacity, vip_enabled)
       VALUES ($1,$2,'https://example.com/p.jpg', NOW() + $3::interval, $4, 'published', 1500, 100, FALSE) RETURNING id`,
      [klub, naslov, pomik, polja.konec || null]);
    return r.rows[0].id;
  }
  let r;
  const PLAN = { width: 24, height: 16, elements: [{ type: "stage", x: 8, y: 0, w: 8, h: 3, label: "" }] };
  r = await api("PUT", "/business/vip", T.lastnik, { plan: PLAN, tables: [
    { label: "T1", x: 2, y: 5, w: 2, h: 2, shape: "round", seats: 6, price_cents: 30000 },
    { label: "T2", x: 6, y: 5, w: 3, h: 2, shape: "rect", seats: 4, price_cents: 20000 },
    { label: "T3", x: 12, y: 5, w: 2, h: 2, shape: "round", seats: 8, price_cents: 45000 },
    { label: "T4", x: 16, y: 5, w: 2, h: 2, shape: "round", seats: 2, price_cents: 10000 },
  ], packages: [{ name: "Jameson 0,7 l", description: "4x Red Bull" }] });
  assert(r.status === 200 && r.body.tables.length === 4, "klub nariše tloris (4 mize, 1 paket)", r.body);
  const [M1, M2, M3, M4] = r.body.tables.map(t => t.id);
  const P1 = r.body.packages[0].id;
  r = await api("PUT", "/business/vip", T.drugi, { plan: PLAN, tables: [{ label: "D1", x: 1, y: 1, w: 2, h: 2, shape: "round", seats: 4, price_cents: 15000 }], packages: [] });
  const MD = r.body.tables[0].id;

  const E1 = await dogodek(1, "Rezervacije", "2 days");
  const EOFF = await dogodek(1, "Brez VIP", "3 days");           // VIP na dogodku NI vklopljen
  const E2 = await dogodek(2, "Tuj dogodek", "2 days");
  for (const e of [E1]) { r = await api("PUT", `/business/events/${e}/vip`, T.lastnik, { enabled: true }); assert(r.status === 200, "VIP vklopljen na dogodku", r.body); }
  r = await api("PUT", `/business/events/${E2}/vip`, T.drugi, { enabled: true });

  const IME = "Janez Novak-Testenko";
  const pot = (e, m) => `/business/events/${e}/tables/${m}/hold`;
  const drzi = (tok, e, m, telo) => api("POST", pot(e, m), tok, telo);
  const nakup = (tok, e, m, telo, glave) => api("POST", `/events/${e}/tables/${m}/orders`, tok, telo === undefined ? { package_id: P1 } : telo, glave);
  const javno = async (e) => (await api("GET", `/events/${e}/vip`)).body;
  const stanje = async (e, tok = T.lastnik) => (await api("GET", `/business/events/${e}/vip`, tok)).body;
  const aktivnih = async (e, m) => (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1 AND table_id=$2 AND status IN ('pending','paid','partially_refunded')", [e, m])).rows[0].n;
  const rezervacij = async (e, m) => (await pool.query("SELECT COUNT(*)::int AS n FROM table_holds WHERE event_id=$1 AND table_id=$2", [e, m])).rows[0].n;

  console.log("\n# Brez zetona, vloge in tuji klubi (I5)");
  r = await drzi(null, E1, M1, { guest_name: IME });
  assert(r.status === 401, "POST hold brez zetona -> 401", r.status);
  r = await api("DELETE", pot(E1, M1), null);
  assert(r.status === 401, "DELETE hold brez zetona -> 401", r.status);
  r = await drzi(T.doorman, E1, M1, { guest_name: IME });
  assert(r.status === 403, "vratar ne more rezervirati -> 403", r.body);
  r = await drzi(T.ana, E1, M1, { guest_name: IME });
  assert(r.status === 403, "navaden uporabnik (ni clan kluba) -> 403", r.body);
  r = await drzi(T.drugi, E1, M1, { guest_name: IME });
  assert(r.status === 404, "lastnik drugega kluba na tujem dogodku -> 404", r.body);
  r = await drzi(T.lastnik, E2, M1, { guest_name: IME });
  assert(r.status === 404, "lastnik na dogodku drugega kluba -> 404", r.body);
  r = await drzi(T.lastnik, E1, MD, { guest_name: IME });
  assert(r.status === 404, "miza drugega kluba -> 404", r.body);
  r = await drzi(T.lastnik, E1, 999999, { guest_name: IME });
  assert(r.status === 404, "miza ne obstaja -> 404", r.body);
  r = await drzi(T.lastnik, 999999, M1, { guest_name: IME });
  assert(r.status === 404, "dogodek ne obstaja -> 404", r.body);
  r = await drzi(T.admin, E1, M1, { guest_name: IME });
  assert(r.status === 404, "admin brez kluba -> 404 (kot ostale poslovne poti)", r.body);
  assert(await rezervacij(E1, M1) === 0, "nobena zavrnjena zahteva ni pustila rezervacije");
  await pool.query("INSERT INTO table_holds (event_id, table_id, guest_name) VALUES ($1,$2,'Tuji')", [E1, M2]);
  r = await api("DELETE", pot(E1, M2), T.doorman);
  assert(r.status === 403, "vratar ne more preklicati -> 403", r.body);
  r = await api("DELETE", pot(E1, M2), T.drugi);
  assert(r.status === 404, "DELETE: lastnik drugega kluba -> 404", r.body);
  assert(await rezervacij(E1, M2) === 1, "tuj klub rezervacije ni pobrisal");
  await pool.query("DELETE FROM table_holds");

  console.log("\n# Validacija: id-ji, ime gosta (1-60), opomba (0-200)");
  for (const [e, m, ime] of [["abc", M1, "id dogodka niz"], [E1, "abc", "id mize niz"], [0, M1, "id dogodka 0"], [E1, -1, "id mize negativen"], [E1, "99999999999", "id mize izven int4"]]) {
    r = await drzi(T.lastnik, e, m, { guest_name: IME });
    assert(r.status === 400, `${ime} -> 400`, [r.status, r.body]);
  }
  const slabi = [
    ["brez telesa", undefined], ["guest_name manjka", {}], ["guest_name prazen", { guest_name: "" }], ["guest_name samo presledki", { guest_name: "   " }],
    ["guest_name 61 znakov", { guest_name: "x".repeat(61) }], ["guest_name stevilo", { guest_name: 5 }], ["guest_name null", { guest_name: null }],
    ["guest_name seznam", { guest_name: ["a"] }], ["guest_name z nadzornim znakom (NUL)", { guest_name: "A\u0000B" }],
    ["opomba 201 znakov", { guest_name: "A", note: "x".repeat(201) }], ["opomba stevilo", { guest_name: "A", note: 5 }], ["opomba z NUL", { guest_name: "A", note: "a\u0000" }],
    ["opomba objekt", { guest_name: "A", note: {} }],
    ["guest_name samo nevidni znaki (U+200B, U+200D, U+2060, U+FEFF)", { guest_name: "\u200b\u200d\u2060\ufeff" }],
    ["guest_name presledki in nevidni znaki", { guest_name: " \u200b \u200c " }],
    ["guest_name 61 kodnih tock (emoji)", { guest_name: "😀".repeat(61) }],
    ["opomba 201 kodnih tock (emoji)", { guest_name: "A", note: "😀".repeat(201) }],
  ];
  for (const [opis, telo] of slabi) {
    r = await drzi(T.lastnik, E1, M1, telo);
    assert(r.status === 400 && typeof r.body === "string" && r.body.length > 3, `${opis} -> 400 z berljivim sporocilom`, [r.status, r.body]);
  }
  assert(await rezervacij(E1, M1) === 0, "zavrnjeni vhodi ne pustijo rezervacije v bazi");

  console.log("\n# Uspesna rezervacija: oblika odgovora (celoten vipDogodkaOdgovor + hold pri vsaki mizi)");
  r = await drzi(T.manager, E1, M1, { guest_name: "  " + IME + "  ", note: "  pride ob 23h, 6 oseb  " });
  assert(r.status === 201, "manager rezervira M1 -> 201", r.body);
  const odg = r.body;
  assert(odg.event_id === E1 && odg.enabled === true && odg.currency === "EUR" && Array.isArray(odg.tables) && odg.tables.length === 4 && Array.isArray(odg.packages) && odg.plan, "odgovor ima obliko GET /business/events/:id/vip", Object.keys(odg));
  const h1 = odg.tables.find(t => t.id === M1).hold;
  assert(h1 && h1.guest_name === IME && h1.note === "pride ob 23h, 6 oseb" && typeof h1.created_at === "string" && !isNaN(Date.parse(h1.created_at)) && Object.keys(h1).sort().join() === "created_at,guest_name,note", "hold: ime in opomba obrezana, created_at ISO, tocno tri polja", h1);
  assert(odg.tables.filter(t => t.id !== M1).every(t => t.hold === null && "hold" in t), "ostale mize imajo hold: null (polje je vedno prisotno)", odg.tables.map(t => t.hold));
  assert(odg.tables.find(t => t.id === M1).booking === null, "rezervacija po telefonu NI booking (booking je samo narocilo prek Outly)", odg.tables.find(t => t.id === M1).booking);
  const gOdg = await stanje(E1);
  assert(JSON.stringify(gOdg) === JSON.stringify(odg), "POST odgovor == GET /business/events/:id/vip", gOdg);
  const vr = await stanje(E1, T.doorman);
  assert(vr.tables.find(t => t.id === M1).hold && vr.tables.find(t => t.id === M1).hold.guest_name === IME, "vratar (GET, vse vloge) vidi rezervacijo z imenom", vr.tables.find(t => t.id === M1).hold);
  const vrm = await stanje(E1, T.manager);
  assert(JSON.stringify(vrm) === JSON.stringify(odg), "manager vidi isto", null);
  const vb = await pool.query("SELECT created_by_user_id, guest_name, note FROM table_holds WHERE event_id=$1 AND table_id=$2", [E1, M1]);
  assert(vb.rows.length === 1 && vb.rows[0].created_by_user_id === await uid("manager@outly.si"), "v bazi: 1 vrstica, created_by = manager", vb.rows);
  r = await drzi(T.lastnik, E1, M4, { guest_name: "A", note: "" });
  assert(r.status === 201 && r.body.tables.find(t => t.id === M4).hold.note === null, "prazna opomba -> note: null", r.body.tables.find(t => t.id === M4).hold);
  r = await drzi(T.lastnik, E1, M2, { guest_name: "Š".repeat(60) });
  assert(r.status === 201 && r.body.tables.find(t => t.id === M2).hold.guest_name.length === 60, "ime z 60 znaki (sumniki) -> 201", r.status);
  await api("DELETE", pot(E1, M2), T.lastnik);
  await api("DELETE", pot(E1, M4), T.lastnik);
  r = await drzi(T.lastnik, E1, M4, { guest_name: "😀".repeat(60), note: "😀".repeat(200) });
  assert(r.status === 201 && [...r.body.tables.find(t => t.id === M4).hold.guest_name].length === 60 && [...r.body.tables.find(t => t.id === M4).hold.note].length === 200, "60 emoji v imenu in 200 emoji v opombi (dolzina v znakih, ne v enotah UTF-16) -> 201", r.status);
  await api("DELETE", pot(E1, M4), T.lastnik);
  r = await drzi(T.lastnik, E1, M4, { guest_name: "A\u200bB\u200d C\ufeff", note: "\u200b\u200b" });
  const hZw = r.body.tables && r.body.tables.find(t => t.id === M4).hold;
  assert(r.status === 201 && hZw && hZw.guest_name === "AB C" && hZw.note === null, "nevidni znaki se odstranijo (ime »AB C«, opomba samo iz nevidnih = null)", hZw);
  await api("DELETE", pot(E1, M4), T.lastnik);

  console.log("\n# Koncan dogodek: rezervacija ni mogoca (isti izraz kot »ended« drugje: end_at, sicer start_at + 8 h)");
  const EKON1 = (await pool.query("INSERT INTO events (club_id,title,poster_url,start_at,status) VALUES (1,'Koncan A','https://example.com/p.jpg', NOW() - INTERVAL '10 hours','published') RETURNING id")).rows[0].id;
  const EKON2 = (await pool.query("INSERT INTO events (club_id,title,poster_url,start_at,end_at,status) VALUES (1,'Koncan B','https://example.com/p.jpg', NOW() - INTERVAL '10 hours', NOW() - INTERVAL '1 hour','published') RETURNING id")).rows[0].id;
  const ETECE1 = (await pool.query("INSERT INTO events (club_id,title,poster_url,start_at,status) VALUES (1,'Tece A','https://example.com/p.jpg', NOW() - INTERVAL '3 hours','published') RETURNING id")).rows[0].id;
  const ETECE2 = (await pool.query("INSERT INTO events (club_id,title,poster_url,start_at,end_at,status) VALUES (1,'Tece B','https://example.com/p.jpg', NOW() - INTERVAL '10 hours', NOW() + INTERVAL '1 hour','published') RETURNING id")).rows[0].id;
  for (const [e, ime] of [[EKON1, "brez end_at, zacetek pred 10 h"], [EKON2, "end_at pred 1 h"]]) {
    r = await drzi(T.lastnik, e, M1, { guest_name: "Prepozni gost" });
    assert(r.status === 409 && r.body === "This event has already ended.", `koncan dogodek (${ime}) -> 409 »This event has already ended.«`, [r.status, r.body]);
    assert(await rezervacij(e, M1) === 0, "  ime se ni shranilo");
  }
  for (const [e, ime] of [[ETECE1, "zacel pred 3 h, brez end_at"], [ETECE2, "end_at cez 1 h"]]) {
    r = await drzi(T.lastnik, e, M1, { guest_name: "Nocni gost" });
    assert(r.status === 201, `dogodek, ki tece (${ime}) -> 201`, [r.status, r.body]);
  }

  console.log("\n# 409: ze rezervirana, prodana, placilo v teku; dovoljeno po preklicu");
  r = await drzi(T.lastnik, E1, M1, { guest_name: "Drug gost" });
  assert(r.status === 409 && r.body === "This table is already booked.", "druga rezervacija iste mize -> 409 »This table is already booked.«", [r.status, r.body]);
  assert((await pool.query("SELECT guest_name FROM table_holds WHERE event_id=$1 AND table_id=$2", [E1, M1])).rows[0].guest_name === IME, "prva rezervacija ostane nespremenjena");
  r = await nakup(T.ana, E1, M3);
  assert(r.status === 201, "ana kupi M3 prek Outly -> 201", r.body);
  const narociloM3 = r.body.order.id;
  const stVstopnicPred = (await pool.query("SELECT COUNT(*)::int AS n FROM tickets")).rows[0].n;
  r = await drzi(T.lastnik, E1, M3, { guest_name: "Gost" });
  assert(r.status === 409 && r.body === "This table is already booked.", "rezervacija placane (prodane) mize -> 409", [r.status, r.body]);
  await pool.query("UPDATE orders SET status='pending' WHERE id=$1", [narociloM3]);
  r = await drzi(T.lastnik, E1, M3, { guest_name: "Gost" });
  assert(r.status === 409, "rezervacija mize s cakajocim (pending) narocilom -> 409", r.body);
  await pool.query("UPDATE orders SET status='partially_refunded' WHERE id=$1", [narociloM3]);
  r = await drzi(T.lastnik, E1, M3, { guest_name: "Gost" });
  assert(r.status === 409, "rezervacija mize z delno vrnjenim narocilom -> 409", r.body);
  await pool.query("UPDATE orders SET status='cancelled', cancelled_at=NOW() WHERE id=$1", [narociloM3]);
  r = await drzi(T.lastnik, E1, M3, { guest_name: "Gost po preklicu" });
  assert(r.status === 201 && r.body.tables.find(t => t.id === M3).hold.guest_name === "Gost po preklicu", "po preklicu narocila je rezervacija mogoca -> 201", r.body);
  assert((await pool.query("SELECT COUNT(*)::int AS n FROM tickets")).rows[0].n === stVstopnicPred, "rezervacija ne ustvari vstopnic (sken se ne spremeni)");
  await api("DELETE", pot(E1, M3), T.lastnik);

  console.log("\n# Nakup rezervirane mize -> 409 (isto sporocilo); javni pogled: Booked, brez imena gosta");
  const stNarocil = (await pool.query("SELECT COUNT(*)::int AS n FROM orders")).rows[0].n;
  r = await nakup(kupci[0], E1, M1);
  assert(r.status === 409 && r.body === "This table is already booked.", "nakup rezervirane mize -> 409 »This table is already booked.«", [r.status, r.body]);
  assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders")).rows[0].n === stNarocil, "zavrnjen nakup ne pusti narocila");
  assert(!r.besedilo.includes("Janez"), "409 ne vsebuje imena gosta", r.besedilo);
  r = await nakup(kupci[0], E1, M1, { package_id: P1, expected_price_cents: 30000 });
  assert(r.status === 409 && r.body === "This table is already booked.", "isto z expected_price_cents (predpomnilnik »razprodano« → ista pot) -> 409", r.body);
  let jv = await javno(E1);
  const jM1 = jv.tables.find(t => t.id === M1);
  assert(jM1 && jM1.available === false, "javni GET: rezervirana miza available: false", jM1);
  assert(jv.tables.filter(t => t.id !== M1).every(t => t.available === true), "javni GET: ostale mize proste", jv.tables.map(t => [t.id, t.available]));
  assert(Object.keys(jM1).sort().join() === "available,h,id,label,price_cents,seats,shape,w,x,y", "javna miza: ista polja kot prej (brez hold/ime)", Object.keys(jM1));
  const javnePoti = [`/events/${E1}/vip`, `/events/${E1}`, "/events?upcoming=true", "/events", "/clubs/1", "/clubs"];
  for (const p of javnePoti) {
    const j = await api("GET", p);
    assert(j.status === 200 && !j.besedilo.includes("Janez") && !j.besedilo.includes("Testenko") && !j.besedilo.includes("pride ob 23h") && !/guest_name|"hold"/.test(j.besedilo), `javno ${p}: nobenega imena gosta, opombe ali polja hold`, j.status);
  }
  const jPrijavljen = await api("GET", `/events/${E1}/vip`, kupci[1]);
  assert(!jPrijavljen.besedilo.includes("Janez") && !/"hold"|guest_name/.test(jPrijavljen.besedilo), "tudi prijavljen kupec ne vidi imena gosta (GET /events/:id/vip)", null);
  for (const p of ["/me/orders", "/me/tickets"]) {
    const j = await api("GET", p, T.ana);
    assert(j.status === 200 && !j.besedilo.includes("Janez") && !/guest_name/.test(j.besedilo), `kupec: ${p} brez imena gosta`, j.status);
  }

  for (const p of [`/business/events/${E1}/scan-list`, `/business/events/${E1}/tickets`, "/business/scan-key"]) {
    for (const [kdo, tok] of [["vratar", T.doorman], ["lastnik", T.lastnik]]) {
      const j = await api("GET", p, tok);
      assert(j.status === 200 && !/Janez|Testenko|pride ob 23h|guest_name/.test(j.besedilo), `${kdo}: ${p.replace(String(E1), ":id")} ne vsebuje imena gosta ali opombe`, j.status);
    }
  }

  console.log("\n# Izklopljena miza / VIP na dogodku ni vklopljen: rezervacija dovoljena");
  r = await api("PUT", `/business/events/${E1}/vip`, T.lastnik, { enabled: true, tables: [{ table_id: M2, disabled: true }] });
  assert(r.status === 200, "M2 izklopljena na dogodku", r.status);
  jv = await javno(E1);
  assert(!jv.tables.some(t => t.id === M2), "izklopljena miza brez rezervacije je javno skrita", jv.tables.map(t => t.id));
  r = await drzi(T.lastnik, E1, M2, { guest_name: "Gost na izklopljeni" });
  assert(r.status === 201 && r.body.tables.find(t => t.id === M2).disabled === true && r.body.tables.find(t => t.id === M2).hold, "rezervacija izklopljene mize -> 201 (disabled ostane true)", r.body.tables.find(t => t.id === M2));
  jv = await javno(E1);
  const jM2 = jv.tables.find(t => t.id === M2);
  assert(jM2 && jM2.available === false, "izklopljena miza z rezervacijo se javno pokaze kot zasedena (kot prodana)", jM2);
  r = await nakup(kupci[0], E1, M2);
  assert(r.status === 404 || r.status === 409, "nakup izklopljene mize ostane zavrnjen", [r.status, r.body]);
  r = await drzi(T.lastnik, EOFF, M1, { guest_name: "Gost, VIP ni vklopljen" });
  assert(r.status === 201 && r.body.enabled === false && r.body.tables.find(t => t.id === M1).hold, "VIP na dogodku NI vklopljen: rezervacija -> 201, enabled false", [r.status, r.body.enabled]);
  jv = await javno(EOFF);
  assert(jv.enabled === false && jv.tables.length === 0 && !JSON.stringify(jv).includes("Gost"), "javno: dogodek brez VIP ostane brez miz in brez imena", jv);
  // Arhivirana miza: rezervacija -> 404 (miza ni vec del tlorisa).
  r = await api("GET", "/business/vip", T.lastnik);
  const sk = r.body;
  await api("PUT", "/business/vip", T.lastnik, { plan: sk.plan, tables: sk.tables.filter(t => t.id !== M4), packages: sk.packages });
  r = await drzi(T.lastnik, E1, M4, { guest_name: "Gost" });
  assert(r.status === 404, "arhivirana miza -> 404", r.body);
  await api("PUT", "/business/vip", T.lastnik, { plan: sk.plan, tables: sk.tables.map(t => t.id === M4 ? { ...t, id: undefined } : t), packages: sk.packages });
  const M4n = (await pool.query("SELECT id FROM club_tables WHERE club_id=1 AND archived_at IS NULL AND label='T4'")).rows[0].id;
  await api("DELETE", pot(EOFF, M1), T.lastnik);
  await api("DELETE", pot(E1, M2), T.lastnik);
  await api("PUT", `/business/events/${E1}/vip`, T.lastnik, { enabled: true, tables: [{ table_id: M2, disabled: false }] });

  console.log("\n# DELETE: sprosti mizo (nakup spet 201), 404 ce rezervacije ni");
  r = await api("DELETE", pot(E1, M1), T.manager);
  assert(r.status === 200 && r.body.tables.find(t => t.id === M1).hold === null && r.body.tables.length >= 4, "manager prekliče → 200 + vipDogodkaOdgovor, hold: null", r.body.tables && r.body.tables.find(t => t.id === M1));
  assert(JSON.stringify(r.body) === JSON.stringify(await stanje(E1)), "DELETE odgovor == GET stanje", null);
  r = await api("DELETE", pot(E1, M1), T.lastnik);
  assert(r.status === 404, "ponoven DELETE (rezervacije ni) -> 404", r.body);
  r = await api("DELETE", pot(E1, M4n), T.lastnik);
  assert(r.status === 404, "DELETE mize brez rezervacije -> 404", r.body);
  r = await api("DELETE", pot(999999, M1), T.lastnik);
  assert(r.status === 404, "DELETE na dogodku, ki ne obstaja -> 404", r.body);
  r = await api("DELETE", pot(E1, "abc"), T.lastnik);
  assert(r.status === 400, "DELETE z neveljavnim id mize -> 400", r.body);
  jv = await javno(E1);
  assert(jv.tables.find(t => t.id === M1).available === true, "javno: miza po preklicu spet available: true", jv.tables.find(t => t.id === M1));
  // Predpomnilnik »razprodano« je pravkar zavrnil nakup (409); po DELETE-u mora nakup takoj uspeti.
  r = await drzi(T.lastnik, E1, M1, { guest_name: "Spet gost" });
  assert(r.status === 201, "ponovna rezervacija po preklicu -> 201", r.status);
  r = await nakup(kupci[2], E1, M1);
  assert(r.status === 409, "nakup rezervirane mize (oznaci »razprodano« v pomnilniku)", r.status);
  r = await api("DELETE", pot(E1, M1), T.lastnik);
  r = await nakup(kupci[2], E1, M1);
  assert(r.status === 201 && r.body.order.table_label === "T1", "TAKOJ po DELETE-u nakup 201 (pomnilniski »razprodano« je pozabljen)", [r.status, r.body]);
  r = await drzi(T.lastnik, E1, M1, { guest_name: "Prepozno" });
  assert(r.status === 409, "po nakupu je rezervacija spet 409", r.body);

  console.log("\n# I18: idempotentni ponovni nakup in rezervacija");
  const K1 = crypto.randomUUID();
  r = await nakup(kupci[3], E1, M4n, { package_id: P1 }, { "Idempotency-Key": K1 });
  assert(r.status === 201, "nakup M4 s kljucem -> 201", r.body);
  const idNar = r.body.order.id;
  r = await drzi(T.lastnik, E1, M4n, { guest_name: "Gost" });
  assert(r.status === 409, "rezervacija kupljene mize -> 409", r.body);
  r = await nakup(kupci[3], E1, M4n, { package_id: P1 }, { "Idempotency-Key": K1 });
  assert(r.status === 201 && r.h["idempotent-replayed"] === "true" && r.body.order.id === idNar, "ponovitev istega nakupa se vedno 201 + Idempotent-Replayed, isto narocilo", [r.status, r.h["idempotent-replayed"]]);
  // Zavrnitev zaradi rezervacije se NE zapomni: po preklicu rezervacije isti kljuc uspe.
  const K2 = crypto.randomUUID();
  await drzi(T.lastnik, E1, M2, { guest_name: "Gost M2" });
  r = await nakup(kupci[4], E1, M2, { package_id: P1 }, { "Idempotency-Key": K2 });
  assert(r.status === 409 && r.body === "This table is already booked.", "nakup rezervirane mize s kljucem -> 409", [r.status, r.body]);
  await api("DELETE", pot(E1, M2), T.lastnik);
  r = await nakup(kupci[4], E1, M2, { package_id: P1 }, { "Idempotency-Key": K2 });
  assert(r.status === 201, "po preklicu rezervacije isti kljuc → 201 (neuspeh se ne zapomni)", [r.status, r.body]);
  assert(await aktivnih(E1, M2) === 1 && await rezervacij(E1, M2) === 0, "M2: 1 narocilo, 0 rezervacij");

  console.log("\n# Prodaja: rezervacije po telefonu NISO prodaja (GET /business/sales, /admin/api/finance)");
  const E3 = await dogodek(1, "Prodaja brez rezervacij", "4 days");
  await api("PUT", `/business/events/${E3}/vip`, T.lastnik, { enabled: true });
  const prodajaPred = await api("GET", "/business/sales", T.lastnik);
  const financePred = await api("GET", "/admin/api/finance", T.admin);
  assert(prodajaPred.status === 200 && financePred.status === 200, "sales in finance dosegljiva", [prodajaPred.status, financePred.status]);
  for (const m of [M1, M2, M3]) await drzi(T.lastnik, E3, m, { guest_name: "Gost " + m });
  assert(await rezervacij(E3, M1) + await rezervacij(E3, M2) + await rezervacij(E3, M3) === 3, "na E3 so 3 rezervacije");
  const prodajaPo = await api("GET", "/business/sales", T.lastnik);
  const financePo = await api("GET", "/admin/api/finance", T.admin);
  assert(JSON.stringify(prodajaPo.body) === JSON.stringify(prodajaPred.body), "GET /business/sales je po 3 rezervacijah BAJT ZA BAJTOM enak (ne tables_sold, ne gross, ne orders)", [prodajaPred.body.summary, prodajaPo.body.summary]);
  assert(JSON.stringify(financePo.body) === JSON.stringify(financePred.body), "GET /admin/api/finance je po rezervacijah enak", null);
  assert(!prodajaPo.besedilo.includes("Gost ") && !financePo.besedilo.includes("Gost "), "prodaja in finance ne vsebujeta imen gostov", null);

  console.log("\n# Cascade: brisanje dogodka pobrise rezervacije; brisanje uporabnika ohrani rezervacijo");
  const E4 = await dogodek(1, "Za brisanje", "6 days");
  await api("PUT", `/business/events/${E4}/vip`, T.lastnik, { enabled: true });
  await drzi(T.manager, E4, M1, { guest_name: "Gost cascade" });
  const mUid = await uid("manager@outly.si");
  await pool.query("DELETE FROM club_members WHERE user_id=$1", [mUid]);
  await pool.query("DELETE FROM users WHERE id=$1", [mUid]);
  const ostalo = await pool.query("SELECT created_by_user_id FROM table_holds WHERE event_id=$1", [E4]);
  assert(ostalo.rows.length === 1 && ostalo.rows[0].created_by_user_id === null, "brisanje avtorja: rezervacija ostane, created_by_user_id = NULL (SET NULL)", ostalo.rows);
  await pool.query("DELETE FROM events WHERE id=$1", [E4]);
  assert(await rezervacij(E4, M1) === 0, "brisanje dogodka pobrise njegove rezervacije (ON DELETE CASCADE)");
  let napaka23505 = null;
  try { await pool.query("INSERT INTO table_holds (event_id, table_id, guest_name) VALUES ($1,$2,'a'),($1,$2,'b')", [E1, M3]); } catch (e) { napaka23505 = e; }
  assert(napaka23505 && napaka23505.code === "23505", "baza sama zavrne dvojno rezervacijo (UNIQUE event_id, table_id)", napaka23505 && napaka23505.code);
  let napakaIme = null;
  try { await pool.query("INSERT INTO table_holds (event_id, table_id, guest_name) VALUES ($1,$2,'')", [E1, M3]); } catch (e) { napakaIme = e; }
  assert(napakaIme && napakaIme.code === "23514", "baza zavrne prazno ime gosta (CHECK)", napakaIme && napakaIme.code);
  await pool.query("DELETE FROM table_holds");

  console.log("\n# I13 razsirjena: hkratni nakupi + rezervacija iste mize -> natanko en zmagovalec");
  const KROGOV = 14;
  const zmagovalci = { nakup: 0, rezervacija: 0 };
  for (let k = 0; k < KROGOV; k++) {
    const dvaProcesa = k % 2 === 1;
    const E = await dogodek(1, "Tekma " + k, "9 days");
    await api("PUT", `/business/events/${E}/vip`, T.lastnik, { enabled: true });
    const mize = [M1, M3];
    const m = mize[k % 2];
    const holdPos = k % (KUPCEV + 1);                 // kje v vrsti zahtevkov je rezervacija
    const zamik = [0, 0, 2, 5][k % 4];               // ms zamika rezervacije (variiranje prekrivanja)
    const delo = [];
    for (let i = 0; i < KUPCEV; i++) {
      delo.push(() => apiNa(dvaProcesa && i % 2 ? BASE_B : BASE, "POST", `/events/${E}/tables/${m}/orders`, kupci[i], { package_id: P1 }));
    }
    delo.splice(holdPos, 0, async () => { if (zamik) await spi(zamik); return apiNa(dvaProcesa ? BASE_B : BASE, "POST", pot(E, m), T.lastnik, { guest_name: "Gost krog " + k, note: "zasebna-opomba-krog" }); });
    const rez = await Promise.all(delo.map(f => f()));
    const hRez = rez[holdPos];
    const nRez = rez.filter((_, i) => i !== holdPos);
    const zmag = rez.filter(x => x.status === 201).length;
    const d409 = rez.filter(x => x.status === 409).length;
    const aktiv = await aktivnih(E, m), hold = await rezervacij(E, m);
    assert(zmag === 1 && d409 === KUPCEV && aktiv + hold === 1,
      `krog ${k + 1}/${KROGOV} (${dvaProcesa ? "2 procesa" : "1 proces"}, hold #${holdPos}, zamik ${zamik} ms): natanko 1 zmagovalec, ostali 409; v bazi narocil+rezervacij = 1`,
      { statusi: rez.map(x => x.status), aktiv, hold });
    if (hRez.status === 201) { zmagovalci.rezervacija++; assert(nRez.every(x => x.status === 409 && x.body === "This table is already booked.") && aktiv === 0, "  zmagala rezervacija: 10 nakupov 409, 0 narocil", nRez.map(x => x.status)); }
    else { zmagovalci.nakup++; assert(hRez.status === 409 && hold === 0, "  zmagal nakup: rezervacija 409, 0 rezervacij", [hRez.status, hold]); }
  }
  console.log(`  (zmagovalci: nakup ${zmagovalci.nakup}, rezervacija ${zmagovalci.rezervacija})`);
  // Kdo zmaga, je naključje (ni trditev): tipično zmagata obe strani, kar dokazuje, da zahtevki res tekmujejo. Pravilnost = natanko eden.
  // Hkratne rezervacije iste mize (dva uporabnika): natanko ena.
  {
    const E = await dogodek(1, "Dve rezervaciji", "9 days");
    const rez = await Promise.all(Array.from({ length: 8 }, (_, i) => apiNa(i % 2 ? BASE_B : BASE, "POST", pot(E, M2), i % 3 ? T.lastnik : T.lastnik, { guest_name: "Gost " + i })));
    assert(rez.filter(x => x.status === 201).length === 1 && rez.filter(x => x.status === 409).length === 7 && await rezervacij(E, M2) === 1, "8 hkratnih rezervacij iste mize (2 procesa): natanko 1 uspe, 7 dobi 409", rez.map(x => x.status));
  }
  assert(!/deadlock/i.test(log), "v logu backenda ni »deadlock«", log.split("\n").filter(l => /deadlock/i.test(l)).slice(0, 2));
  const zivo = await api("GET", "/events");
  assert(zivo.status === 200, "backend po hkratnih zahtevkih odgovarja (pool ni zaseden)", zivo.status);

  console.log("\n# Hramba osebnega podatka: pospravljanje starih rezervacij (konec > 24 h nazaj; brez end_at: start_at + 12 h)");
  await pool.query("DELETE FROM table_holds");
  const ura = (h) => `NOW() + INTERVAL '${h} hours'`;
  async function staro(naslov, startH, endH) {
    const r = await pool.query(
      `INSERT INTO events (club_id, title, poster_url, start_at, end_at, status, ticket_price_cents, capacity)
       VALUES (1,$1,'https://example.com/p.jpg', ${ura(startH)}, ${endH === null ? "NULL" : ura(endH)}, 'published', 1500, 100) RETURNING id`, [naslov]);
    await pool.query("INSERT INTO table_holds (event_id, table_id, guest_name, note) VALUES ($1,$2,$3,'n')", [r.rows[0].id, M1, "Stari gost " + naslov]);
    return r.rows[0].id;
  }
  const primeri = [
    ["konec pred 30 h", -36, -30, true], ["brez konca, zacetek pred 40 h (konec = -28 h)", -40, null, true],
    ["konec pred 25 h", -30, -25, true], ["brez konca, zacetek pred 20 h (konec = -8 h)", -20, null, false],
    ["konec pred 10 h", -15, -10, false], ["konec pred 23 h", -28, -23, false], ["brez konca, zacetek pred 35 h (konec = -23 h)", -35, null, false],
    ["dogodek v prihodnosti", 30, null, false], ["dogodek tece zdaj", -2, 5, false],
  ];
  const idji = [];
  for (const [ime, s, e] of primeri) idji.push(await staro(ime, s, e));
  const srvC = await zazeni(PORT_C, { REZERVACIJE_CISCENJE_MS: "400" });
  let zadnje = null;
  for (let i = 0; i < 40; i++) {
    zadnje = (await pool.query("SELECT event_id FROM table_holds WHERE event_id = ANY($1::int[])", [idji])).rows.map(x => x.event_id);
    if (zadnje.length === primeri.filter(p => !p[3]).length) break;
    await spi(250);
  }
  primeri.forEach(([ime, , , brisana], i) => assert(zadnje.includes(idji[i]) === !brisana, `${ime}: rezervacija ${brisana ? "POBRISANA" : "ostane"}`, zadnje));
  await spi(1200);
  const po = (await pool.query("SELECT COUNT(*)::int AS n FROM table_holds WHERE event_id = ANY($1::int[])", [idji])).rows[0].n;
  assert(po === primeri.filter(p => !p[3]).length, "ponovni tek pospravljalca ne pobrise nicesar vec (idempotentno)", po);
  assert(!/\[rezervacije\].*(napaka|error)/i.test(log), "pospravljalec ne javlja napak", log.split("\n").filter(l => /rezervacije/.test(l)).slice(0, 3));
  await ustavi(srvC);

  console.log("\n# Zasebnost: ime gosta in opomba nista v dnevniku backenda (stdout/stderr vseh procesov)");
  const zasebno = /Janez|Testenko|pride ob 23h|zasebna-opomba|Gost krog|Spet gost|Gost po preklicu|Prepozn|Nocni gost|Stari gost|Gost cascade|Gost na izklopljeni|Gost, VIP|Drug gost|Gost M2/;
  assert(!zasebno.test(log), "dnevnik (POST, DELETE, 409, pospravljalec) ne vsebuje nobenega imena gosta ali opombe", log.split("\n").filter(l => zasebno.test(l)).slice(0, 3));
  assert(/Rezervacija po telefonu: dogodek \d+, miza \d+, uporabnik \d+/.test(log), "dnevnik rezervacije obstaja (samo id-ji, brez imena)", null);

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  const napake = log.split("\n").filter(l => /error|TypeError|Unhandled|deadlock/i.test(l) && !/Server error\./.test(l) && !/Resend/i.test(l));
  if (napake.length) console.log("\nLog backenda (sumljivo):\n" + napake.slice(0, 20).join("\n"));
  for (const s of procesi) { try { s.kill(); } catch (_) {} }
  jwksServer.close();
  await pool.query(TRUNC);
  await pool.end();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); for (const s of procesi) { try { s.kill(); } catch (_) {} } process.exit(1); });
