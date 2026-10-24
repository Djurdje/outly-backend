#!/usr/bin/env node
/**
 * Test "VIP miza: placilo na vratih + rezervacija v aplikaciji" (migracija 067, DECISIONS 23. 10. 2026, invarianta I62).
 * Zagon (lokalno, PG16, baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_vip_vrata.js
 * Vzorec kot test_rezervacija_telefon.js: lokalni JWKS, backend kot otrok proces na svojem portu (3146, pospravljalec 3147).
 * Pokriva: nastavitev `payment` (owner/manager da, vratar/natakar/uporabnik ne, neveljavna vrednost 400, izpusceno = brez spremembe), javni `vip_payment`
 * (GET /events, /events/:id, /events/:id/vip; predpomnilnik I17 po PUT), rezervacijo (oblika, guest_name privzeto/vpisano, paket obvezen, 18+ s paketom I8, demo I41,
 * pavza I53, okno prodaje, zasedena miza z narocilom in s telefonsko rezervacijo I13, limit 1 na uporabnika, vip_pay_in_app), nakup na door dogodku 409 vip_pay_at_door
 * (brez porabe nakupnih poskusov, brez narocila, ponovitev ze obstojecega nakupa ostane 201), preklic (svoja da, tuja 404, po zacetku 409), GET /me/table-reservations,
 * poslovni pogled (source, username, paket, cena; vratar da, natakar ne I27), sprostitev prek DELETE /business/.../hold, vip_reservations v GET /business/events,
 * da rezervacija NI prodaja (GET /business/sales, /admin/api/finance, sold_count, brez narocil, vstopnic in strezbe), hkratnost (8 hkratnih rezervacij iste mize,
 * 6 hkratnih rezervacij enega uporabnika), brisanje racuna (CASCADE), pospravljalec, bazne omejitve migracije 067.
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3146, PORT_C = 3147, PORT_D = 3148, PORT_E = 3149, JWKS_PORT = 3979;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-vrata";
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
let ipStevec = 0;
const novIp = () => `10.46.${(++ipStevec >> 8) & 255}.${(ipStevec & 255) + 1}`;
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
const razvrsti = (o) => Object.keys(o).sort().join();

(async () => {
  const pool = new Pool({ connectionString: DB });
  const TRUNC = "TRUNCATE omejitve, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE";
  await pool.query(TRUNC);
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  // NAKUP_RAZPRODANO_MS=0: pomnilniska oznaka o zasedeni mizi je izklopljena, da testi, ki brisejo rezervacije neposredno v bazi, niso odvisni od casa; odsek 15c jo preizkusi na lastnem procesu.
  await zazeni(PORT, { NAKUP_RAZPRODANO_MS: '0' });

  const T = {
    lastnik: zeton("lastnik@outly.si", uuid(1)), manager: zeton("manager@outly.si", uuid(2)), doorman: zeton("doorman@outly.si", uuid(3)),
    natakar: zeton("natakar@outly.si", uuid(4)), ana: zeton("ana@outly.si", uuid(5)), ben: zeton("ben@outly.si", uuid(6)),
    cara: zeton("cara@outly.si", uuid(7)), mladi: zeton("mladi@outly.si", uuid(8)), brez: zeton("brez@outly.si", uuid(9)),
    drugi: zeton("drugi@outly.si", uuid(10)), admin: zeton("admin@outly.si", uuid(11)), dan: zeton("dan@outly.si", uuid(12)),
  };
  const kupci = Array.from({ length: 8 }, (_, i) => zeton(`hkrati${i}@outly.si`, uuid(100 + i)));
  for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
  for (const t of kupci) await api("GET", "/me", t);
  await pool.query("UPDATE users SET role='business' WHERE email IN ('lastnik@outly.si','drugi@outly.si')");
  await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
  await pool.query("UPDATE users SET date_of_birth = (CURRENT_DATE - INTERVAL '30 years')::date WHERE email IN ('ana@outly.si','ben@outly.si','cara@outly.si','dan@outly.si','admin@outly.si') OR email LIKE 'hkrati%@outly.si'");
  await pool.query("UPDATE users SET date_of_birth = (CURRENT_DATE - INTERVAL '16 years')::date WHERE email = 'mladi@outly.si'");   // 'brez' ostane brez datuma rojstva
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana')");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='drugi@outly.si'), 'Drugi Klub', 'Maribor')");
  await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, (SELECT id FROM users WHERE email='manager@outly.si'), 'manager')");
  await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, (SELECT id FROM users WHERE email='doorman@outly.si'), 'doorman')");
  await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, (SELECT id FROM users WHERE email='natakar@outly.si'), 'bartender')");
  const uid = async (email) => (await pool.query("SELECT id FROM users WHERE email=$1", [email])).rows[0].id;

  async function dogodek(klub, naslov, pomik, polja = {}) {
    const r = await pool.query(
      `INSERT INTO events (club_id, title, poster_url, start_at, end_at, status, ticket_price_cents, capacity, vip_enabled, min_age)
       VALUES ($1,$2,'https://example.com/p.jpg', NOW() + $3::interval, $4, $5, 1500, 100, FALSE, $6) RETURNING id`,
      [klub, naslov, pomik, polja.konec || null, polja.status || "published", polja.minAge || 0]);
    return r.rows[0].id;
  }
  let r;
  const PLAN = { width: 24, height: 16, elements: [{ type: "stage", x: 8, y: 0, w: 8, h: 3, label: "" }] };
  r = await api("PUT", "/business/vip", T.lastnik, { plan: PLAN, tables: [
    { label: "T1", x: 2, y: 5, w: 2, h: 2, shape: "round", seats: 6, price_cents: 30000 },
    { label: "T2", x: 6, y: 5, w: 3, h: 2, shape: "rect", seats: 4, price_cents: 20000 },
    { label: "T3", x: 12, y: 5, w: 2, h: 2, shape: "round", seats: 8, price_cents: 45000 },
    { label: "T4", x: 16, y: 5, w: 2, h: 2, shape: "round", seats: 2, price_cents: 10000 },
    { label: "T5", x: 20, y: 5, w: 2, h: 2, shape: "round", seats: 2, price_cents: 0 },
    { label: "T6", x: 20, y: 9, w: 2, h: 2, shape: "round", seats: 4, price_cents: 15000 },
  ], packages: [{ name: "Jameson 0,7 l", description: "4x Red Bull" }, { name: "Grey Goose", description: "" }] });
  assert(r.status === 200 && r.body.tables.length === 6, "klub narise tloris (6 miz, 2 paketa)", r.body);
  const [M1, M2, M3, M4, M5, M6] = r.body.tables.map(t => t.id);
  const P1 = r.body.packages[0].id, P2 = r.body.packages[1].id;
  r = await api("PUT", "/business/vip", T.drugi, { plan: PLAN, tables: [{ label: "D1", x: 1, y: 1, w: 2, h: 2, shape: "round", seats: 4, price_cents: 15000 }], packages: [] });
  const MD = r.body.tables[0].id;
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='brez@outly.si'), 'Tretji Klub', 'Celje')");
  const PTUJ = (await pool.query("INSERT INTO bottle_packages (club_id, name, description) VALUES (3, 'Tuj paket', '') RETURNING id")).rows[0].id;   // paket kluba 3: za klub 1 in 2 tuj

  const ED = await dogodek(1, "Vrata", "3 days");         // vip_payment = door
  const EA = await dogodek(1, "V aplikaciji", "3 days");  // privzeto app
  const E2 = await dogodek(2, "Tuj dogodek", "3 days");
  for (const e of [ED, EA]) { r = await api("PUT", `/business/events/${e}/vip`, T.lastnik, { enabled: true }); assert(r.status === 200, "VIP vklopljen na dogodku", r.body); }
  r = await api("PUT", `/business/events/${E2}/vip`, T.drugi, { enabled: true, payment: "door" });
  assert(r.status === 200 && r.body.payment === "door", "tuj klub: payment door", r.body);

  const rez = (tok, e, m, telo, glave) => api("POST", `/events/${e}/tables/${m}/reservations`, tok, telo === undefined ? { package_id: P1 } : telo, glave);
  const preklic = (tok, e, m) => api("DELETE", `/events/${e}/tables/${m}/reservations`, tok);
  const nakup = (tok, e, m, telo, glave) => api("POST", `/events/${e}/tables/${m}/orders`, tok, telo === undefined ? { package_id: P1 } : telo, glave);
  const javno = async (e) => (await api("GET", `/events/${e}/vip`)).body;
  const stanje = async (e, tok = T.lastnik) => (await api("GET", `/business/events/${e}/vip`, tok)).body;
  const miza = (s, m) => s.tables.find(t => t.id === m);
  const rezervacij = async (e) => (await pool.query("SELECT COUNT(*)::int AS n FROM table_holds WHERE event_id=$1", [e])).rows[0].n;
  const narocil = async (e) => (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1", [e])).rows[0].n;
  const IME_KLJUCI = "created_at,guest_name,note,package_description,package_name,price_cents,source,username";

  console.log("\n# 1. Nastavitev payment pri dogodku (PUT /business/events/:id/vip)");
  let s0 = await stanje(ED);
  assert(s0.payment === "app", "privzeto: payment = app (GET /business/events/:id/vip)", s0.payment);
  r = await api("PUT", `/business/events/${ED}/vip`, T.doorman, { enabled: true, payment: "door" });
  assert(r.status === 403, "vratar ne more nastaviti -> 403", r.body);
  r = await api("PUT", `/business/events/${ED}/vip`, T.natakar, { enabled: true, payment: "door" });
  assert(r.status === 403, "natakar ne more nastaviti -> 403", r.body);
  r = await api("PUT", `/business/events/${ED}/vip`, T.ana, { enabled: true, payment: "door" });
  assert(r.status === 403, "navaden uporabnik -> 403", r.body);
  r = await api("PUT", `/business/events/${ED}/vip`, T.drugi, { enabled: true, payment: "door" });
  assert(r.status === 404, "lastnik drugega kluba na tujem dogodku -> 404", r.body);
  assert((await stanje(ED)).payment === "app", "zavrnjeni zahtevki niso spremenili payment");
  for (const [opis, v] of [["cash", "cash"], ["prazen niz", ""], ["velike crke", "DOOR"], ["stevilo", 1], ["null", null], ["bool", true], ["seznam", ["door"]], ["objekt", { a: 1 }]]) {
    r = await api("PUT", `/business/events/${ED}/vip`, T.lastnik, { enabled: true, payment: v });
    assert(r.status === 400 && typeof r.body === "string", `payment ${opis} -> 400`, [r.status, r.body]);
  }
  assert((await stanje(ED)).payment === "app", "neveljavne vrednosti ne spremenijo payment");
  // Javni predpomnilnik (I17): GET /events/:id je prvi predpomnjen, PUT ga takoj razveljavi.
  r = await api("GET", `/events/${ED}`);
  assert(r.status === 200 && r.body.vip_payment === "app", "GET /events/:id: vip_payment = app", r.body.vip_payment);
  r = await api("PUT", `/business/events/${ED}/vip`, T.manager, { enabled: true, payment: "door" });
  assert(r.status === 200 && r.body.payment === "door" && r.body.enabled === true, "manager nastavi door (odgovor ima payment)", r.body);
  r = await api("GET", `/events/${ED}`);
  assert(r.body.vip_payment === "door", "GET /events/:id takoj kaze door (predpomnilnik razveljavljen, I17)", r.body.vip_payment);
  r = await api("PUT", `/business/events/${ED}/vip`, T.lastnik, { enabled: true });
  assert(r.status === 200 && r.body.payment === "door", "izpusceno payment = brez spremembe (ostane door)", r.body.payment);
  r = await api("PUT", `/business/events/${ED}/vip`, T.lastnik, { enabled: false, payment: "app" });
  assert(r.status === 200 && r.body.payment === "app" && r.body.enabled === false, "lastnik nastavi app nazaj (skupaj z enabled)", r.body);
  r = await api("PUT", `/business/events/${ED}/vip`, T.lastnik, { enabled: true, payment: "door" });
  assert(r.status === 200 && r.body.payment === "door" && r.body.enabled === true, "lastnik spet door", r.body);
  assert((await pool.query("SELECT vip_payment FROM events WHERE id=$1", [ED])).rows[0].vip_payment === "door", "v bazi: events.vip_payment = door");
  const javnoED = await javno(ED);
  assert(javnoED.vip_payment === "door" && javnoED.enabled === true, "GET /events/:id/vip: vip_payment = door", javnoED.vip_payment);
  assert((await javno(EA)).vip_payment === "app", "GET /events/:id/vip: app dogodek ima vip_payment = app");
  r = await api("GET", "/events");
  const sez = r.body.find ? r.body : (r.body.items || []);
  assert(r.status === 200 && sez.find(e => e.id === ED).vip_payment === "door" && sez.find(e => e.id === EA).vip_payment === "app", "GET /events: vsak dogodek ima vip_payment", sez.map(e => e.vip_payment));
  r = await api("GET", "/events?lite=true");
  assert(r.status === 200 && (r.body.find ? r.body : r.body.items).every(e => e.vip_payment === "door" || e.vip_payment === "app"), "GET /events?lite=true: vip_payment prisoten");

  console.log("\n# 2. Rezervacija v aplikaciji: vloge, validacija, oblika odgovora");
  r = await rez(null, ED, M1);
  assert(r.status === 401, "brez zetona -> 401", r.status);
  r = await api("DELETE", `/events/${ED}/tables/${M1}/reservations`, null);
  assert(r.status === 401, "DELETE brez zetona -> 401", r.status);
  r = await api("GET", "/me/table-reservations", null);
  assert(r.status === 401, "GET /me/table-reservations brez zetona -> 401", r.status);
  for (const [e, m, ime] of [["abc", M1, "id dogodka niz"], [ED, "abc", "id mize niz"], [0, M1, "id dogodka 0"], [ED, -1, "id mize negativen"], [ED, "99999999999", "id mize izven int4"]]) {
    r = await rez(T.ana, e, m, { package_id: P1 });
    assert(r.status === 400, `${ime} -> 400`, [r.status, r.body]);
  }
  r = await rez(T.ana, 999999, M1); assert(r.status === 404, "dogodek ne obstaja -> 404", r.body);
  r = await rez(T.ana, ED, 999999); assert(r.status === 404, "miza ne obstaja -> 404", r.body);
  r = await rez(T.ana, ED, MD); assert(r.status === 404, "miza drugega kluba -> 404", r.body);
  const slabi = [
    ["package_id niz", { package_id: "abc" }], ["package_id negativen", { package_id: -3 }], ["package_id 0.5", { package_id: 0.5 }],
    ["guest_name 61 znakov", { package_id: P1, guest_name: "x".repeat(61) }], ["guest_name stevilo", { package_id: P1, guest_name: 5 }],
    ["guest_name seznam", { package_id: P1, guest_name: ["a"] }], ["guest_name z NUL", { package_id: P1, guest_name: "A\u0000B" }],
    ["guest_name 61 kodnih tock (emoji)", { package_id: P1, guest_name: "😀".repeat(61) }],
    ["guest_name z znakom ničelne širine (U+200B)", { package_id: P1, guest_name: "Ana\u200bNovak" }], ["guest_name z bidi znakom (U+202E)", { package_id: P1, guest_name: "Ana \u202eNovak" }],
    ["guest_name z mehkim vezajem (U+00AD)", { package_id: P1, guest_name: "Ana\u00adNovak" }], ["guest_name z BOM (U+FEFF)", { package_id: P1, guest_name: "\ufeffAna" }],
    ["guest_name z locilom vrstice (U+2028)", { package_id: P1, guest_name: "Ana\u2028Novak" }],
    ["expected_price_cents negativen", { package_id: P1, expected_price_cents: -1 }], ["expected_price_cents 1.5", { package_id: P1, expected_price_cents: 1.5 }],
    ["expected_price_cents niz", { package_id: P1, expected_price_cents: "300" }],
  ];
  for (const [opis, telo] of slabi) {
    r = await rez(T.ana, ED, M1, telo);
    assert(r.status === 400 && typeof r.body === "string" && r.body.length > 3, `${opis} -> 400 z berljivim sporocilom`, [r.status, r.body]);
  }
  r = await rez(T.ana, ED, M1, {});
  assert(r.status === 400 && /bottle package/i.test(r.body), "paket je obvezen, ce ima klub aktivne pakete -> 400", r.body);
  r = await rez(T.ana, ED, M1, { package_id: null });
  assert(r.status === 400 && /bottle package/i.test(r.body), "package_id null -> 400 (klub ima pakete)", r.body);
  r = await rez(T.ana, ED, M1, { package_id: PTUJ });
  assert(r.status === 400 && /package/i.test(r.body), "paket drugega kluba -> 400", r.body);
  r = await rez(T.ana, ED, M1, { package_id: P1, expected_price_cents: 29999 });
  assert(r.status === 409 && r.body === "The table price has changed.", "expected_price_cents ne ustreza -> 409 kot pri nakupu", r.body);
  r = await rez(T.mladi, ED, M1, { package_id: P1 });
  assert(r.status === 403 && /18/.test(r.body), "16-letnik z paketom (dogodek 0+) -> 403, meja 18 (I8)", r.body);
  r = await rez(T.brez, ED, M1, { package_id: P1 });
  assert(r.status === 403 && /date of birth/i.test(r.body), "brez datuma rojstva s paketom -> 403 (I8)", r.body);
  assert(await rezervacij(ED) === 0 && await narocil(ED) === 0, "nobena zavrnjena zahteva ni pustila rezervacije ali narocila");

  console.log("\n# 3. Uspesna rezervacija");
  const nastoj = await uid("ana@outly.si");
  r = await rez(T.ana, ED, M1, { package_id: P1, expected_price_cents: 30000 });
  assert(r.status === 201 && Object.keys(r.body).join() === "reservation", "ana rezervira T1 -> 201 { reservation }", r.body);
  const R1 = r.body.reservation;
  assert(razvrsti(R1) === "club_id,club_name,created_at,currency,event_id,event_start_at,event_title,guest_name,id,package_description,package_id,package_name,price_cents,seats,table_id,table_label",
    "Reservation: tocno dogovorjena polja", Object.keys(R1));
  assert(R1.event_id === ED && R1.event_title === "Vrata" && R1.club_id === 1 && R1.club_name === "Pure Club" && R1.table_id === M1 && R1.table_label === "T1" && R1.seats === 6
    && R1.package_id === P1 && R1.package_name === "Jameson 0,7 l" && R1.package_description === "4x Red Bull" && R1.price_cents === 30000 && R1.currency === "EUR"
    && R1.guest_name === "ana" && typeof R1.id === "number" && !isNaN(Date.parse(R1.created_at)) && !isNaN(Date.parse(R1.event_start_at)),
    "Reservation: vrednosti (guest_name privzeto = uporabnisko ime, cena = posnetek)", R1);
  assert(typeof R1.price_cents === "number" && Number.isInteger(R1.price_cents), "price_cents je celo stevilo centov (I9)");
  const vb = (await pool.query("SELECT source, user_id, created_by_user_id, price_cents, package_id, note FROM table_holds WHERE id=$1", [R1.id])).rows[0];
  assert(vb.source === "app" && vb.user_id === nastoj && vb.price_cents === 30000 && vb.package_id === P1 && vb.note === null, "v bazi: source app, user_id, cena, paket", vb);
  assert(await narocil(ED) === 0 && (await pool.query("SELECT COUNT(*)::int AS n FROM tickets WHERE event_id=$1", [ED])).rows[0].n === 0, "rezervacija NI narocilo in nima vstopnic");
  assert((await pool.query("SELECT sold_count FROM events WHERE id=$1", [ED])).rows[0].sold_count === 0, "sold_count se ne spremeni");
  r = await rez(T.ben, ED, M2, { package_id: P2, guest_name: "  Ben & Co  ", expected_price_cents: 20000 });
  assert(r.status === 201 && r.body.reservation.guest_name === "Ben & Co" && r.body.reservation.package_name === "Grey Goose" && r.body.reservation.package_description === "", "ben: vpisano ime (obrezano), drug paket", r.body);
  r = await rez(T.cara, ED, M5, { package_id: P1 });
  assert(r.status === 201 && r.body.reservation.price_cents === 0 && r.body.reservation.guest_name === "cara", "cara: miza za 0 EUR -> 201, price_cents 0", r.body);
  r = await rez(T.dan, ED, M6, { package_id: P1, guest_name: "   " });
  assert(r.status === 201 && r.body.reservation.guest_name === "dan", "dan: prazno ime (presledki) -> uporabnisko ime", r.body);
  await pool.query("DELETE FROM table_holds WHERE event_id=$1 AND table_id IN ($2,$3)", [ED, M5, M6]);

  console.log("\n# 4. Limit 1 na uporabnika, zasedena miza (I13)");
  r = await rez(T.ana, ED, M3);
  assert(r.status === 409 && r.body.error === "reservation_limit" && r.body.message === "You already have a table reserved for this event.", "ana: druga miza istega dogodka -> 409 reservation_limit", r.body);
  r = await rez(T.ana, ED, M1);
  assert(r.status === 409 && r.body.error === "reservation_limit", "ana: ponovitev iste rezervacije -> 409 reservation_limit", r.body);
  assert(r.body.reservation && r.body.reservation.id === R1.id && r.body.reservation.table_id === M1 && r.body.reservation.event_id === ED && razvrsti(r.body.reservation) === razvrsti(R1),
    "reservation_limit vrne se obstojeco rezervacijo (dodano polje reservation, isto kot Reservation)", r.body);
  r = await rez(T.cara, ED, M1);
  assert(r.status === 409 && r.body === "This table is already booked.", "cara: miza, ki jo je rezervirala ana -> 409 already booked", r.body);
  await api("POST", `/business/events/${ED}/tables/${M3}/hold`, T.lastnik, { guest_name: "Telefonski gost", note: "po telefonu" });
  r = await rez(T.cara, ED, M3);
  assert(r.status === 409 && r.body === "This table is already booked.", "miza s telefonsko rezervacijo -> 409 already booked", r.body);
  assert(await rezervacij(ED) === 3, "stanje: 3 rezervacije (2 aplikacija + 1 telefon)", await rezervacij(ED));
  // Miza z narocilom: dogodek EA je v nacinu app, nakup ok; ko klub preklopi na door, miza ostane zasedena.
  r = await nakup(T.cara, EA, M4, { package_id: P1 });
  assert(r.status === 201 && r.body.order && r.body.order.table_label === "T4", "app dogodek: cara kupi T4 (narocilo)", r.body);
  const orderCara = r.body.order.id;
  r = await rez(T.ben, EA, M2);
  assert(r.status === 409 && r.body.error === "vip_pay_in_app" && r.body.message === "Tables for this event are paid in the app.", "rezervacija na app dogodku -> 409 vip_pay_in_app", r.body);
  assert(await rezervacij(EA) === 0, "vip_pay_in_app ni pustil rezervacije");
  r = await api("PUT", `/business/events/${EA}/vip`, T.lastnik, { enabled: true, payment: "door" });
  assert(r.status === 200 && r.body.payment === "door", "klub preklopi EA na door (obstojece narocilo ostane)", r.body);
  const sEA = await stanje(EA);
  assert(miza(sEA, M4).booking && miza(sEA, M4).booking.order_id === orderCara && miza(sEA, M4).hold === null, "narocilo T4 ostane booking po preklopu", miza(sEA, M4));
  assert(miza(sEA, M4).booking.total_cents === 10000 && Number.isInteger(miza(sEA, M4).booking.total_cents) && miza(sEA, M4).booking.total_cents === (await pool.query("SELECT total_cents FROM orders WHERE id=$1", [orderCara])).rows[0].total_cents,
    "booking.total_cents = orders.total_cents (10000 = cena T4, celi centi)", miza(sEA, M4).booking);
  assert(razvrsti(miza(sEA, M4).booking) === "buyer_username,checked_in,created_at,guests,order_id,package_description,package_name,public_ref,total_cents", "booking: dosedanja polja + total_cents", Object.keys(miza(sEA, M4).booking));
  r = await rez(T.ben, EA, M4);
  assert(r.status === 409 && r.body === "This table is already booked.", "miza z narocilom -> rezervacija 409 already booked", r.body);
  r = await rez(T.ben, EA, M2, { package_id: P1 });
  assert(r.status === 201, "po preklopu na door ben rezervira T2 na EA", r.body);
  await pool.query("DELETE FROM table_holds WHERE event_id=$1", [EA]);

  console.log("\n# 5. Nakup mize na door dogodku -> 409 vip_pay_at_door");
  const IP = "10.77.77.77";
  const stZnaka = (await pool.query("SELECT COUNT(*)::int AS n FROM omejitve")).rows[0].n;
  r = await nakup(T.ben, ED, M2, { package_id: P1 });
  assert(r.status === 409 && r.body.error === "vip_pay_at_door" && r.body.message === "Tables for this event are paid in cash at the door. Update the app to reserve one.", "nakup mize na door dogodku -> 409 vip_pay_at_door (natancno telo)", r.body);
  assert(await narocil(ED) === 0, "nakup ni ustvaril narocila");
  const KLJUC = "9c1a2b3c-0000-4000-8000-000000000001";
  r = await nakup(T.ben, ED, M2, { package_id: P1 }, { "idempotency-key": KLJUC });
  assert(r.status === 409 && r.body.error === "vip_pay_at_door", "z Idempotency-Key: isto 409 vip_pay_at_door", r.body);
  assert(await narocil(ED) === 0, "kljuc ni zapisan (ni narocila)");
  // 25 poskusov z istega IP: nobeden ne porabi nakupnih poskusov (omejevalnik 20/h) -> vsi 409 vip_pay_at_door, nobeden 429
  const izidi = [];
  for (let i = 0; i < 25; i++) izidi.push((await nakup(T.ben, ED, M2, { package_id: P1 }, { "x-forwarded-for": IP })).status);
  assert(izidi.every(x => x === 409), "25 zavrnjenih nakupov z istega IP: vsi 409 (omejevalnik 20/h ni porabljen)", izidi.join());
  r = await nakup(T.ben, ED, M2, { package_id: P1 }, { "x-forwarded-for": IP });
  assert(r.status === 409 && r.body.error === "vip_pay_at_door", "26. poskus: se vedno vip_pay_at_door, ne 429", [r.status, r.body]);
  // Ponovitev ze obstojecega nakupa (idempotenca) ostane 201 tudi po preklopu na door.
  r = await api("PUT", `/business/events/${EA}/vip`, T.lastnik, { enabled: true, payment: "app" });
  const KLJUC2 = "9c1a2b3c-0000-4000-8000-000000000002";
  r = await nakup(T.ben, EA, M2, { package_id: P1 }, { "idempotency-key": KLJUC2 });
  assert(r.status === 201 && r.body.order, "app dogodek: nakup s kljucem -> 201", r.body);
  await api("PUT", `/business/events/${EA}/vip`, T.lastnik, { enabled: true, payment: "door" });
  r = await nakup(T.ben, EA, M2, { package_id: P1 }, { "idempotency-key": KLJUC2 });
  assert(r.status === 201 && r.h["idempotent-replayed"] === "true", "ponovitev nakupa po preklopu na door: 201 Idempotent-Replayed (obstojeci nakup ostane veljaven)", [r.status, r.h["idempotent-replayed"]]);
  r = await nakup(T.ana, EA, M6, { package_id: P1 }, { "idempotency-key": "9c1a2b3c-0000-4000-8000-000000000003" });
  assert(r.status === 409 && r.body.error === "vip_pay_at_door", "nov nakup na door dogodku 409 tudi po preklopu", r.body);
  await api("PUT", `/business/events/${EA}/vip`, T.lastnik, { enabled: true, payment: "app" });
  r = await nakup(T.ana, EA, M6, { package_id: P1 }, { "idempotency-key": "9c1a2b3c-0000-4000-8000-000000000003" });
  assert(r.status === 201, "isti kljuc uspe, ko je dogodek spet app (409 ni zapomnjen)", r.body);
  await pool.query("DELETE FROM tickets WHERE event_id=$1", [EA]);
  await pool.query("DELETE FROM orders WHERE event_id=$1", [EA]);
  await pool.query("DELETE FROM table_holds WHERE event_id=$1", [EA]);

  console.log("\n# 6. Pravila prodaje: demo (I41), pavza (I53), okno prodaje, zacetek, osnutek, izklopljena miza, brez paketov");
  const E3 = await dogodek(1, "Pravila", "3 days");
  await api("PUT", `/business/events/${E3}/vip`, T.lastnik, { enabled: true, payment: "door" });
  await pool.query("UPDATE events SET sales_paused = TRUE WHERE id=$1", [E3]);
  r = await rez(T.ana, E3, M1);
  assert(r.status === 409 && /paused/i.test(r.body), "pavza prodaje (I53) -> 409", r.body);
  await pool.query("UPDATE events SET sales_paused = FALSE, sales_close_at = NOW() - INTERVAL '1 hour' WHERE id=$1", [E3]);
  r = await rez(T.ana, E3, M1);
  assert(r.status === 409 && /closed/i.test(r.body), "prodaja zaprta -> 409", r.body);
  await pool.query("UPDATE events SET sales_close_at = NULL, sales_open_at = NOW() + INTERVAL '1 hour' WHERE id=$1", [E3]);
  r = await rez(T.ana, E3, M1);
  assert(r.status === 409 && /not opened/i.test(r.body), "prodaja se ni odprta -> 409", r.body);
  await pool.query("UPDATE events SET sales_open_at = NULL, start_at = NOW() - INTERVAL '1 hour', end_at = NOW() + INTERVAL '3 hours' WHERE id=$1", [E3]);
  r = await rez(T.ana, E3, M1);
  assert(r.status === 409 && /started/i.test(r.body), "dogodek se je zacel -> 409", r.body);
  await pool.query("UPDATE events SET start_at = NOW() + INTERVAL '3 days', end_at = NULL, status = 'draft' WHERE id=$1", [E3]);
  r = await rez(T.ana, E3, M1);
  assert(r.status === 409 && /not on sale/i.test(r.body), "osnutek -> 409 (ni v prodaji)", r.body);
  await pool.query("UPDATE events SET status = 'published' WHERE id=$1", [E3]);
  r = await api("PUT", `/business/events/${E3}/vip`, T.lastnik, { enabled: true, payment: "door", tables: [{ table_id: M1, price_cents: null, disabled: true }] });
  r = await rez(T.ana, E3, M1);
  assert(r.status === 404, "miza izklopljena na dogodku -> 404", r.body);
  r = await api("PUT", `/business/events/${E3}/vip`, T.lastnik, { enabled: true, payment: "door", tables: [{ table_id: M1, price_cents: 31000, disabled: false }] });
  r = await rez(T.ana, E3, M1, { package_id: P1, expected_price_cents: 30000 });
  assert(r.status === 409 && r.body === "The table price has changed.", "cena po dogodku 31000: stara pricakovana cena -> 409", r.body);
  r = await rez(T.ana, E3, M1, { package_id: P1, expected_price_cents: 31000 });
  assert(r.status === 201 && r.body.reservation.price_cents === 31000, "cena po dogodku 31000 -> 201, posnetek cene 31000", r.body);
  await api("PUT", `/business/events/${E3}/vip`, T.lastnik, { enabled: false });
  r = await rez(T.ben, E3, M2, { package_id: P1 });
  assert(r.status === 404, "VIP na dogodku izklopljen -> 404", r.body);
  await api("PUT", `/business/events/${E3}/vip`, T.lastnik, { enabled: true });
  // Dogodek z min_age 21: 20-letnik ni nikoli dovoljen; (brez paketa pri klubu brez paketov)
  const EVR = await dogodek(2, "Klub brez paketov", "3 days", { minAge: 18 });
  await api("PUT", `/business/events/${EVR}/vip`, T.drugi, { enabled: true, payment: "door" });
  r = await rez(T.mladi, EVR, MD, {});
  assert(r.status === 403, "dogodek 18+, 16-letnik, brez paketov -> 403 (I8)", r.body);
  r = await rez(T.brez, EVR, MD, {});
  assert(r.status === 403 && /date of birth/i.test(r.body), "dogodek 18+ brez datuma rojstva -> 403 (I8)", r.body);
  r = await rez(T.ana, EVR, MD, {});
  assert(r.status === 201 && r.body.reservation.package_id === null && r.body.reservation.package_name === null && r.body.reservation.price_cents === 15000, "klub brez paketov: rezervacija brez paketa -> 201", r.body);
  r = await rez(T.ben, EVR, MD, { package_id: PTUJ });
  assert(r.status === 400 && /package/i.test(r.body), "paket tujega kluba na klubu brez paketov -> 400", [r.status, r.body]);
  await pool.query("DELETE FROM table_holds WHERE event_id=$1", [EVR]);
  // Demo klub (I41): klub 2 postane demo
  await pool.query("UPDATE clubs SET is_demo = TRUE WHERE id=2");
  r = await rez(T.ben, EVR, MD, {});
  assert(r.status === 409 && r.body.error === "demo_club", "demo klub -> 409 demo_club", r.body);
  r = await rez(T.admin, EVR, MD, {});
  assert(r.status === 201, "demo klub: vloga admin sme (kot nakup, I41)", r.body);
  await pool.query("UPDATE clubs SET is_demo = FALSE WHERE id=2");
  await pool.query("DELETE FROM table_holds WHERE event_id = ANY($1::int[])", [[E3, EVR]]);

  console.log("\n# 7. Poslovni pogled: source, username, paket, cena; vratar da, natakar ne (I27)");
  const sD = await stanje(ED);
  const h1 = miza(sD, M1).hold, h2 = miza(sD, M2).hold, h3 = miza(sD, M3).hold;
  assert(razvrsti(h1) === IME_KLJUCI, "hold ima tocno dogovorjena polja", Object.keys(h1));
  assert(h1.source === "app" && h1.username === "ana" && h1.guest_name === "ana" && h1.package_name === "Jameson 0,7 l" && h1.package_description === "4x Red Bull" && h1.price_cents === 30000 && h1.note === null,
    "app rezervacija: source, username, paket, cena", h1);
  assert(h2.source === "app" && h2.username === "ben" && h2.guest_name === "Ben & Co" && h2.package_name === "Grey Goose" && h2.price_cents === 20000, "app rezervacija z vpisanim imenom", h2);
  assert(razvrsti(h3) === IME_KLJUCI && h3.source === "phone" && h3.username === null && h3.package_name === null && h3.package_description === null && h3.price_cents === null && h3.guest_name === "Telefonski gost" && h3.note === "po telefonu",
    "telefonska rezervacija: source phone, username/paket/cena null", h3);
  assert(miza(sD, M1).booking === null && miza(sD, M2).booking === null, "rezervacija v aplikaciji NI booking");
  const vr = await stanje(ED, T.doorman);
  assert(JSON.stringify(vr) === JSON.stringify(sD), "vratar vidi isto kot lastnik", null);
  assert(JSON.stringify(await stanje(ED, T.manager)) === JSON.stringify(sD), "manager vidi isto");
  r = await api("GET", `/business/events/${ED}/vip`, T.natakar);
  assert(r.status === 403, "natakar GET /business/events/:id/vip -> 403 (I27)", r.status);
  r = await api("GET", `/business/events/${ED}/vip`, T.ana);
  assert(r.status === 403, "navaden uporabnik -> 403", r.status);
  r = await api("GET", `/business/events/${ED}/vip`, T.drugi);
  assert(r.status === 404, "tuj klub -> 404", r.status);
  const pj = await javno(ED);
  const jm = pj.tables.find(t => t.id === M1);
  assert(jm.available === false && pj.tables.find(t => t.id === M2).available === false && pj.tables.find(t => t.id === M3).available === false && pj.tables.find(t => t.id === M4).available === true,
    "javno: rezervirane mize (app in telefon) available false, ostale true", pj.tables.map(t => [t.label, t.available]));
  assert(!/ana|Ben & Co|Telefonski|Jameson 0,7 l.*"guest|username|guest_name|hold|user_id/.test(JSON.stringify(pj.tables)), "javno: nobenega imena, uporabnika ali rezervacije pri mizah", pj.tables[0]);
  assert(razvrsti(jm) === "available,h,id,label,price_cents,seats,shape,w,x,y", "javna miza ima ista polja kot doslej", Object.keys(jm));

  // Eno pravo narocilo mize (T4 na EA), da prodaja ni prazna: preklop na app, nakup, preklop na door.
  await api("PUT", `/business/events/${EA}/vip`, T.lastnik, { enabled: true, payment: "app" });
  r = await nakup(T.cara, EA, M4, { package_id: P1 });
  assert(r.status === 201, "cara kupi T4 na EA (narocilo)", r.body);
  await api("PUT", `/business/events/${EA}/vip`, T.lastnik, { enabled: true, payment: "door" });

  console.log("\n# 8. GET /business/events: vip_reservations");
  r = await api("GET", "/business/events", T.lastnik);
  const evED = r.body.find(e => e.id === ED), evEA = r.body.find(e => e.id === EA), evE3 = r.body.find(e => e.id === E3);
  assert(r.status === 200 && evED.vip_reservations === 3 && evEA.vip_reservations === 1 && evE3.vip_reservations === 0, "ED: 2 aplikaciji + 1 telefon = 3; EA: 1 narocilo (T4) = 1; E3: 0", [evED.vip_reservations, evEA.vip_reservations, evE3.vip_reservations]);
  assert(typeof evED.vip_reservations === "number" && evED.vip_payment === "door" && evEA.vip_payment === "door", "dogodki imajo vip_payment (+ vip_reservations)", [evED.vip_payment, evEA.vip_payment]);
  r = await api("GET", "/business/events", T.doorman);
  assert(r.status === 200 && r.body.find(e => e.id === ED).vip_reservations === 3, "vratar tudi vidi vip_reservations", r.body.find(e => e.id === ED).vip_reservations);
  r = await api("GET", "/business/events", T.drugi);
  assert(r.status === 200 && !r.body.some(e => e.id === ED), "tuj klub ne vidi dogodkov", null);

  console.log("\n# 9. Rezervacija NI prodaja (GET /business/sales, /admin/api/finance, strezba)");
  const prodajaPo = await api("GET", "/business/sales", T.lastnik);
  assert(prodajaPo.status === 200 && JSON.stringify(prodajaPo.body).includes("tables_sold"), "GET /business/sales vsebuje tables_sold", Object.keys(prodajaPo.body));
  const financePo = await api("GET", "/admin/api/finance", T.admin);
  await pool.query("DELETE FROM table_holds WHERE event_id=$1 AND source='app'", [ED]);
  const prodajaBrez = await api("GET", "/business/sales", T.lastnik);
  const financeBrez = await api("GET", "/admin/api/finance", T.admin);
  assert(prodajaPo.status === 200 && JSON.stringify(prodajaPo.body) === JSON.stringify(prodajaBrez.body), "GET /business/sales je enak z 2 app rezervacijama in brez njih (ne tables_sold, ne gross)", [prodajaPo.body.summary, prodajaBrez.body.summary]);
  assert(financePo.status === 200 && JSON.stringify(financePo.body) === JSON.stringify(financeBrez.body), "GET /admin/api/finance je enak z rezervacijami in brez njih", null);
  assert((await pool.query("SELECT COUNT(*)::int AS n FROM table_service")).rows[0].n === 0, "rezervacija ne sprozi strezbe (table_service prazna)");
  assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1", [ED])).rows[0].n === 0, "na ED ni narocil");

  console.log("\n# 10. Preklic: svoja da, tuja 404, telefonska 404, po zacetku 409; sprostitev prek kluba");
  r = await rez(T.ana, ED, M1, { package_id: P1 });
  assert(r.status === 201, "ana spet rezervira T1", r.body);
  r = await rez(T.ben, ED, M2, { package_id: P1 });
  assert(r.status === 201, "ben spet rezervira T2", r.body);
  r = await preklic(T.cara, ED, M1);
  assert(r.status === 404, "cara ne more preklicati anine rezervacije -> 404", r.body);
  r = await preklic(T.ana, ED, M3);
  assert(r.status === 404, "ana ne more preklicati telefonske rezervacije -> 404", r.body);
  r = await preklic(T.ana, ED, M4);
  assert(r.status === 404, "ana: miza brez rezervacije -> 404", r.body);
  r = await preklic(T.ana, 999999, M1);
  assert(r.status === 404, "ana: dogodek ne obstaja -> 404", r.body);
  r = await preklic(T.ana, "abc", M1);
  assert(r.status === 400, "ana: id dogodka niz -> 400", r.body);
  assert(await rezervacij(ED) === 3, "tuji poskusi preklica niso pobrisali nicesar", await rezervacij(ED));
  r = await preklic(T.ana, ED, M1);
  assert(r.status === 200 && JSON.stringify(r.body) === '{"ok":true}', "ana prekliche svojo rezervacijo -> 200 { ok: true }", r.body);
  assert((await javno(ED)).tables.find(t => t.id === M1).available === true, "miza T1 je spet prosta (javno)");
  r = await preklic(T.ana, ED, M1);
  assert(r.status === 404, "ponovni preklic -> 404", r.body);
  r = await rez(T.cara, ED, M1, { package_id: P1 });
  assert(r.status === 201, "cara takoj rezervira sproscen T1", r.body);
  r = await rez(T.ana, ED, M4, { package_id: P1 });
  assert(r.status === 201, "ana (po preklicu) lahko rezervira drugo mizo (T4)", r.body);
  // sprostitev prek kluba
  r = await api("DELETE", `/business/events/${ED}/tables/${M4}/hold`, T.doorman);
  assert(r.status === 403, "vratar ne more sprostiti -> 403", r.body);
  r = await api("DELETE", `/business/events/${ED}/tables/${M4}/hold`, T.manager);
  assert(r.status === 200 && miza(r.body, M4).hold === null, "manager sprosti app rezervacijo prek DELETE /business/.../hold -> 200", r.body && miza(r.body, M4));
  r = await api("GET", "/me/table-reservations", T.ana);
  assert(r.status === 200 && !r.body.items.some(x => x.table_id === M4), "klub-sprostitev: rezervacija izgine iz seznama kupca", r.body.items.map(x => x.table_label));
  r = await rez(T.ana, ED, M4, { package_id: P1 });
  assert(r.status === 201, "ana lahko spet rezervira T4 po sprostitvi kluba", r.body);
  // preklic po zacetku
  await pool.query("UPDATE events SET start_at = NOW() - INTERVAL '30 minutes', end_at = NOW() + INTERVAL '5 hours' WHERE id=$1", [ED]);
  r = await preklic(T.ana, ED, M4);
  assert(r.status === 409 && r.body.error === "event_started", "preklic po zacetku dogodka -> 409 event_started", r.body);
  assert(await rezervacij(ED) === 4, "rezervacija po zavrnjenem preklicu ostane (3 + T4)", await rezervacij(ED));
  r = await rez(T.dan, ED, M5, { package_id: P1 });
  assert(r.status === 409, "nova rezervacija po zacetku -> 409", r.body);
  await pool.query("UPDATE events SET start_at = NOW() + INTERVAL '3 days', end_at = NULL WHERE id=$1", [ED]);

  console.log("\n# 11. GET /me/table-reservations");
  const E4 = await dogodek(1, "Prej", "2 days");
  await api("PUT", `/business/events/${E4}/vip`, T.lastnik, { enabled: true, payment: "door" });
  r = await rez(T.ana, E4, M2, { package_id: P2, guest_name: "Ana in prijatelji" });
  assert(r.status === 201, "ana rezervira se na E4 (2 dni, prej kot ED)", r.body);
  // dogodek, ki se je koncal pred 5 h (vkljucen) in pred 30 h (izkljucen)
  const EK5 = await dogodek(1, "Koncan pred 5 h", "-9 hours", { konec: null });
  await pool.query("UPDATE events SET end_at = NOW() - INTERVAL '5 hours', start_at = NOW() - INTERVAL '9 hours' WHERE id=$1", [EK5]);
  const EK30 = await dogodek(1, "Koncan pred 30 h", "-34 hours");
  await pool.query("UPDATE events SET end_at = NOW() - INTERVAL '30 hours', start_at = NOW() - INTERVAL '34 hours' WHERE id=$1", [EK30]);
  const aid = await uid("ana@outly.si");
  for (const e of [EK5, EK30]) await pool.query("INSERT INTO table_holds (event_id, table_id, guest_name, source, user_id, package_id, package_name, price_cents) VALUES ($1,$2,'ana','app',$3,$4,'Jameson 0,7 l',30000)", [e, M1, aid, P1]);
  await pool.query("INSERT INTO table_holds (event_id, table_id, guest_name) VALUES ($1,$2,'Telefon')", [E4, M3]);
  r = await api("GET", "/me/table-reservations", T.ana);
  assert(r.status === 200 && Array.isArray(r.body.items) && Object.keys(r.body).join() === "items", "ana: { items: [...] }", r.body);
  const imena = r.body.items.map(x => x.event_title);
  assert(JSON.stringify(imena) === JSON.stringify(["Vrata", "Prej", "Koncan pred 5 h"]) || JSON.stringify(imena) === JSON.stringify(["Prej", "Vrata", "Koncan pred 5 h"]),
    "ana: prihajajoci + koncan pred < 24 h; koncan pred 30 h NI; najnovejsi zacetek prvi", imena);
  const zacetki = r.body.items.map(x => Date.parse(x.event_start_at));
  assert(zacetki.every((t, i) => i === 0 || zacetki[i - 1] >= t), "urejeno po zacetku padajoce", zacetki);
  assert(r.body.items.every(x => razvrsti(x) === razvrsti(R1) && x.club_name === "Pure Club" && x.currency === "EUR"), "vsak element ima polja Reservation", r.body.items.map(x => Object.keys(x).length));
  assert(!r.body.items.some(x => x.guest_name === "Telefon"), "telefonske rezervacije niso v seznamu kupca");
  assert(r.body.items.find(x => x.event_title === "Prej").guest_name === "Ana in prijatelji", "vpisano ime se vrne");
  r = await api("GET", "/me/table-reservations", T.ben);
  assert(r.status === 200 && r.body.items.every(x => x.guest_name !== "ana") && r.body.items.length === 1 && r.body.items[0].event_id === ED, "ben vidi samo svoje (1 rezervacija na ED)", r.body.items.map(x => [x.event_title, x.guest_name]));
  r = await api("GET", "/me/table-reservations", T.brez);
  assert(r.status === 200 && r.body.items.length === 0, "uporabnik brez rezervacij: prazen seznam", r.body);

  console.log("\n# 12. Hkratnost (I13): 8 hkratnih rezervacij iste mize, 6 hkratnih rezervacij enega uporabnika");
  const EH = await dogodek(1, "Hkrati", "4 days");
  await api("PUT", `/business/events/${EH}/vip`, T.lastnik, { enabled: true, payment: "door" });
  let rs = await Promise.all(kupci.map(t => rez(t, EH, M2, { package_id: P1 })));
  assert(rs.filter(x => x.status === 201).length === 1 && rs.filter(x => x.status === 409).length === 7, "natanko 1 od 8 hkratnih rezervacij iste mize uspe, 7 dobi 409", rs.map(x => x.status));
  assert(await rezervacij(EH) === 1, "v bazi 1 rezervacija");
  rs = await Promise.all([M1, M3, M4, M5, M6, M3].map(m => rez(T.dan, EH, m, { package_id: P1 })));
  assert(rs.filter(x => x.status === 201).length === 1 && rs.filter(x => x.status === 409 && x.body.error === "reservation_limit").length === 5, "natanko 1 od 6 hkratnih rezervacij enega uporabnika uspe, 5 reservation_limit", rs.map(x => [x.status, x.body.error]));
  assert((await pool.query("SELECT COUNT(*)::int AS n FROM table_holds WHERE event_id=$1 AND user_id=$2", [EH, await uid("dan@outly.si")])).rows[0].n === 1, "dan ima v bazi 1 rezervacijo");
  // nakup + rezervacija hkrati preko preklopa: app dogodek EA, 6 nakupov T6 in rezervacije so izkljucni (po preklopu na door)
  rs = await Promise.all([...kupci.slice(0, 4).map(t => nakup(t, EH, M6, { package_id: P1 })), ...kupci.slice(4).map(t => rez(t, EH, M6, { package_id: P1 }))]);
  assert(rs.slice(0, 4).every(x => x.status === 409 && x.body.error === "vip_pay_at_door"), "hkrati: nakupi na door dogodku vsi vip_pay_at_door", rs.slice(0, 4).map(x => x.status));
  assert((await pool.query("SELECT COUNT(*)::int AS n FROM table_holds WHERE event_id=$1 AND table_id=$2", [EH, M6])).rows[0].n <= 1, "T6: najvec 1 rezervacija");

  console.log("\n# 13. Baza (migracija 067): omejitve");
  const dan = await uid("dan@outly.si");
  const EDB = await dogodek(1, "Baza", "6 days");
  await pool.query("INSERT INTO table_holds (event_id, table_id, guest_name, source, user_id) VALUES ($1,$2,'dan','app',$3)", [EDB, M1, dan]);
  const ke = async (sql, args) => { try { await pool.query(sql, args); return null; } catch (e) { return e; } };
  let e = await ke("INSERT INTO table_holds (event_id, table_id, guest_name, source) VALUES ($1,$2,'x','app')", [EDB, M3]);
  assert(e && e.code === "23514", "source app brez user_id: baza zavrne (CHECK)", e && e.code);
  e = await ke("INSERT INTO table_holds (event_id, table_id, guest_name, source) VALUES ($1,$2,'x','mail')", [EDB, M3]);
  assert(e && e.code === "23514", "neveljaven source: baza zavrne", e && e.code);
  e = await ke("INSERT INTO table_holds (event_id, table_id, guest_name, source, user_id) VALUES ($1,$2,'x','app',$3)", [EDB, M3, dan]);
  assert(e && e.code === "23505" && e.constraint === "table_holds_app_uporabnik_key", "2. app rezervacija istega uporabnika na dogodku: delni unikaten indeks", e && e.constraint);
  e = await ke("INSERT INTO table_holds (event_id, table_id, guest_name, source, user_id, price_cents) VALUES ($1,$2,'x','app',$3,-1)", [EDB, M3, aid]);
  assert(e && e.code === "23514", "negativna cena: baza zavrne", e && e.code);
  e = await ke("INSERT INTO table_holds (event_id, table_id, guest_name) VALUES ($1,$2,'Tel 1'), ($1,$3,'Tel 2')", [EDB, M3, M4]);
  assert(e === null, "telefonske rezervacije (user_id NULL) niso omejene na 1");
  e = await ke("UPDATE events SET vip_payment = 'cash' WHERE id = $1", [EDB]);
  assert(e && e.code === "23514", "events.vip_payment: neveljavna vrednost zavrnjena (CHECK)", e && e.code);
  assert((await pool.query("SELECT column_default, is_nullable FROM information_schema.columns WHERE table_name='events' AND column_name='vip_payment'")).rows[0].is_nullable === "NO", "events.vip_payment NOT NULL");
  assert((await pool.query("SELECT COUNT(*)::int AS n FROM events WHERE vip_payment NOT IN ('app','door')")).rows[0].n === 0, "vsi dogodki imajo veljaven vip_payment");
  assert((await pool.query("SELECT vip_payment FROM events WHERE id=$1", [E2])).rows[0].vip_payment === "door", "tuj dogodek: door");

  console.log("\n# 14. Izbris racuna sprosti mizo (ON DELETE CASCADE)");
  const EC = await dogodek(1, "Cascade", "5 days");
  await api("PUT", `/business/events/${EC}/vip`, T.lastnik, { enabled: true, payment: "door" });
  r = await rez(T.cara, EC, M2, { package_id: P1 });
  assert(r.status === 201, "cara rezervira T2 na EC", r.body);
  await pool.query("DELETE FROM users WHERE id=$1", [await uid("cara@outly.si")]);
  assert(await rezervacij(EC) === 0, "po izbrisu uporabnika je rezervacija izginila");
  r = await rez(T.ben, EC, M2, { package_id: P1 });
  assert(r.status === 201, "miza je spet prosta (ben jo rezervira)", r.body);

  console.log("\n# 15. Pospravljalec brise tudi app rezervacije po koncu dogodka + 24 h");
  const EP = await dogodek(1, "Staro", "-60 hours");
  await pool.query("UPDATE events SET start_at = NOW() - INTERVAL '60 hours', end_at = NOW() - INTERVAL '40 hours' WHERE id=$1", [EP]);
  await pool.query("INSERT INTO table_holds (event_id, table_id, guest_name, source, user_id, package_name, price_cents) VALUES ($1,$2,'stara','app',$3,'Jameson 0,7 l',30000)", [EP, M1, aid]);
  await pool.query("INSERT INTO table_holds (event_id, table_id, guest_name, source, user_id, price_cents) VALUES ($1,$2,'sveza','app',$3,1000)", [EK5, M2, await uid("ben@outly.si")]);
  const srvC = await zazeni(PORT_C, { REZERVACIJE_CISCENJE_MS: "400" });
  let ostalo = null;
  for (let i = 0; i < 40; i++) { ostalo = await rezervacij(EP); if (ostalo === 0) break; await spi(250); }
  assert(ostalo === 0, "app rezervacija dogodka, koncanega pred 40 h, je pobrisana", ostalo);
  assert((await pool.query("SELECT COUNT(*)::int AS n FROM table_holds WHERE event_id=$1 AND table_id=$2", [EK5, M2])).rows[0].n === 1, "app rezervacija dogodka, koncanega pred 5 h, ostane");
  await ustavi(srvC);

  console.log("\n# 15b. Odpovedan/skrit dogodek ni v GET /me/table-reservations; zavrniVipNaVratih ne razkrije nastavitve");
  const ES = await dogodek(1, "Skrivni", "7 days");
  await api("PUT", `/business/events/${ES}/vip`, T.lastnik, { enabled: true, payment: "door" });
  r = await rez(T.ana, ES, M3, { package_id: P1 });
  assert(r.status === 201, "ana rezervira na ES", r.body);
  let sez2 = (await api("GET", "/me/table-reservations", T.ana)).body.items;
  assert(sez2.some(x => x.event_id === ES), "ES je v seznamu (objavljen)");
  await pool.query("UPDATE events SET status='cancelled' WHERE id=$1", [ES]);
  sez2 = (await api("GET", "/me/table-reservations", T.ana)).body.items;
  assert(!sez2.some(x => x.event_id === ES) && sez2.length > 0, "odpovedan dogodek ni v seznamu (ostale so)", sez2.map(x => x.event_title));
  await pool.query("UPDATE events SET status='published' WHERE id=$1", [ES]);
  await pool.query("UPDATE clubs SET hidden = TRUE WHERE id=1");
  sez2 = (await api("GET", "/me/table-reservations", T.ana)).body.items;
  assert(sez2.length === 0, "skrit klub: seznam prazen", sez2.map(x => x.event_title));
  r = await nakup(T.ben, ES, M2, { package_id: P1 });
  assert(!(r.body && r.body.error === "vip_pay_at_door") && r.status === 409 && /not on sale/i.test(String(r.body)), "skrit klub: nakup ne razkrije nastavitve (obstojeca pot: not on sale)", [r.status, r.body]);
  await pool.query("UPDATE clubs SET hidden = FALSE WHERE id=1");
  await pool.query("UPDATE events SET status='draft' WHERE id=$1", [ES]);
  r = await nakup(T.ben, ES, M2, { package_id: P1 });
  assert(!(r.body && r.body.error === "vip_pay_at_door") && r.status === 409, "osnutek: nakup ne razkrije nastavitve", [r.status, r.body]);
  r = await nakup(T.ben, 999999, M2, { package_id: P1 });
  assert(r.status === 404, "neobstojec dogodek: 404 (ne vip_pay_at_door)", [r.status, r.body]);
  await pool.query("UPDATE events SET status='published' WHERE id=$1", [ES]);
  r = await nakup(T.ben, ES, M2, { package_id: P1 });
  assert(r.status === 409 && r.body.error === "vip_pay_at_door", "objavljen dogodek: vip_pay_at_door", r.body);

  console.log("\n# 15c. razprodanoOznaci: zasedena miza se pomni (kot pri nakupu), preklic jo pozabi");
  const ER = await dogodek(1, "Razprodano", "8 days");
  await api("PUT", `/business/events/${ER}/vip`, T.lastnik, { enabled: true, payment: "door" });
  await zazeni(PORT_E);   // privzeta oznaka (3 s)
  const rezE = (tok, e, m) => apiNa(`http://127.0.0.1:${PORT_E}`, "POST", `/events/${e}/tables/${m}/reservations`, tok, { package_id: P1 });
  const preklicE = (tok, e, m) => apiNa(`http://127.0.0.1:${PORT_E}`, "DELETE", `/events/${e}/tables/${m}/reservations`, tok);
  r = await rezE(T.ana, ER, M2); assert(r.status === 201, "ana rezervira T2", r.body);
  r = await rezE(T.ben, ER, M2); assert(r.status === 409 && r.body === "This table is already booked.", "ben: 409 (oznaci mizo kot zasedeno)", r.body);
  await pool.query("DELETE FROM table_holds WHERE event_id=$1", [ER]);   // mimo API-ja: pomnilnik ne ve
  r = await rezE(T.ben, ER, M2);
  assert(r.status === 409 && r.body === "This table is already booked.", "takoj po brisanju v bazi: se vedno 409 iz pomnilnika (zavrniRazprodanoMizo, brez baze)", r.body);
  await spi(3300);
  r = await rezE(T.ben, ER, M2); assert(r.status === 201, "po izteku oznake ben rezervira", r.body);
  r = await rezE(T.dan, ER, M2); assert(r.status === 409, "dan: 409", r.body);
  r = await preklicE(T.ben, ER, M2); assert(r.status === 200, "ben prekliche", r.body);
  r = await rezE(T.dan, ER, M2); assert(r.status === 201, "TAKOJ po preklicu dan rezervira (preklic pozabi oznako)", r.body);

  console.log("\n# 15d. Semafor nakupov varuje glavni pool: naval na zaklenjeno mizo ne ustavi ostalih poti");
  const EW = await dogodek(1, "Semafor", "9 days");
  await api("PUT", `/business/events/${EW}/vip`, T.lastnik, { enabled: true, payment: "door" });
  const srvD = await zazeni(PORT_D, { NAKUP_VZPOREDNO: "2", PG_POOL_MAX: "4", NAKUP_CAKANJE_MS: "6000", NAKUP_DB_TIMEOUT_MS: "2500" });
  const BASE_D = `http://127.0.0.1:${PORT_D}`;
  const zaklep = await pool.connect();
  await zaklep.query("BEGIN");
  await zaklep.query("SELECT id FROM club_tables WHERE id=$1 FOR SHARE", [M6]);   // konflikt s FOR NO KEY UPDATE rezervacije
  const naval = kupci.concat([T.ben, T.cara]).map(t => apiNa(BASE_D, "POST", `/events/${EW}/tables/${M6}/reservations`, t, { package_id: P1 }));
  await spi(500);
  const t0 = Date.now();
  const me = await apiNa(BASE_D, "GET", "/me", T.ana);
  const ms = Date.now() - t0;
  assert(me.status === 200 && ms < 1000, "GET /me ne caka na zaklep mize med navalom 10 rezervacij (pool 4, semafor 2)", { status: me.status, ms });
  const izidiNavala = await Promise.all(naval);
  await zaklep.query("ROLLBACK"); zaklep.release();
  assert(izidiNavala.every(x => [201, 409, 503].includes(x.status)) && izidiNavala.filter(x => x.status === 201).length <= 1, "naval: samo 201 (najvec ena), 409, 503; nikoli 500", izidiNavala.map(x => x.status));
  assert(await rezervacij(EW) <= 1, "po navalu najvec 1 rezervacija na mizi");
  await ustavi(srvD);

  console.log("\n# 16. Zasebnost: ime gosta in uporabnisko ime nista v dnevniku");
  const zasebno = /Ben & Co|Ana in prijatelji|Telefonski gost/;
  assert(!zasebno.test(log), "dnevnik ne vsebuje imen rezervacij", log.split("\n").filter(l => zasebno.test(l)).slice(0, 3));
  assert(/Rezervacija mize v aplikaciji: dogodek \d+, miza \d+, uporabnik \d+/.test(log), "dnevnik rezervacije obstaja (samo id-ji)", null);

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  const napake = log.split("\n").filter(l => /error|TypeError|Unhandled|deadlock/i.test(l) && !/Server error\./.test(l) && !/Resend/i.test(l));
  if (napake.length) console.log("\nLog backenda (sumljivo):\n" + napake.slice(0, 20).join("\n"));
  for (const s of procesi) { try { s.kill(); } catch (_) {} }
  jwksServer.close();
  await pool.query(TRUNC);
  await pool.end();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); for (const s of procesi) { try { s.kill(); } catch (_) {} } process.exit(1); });
