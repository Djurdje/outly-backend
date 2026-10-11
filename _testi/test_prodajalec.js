#!/usr/bin/env node
/**
 * Podatki prodajalca (kluba) za kupca in besedilo o DDV (issue #94 + #101, migracija 043). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_prodajalec.js
 * Vzorec kot test_organizatorji.js: lokalni JWKS, lazni Resend, backend na svojem portu (testni nacin placil: brez Stripe kljuca).
 *
 *   1  `seller` v GET /events/:id, /events/:id/vip, /clubs/:id, /guest/order (nadomestki imena in naslova, `complete`); NE v seznamih
 *   2  PATCH /business/clubs/me: owner nastavi polja (camelCase in snake_case, trim, null -> ""), GET /business/clubs/me ima surova polja in seller_complete
 *   3  manager: katero koli od petih polj -> 403 owner_only (nic se ne zapise, tudi ostala polja v istem zahtevku); ostala polja managerju delajo
 *   4  validacija: predolgo, napacen tip (niz, stevilo), vat_payer ni boolean/null -> 400; meje so vkljucne
 *   5  javni predpomnilnik: po PATCH-u je `seller` takoj nov (GET /events/:id in /clubs/:id), drugi gost dobi isti objekt
 *   6  gostovan dogodek: prodajalec je organizator (events.club_id), ne prizorisce (events, vip, guest/order)
 *   7  potrdila po e-posti (kupec z racunom in gost): firma, sedez, maticna, davcna, DDV status; stavek o DDV za vat_payer true / false / null in vat_rate ima prednost
 *   8  admin: polja v obrazcu (POST/PATCH /admin/api/clubs), seller_complete v seznamu, validacija
 *   9  stari odgovori nespremenjeni (vsa stara polja so se vedno tu), brez surovih polj in brez stripe_account_id v javnih odgovorih (I4)
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3281, JWKS_PORT = 3282, RESEND_PORT = 3283;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-prodajalec";
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
const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
async function api(method, p, token, body, glave = {}) {
  const r = await fetch(BASE + p, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}), ...glave },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, text: t };
}
const pocakaj = (ms) => new Promise(r => setTimeout(r, ms));
async function cakaj(pogoj, ms = 6000) { const do_ = Date.now() + ms; while (Date.now() < do_) { if (await pogoj()) return true; await pocakaj(100); } return false; }

// ---------- lazni Resend ----------
const poslano = [];
const resendServer = http.createServer((req, res) => {
  let d = ""; req.on("data", x => d += x);
  req.on("end", () => {
    if (req.method === "POST" && req.url === "/emails") {
      poslano.push(JSON.parse(d));
      res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify({ id: "mail_" + poslano.length }));
    }
    res.writeHead(404, { "content-type": "application/json" }); res.end("{}");
  });
});
const poslanoNa = (email) => poslano.filter(m => m.to === email || (Array.isArray(m.to) && m.to.includes(email)));

const SELLER_KLJUCI = ["name", "address", "registration_number", "tax_number", "vat_payer", "phone", "email", "complete"];
const SUROVA = ["legal_name", "legal_address", "registration_number", "tax_number", "vat_payer"];
const ima = (o, ks) => ks.every(k => k in o);
const natanko = (o, ks) => Object.keys(o).length === ks.length && ima(o, ks);

let srv = null;
(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, guest_list_members, guest_lists, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  await new Promise(r => resendServer.listen(RESEND_PORT, r));
  srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "re_test",
    RESEND_BASE_URL: `http://127.0.0.1:${RESEND_PORT}`, EMAIL_FROM: "Outly <test@outly.test>", QR_SECRET: "test", APP_URL: "https://outly.test",
    STRIPE_SECRET_KEY: "", STRIPE_WEBHOOK_SECRET: "", TEST_PLACILA: "", JAVNI_PREDPOMNILNIK_MS: "60000", GOST_NAKUP_NA_URO: "1000" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await pocakaj(100); } }

  try {
    const T = {};
    for (const [i, ime] of ["admin", "lastnik", "manager", "orglastnik", "gostlastnik", "ana", "bor"].entries()) T[ime] = zeton(`${ime}@outly.si`, uuid(i + 1));
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("UPDATE users SET role='business' WHERE email IN ('lastnik@outly.si','orglastnik@outly.si','gostlastnik@outly.si')");
    const uid = async (ime) => (await pool.query("SELECT id FROM users WHERE email=$1", [`${ime}@outly.si`])).rows[0].id;
    const rojstvo = new Date(Date.now() - 25 * 365.25 * 24 * 3600 * 1000).toISOString().slice(0, 10);
    for (const k of ["ana", "bor"]) await api("PATCH", "/me", T[k], { dateOfBirth: rojstvo });
    // Klub 1: "stari" klub (samo stolpci pred 043), s kontaktom. Klub 2: organizator (pisarna). Klub 3: gostitelj.
    const klub = (await pool.query(
      `INSERT INTO clubs (owner_user_id, name, city, address, contact_phone, contact_email) VALUES ($1, 'Stolpni Klub', 'Ljubljana', 'Slovenska 1', '+38640111222', 'info@stolpni.si') RETURNING id`, [await uid("lastnik")])).rows[0].id;
    const org = (await pool.query(
      `INSERT INTO clubs (owner_user_id, name, city, address, contact_email, is_organizer) VALUES ($1, 'Promotor X', 'Kranj', 'Pisarna 5', 'promotor@x.si', TRUE) RETURNING id`, [await uid("orglastnik")])).rows[0].id;
    const gost = (await pool.query(
      `INSERT INTO clubs (owner_user_id, name, city, address, contact_phone, contact_email) VALUES ($1, 'Gostitelj Klub', 'Celje', 'Gostiteljeva 1', '+38641999888', 'gostitelj@g.si') RETURNING id`, [await uid("gostlastnik")])).rows[0].id;
    await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES ($1, $2, 'manager')", [klub, await uid("manager")]);
    const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    const dogodek = async (token, clubId, title, extra = {}) => {
      const r = await api("POST", "/events", token, { clubId, title, startAt: cezDan, ticketPriceCents: 1500, capacity: 50, minAge: 0, ...extra });
      assert(r.status === 201, `dogodek ${title}`, r.body); return r.body.id;
    };
    const ev1 = await dogodek(T.lastnik, klub, "Stolpna noc");
    const evHost = await dogodek(T.orglastnik, org, "Org noc", { venueClubId: gost });
    const evVat = await dogodek(T.lastnik, klub, "Noc z DDV");
    const evVat2 = await dogodek(T.lastnik, klub, "Noc z DDV 2");
    const stolpecKluba = async (id) => (await pool.query("SELECT legal_name, legal_address, registration_number, tax_number, vat_payer FROM clubs WHERE id=$1", [id])).rows[0];

    // ============================================================
    console.log("\n# 1. seller: oblika, nadomestki, seznami ga nimajo");
    let r = await api("GET", `/events/${ev1}`);
    const praznoSeller = { name: "Stolpni Klub", address: "Slovenska 1, Ljubljana", registration_number: "", tax_number: "", vat_payer: null, phone: "+38640111222", email: "info@stolpni.si", complete: false };
    assert(r.status === 200 && r.body.seller && natanko(r.body.seller, SELLER_KLJUCI), "GET /events/:id: seller ima natanko 8 polj", r.body.seller);
    assert(JSON.stringify(r.body.seller) === JSON.stringify(praznoSeller), "stari klub (brez podatkov): nadomestek imena in naslova, prazni nizi, vat_payer null, complete false", r.body.seller);
    r = await api("GET", `/clubs/${klub}`);
    assert(r.status === 200 && JSON.stringify(r.body.seller) === JSON.stringify(praznoSeller), "GET /clubs/:id: isti seller", r.body.seller);
    r = await api("GET", `/events/${ev1}/vip`);
    assert(r.status === 200 && JSON.stringify(r.body.seller) === JSON.stringify(praznoSeller), "GET /events/:id/vip: isti seller", r.body.seller);
    r = await api("GET", "/events");
    assert(r.status === 200 && r.body.length >= 3 && r.body.every(e => !("seller" in e) && !("seller_raw" in e)), "GET /events (seznam): brez sellerja", Object.keys(r.body[0] || {}));
    r = await api("GET", "/clubs");
    assert(r.status === 200 && r.body.length === 3 && r.body.every(c => !("seller" in c) && ["legal_name", "legal_address", "tax_number", "vat_payer"].every(k => !(k in c))), "GET /clubs (seznam): brez sellerja in surovih polj", Object.keys(r.body[0] || {}));
    r = await api("GET", `/clubs/${klub}`);
    assert(r.status === 200 && SUROVA.every(k => !(k in r.body)), "GET /clubs/:id: surova polja NISO v javnem odgovoru (samo seller)", Object.keys(r.body));
    r = await api("GET", `/events/${evHost}`);
    assert(r.status === 200 && r.body.seller.name === "Promotor X" && r.body.seller.address === "Pisarna 5, Kranj" && r.body.seller.phone === "" && r.body.seller.email === "promotor@x.si",
      "organizator brez telefona: phone je \"\", email je", r.body.seller);

    // ============================================================
    console.log("\n# 2. Lastnik nastavi podatke");
    r = await api("GET", "/business/clubs/me", T.lastnik);
    assert(r.status === 200 && r.body.legal_name === "" && r.body.legal_address === "" && r.body.registration_number === "" && r.body.tax_number === "" && r.body.vat_payer === null && r.body.seller_complete === false && r.body.my_role === "owner",
      "GET /business/clubs/me (star klub): surova polja prazna, vat_payer null, seller_complete false", r.body);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { legalName: "  Stolpni Klub d.o.o.  ", legalAddress: "Slovenska cesta 1, 1000 Ljubljana", registrationNumber: "1234567000", taxNumber: "SI12345678" });
    assert(r.status === 200 && r.body.legal_name === "Stolpni Klub d.o.o." && r.body.legal_address === "Slovenska cesta 1, 1000 Ljubljana" && r.body.registration_number === "1234567000" && r.body.tax_number === "SI12345678",
      "PATCH (camelCase, trim): polja shranjena in vrnjena", r.body);
    assert(r.body.vat_payer === null && r.body.seller_complete === false, "brez DDV statusa seller_complete ostane false", [r.body.vat_payer, r.body.seller_complete]);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { vat_payer: true });
    assert(r.status === 200 && r.body.vat_payer === true && r.body.seller_complete === true, "PATCH (snake_case) vat_payer true -> seller_complete true", r.body);
    r = await api("GET", "/business/clubs/me", T.lastnik);
    assert(r.status === 200 && r.body.legal_name === "Stolpni Klub d.o.o." && r.body.vat_payer === true && r.body.seller_complete === true, "GET /business/clubs/me: surova polja + seller_complete", r.body);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { vatPayer: false });
    assert(r.status === 200 && r.body.vat_payer === false && r.body.seller_complete === true, "vatPayer false je veljaven status (complete ostane true)", r.body);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { vatPayer: null, taxNumber: null });
    assert(r.status === 200 && r.body.vat_payer === null && r.body.tax_number === "" && r.body.seller_complete === false, "null: vat_payer -> null, taxNumber -> \"\", complete false", r.body);
    await api("PATCH", "/business/clubs/me", T.lastnik, { taxNumber: "SI12345678", vatPayer: true });
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { contactPhone: "", contactEmail: "" });
    assert(r.status === 200 && r.body.seller_complete === false, "brez telefona in e-naslova seller_complete false", r.body);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { contactEmail: "info@stolpni.si" });
    assert(r.status === 200 && r.body.seller_complete === true, "samo e-naslov zadostuje za kontakt (complete true)", r.body);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { contactPhone: "+38640111222" });
    const poln = { name: "Stolpni Klub d.o.o.", address: "Slovenska cesta 1, 1000 Ljubljana", registration_number: "1234567000", tax_number: "SI12345678", vat_payer: true, phone: "+38640111222", email: "info@stolpni.si", complete: true };
    r = await api("GET", `/events/${ev1}`);
    assert(JSON.stringify(r.body.seller) === JSON.stringify(poln), "GET /events/:id: seller s firmo in sedezem (brez nadomestkov), complete true", r.body.seller);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, {});
    assert(r.status === 200 && r.body.legal_name === "Stolpni Klub d.o.o." && r.body.seller_complete === true, "prazen PATCH vrne klub s surovimi polji in seller_complete", r.body);

    // ============================================================
    console.log("\n# 3. Manager: owner_only");
    const pred = await stolpecKluba(klub);
    for (const [ime, telo] of [["legalName", { legalName: "Hekerski d.o.o." }], ["legal_address", { legal_address: "Drugje 1" }], ["registrationNumber", { registrationNumber: "1" }],
      ["taxNumber", { taxNumber: "SI1" }], ["vatPayer", { vatPayer: false }], ["vat_payer null", { vat_payer: null }], ["isto vrednost", { legalName: "Stolpni Klub d.o.o." }]]) {
      r = await api("PATCH", "/business/clubs/me", T.manager, telo);
      assert(r.status === 403 && r.body && r.body.error === "owner_only" && typeof r.body.message === "string", `manager: ${ime} -> 403 owner_only`, r);
    }
    r = await api("PATCH", "/business/clubs/me", T.manager, { description: "Manager je spremenil opis", taxNumber: "SI999" });
    assert(r.status === 403 && r.body.error === "owner_only", "manager: opis + davcna v istem zahtevku -> 403", r.status);
    const po = await stolpecKluba(klub);
    assert(JSON.stringify(po) === JSON.stringify(pred), "baza: nobeno polje prodajalca se ni spremenilo", [pred, po]);
    r = await pool.query("SELECT description FROM clubs WHERE id=$1", [klub]);
    assert(r.rows[0].description !== "Manager je spremenil opis", "ob 403 se tudi opis v istem zahtevku NI zapisal");
    r = await api("PATCH", "/business/clubs/me", T.manager, { description: "Opis od managerja", contactPhone: "+38640555666" });
    assert(r.status === 200 && r.body.description === "Opis od managerja" && r.body.contact_phone === "+38640555666", "manager: ostala polja delajo (opis, telefon)", r.body);
    assert(r.body.legal_name === "Stolpni Klub d.o.o." && r.body.seller_complete === true, "odgovor managerju ima surova polja prodajalca", r.body);
    r = await api("GET", "/business/clubs/me", T.manager);
    assert(r.status === 200 && r.body.my_role === "manager" && r.body.legal_name === "Stolpni Klub d.o.o." && r.body.seller_complete === true, "manager lahko BERE podatke (GET), le ne spreminja", r.body);
    r = await api("PATCH", "/business/clubs/me", T.manager, { name: "Stolpni Klub" });
    assert(r.status === 200, "manager: ime kluba se spreminja kot doslej", r.status);
    await api("PATCH", "/business/clubs/me", T.lastnik, { contactPhone: "+38640111222" });
    r = await api("PATCH", "/business/clubs/me", T.ana, { legalName: "X" });
    assert(r.status === 403 || r.status === 404, "navaden uporabnik brez kluba: ni dostopa", r.status);
    r = await api("PATCH", "/business/clubs/me", undefined, { legalName: "X" });
    assert(r.status === 401, "brez zetona 401", r.status);

    // ============================================================
    console.log("\n# 4. Validacija");
    const slabo = async (telo, msg) => { const x = await api("PATCH", "/business/clubs/me", T.lastnik, telo); assert(x.status === 400, msg, x); };
    await slabo({ legalName: "x".repeat(201) }, "legalName 201 znakov -> 400");
    await slabo({ legalAddress: "x".repeat(301) }, "legalAddress 301 znakov -> 400");
    await slabo({ registrationNumber: "1".repeat(21) }, "registrationNumber 21 znakov -> 400");
    await slabo({ taxNumber: "1".repeat(21) }, "taxNumber 21 znakov -> 400");
    await slabo({ legal_name: 5 }, "legal_name stevilo -> 400");
    await slabo({ taxNumber: ["SI1"] }, "taxNumber seznam -> 400");
    await slabo({ registrationNumber: { a: 1 } }, "registrationNumber objekt -> 400");
    await slabo({ vatPayer: "true" }, "vatPayer niz -> 400");
    await slabo({ vat_payer: 1 }, "vat_payer stevilo -> 400");
    await slabo({ vatPayer: "yes" }, "vatPayer \"yes\" -> 400");
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { legalName: "x".repeat(200), legalAddress: "y".repeat(300), registrationNumber: "1".repeat(20), taxNumber: "2".repeat(20) });
    assert(r.status === 200 && r.body.legal_name.length === 200 && r.body.legal_address.length === 300 && r.body.registration_number.length === 20 && r.body.tax_number.length === 20, "natanko na meji (200/300/20/20) je veljavno", r.status);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { legalName: "  " + "z".repeat(200) + "  " });
    assert(r.status === 200 && r.body.legal_name.length === 200, "meja velja za obrezan niz", r.status);
    const rs = await pool.query("SELECT legal_name FROM clubs WHERE id=$1", [klub]);
    assert(rs.rows[0].legal_name === "z".repeat(200), "baza: obrezano");
    await slabo({ legalName: "x".repeat(201), name: "Ne smem se zapisati" }, "neveljavno polje prodajalca zavrne cel zahtevek");
    const ime = await pool.query("SELECT name FROM clubs WHERE id=$1", [klub]);
    assert(ime.rows[0].name === "Stolpni Klub", "ime se ob 400 ni spremenilo");
    let e = null;
    try { await pool.query("UPDATE clubs SET tax_number = $1 WHERE id=$2", ["1".repeat(21), klub]); } catch (x) { e = x; }
    assert(e && e.code === "23514" && /clubs_tax_number_chk/.test(e.constraint || ""), "baza: CHECK dolzine zavrne tudi mimo API-ja", e && e.message);
    await api("PATCH", "/business/clubs/me", T.lastnik, { legalName: "Stolpni Klub d.o.o.", legalAddress: "Slovenska cesta 1, 1000 Ljubljana", registrationNumber: "1234567000", taxNumber: "SI12345678", vatPayer: true });

    // ============================================================
    console.log("\n# 5. Javni predpomnilnik: seller je po PATCH-u takoj nov");
    r = await api("GET", `/events/${ev1}`); const prej = r.body.seller;
    r = await api("GET", `/clubs/${klub}`);
    assert(r.body.seller.name === "Stolpni Klub d.o.o.", "predpomnjeni odgovor ima seller", r.body.seller);
    r = await api("GET", `/events/${ev1}`, T.ana);
    assert(JSON.stringify(r.body.seller) === JSON.stringify(prej) && "my_plan" in r.body, "prijavljen kupec dobi isti seller + svoja osebna polja", r.body.seller);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { legalName: "Preimenovana d.o.o." });
    assert(r.status === 200, "PATCH legalName");
    r = await api("GET", `/events/${ev1}`);
    assert(r.body.seller.name === "Preimenovana d.o.o.", "GET /events/:id takoj kaze novo firmo (razveljavitev predpomnilnika)", r.body.seller);
    r = await api("GET", `/clubs/${klub}`);
    assert(r.body.seller.name === "Preimenovana d.o.o.", "GET /clubs/:id takoj kaze novo firmo", r.body.seller);
    r = await api("GET", `/events/${ev1}`, T.bor);
    assert(r.body.seller.name === "Preimenovana d.o.o.", "drug kupec dobi isto", r.body.seller);
    await api("PATCH", "/business/clubs/me", T.lastnik, { legalName: "Stolpni Klub d.o.o." });

    // ============================================================
    console.log("\n# 6. Gostovan dogodek: prodajalec je organizator");
    await api("PATCH", "/business/clubs/me", T.orglastnik, { legalName: "Promotor X d.o.o.", legalAddress: "Pisarna 5, 4000 Kranj", registrationNumber: "7654321", taxNumber: "12345678", vatPayer: false, contactPhone: "+38631000111" });
    r = await api("GET", `/events/${evHost}`);
    assert(r.status === 200 && r.body.venue_club_id === gost && r.body.club_id === org, "dogodek je gostovan (prizorisce = Gostitelj Klub)", [r.body.venue_club_id, r.body.club_id]);
    assert(r.body.seller.name === "Promotor X d.o.o." && r.body.seller.tax_number === "12345678" && r.body.seller.vat_payer === false && r.body.seller.complete === true && !JSON.stringify(r.body.seller).includes("Gostitelj"),
      "GET /events/:id: seller = organizator, ne prizorisce", r.body.seller);
    r = await api("GET", `/events/${evHost}/vip`);
    assert(r.status === 200 && r.body.seller.name === "Promotor X d.o.o." && r.body.seller.vat_payer === false, "GET /events/:id/vip: seller = organizator", r.body.seller);
    const TERMS = { accept_terms: true, terms_version: "2026-10-01" };
    r = await api("POST", `/guest/events/${evHost}/orders`, null, { email: "gost.host@example.com", quantity: 1, ...TERMS });
    assert(r.status === 201 && r.body.guest_token, "gostujoci nakup na gostovanem dogodku", r.body);
    const zetonGost = r.body.guest_token;
    r = await api("GET", "/guest/order", null, undefined, { "x-guest-token": zetonGost });
    assert(r.status === 200 && JSON.stringify(r.body.seller) === JSON.stringify(r.body.order.seller), "GET /guest/order: seller na vrhu = order.seller", r.body.seller);
    assert(r.body.seller.name === "Promotor X d.o.o." && r.body.seller.address === "Pisarna 5, 4000 Kranj" && r.body.seller.registration_number === "7654321" && r.body.seller.complete === true && natanko(r.body.seller, SELLER_KLJUCI),
      "seller = organizator (firma, sedez, maticna), ne gostitelj", r.body.seller);
    assert(r.body.order.event.venue_club_name === "Gostitelj Klub" && r.body.order.event.address === "Gostiteljeva 1" && r.body.order.club_name === "Promotor X", "ostala polja naročila nespremenjena (prizorisce = gostitelj, club_name = organizator)", r.body.order.event);
    r = await api("GET", "/guest/order", null, undefined, { "x-guest-token": "napacen" });
    assert(r.status === 404, "napacen zeton: se vedno 404 (brez sellerja)", r.status);

    // ============================================================
    console.log("\n# 7. Potrdila po e-posti");
    const mail = async (email) => { await cakaj(() => poslanoNa(email).length >= 1); await pocakaj(300); return poslanoNa(email); };
    const nakup = (token, ev) => api("POST", `/events/${ev}/orders`, token, { quantity: 1 });
    // gost, organizator: vat_payer false, vat_rate NULL
    let m = await mail("gost.host@example.com");
    let t = (m[0] && m[0].text) || "";
    assert(m.length === 1, "gost: natanko en mail", m.length);
    assert(/SELLER\nThe ticket is sold by the club: Promotor X d\.o\.o\., Pisarna 5, 4000 Kranj, \+38631000111, promotor@x\.si\.\n/.test(t), "gost: firma, sedez, telefon, e-naslov (organizator)", t.split("SELLER")[1]);
    assert(t.includes("Company registration number: 7654321. Tax number: 12345678."), "gost: maticna in davcna stevilka", t);
    assert(t.includes("VAT status: the seller is not a VAT payer.") && t.includes("The seller is not a VAT payer; no VAT is charged."), "gost: vat_payer false -> stavek v Tickets in DDV status", t);
    assert(t.includes("Status DDV: prodajalec ni zavezanec za DDV.") && t.includes("Prodajalec ni zavezanec za DDV, zato DDV ni obračunan.") && t.indexOf("Status DDV") < t.indexOf("VAT status:"), "gost (sl, pred en): vat_payer false -> »Prodajalec ni zavezanec za DDV«", t);
    assert(/PRODAJALEC\nVstopnico prodaja klub: Promotor X d\.o\.o\., Pisarna 5, 4000 Kranj, \+38631000111, promotor@x\.si\.\nMatična številka: 7654321\. Davčna številka: 12345678\./.test(t), "gost (sl): firma, sedez, kontakt, maticna in davcna stevilka", t.split("PRODAJALEC")[1]);
    assert(/EVENT\n[^]*Gostitelj Klub, Gostiteljeva 1, Celje[^]*SELLER/.test(t), "gost: prizorisce (gostitelj) je v razdelku Event", t.split("SELLER")[0]);
    assert(!/SELLER[^]*Gostitelj[^]*NO RIGHT/.test(t), "gost: gostitelj NI v razdelku Seller", t.split("SELLER")[1]);
    assert(t.includes("Outly is only the intermediary"), "gost: Outly je posrednik");
    // kupec z racunom: vat_payer true
    r = await nakup(T.ana, ev1);
    assert(r.status === 201, "nakup (ana, vat_payer true)", r.body);
    m = await mail("ana@outly.si"); t = (m[0] && m[0].text) || "";
    assert(m.length === 1 && /SELLER\nThe ticket is sold by the club: Stolpni Klub d\.o\.o\., Slovenska cesta 1, 1000 Ljubljana, \+38640111222, info@stolpni\.si\.\n/.test(t), "kupec: firma, sedez, kontakt", t.split("SELLER")[1]);
    assert(t.includes("Company registration number: 1234567000. Tax number: SI12345678."), "kupec: maticna in davcna stevilka");
    assert(t.includes("1 x 15.00 EUR = 15.00 EUR. The price includes VAT.") && t.includes("VAT status: the seller is a VAT payer.") && !t.includes("VAT is charged according"), "kupec: vat_payer true -> »The price includes VAT.«", t);
    assert(t.includes("1 x 15,00 EUR = 15,00 EUR. Cena vključuje DDV.") && t.includes("Status DDV: prodajalec je zavezanec za DDV.") && !t.includes("DDV se obračuna v skladu"), "kupec (sl): vat_payer true -> »Cena vključuje DDV.«", t);
    // kupec: vat_payer null, brez matične
    await pool.query("UPDATE clubs SET vat_payer = NULL, registration_number = '', tax_number = '' WHERE id=$1", [klub]);
    r = await nakup(T.ana, evVat);
    assert(r.status === 201, "nakup (ana, vat_payer null)");
    await cakaj(() => poslanoNa("ana@outly.si").length >= 2); await pocakaj(300);
    t = (poslanoNa("ana@outly.si")[1] || {}).text || "";
    assert(t.includes("15.00 EUR. VAT is charged according to the seller's VAT status.") && !t.includes("VAT status:") && !t.includes("Company registration") && !t.includes("Tax number"), "kupec: vat_payer null -> obstojeci stavek, brez prazne maticne/davcne vrstice", t.split("SELLER")[1]);
    assert(t.includes("15,00 EUR. DDV se obračuna v skladu s statusom prodajalca.") && !t.includes("Status DDV") && !t.includes("Matična številka") && !t.includes("Davčna številka"), "kupec (sl): vat_payer null -> »DDV se obračuna v skladu s statusom prodajalca«, brez prazne vrstice", t.split("PRODAJALEC")[1]);
    // kupec: vat_payer false
    await pool.query("UPDATE clubs SET vat_payer = FALSE WHERE id=$1", [klub]);
    r = await nakup(T.ana, evVat2);
    assert(r.status === 201, "nakup (ana, vat_payer false)");
    await cakaj(() => poslanoNa("ana@outly.si").length >= 3); await pocakaj(300);
    t = (poslanoNa("ana@outly.si")[2] || {}).text || "";
    assert(t.includes("The seller is not a VAT payer; no VAT is charged.") && t.includes("VAT status: the seller is not a VAT payer."), "kupec: vat_payer false -> »The seller is not a VAT payer; no VAT is charged.«", t.split("SELLER")[1]);
    assert(t.includes("Prodajalec ni zavezanec za DDV, zato DDV ni obračunan.") && t.includes("Status DDV: prodajalec ni zavezanec za DDV."), "kupec (sl): vat_payer false -> »Prodajalec ni zavezanec za DDV«", t.split("PRODAJALEC")[1]);
    // vat_rate ima prednost (stopnja, zamrznjena na narocilu)
    await pool.query("UPDATE events SET vat_rate = 0.22 WHERE id=$1", [ev1]);
    await pool.query("UPDATE clubs SET vat_payer = TRUE WHERE id=$1", [klub]);
    r = await nakup(T.bor, ev1);
    assert(r.status === 201, "nakup (bor, vat_rate 0.22)");
    m = await mail("bor@outly.si"); t = (m[0] && m[0].text) || "";
    assert(t.includes("The price includes VAT (22%).") && !t.includes("The price includes VAT.\n"), "vat_rate 22 % ima prednost pred vat_payer", t.split("TICKETS")[1]);
    assert(t.includes("Cena vključuje DDV (22 %).") && !t.includes("Cena vključuje DDV.\n"), "vat_rate 22 % ima prednost pred vat_payer (sl)", t.split("VSTOPNICE")[1]);
    // gost: vat_payer null -> obstojeci stavek; klub brez firme -> ime kluba
    await pool.query("UPDATE clubs SET vat_payer = NULL, legal_name = '', legal_address = '' WHERE id=$1", [klub]);
    await pool.query("UPDATE events SET vat_rate = NULL WHERE id=$1", [ev1]);
    r = await api("POST", `/guest/events/${evVat}/orders`, null, { email: "gost.null2@example.com", quantity: 1, ...TERMS });
    assert(r.status === 201, "gostujoci nakup (vat_payer null, brez firme)");
    m = await mail("gost.null2@example.com"); t = (m[0] && m[0].text) || "";
    assert(/The ticket is sold by the club: Stolpni Klub, Slovenska 1, Ljubljana, /.test(t) && t.includes("15.00 EUR. VAT is charged according to the seller's VAT status."), "gost: brez firme se uporabi ime in naslov kluba; null -> obstojeci stavek", t.split("SELLER")[1]);
    assert(!/Resend napaka|\[potrdilo\] POZOR/.test(log), "brez napak pri posiljanju", log.slice(-300));

    // ============================================================
    console.log("\n# 8. Admin");
    r = await api("POST", "/admin/api/clubs", T.admin, { ownerEmail: "bor@outly.si", name: "Admin Klub", city: "Maribor", contactEmail: "a@a.si",
      legalName: "Admin Klub s.p.", legalAddress: "Trg 1, 2000 Maribor", registrationNumber: "5555555", taxNumber: "SI55555555", vatPayer: true });
    assert(r.status === 201 && r.body.legal_name === "Admin Klub s.p." && r.body.tax_number === "SI55555555" && r.body.vat_payer === true && r.body.seller_complete === true, "admin POST: polja prodajalca + seller_complete", r.body);
    const adminKlub = r.body.id;
    r = await api("POST", "/admin/api/clubs", T.admin, { ownerEmail: "ana@outly.si", name: "Admin Klub 2", city: "Maribor" });
    assert(r.status === 201 && r.body.legal_name === "" && r.body.vat_payer === null && r.body.seller_complete === false, "admin POST brez podatkov: prazna polja, seller_complete false", r.body);
    const prazni = r.body.id;
    r = await api("GET", "/admin/api/clubs", T.admin);
    const aK = r.body.find(k => k.id === adminKlub), aP = r.body.find(k => k.id === prazni), aS = r.body.find(k => k.id === klub);
    assert(r.status === 200 && aK.seller_complete === true && aP.seller_complete === false && SUROVA.every(k => k in aK), "admin GET: polja + seller_complete v seznamu (oznaka »podatki manjkajo«)", [aK, aP]);
    assert(aS && aS.seller_complete === false, "admin GET: klub z delnimi podatki je oznacen kot nepopoln", aS);
    r = await api("PATCH", `/admin/api/clubs/${prazni}`, T.admin, { legal_name: "Prazni d.o.o.", vat_payer: false });
    assert(r.status === 200 && r.body.legal_name === "Prazni d.o.o." && r.body.vat_payer === false && r.body.seller_complete === false, "admin PATCH (snake_case): nastavi, se vedno nepopoln", r.body);
    r = await api("PATCH", `/admin/api/clubs/${prazni}`, T.admin, { name: "Preimenovan" });
    assert(r.status === 200 && r.body.legal_name === "Prazni d.o.o." && r.body.vat_payer === false, "admin PATCH drugega polja ne izbrise podatkov prodajalca", r.body);
    r = await api("PATCH", `/admin/api/clubs/${prazni}`, T.admin, { vatPayer: "ne" });
    assert(r.status === 400, "admin: vatPayer niz -> 400", r.status);
    r = await api("PATCH", `/admin/api/clubs/${prazni}`, T.admin, { taxNumber: "1".repeat(21) });
    assert(r.status === 400, "admin: davcna predolga -> 400", r.status);
    r = await api("PATCH", `/admin/api/clubs/${prazni}`, T.admin, { legalName: 7 });
    assert(r.status === 400, "admin: legalName stevilo -> 400", r.status);
    r = await api("PATCH", `/admin/api/clubs/${prazni}`, T.admin, { vatPayer: null, legalName: null });
    assert(r.status === 200 && r.body.vat_payer === null && r.body.legal_name === "", "admin: null pocisti", r.body);
    r = await api("GET", "/admin/api/clubs", T.lastnik);
    assert(r.status === 403 || r.status === 401, "lastnik ne vidi admin API-ja", r.status);
    r = await api("GET", `/clubs/${adminKlub}`);
    assert(r.status === 200 && r.body.seller.name === "Admin Klub s.p." && r.body.seller.complete === true, "javni seller po adminovem zapisu", r.body.seller);

    // ============================================================
    console.log("\n# 9. Stari odgovori nespremenjeni, brez uhajanja");
    const starEvent = ["id", "club_id", "club_name", "title", "description", "poster_url", "start_at", "end_at", "min_age", "genres", "status", "created_at", "ticket_price_cents", "currency", "ticket_url",
      "capacity", "sold_count", "availability", "time_status", "recap_video_url", "lifecycle", "interested_count", "vip_enabled", "vip_from_cents", "vip_layout_source",
      "venue_club_id", "venue_club_name", "venue_name", "venue_address", "venue_city", "payment_mode", "my_plan", "friends_going", "friends_interested"];
    r = await api("GET", `/events/${ev1}`);
    assert(r.status === 200 && ima(r.body, starEvent) && "seller" in r.body, "GET /events/:id: vsa stara polja so se tu + seller", starEvent.filter(k => !(k in r.body)));
    const starKlub = ["id", "name", "logo_url", "banner_url", "description", "contact_email", "contact_phone", "instagram", "website", "address", "city", "country", "lat", "lng", "min_age", "genres",
      "created_at", "bar_prices", "gallery_urls", "video_url", "is_organizer", "is_official", "followers_count", "is_following"];
    r = await api("GET", `/clubs/${klub}`);
    assert(r.status === 200 && ima(r.body, starKlub) && "seller" in r.body, "GET /clubs/:id: vsa stara polja so se tu + seller", starKlub.filter(k => !(k in r.body)));
    r = await api("GET", `/events/${ev1}/vip`);
    assert(r.status === 200 && ima(r.body, ["event_id", "enabled", "on_sale", "payment_mode", "currency", "plan", "tables", "packages", "package_min_age", "seller"]), "GET /events/:id/vip: vsa stara polja + seller", Object.keys(r.body));
    r = await api("GET", "/guest/order", null, undefined, { "x-guest-token": zetonGost });
    assert(r.status === 200 && ima(r.body, ["order", "tickets", "seller"]) && ima(r.body.order, ["id", "public_ref", "status", "quantity", "unit_price_cents", "total_cents", "currency", "event", "club_name", "checkout_url", "checkout_expired", "payment_processing"]), "GET /guest/order: vsa stara polja + seller", Object.keys(r.body));
    const javno = [await api("GET", "/clubs"), await api("GET", `/clubs/${klub}`), await api("GET", "/events"), await api("GET", `/events/${ev1}`), await api("GET", `/events/${ev1}/vip`)];
    assert(javno.every(x => x.status === 200 && !/stripe_account_id|owner_user_id|seller_raw/.test(x.text)), "javni odgovori: brez stripe_account_id, owner_user_id in pomoznega seller_raw (I4)");
    assert(javno.slice(2).every(x => !/"legal_name"|"legal_address"/.test(x.text)) && !/"legal_name"|"legal_address"/.test(javno[0].text + javno[1].text), "javni odgovori: surova polja prodajalca (legal_*) ne uhajajo", null);
    r = await api("GET", "/business/clubs/me", T.lastnik);
    assert(r.status === 200 && !/stripe_account_id|owner_user_id/.test(r.text) && ima(r.body, [...SUROVA, "seller_complete", "stripe_charges_enabled", "hidden", "my_role"]), "GET /business/clubs/me: nova polja, I4 drzi", Object.keys(r.body));
  } catch (e) {
    fail++; console.log("  ✗ IZJEMA", e && e.stack || e);
  } finally {
    try { srv && srv.kill(); } catch {}
    jwksServer.close(); resendServer.close();
    await pool.end().catch(() => {});
  }
  console.log(`\n${ok} ok, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
