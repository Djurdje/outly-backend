#!/usr/bin/env node
/**
 * Brezplacno (0 EUR) naroclilo deluje tudi pri klubu BREZ dokoncanega Stripa, tudi ob zivem kljucu (I49; Martin v chatu z menedzerjem
 * 18. 10. 2026, »pri 1 DA«; #16 tocka 2, #198 A (1)). Placljiv nakup pri takem klubu OSTANE zavrnjen (denar brez povezanega racuna ne sme
 * nikamor), na sk_test_ / brez kljuca se nic ne spremeni. Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_brezplacno_brez_stripa.js
 * Vzorec kot test_prodajalec_nakup.js: lokalni JWKS (ES256), lazni Stripe (STRIPE_API_BASE), vec backendov na svojih portih:
 *   ZIV      sk_live_ (GOST_NAKUP_LIVE=1)   klub 1 s zivim Stripom, klub 2 BREZ Stripa, klub 3 s SANDBOX racunom (I36), klub 4 demo brez Stripa
 *   ZIV_TP   sk_live_ + TEST_PLACILA=true   isti klubi (vsiljen testni nacin se ob zivem kljucu ignorira, I31)
 *   ZIV_BREZ_WH  sk_live_ brez webhook skrivnosti (payments_not_configured: 503 za vse, tudi 0 EUR - ni stvar kluba)
 *   SANDBOX  sk_test_                       isti klubi
 *   TESTNI   brez STRIPE_SECRET_KEY         isti klubi
 *
 *   1  ZIV, klub brez Stripa, 0 EUR: vstopnica, VIP miza, gost -> 201 paid (mode "stripe", checkout_url null, PI in racun NULL, Stripe 0 klicev)
 *   2  ZIV, klub brez Stripa, placljivo: vstopnica, miza, gost -> 409 »does not accept online payments« (brez narocila, zaloge, mize, ključa, Stripa)
 *   3  meje brezplacnih veljajo enako: ZASTONJ_NA_OSEBO (uporabnik, gost z gmail pikami/+oznako), kapaciteta, idempotenca, starost
 *   4  payment_mode: 0 EUR "stripe", placljivo "unavailable" na vseh poteh; mesanice po vstopnici; /business/sales kluba ostane unavailable/stripe_not_ready
 *      In za vsak dogodek: payment_mode "unavailable" <=> nakup tega dela 409 (ena funkcija pogoja)
 *   5  I36: klub s sandbox racunom ob zivem kljucu: 0 EUR gre, placljivo 409
 *   6  TEST_PLACILA=true + sk_live_ (I31): 0 EUR je PRAVO naroclilo (PI NULL, ne test_), placljivo 409
 *   7  demo klub brez Stripa: 0 EUR se vedno 409 demo_club (I41)
 *   8  Stripe kljuc brez webhook skrivnosti: 503 tudi za 0 EUR (nespremenjeno)
 *   9  SANDBOX in TESTNI nacin: klub brez Stripa se vede kot doslej (mode "test", test_ PI), payment_mode "test"
 *  10  klub S Stripom: 0 EUR in placljivo kot doslej (regresija)
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT_ZIV = 3621, PORT_SANDBOX = 3622, PORT_TESTNI = 3623, JWKS_PORT = 3624, STRIPE_PORT = 3625, PORT_ZIV_TP = 3626, PORT_ZIV_BREZ_WH = 3627;
const WHSEC = "whsec_test_brezplacno";

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-brezplacno-brez-stripa";
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
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra).slice(0, 400) : ""); } }
let ipStevec = 0;   // vsak zahtevek svoj naslov (X-Forwarded-For): omejevalnik nakupov je po IP
async function api(baza, method, p, token, body, glave = {}) {
  const r = await fetch(baza + p, { method, headers: { "content-type": "application/json", "x-forwarded-for": `10.62.${(++ipStevec >> 8) & 255}.${(ipStevec & 255) + 1}`, ...(token ? { authorization: "Bearer " + token } : {}), ...glave },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, text: t };
}
const pocakaj = (ms) => new Promise(r => setTimeout(r, ms));

// ---------- lazni Stripe (samo Checkout seje; stevec klicev) ----------
const S = { seje: {}, stSej: 0, zahtevki: 0 };
const stripeServer = http.createServer((req, res) => {
  let d = ""; req.on("data", x => d += x);
  req.on("end", () => {
    const p = Object.fromEntries(new URLSearchParams(d));
    const odg = (status, o) => { res.writeHead(status, { "content-type": "application/json", "request-id": "req_test" }); res.end(JSON.stringify(o)); };
    S.zahtevki++;
    if (req.method === "POST" && req.url.split("?")[0] === "/v1/checkout/sessions") {
      const id = "cs_test_" + (++S.stSej);
      S.seje[id] = { id, object: "checkout.session", url: `https://checkout.stripe.test/c/pay/${id}`, status: "open", payment_status: "unpaid",
        client_reference_id: p.client_reference_id, expires_at: Number(p.expires_at), payment_intent: null, metadata: { order_id: p["metadata[order_id]"] } };
      return odg(200, S.seje[id]);
    }
    return odg(404, { error: { type: "invalid_request_error", message: "Lazni Stripe: neznana pot " + req.method + " " + req.url } });
  });
});

function zagon(port, okolje) {
  const srv = spawn("node", ["index.js"], { env: { ...process.env, GOST_NAKUP_TEST: "1", PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test",
    APP_URL: "https://outly.test", TEST_PLACILA: "", STRIPE_SECRET_KEY: "", STRIPE_WEBHOOK_SECRET: "", JAVNI_PREDPOMNILNIK_MS: "0", ...okolje }, stdio: ["ignore", "pipe", "pipe"] });
  const o = { srv, log: "" };
  srv.stdout.on("data", d => o.log += d); srv.stderr.on("data", d => o.log += d);
  return o;
}
async function cakajStreznik(baza) { for (let i = 0; i < 80; i++) { try { await fetch(baza + "/"); return; } catch { await pocakaj(100); } } }

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, stripe_events, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  await new Promise(r => stripeServer.listen(STRIPE_PORT, r));
  const stripeOkolje = { STRIPE_WEBHOOK_SECRET: WHSEC, STRIPE_API_BASE: `http://127.0.0.1:${STRIPE_PORT}` };
  const ZIV = zagon(PORT_ZIV, { ...stripeOkolje, STRIPE_SECRET_KEY: "sk_live_lokalno", GOST_NAKUP_LIVE: "1" });
  const ZIV_TP = zagon(PORT_ZIV_TP, { ...stripeOkolje, STRIPE_SECRET_KEY: "sk_live_lokalno", GOST_NAKUP_LIVE: "1", TEST_PLACILA: "true" });
  const ZIV_BREZ_WH = zagon(PORT_ZIV_BREZ_WH, { STRIPE_SECRET_KEY: "sk_live_lokalno", STRIPE_API_BASE: `http://127.0.0.1:${STRIPE_PORT}`, GOST_NAKUP_LIVE: "1" });
  const SAND = zagon(PORT_SANDBOX, { ...stripeOkolje, STRIPE_SECRET_KEY: "sk_test_lokalno" });
  const TEST = zagon(PORT_TESTNI, {});
  const bZ = `http://127.0.0.1:${PORT_ZIV}`, bP = `http://127.0.0.1:${PORT_ZIV_TP}`, bW = `http://127.0.0.1:${PORT_ZIV_BREZ_WH}`, bS = `http://127.0.0.1:${PORT_SANDBOX}`, bT = `http://127.0.0.1:${PORT_TESTNI}`;
  await Promise.all([bZ, bP, bW, bS, bT].map(cakajStreznik));

  try {
    const imena = ["lastnik", "lastnik2", "lastnik3", "lastnik4", "ana", "bor", "cene", "dana", "eva", "fran", "gina", "hana", "iva", "jan", "kaja"];
    const T = {};
    imena.forEach((k, i) => { T[k] = zeton(`${k}@outly.si`, uuid(i + 1)); });
    for (const k of imena) { const r = await api(bZ, "GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='business' WHERE email LIKE 'lastnik%@outly.si'");
    const lastnikKluba = (e) => `(SELECT id FROM users WHERE email='${e}@outly.si')`;
    // Klub 1: zivi Stripe (kot v prihodnji produkciji po onboardingu), popolni podatki prodajalca. Klub 2: BREZ Stripa. Klub 3: SANDBOX racun (I36). Klub 4: demo, brez Stripa.
    await pool.query(`INSERT INTO clubs (owner_user_id, name, city, address, stripe_account_id, stripe_charges_enabled, stripe_account_livemode, legal_name, legal_address, registration_number, tax_number, vat_payer, contact_email)
                      VALUES (${lastnikKluba("lastnik")}, 'S Stripom', 'Ljubljana', 'Slovenska 1', 'acct_ziv1', TRUE, TRUE, 'Klub d.o.o.', 'Slovenska 1, Ljubljana', '1234567000', 'SI12345678', TRUE, 'info@klub.si')`);
    await pool.query(`INSERT INTO clubs (owner_user_id, name, city, address) VALUES (${lastnikKluba("lastnik2")}, 'Brez Stripa', 'Maribor', 'Glavni trg 2')`);
    await pool.query(`INSERT INTO clubs (owner_user_id, name, city, address, stripe_account_id, stripe_charges_enabled, stripe_account_livemode) VALUES (${lastnikKluba("lastnik3")}, 'Sandbox racun', 'Celje', 'Trg 3', 'acct_sandbox3', TRUE, FALSE)`);
    await pool.query(`INSERT INTO clubs (owner_user_id, name, city, address, is_demo) VALUES (${lastnikKluba("lastnik4")}, 'Demo brez Stripa', 'Kranj', 'Trg 4', TRUE)`);

    const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    const dogodek = async (klub, lastnik, title, cena, kapaciteta = 100, minAge = 0) => {
      const r = await api(bZ, "POST", "/events", T[lastnik], { clubId: klub, title, startAt: cezDan, ticketPriceCents: cena, capacity: kapaciteta, minAge });
      assert(r.status === 201, `dogodek ${title}`, r.body); return r.body.id;
    };
    // Klub 2 (brez Stripa)
    const evZ = await dogodek(2, "lastnik2", "Brezplacen", 0);
    const evP = await dogodek(2, "lastnik2", "Placljiv", 1500);
    const evKap = await dogodek(2, "lastnik2", "Brezplacen kapaciteta 3", 0, 3);
    const evStar = await dogodek(2, "lastnik2", "Brezplacen 18+", 0, 100, 18);
    const evMeja = await dogodek(2, "lastnik2", "Brezplacen meja", 0);
    const evGost = await dogodek(2, "lastnik2", "Brezplacen gost", 0);
    const evIdem = await dogodek(2, "lastnik2", "Brezplacen idempotenca", 0);
    const evZZ = await dogodek(2, "lastnik2", "Vstopnica 0, miza 0", 0);
    const evZP = await dogodek(2, "lastnik2", "Vstopnica 0, miza placljiva", 0);
    const evPZ = await dogodek(2, "lastnik2", "Vstopnica placljiva, miza 0", 1500);
    const evPP = await dogodek(2, "lastnik2", "Vstopnica placljiva, miza placljiva", 1500);
    const evZZb = await dogodek(2, "lastnik2", "Vstopnica 0, miza 0 (nedotaknjena)", 0);
    // Klub 3 (sandbox racun), klub 1 (zivi Stripe), klub 4 (demo)
    const evS0 = await dogodek(3, "lastnik3", "Sandbox racun 0", 0);
    const evS1 = await dogodek(3, "lastnik3", "Sandbox racun placljiv", 1500);
    const evC0 = await dogodek(1, "lastnik", "S Stripom 0", 0);
    const evC1 = await dogodek(1, "lastnik", "S Stripom placljiv", 1500);
    const evD0 = await dogodek(4, "lastnik4", "Demo 0", 0);
    // VIP mize kluba 2: tri za 0 EUR (F1..F3) in tri placljive (P1..P3); dogodek z mizami izbere, katere so vklopljene (event_tables.disabled)
    await pool.query("UPDATE events SET vip_enabled = TRUE WHERE id = ANY($1)", [[evZZ, evZP, evPZ, evPP, evZZb]]);
    await pool.query(`INSERT INTO club_tables (club_id, label, x, y, w, h, seats, price_cents) VALUES
      (2,'F1',0,0,2,2,4,0),(2,'F2',3,0,2,2,4,0),(2,'F3',6,0,2,2,4,0),(2,'P1',9,0,2,2,4,20000),(2,'P2',12,0,2,2,4,20000),(2,'P3',15,0,2,2,4,20000)`);
    const miza = async (label) => (await pool.query("SELECT id FROM club_tables WHERE club_id=2 AND label=$1", [label])).rows[0].id;
    const M = {}; for (const l of ["F1", "F2", "F3", "P1", "P2", "P3"]) M[l] = await miza(l);
    const samo = (ev, predpona) => pool.query(`INSERT INTO event_tables (event_id, table_id, disabled) SELECT $1, id, TRUE FROM club_tables WHERE club_id = 2 AND label NOT LIKE $2`, [ev, predpona + "%"]);
    await samo(evZZ, "F"); await samo(evZZb, "F"); await samo(evZP, "P"); await samo(evPZ, "F"); await samo(evPP, "P");
    // Klub 3 in klub 1: po ena miza za 0 in placljiva (I36 / regresija)
    await pool.query("UPDATE events SET vip_enabled = TRUE WHERE id = ANY($1)", [[evS0, evC0]]);
    await pool.query(`INSERT INTO club_tables (club_id, label, x, y, w, h, seats, price_cents) VALUES (3,'SF',0,0,2,2,4,0),(1,'CF',0,0,2,2,4,0)`);
    const mizaSF = (await pool.query("SELECT id FROM club_tables WHERE club_id=3")).rows[0].id;
    const mizaCF = (await pool.query("SELECT id FROM club_tables WHERE club_id=1")).rows[0].id;

    const TERMS = { accept_terms: true, terms_version: "2026-10-01" };
    const kupiV = (baza, tok, ev, q = 1, k) => api(baza, "POST", `/events/${ev}/orders`, tok, { quantity: q }, k ? { "idempotency-key": k } : {});
    const kupiM = (baza, tok, ev, m, k) => api(baza, "POST", `/events/${ev}/tables/${m}/orders`, tok, {}, k ? { "idempotency-key": k } : {});
    const kupiG = (baza, ev, email, q = 1) => api(baza, "POST", `/guest/events/${ev}/orders`, null, { email, quantity: q, ...TERMS });
    const BREZ_STRIPA = "This club does not accept online payments yet.";
    const jeBrezStripa = (r) => r.status === 409 && r.body === BREZ_STRIPA;
    const jePlacano0 = (r) => r.status === 201 && r.body.order && r.body.order.status === "paid" && r.body.order.total_cents === 0 && r.body.checkout_url === null;
    const stNaroclil = (ev) => pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id = ANY($1)", [Array.isArray(ev) ? ev : [ev]]).then(r => r.rows[0].n);
    const prodano = (ev) => pool.query("SELECT COALESCE(SUM(sold_count),0)::int AS n FROM events WHERE id = ANY($1)", [Array.isArray(ev) ? ev : [ev]]).then(r => r.rows[0].n);
    const vrstica = (id) => !id ? Promise.resolve({}) : pool.query("SELECT status, total_cents, stripe_payment_intent_id, stripe_account_id, stripe_checkout_session_id, application_fee_cents, paid_at IS NOT NULL AS placano FROM orders WHERE id=$1", [id]).then(r => r.rows[0]);

    // ================================================================
    console.log("\n# 1. ZIV (sk_live_), klub BREZ Stripa: 0 EUR gre");
    const stripe0 = S.zahtevki;
    let r = await kupiV(bZ, T.ana, evZ, 2);
    assert(jePlacano0(r) && r.body.mode === "stripe" && (r.body.tickets || []).length === 2, "vstopnice 2 x 0 EUR: 201 paid, mode stripe, checkout_url null, 2 vstopnici", r);
    let v = await vrstica((r.body.order || {}).id);
    assert(v.status === "paid" && v.total_cents === 0 && v.stripe_payment_intent_id === null && v.stripe_account_id === null && v.stripe_checkout_session_id === null && v.application_fee_cents === 0 && v.placano,
      "baza: paid, PI / racun / seja NULL, provizija 0 (pravo naroclilo z zneskom 0, ne testno)", v);
    assert(await prodano(evZ) === 2, "sold_count = 2 (zaloga se steje)");
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM tickets WHERE order_id=$1", [(r.body.order || {}).id || 0])).rows[0].n === 2, "v bazi 2 vstopnici");
    r = await kupiM(bZ, T.bor, evZZ, M.F1);
    assert(jePlacano0(r) && r.body.mode === "stripe" && (r.body.tickets || []).length === 4, "VIP miza za 0 EUR: 201 paid, 4 vstopnice", r);
    r = await kupiG(bZ, evGost, "gost-brez-stripa@example.com");
    assert(jePlacano0(r) && r.body.guest_token, "gost, 0 EUR: 201 paid + guest_token", r);
    assert(S.zahtevki === stripe0, "Stripa se ni klicalo (0 EUR gre mimo Checkouta)", S.zahtevki - stripe0);
    // Tudi ponovljen nakup istega uporabnika dela (meja je sele pri 10)
    r = await kupiV(bZ, T.ana, evZ, 1);
    assert(jePlacano0(r), "isti uporabnik, drugi nakup 0 EUR: 201", r);

    // ================================================================
    console.log("\n# 2. ZIV, klub BREZ Stripa: placljivo OSTANE zavrnjeno (denar brez racuna ne gre nikamor)");
    const pred2 = { nar: await stNaroclil([evP, evPZ, evPP, evZP]), prod: await prodano([evP, evPZ, evPP, evZP]) };
    const kljuc2 = crypto.randomUUID(), kljuc2m = crypto.randomUUID();
    r = await kupiV(bZ, T.cene, evP, 1, kljuc2);
    assert(jeBrezStripa(r), "placljiva vstopnica: 409 »does not accept online payments«", r);
    r = await kupiV(bZ, T.cene, evP, 10);
    assert(jeBrezStripa(r), "placljive 10 vstopnic: 409", r);
    r = await kupiM(bZ, T.cene, evZP, M.P1, kljuc2m);
    assert(jeBrezStripa(r), "placljiva VIP miza (dogodek z vstopnico 0 EUR): 409", r);
    r = await kupiM(bZ, T.cene, evPP, M.P2);
    assert(jeBrezStripa(r), "placljiva VIP miza (placljiva vstopnica): 409", r);
    r = await kupiG(bZ, evP, "gost-placljivo@example.com");
    assert(jeBrezStripa(r), "gost, placljiva vstopnica: 409", r);
    r = await kupiV(bZ, T.cene, evPP, 1);
    assert(jeBrezStripa(r), "placljiva vstopnica na mesanem dogodku: 409", r);
    r = await kupiV(bZ, T.cene, evPZ, 1);
    assert(jeBrezStripa(r), "placljiva vstopnica + miza 0 EUR: vstopnica 409", r);
    r = await kupiM(bZ, T.cene, evZP, M.P3);
    assert(jeBrezStripa(r), "vstopnica 0 EUR + placljiva miza: miza 409", r);
    assert(await stNaroclil([evP, evPZ, evPP, evZP]) === pred2.nar && await prodano([evP, evPZ, evPP, evZP]) === pred2.prod, "nobenega naroclila, sold_count nedotaknjen");
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE idempotency_key IN ($1,$2)", [kljuc2, kljuc2m])).rows[0].n === 0, "kljuca nista porabljena");
    assert(S.zahtevki === stripe0, "Stripa se ni klicalo");
    // Prepis: 0 EUR s PLACLJIVO ceno ne more »uiti« (cena iz baze, ne iz telesa)
    r = await api(bZ, "POST", `/events/${evP}/orders`, T.cene, { quantity: 1, ticketPriceCents: 0, priceCents: 0, total_cents: 0 });
    assert(jeBrezStripa(r), "polja cene v telesu ne obidejo zavrnitve (cena je iz baze)", r);
    r = await api(bZ, "POST", `/events/${evP}/orders`, T.cene, { quantity: 1, expected_price_cents: 0 });
    assert(r.status === 409, "expected_price_cents 0 pri ceni 1500: 409 (nikoli brezplacno naroclilo)", r);
    assert(await stNaroclil(evP) === 0, "pri placljivem dogodku se vedno 0 naroclil");
    // Cena se spremeni na 0 -> dobi se brezplacno; nazaj na placljivo -> zavrnjeno spet (odlocitev ob nakupu, ne zgodovina)
    const evCena = await dogodek(2, "lastnik2", "Cena se spreminja", 1500);
    r = await kupiV(bZ, T.cene, evCena, 1); assert(jeBrezStripa(r), "evCena 1500: 409", r);
    await pool.query("UPDATE events SET ticket_price_cents = 0 WHERE id=$1", [evCena]);
    r = await kupiV(bZ, T.cene, evCena, 1);
    assert(jePlacano0(r), "organizator postavi ceno na 0: nakup gre", r);
    await pool.query("UPDATE events SET ticket_price_cents = 1500 WHERE id=$1", [evCena]);
    r = await kupiV(bZ, T.dana, evCena, 1);
    assert(jeBrezStripa(r), "cena nazaj na 1500: spet 409", r);

    // ================================================================
    console.log("\n# 3. Meje brezplacnih veljajo enako");
    // Uporabnik: ZASTONJ_NA_OSEBO (10) na osebo in dogodek
    r = await kupiV(bZ, T.eva, evMeja, 6); assert(jePlacano0(r), "uporabnik: 6 brezplacnih", r);
    r = await kupiV(bZ, T.eva, evMeja, 4); assert(jePlacano0(r), "uporabnik: se 4 (skupaj 10 = meja)", r);
    r = await kupiV(bZ, T.eva, evMeja, 1); assert(r.status === 409 && r.body.error === "free_limit", "uporabnik: 11. brezplacna -> 409 free_limit", r);
    r = await kupiM(bZ, T.eva, evZZ, M.F2);
    assert(jePlacano0(r), "free_limit je na dogodek: ista oseba na drugem dogodku dobi", r);
    // Gost: meja po normaliziranem naslovu (gmail: pike in +oznaka sta isti nabiralnik)
    r = await kupiG(bZ, evMeja, "Gost.Meja@gmail.com", 6); assert(jePlacano0(r), "gost: 6 brezplacnih", r);
    r = await kupiG(bZ, evMeja, "gostmeja+x@gmail.com", 4); assert(jePlacano0(r), "gost: isti nabiralnik (pike, +oznaka) se 4 = meja", r);
    r = await kupiG(bZ, evMeja, "g.o.s.t.m.e.j.a@googlemail.com", 1); assert(r.status === 409 && r.body.error === "free_limit", "gost: 11. brezplacna -> 409 free_limit", r);
    r = await kupiG(bZ, evMeja, "drug.naslov@example.com", 1); assert(jePlacano0(r), "drug naslov meje ne zadene (znana omejitev)", r);
    // Kapaciteta: dogodek za 3
    r = await kupiV(bZ, T.fran, evKap, 2); assert(jePlacano0(r), "kapaciteta 3: 2 vstopnici", r);
    r = await kupiV(bZ, T.gina, evKap, 2); assert(r.status === 409 && /Only 1 tickets left/.test(r.body), "kapaciteta 3: se 2 -> 409 »Only 1 tickets left«", r);
    r = await kupiG(bZ, evKap, "gost-kap@example.com", 2); assert(r.status === 409 && /Only 1 tickets left/.test(r.body), "gost: kapaciteta -> 409", r);
    r = await kupiV(bZ, T.gina, evKap, 1); assert(jePlacano0(r), "kapaciteta 3: zadnja vstopnica", r);
    r = await kupiV(bZ, T.hana, evKap, 1); assert(r.status === 409, "kapaciteta 3: razprodano -> 409", r);
    assert(await prodano(evKap) === 3, "sold_count natanko 3 (nikoli nad kapaciteto)", await prodano(evKap));
    // Hkratno: 8 hkratnih nakupov za zadnje 3 vstopnice na svezem dogodku
    const evHkr = await dogodek(2, "lastnik2", "Hkratno", 0, 3);
    const hk = await Promise.all(["ana", "bor", "cene", "dana", "eva", "fran", "gina", "hana"].map(k => kupiV(bZ, T[k], evHkr, 1)));
    assert(hk.filter(x => x.status === 201).length === 3 && hk.filter(x => x.status === 409).length === 5 && await prodano(evHkr) === 3, "8 hkratnih na 3 mesta: natanko 3 uspejo", hk.map(x => x.status));
    // Starost: 18+ brez datuma rojstva ne gre (I8), z datumom gre
    r = await kupiV(bZ, T.iva, evStar, 1); assert(r.status === 403, "18+ brez datuma rojstva: 403 (starost velja)", r);
    r = await kupiG(bZ, evStar, "gost-star@example.com"); assert(r.status === 403, "gost, 18+ brez datuma rojstva: 403", r);
    await pool.query("UPDATE users SET date_of_birth = '1990-01-01' WHERE email='iva@outly.si'");
    r = await kupiV(bZ, T.iva, evStar, 1); assert(jePlacano0(r), "18+ z datumom rojstva: 201", r);
    // Idempotenca: ponovitev ključa vrne prvo naročilo (ne novega)
    const kIdem = crypto.randomUUID();
    r = await kupiV(bZ, T.jan, evIdem, 1, kIdem);
    const r2 = await kupiV(bZ, T.jan, evIdem, 1, kIdem);
    assert(jePlacano0(r) && (r2.status === 200 || r2.status === 201) && r2.body.order && (r2.body.order || {}).id === (r.body.order || {}).id, "idempotenca: ponovitev kljuca vrne isto naroclilo", [r.status, r2.status]);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE idempotency_key=$1", [kIdem])).rows[0].n === 1 && await prodano(evIdem) === 1, "idempotenca: natanko eno naroclilo, sold_count 1");
    // VIP miza: ista miza dvakrat (I13)
    r = await kupiM(bZ, T.jan, evZZ, M.F3); assert(jePlacano0(r), "miza F3 za 0 EUR: 201", r);
    r = await kupiM(bZ, T.kaja, evZZ, M.F3); assert(r.status === 409 && /already booked/.test(r.body), "ista miza drugic: 409 (I13)", r);
    // Ob odpovedi dogodka z brezplacnimi naroclili ni denarja za vrniti (0 EUR ne gre v vracila)
    const vracil = (await pool.query("SELECT COUNT(*)::int AS n FROM vracila")).rows[0].n;
    assert(vracil === 0, "brezplacna naroclila brez Stripa ne ustvarijo vrstic v vracilih", vracil);

    // ================================================================
    console.log("\n# 4. payment_mode: 0 EUR stripe, placljivo unavailable; isti pogoj kot nakup");
    const poId = (r, id) => (r && Array.isArray(r.body) ? r.body.find(x => x.id === id) : null) || {};
    const modi = async (baza, tok, glave) => {
      const o = {}; const g = (pot, h) => api(baza, "GET", pot, tok, undefined, h);
      let r = await g(`/events/${evZ}`); o.zastonj = r.body.payment_mode;
      r = await g(`/events/${evP}`); o.placljiv = r.body.payment_mode;
      r = await g("/events"); const sez = (id) => poId(r, id).payment_mode;
      o.sezZastonj = sez(evZ); o.sezPlacljiv = sez(evP); o.sezZP = sez(evZP); o.sezPZ = sez(evPZ); o.sezPP = sez(evPP); o.sezZZ = sez(evZZ);
      r = await g("/events?lite=true"); o.lahkiZastonj = poId(r, evZ).payment_mode; o.lahkiPlacljiv = poId(r, evP).payment_mode;
      r = await g("/events?clubId=2"); o.klubZastonj = poId(r, evZ).payment_mode; o.klubPlacljiv = poId(r, evP).payment_mode;
      r = await g(`/events/${evZP}`); o.zp = r.body.payment_mode;
      r = await g(`/events/${evPZ}`); o.pz = r.body.payment_mode;
      r = await g(`/events/${evPP}`); o.pp = r.body.payment_mode;
      r = await g(`/events/${evZZ}`); o.zz = r.body.payment_mode;
      r = await g(`/events/${evZZb}/vip`); o.vipZZ = r.body.payment_mode;
      r = await g(`/events/${evZP}/vip`); o.vipZP = r.body.payment_mode;
      r = await g(`/events/${evPZ}/vip`); o.vipPZ = r.body.payment_mode;
      r = await g(`/events/${evPP}/vip`); o.vipPP = r.body.payment_mode;
      return o;
    };
    let o = await modi(bZ, null);
    assert(o.zastonj === "stripe" && o.sezZastonj === "stripe" && o.lahkiZastonj === "stripe" && o.klubZastonj === "stripe",
      "dogodek z vstopnico 0 EUR: stripe (GET /events/:id, /events, ?lite, ?clubId)", o);
    assert(o.placljiv === "unavailable" && o.sezPlacljiv === "unavailable" && o.lahkiPlacljiv === "unavailable" && o.klubPlacljiv === "unavailable",
      "dogodek s placljivo vstopnico: unavailable (vse poti)", o);
    assert(o.zz === "stripe" && o.sezZZ === "stripe" && o.vipZZ === "stripe", "vstopnica 0 + miza 0: dogodek stripe, /vip stripe", o);
    assert(o.zp === "stripe" && o.sezZP === "stripe" && o.vipZP === "unavailable", "vstopnica 0 + placljive mize: dogodek stripe (po vstopnici), /vip unavailable", o);
    assert(o.pz === "unavailable" && o.sezPZ === "unavailable" && o.vipPZ === "stripe", "placljiva vstopnica + miza 0: dogodek unavailable (po vstopnici), /vip stripe", o);
    assert(o.pp === "unavailable" && o.sezPP === "unavailable" && o.vipPP === "unavailable", "placljiva vstopnica + placljiva miza: vse unavailable", o);
    const oA = await modi(bZ, T.ana);
    assert(JSON.stringify(oA) === JSON.stringify(o), "prijavljen kupec vidi enak payment_mode kot gost (I17)", [oA, o]);
    // ISTI POGOJ: unavailable <=> nakup tega dela 409 (brez razhajanja)
    const kupci = ["kaja", "hana", "gina", "fran", "dana", "cene", "bor", "ana", "iva", "jan"];
    let ki = 0; const kupec = () => T[kupci[ki++ % kupci.length]];
    const evX0 = await dogodek(2, "lastnik2", "Ujemanje 0", 0), evX1 = await dogodek(2, "lastnik2", "Ujemanje 1500", 1500);
    for (const [ev, mode] of [[evX0, "stripe"], [evX1, "unavailable"]]) {
      const jav = await api(bZ, "GET", `/events/${ev}`);
      const nak = await kupiV(bZ, kupec(), ev, 1);
      assert(jav.body.payment_mode === mode && ((mode === "stripe") === (nak.status === 201)) && ((mode === "unavailable") === jeBrezStripa(nak)), `dogodek ${ev}: payment_mode ${mode} <=> nakup ${mode === "stripe" ? "201" : "409"}`, [jav.body.payment_mode, nak.status]);
      const gnak = await kupiG(bZ, ev, `ujemanje-${ev}@example.com`);
      assert(((mode === "stripe") === (gnak.status === 201)) && ((mode === "unavailable") === jeBrezStripa(gnak)), `dogodek ${ev}: isto za gosta`, gnak.status);
    }
    for (const [ev, m, mode] of [[evPZ, "F2", "stripe"], [evZP, "P1", "unavailable"], [evPP, "P2", "unavailable"]]) {
      const jav = await api(bZ, "GET", `/events/${ev}/vip`);
      const nak = await kupiM(bZ, kupec(), ev, M[m]);
      assert(jav.body.payment_mode === mode && ((mode === "stripe") === (nak.status === 201)) && ((mode === "unavailable") === jeBrezStripa(nak)), `VIP dogodka ${ev}: payment_mode ${mode} <=> nakup mize ${m}`, [jav.body.payment_mode, nak.status]);
    }
    // Lastnik: GET /business/events (po dogodku) in GET /business/sales (klub: znesek ni znan -> predpostavljeno placljivo)
    const g2 = { "x-outly-club": "2" };
    let rb = await api(bZ, "GET", "/business/events", T.lastnik2, undefined, g2);
    assert(rb.status === 200 && poId(rb, evZ).payment_mode === "stripe" && poId(rb, evP).payment_mode === "unavailable", "GET /business/events: 0 EUR stripe, placljiv unavailable", Array.isArray(rb.body) && rb.body.map(x => [x.id, x.payment_mode]).slice(0, 4));
    rb = await api(bZ, "GET", "/business/sales", T.lastnik2, undefined, g2);
    assert(rb.status === 200 && rb.body.payment_mode === "unavailable" && rb.body.payment_unavailable_reason === "stripe_not_ready", "GET /business/sales: klub ostane unavailable / stripe_not_ready (placljivo se ne proda)", [rb.body.payment_mode, rb.body.payment_unavailable_reason]);
    assert(rb.body.summary && Number(rb.body.summary.orders ?? 0) >= 0 && rb.body.events.some(e => e.id === evZ && e.tickets_sold >= 2), "GET /business/sales: brezplacni nakupi so v prodaji dogodka", rb.body.events && rb.body.events.map(e => [e.id, e.tickets_sold]));
    assert(rb.body.test_summary.orders === 0, "brezplacni nakupi niso »testni« promet (test_summary 0)", rb.body.test_summary);
    for (const pot of ["/events", `/events/${evZ}`, `/events/${evZZ}/vip`]) {
      const sur = await api(bZ, "GET", pot, null);
      assert(sur.status === 200 && !/club_stripe_ready|club_seller_raw|seller_raw|acct_|stripe_account_id|payment_unavailable_reason/.test(sur.text), `GET ${pot}: brez pomoznih stolpcev, racuna in razloga (I4)`);
    }

    // ================================================================
    console.log("\n# 5. I36: klub s SANDBOX racunom ob zivem kljucu = nepovezan: 0 EUR gre, placljivo 409");
    r = await api(bZ, "GET", `/events/${evS0}`); assert(r.body.payment_mode === "stripe", "dogodek 0 EUR: stripe", r.body.payment_mode);
    r = await api(bZ, "GET", `/events/${evS1}`); assert(r.body.payment_mode === "unavailable", "dogodek 1500: unavailable", r.body.payment_mode);
    r = await api(bZ, "GET", `/events/${evS0}/vip`); assert(r.body.payment_mode === "stripe", "/vip z mizo 0 EUR: stripe", r.body.payment_mode);
    const sBiloStripa = S.zahtevki;
    r = await kupiV(bZ, T.ana, evS0); assert(jePlacano0(r) && r.body.mode === "stripe", "vstopnica 0 EUR: 201 paid", r);
    r = await kupiM(bZ, T.bor, evS0, mizaSF); assert(jePlacano0(r), "miza 0 EUR: 201 paid", r);
    r = await kupiG(bZ, evS0, "gost-sandbox-racun@example.com"); assert(jePlacano0(r), "gost 0 EUR: 201 paid", r);
    r = await kupiV(bZ, T.ana, evS1); assert(jeBrezStripa(r), "placljiva vstopnica: 409", r);
    r = await kupiG(bZ, evS1, "gost-sandbox-placljivo@example.com"); assert(jeBrezStripa(r), "gost, placljivo: 409", r);
    assert(S.zahtevki === sBiloStripa, "Stripa se ni klicalo (sandbox racun se ob zivem kljucu ne uporabi)");
    v = await vrstica(((await pool.query("SELECT id FROM orders WHERE event_id=$1 ORDER BY id LIMIT 1", [evS0])).rows[0] || {}).id);
    assert(v.stripe_account_id === null && v.stripe_payment_intent_id === null, "naroclilo ne nosi sandbox racuna (acct_sandbox3)", v);
    rb = await api(bZ, "GET", "/business/sales", T.lastnik3, undefined, { "x-outly-club": "3" });
    assert(rb.body.payment_mode === "unavailable" && rb.body.payment_unavailable_reason === "stripe_not_ready", "/business/sales kluba s sandbox racunom: unavailable / stripe_not_ready", [rb.body.payment_mode, rb.body.payment_unavailable_reason]);

    // ================================================================
    console.log("\n# 6. TEST_PLACILA=true + sk_live_ (I31): vsiljen testni nacin se ignorira; 0 EUR je PRAVO naroclilo");
    r = await kupiV(bP, T.kaja, evZ, 1);
    assert(jePlacano0(r) && r.body.mode === "stripe", "0 EUR: 201 paid, mode stripe (ne test)", r);
    v = await vrstica((r.body.order || {}).id);
    assert(v.stripe_payment_intent_id === null, "PI je NULL (ne test_...): ni testno naroclilo", v);
    r = await kupiV(bP, T.kaja, evP, 1); assert(jeBrezStripa(r), "placljivo: 409 (TEST_PLACILA ne odpre prodaje brez placila)", r);
    r = await kupiM(bP, T.kaja, evPZ, M.F3); assert(jePlacano0(r) && r.body.mode === "stripe", "miza za 0 EUR: 201 paid (ne test)", r);
    r = await kupiM(bP, T.hana, evZP, M.P1); assert(r.status === 409, "placljiva miza: 409", r);
    r = await kupiG(bP, evP, "gost-tp@example.com"); assert(jeBrezStripa(r), "gost, placljivo: 409", r);
    r = await api(bP, "GET", `/events/${evZ}`); assert(r.body.payment_mode === "stripe", "payment_mode 0 EUR: stripe", r.body.payment_mode);
    r = await api(bP, "GET", `/events/${evP}`); assert(r.body.payment_mode === "unavailable", "payment_mode 1500: unavailable (ne test)", r.body.payment_mode);

    // ================================================================
    console.log("\n# 7. Demo klub brez Stripa: 0 EUR se vedno 409 demo_club (I41)");
    r = await kupiV(bZ, T.ana, evD0); assert(r.status === 409 && r.body.error === "demo_club", "demo, vstopnica 0 EUR: 409 demo_club", r);
    r = await kupiG(bZ, evD0, "gost-demo@example.com"); assert(r.status === 409 && r.body.error === "demo_club", "demo, gost: 409 demo_club", r);
    r = await api(bZ, "GET", `/events/${evD0}`); assert(r.body.payment_mode === "unavailable" && r.body.is_demo === true, "demo: payment_mode unavailable tudi za 0 EUR", [r.body.payment_mode, r.body.is_demo]);
    rb = await api(bZ, "GET", "/business/sales", T.lastnik4, undefined, { "x-outly-club": "4" });
    assert(rb.body.payment_mode === "unavailable" && rb.body.payment_unavailable_reason === "demo_club", "demo: /business/sales demo_club", [rb.body.payment_mode, rb.body.payment_unavailable_reason]);

    // ================================================================
    console.log("\n# 8. Stripe kljuc brez webhook skrivnosti: 503 tudi za 0 EUR (ni stvar kluba, nespremenjeno)");
    r = await kupiV(bW, T.ana, evZ); assert(r.status === 503 && r.body === "Payments are not available yet.", "0 EUR: 503", r);
    r = await kupiG(bW, evZ, "gost-wh@example.com"); assert(r.status === 503, "gost 0 EUR: 503", r);
    r = await api(bW, "GET", `/events/${evZ}`); assert(r.body.payment_mode === "unavailable", "payment_mode 0 EUR: unavailable (503)", r.body.payment_mode);
    rb = await api(bW, "GET", "/business/sales", T.lastnik2, undefined, g2);
    assert(rb.body.payment_unavailable_reason === "payments_not_configured", "razlog payments_not_configured", rb.body.payment_unavailable_reason);

    // ================================================================
    console.log("\n# 9. SANDBOX in TESTNI nacin: klub brez Stripa kot doslej (test, PI test_...)");
    for (const [ime, b] of [["sandbox", bS], ["testni", bT]]) {
      r = await kupiV(b, T.ana, evP);
      assert(r.status === 201 && r.body.mode === "test" && r.body.order.status === "paid", `${ime}: placljiva vstopnica 201 mode test`, r);
      v = await vrstica((r.body.order || {}).id); assert(/^test_/.test(v.stripe_payment_intent_id || ""), `${ime}: PI test_...`, v);
      r = await kupiV(b, T.bor, evX0);
      assert(r.status === 201 && r.body.mode === "test", `${ime}: 0 EUR kot doslej (mode test)`, r);
      r = await api(b, "GET", `/events/${evP}`); assert(r.body.payment_mode === "test", `${ime}: payment_mode test (placljiv)`, r.body.payment_mode);
      r = await api(b, "GET", `/events/${evZ}`); assert(r.body.payment_mode === "test", `${ime}: payment_mode test (0 EUR)`, r.body.payment_mode);
    }

    // ================================================================
    console.log("\n# 10. Klub S Stripom: kot doslej");
    const pred10 = S.zahtevki;
    r = await kupiV(bZ, T.cene, evC0); assert(jePlacano0(r) && r.body.mode === "stripe", "0 EUR: 201 paid brez Stripa", r);
    assert(S.zahtevki === pred10, "0 EUR: Stripa se ne klice");
    r = await kupiV(bZ, T.cene, evC1); assert(r.status === 201 && r.body.mode === "stripe" && /^https:\/\/checkout\.stripe\.test\//.test(r.body.checkout_url || ""), "placljivo: 201 stripe + checkout_url", r);
    assert(S.zahtevki === pred10 + 1, "placljivo: Stripe klican enkrat");
    r = await api(bZ, "GET", `/events/${evC1}`); assert(r.body.payment_mode === "stripe", "payment_mode placljivo: stripe", r.body.payment_mode);

    // ================================================================
    console.log("\n# 11. Neznane napake streznika");
    for (const [ime, s] of [["ZIV", ZIV], ["ZIV_TP", ZIV_TP], ["ZIV_BREZ_WH", ZIV_BREZ_WH], ["SAND", SAND], ["TEST", TEST]]) {
      assert(!/Error|TypeError|ReferenceError/.test(s.log.replace(/\[placila\] POZOR[^\n]*/g, "")), `${ime}: v dnevniku ni izjem`, s.log.split("\n").filter(l => /Error/.test(l)).slice(0, 3));
    }
  } catch (e) {
    fail++; console.error("NEPRICAKOVANA NAPAKA", e);
  } finally {
    for (const s of [ZIV, ZIV_TP, ZIV_BREZ_WH, SAND, TEST]) s.srv.kill();
    jwksServer.close(); stripeServer.close();
    await pool.end();
  }
  console.log(`\n${ok} uspesnih, ${fail} neuspesnih`);
  process.exit(fail ? 1 : 0);
})();
