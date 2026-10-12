#!/usr/bin/env node
/**
 * Placljiv nakup v ZIVEM nacinu zahteva popolne podatke prodajalca (I34; ZVPot-1 18/1 2. tc.: kupec mora pred nakupom poznati
 * identiteto in naslov prodajalca; Martin 12. 10. 2026, izbira priporocila a). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_prodajalec_nakup.js
 * Vzorec kot test_pogoji_racun.js / test_stripe.js: lokalni JWKS (ES256), lazni Stripe (STRIPE_API_BASE), trije backendi na svojih portih:
 *   ZIV      sk_live_ (GOST_NAKUP_LIVE=1)      klub 1 s Stripom, klub 2 brez Stripa
 *   SANDBOX  sk_test_                          isti klubi
 *   TESTNI   brez STRIPE_SECRET_KEY            isti klubi
 *   ZIV_TP   sk_live_ + TEST_PLACILA=true      isti klubi (vsiljen testni nacin se ob live kljucu ignorira, I31)
 *
 *   1  ZIV, klub s Stripom, podatki prodajalca NEPOPOLNI (vsako od pol posebej): vstopnice, VIP miza in gost -> 409 { error: "seller_incomplete", message };
 *      brez stranskih ucinkov: nobenega naroclila, zaloga in miza nedotaknjeni, Stripa se ne kliche
 *   2  idempotenca nedotaknjena: ponovitev ISTEGA kljuca po dopolnitvi podatkov je navaden nov nakup (201 s Checkoutom), ne ponovitev 409
 *   3  ZIV, podatki POPOLNI: vstopnice, VIP miza, gost -> 201 mode stripe + checkout_url (Stripe je klican)
 *   4  ZIV, 0 EUR (vstopnice in miza) pri NEPOPOLNIH podatkih: se vedno 201 paid (brezplacno ni placljiv nakup)
 *   5  ZIV, klub brez Stripa: obstojece pravilo 409 (besedilo) pride PREJ kot seller_incomplete
 *   6  SANDBOX in TESTNI nacin: nepopolni podatki NE ustavijo nakupa (danes produkcija = sk_test_: nic se ne spremeni)
 *   7  javni odgovori: seller.complete in payment_mode sta ze v GET /events/:id (payment_mode od #220 unavailable ob nepopolnih podatkih); stripe_account_id ni
 *   8  payment_mode "unavailable" (#220): ZIV + nepopolni podatki -> GET /events, /events?lite, /events?clubId, /events/:id, /events/:id/vip,
 *      /business/events, /business/sales kazejo "unavailable" (isti pogoj kot 409 pri nakupu); popolni -> "stripe"; 0 EUR (vstopnica,
 *      prosta VIP miza) ostane "stripe"; sandbox in testni nacin ostaneta "test"/"stripe" kot doslej
 *      Dogodek odloca po VSTOPNICI, ce jo ima (placljiva vstopnica + miza za 0 EUR -> dogodek "unavailable", /vip "stripe";
 *      vstopnica 0 EUR + placljive mize -> dogodek "stripe", /vip "unavailable"). GET /business/sales ima se payment_unavailable_reason:
 *      "seller_incomplete" | "stripe_not_ready" | "payments_not_configured" | null
 *   9  TEST_PLACILA=true + sk_live_ (I31): vsiljen testni nacin se ignorira -> nepopolni podatki 409 seller_incomplete (vstopnice, miza, gost),
 *      payment_mode "unavailable"; popolni podatki -> "stripe" in 201 stripe
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT_ZIV = 3300, PORT_SANDBOX = 3301, PORT_TESTNI = 3302, JWKS_PORT = 3303, STRIPE_PORT = 3304, PORT_ZIV_TP = 3305, PORT_ZIV_BREZ_WH = 3306;
const WHSEC = "whsec_test_prodajalec";

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-prodajalec-nakup";
const jwksServer = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url.startsWith("/auth/v1/user")) { try { const t = JSON.parse(Buffer.from(String(req.headers.authorization).split(".")[1], "base64url")); return res.end(JSON.stringify({ id: t.sub, email: t.email, email_confirmed_at: "2026-01-01T00:00:00Z" })); } catch (_) { res.statusCode = 401; return res.end("{}"); } }   // potrditev e-naslova pri viru (#222): stub potrdi vsak naslov iz zetona
  if (req.url.startsWith("/auth/v1/settings")) return res.end(JSON.stringify({ mailer_autoconfirm: false, external: { anonymous_users: false } }));   // nastavitve Supabase (#222): »Confirm email« vklopljen, brez anonimnih
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
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra).slice(0, 300) : ""); } }
let ipStevec = 0;   // vsak zahtevek svoj naslov (X-Forwarded-For): omejevalnik nakupov je po IP in v skupni tabeli omejitve
async function api(baza, method, p, token, body, glave = {}) {
  const r = await fetch(baza + p, { method, headers: { "content-type": "application/json", "x-forwarded-for": `10.31.${(++ipStevec >> 8) & 255}.${(ipStevec & 255) + 1}`, ...(token ? { authorization: "Bearer " + token } : {}), ...glave },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, text: t };
}
const pocakaj = (ms) => new Promise(r => setTimeout(r, ms));

// ---------- lazni Stripe (samo Checkout seje) ----------
const S = { seje: {}, stSej: 0, zahtevki: 0 };
const stripeServer = http.createServer((req, res) => {
  let d = ""; req.on("data", x => d += x);
  req.on("end", () => {
    const p = Object.fromEntries(new URLSearchParams(d));
    const odg = (status, o) => { res.writeHead(status, { "content-type": "application/json", "request-id": "req_test" }); res.end(JSON.stringify(o)); };
    if (req.method === "POST" && req.url.split("?")[0] === "/v1/checkout/sessions") {
      S.zahtevki++;
      const id = "cs_test_" + (++S.stSej);
      S.seje[id] = { id, object: "checkout.session", url: `https://checkout.stripe.test/c/pay/${id}`, status: "open", payment_status: "unpaid",
        client_reference_id: p.client_reference_id, expires_at: Number(p.expires_at), payment_intent: null, metadata: { order_id: p["metadata[order_id]"] } };
      return odg(200, S.seje[id]);
    }
    return odg(404, { error: { type: "invalid_request_error", message: "Lazni Stripe: neznana pot " + req.method + " " + req.url } });
  });
});

function zagon(port, okolje) {
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test",
    APP_URL: "https://outly.test", TEST_PLACILA: "", STRIPE_SECRET_KEY: "", STRIPE_WEBHOOK_SECRET: "", ...okolje }, stdio: ["ignore", "pipe", "pipe"] });
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
  // Javni predpomnilnik izklopljen na streznikih, kjer podatkov prodajalca ne spreminjamo prek API-ja (da test ni odvisen od vmesnih POST-ov); ZIV ga ima vklopljenega (sklop 8 preverja razveljavitev).
  const BREZ_PREDPOMNILNIKA = { JAVNI_PREDPOMNILNIK_MS: "0" };
  const SAND = zagon(PORT_SANDBOX, { ...stripeOkolje, STRIPE_SECRET_KEY: "sk_test_lokalno", ...BREZ_PREDPOMNILNIKA });
  const TEST = zagon(PORT_TESTNI, { ...BREZ_PREDPOMNILNIKA });
  const ZIV_TP = zagon(PORT_ZIV_TP, { ...stripeOkolje, STRIPE_SECRET_KEY: "sk_live_lokalno", GOST_NAKUP_LIVE: "1", TEST_PLACILA: "true", ...BREZ_PREDPOMNILNIKA });
  const ZIV_BREZ_WH = zagon(PORT_ZIV_BREZ_WH, { STRIPE_SECRET_KEY: "sk_live_lokalno", STRIPE_API_BASE: `http://127.0.0.1:${STRIPE_PORT}`, ...BREZ_PREDPOMNILNIKA });
  const bZ = `http://127.0.0.1:${PORT_ZIV}`, bS = `http://127.0.0.1:${PORT_SANDBOX}`, bT = `http://127.0.0.1:${PORT_TESTNI}`, bP = `http://127.0.0.1:${PORT_ZIV_TP}`, bW = `http://127.0.0.1:${PORT_ZIV_BREZ_WH}`;
  await Promise.all([bZ, bS, bT, bP, bW].map(cakajStreznik));

  try {
    const imena = ["lastnik", "lastnik2", "ana", "bor", "cene", "dana", "eva", "fran", "gina", "hana"];
    const T = {};
    imena.forEach((k, i) => { T[k] = zeton(`${k}@outly.si`, uuid(i + 1)); });
    for (const k of imena) { const r = await api(bZ, "GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='business' WHERE email IN ('lastnik@outly.si','lastnik2@outly.si')");
    // Klub 1: Stripe pripravljen (Connect onboarding koncan). Klub 2: brez Stripa. Podatki prodajalca na obeh sprva prazni (le kontakt je lahko izpolnjen).
    await pool.query("INSERT INTO clubs (owner_user_id, name, city, address, stripe_account_id, stripe_charges_enabled) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Prodajalec Club', 'Ljubljana', 'Slovenska 1', 'acct_prodajalec1', TRUE)");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city, address) VALUES ((SELECT id FROM users WHERE email='lastnik2@outly.si'), 'Brez Stripa Club', 'Maribor', 'Glavni trg 2')");
    const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    const dogodek = async (klub, lastnik, title, cena, kapaciteta = 100) => {
      const r = await api(bZ, "POST", "/events", T[lastnik], { clubId: klub, title, startAt: cezDan, ticketPriceCents: cena, capacity: kapaciteta, minAge: 0 });
      assert(r.status === 201, `dogodek ${title}`, r.body); return r.body.id;
    };
    const evPlac = await dogodek(1, "lastnik", "Placljiv", 1500);
    const evZastonj = await dogodek(1, "lastnik", "Brezplacen", 0);
    const evMize = await dogodek(1, "lastnik", "Mize", 1500);
    const evBrezStripa = await dogodek(2, "lastnik2", "Brez Stripa", 1500);
    // VIP mize: placljive (dogodek Mize) in ena za 0 EUR (dogodek Brezplacen); en kupec ima na dogodek najvec eno cakajoce placilo, zato vstopnice in mize na loceni dogodkih
    await pool.query("UPDATE events SET vip_enabled = TRUE WHERE id = ANY($1)", [[evMize, evZastonj]]);
    await pool.query("INSERT INTO club_tables (club_id, label, x, y, w, h, seats, price_cents) VALUES (1,'M1',0,0,2,2,4,20000),(1,'M2',3,0,2,2,4,20000),(1,'M3',6,0,2,2,4,20000),(1,'M4',9,0,2,2,4,20000),(1,'MZ',12,0,2,2,4,0)");
    const mizaId = async (label) => (await pool.query("SELECT id FROM club_tables WHERE club_id=1 AND label=$1", [label])).rows[0].id;

    const sticna = () => pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id = ANY($1)", [[evPlac, evMize]]).then(r => r.rows[0].n);
    const prodano = () => pool.query("SELECT COALESCE(SUM(sold_count),0)::int AS n FROM events WHERE id = ANY($1)", [[evPlac, evMize]]).then(r => r.rows[0].n);
    const nastaviProdajalca = (o) => pool.query(
      "UPDATE clubs SET legal_name=$1, legal_address=$2, registration_number=$3, tax_number=$4, vat_payer=$5, contact_phone=$6, contact_email=$7 WHERE id=1",
      [o.legal_name, o.legal_address, o.registration_number, o.tax_number, o.vat_payer, o.contact_phone, o.contact_email]);
    const POPOLNO = { legal_name: "Prodajalec d.o.o.", legal_address: "Slovenska cesta 1, 1000 Ljubljana", registration_number: "1234567000", tax_number: "SI12345678",
      vat_payer: true, contact_phone: "+38640111222", contact_email: "info@prodajalec.si" };
    const NAPAKA = { error: "seller_incomplete", message: "This organizer has not completed seller details yet. Purchase is not available." };
    const jeNapaka = (r) => r.status === 409 && r.body && typeof r.body === "object" && r.body.error === NAPAKA.error && r.body.message === NAPAKA.message;
    const TERMS = { accept_terms: true, terms_version: "2026-10-01" };
    const kupiVstopnico = (baza, tok, ev, k) => api(baza, "POST", `/events/${ev}/orders`, tok, { quantity: 1 }, k ? { "idempotency-key": k } : {});
    const kupiMizo = (baza, tok, ev, miza, k) => api(baza, "POST", `/events/${ev}/tables/${miza}/orders`, tok, {}, k ? { "idempotency-key": k } : {});
    const kupiGost = (baza, ev, email) => api(baza, "POST", `/guest/events/${ev}/orders`, null, { email, quantity: 1, ...TERMS });

    // ================================================================
    console.log("\n# 1. ZIV, podatki prodajalca nepopolni: nakup zavrnjen brez stranskih ucinkov");
    const M1 = await mizaId("M1"), M2 = await mizaId("M2"), M3 = await mizaId("M3"), M4 = await mizaId("M4"), MZ = await mizaId("MZ");
    const brezStripe0 = S.zahtevki;
    // Vsaka »luknja« posebej (po eno polje manjka), nato popolnoma prazno. Vsaka vrstica je ena nepopolna stopnja.
    const luknje = {
      "vse prazno": { legal_name: "", legal_address: "", registration_number: "", tax_number: "", vat_payer: null, contact_phone: "", contact_email: "" },
      "brez firme": { ...POPOLNO, legal_name: "" },
      "brez sedeza": { ...POPOLNO, legal_address: "  " },
      "brez maticne": { ...POPOLNO, registration_number: "" },
      "brez davcne": { ...POPOLNO, tax_number: "" },
      "brez DDV statusa": { ...POPOLNO, vat_payer: null },
      "brez kontakta": { ...POPOLNO, contact_phone: "", contact_email: "" },
    };
    let stevec = 0;
    for (const [ime, vrednosti] of Object.entries(luknje)) {
      await nastaviProdajalca(vrednosti);
      const kupec = T[["ana", "bor", "cene", "dana", "eva", "fran", "gina"][stevec % 7]];
      const mail = `luknja${stevec++}@example.com`;
      let r = await kupiVstopnico(bZ, kupec, evPlac);
      assert(jeNapaka(r), `${ime}: vstopnice -> 409 seller_incomplete`, r);
      r = await kupiMizo(bZ, kupec, evMize, M1);
      assert(jeNapaka(r), `${ime}: VIP miza -> 409 seller_incomplete`, r);
      r = await kupiGost(bZ, evPlac, mail);
      assert(jeNapaka(r), `${ime}: gost -> 409 seller_incomplete`, r);
    }
    assert(await sticna() === 0 && await prodano() === 0, "nobenega naroclila, sold_count 0 (zaloga nedotaknjena)", [await sticna(), await prodano()]);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM tickets")).rows[0].n === 0, "nobene vstopnice");
    assert(S.zahtevki === brezStripe0, "Stripa se ni klicalo", S.zahtevki - brezStripe0);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE guest_email LIKE 'luknja%'")).rows[0].n === 0, "gost: nobenega naroclila");

    console.log("\n# 2. Idempotenca nedotaknjena: ponovitev istega kljuca po dopolnitvi je navaden nakup");
    await nastaviProdajalca(luknje["brez davcne"]);
    const k1 = crypto.randomUUID(), k2 = crypto.randomUUID();
    let r = await kupiVstopnico(bZ, T.hana, evPlac, k1);
    assert(jeNapaka(r), "kljuc 1 (vstopnice), podatki nepopolni: 409 seller_incomplete", r);
    r = await kupiMizo(bZ, T.hana, evMize, M1, k2);
    assert(jeNapaka(r), "kljuc 2 (miza), podatki nepopolni: 409 seller_incomplete", r);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE idempotency_key IN ($1,$2)", [k1, k2])).rows[0].n === 0, "kljuca nista zapisana v bazo");
    await nastaviProdajalca(POPOLNO);
    r = await kupiVstopnico(bZ, T.hana, evPlac, k1);
    assert(r.status === 201 && r.body.mode === "stripe" && /^https:\/\/checkout\.stripe\.test\//.test(r.body.checkout_url || ""), "po dopolnitvi isti kljuc 1: 201 stripe + checkout_url (ne ponovitev 409)", r);
    const pocasi = await kupiMizo(bZ, T.hana, evMize, M1, k2);
    assert(pocasi.status === 201 && pocasi.body.mode === "stripe", "po dopolnitvi isti kljuc 2 (miza): 201 stripe", pocasi);

    console.log("\n# 3. ZIV, podatki popolni: placljiv nakup gre skozi Stripe");
    const pred = S.zahtevki;
    r = await kupiVstopnico(bZ, T.ana, evPlac);
    assert(r.status === 201 && r.body.mode === "stripe" && r.body.checkout_url && r.body.tickets.length === 0, "vstopnice: 201 stripe, checkout_url, vstopnic se ni (cakajoce)", r);
    r = await kupiMizo(bZ, T.bor, evMize, M2);
    assert(r.status === 201 && r.body.mode === "stripe" && r.body.checkout_url, "VIP miza: 201 stripe + checkout_url", r);
    r = await kupiGost(bZ, evPlac, "gost-popoln@example.com");
    assert(r.status === 201 && r.body.mode === "stripe" && r.body.checkout_url && r.body.guest_token, "gost: 201 stripe + checkout_url + guest_token", r);
    assert(S.zahtevki - pred === 3, "Stripe je klican 3x (po enkrat na nakup)", S.zahtevki - pred);
    // Vsi trije kontakti so res enakovredni: dovolj je telefon ALI e-naslov (obstojece pravilo prodajalecPopoln)
    await nastaviProdajalca({ ...POPOLNO, contact_phone: "" });
    r = await kupiVstopnico(bZ, T.cene, evPlac);
    assert(r.status === 201 && r.body.mode === "stripe", "samo e-naslov kot kontakt zadostuje", r);
    await nastaviProdajalca({ ...POPOLNO, contact_email: "", vat_payer: false });
    r = await kupiVstopnico(bZ, T.dana, evPlac);
    assert(r.status === 201 && r.body.mode === "stripe", "samo telefon kot kontakt in vat_payer = false zadostujeta", r);

    console.log("\n# 4. ZIV, 0 EUR pri nepopolnih podatkih: brezplacno ni placljiv nakup");
    await nastaviProdajalca(luknje["vse prazno"]);
    const pred4 = S.zahtevki;
    r = await kupiVstopnico(bZ, T.eva, evZastonj);
    assert(r.status === 201 && r.body.order.status === "paid" && r.body.tickets.length === 1, "brezplacna vstopnica: 201 paid", r);
    r = await kupiMizo(bZ, T.fran, evZastonj, MZ);
    assert(r.status === 201 && r.body.order.status === "paid", "VIP miza za 0 EUR: 201 paid", r);
    r = await kupiGost(bZ, evZastonj, "gost-zastonj@example.com");
    assert(r.status === 201 && r.body.order.status === "paid", "gost, 0 EUR: 201 paid", r);
    assert(S.zahtevki === pred4, "Stripa se ni klicalo (0 EUR gre mimo Checkouta)");

    console.log("\n# 5. ZIV, klub brez Stripa: obstojece pravilo ima prednost");
    r = await kupiVstopnico(bZ, T.gina, evBrezStripa);
    assert(r.status === 409 && r.body === "This club does not accept online payments yet.", "klub brez Stripa: obstojece besedilo 409 (ne seller_incomplete)", r);
    r = await kupiGost(bZ, evBrezStripa, "gost-brez-stripa@example.com");
    assert(r.status === 409 && r.body === "This club does not accept online payments yet.", "gost, klub brez Stripa: obstojece besedilo 409", r);

    console.log("\n# 6. Sandbox (sk_test_) in testni nacin: nepopolni podatki nakupa NE ustavijo (produkcija danes = sandbox)");
    await nastaviProdajalca(luknje["vse prazno"]);
    r = await kupiVstopnico(bS, T.eva, evPlac);
    assert(r.status === 201 && r.body.mode === "stripe" && r.body.checkout_url, "sandbox + klub s Stripom: 201 stripe kot doslej", r);
    r = await kupiMizo(bS, T.fran, evMize, M3);
    assert(r.status === 201 && r.body.mode === "stripe", "sandbox, VIP miza: 201 stripe", r);
    r = await kupiGost(bS, evPlac, "gost-sandbox@example.com");
    assert(r.status === 201 && r.body.mode === "stripe", "sandbox, gost: 201 stripe", r);
    r = await kupiVstopnico(bS, T.gina, evBrezStripa);
    assert(r.status === 201 && r.body.mode === "test" && r.body.order.status === "paid", "sandbox + klub brez Stripa: 201 test (demo klubi delajo naprej)", r);
    r = await kupiVstopnico(bT, T.hana, evBrezStripa);
    assert(r.status === 201 && r.body.mode === "test" && r.body.order.status === "paid", "testni nacin (brez kljuca): 201 test", r);
    r = await kupiMizo(bT, T.ana, evMize, M4);
    assert(r.status === 201 && r.body.mode === "test" && r.body.order.status === "paid", "testni nacin, VIP miza: 201 test", r);
    r = await kupiGost(bT, evPlac, "gost-testni@example.com");
    assert(r.status === 201 && r.body.mode === "test" && r.body.order.status === "paid", "testni nacin, gost: 201 test", r);

    console.log("\n# 7. Javni odgovori nespremenjeni (seller.complete in payment_mode sta ze v odgovoru)");
    r = await api(bZ, "GET", `/events/${evPlac}`);
    assert(r.status === 200 && r.body.seller && r.body.seller.complete === false && r.body.payment_mode === "unavailable", "GET /events/:id: seller.complete false, payment_mode unavailable (#220; poln pregled v sklopu 8)", [r.body.seller, r.body.payment_mode]);
    assert(!/seller_incomplete|stripe_account_id|acct_prodajalec1/.test(r.text), "odgovor brez seller_incomplete in brez stripe_account_id (I4)");

    // ================================================================
    console.log("\n# 8. payment_mode \"unavailable\" (#220): isti pogoj kot 409 seller_incomplete pri nakupu");
    // Predpomnilnik javnih odgovorov se razveljavi samo prek API-ja (pisanje 2xx): podatke prodajalca nastavimo v bazi, nato "prazen" PATCH
    // kluba (enaka vrednost mesta) razveljavi predpomnilnik, kot bi ga razveljavil lastnik v aplikaciji.
    const lastnikGlava = { "x-outly-club": "1" };
    const razveljaviPredpomnilnik = async () => { const p = await api(bZ, "PATCH", "/business/clubs/me", T.lastnik, { city: "Ljubljana" }, lastnikGlava); assert(p.status === 200, "PATCH kluba (razveljavitev predpomnilnika)", p); };
    const nastaviInRazveljavi = async (o) => { await nastaviProdajalca(o); await razveljaviPredpomnilnik(); };
    // Dogodek z VIP mizami, med katerimi je ena za 0 EUR (MZ): prosta miza za 0 EUR je kupljiva, zato ne sme biti "unavailable".
    const evMizaZastonj = await dogodek(1, "lastnik", "Mize z brezplacno", 1500);
    await pool.query("UPDATE events SET vip_enabled = TRUE WHERE id = $1", [evMizaZastonj]);
    // evMize: brezplacno mizo izklopimo (event_tables.disabled), ostanejo samo placljive -> "unavailable". evMizaZastonj: MZ ostane.
    await pool.query("INSERT INTO event_tables (event_id, table_id, disabled) VALUES ($1, $2, TRUE)", [evMize, MZ]);
    // Placljiva vstopnica + samo miza za 0 EUR (M1..M4 izklopljene): dogodek odloca vstopnica -> "unavailable", /vip pa "stripe" (prosta miza za 0 EUR je kupljiva).
    const evBiletMiza = await dogodek(1, "lastnik", "Placljiva vstopnica, miza zastonj", 2000);
    await pool.query("UPDATE events SET vip_enabled = TRUE WHERE id = $1", [evBiletMiza]);
    await pool.query("INSERT INTO event_tables (event_id, table_id, disabled) SELECT $1, id, TRUE FROM club_tables WHERE club_id = 1 AND label IN ('M1','M2','M3','M4')", [evBiletMiza]);
    const VSE_PRAZNO = luknje["vse prazno"];
    const poIdIz = (r, id) => (r && Array.isArray(r.body) ? r.body.find(x => x.id === id) : null) || {};
    const modi = async (baza, tok) => {
      const o = {};
      const g = (pot, glave) => api(baza, "GET", pot, tok, undefined, glave);
      let r = await g(`/events/${evPlac}`); o.dogodek = r.body.payment_mode;
      r = await g(`/events/${evZastonj}`); o.dogodekZastonj = r.body.payment_mode;
      r = await g(`/events/${evBrezStripa}`); o.dogodekBrezStripa = r.body.payment_mode;
      r = await g("/events");
      o.seznam = poIdIz(r, evPlac).payment_mode; o.seznamZastonj = poIdIz(r, evZastonj).payment_mode; o.seznamMize = poIdIz(r, evMize).payment_mode; o.seznamBrezStripa = poIdIz(r, evBrezStripa).payment_mode;
      r = await g("/events?lite=true"); o.lahki = poIdIz(r, evPlac).payment_mode;
      r = await g("/events?clubId=1"); o.klub = poIdIz(r, evPlac).payment_mode;
      r = await g(`/events/${evMize}/vip`); o.vipPlacljive = r.body.payment_mode;
      r = await g(`/events/${evMizaZastonj}/vip`); o.vipZastonj = r.body.payment_mode;
      r = await g(`/events/${evZastonj}/vip`); o.vipZastonjDogodekPlacljiveMize = r.body.payment_mode;   // vstopnica 0 EUR, mize placljive (MZ zasedena)
      r = await g(`/events/${evBiletMiza}`); o.biletMiza = r.body.payment_mode;
      r = await g("/events"); o.seznamBiletMiza = poIdIz(r, evBiletMiza).payment_mode;
      r = await g(`/events/${evBiletMiza}/vip`); o.vipBiletMiza = r.body.payment_mode;
      return o;
    };
    const ujema = (o, v) => Object.entries(v).every(([k, x]) => o[k] === x);

    await nastaviInRazveljavi(VSE_PRAZNO);
    let r8x;
    let o = await modi(bZ, null);
    assert(ujema(o, { dogodek: "unavailable", seznam: "unavailable", seznamMize: "unavailable", lahki: "unavailable", klub: "unavailable", vipPlacljive: "unavailable" }),
      "ZIV + nepopolni podatki: GET /events/:id, /events, ?lite, ?clubId, /vip (samo placljive mize) -> unavailable", o);
    assert(ujema(o, { dogodekZastonj: "stripe", seznamZastonj: "stripe" }), "ZIV + nepopolni podatki: dogodek z vstopnico za 0 EUR ostane stripe (kupljiv)", o);
    assert(ujema(o, { vipZastonj: "stripe" }), "ZIV + nepopolni podatki: VIP z mizo za 0 EUR ostane stripe (kupljiv)", o);
    assert(ujema(o, { biletMiza: "unavailable", seznamBiletMiza: "unavailable", vipBiletMiza: "stripe" }),
      "placljiva vstopnica + miza za 0 EUR: dogodek unavailable (vstopnica odloca), /vip stripe (prosta miza)", o);
    assert(ujema(o, { dogodekZastonj: "stripe", vipZastonjDogodekPlacljiveMize: "unavailable" }), "vstopnica 0 EUR + placljive mize: dogodek stripe, /vip unavailable", o);
    r8x = await kupiVstopnico(bZ, T.cene, evBiletMiza);
    assert(jeNapaka(r8x), "dogodek unavailable <=> nakup vstopnice 409 seller_incomplete (miza za 0 EUR tega ne spremeni)", r8x);
    r8x = await kupiMizo(bZ, T.cene, evBiletMiza, MZ);
    assert(r8x.status === 201 && r8x.body.order.status === "paid", "prosta miza za 0 EUR (/vip stripe) je kupljiva: 201 paid", r8x);
    assert(ujema(o, { dogodekBrezStripa: "unavailable", seznamBrezStripa: "unavailable" }), "klub brez Stripa: unavailable kot doslej", o);
    // Prijavljen uporabnik: isti javni del (predpomnilnik, I17)
    const oA = await modi(bZ, T.ana);
    assert(JSON.stringify(oA) === JSON.stringify(o), "prijavljen kupec vidi enak payment_mode kot gost", [oA, o]);
    // Lastnik: GET /business/events in GET /business/sales
    let r8 = await api(bZ, "GET", "/business/events", T.lastnik, undefined, lastnikGlava);
    assert(r8.status === 200 && poIdIz(r8, evPlac).payment_mode === "unavailable" && poIdIz(r8, evZastonj).payment_mode === "stripe", "GET /business/events: unavailable pri placljivem, stripe pri 0 EUR", Array.isArray(r8.body) && r8.body.map(x => [x.id, x.payment_mode]));
    r8 = await api(bZ, "GET", "/business/sales", T.lastnik, undefined, lastnikGlava);
    assert(r8.status === 200 && r8.body.payment_mode === "unavailable", "GET /business/sales: payment_mode kluba unavailable", r8.body.payment_mode);
    assert(r8.body.payment_unavailable_reason === "seller_incomplete", "GET /business/sales: payment_unavailable_reason seller_incomplete", r8.body.payment_unavailable_reason);
    r8 = await api(bZ, "GET", "/business/sales", T.lastnik2, undefined, { "x-outly-club": "2" });
    assert(r8.status === 200 && r8.body.payment_mode === "unavailable" && r8.body.payment_unavailable_reason === "stripe_not_ready", "klub brez Stripa (live): payment_unavailable_reason stripe_not_ready", [r8.body.payment_mode, r8.body.payment_unavailable_reason]);
    r8 = await api(bW, "GET", "/business/sales", T.lastnik, undefined, lastnikGlava);
    assert(r8.status === 200 && r8.body.payment_mode === "unavailable" && r8.body.payment_unavailable_reason === "payments_not_configured", "Stripe kljuc brez webhook skrivnosti: payment_unavailable_reason payments_not_configured", [r8.body.payment_mode, r8.body.payment_unavailable_reason]);
    const javni = await api(bZ, "GET", `/events/${evPlac}`);
    assert(javni.status === 200 && !("payment_unavailable_reason" in javni.body) && !/payment_unavailable_reason/.test((await api(bZ, "GET", "/events")).text), "razlog NI na javnih poteh (GET /events, /events/:id)");
    // Ujemanje z nakupom: kar javni odgovor oznaci kot unavailable, nakup zavrne s seller_incomplete (isti pogoj)
    r8 = await kupiVstopnico(bZ, T.ana, evPlac);
    assert(jeNapaka(r8), "unavailable v javnem odgovoru <=> 409 seller_incomplete pri nakupu (vstopnica)", r8);
    r8 = await kupiMizo(bZ, T.ana, evMize, M1);
    assert(jeNapaka(r8), "unavailable v /vip <=> 409 seller_incomplete pri nakupu (miza)", r8);
    for (const pot of ["/events", `/events/${evPlac}`, "/events?lite=true", `/events/${evMize}/vip`]) {
      const surovi = await api(bZ, "GET", pot, null);
      assert(surovi.status === 200 && !/club_stripe_ready|club_seller_raw|seller_raw|acct_prodajalec1|stripe_account_id/.test(surovi.text), `GET ${pot}: brez pomoznih stolpcev (club_seller_raw, club_stripe_ready, seller_raw) in racuna (I4)`);
    }
    const surovi = await api(bZ, "GET", "/business/events", T.lastnik, undefined, lastnikGlava);
    assert(surovi.status === 200 && !/club_stripe_ready|club_seller_raw|seller_raw|acct_prodajalec1|stripe_account_id/.test(surovi.text), "GET /business/events: brez pomoznih stolpcev in racuna (I4)");

    // Lastnik dopolni podatke prodajalca prek API-ja -> vse postane stripe (predpomnilnik razveljavljen, brez zamika)
    await nastaviInRazveljavi({ ...VSE_PRAZNO, contact_email: "info@prodajalec.si" });
    const dop = await api(bZ, "PATCH", "/business/clubs/me", T.lastnik, { legalName: POPOLNO.legal_name, legalAddress: POPOLNO.legal_address, registrationNumber: POPOLNO.registration_number, taxNumber: POPOLNO.tax_number, vatPayer: true }, lastnikGlava);
    assert(dop.status === 200, "lastnik dopolni podatke prodajalca prek PATCH", dop);
    o = await modi(bZ, null);
    assert(ujema(o, { dogodek: "stripe", seznam: "stripe", seznamMize: "stripe", lahki: "stripe", klub: "stripe", vipPlacljive: "stripe", vipZastonj: "stripe", dogodekZastonj: "stripe" }),
      "ZIV + popolni podatki (po PATCH): vse stripe", o);
    assert(ujema(o, { biletMiza: "stripe", seznamBiletMiza: "stripe", vipBiletMiza: "stripe", vipZastonjDogodekPlacljiveMize: "stripe" }), "popolni podatki: tudi mesani dogodki stripe", o);
    assert(ujema(o, { dogodekBrezStripa: "unavailable" }), "popolni podatki ne popravijo kluba brez Stripa (unavailable)", o);
    r8 = await api(bZ, "GET", "/business/sales", T.lastnik, undefined, lastnikGlava);
    assert(r8.status === 200 && r8.body.payment_mode === "stripe" && r8.body.payment_unavailable_reason === null, "GET /business/sales: stripe po dopolnitvi, payment_unavailable_reason null", [r8.body.payment_mode, r8.body.payment_unavailable_reason]);

    // Sandbox in testni nacin: payment_mode ni odvisen od podatkov prodajalca (I34 velja samo ob sk_live_)
    await nastaviInRazveljavi(VSE_PRAZNO);
    const oS = await modi(bS, null), oT = await modi(bT, null);
    assert(ujema(oS, { dogodek: "stripe", seznam: "stripe", vipPlacljive: "stripe", dogodekBrezStripa: "test" }), "sandbox + nepopolni podatki: stripe / test kot doslej", oS);
    assert(ujema(oT, { dogodek: "test", seznam: "test", vipPlacljive: "test", dogodekBrezStripa: "test" }), "testni nacin + nepopolni podatki: test kot doslej", oT);
    r8 = await api(bS, "GET", "/business/sales", T.lastnik, undefined, lastnikGlava);
    assert(r8.status === 200 && r8.body.payment_mode === "stripe" && r8.body.payment_unavailable_reason === null, "sandbox: GET /business/sales payment_mode stripe, razlog null", [r8.body.payment_mode, r8.body.payment_unavailable_reason]);

    // ================================================================
    console.log("\n# 9. TEST_PLACILA=true + sk_live_ (I31): vsiljen testni nacin se ignorira, I34 velja");
    // Zagon izpise POZOR (preverja test_placila_zagon.js); tu: nepopolni podatki -> 409 in unavailable, kot brez TEST_PLACILA.
    const pred9 = S.zahtevki, naroc9 = (await pool.query("SELECT COUNT(*)::int AS n FROM orders")).rows[0].n;
    await nastaviInRazveljavi(VSE_PRAZNO);
    r = await kupiVstopnico(bP, T.ana, evPlac);
    assert(jeNapaka(r), "TEST_PLACILA + sk_live_ + nepopolni podatki: vstopnice -> 409 seller_incomplete (ne testna vstopnica)", r);
    r = await kupiMizo(bP, T.bor, evMize, M1);
    assert(jeNapaka(r), "TEST_PLACILA + sk_live_ + nepopolni podatki: VIP miza -> 409 seller_incomplete", r);
    r = await kupiGost(bP, evPlac, "gost-tp@example.com");
    assert(jeNapaka(r), "TEST_PLACILA + sk_live_ + nepopolni podatki: gost -> 409 seller_incomplete", r);
    assert(S.zahtevki === pred9, "Stripa se ni klicalo");
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders")).rows[0].n === naroc9, "nobenega novega naroclila (testni nacin NI vsiljen)");
    r = await api(bP, "GET", `/events/${evPlac}`);
    assert(r.status === 200 && r.body.payment_mode === "unavailable", "TEST_PLACILA + sk_live_ + nepopolni podatki: GET /events/:id -> unavailable (ne test)", r.body.payment_mode);
    r = await api(bP, "GET", `/events/${evMize}/vip`);
    assert(r.status === 200 && r.body.payment_mode === "unavailable", "isto za /vip", r.body.payment_mode);
    r = await api(bP, "GET", `/events/${evZastonj}`);
    assert(r.status === 200 && r.body.payment_mode === "stripe", "0 EUR dogodek: stripe (kupljiv)", r.body.payment_mode);
    r = await kupiVstopnico(bP, T.cene, evZastonj);
    assert(r.status === 201 && r.body.order.status === "paid", "0 EUR vstopnica: 201 paid", r);
    // Popolni podatki: stripe + pravi Checkout
    await nastaviInRazveljavi(POPOLNO);
    r = await api(bP, "GET", `/events/${evPlac}`);
    assert(r.status === 200 && r.body.payment_mode === "stripe", "TEST_PLACILA + sk_live_ + popolni podatki: GET /events/:id -> stripe", r.body.payment_mode);
    r = await kupiVstopnico(bP, T.gina, evPlac);
    assert(r.status === 201 && r.body.mode === "stripe" && r.body.checkout_url, "TEST_PLACILA + sk_live_ + popolni podatki: 201 stripe + checkout_url", r);
  } finally {
    for (const o of [ZIV, SAND, TEST, ZIV_TP, ZIV_BREZ_WH]) { try { o.srv.kill(); } catch {} }
    stripeServer.close(); jwksServer.close(); await pool.end().catch(() => {});
  }
  console.log(`\n${ok} OK, ${fail} NAPAK`);
  process.exit(fail === 0 ? 0 : 1);
})().catch(e => { console.error(e); process.exit(1); });
