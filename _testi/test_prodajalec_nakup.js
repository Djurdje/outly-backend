#!/usr/bin/env node
/**
 * Placljiv nakup v ZIVEM nacinu zahteva popolne podatke prodajalca (I34; ZVPot-1 18/1 2. tc.: kupec mora pred nakupom poznati
 * identiteto in naslov prodajalca; Martin 12. 10. 2026, izbira priporocila a). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_prodajalec_nakup.js
 * Vzorec kot test_pogoji_racun.js / test_stripe.js: lokalni JWKS (ES256), lazni Stripe (STRIPE_API_BASE), trije backendi na svojih portih:
 *   ZIV      sk_live_ (GOST_NAKUP_LIVE=1)      klub 1 s Stripom, klub 2 brez Stripa
 *   SANDBOX  sk_test_                          isti klubi
 *   TESTNI   brez STRIPE_SECRET_KEY            isti klubi
 *
 *   1  ZIV, klub s Stripom, podatki prodajalca NEPOPOLNI (vsako od pol posebej): vstopnice, VIP miza in gost -> 409 { error: "seller_incomplete", message };
 *      brez stranskih ucinkov: nobenega naroclila, zaloga in miza nedotaknjeni, Stripa se ne kliche
 *   2  idempotenca nedotaknjena: ponovitev ISTEGA kljuca po dopolnitvi podatkov je navaden nov nakup (201 s Checkoutom), ne ponovitev 409
 *   3  ZIV, podatki POPOLNI: vstopnice, VIP miza, gost -> 201 mode stripe + checkout_url (Stripe je klican)
 *   4  ZIV, 0 EUR (vstopnice in miza) pri NEPOPOLNIH podatkih: se vedno 201 paid (brezplacno ni placljiv nakup)
 *   5  ZIV, klub brez Stripa: obstojece pravilo 409 (besedilo) pride PREJ kot seller_incomplete
 *   6  SANDBOX in TESTNI nacin: nepopolni podatki NE ustavijo nakupa (danes produkcija = sk_test_: nic se ne spremeni)
 *   7  javni odgovori nespremenjeni: seller.complete in payment_mode sta ze v GET /events/:id; stripe_account_id ni
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT_ZIV = 3300, PORT_SANDBOX = 3301, PORT_TESTNI = 3302, JWKS_PORT = 3303, STRIPE_PORT = 3304;
const WHSEC = "whsec_test_prodajalec";

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-prodajalec-nakup";
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
  const SAND = zagon(PORT_SANDBOX, { ...stripeOkolje, STRIPE_SECRET_KEY: "sk_test_lokalno" });
  const TEST = zagon(PORT_TESTNI, {});
  const bZ = `http://127.0.0.1:${PORT_ZIV}`, bS = `http://127.0.0.1:${PORT_SANDBOX}`, bT = `http://127.0.0.1:${PORT_TESTNI}`;
  await Promise.all([bZ, bS, bT].map(cakajStreznik));

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
    assert(r.status === 200 && r.body.seller && r.body.seller.complete === false && r.body.payment_mode === "stripe", "GET /events/:id: seller.complete false, payment_mode stripe", [r.body.seller, r.body.payment_mode]);
    assert(!/seller_incomplete|stripe_account_id|acct_prodajalec1/.test(r.text), "odgovor brez seller_incomplete in brez stripe_account_id (I4)");
  } finally {
    for (const o of [ZIV, SAND, TEST]) { try { o.srv.kill(); } catch {} }
    stripeServer.close(); jwksServer.close(); await pool.end().catch(() => {});
  }
  console.log(`\n${ok} OK, ${fail} NAPAK`);
  process.exit(fail === 0 ? 0 : 1);
})().catch(e => { console.error(e); process.exit(1); });
