#!/usr/bin/env node
/**
 * Nakup vstopnice BREZ racuna (migracija 033, invarianta I22). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_gost.js
 * Vzorec kot test_stripe.js / test_zloraba.js: lokalni JWKS, lazni Stripe, backend na svojem portu; poleg tega lazni Resend
 * (RESEND_BASE_URL), da se vidi, koliko mailov je poslanih in kaj piše v njih.
 *
 *   1  testni nacin: nakup z e-naslovom, zeton, vstopnice, v bazi samo hash, brez vrstice v `users`
 *   2  mail z vstopnico: poslan natanko enkrat, povezava deluje, brez sledilnikov
 *   3  GET /guest/order: oblika, napacen/manjkajoc zeton 404, Cache-Control: no-store, CORS za X-Guest-Token
 *   4  validacija (400) pred omejevalnikom; starost (I8, 403); razprodano (I2, 409); hkratni nakupi
 *   5  idempotenca (I18): ponovitev, svez zeton, 422, vezano na e-naslov, hkratnost
 *   6  Stripe nacin: checkout_url, success_url z zetonom, customer_email, webhook -> paid -> mail enkrat, pospravljalec, potekla seja
 *   7  zloraba: 1 neplacano na (e-naslov, dogodek), brez enumeracije racunov, gost ne steje v omejitev uporabnika; nakup 10/h/IP (429; GOST_NAKUP_NA_URO)
 *   8  poslovni pogledi: vratar brez e-naslova, »Guest«, sken, prodaja
 *   9  prevzem v racun: GET /me, /me/orders, /me/tickets; neprevzet pri nepotrjenem e-naslovu; tuji uporabniki ne vidijo
 *  10  napaka Resenda ne podre nakupa, pospravljalec poslje mail (enkrat); potek zetona + pospravljanje
 *  10b hramba: anonimizacija e-naslova (neplacano 24 h, placano 180 dni po dogodku)
 *  10c preklic: ob ponavljanju in vzporednih klicih Stripa ne obremenjujemo (409 request_in_progress)
 *  14  dnevna meja mailov samo za testna narocila; placano potrdilo gre vedno
 *  15  pospravljalec: naroila v premoru ne stradajo novejsih
 *  16  mail natanko enkrat tudi ob pocasnem posiljanju (#201): mnozica v teku + spodnja meja premora
 *  11  obstojeci nakupi prijavljenih nespremenjeni
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");
const Stripe = require("stripe");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT_A = 3191, PORT_B = 3192, JWKS_PORT = 3951, STRIPE_PORT = 3952, RESEND_PORT = 3953;
const A = `http://127.0.0.1:${PORT_A}`, B = `http://127.0.0.1:${PORT_B}`;
const WHSEC = "whsec_test_gost";
const stripeLokalno = new Stripe("sk_test_lokalno");

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-gost";
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
async function zahtevek(baza, method, path, token, body, glave = {}) {
  const r = await fetch(baza + path, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}), ...glave },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, headers: r.headers };
}
const api = (m, p, t, b, g) => zahtevek(A, m, p, t, b, g);
const pocakaj = (ms) => new Promise(r => setTimeout(r, ms));
async function cakaj(pogoj, ms = 6000) { const do_ = Date.now() + ms; while (Date.now() < do_) { if (await pogoj()) return true; await pocakaj(100); } return false; }

// ---------- lazni Resend ----------
const R = { poslano: [], napaka: false, zamik: 0, vLetu: 0, najvecSocasnih: 0, zamudnjena: [] };
const resendServer = http.createServer((req, res) => {
  let d = ""; req.on("data", x => d += x);
  req.on("end", () => {
    if (req.method === "POST" && req.url === "/emails") {
      if (R.napaka) { res.writeHead(422, { "content-type": "application/json" }); return res.end(JSON.stringify({ name: "validation_error", message: "stub: zavrnjeno", statusCode: 422 })); }
      const m = JSON.parse(d);
      R.vLetu++; R.najvecSocasnih = Math.max(R.najvecSocasnih, R.vLetu);
      const koncaj = (arr) => { R.vLetu--; arr.push(m); res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ id: "mail_" + (R.poslano.length + R.zamudnjena.length) })); };
      // zamik > GOST_POSTA_TIMEOUT_MS: odgovor pride prepozno; mail se steje med »zamudnjene« (backend ga je ze zavrgel)
      if (R.zamik) return setTimeout(() => koncaj(R.zamik > 1500 ? R.zamudnjena : R.poslano), R.zamik);
      return koncaj(R.poslano);
    }
    res.writeHead(404, { "content-type": "application/json" }); res.end("{}");
  });
});
const poslanoNa = (email) => R.poslano.filter(m => m.to === email || (Array.isArray(m.to) && m.to.includes(email)));
const zetonIzMaila = (m) => { const x = /\/app\/guest\/order#t=([A-Za-z0-9_-]{43})/.exec(m.html || ""); return x ? x[1] : null; };

// ---------- lazni Stripe ----------
const S = { seje: {}, stSej: 0, zahtevki: [], branj: 0, zamikBranja: 0 };
const stripeServer = http.createServer((req, res) => {
  let d = ""; req.on("data", x => d += x);
  req.on("end", () => {
    const p = Object.fromEntries(new URLSearchParams(d));
    const odg = (s, o) => { res.writeHead(s, { "content-type": "application/json", "request-id": "req_test" }); res.end(JSON.stringify(o)); };
    const u = req.url.split("?")[0];
    let m;
    if (req.method === "POST" && u === "/v1/checkout/sessions") {
      const kljuc = req.headers["idempotency-key"];
      S.zahtevki.push({ params: p, kljuc });
      const id = "cs_test_" + (++S.stSej);
      const kol = Number(p["line_items[0][quantity]"]), cena = Number(p["line_items[0][price_data][unit_amount]"]);
      S.seje[id] = { id, object: "checkout.session", url: `https://checkout.stripe.test/c/pay/${id}`, status: "open", payment_status: "unpaid",
        amount_total: kol * cena, currency: p["line_items[0][price_data][currency]"], client_reference_id: p.client_reference_id,
        metadata: { order_id: p["metadata[order_id]"], public_ref: p["metadata[public_ref]"] }, expires_at: Number(p.expires_at), payment_intent: null };
      return odg(200, S.seje[id]);
    }
    if (req.method === "GET" && (m = u.match(/^\/v1\/checkout\/sessions\/(cs_\w+)$/))) { S.branj++; return S.zamikBranja ? setTimeout(() => odg(200, S.seje[m[1]]), S.zamikBranja) : odg(200, S.seje[m[1]]); }
    if (req.method === "POST" && (m = u.match(/^\/v1\/checkout\/sessions\/(cs_\w+)\/expire$/))) { S.seje[m[1]].status = "expired"; return odg(200, S.seje[m[1]]); }
    return odg(404, { error: { type: "invalid_request_error", message: "Lazni Stripe: neznana pot " + req.method + " " + u } });
  });
});
let stDogodka = 0;
async function webhook(tip, objekt, id) {
  const d = { id: id || `evt_gost_${++stDogodka}`, object: "event", type: tip, data: { object: objekt }, created: Math.floor(Date.now() / 1000) };
  const payload = JSON.stringify(d);
  const glava = stripeLokalno.webhooks.generateTestHeaderString({ payload, secret: WHSEC });
  const r = await fetch(A + "/stripe/webhook", { method: "POST", headers: { "content-type": "application/json", "stripe-signature": glava }, body: payload });
  return { status: r.status };
}
const placana = (s, pi) => ({ ...s, status: "complete", payment_status: "paid", payment_intent: pi });

function zagon(port, okolje) {
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, QR_SECRET: "test", APP_URL: "https://outly.test",
    TEST_PLACILA: "", GOST_PREVZEM_MS: "0", ...okolje }, stdio: ["ignore", "pipe", "pipe"] });
  const s = { srv, log: "" };
  srv.stdout.on("data", d => s.log += d); srv.stderr.on("data", d => s.log += d);
  return s;
}
async function cakajStreznik(baza) { for (let i = 0; i < 80; i++) { try { await fetch(baza + "/"); return; } catch { await pocakaj(100); } } }

const TERMS = { accept_terms: true, terms_version: "2026-10-01" };
const nakup = (ev, email, dodatno = {}, glave = {}, baza = A) => zahtevek(baza, "POST", `/guest/events/${ev}/orders`, null, { email, quantity: 1, ...TERMS, ...dodatno }, glave);
const brezAvtorizacije = (baza, path, zetonGosta) => zahtevek(baza, "GET", path, null, undefined, zetonGosta === undefined ? {} : { "x-guest-token": zetonGosta });
const iso = (d) => d.toISOString().slice(0, 10);
const letaNazaj = (leta, dniNaprej = 0) => { const d = new Date(); d.setUTCFullYear(d.getUTCFullYear() - leta); d.setUTCDate(d.getUTCDate() + dniNaprej); return iso(d); };

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, stripe_events, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  await new Promise(r => stripeServer.listen(STRIPE_PORT, r));
  await new Promise(r => resendServer.listen(RESEND_PORT, r));
  const a = zagon(PORT_A, { RESEND_API_KEY: "re_test", RESEND_BASE_URL: `http://127.0.0.1:${RESEND_PORT}`, EMAIL_FROM: "Outly <test@outly.test>",
    STRIPE_SECRET_KEY: "sk_test_lokalno", STRIPE_WEBHOOK_SECRET: WHSEC, STRIPE_API_BASE: `http://127.0.0.1:${STRIPE_PORT}`, STRIPE_POSPRAVI_MS: "600",
    GOST_NAKUP_NA_URO: "1000", GOST_PREKLIC_OKNO_MS: "1500", GOST_POSTA_PONOVI_MS: "500", GOST_POSTA_PREMOR_MS: "400", GOST_POSTA_TIMEOUT_MS: "1000", GOST_POSTA_REZERVA_MS: "100", GOST_NEUSPESNI_NA_URO: "1000", REZERVACIJE_CISCENJE_MS: "1000", GOST_HRAMBA_DNI: "180" });
  let b = null;
  await cakajStreznik(A);

  try {
    const T = { lastnik: zeton("lastnik@outly.si", uuid(1)), lastnik2: zeton("lastnik2@outly.si", uuid(2)), vratar: zeton("vratar@outly.si", uuid(3)),
      manager: zeton("manager@outly.si", uuid(4)), ana: zeton("ana@outly.si", uuid(5)), tuj: zeton("tuj@outly.si", uuid(6)) };
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='business' WHERE email IN ('lastnik@outly.si','lastnik2@outly.si')");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana')");
    await pool.query(`INSERT INTO clubs (owner_user_id, name, city, stripe_account_id, stripe_charges_enabled)
                      VALUES ((SELECT id FROM users WHERE email='lastnik2@outly.si'), 'Stripe Klub', 'Maribor', 'acct_test2', TRUE)`);
    await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, (SELECT id FROM users WHERE email='vratar@outly.si'), 'doorman')");
    await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, (SELECT id FROM users WHERE email='manager@outly.si'), 'manager')");
    const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    const dogodek = async (lastnik, clubId, title, capacity, minAge = 0) => {
      const r = await api("POST", "/events", T[lastnik], { clubId, title, startAt: cezDan, ticketPriceCents: 1500, capacity, minAge });
      assert(r.status === 201, `dogodek »${title}« ustvarjen`, r.body);
      return r.body.id;
    };
    const evA = await dogodek("lastnik", 1, "Gost Noc", 50);
    const ev18 = await dogodek("lastnik", 1, "Gost 18+", 50, 18);
    const evMali = await dogodek("lastnik", 1, "Gost Mali", 2);
    const evTekma = await dogodek("lastnik", 1, "Gost Tekma", 3);
    const evIdem = await dogodek("lastnik", 1, "Gost Idem", 4);
    const evMail = await dogodek("lastnik", 1, "Gost Mail", 50);
    const evPotek = await dogodek("lastnik", 1, "Gost Potek", 50);
    const evStripe = await dogodek("lastnik2", 2, "Stripe Noc", 20);
    const evCap = await dogodek("lastnik2", 2, "Stripe Cap", 30);
    const evCap2 = await dogodek("lastnik2", 2, "Stripe Cap 2", 30);
    const evStripe2 = await dogodek("lastnik2", 2, "Stripe Noc 2", 20);
    const sold = async (ev) => (await pool.query("SELECT sold_count FROM events WHERE id=$1", [ev])).rows[0].sold_count;

    // ============================================================
    console.log("\n# 1. Testni nacin: nakup z e-naslovom");
    let r = await nakup(evA, "  Gost@Example.COM ", { quantity: 2 });
    assert(r.status === 201 && r.body.mode === "test", "201, mode test", r);
    const zeton1 = r.body.guest_token;
    assert(typeof zeton1 === "string" && /^[A-Za-z0-9_-]{43}$/.test(zeton1), "guest_token: 43 znakov base64url (32 B)", zeton1);
    assert(r.body.order.status === "paid" && r.body.order.quantity === 2 && r.body.order.total_cents === 3000 && r.body.order.event_title === "Gost Noc", "order: paid, 2 x 15 EUR, naslov dogodka", r.body.order);
    assert(r.body.tickets.length === 2 && r.body.tickets.every(t => t.qr && t.serial && t.status === "valid"), "2 vstopnici s QR in serialom v odgovoru", r.body.tickets);
    assert(!("checkout_url" in r.body), "testno narocilo nima checkout_url");
    assert(r.headers.get("cache-control") === "no-store", "Cache-Control: no-store", r.headers.get("cache-control"));
    const n1 = r.body.order.id;
    let o = (await pool.query("SELECT user_id, buyer_email, guest_email, guest_terms_version, guest_terms_accepted_at, status, table_id FROM orders WHERE id=$1", [n1])).rows[0];
    assert(o.user_id === null && o.guest_email === "gost@example.com" && o.buyer_email === "gost@example.com", "v bazi: user_id NULL, e-naslov normaliziran (trim + lower)", o);
    assert(o.guest_terms_version === "2026-10-01" && o.guest_terms_accepted_at, "sprejeti pogoji shranjeni (verzija + cas)", o);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM users WHERE lower(email)='gost@example.com'")).rows[0].n === 0, "gost NI vrstica v users");
    assert(await sold(evA) === 2, "sold_count 2", await sold(evA));
    const hash = crypto.createHash("sha256").update(zeton1).digest("hex");
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM gost_zetoni WHERE token_hash=$1 AND order_id=$2", [hash, n1])).rows[0].n === 1, "v bazi je sha256 zetona");
    const povsod = (await pool.query("SELECT (SELECT string_agg(o::text, ' ') FROM orders o) || (SELECT string_agg(z::text, ' ') FROM gost_zetoni z) AS t")).rows[0].t;
    assert(!povsod.includes(zeton1), "cistopisa zetona nikjer v orders / gost_zetoni");

    console.log("\n# 2. Mail z vstopnico");
    assert(await cakaj(() => poslanoNa("gost@example.com").length >= 1), "mail na gostov naslov poslan");
    await pocakaj(1500);   // pospravljalec (500 ms) ne sme poslati drugega
    const mail = poslanoNa("gost@example.com");
    assert(mail.length === 1, "mail poslan natanko enkrat (tudi po pospravljalcu)", mail.length);
    const m0 = mail[0] || {};
    assert(/Gost Noc/.test(m0.subject || "") && /Gost Noc/.test(m0.html || "") && /Pure Club/.test(m0.html || "") && /2 x 15\.00 EUR/.test(m0.html || ""), "mail: dogodek, klub, stevilo vstopnic", m0.subject);
    assert(/^Outly <test@outly\.test>$/.test(m0.from || ""), "mail: posiljatelj iz EMAIL_FROM", m0.from);
    assert(!/<script|pixel|track/i.test(m0.html || "") && !/<img[^>]+src="(?!cid:)/i.test(m0.html || ""), "mail: brez sledilnikov in zunanjih slik (samo vgrajene cid:)");
    // QR inline + PDF (migracija 034): 2 vstopnici -> vgrajena slika PNG SAMO za prvo kodo (content_id) + 1 PDF z 2 stranema (vse kode)
    const pr = m0.attachments || [];
    const slike = pr.filter(x => x.content_type === "image/png");
    assert(slike.length === 1 && slike[0].content_id === "ticket-qr-1" && Buffer.from(slike[0].content, "base64").subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])), "mail: ena vgrajena slika QR (prva koda; PNG, content_id)", pr.map(x => [x.filename, x.content_type, x.content_id]));
    assert(/src="cid:ticket-qr-1"/.test(m0.html || "") && !/cid:ticket-qr-2/.test(m0.html || "") && /first QR code is below; all your QR codes \(one per page\) are in the attached PDF/.test(m0.text || ""), "mail: HTML kaze prvo sliko (cid:), besedilo pove, da so vse kode v PDF");
    const pdfP = pr.find(x => x.content_type === "application/pdf");
    const pdfB = pdfP ? Buffer.from(pdfP.content, "base64") : Buffer.alloc(0);
    assert(pdfP && pdfP.filename === "outly-tickets.pdf" && pdfB.subarray(0, 5).toString() === "%PDF-" && pdfB.toString("latin1").includes("%%EOF") && (pdfB.toString("latin1").match(/\/Type \/Page /g) || []).length === 2, "mail: priloga PDF (2 strani, vse kode)", pdfP && pdfP.filename);
    assert(!JSON.stringify(pdfP || {}).includes("gost@example.com") && !pdfB.toString("latin1").includes("gost@example.com"), "PDF brez e-naslova prejemnika");
    assert(m0.reply_to === "luka@outly.si", "mail: reply-to luka@outly.si", m0.reply_to);
    const t0 = m0.text || "";
    const ob = (re, opis) => assert(re.test(t0), `potrdilo (besedilo maila): ${opis}`, t0.slice(0, 200));
    const nr = (await pool.query("SELECT public_ref FROM orders WHERE guest_email='gost@example.com'")).rows[0].public_ref;
    ob(new RegExp(`Order ${nr}, placed on .*\\(Ljubljana time\\)`), "stevilka narocila + datum in ura nakupa");
    ob(/Gost Noc\n.*\(Ljubljana time\)\nPure Club, .*Ljubljana\nNo age limit\./s, "dogodek: naziv, datum/ura, kraj, starostna meja");
    ob(/2 x 15\.00 EUR = 30\.00 EUR\. VAT is charged according to the seller's VAT status\./, "stevilo, cena/vstopnico, skupaj; DDV stavek ob neznani stopnji (vat_rate NULL)");
    ob(/Complaints\s+About the event: contact the club.*About the purchase or the payment: contact Outly at luka@outly\.si/is, "stavek o pritozbah (klub za dogodek, Outly za nakup/placilo)");
    ob(/sold by the club: Pure Club/, "prodajalec = klub");
    ob(/NEXT DIMENSIONS, družba za marketing, d\.o\.o\., Trebče 81, 3256 Bistrica ob Sotli, luka@outly\.si/, "posrednik NEXT DIMENSIONS");
    ob(/no right of withdrawal.*ZVPot-1, Article 135, point 12/i, "izjema od odstopa (ZVPot-1 135/12)");
    ob(/terms, version 2026-10-01: https:\/\/outly\.si\/terms/, "povezava do pogojev z razlicico iz narocila");
    ob(/This link is your ticket\. Don't share it except with people coming with you\./, "stavek o skrivni povezavi");
    ob(/If you create an Outly account with this email, your tickets will appear there\./, "stavek o prevzemu v racun");
    assert(!/you might also like|recommend|other events/i.test(t0), "potrdilo: brez oglasov in priporocil");
    const zetonMail = zetonIzMaila(m0);
    assert(zetonMail && zetonMail !== zeton1, "mail: povezava https://outly.test/app/guest/order#t=<svez zeton> (fragment, ne poizvedba)", zetonMail);
    assert((m0.text || "").includes(`https://outly.test/app/guest/order#t=${zetonMail}`), "mail: povezava tudi v tekstovni razlicici");
    assert((await pool.query("SELECT guest_mail_sent_at FROM orders WHERE id=$1", [n1])).rows[0].guest_mail_sent_at !== null, "guest_mail_sent_at zapisan");

    // ============================================================
    console.log("\n# 3. GET /guest/order");
    r = await brezAvtorizacije(A, "/guest/order", zeton1);
    assert(r.status === 200 && r.body.order.status === "paid" && r.body.order.quantity === 2 && r.body.order.total_cents === 3000 && r.body.order.currency === "EUR", "200: order status/quantity/total/currency", r.body.order);
    assert(r.body.order.event.title === "Gost Noc" && r.body.order.event.club_name === "Pure Club" && r.body.order.event.start_at && r.body.order.event.id === evA, "order.event: id, title, start_at, club_name", r.body.order.event);
    assert(r.body.order.event_title === "Gost Noc" && r.body.order.club_name === "Pure Club", "order: tudi ravna polja kot /me/orders (event_title, club_name)");
    assert(!("buyer_email" in r.body.order) && !JSON.stringify(r.body).includes("gost@example.com"), "odgovor ne vsebuje e-naslova");
    assert(r.body.tickets.length === 2 && r.body.tickets.every(t => t.qr && t.serial && t.status === "valid" && t.event_title === "Gost Noc" && t.transferable === false), "tickets: ista oblika kot /me/tickets (qr, serial, status, event_title), ne prenosljive", r.body.tickets[0]);
    assert(r.headers.get("cache-control") === "no-store", "Cache-Control: no-store");
    const kljuciGost = Object.keys(r.body.tickets[0]).sort().join(",");
    const meVst = await api("GET", "/me/tickets", T.ana);   // ana je bila prijavljena: oblika mora biti ista, ko bo vstopnico imela
    r = await brezAvtorizacije(A, "/guest/order", zetonMail);
    assert(r.status === 200 && r.body.tickets.length === 2, "zeton iz maila deluje (vec zetonov na narocilo)", r.status);
    r = await brezAvtorizacije(A, "/guest/order", zeton1.slice(0, -1) + (zeton1.endsWith("A") ? "B" : "A"));
    assert(r.status === 404, "napacen zeton -> 404", r.status);
    const tekstNapacen = r.body;
    r = await brezAvtorizacije(A, "/guest/order", "kratek");
    assert(r.status === 404 && r.body === tekstNapacen, "zeton napacne oblike -> 404 (enako besedilo)", r);
    r = await brezAvtorizacije(A, "/guest/order");
    assert(r.status === 404, "brez zetona -> 404", r.status);
    r = await brezAvtorizacije(A, `/guest/order?t=${zeton1}`);
    assert(r.status === 404, "zeton v URL-ju se NE sprejme (samo glava)", r.status);
    r = await zahtevek(A, "GET", "/guest/order", T.ana, undefined, { "x-guest-token": zeton1 });
    assert(r.status === 200, "zeton velja tudi, ce je zahtevek prijavljen (neodvisen od racuna)", r.status);
    let pf = await fetch(`${A}/guest/order`, { method: "OPTIONS", headers: { origin: "https://outly.si", "access-control-request-method": "GET", "access-control-request-headers": "x-guest-token" } });
    assert(pf.status === 204 && (pf.headers.get("access-control-allow-headers") || "").toLowerCase().includes("x-guest-token"), "CORS preflight dovoli X-Guest-Token", [pf.status, pf.headers.get("access-control-allow-headers")]);
    pf = await fetch(`${A}/guest/events/${evA}/orders`, { method: "OPTIONS", headers: { origin: "https://outly.si", "access-control-request-method": "POST", "access-control-request-headers": "content-type,idempotency-key" } });
    assert(pf.status === 204 && (pf.headers.get("access-control-allow-headers") || "").toLowerCase().includes("idempotency-key"), "CORS preflight dovoli Idempotency-Key na POST /guest/events/:id/orders");
    r = await zahtevek(A, "POST", `/guest/events/${evA}/tables/1/orders`, null, { email: "x@example.com", ...TERMS });
    assert(r.status === 404, "VIP miza za goste ne obstaja (404)", r.status);

    // ============================================================
    console.log("\n# 4. Validacija, starost, razprodano");
    const prej = await sold(evA);
    const slabi = [
      [{ accept_terms: false }, "accept_terms false"], [{ accept_terms: "true" }, "accept_terms kot niz"], [{ accept_terms: undefined }, "brez accept_terms"],
      [{ terms_version: undefined }, "brez terms_version"], [{ terms_version: "x y" }, "terms_version z presledkom"],
      [{ email: "ni-naslov" }, "e-naslov brez @"], [{ email: "a@b" }, "e-naslov brez domene s piko"], [{ email: "a@b.c" }, "TLD 1 znak"], [{ email: "a b@c.si" }, "presledek v e-naslovu"],
      [{ email: ".a@c.si" }, "pika na zacetku"], [{ email: "a..b@c.si" }, "dvojna pika"], [{ email: "a@-c.si" }, "domena z vezajem na zacetku"],
      [{ email: `${"a".repeat(250)}@c.si` }, "e-naslov > 254"], [{ email: 5 }, "e-naslov ni niz"], [{ email: undefined }, "brez e-naslova"],
      [{ quantity: 0 }, "quantity 0"], [{ quantity: 7 }, "quantity 7 (meja za goste 6)"], [{ quantity: 1.5 }, "quantity 1.5"], [{ quantity: "dva" }, "quantity niz"],
      [{ date_of_birth: "1990-13-01" }, "datum rojstva: mesec 13"], [{ date_of_birth: "1990-02-30" }, "datum rojstva: 30. 2."], [{ date_of_birth: "01.01.1990" }, "datum rojstva: napacna oblika"],
    ];
    for (const [dod, opis] of slabi) {
      r = await nakup(evA, "veljaven@example.com", dod);
      assert(r.status === 400 && typeof r.body === "string", `400: ${opis}`, [r.status, r.body]);
    }
    r = await zahtevek(A, "POST", `/guest/events/${evA}/orders`, null, undefined);
    assert(r.status === 400, "brez telesa -> 400", r.status);
    r = await zahtevek(A, "POST", "/guest/events/abc/orders", null, { email: "x@example.com", ...TERMS });
    assert(r.status === 400, "neveljaven id dogodka -> 400", r.status);
    r = await nakup(evA, "veljaven@example.com", {}, { "idempotency-key": "ni-uuid" });
    assert(r.status === 400 && r.body.error === "invalid_idempotency_key", "neveljaven Idempotency-Key -> 400", r);
    r = await nakup(99999, "veljaven@example.com");
    assert(r.status === 404, "dogodek ne obstaja -> 404", r.status);
    r = await nakup(evA, "veljaven@example.com", { date_of_birth: letaNazaj(0, 5) });
    assert(r.status === 400, "datum rojstva v prihodnosti -> 400", r);
    assert(await sold(evA) === prej, "zavrnjeni nakupi niso porabili zaloge", await sold(evA));
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE guest_email='veljaven@example.com'")).rows[0].n === 0, "zavrnjeni nakupi niso ustvarili narocil");

    r = await nakup(ev18, "mladi@example.com");
    assert(r.status === 403 && /date of birth/i.test(r.body), "18+: brez datuma rojstva -> 403 (I8)", r);
    r = await nakup(ev18, "mladi@example.com", { date_of_birth: letaNazaj(18, 40) });
    assert(r.status === 403 && /at least 18/.test(r.body), "18+: 17-letnik -> 403 (I8)", r);
    r = await nakup(ev18, "star@example.com", { date_of_birth: letaNazaj(18, -2) });
    assert(r.status === 201 && r.body.tickets.length === 1, "18+: dopolnjenih 18 let -> 201", r);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE guest_email='mladi@example.com'")).rows[0].n === 0, "18+: zavrnjen kupec nima narocila");
    assert((await pool.query("SELECT guest_age_min FROM orders WHERE guest_email='star@example.com'")).rows[0].guest_age_min === 18, "v narocilu samo guest_age_min = 18 (datum rojstva se NE shrani)");
    const stolpci = (await pool.query("SELECT column_name FROM information_schema.columns WHERE table_name IN ('orders','gost_zetoni') AND column_name ~* '(birth|dob|rojstv)'")).rows;
    assert(stolpci.length === 0, "ni stolpca za datum rojstva", stolpci);
    assert(!(await pool.query("SELECT string_agg(o::text, ' ') AS t FROM orders o")).rows[0].t.includes(letaNazaj(18, -2)), "datum rojstva ni nikjer v vrsticah orders");
    r = await nakup(evA, "mladi@example.com", { date_of_birth: letaNazaj(16) });
    assert(r.status === 201, "dogodek brez omejitve: datum rojstva ni obvezen, mladoleten sme (min_age 0)", r);

    r = await nakup(evMali, "m1@example.com", { quantity: 2 });
    assert(r.status === 201, "evMali (kapaciteta 2): 2 vstopnici", r);
    r = await nakup(evMali, "m2@example.com");
    assert(r.status === 409 && /Only 0 tickets left/.test(r.body), "razprodano -> 409 (I2)", r);
    r = await nakup(evMali, "m3@example.com");
    assert(r.status === 409, "razprodano (iz spomina razprodano) -> 409", r);
    const hkrati = await Promise.all([1, 2, 3, 4, 5, 6].map(i => nakup(evTekma, `tekma${i}@example.com`)));
    assert(hkrati.filter(x => x.status === 201).length === 3 && hkrati.filter(x => x.status === 409).length === 3, "kapaciteta 3, 6 hkratnih nakupov: natanko 3 uspejo", hkrati.map(x => x.status));
    assert(await sold(evTekma) === 3, "sold_count == capacity (brez oversell)", await sold(evTekma));
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM tickets WHERE event_id=$1", [evTekma])).rows[0].n === 3, "natanko 3 vstopnice");

    // ============================================================
    console.log("\n# 5. Idempotenca (kot I18, vezana na e-naslov)");
    const K = crypto.randomUUID();
    r = await nakup(evIdem, "idem@example.com", { quantity: 4 }, { "idempotency-key": K });
    assert(r.status === 201 && r.body.tickets.length === 4, "prvi nakup 201 (vsa kapaciteta dogodka)", r);
    const idemOrder = r.body.order.id, idemTokenPrvi = r.body.guest_token, idemSerials = r.body.tickets.map(t => t.id).sort();
    r = await nakup(evIdem, "idem@example.com", { quantity: 4 }, { "idempotency-key": K });
    assert(r.status === 201 && r.headers.get("idempotent-replayed") === "true", "ponovitev: 201 + Idempotent-Replayed", [r.status, r.headers.get("idempotent-replayed")]);
    assert(r.body.order.id === idemOrder && r.body.tickets.map(t => t.id).sort().join() === idemSerials.join(), "ponovitev: isto narocilo in iste vstopnice", r.body.order);
    assert(r.body.guest_token && r.body.guest_token !== idemTokenPrvi, "ponovitev dobi SVEZ guest_token (cistopisa prvega ni)", r.body.guest_token);
    let g = await brezAvtorizacije(A, "/guest/order", r.body.guest_token);
    assert(g.status === 200 && g.body.tickets.length === 4, "svez zeton deluje", g.status);
    g = await brezAvtorizacije(A, "/guest/order", idemTokenPrvi);
    assert(g.status === 200, "prvi zeton se vedno deluje", g.status);
    assert(await sold(evIdem) === 4 && (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1", [evIdem])).rows[0].n === 1, "ponovitev: eno narocilo, zaloga enkrat");
    r = await nakup(evIdem, "idem@example.com", { quantity: 4 }, { "idempotency-key": K });
    assert(r.status === 201, "ponovitev na RAZPRODANEM dogodku je 201 (NE 409 »Only 0 tickets left«)", r);
    r = await nakup(evIdem, "idem@example.com", { quantity: 3 }, { "idempotency-key": K });
    assert(r.status === 422 && r.body.error === "idempotency_key_reused", "isti kljuc, druga kolicina -> 422", r);
    r = await nakup(evA, "idem@example.com", { quantity: 4 }, { "idempotency-key": K });
    assert(r.status === 422, "isti kljuc, drug dogodek -> 422", r);
    r = await nakup(evA, "drugi-idem@example.com", { quantity: 1 }, { "idempotency-key": K });
    assert(r.status === 201 && !r.headers.get("idempotent-replayed") && r.body.order.id !== idemOrder, "isti UUID z drugim e-naslovom = njegovo lastno novo narocilo (kljuc je vezan na e-naslov)", r.body.order);
    const K2 = crypto.randomUUID();
    const vzp = await Promise.all([1, 2, 3, 4, 5, 6].map(() => nakup(evA, "vzporedni@example.com", {}, { "idempotency-key": K2 })));
    assert(vzp.every(x => x.status === 201) && new Set(vzp.map(x => x.body.order.id)).size === 1, "6 hkratnih z istim kljucem: vsi 201, isto narocilo", vzp.map(x => x.status));
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE guest_email='vzporedni@example.com'")).rows[0].n === 1, "v bazi natanko 1 narocilo");
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM tickets t JOIN orders o ON o.id=t.order_id WHERE o.guest_email='vzporedni@example.com'")).rows[0].n === 1, "natanko 1 vstopnica");
    await pool.query("UPDATE orders SET status='refunded', refunded_cents=total_cents WHERE id=$1", [idemOrder]);
    r = await nakup(evIdem, "idem@example.com", { quantity: 4 }, { "idempotency-key": K });
    assert(r.status === 409 && r.body.error === "order_not_active", "vrnjeno narocilo: ponovitev -> 409 order_not_active", r);
    await pool.query("UPDATE orders SET status='paid', refunded_cents=0 WHERE id=$1", [idemOrder]);
    let nepl = await nakup(evA, "idem3@example.com", { quantity: 1 }, { "idempotency-key": crypto.randomUUID() });
    assert(nepl.status === 201, "nakup z novim kljucem normalno gre", nepl.status);
    const bazaIdem = await pool.query("SELECT indexdef FROM pg_indexes WHERE indexname='orders_gost_idempotency_key'");
    assert(/UNIQUE/.test(bazaIdem.rows[0].indexdef), "baza: unikaten indeks (guest_email, idempotency_key)");
    let bazaZavrne = false;
    try { await pool.query(`INSERT INTO orders (public_ref, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, paid_at, idempotency_key, guest_email, guest_terms_version, guest_terms_accepted_at)
      SELECT 'OUT-DUP', event_id, club_id, quantity, unit_price_cents, total_cents, 'paid', buyer_email, NOW(), idempotency_key, guest_email, 'x', NOW() FROM orders WHERE id=$1`, [idemOrder]); }
    catch (e) { bazaZavrne = e.code === "23505"; }
    assert(bazaZavrne, "baza sama zavrne dvojnik (guest_email, kljuc): 23505");

    // ============================================================
    console.log("\n# 6. Stripe nacin");
    const stZah = S.zahtevki.length;
    r = await nakup(evStripe, "plac@example.com", { quantity: 2 });
    assert(r.status === 201 && r.body.mode === "stripe" && r.body.order.status === "pending", "201 stripe, pending", r);
    assert(r.body.tickets.length === 0 && r.body.checkout_url === "https://checkout.stripe.test/c/pay/cs_test_1", "tickets [] in checkout_url", r.body);
    const zetonStripe = r.body.guest_token, nS = r.body.order.id;
    const P = S.zahtevki[stZah].params;
    assert(P.success_url === `https://outly.test/app/guest/order#t=${zetonStripe}`, "success_url = https://outly.test/app/guest/order#t=<guest_token> (fragment)", P.success_url);
    assert(P.cancel_url === `https://outly.test/app/guest/order#t=${zetonStripe}`, "cancel_url = stran narocila (Complete payment / Cancel order)", P.cancel_url);
    assert(P.customer_email === "plac@example.com", "Stripe Checkout: customer_email predizpolnjen", P.customer_email);
    assert(P["payment_intent_data[on_behalf_of]"] === "acct_test2" && P["payment_intent_data[transfer_data][destination]"] === "acct_test2" && P["payment_intent_data[application_fee_amount]"] === "300", "Connect: racun kluba + provizija 10 % (isto kot pri racunih)", P);
    r = await brezAvtorizacije(A, "/guest/order", zetonStripe);
    assert(r.status === 200 && r.body.order.status === "pending" && r.body.tickets.length === 0 && r.body.order.checkout_url, "GET /guest/order pending: tickets [], checkout_url", r.body);
    await pocakaj(800);
    assert(poslanoNa("plac@example.com").length === 0, "pending: mail se NI poslan");
    const sP = S.seje.cs_test_1;
    Object.assign(sP, placana(sP, "pi_gost_1"));
    let w = await webhook("checkout.session.completed", { id: sP.id, object: "checkout.session" }, "evt_gost_placilo_1");
    assert(w.status === 200, "webhook completed -> 200");
    r = await brezAvtorizacije(A, "/guest/order", zetonStripe);
    assert(r.status === 200 && r.body.order.status === "paid" && r.body.tickets.length === 2 && r.body.tickets.every(t => t.qr), "po webhooku: paid + 2 vstopnici z QR (zeton iz success_url)", r.body.order);
    assert(await cakaj(() => poslanoNa("plac@example.com").length >= 1), "po webhooku: mail poslan");
    w = await webhook("checkout.session.completed", { id: sP.id, object: "checkout.session" }, "evt_gost_placilo_1");
    assert(w.status === 200, "ponovljen webhook (isti evt) -> 200");
    w = await webhook("checkout.session.completed", { id: sP.id, object: "checkout.session" });
    await pocakaj(1500);
    assert(poslanoNa("plac@example.com").length === 1, "mail natanko enkrat (ponovljen webhook in nov dogodek za isto sejo)", poslanoNa("plac@example.com").length);
    const zetonStripeMail = zetonIzMaila(poslanoNa("plac@example.com")[0]);
    r = await brezAvtorizacije(A, "/guest/order", zetonStripeMail);
    assert(r.status === 200 && r.body.tickets.length === 2, "zeton iz maila (nastal ob webhooku) deluje", r.status);

    // zloraba: 1 neplacano na (e-naslov, dogodek)
    console.log("\n# 7. Zloraba");
    r = await nakup(evStripe2, "pend@example.com");
    assert(r.status === 201 && r.body.order.status === "pending", "prvo neplacano gostujoce narocilo: 201", r);
    const nPend = r.body.order.id, zetonPend = r.body.guest_token;
    r = await nakup(evStripe2, "pend@example.com");
    assert(r.status === 409 && /unfinished payment for this event/.test(r.body), "drugo neplacano za isti (e-naslov, dogodek) -> 409", r);
    assert(await sold(evStripe2) === 1, "zaloga: zasedena samo 1 (ne 2)", await sold(evStripe2));
    r = await nakup(evStripe2, "PEND@example.com ");
    assert(r.status === 409, "isti naslov z drugimi velikimi crkami / presledki -> 409 (normalizacija)", r.status);
    r = await nakup(evStripe2, "pend2@example.com");
    assert(r.status === 201, "drug e-naslov za isti dogodek: 201", r.status);
    r = await nakup(evStripe, "pend@example.com");
    assert(r.status === 201, "isti e-naslov, drug dogodek: 201", r.status);
    const hk = await Promise.all([1, 2, 3, 4, 5].map(() => nakup(evStripe2, "hkrati@example.com")));
    assert(hk.filter(x => x.status === 201).length === 1 && hk.filter(x => x.status === 409).length === 4, "5 hkratnih za isti (e-naslov, dogodek): tocno 1 uspe, 4 dobijo 409", hk.map(x => x.status));
    const kP = crypto.randomUUID();
    r = await nakup(evStripe, "kljuc@example.com", {}, { "idempotency-key": kP });
    const urlPrvi = r.body.checkout_url;
    r = await nakup(evStripe, "kljuc@example.com", {}, { "idempotency-key": kP });
    assert(r.status === 201 && r.body.checkout_url === urlPrvi && r.headers.get("idempotent-replayed") === "true", "ponovitev kljuca pri cakajocem: isti checkout_url (NE 409)", r);
    // potekla seja -> cancelled -> zaloga sproscena, zeton ne kaze nicesar
    const sPend = S.seje[(await pool.query("SELECT stripe_checkout_session_id FROM orders WHERE id=$1", [nPend])).rows[0].stripe_checkout_session_id];
    sPend.status = "expired";
    w = await webhook("checkout.session.expired", { id: sPend.id, object: "checkout.session" });
    assert((await pool.query("SELECT status FROM orders WHERE id=$1", [nPend])).rows[0].status === "cancelled", "potekla seja: narocilo cancelled");
    r = await brezAvtorizacije(A, "/guest/order", zetonPend);
    assert(r.status === 404, "preklicano neplacano narocilo: zeton -> 404 (kot napacen)", r.status);
    r = await nakup(evStripe2, "pend@example.com");
    assert(r.status === 201, "po preteku prvega gre nov nakup", r.status);

    // placana seja brez webhooka: pospravljalec
    r = await nakup(evStripe, "pospravi@example.com");
    const nPo = r.body.order.id;
    const sPo = S.seje[(await pool.query("SELECT stripe_checkout_session_id FROM orders WHERE id=$1", [nPo])).rows[0].stripe_checkout_session_id];
    Object.assign(sPo, placana(sPo, "pi_gost_pospravi"));
    await pool.query("UPDATE orders SET checkout_expires_at = NOW() - INTERVAL '10 minutes' WHERE id=$1", [nPo]);
    assert(await cakaj(async () => (await pool.query("SELECT status FROM orders WHERE id=$1", [nPo])).rows[0].status === "paid", 8000), "placana seja brez webhooka: pospravljalec vknjizi placilo");
    assert(await cakaj(() => poslanoNa("pospravi@example.com").length >= 1), "pospravljalec Stripa: mail poslan");
    await pocakaj(1200);
    assert(poslanoNa("pospravi@example.com").length === 1, "natanko 1 mail", poslanoNa("pospravi@example.com").length);

    // gost ni uporabnik: omejitev neplacanih obstojecega racuna ni prizadeta
    r = await nakup(evStripe, "ana@outly.si");
    const kljuciGostSt = Object.keys(r.body).sort().join(",");
    assert(r.status === 201 && r.body.order.status === "pending", "gostujoci nakup z e-naslovom OBSTOJECEGA racuna: 201 (brez razkritja, da racun obstaja)", r);
    r = await nakup(evStripe, "popolnoma-nov@example.com");
    assert(Object.keys(r.body).sort().join(",") === kljuciGostSt, "enaka oblika odgovora za e-naslov z racunom in brez", [kljuciGostSt, Object.keys(r.body).sort().join(",")]);
    r = await api("POST", `/events/${evStripe}/orders`, T.ana, { quantity: 1 });
    assert(r.status === 201 && r.body.order.status === "pending", "ana (racun) za isti dogodek: gostujoce naroilo NE steje v njeno omejitev neplacanih (201)", r);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE user_id=(SELECT id FROM users WHERE email='ana@outly.si') AND status='pending'")).rows[0].n === 1, "ana ima 1 cakajoce narocilo v svoji omejitvi");

    // ============================================================
    console.log("\n# 8. Poslovni pogledi");
    const gostOrder = n1;
    r = await api("GET", `/business/events/${evA}/tickets`, T.vratar);
    const gv = r.body.filter(t => t.order_id === gostOrder);
    assert(r.status === 200 && gv.length === 2, "vratar: seznam vstopnic dogodka vsebuje gostujoce", [r.status, gostOrder, r.body.length, r.body[0]]);
    assert(gv.every(t => !("buyer_email" in t) && !("holder_email" in t)), "vratar: gostujoce vstopnice BREZ buyer_email in holder_email", gv[0]);
    assert(gv.every(t => t.holder_username === "Guest" && t.buyer_username === "Guest" && t.is_guest === true && t.qr), "vratar: imetnik »Guest«, QR ostane", gv[0]);
    r = await api("GET", `/business/events/${evA}/tickets`, T.lastnik);
    const gl = r.body.filter(t => t.order_id === gostOrder);
    assert(gl.every(t => t.holder_email === null && t.holder_username === "Guest" && t.buyer_email === "gost@example.com"), "lastnik: holder »Guest« brez e-naslova; buyer_email kot pri vseh kupcih", gl[0]);
    const vseVratar = JSON.stringify((await api("GET", `/business/events/${evA}/tickets`, T.vratar)).body);
    assert(!/@example\.com/.test(vseVratar), "vratar: nikjer v seznamu ni gostovega e-naslova");
    const qr1 = gv[0].qr, serial1 = gv[0].serial;
    await pool.query("UPDATE events SET start_at = NOW() + INTERVAL '2 hours' WHERE id=$1", [evA]);   // okno skena (I25): dogodek zacne cez 2 h (nakupi so se mogoci)
    r = await api("POST", "/business/tickets/scan", T.vratar, { qr: qr1 });
    assert(r.status === 200 && r.body.result === "ok" && r.body.ticket.status === "used", "vratar skenira gostujoco vstopnico: ok (ista QR logika)", r);
    assert(!("buyer_email" in r.body.ticket) && !JSON.stringify(r.body).includes("@example.com") && r.body.ticket.holder_username === "Guest", "odgovor skena: brez e-naslova, imetnik »Guest«", r.body.ticket);
    r = await api("POST", "/business/tickets/scan", T.vratar, { qr: qr1 });
    assert(r.status === 409 && r.body.result === "already_used", "dvojni sken gostujoce vstopnice -> 409 already_used (I1)", r);
    r = await api("GET", `/business/events/${evA}/scan-list`, T.vratar);
    const sl = r.body.tickets.find(t => t.serial === serial1);
    assert(r.status === 200 && sl && sl.status === "used" && sl.holder_username === "Guest", "scan-list: gostujoca vstopnica z imetnikom »Guest«", sl);
    assert(!JSON.stringify(r.body).includes("@example.com"), "scan-list: brez e-naslovov");
    r = await api("POST", "/business/tickets/scan-batch", T.vratar, { device_id: crypto.randomUUID(), scans: [{ client_scan_id: crypto.randomUUID(), qr: gv[1].qr, scanned_at: new Date().toISOString() }] });
    assert(r.status === 200 && r.body.results[0].result === "ok", "scan-batch: gostujoca vstopnica ok", r.body);
    r = await brezAvtorizacije(A, "/guest/order", zeton1);
    assert(r.body.tickets.every(t => t.status === "used"), "gost vidi, da sta vstopnici porabljeni", r.body.tickets.map(t => t.status));
    r = await api("GET", "/business/sales", T.lastnik, undefined, { "x-outly-club": "1" });
    const gostov = r.body.recent_orders.find(x => x.id === gostOrder);
    assert(r.status === 200 && gostov && gostov.buyer_username === "Guest" && gostov.is_guest === true, "prodaja: gostujoce narocilo med zadnjimi, kupec »Guest«", gostov);
    const placanaGost = (await pool.query("SELECT COUNT(*)::int AS n, COALESCE(SUM(total_cents),0)::int AS vsota, COUNT(DISTINCT COALESCE(user_id::text, lower(guest_email)))::int AS kupcev, COALESCE(SUM(quantity),0)::int AS vst FROM orders WHERE club_id=1 AND status IN ('paid','partially_refunded')")).rows[0];
    assert(r.body.summary.orders === placanaGost.n && r.body.summary.gross_cents === placanaGost.vsota && r.body.summary.tickets_sold === placanaGost.vst, "prodaja: gostujoca narocila se STEJEJO (orders, gross, tickets_sold)", [r.body.summary, placanaGost]);
    assert(r.body.summary.buyers === placanaGost.kupcev && r.body.summary.buyers > 1, "prodaja: buyers steje tudi goste", r.body.summary.buyers);

    // ============================================================
    console.log("\n# 9. Prevzem v racun");
    // racun z istim, POTRJENIM e-naslovom: gost + (Stripe) pending
    const serialiGost = (await brezAvtorizacije(A, "/guest/order", zeton1)).body.tickets.map(t => t.serial).sort();
    const ZG = zeton("gost@example.com", uuid(20));
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE guest_email='gost@example.com' AND user_id IS NULL")).rows[0].n === 1, "pred prijavo: gostujoce narocilo je brez uporabnika");
    r = await api("GET", "/me/orders", ZG);
    assert(r.status === 200 && r.body.length === 1 && r.body[0].id === n1 && r.body[0].tickets.length === 2 && r.body[0].is_guest === false, "nov racun z istim e-naslovom: /me/orders vsebuje gostujoce narocilo (prevzeto)", r.body);
    r = await api("GET", "/me/tickets", ZG);
    assert(r.status === 200 && r.body.length === 2 && r.body.every(t => t.order_status === "paid" && t.holder_username === "gost"), "/me/tickets: obe vstopnici, imetnik je zdaj uporabnik", r.body.map(t => t.holder_username));
    assert(Object.keys(r.body[0]).sort().join(",") === kljuciGost, "oblika vstopnice v /me/tickets == oblika v GET /guest/order", [Object.keys(r.body[0]).sort().join(","), kljuciGost]);
    const serialiMe = r.body.map(t => t.serial).sort();
    assert(serialiMe.join() === serialiGost.join(), "iste vstopnice (serial) v racunu in prek zetona");
    r = await brezAvtorizacije(A, "/guest/order", zeton1);
    assert(r.status === 404, "ob prevzemu v racun se zeton gosta PRECE (404)", r.status);
    r = await brezAvtorizacije(A, "/guest/order", zetonMail);
    assert(r.status === 404, "tudi zeton iz maila (vsi zetoni narocila)", r.status);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM gost_zetoni WHERE order_id=$1", [n1])).rows[0].n === 0, "v bazi ni vec zetonov prevzetega narocila");
    r = await api("GET", `/business/events/${evA}/tickets`, T.vratar);
    assert(r.body.filter(t => t.order_id === n1).every(t => t.holder_username === "gost" && t.is_guest === false), "poslovni pogled po prevzemu: imetnik je uporabnik, ne vec »Guest«");
    r = await api("GET", "/me/orders", T.tuj);
    assert(r.status === 200 && !r.body.some(x => x.id === n1), "tuj uporabnik NIKOLI ne vidi gostovih narocil (I3)", r.body.length);
    r = await api("GET", "/me/tickets", T.tuj);
    assert(r.status === 200 && r.body.length === 0, "tuj uporabnik: /me/tickets prazen");
    // nepotrjen e-naslov: ne prevzame
    await pool.query("INSERT INTO users (email, username, email_verified, supabase_uid) VALUES ('nepotrjen@example.com', 'nepotrjen', FALSE, $1)", [uuid(21)]);
    r = await nakup(evA, "nepotrjen@example.com");
    assert(r.status === 201, "gostujoci nakup z e-naslovom racuna s NEPOTRJENIM e-naslovom: 201");
    const ZN = zeton("nepotrjen@example.com", uuid(21));
    r = await api("GET", "/me", ZN);
    assert(r.status === 200, "GET /me nepotrjen (obstojeca vrstica po uid)", r.status);
    r = await api("GET", "/me/orders", ZN);
    assert(r.status === 200 && r.body.length === 0, "nepotrjen e-naslov (users.email_verified = false): gostujoce narocilo NI prevzeto", r.body.length);
    await pool.query("UPDATE users SET email_verified = TRUE WHERE email='nepotrjen@example.com'");
    r = await api("GET", "/me", ZN);
    r = await api("GET", "/me/orders", ZN);
    assert(r.body.length === 1, "po potrditvi e-naslova se prevzame", r.body.length);
    // obstojec racun (ana): cakajoce gostujoce narocilo se NE prevzame (zeton iz success_url mora veljati do placila), placano se
    r = await api("GET", "/me", T.ana);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE guest_email='ana@outly.si' AND user_id IS NOT NULL")).rows[0].n === 0, "cakajoce gostujoce narocilo se ne prevzame");
    await pool.query("UPDATE orders SET status='paid', paid_at=NOW() WHERE guest_email='ana@outly.si'");
    r = await api("GET", "/me", T.ana);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE guest_email='ana@outly.si' AND user_id IS NOT NULL")).rows[0].n === 1, "obstojec racun (ana): ko je narocilo placano, /me ga prevzame");

    // ============================================================
    console.log("\n# 10. Napaka Resenda, potek zetona");
    R.napaka = true;
    const mailov = R.poslano.length;
    r = await nakup(evMail, "resend-napaka@example.com");
    assert(r.status === 201 && r.body.tickets.length === 1, "Resend zavrne mail: nakup se vedno 201 z vstopnico", r);
    const nMail = r.body.order.id, zetonMail2 = r.body.guest_token;
    assert(await cakaj(async () => (await pool.query("SELECT guest_mail_attempts FROM orders WHERE id=$1", [nMail])).rows[0].guest_mail_attempts >= 2, 8000), "pospravljalec je ze ponovil poskus (stevec poskusov >= 2)");
    let st = (await pool.query("SELECT guest_mail_sent_at, guest_mail_attempts, status FROM orders WHERE id=$1", [nMail])).rows[0];
    assert(st.status === "paid" && st.guest_mail_sent_at === null && st.guest_mail_attempts >= 1, "mail ni poslan, poskusi so zabelezeni, narocilo placano", st);
    assert(R.poslano.length === mailov, "stub Resend ni sprejel nicesar (pospravljalec je poskusil vsaj 2x: poskusi so narascali)");
    assert(/Resend napaka \(gost, vstopnice/.test(a.log) && !/resend-napaka@example\.com/.test(a.log), "napaka je v dnevniku, BREZ e-naslova", a.log.split("\n").filter(l => /Resend/.test(l)).slice(-2));
    r = await brezAvtorizacije(A, "/guest/order", zetonMail2);
    assert(r.status === 200 && r.body.tickets.length === 1, "gost vstopnico vidi kljub neuspelemu mailu");
    R.napaka = false;
    assert(await cakaj(() => poslanoNa("resend-napaka@example.com").length >= 1, 8000), "ko Resend spet dela, pospravljalec poslje mail");
    await pocakaj(1500);
    assert(poslanoNa("resend-napaka@example.com").length === 1, "mail natanko enkrat", poslanoNa("resend-napaka@example.com").length);
    const nPoskusovPrej = (await pool.query("SELECT guest_mail_attempts FROM orders WHERE id=$1", [nMail])).rows[0].guest_mail_attempts;
    await pocakaj(1200);
    assert((await pool.query("SELECT guest_mail_attempts FROM orders WHERE id=$1", [nMail])).rows[0].guest_mail_attempts === nPoskusovPrej, "poslano narocilo se vec ne obdeluje");

    // zeton potece: konec dogodka + 30 dni
    r = await nakup(evPotek, "potek@example.com");
    const zetonPotek = r.body.guest_token, nPotek = r.body.order.id;
    await pool.query("UPDATE events SET start_at = NOW() - INTERVAL '10 days', end_at = NULL WHERE id=$1", [evPotek]);
    r = await brezAvtorizacije(A, "/guest/order", zetonPotek);
    assert(r.status === 200, "10 dni po zacetku dogodka: zeton velja (konec + 30 dni)", r.status);
    await pool.query("UPDATE events SET start_at = NOW() - INTERVAL '30 days', end_at = NOW() - INTERVAL '29 days' WHERE id=$1", [evPotek]);
    r = await brezAvtorizacije(A, "/guest/order", zetonPotek);
    assert(r.status === 200, "29 dni po koncu: se velja", r.status);
    await pool.query("UPDATE events SET start_at = NOW() - INTERVAL '32 days', end_at = NOW() - INTERVAL '31 days' WHERE id=$1", [evPotek]);
    r = await brezAvtorizacije(A, "/guest/order", zetonPotek);
    assert(r.status === 404, "31 dni po koncu: zeton potekel -> 404", r.status);
    assert(await cakaj(async () => (await pool.query("SELECT COUNT(*)::int AS n FROM gost_zetoni WHERE order_id=$1", [nPotek])).rows[0].n === 0, 8000), "pospravljalec izbrise potecene zetone");
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE id=$1", [nPotek])).rows[0].n === 1, "narocilo samo ostane (racunovodski podatek)");
    // omejitev stevila zetonov na narocilo
    const Kz = crypto.randomUUID();
    r = await nakup(evMail, "zetoni@example.com", {}, { "idempotency-key": Kz });
    for (let i = 0; i < 14; i++) await nakup(evMail, "zetoni@example.com", {}, { "idempotency-key": Kz });
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM gost_zetoni WHERE order_id=$1", [r.body.order.id])).rows[0].n <= 10 + 1, "najvec ~10 zetonov na narocilo (ponovitve ne rastejo v nedogled)", (await pool.query("SELECT COUNT(*)::int AS n FROM gost_zetoni WHERE order_id=$1", [r.body.order.id])).rows[0].n);

    // ============================================================
    console.log("\n# 10c. Preklic neplacanega narocila (POST /guest/order/cancel)");
    const seja = async (id) => S.seje[(await pool.query("SELECT stripe_checkout_session_id FROM orders WHERE id=$1", [id])).rows[0].stripe_checkout_session_id];
    const preklic = (t) => zahtevek(A, "POST", "/guest/order/cancel", null, undefined, t === undefined ? {} : { "x-guest-token": t });
    r = await nakup(evCap, "preklic@example.com", { quantity: 3 });
    assert(r.status === 201 && r.body.order.status === "pending", "pending naroilo za preklic", r);
    const zPk = r.body.guest_token, nPk = r.body.order.id, sPk = await seja(nPk);
    assert(await sold(evCap) === 3, "zaloga zasedena (3)");
    r = await preklic(zPk);
    assert(r.status === 200 && r.body.order.status === "cancelled" && r.body.order.id === nPk && !JSON.stringify(r.body).includes("preklic@example.com"), "preklic: 200 { order } status cancelled, brez e-naslova", r);
    assert(await sold(evCap) === 0, "zaloga se sprosti takoj", await sold(evCap));
    assert(sPk.status === "expired", "Stripe seja potecena (expire)", sPk.status);
    r = await preklic(zPk);
    assert(r.status === 404, "ponoven preklic: zeton ne velja vec (404)", r.status);
    r = await brezAvtorizacije(A, "/guest/order", zPk);
    assert(r.status === 404, "GET po preklicu: 404", r.status);
    r = await preklic("x".repeat(43));
    assert(r.status === 404, "napacen zeton -> 404", r.status);
    r = await preklic();
    assert(r.status === 404, "brez zetona -> 404", r.status);
    r = await nakup(evA, "placan-preklic@example.com");
    r = await preklic(r.body.guest_token);
    assert(r.status === 409 && r.body.error === "order_not_pending", "placano (test) naroilo: preklic 409 order_not_pending", r);
    r = await nakup(evCap, "ze-placano@example.com", { quantity: 2 });
    const nZp = r.body.order.id, zZp = r.body.guest_token, sZp = await seja(nZp);
    Object.assign(sZp, placana(sZp, "pi_gost_zp"));
    r = await preklic(zZp);
    assert(r.status === 409 && r.body.error === "order_not_pending", "seja je ze placana (webhook se ni prispel): preklic 409", r);
    assert((await pool.query("SELECT status FROM orders WHERE id=$1", [nZp])).rows[0].status === "pending", "narocilo ostane pending (placilo ni povozeno)");
    w = await webhook("checkout.session.completed", { id: sZp.id, object: "checkout.session" });
    assert((await pool.query("SELECT status FROM orders WHERE id=$1", [nZp])).rows[0].status === "paid", "webhook nato vknjizi placilo");
    r = await nakup(evCap, "brez-seje@example.com");
    const nBs = r.body.order.id, zBs = r.body.guest_token;
    await pool.query("UPDATE orders SET stripe_checkout_session_id = NULL WHERE id=$1", [nBs]);
    r = await preklic(zBs);
    assert(r.status === 409 && r.body.error === "request_in_progress" && r.headers.get("retry-after"), "seja se ustvarja (< 60 s, brez seje): 409 request_in_progress", r);
    await pool.query("UPDATE orders SET created_at = NOW() - INTERVAL '5 minutes' WHERE id=$1", [nBs]);
    r = await preklic(zBs);
    assert(r.status === 200 && r.body.order.status === "cancelled", "brez seje in starejse od 60 s: preklic gre", r);

    // Stripova omejitev branja: preklic seje, ki ni ne odprta ne placana (complete + unpaid), ne sme ob vsakem klicu v Stripe
    r = await nakup(evCap, "complete-unpaid@example.com", { quantity: 1 });
    const nCu = r.body.order.id, zCu = r.body.guest_token, sCu = await seja(nCu);
    sCu.status = "complete"; sCu.payment_status = "unpaid";
    let br0 = S.branj;
    r = await preklic(zCu);
    assert(r.status === 409 && r.body.error === "order_not_pending" && S.branj === br0 + 1, "complete+unpaid: 1. preklic 409 order_not_pending, en Stripov klic", [r.status, S.branj - br0]);
    r = await preklic(zCu);
    assert(r.status === 409 && r.body.error === "request_in_progress" && Number(r.headers.get("retry-after")) >= 1 && S.branj === br0 + 1, "ponovitev znotraj okna: 409 request_in_progress + Retry-After, BREZ Stripa", [r.status, r.body, S.branj - br0]);
    const ponovitve = await Promise.all([1, 2, 3, 4, 5].map(() => preklic(zCu)));
    assert(ponovitve.every(x => x.status === 409 && x.body.error === "request_in_progress") && S.branj === br0 + 1, "5 hitrih ponovitev: vse 409 request_in_progress, noben ne 429, brez Stripa", [ponovitve.map(x => x.status), S.branj - br0]);
    await pocakaj(1700);
    r = await preklic(zCu);
    assert(r.status === 409 && r.body.error === "order_not_pending" && S.branj === br0 + 2, "po izteku okna spet en Stripov klic", [r.status, S.branj - br0]);
    // vzporedni preklic istega narocila: pocasen Stripe (zamik daljsi od okna) -> drugi klic ne gre do Stripa
    r = await nakup(evCap, "vzporeden-preklic@example.com", { quantity: 1 });
    const nVp = r.body.order.id, zVp = r.body.guest_token, sVp = await seja(nVp);
    br0 = S.branj; S.zamikBranja = 2200;
    const prvi = preklic(zVp);
    await pocakaj(1700);   // okno (1500 ms) je ze poteklo, prvi klic pa se vedno caka na Stripe
    const drugi = await preklic(zVp);
    assert(drugi.status === 409 && drugi.body.error === "request_in_progress" && Number(drugi.headers.get("retry-after")) >= 1, "vzporeden preklic istega narocila: 409 request_in_progress (brez Stripa)", [drugi.status, drugi.body]);
    r = await prvi; S.zamikBranja = 0;
    assert(r.status === 200 && r.body.order.status === "cancelled" && sVp.status === "expired" && S.branj === br0 + 1, "prvi preklic uspe, Stripe ni bil poklican dvakrat", [r.status, S.branj - br0]);

    console.log("\n# 10d. Skupna meja cakajocih gostujocih vstopnic na dogodek");
    // evCap2: kapaciteta 30 -> meja max(10, 20 % = 6) = 10 cakajocih vstopnic
    r = await nakup(evCap2, "cap-a@example.com", { quantity: 6 });
    assert(r.status === 201, "6 cakajocih (cap-a)", r.status);
    r = await nakup(evCap2, "cap-b@example.com", { quantity: 4 });
    assert(r.status === 201, "+4 = 10 cakajocih (cap-b): na meji, 201", r.status);
    const zCapB = r.body.guest_token;
    r = await nakup(evCap2, "cap-c@example.com", { quantity: 1 });
    assert(r.status === 409 && r.body === "Too many unfinished payments for this event right now, try again in a few minutes.", "11. cakajoca vstopnica -> 409 z navodilom", r);
    assert(await sold(evCap2) === 10, "zaloga: samo 10 (meja drzi)", await sold(evCap2));
    r = await api("POST", `/events/${evCap2}/orders`, T.ana, { quantity: 1 });
    assert(r.status === 201, "meja velja samo za goste: prijavljen uporabnik se vedno 201", r.status);
    r = await preklic(zCapB);
    assert(r.status === 200, "cap-b prekliče");
    r = await nakup(evCap2, "cap-c@example.com", { quantity: 1 });
    assert(r.status === 201, "po preklicu se sprosti: cap-c 201", r.status);
    const hk2 = await Promise.all([1, 2, 3, 4, 5, 6, 7, 8].map(i => nakup(evCap2, `cap-h${i}@example.com`, { quantity: 2 })));
    assert(await sold(evCap2) <= 10 + 1 + 1 + 6 + 4 && (await pool.query("SELECT COALESCE(SUM(quantity),0)::int AS n FROM orders WHERE event_id=$1 AND guest_email IS NOT NULL AND status='pending'", [evCap2])).rows[0].n <= 10,
      "hkratni nakupi: cakajocih gostujocih vstopnic nikoli > 10", hk2.map(x => x.status));

    console.log("\n# 10e. Mail: meje in obnasanje ob pocasnem Resendu");
    r = await nakup(evA, "dvakrat@example.com");
    assert(await cakaj(() => poslanoNa("dvakrat@example.com").length >= 1), "prvi mail na naslov poslan");
    r = await nakup(evA, "dvakrat@example.com");
    const nDv = r.body.order.id;
    assert(r.status === 201 && r.body.tickets.length === 1, "drugi nakup z istim naslovom v testnem nacinu: 201");
    assert(await cakaj(async () => (await pool.query("SELECT guest_mail_attempts FROM orders WHERE id=$1", [nDv])).rows[0].guest_mail_attempts >= 8), "testni nacin: drugi mail v 24 h izpuscen (poskusi izcrpani)");
    assert(poslanoNa("dvakrat@example.com").length === 1 && /mail na isti naslov je bil ze poslan v 24 h/.test(a.log) && !/dvakrat@example\.com/.test(a.log), "samo 1 mail; zapis v dnevniku brez e-naslova");
    const mailovPrej = R.poslano.length;
    R.zamik = 600; R.najvecSocasnih = 0;
    const osem = await Promise.all([1, 2, 3, 4, 5, 6, 7, 8].map(i => nakup(evA, `socasen${i}@example.com`)));
    assert(osem.every(x => x.status === 201), "8 hkratnih nakupov: vsi 201", osem.map(x => x.status));
    assert(await cakaj(() => R.poslano.length >= mailovPrej + 8, 15000), "vseh 8 mailov poslanih");
    R.zamik = 0;
    assert(R.najvecSocasnih <= 3 && R.najvecSocasnih >= 2, "najvec 3 socasna posiljanja Resendu", R.najvecSocasnih);
    R.zamik = 2500;
    r = await nakup(evA, "pocasen@example.com");
    const nPo2 = r.body.order.id;
    assert(r.status === 201, "pocasen Resend: nakup 201");
    assert(await cakaj(() => /rok za Resend potekel/.test(a.log), 6000), "klic Resenda ima rok: po izteku napaka v dnevniku");
    assert((await pool.query("SELECT guest_mail_sent_at, guest_mail_attempts FROM orders WHERE id=$1", [nPo2])).rows[0].guest_mail_sent_at === null, "po preteku roka poslano NI zapisano");
    R.zamik = 0;
    assert(await cakaj(() => poslanoNa("pocasen@example.com").length >= 1, 8000), "ko je Resend spet hiter, pospravljalec poslje");

    console.log("\n# 10f. Prevzem: trk idempotentnega kljuca (N1), zeton po prevzemu (N4), izbris racuna");
    const ZK = zeton("kolizija@example.com", uuid(23));
    await api("GET", "/me", ZK);
    const uidK = (await pool.query("SELECT id FROM users WHERE email='kolizija@example.com'")).rows[0].id;
    const kKolizija = crypto.randomUUID();
    const vstavi = async (user, email, kljuc) => (await pool.query(
      `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, paid_at, idempotency_key, guest_email, guest_terms_version, guest_terms_accepted_at)
       VALUES ('OUT-K'||floor(random()*1e9)::text, $1, $2, 1, 1, 1500, 1500, 'paid', $3, NOW(), $4, $5, $6, CASE WHEN $5::text IS NULL THEN NULL ELSE NOW() END) RETURNING id`,
      [user, evA, email, kljuc, user ? null : email, user ? null : "x"])).rows[0].id;
    await vstavi(uidK, "kolizija@example.com", kKolizija);
    const gTrk = await vstavi(null, "kolizija@example.com", kKolizija);
    const gOk = await vstavi(null, "kolizija@example.com", null);
    r = await api("GET", "/me", ZK);
    assert(r.status === 200, "GET /me ob trku kljuca: 200 (prevzem ne podre prijave)", r.status);
    const po = (await pool.query("SELECT id, user_id FROM orders WHERE id = ANY($1::bigint[])", [[gTrk, gOk]])).rows;
    assert(po.find(x => x.id === gOk).user_id === uidK && po.find(x => x.id === gTrk).user_id === null, "naroilo brez trka prevzeto, tisto s trkom kljuca preskoceno", po);
    const ZI = zeton("idem@example.com", uuid(22));
    await api("GET", "/me", ZI);
    assert((await pool.query("SELECT user_id FROM orders WHERE id=$1", [idemOrder])).rows[0].user_id !== null, "idem@example.com: narocilo prevzeto");
    r = await nakup(evIdem, "idem@example.com", { quantity: 4 }, { "idempotency-key": K });
    assert(r.status === 201 && r.body.guest_token === null && r.body.tickets.length === 4, "ponovitev kljuca PO prevzemu: 201 s vstopnicami, guest_token null (zetonov ni vec)", [r.status, r.body.guest_token]);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM gost_zetoni WHERE order_id=$1", [idemOrder])).rows[0].n === 0, "po prevzemu se noben zeton ne kuje");
    r = await api("DELETE", "/me", ZG, { password: "x" });
    assert(r.status === 200, "DELETE /me po prevzemu gostujocega narocila: 200", r);
    const izb = (await pool.query("SELECT user_id, guest_email, buyer_email FROM orders WHERE id=$1", [n1])).rows[0];
    assert(izb.user_id === null && izb.guest_email === null && izb.buyer_email === `izbrisan-${n1}@outly.invalid`, "izbris racuna: guest_email NULL, buyer_email anonimiziran, narocilo ostane", izb);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM gost_zetoni WHERE order_id=$1", [n1])).rows[0].n === 0, "ni zetonov");

    // hramba osebnih podatkov
    console.log("\n# 10b. Hramba: anonimizacija e-naslova");
    const mk = async (email, status, dniPo, user = null) => (await pool.query(
      `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, paid_at, cancelled_at, created_at, guest_email, guest_terms_version, guest_terms_accepted_at)
       VALUES ('OUT-H'||floor(random()*1e9)::text, $4, $1, 1, 1, 1500, 1500, $2, $3, CASE WHEN $2 IN ('paid','refunded') THEN NOW() END, CASE WHEN $2 IN ('cancelled','failed') THEN NOW() - $5::int * INTERVAL '1 hour' END,
               NOW() - $5::int * INTERVAL '1 hour', $3, 'x', NOW()) RETURNING id`, [evMail, status, email, user, dniPo])).rows[0].id;
    const hSveza = await mk("sveza-preklic@example.com", "cancelled", 2);
    const hStara = await mk("stara-preklic@example.com", "failed", 30);
    const hPlacana = await mk("placana-vsa@example.com", "paid", 1);
    await pool.query("INSERT INTO gost_zetoni (token_hash, order_id) VALUES ($1, $2)", [crypto.randomBytes(32).toString("hex"), hStara]);
    assert(await cakaj(async () => (await pool.query("SELECT guest_email FROM orders WHERE id=$1", [hStara])).rows[0].guest_email === null, 8000), "preklicano neplacano narocilo (> 24 h): e-naslov anonimiziran");
    let h = (await pool.query("SELECT buyer_email, guest_email, status, total_cents FROM orders WHERE id=$1", [hStara])).rows[0];
    assert(h.buyer_email === `izbrisan-${hStara}@outly.invalid` && h.total_cents === 1500, "buyer_email -> izbrisan-<id>@outly.invalid, znesek ostane", h);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM gost_zetoni WHERE order_id=$1", [hStara])).rows[0].n === 0, "zetoni anonimiziranega narocila izbrisani");
    h = (await pool.query("SELECT guest_email FROM orders WHERE id=$1", [hSveza])).rows[0];
    assert(h.guest_email === "sveza-preklic@example.com", "preklic pred < 24 h: e-naslov se ostane");
    assert((await pool.query("SELECT guest_email FROM orders WHERE id=$1", [hPlacana])).rows[0].guest_email === "placana-vsa@example.com", "placano narocilo, dogodek se ni koncan: e-naslov ostane");
    await pool.query("UPDATE events SET start_at = NOW() - INTERVAL '170 days' WHERE id=$1", [evMail]);
    await pocakaj(2500);
    assert((await pool.query("SELECT guest_email FROM orders WHERE id=$1", [hPlacana])).rows[0].guest_email === "placana-vsa@example.com", "placano, 170 dni po dogodku: e-naslov se ostane (rok 180 dni)");
    const hPrevzeta = await mk("prevzeta-vsa@example.com", "paid", 1, (await pool.query("SELECT id FROM users WHERE email='ana@outly.si'")).rows[0].id);
    await pool.query("UPDATE events SET start_at = NOW() - INTERVAL '200 days' WHERE id=$1", [evMail]);
    assert(await cakaj(async () => (await pool.query("SELECT guest_email FROM orders WHERE id=$1", [hPlacana])).rows[0].guest_email === null, 8000), "placano, 200 dni po dogodku: e-naslov anonimiziran");
    assert((await pool.query("SELECT buyer_email FROM orders WHERE id=$1", [hPlacana])).rows[0].buyer_email === `izbrisan-${hPlacana}@outly.invalid`, "placano: buyer_email -> izbrisan-<id>@outly.invalid");
    h = (await pool.query("SELECT guest_email, buyer_email FROM orders WHERE id=$1", [hPrevzeta])).rows[0];
    assert(h.guest_email === null && h.buyer_email === "prevzeta-vsa@example.com", "prevzeto v racun: pocisti se samo guest_email (buyer_email je e-naslov racuna)", h);

    // ============================================================
    console.log("\n# 11. Obstojeci nakupi prijavljenih");
    const mailPrej = R.poslano.length;
    r = await api("POST", `/events/${evA}/orders`, T.ana, { quantity: 1 });
    assert(r.status === 201 && r.body.mode === "test" && r.body.tickets.length === 1 && !("guest_token" in r.body), "ana (racun): nakup kot doslej, brez guest_token", r.body.mode);
    assert(r.body.order.is_guest === false, "order.is_guest = false pri racunu");
    const nAna = r.body.order.id;
    assert((await pool.query("SELECT guest_email FROM orders WHERE id=$1", [nAna])).rows[0].guest_email === null, "racunsko narocilo nima guest_email");
    r = await api("GET", "/me/orders", T.ana);
    assert(r.status === 200 && r.body.some(x => x.id === nAna && x.tickets.length === 1), "GET /me/orders deluje kot doslej");
    await pocakaj(1200);
    assert(R.poslano.length === mailPrej, "navaden nakup ne poslje maila gostu", [R.poslano.length, mailPrej]);

    // ============================================================
    console.log("\n# 12. Omejitev po IP (instanca B: 3 na uro)");
    b = zagon(PORT_B, { RESEND_API_KEY: "", GOST_NAKUP_NA_URO: "3", STRIPE_SECRET_KEY: "", GOST_POSTA_PONOVI_MS: "0", GOST_NEUSPESNI_NA_URO: "4", GOST_IDEM_ISKANJ_NA_URO: "4" });
    await cakajStreznik(B);
    const nB = (email, dod, g) => nakup(evA, email, dod, g, B);
    const KB = crypto.randomUUID();
    r = await nB("ip1@example.com", {}, { "idempotency-key": KB });
    assert(r.status === 201, "1. nakup z IP: 201", r.status);
    const zetonB = r.body.guest_token;
    r = await nB("   ", {});
    assert(r.status === 400, "neveljaven zahtevek je 400 PRED omejevalnikom", r.status);
    r = await nB("ip2@example.com");
    r = await nB("ip3@example.com");
    assert(r.status === 201, "3. nakup z IP: 201", r.status);
    r = await nB("ip4@example.com");
    assert(r.status === 429 && r.headers.get("retry-after"), "4. nakup z istega IP: 429 + Retry-After", [r.status, r.headers.get("retry-after")]);
    r = await nB("ip1@example.com", {}, { "idempotency-key": KB });
    assert(r.status === 201 && r.headers.get("idempotent-replayed") === "true", "ponovitev kljuca ob presezeni meji: 201 (ne porabi poskusa)", r.status);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE guest_email='ip4@example.com'")).rows[0].n === 0, "zavrnjeni nakup (429) nima narocila");
    r = await brezAvtorizacije(B, "/guest/order", zetonB);
    assert(r.status === 200, "branje gostujocega narocila ni vezano na mejo nakupov");
    // N3: iskanje po Idempotency-Key (pred omejevalnikom nakupov) je omejeno na IP (4/h): doslej 2 iskanja (KB + ponovitev)
    r = await nB("ip1@example.com", {}, { "idempotency-key": KB });
    r = await nB("ip1@example.com", {}, { "idempotency-key": KB });
    assert(r.status === 201, "iskanje po kljucu #4: se 201", r.status);
    r = await nB("ip1@example.com", {}, { "idempotency-key": KB });
    assert(r.status === 429 && r.headers.get("retry-after"), "iskanje po kljucu #5: 429 + Retry-After (omejitev iskanj pred omejevalnikom nakupov)", [r.status, r.headers.get("retry-after")]);
    r = await nB("ip5@example.com");
    assert(r.status === 429, "nakup brez kljuca ob presezeni meji nakupov: se vedno 429");
    // S5: GET /guest/order steje samo NEUSPESNE (404) zahtevke: 4 uspesni niso porabili nicesar
    for (let i = 0; i < 6; i++) { r = await brezAvtorizacije(B, "/guest/order", zetonB); if (r.status !== 200) break; }
    assert(r.status === 200, "uspesni ogledi niso omejeni (6x 200)", r.status);
    for (let i = 0; i < 4; i++) { r = await brezAvtorizacije(B, "/guest/order", "napacen" + i); assert(r.status === 404, `neuspesen ogled ${i + 1}/4: 404`, r.status); }
    r = await brezAvtorizacije(B, "/guest/order", "napacen5");
    assert(r.status === 429 && r.headers.get("retry-after"), "5. neuspesen ogled z IP: 429 + Retry-After (ugibanje zetonov)", [r.status, r.headers.get("retry-after")]);
    r = await zahtevek(B, "POST", "/guest/order/cancel", null, undefined, { "x-guest-token": "napacen6" });
    assert(r.status === 429, "isti stevec velja za preklic");
    r = await brezAvtorizacije(B, "/guest/order", zetonB);
    assert(r.status === 200 && r.body.order.id, "IP nad mejo neuspesnih + VELJAVEN zeton -> 200 (vstopnica na vratih se vedno prikaze)", r.status);
    r = await zahtevek(B, "POST", "/guest/order/cancel", null, undefined, { "x-guest-token": zetonB });
    assert(r.status === 409 && r.body.error === "order_not_pending", "preklic z veljavnim zetonom nad mejo: obdelan (409: narocilo je placano), ne 429", r);
    const zetonPk = crypto.randomBytes(32).toString("base64url");
    const nPk2 = (await pool.query(
      `INSERT INTO orders (public_ref, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, created_at, guest_email, guest_terms_version, guest_terms_accepted_at)
       VALUES ('OUT-PK'||floor(random()*1e9)::text, $1, 1, 1, 1500, 1500, 'pending', 'pk@example.com', NOW() - INTERVAL '5 minutes', 'pk@example.com', 'x', NOW()) RETURNING id`, [evA])).rows[0].id;
    await pool.query("INSERT INTO gost_zetoni (token_hash, order_id) VALUES ($1, $2)", [crypto.createHash("sha256").update(zetonPk).digest("hex"), nPk2]);
    r = await zahtevek(B, "POST", "/guest/order/cancel", null, undefined, { "x-guest-token": zetonPk });
    assert(r.status === 200 && r.body.order.status === "cancelled", "preklic neplacanega narocila z veljavnim zetonom nad mejo neuspesnih: 200", r);
    b.srv.kill(); b = null;

    console.log("\n# 13. Stikalo za pravi denar (GOST_NAKUP_LIVE)");
    const PORT_C = 3193, PORT_E = 3194;
    const okoljeLive = { RESEND_API_KEY: "", STRIPE_SECRET_KEY: "sk_live_x", STRIPE_WEBHOOK_SECRET: WHSEC, GOST_POSTA_PONOVI_MS: "0" };
    let c2 = zagon(PORT_C, okoljeLive);
    await cakajStreznik(`http://127.0.0.1:${PORT_C}`);
    r = await nakup(evA, "live@example.com", {}, {}, `http://127.0.0.1:${PORT_C}`);
    assert(r.status === 503 && r.body === "Guest checkout is not available yet.", "sk_live_ brez GOST_NAKUP_LIVE=1: 503 »Guest checkout is not available yet.«", r);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE guest_email='live@example.com'")).rows[0].n === 0, "naroilo ni nastalo");
    c2.srv.kill();
    c2 = zagon(PORT_E, { ...okoljeLive, GOST_NAKUP_LIVE: "1" });
    await cakajStreznik(`http://127.0.0.1:${PORT_E}`);
    r = await nakup(evA, "live@example.com", {}, {}, `http://127.0.0.1:${PORT_E}`);
    assert(r.status === 409 && /does not accept online payments/.test(r.body), "z GOST_NAKUP_LIVE=1 gre naprej (klub brez Stripa: obstojece pravilo 409)", r);
    c2.srv.kill();
    assert(true, "sandbox/testni nacin deluje brez stikala (instanca A, sekcije 1-12)");

    console.log("\n# 14. Globalna dnevna meja mailov (GOST_POSTA_DNEVNO)");
    a.srv.kill(); await pocakaj(500);
    await pool.query("UPDATE orders SET guest_mail_sent_at = NOW() - INTERVAL '2 days' WHERE guest_mail_sent_at IS NOT NULL");
    await pool.query("UPDATE orders SET guest_mail_attempts = 8 WHERE guest_email IS NOT NULL AND guest_mail_sent_at IS NULL");
    const PORT_D = 3195, D = `http://127.0.0.1:${PORT_D}`;
    const d = zagon(PORT_D, { RESEND_API_KEY: "re_test", RESEND_BASE_URL: `http://127.0.0.1:${RESEND_PORT}`, GOST_POSTA_DNEVNO: "2", GOST_POSTA_PONOVI_MS: "300", GOST_POSTA_PREMOR_MS: "200" });
    await cakajStreznik(D);
    const prejD = R.poslano.length;
    for (const i of [1, 2]) {
      r = await nakup(evA, `dnevno${i}@example.com`, {}, {}, D);
      assert(r.status === 201 && await cakaj(() => poslanoNa(`dnevno${i}@example.com`).length === 1), `dnevno${i}: mail poslan (meja 2)`);
    }
    r = await nakup(evA, "dnevno3@example.com", {}, {}, D);
    const n3 = r.body.order.id;
    assert(r.status === 201 && r.body.tickets.length === 1, "3. nakup: 201 z vstopnico");
    assert(await cakaj(async () => (await pool.query("SELECT guest_mail_attempts FROM orders WHERE id=$1", [n3])).rows[0].guest_mail_attempts >= 8), "preko dnevne meje: testni mail izpuscen (poskusi izcrpani)");
    assert(poslanoNa("dnevno3@example.com").length === 0 && R.poslano.length === prejD + 2 && /dnevna meja gostujocih mailov/.test(d.log) && !/dnevno3@example\.com/.test(d.log), "mail se ne poslje, zapis v dnevniku brez e-naslova", R.poslano.length - prejD);
    const nOdl = await vstavi(null, "placan-nad-mejo@example.com", null);   // placano (ne testno), meja (2) je ze presezena: potrdilo vseeno gre
    assert(await cakaj(() => poslanoNa("placan-nad-mejo@example.com").length === 1), "resnicno placano narocilo NAD dnevno mejo: potrdilo je poslano");
    await cakaj(async () => (await pool.query("SELECT guest_mail_sent_at FROM orders WHERE id=$1", [nOdl])).rows[0].guest_mail_sent_at !== null);   // zapis »poslano« sledi odgovoru Resenda
    const odl = (await pool.query("SELECT guest_mail_attempts, guest_mail_sent_at FROM orders WHERE id=$1", [nOdl])).rows[0];
    assert(odl.guest_mail_sent_at !== null && odl.guest_mail_attempts === 1, "poslano v 1. poskusu, ni odloženo", odl);
    assert(/opozorilo: ze \d+ gostujocih mailov v 24 h/.test(d.log) && !/placan-nad-mejo@example\.com/.test(d.log), "ob preseznem stevilu samo opozorilo v dnevniku, brez e-naslova");
    const nOdl2 = await vstavi(null, "dnevno1@example.com", null);   // placano, isti naslov kot testni nakup v 24 h: tudi 1/naslov/24 h velja samo za testna
    assert(await cakaj(() => poslanoNa("dnevno1@example.com").length === 2), "placano narocilo na naslov, ki je v 24 h ze dobil mail: potrdilo poslano");
    d.srv.kill();

    console.log("\n# 15. Pospravljalec: naroila v premoru ne stradajo novejsih");
    await pool.query("UPDATE orders SET guest_mail_attempts = 8 WHERE guest_email IS NOT NULL AND guest_mail_sent_at IS NULL");
    await pool.query("UPDATE events SET capacity = 500 WHERE id = $1", [evA]);   // vstavi() zasede zalogo; evA je do zdaj skoraj polen
    const premor = [];
    for (let i = 1; i <= 25; i++) premor.push(await vstavi(null, `premor${i}@example.com`, null));
    // 25 starejsih placanih narocil: 1. poskus je ze bil pred trenutkom, naslednji je zaradi premora (10 min) mogoc sele pozneje
    await pool.query("UPDATE orders SET guest_mail_attempts = 1, guest_mail_claimed_at = NOW() WHERE id = ANY($1::bigint[])", [premor]);
    const novo = await vstavi(null, "premor-novo@example.com", null);   // vecji id, prvi poskus
    const PORT_F = 3196;
    const f = zagon(PORT_F, { RESEND_API_KEY: "re_test", RESEND_BASE_URL: `http://127.0.0.1:${RESEND_PORT}`, GOST_POSTA_PONOVI_MS: "300", GOST_POSTA_PREMOR_MS: "600000" });
    await cakajStreznik(`http://127.0.0.1:${PORT_F}`);
    assert(await cakaj(() => poslanoNa("premor-novo@example.com").length === 1, 6000), "novejse narocilo dobi mail, ceprav je pred njim 25 starejsih v premoru (LIMIT 20)");
    await pocakaj(900);
    assert(R.poslano.filter(m => /^premor\d+@/.test(String(m.to))).length === 0, "narocila v premoru niso bila poslana pred iztekom premora");
    f.srv.kill();

    // ============================================================
    // #201: pospravljalec ne sme prevzeti narocila, ki ga isti ali drug proces SE poslje (priprava maila + Resend trajata dlje od premora).
    console.log("\n# 16. Mail gostu natanko enkrat tudi ob pocasnem posiljanju (#201)");
    await pool.query("UPDATE orders SET guest_mail_attempts = 8 WHERE guest_email IS NOT NULL AND guest_mail_sent_at IS NULL");
    const PORT_G = 3197, G = `http://127.0.0.1:${PORT_G}`;
    // premor 200 ms, rok Resenda 3 s, rezerva 100 ms; pospravljalec vsakih 100 ms
    const okoljeG = { RESEND_API_KEY: "re_test", RESEND_BASE_URL: `http://127.0.0.1:${RESEND_PORT}`, GOST_POSTA_PONOVI_MS: "100", GOST_POSTA_PREMOR_MS: "200",
      GOST_POSTA_TIMEOUT_MS: "3000", GOST_POSTA_REZERVA_MS: "100", GOST_NAKUP_NA_URO: "1000" };
    const gp = zagon(PORT_G, okoljeG);
    await cakajStreznik(G);
    // (a) en proces: Resend odgovori po 900 ms (> premor 200 ms, < rok 3 s), pospravljalec tece vsakih 100 ms
    R.zamik = 900;
    r = await nakup(evA, "pocasno-enkrat@example.com", {}, {}, G);
    assert(r.status === 201, "16a: nakup 201", r.body);
    assert(await cakaj(() => poslanoNa("pocasno-enkrat@example.com").length >= 1, 8000), "16a: mail poslan");
    await pocakaj(2500);   // pospravljalec bi v tem casu po premoru prevzel isto narocilo
    R.zamik = 0;
    assert(poslanoNa("pocasno-enkrat@example.com").length === 1, "16a: pocasen Resend (900 ms > premor 200 ms): mail natanko enkrat", poslanoNa("pocasno-enkrat@example.com").length);
    const aG = (await pool.query("SELECT guest_mail_attempts AS n, guest_mail_sent_at FROM orders WHERE id=$1", [r.body.order.id])).rows[0];
    assert(aG.n === 1 && aG.guest_mail_sent_at !== null, "16a: v bazi en poskus, poslano", aG);
    gp.srv.kill(); await pocakaj(500);
    // (b) drug proces: prevzem je v bazi (guest_mail_claimed_at) in ga lokalna mnozica ne vidi. Premor za ponovni prevzem je vsaj rok Resenda + rezerva
    // (3 s + 1 s), ne samo 200 ms. Prevzem v drugem procesu simuliramo z vrstico v bazi, pospravljalec tece v svežem procesu.
    const nDrug = await vstavi(null, "drug-proces@example.com", null);
    await pool.query("UPDATE orders SET guest_mail_attempts = 1, guest_mail_claimed_at = NOW() WHERE id = $1", [nDrug]);
    const t0drug = Date.now();
    const hp = zagon(3198, { ...okoljeG, GOST_POSTA_REZERVA_MS: "1000" });
    await cakajStreznik("http://127.0.0.1:3198");
    await pocakaj(Math.max(0, 1800 - (Date.now() - t0drug)));
    assert(poslanoNa("drug-proces@example.com").length === 0 && (await pool.query("SELECT guest_mail_attempts AS n FROM orders WHERE id=$1", [nDrug])).rows[0].n === 1,
      "16b: 1,8 s po prevzemu v drugem procesu pospravljalec narocila se ne prevzame (premor >= rok Resenda + rezerva)", poslanoNa("drug-proces@example.com").length);
    assert(await cakaj(() => poslanoNa("drug-proces@example.com").length >= 1, 10000), "16b: po izteku spodnje meje premora pospravljalec vseeno poslje (ponovni poskus deluje)");
    await pocakaj(1000);
    assert(poslanoNa("drug-proces@example.com").length === 1, "16b: mail natanko enkrat", poslanoNa("drug-proces@example.com").length);
    hp.srv.kill();
  } catch (e) {
    fail++; console.error("NAPAKA TESTA:", e);
  } finally {
    try { a.srv.kill(); } catch (e) {} if (b) b.srv.kill(); jwksServer.close(); stripeServer.close(); resendServer.close(); await pool.end();
    if (fail) console.log("\n--- dnevnik streznika ---\n" + a.log.split("\n").slice(-40).join("\n"));
    console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
    process.exit(fail ? 1 : 0);
  }
})();
