#!/usr/bin/env node
/**
 * Potrdilo o nakupu po e-posti kupcu Z RACUNOM (issue #95, migracija 042, invarianta I31). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_potrdilo_kupcu.js
 * Vzorec kot test_gost.js: lokalni JWKS, lazni Stripe (STRIPE_API_BASE), lazni Resend (RESEND_BASE_URL), backend na svojem portu.
 *
 *   1  testni nacin: nakup z racunom -> natanko en mail na e-naslov racuna, vsebina (prodajalec, dogodek, datum, stevilo, cena, DDV, st. narocila, povezava,
 *      odstopna pravica, pogoji), HTML ucinkovito ubezen, brez priloge/QR/sledilnika; ponovitev kljuca ne poslje drugega
 *   2  VIP miza (paket): vsebina mize, starostna meja paketa
 *   3  0 EUR pri klubu s Stripom: potrdilo »free«, Stripe ni klican
 *   4  Stripe: mail sele po placilu (webhook), hkratni podvojeni webhooki -> natanko en mail; placana potrdila se ne omejijo
 *   5  placano tik pred rokom (GET /me/orders preveri sejo) -> mail enkrat
 *   6  brez potrdila: guest lista, gostujoce narocilo (ima svoj mail, tudi po prevzemu v racun), stara narocila (receipt_mail_attempts NULL)
 *   7  napaka Resenda ne podre nakupa ali webhooka; pospravljalec poslje enkrat; izbrisan racun se ne poslje; meja brez placila
 *   8  natanko enkrat tudi ob pocasnem Resendu in pospravljalcu, ki tece med posiljanjem (druga instanca z daljsim rokom)
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");
const Stripe = require("stripe");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT_A = 3221, PORT_B = 3222, JWKS_PORT = 3987, STRIPE_PORT = 3988, RESEND_PORT = 3989;
const BA = `http://127.0.0.1:${PORT_A}`, BB = `http://127.0.0.1:${PORT_B}`;
const WHSEC = "whsec_test_potrdilo";
const stripeLokalno = new Stripe("sk_test_lokalno");

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-potrdilo";
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
const kljuc = () => crypto.randomUUID();
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
async function zahtevek(baza, method, path, token, body, glave = {}) {
  const r = await fetch(baza + path, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}), ...glave },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, text: t, headers: r.headers };
}
const pocakaj = (ms) => new Promise(r => setTimeout(r, ms));
async function cakaj(pogoj, ms = 8000) { const do_ = Date.now() + ms; while (Date.now() < do_) { if (await pogoj()) return true; await pocakaj(100); } return false; }

// ---------- lazni Resend ----------
const R = { poslano: [], napaka: false, zamik: 0 };
const resendServer = http.createServer((req, res) => {
  let d = ""; req.on("data", x => d += x);
  req.on("end", () => {
    if (req.method === "POST" && req.url === "/emails") {
      if (R.napaka) { res.writeHead(422, { "content-type": "application/json" }); return res.end(JSON.stringify({ name: "validation_error", message: "stub: zavrnjeno", statusCode: 422 })); }
      const m = JSON.parse(d);
      const koncaj = () => { R.poslano.push(m); res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ id: "mail_" + R.poslano.length })); };
      return R.zamik ? setTimeout(koncaj, R.zamik) : koncaj();
    }
    res.writeHead(404, { "content-type": "application/json" }); res.end("{}");
  });
});
const mailiNa = (email) => R.poslano.filter(m => m.to === email || (Array.isArray(m.to) && m.to.includes(email)));

// ---------- lazni Stripe ----------
const S = { seje: {}, stSej: 0, zahtevki: 0 };
const stripeServer = http.createServer((req, res) => {
  let d = ""; req.on("data", x => d += x);
  req.on("end", () => {
    const p = Object.fromEntries(new URLSearchParams(d));
    const odg = (st, o) => { res.writeHead(st, { "content-type": "application/json", "request-id": "req_test" }); res.end(JSON.stringify(o)); };
    const u = req.url.split("?")[0];
    let m;
    if (req.method === "POST" && u === "/v1/checkout/sessions") {
      S.zahtevki++;
      const kol = Number(p["line_items[0][quantity]"]), cena = Number(p["line_items[0][price_data][unit_amount]"]);
      if (kol * cena < 50) return odg(400, { error: { type: "invalid_request_error", message: "amount too small" } });
      const id = "cs_test_" + (++S.stSej);
      S.seje[id] = { id, object: "checkout.session", url: `https://checkout.stripe.test/c/pay/${id}`, status: "open", payment_status: "unpaid",
        amount_total: kol * cena, currency: p["line_items[0][price_data][currency]"], client_reference_id: p.client_reference_id,
        metadata: { order_id: p["metadata[order_id]"], public_ref: p["metadata[public_ref]"] }, expires_at: Number(p.expires_at), payment_intent: null };
      return odg(200, S.seje[id]);
    }
    if (req.method === "GET" && (m = u.match(/^\/v1\/checkout\/sessions\/(cs_\w+)$/))) return S.seje[m[1]] ? odg(200, S.seje[m[1]]) : odg(404, { error: { type: "invalid_request_error", message: "No such session" } });
    if (req.method === "POST" && (m = u.match(/^\/v1\/checkout\/sessions\/(cs_\w+)\/expire$/))) { S.seje[m[1]].status = "expired"; return odg(200, S.seje[m[1]]); }
    return odg(404, { error: { type: "invalid_request_error", message: "Lazni Stripe: neznana pot " + req.method + " " + u } });
  });
});
let stDogodka = 0;
async function webhook(baza, tip, objekt, id) {
  const d = { id: id || `evt_potr_${++stDogodka}`, object: "event", type: tip, data: { object: objekt }, created: Math.floor(Date.now() / 1000) };
  const payload = JSON.stringify(d);
  const glava = stripeLokalno.webhooks.generateTestHeaderString({ payload, secret: WHSEC });
  const r = await fetch(baza + "/stripe/webhook", { method: "POST", headers: { "content-type": "application/json", "stripe-signature": glava }, body: payload });
  return { status: r.status };
}
const placana = (s, pi) => ({ ...s, status: "complete", payment_status: "paid", payment_intent: pi });

function zagon(port, okolje) {
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, QR_SECRET: "test", APP_URL: "https://outly.test",
    STRIPE_API_BASE: `http://127.0.0.1:${STRIPE_PORT}`, STRIPE_SECRET_KEY: "sk_test_lokalno", STRIPE_WEBHOOK_SECRET: WHSEC, STRIPE_POSPRAVI_MS: "3600000", PREVERI_OKNO_MS: "0",
    TEST_PLACILA: "", GOST_PREVZEM_MS: "0", RESEND_API_KEY: "re_test", RESEND_BASE_URL: `http://127.0.0.1:${RESEND_PORT}`, EMAIL_FROM: "Outly <test@outly.test>",
    ...okolje }, stdio: ["ignore", "pipe", "pipe"] });
  const s = { srv, log: "" };
  srv.stdout.on("data", d => s.log += d); srv.stderr.on("data", d => s.log += d);
  return s;
}
async function cakajStreznik(baza) { for (let i = 0; i < 80; i++) { try { await fetch(baza + "/"); return; } catch { await pocakaj(100); } } }

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, stripe_events, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  await new Promise(r => stripeServer.listen(STRIPE_PORT, r));
  await new Promise(r => resendServer.listen(RESEND_PORT, r));
  // A: hitri ponovni poskusi (rok Resenda 400 ms, brez rezerve, premor 100 ms ali spodnja meja 400 ms), pospravljalec na 200 ms
  const A = zagon(PORT_A, { GOST_POSTA_PONOVI_MS: "200", GOST_POSTA_TIMEOUT_MS: "400", GOST_POSTA_REZERVA_MS: "0", GOST_POSTA_PREMOR_MS: "100", POTRDILO_BREZ_PLACILA_NA_DAN: "3" });
  // B: rok Resenda 5 s (spodnja meja premora 5 s) in pospravljalec na 200 ms: pocasen Resend (1,5 s) se mora koncati z enim mailom
  const B = zagon(PORT_B, { GOST_POSTA_PONOVI_MS: "200", GOST_POSTA_TIMEOUT_MS: "5000", GOST_POSTA_REZERVA_MS: "0", GOST_POSTA_PREMOR_MS: "100" });
  const api = (m, p, t, b, g) => zahtevek(BA, m, p, t, b, g);
  const apiB = (m, p, t, b, g) => zahtevek(BB, m, p, t, b, g);
  await cakajStreznik(BA); await cakajStreznik(BB);

  try {
    const imena = ["lastnik", "lastnik2", "admin", "ana", "bor", "cene", "dana", "eva", "fran", "gina", "hana", "ivan", "jan", "kim", "lara", "mia"];
    const T = {}; const U = {};
    imena.forEach((k, i) => { T[k] = zeton(`${k}@outly.si`, uuid(i + 1)); });
    for (const k of imena) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); U[k] = r.body.id; }
    await pool.query("UPDATE users SET role='business' WHERE email IN ('lastnik@outly.si','lastnik2@outly.si')");
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city, address, contact_phone, contact_email) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Stripe Club', 'Ljubljana', 'Slovenska 1', '+38640111222', 'info@stripe-club.si')");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city, address, contact_phone, contact_email) VALUES ((SELECT id FROM users WHERE email='lastnik2@outly.si'), 'Plain Club', 'Maribor', 'Glavni trg 5', '+38641333444', 'hello@plain-club.si')");
    await pool.query("UPDATE clubs SET stripe_account_id='acct_test1', stripe_charges_enabled=TRUE, stripe_payouts_enabled=TRUE WHERE id=1");
    const rojstvo = new Date(Date.now() - 25 * 365.25 * 24 * 3600 * 1000).toISOString().slice(0, 10);
    for (const k of imena) await api("PATCH", "/me", T[k], { dateOfBirth: rojstvo });
    const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    const dogodek = async (token, klub, title, cena, extra = {}) => {
      const r = await api("POST", "/events", token, { clubId: klub, title, startAt: cezDan, ticketPriceCents: cena, capacity: 50, minAge: 0, ...extra });
      assert(r.status === 201, `dogodek ${title}`, r.body); return r.body.id;
    };
    const evTest = await dogodek(T.lastnik2, 2, "Noc & <b>Test</b>", 1500);
    await pool.query("UPDATE events SET vat_rate = 0.22 WHERE id=$1", [evTest]);
    const evVip = await dogodek(T.lastnik2, 2, "VIP noc", 1500);
    const evFree = await dogodek(T.lastnik, 1, "Brezplacna noc", 0);
    const evPaid = []; for (let i = 1; i <= 6; i++) evPaid.push(await dogodek(T.lastnik, 1, `Placana ${i}`, 2000));
    const evLista = await dogodek(T.lastnik2, 2, "Lista", 1000);
    const vrstica = async (id) => (await pool.query("SELECT * FROM orders WHERE id=$1", [id])).rows[0];
    const nakup = (token, ev, q = 1, k = null, baza = BA) => zahtevek(baza, "POST", `/events/${ev}/orders`, token, { quantity: q }, k ? { "idempotency-key": k } : {});
    const sejaOd = async (id) => (await vrstica(id)).stripe_checkout_session_id;
    const placajStripe = async (token, ev, pi) => {
      const r = await nakup(token, ev);
      const id = r.body.order.id, sid = await sejaOd(id);
      S.seje[sid] = placana(S.seje[sid], pi);
      const w = await webhook(BA, "checkout.session.completed", S.seje[sid]);
      return { id, status: w.status };
    };

    // ================================================================
    console.log("\n# 1. Testni nacin: potrdilo kupcu z racunom");
    const K1 = kljuc();
    let r = await nakup(T.ana, evTest, 2, K1);
    assert(r.status === 201 && r.body.mode === "test" && r.body.tickets.length === 2, "nakup 2 vstopnic v testnem nacinu", r.body);
    const o1 = r.body.order.id;
    assert(await cakaj(() => mailiNa("ana@outly.si").length >= 1), "mail prispe");
    await pocakaj(1200);
    let m = mailiNa("ana@outly.si");
    assert(m.length === 1, "natanko en mail (pospravljalec ga ne podvoji)", m.length);
    const besedilo = m[0] ? m[0].text : "", html = m[0] ? m[0].html : "";
    assert(m[0] && m[0].subject.includes("Noc & <b>Test</b>") && m[0].subject.includes(r.body.order.public_ref), "zadeva: dogodek + stevilka narocila", m[0] && m[0].subject);
    assert(m[0] && m[0].reply_to === "luka@outly.si", "reply_to luka@outly.si");
    assert(besedilo.includes(`Order ${r.body.order.public_ref}`), "besedilo: stevilka narocila");
    assert(besedilo.includes("Noc & <b>Test</b>") && /\(Ljubljana time\)/.test(besedilo), "besedilo: dogodek in datum (Ljubljana)");
    assert(besedilo.includes("2 x 15.00 EUR = 30.00 EUR"), "besedilo: stevilo vstopnic in cena", besedilo);
    assert(besedilo.includes("The price includes VAT (22%)."), "besedilo: stopnja DDV iz narocila");
    assert(besedilo.includes("Plain Club") && besedilo.includes("Glavni trg 5, Maribor") && besedilo.includes("+38641333444") && besedilo.includes("hello@plain-club.si"), "besedilo: prodajalec (klub: ime, naslov, kontakt)");
    assert(besedilo.includes("NEXT DIMENSIONS") && /intermediary/.test(besedilo), "besedilo: Outly kot posrednik");
    assert(besedilo.includes("Article 135, point 12") && /no right of withdrawal/i.test(besedilo), "besedilo: odstopna pravica (ZVPot-1 135/12)");
    assert(besedilo.includes("https://outly.test/app/tickets") && besedilo.includes("https://outly.si/terms"), "besedilo: povezava na vstopnice v aplikaciji in pogoje");
    assert(/test purchase: nothing was charged/.test(besedilo), "besedilo: testno narocilo je oznaceno");
    assert(!/guest\/order/.test(besedilo + html), "brez gostovega zetona/povezave");
    assert(!m[0].attachments && !/cid:|<img/i.test(html), "brez priloge, QR slike in sledilnika");
    assert(html.includes("Noc &amp; &lt;b&gt;Test&lt;/b&gt;") && !html.includes("<b>Test</b>"), "HTML: ime dogodka ubezeno");
    assert(html.includes('<a href="https://outly.test/app/tickets">'), "HTML: povezava je klikljiva");
    let v = await vrstica(o1);
    assert(v.receipt_mail_attempts === 1 && v.receipt_mail_sent_at && v.receipt_mail_claimed_at, "baza: 1 poskus, poslano", [v.receipt_mail_attempts, v.receipt_mail_sent_at]);
    r = await nakup(T.ana, evTest, 2, K1);
    assert(r.status === 201 && r.headers.get("idempotent-replayed") === "true" && r.body.order.id === o1, "ponovitev kljuca: isto narocilo");
    await pocakaj(800);
    assert(mailiNa("ana@outly.si").length === 1, "ponovitev kljuca ne poslje drugega maila");
    assert(!/\[potrdilo\] POZOR|Resend napaka/.test(A.log), "brez napak v dnevniku", A.log.slice(-300));

    // ================================================================
    console.log("\n# 2. VIP miza");
    const miza = (await pool.query("INSERT INTO club_tables (club_id, label, x, y, w, h, seats, price_cents) VALUES (2,'T1',0,0,2,2,3,30000) RETURNING id")).rows[0].id;
    const paket = (await pool.query("INSERT INTO bottle_packages (club_id, name) VALUES (2,'Magnum') RETURNING id")).rows[0].id;
    await pool.query("UPDATE events SET vip_enabled = TRUE WHERE id=$1", [evVip]);
    r = await zahtevek(BA, "POST", `/events/${evVip}/tables/${miza}/orders`, T.bor, { package_id: paket });
    assert(r.status === 201 && r.body.tickets.length === 3, "nakup mize s paketom", r.body);
    assert(await cakaj(() => mailiNa("bor@outly.si").length >= 1), "mail prispe");
    await pocakaj(600);
    m = mailiNa("bor@outly.si");
    assert(m.length === 1 && m[0].text.includes("VIP table T1 (3 seats), package: Magnum: 300.00 EUR."), "VIP: miza, sedezi, paket, cena", m[0] && m[0].text);
    assert(m[0].text.includes("Age limit: 18+ (table with a drinks package)"), "VIP: starost za paket pijace 18+");
    assert(m[0].text.includes("TABLE") && !/\d x \d/.test(m[0].text.split("TABLE")[1].split("\n")[1] || ""), "VIP: razdelek Table brez stevila vstopnic");

    // ================================================================
    console.log("\n# 3. 0 EUR pri klubu s Stripom");
    const st0 = S.zahtevki;
    r = await nakup(T.cene, evFree, 1);
    assert(r.status === 201 && r.body.order.status === "paid" && r.body.order.total_cents === 0, "brezplacna vstopnica paid", r.body);
    assert(await cakaj(() => mailiNa("cene@outly.si").length >= 1), "mail prispe");
    m = mailiNa("cene@outly.si");
    assert(m.length === 1 && /free: nothing was charged/.test(m[0].text) && m[0].text.includes("1 x 0.00 EUR = 0.00 EUR"), "potrdilo za brezplacno narocilo", m[0] && m[0].text.slice(0, 200));
    assert(!/test purchase/.test(m[0].text) && S.zahtevki === st0, "ni testno narocilo, Stripe ni klican");

    // ================================================================
    console.log("\n# 4. Stripe: mail sele po placilu, natanko enkrat");
    r = await nakup(T.dana, evPaid[0]);
    assert(r.status === 201 && r.body.mode === "stripe" && r.body.checkout_url, "nakup: pending s Checkoutom", r.body.mode);
    const o4 = r.body.order.id, s4 = await sejaOd(o4);
    await pocakaj(1000);
    v = await vrstica(o4);
    assert(mailiNa("dana@outly.si").length === 0 && v.receipt_mail_attempts === null, "pred placilom ni maila in potrdilo ni dolgovano", [v.receipt_mail_attempts]);
    S.seje[s4] = placana(S.seje[s4], "pi_potr_4");
    const w = await Promise.all([
      webhook(BA, "checkout.session.completed", S.seje[s4], "evt_isti_1"), webhook(BA, "checkout.session.completed", S.seje[s4], "evt_isti_1"),
      webhook(BA, "checkout.session.completed", S.seje[s4]), webhook(BA, "checkout.session.async_payment_succeeded", S.seje[s4]),
      webhook(BA, "checkout.session.completed", S.seje[s4]),
    ]);
    assert(w.every(x => x.status === 200), "5 hkratnih webhookov (podvojen ID, druga ID-ja, async) vsi 200", w.map(x => x.status));
    assert(await cakaj(() => mailiNa("dana@outly.si").length >= 1), "mail prispe po placilu");
    await pocakaj(1500);
    m = mailiNa("dana@outly.si");
    assert(m.length === 1, "natanko en mail kljub podvojenim webhookom in pospravljalcu", m.length);
    assert(!/test purchase|free: nothing/.test(m[0].text) && m[0].text.includes("1 x 20.00 EUR = 20.00 EUR") && m[0].text.includes("Stripe Club") && m[0].text.includes("Slovenska 1, Ljubljana"), "vsebina placanega narocila", m[0].text.slice(0, 300));
    v = await vrstica(o4);
    assert(v.status === "paid" && v.receipt_mail_attempts === 1 && v.receipt_mail_sent_at, "baza: paid, 1 poskus, poslano", v);
    // Placana potrdila se ne omejijo (meja 3 velja samo za narocila brez placila): eva placa 4 narocila
    let n = 0;
    for (let i = 1; i <= 4; i++) { const p = await placajStripe(T.eva, evPaid[i % 5 + 1], `pi_potr_eva_${i}`); if (p.status === 200) n++; await cakaj(() => mailiNa("eva@outly.si").length >= i, 4000); }
    assert(n === 4 && mailiNa("eva@outly.si").length === 4, "4 placana narocila istega uporabnika: 4 potrdila (meja brez placila jih ne zadene)", [n, mailiNa("eva@outly.si").length]);

    // ================================================================
    console.log("\n# 5. Placano tik pred rokom (brez webhooka)");
    r = await nakup(T.fran, evPaid[5]);
    const o5 = r.body.order.id, s5 = await sejaOd(o5);
    await pool.query("UPDATE orders SET checkout_expires_at = NOW() - INTERVAL '1 minute' WHERE id=$1", [o5]);
    S.seje[s5] = placana(S.seje[s5], "pi_potr_5");
    r = await api("GET", "/me/orders", T.fran);
    assert(r.body.find(x => x.id === o5).status === "paid", "GET /me/orders vknjizi placilo");
    assert(await cakaj(() => mailiNa("fran@outly.si").length >= 1), "mail prispe");
    await pocakaj(1000);
    assert(mailiNa("fran@outly.si").length === 1, "natanko en mail");

    // ================================================================
    console.log("\n# 6. Brez potrdila: guest lista, gost, stara narocila");
    r = await api("POST", "/admin/api/guest-lists", T.admin, { event_id: evLista, user_id: U.gina, spots: 2 });
    assert(r.status === 201 || r.status === 200, "admin ustvari guest listo", r.body);
    const ol = (await pool.query("SELECT id, receipt_mail_attempts FROM orders WHERE guest_list_id IS NOT NULL")).rows;
    await pocakaj(1500);
    assert(ol.length === 1 && ol[0].receipt_mail_attempts === null && mailiNa("gina@outly.si").length === 0, "guest lista: narocilo brez potrdila, gostitelj ne dobi maila", [ol, mailiNa("gina@outly.si").length]);
    // gost (brez racuna) s tem e-naslovom: svoj mail z vstopnico; po prevzemu v racun ni potrdila
    r = await zahtevek(BA, "POST", `/guest/events/${evTest}/orders`, null, { email: "hana@outly.si", quantity: 1, accept_terms: true, terms_version: "2026-10-01" });
    assert(r.status === 201 && r.body.order.status === "paid", "gost: nakup v testnem nacinu", r.body);
    const og = r.body.order.id;
    assert(await cakaj(() => mailiNa("hana@outly.si").length >= 1), "gost dobi svoj mail");
    assert(/guest\/order#t=/.test(mailiNa("hana@outly.si")[0].html) && mailiNa("hana@outly.si")[0].attachments, "gostov mail ima zeton in prilogo (vstopnice), ni potrdilo kupca");
    assert((await vrstica(og)).receipt_mail_attempts === null, "gostujoce narocilo: potrdilo ni dolgovano");
    r = await api("GET", "/me", T.hana);
    await api("GET", "/me/orders", T.hana);
    assert((await vrstica(og)).user_id === U.hana, "narocilo prevzeto v racun");
    await pocakaj(1500);
    assert(mailiNa("hana@outly.si").length === 1 && (await vrstica(og)).receipt_mail_attempts === null, "po prevzemu v racun ni drugega maila");
    // stara narocila (pred migracijo): receipt_mail_attempts NULL -> nikoli
    await pool.query("UPDATE orders SET receipt_mail_attempts = NULL, receipt_mail_sent_at = NULL, receipt_mail_claimed_at = NULL WHERE id=$1", [o1]);
    await pocakaj(1500);
    assert(mailiNa("ana@outly.si").length === 1, "narocilo brez receipt_mail_attempts (staro) ne dobi potrdila");

    // ================================================================
    console.log("\n# 7. Napake: Resend, izbrisan racun, meja brez placila");
    await pool.query("TRUNCATE omejitve");   // omejevalnik nakupov (20/h/IP)
    R.napaka = true;
    r = await nakup(T.ivan, evTest);
    assert(r.status === 201 && r.body.order.status === "paid" && r.body.tickets.length === 1, "Resend zavrne: nakup vseeno 201", r.body);
    const o7 = r.body.order.id;
    await pocakaj(1000);
    v = await vrstica(o7);
    assert(v.receipt_mail_sent_at === null && v.receipt_mail_attempts >= 1 && mailiNa("ivan@outly.si").length === 0, "baza: poskusi porabljeni, ni poslano", [v.receipt_mail_attempts]);
    assert(/Resend napaka \(potrdilo kupcu/.test(A.log) && !/ivan@outly\.si/.test(A.log), "napaka v dnevniku brez e-naslova");
    R.napaka = false;
    assert(await cakaj(() => mailiNa("ivan@outly.si").length >= 1, 10000), "pospravljalec poslje, ko Resend spet dela");
    await pocakaj(1500);
    v = await vrstica(o7);
    assert(mailiNa("ivan@outly.si").length === 1 && v.receipt_mail_sent_at && v.receipt_mail_attempts >= 2, "natanko en mail, poslano", [mailiNa("ivan@outly.si").length, v.receipt_mail_attempts]);
    // Stripe webhook ob napaki Resenda: 200, narocilo paid, mail pozneje
    R.napaka = true;
    r = await nakup(T.mia, evPaid[0]);
    const o7b = r.body.order.id, s7b = await sejaOd(o7b);
    S.seje[s7b] = placana(S.seje[s7b], "pi_potr_7b");
    const w7 = await webhook(BA, "checkout.session.completed", S.seje[s7b]);
    v = await vrstica(o7b);
    assert(w7.status === 200 && v.status === "paid", "webhook ob napaki Resenda: 200 in paid (Stripe ne ponavlja)", [w7.status, v.status]);
    R.napaka = false;
    assert(await cakaj(() => mailiNa("mia@outly.si").length >= 1, 10000), "potrdilo pride, ko Resend spet dela");
    await pocakaj(1200);
    assert(mailiNa("mia@outly.si").length === 1, "natanko enkrat");
    // izbrisan racun
    R.napaka = true;
    r = await nakup(T.jan, evTest);
    const o7c = r.body.order.id;
    await cakaj(async () => (await vrstica(o7c)).receipt_mail_attempts >= 1);   // prvi (neuspeli) poskus je opravljen, preden spremenimo naslov
    await pool.query("UPDATE orders SET buyer_email = 'izbrisan-' || id || '@outly.invalid' WHERE id=$1", [o7c]);
    R.napaka = false;
    await pocakaj(2500);
    v = await vrstica(o7c);
    assert(v.receipt_mail_sent_at === null && v.receipt_mail_attempts === 8 && R.poslano.every(x => !/outly\.invalid/.test(String(x.to))), "izbrisan racun: potrdilo se ne poslje, poskusi izcrpani", [v.receipt_mail_attempts, A.log.slice(-600)]);
    // meja za narocila brez placila: 3 na uporabnika na 24 h
    for (let i = 1; i <= 3; i++) { await nakup(T.kim, evTest); await cakaj(() => mailiNa("kim@outly.si").length >= i, 5000); }
    assert(mailiNa("kim@outly.si").length === 3, "3 testna narocila: 3 potrdila", mailiNa("kim@outly.si").length);
    r = await nakup(T.kim, evTest);
    const o7d = r.body.order.id;
    await pocakaj(1800);
    v = await vrstica(o7d);
    assert(r.status === 201 && mailiNa("kim@outly.si").length === 3 && v.receipt_mail_attempts === 8 && v.receipt_mail_sent_at === null, "4. testno narocilo: nakup uspe, potrdilo izpuscen (meja)", [mailiNa("kim@outly.si").length, v.receipt_mail_attempts]);
    assert(/meja 3 potrdil na uporabnika/.test(A.log) && !/kim@outly\.si/.test(A.log), "meja zapisana v dnevnik brez e-naslova");

    // ================================================================
    console.log("\n# 8. Natanko enkrat ob pocasnem Resendu (druga instanca, pospravljalec tece med posiljanjem)");
    A.srv.kill();   // ponovni prevzem v bazi je odvisen od nastavitev VSAKEGA procesa; instanca A ima kratek premor, zato pri B ne sme sodelovati
    await pocakaj(300);
    R.zamik = 1500;
    r = await apiB("POST", `/events/${evTest}/orders`, T.lara, { quantity: 1 });
    assert(r.status === 201 && r.body.order.status === "paid", "nakup na instanci B", r.body);
    const o8 = r.body.order.id;
    await pocakaj(5000);
    R.zamik = 0;
    v = await vrstica(o8);
    assert(mailiNa("lara@outly.si").length === 1, "natanko en mail (pospravljalec med posiljanjem ni prevzel narocila)", mailiNa("lara@outly.si").length);
    assert(v.receipt_mail_attempts === 1 && v.receipt_mail_sent_at, "baza: en sam poskus", [v.receipt_mail_attempts]);
  } catch (e) {
    fail++; console.log("  ✗ IZJEMA v testu:", e && e.stack || e);
  } finally {
    A.srv.kill(); B.srv.kill();
    jwksServer.close(); stripeServer.close(); resendServer.close();
    await pool.end();
    console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
    process.exit(fail ? 1 : 0);
  }
})().catch((e) => { console.error(e); process.exit(1); });
