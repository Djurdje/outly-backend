#!/usr/bin/env node
/**
 * Pavza prodaje in dnevnik admin dejanj (admin panel faza 1, migracija 055, invarianta I53). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_prodaja_pavza.js
 * Vzorec kot test_nakup_stripe.js: lokalni JWKS, lazni Stripe (STRIPE_API_BASE), backend na svojem portu, TRUNCATE na zacetku.
 *
 *  P1  javni odgovor: nova polja `sales_paused` in `on_sale`, obstojeca polja nespremenjena (availability, cena)
 *  P2  pavza (admin, PATCH /events/:id { salesPaused: true }): vstopnice, gost in VIP miza -> 409 z besedilom, ki vsebuje »not on sale«; cena ostane;
 *      GET /events/:id: sales_paused true, on_sale false, payment_mode "unavailable"; GET /events/:id/vip: on_sale false, payment_mode "unavailable"
 *  P3  odprta placilna okna: cakajoce narocilo (vstopnice, gost, miza) ob pavzi -> `cancelled` (zaloga sproscena), Stripova seja zaprta (expire),
 *      placilo v obdelavi (odlozeno placilo) ostane `pending`
 *  P4  dirka: placilo (webhook completed) za narocilo, ki ga je pavza preklicala -> brez vstopnic, vracilo `inactive_order` v vrsti
 *  P5  ponovni vklop: { salesPaused: false } -> nakup spet 201, isti znesek kot pred pavzo
 *  P6  dnevnik: vsaka admin sprememba = ena vrstica admin_dejanja (prej/potem samo spremenjena polja, brez e-naslovov kupcev);
 *      sprememba lastnika kluba vrstice NE ustvari; napaka (kapaciteta pod prodanim) -> ni ne spremembe ne vrstice
 *  P7  kapaciteta pod prodanim -> 400 capacity_below_sold (ne 500), lastnik in admin
 *  P8  vloge: lastnik sme pavzo za svoj dogodek, tuj lastnik 403, navaden uporabnik 403, brez zetona 401; admin poti (/admin/api/events/:id, /audit)
 *      samo admin; neveljaven salesPaused -> 400
 *  P9  admin panel PATCH /admin/api/events/:id: objava obvesti sledilce (club_event_notifications) kot PATCH /events/:id, odpoved zapise vrstico z razlogom
 *  P10 transakcija: ce vpis v admin_dejanja pade (sprozilec v testu), PATCH vrne 500 in dogodek ostane nespremenjen
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");
const Stripe = require("stripe");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 5821, JWKS_PORT = 5822, STRIPE_PORT = 5823;
const BASE = `http://127.0.0.1:${PORT}`;
const WHSEC = "whsec_test_pavza";

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-pavza";
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
const pocakaj = (ms) => new Promise(r => setTimeout(r, ms));
async function cakajPogoj(f, ms = 8000) { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (await f()) return true; await pocakaj(50); } return false; }

let ipSt = 0;
async function api(method, p, token, body, glave = {}) {
  const r = await fetch(BASE + p, { method, headers: { "content-type": "application/json", "x-forwarded-for": `10.77.${(++ipSt >> 8) & 255}.${(ipSt & 255) + 1}`, ...(token ? { authorization: "Bearer " + token } : {}), ...glave }, body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}

// Lazni Stripe: ustvari sejo, vrne sejo, expire (belezi), PaymentIntent.
const S = { seje: {}, st: 0, potekle: [], expireNapak: 0 };
const stripeServer = http.createServer((req, res) => {
  let d = ""; req.on("data", x => d += x);
  req.on("end", () => {
    const p = Object.fromEntries(new URLSearchParams(d));
    const odg = (s, o) => { res.writeHead(s, { "content-type": "application/json", "request-id": "req_test" }); res.end(JSON.stringify(o)); };
    const u = req.url.split("?")[0];
    let m;
    if (req.method === "POST" && u === "/v1/checkout/sessions") {
      const id = "cs_test_p" + (++S.st);
      const kol = Number(p["line_items[0][quantity]"]), cena = Number(p["line_items[0][price_data][unit_amount]"]);
      S.seje[id] = { id, object: "checkout.session", url: `https://checkout.stripe.test/c/pay/${id}`, status: "open", payment_status: "unpaid",
        amount_total: kol * cena, currency: p["line_items[0][price_data][currency]"], livemode: false,
        metadata: { order_id: p["metadata[order_id]"] }, client_reference_id: p.client_reference_id, expires_at: Number(p.expires_at), payment_intent: null };
      return odg(200, S.seje[id]);
    }
    if (req.method === "POST" && (m = u.match(/^\/v1\/checkout\/sessions\/(cs_\w+)\/expire$/))) {
      if (S.expireNapak > 0) { S.expireNapak--; return odg(500, { error: { type: "api_error", message: "zacasna napaka (test)" } }); }
      const s = S.seje[m[1]];
      if (!s) return odg(404, { error: { type: "invalid_request_error", message: "No such checkout.session" } });
      if (s.status !== "open") return odg(400, { error: { type: "invalid_request_error", message: "Session is not open" } });
      S.potekle.push(m[1]); s.status = "expired"; return odg(200, s);
    }
    if (req.method === "GET" && (m = u.match(/^\/v1\/checkout\/sessions\/(cs_\w+)$/))) return S.seje[m[1]] ? odg(200, S.seje[m[1]]) : odg(404, { error: { type: "invalid_request_error", message: "No such session" } });
    if (req.method === "GET" && (m = u.match(/^\/v1\/payment_intents\/(pi_\w+)$/))) return odg(200, { id: m[1], object: "payment_intent", status: "processing" });
    return odg(404, { error: { type: "invalid_request_error", message: "Lazni Stripe: neznana pot " + req.method + " " + u } });
  });
});
const stripeLokalno = new Stripe("sk_test_lokalno");
let stDog = 0;
async function webhook(tip, objekt) {
  const d = { id: `evt_pavza_${++stDog}`, object: "event", type: tip, data: { object: objekt }, created: Math.floor(Date.now() / 1000), livemode: false };
  const payload = JSON.stringify(d);
  const glava = stripeLokalno.webhooks.generateTestHeaderString({ payload, secret: WHSEC });
  const r = await fetch(BASE + "/stripe/webhook", { method: "POST", headers: { "content-type": "application/json", "stripe-signature": glava }, body: payload });
  return { status: r.status, body: await r.text() };
}

let srv = null, log = "";
(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, admin_dejanja, vracila, stripe_events, club_event_notifications, club_follows, guest_list_members, guest_lists, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, event_tables, club_tables, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  await new Promise(r => stripeServer.listen(STRIPE_PORT, r));
  srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test",
    STRIPE_SECRET_KEY: "sk_test_lokalno", STRIPE_WEBHOOK_SECRET: WHSEC, STRIPE_API_BASE: `http://127.0.0.1:${STRIPE_PORT}`, STRIPE_POSPRAVI_MS: "3600000",
    APP_URL: "https://outly.test", TEST_PLACILA: "", GOST_NAKUP_TEST: "1", GOST_NAKUP_NA_URO: "1000", REZERVACIJE_CISCENJE_MS: "0",
    VRACILA_TICK_MS: "0", VRACILA_SWEEP_MS: "0", JAVNI_PREDPOMNILNIK_MS: "0",
    PAVZA_STRIPE_PREMOR_MS: "20", PAVZA_KMALU_MS: "400", PAVZA_PONOVNO_MS: "1500" }, stdio: ["ignore", "pipe", "pipe"] });
  srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 60; i++) { try { await fetch(BASE + "/"); break; } catch { await pocakaj(100); } }

  try {
    const T = { lastnik: zeton("lastnik@outly.si", uuid(1)), tuj: zeton("tuj@outly.si", uuid(2)), admin: zeton("admin@outly.si", uuid(3)),
      ana: zeton("ana@outly.si", uuid(4)), bor: zeton("bor@outly.si", uuid(5)), cene: zeton("cene@outly.si", uuid(6)), dana: zeton("dana@outly.si", uuid(7)) };
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='business' WHERE email IN ('lastnik@outly.si','tuj@outly.si')");
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("UPDATE users SET date_of_birth='1990-01-01'");
    await pool.query(`INSERT INTO clubs (owner_user_id, name, city, stripe_account_id, stripe_charges_enabled)
                      VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana', 'acct_test1', TRUE)`);
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='tuj@outly.si'), 'Tuj Club', 'Maribor')");
    await pool.query("INSERT INTO club_follows (user_id, club_id) SELECT id, 1 FROM users WHERE email IN ('ana@outly.si','bor@outly.si')");
    const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    const dogodek = async (naslov, kap = 100, status = "published") => (await pool.query(
      "INSERT INTO events (club_id, title, start_at, status, ticket_price_cents, capacity, min_age, vip_enabled) VALUES (1,$1,$2,$3,1500,$4,0,TRUE) RETURNING id", [naslov, cezDan, status, kap])).rows[0].id;
    const E = await dogodek("Pavza noc");
    await pool.query("INSERT INTO club_tables (club_id, label, x, y, w, h, seats, price_cents) VALUES (1, 'A1', 10, 10, 10, 10, 4, 20000), (1, 'A2', 30, 10, 10, 10, 4, 20000), (1, 'A3', 50, 10, 10, 10, 4, 20000)");
    const sold = async () => (await pool.query("SELECT sold_count FROM events WHERE id=$1", [E])).rows[0].sold_count;
    const narocilo = async (id) => (await pool.query("SELECT id, status, stripe_checkout_session_id AS seja, checkout_url FROM orders WHERE id=$1", [id])).rows[0];
    const dnevnik = async (ev) => (await pool.query("SELECT dejanje, prej, potem, razlog, admin_user_id FROM admin_dejanja WHERE cilj_tip='event' AND cilj_id=$1 ORDER BY id", [String(ev)])).rows;
    const kupiV = (tok, kol = 1) => api("POST", `/events/${E}/orders`, tok, { quantity: kol });
    const kupiG = (email) => api("POST", `/guest/events/${E}/orders`, null, { email, quantity: 1, accept_terms: true, terms_version: "2026-10-01" });
    const kupiM = (tok, miza) => api("POST", `/events/${E}/tables/${miza}/orders`, tok, {});
    const PAVZA = /not on sale/i;

    console.log("\n# P1: javni odgovor ima nova polja, obstojeca nespremenjena");
    let r = await api("GET", `/events/${E}`);
    assert(r.status === 200 && r.body.sales_paused === false && r.body.on_sale === true, "GET /events/:id: sales_paused false, on_sale true", r.body);
    assert(r.body.availability === "available" && r.body.ticket_price_cents === 1500 && r.body.payment_mode === "stripe", "availability/cena/payment_mode kot doslej", r.body);
    r = await api("GET", "/events");
    assert(r.status === 200 && r.body.length === 1 && r.body[0].sales_paused === false && r.body[0].on_sale === true, "GET /events: polji v seznamu", r.body);

    console.log("\n# P3 priprava: odprta placilna okna (vstopnice, gost, miza) + placilo v obdelavi");
    const nV = await kupiV(T.ana, 2);
    assert(nV.status === 201 && nV.body.checkout_url, "vstopnice: cakajoce narocilo s checkout_url", nV.body);
    const nG = await kupiG("gost1@example.com");
    assert(nG.status === 201 && nG.body.checkout_url, "gost: cakajoce narocilo s checkout_url", nG.body);
    const nM = await kupiM(T.bor, 1);
    assert(nM.status === 201 && nM.body.checkout_url, "miza: cakajoce narocilo s checkout_url", nM.body);
    const nO = await kupiV(T.cene, 1);   // postane »v obdelavi« (odlozeno placilo)
    assert(nO.status === 201, "cetrto narocilo (za placilo v obdelavi)", nO.body);
    const sejaO = (await narocilo(nO.body.order.id)).seja;
    Object.assign(S.seje[sejaO], { status: "complete", payment_status: "unpaid", payment_intent: "pi_obdelava" });
    r = await webhook("checkout.session.completed", S.seje[sejaO]);
    assert(r.status === 200 && (await narocilo(nO.body.order.id)).checkout_url === null, "placilo v obdelavi: checkout_url NULL, pending", await narocilo(nO.body.order.id));
    assert(await sold() === 4, "zaloga 4 (2 + 1 gost + 1 v obdelavi; miza ne steje)", await sold());

    console.log("\n# P2: pavza (admin) zavrne vse nakupne poti, cena ostane");
    r = await api("PATCH", `/events/${E}`, T.admin, { salesPaused: true });
    assert(r.status === 200 && r.body.sales_paused === true && r.body.ticket_price_cents === 1500, "PATCH { salesPaused: true } -> 200, cena 1500 ostane", r.body);
    let k = await kupiV(T.dana);
    assert(k.status === 409 && PAVZA.test(k.body) && /paused/i.test(k.body), "vstopnice -> 409 »paused … not on sale«", k);
    k = await kupiG("gost2@example.com");
    assert(k.status === 409 && PAVZA.test(k.body), "gost -> 409", k);
    k = await kupiM(T.dana, 2);
    assert(k.status === 409 && PAVZA.test(k.body), "VIP miza -> 409", k);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE user_id=(SELECT id FROM users WHERE email='dana@outly.si') OR guest_email='gost2@example.com'")).rows[0].n === 0, "zavrnjeni nakupi niso ustvarili narocil");
    r = await api("GET", `/events/${E}`);
    assert(r.body.sales_paused === true && r.body.on_sale === false && r.body.payment_mode === "unavailable" && r.body.ticket_price_cents === 1500,
      "GET /events/:id: sales_paused true, on_sale false, payment_mode unavailable, cena vidna", r.body);
    assert(r.body.availability === "available", "availability ostane »available« (vrednost se ne spremeni, stari dekoderji)", r.body.availability);
    r = await api("GET", `/events/${E}/vip`);
    assert(r.status === 200 && r.body.on_sale === false && r.body.payment_mode === "unavailable", "GET /events/:id/vip: on_sale false, unavailable", r.body);

    console.log("\n# P3: odprta placilna okna prekinjena");
    for (const [ime, n] of [["vstopnice", nV], ["gost", nG], ["miza", nM]]) {
      const o = await narocilo(n.body.order.id);
      assert(o.status === "cancelled", `${ime}: cakajoce narocilo -> cancelled`, o);
    }
    assert(await cakajPogoj(() => [nV, nG, nM].every(async () => true) && S.potekle.length >= 3), "lazni Stripe je dobil expire za tri seje", S.potekle);
    const seje3 = await Promise.all([nV, nG, nM].map(async n => (await narocilo(n.body.order.id)).seja));
    assert(seje3.every(s => S.potekle.includes(s)), "zaprte so ravno seje treh preklicanih narocil", { seje3, potekle: S.potekle });
    assert(!S.potekle.includes(sejaO) && (await narocilo(nO.body.order.id)).status === "pending", "placilo v obdelavi: NI preklicano in seja ni zaprta", await narocilo(nO.body.order.id));
    assert(await sold() === 1, "zaloga sproscena (ostane samo narocilo v obdelavi)", await sold());
    r = await api("GET", "/me/orders", T.ana);
    assert(!r.body.some(o => o.id === nV.body.order.id && o.checkout_url), "kupec v /me/orders nima vec povezave za placilo", r.body);
    assert(/\[pavza\] dogodek \d+: prvi korak, zaprtih placilnih oken 3 od 3/.test(log), "dnevnik [pavza] zabelezi zaprta okna");

    console.log("\n# P4: dirka - placilo pride po pavzi");
    const sejaV = seje3[0];
    Object.assign(S.seje[sejaV], { status: "complete", payment_status: "paid", payment_intent: "pi_dirka" });
    r = await webhook("checkout.session.completed", S.seje[sejaV]);
    assert(r.status === 200, "webhook completed -> 200", r);
    const o4 = await narocilo(nV.body.order.id);
    const vst4 = (await pool.query("SELECT COUNT(*)::int AS n FROM tickets WHERE order_id=$1", [nV.body.order.id])).rows[0].n;
    const vr4 = (await pool.query("SELECT razlog, znesek_cents, payment_intent_id FROM vracila WHERE order_id=$1", [nV.body.order.id])).rows;
    assert(o4.status === "cancelled" && vst4 === 0, "narocilo ostane cancelled, NI vstopnic", { o4, vst4 });
    assert(vr4.length === 1 && vr4[0].razlog === "inactive_order" && vr4[0].znesek_cents === 3000 && vr4[0].payment_intent_id === "pi_dirka", "vracilo celotnega zneska v vrsti (inactive_order)", vr4);

    console.log("\n# P3b: ponovni korak ujame narocilo, ki je nastalo tik pred pavzo (vstavljeno mimo API-ja med pavzo)");
    const rocno = (await pool.query(
      `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, currency, application_fee_cents, status, buyer_email, stripe_account_id)
       VALUES ('OUT-PAVZA1', (SELECT id FROM users WHERE email='dana@outly.si'), $1, 1, 1, 1500, 1500, 'EUR', 150, 'pending', 'dana@outly.si', 'acct_test1') RETURNING id`, [E])).rows[0].id;
    assert(await cakajPogoj(async () => (await narocilo(rocno)).status === "cancelled", 5000), "ponovni korak (PAVZA_KMALU_MS / PAVZA_PONOVNO_MS) preklice zamudnika", await narocilo(rocno));

    console.log("\n# P5: ponovni vklop");
    await pocakaj(1700);   // drugi ponovni korak je mimo (ne sme preklicati nakupa po vklopu)
    r = await api("PATCH", `/events/${E}`, T.admin, { salesPaused: false });
    assert(r.status === 200 && r.body.sales_paused === false, "PATCH { salesPaused: false } -> 200", r.body);
    k = await kupiV(T.dana);
    assert(k.status === 201 && k.body.order.total_cents === 1500 && k.body.checkout_url, "nakup spet 201, ista cena 1500", k.body);
    r = await api("GET", `/events/${E}`);
    assert(r.body.on_sale === true && r.body.payment_mode === "stripe", "on_sale true, payment_mode stripe", r.body);
    await pocakaj(300);
    assert((await narocilo(k.body.order.id)).status === "pending", "nakup po vklopu ostane pending (ponovni korak ga ne preklice)", await narocilo(k.body.order.id));

    console.log("\n# P6: dnevnik admin dejanj");
    let dn = await dnevnik(E);
    assert(dn.length === 2 && dn[0].dejanje === "event.sales_pause" && dn[1].dejanje === "event.sales_resume", "dve vrstici: sales_pause, sales_resume", dn);
    assert(JSON.stringify(dn[0].prej) === '{"sales_paused":false}' && JSON.stringify(dn[0].potem) === '{"sales_paused":true}', "prej/potem samo spremenjeno polje", dn[0]);
    const vsebina = JSON.stringify((await pool.query("SELECT * FROM admin_dejanja")).rows);
    assert(!/@example\.com|ana@|bor@|gost1|cs_test|pi_/.test(vsebina), "dnevnik ne vsebuje e-naslovov kupcev ne Stripovih ID-jev", vsebina);
    r = await api("PATCH", `/events/${E}`, T.admin, { title: "Pavza noc 2", ticketPriceCents: 1500, capacity: 100 });
    dn = await dnevnik(E);
    assert(r.status === 200 && dn.length === 3 && dn[2].dejanje === "event.update" && JSON.stringify(dn[2].potem) === '{"title":"Pavza noc 2"}',
      "PATCH vec polj, spremenjen samo naslov -> ena vrstica s samo naslovom", dn[2]);
    r = await api("PATCH", `/events/${E}`, T.admin, { title: "Pavza noc 2" });
    assert(r.status === 200 && (await dnevnik(E)).length === 3, "PATCH brez dejanske spremembe -> brez vrstice");
    r = await api("PATCH", `/events/${E}`, T.lastnik, { description: "lastnik ureja" });
    assert(r.status === 200 && (await dnevnik(E)).length === 3, "lastnik kluba ureja -> brez vrstice (dnevnik je samo za admina)");

    console.log("\n# P7: kapaciteta pod prodanim -> 400");
    const prodano = await sold();
    for (const vloga of ["admin", "lastnik"]) {
      r = await api("PATCH", `/events/${E}`, T[vloga], { capacity: 1, title: "Ne sme" });
      assert(r.status === 400 && r.body.error === "capacity_below_sold" && r.body.sold === prodano, `${vloga}: kapaciteta 1 pod prodanim (${prodano}) -> 400 capacity_below_sold`, r);
    }
    const ev7 = (await pool.query("SELECT title, capacity FROM events WHERE id=$1", [E])).rows[0];
    assert(ev7.title === "Pavza noc 2" && ev7.capacity === 100 && (await dnevnik(E)).length === 3, "po 400: ni spremembe (naslov, kapaciteta) in ni vrstice v dnevniku", ev7);

    console.log("\n# P8: vloge");
    r = await api("PATCH", `/events/${E}`, T.lastnik, { salesPaused: true });
    assert(r.status === 200 && r.body.sales_paused === true, "lastnik kluba sme ustaviti prodajo svojega dogodka", r.body);
    r = await api("PATCH", `/events/${E}`, T.lastnik, { sales_paused: false });
    assert(r.status === 200 && r.body.sales_paused === false, "lastnik: snake_case sales_paused false", r.body);
    r = await api("PATCH", `/events/${E}`, T.tuj, { salesPaused: true });
    assert(r.status === 403, "tuj lastnik -> 403", r);
    r = await api("PATCH", `/events/${E}`, T.ana, { salesPaused: true });
    assert(r.status === 403, "navaden uporabnik -> 403", r);
    r = await api("PATCH", `/events/${E}`, null, { salesPaused: true });
    assert(r.status === 401, "brez zetona -> 401", r);
    for (const slab of ["true", 1, null]) {
      r = await api("PATCH", `/events/${E}`, T.admin, { salesPaused: slab });
      assert(r.status === 400 && /salesPaused must be/.test(r.body), `salesPaused ${JSON.stringify(slab)} -> 400`, r);
    }
    assert((await pool.query("SELECT sales_paused FROM events WHERE id=$1", [E])).rows[0].sales_paused === false, "po zavrnitvah ostane prodaja odprta");
    for (const pot of [`/admin/api/events/${E}`, `/admin/api/audit?target_type=event&target_id=${E}`]) {
      for (const [vloga, tok, pric] of [["lastnik", T.lastnik, 403], ["ana", T.ana, 403], ["brez", null, 401]]) {
        r = await api("GET", pot, tok);
        assert(r.status === pric, `GET ${pot.split("?")[0]} ${vloga} -> ${pric}`, r.status);
      }
    }
    r = await api("GET", `/admin/api/events/${E}`, T.admin);
    assert(r.status === 200 && r.body.event.sales_paused === false && r.body.event.ticket_price_cents === 1500 && Array.isArray(r.body.audit) && r.body.audit.length === 3,
      "admin GET /admin/api/events/:id: polja + dnevnik (3 admin vrstice; pavza lastnika ni v dnevniku)", r.body);
    assert(r.body.audit[0].admin_email === "admin@outly.si" && Number.isInteger(r.body.audit[0].id) && r.body.stats && typeof r.body.stats.pending_orders === "number",
      "dnevnik ima e-naslov admina, id (BIGINT, setTypeParser(20)) kot stevilo; stats", r.body.audit[0]);
    r = await api("GET", `/admin/api/audit?target_type=event&target_id=${E}&limit=2`, T.admin);
    assert(r.status === 200 && r.body.length === 2 && r.body[0].target_id === String(E), "GET /admin/api/audit filter + limit", r.body);
    r = await api("GET", `/admin/api/audit?target_type=EV;drop`, T.admin);
    assert(r.status === 400, "audit: neveljaven target_type -> 400", r);
    r = await api("GET", "/admin/api/events", T.admin);
    assert(r.status === 200 && r.body[0].sales_paused === false && r.body[0].capacity === 100 && "sold_count" in r.body[0], "GET /admin/api/events: dodani stolpci", r.body[0]);

    console.log("\n# P9: admin panel PATCH /admin/api/events/:id (objava obvesti sledilce, odpoved z razlogom)");
    const E2 = await dogodek("Osnutek", 50, "draft");
    r = await api("PATCH", `/admin/api/events/${E2}`, T.admin, { status: "published" });
    assert(r.status === 200 && r.body.status === "published", "objava iz panela -> 200", r.body);
    const obv = (await pool.query("SELECT COUNT(*)::int AS n FROM club_event_notifications WHERE event_id=$1", [E2])).rows[0].n;
    assert(obv === 2, "sledilca kluba (ana, bor) dobita obvestilo kot pri PATCH /events/:id (U1)", obv);
    r = await api("PATCH", `/admin/api/events/${E2}`, T.admin, { status: "cancelled", reason: "Izvajalec odpovedal" });
    let dn2 = await dnevnik(E2);
    assert(r.status === 200 && dn2.length === 2 && dn2[0].dejanje === "event.publish" && dn2[1].dejanje === "event.cancel" && dn2[1].razlog === "Izvajalec odpovedal",
      "dnevnik: event.publish, event.cancel z razlogom", dn2);
    r = await api("PATCH", `/admin/api/events/${E2}`, T.lastnik, { status: "published" });
    assert(r.status === 403, "admin pot: lastnik kluba -> 403", r);
    const E3 = await dogodek("Za DELETE", 50);
    r = await api("DELETE", `/events/${E3}`, T.admin);
    dn2 = await dnevnik(E3);
    assert(r.status === 200 && dn2.length === 1 && dn2[0].dejanje === "event.delete", "admin DELETE dogodka brez narocil -> vrstica event.delete", dn2);

    console.log("\n# P10: vpis v dnevnik pade -> ni spremembe");
    k = await kupiV(T.dana);
    assert(k.status === 201 && k.body.checkout_url, "nov cakajoc nakup (za P10/P11)", k.body);
    await pool.query(`CREATE OR REPLACE FUNCTION test_pavza_zavrni() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test: dnevnik zavrnjen'; END $$`);
    await pool.query("CREATE TRIGGER test_pavza_zavrni BEFORE INSERT ON admin_dejanja FOR EACH ROW EXECUTE FUNCTION test_pavza_zavrni()");
    try {
      r = await api("PATCH", `/events/${E}`, T.admin, { salesPaused: true, title: "Ne sme ostati" });
      const ev10 = (await pool.query("SELECT title, sales_paused FROM events WHERE id=$1", [E])).rows[0];
      assert(r.status === 500 && ev10.title === "Pavza noc 2" && ev10.sales_paused === false, "PATCH -> 500, dogodek nespremenjen (naslov, pavza)", { r, ev10 });
      assert((await narocilo(k.body.order.id)).status === "pending", "cakajoce narocilo NI preklicano (preklic je v isti transakciji)", await narocilo(k.body.order.id));
      r = await api("PATCH", `/admin/api/events/${E}`, T.admin, { status: "draft" });
      assert(r.status === 500 && (await pool.query("SELECT status FROM events WHERE id=$1", [E])).rows[0].status === "published", "admin PATCH status -> 500, status nespremenjen", r);
    } finally {
      await pool.query("DROP TRIGGER test_pavza_zavrni ON admin_dejanja");
      await pool.query("DROP FUNCTION test_pavza_zavrni()");
    }

    console.log("\n# P11: zacasna napaka Stripa ob zapiranju okna -> ponovitev");
    S.expireNapak = 2;
    r = await api("PATCH", `/events/${E}`, T.admin, { salesPaused: true });
    const sejaK = (await narocilo(k.body.order.id)).seja;
    assert(r.status === 200 && (await narocilo(k.body.order.id)).status === "cancelled", "pavza preklice nakup", r.body);
    assert(await cakajPogoj(() => S.potekle.includes(sejaK), 5000), "seja zaprta po dveh zacasnih napakah (ponovitev)", S.potekle);
  } catch (e) {
    fail++; console.error("NAPAKA TESTA:", e);
  } finally {
    srv.kill(); jwksServer.close(); stripeServer.close(); await pool.end();
    if (fail) console.log("\n--- dnevnik streznika ---\n" + log.split("\n").slice(-60).join("\n"));
    console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
    process.exit(fail ? 1 : 0);
  }
})();
