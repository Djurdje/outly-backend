#!/usr/bin/env node
/**
 * Test Stripe placil (issue #19, placila_stripe.js, migracija 030). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_stripe.js
 * Brez pravega Stripa: lazni Stripe API na svojem portu (STRIPE_API_BASE), webhooki podpisani s Stripovim paketom.
 * Vzorec kot test_vstopnice.js: lokalni JWKS, backend na svojem portu.
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");
const Stripe = require("stripe");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3161, JWKS_PORT = 3962, STRIPE_PORT = 3963;
const BASE = `http://127.0.0.1:${PORT}`;
const WHSEC = "whsec_test_outly";
const stripeLokalno = new Stripe("sk_test_lokalno");

// ---------- JWKS + zetoni (kot test_vstopnice.js) ----------
const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-stripe";
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
async function api(method, path, token, body, glave = {}) {
  const r = await fetch(BASE + path, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}), ...glave }, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}
const pocakaj = (ms) => new Promise(r => setTimeout(r, ms));

// ---------- lazni Stripe ----------
const S = { racuni: {}, seje: {}, stRacunov: 0, stSej: 0, zahtevkiSej: [], pokvarjeneSeje: false, potekle: [] };
function telo(req) { return new Promise(r => { let d = ""; req.on("data", x => d += x); req.on("end", () => r(d)); }); }
function obrazec(besedilo) { const o = {}; for (const [k, v] of new URLSearchParams(besedilo)) o[k] = v; return o; }
const stripeServer = http.createServer(async (req, res) => {
  const t = await telo(req);
  const p = obrazec(t);
  const odg = (status, o) => { res.writeHead(status, { "content-type": "application/json", "request-id": "req_test" }); res.end(JSON.stringify(o)); };
  const u = req.url.split("?")[0];
  let m;
  if (req.method === "POST" && u === "/v1/accounts") {
    S.stRacunov++;
    const kljuc = req.headers["idempotency-key"];
    const obst = Object.values(S.racuni).find(a => a._kljuc === kljuc);
    if (obst) return odg(200, obst);
    const id = "acct_test" + S.stRacunov;
    S.racuni[id] = { id, object: "account", _kljuc: kljuc, _params: p, charges_enabled: false, payouts_enabled: false, details_submitted: false,
      requirements: { currently_due: ["external_account"], disabled_reason: "requirements.past_due" } };
    return odg(200, S.racuni[id]);
  }
  if (req.method === "POST" && u === "/v1/account_links") return odg(200, { object: "account_link", url: `https://connect.stripe.test/setup/${p.account}`, _params: p });
  if (req.method === "GET" && (m = u.match(/^\/v1\/accounts\/(acct_\w+)$/))) return S.racuni[m[1]] ? odg(200, S.racuni[m[1]]) : odg(404, { error: { type: "invalid_request_error", message: "No such account" } });
  if (req.method === "POST" && (m = u.match(/^\/v1\/accounts\/(acct_\w+)\/login_links$/))) {
    const a = S.racuni[m[1]];
    if (!a || !a.details_submitted) return odg(400, { error: { type: "invalid_request_error", message: "Cannot create a login link for an account that has not completed onboarding." } });
    return odg(200, { object: "login_link", url: `https://connect.stripe.test/express/${m[1]}` });
  }
  if (req.method === "POST" && u === "/v1/checkout/sessions") {
    if (S.pokvarjeneSeje) return odg(500, { error: { type: "api_error", message: "Stripe je padel" } });
    const kljuc = req.headers["idempotency-key"];
    S.zahtevkiSej.push({ params: p, kljuc });
    const obst = Object.values(S.seje).find(s => s._kljuc === kljuc);
    if (obst) return odg(200, obst);
    const id = "cs_test_" + (++S.stSej);
    const kol = Number(p["line_items[0][quantity]"]), cena = Number(p["line_items[0][price_data][unit_amount]"]);
    S.seje[id] = { id, object: "checkout.session", _kljuc: kljuc, url: `https://checkout.stripe.test/c/pay/${id}`, status: "open", payment_status: "unpaid",
      amount_total: kol * cena, currency: p["line_items[0][price_data][currency]"], client_reference_id: p.client_reference_id,
      metadata: { order_id: p["metadata[order_id]"], public_ref: p["metadata[public_ref]"] }, expires_at: Number(p.expires_at), payment_intent: null };
    return odg(200, S.seje[id]);
  }
  if (req.method === "GET" && (m = u.match(/^\/v1\/checkout\/sessions\/(cs_\w+)$/))) return odg(200, S.seje[m[1]]);
  if (req.method === "POST" && (m = u.match(/^\/v1\/checkout\/sessions\/(cs_\w+)\/expire$/))) {
    S.potekle.push(m[1]); S.seje[m[1]].status = "expired"; return odg(200, S.seje[m[1]]);
  }
  return odg(404, { error: { type: "invalid_request_error", message: "Lazni Stripe: neznana pot " + req.method + " " + u } });
});

let stDogodka = 0;
async function webhook(tip, objekt, { id, podpis } = {}) {
  const d = { id: id || `evt_test_${++stDogodka}`, object: "event", type: tip, data: { object: objekt }, created: Math.floor(Date.now() / 1000) };
  const payload = JSON.stringify(d);
  const glava = podpis || stripeLokalno.webhooks.generateTestHeaderString({ payload, secret: WHSEC });
  const r = await fetch(BASE + "/stripe/webhook", { method: "POST", headers: { "content-type": "application/json", "stripe-signature": glava }, body: payload });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, id: d.id };
}
const placana = (s, pi) => ({ ...s, status: "complete", payment_status: "paid", payment_intent: pi });

(async () => {
  // ---------- nacinPlacila (cista funkcija, brez streznika) ----------
  console.log("\n# nacinPlacila");
  {
    const { nacinPlacila } = require("../placila_stripe");
    const shrani = { ...process.env };
    const nastavi = (o) => { for (const k of ["TEST_PLACILA", "STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET"]) delete process.env[k]; Object.assign(process.env, o); };
    const s = { stripe_account_id: "acct_1", stripe_charges_enabled: true }, brez = { stripe_account_id: null, stripe_charges_enabled: false };
    nastavi({}); assert(nacinPlacila(s) === "test", "brez kljuca -> test");
    nastavi({ STRIPE_SECRET_KEY: "sk_test_x" }); assert(nacinPlacila(s) === "nastavitve", "kljuc brez webhook skrivnosti -> nastavitve (503)");
    nastavi({ STRIPE_SECRET_KEY: "sk_test_x", STRIPE_WEBHOOK_SECRET: "whsec" });
    assert(nacinPlacila(s) === "stripe", "sandbox + klub s Stripom -> stripe");
    assert(nacinPlacila(brez) === "test", "sandbox + klub brez Stripa -> test (demo klubi delajo naprej)");
    assert(nacinPlacila({ stripe_account_id: "acct_1", stripe_charges_enabled: false }) === "test", "sandbox + nedokoncan onboarding -> test");
    nastavi({ STRIPE_SECRET_KEY: "sk_live_x", STRIPE_WEBHOOK_SECRET: "whsec" });
    assert(nacinPlacila(s) === "stripe", "live + klub s Stripom -> stripe");
    assert(nacinPlacila(brez) === "klub", "live + klub brez Stripa -> klub (409)");
    nastavi({ STRIPE_SECRET_KEY: "sk_live_x", STRIPE_WEBHOOK_SECRET: "whsec", TEST_PLACILA: "true" });
    assert(nacinPlacila(s) === "test", "TEST_PLACILA=true vsili test");
    for (const k of Object.keys(process.env)) if (!(k in shrani)) delete process.env[k];
    Object.assign(process.env, shrani);
  }

  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, stripe_events, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  await new Promise(r => stripeServer.listen(STRIPE_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test",
    STRIPE_SECRET_KEY: "sk_test_lokalno", STRIPE_WEBHOOK_SECRET: WHSEC, STRIPE_API_BASE: `http://127.0.0.1:${STRIPE_PORT}`, STRIPE_POSPRAVI_MS: "600",
    APP_URL: "https://outly.test", TEST_PLACILA: "" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await pocakaj(100); } }

  try {
    const T = { lastnik: zeton("lastnik@outly.si", uuid(1)), manager: zeton("manager@outly.si", uuid(2)), ana: zeton("ana@outly.si", uuid(3)), bor: zeton("bor@outly.si", uuid(4)) };
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana')");
    await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, (SELECT id FROM users WHERE email='manager@outly.si'), 'manager')");
    const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    let r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Stripe Noc", startAt: cezDan, ticketPriceCents: 1500, capacity: 5, minAge: 0 });
    assert(r.status === 201, "dogodek ustvarjen", r.body);
    const ev = r.body.id;
    const sold = async () => (await pool.query("SELECT sold_count FROM events WHERE id=$1", [ev])).rows[0].sold_count;

    console.log("\n# Sandbox, klub brez Stripa: testni nacin kot doslej");
    r = await api("POST", `/events/${ev}/orders`, T.ana, { quantity: 1 });
    assert(r.status === 201 && r.body.mode === "test", "201 mode test", r.body);
    assert(r.body.tickets.length === 1 && r.body.order.is_test === true, "vstopnica takoj, is_test", r.body);
    assert(!("checkout_url" in r.body), "testno narocilo nima checkout_url", r.body);
    assert(S.zahtevkiSej.length === 0, "Stripe ni bil klican");

    console.log("\n# Connect onboarding");
    r = await api("GET", "/business/stripe/status", T.lastnik, undefined, { "x-outly-club": "1" });
    assert(r.status === 200 && r.body.configured && r.body.sandbox && !r.body.connected, "status: nastavljen, sandbox, ni povezan", r.body);
    r = await api("POST", "/business/stripe/onboard", T.manager, {}, { "x-outly-club": "1" });
    assert(r.status === 403, "manager ne sme onboardati -> 403", r.body);
    r = await api("POST", "/business/stripe/onboard", T.ana, {}, { "x-outly-club": "1" });
    assert(r.status === 404 || r.status === 403, "navaden uporabnik -> 403/404", r.status);
    r = await api("POST", "/business/stripe/onboard", T.lastnik, {}, { "x-outly-club": "1" });
    assert(r.status === 200 && /^https:\/\/connect\.stripe\.test\/setup\/acct_test1$/.test(r.body.url), "lastnik dobi povezavo onboardinga", r.body);
    const racun = S.racuni.acct_test1;
    assert(racun && racun._params.type === "express" && racun._params.country === "SI", "Express racun, SI", racun && racun._params);
    assert(racun._params["capabilities[card_payments][requested]"] === "true" && racun._params["capabilities[transfers][requested]"] === "true", "zmoznosti card_payments + transfers");
    assert(racun._params["metadata[club_id]"] === "1" && racun._params.email === "lastnik@outly.si", "metadata club_id + e-naslov lastnika");
    let k = (await pool.query("SELECT stripe_account_id, stripe_charges_enabled FROM clubs WHERE id=1")).rows[0];
    assert(k.stripe_account_id === "acct_test1" && k.stripe_charges_enabled === false, "racun shranjen, placila se ne", k);
    r = await api("POST", "/business/stripe/onboard", T.lastnik, {}, { "x-outly-club": "1" });
    assert(r.status === 200 && Object.keys(S.racuni).length === 1, "drugi klic: isti racun, nova povezava", Object.keys(S.racuni));
    r = await api("POST", "/business/stripe/dashboard", T.lastnik, {}, { "x-outly-club": "1" });
    assert(r.status === 409, "Express pregled pred dokoncanim onboardingom -> 409", r);

    // Klub z nedokoncanim onboardingom v sandboxu se vedno prodaja testno
    r = await api("POST", `/events/${ev}/orders`, T.ana, { quantity: 1 });
    assert(r.status === 201 && r.body.mode === "test", "nedokoncan onboarding -> se vedno test", r.body);

    console.log("\n# Webhook: podpis in account.updated");
    r = await webhook("account.updated", { id: "acct_test1", object: "account", charges_enabled: true, payouts_enabled: true, details_submitted: true }, { podpis: "t=1,v1=napacen" });
    assert(r.status === 400, "napacen podpis -> 400", r);
    k = (await pool.query("SELECT stripe_charges_enabled FROM clubs WHERE id=1")).rows[0];
    assert(k.stripe_charges_enabled === false, "napacen podpis nic ne spremeni");
    Object.assign(racun, { charges_enabled: true, payouts_enabled: true, details_submitted: true, requirements: { currently_due: [], disabled_reason: null } });
    r = await webhook("account.updated", { id: "acct_test1", object: "account", charges_enabled: true, payouts_enabled: true, details_submitted: true });
    assert(r.status === 200, "account.updated -> 200", r);
    k = (await pool.query("SELECT stripe_charges_enabled, stripe_payouts_enabled, stripe_onboarded_at FROM clubs WHERE id=1")).rows[0];
    assert(k.stripe_charges_enabled && k.stripe_payouts_enabled && k.stripe_onboarded_at, "klub: placila in izplacila vklopljena", k);
    r = await api("GET", "/business/stripe/status", T.manager, undefined, { "x-outly-club": "1" });
    assert(r.status === 200 && r.body.connected && r.body.charges_enabled && r.body.details_submitted, "status (manager): povezan, placila vklopljena", r.body);
    assert(!JSON.stringify(r.body).includes("acct_"), "status ne razkrije stripe_account_id", r.body);
    r = await api("POST", "/business/stripe/dashboard", T.lastnik, {}, { "x-outly-club": "1" });
    assert(r.status === 200 && r.body.url.includes("/express/acct_test1"), "lastnik dobi povezavo v Express pregled", r.body);

    console.log("\n# Nakup prek Stripe Checkout");
    const kljuc = crypto.randomUUID();
    const soldPrej = await sold();
    r = await api("POST", `/events/${ev}/orders`, T.bor, { quantity: 2 }, { "idempotency-key": kljuc });
    assert(r.status === 201 && r.body.mode === "stripe", "201 mode stripe", r.body);
    assert(r.body.order.status === "pending" && r.body.order.is_test === false, "narocilo pending, is_test false", r.body.order);
    assert(Array.isArray(r.body.tickets) && r.body.tickets.length === 0, "vstopnic se ni", r.body.tickets);
    assert(/^https:\/\/checkout\.stripe\.test\/c\/pay\/cs_test_1$/.test(r.body.checkout_url), "checkout_url", r.body.checkout_url);
    assert(await sold() === soldPrej + 2, "zaloga rezervirana (+2)");
    const n1 = r.body.order;
    const zs = S.zahtevkiSej[0];
    assert(zs && zs.kljuc === `outly-narocilo-${n1.id}`, "idempotentni kljuc seje = id narocila", zs && zs.kljuc);
    const P = zs.params;
    assert(P["payment_intent_data[application_fee_amount]"] === "300", "provizija 10 % od 3000 = 300", P["payment_intent_data[application_fee_amount]"]);
    assert(P["payment_intent_data[transfer_data][destination]"] === "acct_test1", "destination = racun kluba");
    assert(P["payment_intent_data[on_behalf_of]"] === "acct_test1", "on_behalf_of = racun kluba (klub je business of record)");
    assert(P["line_items[0][price_data][unit_amount]"] === "1500" && P["line_items[0][quantity]"] === "2" && P["line_items[0][price_data][currency]"] === "eur", "cena iz baze, 2 kosa, EUR");
    assert(P.customer_email === "bor@outly.si" && P.client_reference_id === String(n1.id) && P.mode === "payment", "e-naslov kupca, client_reference_id, mode payment");
    assert(P.success_url.startsWith("https://outly.test/app/tickets?placilo=uspeh") && P.cancel_url.startsWith(`https://outly.test/app/event/${ev}?placilo=preklic`), "povratna naslova", [P.success_url, P.cancel_url]);
    const potek = Number(P.expires_at) - Math.floor(Date.now() / 1000);
    assert(potek > 25 * 60 && potek <= 30 * 60, "seja poteče v ~30 min", potek);
    const d = (await pool.query("SELECT stripe_account_id, stripe_checkout_session_id, checkout_expires_at, paid_at FROM orders WHERE id=$1", [n1.id])).rows[0];
    assert(d.stripe_account_id === "acct_test1" && d.stripe_checkout_session_id === "cs_test_1" && d.checkout_expires_at && d.paid_at === null, "narocilo: racun, seja, rok, brez paid_at", d);

    r = await api("POST", `/events/${ev}/orders`, T.bor, { quantity: 2 }, { "idempotency-key": kljuc });
    assert(r.status === 201 && r.body.order.id === n1.id && r.body.checkout_url === "https://checkout.stripe.test/c/pay/cs_test_1", "ponovitev z istim kljucem: isto narocilo, isti URL", r.body);
    assert(S.zahtevkiSej.length === 1, "ponovitev ni ustvarila nove seje", S.zahtevkiSej.length);
    r = await api("GET", "/me/orders", T.bor);
    assert(r.status === 200 && r.body.length === 1 && r.body[0].status === "pending" && r.body[0].checkout_url, "GET /me/orders: cakajoce narocilo s checkout_url", r.body);

    console.log("\n# Webhook: placilo uspelo");
    const s1 = S.seje.cs_test_1;
    r = await webhook("checkout.session.completed", { ...placana(s1, "pi_test_1"), amount_total: 2999 });
    assert(r.status === 200, "napacen znesek -> 200 (zabelezeno)", r);
    let o = (await pool.query("SELECT status FROM orders WHERE id=$1", [n1.id])).rows[0];
    assert(o.status === "pending", "napacen znesek: narocilo ostane pending", o);
    Object.assign(s1, placana(s1, "pi_test_1"));
    r = await webhook("checkout.session.completed", s1, { id: "evt_placilo_1" });
    assert(r.status === 200 && r.body.received, "checkout.session.completed -> 200", r);
    o = (await pool.query("SELECT status, paid_at, stripe_payment_intent_id FROM orders WHERE id=$1", [n1.id])).rows[0];
    assert(o.status === "paid" && o.paid_at && o.stripe_payment_intent_id === "pi_test_1", "narocilo paid, paid_at, PI", o);
    let vst = (await pool.query("SELECT COUNT(*)::int AS n FROM tickets WHERE order_id=$1", [n1.id])).rows[0].n;
    assert(vst === 2, "nastali 2 vstopnici", vst);
    r = await webhook("checkout.session.completed", s1, { id: "evt_placilo_1" });
    assert(r.status === 200 && r.body.duplicate === true, "isti dogodek drugic -> 200 duplicate", r.body);
    r = await webhook("checkout.session.completed", s1);
    assert(r.status === 200, "drug dogodek za isto sejo -> 200", r);
    vst = (await pool.query("SELECT COUNT(*)::int AS n FROM tickets WHERE order_id=$1", [n1.id])).rows[0].n;
    assert(vst === 2, "se vedno 2 vstopnici (idempotentno)", vst);
    r = await api("GET", "/me/orders", T.bor);
    assert(r.body[0].status === "paid" && r.body[0].tickets.length === 2 && r.body[0].tickets[0].qr && r.body[0].checkout_url === null, "kupec vidi placano narocilo z QR, brez checkout_url", r.body[0]);
    r = await api("POST", `/events/${ev}/orders`, T.bor, { quantity: 2 }, { "idempotency-key": kljuc });
    assert(r.status === 201 && r.body.tickets.length === 2 && r.body.order.status === "paid", "ponovitev kljuca po placilu: placano narocilo z vstopnicami", r.body);
    r = await api("GET", "/business/sales", T.lastnik, undefined, { "x-outly-club": "1" });
    assert(r.status === 200, "GET /business/sales deluje", r.body);

    console.log("\n# Webhook: seja potekla");
    const soldPred = await sold();
    r = await api("POST", `/events/${ev}/orders`, T.ana, { quantity: 1 });
    assert(r.status === 201 && r.body.mode === "stripe", "nakup 2 (stripe)", r.body);
    const n2 = r.body.order;
    assert(await sold() === soldPred + 1, "zaloga +1");
    r = await webhook("checkout.session.expired", { ...S.seje.cs_test_2, status: "expired" });
    assert(r.status === 200, "checkout.session.expired -> 200", r);
    o = (await pool.query("SELECT status, cancelled_at FROM orders WHERE id=$1", [n2.id])).rows[0];
    assert(o.status === "cancelled" && o.cancelled_at, "narocilo cancelled", o);
    assert(await sold() === soldPred, "zaloga sproscena");
    r = await api("GET", "/me/orders", T.ana);
    assert(!r.body.some(x => x.id === n2.id), "opusceno narocilo ni v /me/orders", r.body.map(x => x.id));
    r = await webhook("checkout.session.completed", placana(S.seje.cs_test_2, "pi_pozno"));
    o = (await pool.query("SELECT status FROM orders WHERE id=$1", [n2.id])).rows[0];
    assert(r.status === 200 && o.status === "cancelled", "placilo za preklicano narocilo ga ne obudi (zabelezeno za rocno vracilo)", o);
    assert(/POZOR: placilo za neaktivno narocilo/.test(log), "dnevnik opozori na rocno vracilo");

    console.log("\n# Stripe nedosegljiv");
    S.pokvarjeneSeje = true;
    const soldPred3 = await sold();
    r = await api("POST", `/events/${ev}/orders`, T.ana, { quantity: 1 });
    assert(r.status === 502, "Stripe pade -> 502", r);
    S.pokvarjeneSeje = false;
    o = (await pool.query("SELECT status FROM orders ORDER BY id DESC LIMIT 1")).rows[0];
    assert(o.status === "failed", "narocilo failed", o);
    assert(await sold() === soldPred3, "zaloga sproscena");

    console.log("\n# Vracila (charge.refunded)");
    r = await webhook("charge.refunded", { id: "ch_test_1", object: "charge", payment_intent: "pi_test_1", amount: 3000, amount_refunded: 1500, refunded: false });
    o = (await pool.query("SELECT status, refunded_cents FROM orders WHERE id=$1", [n1.id])).rows[0];
    assert(r.status === 200 && o.status === "partially_refunded" && o.refunded_cents === 1500, "delno vracilo", o);
    const soldPred4 = await sold();
    r = await webhook("charge.refunded", { id: "ch_test_1", object: "charge", payment_intent: "pi_test_1", amount: 3000, amount_refunded: 3000, refunded: true });
    o = (await pool.query("SELECT status, refunded_cents FROM orders WHERE id=$1", [n1.id])).rows[0];
    assert(o.status === "refunded" && o.refunded_cents === 3000, "polno vracilo", o);
    const vs = (await pool.query("SELECT status FROM tickets WHERE order_id=$1", [n1.id])).rows.map(x => x.status);
    assert(vs.every(s => s === "refunded"), "vstopnice refunded", vs);
    assert(await sold() === soldPred4 - 2, "zaloga sproscena (-2)");

    console.log("\n# Pospravljalec (izgubljen webhook)");
    r = await api("POST", `/events/${ev}/orders`, T.ana, { quantity: 1 });
    const n3 = r.body.order;   // seja ostane odprta -> pospravljalec jo pri Stripu zakljuci (expire) in preklice narocilo
    r = await api("POST", `/events/${ev}/orders`, T.bor, { quantity: 1 });
    const n4 = r.body.order;   // seja je bila placana, webhook se je izgubil -> pospravljalec vknjizi placilo
    const s4 = S.seje[(await pool.query("SELECT stripe_checkout_session_id FROM orders WHERE id=$1", [n4.id])).rows[0].stripe_checkout_session_id];
    Object.assign(s4, placana(s4, "pi_izgubljen"));
    await pool.query("UPDATE orders SET checkout_expires_at = NOW() - INTERVAL '10 minutes' WHERE id = ANY($1::bigint[])", [[n3.id, n4.id]]);
    let o3, o4;
    for (let i = 0; i < 40; i++) {
      await pocakaj(150);
      o3 = (await pool.query("SELECT status FROM orders WHERE id=$1", [n3.id])).rows[0];
      o4 = (await pool.query("SELECT status FROM orders WHERE id=$1", [n4.id])).rows[0];
      if (o3.status !== "pending" && o4.status !== "pending") break;
    }
    assert(o3.status === "cancelled", "odprta seja: pospravljalec jo zakljuci in preklice narocilo", o3);
    assert(S.potekle.length >= 1, "pospravljalec je klical expire", S.potekle);
    assert(o4.status === "paid", "placana seja brez webhooka: pospravljalec vknjizi placilo", o4);
    vst = (await pool.query("SELECT COUNT(*)::int AS n FROM tickets WHERE order_id=$1", [n4.id])).rows[0].n;
    assert(vst === 1, "in ustvari vstopnico", vst);

    console.log("\n# VIP miza prek Stripa");
    await pool.query("UPDATE events SET vip_enabled = TRUE WHERE id=$1", [ev]);
    await pool.query("INSERT INTO club_tables (club_id, label, x, y, w, h, seats, price_cents) VALUES (1, 'A1', 10, 10, 10, 10, 4, 20000)");
    const sejePrej = S.zahtevkiSej.length;
    r = await api("POST", `/events/${ev}/tables/1/orders`, T.ana, {});
    assert(r.status === 201 && r.body.mode === "stripe" && r.body.checkout_url && r.body.tickets.length === 0, "miza: 201 stripe, checkout_url, brez vstopnic", r.body);
    const nm = r.body.order;
    const Pm = S.zahtevkiSej[sejePrej].params;
    assert(Pm["line_items[0][price_data][unit_amount]"] === "20000" && Pm["payment_intent_data[application_fee_amount]"] === "2000", "miza: cena 200 EUR, provizija 20 EUR", Pm);
    r = await api("POST", `/events/${ev}/tables/1/orders`, T.bor, {});
    assert(r.status === 409, "cakajoce narocilo drzi mizo -> 409 za drugega", r);
    const sm = S.seje[(await pool.query("SELECT stripe_checkout_session_id FROM orders WHERE id=$1", [nm.id])).rows[0].stripe_checkout_session_id];
    r = await webhook("checkout.session.completed", placana(sm, "pi_miza"));
    vst = (await pool.query("SELECT COUNT(*)::int AS n FROM tickets WHERE order_id=$1", [nm.id])).rows[0].n;
    assert(r.status === 200 && vst === 4, "miza placana: 4 vstopnice (sedezi)", vst);

    console.log("\n# Neznan dogodek");
    r = await webhook("payment_intent.created", { id: "pi_x", object: "payment_intent" });
    assert(r.status === 200, "neznan dogodek -> 200", r);
  } catch (e) {
    fail++; console.error("NAPAKA TESTA:", e);
  } finally {
    srv.kill(); jwksServer.close(); stripeServer.close(); await pool.end();
    if (fail) console.log("\n--- dnevnik streznika ---\n" + log.split("\n").slice(-60).join("\n"));
    console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
    process.exit(fail ? 1 : 0);
  }
})();
