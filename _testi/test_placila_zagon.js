#!/usr/bin/env node
/**
 * Varovala pred zivo prodajo in pogodba za odjemalce (issue #191, #149). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_placila_zagon.js
 * Vzorec kot test_stripe.js: lokalni JWKS, lazni Stripe (STRIPE_API_BASE), vec backendov na svojih portih nad isto bazo.
 * Lazni Stripe posnema Stripovo omejitev: Checkout seja pod 0,50 EUR (tudi 0) je zavrnjena (po dokumentirani najmanjsi vrednosti,
 * NI preverjeno proti pravemu Stripu).
 *
 *   1  TEST_PLACILA=true ob sk_live_ ne vsili testnega nacina (#191): nakup kluba brez Stripa 409, gostje 503 (stikalo), POZOR v dnevniku; sandbox ga se vedno spostuje
 *   2  0 EUR pri klubu s Stripom (#191): vstopnica, VIP miza in gost gredo mimo Stripa (paid takoj, brez provizije, brez seje); zaloga, idempotenca, hkratnost
 *   3  payment_mode (#149): /events, /events/:id (gost in prijavljen enako, predpomnilnik), /events/:id/vip, /business/events; test | stripe | unavailable; brez uhajanja racuna
 *   4  potekel checkout_url (#149): ponovitev kljuca, GET /me/orders, GET /guest/order; placano tik pred rokom -> paid; Stripe nedosegljiv -> checkout_expired; omejitev klicev
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");
const Stripe = require("stripe");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT_S = 3211, PORT_L = 3212, PORT_N = 3213, PORT_T = 3214, PORT_P = 3215, JWKS_PORT = 3967, STRIPE_PORT = 3968;
const BS = `http://127.0.0.1:${PORT_S}`, BL = `http://127.0.0.1:${PORT_L}`, BN = `http://127.0.0.1:${PORT_N}`, BT = `http://127.0.0.1:${PORT_T}`, BP = `http://127.0.0.1:${PORT_P}`;
const WHSEC = "whsec_test_zagon";
const stripeLokalno = new Stripe("sk_test_lokalno");

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-zagon";
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
// SKLOP=4 (ali 2,4): samo izbrani sklopi (za diagnozo); privzeto vsi
const sklop = (n) => !process.env.SKLOP || process.env.SKLOP.split(",").includes(String(n));

// ---------- lazni Stripe ----------
const S = { racuni: {}, seje: {}, stSej: 0, zahtevkiSej: [], potekle: [], zavrniBranje: false, zamikBranja: 0, branjPoSeji: {} };
const stripeServer = http.createServer((req, res) => {
  let d = ""; req.on("data", x => d += x);
  req.on("end", () => {
    const p = Object.fromEntries(new URLSearchParams(d));
    const odg = (st, o) => { res.writeHead(st, { "content-type": "application/json", "request-id": "req_test" }); res.end(JSON.stringify(o)); };
    const u = req.url.split("?")[0];
    let m;
    if (req.method === "POST" && u === "/v1/checkout/sessions") {
      const kol = Number(p["line_items[0][quantity]"]), cena = Number(p["line_items[0][price_data][unit_amount]"]);
      S.zahtevkiSej.push({ params: p, znesek: kol * cena });
      // Stripe: najmanjsi znesek seje je 0,50 EUR (0 EUR ni dovoljen). Posnetek dokumentirane omejitve.
      if (kol * cena < 50) return odg(400, { error: { type: "invalid_request_error", code: "amount_too_small", message: "The Checkout Session's total amount due must add up to at least 0.50 EUR" } });
      const id = "cs_test_" + (++S.stSej);
      S.seje[id] = { id, object: "checkout.session", url: `https://checkout.stripe.test/c/pay/${id}`, status: "open", payment_status: "unpaid",
        amount_total: kol * cena, currency: p["line_items[0][price_data][currency]"], client_reference_id: p.client_reference_id,
        metadata: { order_id: p["metadata[order_id]"], public_ref: p["metadata[public_ref]"] }, expires_at: Number(p.expires_at), payment_intent: null };
      return odg(200, S.seje[id]);
    }
    if (req.method === "GET" && (m = u.match(/^\/v1\/checkout\/sessions\/(cs_\w+)$/))) {
      S.branjPoSeji[m[1]] = (S.branjPoSeji[m[1]] || 0) + 1;
      if (S.zavrniBranje) return odg(500, { error: { type: "api_error", message: "Stripe je padel" } });
      const odgovor = () => (S.seje[m[1]] ? odg(200, S.seje[m[1]]) : odg(404, { error: { type: "invalid_request_error", message: "No such session" } }));
      return S.zamikBranja ? setTimeout(odgovor, S.zamikBranja) : odgovor();
    }
    if (req.method === "POST" && (m = u.match(/^\/v1\/checkout\/sessions\/(cs_\w+)\/expire$/))) {
      if (S.seje[m[1]].status !== "open") return odg(400, { error: { type: "invalid_request_error", message: "Only open sessions can be expired" } });
      S.potekle.push(m[1]); S.seje[m[1]].status = "expired"; return odg(200, S.seje[m[1]]);
    }
    if (req.method === "GET" && (m = u.match(/^\/v1\/accounts\/(acct_\w+)$/))) return S.racuni[m[1]] ? odg(200, S.racuni[m[1]]) : odg(404, { error: { type: "invalid_request_error", message: "No such account" } });
    return odg(404, { error: { type: "invalid_request_error", message: "Lazni Stripe: neznana pot " + req.method + " " + u } });
  });
});
let stDogodka = 0;
async function webhook(baza, tip, objekt) {
  const dogodek = { id: `evt_zagon_${++stDogodka}`, object: "event", type: tip, data: { object: objekt }, created: Math.floor(Date.now() / 1000) };
  const payload = JSON.stringify(dogodek);
  const glava = stripeLokalno.webhooks.generateTestHeaderString({ payload, secret: WHSEC });
  const r = await fetch(baza + "/stripe/webhook", { method: "POST", headers: { "content-type": "application/json", "stripe-signature": glava }, body: payload });
  return { status: r.status };
}

function zagon(port, okolje) {
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test",
    APP_URL: "https://outly.test", STRIPE_API_BASE: `http://127.0.0.1:${STRIPE_PORT}`, STRIPE_POSPRAVI_MS: "3600000", TEST_PLACILA: "", STRIPE_SECRET_KEY: "", STRIPE_WEBHOOK_SECRET: "",
    GOST_NAKUP_LIVE: "", GOST_PREVZEM_MS: "0", ...okolje }, stdio: ["ignore", "pipe", "pipe"] });
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
  const sandbox = { STRIPE_SECRET_KEY: "sk_test_lokalno", STRIPE_WEBHOOK_SECRET: WHSEC, PREVERI_OKNO_MS: "0" };
  const A = zagon(PORT_S, sandbox);
  const L = zagon(PORT_L, { STRIPE_SECRET_KEY: "sk_live_lokalno", STRIPE_WEBHOOK_SECRET: WHSEC, TEST_PLACILA: "true" });
  const N = zagon(PORT_N, { TEST_PLACILA: "true" });
  const Tz = zagon(PORT_T, { ...sandbox, PREVERI_OKNO_MS: "60000", PREVERI_ROK_MS: "600" });
  // P: meja brezplacnih vstopnic 3 na osebo in dogodek (ZASTONJ_NA_OSEBO), pospravljalec na 500 ms (izgubljen webhook za odlozeno placilo), produkcijski RENDER (POZOR v dnevniku)
  const Pz = zagon(PORT_P, { ...sandbox, ZASTONJ_NA_OSEBO: "3", STRIPE_POSPRAVI_MS: "500", RENDER: "true", GOST_NAKUP_NA_URO: "1000" });
  const vsi = [A, L, N, Tz, Pz];
  const api = (m, p, t, b, g) => zahtevek(BS, m, p, t, b, g);
  const apiL = (m, p, t, b, g) => zahtevek(BL, m, p, t, b, g);
  const apiN = (m, p, t, b, g) => zahtevek(BN, m, p, t, b, g);
  const apiT = (m, p, t, b, g) => zahtevek(BT, m, p, t, b, g);
  const apiP = (m, p, t, b, g) => zahtevek(BP, m, p, t, b, g);
  for (const b of [BS, BL, BN, BT, BP]) await cakajStreznik(b);

  try {
    const T = {};
    const imena = ["lastnik", "lastnik2", "ana", "bor", "cene", "dana"];
    imena.forEach((k, i) => { T[k] = zeton(`${k}@outly.si`, uuid(i + 1)); });
    for (const k of imena) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='business' WHERE email IN ('lastnik@outly.si','lastnik2@outly.si')");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Stripe Club', 'Ljubljana')");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik2@outly.si'), 'Plain Club', 'Maribor')");
    // Klub 1 ima dokoncan Connect (racun v lazni bazi Stripa, da ga account.updated lahko ponovno prebere), klub 2 ga nima.
    S.racuni.acct_test1 = { id: "acct_test1", object: "account", charges_enabled: true, payouts_enabled: true, details_submitted: true, requirements: { currently_due: [], disabled_reason: null } };
    await pool.query("UPDATE clubs SET stripe_account_id='acct_test1', stripe_charges_enabled=TRUE, stripe_payouts_enabled=TRUE WHERE id=1");
    const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    const dogodek = async (klubToken, klub, title, cena, kapaciteta = 10) => {
      const r = await api("POST", "/events", klubToken, { clubId: klub, title, startAt: cezDan, ticketPriceCents: cena, capacity: kapaciteta, minAge: 0 });
      assert(r.status === 201, `dogodek ${title}`, r.body); return r.body.id;
    };
    const evStripe = await dogodek(T.lastnik, 1, "Placan", 1500);
    const evFree = await dogodek(T.lastnik, 1, "Brezplacen", 0, 3);
    const evFreeKonc = await dogodek(T.lastnik, 1, "Brezplacen hkrati", 0, 3);
    const evFreeGost = await dogodek(T.lastnik, 1, "Brezplacen za goste", 0, 5);
    const evFreeVip = await dogodek(T.lastnik, 1, "Brezplacna miza", 1500);
    const evPlain = await dogodek(T.lastnik2, 2, "Brez Stripa", 1500);
    const evFreeMax = await dogodek(T.lastnik, 1, "Brezplacen meja", 0, 100);
    const evFreeP = []; for (let i = 1; i <= 4; i++) evFreeP.push(await dogodek(T.lastnik, 1, `Brezplacen P${i}`, 0, 100));
    const evProc = []; for (let i = 1; i <= 5; i++) evProc.push(await dogodek(T.lastnik, 1, `V obdelavi ${i}`, 1500));
    const evX = []; for (let i = 1; i <= 8; i++) evX.push(await dogodek(T.lastnik, 1, `Potek ${i}`, 1500));
    const sold = async (id) => (await pool.query("SELECT sold_count FROM events WHERE id=$1", [id])).rows[0].sold_count;
    const vrstica = async (id) => (await pool.query("SELECT * FROM orders WHERE id=$1", [id])).rows[0];

    // ================================================================
    console.log("\n# 1. TEST_PLACILA=true ob sk_live_ ne vsili testnega nacina (#191)");
    if (sklop(1)) {
      const poZagonu = Date.now();
      while (!/\[placila\] POZOR: TEST_PLACILA=true/.test(L.log) && Date.now() - poZagonu < 4000) await pocakaj(100);
      assert(/\[placila\] POZOR: TEST_PLACILA=true je nastavljen ob ZIVEM Stripe kljucu/.test(L.log) && /IGNORIRAN/.test(L.log), "live + TEST_PLACILA: glasen POZOR v dnevniku ob zagonu", L.log.slice(0, 300));
      assert(!/\[placila\] POZOR/.test(A.log + N.log), "sandbox / brez kljuca: brez POZOR");
      let r = await apiL("POST", `/events/${evPlain}/orders`, T.ana, { quantity: 1 });
      assert(r.status === 409 && /does not accept online payments/.test(r.text), "live + TEST_PLACILA + klub brez Stripa: nakup 409 (ne testna vstopnica)", [r.status, r.text.slice(0, 80)]);
      assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1", [evPlain])).rows[0].n === 0, "brez narocila v bazi");
      r = await apiL("POST", `/guest/events/${evPlain}/orders`, null, { email: "gost@example.com", quantity: 1, accept_terms: true, terms_version: "2026-10-01" });
      assert(r.status === 503 && /Guest checkout is not available yet/.test(r.text), "live + TEST_PLACILA: gost brez GOST_NAKUP_LIVE 503 (stikalo ostane v veljavi)", [r.status, r.text.slice(0, 80)]);
      const stSej = S.zahtevkiSej.length;
      r = await apiL("POST", `/events/${evStripe}/orders`, T.ana, { quantity: 1 });
      assert(r.status === 201 && r.body.mode === "stripe" && r.body.checkout_url && r.body.tickets.length === 0, "live + TEST_PLACILA + klub s Stripom: pravi Stripe (checkout_url, brez vstopnic)", r.body);
      assert(S.zahtevkiSej.length === stSej + 1, "Stripe je bil klican");
      await pool.query("UPDATE orders SET status='cancelled', cancelled_at=NOW() WHERE id=$1", [r.body.order.id]);
      r = await apiL("GET", "/business/sales", T.lastnik, undefined, { "x-outly-club": "1" });
      assert(r.status === 200 && r.body.mode === "live" && r.body.payment_mode === "stripe", "dashboard: mode live (TEST_PLACILA ignoriran), payment_mode kluba stripe", [r.body.mode, r.body.payment_mode]);
      r = await apiL("GET", `/events/${evPlain}`);
      assert(r.status === 200 && r.body.payment_mode === "unavailable", "live: dogodek kluba brez Stripa payment_mode unavailable", r.body.payment_mode);
      r = await apiL("GET", `/events/${evStripe}`);
      assert(r.status === 200 && r.body.payment_mode === "stripe", "live: dogodek kluba s Stripom payment_mode stripe", r.body.payment_mode);
      // Sandbox: TEST_PLACILA se spostuje (ni v produkcijski vrsti); brez kljuca: test
      r = await apiN("POST", `/events/${evPlain}/orders`, T.ana, { quantity: 1 });
      assert(r.status === 201 && r.body.mode === "test", "brez kljuca + TEST_PLACILA=true: testni nacin kot doslej", r.body.mode);
    }

    // ================================================================
    console.log("\n# 2. 0 EUR pri klubu s Stripom gre mimo Stripa (#191)");
    if (sklop(2)) {
      await pool.query("TRUNCATE omejitve");
      const stSej = S.zahtevkiSej.length;
      const K = kljuc();
      let r = await api("POST", `/events/${evFree}/orders`, T.ana, { quantity: 2 }, { "idempotency-key": K });
      assert(r.status === 201 && r.body.mode === "stripe" && r.body.order.status === "paid" && r.body.tickets.length === 2, "brezplacna vstopnica: 201, paid takoj, 2 vstopnici", r.body);
      assert(r.body.checkout_url === null && r.body.order.total_cents === 0 && r.body.order.is_test === false, "brez checkout_url, 0 c, ni testno narocilo", r.body);
      assert(S.zahtevkiSej.length === stSej, "Stripe ni bil klican (0 EUR gre mimo Checkouta)", S.zahtevkiSej.slice(stSej));
      const id = r.body.order.id;
      const v = await vrstica(id);
      assert(v.status === "paid" && v.paid_at && v.total_cents === 0 && v.application_fee_cents === 0, "baza: paid, paid_at, brez provizije", v);
      assert(v.stripe_checkout_session_id === null && v.stripe_payment_intent_id === null && v.stripe_account_id === null && v.checkout_url === null, "baza: brez Stripove seje, PI in racuna");
      assert(await sold(evFree) === 2, "sold_count 2");
      r = await api("POST", `/events/${evFree}/orders`, T.ana, { quantity: 2 }, { "idempotency-key": K });
      assert(r.status === 201 && r.headers.get("idempotent-replayed") === "true" && r.body.order.id === id && r.body.tickets.length === 2, "ponovitev istega kljuca: isto narocilo", r.status);
      assert(await sold(evFree) === 2 && S.zahtevkiSej.length === stSej, "ponovitev ne porabi zaloge in ne klice Stripa");
      r = await api("POST", `/events/${evFree}/orders`, T.bor, { quantity: 2 });
      assert(r.status === 409 && /Only 1 tickets left/.test(r.text), "zaloga velja tudi za brezplacne: 409 Only 1 tickets left", [r.status, r.text]);
      r = await api("POST", `/events/${evFree}/orders`, T.bor, { quantity: 1 });
      assert(r.status === 201 && await sold(evFree) === 3, "zadnja vstopnica 201, sold_count == capacity");
      r = await api("POST", `/events/${evFree}/orders`, T.cene, { quantity: 1 });
      assert(r.status === 409 && await sold(evFree) === 3, "razprodano: 409, brez oversell");
      const pred = (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1 AND status='failed'", [evFree])).rows[0].n;
      assert(pred === 0, "brez failed narocil (nic ni sla v Stripe)");

      // hkratnost: 5 hkratnih nakupov, kapaciteta 3
      const rs = await Promise.all(["ana", "bor", "cene", "ana", "bor"].map((k) => api("POST", `/events/${evFreeKonc}/orders`, T[k], { quantity: 1 })));
      assert(rs.filter(x => x.status === 201).length === 3 && rs.filter(x => x.status === 409).length === 2, "5 hkratnih brezplacnih na kapaciteto 3: natanko 3 uspejo", rs.map(x => x.status));
      assert(await sold(evFreeKonc) === 3, "sold_count == 3 (brez oversell)");

      // kontrola: placan dogodek istega kluba gre v Stripe
      const st2 = S.zahtevkiSej.length;
      r = await api("POST", `/events/${evStripe}/orders`, T.bor, { quantity: 1 });
      assert(r.status === 201 && r.body.mode === "stripe" && r.body.checkout_url && S.zahtevkiSej.length === st2 + 1 && S.zahtevkiSej[st2].znesek === 1500, "kontrola: placan dogodek (1500 c) gre v Stripe", r.body);
      await pool.query("UPDATE orders SET status='cancelled', cancelled_at=NOW() WHERE id=$1", [r.body.order.id]);

      // VIP miza za 0 EUR
      await pool.query("UPDATE events SET vip_enabled = TRUE WHERE id=$1", [evFreeVip]);
      const miza = (await pool.query("INSERT INTO club_tables (club_id, label, x, y, w, h, seats, price_cents) VALUES (1,'F1',0,0,2,2,2,0) RETURNING id")).rows[0].id;
      const mizaPlacana = (await pool.query("INSERT INTO club_tables (club_id, label, x, y, w, h, seats, price_cents) VALUES (1,'P1',0,0,2,2,4,30000) RETURNING id")).rows[0].id;
      const st3 = S.zahtevkiSej.length;
      r = await api("POST", `/events/${evFreeVip}/tables/${miza}/orders`, T.ana, {});
      assert(r.status === 201 && r.body.order.status === "paid" && r.body.tickets.length === 2 && r.body.checkout_url === null && r.body.order.total_cents === 0, "brezplacna VIP miza: 201, paid, 2 vstopnici", r.body);
      assert(S.zahtevkiSej.length === st3, "VIP 0 EUR: Stripe ni klican");
      r = await api("POST", `/events/${evFreeVip}/tables/${miza}/orders`, T.bor, {});
      assert(r.status === 409 && /already booked/.test(r.text), "ista miza drugic: 409 (I13 velja)", [r.status, r.text]);
      r = await api("POST", `/events/${evFreeVip}/tables/${mizaPlacana}/orders`, T.bor, {});
      assert(r.status === 201 && r.body.mode === "stripe" && r.body.checkout_url && S.zahtevkiSej.length === st3 + 1, "kontrola: placana miza gre v Stripe", r.body);
      await pool.query("UPDATE orders SET status='cancelled', cancelled_at=NOW() WHERE id=$1", [r.body.order.id]);

      // gost, 0 EUR
      const st4 = S.zahtevkiSej.length;
      r = await api("POST", `/guest/events/${evFreeGost}/orders`, null, { email: "gost.brezplacno@example.com", quantity: 2, accept_terms: true, terms_version: "2026-10-01" });
      assert(r.status === 201 && r.body.order.status === "paid" && r.body.tickets.length === 2 && typeof r.body.guest_token === "string" && r.body.checkout_url === null, "gost, 0 EUR: 201, paid, vstopnici, zeton", r.body);
      assert(S.zahtevkiSej.length === st4, "gost 0 EUR: Stripe ni klican");
      const gv = await vrstica(r.body.order.id);
      assert(gv.status === "paid" && gv.application_fee_cents === 0 && gv.stripe_checkout_session_id === null && gv.receipt_mail_attempts === null, "gost: baza paid brez seje, potrdilo racuna ni dolgovano (ima svoj mail)", gv);
      const gk = kljuc();
      const g1 = await api("POST", `/guest/events/${evFreeGost}/orders`, null, { email: "gost.dva@example.com", quantity: 1, accept_terms: true, terms_version: "2026-10-01" }, { "idempotency-key": gk });
      const g2 = await api("POST", `/guest/events/${evFreeGost}/orders`, null, { email: "gost.dva@example.com", quantity: 1, accept_terms: true, terms_version: "2026-10-01" }, { "idempotency-key": gk });
      assert(g1.status === 201 && g2.status === 201 && g2.body.order.id === g1.body.order.id && await sold(evFreeGost) === 3, "gost: idempotentna ponovitev brezplacnega nakupa je isto narocilo", [g1.status, g2.status]);
      r = await api("GET", "/me/orders", T.ana);
      assert(r.status === 200 && r.body.some(x => x.status === "paid" && x.total_cents === 0 && x.tickets.length === 2 && x.checkout_url === null), "GET /me/orders: brezplacno narocilo je paid z vstopnicami");
    }

    // ================================================================
    console.log("\n# 3. payment_mode v javnih odgovorih (#149)");
    if (sklop(3)) {
      const nima = (o) => !/acct_|stripe_account_id|club_stripe_ready|stripe_charges_enabled/.test(typeof o === "string" ? o : JSON.stringify(o));
      let r = await api("GET", `/events/${evPlain}`);
      assert(r.status === 200 && r.body.payment_mode === "test", "sandbox + klub brez Stripa: test", r.body.payment_mode);
      r = await api("GET", `/events/${evStripe}`);
      assert(r.status === 200 && r.body.payment_mode === "stripe" && nima(r.text), "sandbox + klub s Stripom: stripe, brez uhajanja racuna", r.body.payment_mode);
      const rA = await api("GET", `/events/${evStripe}`, T.ana);
      assert(rA.status === 200 && rA.body.payment_mode === "stripe" && nima(rA.text), "isto za prijavljenega (predpomnjen javni del, I17)");
      assert(rA.body.my_plan === null && Array.isArray(rA.body.friends_going), "osebna polja se ne mešajo");
      r = await api("GET", "/events");
      const poId = (id) => r.body.find(x => x.id === id);
      assert(r.status === 200 && r.body.length >= 8 && r.body.every(x => ["test", "stripe", "unavailable"].includes(x.payment_mode)), "GET /events: vsak dogodek ima payment_mode", r.body.map(x => x.payment_mode));
      assert(poId(evPlain).payment_mode === "test" && poId(evStripe).payment_mode === "stripe" && nima(r.text), "GET /events: pravilne vrednosti, brez uhajanja");
      r = await api("GET", "/events?lite=true");
      assert(r.status === 200 && poId(evStripe).payment_mode === "stripe" && !("description" in poId(evStripe)) && nima(r.text), "GET /events?lite=true: payment_mode, brez description, brez uhajanja");
      r = await api("GET", "/events?clubId=2");
      assert(r.status === 200 && r.body.length === 1 && r.body[0].payment_mode === "test" && r.body[0].hosted === false, "GET /events?clubId=: payment_mode + hosted ostane");
      r = await api("GET", `/events/${evFreeVip}/vip`);
      assert(r.status === 200 && r.body.payment_mode === "stripe" && r.body.enabled === true && nima(r.text), "GET /events/:id/vip: payment_mode stripe", r.body.payment_mode);
      r = await api("GET", `/events/${evPlain}/vip`);
      assert(r.status === 200 && r.body.payment_mode === "test", "GET /events/:id/vip: klub brez Stripa -> test", r.body.payment_mode);
      r = await api("GET", "/business/events", T.lastnik, undefined, { "x-outly-club": "1" });
      assert(r.status === 200 && r.body.length >= 5 && r.body.every(x => x.payment_mode === "stripe") && nima(r.text), "GET /business/events: payment_mode kluba, brez uhajanja");
      r = await api("GET", "/business/sales", T.lastnik, undefined, { "x-outly-club": "1" });
      assert(r.status === 200 && r.body.payment_mode === "stripe", "GET /business/sales: payment_mode kluba (dodano polje, mode ostane)", [r.body.mode, r.body.payment_mode]);
      r = await api("GET", "/business/sales", T.lastnik2, undefined, { "x-outly-club": "2" });
      assert(r.status === 200 && r.body.payment_mode === "test" && r.body.mode === "live", "klub brez Stripa v sandboxu: payment_mode test", [r.body.mode, r.body.payment_mode]);
      r = await apiN("GET", `/events/${evStripe}`);
      assert(r.status === 200 && r.body.payment_mode === "test", "brez kljuca: tudi klub s Stripom v bazi kaze test (nic se ne zaracuna)", r.body.payment_mode);

      // Nedokoncan onboarding (account.updated) takoj spremeni vrednost: webhook je zapis, javni predpomnilnik se razveljavi (I17)
      S.racuni.acct_test1.charges_enabled = false;
      const w = await webhook(BS, "account.updated", { id: "acct_test1", object: "account" });
      assert(w.status === 200, "webhook account.updated 200");
      r = await api("GET", `/events/${evStripe}`);
      assert(r.body.payment_mode === "test", "klub izgubi charges_enabled -> test (predpomnilnik razveljavljen)", r.body.payment_mode);
      S.racuni.acct_test1.charges_enabled = true;
      await webhook(BS, "account.updated", { id: "acct_test1", object: "account" });
      r = await api("GET", `/events/${evStripe}`);
      assert(r.body.payment_mode === "stripe", "ponovno charges_enabled -> stripe", r.body.payment_mode);

      // Enota: kaj ne sme biti "stripe/test"
      const { javniNacin, nacinPlacilaZ } = require("../placila_stripe");
      const shrani = { ...process.env };
      for (const k of ["TEST_PLACILA", "STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET"]) delete process.env[k];
      process.env.STRIPE_SECRET_KEY = "sk_live_x";
      assert(javniNacin(nacinPlacilaZ(true)) === "unavailable", "kljuc brez webhook skrivnosti (503 ob nakupu) -> unavailable");
      process.env.STRIPE_WEBHOOK_SECRET = "whsec";
      assert(javniNacin(nacinPlacilaZ(false)) === "unavailable" && javniNacin(nacinPlacilaZ(true)) === "stripe", "live: klub brez Stripa unavailable, s Stripom stripe");
      for (const k of Object.keys(process.env)) if (!(k in shrani)) delete process.env[k];
      Object.assign(process.env, shrani);
    }

    // ================================================================
    console.log("\n# 4. Potekel checkout_url (#149)");
    if (sklop(4)) {
      await pool.query("TRUNCATE omejitve");   // omejevalnik nakupov (20/h/IP) je skupen vsem sklopom in instancam
      // Rok seje je potekel pred 3 min (odlog preverjanja je 2 min, sredi 3DS ne sprasujemo); Stripe seje po roku sam zapre (emulacija: status expired).
      const sejaOd = async (id) => (await vrstica(id)).stripe_checkout_session_id;
      const potekni = async (id, { stripeZapre = true } = {}) => {
        await pool.query("UPDATE orders SET checkout_expires_at = NOW() - INTERVAL '3 minutes' WHERE id=$1", [id]);
        const sid = await sejaOd(id);
        if (stripeZapre && sid && S.seje[sid] && S.seje[sid].status === "open") S.seje[sid].status = "expired";
      };

      // 4a: seja se ni potekla -> checkout_url + checkout_expired false; po poteku Stripe seja potece -> cancelled
      const K1 = kljuc();
      let r = await api("POST", `/events/${evX[0]}/orders`, T.ana, { quantity: 1 }, { "idempotency-key": K1 });
      assert(r.status === 201 && r.body.mode === "stripe" && /^https:\/\/checkout\.stripe\.test\//.test(r.body.checkout_url) && r.body.order.checkout_expired === false, "nakup: checkout_url + checkout_expired false", r.body);
      const o1 = r.body.order.id;
      r = await api("GET", "/me/orders", T.ana);
      let x = r.body.find(y => y.id === o1);
      assert(x && x.status === "pending" && /^https:\/\//.test(x.checkout_url) && x.checkout_expired === false, "GET /me/orders pred potekom: checkout_url + checkout_expired false", x);
      r = await api("POST", `/events/${evX[0]}/orders`, T.ana, { quantity: 1 }, { "idempotency-key": K1 });
      assert(r.status === 201 && r.headers.get("idempotent-replayed") === "true" && /^https:\/\//.test(r.body.checkout_url), "ponovitev pred potekom: isti checkout_url", r.status);
      await potekni(o1);
      r = await api("POST", `/events/${evX[0]}/orders`, T.ana, { quantity: 1 }, { "idempotency-key": K1 });
      assert(r.status === 409 && r.body.error === "order_not_active", "ponovitev PO poteku seje: 409 order_not_active (ne potekel checkout_url)", [r.status, r.body]);
      assert((await vrstica(o1)).status === "cancelled" && !S.potekle.includes(await sejaOd(o1)), "narocilo takoj preklicano po Stripovi potekli seji (ne caka na pospravljalca); expire() se ne klice");
      assert(await sold(evX[0]) === 0, "zaloga sproscena");

      // 4b: placano tik pred rokom (webhook se ni prisel): GET /me/orders ga vknjizi
      const K2 = kljuc();
      r = await api("POST", `/events/${evX[1]}/orders`, T.ana, { quantity: 1 }, { "idempotency-key": K2 });
      const o2 = r.body.order.id, s2 = await sejaOd(o2);
      await potekni(o2);
      S.seje[s2] = { ...S.seje[s2], status: "complete", payment_status: "paid", payment_intent: "pi_zagon_2" };
      r = await api("GET", "/me/orders", T.ana);
      x = r.body.find(y => y.id === o2);
      assert(x && x.status === "paid" && x.checkout_url === null && x.checkout_expired === false && x.tickets.length === 1, "GET /me/orders po poteku: Stripe pove placano -> paid z vstopnico", x);
      r = await api("POST", `/events/${evX[1]}/orders`, T.ana, { quantity: 1 }, { "idempotency-key": K2 });
      assert(r.status === 201 && r.headers.get("idempotent-replayed") === "true" && r.body.order.status === "paid" && r.body.tickets.length === 1 && r.body.checkout_url === null, "ponovitev: placano narocilo z vstopnico", r.body);

      // 4c: Stripe nedosegljiv: povezave ne vracamo, jasno stanje checkout_expired
      const K3 = kljuc();
      r = await api("POST", `/events/${evX[2]}/orders`, T.ana, { quantity: 1 }, { "idempotency-key": K3 });
      const o3 = r.body.order.id;
      await potekni(o3);
      S.zavrniBranje = true;
      r = await api("GET", "/me/orders", T.ana);
      x = r.body.find(y => y.id === o3);
      assert(r.status === 200 && x && x.status === "pending" && x.checkout_url === null && x.checkout_expired === true, "Stripe nedosegljiv: pending, checkout_url null, checkout_expired true", x);
      r = await api("POST", `/events/${evX[2]}/orders`, T.ana, { quantity: 1 }, { "idempotency-key": K3 });
      assert(r.status === 409 && r.body.error === "request_in_progress" && r.headers.get("retry-after"), "ponovitev ob nedosegljivem Stripu: 409 request_in_progress + Retry-After (ne potekel URL)", [r.status, r.body]);
      S.zavrniBranje = false;
      r = await api("GET", "/me/orders", T.ana);
      assert(!r.body.some(y => y.id === o3) && (await vrstica(o3)).status === "cancelled", "Stripe spet dosegljiv: narocilo preklicano in izpade iz seznama");

      // 4d: gost
      const gost = (email, ev, glave = {}) => api("POST", `/guest/events/${ev}/orders`, null, { email, quantity: 1, accept_terms: true, terms_version: "2026-10-01" }, glave);
      r = await gost("potek.eden@example.com", evX[3]);
      assert(r.status === 201 && r.body.mode === "stripe" && r.body.checkout_url && r.body.order.checkout_expired === false, "gost: checkout_url + checkout_expired false", r.body);
      const og = r.body.order.id, zg = r.body.guest_token;
      await potekni(og);
      r = await api("GET", "/guest/order", null, undefined, { "x-guest-token": zg });
      assert(r.status === 200 && r.body.order.status === "cancelled" && r.body.order.checkout_url === null && r.body.order.checkout_expired === false, "GET /guest/order po poteku: preverjeno pri Stripu, cancelled, brez potekle povezave", r.body.order);
      const Kg = kljuc();
      r = await gost("potek.dva@example.com", evX[4], { "idempotency-key": Kg });
      const og2 = r.body.order.id;
      await potekni(og2);
      r = await gost("potek.dva@example.com", evX[4], { "idempotency-key": Kg });
      assert(r.status === 409 && r.body.error === "order_not_active", "gost: ponovitev kljuca po poteku seje -> 409 order_not_active", [r.status, r.body]);
      r = await gost("potek.tri@example.com", evX[4]);
      const og3 = r.body.order.id, zg3 = r.body.guest_token, sg3 = await sejaOd(og3);
      await potekni(og3);
      S.seje[sg3] = { ...S.seje[sg3], status: "complete", payment_status: "paid", payment_intent: "pi_zagon_g3" };
      r = await api("GET", "/guest/order", null, undefined, { "x-guest-token": zg3 });
      assert(r.status === 200 && r.body.order.status === "paid" && r.body.tickets.length === 1 && r.body.order.checkout_url === null, "gost: placano tik pred rokom -> paid z vstopnico", r.body);

      // 4e: omejitev klicev Stripa (instanca T: razmik 60 s po narocilu)
      r = await apiT("POST", `/events/${evX[5]}/orders`, T.bor, { quantity: 1 });
      const o5 = r.body.order.id, s5 = await sejaOd(o5);
      await potekni(o5);
      S.zavrniBranje = true;
      const branj = [];
      for (let i = 0; i < 3; i++) {
        r = await apiT("GET", "/me/orders", T.bor);
        x = r.body.find(y => y.id === o5);
        assert(x && x.checkout_url === null && x.checkout_expired === true, `omejitev: poziv ${i + 1} vrne checkout_expired`, x);
        branj.push(S.branjPoSeji[s5] || 0);
      }
      // Stripov paket ob napaki 500 sam ponovi klic (maxNetworkRetries 2): en logicni klic = do 3 zahtevkov. Drugi in tretji GET /me/orders Stripa sploh ne klicata.
      assert(branj[0] > 0 && branj[0] <= 3 && branj[1] === branj[0] && branj[2] === branj[0], "omejitev: Stripe poklican enkrat na okno (ne ob vsakem branju)", branj);
      S.zavrniBranje = false;
      await pool.query("UPDATE orders SET status='cancelled', cancelled_at=NOW() WHERE id=$1", [o5]);

      // 4g: pocasen Stripe ne zadrzi odgovora: cakanje je omejeno (PREVERI_ROK_MS), preverjanje se konca v ozadju
      r = await apiT("POST", `/events/${evX[7]}/orders`, T.bor, { quantity: 1 });
      assert(r.status === 201, "4g: nakup na instanci T", [r.status, r.text]);
      const o8 = r.body.order.id;
      await potekni(o8);
      S.zamikBranja = 2500;
      r = await apiT("GET", "/me/orders", T.bor);
      x = r.body.find(y => y.id === o8);
      // Brez omejitve cakanja bi odgovor pocakal Stripa (2,5 s) in naroclio bi bilo ze cancelled (izpadlo iz seznama); casovne meje ne merimo (flake), dokaz je stanje.
      assert(r.status === 200 && x && x.status === "pending" && x.checkout_url === null && x.checkout_expired === true, "pocasen Stripe: GET /me/orders vrne brez cakanja na Stripe, checkout_expired", [x && x.status]);
      assert(await (async () => { for (let i = 0; i < 50; i++) { if ((await vrstica(o8)).status === "cancelled") return true; await pocakaj(100); } return false; })(), "preverjanje se konca v ozadju: narocilo preklicano");
      S.zamikBranja = 0;

      // 4f: zasebnost: tuj uporabnik ne sproziva preverjanja tujih narocil
      r = await api("POST", `/events/${evX[6]}/orders`, T.cene, { quantity: 1 });
      const o6 = r.body.order.id, s6 = await sejaOd(o6);
      await potekni(o6);
      const pred6 = S.branjPoSeji[s6] || 0;
      r = await api("GET", "/me/orders", T.ana);
      assert((S.branjPoSeji[s6] || 0) === pred6 && !r.body.some(y => y.id === o6), "GET /me/orders drugega uporabnika ne sprozi preverjanja tujega narocila in ga ne vrne");
      await pool.query("UPDATE orders SET status='cancelled', cancelled_at=NOW() WHERE id=$1", [o6]);
    }
    // ================================================================
    console.log("\n# 5. Meja brezplacnih vstopnic na osebo in dogodek (ZASTONJ_NA_OSEBO)");
    if (sklop(5)) {
      await pool.query("TRUNCATE omejitve");
      let r = await api("POST", `/events/${evFreeMax}/orders`, T.dana, { quantity: 6 });
      assert(r.status === 201, "privzeta meja 10: 6 vstopnic 201", r.status);
      r = await api("POST", `/events/${evFreeMax}/orders`, T.dana, { quantity: 4 });
      assert(r.status === 201, "skupaj 10: 4 vstopnice se 201", r.status);
      r = await api("POST", `/events/${evFreeMax}/orders`, T.dana, { quantity: 1 });
      assert(r.status === 409 && r.body.error === "free_limit" && /at most 10 free tickets/.test(r.body.message), "11. brezplacna: 409 free_limit z jasnim sporocilom", r.body);
      r = await api("POST", `/events/${evFreeMax}/orders`, T.bor, { quantity: 1 });
      assert(r.status === 201, "drug uporabnik je neodvisen: 201");
      assert((await pool.query("SELECT COALESCE(SUM(quantity),0)::int AS n FROM orders WHERE event_id=$1 AND user_id=(SELECT id FROM users WHERE email='dana@outly.si')", [evFreeMax])).rows[0].n === 10, "dana ima natanko 10");

      // instanca P: meja 3. Uporabnik, hkratnost, VIP, gost
      await pool.query("TRUNCATE omejitve");
      r = await apiP("POST", `/events/${evFreeP[0]}/orders`, T.ana, { quantity: 2 });
      assert(r.status === 201, "P: 2 od 3");
      r = await apiP("POST", `/events/${evFreeP[0]}/orders`, T.ana, { quantity: 2 });
      assert(r.status === 409 && r.body.error === "free_limit" && /1 left for you/.test(r.body.message), "P: 2 + 2 > 3: 409 free_limit (ostane 1)", r.body);
      r = await apiP("POST", `/events/${evFreeP[1]}/orders`, T.ana, { quantity: 3 });
      assert(r.status === 201, "P: meja je na dogodek: drug dogodek 201");
      const hk = await Promise.all(Array.from({ length: 8 }, () => apiP("POST", `/events/${evFreeP[2]}/orders`, T.bor, { quantity: 1 })));
      assert(hk.filter(x => x.status === 201).length === 3 && hk.filter(x => x.status === 409 && x.body.error === "free_limit").length === 5, "P: 8 hkratnih ene vstopnice: natanko 3 uspejo (zaklep)", hk.map(x => x.status));
      // VIP miza za 0 EUR steje 1
      await pool.query("UPDATE events SET vip_enabled = TRUE WHERE id=$1", [evFreeP[3]]);
      const mize = []; for (let i = 1; i <= 4; i++) mize.push((await pool.query("INSERT INTO club_tables (club_id, label, x, y, w, h, seats, price_cents) VALUES (1,$1,0,0,2,2,8,0) RETURNING id", ["Z" + i])).rows[0].id);
      const vr = [];
      for (const m of mize) vr.push(await apiP("POST", `/events/${evFreeP[3]}/tables/${m}/orders`, T.cene, {}));
      assert(vr.slice(0, 3).every(x => x.status === 201) && vr[3].status === 409 && vr[3].body.error === "free_limit", "P: VIP mize za 0 EUR: 3 uspejo (ne glede na sedeze), 4. 409 free_limit", vr.map(x => x.status));
      // gost: normaliziran e-naslov (+oznaka, gmail pike, googlemail)
      const gost = (email, q = 1) => apiP("POST", `/guest/events/${evFreeP[0]}/orders`, null, { email, quantity: q, accept_terms: true, terms_version: "2026-10-01" });
      r = await gost("Gost.Test+a@gmail.com", 2);
      assert(r.status === 201, "P gost: 2 od 3");
      r = await gost("gosttest+b@gmail.com", 2);
      assert(r.status === 409 && r.body.error === "free_limit", "P gost: isti nabiralnik z drugo +oznako in brez pike steje skupaj: 409 free_limit", r.body);
      r = await gost("g.o.s.t.t.e.s.t@googlemail.com", 2);
      assert(r.status === 409 && r.body.error === "free_limit", "P gost: googlemail s pikami je isti nabiralnik: 409", r.body);
      r = await gost("gosttest@gmail.com", 1);
      assert(r.status === 201, "P gost: tretja vstopnica se 201");
      r = await gost("drug@example.com", 3);
      assert(r.status === 201, "P gost: drug naslov je neodvisen");
      const hg = await Promise.all(Array.from({ length: 6 }, () => gost("hkrati@example.com", 1)));
      assert(hg.filter(x => x.status === 201).length === 3, "P gost: 6 hkratnih istega naslova: natanko 3 (zaklep)", hg.map(x => x.status));
    }

    // ================================================================
    console.log("\n# 6. Odlozeno placilo, odlog preverjanja (3DS) in opozorilo v produkciji");
    if (sklop(6)) {
      await pool.query("TRUNCATE omejitve");
      const sejaOd = async (id) => (await vrstica(id)).stripe_checkout_session_id;
      // produkcija s sandbox kljucem: glasen POZOR, brez blokade; live in lokalni zagon sta tiha
      assert(/\[placila\] POZOR: placila v TESTNEM nacinu — vstopnice brez placila \(sandbox kljuc sk_test_\)/.test(Pz.log), "RENDER + sk_test_: POZOR ob zagonu", Pz.log.slice(0, 200));
      assert((Pz.log.match(/\[placila\] POZOR: placila v TESTNEM/g) || []).length === 1, "POZOR natanko enkrat");
      assert(!/\[placila\] POZOR: placila v TESTNEM/.test(A.log + L.log), "lokalni zagon (brez RENDER) in live ključ: brez tega POZOR");
      let r = await apiP("POST", `/events/${evPlain}/orders`, T.ana, { quantity: 1 });
      assert(r.status === 201 && r.body.mode === "test", "produkcijski nacin se vedno prodaja testno (brez blokade)", r.body.mode);

      // 3DS: seja je dve minuti po roku se odprta -> Stripa ne sprasujemo, expire() se ne klice
      r = await api("POST", `/events/${evProc[0]}/orders`, T.ana, { quantity: 1 }, { "idempotency-key": kljuc() });
      const oA = r.body.order.id, sA = await sejaOd(oA);
      await pool.query("UPDATE orders SET checkout_expires_at = NOW() - INTERVAL '30 seconds' WHERE id=$1", [oA]);
      let prej = S.branjPoSeji[sA] || 0;
      r = await api("GET", "/me/orders", T.ana);
      let x = r.body.find(y => y.id === oA);
      assert(x && x.status === "pending" && x.checkout_url === null && x.checkout_expired === true && x.payment_processing === false, "30 s po roku: checkout_expired, ne v obdelavi", x);
      assert((S.branjPoSeji[sA] || 0) === prej && !S.potekle.includes(sA), "30 s po roku (morda sredi 3DS): Stripa ne sprasujemo, expire() se ne klice");
      await pool.query("UPDATE orders SET checkout_expires_at = NOW() - INTERVAL '3 minutes' WHERE id=$1", [oA]);
      r = await api("GET", "/me/orders", T.ana);
      x = r.body.find(y => y.id === oA);
      assert((S.branjPoSeji[sA] || 0) > prej && !S.potekle.includes(sA) && x && x.status === "pending", "3 min po roku, seja pri Stripu se odprta: vprasamo, a expire() NE (to je naloga pospravljalca)", [x && x.status]);
      await pool.query("UPDATE orders SET status='cancelled', cancelled_at=NOW() WHERE id=$1", [oA]);

      // Odlozeno placilo: webhook completed + unpaid
      const obdelavi = [];
      for (let i = 1; i <= 3; i++) {
        const k = kljuc();
        r = await api("POST", `/events/${evProc[i]}/orders`, T.bor, { quantity: 1 }, { "idempotency-key": k });
        const o = r.body.order.id, sid = await sejaOd(o);
        S.seje[sid] = { ...S.seje[sid], status: "complete", payment_status: "unpaid", payment_intent: "pi_odl_" + i };
        const w = await webhook(BS, "checkout.session.completed", S.seje[sid]);
        assert(w.status === 200, `odlozeno placilo ${i}: webhook completed + unpaid 200`);
        obdelavi.push({ o, sid, k, ev: evProc[i] });
      }
      const b1 = obdelavi[0];
      r = await api("GET", "/me/orders", T.bor);
      x = r.body.find(y => y.id === b1.o);
      assert(x && x.status === "pending" && x.checkout_url === null && x.checkout_expired === false && x.payment_processing === true && x.tickets.length === 0, "odlozeno placilo: pending, brez povezave, payment_processing true, NI checkout_expired", x);
      await pool.query("UPDATE orders SET checkout_expires_at = NOW() - INTERVAL '10 minutes' WHERE id=$1", [b1.o]);
      prej = S.branjPoSeji[b1.sid] || 0;
      r = await api("GET", "/me/orders", T.bor);
      x = r.body.find(y => y.id === b1.o);
      assert(x && x.payment_processing === true && x.checkout_expired === false && (S.branjPoSeji[b1.sid] || 0) === prej && !S.potekle.includes(b1.sid), "po roku seje: se vedno v obdelavi, Stripa ne sprasujemo, expire() se ne klice", x);
      r = await api("POST", `/events/${b1.ev}/orders`, T.bor, { quantity: 1 }, { "idempotency-key": b1.k });
      assert(r.status === 409 && r.body.error === "request_in_progress", "ponovitev ključa za narocilo v obdelavi: 409 request_in_progress (ne potekla povezava)", [r.status, r.body]);
      // I20: tri narocila v obdelavi ne blokirajo novega nakupa istega uporabnika
      r = await api("POST", `/events/${evProc[4]}/orders`, T.bor, { quantity: 1 });
      assert(r.status === 201 && r.body.checkout_url, "3 odlozena placila ne stejejo med »nedokoncana placila«: nov nakup 201", [r.status, r.text.slice(0, 100)]);
      await pool.query("UPDATE orders SET status='cancelled', cancelled_at=NOW() WHERE id=$1", [r.body.order.id]);
      // async_payment_failed -> failed, async_payment_succeeded -> paid
      const b2 = obdelavi[1], b3 = obdelavi[2];
      let w = await webhook(BS, "checkout.session.async_payment_failed", S.seje[b2.sid]);
      assert(w.status === 200 && (await vrstica(b2.o)).status === "failed", "async_payment_failed: narocilo failed (zaloga prosta)");
      S.seje[b3.sid] = { ...S.seje[b3.sid], payment_status: "paid" };
      w = await webhook(BS, "checkout.session.async_payment_succeeded", S.seje[b3.sid]);
      const v3 = await vrstica(b3.o);
      assert(w.status === 200 && v3.status === "paid", "async_payment_succeeded: narocilo paid");
      // izgubljen webhook: pospravljalec (instanca P) odkrije complete + unpaid in narocilo oznaci kot v obdelavi, ne preklice ga in ne klice expire()
      r = await apiP("POST", `/events/${evProc[0]}/orders`, T.cene, { quantity: 1 });
      const oP = r.body.order.id, sP = await sejaOd(oP);
      S.seje[sP] = { ...S.seje[sP], status: "complete", payment_status: "unpaid", payment_intent: "pi_odl_p" };
      await pool.query("UPDATE orders SET checkout_expires_at = NOW() - INTERVAL '10 minutes' WHERE id=$1", [oP]);
      let obdelan = false;
      for (let i = 0; i < 40 && !obdelan; i++) { await pocakaj(100); obdelan = (await vrstica(oP)).checkout_url === null; }
      const vP = await vrstica(oP);
      assert(obdelan && vP.status === "pending" && !S.potekle.includes(sP), "pospravljalec: odlozeno placilo ostane pending v obdelavi, brez expire()", [vP.status, vP.checkout_url]);
      r = await apiP("GET", "/me/orders", T.cene);
      assert(r.body.find(y => y.id === oP).payment_processing === true, "GET /me/orders: payment_processing true");
    }
  } catch (e) {
    fail++; console.log("  ✗ IZJEMA v testu:", e && e.stack || e);
  } finally {
    for (const s of vsi) s.srv.kill();
    jwksServer.close(); stripeServer.close();
    await pool.end();
    console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
    process.exit(fail ? 1 : 0);
  }
})().catch((e) => { console.error(e); process.exit(1); });
