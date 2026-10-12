#!/usr/bin/env node
/**
 * Vracila in spori (issue #190, prva faza; migracija 047, vracila_stripe.js, I37). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_vracila.js
 * Brez pravega Stripa: lazni Stripe (STRIPE_API_BASE), ki posnema refunds / application_fees/:id/refunds / paymentIntents (expand) / disputes, idempotentni kljuc,
 * nacin napak (prehodne, trajne) in »vracilo je ze narejeno«. NI preverjeno proti pravemu Stripu (reverse_transfer, vracilo provizije, fee_details).
 * Lazni Resend (RESEND_BASE_URL) za obvestila kupcem in lastniku kluba.
 *
 *   1  Odpoved dogodka (DELETE): hitro (vstavi vrstice, Stripa ne klice v zahtevku); vsako placano naroceno (vstopnica, gost, VIP miza, cenena, delno vrnjeno, 0 EUR, test,
 *      anonimiziran gost) dobi TOCNO eno vracilo; guest lista, cakajoce in tuje narocilo se ne dotaknejo
 *   2  Stripov klic: reverse_transfer, refund_application_fee=false, znesek = ostanek, idempotentni kljuc; vracilo provizije = provizija - Stripova pristojbina (0 pri ceneni vstopnici)
 *   3  Stanje: narocilo `refunded`, refunded_cents = znesek, vstopnice `refunded`; 0 EUR in test brez Stripa; naroceno iz drugega nacina -> `rocno` brez klica Stripa + alarm
 *   4  Obvestilo kupcem (dvojezicno), gost z naslovom, anonimiziran gost brez maila
 *   5  Ponovitev: drugi DELETE in nov tek ne podvojita; webhook charge.refunded po nasem vracilu ne spremeni stanja; isti dogodek = duplicate
 *   6  Napake: prehodna napaka -> ponovitev in uspeh; trajna -> `ni_uspelo` + alarm + admin API + retry; izcrpani poskusi; napaka pri vracilu provizije ponovi samo ta korak;
 *      crash po Stripu (idempotentni kljuc, potekel kljuc)
 *   7  Dogodek obnovljen pred obdelavo -> `preklicano`, brez Stripa
 *   8  Placilo za ze preklicano naroceno -> samodejno vracilo (reverse_transfer + refund_application_fee=true), brez vstopnic, enkrat
 *   9  Spori: dispute.created/updated/closed zapise stanje, alarm, mail lastniku (2x), NE premakne denarja, NE razveljavi vstopnice; spor brez narocila
 *  10  Sken: vrnjena vstopnica (odpovedan dogodek in vrnjeno prek Stripa) se zavrne, veljavna dela
 *  11  Zanesljivost: odpoved z 40 naroceni je hitra, med obdelavo GET /events, GET /clubs in sken niso blokirani
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");
const Stripe = require("stripe");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 4361, JWKS_PORT = 4362, STRIPE_PORT = 4363, RESEND_PORT = 4364;
const BASE = `http://127.0.0.1:${PORT}`;
const WHSEC = "whsec_test_vracila";
const stripeLokalno = new Stripe("sk_test_lokalno");

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-vracila";
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
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
async function api(method, path, token, body, glave = {}) {
  const r = await fetch(BASE + path, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}), ...glave }, body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}
const pocakaj = (ms) => new Promise(r => setTimeout(r, ms));
async function cakaj(pogoj, ms = 15000) { const do_ = Date.now() + ms; while (Date.now() < do_) { if (await pogoj()) return true; await pocakaj(80); } return false; }

// ---------- lazni Resend ----------
const R = { poslano: [] };
const resendServer = http.createServer((req, res) => {
  let d = ""; req.on("data", x => d += x);
  req.on("end", () => {
    if (req.method === "POST" && req.url === "/emails") { R.poslano.push(JSON.parse(d)); res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify({ id: "mail_" + R.poslano.length })); }
    res.writeHead(404, { "content-type": "application/json" }); res.end("{}");
  });
});
const mailiNa = (email) => R.poslano.filter(m => m.to === email || (Array.isArray(m.to) && m.to.includes(email)));

// ---------- lazni Stripe ----------
// pi: PaymentIntent, ch: naboj, fee: application fee, bt: balance transaction. refundi: ustvarjena vracila; fee_refundi: vracila provizije; klici: vsi zahtevki.
const S = { pi: {}, ch: {}, fee: {}, bt: {}, seje: {}, spori: {}, idem: {}, refundi: [], fee_refundi: [], klici: [], zakasnitev: 0, stR: 0, stSej: 0,
  refundHook: null, feeHook: null, idemPotekel: false };
const obrazec = (t) => { const o = {}; for (const [k, v] of new URLSearchParams(t)) o[k] = v; return o; };
function dodajPlacilo(pi, { amount, fee = 0, stripeFee = 59, vrnjeno = 0 }) {
  const n = pi.replace(/\W/g, "");
  S.pi[pi] = { id: pi, object: "payment_intent", status: "succeeded", amount, latest_charge: "ch_" + n };
  S.ch["ch_" + n] = { id: "ch_" + n, object: "charge", amount, amount_refunded: vrnjeno, payment_intent: pi, application_fee: fee > 0 ? "fee_" + n : null, balance_transaction: "txn_" + n };
  if (fee > 0) S.fee["fee_" + n] = { id: "fee_" + n, object: "application_fee", amount: fee, amount_refunded: 0 };
  S.bt["txn_" + n] = { id: "txn_" + n, object: "balance_transaction", fee: stripeFee + fee * 0, fee_details: [{ type: "stripe_fee", amount: stripeFee }] };
}
const razsiri = (ch, expand) => {
  const o = { ...ch };
  if (expand.includes("latest_charge.balance_transaction")) o.balance_transaction = S.bt[ch.balance_transaction];
  if (expand.includes("latest_charge.application_fee") && ch.application_fee) o.application_fee = S.fee[ch.application_fee];
  return o;
};
const stripeServer = http.createServer((req, res) => {
  let d = ""; req.on("data", x => d += x);
  req.on("end", async () => {
    const url = new URL(req.url, "http://x");
    const u = url.pathname, p = obrazec(d), kljuc = req.headers["idempotency-key"];
    S.klici.push({ m: req.method, u, p, kljuc });
    if (S.zakasnitev) await pocakaj(S.zakasnitev);
    const odg = (st, o) => { res.writeHead(st, { "content-type": "application/json", "request-id": "req_test", "stripe-should-retry": "false" }); res.end(JSON.stringify(o)); };
    const napaka = (st, tip, code, msg) => odg(st, { error: { type: tip, ...(code ? { code } : {}), message: msg } });
    let m;
    if (req.method === "POST" && u === "/v1/checkout/sessions") {
      const id = "cs_test_" + (++S.stSej);
      const kol = Number(p["line_items[0][quantity]"]), cena = Number(p["line_items[0][price_data][unit_amount]"]);
      S.seje[id] = { id, object: "checkout.session", url: `https://checkout.stripe.test/c/pay/${id}`, status: "open", payment_status: "unpaid", amount_total: kol * cena,
        currency: p["line_items[0][price_data][currency]"], client_reference_id: p.client_reference_id, metadata: { order_id: p["metadata[order_id]"], public_ref: p["metadata[public_ref]"] },
        expires_at: Number(p.expires_at), payment_intent: null };
      return odg(200, S.seje[id]);
    }
    if (req.method === "GET" && (m = u.match(/^\/v1\/checkout\/sessions\/(cs_\w+)$/))) return S.seje[m[1]] ? odg(200, S.seje[m[1]]) : napaka(404, "invalid_request_error", "resource_missing", "No such session");
    if (req.method === "GET" && (m = u.match(/^\/v1\/payment_intents\/(\w+)$/))) {
      const pi = S.pi[m[1]]; if (!pi) return napaka(404, "invalid_request_error", "resource_missing", "No such payment_intent");
      const expand = [...url.searchParams].filter(([k]) => /^expand(\[\d*\])?$/.test(k)).map(([, v]) => v);
      return odg(200, expand.some(x => x.startsWith("latest_charge")) ? { ...pi, latest_charge: razsiri(S.ch[pi.latest_charge], expand) } : pi);
    }
    if (req.method === "GET" && (m = u.match(/^\/v1\/charges\/(\w+)$/))) return S.ch[m[1]] ? odg(200, S.ch[m[1]]) : napaka(404, "invalid_request_error", "resource_missing", "No such charge");
    if (req.method === "GET" && (m = u.match(/^\/v1\/disputes\/(dp_\w+)$/))) return S.spori[m[1]] ? odg(200, S.spori[m[1]]) : napaka(404, "invalid_request_error", "resource_missing", "No such dispute");
    if (req.method === "GET" && u === "/v1/refunds") {
      const pi = url.searchParams.get("payment_intent");
      return odg(200, { object: "list", has_more: false, data: S.refundi.filter(r => r.payment_intent === pi) });
    }
    if (req.method === "POST" && u === "/v1/refunds") {
      if (kljuc && S.idem[kljuc] && !S.idemPotekel) return odg(200, S.idem[kljuc]);   // ponovitev z istim kljucem: isti odgovor, nic novega
      const hook = S.refundHook && S.refundHook(p, kljuc);
      if (hook) return odg(hook.status, hook.body);
      const pi = S.pi[p.payment_intent]; if (!pi) return napaka(404, "invalid_request_error", "resource_missing", "No such payment_intent");
      const ch = S.ch[pi.latest_charge], ostane = ch.amount - ch.amount_refunded;
      if (ostane <= 0) return napaka(400, "invalid_request_error", "charge_already_refunded", "Charge has already been refunded.");
      const znesek = p.amount ? Number(p.amount) : ostane;
      if (znesek > ostane) return napaka(400, "invalid_request_error", "amount_too_large", "Refund amount is greater than unrefunded amount on charge");
      ch.amount_refunded += znesek;
      const md = {}; for (const [k, v] of Object.entries(p)) { const mm = k.match(/^metadata\[(\w+)\]$/); if (mm) md[mm[1]] = v; }
      const re = { id: "re_" + (++S.stR), object: "refund", amount: znesek, status: "succeeded", payment_intent: pi.id, charge: ch.id, metadata: md };
      S.refundi.push({ ...re, params: p, kljuc });
      if (kljuc) S.idem[kljuc] = re;
      return odg(200, re);
    }
    if (req.method === "POST" && (m = u.match(/^\/v1\/application_fees\/(fee_\w+)\/refunds$/))) {
      if (kljuc && S.idem[kljuc]) return odg(200, S.idem[kljuc]);
      const hook = S.feeHook && S.feeHook(m[1], kljuc);
      if (hook) return odg(hook.status, hook.body);
      const f = S.fee[m[1]]; if (!f) return napaka(404, "invalid_request_error", "resource_missing", "No such application fee");
      const znesek = p.amount ? Number(p.amount) : f.amount - f.amount_refunded;
      if (znesek > f.amount - f.amount_refunded) return napaka(400, "invalid_request_error", "amount_too_large", "too large");
      f.amount_refunded += znesek;
      const fr = { id: "fr_" + (S.fee_refundi.length + 1), object: "fee_refund", amount: znesek, fee: f.id };
      S.fee_refundi.push({ ...fr, params: p, kljuc }); if (kljuc) S.idem[kljuc] = fr;
      return odg(200, fr);
    }
    return napaka(404, "invalid_request_error", null, "Lazni Stripe: neznana pot " + req.method + " " + u);
  });
});
const klici = (m, re) => S.klici.filter(k => k.m === m && re.test(k.u));
let stDogodka = 0;
async function webhook(tip, objekt, id) {
  const dogodek = { id: id || `evt_vr_${++stDogodka}`, object: "event", type: tip, data: { object: objekt }, created: Math.floor(Date.now() / 1000) };
  const payload = JSON.stringify(dogodek);
  const glava = stripeLokalno.webhooks.generateTestHeaderString({ payload, secret: WHSEC });
  const r = await fetch(BASE + "/stripe/webhook", { method: "POST", headers: { "content-type": "application/json", "stripe-signature": glava }, body: payload });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, id: dogodek.id };
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, stripe_events, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  await new Promise(r => stripeServer.listen(STRIPE_PORT, r));
  await new Promise(r => resendServer.listen(RESEND_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, QR_SECRET: "test", APP_URL: "https://outly.test",
    STRIPE_API_BASE: `http://127.0.0.1:${STRIPE_PORT}`, STRIPE_SECRET_KEY: "sk_test_lokalno", STRIPE_WEBHOOK_SECRET: WHSEC, STRIPE_POSPRAVI_MS: "3600000", PREVERI_OKNO_MS: "0", TEST_PLACILA: "",
    RESEND_API_KEY: "re_test", RESEND_BASE_URL: `http://127.0.0.1:${RESEND_PORT}`, EMAIL_FROM: "Outly <test@outly.test>", GOST_POSTA_PONOVI_MS: "0", JAVNI_PREDPOMNILNIK_MS: "0",
    VRACILA_TICK_MS: "250", VRACILA_RAZMAK_MS: "10", VRACILA_ZAMIK_S: "0", VRACILA_PREMOR_MS: "150", VRACILA_POSKUSOV: "3", VRACILA_SWEEP_MS: "400", VRACILA_MAIL_RAZMAK_MS: "0" },
    stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", x => log += x); srv.stderr.on("data", x => log += x);
  for (let i = 0; i < 80; i++) { try { await fetch(BASE + "/"); break; } catch { await pocakaj(100); } }

  try {
    const imena = ["lastnik", "ana", "bor", "admin", "gost"];
    const T = {}, U = {};
    imena.forEach((k, i) => { T[k] = zeton(`${k}@outly.si`, uuid(i + 1)); });
    for (const k of imena) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); U[k] = r.body.id; }
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city, address, contact_phone, contact_email) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Stripe Club', 'Ljubljana', 'Slovenska 1', '+38640111222', 'info@stripe-club.si')");
    await pool.query("UPDATE clubs SET stripe_account_id='acct_test1', stripe_charges_enabled=TRUE, stripe_payouts_enabled=TRUE WHERE id=1");
    const rojstvo = new Date(Date.now() - 25 * 365.25 * 24 * 3600 * 1000).toISOString().slice(0, 10);
    for (const k of imena) await api("PATCH", "/me", T[k], { dateOfBirth: rojstvo });
    const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    const dogodek = async (title, cena, extra = {}) => {
      const r = await api("POST", "/events", T.lastnik, { clubId: 1, title, startAt: cezDan, ticketPriceCents: cena, capacity: 500, minAge: 0, ...extra });
      assert(r.status === 201, `dogodek ${title}`, r.body); return r.body.id;
    };
    const evA = await dogodek("Odpovedana noc", 2000), evD = await dogodek("Kontrolna noc", 2000), evE = await dogodek("Noc napak", 2000);
    const evF = await dogodek("Obnovljena noc", 2000), evH = await dogodek("Noc placila po preklicu", 2000), evG = await dogodek("Velika noc", 1000);
    const evPrazen = await dogodek("Brez prodaje", 1000), evSw = await dogodek("Sweep noc", 2000), evStar = await dogodek("Star odpovedan", 2000);
    await pool.query("INSERT INTO club_tables (club_id, label, x, y, w, h, seats, price_cents) VALUES (1, 'T1', 1, 1, 2, 2, 4, 15000)");

    let stRef = 0;
    // Placano naroceno neposredno v bazi (nakupne poti pokrivajo drugi testi): tocno doloceni zneski, PI in nacin; vstopnice nastanejo kot po zakljuci().
    const narocilo = async ({ ev, uporabnik = null, gostEmail = null, kolicina = 1, cena = 2000, pi = undefined, status = "paid", email, miza = false, seja = null, stripeFee = 59, vrnjeno = 0, brezPlacila = false }) => {
      const skupaj = kolicina * cena, provizija = Math.round(skupaj * 0.1), ref = "OUT-VR" + String(++stRef).padStart(4, "0");
      const piId = pi === undefined ? "pi_" + ref.replace("-", "") : pi;
      const naslov = email || (gostEmail || `u${uporabnik}@outly.si`);
      const r = await pool.query(
        `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, currency, application_fee_cents, status, stripe_payment_intent_id, buyer_email, paid_at,
                             stripe_account_id, stripe_checkout_session_id, guest_email, guest_terms_version, guest_terms_accepted_at, table_id, table_label, table_seats)
         VALUES ($1,$2,$3,1,$4,$5,$6,'EUR',$7,$8,$9,$10,CASE WHEN $8 = 'paid' THEN NOW() END,'acct_test1',$11,$12,CASE WHEN $12::text IS NULL THEN NULL ELSE 'v1' END,CASE WHEN $12::text IS NULL THEN NULL ELSE NOW() END,
                 $13, $14, $15) RETURNING id`,
        [ref, uporabnik, ev, kolicina, cena, skupaj, brezPlacila ? 0 : provizija, status, piId, naslov, seja, gostEmail, miza ? 1 : null, miza ? "T1" : null, miza ? 4 : null]);
      const id = r.rows[0].id;
      if (status === "paid") await pool.query("INSERT INTO tickets (order_id, event_id) SELECT $1, $2 FROM generate_series(1, $3::int)", [id, ev, miza ? 4 : kolicina]);
      if (piId && !piId.startsWith("test_")) dodajPlacilo(piId, { amount: skupaj, fee: brezPlacila ? 0 : provizija, stripeFee, vrnjeno });
      return { id, ref, pi: piId, skupaj, provizija };
    };
    const vrsticaN = async (id) => (await pool.query("SELECT * FROM orders WHERE id=$1", [id])).rows[0];
    const vracilo = async (oid, razlog = "event_cancelled") => (await pool.query("SELECT * FROM vracila WHERE order_id=$1 AND razlog=$2", [oid, razlog])).rows[0];
    const vstopnice = async (oid) => (await pool.query("SELECT status FROM tickets WHERE order_id=$1", [oid])).rows.map(x => x.status);
    const koncna = (st) => ["opravljeno", "ni_uspelo", "rocno", "preklicano"].includes(st);

    // ================================================================
    console.log("\n# 1. Priprava: naroceila vseh vrst na dogodku A");
    const A1 = await narocilo({ ev: evA, uporabnik: U.ana, cena: 2000 });
    const A2 = await narocilo({ ev: evA, uporabnik: U.bor, kolicina: 2, cena: 2000, stripeFee: 146 });
    const A3 = await narocilo({ ev: evA, gostEmail: "gost@outly.si", cena: 2000 });
    const A4 = await narocilo({ ev: evA, uporabnik: U.ana, cena: 15000, miza: true, stripeFee: 450 });
    const A5 = await narocilo({ ev: evA, uporabnik: U.ana, cena: 300, stripeFee: 59 });   // provizija 30 < Stripova pristojbina 59: vracilo provizije 0, razliko nosi Outly
    const A6 = await narocilo({ ev: evA, uporabnik: U.bor, cena: 2000 });
    const A7 = await narocilo({ ev: evA, uporabnik: U.ana, cena: 0, pi: null, brezPlacila: true });
    const A8 = await narocilo({ ev: evA, uporabnik: U.bor, cena: 1500, pi: "test_abc123" });
    const A9 = await narocilo({ ev: evA, uporabnik: U.ana, cena: 2000, seja: "cs_live_tuj" });   // iz zivega nacina, kljuc je sandbox (I36)
    const A12 = await narocilo({ ev: evA, gostEmail: "izbrisan-12@outly.invalid", cena: 2000 });
    const A11 = await narocilo({ ev: evA, uporabnik: U.ana, cena: 2000, pi: null, status: "pending" });   // cakajoce: ni placano, ne vracamo
    const D1 = await narocilo({ ev: evD, uporabnik: U.ana, cena: 2000 });
    const D2 = await narocilo({ ev: evD, uporabnik: U.bor, cena: 2000 });
    const D3 = await narocilo({ ev: evD, uporabnik: U.ana, cena: 2000 });
    const gl = await api("POST", "/admin/api/guest-lists", T.admin, { event_id: evA, user_id: U.ana, spots: 2 });
    assert(gl.status === 201, "guest lista na dogodku A (brezplacne vstopnice, ni prodaja)", gl.body);
    const stGl = (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1 AND guest_list_id IS NOT NULL", [evA])).rows[0].n;
    assert(stGl === 1, "naroceno guest liste obstaja", stGl);

    // Delno vrnjeno prek Stripove nadzorne plosce (webhook charge.refunded, kot dosle): A6 -> partially_refunded, 500 c
    S.ch[S.pi[A6.pi].latest_charge].amount_refunded = 500;
    let w = await webhook("charge.refunded", { id: S.pi[A6.pi].latest_charge });
    assert(w.status === 200, "webhook charge.refunded (delno, nadzorna plosca): 200", w);
    let o6 = await vrsticaN(A6.id);
    assert(o6.status === "partially_refunded" && o6.refunded_cents === 500, "A6: partially_refunded, 500 c", [o6.status, o6.refunded_cents]);

    // ================================================================
    console.log("\n# 2. Odpoved dogodka A: hitro, brez Stripa v zahtevku");
    const kliciPred = S.klici.length;
    S.zakasnitev = 40;   // pocasen Stripe: ce bi DELETE klical Stripe, bi trajalo >> 1 s
    const t0 = Date.now();
    let r = await api("DELETE", `/events/${evA}`, T.lastnik);
    const trajanje = Date.now() - t0;
    assert(r.status === 200 && r.body.event.status === "cancelled", "DELETE: dogodek odpovedan", r.body);
    assert(r.body.refunds_queued === 10 && r.body.orders === 11, "odgovor: refunds_queued = 10 (placana brez guest liste, cakajoca in tuja ne)", [r.body.refunds_queued, r.body.orders]);
    assert(trajanje < 1000, `DELETE hiter (${trajanje} ms)`, trajanje);
    assert(S.klici.length === kliciPred || klici("POST", /refunds/).length === 0, "v zahtevku NI klicev Stripa za vracila", S.klici.length - kliciPred);
    const odp = await pool.query("SELECT 1 FROM odpovedi_dogodkov WHERE event_id=$1", [evA]);
    assert(odp.rows.length === 1, "sprozilec: zapis odpovedi dogodka");
    assert(await cakaj(async () => { const q = await pool.query("SELECT COUNT(*)::int AS n FROM vracila WHERE event_id=$1 AND NOT (stanje IN ('opravljeno','ni_uspelo','rocno','preklicano'))", [evA]); return q.rows[0].n === 0; }), "obdelovalec vsa vracila dokonca");
    S.zakasnitev = 0;
    const st = (await pool.query("SELECT stanje, COUNT(*)::int AS n FROM vracila WHERE event_id=$1 GROUP BY stanje", [evA])).rows;
    assert(st.length === 2 && st.find(x => x.stanje === "opravljeno").n === 9 && st.find(x => x.stanje === "rocno").n === 1, "9 opravljenih, 1 za rocno obravnavo (A9)", st);

    // ================================================================
    console.log("\n# 3. Stripovi klici: reverse_transfer, znesek, provizija, idempotentni kljuc");
    const refA = (pi) => S.refundi.filter(x => x.payment_intent === pi);
    for (const [ime, a, znesek] of [["A1 vstopnica", A1, 2000], ["A2 2 vstopnici", A2, 4000], ["A3 gost", A3, 2000], ["A4 VIP miza", A4, 15000], ["A5 cenena", A5, 300], ["A12 anonimiziran gost", A12, 2000]]) {
      const x = refA(a.pi);
      const vr = await vracilo(a.id);
      assert(x.length === 1, `${ime}: TOCNO eno Stripovo vracilo`, x.length);
      assert(x[0] && x[0].params.reverse_transfer === "true" && x[0].params.refund_application_fee === "false" && Number(x[0].params.amount) === znesek, `${ime}: reverse_transfer, brez refund_application_fee, znesek ${znesek}`, x[0] && x[0].params);
      assert(x[0] && x[0].kljuc === `outly-vracilo-${vr.id}` && x[0].params["metadata[vracilo_id]"] === String(vr.id), `${ime}: idempotentni kljuc outly-vracilo-<id> + metadata`, x[0] && x[0].kljuc);
    }
    const x6 = refA(A6.pi);
    assert(x6.length === 1 && Number(x6[0].params.amount) === 1500, "A6 (delno vrnjeno 500): vracilo samo ostanka, 1500", x6.map(x => x.params.amount));
    const feeOd = (a) => S.fee_refundi.filter(x => x.fee === "fee_" + a.pi.replace(/\W/g, ""));
    for (const [ime, a, pricakovano] of [["A1", A1, 141], ["A2", A2, 254], ["A3", A3, 141], ["A4", A4, 1050], ["A6", A6, 141], ["A12", A12, 141]]) {
      const f = feeOd(a);
      assert(f.length === 1 && f[0].amount === pricakovano, `${ime}: vracilo provizije = provizija - Stripova pristojbina (${pricakovano})`, f.map(x => x.amount));
      assert(f[0] && f[0].kljuc === `outly-vracilo-${(await vracilo(a.id)).id}-provizija`, `${ime}: idempotentni kljuc vracila provizije`, f[0] && f[0].kljuc);
    }
    assert(feeOd(A5).length === 0, "A5 (provizija 30 < pristojbina 59): vracila provizije NI (razliko 29 nosi Outly)");
    const v5 = await vracilo(A5.id);
    assert(v5.provizija_za_vrnitev_cents === 0 && v5.stripe_pristojbina_cents === 59, "A5: zapisano 0 / 59", [v5.provizija_za_vrnitev_cents, v5.stripe_pristojbina_cents]);
    assert(klici("POST", /^\/v1\/refunds$/).length === 7 && S.fee_refundi.length === 6, "skupaj 7 vracil in 6 vracil provizije", [klici("POST", /^\/v1\/refunds$/).length, S.fee_refundi.length]);

    // ================================================================
    console.log("\n# 4. Stanje po vracilu");
    for (const [ime, a] of [["A1", A1], ["A2", A2], ["A3", A3], ["A4", A4], ["A5", A5], ["A6", A6], ["A12", A12]]) {
      const o = await vrsticaN(a.id), vs = await vstopnice(a.id);
      assert(o.status === "refunded" && o.refunded_cents === a.skupaj, `${ime}: refunded, refunded_cents = ${a.skupaj}`, [o.status, o.refunded_cents]);
      assert(vs.length > 0 && vs.every(x => x === "refunded"), `${ime}: vse vstopnice refunded`, vs);
    }
    assert((await vstopnice(A4.id)).length === 4, "A4: VIP miza ima 4 vstopnice");
    const v7 = await vracilo(A7.id), v8 = await vracilo(A8.id), o7 = await vrsticaN(A7.id), o8 = await vrsticaN(A8.id);
    assert(v7.stanje === "opravljeno" && v7.brez_stripa && o7.status === "refunded" && (await vstopnice(A7.id)).every(x => x === "refunded"), "A7 (0 EUR): brez Stripa, samo stanje");
    assert(v8.stanje === "opravljeno" && v8.brez_stripa && o8.status === "refunded" && o8.refunded_cents === 1500, "A8 (testni nacin, test_ PI): brez Stripa, samo stanje", [o8.status, o8.refunded_cents]);
    assert(S.klici.every(k => !/test_abc123/.test(k.u + JSON.stringify(k.p))), "Stripe nikoli ni dobil testnega PI");
    const v9 = await vracilo(A9.id), o9 = await vrsticaN(A9.id);
    assert(v9.stanje === "rocno" && /ZIV|zivega|SANDBOX/i.test(v9.napaka), "A9 (drug nacin, I36): stanje rocno z razlago", [v9.stanje, v9.napaka]);
    assert(o9.status === "paid" && (await vstopnice(A9.id)).every(x => x === "valid") && refA(A9.pi).length === 0, "A9: naroceno nespremenjeno, Stripe NI klican");
    assert(/\[vracila\] POZOR: vracilo narocila OUT-VR0009 \(event_cancelled\) zahteva ROCNO/.test(log), "A9: alarm [vracila] POZOR v dnevniku");
    const o10 = (await pool.query("SELECT status FROM orders WHERE event_id=$1 AND guest_list_id IS NOT NULL", [evA])).rows[0];
    assert(o10.status === "paid" && (await pool.query("SELECT 1 FROM vracila v JOIN orders o ON o.id=v.order_id WHERE o.guest_list_id IS NOT NULL")).rows.length === 0, "guest lista: nedotaknjena, brez vracila");
    const o11 = await vrsticaN(A11.id);
    assert(o11.status === "pending" && !(await vracilo(A11.id)), "cakajoce naroceno: nedotaknjeno");
    for (const d of [D1, D2, D3]) assert((await vrsticaN(d.id)).status === "paid" && !(await vracilo(d.id)), "narocilo drugega dogodka nedotaknjeno");

    // ================================================================
    console.log("\n# 5. Obvestila kupcem");
    assert(await cakaj(() => R.poslano.filter(m => /Event cancelled/.test(m.subject)).length >= 8), "8 mailov o odpovedi (ana 4, bor 3, gost 1)", R.poslano.length);
    await pocakaj(700);
    const odpMaili = R.poslano.filter(m => /Event cancelled/.test(m.subject));
    assert(odpMaili.length === 8, "natanko 8 mailov (brez A9 rocno, brez anonimiziranega A12)", odpMaili.length);
    const naslovi = (e) => odpMaili.filter(m => m.to === e).length;
    assert(naslovi(`u${U.ana}@outly.si`) === 4 && naslovi(`u${U.bor}@outly.si`) === 3 && naslovi("gost@outly.si") === 1, "ana 4, bor 3, gost 1", [naslovi(`u${U.ana}@outly.si`), naslovi(`u${U.bor}@outly.si`), naslovi("gost@outly.si")]);
    assert(!R.poslano.some(m => m.to === "izbrisan-12@outly.invalid"), "anonimiziran gost (*@outly.invalid): brez maila");
    const m1 = odpMaili.find(m => m.subject.includes(A1.ref));
    assert(m1 && m1.subject === `Dogodek odpovedan / Event cancelled: Odpovedana noc (${A1.ref})`, "zadeva dvojezicna", m1 && m1.subject);
    assert(m1 && /We have refunded the full amount of 20\.00 EUR/.test(m1.text) && /Vrnili smo vam celoten znesek 20,00 EUR/.test(m1.text), "besedilo: celoten znesek (SL in EN)", m1 && m1.text);
    assert(m1 && /no longer valid/.test(m1.text) && !/cid:|<img/i.test(m1.html), "besedilo: vstopnice ne veljajo vec; brez QR", m1 && m1.text);
    const m8 = odpMaili.find(m => m.subject.includes(A8.ref)), m7 = odpMaili.find(m => m.subject.includes(A7.ref));
    assert(m8 && /Nothing was charged for this order/.test(m8.text) && m7 && /Nothing was charged for this order/.test(m7.text), "0 EUR in testno: mail pove, da ni bilo zaracunano nic");
    const m4 = odpMaili.find(m => m.subject.includes(A4.ref));
    assert(m4 && /VIP table T1/.test(m4.text) && /150\.00 EUR/.test(m4.text), "VIP miza: mail omenja mizo in znesek");
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM vracila WHERE razlog='event_cancelled' AND stanje='opravljeno' AND mail_poslano_at IS NOT NULL")).rows[0].n === 8, "mail_poslano_at zapisan pri 8 vracilih");

    // ================================================================
    console.log("\n# 6. Ponovitev ne podvoji; webhook charge.refunded po nasem vracilu");
    const stRef0 = S.refundi.length, stFee0 = S.fee_refundi.length, stMail0 = R.poslano.length;
    r = await api("DELETE", `/events/${evA}`, T.lastnik);
    assert(r.status === 200 && r.body.refunds_queued === 0, "drugi DELETE: refunds_queued 0 (UNIQUE order_id, razlog)", r.body);
    await pool.query("UPDATE vracila SET stanje='caka', naslednji_poskus_at=NOW() WHERE event_id=$1 AND stanje='opravljeno' AND NOT brez_stripa", [evA]);   // »ponovni zagon obdelovalca«
    await pocakaj(1500);
    assert(S.refundi.length === stRef0 && S.fee_refundi.length === stFee0, "ponovni zagon obdelovalca: nobenega novega vracila ne vracila provizije", [S.refundi.length - stRef0, S.fee_refundi.length - stFee0]);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM vracila WHERE event_id=$1 AND stanje='opravljeno'", [evA])).rows[0].n === 9, "vracila spet opravljena (9)");
    await pocakaj(500);
    assert(R.poslano.length === stMail0, "ponovni zagon: mail kupcu se NE poslje drugic", R.poslano.length - stMail0);
    const chA1 = S.pi[A1.pi].latest_charge;
    w = await webhook("charge.refunded", { id: chA1 }, "evt_vr_ponovno");
    assert(w.status === 200 && !w.body.duplicate, "webhook charge.refunded po nasem vracilu: 200", w);
    let oA1 = await vrsticaN(A1.id);
    assert(oA1.status === "refunded" && oA1.refunded_cents === 2000 && (await vstopnice(A1.id)).every(x => x === "refunded"), "A1: stanje nespremenjeno (refunded, 2000)", [oA1.status, oA1.refunded_cents]);
    w = await webhook("charge.refunded", { id: chA1 }, "evt_vr_ponovno");
    assert(w.status === 200 && w.body.duplicate === true, "isti dogodek drugic: duplicate", w.body);
    w = await webhook("charge.refunded", { id: chA1 });
    oA1 = await vrsticaN(A1.id);
    assert(w.status === 200 && oA1.refunded_cents === 2000 && oA1.status === "refunded", "nov dogodek za isti naboj: isto stanje (refunded_cents ne naraste)", oA1.refunded_cents);

    // ================================================================
    console.log("\n# 7. Napake Stripa");
    const E1 = await narocilo({ ev: evE, uporabnik: U.ana }), E2 = await narocilo({ ev: evE, uporabnik: U.bor }), E3 = await narocilo({ ev: evE, uporabnik: U.ana });
    const E4 = await narocilo({ ev: evE, uporabnik: U.bor }), E6 = await narocilo({ ev: evE, uporabnik: U.ana }), E7 = await narocilo({ ev: evE, uporabnik: U.bor });
    const stanjeNapak = { [E1.pi]: 2, [E3.pi]: 999 };
    const prehodna = { status: 500, body: { error: { type: "api_error", message: "Stripe je trenutno nedosegljiv" } } };
    S.refundHook = (p) => {
      if (p.payment_intent === E2.pi) return { status: 400, body: { error: { type: "invalid_request_error", code: "balance_insufficient", message: "Insufficient funds in Stripe account." } } };
      if (stanjeNapak[p.payment_intent] > 0) { stanjeNapak[p.payment_intent]--; return prehodna; }
      return null;
    };
    let feeNapak = 1;
    S.feeHook = (feeId) => { if (feeId === "fee_" + E4.pi.replace(/\W/g, "") && feeNapak-- > 0) return prehodna; return null; };
    // E6: crash po Stripu (vracilo je narejeno, vrstica ga ne pozna; idempotentni kljuc se ujema); E7: kljuc je potekel (vracilo je na seznamu vracil, napaka charge_already_refunded)
    const vnesi = async (a) => (await pool.query(
      `INSERT INTO vracila (order_id, event_id, razlog, stanje, znesek_cents, application_fee_id, provizija_za_vrnitev_cents, stripe_pristojbina_cents, naslednji_poskus_at)
       VALUES ($1, $2, 'event_cancelled', 'caka', $3, $4, 141, 59, NOW() + INTERVAL '1 hour') RETURNING id`, [a.id, evE, a.skupaj, "fee_" + a.pi.replace(/\W/g, "")])).rows[0].id;
    const id6 = await vnesi(E6), id7 = await vnesi(E7);
    for (const [id, a, kljuc] of [[id6, E6, `outly-vracilo-${id6}`], [id7, E7, `outly-vracilo-${id7}`]]) {
      const ch = S.ch[S.pi[a.pi].latest_charge]; ch.amount_refunded = a.skupaj;
      const re = { id: "re_prej" + id, object: "refund", amount: a.skupaj, status: "succeeded", payment_intent: a.pi, charge: ch.id, metadata: { vracilo_id: String(id) } };
      S.refundi.push({ ...re, params: {}, kljuc, prej: true });
      if (id === id6) S.idem[kljuc] = re;
    }
    S.idemPotekel = false;
    const stRefE = S.refundi.length;
    r = await api("DELETE", `/events/${evE}`, T.lastnik);
    assert(r.status === 200 && r.body.refunds_queued === 4, "odpoved dogodka E: 4 nova vracila (E6, E7 ze v vrsti)", r.body);
    await pool.query("UPDATE vracila SET naslednji_poskus_at = NOW() WHERE id IN ($1, $2)", [id6, id7]);
    assert(await cakaj(async () => { const q = await pool.query("SELECT COUNT(*)::int AS n FROM vracila WHERE event_id=$1 AND stanje IN ('caka','v_teku')", [evE]); return q.rows[0].n === 0; }, 20000), "vsa vracila dogledno koncana");
    const vE = async (a) => vracilo(a.id);
    let v = await vE(E1);
    assert(v.stanje === "opravljeno" && v.poskusi === 3, "E1: dve prehodni napaki -> ponovitev -> uspeh (3. poskus)", [v.stanje, v.poskusi]);
    assert(refA(E1.pi).length === 1, "E1: kljub ponovitvam TOCNO eno vracilo", refA(E1.pi).length);
    v = await vE(E2);
    assert(v.stanje === "ni_uspelo" && v.poskusi === 1 && /balance_insufficient/.test(v.napaka), "E2: trajna napaka (balance_insufficient) -> ni_uspelo brez ponavljanja", [v.stanje, v.poskusi, v.napaka]);
    assert((await vrsticaN(E2.id)).status === "paid" && (await vstopnice(E2.id)).every(x => x === "valid"), "E2: naroceno OSTANE placano (vracilo ni uspelo, nic tiho)");
    v = await vE(E3);
    assert(v.stanje === "ni_uspelo" && v.poskusi === 3, "E3: prehodna napaka vsakic -> po 3 poskusih ni_uspelo", [v.stanje, v.poskusi]);
    assert(/\[vracila\] POZOR: vracilo narocila OUT-VR\d+ \(event_cancelled\) NI uspelo \(poskus 3\/3\)/.test(log) && /balance_insufficient/.test(log), "alarm [vracila] POZOR v dnevniku (ni_uspelo)");
    v = await vE(E4);
    assert(v.stanje === "opravljeno" && v.provizija_vracilo_id && refA(E4.pi).length === 1, "E4: napaka pri vracilu provizije -> ponovljen SAMO ta korak (eno vracilo, vracilo provizije opravljeno)", [v.stanje, refA(E4.pi).length]);
    assert(S.fee_refundi.filter(x => x.fee === "fee_" + E4.pi.replace(/\W/g, "")).length === 1, "E4: vracilo provizije natanko enkrat");
    v = await vE(E6); const vz6 = S.refundi.filter(x => x.payment_intent === E6.pi);
    assert(v.stanje === "opravljeno" && vz6.length === 1 && v.stripe_vracilo_id === "re_prej" + id6 && v.provizija_vracilo_id, "E6 (crash po Stripu): isti idempotentni kljuc vrne obstojece vracilo, novega NI, vracilo provizije opravljeno", [v.stanje, vz6.length, v.stripe_vracilo_id]);
    v = await vE(E7); const vz7 = S.refundi.filter(x => x.payment_intent === E7.pi);
    assert(v.stanje === "opravljeno" && vz7.length === 1, "E7 (potekel kljuc): vracilo najdeno po metadata, novega NI", [v.stanje, vz7.length]);
    // admin API
    let ad = await api("GET", "/admin/api/refunds?state=ni_uspelo", T.admin);
    assert(ad.status === 200 && ad.body.items.length === 2 && ad.body.attention >= 3 && ad.body.counts.ni_uspelo === 2 && ad.body.counts.rocno === 1, "admin: GET /admin/api/refunds?state=ni_uspelo (2) + counts + attention", ad.body.counts);
    assert(ad.body.items.every(x => x.public_ref && x.event_title === "Noc napak" && x.error && !("buyer_email" in x)) && !/@/.test(JSON.stringify(ad.body)), "admin: napaka vidna, brez e-naslovov kupcev");
    assert((await api("GET", "/admin/api/refunds?state=slab", T.admin)).status === 400 && (await api("GET", "/admin/api/refunds", T.lastnik)).status === 403 && (await api("GET", "/admin/api/refunds")).status === 401, "admin: 400 za slabo stanje, 403 za lastnika kluba, 401 brez zetona");
    const sum = await api("GET", "/admin/api/summary", T.admin);
    assert(sum.status === 200 && sum.body.refunds_attention === 3, "admin summary: refunds_attention = 3 (2 ni_uspelo + 1 rocno)", sum.body.refunds_attention);
    // Popravek vzroka (klub ima sredstva) -> retry -> opravljeno
    S.refundHook = null;
    const id2 = (await vE(E2)).id;
    r = await api("POST", `/admin/api/refunds/${id2}/retry`, T.admin);
    assert(r.status === 200, "admin: POST retry -> 200", r.body);
    assert(await cakaj(async () => (await vE(E2)).stanje === "opravljeno"), "E2 po retry: opravljeno");
    assert(refA(E2.pi).length === 1 && (await vrsticaN(E2.id)).status === "refunded", "E2: eno vracilo, naroceno refunded");
    assert((await api("POST", `/admin/api/refunds/${id2}/retry`, T.admin)).status === 409 && (await api("POST", `/admin/api/refunds/${id2}/retry`, T.lastnik)).status === 403, "retry opravljenega: 409; lastnik kluba: 403");

    // ================================================================
    console.log("\n# 8. Dogodek obnovljen pred obdelavo");
    const F1 = await narocilo({ ev: evF, uporabnik: U.ana });
    const idF = (await pool.query("INSERT INTO vracila (order_id, event_id, razlog, naslednji_poskus_at) VALUES ($1, $2, 'event_cancelled', NOW() + INTERVAL '1 hour') RETURNING id", [F1.id, evF])).rows[0].id;
    r = await api("PATCH", `/events/${evF}`, T.lastnik, { status: "cancelled" });
    assert(r.status === 200 && (await pool.query("SELECT 1 FROM odpovedi_dogodkov WHERE event_id=$1", [evF])).rows.length === 1, "PATCH status cancelled: dogodek odpovedan, sprozilec zapise odpoved", r.status);
    r = await api("PATCH", `/events/${evF}`, T.lastnik, { status: "published" });
    assert(r.status === 200, "lastnik dogodek obnovi, preden steče denar");
    await pool.query("UPDATE vracila SET naslednji_poskus_at = NOW() WHERE id=$1", [idF]);
    assert(await cakaj(async () => (await vracilo(F1.id)).stanje === "preklicano"), "dogodek spet objavljen: vracilo `preklicano`");
    assert(refA(F1.pi).length === 0 && (await vrsticaN(F1.id)).status === "paid", "brez Stripa, naroceno placano");
    // Odpoved po drugi poti kot DELETE (PATCH, admin, SQL): sweep vstavi vracila za dogodke iz odpovedi_dogodkov
    const SW1 = await narocilo({ ev: evSw, uporabnik: U.bor });
    r = await api("PATCH", `/events/${evSw}`, T.lastnik, { status: "cancelled" });
    assert(r.status === 200, "PATCH status cancelled brez DELETE");
    assert(await cakaj(async () => { const q = await vracilo(SW1.id); return q && q.stanje === "opravljeno"; }), "sweep: vracilo vstavljeno in opravljeno tudi brez DELETE");
    assert(refA(SW1.pi).length === 1 && (await vrsticaN(SW1.id)).status === "refunded", "SW: eno vracilo, naroceno refunded");
    // Dogodek, odpovedan PRED migracijo 047 (ni v odpovedi_dogodkov): sweep ga NE dotakne (migracija ne dela UPDATE, produkcijski podatki ostanejo)
    const ST1 = await narocilo({ ev: evStar, uporabnik: U.ana });
    await pool.query("UPDATE events SET status='cancelled' WHERE id=$1", [evStar]);
    await pool.query("DELETE FROM odpovedi_dogodkov WHERE event_id=$1", [evStar]);
    await pocakaj(1500);
    assert(!(await vracilo(ST1.id)) && (await vrsticaN(ST1.id)).status === "paid", "star odpovedan dogodek (brez zapisa odpovedi): sweep ga ne dotakne");
    r = await api("DELETE", `/events/${evStar}`, T.lastnik);
    assert(r.status === 200 && r.body.refunds_queued === 1, "izrecen DELETE na ze odpovedanem dogodku vendarle vstavi vracila", r.body);
    assert(await cakaj(async () => { const q = await vracilo(ST1.id); return q && q.stanje === "opravljeno"; }), "star dogodek po izrecnem DELETE: vracilo opravljeno");
    assert((await pool.query("SELECT 1 FROM odpovedi_dogodkov WHERE event_id=$1", [evStar])).rows.length === 1, "izrecni DELETE zabelezi odpoved (odslej ga spremlja sweep)");

    // ================================================================
    console.log("\n# 9. Placilo za ze preklicano naroceno -> samodejno vracilo");
    const sejaPlacana = async (oid) => { const s = await vrsticaN(oid); return s.stripe_checkout_session_id; };
    r = await api("POST", `/events/${evH}/orders`, T.ana, { quantity: 1 });
    assert(r.status === 201 && r.body.mode === "stripe", "nakup v Stripe nacinu: cakajoce naroceno + seja", r.body);
    const idH = r.body.order.id, sejaH = await sejaPlacana(idH);
    await pool.query("UPDATE orders SET status='cancelled', cancelled_at=NOW() WHERE id=$1", [idH]);   // seja je potekla / gost preklical, sprozilec je sprostil zalogo
    dodajPlacilo("pi_zamujeno", { amount: 2000, fee: 200, stripeFee: 59 });
    S.seje[sejaH] = { ...S.seje[sejaH], status: "complete", payment_status: "paid", payment_intent: "pi_zamujeno" };
    w = await webhook("checkout.session.completed", S.seje[sejaH]);
    assert(w.status === 200, "webhook: seja placana, naroceno je cancelled", w);
    assert(await cakaj(async () => { const q = await vracilo(idH, "inactive_order"); return q && q.stanje === "opravljeno"; }), "vracilo `inactive_order` opravljeno");
    const xi = refA("pi_zamujeno");
    assert(xi.length === 1 && xi[0].params.reverse_transfer === "true" && xi[0].params.refund_application_fee === "true" && Number(xi[0].params.amount) === 2000, "samodejno vracilo: reverse_transfer + refund_application_fee=true, znesek seje (Stripovo pristojbino nosi Outly)", xi[0] && xi[0].params);
    assert(klici("POST", /application_fees\/fee_pi_zamujeno/).length === 0, "brez ločenega vračila provizije (Stripe jo vrne sam)");
    const oH = await vrsticaN(idH);
    assert(oH.status === "cancelled" && (await vstopnice(idH)).length === 0, "naroceno ostane preklicano, vstopnic NI");
    assert(/POZOR: placilo za neaktivno narocilo .*vracilo v vrsti \(samodejno\)/.test(log), "alarm POZOR (vracilo v vrsti)");
    w = await webhook("checkout.session.completed", S.seje[sejaH]);
    await pocakaj(800);
    assert(w.status === 200 && refA("pi_zamujeno").length === 1, "isti webhook (nov evt) drugic: vracilo se NE podvoji", refA("pi_zamujeno").length);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM vracila WHERE order_id=$1", [idH])).rows[0].n === 1, "ena vrstica vracila");
    w = await webhook("charge.refunded", { id: S.pi.pi_zamujeno.latest_charge });
    assert(w.status === 200 && (await vrsticaN(idH)).status === "cancelled", "charge.refunded za neaktivno naroceno: stanje nespremenjeno (cancelled)");

    // ================================================================
    console.log("\n# 10. Spori (chargeback)");
    const cD1 = S.pi[D1.pi].latest_charge, stRef9 = S.refundi.length, stFee9 = S.fee_refundi.length, klicov9 = S.klici.filter(k => k.m === "POST").length;
    S.spori.dp_1 = { id: "dp_1", object: "dispute", charge: cD1, payment_intent: D1.pi, amount: 2000, currency: "eur", reason: "fraudulent", status: "needs_response", created: Math.floor(Date.now() / 1000), evidence_details: { due_by: Math.floor(Date.now() / 1000) + 7 * 86400 } };
    w = await webhook("charge.dispute.created", { id: "dp_1" });
    assert(w.status === 200, "webhook charge.dispute.created: 200", w);
    let sp = (await pool.query("SELECT * FROM spori WHERE id='dp_1'")).rows[0];
    assert(sp && sp.order_id === D1.id && sp.stanje === "needs_response" && sp.razlog === "fraudulent" && sp.znesek_cents === 2000 && sp.valuta === "EUR" && sp.rok_dokazov_at && !sp.zaprt_at, "spor zapisan na narocilo (stanje, razlog, znesek, rok dokazov)", sp);
    const oD1 = await vrsticaN(D1.id);
    assert(oD1.status === "paid" && oD1.refunded_cents === 0 && (await vstopnice(D1.id)).every(x => x === "valid"), "narocilo ostane placano, vstopnice VELJAVNE (denar in vstopnica se ne premakneta)");
    assert(/\[spori\] POZOR: nov spor dp_1 \(fraudulent\) 2000 c, stanje needs_response, narocilo OUT-VR\d+/.test(log), "alarm [spori] POZOR v dnevniku");
    assert(await cakaj(() => mailiNa("lastnik@outly.si").some(m => /Payment dispute/.test(m.subject))), "mail lastniku kluba ob odprtju spora");
    const ms = mailiNa("lastnik@outly.si").find(m => /Payment dispute/.test(m.subject));
    assert(ms && Array.isArray(ms.to) && ms.to.includes("info@stripe-club.si") && ms.to.includes("lastnik@outly.si"), "prejemnika: lastnik kluba + kontaktni e-naslov kluba", ms && ms.to);
    assert(ms && /Disputed amount: 20\.00 EUR/.test(ms.text) && /Znesek spora: 20,00 EUR/.test(ms.text) && !/refund|vrnil/i.test(ms.text.replace(/Next steps[\s\S]*/, "")), "besedilo dvojezicno, brez obljub o denarju", ms && ms.text);
    w = await webhook("charge.dispute.created", { id: "dp_1" }, w.id);
    assert(w.body.duplicate === true, "isti dogodek: duplicate");
    S.spori.dp_1 = { ...S.spori.dp_1, status: "lost" };
    w = await webhook("charge.dispute.closed", { id: "dp_1" });
    sp = (await pool.query("SELECT * FROM spori WHERE id='dp_1'")).rows[0];
    assert(w.status === 200 && sp.stanje === "lost" && sp.zaprt_at, "dispute.closed (lost): stanje lost, zaprt_at");
    assert(await cakaj(() => mailiNa("lastnik@outly.si").filter(m => /Dispute closed/.test(m.subject)).length === 1), "mail ob zaprtju spora");
    await pocakaj(600);
    assert(mailiNa("lastnik@outly.si").filter(m => /Payment dispute/.test(m.subject)).length === 1 && mailiNa("lastnik@outly.si").filter(m => /Dispute closed/.test(m.subject)).length === 1, "vsak mail natanko enkrat");
    const oD1b = await vrsticaN(D1.id);
    assert(oD1b.status === "paid" && oD1b.refunded_cents === 0 && (await vstopnice(D1.id)).every(x => x === "valid") && S.refundi.length === stRef9 && S.fee_refundi.length === stFee9
      && S.klici.filter(k => k.m === "POST").length === klicov9, "tudi izgubljen spor: vstopnica veljavna, NOBEN POST na Stripe (ni vracila, ni transfer_reversal)");
    S.spori.dp_2 = { id: "dp_2", object: "dispute", charge: "ch_neznan", payment_intent: "pi_neznan", amount: 500, currency: "eur", reason: "general", status: "needs_response", created: Math.floor(Date.now() / 1000) };
    const mailov = R.poslano.length;
    w = await webhook("charge.dispute.created", { id: "dp_2" });
    sp = (await pool.query("SELECT * FROM spori WHERE id='dp_2'")).rows[0];
    assert(w.status === 200 && sp && sp.order_id === null, "spor brez narocila: zapisan z order_id NULL");
    assert(/\[spori\] POZOR: spor dp_2 .* narocilo NEZNANO/.test(log), "alarm: spora ni mogoce povezati z narocilom");
    await pocakaj(600);
    assert(R.poslano.length === mailov, "spor brez narocila: nobenega maila");
    ad = await api("GET", "/admin/api/disputes?open=1", T.admin);
    assert(ad.status === 200 && ad.body.items.length === 1 && ad.body.items[0].id === "dp_2" && (await api("GET", "/admin/api/disputes", T.admin)).body.items.length === 2, "admin: GET /admin/api/disputes (odprti 1, vsi 2)");

    // ================================================================
    console.log("\n# 11. Sken");
    await pool.query("UPDATE events SET start_at = NOW() + INTERVAL '1 hour' WHERE id IN ($1, $2)", [evA, evD]);
    const serial = async (oid) => (await pool.query("SELECT serial FROM tickets WHERE order_id=$1 ORDER BY id LIMIT 1", [oid])).rows[0].serial;
    r = await api("POST", "/business/tickets/scan", T.lastnik, { serial: await serial(A1.id) });
    assert(r.status === 409 && r.body.result === "event_cancelled", "vstopnica vrnjenega naroceno odpovedanega dogodka: 409 event_cancelled", r.body);
    r = await api("POST", "/business/tickets/scan", T.lastnik, { serial: await serial(A7.id) });
    assert(r.status === 409, "vstopnica 0 EUR naroceno po odpovedi: 409", r.body);
    // vracilo prek Stripe (nadzorna plosca, webhook) na AKTIVNEM dogodku: naroceno refunded -> vstopnica na vratih ne velja
    S.ch[S.pi[D2.pi].latest_charge].amount_refunded = 2000;
    w = await webhook("charge.refunded", { id: S.pi[D2.pi].latest_charge });
    r = await api("POST", "/business/tickets/scan", T.lastnik, { serial: await serial(D2.id) });
    assert(w.status === 200 && r.status === 409 && r.body.result === "unpaid", "vrnjena vstopnica na aktivnem dogodku: 409", [r.status, r.body.result]);
    r = await api("POST", "/business/tickets/scan", T.lastnik, { serial: await serial(D3.id) });
    assert(r.status === 200 && r.body.result === "ok", "veljavna vstopnica (tudi s sporom na drugem naroceno istega dogodka): vstop dovoljen", r.body);

    // ================================================================
    console.log("\n# 12. Zanesljivost: velika odpoved ne blokira drugih zahtevkov");
    for (let i = 0; i < 40; i++) await narocilo({ ev: evG, uporabnik: i % 2 ? U.ana : U.bor, cena: 1000 });
    S.zakasnitev = 60;
    const t1 = Date.now();
    r = await api("DELETE", `/events/${evG}`, T.lastnik);
    const trajanje2 = Date.now() - t1;
    assert(r.status === 200 && r.body.refunds_queued === 40 && trajanje2 < 1000, `odpoved z 40 naroceni: refunds_queued 40, ${trajanje2} ms`, [r.status, r.body.refunds_queued]);
    const casi = [];
    const sproti = [];
    const zacetek = Date.now();
    while (Date.now() - zacetek < 2500) {
      const t = Date.now();
      const odgovori = await Promise.all([api("GET", "/events"), api("GET", "/clubs"), api("GET", "/events"), api("GET", "/clubs"), api("GET", "/me", T.ana)]);
      casi.push(Date.now() - t); sproti.push(...odgovori.map(x => x.status));
      await pocakaj(100);
    }
    const stanjeG = (await pool.query("SELECT COUNT(*) FILTER (WHERE stanje='opravljeno')::int AS koncano, COUNT(*)::int AS vse FROM vracila WHERE event_id=$1", [evG])).rows[0];
    assert(stanjeG.koncano < 40 && stanjeG.koncano > 0, `med obdelavo (${stanjeG.koncano}/40 koncanih) zahtevki tecejo`, stanjeG);
    assert(sproti.length >= 20 && sproti.every(s => s === 200), `GET /events, /clubs, /me: vsi 200 med obdelavo (${sproti.length} zahtevkov)`, sproti.filter(s => s !== 200));
    assert(Math.max(...casi) < 1000, `najpocasnejsa serija 5 zahtevkov ${Math.max(...casi)} ms (< 1 s)`, casi);
    r = await api("POST", "/business/tickets/scan", T.lastnik, { serial: await serial(D3.id) });
    assert(r.status === 409 && r.body.result === "already_used", "sken med obdelavo odgovarja (ze uporabljena vstopnica: 409 already_used)", r.body);
    S.zakasnitev = 0;
    assert(await cakaj(async () => (await pool.query("SELECT COUNT(*)::int AS n FROM vracila WHERE event_id=$1 AND stanje='opravljeno'", [evG])).rows[0].n === 40, 30000), "vseh 40 vracil opravljenih");
    assert(S.refundi.filter(x => (x.params.payment_intent || "") && Object.keys(S.pi).includes(x.payment_intent)).length >= 40, "40 Stripovih vracil za dogodek G");
    assert(new Set(S.refundi.map(x => x.kljuc).filter(Boolean)).size === S.refundi.filter(x => x.kljuc).length, "vsako vracilo ima svoj idempotentni kljuc (brez podvajanja)");

    // Odpoved dogodka brez placanih narocil: stara pot (izbris), brez vracil
    r = await api("DELETE", `/events/${evPrazen}`, T.lastnik);
    assert(r.status === 200 && r.body.message === "Event deleted.", "dogodek brez placanih narocil: izbris kot doslej");
    assert(!/\[vracila\] tek:|Unhandled|TypeError|ReferenceError/.test(log), "dnevnik brez nepricakovanih napak obdelovalca");
  } catch (e) { fail++; console.log("  ✗ NEPRICAKOVANA NAPAKA:", e); }
  finally {
    srv.kill();
    await pocakaj(300);
    console.log(`\n${ok} OK, ${fail} NAPAK`);
    if (fail) console.log("--- dnevnik streznika (zadnjih 3000 znakov) ---\n" + log.slice(-3000));
    process.exit(fail ? 1 : 0);
  }
})();
