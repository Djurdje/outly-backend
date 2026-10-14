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
const S = { pi: {}, ch: {}, fee: {}, bt: {}, tr: {}, seje: {}, spori: {}, idem: {}, refundi: [], reById: {}, fee_refundi: [], reversali: [], klici: [], zakasnitev: 0, stR: 0, stSej: 0,
  refundHook: null, feeHook: null, revHook: null, idemPotekel: false, pending: new Set() };
const obrazec = (t) => { const o = {}; for (const [k, v] of new URLSearchParams(t)) o[k] = v; return o; };
function dodajPlacilo(pi, { amount, fee = 0, stripeFee = 59, vrnjeno = 0, btValuta = "eur", brezStripeFee = false }) {
  const n = pi.replace(/\W/g, "");
  S.pi[pi] = { id: pi, object: "payment_intent", status: "succeeded", amount, latest_charge: "ch_" + n };
  S.ch["ch_" + n] = { id: "ch_" + n, object: "charge", amount, currency: "eur", amount_refunded: vrnjeno, payment_intent: pi, application_fee: fee > 0 ? "fee_" + n : null, balance_transaction: "txn_" + n, transfer: "tr_" + n };
  S.tr["tr_" + n] = { id: "tr_" + n, object: "transfer", amount, amount_reversed: 0, currency: "eur" };
  if (fee > 0) S.fee["fee_" + n] = { id: "fee_" + n, object: "application_fee", amount: fee, amount_refunded: 0, currency: "eur" };
  S.bt["txn_" + n] = { id: "txn_" + n, object: "balance_transaction", currency: btValuta, fee: stripeFee, fee_details: brezStripeFee ? [{ type: "application_fee", amount: fee, currency: btValuta }] : [{ type: "stripe_fee", amount: stripeFee, currency: btValuta }] };
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
    if (req.method === "GET" && (m = u.match(/^\/v1\/charges\/(\w+)$/))) {
      if (!S.ch[m[1]]) return napaka(404, "invalid_request_error", "resource_missing", "No such charge");
      const ex = [...url.searchParams].filter(([k]) => /^expand/.test(k)).map(([, v]) => v);
      const c0 = S.ch[m[1]];
      return odg(200, ex.includes("application_fee") && c0.application_fee ? { ...c0, application_fee: S.fee[c0.application_fee] } : c0);
    }
    if (req.method === "GET" && (m = u.match(/^\/v1\/refunds\/(re_\w+)$/))) return S.reById[m[1]] ? odg(200, S.reById[m[1]]) : napaka(404, "invalid_request_error", "resource_missing", "No such refund");
    if (req.method === "GET" && (m = u.match(/^\/v1\/transfers\/(tr_\w+)$/))) return S.tr[m[1]] ? odg(200, S.tr[m[1]]) : napaka(404, "invalid_request_error", "resource_missing", "No such transfer");
    if (req.method === "GET" && (m = u.match(/^\/v1\/transfers\/(tr_\w+)\/reversals$/))) return odg(200, { object: "list", has_more: false, data: S.reversali.filter(x => x.transfer === m[1]) });
    if (req.method === "POST" && (m = u.match(/^\/v1\/transfers\/(tr_\w+)\/reversals$/))) {
      if (kljuc && S.idem[kljuc]) return odg(200, S.idem[kljuc]);
      const hook = S.revHook && S.revHook(m[1], kljuc);
      if (hook) return odg(hook.status, hook.body);
      const t = S.tr[m[1]]; if (!t) return napaka(404, "invalid_request_error", "resource_missing", "No such transfer");
      const znesek = Number(p.amount);
      if (znesek > t.amount - t.amount_reversed) return napaka(400, "invalid_request_error", "amount_too_large", "Reversal amount is greater than the unreversed amount on the transfer.");
      t.amount_reversed += znesek;
      const md = {}; for (const [k, v] of Object.entries(p)) { const mm = k.match(/^metadata\[(\w+)\]$/); if (mm) md[mm[1]] = v; }
      const rv = { id: "trr_" + (S.reversali.length + 1), object: "transfer_reversal", amount: znesek, transfer: t.id, metadata: md };
      S.reversali.push({ ...rv, kljuc }); if (kljuc) S.idem[kljuc] = rv;
      return odg(200, rv);
    }
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
      const re = { id: "re_" + (++S.stR), object: "refund", amount: znesek, status: S.pending.has(pi.id) ? "pending" : "succeeded", payment_intent: pi.id, charge: ch.id, metadata: md };
      S.reById[re.id] = re;
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
      const md = {}; for (const [k, v] of Object.entries(p)) { const mm = k.match(/^metadata\[(\w+)\]$/); if (mm) md[mm[1]] = v; }
      const fr = { id: "fr_" + (S.fee_refundi.length + 1), object: "fee_refund", amount: znesek, fee: f.id, metadata: md };
      S.fee_refundi.push({ ...fr, params: p, kljuc }); if (kljuc) S.idem[kljuc] = fr;
      return odg(200, fr);
    }
    if (req.method === "GET" && (m = u.match(/^\/v1\/application_fees\/(fee_\w+)\/refunds$/))) return odg(200, { object: "list", has_more: false, data: S.fee_refundi.filter(x => x.fee === m[1]) });
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
    VRACILA_TICK_MS: "250", VRACILA_RAZMAK_MS: "10", VRACILA_ZAMIK_S: "0", VRACILA_PREMOR_MS: "150", VRACILA_POSKUSOV: "3", VRACILA_SWEEP_MS: "400", VRACILA_MAIL_RAZMAK_MS: "0", VRACILA_POTRDITEV_MS: "700" },
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

    // Indeks za mail »vrnili smo« (048, #233): pogoj poizvedbe (VRACILO_MAIL.vrnjeno) NE vsebuje stripe_vracilo_id, zato ga indeks ne sme imeti (sicer ga planer ne uporabi).
    const ixMail = (await pool.query("SELECT indexdef FROM pg_indexes WHERE tablename='vracila' AND indexname='vracila_mail_idx'")).rows[0];
    assert(ixMail && !/stripe_vracilo_id/.test(ixMail.indexdef) && /brez_stripa/.test(ixMail.indexdef) && /mail_poslano_at IS NULL/.test(ixMail.indexdef), "vracila_mail_idx brez pogoja stripe_vracilo_id (048)", ixMail);

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
    console.log("\n# 5. Obvestila kupcem (Martin 12. 10.: takoj »odpovedan, vracilo na poti« po zamiku, nato »vrnili smo«; natanko enkrat vsak)");
    const odpMaili = () => R.poslano.filter(m => /Event cancelled/.test(m.subject));
    const vrnMaili = () => R.poslano.filter(m => /^Vračilo \/ Refund/.test(m.subject));
    assert(await cakaj(() => odpMaili().length >= 9 && vrnMaili().length >= 6), "9 mailov »odpovedan« + 6 mailov »vrnili smo«", [odpMaili().length, vrnMaili().length]);
    await pocakaj(700);
    assert(odpMaili().length === 9 && vrnMaili().length === 6, "natanko 9 + 6 (A12 anonimiziran brez maila; 0 EUR/test samo prvi; A9 rocno samo prvi)", [odpMaili().length, vrnMaili().length]);
    const naslovi = (seznam, e) => seznam.filter(m => m.to === e).length;
    const eA = `u${U.ana}@outly.si`, eB = `u${U.bor}@outly.si`;
    assert(naslovi(odpMaili(), eA) === 5 && naslovi(odpMaili(), eB) === 3 && naslovi(odpMaili(), "gost@outly.si") === 1, "»odpovedan«: ana 5 (A1, A4, A5, A7, A9), bor 3 (A2, A6, A8), gost 1", [naslovi(odpMaili(), eA), naslovi(odpMaili(), eB)]);
    assert(naslovi(vrnMaili(), eA) === 3 && naslovi(vrnMaili(), eB) === 2 && naslovi(vrnMaili(), "gost@outly.si") === 1, "»vrnili smo«: ana 3 (A1, A4, A5), bor 2 (A2, A6), gost 1", [naslovi(vrnMaili(), eA), naslovi(vrnMaili(), eB)]);
    assert(!R.poslano.some(m => m.to === "izbrisan-12@outly.invalid"), "anonimiziran gost (*@outly.invalid): brez maila");
    const m1 = odpMaili().find(m => m.subject.includes(A1.ref)), m1b = vrnMaili().find(m => m.subject.includes(A1.ref));
    assert(m1 && m1.subject === `Dogodek odpovedan / Event cancelled: Odpovedana noc (${A1.ref})`, "zadeva dvojezicna", m1 && m1.subject);
    assert(m1 && /We are refunding the full amount of 20\.00 EUR/.test(m1.text) && /Celoten znesek 20,00 EUR vam vrnemo/.test(m1.text) && /another email/.test(m1.text), "mail 1: vracilo je v teku, celoten znesek (SL in EN)", m1 && m1.text);
    assert(m1b && /We have refunded the full amount of 20\.00 EUR/.test(m1b.text) && /Vrnili smo vam celoten znesek 20,00 EUR/.test(m1b.text) && /no longer valid/.test(m1b.text) && !/cid:|<img/i.test(m1b.html), "mail 2: vrnili smo (SL in EN), vstopnice ne veljajo, brez QR", m1b && m1b.text);
    const m8 = odpMaili().find(m => m.subject.includes(A8.ref)), m7 = odpMaili().find(m => m.subject.includes(A7.ref));
    assert(m8 && /Nothing was charged for this order/.test(m8.text) && m7 && /Nothing was charged for this order/.test(m7.text), "0 EUR in testno: en mail »nic ni bilo zaracunano«");
    assert(!vrnMaili().some(m => m.subject.includes(A7.ref) || m.subject.includes(A8.ref) || m.subject.includes(A9.ref)), "0 EUR, test in rocno (A9): brez maila »vrnili smo«");
    const m4 = odpMaili().find(m => m.subject.includes(A4.ref));
    assert(m4 && /VIP table T1/.test(m4.text) && /150\.00 EUR/.test(m4.text), "VIP miza: mail omenja mizo in znesek");
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM vracila WHERE mail_poslano_at IS NOT NULL")).rows[0].n === 6 && (await pool.query("SELECT COUNT(*)::int AS n FROM vracila WHERE mail_odpoved_poslano_at IS NOT NULL")).rows[0].n === 9, "mail_poslano_at 6, mail_odpoved_poslano_at 9");

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
    assert(R.poslano.length === stMail0, "ponovni zagon: nobenega maila kupcu drugic", R.poslano.length - stMail0);
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
    const idF = (await pool.query("INSERT INTO vracila (order_id, event_id, razlog, naslednji_poskus_at, mail_odpoved_po_at) VALUES ($1, $2, 'event_cancelled', NOW() + INTERVAL '1 hour', NOW() + INTERVAL '1 hour') RETURNING id", [F1.id, evF])).rows[0].id;
    r = await api("PATCH", `/events/${evF}`, T.lastnik, { status: "cancelled" });
    assert(r.status === 200 && (await pool.query("SELECT 1 FROM odpovedi_dogodkov WHERE event_id=$1", [evF])).rows.length === 1, "PATCH status cancelled: dogodek odpovedan, sprozilec zapise odpoved", r.status);
    r = await api("PATCH", `/events/${evF}`, T.lastnik, { status: "published" });
    assert(r.status === 200, "lastnik dogodek obnovi, preden steče denar");
    await pool.query("UPDATE vracila SET naslednji_poskus_at = NOW() WHERE id=$1", [idF]);
    assert(await cakaj(async () => (await vracilo(F1.id)).stanje === "preklicano"), "dogodek spet objavljen: vracilo `preklicano`");
    assert(refA(F1.pi).length === 0 && (await vrsticaN(F1.id)).status === "paid", "brez Stripa, naroceno placano");
    await pocakaj(500);
    assert(!R.poslano.some(m => m.subject.includes(F1.ref)), "obnova v zamiku: kupec NI dobil maila odpovedan (odpoved ni dokoncna)");
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
    assert(await cakaj(() => mailiNa("ana@outly.si").some(m => m.subject.includes("Noc placila po preklicu"))), "kupec dobi mail: placilo vrnjeno, naroceno ni bilo zakljuceno");
    const mH = mailiNa("ana@outly.si").find(m => m.subject.includes("Noc placila po preklicu"));
    assert(mH && /the order was not completed, so no tickets were issued/.test(mH.text) && /naročilo ni bilo zaključeno/.test(mH.text) && /20\.00 EUR/.test(mH.text), "mail inactive_order: SL + EN, znesek", mH && mH.text);
    await pocakaj(600);
    assert(mailiNa("ana@outly.si").filter(m => m.subject.includes("Noc placila po preklicu")).length === 1, "mail natanko enkrat");

    // ================================================================
    console.log("\n# 10. Spori (chargeback): vstopnice neveljavne med sporom, povrnitev od kluba ob lost");
    await pool.query("UPDATE events SET start_at = NOW() + INTERVAL '1 hour' WHERE id IN ($1, $2)", [evA, evD]);   // okno skena odprto
    const serial = async (oid) => (await pool.query("SELECT serial FROM tickets WHERE order_id=$1 ORDER BY id LIMIT 1", [oid])).rows[0].serial;
    const skeniraj = (oid) => serial(oid).then(se => api("POST", "/business/tickets/scan", T.lastnik, { serial: se }));
    const cD1 = S.pi[D1.pi].latest_charge, stRef9 = S.refundi.length, stFee9 = S.fee_refundi.length;
    const dispute = (id, pi, { znesek, razlog = "fraudulent", status = "needs_response", pristojbina = 0 }) => {
      S.spori[id] = { id, object: "dispute", charge: S.pi[pi].latest_charge, payment_intent: pi, amount: znesek, currency: "eur", reason: razlog, status, created: Math.floor(Date.now() / 1000),
        evidence_details: { due_by: Math.floor(Date.now() / 1000) + 7 * 86400 }, balance_transactions: pristojbina ? [{ id: "txn_dp_" + id, object: "balance_transaction", amount: -znesek, fee: pristojbina, currency: "eur", reporting_category: "dispute" }] : [] };
    };
    r = await skeniraj(D1.id);
    assert(r.status === 200 && r.body.result === "ok", "pred sporom: vstopnica D1 se sprejme (preverjeno z drugo vstopnico spodaj), ne porabimo je");
    // zgornji sken je vstopnico porabil: za preizkus spora vzamemo nova naroceila
    const D1b = await narocilo({ ev: evD, uporabnik: U.ana, cena: 2000 });
    dispute("dp_1", D1b.pi, { znesek: 2000 });
    w = await webhook("charge.dispute.created", { id: "dp_1" });
    assert(w.status === 200, "webhook charge.dispute.created: 200", w);
    let sp = (await pool.query("SELECT * FROM spori WHERE id='dp_1'")).rows[0];
    assert(sp && sp.order_id === D1b.id && sp.stanje === "needs_response" && sp.razlog === "fraudulent" && sp.znesek_cents === 2000 && sp.valuta === "EUR" && sp.rok_dokazov_at && !sp.zaprt_at && sp.povrnitev_stanje === null, "spor zapisan na naročilo; povrnitve se ni (spor ni izgubljen)", sp);
    const oD1 = await vrsticaN(D1b.id);
    assert(oD1.status === "paid" && oD1.refunded_cents === 0 && (await vstopnice(D1b.id)).every(x => x === "valid"), "narocilo ostane placano, status vstopnice valid (denar se ne premakne)");
    r = await skeniraj(D1b.id);
    assert(r.status === 409 && r.body.result === "payment_disputed" && /disputed/.test(r.body.message) && r.body.ticket.payment_disputed === true, "SKEN: vstopnica narocila s sporom -> 409 payment_disputed + sporocilo vratarju", r.body);
    const sl = await api("GET", `/business/events/${evD}/scan-list`, T.lastnik);
    const tSl = sl.body.tickets.find(x => x.serial === (r.body.ticket.serial));
    assert(sl.status === 200 && tSl && tSl.status === "unpaid" && tSl.payment_disputed === true && sl.body.tickets.some(x => x.payment_disputed === false), "scan-list (brez povezave): status unpaid (rdece) + novo polje payment_disputed", tSl);
    const mt = await api("GET", "/me/tickets", T.ana);
    assert(mt.status === 200 && mt.body.find(x => x.id === r.body.ticket.id).payment_disputed === true && mt.body.some(x => x.payment_disputed === false), "/me/tickets: novo polje payment_disputed (true samo za spor)");
    const mo = await api("GET", "/me/orders", T.ana);
    const moD = mo.body.find && mo.body.find(o => Number(o.id) === Number(D1b.id)), moC = mo.body.find && mo.body.find(o => Number(o.id) === Number(D1.id));
    assert(mo.status === 200 && moD && moD.tickets.length > 0 && moD.tickets.every(x => x.payment_disputed === true) && moC && moC.tickets.length > 0 && moC.tickets.every(x => x.payment_disputed === false), "GET /me/orders: tickets[].payment_disputed (true pri sporu, false brez)", { d: moD && moD.tickets.map(x => x.payment_disputed), c: moC && moC.tickets.map(x => x.payment_disputed) });
    // Poslovni seznam vstopnic dogodka (splet #62, iOS #93 berejo payment_disputed tudi tu) in /guest/ticket (bel seznam polj)
    const tDisp = r.body.ticket.id, tCist = (await pool.query("SELECT t.id FROM tickets t WHERE t.event_id=$1 AND t.id <> $2 AND NOT EXISTS (SELECT 1 FROM spori sp WHERE sp.order_id = t.order_id) ORDER BY t.id LIMIT 1", [evD, tDisp])).rows[0].id * 1;
    const bt = await api("GET", `/business/events/${evD}/tickets`, T.lastnik);
    const btD = bt.body.find && bt.body.find(x => x.id === tDisp), btC = bt.body.find && bt.body.find(x => x.id === tCist);
    assert(bt.status === 200 && btD && btD.payment_disputed === true && btD.status === "valid" && btC && btC.payment_disputed === false, "GET /business/events/:id/tickets: payment_disputed true pri sporu, false brez (status ostane valid)", { btD, btC });
    const prejHolder = (await pool.query("SELECT id, holder_user_id, holder_is_guest FROM tickets WHERE id = ANY($1)", [[tDisp, tCist]])).rows;
    const zDisp = "d".repeat(43), zCist = "c".repeat(43);
    await pool.query("UPDATE tickets SET holder_is_guest = TRUE, holder_user_id = NULL WHERE id = ANY($1)", [[tDisp, tCist]]);
    await pool.query("INSERT INTO gost_zetoni_vstopnic (token_hash, ticket_id) VALUES ($1, $2), ($3, $4)", [crypto.createHash("sha256").update(zDisp).digest("hex"), tDisp, crypto.createHash("sha256").update(zCist).digest("hex"), tCist]);
    const gD = await api("GET", "/guest/ticket", null, undefined, { "X-Guest-Token": zDisp }), gC = await api("GET", "/guest/ticket", null, undefined, { "X-Guest-Token": zCist });
    assert(gD.status === 200 && gD.body.ticket.payment_disputed === true && gC.status === 200 && gC.body.ticket.payment_disputed === false, "GET /guest/ticket: payment_disputed true pri sporu, false brez", { d: gD.body.ticket && gD.body.ticket.payment_disputed, c: gC.body.ticket && gC.body.ticket.payment_disputed });
    await pool.query("DELETE FROM gost_zetoni_vstopnic WHERE ticket_id = ANY($1)", [[tDisp, tCist]]);
    for (const x of prejHolder) await pool.query("UPDATE tickets SET holder_is_guest = $2, holder_user_id = $3 WHERE id = $1", [x.id, x.holder_is_guest, x.holder_user_id]);
    const sb = await api("POST", "/business/tickets/scan-batch", T.lastnik, { device_id: "dev-spor-1", scans: [{ client_scan_id: "cs-spor-0001", serial: r.body.ticket.serial }] });
    assert(sb.status === 200 && sb.body.results && sb.body.results[0].result === "payment_disputed", "scan-batch: payment_disputed", sb.body);
    const casiSkena = [];
    for (let i = 0; i < 30; i++) { const t = Date.now(); const x = await api("POST", "/business/tickets/scan", T.lastnik, { serial: r.body.ticket.serial }); casiSkena.push(Date.now() - t); if (x.status !== 409) casiSkena.push(99999); }
    assert(Math.max(...casiSkena) < 500, `sken zavrnjene vstopnice hiter: 30 skenov, najpocasnejsi ${Math.max(...casiSkena)} ms (en indeksiran EXISTS, brez Stripa)`, casiSkena);
    assert(/\[spori\] POZOR: nov spor dp_1 \(fraudulent\) 2000 c, stanje needs_response, narocilo OUT-VR\d+/.test(log), "alarm [spori] POZOR v dnevniku");
    assert(await cakaj(() => mailiNa("lastnik@outly.si").some(m => /Payment dispute/.test(m.subject))), "mail lastniku kluba ob odprtju spora");
    const ms = mailiNa("lastnik@outly.si").find(m => /Payment dispute/.test(m.subject));
    assert(ms && Array.isArray(ms.to) && ms.to.includes("info@stripe-club.si") && ms.to.includes("lastnik@outly.si"), "prejemnika: lastnik kluba + kontaktni e-naslov kluba", ms && ms.to);
    assert(ms && /Disputed amount: 20\.00 EUR/.test(ms.text) && /Znesek spora: 20,00 EUR/.test(ms.text) && /not valid at the door/.test(ms.text), "besedilo dvojezicno; vstopnice na vratih ne veljajo", ms && ms.text);
    w = await webhook("charge.dispute.created", { id: "dp_1" }, w.id);
    assert(w.body.duplicate === true, "isti dogodek: duplicate");

    // won: vstopnica spet velja
    const D4 = await narocilo({ ev: evD, uporabnik: U.bor, cena: 2000 });
    dispute("dp_w", D4.pi, { znesek: 2000 });
    await webhook("charge.dispute.created", { id: "dp_w" });
    r = await skeniraj(D4.id);
    assert(r.status === 409 && r.body.result === "payment_disputed", "dp_w odprt: sken zavrne");
    S.spori.dp_w.status = "won";
    w = await webhook("charge.dispute.closed", { id: "dp_w" });
    r = await skeniraj(D4.id);
    assert(w.status === 200 && r.status === 200 && r.body.result === "ok", "dp_w won: vstopnica SPET velja (sprejeta)", [r.status, r.body.result]);
    assert((await pool.query("SELECT povrnitev_stanje FROM spori WHERE id='dp_w'")).rows[0].povrnitev_stanje === null, "won: povrnitve od kluba ni");
    assert(await cakaj(() => mailiNa(eB).some(m => /Dispute closed/.test(m.subject)) || mailiNa("lastnik@outly.si").filter(m => /Dispute closed/.test(m.subject)).length >= 1), "mail ob zaprtju (won) lastniku");
    const mw = mailiNa("lastnik@outly.si").find(m => /Dispute closed/.test(m.subject));
    assert(mw && /valid at the door again/.test(mw.text), "mail won: vstopnice spet veljajo", mw && mw.text);

    // poizvedba (warning_needs_response) NI chargeback: vrat ne zapre
    const Dw = await narocilo({ ev: evD, uporabnik: U.bor, cena: 2000 });
    dispute("dp_warn", Dw.pi, { znesek: 2000, status: "warning_needs_response", razlog: "general" });
    w = await webhook("charge.dispute.created", { id: "dp_warn" });
    r = await skeniraj(Dw.id);
    assert(w.status === 200 && (await pool.query("SELECT stanje FROM spori WHERE id='dp_warn'")).rows[0].stanje === "warning_needs_response" && r.status === 200 && r.body.result === "ok", "S-A: warning_needs_response (poizvedba, ne chargeback): zapisan, alarm, a sken vstopnico SPREJME", [r.status, r.body.result]);
    assert(await cakaj(() => mailiNa("lastnik@outly.si").some(m => /Payment dispute/.test(m.subject) && m.subject.includes(Dw.ref))), "S-A: mail lastniku o poizvedbi");
    const mwarn = mailiNa("lastnik@outly.si").find(m => /Payment dispute/.test(m.subject) && m.subject.includes(Dw.ref));
    assert(/inquiry/.test(mwarn.text) && /stay valid/.test(mwarn.text) && !/not valid at the door/.test(mwarn.text), "S-A: mail pove, da vstopnice ostanejo veljavne", mwarn.text);

    // lost, poceni vstopnica: omejitev na neobrnjen del transferja (transfer 2000, terjatev bi bila 1800 + 500 = 2300)
    dispute("dp_1", D1b.pi, { znesek: 2000, status: "lost", pristojbina: 500 });
    const kliciRev0 = klici("POST", /reversals/).length;
    w = await webhook("charge.dispute.closed", { id: "dp_1" });
    assert(w.status === 200, "dispute.closed (lost)");
    assert(await cakaj(async () => (await pool.query("SELECT povrnitev_stanje FROM spori WHERE id='dp_1'")).rows[0].povrnitev_stanje === "opravljeno"), "povrnitev od kluba opravljena");
    sp = (await pool.query("SELECT * FROM spori WHERE id='dp_1'")).rows[0];
    const trD1 = "tr_" + D1b.pi.replace(/\W/g, "");
    assert(sp.stanje === "lost" && sp.zaprt_at && sp.povrnitev_zelena_cents === 2300 && sp.povrnitev_cents === 2000 && sp.pristojbina_spora_cents === 500 && sp.reversal_id, "zelena 2300 (znesek - provizija 200 + pristojbina spora 500, iz balance_transactions), vrnjeno omejeno na 2000", sp);
    const rev1 = S.reversali.filter(x => x.transfer === trD1);
    assert(rev1.length === 1 && rev1[0].amount === 2000 && rev1[0].kljuc === "outly-spor-dp_1" && rev1[0].metadata.spor_id === "dp_1", "transfer reversal: znesek, idempotentni kljuc outly-spor-<id>, metadata", rev1);
    assert(/neobrnjeni del transferja ne zadosti: 300 c nosi Outly/.test(sp.povrnitev_napaka) && /\[spori\] POZOR: spor dp_1: od kluba je mogoce povrniti samo 2000 c od 2300 c/.test(log), "razliko (300 c) nosi Outly: zapis v vrstici + alarm POZOR");
    w = await webhook("charge.dispute.closed", { id: "dp_1" });
    await webhook("charge.dispute.updated", { id: "dp_1" });
    await pocakaj(900);
    assert(klici("POST", /reversals/).length === kliciRev0 + 1 && S.reversali.filter(x => x.transfer === trD1).length === 1, "ponovljen webhook (nov evt): BREZ dvojne povrnitve");
    r = await skeniraj(D1b.id);
    assert(r.status === 409 && r.body.result === "payment_disputed", "lost: vstopnica OSTANE neveljavna");
    assert(await cakaj(() => mailiNa("lastnik@outly.si").some(m => /Dispute closed/.test(m.subject) && m.subject.includes(D1b.ref))), "mail ob zaprtju (lost)");
    const ml = mailiNa("lastnik@outly.si").find(m => /Dispute closed/.test(m.subject) && m.subject.includes(D1b.ref));
    assert(ml && /we recovered 20\.00 EUR from your Stripe account/.test(ml.text) && /smo povrnili 20,00 EUR/.test(ml.text) && /stay invalid/.test(ml.text), "mail lost: navede povrnjen znesek (SL + EN)", ml && ml.text);

    // lost, draga vstopnica: polna terjatev brez omejitve
    const D5 = await narocilo({ ev: evD, uporabnik: U.bor, cena: 100000 });
    dispute("dp_5", D5.pi, { znesek: 100000, status: "needs_response", pristojbina: 1500 });
    await webhook("charge.dispute.created", { id: "dp_5" });
    S.spori.dp_5.status = "lost";
    await webhook("charge.dispute.closed", { id: "dp_5" });
    assert(await cakaj(async () => (await pool.query("SELECT povrnitev_stanje FROM spori WHERE id='dp_5'")).rows[0].povrnitev_stanje === "opravljeno"), "dp_5 povrnitev opravljena");
    sp = (await pool.query("SELECT * FROM spori WHERE id='dp_5'")).rows[0];
    assert(sp.povrnitev_zelena_cents === 91500 && sp.povrnitev_cents === 91500 && sp.povrnitev_napaka === null && S.reversali.find(x => x.metadata.spor_id === "dp_5").amount === 91500, "dp_5: 100000 - provizija 10000 + pristojbina 1500 = 91500, brez omejitve, nic ne nosi Outly");
    const oD5 = await vrsticaN(D5.id);
    assert(oD5.status === "paid" && oD5.refunded_cents === 0 && S.refundi.length === stRef9 && S.fee_refundi.length === stFee9, "lost: naroceno ostane placano, NI vracila kupcu (samo povrnitev od kluba)");

    // neuspeh povrnitve (klub nima sredstev): stanje + alarm, admin retry
    const D6 = await narocilo({ ev: evD, uporabnik: U.ana, cena: 100000 });
    const trD6 = "tr_" + D6.pi.replace(/\W/g, "");
    S.revHook = (tr) => (tr === trD6 ? { status: 400, body: { error: { type: "invalid_request_error", code: "balance_insufficient", message: "Insufficient funds in Stripe account." } } } : null);
    dispute("dp_6", D6.pi, { znesek: 100000, status: "lost", pristojbina: 1500 });
    await webhook("charge.dispute.created", { id: "dp_6" });
    await webhook("charge.dispute.closed", { id: "dp_6" });
    assert(await cakaj(async () => (await pool.query("SELECT povrnitev_stanje FROM spori WHERE id='dp_6'")).rows[0].povrnitev_stanje === "ni_uspelo"), "dp_6: povrnitev ni_uspelo (balance_insufficient)");
    assert(/\[spori\] POZOR: povrnitev od kluba za izgubljen spor dp_6 NI uspela/.test(log) && /balance_insufficient/.test(log), "alarm [spori] POZOR (nikoli tiho)");
    ad = await api("GET", "/admin/api/disputes", T.admin);
    const a6 = ad.body.items.find(x => x.id === "dp_6");
    assert(a6 && a6.recovery_state === "ni_uspelo" && /balance_insufficient/.test(a6.recovery_error) && a6.recovery_wanted_cents === 91500, "admin: GET /admin/api/disputes kaze recovery_state ni_uspelo", a6);
    assert((await api("GET", "/admin/api/summary", T.admin)).body.dispute_recovery_attention === 1, "admin summary: dispute_recovery_attention 1");
    assert(await cakaj(() => mailiNa("lastnik@outly.si").some(m => /Dispute closed/.test(m.subject) && m.subject.includes(D6.ref))), "mail ob zaprtju (lost, povrnitev ni uspela)");
    const m6 = mailiNa("lastnik@outly.si").find(m => /Dispute closed/.test(m.subject) && m.subject.includes(D6.ref));
    assert(m6 && /did not succeed/.test(m6.text), "mail: samodejna povrnitev ni uspela, Outly bo kontaktiral", m6 && m6.text);
    S.revHook = null;
    assert((await api("POST", "/admin/api/disputes/dp_6/retry", T.lastnik)).status === 403 && (await api("POST", "/admin/api/disputes/slab/retry", T.admin)).status === 400, "retry: lastnik 403, slab id 400");
    r = await api("POST", "/admin/api/disputes/dp_6/retry", T.admin);
    assert(r.status === 200, "admin: POST /admin/api/disputes/dp_6/retry", r.body);
    assert(await cakaj(async () => (await pool.query("SELECT povrnitev_stanje FROM spori WHERE id='dp_6'")).rows[0].povrnitev_stanje === "opravljeno"), "dp_6 po retry: opravljeno");
    const rev6 = S.reversali.filter(x => x.transfer === trD6);
    assert(rev6.length === 1 && rev6[0].amount === 91500 && rev6[0].kljuc === "outly-spor-dp_6-g1", "retry: nova generacija kljuca (-g1), natanko en reversal", rev6.map(x => x.kljuc));
    assert((await api("POST", "/admin/api/disputes/dp_6/retry", T.admin)).status === 409, "retry opravljenega: 409");

    // spor brez narocila
    S.spori.dp_2 = { id: "dp_2", object: "dispute", charge: "ch_neznan", payment_intent: "pi_neznan", amount: 500, currency: "eur", reason: "general", status: "needs_response", created: Math.floor(Date.now() / 1000), balance_transactions: [] };
    const mailov = R.poslano.length;
    w = await webhook("charge.dispute.created", { id: "dp_2" });
    sp = (await pool.query("SELECT * FROM spori WHERE id='dp_2'")).rows[0];
    assert(w.status === 200 && sp && sp.order_id === null, "spor brez narocila: zapisan z order_id NULL");
    assert(/\[spori\] POZOR: spor dp_2 .* narocilo NEZNANO/.test(log), "alarm: spora ni mogoce povezati z narocilom");
    await pocakaj(600);
    assert(R.poslano.length === mailov, "spor brez narocila: nobenega maila");
    S.spori.dp_3 = { id: "dp_3", object: "dispute", charge: "ch_neznan3", payment_intent: "pi_neznan3", amount: 700, currency: "eur", reason: "general", status: "lost", created: Math.floor(Date.now() / 1000), balance_transactions: [{ id: "txn_x", fee: 1500, currency: "eur" }] };
    const kliciRev3 = klici("POST", /reversals/).length;
    w = await webhook("charge.dispute.closed", { id: "dp_3" });
    sp = (await pool.query("SELECT * FROM spori WHERE id='dp_3'")).rows[0];
    await pocakaj(900);
    assert(w.status === 200 && sp.order_id === null && sp.povrnitev_stanje === "rocno" && /brez narocila/.test(sp.povrnitev_napaka) && klici("POST", /reversals/).length === kliciRev3, "S-B: izgubljen spor BREZ narocila: povrnitev `rocno`, NI samodejnega reversala", [sp.povrnitev_stanje, sp.povrnitev_napaka]);
    assert(/\[spori\] POZOR: spor dp_3 .* IZGUBLJEN: povrnitev od kluba NI sprozena/.test(log), "S-B: alarm [spori] POZOR");
    ad = await api("GET", "/admin/api/disputes?open=1", T.admin);
    assert(ad.status === 200 && ad.body.items.length === 2 && ad.body.items.some(x => x.id === "dp_2") && ad.body.items.some(x => x.id === "dp_warn") && (await api("GET", "/admin/api/disputes", T.admin)).body.items.length === 7, "admin: GET /admin/api/disputes (odprti 2: dp_2 in poizvedba dp_warn, vsi 7)");

    // ================================================================
    console.log("\n# 11. Sken");
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

    // ================================================================
    console.log("\n# 13. Popravki po pregledu (V1, V2, S1-S3, N1-N3, N5)");
    const koncano = async (oid, stanja = ["opravljeno", "ni_uspelo", "rocno", "preklicano"], ms = 15000) => cakaj(async () => { const q = await vracilo(oid); return q && stanja.includes(q.stanje); }, ms);
    const vnesiVrsto = async (a, ev, polja = {}) => {
      const k = { stanje: "caka", znesek_cents: null, naslednji_poskus_at: new Date(Date.now() + 3600e3), ...polja };   // v prihodnosti: vrstica steče šele po odpovedi dogodka (odpovedSql)
      const kolone = Object.keys(k), vr = Object.values(k);
      return (await pool.query(`INSERT INTO vracila (order_id, event_id, razlog, ${kolone.join(", ")}) VALUES ($1, $2, 'event_cancelled', ${kolone.map((_, i) => "$" + (i + 3)).join(", ")}) RETURNING id`, [a.id, ev, ...vr])).rows[0].id;
    };
    const odpovedSql = async (ev) => { await pool.query("UPDATE events SET status='cancelled' WHERE id=$1", [ev]); await pool.query("UPDATE vracila SET naslednji_poskus_at = NOW() WHERE event_id=$1 AND stanje = 'caka' AND naslednji_poskus_at > NOW() + INTERVAL '30 minutes'", [ev]); };
    const reDodaj = (a, id, znesek, extra = {}) => {   // Stripe je nase vracilo ze naredil (korak A)
      const ch = S.ch[S.pi[a.pi].latest_charge]; ch.amount_refunded += znesek;
      const re = { id: "re_x" + id, object: "refund", amount: znesek, status: "succeeded", payment_intent: a.pi, charge: ch.id, metadata: { vracilo_id: String(id) }, ...extra };
      S.reById[re.id] = re; S.refundi.push({ ...re, params: {}, kljuc: "prej" }); return re;
    };

    // V1: korak A uspel, korak B (provizija) se ni narejen, medtem je webhook charge.refunded narocilo ze oznacil `refunded`: vracilo provizije MORA vseeno steci
    const evV1 = await dogodek("V1 noc", 5000);
    const V1 = await narocilo({ ev: evV1, uporabnik: U.ana, cena: 5000 });
    const idV1 = await vnesiVrsto(V1, evV1, { znesek_cents: 5000, stripe_vracilo_id: "re_xV1", stripe_stanje: "succeeded" });
    S.ch[S.pi[V1.pi].latest_charge].amount_refunded = 5000; S.reById.re_xV1 = { id: "re_xV1", object: "refund", amount: 5000, status: "succeeded", metadata: { vracilo_id: String(idV1) } };
    await pool.query("UPDATE orders SET status='refunded', refunded_cents=5000 WHERE id=$1", [V1.id]);   // kot webhook charge.refunded -> uveljaviVracilo
    await odpovedSql(evV1);
    assert(await koncano(V1.id), "V1: vrstica dokoncana");
    const fV1 = S.fee_refundi.filter(x => x.fee === "fee_" + V1.pi.replace(/\W/g, ""));
    assert((await vracilo(V1.id)).stanje === "opravljeno" && fV1.length === 1 && fV1[0].amount === 441, "V1: vracilo provizije (500 - pristojbina 59 = 441) KLJUB temu, da je narocilo ze `refunded`", [fV1.map(x => x.amount), (await vracilo(V1.id)).stanje]);
    assert(refA(V1.pi).length === 0, "V1: novega vracila kupcu NI");

    // V2: odpoved -> obnova (preklicano) -> ponovna odpoved: vracila MORAJO steci (DELETE in sweep)
    const evV2 = await dogodek("V2 noc", 2000), evV2b = await dogodek("V2b noc", 2000);
    const V2 = await narocilo({ ev: evV2, uporabnik: U.ana }), V2b = await narocilo({ ev: evV2b, uporabnik: U.bor });
    await vnesiVrsto(V2, evV2, { stanje: "preklicano", napaka: "dogodek ni vec odpovedan" });
    await vnesiVrsto(V2b, evV2b, { stanje: "preklicano", napaka: "dogodek ni vec odpovedan" });
    r = await api("DELETE", `/events/${evV2}`, T.lastnik);
    assert(r.status === 200 && r.body.refunds_queued === 1, "V2: ponovna odpoved (DELETE) vrne `preklicano` vrstico v vrsto", r.body);
    assert(await koncano(V2.id, ["opravljeno"]) && (await vracilo(V2.id)).stanje === "opravljeno" && refA(V2.pi).length === 1, "V2: vracilo opravljeno (DELETE)");
    await api("PATCH", `/events/${evV2b}`, T.lastnik, { status: "cancelled" });
    assert(await koncano(V2b.id, ["opravljeno"]) && (await vracilo(V2b.id)).stanje === "opravljeno" && refA(V2b.pi).length === 1, "V2: vracilo opravljeno (sweep po PATCH)", [await vracilo(V2b.id), (await pool.query("SELECT * FROM odpovedi_dogodkov WHERE event_id=$1", [evV2b])).rows, (await pool.query("SELECT status FROM events WHERE id=$1", [evV2b])).rows]);

    // S1: admin API: stevilo placanih narocil in znesek za potrditveno okno; admin panel zahteva potrditev
    const evS1 = await dogodek("S1 noc", 2000);
    await narocilo({ ev: evS1, uporabnik: U.ana }); const S1b = await narocilo({ ev: evS1, uporabnik: U.bor, cena: 3000 });
    await pool.query("UPDATE orders SET status='partially_refunded', refunded_cents=500 WHERE id=$1", [S1b.id]);
    ad = await api("GET", "/admin/api/events?status=published", T.admin);
    const eS1 = ad.body.find(x => x.id === evS1);
    assert(eS1 && eS1.paid_orders === 2 && eS1.paid_cents === 2000 + 2500, "S1: GET /admin/api/events ima paid_orders (2) in paid_cents (4500, brez ze vrnjenega)", eS1 && [eS1.paid_orders, eS1.paid_cents]);
    const html = require("fs").readFileSync(require("path").join(__dirname, "..", "admin", "index.html"), "utf8");
    assert(/window\.confirm\(besedilo\)/.test(html) && /x\.paid_orders/.test(html) && /VRNE v celoti/.test(html) && /status === "cancelled"/.test(html), "S1: admin panel pred »Umakni« pokaze potrditveno okno s stevilom placanih narocil");

    // S2: Stripe vracilo sprejme kot pending -> `potrditev`; izid z webhookom (succeeded -> opravljeno + mail »vrnili smo«; failed -> ni_uspelo + alarm) ali preverbo
    const evP = await dogodek("Pending noc", 2000);
    const P1 = await narocilo({ ev: evP, uporabnik: U.ana }), P2 = await narocilo({ ev: evP, uporabnik: U.bor }), P3 = await narocilo({ ev: evP, uporabnik: U.ana });
    for (const a of [P1, P2, P3]) S.pending.add(a.pi);
    r = await api("DELETE", `/events/${evP}`, T.lastnik);
    assert(r.body.refunds_queued === 3, "S2: odpoved s 3 narocili", r.body);
    assert(await cakaj(async () => (await pool.query("SELECT COUNT(*)::int AS n FROM vracila WHERE event_id=$1 AND stanje='potrditev'", [evP])).rows[0].n === 3), "S2: vsa 3 vracila v stanju `potrditev` (Stripe pending)");
    const adPot = await api("GET", "/admin/api/refunds?state=potrditev", T.admin);
    assert(adPot.status === 200 && adPot.body.items.length === 3 && adPot.body.items.every(x => x.state === "potrditev") && adPot.body.counts.potrditev === 3, "S2: GET /admin/api/refunds?state=potrditev (admin zaslon #233): 3 vracila + counts.potrditev", adPot.body.counts);
    assert((await vrsticaN(P1.id)).status === "refunded", "S2: naroceno je lokalno ze refunded (kot webhook charge.refunded)");
    await pocakaj(400);
    assert(!vrnMaili().some(m => m.subject.includes(P1.ref)) && odpMaili().some(m => m.subject.includes(P1.ref)), "S2: mail »odpovedan« da, mail »vrnili smo« NE, dokler vracilo ni succeeded");
    const reP1 = (await vracilo(P1.id)).stripe_vracilo_id, reP2 = (await vracilo(P2.id)).stripe_vracilo_id, reP3 = (await vracilo(P3.id)).stripe_vracilo_id;
    S.reById[reP1].status = "succeeded";
    w = await webhook("refund.updated", { id: reP1 });
    assert(w.status === 200 && await koncano(P1.id) && (await vracilo(P1.id)).stanje === "opravljeno", "S2: webhook refund.updated (succeeded) -> opravljeno");
    assert(await cakaj(() => vrnMaili().some(m => m.subject.includes(P1.ref))), "S2: po succeeded mail »vrnili smo«");
    S.reById[reP2].status = "failed"; S.reById[reP2].failure_reason = "expired_or_canceled_card";
    w = await webhook("refund.failed", { id: reP2 });
    await cakaj(async () => (await vracilo(P2.id)).stanje === "ni_uspelo", 5000);
    const vP2 = await vracilo(P2.id);
    assert(w.status === 200 && vP2.stanje === "ni_uspelo" && vP2.stripe_stanje === "failed" && /\[vracila\] POZOR: Stripe vracilo .* je failed, razlog expired_or_canceled_card: kupec NI dobil denarja/.test(log), "S2: refund.failed -> ni_uspelo + alarm POZOR", vP2.stanje);
    assert(!vrnMaili().some(m => m.subject.includes(P2.ref)), "S2: pri failed mail »vrnili smo« NI poslan");
    r = await api("POST", `/admin/api/refunds/${vP2.id}/retry`, T.admin);
    assert(r.status === 409, "S2: retry vracila, ki ga je Stripe zavrnil po sprejetju: 409 (rocno v Stripu, da ne bo dvojnega)", r.status);
    // S2b: admin API kaze `stripe_state` (samo dodajanje), da panel gumba »Poskusi znova« ne ponuja, kjer bi retry vrnil 409
    const evZ = await dogodek("Failed noc", 2000), Z1 = await narocilo({ ev: evZ, uporabnik: U.ana }), Z2 = await narocilo({ ev: evZ, uporabnik: U.bor }), Z3 = await narocilo({ ev: evZ, uporabnik: U.ana });
    const idZ1 = await vnesiVrsto(Z1, evZ, { stanje: "rocno", stripe_stanje: "failed", napaka: "Stripe vracilo failed" });
    const idZ2 = await vnesiVrsto(Z2, evZ, { stanje: "ni_uspelo", stripe_stanje: "canceled", napaka: "Stripe vracilo canceled" });
    const idZ3 = await vnesiVrsto(Z3, evZ, { stanje: "ni_uspelo", napaka: "balance_insufficient" });
    const adZ = await api("GET", `/admin/api/refunds?event_id=${evZ}`, T.admin), stZ = (id) => (adZ.body.items.find(x => String(x.id) === String(id)) || {}).stripe_state;
    assert(adZ.status === 200 && "stripe_state" in adZ.body.items[0] && stZ(idZ1) === "failed" && stZ(idZ2) === "canceled" && stZ(idZ3) === null,
      "S2b: GET /admin/api/refunds ima stripe_state (failed / canceled / null)", adZ.body.items.map(x => [x.id, x.stripe_state]));
    const adP2 = await api("GET", `/admin/api/refunds?state=ni_uspelo`, T.admin);
    assert(adP2.body.items.every(x => "stripe_state" in x) && (adP2.body.items.find(x => String(x.id) === String(vP2.id)) || {}).stripe_state === "failed", "S2b: stripe_state je v vseh vrsticah; vracilo S2 (refund.failed) ima failed");
    assert((await api("POST", `/admin/api/refunds/${idZ1}/retry`, T.admin)).status === 409 && (await api("POST", `/admin/api/refunds/${idZ2}/retry`, T.admin)).status === 409,
      "S2b: retry vracila `rocno`/`ni_uspelo` z stripe_stanje failed/canceled: 409");
    const stanjaZ = (await pool.query("SELECT id, stanje, kljuc_gen FROM vracila WHERE id = ANY($1)", [[idZ1, idZ2]])).rows;
    assert(stanjaZ.every(x => x.kljuc_gen === 0) && stanjaZ.find(x => x.id === idZ1).stanje === "rocno" && stanjaZ.find(x => x.id === idZ2).stanje === "ni_uspelo", "S2b: zavrnjen retry vrstice ne spremeni (stanje, kljuc_gen 0)", stanjaZ);
    const odgZ3 = await api("POST", `/admin/api/refunds/${idZ3}/retry`, T.admin);
    assert(odgZ3.status === 200, "S2b: retry `ni_uspelo` brez Stripovega vracila (stripe_state null) ostane mozen: 200", odgZ3.body);
    assert(/stripe_state/.test(html) && /RETRY_STANJA\.includes\(x\.state\) && !STRIPE_ZAVRNJENO\.includes\(x\.stripe_state\)/.test(html), "S2b: admin panel gumba ne ponuja pri stripe_state failed/canceled");
    S.reById[reP3].status = "succeeded";   // brez webhooka: preverba v obdelovalcu (VRACILA_POTRDITEV_MS)
    assert(await cakaj(async () => (await vracilo(P3.id)).stanje === "opravljeno", 8000), "S2: brez webhooka obdelovalec sam preveri pending vracilo");

    // S3: zamrznjen napacen znesek (amount_too_large po rocnem delnem vracilu), isti kljuc = isti shranjen odgovor: admin retry z novo generacijo kljuca
    const evS3 = await dogodek("S3 noc", 2000), S3 = await narocilo({ ev: evS3, uporabnik: U.ana });
    const idS3 = await vnesiVrsto(S3, evS3, { stanje: "ni_uspelo", znesek_cents: 2000, poskusi: 1, napaka: "StripeInvalidRequestError amount_too_large" });
    S.ch[S.pi[S3.pi].latest_charge].amount_refunded = 500;   // rocno delno vracilo v nadzorni plosci
    S.refundHook = (p, kljuc) => (kljuc === `outly-vracilo-${idS3}` ? { status: 400, body: { error: { type: "invalid_request_error", code: "amount_too_large", message: "Refund amount is greater than unrefunded amount on charge" } } } : null);
    await odpovedSql(evS3);
    r = await api("POST", `/admin/api/refunds/${idS3}/retry`, T.admin);
    assert(r.status === 200, "S3: retry", r.body);
    assert(await koncano(S3.id) && (await vracilo(S3.id)).stanje === "opravljeno", "S3: po retry opravljeno");
    const xS3 = refA(S3.pi);
    assert(xS3.length === 1 && Number(xS3[0].params.amount) === 1500 && xS3[0].kljuc === `outly-vracilo-${idS3}-g1`, "S3: znesek ponovno izracunan (1500), nova generacija kljuca -g1", xS3.map(x => [x.params.amount, x.kljuc]));
    assert(S.fee_refundi.some(x => x.fee === "fee_" + S3.pi.replace(/\W/g, "") && x.kljuc === `outly-vracilo-${idS3}-provizija-g1`), "S3: tudi kljuc vracila provizije ima generacijo");
    S.refundHook = null;

    // N1: vracilo provizije je ze narejeno (potekel kljuc, crash pred zapisom): pri ponovitvi se najde po metadata in NE vrne dvakrat
    const evN1 = await dogodek("N1 noc", 2000), N1 = await narocilo({ ev: evN1, uporabnik: U.bor });
    const feeN1 = "fee_" + N1.pi.replace(/\W/g, "");
    const idN1 = await vnesiVrsto(N1, evN1, { znesek_cents: 2000, stripe_vracilo_id: "re_xN1", stripe_stanje: "succeeded", application_fee_id: feeN1, provizija_za_vrnitev_cents: 141, stripe_pristojbina_cents: 59, poskusi: 1 });
    S.reById.re_xN1 = { id: "re_xN1", object: "refund", amount: 2000, status: "succeeded", metadata: { vracilo_id: String(idN1) } };
    S.ch[S.pi[N1.pi].latest_charge].amount_refunded = 2000; S.fee[feeN1].amount_refunded = 141;
    S.fee_refundi.push({ id: "fr_prej", object: "fee_refund", amount: 141, fee: feeN1, metadata: { vracilo_id: String(idN1) }, kljuc: "potekel" });
    await pool.query("UPDATE orders SET status='refunded', refunded_cents=2000 WHERE id=$1", [N1.id]);
    await odpovedSql(evN1);
    assert(await koncano(N1.id), "N1: dokoncano");
    const vN1 = await vracilo(N1.id);
    assert(vN1.stanje === "opravljeno" && vN1.provizija_vracilo_id === "fr_prej" && S.fee_refundi.filter(x => x.fee === feeN1).length === 1, "N1: obstojece vracilo provizije posvojeno, drugega NI", [vN1.stanje, vN1.provizija_vracilo_id]);

    // N2: narocilo je ze v celoti vrnjeno rocno v nadzorni plosci (po webhooku, ali webhook se ni prispel): alarm, brez novega vracila
    const evN2 = await dogodek("N2 noc", 2000), N2a = await narocilo({ ev: evN2, uporabnik: U.ana }), N2b = await narocilo({ ev: evN2, uporabnik: U.bor });
    S.ch[S.pi[N2a.pi].latest_charge].amount_refunded = 2000; S.ch[S.pi[N2b.pi].latest_charge].amount_refunded = 2000;
    await webhook("charge.refunded", { id: S.pi[N2a.pi].latest_charge });   // N2a: baza ve (refunded); N2b: webhook ni prispel (baza paid, Stripe vrnjen)
    const idN2a = await vnesiVrsto(N2a, evN2), idN2b = await vnesiVrsto(N2b, evN2);
    await odpovedSql(evN2);
    assert(await koncano(N2a.id) && await koncano(N2b.id), "N2: dokoncano");
    for (const [a, id] of [[N2a, idN2a], [N2b, idN2b]]) {
      const v = await vracilo(a.id);
      assert(v.stanje === "opravljeno" && v.napaka === "rocno_vrnjeno_v_stripu" && refA(a.pi).length === 0, `N2 ${a.ref}: opravljeno z opombo rocno_vrnjeno_v_stripu, novega vracila NI`, [v.stanje, v.napaka]);
      assert(new RegExp(`\\[vracila\\] POZOR: narocilo ${a.ref} je ze v celoti vrnjeno v Stripu \\(rocno vracilo`).test(log), `N2 ${a.ref}: alarm POZOR (rocno vracilo, provizija klubu ni vrnjena)`);
    }

    // N3: anomalija v podatkih za provizijo -> kupec je vrnjen, vracilo provizije `rocno` z alarmom (nikoli tiho 0)
    const evN3 = await dogodek("N3 noc", 2000);
    const N3a = await narocilo({ ev: evN3, uporabnik: U.ana }); dodajPlacilo(N3a.pi, { amount: 2000, fee: 200, btValuta: "usd" });
    const N3b = await narocilo({ ev: evN3, uporabnik: U.bor }); dodajPlacilo(N3b.pi, { amount: 2000, fee: 200, brezStripeFee: true });
    await vnesiVrsto(N3a, evN3); await vnesiVrsto(N3b, evN3);
    await odpovedSql(evN3);
    assert(await koncano(N3a.id) && await koncano(N3b.id), "N3: dokoncano");
    for (const [a, re] of [[N3a, /valuta/], [N3b, /stripe_fee/]]) {
      const v = await vracilo(a.id), o = await vrsticaN(a.id);
      assert(v.stanje === "rocno" && re.test(v.napaka) && refA(a.pi).length === 1 && o.status === "refunded" && !S.fee_refundi.some(x => x.fee === "fee_" + a.pi.replace(/\W/g, "")), `N3 ${a.ref}: kupec vrnjen (1 vracilo), vracilo provizije rocno (${v.napaka.slice(0, 60)}), brez klica`, [v.stanje, v.napaka]);
    }
    assert(/\[vracila\] POZOR: vracilo narocila OUT-VR\d+ \(event_cancelled\) zahteva ROCNO obravnavo: .*Kupec je vrnjen, dokoncaj vracilo provizije rocno/.test(log), "N3: alarm POZOR (kupec vrnjen, provizija rocno)");
    assert(await cakaj(() => vrnMaili().some(m => m.subject.includes(N3a.ref)) && vrnMaili().some(m => m.subject.includes(N3b.ref))), "N-c: kupec dobi mail »vrnili smo« TUDI ko vrstica konca v `rocno` zaradi provizije");
    await pocakaj(700);
    assert(vrnMaili().filter(m => m.subject.includes(N3a.ref)).length === 1 && vrnMaili().filter(m => m.subject.includes(N3b.ref)).length === 1, "N-c: natanko enkrat");

    // N5: sweep ne dotakne dogodkov, odpovedanih pred vec kot 30 dnevi
    const evN5 = await dogodek("N5 noc", 2000), N5 = await narocilo({ ev: evN5, uporabnik: U.ana });
    await odpovedSql(evN5);
    await pool.query("UPDATE odpovedi_dogodkov SET odpovedan_at = NOW() - INTERVAL '40 days' WHERE event_id=$1", [evN5]);
    await pocakaj(1500);
    assert(!(await vracilo(N5.id)) && (await vrsticaN(N5.id)).status === "paid", "N5: dogodek odpovedan pred 40 dnevi: sweep ga ne dotakne");

    // N-a: webhook refund.* prehiti zapis stripe_vracilo_id: vrstica se najde po metadata iz svezega vracila (ne caka na urno preverbo)
    const evN4 = await dogodek("N4 noc", 2000), N4 = await narocilo({ ev: evN4, uporabnik: U.ana });
    const idN4 = await vnesiVrsto(N4, evN4, { znesek_cents: 2000, naslednji_poskus_at: new Date(Date.now() + 3600e3) });
    S.reById.re_n4 = { id: "re_n4", object: "refund", amount: 2000, status: "pending", payment_intent: N4.pi, metadata: { vracilo_id: String(idN4), order_id: String(N4.id), public_ref: N4.ref } };
    w = await webhook("refund.updated", { id: "re_n4" });
    let vN4 = await vracilo(N4.id);
    assert(w.status === 200 && await cakaj(async () => (await vracilo(N4.id)).stripe_vracilo_id === "re_n4", 5000) && (await vracilo(N4.id)).stripe_stanje === "pending", "N-a: webhook refund.updated posvoji vracilo po metadata (stripe_vracilo_id, stripe_stanje pending)", vN4.stripe_vracilo_id);
    S.reById.re_n4.status = "succeeded";
    await webhook("refund.updated", { id: "re_n4" });
    assert(await cakaj(async () => (await vracilo(N4.id)).stripe_stanje === "succeeded", 5000), "N-a: nato stripe_stanje succeeded");
    await webhook("refund.updated", { id: "re_n4" }, "evt_vr_n4_tuj");
    S.reById.re_n5 = { id: "re_n5", object: "refund", amount: 1, status: "succeeded", payment_intent: N4.pi, metadata: { vracilo_id: String(idN4), order_id: "999999" } };
    await webhook("refund.updated", { id: "re_n5" });
    await pocakaj(300);
    assert((await vracilo(N4.id)).stripe_vracilo_id === "re_n4", "N-a: vracilo z drugim order_id v metadata se NE posvoji");

    // N-b: ob posvojitvi ze narejenega reversala se zapise NJEGOV znesek, brez lazne razlike in alarma, brez drugega reversala
    const D7 = await narocilo({ ev: evD, uporabnik: U.bor, cena: 100000 });
    const trD7 = "tr_" + D7.pi.replace(/\W/g, "");
    S.tr[trD7].amount_reversed = 91500;
    S.reversali.push({ id: "trr_prej", object: "transfer_reversal", amount: 91500, transfer: trD7, metadata: { spor_id: "dp_7" }, kljuc: "potekel" });
    dispute("dp_7", D7.pi, { znesek: 100000, status: "lost", pristojbina: 1500 });
    await pool.query("INSERT INTO spori (id, order_id, stanje, razlog, znesek_cents, valuta, zaprt_at, povrnitev_stanje, povrnitev_poskusi) VALUES ('dp_7', $1, 'lost', 'fraudulent', 100000, 'EUR', NOW(), 'caka', 1)", [D7.id]);
    const kliciRev7 = klici("POST", /reversals/).length;
    assert(await cakaj(async () => (await pool.query("SELECT povrnitev_stanje FROM spori WHERE id='dp_7'")).rows[0].povrnitev_stanje === "opravljeno"), "N-b: povrnitev dokoncana");
    sp = (await pool.query("SELECT * FROM spori WHERE id='dp_7'")).rows[0];
    assert(sp.reversal_id === "trr_prej" && sp.povrnitev_cents === 91500 && sp.povrnitev_zelena_cents === 91500 && sp.povrnitev_napaka === null && klici("POST", /reversals/).length === kliciRev7, "N-b: posvojen obstojeci reversal (91500), brez drugega reversala in brez razlike", sp);
    assert(!/spor dp_7: od kluba je mogoce povrniti samo/.test(log), "N-b: brez lazne opozorilne vrstice POZOR");

    // N-d: odprt spor na naroceno -> vracilo `rocno` z razlogom spor_odprt (ne generican ni_uspelo); po izidu spora admin retry
    const evN7 = await dogodek("N7 noc", 2000), N7 = await narocilo({ ev: evN7, uporabnik: U.ana });
    dispute("dp_n7", N7.pi, { znesek: 2000 });
    await webhook("charge.dispute.created", { id: "dp_n7" });
    const idN7 = await vnesiVrsto(N7, evN7);
    await odpovedSql(evN7);
    assert(await koncano(N7.id), "N-d: dokoncano");
    const vN7 = await vracilo(N7.id);
    assert(vN7.stanje === "rocno" && /spor_odprt:/.test(vN7.napaka) && refA(N7.pi).length === 0, "N-d: stanje rocno, razlog spor_odprt, kupec NI vrnjen (spor ze odtegnil znesek)", [vN7.stanje, vN7.napaka]);
    assert(new RegExp(`\\[vracila\\] POZOR: vracilo narocila ${N7.ref} \\(event_cancelled\\) zahteva ROCNO obravnavo: (Error: )?spor_odprt`).test(log), "N-d: jasen alarm POZOR (spor_odprt)");
    S.spori.dp_n7.status = "won";
    await webhook("charge.dispute.closed", { id: "dp_n7" });
    r = await api("POST", `/admin/api/refunds/${idN7}/retry`, T.admin);
    assert(r.status === 200 && await koncano(N7.id, ["opravljeno"]) && refA(N7.pi).length === 1, "N-d: po won admin retry -> vracilo opravljeno", r.status);

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
