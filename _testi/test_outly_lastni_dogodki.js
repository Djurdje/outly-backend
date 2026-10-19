#!/usr/bin/env node
/**
 * Lastni dogodki Outly: prodajalec je NEXT DIMENSIONS = platforma (I50; Martin v seji menedzerja 19. 10. 2026, DECISIONS »Lastni dogodki Outly«).
 * Za dogodek, katerega prodajalec (events.club_id) ima clubs.is_official = TRUE, gre placilo NEPOSREDNO na platformni Stripe racun: Checkout seja brez
 * transfer_data, brez on_behalf_of, brez application_fee_amount; provizija naroclila 0; vracilo brez reverse_transfer in brez refund_application_fee;
 * spor ne bremeni nobenega kluba. Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_outly_lastni_dogodki.js
 * Vzorec kot test_brezplacno_brez_stripa.js (lokalni JWKS, lazni Stripe) in test_vracila.js (lazni Stripe z vracili, spori, transferji). Lazni Stripe posnema
 * Stripovo napako: vracilo z reverse_transfer / refund_application_fee na naboju BREZ transferja je 400 (zato ta test pade tudi, ce bi kdo pozabil vejo za platformo).
 *
 *   0  cista funkcija: nacinPlacila (is_official brez Connecta: stripe; brez kljuca test; brez webhook skrivnosti nastavitve; navaden klub brez Stripa ob live: klub),
 *      ustvariCheckout brez racuna kluba in brez zastavice platforme zavrne (fail closed, Stripe se ne pokliche)
 *   1  payment_mode (sk_live_): is_official brez Connecta "stripe" (dogodek, seznam, VIP, /business/sales), I34 "unavailable" (nepopolni podatki), demo "unavailable";
 *      sk_test_: is_official "stripe", navaden klub brez Stripa "test"; racun nikoli v odgovoru (I4)
 *   2  nakup (vstopnica z racunom, gost, VIP miza): seja BREZ transfer_data / on_behalf_of / application_fee_amount, cena iz baze, rok 30 min, provizija 0, orders.stripe_account_id = "platform";
 *      is_official Z Connect racunom gre tudi neposredno; NAVADEN KLUB: destination charge + on_behalf_of + 10 % ostane
 *   3  webhook: checkout.session.completed zakljuci (paid + vstopnice), podvojen dogodek, napacen znesek -> cancelled + samodejno vracilo (inactive_order, navadno vracilo),
 *      pospravljalec zakljuci sejo brez webhooka
 *   4  varovala ostanejo: I46 cena, zaloga, 0 EUR mimo Stripa, starost, I34 (409), I41 demo, klub brez Stripa (409), idempotenca
 *   5  finance: admin (provizija, »za klube«, lastna prodaja) in /business/sales (fee_percent 0)
 *   6  spori: platforma - zapis in alarm, brez povrnitve od kluba, brez maila lastniku, brez klica transferjev; spor pred placilom; navaden klub: povrnitev in mail kot doslej
 *   7  odpoved dogodka: vracilo brez reverse_transfer, brez refund_application_fee, brez vracila provizije; navaden klub ostane z reverse_transfer + vracilom provizije;
 *      admin »Poskusi znova« za platformno vracilo
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");
const Stripe = require("stripe");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT_ZIV = 4801, PORT_SAND = 4802, JWKS_PORT = 4803, STRIPE_PORT = 4804, RESEND_PORT = 4805;
const WHSEC = "whsec_test_lastni";
const stripeLokalno = new Stripe("sk_test_lokalno");

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-lastni-dogodki";
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
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra).slice(0, 500) : ""); } }
let ipStevec = 0;   // vsak zahtevek svoj naslov (X-Forwarded-For): omejevalnik nakupov je po IP
async function api(baza, method, p, token, body, glave = {}) {
  const r = await fetch(baza + p, { method, headers: { "content-type": "application/json", "x-forwarded-for": `10.88.${(++ipStevec >> 8) & 255}.${(ipStevec & 255) + 1}`, ...(token ? { authorization: "Bearer " + token } : {}), ...glave },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, text: t };
}
const pocakaj = (ms) => new Promise(r => setTimeout(r, ms));
async function cakaj(pogoj, ms = 15000) { const do_ = Date.now() + ms; while (Date.now() < do_) { if (await pogoj()) return true; await pocakaj(80); } return false; }

// ---------- lazni Resend (maili lastnikom klubov o sporu) ----------
const R = { poslano: [] };
const resendServer = http.createServer((req, res) => {
  let d = ""; req.on("data", x => d += x);
  req.on("end", () => {
    if (req.method === "POST" && req.url === "/emails") { R.poslano.push(JSON.parse(d)); res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify({ id: "mail_" + R.poslano.length })); }
    res.writeHead(404, { "content-type": "application/json" }); res.end("{}");
  });
});
const mailiSporaNa = (email) => R.poslano.filter(m => (m.to === email || (Array.isArray(m.to) && m.to.includes(email))) && /Spor|Dispute/.test(String(m.subject)));

// ---------- lazni Stripe ----------
const S = { seje: {}, stSej: 0, zahtevkiSej: [], pi: {}, ch: {}, fee: {}, bt: {}, tr: {}, spori: {}, idem: {}, refundi: [], reById: {}, fee_refundi: [], reversali: [], klici: [], stR: 0, refundHook: null };
const obrazec = (t) => { const o = {}; for (const [k, v] of new URLSearchParams(t)) o[k] = v; return o; };
const meta = (p) => { const md = {}; for (const [k, v] of Object.entries(p)) { const mm = k.match(/^metadata\[(\w+)\]$/); if (mm) md[mm[1]] = v; } return md; };
// Placilo v lazni Stripe: platforma = naboj brez transferja in brez provizije (neposredno placilo na platformni racun); sicer destination charge (transfer + provizija).
function dodajPlacilo(pi, { amount, platforma, fee = 0, stripeFee = 59 }) {
  const n = pi.replace(/\W/g, "");
  S.pi[pi] = { id: pi, object: "payment_intent", status: "succeeded", amount, latest_charge: "ch_" + n, transfer_data: platforma ? null : { destination: "acct_ziv1" } };
  S.ch["ch_" + n] = { id: "ch_" + n, object: "charge", amount, currency: "eur", amount_refunded: 0, payment_intent: pi, application_fee: !platforma && fee > 0 ? "fee_" + n : null, balance_transaction: "txn_" + n, transfer: platforma ? null : "tr_" + n };
  if (!platforma) S.tr["tr_" + n] = { id: "tr_" + n, object: "transfer", amount, amount_reversed: 0, currency: "eur" };
  if (!platforma && fee > 0) S.fee["fee_" + n] = { id: "fee_" + n, object: "application_fee", amount: fee, amount_refunded: 0, currency: "eur" };
  S.bt["txn_" + n] = { id: "txn_" + n, object: "balance_transaction", currency: "eur", fee: stripeFee, fee_details: [{ type: "stripe_fee", amount: stripeFee, currency: "eur" }] };
}
const stripeServer = http.createServer((req, res) => {
  let d = ""; req.on("data", x => d += x);
  req.on("end", () => {
    const url = new URL(req.url, "http://x");
    const u = url.pathname, p = obrazec(d), kljuc = req.headers["idempotency-key"];
    S.klici.push({ m: req.method, u, p, kljuc });
    const odg = (st, o) => { res.writeHead(st, { "content-type": "application/json", "request-id": "req_test", "stripe-should-retry": "false" }); res.end(JSON.stringify(o)); };
    const napaka = (st, tip, code, msg) => odg(st, { error: { type: tip, ...(code ? { code } : {}), message: msg } });
    let m;
    if (req.method === "POST" && u === "/v1/checkout/sessions") {
      S.zahtevkiSej.push({ params: p, kljuc });
      const obst = Object.values(S.seje).find(s => s._kljuc === kljuc);
      if (obst) return odg(200, obst);
      const id = "cs_live_" + (++S.stSej);
      const kol = Number(p["line_items[0][quantity]"]), cena = Number(p["line_items[0][price_data][unit_amount]"]);
      S.seje[id] = { id, object: "checkout.session", livemode: true, _kljuc: kljuc, _platforma: !p["payment_intent_data[transfer_data][destination]"], _fee: Number(p["payment_intent_data[application_fee_amount]"] || 0),
        url: `https://checkout.stripe.test/c/pay/${id}`, status: "open", payment_status: "unpaid", amount_total: kol * cena, currency: p["line_items[0][price_data][currency]"],
        client_reference_id: p.client_reference_id, metadata: { order_id: p["metadata[order_id]"], public_ref: p["metadata[public_ref]"] }, expires_at: Number(p.expires_at), payment_intent: null };
      return odg(200, S.seje[id]);
    }
    if (req.method === "GET" && (m = u.match(/^\/v1\/checkout\/sessions\/(cs_\w+)$/))) return S.seje[m[1]] ? odg(200, S.seje[m[1]]) : napaka(404, "invalid_request_error", "resource_missing", "No such session");
    if (req.method === "GET" && (m = u.match(/^\/v1\/payment_intents\/(\w+)$/))) {
      const pi = S.pi[m[1]]; if (!pi) return napaka(404, "invalid_request_error", "resource_missing", "No such payment_intent");
      const expand = [...url.searchParams].filter(([k]) => /^expand(\[\d*\])?$/.test(k)).map(([, v]) => v);
      if (!expand.some(x => x.startsWith("latest_charge"))) return odg(200, pi);
      const ch = { ...S.ch[pi.latest_charge] };
      if (expand.includes("latest_charge.balance_transaction")) ch.balance_transaction = S.bt[ch.balance_transaction];
      if (expand.includes("latest_charge.application_fee") && ch.application_fee) ch.application_fee = S.fee[ch.application_fee];
      return odg(200, { ...pi, latest_charge: ch });
    }
    if (req.method === "GET" && (m = u.match(/^\/v1\/charges\/(\w+)$/))) {
      if (!S.ch[m[1]]) return napaka(404, "invalid_request_error", "resource_missing", "No such charge");
      const c0 = S.ch[m[1]];
      return odg(200, [...url.searchParams].some(([, v]) => v === "application_fee") && c0.application_fee ? { ...c0, application_fee: S.fee[c0.application_fee] } : c0);
    }
    if (req.method === "GET" && (m = u.match(/^\/v1\/refunds\/(re_\w+)$/))) return S.reById[m[1]] ? odg(200, S.reById[m[1]]) : napaka(404, "invalid_request_error", "resource_missing", "No such refund");
    if (req.method === "GET" && u === "/v1/refunds") return odg(200, { object: "list", has_more: false, data: S.refundi.filter(r => r.payment_intent === url.searchParams.get("payment_intent")) });
    if (req.method === "POST" && u === "/v1/refunds") {
      if (kljuc && S.idem[kljuc]) return odg(200, S.idem[kljuc]);
      const hook = S.refundHook && S.refundHook(p, kljuc);
      if (hook) return odg(hook.status, hook.body);
      const pi = S.pi[p.payment_intent]; if (!pi) return napaka(404, "invalid_request_error", "resource_missing", "No such payment_intent");
      const ch = S.ch[pi.latest_charge], ostane = ch.amount - ch.amount_refunded;
      // Kot pravi Stripe: reverse_transfer / refund_application_fee na naboju brez transferja (neposredno placilo na platformo) je napaka.
      if (!ch.transfer && (p.reverse_transfer !== undefined || p.refund_application_fee !== undefined)) return napaka(400, "invalid_request_error", null, "This charge has no transfer or application fee to reverse or refund.");
      if (ostane <= 0) return napaka(400, "invalid_request_error", "charge_already_refunded", "Charge has already been refunded.");
      const znesek = p.amount ? Number(p.amount) : ostane;
      if (znesek > ostane) return napaka(400, "invalid_request_error", "amount_too_large", "Refund amount is greater than unrefunded amount on charge");
      ch.amount_refunded += znesek;
      const re = { id: "re_" + (++S.stR), object: "refund", amount: znesek, status: "succeeded", payment_intent: pi.id, charge: ch.id, metadata: meta(p) };
      S.reById[re.id] = re; S.refundi.push({ ...re, params: p, kljuc }); if (kljuc) S.idem[kljuc] = re;
      return odg(200, re);
    }
    if (req.method === "POST" && (m = u.match(/^\/v1\/application_fees\/(fee_\w+)\/refunds$/))) {
      const f = S.fee[m[1]]; if (!f) return napaka(404, "invalid_request_error", "resource_missing", "No such application fee");
      const znesek = p.amount ? Number(p.amount) : f.amount - f.amount_refunded;
      f.amount_refunded += znesek;
      const fr = { id: "fr_" + (S.fee_refundi.length + 1), object: "fee_refund", amount: znesek, fee: f.id, metadata: meta(p) };
      S.fee_refundi.push({ ...fr, params: p, kljuc }); return odg(200, fr);
    }
    if (req.method === "GET" && (m = u.match(/^\/v1\/application_fees\/(fee_\w+)\/refunds$/))) return odg(200, { object: "list", has_more: false, data: S.fee_refundi.filter(x => x.fee === m[1]) });
    if (req.method === "GET" && (m = u.match(/^\/v1\/transfers\/(tr_\w+)$/))) return S.tr[m[1]] ? odg(200, S.tr[m[1]]) : napaka(404, "invalid_request_error", "resource_missing", "No such transfer");
    if (req.method === "GET" && (m = u.match(/^\/v1\/transfers\/(tr_\w+)\/reversals$/))) return odg(200, { object: "list", has_more: false, data: S.reversali.filter(x => x.transfer === m[1]) });
    if (req.method === "POST" && (m = u.match(/^\/v1\/transfers\/(tr_\w+)\/reversals$/))) {
      const t = S.tr[m[1]]; if (!t) return napaka(404, "invalid_request_error", "resource_missing", "No such transfer");
      const znesek = Number(p.amount); t.amount_reversed += znesek;
      const rv = { id: "trr_" + (S.reversali.length + 1), object: "transfer_reversal", amount: znesek, transfer: t.id, metadata: meta(p) };
      S.reversali.push({ ...rv }); return odg(200, rv);
    }
    if (req.method === "GET" && (m = u.match(/^\/v1\/disputes\/(dp_\w+)$/))) return S.spori[m[1]] ? odg(200, S.spori[m[1]]) : napaka(404, "invalid_request_error", "resource_missing", "No such dispute");
    return napaka(404, "invalid_request_error", null, "Lazni Stripe: neznana pot " + req.method + " " + u);
  });
});
const klici = (m, re) => S.klici.filter(k => k.m === m && re.test(k.u));
const sejeParametri = () => S.zahtevkiSej.map(z => z.params);
const imaConnect = (p) => Object.keys(p).some(k => /transfer_data|on_behalf_of|application_fee/.test(k));
let stDogodka = 0;
async function webhook(baza, tip, objekt, id) {
  const dogodek = { id: id || `evt_ld_${++stDogodka}`, object: "event", type: tip, data: { object: objekt }, created: Math.floor(Date.now() / 1000) };
  const payload = JSON.stringify(dogodek);
  const glava = stripeLokalno.webhooks.generateTestHeaderString({ payload, secret: WHSEC });
  const r = await fetch(baza + "/stripe/webhook", { method: "POST", headers: { "content-type": "application/json", "stripe-signature": glava }, body: payload });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, id: dogodek.id };
}
// Kupec je placal sejo: lazni Stripe dobi PaymentIntent + naboj (platforma ali destination charge, po seji) in sejo oznaci kot placano.
function placaj(sejaId, { znesek } = {}) {
  const s = S.seje[sejaId], pi = "pi_" + sejaId.replace(/\W/g, "");
  dodajPlacilo(pi, { amount: znesek !== undefined ? znesek : s.amount_total, platforma: s._platforma, fee: s._fee });
  Object.assign(s, { status: "complete", payment_status: "paid", payment_intent: pi });
  if (znesek !== undefined) s.amount_total = znesek;
  return pi;
}
// Spor (chargeback) na PaymentIntent
function dodajSpor(id, pi, stanje, znesek) {
  S.spori[id] = { id, object: "dispute", amount: znesek, currency: "eur", status: stanje, reason: "fraudulent", charge: S.pi[pi].latest_charge, payment_intent: pi, created: Math.floor(Date.now() / 1000),
    evidence_details: { due_by: Math.floor(Date.now() / 1000) + 86400 * 7 }, balance_transactions: [{ id: "txn_sp_" + id, currency: "eur", fee: 1500 }] };
}

function zagon(port, okolje) {
  const srv = spawn("node", ["index.js"], { env: { ...process.env, GOST_NAKUP_TEST: "1", PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, QR_SECRET: "test", APP_URL: "https://outly.test",
    STRIPE_API_BASE: `http://127.0.0.1:${STRIPE_PORT}`, STRIPE_WEBHOOK_SECRET: WHSEC, TEST_PLACILA: "", JAVNI_PREDPOMNILNIK_MS: "0", PREVERI_OKNO_MS: "0",
    RESEND_API_KEY: "re_test", RESEND_BASE_URL: `http://127.0.0.1:${RESEND_PORT}`, EMAIL_FROM: "Outly <test@outly.test>", GOST_POSTA_PONOVI_MS: "0", VRACILA_MAIL_RAZMAK_MS: "0", ...okolje }, stdio: ["ignore", "pipe", "pipe"] });
  const o = { srv, log: "" };
  srv.stdout.on("data", d => o.log += d); srv.stderr.on("data", d => o.log += d);
  return o;
}
async function cakajStreznik(baza) { for (let i = 0; i < 80; i++) { try { await fetch(baza + "/"); return; } catch { await pocakaj(100); } } }

(async () => {
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  await new Promise(r => stripeServer.listen(STRIPE_PORT, r));
  await new Promise(r => resendServer.listen(RESEND_PORT, r));

  // ================================================================
  console.log("\n# 0. Cista funkcija: nacinPlacila in ustvariCheckout");
  {
    const shrani = { ...process.env };
    const nastavi = (o) => { for (const k of ["TEST_PLACILA", "STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET"]) delete process.env[k]; Object.assign(process.env, o); };
    process.env.STRIPE_API_BASE = `http://127.0.0.1:${STRIPE_PORT}`;
    const pl = require("../placila_stripe");
    const outly = { is_official: true, stripe_account_id: null, stripe_charges_enabled: false, stripe_account_livemode: null };
    const navaden = { is_official: false, stripe_account_id: null, stripe_charges_enabled: false };
    nastavi({ STRIPE_SECRET_KEY: "sk_live_x", STRIPE_WEBHOOK_SECRET: "whsec" });
    assert(pl.nacinPlacila(outly) === "stripe", "live + is_official brez Connecta -> stripe");
    assert(pl.nacinPlacila({ ...outly, stripe_account_id: "acct_x", stripe_charges_enabled: false }) === "stripe", "live + is_official z nedokoncanim Connectom -> stripe (racun ni pogoj)");
    assert(pl.nacinPlacila(navaden) === "klub", "live + navaden klub brez Stripa -> klub (409), nespremenjeno");
    assert(pl.nacinPlacila({ ...navaden, is_official: undefined }) === "klub" && pl.nacinPlacila(null) === "klub", "live + manjkajoca zastavica / brez kluba -> klub");
    assert(pl.nacinPlacila({ ...outly, is_official: "true" }) === "klub", "is_official mora biti natanko TRUE (niz ne velja)");
    nastavi({ STRIPE_SECRET_KEY: "sk_test_x", STRIPE_WEBHOOK_SECRET: "whsec" });
    assert(pl.nacinPlacila(outly) === "stripe" && pl.nacinPlacila(navaden) === "test", "sandbox: is_official stripe, navaden klub brez Stripa test");
    nastavi({ STRIPE_SECRET_KEY: "sk_live_x" });
    assert(pl.nacinPlacila(outly) === "nastavitve", "live brez webhook skrivnosti + is_official -> nastavitve (503)");
    nastavi({});
    assert(pl.nacinPlacila(outly) === "test", "brez kljuca + is_official -> test");
    nastavi({ STRIPE_SECRET_KEY: "sk_test_x", STRIPE_WEBHOOK_SECRET: "whsec", TEST_PLACILA: "true" });
    assert(pl.nacinPlacila(outly) === "test", "TEST_PLACILA=true ob sandbox kljucu vsili test tudi za is_official");
    nastavi({ STRIPE_SECRET_KEY: "sk_live_x", STRIPE_WEBHOOK_SECRET: "whsec", TEST_PLACILA: "true" });
    assert(pl.nacinPlacila(outly) === "stripe", "TEST_PLACILA=true ob sk_live_ je ignoriran (I31) tudi za is_official");
    assert(typeof pl.jePlatformniProdajalec === "function" && pl.jePlatformniProdajalec(outly) === true && pl.jePlatformniProdajalec(navaden) === false && pl.jePlatformniProdajalec(null) === false, "jePlatformniProdajalec");
    // ustvariCheckout: brez racuna kluba in brez zastavice platforme ZAVRNE (nikoli tiho neposredno placilo za navaden klub), Stripe se ne pokliche
    nastavi({ STRIPE_SECRET_KEY: "sk_live_x", STRIPE_WEBHOOK_SECRET: "whsec" });
    const nar = { id: 99991, public_ref: "OUT-UNIT", currency: "EUR", application_fee_cents: 0 };
    const prej = S.zahtevkiSej.length;
    let napaka = null;
    try { await pl.ustvariCheckout({ narocilo: nar, opis: "x", kolicina: 1, cenaEnoteCents: 1000, racunKluba: null, email: null, eventId: 1, odjemalec: "splet" }); } catch (e) { napaka = e; }
    assert(napaka && S.zahtevkiSej.length === prej, "ustvariCheckout brez racuna kluba in brez zastavice platforme: napaka, Stripe se ne pokliche", napaka && napaka.message);
    for (const k of Object.keys(process.env)) if (!(k in shrani)) delete process.env[k];
    Object.assign(process.env, shrani);
  }

  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, stripe_events, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  const ZIV = zagon(PORT_ZIV, { STRIPE_SECRET_KEY: "sk_live_lokalno", GOST_NAKUP_LIVE: "1", STRIPE_POSPRAVI_MS: "600",
    VRACILA_TICK_MS: "250", VRACILA_RAZMAK_MS: "10", VRACILA_ZAMIK_S: "0", VRACILA_SWEEP_MS: "400", VRACILA_PREMOR_MS: "150", VRACILA_POSKUSOV: "2", VRACILA_NI_IZVEDENO_PO_MS: "600000" });
  const SAND = zagon(PORT_SAND, { STRIPE_SECRET_KEY: "sk_test_lokalno", STRIPE_POSPRAVI_MS: "3600000", VRACILA_TICK_MS: "0" });
  const bZ = `http://127.0.0.1:${PORT_ZIV}`, bS = `http://127.0.0.1:${PORT_SAND}`;
  await Promise.all([bZ, bS].map(cakajStreznik));

  try {
    const imena = ["lastnik", "lastnik2", "lastnik3", "lastnik4", "lastnik5", "lastnik6", "ana", "bor", "cene", "mladi", "admin", "kupec1", "kupec2"];
    const T = {}, U = {};
    imena.forEach((k, i) => { T[k] = zeton(`${k}@outly.si`, uuid(i + 1)); });
    for (const k of imena) { const r = await api(bZ, "GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); U[k] = r.body.id; }
    await pool.query("UPDATE users SET role='business' WHERE email LIKE 'lastnik%@outly.si'");
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    const odrasel = new Date(Date.now() - 25 * 365.25 * 24 * 3600 * 1000).toISOString().slice(0, 10);
    const otrok = new Date(Date.now() - 16 * 365.25 * 24 * 3600 * 1000).toISOString().slice(0, 10);
    for (const k of ["ana", "bor", "cene", "admin"]) await api(bZ, "PATCH", "/me", T[k], { dateOfBirth: odrasel });
    await api(bZ, "PATCH", "/me", T.mladi, { dateOfBirth: otrok });
    const lastnik = (e) => `(SELECT id FROM users WHERE email='${e}@outly.si')`;
    const prod = (ime) => `'${ime}', 'Naslov 1, Ljubljana', '1234567000', 'SI12345678', TRUE, 'info@${ime.toLowerCase().replace(/\W/g, "")}.si'`;
    const STOLPCI = "owner_user_id, name, city, address, legal_name, legal_address, registration_number, tax_number, vat_payer, contact_email";
    // 1: navaden klub z zivim Connectom (kontrola). 2: uradni profil Outly (ni Connecta, popolni podatki prodajalca). 3: uradni brez podatkov prodajalca (I34).
    // 4: uradni Z Connect racunom (vseeno neposredno). 5: navaden klub brez Stripa (kontrola 409). 6: uradni DEMO klub (I41).
    await pool.query(`INSERT INTO clubs (${STOLPCI}, stripe_account_id, stripe_charges_enabled, stripe_account_livemode) VALUES (${lastnik("lastnik")}, 'Navaden klub', 'Ljubljana', 'Slovenska 1', ${prod("Navaden klub d.o.o.")}, 'acct_ziv1', TRUE, TRUE)`);
    await pool.query(`INSERT INTO clubs (${STOLPCI}, is_official, is_organizer) VALUES (${lastnik("lastnik2")}, 'Outly', 'Ljubljana', 'Trg 2', ${prod("NEXT DIMENSIONS d.o.o.")}, TRUE, TRUE)`);
    await pool.query(`INSERT INTO clubs (owner_user_id, name, city, address, is_official, is_organizer) VALUES (${lastnik("lastnik3")}, 'Outly brez podatkov', 'Ljubljana', 'Trg 3', TRUE, TRUE)`);
    await pool.query(`INSERT INTO clubs (${STOLPCI}, is_official, is_organizer, stripe_account_id, stripe_charges_enabled, stripe_account_livemode) VALUES (${lastnik("lastnik4")}, 'Outly s Connectom', 'Ljubljana', 'Trg 4', ${prod("NEXT DIMENSIONS d.o.o.")}, TRUE, TRUE, 'acct_ziv4', TRUE, TRUE)`);
    await pool.query(`INSERT INTO clubs (${STOLPCI}) VALUES (${lastnik("lastnik5")}, 'Klub brez Stripa', 'Maribor', 'Trg 5', ${prod("Klub brez Stripa d.o.o.")})`);
    await pool.query(`INSERT INTO clubs (${STOLPCI}, is_official, is_demo) VALUES (${lastnik("lastnik6")}, 'Demo uradni', 'Kranj', 'Trg 6', ${prod("Demo d.o.o.")}, TRUE, TRUE)`);
    const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    const dogodek = async (klub, naslov, cena, kap = 100, minAge = 0) => (await pool.query(
      "INSERT INTO events (club_id, title, start_at, status, ticket_price_cents, capacity, min_age, vip_enabled) VALUES ($1,$2,$3,'published',$4,$5,$6,TRUE) RETURNING id", [klub, naslov, cezDan, cena, kap, minAge])).rows[0].id;
    const evN = await dogodek(1, "Navadna noc", 1000), evN2 = await dogodek(1, "Navadna noc 2", 1000), evN3 = await dogodek(1, "Navadna noc 3 (spor)", 1000);
    const evO = await dogodek(2, "Outly Launch Party", 1000), evO18 = await dogodek(2, "Outly 18+", 1000, 100, 18), evOcap = await dogodek(2, "Outly majhna", 1000, 2);
    const evO0 = await dogodek(2, "Outly brezplacno", 0), evOspor = await dogodek(2, "Outly spor", 1000), evOvrst = await dogodek(2, "Outly vrstni red", 1000), evORetry = await dogodek(4, "Outly Connect", 1000);
    const evOnep = await dogodek(3, "Outly brez podatkov", 1000), evOnep0 = await dogodek(3, "Outly brez podatkov 0", 0);
    const evK5 = await dogodek(5, "Klub brez Stripa", 1000), evDemo = await dogodek(6, "Demo uradni", 1000);
    await pool.query("INSERT INTO club_tables (club_id, label, x, y, w, h, seats, price_cents) VALUES (2, 'T1', 1, 1, 2, 2, 4, 20000), (2, 'T2', 5, 1, 2, 2, 4, 20000)");
    const TERMS = { accept_terms: true, terms_version: "2026-10-01" };
    const nar = async (id) => (await pool.query("SELECT * FROM orders WHERE id=$1", [id])).rows[0];
    const stNar = async (ev) => (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1", [ev])).rows[0].n;
    const sold = async (ev) => (await pool.query("SELECT sold_count FROM events WHERE id=$1", [ev])).rows[0].sold_count;
    const vstopnice = async (oid) => (await pool.query("SELECT status FROM tickets WHERE order_id=$1", [oid])).rows.map(x => x.status);
    const sejaNarocila = async (oid) => S.seje[(await nar(oid)).stripe_checkout_session_id];

    // ================================================================
    console.log("\n# 1. payment_mode: sk_live_ (ZIV) in sk_test_ (SAND)");
    const pm = async (baza, ev) => (await api(baza, "GET", `/events/${ev}`)).body;
    let e = await pm(bZ, evO);
    assert(e.payment_mode === "stripe", "ZIV: dogodek uradnega profila brez Connecta: payment_mode stripe", e.payment_mode);
    e = await pm(bZ, evN);
    assert(e.payment_mode === "stripe", "ZIV: navaden klub z Connectom: stripe (kot doslej)", e.payment_mode);
    assert((await pm(bZ, evORetry)).payment_mode === "stripe", "ZIV: uradni profil Z Connectom: stripe");
    assert((await pm(bZ, evK5)).payment_mode === "unavailable", "ZIV: navaden klub brez Stripa: unavailable (409), nespremenjeno");
    assert((await pm(bZ, evOnep)).payment_mode === "unavailable", "ZIV: uradni profil brez podatkov prodajalca, placljivo: unavailable (I34)");
    assert((await pm(bZ, evOnep0)).payment_mode === "stripe", "ZIV: uradni profil brez podatkov prodajalca, 0 EUR: stripe (0 EUR mimo I34)");
    assert((await pm(bZ, evDemo)).payment_mode === "unavailable", "ZIV: uradni DEMO klub: unavailable (I41)");
    const sez = await api(bZ, "GET", "/events?limit=100");
    const poId = Object.fromEntries((Array.isArray(sez.body) ? sez.body : sez.body.events || []).map(x => [x.id, x]));
    assert(poId[evO] && poId[evO].payment_mode === "stripe" && poId[evOnep] && poId[evOnep].payment_mode === "unavailable", "ZIV: seznam GET /events: enak payment_mode kot dogodek", [poId[evO] && poId[evO].payment_mode, poId[evOnep] && poId[evOnep].payment_mode]);
    const vip = await api(bZ, "GET", `/events/${evO}/vip`);
    assert(vip.status === 200 && vip.body.payment_mode === "stripe", "ZIV: GET /events/:id/vip uradnega profila: stripe", vip.body && vip.body.payment_mode);
    const prodaja2 = await api(bZ, "GET", "/business/sales", T.lastnik2, undefined, { "x-outly-club": "2" });
    assert(prodaja2.status === 200 && prodaja2.body.payment_mode === "stripe" && prodaja2.body.payment_unavailable_reason === null, "ZIV: GET /business/sales uradnega profila: stripe, brez razloga", [prodaja2.status, prodaja2.body.payment_mode, prodaja2.body.payment_unavailable_reason]);
    const prodaja5 = await api(bZ, "GET", "/business/sales", T.lastnik5, undefined, { "x-outly-club": "5" });
    assert(prodaja5.body.payment_mode === "unavailable" && prodaja5.body.payment_unavailable_reason === "stripe_not_ready", "ZIV: navaden klub brez Stripa: unavailable / stripe_not_ready (nespremenjeno)", [prodaja5.body.payment_mode, prodaja5.body.payment_unavailable_reason]);
    assert(!/acct_/.test((await api(bZ, "GET", `/events/${evORetry}`)).text) && !/acct_/.test(sez.text), "I4: racun kluba nikjer v odgovoru (tudi uradni profil z Connectom)");
    assert((await pm(bS, evO)).payment_mode === "stripe", "SAND: uradni profil brez Connecta: stripe (nacin doloca platformni kljuc)", (await pm(bS, evO)).payment_mode);
    assert((await pm(bS, evK5)).payment_mode === "test", "SAND: navaden klub brez Stripa: test (nespremenjeno)");

    // ================================================================
    console.log("\n# 2. Nakup: seja brez transfer_data / on_behalf_of / application_fee_amount");
    const nakup = (token, ev, telo = {}, glave = {}) => api(bZ, "POST", `/events/${ev}/orders`, token, { quantity: 1, ...telo }, glave);
    const kljucA = crypto.randomUUID();
    const sejPred = S.zahtevkiSej.length;
    let r = await nakup(T.ana, evO, { quantity: 2, ticketPriceCents: 1, unit_price_cents: 1, total_cents: 1 }, { "idempotency-key": kljucA });   // cena v telesu se ne upošteva (I46)
    assert(r.status === 201 && r.body.mode === "stripe" && r.body.order.status === "pending" && /^https:\/\/checkout\.stripe\.test\//.test(r.body.checkout_url), "ana: vstopnice uradnega profila: 201 pending s povezavo Checkout", [r.status, r.body]);
    const O1 = r.body.order.id;
    assert(S.zahtevkiSej.length === sejPred + 1, "en klic Stripa za sejo", S.zahtevkiSej.length - sejPred);
    let p = S.zahtevkiSej[S.zahtevkiSej.length - 1].params;
    assert(!imaConnect(p), "seja NI Connect: brez transfer_data, on_behalf_of in application_fee_amount", Object.keys(p).filter(k => /transfer|behalf|fee/.test(k)));
    assert(p["line_items[0][price_data][unit_amount]"] === "1000" && p["line_items[0][quantity]"] === "2" && p["line_items[0][price_data][currency]"] === "eur", "cena iz baze (1000 c), kolicina 2, EUR");
    assert(p["metadata[order_id]"] === String(O1) && p.client_reference_id === String(O1) && p["payment_intent_data[metadata][order_id]"] === String(O1), "metadata order_id na seji in PaymentIntentu");
    const zdaj = Math.floor(Date.now() / 1000);
    assert(Number(p.expires_at) > zdaj + 29 * 60 && Number(p.expires_at) < zdaj + 31 * 60, "okno 30 min", Number(p.expires_at) - zdaj);
    let o = await nar(O1);
    assert(o.application_fee_cents === 0 && o.stripe_account_id === "platform" && o.total_cents === 2000 && o.status === "pending" && o.club_id === 2, "narocilo: provizija 0, racun »platform« (ne kluba), 2000 c", [o.application_fee_cents, o.stripe_account_id, o.total_cents]);
    assert(r.body.order.application_fee_cents === 0, "odgovor: application_fee_cents 0", r.body.order.application_fee_cents);
    r = await nakup(T.ana, evO, { quantity: 2 }, { "idempotency-key": kljucA });
    assert(r.status === 201 && r.body.order.id === O1 && S.zahtevkiSej.length === sejPred + 1, "idempotenca (I18): isti kljuc -> isto narocilo, se vedno en klic Stripa", [r.status, r.body.order && r.body.order.id, S.zahtevkiSej.length - sejPred]);
    // navaden klub: destination charge ostane
    r = await nakup(T.ana, evN);
    assert(r.status === 201 && r.body.mode === "stripe", "ana: navaden klub: 201 stripe", [r.status, r.body]);
    const N1 = r.body.order.id;
    p = S.zahtevkiSej[S.zahtevkiSej.length - 1].params;
    assert(p["payment_intent_data[transfer_data][destination]"] === "acct_ziv1" && p["payment_intent_data[on_behalf_of]"] === "acct_ziv1" && p["payment_intent_data[application_fee_amount]"] === "100",
      "NAVADEN KLUB: destination charge + on_behalf_of + provizija 10 % (100 c) nespremenjeno", Object.fromEntries(Object.entries(p).filter(([k]) => /transfer|behalf|fee/.test(k))));
    o = await nar(N1);
    assert(o.application_fee_cents === 100 && o.stripe_account_id === "acct_ziv1", "navaden klub: narocilo provizija 100, racun acct_ziv1", [o.application_fee_cents, o.stripe_account_id]);
    // uradni profil Z Connect racunom: vseeno neposredno na platformo
    r = await nakup(T.bor, evORetry);
    assert(r.status === 201 && r.body.mode === "stripe", "bor: uradni profil z Connectom: 201", [r.status, r.body]);
    const O4 = r.body.order.id;
    p = S.zahtevkiSej[S.zahtevkiSej.length - 1].params;
    o = await nar(O4);
    assert(!imaConnect(p) && o.application_fee_cents === 0 && o.stripe_account_id === "platform", "uradni profil Z Connect racunom: seja neposredna, provizija 0, racun »platform« na narocilu", [Object.keys(p).filter(k => /transfer|behalf|fee/.test(k)), o.application_fee_cents, o.stripe_account_id]);
    // gost
    r = await api(bZ, "POST", `/guest/events/${evO}/orders`, null, { email: "gost1@example.com", quantity: 1, ...TERMS });
    assert(r.status === 201 && r.body.mode === "stripe" && r.body.checkout_url && r.body.guest_token, "gost: uradni profil: 201 stripe", [r.status, r.body]);
    const G1 = r.body.order.id;
    const gGo = await api(bZ, "GET", "/guest/order", null, undefined, { "x-guest-token": r.body.guest_token });
    assert(gGo.status === 200 && gGo.body.seller && gGo.body.seller.is_platform === true && gGo.body.order.seller.is_platform === true, "gost: GET /guest/order: seller.is_platform true (oznaka naroclila)", [gGo.status, gGo.body.seller]);
    p = S.zahtevkiSej[S.zahtevkiSej.length - 1].params;
    o = await nar(G1);
    assert(!imaConnect(p) && o.application_fee_cents === 0 && o.stripe_account_id === "platform" && o.guest_email === "gost1@example.com", "gost: seja neposredna, provizija 0", [Object.keys(p).filter(k => /transfer|behalf|fee/.test(k)), o.application_fee_cents]);
    r = await api(bZ, "POST", `/guest/events/${evN}/orders`, null, { email: "gost2@example.com", quantity: 1, ...TERMS });
    p = S.zahtevkiSej[S.zahtevkiSej.length - 1].params;
    assert(r.status === 201 && p["payment_intent_data[transfer_data][destination]"] === "acct_ziv1" && p["payment_intent_data[application_fee_amount]"] === "100", "gost pri navadnem klubu: destination charge nespremenjen", Object.keys(p).filter(k => /transfer|behalf|fee/.test(k)));
    // VIP miza
    r = await api(bZ, "POST", `/events/${evO}/tables/1/orders`, T.bor, {});
    assert(r.status === 201 && r.body.mode === "stripe" && r.body.checkout_url, "bor: VIP miza uradnega profila: 201 stripe", [r.status, r.body]);
    const V1 = r.body.order.id;
    p = S.zahtevkiSej[S.zahtevkiSej.length - 1].params;
    o = await nar(V1);
    assert(!imaConnect(p) && o.application_fee_cents === 0 && o.stripe_account_id === "platform" && o.total_cents === 20000 && p["line_items[0][price_data][unit_amount]"] === "20000", "VIP miza: seja neposredna, provizija 0, 20000 c iz baze", [Object.keys(p).filter(k => /transfer|behalf|fee/.test(k)), o.total_cents]);

    // ================================================================
    console.log("\n# 3. Webhook: zakljucek, podvojen dogodek, napacen znesek, pospravljalec");
    const seja1 = (await nar(O1)).stripe_checkout_session_id;
    const pi1 = placaj(seja1);
    let w = await webhook(bZ, "checkout.session.completed", { id: seja1 });
    assert(w.status === 200 && !w.body.duplicate, "checkout.session.completed (neposredno placilo na platformo): 200", w);
    o = await nar(O1);
    assert(o.status === "paid" && o.stripe_payment_intent_id === pi1 && o.paid_at && o.application_fee_cents === 0 && o.stripe_account_id === "platform", "narocilo paid, PI zapisan, provizija 0", [o.status, o.stripe_payment_intent_id]);
    assert((await vstopnice(O1)).length === 2, "2 vstopnici", await vstopnice(O1));
    w = await webhook(bZ, "checkout.session.completed", { id: seja1 }, w.id);
    assert(w.status === 200 && w.body.duplicate === true, "isti dogodek drugic: duplicate");
    w = await webhook(bZ, "checkout.session.completed", { id: seja1 });
    assert(w.status === 200 && (await vstopnice(O1)).length === 2, "drug dogodek za isto sejo: se vedno 2 vstopnici (idempotentno)");
    // navaden klub placan (kontrola za finance in odpoved)
    const sejaN1 = (await nar(N1)).stripe_checkout_session_id; const piN1 = placaj(sejaN1);
    w = await webhook(bZ, "checkout.session.completed", { id: sejaN1 });
    assert(w.status === 200 && (await nar(N1)).status === "paid" && S.pi[piN1].transfer_data && S.ch[S.pi[piN1].latest_charge].transfer, "navaden klub: zakljucek kot doslej (destination charge)");
    // S1: potrdilo kupcu in javni seller (I50): platforma = »vstopnico prodaja NEXT DIMENSIONS«, BREZ stavka o posredniku; navaden klub nespremenjen
    {
      const refO1 = (await nar(O1)).public_ref, refN1 = (await nar(N1)).public_ref;
      const mailZa = (ref) => R.poslano.find(m => /Potrdilo|Confirm|Order|Naro/i.test(String(m.subject) + String(m.text || "")) && String(m.text || "").includes(ref) && /Seller|Prodajalec/i.test(String(m.text || "")));
      assert(await cakaj(async () => !!mailZa(refO1) && !!mailZa(refN1), 15000), "potrdili kupcu (platforma in navaden klub) poslani", R.poslano.map(m => m.subject));
      const mO = mailZa(refO1), mN = mailZa(refN1);
      assert(mO && /Vstopnico prodaja[^\n]*NEXT DIMENSIONS/.test(mO.text) && /The ticket is sold by[^\n]*NEXT DIMENSIONS/.test(mO.text), "PLATFORMA: potrdilo (sl in en) pravi, da vstopnico prodaja NEXT DIMENSIONS", mO && mO.text);
      assert(mO && !/posrednik|intermediary|Vstopnico prodaja klub|sold by the club/i.test(mO.text) && !/posrednik|intermediary/i.test(mO.html || ""), "PLATFORMA: potrdilo BREZ stavka o posredniku in brez »klub«", mO && mO.text);
      assert(mN && /Vstopnico prodaja klub: /.test(mN.text) && /Outly je samo posrednik: NEXT DIMENSIONS/.test(mN.text) && /Outly is only the intermediary: NEXT DIMENSIONS/.test(mN.text) && /The ticket is sold by the club: /.test(mN.text), "NAVADEN KLUB: potrdilo nespremenjeno (klub + Outly je samo posrednik)", mN && mN.text);
      const sO = (await api(bZ, "GET", `/events/${evO}`)).body.seller, sN = (await api(bZ, "GET", `/events/${evN}`)).body.seller;
      assert(sO && sO.is_platform === true && sN && !("is_platform" in sN) && Object.keys(sN).length === 8, "javni seller: platforma ima is_platform true, navaden klub ima nespremenjenih 8 polj", [sO, sN]);
      assert((await api(bZ, "GET", `/clubs/2`)).body.seller.is_platform === true && !("is_platform" in (await api(bZ, "GET", `/clubs/1`)).body.seller), "GET /clubs/:id: isto");
    }
    // VIP miza
    const sejaV1 = (await nar(V1)).stripe_checkout_session_id; placaj(sejaV1);
    w = await webhook(bZ, "checkout.session.completed", { id: sejaV1 });
    assert(w.status === 200 && (await nar(V1)).status === "paid" && (await vstopnice(V1)).length === 4, "VIP miza: paid, 4 vstopnice");
    // gost: kupec je placal DRUG znesek (550 namesto 1000): narocilo cancelled + samodejno vracilo celotnega placanega zneska BREZ reverse_transfer in refund_application_fee
    const sejaG1 = (await nar(G1)).stripe_checkout_session_id; const piG1 = placaj(sejaG1, { znesek: 550 });
    w = await webhook(bZ, "checkout.session.completed", { id: sejaG1 });
    assert(w.status === 200, "napacen znesek seje: webhook 200", w);
    o = await nar(G1);
    assert(o.status === "cancelled" && (await vstopnice(G1)).length === 0, "napacen znesek: narocilo cancelled, brez vstopnic", [o.status]);
    assert(await cakaj(async () => (await pool.query("SELECT stanje FROM vracila WHERE order_id=$1 AND razlog='inactive_order'", [G1])).rows[0]?.stanje === "opravljeno"), "inactive_order: vracilo opravljeno");
    let re = S.refundi.filter(x => x.payment_intent === piG1);
    assert(re.length === 1 && Number(re[0].params.amount) === 550 && re[0].params.reverse_transfer === undefined && re[0].params.refund_application_fee === undefined,
      "inactive_order platforma: navadno vracilo 550 c, BREZ reverse_transfer in refund_application_fee", re.map(x => x.params));
    // pospravljalec: seja placana, webhook izgubljen
    r = await nakup(T.cene, evO);
    const O5 = r.body.order.id; const seja5 = (await nar(O5)).stripe_checkout_session_id; const pi5 = placaj(seja5);
    await pool.query("UPDATE orders SET checkout_expires_at = NOW() - INTERVAL '10 minutes' WHERE id=$1", [O5]);
    assert(await cakaj(async () => (await nar(O5)).status === "paid", 12000), "pospravljalec: placana seja brez webhooka -> paid", (await nar(O5)).status);
    o = await nar(O5);
    assert(o.stripe_payment_intent_id === pi5 && (await vstopnice(O5)).length === 1, "pospravljalec: PI zapisan, 1 vstopnica");

    // ================================================================
    console.log("\n# 4. Varovala ostanejo");
    const sPred = S.zahtevkiSej.length, nPred = await stNar(evO);
    r = await nakup(T.ana, evO, { expected_price_cents: 500 });
    assert(r.status === 409 && /price has changed/i.test(String(r.body)) && await stNar(evO) === nPred && S.zahtevkiSej.length === sPred, "I46: spremenjena cena -> 409, brez narocila in brez Stripa", [r.status, r.body]);
    r = await nakup(T.ana, evOcap, { quantity: 3 });
    assert(r.status === 409 && /left/i.test(String(r.body)) && await stNar(evOcap) === 0 && await sold(evOcap) === 0, "zaloga: 3 od 2 -> 409, nic rezerviranega", [r.status, r.body]);
    const a1 = await nakup(T.ana, evOcap, { quantity: 2 });
    const b1 = await nakup(T.bor, evOcap, { quantity: 1 });
    assert(a1.status === 201 && b1.status === 409 && await sold(evOcap) === 2, "zaloga: cakajoce narocilo drzi zalogo (2 od 2), drugi kupec 409", [a1.status, b1.status, await sold(evOcap)]);
    const nul = await nakup(T.ana, evO0);
    const sPo0 = S.zahtevkiSej.length;
    o = nul.status === 201 ? await nar(nul.body.order.id) : null;
    assert(nul.status === 201 && nul.body.order.status === "paid" && nul.body.mode === "stripe" && !nul.body.checkout_url && o.application_fee_cents === 0 && o.stripe_payment_intent_id === null, "0 EUR: 201 paid takoj, brez Checkouta, PI NULL", [nul.status, nul.body]);
    assert(sPo0 === S.zahtevkiSej.length, "0 EUR: Stripe ni bil klican");
    r = await nakup(T.mladi, evO18);
    assert(r.status === 403 && await stNar(evO18) === 0, "I8: mladoletnik na 18+ dogodku uradnega profila -> 403", [r.status, r.body]);
    r = await nakup(T.ana, evO18);
    assert(r.status === 201, "I8: polnoletna ana na 18+ dogodku -> 201", [r.status, r.body]);
    r = await nakup(T.ana, evOnep);
    assert(r.status === 409 && r.body.error === "seller_incomplete" && await stNar(evOnep) === 0, "I34: uradni profil brez podatkov prodajalca, placljivo -> 409 seller_incomplete, brez narocila", [r.status, r.body]);
    r = await api(bZ, "POST", `/guest/events/${evOnep}/orders`, null, { email: "gost3@example.com", quantity: 1, ...TERMS });
    assert(r.status === 409 && r.body.error === "seller_incomplete" && await stNar(evOnep) === 0, "I34: gost -> 409 seller_incomplete", [r.status, r.body]);
    r = await nakup(T.ana, evOnep0);
    assert(r.status === 201 && r.body.order.status === "paid", "I34: 0 EUR pri uradnem profilu brez podatkov: 201 paid", [r.status, r.body]);
    r = await nakup(T.ana, evDemo);
    assert(r.status === 409 && r.body.error === "demo_club" && await stNar(evDemo) === 0, "I41: uradni DEMO klub -> 409 demo_club", [r.status, r.body]);
    r = await nakup(T.ana, evK5);
    assert(r.status === 409 && /does not accept online payments/.test(String(r.body)) && await stNar(evK5) === 0, "navaden klub brez Stripa ob sk_live_: 409 (nespremenjeno)", [r.status, r.body]);
    r = await api(bS, "POST", `/events/${evO}/orders`, T.ana, { quantity: 1 });
    p = S.zahtevkiSej[S.zahtevkiSej.length - 1].params;
    assert(r.status === 201 && r.body.mode === "stripe" && !imaConnect(p), "SAND: uradni profil: pravi (sandbox) Checkout brez Connecta", [r.status, r.body.mode]);
    r = await api(bS, "POST", `/events/${evK5}/orders`, T.bor, { quantity: 1 });
    assert(r.status === 201 && r.body.mode === "test" && r.body.order.status === "paid", "SAND: navaden klub brez Stripa: testni nacin (takoj paid), nespremenjeno", [r.status, r.body.mode]);

    // ================================================================
    console.log("\n# 5. Finance");
    const f = (await api(bZ, "GET", "/admin/api/finance", T.admin)).body;
    const k2 = f.by_club.find(x => x.id === 2), k1 = f.by_club.find(x => x.id === 1);
    const platPaid = (await pool.query("SELECT COALESCE(SUM(total_cents),0)::int AS z FROM orders WHERE club_id=2 AND status IN ('paid','partially_refunded') AND stripe_payment_intent_id NOT LIKE 'test\\_%' AND total_cents > 0")).rows[0].z;
    assert(platPaid === 2000 + 20000 + 1000 && k2 && k2.gross_cents === platPaid, "admin by_club Outly: bruto = vsa prodaja uradnega profila (23000)", [platPaid, k2 && k2.gross_cents]);
    assert(k2.fee_cents === 0 && k2.net_cents === 0, "admin by_club Outly: provizija 0, »za klube« 0", [k2.fee_cents, k2.net_cents]);
    assert(k2.own_sales_cents === platPaid, "admin by_club Outly: lastna prodaja Outly (own_sales_cents) = 23000", k2.own_sales_cents);
    assert(k1.gross_cents === 1000 && k1.fee_cents === 100 && k1.net_cents === 900 && k1.own_sales_cents === 0, "admin by_club navaden klub: bruto 1000, provizija 100, za klub 900, lastne prodaje 0", [k1.gross_cents, k1.fee_cents, k1.net_cents, k1.own_sales_cents]);
    const s = f.summary;
    assert(s.fee_cents === 100 && s.clubs_net_cents === 900, "admin summary: prihodek iz provizij 100, »za klube« 900 (brez prodaje Outly)", [s.fee_cents, s.clubs_net_cents]);
    assert(s.own_sales_cents === platPaid && s.gross_cents === platPaid + 1000, "admin summary: lastna prodaja Outly 23000, bruto 24000", [s.own_sales_cents, s.gross_cents]);
    const prodaja2b = (await api(bZ, "GET", "/business/sales", T.lastnik2, undefined, { "x-outly-club": "2" })).body;
    assert(prodaja2b.fee_percent === 0 && prodaja2b.summary.fee_cents === 0 && prodaja2b.summary.gross_cents === platPaid && prodaja2b.summary.net_cents === platPaid, "GET /business/sales Outly: provizija 0 % / 0 c, bruto = neto = 23000", [prodaja2b.fee_percent, prodaja2b.summary]);
    const prodaja1 = (await api(bZ, "GET", "/business/sales", T.lastnik, undefined, { "x-outly-club": "1" })).body;
    assert(prodaja1.fee_percent === 10 && prodaja1.summary.fee_cents === 100 && prodaja1.summary.net_cents === 900, "GET /business/sales navaden klub: 10 %, provizija 100, neto 900 (nespremenjeno)", [prodaja1.fee_percent, prodaja1.summary]);

    // ================================================================
    console.log("\n# 6. Spori");
    // 6a platforma: dva naroceila na evOspor (eno bo izgubljeno), spor ne bremeni kluba
    r = await nakup(T.kupec1, evOspor); const P1 = r.body.order.id; const seP1 = (await nar(P1)).stripe_checkout_session_id; const piP1 = placaj(seP1);
    await webhook(bZ, "checkout.session.completed", { id: seP1 });
    assert((await nar(P1)).status === "paid", "spor: platformno narocilo paid");
    R.poslano.length = 0; const pred = S.klici.length;
    dodajSpor("dp_plat1", piP1, "needs_response", 1000);
    w = await webhook(bZ, "charge.dispute.created", { id: "dp_plat1" });
    assert(w.status === 200, "charge.dispute.created: 200");
    let sp = (await pool.query("SELECT * FROM spori WHERE id='dp_plat1'")).rows[0];
    assert(sp && Number(sp.order_id) === P1 && sp.stanje === "needs_response" && sp.povrnitev_stanje === null, "spor zapisan, povezan z narocilom, brez povrnitve od kluba", sp && [sp.order_id, sp.stanje, sp.povrnitev_stanje]);
    assert(/\[spori\] POZOR: nov spor dp_plat1/.test(ZIV.log), "alarm v dnevniku (POZOR nov spor)");
    r = await api(bZ, "GET", "/me/tickets", T.kupec1);
    const tP1 = (Array.isArray(r.body) ? r.body : r.body.tickets || []).filter(t => t.order_id === P1 || t.orderId === P1);
    assert(r.status === 200 && tP1.length === 1 && tP1[0].payment_disputed === true, "vstopnica spornega naroclila ne velja na vratih (payment_disputed)", tP1.map(t => t.payment_disputed));
    S.spori.dp_plat1.status = "lost";
    w = await webhook(bZ, "charge.dispute.closed", { id: "dp_plat1" });
    sp = (await pool.query("SELECT * FROM spori WHERE id='dp_plat1'")).rows[0];
    assert(w.status === 200 && sp.stanje === "lost" && sp.zaprt_at && sp.povrnitev_stanje === null && sp.povrnitev_napaka === null, "izgubljen spor: zapisan, povrnitev od kluba NI sprozena (nikogar ni treba terjati)", sp && [sp.stanje, sp.povrnitev_stanje, sp.povrnitev_napaka]);
    await pocakaj(1500);
    assert(klici("POST", /\/transfers/).length === 0 && klici("GET", /\/transfers/).length === 0 && S.reversali.length === 0, "platforma: nobenega klica transferjev (brez povrnitve od kluba)");
    assert(/izgubljen/i.test(ZIV.log) && /\[spori\] POZOR: spor zaprt: spor dp_plat1/.test(ZIV.log) && /platform/i.test(ZIV.log.slice(ZIV.log.indexOf("dp_plat1"))), "alarm: izgubljen spor nosi platforma (POZOR zaprt, omemba platforme)");
    assert(mailiSporaNa("lastnik2@outly.si").length === 0 && mailiSporaNa("info@nextdimensionsdoo.si").length === 0 && R.poslano.every(m => !/Spor|Dispute/.test(String(m.subject))), "platforma: mail o sporu NI poslan nikomur (kluba ni)", R.poslano.map(m => m.subject));
    // 6b spor pred placilom (platforma): povezava ob zakljuci() ne sprozi povrnitve od kluba
    r = await nakup(T.bor, evOvrst); const P2 = r.body.order.id; const seP2 = (await nar(P2)).stripe_checkout_session_id;
    const piP2 = "pi_" + seP2.replace(/\W/g, "");
    dodajPlacilo(piP2, { amount: 1000, platforma: true });
    dodajSpor("dp_plat2", piP2, "lost", 1000);
    w = await webhook(bZ, "charge.dispute.closed", { id: "dp_plat2" });
    sp = (await pool.query("SELECT * FROM spori WHERE id='dp_plat2'")).rows[0];
    assert(w.status === 200 && sp.order_id === null && sp.povrnitev_stanje === "rocno", "spor pred placilom: zapisan brez narocila (rocno)", sp && [sp.order_id, sp.povrnitev_stanje]);
    Object.assign(S.seje[seP2], { status: "complete", payment_status: "paid", payment_intent: piP2 });
    w = await webhook(bZ, "checkout.session.completed", { id: seP2 });
    sp = (await pool.query("SELECT * FROM spori WHERE id='dp_plat2'")).rows[0];
    assert(w.status === 200 && Number(sp.order_id) === P2 && sp.povrnitev_stanje === null && sp.povrnitev_napaka === null, "spor pred placilom (platforma): ob zakljucku povezan z narocilom, povrnitve od kluba NI", sp && [sp.order_id, sp.povrnitev_stanje, sp.povrnitev_napaka]);
    await pocakaj(800);
    assert(klici("POST", /\/transfers/).length === 0, "platforma: se vedno nobenega klica transferjev");
    // 6c navaden klub: povrnitev od kluba in mail kot doslej
    r = await nakup(T.kupec2, evN3); const N3 = r.body.order.id; const seN3 = (await nar(N3)).stripe_checkout_session_id; const piN3 = placaj(seN3);
    await webhook(bZ, "checkout.session.completed", { id: seN3 });
    dodajSpor("dp_navaden1", piN3, "needs_response", 1000);
    await webhook(bZ, "charge.dispute.created", { id: "dp_navaden1" });
    assert(await cakaj(async () => mailiSporaNa("lastnik@outly.si").length >= 1, 8000), "navaden klub: lastnik dobi mail o sporu (kot doslej)", R.poslano.map(m => [m.to, m.subject]));
    S.spori.dp_navaden1.status = "lost";
    await webhook(bZ, "charge.dispute.closed", { id: "dp_navaden1" });
    assert(await cakaj(async () => (await pool.query("SELECT povrnitev_stanje FROM spori WHERE id='dp_navaden1'")).rows[0].povrnitev_stanje === "opravljeno", 10000), "navaden klub: izgubljen spor -> povrnitev od kluba opravljena (transfer reversal, kot doslej)",
      (await pool.query("SELECT povrnitev_stanje, povrnitev_napaka FROM spori WHERE id='dp_navaden1'")).rows[0]);
    assert(S.reversali.length === 1 && S.reversali[0].transfer === "tr_" + piN3.replace(/\W/g, ""), "navaden klub: natanko en transfer reversal", S.reversali);
    assert(klici("POST", /\/transfers/).length === 1, "transferji so bili klicani samo za navaden klub");

    // ================================================================
    console.log("\n# 7. Odpoved dogodka in vracila");
    // Placana naroceila uradnega profila na evO: O1 (2 vstopnici), V1 (miza), O5 (pospravljalec), 0 EUR; gost G1 je cancelled (ze vrnjen).
    const prejRe = S.refundi.length, prejFee = S.fee_refundi.length;
    const placanaO = (await pool.query("SELECT id, public_ref, total_cents, stripe_payment_intent_id AS pi FROM orders WHERE event_id=$1 AND status='paid' ORDER BY id", [evO])).rows;
    assert(placanaO.length === 3, "dogodek uradnega profila: 3 placana naroceila (vstopnice, miza, pospravljalec)", placanaO.map(x => [x.id, x.total_cents]));
    r = await api(bZ, "DELETE", `/events/${evO}`, T.lastnik2, undefined, { "x-outly-club": "2" });
    assert(r.status === 200 && r.body.event.status === "cancelled", "DELETE dogodka uradnega profila: odpovedan", [r.status, r.body]);
    assert(await cakaj(async () => (await pool.query("SELECT COUNT(*)::int AS n FROM vracila WHERE event_id=$1 AND razlog='event_cancelled' AND stanje IN ('opravljeno','ni_uspelo','rocno','preklicano')", [evO])).rows[0].n === 3, 20000), "odpoved: 3 vracila koncana", (await pool.query("SELECT stanje, napaka FROM vracila WHERE event_id=$1", [evO])).rows);
    const stanja = (await pool.query("SELECT order_id, stanje, napaka, znesek_cents, brez_stripa, provizija_vracilo_id, application_fee_id FROM vracila WHERE event_id=$1 AND razlog='event_cancelled' ORDER BY order_id", [evO])).rows;
    assert(stanja.every(x => x.stanje === "opravljeno" && x.napaka === null), "vsa vracila opravljena brez napake", stanja);
    const novaRe = S.refundi.slice(prejRe).filter(x => placanaO.some(y => y.pi === x.payment_intent));
    assert(novaRe.length === 3, "Stripova vracila za 3 placana naroceila z denarjem", novaRe.length);
    for (const x of novaRe) {
      const nr = placanaO.find(y => y.pi === x.payment_intent);
      assert(Number(x.params.amount) === nr.total_cents && x.params.reverse_transfer === undefined && x.params.refund_application_fee === undefined && /^outly-vracilo-\d+$/.test(x.kljuc) && x.params["metadata[order_id]"] === String(nr.id),
        `naroceno ${nr.id}: vracilo ${nr.total_cents} c BREZ reverse_transfer in refund_application_fee, idempotentni kljuc + metadata`, x.params);
    }
    assert(S.fee_refundi.length === prejFee && klici("GET", /application_fees/).length === 0 && klici("POST", /application_fees/).length === 0, "platforma: NOBENEGA vracila provizije (ni provizije), nobenega klica application_fees");
    // 0 EUR naroceno (dogodek evO0): odpoved dogodka je samo stanje, brez Stripa
    const prejKl = S.klici.length;
    r = await api(bZ, "DELETE", `/events/${evO0}`, T.lastnik2, undefined, { "x-outly-club": "2" });
    assert(r.status === 200, "DELETE brezplacnega dogodka uradnega profila", [r.status, r.body]);
    assert(await cakaj(async () => (await pool.query("SELECT stanje FROM vracila WHERE event_id=$1", [evO0])).rows[0]?.stanje === "opravljeno", 15000), "0 EUR: vracilo opravljeno");
    const nulVr = (await pool.query("SELECT znesek_cents, brez_stripa FROM vracila WHERE event_id=$1", [evO0])).rows[0];
    assert(nulVr && nulVr.brez_stripa === true && nulVr.znesek_cents === 0 && S.klici.slice(prejKl).filter(k => /refunds/.test(k.u)).length === 0, "0 EUR naroceno: samo stanje, brez Stripa", nulVr);
    assert(stanja.every(x => x.provizija_vracilo_id === null && x.application_fee_id === null), "vracila nimajo ne vracila provizije ne application_fee_id");
    for (const x of placanaO) {
      const n2 = await nar(x.id);
      assert(n2.status === "refunded" && n2.refunded_cents === x.total_cents && (await vstopnice(x.id)).every(t => t === "refunded"), `naroceno ${x.id}: refunded, refunded_cents ${x.total_cents}, vstopnice refunded`, [n2.status, n2.refunded_cents]);
    }
    assert(klici("POST", /\/transfers/).length === 1, "se vedno samo en klic transferjev (spor navadnega kluba)");
    // navaden klub: odpoved ostane z reverse_transfer in vracilom provizije
    const prejRe2 = S.refundi.length;
    r = await api(bZ, "DELETE", `/events/${evN}`, T.lastnik);
    assert(r.status === 200, "DELETE dogodka navadnega kluba", [r.status, r.body]);
    assert(await cakaj(async () => (await pool.query("SELECT stanje FROM vracila WHERE order_id=$1 AND razlog='event_cancelled'", [N1])).rows[0]?.stanje === "opravljeno", 15000), "navaden klub: vracilo opravljeno", (await pool.query("SELECT stanje, napaka FROM vracila WHERE order_id=$1", [N1])).rows);
    const reN = S.refundi.slice(prejRe2).find(x => x.payment_intent === piN1);
    assert(reN && reN.params.reverse_transfer === "true" && reN.params.refund_application_fee === "false" && Number(reN.params.amount) === 1000, "NAVADEN KLUB: vracilo z reverse_transfer=true in refund_application_fee=false (nespremenjeno)", reN && reN.params);
    assert(S.fee_refundi.length === prejFee + 1 && S.fee_refundi[S.fee_refundi.length - 1].amount === 41, "NAVADEN KLUB: vracilo provizije 100 - 59 (Stripova pristojbina) = 41", S.fee_refundi.map(x => x.amount));
    // admin »Poskusi znova« za platformno vracilo: Stripe zavrne (trajna napaka), nato popravek in retry
    const seO4 = (await nar(O4)).stripe_checkout_session_id; placaj(seO4); await webhook(bZ, "checkout.session.completed", { id: seO4 });
    r = await nakup(T.bor, evORetry);   // drugi nakup istega kupca (O4 je ze placan)
    const O6 = r.body.order.id; const seO6 = (await nar(O6)).stripe_checkout_session_id; const piO6 = placaj(seO6);
    await webhook(bZ, "checkout.session.completed", { id: seO6 });
    assert((await nar(O6)).status === "paid" && (await nar(O4)).status === "paid", "uradni profil z Connectom: dve narocili paid (neposredno placilo)");
    S.refundHook = (p) => (p.payment_intent === piO6 ? { status: 400, body: { error: { type: "invalid_request_error", message: "Refund ni mogoc (test)" } } } : null);
    const prejRe3 = S.refundi.length;
    r = await api(bZ, "DELETE", `/events/${evORetry}`, T.lastnik4, undefined, { "x-outly-club": "4" });
    assert(r.status === 200, "DELETE dogodka (uradni profil z Connectom)", [r.status, r.body]);
    assert(await cakaj(async () => (await pool.query("SELECT stanje FROM vracila WHERE order_id=$1", [O6])).rows[0]?.stanje === "ni_uspelo", 15000), "zavrnjeno vracilo: ni_uspelo (alarm)", (await pool.query("SELECT stanje, napaka FROM vracila WHERE order_id=$1", [O6])).rows);
    assert(await cakaj(async () => (await pool.query("SELECT stanje FROM vracila WHERE order_id=$1", [O4])).rows[0]?.stanje === "opravljeno", 15000), "drugo vracilo istega dogodka opravljeno");
    S.refundHook = null;
    const vrId = (await pool.query("SELECT id FROM vracila WHERE order_id=$1", [O6])).rows[0].id;
    r = await api(bZ, "POST", `/admin/api/refunds/${vrId}/retry`, T.admin);
    assert(r.status === 200 && r.body.state === "caka", "admin: Poskusi znova -> v vrsti", [r.status, r.body]);
    assert(await cakaj(async () => (await pool.query("SELECT stanje FROM vracila WHERE order_id=$1", [O6])).rows[0]?.stanje === "opravljeno", 15000), "po retry: vracilo opravljeno", (await pool.query("SELECT stanje, napaka FROM vracila WHERE order_id=$1", [O6])).rows);
    const reRetry = S.refundi.slice(prejRe3).filter(x => x.payment_intent === piO6);
    assert(reRetry.length === 1 && reRetry[0].params.reverse_transfer === undefined && reRetry[0].params.refund_application_fee === undefined && Number(reRetry[0].params.amount) === 1000,
      "retry: eno vracilo 1000 c BREZ reverse_transfer in refund_application_fee", reRetry.map(x => x.params));
    assert((await nar(O6)).status === "refunded", "po retry: naroceno refunded");
    assert(S.fee_refundi.length === prejFee + 1, "platforma tudi po retry: se vedno brez vracila provizije");

    // ================================================================
    console.log("\n# 8. Vracilo odloca oznaka NAROCILA, ne trenutna zastavica kluba; dnevnik stikala is_official; opozorilo v panelu");
    // 8a: placano kot platforma (klub 2 je is_official) -> admin izklopi is_official -> odpoved -> vracilo BREZ reverse_transfer
    const evFlag = await dogodek(2, "Outly oznaka narocila", 1000);
    r = await nakup(T.kupec1, evFlag);
    const OF = r.body.order.id; const seOF = (await nar(OF)).stripe_checkout_session_id; const piOF = placaj(seOF);
    await webhook(bZ, "checkout.session.completed", { id: seOF });
    assert((await nar(OF)).status === "paid" && (await nar(OF)).stripe_account_id === "platform" && !S.pi[piOF].transfer_data, "8a: placano kot platforma (oznaka platform, PI brez transfer_data)");
    const logPred = ZIV.log.length;
    const klubi0 = await api(bZ, "GET", "/admin/api/clubs", T.admin);
    const kl2 = (klubi0.body || []).find(x => x.id === 2), kl1 = (klubi0.body || []).find(x => x.id === 1), kl5 = (klubi0.body || []).find(x => x.id === 5);
    assert(kl2 && kl2.has_stripe_account === false && kl2.order_count > 0 && kl1.has_stripe_account === true && kl1.order_count > 0 && kl5.has_stripe_account === false && typeof kl5.order_count === "number" && !/acct_/.test(klubi0.text),
      "admin seznam klubov: has_stripe_account + order_count (panel potrdi vklop), racun sam ne uhaja", [kl2 && [kl2.has_stripe_account, kl2.order_count], kl1 && [kl1.has_stripe_account, kl1.order_count], kl5 && [kl5.has_stripe_account, kl5.order_count]]);
    r = await api(bZ, "PATCH", "/admin/api/clubs/2", T.admin, { isOfficial: false });
    assert(r.status === 200 && r.body.is_official === false, "8a: admin izklopi is_official kluba 2", [r.status, r.body && r.body.is_official]);
    assert(new RegExp(`is_official: admin uporabnik ${U.admin} je klubu 2 .*true -> false`).test(ZIV.log.slice(logPred)), "S2: dnevnik: kdo, kateri klub, staro -> novo (true -> false)", ZIV.log.slice(logPred).slice(-600));
    const logPred2 = ZIV.log.length;
    r = await api(bZ, "PATCH", "/admin/api/clubs/2", T.admin, { isOfficial: false, name: "Outly" });
    assert(r.status === 200 && !/is_official:/.test(ZIV.log.slice(logPred2)), "S2: brez spremembe stikala ni vrstice v dnevniku");
    const prejOF = S.refundi.length;
    r = await api(bZ, "DELETE", `/events/${evFlag}`, T.lastnik2, undefined, { "x-outly-club": "2" });
    assert(r.status === 200, "8a: odpoved dogodka po izklopu is_official", [r.status, r.body]);
    assert(await cakaj(async () => (await pool.query("SELECT stanje FROM vracila WHERE order_id=$1", [OF])).rows[0]?.stanje === "opravljeno", 15000), "8a: vracilo opravljeno", (await pool.query("SELECT stanje, napaka FROM vracila WHERE order_id=$1", [OF])).rows);
    const reOF = S.refundi.slice(prejOF).filter(x => x.payment_intent === piOF);
    assert(reOF.length === 1 && reOF[0].params.reverse_transfer === undefined && reOF[0].params.refund_application_fee === undefined && Number(reOF[0].params.amount) === 1000,
      "8a: kljub izklopljeni zastavici vracilo BREZ reverse_transfer in refund_application_fee (odloca oznaka naroclila)", reOF.map(x => x.params));
    assert(S.fee_refundi.length === prejFee + 1, "8a: brez vracila provizije");
    // 8b: placano z acct_ (navaden klub 1) -> admin vklopi is_official -> odpoved -> vracilo Z reverse_transfer
    const evFlag2 = await dogodek(1, "Navadna noc oznaka narocila", 1000);
    r = await nakup(T.kupec2, evFlag2);
    const NF = r.body.order.id; const seNF = (await nar(NF)).stripe_checkout_session_id; const piNF = placaj(seNF);
    await webhook(bZ, "checkout.session.completed", { id: seNF });
    assert((await nar(NF)).status === "paid" && (await nar(NF)).stripe_account_id === "acct_ziv1" && S.pi[piNF].transfer_data, "8b: placano z acct_ (destination charge)");
    const logPred3 = ZIV.log.length;
    r = await api(bZ, "PATCH", "/admin/api/clubs/1", T.admin, { isOfficial: true });
    assert(r.status === 200 && r.body.is_official === true, "8b: admin vklopi is_official kluba 1", [r.status, r.body && r.body.is_official]);
    assert(new RegExp(`is_official: admin uporabnik ${U.admin} je klubu 1 .*false -> true`).test(ZIV.log.slice(logPred3)), "S2: dnevnik: false -> true", ZIV.log.slice(logPred3).slice(-600));
    assert((await nar(NF)).stripe_account_id === "acct_ziv1", "8b: oznaka narocila se ob vklopu zastavice NE spremeni");
    const prejNF = S.refundi.length, prejFeeNF = S.fee_refundi.length;
    r = await api(bZ, "DELETE", `/events/${evFlag2}`, T.lastnik);
    assert(r.status === 200, "8b: odpoved dogodka po vklopu is_official", [r.status, r.body]);
    assert(await cakaj(async () => (await pool.query("SELECT stanje FROM vracila WHERE order_id=$1", [NF])).rows[0]?.stanje === "opravljeno", 15000), "8b: vracilo opravljeno", (await pool.query("SELECT stanje, napaka FROM vracila WHERE order_id=$1", [NF])).rows);
    const reNF = S.refundi.slice(prejNF).filter(x => x.payment_intent === piNF);
    assert(reNF.length === 1 && reNF[0].params.reverse_transfer === "true" && reNF[0].params.refund_application_fee === "false" && Number(reNF[0].params.amount) === 1000,
      "8b: kljub vklopljeni zastavici vracilo Z reverse_transfer=true (odloca oznaka naroclila)", reNF.map(x => x.params));
    assert(S.fee_refundi.length === prejFeeNF + 1, "8b: vracilo provizije kot pri navadnem klubu");
    // S1 vracilo: mail o odpovedi pri platformi brez »v imenu organizatorja«
    const refOF = (await nar(OF)).public_ref, refNF = (await nar(NF)).public_ref;
    await cakaj(async () => R.poslano.some(m => String(m.text || "").includes(refOF) && /odpovedan|cancelled/i.test(m.text)), 15000);
    const mvO = R.poslano.filter(m => String(m.text || "").includes(refOF) && /odpovedan|cancelled/i.test(String(m.text || "")) && !/Prodajalec/.test(m.text));
    assert(mvO.length > 0 && mvO.every(m => !/posrednik|intermediary|v imenu organizatorja|on the organiser/i.test(m.text)), "mail o odpovedi/vracilu (platforma): brez stavka o posredniku", mvO.map(m => m.subject));
    // vrni stikali (kontrola: vklop kluba 2 brez Stripa, izklop kluba 1) in preveri se, da panel dobi opozorilo
    r = await api(bZ, "PATCH", "/admin/api/clubs/1", T.admin, { isOfficial: false });
    r = await api(bZ, "PATCH", "/admin/api/clubs/2", T.admin, { isOfficial: true });
    assert(r.status === 200 && r.body.is_official === true, "stikali vrnjeni");
    const html = require("fs").readFileSync(require("path").join(__dirname, "..", "admin", "index.html"), "utf8");
    assert(/Vse prodaje tega kluba gredo na račun NEXT DIMENSIONS, provizije ni, klub ne dobi denarja\./.test(html) && /window\.confirm\([^)]*has_stripe_account|has_stripe_account[\s\S]{0,400}window\.confirm/.test(html) && /star\.has_stripe_account \|\| star\.order_count > 0/.test(html),
      "panel: opozorilo ob stikalu + confirm ob vklopu pri klubu s Stripe racunom ali narocili");
  } finally {
    for (const x of [ZIV, SAND]) { x.srv.kill(); }
    stripeServer.close(); jwksServer.close(); resendServer.close(); await pool.end().catch(() => {});
  }
  console.log(`\n${ok} uspelo, ${fail} padlo`);
  if (fail) { console.log("--- dnevnik (ZIV) ---\n" + ZIV.log.slice(-4000)); process.exit(1); }
  process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
