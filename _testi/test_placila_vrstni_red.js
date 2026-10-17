#!/usr/bin/env node
/**
 * Test #276: vrstni red Stripe dogodkov in izbris racuna med Checkoutom (placila_stripe.js, DELETE /me v index.js). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_placila_vrstni_red.js
 * Brez pravega Stripa: lazni Stripe API na svojem portu (STRIPE_API_BASE), webhooki podpisani s Stripovim paketom (kot test_stripe.js).
 *  S2: charge.refunded / charge.dispute.created PRED checkout.session.completed se ne smeta izgubiti (narocilo je pozneje paid, vstopnice veljajo, denar je vrnjen).
 *  S4: DELETE /me prekliče cakajoca narocila (+ expire seje po COMMIT-u, napaka ni usodna); zakljuci() narocilo brez imetnika vrne kupcu (inactive_order).
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");
const Stripe = require("stripe");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 4531, JWKS_PORT = 4532, STRIPE_PORT = 4533, RESEND_PORT = 4534;
const BASE = `http://127.0.0.1:${PORT}`;
const WHSEC = "whsec_test_outly";
const stripeLokalno = new Stripe("sk_test_lokalno");

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-vrstni-red";
const jwksServer = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url.startsWith("/auth/v1/user")) { try { const t = JSON.parse(Buffer.from(String(req.headers.authorization).split(".")[1], "base64url")); return res.end(JSON.stringify({ id: t.sub, email: t.email, email_confirmed_at: "2026-01-01T00:00:00Z" })); } catch (_) { res.statusCode = 401; return res.end("{}"); } }
  if (req.url.startsWith("/auth/v1/settings")) return res.end(JSON.stringify({ mailer_autoconfirm: false, external: { anonymous_users: false } }));
  res.end(JSON.stringify({ keys: [{ ...jwk, kid: KID, alg: "ES256", use: "sig" }] }));   // vse ostalo (grant_type=password, rpc/delete_my_account ob DELETE /me) odgovori 200
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
async function cakaj(fn, ms = 8000) { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (await fn()) return true; await pocakaj(50); } return false; }

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
const S = { seje: {}, naboji: {}, spori: {}, stSej: 0, potekle: [], expireNapaka: false };
function telo(req) { return new Promise(r => { let d = ""; req.on("data", x => d += x); req.on("end", () => r(d)); }); }
function obrazec(besedilo) { const o = {}; for (const [k, v] of new URLSearchParams(besedilo)) o[k] = v; return o; }
const stripeServer = http.createServer(async (req, res) => {
  const p = obrazec(await telo(req));
  const odg = (status, o) => { res.writeHead(status, { "content-type": "application/json", "request-id": "req_test" }); res.end(JSON.stringify(o)); };
  const u = req.url.split("?")[0];
  let m;
  if (req.method === "POST" && u === "/v1/checkout/sessions") {
    const kljuc = req.headers["idempotency-key"];
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
    S.potekle.push(m[1]);
    if (S.expireNapaka) return odg(500, { error: { type: "api_error", message: "Stripe je padel" } });
    S.seje[m[1]].status = "expired"; return odg(200, S.seje[m[1]]);
  }
  if (req.method === "GET" && (m = u.match(/^\/v1\/charges\/(ch_\w+)$/))) return S.naboji[m[1]] ? odg(200, S.naboji[m[1]]) : odg(404, { error: { type: "invalid_request_error", message: "No such charge" } });
  if (req.method === "GET" && (m = u.match(/^\/v1\/disputes\/(dp_\w+)$/))) return S.spori[m[1]] ? odg(200, S.spori[m[1]]) : odg(404, { error: { type: "invalid_request_error", message: "No such dispute" } });
  return odg(404, { error: { type: "invalid_request_error", message: "Lazni Stripe: neznana pot " + req.method + " " + u } });
});

let stDogodka = 0;
async function webhook(tip, objekt, { id, created } = {}) {
  const d = { id: id || `evt_test_${++stDogodka}`, object: "event", type: tip, data: { object: objekt }, created: created || Math.floor(Date.now() / 1000) };
  const payload = JSON.stringify(d);
  const glava = stripeLokalno.webhooks.generateTestHeaderString({ payload, secret: WHSEC });
  const r = await fetch(BASE + "/stripe/webhook", { method: "POST", headers: { "content-type": "application/json", "stripe-signature": glava }, body: payload });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, id: d.id };
}
const placi = (sejaId, pi) => Object.assign(S.seje[sejaId], { status: "complete", payment_status: "paid", payment_intent: pi });

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, stripe_events, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  await new Promise(r => stripeServer.listen(STRIPE_PORT, r));
  await new Promise(r => resendServer.listen(RESEND_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "re_test", RESEND_BASE_URL: `http://127.0.0.1:${RESEND_PORT}`, EMAIL_FROM: "Outly <test@outly.test>", GOST_POSTA_PONOVI_MS: "0",
    VRACILA_TICK_MS: "250", VRACILA_RAZMAK_MS: "10", VRACILA_ZAMIK_S: "0", VRACILA_SWEEP_MS: "400", VRACILA_MAIL_RAZMAK_MS: "0", QR_SECRET: "test",
    STRIPE_SECRET_KEY: "sk_test_lokalno", STRIPE_WEBHOOK_SECRET: WHSEC, STRIPE_API_BASE: `http://127.0.0.1:${STRIPE_PORT}`, STRIPE_POSPRAVI_MS: "3600000",
    APP_URL: "https://outly.test", TEST_PLACILA: "" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await pocakaj(100); } }

  try {
    const imena = ["lastnik", "ana", "bor", "cene", "dar", "eva", "fra", "gal", "hana", "ivo", "jan"];
    const T = {}; imena.forEach((n, i) => { T[n] = zeton(`${n}@outly.si`, uuid(i + 1)); });
    for (const k of imena) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    await pool.query(`INSERT INTO clubs (owner_user_id, name, city, stripe_account_id, stripe_charges_enabled, stripe_payouts_enabled, stripe_onboarded_at)
                      VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana', 'acct_t1', TRUE, TRUE, NOW())`);
    const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    let r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Vrstni red", startAt: cezDan, ticketPriceCents: 1500, capacity: 30, minAge: 0 });
    assert(r.status === 201, "dogodek ustvarjen", r.body);
    const ev = r.body.id;
    const sold = async () => (await pool.query("SELECT sold_count FROM events WHERE id=$1", [ev])).rows[0].sold_count;
    const kupi = async (kdo, kol) => {
      const x = await api("POST", `/events/${ev}/orders`, T[kdo], { quantity: kol }, { "idempotency-key": crypto.randomUUID() });
      if (x.status !== 201 || x.body.mode !== "stripe") throw new Error("nakup " + kdo + ": " + JSON.stringify(x));
      return { id: x.body.order.id, seja: (await pool.query("SELECT stripe_checkout_session_id AS s FROM orders WHERE id=$1", [x.body.order.id])).rows[0].s };
    };
    const narocilo = async (id) => (await pool.query("SELECT status, refunded_cents, user_id, stripe_payment_intent_id AS pi FROM orders WHERE id=$1", [id])).rows[0];
    const vstopnice = async (id) => (await pool.query("SELECT status FROM tickets WHERE order_id=$1", [id])).rows.map(x => x.status);
    const dogodekZapisan = async (id) => (await pool.query("SELECT 1 FROM stripe_events WHERE id=$1", [id])).rows.length > 0;

    // ============ S2: vracilo pred placilom ============
    console.log("\n# S2: charge.refunded PRED checkout.session.completed");
    const a = await kupi("ana", 2);
    S.naboji.ch_a = { id: "ch_a", object: "charge", payment_intent: "pi_a", amount: 3000, amount_refunded: 3000, refunded: true, metadata: { order_id: String(a.id), public_ref: "x" } };
    let w = await webhook("charge.refunded", { id: "ch_a", object: "charge" }, { id: "evt_vracilo_a" });
    assert(w.status === 503, "vracilo pred vknjizbo placila: 503 (Stripe ponovi)", w);
    assert(!(await dogodekZapisan("evt_vracilo_a")), "dogodek NI zabelezen kot obdelan");
    assert((await narocilo(a.id)).status === "pending", "narocilo ostane pending");
    assert(!/POZOR: charge\.refunded evt_vracilo_a/.test(log), "sveze zamujeno vracilo: brez alarma (samo dnevnik)");
    w = await webhook("charge.refunded", { id: "ch_a", object: "charge" }, { id: "evt_vracilo_stara", created: Math.floor(Date.now() / 1000) - 2 * 3600 });
    assert(w.status === 503 && /POZOR: charge\.refunded evt_vracilo_stara caka na placilo ze 12\d min/.test(log), "vracilo, ki caka ze > 1 h: 503 + alarm (Sentry)", { w, log: log.slice(-300) });
    placi(a.seja, "pi_a");
    w = await webhook("checkout.session.completed", { id: a.seja, object: "checkout.session" }, { id: "evt_placilo_a" });
    assert(w.status === 200 && (await narocilo(a.id)).status === "paid", "completed (zamujen): narocilo paid", w);
    assert((await vstopnice(a.id)).join() === "valid,valid", "tik pred ponovitvijo vstopnice se veljajo (vmesno stanje)");
    w = await webhook("charge.refunded", { id: "ch_a", object: "charge" }, { id: "evt_vracilo_a" });
    const na = await narocilo(a.id);
    assert(w.status === 200 && !w.body.duplicate, "ponovitev istega dogodka: 200, obdelan (ne duplicate)", w);
    assert(na.status === "refunded" && na.refunded_cents === 3000, "narocilo refunded, 3000 c", na);
    assert((await vstopnice(a.id)).every(s => s === "refunded"), "vstopnice refunded", await vstopnice(a.id));
    w = await webhook("charge.refunded", { id: "ch_a", object: "charge" }, { id: "evt_vracilo_a" });
    assert(w.status === 200 && w.body.duplicate === true, "tretja dostava: duplicate");

    console.log("\n# S2: dogodek, ki se nikoli ne bo ujemal, NE ustvarja neskoncnih ponovitev");
    S.naboji.ch_tuj = { id: "ch_tuj", object: "charge", payment_intent: "pi_tuj", amount: 100, amount_refunded: 100, metadata: {} };
    w = await webhook("charge.refunded", { id: "ch_tuj" }, { id: "evt_tuj_1" });
    assert(w.status === 200 && await dogodekZapisan("evt_tuj_1"), "PI brez metadata.order_id: 200 + zabelezeno", w);
    S.naboji.ch_tuj2 = { id: "ch_tuj2", object: "charge", payment_intent: "pi_tuj2", amount: 100, amount_refunded: 100, metadata: { order_id: "987654" } };
    w = await webhook("charge.refunded", { id: "ch_tuj2" }, { id: "evt_tuj_2" });
    assert(w.status === 200 && await dogodekZapisan("evt_tuj_2"), "metadata.order_id brez narocila v bazi: 200 + zabelezeno", w);
    const preklic = await kupi("bor", 1);
    await pool.query("UPDATE orders SET status = 'cancelled', cancelled_at = NOW() WHERE id = $1", [preklic.id]);
    S.naboji.ch_tuj3 = { id: "ch_tuj3", object: "charge", payment_intent: "pi_tuj3", amount: 1500, amount_refunded: 1500, metadata: { order_id: String(preklic.id) } };
    w = await webhook("charge.refunded", { id: "ch_tuj3" }, { id: "evt_tuj_3" });
    assert(w.status === 200 && await dogodekZapisan("evt_tuj_3"), "narocilo je ze cancelled (ne caka vec na placilo): 200 + zabelezeno", w);

    // ============ S2: spor pred placilom ============
    console.log("\n# S2: charge.dispute.created PRED checkout.session.completed");
    const c = await kupi("cene", 1);
    S.naboji.ch_c = { id: "ch_c", object: "charge", payment_intent: "pi_c", amount: 1500, amount_refunded: 0, metadata: { order_id: String(c.id) } };
    S.spori.dp_c = { id: "dp_c", object: "dispute", charge: "ch_c", payment_intent: "pi_c", amount: 1500, currency: "eur", reason: "fraudulent", status: "needs_response",
      created: Math.floor(Date.now() / 1000), evidence_details: { due_by: Math.floor(Date.now() / 1000) + 7 * 86400 } };
    w = await webhook("charge.dispute.created", { id: "dp_c" }, { id: "evt_spor_c" });
    assert(w.status === 200, "spor pred placilom: 200 (spor se zapise)", w);
    let sp = (await pool.query("SELECT order_id, stanje FROM spori WHERE id='dp_c'")).rows[0];
    assert(sp && sp.order_id === null && sp.stanje === "needs_response", "spor zapisan brez narocila", sp);
    placi(c.seja, "pi_c");
    w = await webhook("checkout.session.completed", { id: c.seja, object: "checkout.session" }, { id: "evt_placilo_c" });
    sp = (await pool.query("SELECT order_id FROM spori WHERE id='dp_c'")).rows[0];
    assert(w.status === 200 && (await narocilo(c.id)).status === "paid", "completed: narocilo paid", w);
    assert(String(sp.order_id) === String(c.id), "spor povezan z narocilom, ko to postane placano", sp);
    r = await api("GET", "/me/orders", T.cene);
    const tk = r.status === 200 && r.body.find(x => x.id === c.id);
    assert(tk && tk.tickets.length === 1 && tk.tickets.every(t => t.payment_disputed === true), "vstopnice na vratih NE veljajo (payment_disputed)", tk && tk.tickets);
    // sprememba stanja spora po povezavi ne izgubi povezave
    S.spori.dp_c.status = "won";
    w = await webhook("charge.dispute.closed", { id: "dp_c" });
    sp = (await pool.query("SELECT order_id, stanje FROM spori WHERE id='dp_c'")).rows[0];
    assert(w.status === 200 && sp.stanje === "won" && String(sp.order_id) === String(c.id), "dispute.closed: won, povezava ostane", sp);

    assert(await cakaj(() => mailiNa("lastnik@outly.si").some(m => /Payment dispute/.test(m.subject))), "S1: mail lastniku kluba o sporu PRIDE tudi, ce je spor prisel pred placilom", R.poslano.map(m => m.subject));
    sp = (await pool.query("SELECT mail_odprt_poslano_at FROM spori WHERE id='dp_c'")).rows[0];
    assert(sp.mail_odprt_poslano_at, "S1: mail_odprt_poslano_at zapisan");

    console.log("\n# S2: izgubljen spor PRED placilom: povrnitev od kluba se po povezavi sprozi");
    const iv = await kupi("ivo", 1);
    S.naboji.ch_iv = { id: "ch_iv", object: "charge", payment_intent: "pi_iv", amount: 1500, amount_refunded: 0, metadata: { order_id: String(iv.id) } };
    S.spori.dp_iv = { id: "dp_iv", object: "dispute", charge: "ch_iv", payment_intent: "pi_iv", amount: 1500, currency: "eur", reason: "fraudulent", status: "lost",
      created: Math.floor(Date.now() / 1000), evidence_details: { due_by: Math.floor(Date.now() / 1000) + 7 * 86400 } };
    w = await webhook("charge.dispute.closed", { id: "dp_iv" });
    sp = (await pool.query("SELECT order_id, povrnitev_stanje, povrnitev_napaka FROM spori WHERE id='dp_iv'")).rows[0];
    assert(w.status === 200 && sp.order_id === null && sp.povrnitev_stanje === "rocno" && /spor brez narocila/.test(sp.povrnitev_napaka), "lost brez narocila: rocno", sp);
    placi(iv.seja, "pi_iv");
    w = await webhook("checkout.session.completed", { id: iv.seja, object: "checkout.session" });
    sp = (await pool.query("SELECT order_id, povrnitev_stanje, COALESCE(povrnitev_napaka, '') AS napaka FROM spori WHERE id='dp_iv'")).rows[0];
    assert(w.status === 200 && String(sp.order_id) === String(iv.id) && !(sp.povrnitev_stanje === "rocno" && /spor brez narocila/.test(sp.napaka)),
      "po povezavi: povrnitev ni vec »rocno: spor brez narocila« (caka / v teku / obdelana)", sp);
    const refIv = (await pool.query("SELECT public_ref FROM orders WHERE id=$1", [iv.id])).rows[0].public_ref;
    assert(await cakaj(() => mailiNa("lastnik@outly.si").some(m => m.subject.includes(refIv))), "mail o sporu lastniku tudi za lost-pred-placilom", R.poslano.map(m => m.subject));

    console.log("\n# N1: vracilo se seka z zakljuci() (zaklep vrstice): ne izgubi se");
    const jn = await kupi("jan", 1);
    S.naboji.ch_jn = { id: "ch_jn", object: "charge", payment_intent: "pi_jn", amount: 1500, amount_refunded: 1500, metadata: { order_id: String(jn.id) } };
    const drzi = await pool.connect();
    await drzi.query("BEGIN");
    await drzi.query("SELECT id FROM orders WHERE id = $1 FOR UPDATE", [jn.id]);
    const vmes = webhook("charge.refunded", { id: "ch_jn" }, { id: "evt_vracilo_jn" });   // obvisi na zaklepu vrstice
    await pocakaj(600);
    await drzi.query("UPDATE orders SET status = 'paid', paid_at = NOW(), stripe_payment_intent_id = 'pi_jn' WHERE id = $1", [jn.id]);   // kot zakljuci(): placilo vknjizeno tik pred nami
    await drzi.query("COMMIT"); drzi.release();
    w = await vmes;
    assert(w.status === 503 && !(await dogodekZapisan("evt_vracilo_jn")), "vracilo, ki je cakalo na zakljuci(): 503 (ne tiho 200), dogodek ni zabelezen", w);
    w = await webhook("charge.refunded", { id: "ch_jn" }, { id: "evt_vracilo_jn" });
    assert(w.status === 200 && (await narocilo(jn.id)).status === "refunded", "ponovitev: naroceno refunded", w);

    // ============ S4: DELETE /me med odprtim Checkoutom ============
    console.log("\n# S4: DELETE /me prekliče cakajoce narocilo");
    const soldPrej = await sold();
    const d = await kupi("dar", 2);
    assert(await sold() === soldPrej + 2, "zaloga rezervirana (+2)");
    r = await api("DELETE", "/me", T.dar, { password: "x" });
    assert(r.status === 200, "DELETE /me -> 200", r);
    let nd = await narocilo(d.id);
    assert(nd.status === "cancelled" && nd.user_id === null, "cakajoce narocilo cancelled (in anonimizirano)", nd);
    assert(await sold() === soldPrej, "zaloga sproscena");
    assert(await cakaj(() => S.potekle.includes(d.seja)), "Checkout seja zaprta pri Stripu (expire po COMMIT-u)", S.potekle);
    // placilo kljub temu prispe (seja je bila ze placana / tekma): kupec dobi vse nazaj, vstopnic ni
    placi(d.seja, "pi_d");
    w = await webhook("checkout.session.completed", { id: d.seja, object: "checkout.session" });
    nd = await narocilo(d.id);
    const vr = (await pool.query("SELECT razlog, znesek_cents, payment_intent_id FROM vracila WHERE order_id=$1", [d.id])).rows;
    assert(w.status === 200 && nd.status === "cancelled" && (await vstopnice(d.id)).length === 0, "pozno placilo: narocilo ostane cancelled, vstopnic ni", { w: w.status, nd });
    assert(vr.length === 1 && vr[0].razlog === "inactive_order" && vr[0].znesek_cents === 3000 && vr[0].payment_intent_id === "pi_d", "vracilo v vrsti (inactive_order, 3000 c)", vr);

    console.log("\n# S4: napaka pri expire ni usodna");
    S.expireNapaka = true;
    const e = await kupi("eva", 1);
    r = await api("DELETE", "/me", T.eva, { password: "x" });
    assert(r.status === 200, "Stripe expire pade: DELETE /me vseeno 200", r);
    assert(await cakaj(() => S.potekle.filter(x => x === e.seja).length === 1), "expire je bil poskusen");
    assert((await narocilo(e.id)).status === "cancelled", "narocilo cancelled kljub napaki Stripa");
    S.expireNapaka = false;

    console.log("\n# S4: placano narocilo izbrisanega racuna ostane placano");
    const f = await kupi("fra", 1);
    placi(f.seja, "pi_f");
    w = await webhook("checkout.session.completed", { id: f.seja, object: "checkout.session" });
    assert((await narocilo(f.id)).status === "paid", "narocilo paid");
    r = await api("DELETE", "/me", T.fra, { password: "x" });
    assert(r.status === 200, "DELETE /me -> 200", r);
    assert((await narocilo(f.id)).status === "paid" && (await vstopnice(f.id)).join() === "valid", "paid ostane paid, vstopnica ostane");

    console.log("\n# S4: zakljuci() brez imetnika (user_id in guest_email NULL) -> vracilo");
    const g = await kupi("gal", 2);
    await pool.query("UPDATE orders SET user_id = NULL WHERE id = $1", [g.id]);   // stanje, kakrsno je pustil stari DELETE /me
    const soldG = await sold();
    placi(g.seja, "pi_g");
    w = await webhook("checkout.session.completed", { id: g.seja, object: "checkout.session" });
    const ng = await narocilo(g.id);
    const vg = (await pool.query("SELECT razlog, znesek_cents, payment_intent_id FROM vracila WHERE order_id=$1", [g.id])).rows;
    assert(w.status === 200 && ng.status === "cancelled" && ng.pi === "pi_g", "narocilo brez imetnika: cancelled (ne paid), PI zapisan", ng);
    assert((await vstopnice(g.id)).length === 0, "vstopnic ni");
    assert(vg.length === 1 && vg[0].razlog === "inactive_order" && vg[0].znesek_cents === 3000, "vracilo v vrsti (inactive_order)", vg);
    assert(await sold() === soldG - 2, "zaloga sproscena");
    assert(/placilo za neaktivno narocilo/.test(log), "alarm v dnevniku");
    w = await webhook("checkout.session.completed", { id: g.seja, object: "checkout.session" });
    assert(w.status === 200 && (await pool.query("SELECT 1 FROM vracila WHERE order_id=$1", [g.id])).rows.length === 1, "ponovna dostava: se vedno ena vrstica vracila");

    console.log("\n# Gostujoce narocilo (guest_email) ostane normalno");
    const h = await kupi("hana", 1);
    await pool.query(`UPDATE orders SET user_id = NULL, guest_email = 'gost@example.com', guest_terms_version = 'v1', guest_terms_accepted_at = NOW() WHERE id = $1`, [h.id]);
    placi(h.seja, "pi_h");
    w = await webhook("checkout.session.completed", { id: h.seja, object: "checkout.session" });
    assert(w.status === 200 && (await narocilo(h.id)).status === "paid" && (await vstopnice(h.id)).length === 1, "gost z e-naslovom: paid + vstopnica", await narocilo(h.id));
  } catch (e) { fail++; console.error("NAPAKA TESTA:", e); }
  finally {
    console.log(`\n${ok} OK, ${fail} NAPAK`);
    srv.kill(); jwksServer.close(); stripeServer.close(); resendServer.close();
    await pool.end().catch(() => {});
    process.exit(fail ? 1 : 0);
  }
})();
