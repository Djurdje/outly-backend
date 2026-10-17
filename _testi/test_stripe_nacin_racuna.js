#!/usr/bin/env node
/**
 * Nacin Stripe racuna kluba: sandbox ali ziv (issue #227, I36, migracija 046). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_stripe_nacin_racuna.js
 * Brez pravega Stripa: lazni Stripe (STRIPE_API_BASE), ki POSNEMA lastnost, zaradi katere je nastal #227: sandbox objekti (acct_sbx_*, cs_test_*)
 * v zivem nacinu ne obstajajo (404 / 400) in obratno; nacin doloci kljuc v glavi Authorization (sk_live_ / sk_test_). NI preverjeno proti pravemu Stripu.
 * Dva backenda nad isto bazo: LIVE (sk_live_) in SAND (sk_test_). Klub 1 ima ob zacetku SANDBOX racun (stripe_account_livemode NULL = stanje produkcije).
 *
 *   1  SAND (današnja produkcija): livemode NULL in FALSE -> nic se ne spremeni (stripe, nakup 201, status povezan), nastane sandbox cakajoce narocilo
 *   2  LIVE + sandbox racun: payment_mode unavailable (vsi javni odgovori), /business/sales stripe_not_ready, nakup 409 (vstopnica, gost), brez klica Stripa, status nepovezan
 *   3  LIVE: »Connect Stripe« ustvari NOV racun (accounts.create), zapise livemode TRUE, charges/payouts false, onboarded_at NULL; dva hkratna klika = en racun
 *   4  LIVE: account.updated (charges_enabled) -> klub prodaja normalno; Checkout gre na ZIVI racun
 *   5  LIVE: dogodek iz sandboxa ne prepise ziveg stanja (livemode false -> 200 zanemarjen; brez livemode: SQL varovalo po nacinu racuna)
 *   6  LIVE: pending sandbox narocilo (cs_test_) pospravljalec zapre (cancelled, zaloga prosta), brez klica Stripa in brez ponovitev; zivo narocilo gre po obicajni poti
 *   7  SAND po preklopu nazaj: ziv racun se NE prepise (409), klub ni pripravljen (test), ziv racun v bazi nespremenjen
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");
const Stripe = require("stripe");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT_L = 3351, PORT_S = 3352, JWKS_PORT = 3353, STRIPE_PORT = 3354;
const BL = `http://127.0.0.1:${PORT_L}`, BS = `http://127.0.0.1:${PORT_S}`;
const WHSEC = "whsec_test_nacin";
const stripeLokalno = new Stripe("sk_test_lokalno");

// ---------- JWKS + zetoni (kot test_stripe.js) ----------
const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-nacin";
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
async function zahtevek(baza, method, path, token, body, glave = {}) {
  const r = await fetch(baza + path, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}), ...glave }, body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, text: t };
}
const pocakaj = (ms) => new Promise(r => setTimeout(r, ms));
async function cakajDo(pogoj, ms = 8000) { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (await pogoj()) return true; await pocakaj(100); } return false; }

// ---------- lazni Stripe, ki loci sandbox in ziv nacin ----------
const S = { racuni: {}, seje: {}, stRacunov: 0, stSej: 0, dnevnik: [] };   // dnevnik: { m, u, ziv }
const nobenih = () => S.dnevnik.length;
const stripeServer = http.createServer((req, res) => {
  let d = ""; req.on("data", x => d += x);
  req.on("end", () => {
    const p = Object.fromEntries(new URLSearchParams(d));
    const ziv = /Bearer sk_live_/.test(String(req.headers.authorization || ""));
    const u = req.url.split("?")[0];
    S.dnevnik.push({ m: req.method, u, ziv, p });
    const odg = (st, o) => { res.writeHead(st, { "content-type": "application/json", "request-id": "req_test" }); res.end(JSON.stringify(o)); };
    const napaka = (st, msg, code) => odg(st, { error: { type: "invalid_request_error", message: msg, ...(code ? { code } : {}) } });
    // objekt iz drugega nacina »ne obstaja« (kot pri pravem Stripu: sandbox objekt z zivim kljucem in obratno)
    const nacinObjekta = (id) => (/^(acct_live|cs_live)/.test(id) ? true : false);
    const tuj = (id) => nacinObjekta(id) !== ziv;
    let m;
    if (req.method === "POST" && u === "/v1/accounts") {
      const id = (ziv ? "acct_live_" : "acct_sbx_") + (++S.stRacunov);
      S.racuni[id] = { id, object: "account", charges_enabled: false, payouts_enabled: false, details_submitted: false, requirements: { currently_due: ["external_account"], disabled_reason: "requirements.past_due" }, _params: p };
      return odg(200, S.racuni[id]);
    }
    if (req.method === "POST" && u === "/v1/account_links") return tuj(p.account) || !S.racuni[p.account] ? napaka(400, "No such account: " + p.account, "resource_missing") : odg(200, { object: "account_link", url: `https://connect.stripe.test/setup/${p.account}` });
    if (req.method === "GET" && (m = u.match(/^\/v1\/accounts\/(acct_\w+)$/))) return !tuj(m[1]) && S.racuni[m[1]] ? odg(200, S.racuni[m[1]]) : napaka(404, "No such account: " + m[1], "resource_missing");
    if (req.method === "POST" && (m = u.match(/^\/v1\/accounts\/(acct_\w+)\/login_links$/))) return tuj(m[1]) ? napaka(404, "No such account", "resource_missing") : odg(200, { object: "login_link", url: "https://connect.stripe.test/express/" + m[1] });
    if (req.method === "POST" && u === "/v1/checkout/sessions") {
      const dest = p["payment_intent_data[transfer_data][destination]"];
      if (tuj(dest) || !S.racuni[dest]) return napaka(400, "No such destination: '" + dest + "'", "resource_missing");
      const id = (ziv ? "cs_live_" : "cs_test_") + (++S.stSej);
      const kol = Number(p["line_items[0][quantity]"]), cena = Number(p["line_items[0][price_data][unit_amount]"]);
      S.seje[id] = { id, object: "checkout.session", url: `https://checkout.stripe.test/c/pay/${id}`, status: "open", payment_status: "unpaid", amount_total: kol * cena,
        currency: p["line_items[0][price_data][currency]"], client_reference_id: p.client_reference_id, metadata: { order_id: p["metadata[order_id]"], public_ref: p["metadata[public_ref]"] },
        expires_at: Number(p.expires_at), payment_intent: null, _destination: dest };
      return odg(200, S.seje[id]);
    }
    if (req.method === "GET" && (m = u.match(/^\/v1\/checkout\/sessions\/(cs_\w+)$/))) return !tuj(m[1]) && S.seje[m[1]] ? odg(200, S.seje[m[1]]) : napaka(404, "No such checkout.session: '" + m[1] + "'", "resource_missing");
    if (req.method === "POST" && (m = u.match(/^\/v1\/checkout\/sessions\/(cs_\w+)\/expire$/))) {
      if (tuj(m[1]) || !S.seje[m[1]]) return napaka(404, "No such checkout.session", "resource_missing");
      S.seje[m[1]].status = "expired"; return odg(200, S.seje[m[1]]);
    }
    return napaka(404, "Lazni Stripe: neznana pot " + req.method + " " + u);
  });
});
const klici = (re, ziv) => S.dnevnik.filter(x => re.test(x.m + " " + x.u) && (ziv === undefined || x.ziv === ziv));

let stDogodka = 0;
async function webhook(baza, tip, objekt, livemode) {
  const dogodek = { id: `evt_nacin_${++stDogodka}`, object: "event", type: tip, data: { object: objekt }, created: Math.floor(Date.now() / 1000), ...(livemode === undefined ? {} : { livemode }) };
  const payload = JSON.stringify(dogodek);
  const glava = stripeLokalno.webhooks.generateTestHeaderString({ payload, secret: WHSEC });
  const r = await fetch(baza + "/stripe/webhook", { method: "POST", headers: { "content-type": "application/json", "stripe-signature": glava }, body: payload });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, id: dogodek.id };
}

function zagon(port, okolje) {
  const srv = spawn("node", ["index.js"], { env: { ...process.env, GOST_NAKUP_TEST: "1", PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test",
    APP_URL: "https://outly.test", STRIPE_API_BASE: `http://127.0.0.1:${STRIPE_PORT}`, STRIPE_WEBHOOK_SECRET: WHSEC, TEST_PLACILA: "", JAVNI_PREDPOMNILNIK_MS: "0", PREVERI_OKNO_MS: "0", ...okolje }, stdio: ["ignore", "pipe", "pipe"] });
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
  // LIVE: pospravljalec na 600 ms (sklop 6); SAND: pospravljalec izklopljen (da sandbox narocilo zapre LIVE)
  const L = zagon(PORT_L, { STRIPE_SECRET_KEY: "sk_live_lokalno", GOST_NAKUP_LIVE: "1", STRIPE_POSPRAVI_MS: "600" });
  const Sz = zagon(PORT_S, { STRIPE_SECRET_KEY: "sk_test_lokalno", STRIPE_POSPRAVI_MS: "3600000" });
  const api = (b, m, p, t, body, g) => zahtevek(b, m, p, t, body, g);
  await Promise.all([BL, BS].map(cakajStreznik));

  try {
    const T = {};
    const imena = ["lastnik", "ana", "bor"];
    imena.forEach((k, i) => { T[k] = zeton(`${k}@outly.si`, uuid(i + 1)); });
    for (const k of imena) { const r = await api(BS, "GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    // Klub 1: SANDBOX racun, dokoncan onboarding, livemode NULL (= stanje produkcije pred preklopom). Podatki prodajalca popolni (I34 ne sme motiti).
    S.racuni.acct_sbx_old = { id: "acct_sbx_old", object: "account", charges_enabled: true, payouts_enabled: true, details_submitted: true, requirements: { currently_due: [], disabled_reason: null } };
    await pool.query(`INSERT INTO clubs (owner_user_id, name, city, address, stripe_account_id, stripe_charges_enabled, stripe_payouts_enabled, stripe_onboarded_at,
                        legal_name, legal_address, registration_number, tax_number, vat_payer, contact_email)
                      VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Prehod Club', 'Ljubljana', 'Slovenska 1', 'acct_sbx_old', TRUE, TRUE, NOW(),
                        'Prehod d.o.o.', 'Slovenska 1, 1000 Ljubljana', '1234567000', 'SI12345678', TRUE, 'info@prehod.si')`);
    const livemodeKluba = async () => (await pool.query("SELECT stripe_account_id, stripe_account_livemode, stripe_charges_enabled, stripe_payouts_enabled, stripe_onboarded_at FROM clubs WHERE id=1")).rows[0];
    let kb = await livemodeKluba();
    assert(kb.stripe_account_livemode === null, "migracija 046: obstojec klub ima stripe_account_livemode NULL (brez UPDATE)", kb);
    const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    const dogodek = async (title, cena, kapaciteta = 50) => {
      const r = await api(BS, "POST", "/events", T.lastnik, { clubId: 1, title, startAt: cezDan, ticketPriceCents: cena, capacity: kapaciteta, minAge: 0 });
      assert(r.status === 201, `dogodek ${title}`, r.body); return r.body.id;
    };
    const evPlac = await dogodek("Placan", 1500), evPlac2 = await dogodek("Placan 2", 1500, 20), evGost = await dogodek("Placan gost", 1500, 10);
    const sold = async (id) => (await pool.query("SELECT sold_count FROM events WHERE id=$1", [id])).rows[0].sold_count;
    const glavaKlub = { "x-outly-club": "1" };
    const kupi = (b, tok, ev) => api(b, "POST", `/events/${ev}/orders`, tok, { quantity: 1 });
    const gost = (b, ev) => api(b, "POST", `/guest/events/${ev}/orders`, null, { email: "gost@example.com", quantity: 1, accept_terms: true, terms_version: "2026-10-01" });
    const nacini = async (b) => {
      const o = {};
      let r = await api(b, "GET", `/events/${evPlac}`); o.dogodek = r.body && r.body.payment_mode;
      r = await api(b, "GET", "/events"); o.seznam = Array.isArray(r.body) ? (r.body.find(x => x.id === evPlac) || {}).payment_mode : undefined;
      r = await api(b, "GET", "/events?lite=true"); o.lite = Array.isArray(r.body) ? (r.body.find(x => x.id === evPlac) || {}).payment_mode : undefined;
      r = await api(b, "GET", "/events?clubId=1"); o.klub = Array.isArray(r.body) ? (r.body.find(x => x.id === evPlac) || {}).payment_mode : undefined;
      r = await api(b, "GET", "/business/events", T.lastnik, undefined, glavaKlub); o.poslovni = Array.isArray(r.body) ? (r.body.find(x => x.id === evPlac) || {}).payment_mode : undefined;
      return o;
    };
    const vsi = (o, v) => Object.values(o).every(x => x === v) && Object.keys(o).length === 5;

    // ================================================================
    console.log("\n# 1. SAND (danasnja produkcija): livemode NULL in FALSE = nic se ne spremeni");
    for (const v of [null, false]) {
      await pool.query("UPDATE clubs SET stripe_account_livemode=$1 WHERE id=1", [v]);
      const o = await nacini(BS);
      assert(vsi(o, "stripe"), `sandbox + sandbox racun (livemode ${v}): payment_mode stripe povsod`, o);
      let r = await api(BS, "GET", "/business/sales", T.lastnik, undefined, glavaKlub);
      assert(r.status === 200 && r.body.payment_mode === "stripe" && r.body.payment_unavailable_reason === null, `livemode ${v}: /business/sales stripe, razlog null`, [r.body.payment_mode, r.body.payment_unavailable_reason]);
      r = await api(BS, "GET", "/business/stripe/status", T.lastnik, undefined, glavaKlub);
      assert(r.status === 200 && r.body.connected === true && r.body.charges_enabled === true && r.body.payouts_enabled === true && r.body.sandbox === true, `livemode ${v}: status povezan, charges true`, r.body);
      r = await api(BS, "GET", "/business/clubs/me", T.lastnik, undefined, glavaKlub);
      assert(r.status === 200 && r.body.stripe_charges_enabled === true && r.body.stripe_payouts_enabled === true, `livemode ${v}: /business/clubs/me stripe_charges_enabled true`, r.body);
      assert(!JSON.stringify(r.body).includes("acct_") && !("stripe_account_livemode" in r.body), "odgovor brez racuna in brez surovega stolpca (I4)");
    }
    await pool.query("UPDATE clubs SET stripe_account_livemode=NULL WHERE id=1");
    // Za sklop 6 ostane en CAKAJOCE sandbox narocilo (cs_test_), ustvarjeno z veljavnim sandbox racunom
    let r = await kupi(BS, T.ana, evPlac);
    assert(r.status === 201 && r.body.mode === "stripe" && r.body.order.status === "pending", "sandbox nakup: 201 stripe, cakajoce narocilo", [r.status, r.body.mode]);
    const oSand = r.body.order.id;
    const sejaSand = (await pool.query("SELECT stripe_checkout_session_id FROM orders WHERE id=$1", [oSand])).rows[0].stripe_checkout_session_id;
    assert(/^cs_test_/.test(sejaSand) && S.seje[sejaSand]._destination === "acct_sbx_old", "seja je sandbox (cs_test_) in gre na sandbox racun", sejaSand);
    assert(await sold(evPlac) === 1, "zaloga zasedena (1)");
    // gostujoce sandbox narocilo (za sklop 6: preklic gosta ob zivem kljucu)
    r = await gost(BS, evGost);
    assert(r.status === 201 && r.body.mode === "stripe" && r.body.guest_token, "sandbox gost: 201 stripe, cakajoce narocilo", [r.status, r.body && r.body.mode]);
    const zetonGost = r.body.guest_token, oGost = r.body.order.id;
    assert(await sold(evGost) === 1, "zaloga gosta zasedena (1)");

    // ================================================================
    console.log("\n# 2. LIVE + sandbox racun: klub NI pripravljen (stripe_not_ready), nakup 409, brez klica Stripa");
    S.dnevnik.length = 0;
    const o2 = await nacini(BL);
    assert(vsi(o2, "unavailable"), "payment_mode unavailable povsod (/events/:id, /events, ?lite, ?clubId, /business/events)", o2);
    r = await api(BL, "GET", "/business/sales", T.lastnik, undefined, glavaKlub);
    assert(r.status === 200 && r.body.mode === "live" && r.body.payment_mode === "unavailable" && r.body.payment_unavailable_reason === "stripe_not_ready", "/business/sales: unavailable + stripe_not_ready", [r.body.mode, r.body.payment_mode, r.body.payment_unavailable_reason]);
    r = await kupi(BL, T.bor, evPlac2);
    assert(r.status === 409 && r.body === "This club does not accept online payments yet.", "nakup placljive vstopnice: 409 (ne 502)", r);
    r = await gost(BL, evPlac2);
    assert(r.status === 409 && r.body === "This club does not accept online payments yet.", "gost: 409 (ne 502)", r);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1", [evPlac2])).rows[0].n === 0 && await sold(evPlac2) === 0, "brez narocila, zaloga nedotaknjena");
    assert(klici(/checkout\/sessions/).length === 0, "nobenega klica na Stripe Checkout", S.dnevnik);
    r = await api(BL, "GET", "/business/stripe/status", T.lastnik, undefined, glavaKlub);
    assert(r.status === 200 && r.body.connected === false && r.body.charges_enabled === false && r.body.payouts_enabled === false && r.body.sandbox === false, "status: nepovezan, charges false (live)", r.body);
    assert(klici(/accounts/).length === 0, "status: accounts.retrieve se NI klical (sandbox racun v zivem)", S.dnevnik);
    r = await api(BL, "GET", "/business/clubs/me", T.lastnik, undefined, glavaKlub);
    assert(r.status === 200 && r.body.stripe_charges_enabled === false && r.body.stripe_payouts_enabled === false, "/business/clubs/me: stripe_charges_enabled false", r.body);
    r = await api(BL, "POST", "/business/stripe/dashboard", T.lastnik, {}, glavaKlub);
    assert(r.status === 409 && klici(/login_links/).length === 0, "Express pregled: 409 brez klica Stripa", r);
    kb = await livemodeKluba();
    assert(kb.stripe_account_id === "acct_sbx_old" && kb.stripe_account_livemode === null && kb.stripe_charges_enabled === true, "baza se pri branju NI spremenila (stari racun, NULL, charges true)", kb);

    // ================================================================
    console.log("\n# 3. LIVE: »Connect Stripe« ustvari NOV racun in zapise livemode");
    S.dnevnik.length = 0; const racunovPred = S.stRacunov;
    const dvaKlika = await Promise.all([1, 2].map(() => api(BL, "POST", "/business/stripe/onboard", T.lastnik, {}, glavaKlub)));
    assert(dvaKlika.every(x => x.status === 200), "onboard: 200 (dva hkratna klika)", dvaKlika.map(x => [x.status, x.body]));
    assert(S.stRacunov === racunovPred + 1 && klici(/POST \/v1\/accounts$/, true).length === 1, "natanko en accounts.create z zivim kljucem", S.stRacunov - racunovPred);
    const novId = "acct_live_" + S.stRacunov;
    assert(dvaKlika.every(x => x.body && x.body.url === `https://connect.stripe.test/setup/${novId}`), "povezava onboardinga je za NOV zivi racun", dvaKlika.map(x => x.body));
    kb = await livemodeKluba();
    assert(kb.stripe_account_id === novId && kb.stripe_account_livemode === true && kb.stripe_charges_enabled === false && kb.stripe_payouts_enabled === false && kb.stripe_onboarded_at === null, "baza: nov racun, livemode TRUE, charges/payouts false, onboarded_at NULL", kb);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM clubs WHERE stripe_account_id='acct_sbx_old'")).rows[0].n === 0, "stari sandbox racun ni vec zapisan");
    r = await api(BL, "POST", "/business/stripe/onboard", T.lastnik, {}, glavaKlub);
    assert(r.status === 200 && S.stRacunov === racunovPred + 1, "tretji klik: isti racun (nov ni ustvarjen)", S.stRacunov - racunovPred);
    const o3 = await nacini(BL);
    assert(vsi(o3, "unavailable"), "do konca onboardinga ostane unavailable", o3);
    r = await api(BL, "GET", "/business/stripe/status", T.lastnik, undefined, glavaKlub);
    assert(r.status === 200 && r.body.connected === true && r.body.charges_enabled === false && !JSON.stringify(r.body).includes("acct_"), "status: povezan (nov racun), charges false, brez racuna v odgovoru", r.body);

    // ================================================================
    console.log("\n# 4. LIVE: account.updated (charges_enabled) -> klub prodaja normalno");
    S.racuni[novId].charges_enabled = true; S.racuni[novId].payouts_enabled = true; S.racuni[novId].details_submitted = true;
    r = await webhook(BL, "account.updated", { id: novId, object: "account" }, true);
    assert(r.status === 200 && r.body.ignored === undefined, "webhook account.updated (livemode true): 200, obdelan", r);
    kb = await livemodeKluba();
    assert(kb.stripe_charges_enabled === true && kb.stripe_payouts_enabled === true && kb.stripe_onboarded_at !== null && kb.stripe_account_livemode === true, "klub: charges + payouts true, livemode TRUE", kb);
    const o4 = await nacini(BL);
    assert(vsi(o4, "stripe"), "payment_mode stripe povsod", o4);
    r = await api(BL, "GET", "/business/sales", T.lastnik, undefined, glavaKlub);
    assert(r.status === 200 && r.body.payment_mode === "stripe" && r.body.payment_unavailable_reason === null, "/business/sales: stripe, razlog null", [r.body.payment_mode, r.body.payment_unavailable_reason]);
    r = await kupi(BL, T.bor, evPlac2);
    assert(r.status === 201 && r.body.mode === "stripe" && r.body.checkout_url, "nakup: 201 stripe + checkout_url", r);
    const oZiv = r.body.order.id;
    const sejaZiv = (await pool.query("SELECT stripe_checkout_session_id, stripe_account_id FROM orders WHERE id=$1", [oZiv])).rows[0];
    assert(/^cs_live_/.test(sejaZiv.stripe_checkout_session_id) && S.seje[sejaZiv.stripe_checkout_session_id]._destination === novId && sejaZiv.stripe_account_id === novId, "Checkout gre na ZIVI racun (transfer_data.destination), narocilo ima zivi racun", sejaZiv);
    r = await api(BL, "GET", "/business/stripe/status", T.lastnik, undefined, glavaKlub);
    assert(r.status === 200 && r.body.connected && r.body.charges_enabled && r.body.payouts_enabled && r.body.details_submitted, "status: povezan, charges, payouts, details_submitted", r.body);
    r = await api(BL, "POST", "/business/stripe/dashboard", T.lastnik, {}, glavaKlub);
    assert(r.status === 200 && /express/.test(r.body.url || ""), "Express pregled: 200 za zivi racun", r);

    // ================================================================
    console.log("\n# 5. LIVE: dogodek iz sandboxa ne prepise ziveg stanja");
    S.racuni[novId].charges_enabled = false;   // ce bi dogodek bil obdelan, bi stanje padlo na false
    r = await webhook(BL, "account.updated", { id: novId, object: "account" }, false);
    assert(r.status === 200 && r.body.ignored === "livemode", "account.updated z livemode false ob sk_live_: 200, zanemarjen", r);
    assert((await livemodeKluba()).stripe_charges_enabled === true, "zivo stanje (charges true) ni prepisano");
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM stripe_events WHERE id=$1", [r.id])).rows[0].n === 0, "zanemarjen dogodek ni vpisan med obdelane");
    r = await webhook(BL, "checkout.session.expired", { id: sejaSand, object: "checkout.session", client_reference_id: String(oSand) }, false);
    assert(r.status === 200 && r.body.ignored === "livemode", "sandbox checkout.session.expired ob sk_live_: 200 zanemarjen (brez 502 in ponavljanja)", r);
    // SQL varovalo: dogodek brez polja livemode za racun, ki ga baza steje za racun drugega nacina (livemode FALSE), ne spremeni nic
    await pool.query("UPDATE clubs SET stripe_account_livemode=FALSE WHERE id=1");
    r = await webhook(BL, "account.updated", { id: novId, object: "account" });
    assert(r.status === 200, "account.updated brez livemode: 200", r);
    kb = await livemodeKluba();
    assert(kb.stripe_charges_enabled === true, "racun, ki ni iz tekocega nacina, se ne posodobi (varovalo v posodobiKlub)", kb);
    await pool.query("UPDATE clubs SET stripe_account_livemode=TRUE WHERE id=1");
    S.racuni[novId].charges_enabled = true;
    r = await webhook(BL, "account.updated", { id: novId, object: "account" }, true);
    assert(r.status === 200 && (await livemodeKluba()).stripe_charges_enabled === true, "zivi dogodek za zivi racun deluje naprej");

    // ================================================================
    console.log("\n# 6. LIVE: pending sandbox narocilo pospravljalec zapre (brez klica Stripa), zivo gre po obicajni poti");
    const vrstica = async (id) => (await pool.query("SELECT status, cancelled_at FROM orders WHERE id=$1", [id])).rows[0];
    assert((await vrstica(oSand)).status === "pending" && await sold(evPlac) === 1, "pred: sandbox narocilo pending, zaloga 1");
    S.dnevnik.length = 0;
    await pool.query("UPDATE orders SET checkout_expires_at = NOW() - INTERVAL '10 minutes' WHERE id=$1", [oSand]);
    await pool.query("UPDATE orders SET checkout_expires_at = NOW() - INTERVAL '10 minutes' WHERE id=$1", [oZiv]);
    S.seje[sejaZiv.stripe_checkout_session_id].status = "expired";   // Stripe zivo sejo po roku sam zapre
    assert(await cakajDo(async () => (await vrstica(oSand)).status !== "pending"), "sandbox narocilo je zaprto");
    assert((await vrstica(oSand)).status === "cancelled" && (await vrstica(oSand)).cancelled_at !== null, "status cancelled (ne failed), cancelled_at zapisan", await vrstica(oSand));
    assert(await sold(evPlac) === 0, "zaloga sproscena (sold_count 0)");
    assert(await cakajDo(async () => (await vrstica(oZiv)).status === "cancelled"), "zivo narocilo (cs_live_) gre po obicajni poti: potekla seja -> cancelled");
    assert(await sold(evPlac2) === 0, "zaloga zivega narocila sproscena");
    // preklic gosta (POST /guest/order/cancel) za sandbox sejo ob zivem kljucu: brez klica Stripa, cancelled, zaloga prosta (prej 502)
    S.dnevnik.length = 0;
    r = await api(BL, "POST", "/guest/order/cancel", null, undefined, { "x-guest-token": zetonGost });
    assert(r.status === 200 && r.body.order && r.body.order.status === "cancelled", "gost preklice sandbox narocilo ob sk_live_: 200 cancelled (ne 502)", [r.status, r.text.slice(0, 120)]);
    assert((await vrstica(oGost)).status === "cancelled" && await sold(evGost) === 0, "baza: cancelled, zaloga sproscena");
    assert(S.dnevnik.length === 0, "preklic gosta: brez klica Stripa", S.dnevnik.map(x => x.m + " " + x.u));
    await pocakaj(2000);   // vsaj 3 kroge pospravljalca
    assert(!S.dnevnik.some(x => x.u.includes(sejaSand)), "Stripe NIKOLI ni dobil sandbox seje z zivim kljucem (ni ponovitev)", S.dnevnik.filter(x => x.u.includes(sejaSand)).length);
    assert(!/pospravljanje narocila[^\n]*No such/.test(L.log), "dnevnik zivega backenda brez napak pospravljanja", L.log.split("\n").filter(l => /pospravljanje/.test(l)).slice(0, 2));
    assert(/ima sandbox sejo/.test(L.log), "dnevnik: sandbox narocilo omenjeno ob zapiranju");

    // ================================================================
    console.log("\n# 7. SAND po preklopu nazaj: ziv racun se NE prepise");
    S.dnevnik.length = 0; const racunovPred7 = S.stRacunov;
    const o7 = await nacini(BS);
    assert(vsi(o7, "test"), "sandbox + ziv racun: klub ni pripravljen -> payment_mode test (nic se ne zaracuna)", o7);
    r = await api(BS, "POST", "/business/stripe/onboard", T.lastnik, {}, glavaKlub);
    assert(r.status === 409 && S.stRacunov === racunovPred7 && klici(/POST \/v1\/accounts$/).length === 0, "onboard ob sk_test_: 409, accounts.create se NI klical", [r.status, r.body]);
    kb = await livemodeKluba();
    assert(kb.stripe_account_id === novId && kb.stripe_account_livemode === true && kb.stripe_charges_enabled === true, "ziv racun v bazi nespremenjen", kb);
    r = await api(BS, "GET", "/business/stripe/status", T.lastnik, undefined, glavaKlub);
    assert(r.status === 200 && r.body.connected === false && r.body.charges_enabled === false, "status ob sandbox kljucu: nepovezan (brez klica Stripa)", r.body);
    assert(klici(/accounts/).length === 0, "brez klica accounts.* ob sk_test_");
    r = await api(BS, "GET", "/business/clubs/me", T.lastnik, undefined, glavaKlub);
    assert(r.status === 200 && r.body.stripe_charges_enabled === false, "/business/clubs/me ob sandbox kljucu: false", r.body);

    assert(!/Unhandled|TypeError|ReferenceError/.test(L.log + Sz.log), "brez nepricakovanih napak v dnevnikih backendov", (L.log + Sz.log).split("\n").filter(l => /Unhandled|TypeError|ReferenceError/.test(l)).slice(0, 3));
  } catch (e) {
    fail++; console.log("  ✗ izjema:", e && e.stack || e);
  } finally {
    for (const s of [L, Sz]) s.srv.kill();
    jwksServer.close(); stripeServer.close(); await pool.end();
  }
  console.log(`\n${ok} OK, ${fail} NAPAK`);
  process.exit(fail ? 1 : 0);
})();
