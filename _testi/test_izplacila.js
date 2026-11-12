#!/usr/bin/env node
/**
 * Izplacila klubom sele po dogodku (#424 A; Martin 8. 11. 2026; migracija 077, izplacila_stripe.js, invarianta I72). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_izplacila.js
 * Pravi Stripe SDK proti laznemu Stripe strezniku (accounts update, balance, payouts s Stripe-Account); nikoli pravi Stripe. NI preverjeno v Stripovem sandboxu.
 *
 *   1  delovni dnevi: konec v soboto -> sprosceno v torek (N=2), sreda -> petek, N=0 takoj po koncu, odpovedan nikoli, odobren prej vedno
 *   2  izklopljeno (IZPLACILA_PO_DOGODKU ni 1): noben klic Stripa
 *   3  urnik: obstojec racun dobi interval=manual (enkrat), napaka -> POZOR, ponovitev pozneje, brez izplacila za ta racun
 *   4  samo prihodnji dogodek -> ni izplacila; koncan + 2 delovna dneva -> izplacilo TOCNO neto tega dogodka (Stripe-Account, idempotentni kljuc); naslednji krog nic
 *   5  zadrzanje: odprt spor (znesek + pristojbine; na nesproscenem dogodku samo pristojbine), izgubljen spor s cakajoco povrnitvijo, vracilo inactive_order, odpovedan dogodek,
 *      dogodek 1 delovni dan po koncu; v_cakanju (pending) pokrije zadrzano; testno/tuje/platformno narocilo ne steje; narocilo starejse od 85 dni se ne zadrzi
 *   5b rok hrambe (pogodba 7. clen): denar prihodnjega dogodka, starejsi od 85 dni, gre ven, zapis rok_hrambe, POZOR enkrat
 *   6  admin odobri prej -> denar dogodka gre ven
 *   7  socasnost: dva hkratna krogi/racuni = eno izplacilo; zavrnjeno izplacilo -> ni_uspelo + POZOR + 24 h premor; napaka po ustvarjanju -> posvojeno po metadata
 *   8  izid: paid -> placano, failed -> ni_uspelo + POZOR; obviselo v_teku -> posvojeno ali zaprto; racun brez payouts_enabled se preskoci
 *   9  backend: onboarding z vklopom ustvari racun z rocnimi izplacili; account.updated z drugim urnikom ga vrne v ponovno nastavitev;
 *      POST /admin/api/events/:id/payout-early (samo admin, razlog, sled v admin_dejanja natanko enkrat, platformni dogodek 409); GET /admin/api/payouts; stats.payout_early_at
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");
const Stripe = require("stripe");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 5891, JWKS_PORT = 5892, STRIPE_PORT = 5893;
const BASE = `http://127.0.0.1:${PORT}`;
const WHSEC = "whsec_test_izplacila";
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
const pocakaj = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- lazni Stripe ----------
const F = { racuni: {}, stanje: {}, izplacila: {}, idem: {}, klici: [], stIzpl: 0, napakaUrnik: null, napakaIzplacilo: null, napakaPoUstvarjanju: false, zakasnitev: 0 };
const obrazec = (t) => { const o = {}; for (const [k, v] of new URLSearchParams(t)) o[k] = v; return o; };
const stripeServer = http.createServer((req, res) => {
  let d = ""; req.on("data", (x) => d += x);
  req.on("end", async () => {
    const url = new URL(req.url, "http://x"), u = url.pathname, p = obrazec(d), racun = req.headers["stripe-account"] || null, kljuc = req.headers["idempotency-key"] || null;
    F.klici.push({ m: req.method, u, p, racun, kljuc });
    if (F.zakasnitev) await pocakaj(F.zakasnitev);
    const odg = (st, o) => { res.writeHead(st, { "content-type": "application/json", "request-id": "req_t", "stripe-should-retry": "false" }); res.end(JSON.stringify(o)); };
    const napaka = (st, tip, code, msg) => odg(st, { error: { type: tip, ...(code ? { code } : {}), message: msg } });
    let m;
    if (req.method === "POST" && u === "/v1/accounts") {
      const id = "acct_nov" + (Object.keys(F.racuni).length + 1);
      F.racuni[id] = { id, object: "account", _params: p, charges_enabled: false, payouts_enabled: false, details_submitted: false,
        settings: { payouts: { schedule: { interval: p["settings[payouts][schedule][interval]"] || "daily" } } }, requirements: { currently_due: [] } };
      return odg(200, F.racuni[id]);
    }
    if (req.method === "POST" && u === "/v1/account_links") return odg(200, { object: "account_link", url: `https://connect.stripe.test/setup/${p.account}` });
    if ((m = u.match(/^\/v1\/accounts\/(acct_\w+)$/))) {
      if (req.method === "GET") return F.racuni[m[1]] ? odg(200, F.racuni[m[1]]) : napaka(404, "invalid_request_error", "resource_missing", "No such account");
      if (F.napakaUrnik && F.napakaUrnik(m[1])) return napaka(400, "invalid_request_error", null, "You cannot change payout schedule for this account.");
      const a = F.racuni[m[1]] || (F.racuni[m[1]] = { id: m[1], object: "account", settings: { payouts: { schedule: { interval: "daily" } } } });
      if (p["settings[payouts][schedule][interval]"]) a.settings.payouts.schedule.interval = p["settings[payouts][schedule][interval]"];
      return odg(200, a);
    }
    if (req.method === "GET" && u === "/v1/balance") {
      const s = F.stanje[racun] || { a: 0, p: 0 };
      return odg(200, { object: "balance", available: [{ amount: s.a, currency: "eur" }, { amount: 999999, currency: "usd" }], pending: [{ amount: s.p, currency: "eur" }] });
    }
    if (req.method === "POST" && u === "/v1/payouts") {
      if (kljuc && F.idem[kljuc]) return odg(200, F.idem[kljuc]);
      const s = F.stanje[racun] || { a: 0, p: 0 }, amount = Number(p.amount);
      if (F.napakaIzplacilo) return napaka(400, "invalid_request_error", F.napakaIzplacilo, "Payout failed");
      if (amount > s.a) return napaka(400, "invalid_request_error", "balance_insufficient", "Insufficient funds");
      s.a -= amount; F.stanje[racun] = s;
      const id = "po_" + (++F.stIzpl);
      const po = { id, object: "payout", amount, currency: p.currency, status: "pending", metadata: { izplacilo_id: p["metadata[izplacilo_id]"], club_id: p["metadata[club_id]"] }, _racun: racun };
      F.izplacila[id] = po; if (kljuc) F.idem[kljuc] = po;
      if (F.napakaPoUstvarjanju) { F.napakaPoUstvarjanju = false; return napaka(500, "api_error", null, "Internal error"); }
      return odg(200, po);
    }
    if (req.method === "GET" && u === "/v1/payouts") return odg(200, { object: "list", has_more: false, data: Object.values(F.izplacila).filter((x) => x._racun === racun) });
    if (req.method === "GET" && (m = u.match(/^\/v1\/payouts\/(po_\w+)$/))) { const x = F.izplacila[m[1]]; return x && x._racun === racun ? odg(200, x) : napaka(404, "invalid_request_error", "resource_missing", "No such payout"); }
    return napaka(404, "invalid_request_error", null, "Unknown " + req.method + " " + u);
  });
});
const klici = (pot, metoda) => F.klici.filter((k) => (!metoda || k.m === metoda) && (typeof pot === "string" ? k.u === pot : pot.test(k.u)));

// ---------- JWKS (del 9) ----------
const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-izplacila";
const jwksServer = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url.startsWith("/auth/v1/user")) { try { const t = JSON.parse(Buffer.from(String(req.headers.authorization).split(".")[1], "base64url")); return res.end(JSON.stringify({ id: t.sub, email: t.email, email_confirmed_at: "2026-01-01T00:00:00Z" })); } catch (_) { res.statusCode = 401; return res.end("{}"); } }
  if (req.url.startsWith("/auth/v1/settings")) return res.end(JSON.stringify({ mailer_autoconfirm: false, external: { anonymous_users: false } }));
  res.end(JSON.stringify({ keys: [{ ...jwk, kid: KID, alg: "ES256", use: "sig" }] }));
});
const b64u = (o) => Buffer.from(typeof o === "string" ? o : JSON.stringify(o)).toString("base64url");
function zeton(email, sub) {
  const now = Math.floor(Date.now() / 1000);
  const h = b64u({ alg: "ES256", typ: "JWT", kid: KID });
  const p = b64u({ iss: `http://127.0.0.1:${JWKS_PORT}/auth/v1`, aud: "authenticated", sub, email, exp: now + 3600, iat: now, user_metadata: { email_verified: true, username: email.split("@")[0].replace(/[^a-z0-9_]/gi, "") } });
  return h + "." + p + "." + crypto.sign("sha256", Buffer.from(h + "." + p), { key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
}
const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
async function api(method, path, token, body, glave = {}) {
  const r = await fetch(BASE + path, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}), ...glave }, body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}

async function main() {
  await new Promise((r) => stripeServer.listen(STRIPE_PORT, r));
  process.env.STRIPE_SECRET_KEY = "sk_test_izplacila";
  process.env.STRIPE_API_BASE = `http://127.0.0.1:${STRIPE_PORT}`;
  const placila = require("../placila_stripe");
  const iz = require("../izplacila_stripe");
  const pool = new Pool({ connectionString: DB, max: 8 });
  const dnevnik = [];
  const log = { log: () => {}, error: (s) => dnevnik.push(String(s)) };
  const T = { zdaj: new Date("2026-11-18T10:00:00Z") };   // sreda
  const zapisiAdminDejanje = async (c, req, dejanje, tip, id, prej, potem, razlog) => c.query(
    "INSERT INTO admin_dejanja (admin_user_id, dejanje, cilj_tip, cilj_id, prej, potem, razlog) VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7)",
    [null, dejanje, tip, String(id), JSON.stringify(prej), JSON.stringify(potem), razlog]);
  const I = iz.ustvari({ pool, stripe: placila.stripe, jeLive: placila.jeLive, zapisiAdminDejanje, celoId4: (v) => (/^\d+$/.test(String(v)) ? Number(v) : null), log, zdaj: () => T.zdaj });
  const s = placila.stripe();

  try {
    console.log("\n# 1 Delovni dnevi in sprostitev");
    process.env.IZPLACILA_DNI_PO_DOGODKU = "2";
    const sob = new Date("2026-11-14T02:00:00Z");   // sobota 03:00 LJ
    assert(iz.plusDelovni("2026-11-14", 2) === "2026-11-17", "sobota + 2 delovna dneva = torek");
    assert(iz.plusDelovni("2026-11-18", 2) === "2026-11-20", "sreda + 2 = petek");
    assert(iz.plusDelovni("2026-11-20", 2) === "2026-11-24", "petek + 2 = torek");
    assert(!iz.sproscen({ status: "published", konec: sob }, new Date("2026-11-16T22:59:00Z")), "ponedeljek 23:59 LJ: se ne");
    assert(iz.sproscen({ status: "published", konec: sob }, new Date("2026-11-16T23:01:00Z")), "torek 00:01 LJ: sprosceno");
    assert(!iz.sproscen({ status: "published", konec: new Date("2026-11-18T09:00:00Z") }, T.zdaj, 0) === false && !iz.sproscen({ status: "published", konec: new Date("2026-11-18T11:00:00Z") }, T.zdaj, 0), "N=0: po koncu da, pred koncem ne");
    assert(!iz.sproscen({ status: "cancelled", konec: sob }, T.zdaj), "odpovedan nikoli");
    assert(iz.sproscen({ status: "cancelled", konec: sob, prej: true }, T.zdaj) && iz.sproscen({ status: "published", konec: new Date("2027-01-01"), prej: true }, T.zdaj), "odobren prej vedno");
    assert(iz.dniPoDogodku() === 2 && (delete process.env.IZPLACILA_DNI_PO_DOGODKU, iz.dniPoDogodku() === 2), "privzeto 2 delovna dneva (Martin 12. 11. 13:23)");

    // ---------- podatki ----------
    await pool.query("TRUNCATE izplacila, izplacila_racuni, izplacila_odobritve, vracila, spori, admin_dejanja, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
    const u = (await pool.query("INSERT INTO users (email, username, role) VALUES ('lastnik@primer.si', 'lastnik', 'business') RETURNING id")).rows[0].id;
    const klub = async (ime, racun, payouts = true) => (await pool.query(
      "INSERT INTO clubs (owner_user_id, name, stripe_account_id, stripe_account_livemode, stripe_charges_enabled, stripe_payouts_enabled) VALUES ($1, $2, $3, FALSE, TRUE, $4) RETURNING id",
      [u, ime, racun, payouts])).rows[0].id;
    const K1 = await klub("Klub Ena", "acct_k1"), K2 = await klub("Klub Dva", "acct_k2"), K3 = await klub("Klub Brez", "acct_k3", false);
    const dogodek = async (klubId, start, end, status = "published") => (await pool.query(
      "INSERT INTO events (club_id, title, start_at, end_at, status) VALUES ($1, 'D', $2, $3, $4) RETURNING id", [klubId, start, end, status])).rows[0].id;
    const E1 = await dogodek(K1, "2026-11-13T21:00:00Z", "2026-11-14T02:00:00Z");     // koncan sobota, sproscen v torek
    const E2 = await dogodek(K1, "2026-11-28T21:00:00Z", "2026-11-29T03:00:00Z");     // prihodnji
    const E3 = await dogodek(K1, "2026-11-16T21:00:00Z", "2026-11-17T02:00:00Z");     // koncan torek, sproscen v cetrtek
    const E4 = await dogodek(K1, "2026-11-25T21:00:00Z", null, "cancelled");          // odpovedan
    let st = 0;
    const narocilo = async (ev, klubId, p = {}) => {
      const o = { cena: 2000, fee: 200, refunded: 0, status: "paid", pi: `pi_${++st}`, racun: "acct_k1", placano: "2026-11-10T12:00:00Z", ...p };
      return (await pool.query(
        `INSERT INTO orders (public_ref, event_id, club_id, quantity, unit_price_cents, total_cents, currency, application_fee_cents, status, buyer_email, paid_at, refunded_cents, stripe_payment_intent_id, stripe_account_id)
         VALUES ($1, $2, $3, 1, $4, $4, 'EUR', $5, $6, 'kupec@primer.si', $7, $8, $9, $10) RETURNING id`,
        ["OUT-IZP-" + st, ev, klubId, o.cena, o.fee, o.status, o.placano, o.refunded, o.pi, o.racun])).rows[0].id;
    };
    const n1a = await narocilo(E1, K1), n1b = await narocilo(E1, K1, { cena: 1500, fee: 150, refunded: 500, status: "partially_refunded" });   // neto E1 = 1800 + 850 = 2650
    const n2 = await narocilo(E2, K1, { cena: 3000, fee: 300 });   // neto E2 = 2700
    const NETO1 = 2650, NETO2 = 2700;
    const ciste = async () => { await pool.query("TRUNCATE izplacila, izplacila_odobritve, spori, vracila RESTART IDENTITY"); F.izplacila = {}; F.idem = {}; F.klici = []; dnevnik.length = 0; };

    console.log("\n# 2 Izklopljeno");
    delete process.env.IZPLACILA_PO_DOGODKU;
    F.klici = [];
    let r = await I.krog();
    assert(r.preskoceno === "izklopljeno" && F.klici.length === 0, "brez IZPLACILA_PO_DOGODKU=1: noben klic Stripa", r);
    process.env.IZPLACILA_PO_DOGODKU = "1";

    console.log("\n# 3 Urnik Connect racunov");
    F.napakaUrnik = (a) => a === "acct_k2";
    F.stanje = { acct_k1: { a: NETO2, p: 0 }, acct_k2: { a: 5000, p: 0 } };
    r = await I.krog();
    const upd = klici(/^\/v1\/accounts\/acct_k[123]$/, "POST");
    assert(upd.length === 3 && upd.every((k) => k.p["settings[payouts][schedule][interval]"] === "manual"), "vsi trije racuni: POST accounts/:id settings.payouts.schedule.interval=manual", upd.map((k) => k.u));
    let racuni = (await pool.query("SELECT stripe_account_id, rocno_at IS NOT NULL AS rocno, napaka, poskusi FROM izplacila_racuni ORDER BY 1")).rows;
    assert(racuni.find((x) => x.stripe_account_id === "acct_k1").rocno && racuni.find((x) => x.stripe_account_id === "acct_k3").rocno, "acct_k1 in acct_k3: rocno potrjeno", racuni);
    const k2 = racuni.find((x) => x.stripe_account_id === "acct_k2");
    assert(k2 && !k2.rocno && k2.poskusi === 1 && /payout schedule/.test(k2.napaka), "acct_k2: napaka zapisana, ni rocno", k2);
    assert(dnevnik.some((x) => /POZOR: klub \d+: rocnega urnika/.test(x)), "POZOR ob napaki urnika", dnevnik);
    assert(!klici("/v1/balance").some((k) => k.racun === "acct_k2") && !klici("/v1/balance").some((k) => k.racun === "acct_k3"), "brez izplacil za racun brez rocnega urnika in za racun brez payouts_enabled");
    F.klici = [];
    await I.krog();
    assert(klici(/^\/v1\/accounts\//, "POST").length === 0, "drugi krog: urnik se ne nastavlja znova (acct_k2 caka na premor)");

    console.log("\n# 4 Prihodnji dogodek ostane, koncan + 2 delovna dneva gre ven");
    await ciste();
    F.stanje.acct_k1 = { a: NETO2, p: 0 };   // samo denar prihodnjega dogodka (E1 ze izplacan / ga se ni)
    // Ze zgoraj: samo NETO2 na voljo, zadrzano NETO2 -> nic
    r = await I.krog();
    assert(klici("/v1/payouts", "POST").length === 0 && (r.racuni || []).find((x) => x.club_id === K1).stanje === "nic", "denar prihodnjega dogodka: ni izplacila", r);
    F.stanje.acct_k1 = { a: NETO1 + NETO2, p: 0 };
    F.klici = [];
    r = await I.krog();
    let po = klici("/v1/payouts", "POST");
    assert(po.length === 1 && Number(po[0].p.amount) === NETO1 && po[0].p.currency === "eur", `izplacilo TOCNO neto koncanega dogodka (${NETO1} c)`, po.map((x) => x.p));
    assert(po[0].racun === "acct_k1" && /^outly-izplacilo-\d+$/.test(po[0].kljuc), "Stripe-Account kluba in idempotentni kljuc iz vrstice", po[0]);
    let vr = (await pool.query("SELECT stanje, znesek_cents, zadrzano_cents, na_voljo_cents, payout_id, podrobnosti FROM izplacila")).rows;
    assert(vr.length === 1 && vr[0].stanje === "poslano" && vr[0].znesek_cents === NETO1 && Number(vr[0].zadrzano_cents) === NETO2 && /^po_/.test(vr[0].payout_id), "vrstica poslano z zamrznjenim zneskom in posnetkom", vr);
    assert(vr[0].podrobnosti.length === 1 && vr[0].podrobnosti[0].event_id === E2 && vr[0].podrobnosti[0].cents === NETO2 && vr[0].podrobnosti[0].vrsta === "dogodek" && Object.keys(vr[0].podrobnosti[0]).length === 3 && !/@/.test(JSON.stringify(vr)), "podrobnosti: samo ID dogodka in centi, brez e-naslova", vr[0].podrobnosti);
    F.klici = [];
    await I.krog();
    assert(klici("/v1/payouts", "POST").length === 0, "naslednji krog: ostanek je zadrzan, ni izplacila");

    console.log("\n# 5 Zadrzanje");
    const izracun = async () => (await I.zadrzano(K1, "acct_k1")).zadrzano;
    await ciste();
    assert(await izracun() === NETO2, "osnova: zadrzan samo prihodnji dogodek");
    await pool.query("INSERT INTO spori (id, order_id, stanje, znesek_cents, valuta) VALUES ('dp_1', $1, 'needs_response', 1800, 'EUR')", [n1a]);
    assert(await izracun() === NETO2 + 1800 + 4000, "odprt spor na sproscenem dogodku: znesek + 2 x 20 EUR pristojbine");
    await pool.query("INSERT INTO spori (id, order_id, stanje, znesek_cents, valuta) VALUES ('dp_2', $1, 'warning_needs_response', 3000, 'EUR')", [n2]);
    assert(await izracun() === NETO2 + 5800 + 4000, "spor (poizvedba) na nesproscenem dogodku: samo pristojbine (neto je ze zadrzan)");
    await pool.query("UPDATE spori SET stanje = 'won', zaprt_at = NOW() WHERE id = 'dp_1'");
    await pool.query("UPDATE spori SET stanje = 'warning_closed', zaprt_at = NOW() WHERE id = 'dp_2'");
    assert(await izracun() === NETO2, "dobljen/zaprt spor: nic vec zadrzano");
    await pool.query("UPDATE spori SET stanje = 'lost', povrnitev_stanje = 'caka' WHERE id = 'dp_1'");
    assert(await izracun() === NETO2 + 5800, "izgubljen spor s cakajoco povrnitvijo od kluba: zadrzan");
    await pool.query("UPDATE spori SET povrnitev_stanje = 'opravljeno' WHERE id = 'dp_1'");
    assert(await izracun() === NETO2, "povrnitev opravljena: sprosceno");
    const nc = await narocilo(E1, K1, { status: "cancelled", cena: 1000, fee: 100 });
    await pool.query("INSERT INTO vracila (order_id, event_id, razlog, znesek_cents, stanje) VALUES ($1, $2, 'inactive_order', 1000, 'caka')", [nc, E1]);
    assert(await izracun() === NETO2 + 1000, "vracilo neaktivnega narocila v vrsti: zadrzano");
    await pool.query("UPDATE vracila SET stanje = 'opravljeno'");
    assert(await izracun() === NETO2, "vracilo opravljeno: sprosceno");
    await narocilo(E4, K1, { cena: 1200, fee: 120 });
    await narocilo(E3, K1, { cena: 1000, fee: 100 });
    assert(await izracun() === NETO2 + 1080 + 900, "odpovedan dogodek in dogodek 1 delovni dan po koncu: zadrzana");
    process.env.IZPLACILA_DNI_PO_DOGODKU = "0";
    assert(await izracun() === NETO2 + 1080, "N=0: dogodek po koncu sprosceno takoj (odpovedan ostane)");
    delete process.env.IZPLACILA_DNI_PO_DOGODKU;
    await narocilo(E2, K1, { pi: "test_lazni_1", cena: 5000, fee: 0 });
    await narocilo(E2, K1, { racun: "acct_drug", cena: 5000, fee: 0 });
    await narocilo(E2, K1, { racun: "platform", cena: 5000, fee: 0 });
    await narocilo(E2, K1, { status: "pending", cena: 5000, fee: 0 });
    assert(await izracun() === NETO2 + 1980, "testno, tuje, platformno in neplacano narocilo se ne zadrzijo");
    await narocilo(E2, K1, { placano: "2026-08-20T12:00:00Z", cena: 4000, fee: 0 });   // 90 dni pred T.zdaj
    assert(await izracun() === NETO2 + 1980, "narocilo starejse od 85 dni se ne zadrzi (Stripe: najvec 90 dni)");
    // v_cakanju pokrije zadrzano: na voljo samo sproscen denar, prihodnji je se pending
    await ciste();
    const zad = await izracun();
    F.stanje.acct_k1 = { a: 2500, p: zad };
    await I.krog();
    po = klici("/v1/payouts", "POST");
    assert(po.length === 1 && Number(po[0].p.amount) === 2500, "zadrzano je se v cakanju (pending): na voljo gre v celoti ven", po.map((x) => x.p));
    await ciste();
    F.stanje.acct_k1 = { a: 2500, p: 0 };
    await I.krog();
    assert(klici("/v1/payouts", "POST").length === 0, "na voljo manj kot zadrzano, nic v cakanju: ni izplacila");

    console.log("\n# 5b Rok hrambe (pogodba 7. clen): denar prihodnjega dogodka, star > 85 dni, gre ven z zapisom in POZOR enkrat");
    await ciste();
    F.stanje.acct_k1 = { a: zad + 4000, p: 0 };
    r = await I.izplacajRacun(s, K1, "acct_k1");
    vr = (await pool.query("SELECT znesek_cents, podrobnosti FROM izplacila WHERE stanje = 'poslano'")).rows;
    const rh = vr.length ? vr[0].podrobnosti.filter((x) => x.vrsta === "rok_hrambe") : [];
    assert(r.stanje === "poslano" && r.znesek === 4000 && rh.length === 1 && rh[0].event_id === E2 && rh[0].cents === 4000, "izplacan TOCNO denar, star vec kot 85 dni; zapisan kot rok_hrambe", { r, vr });
    const pozorRh = () => dnevnik.filter((x) => /izplacan PRED dogodkom/.test(x) && x.includes(`dogodek ${E2}: 4000 c`)).length;
    assert(pozorRh() === 1, "POZOR adminu (Sentry) ob izplacilu pred dogodkom", dnevnik);
    F.stanje.acct_k1.a += 500;
    r = await I.izplacajRacun(s, K1, "acct_k1");
    assert(r.stanje === "poslano" && r.znesek === 500 && pozorRh() === 1, "naslednje izplacilo: brez ponovnega POZOR za isti dogodek", { r, n: pozorRh() });

    console.log("\n# 6 Admin odobri prej");
    await ciste();
    F.stanje.acct_k1 = { a: zad, p: 0 };
    await pool.query("INSERT INTO izplacila_odobritve (event_id, razlog) VALUES ($1, 'klub rabi denar za izvajalce')", [E2]);
    const brezE2 = await izracun();
    await I.krog();
    po = klici("/v1/payouts", "POST");
    assert(po.length === 1 && Number(po[0].p.amount) === zad - brezE2 && zad - brezE2 >= NETO2, "odobren prej: denar prihodnjega dogodka gre ven, ostalo zadrzano", { po: po.map((x) => x.p.amount), zad, brezE2 });

    console.log("\n# 7 Socasnost in napake");
    await ciste();
    await pool.query("DELETE FROM orders WHERE event_id IN ($1, $2, $3) OR status <> 'paid' AND status <> 'partially_refunded'", [E2, E3, E4]);
    F.stanje.acct_k1 = { a: 10000, p: 0 };
    F.zakasnitev = 150;
    const rr = await Promise.all([I.izplacajRacun(s, K1, "acct_k1"), I.izplacajRacun(s, K1, "acct_k1"), I.izplacajRacun(s, K1, "acct_k1")]);
    F.zakasnitev = 0;
    assert(klici("/v1/payouts", "POST").length === 1 && rr.filter((x) => x.stanje === "poslano").length === 1 && rr.filter((x) => x.stanje === "v_teku").length === 2, "tri hkratna izplacila istega racuna = eno izplacilo", rr);
    await ciste();
    F.stanje.acct_k1 = { a: 10000, p: 0 };
    F.napakaIzplacilo = "payouts_not_allowed";
    r = await I.izplacajRacun(s, K1, "acct_k1");
    F.napakaIzplacilo = null;
    vr = (await pool.query("SELECT stanje, napaka FROM izplacila")).rows;
    assert(r.stanje === "ni_uspelo" && vr[0].stanje === "ni_uspelo" && /payouts_not_allowed/.test(vr[0].napaka) && dnevnik.some((x) => /POZOR: klub \d+: izplacilo \d+ 10000 c ni uspelo/.test(x)), "zavrnjeno izplacilo: ni_uspelo + POZOR", { r, vr, dnevnik });
    r = await I.izplacajRacun(s, K1, "acct_k1");
    assert(r.stanje === "odlozeno" && klici("/v1/payouts", "POST").length === 1, "v 24 h po zavrnitvi: brez novega poskusa", r);
    await ciste();
    F.napakaPoUstvarjanju = true;
    r = await I.izplacajRacun(s, K1, "acct_k1");
    vr = (await pool.query("SELECT stanje, payout_id, znesek_cents FROM izplacila")).rows;
    assert(r.stanje === "poslano" && vr.length === 1 && vr[0].stanje === "poslano" && /^po_/.test(vr[0].payout_id) && Object.keys(F.izplacila).length === 1, "Stripe ustvari izplacilo, odgovor pade: posvojeno po metadata, brez dvojnega", { r, vr });

    console.log("\n# 8 Izid in pospravljanje");
    await pool.query("UPDATE izplacila SET posodobljeno_at = NOW() - INTERVAL '1 hour'");
    Object.values(F.izplacila)[0].status = "paid";
    await I.krog();
    assert((await pool.query("SELECT stanje FROM izplacila")).rows[0].stanje === "placano", "Stripe paid -> placano");
    await ciste();
    F.stanje.acct_k1 = { a: 3000, p: 0 };
    await I.izplacajRacun(s, K1, "acct_k1");
    await pool.query("UPDATE izplacila SET posodobljeno_at = NOW() - INTERVAL '1 hour'");
    Object.values(F.izplacila)[0].status = "failed"; Object.values(F.izplacila)[0].failure_code = "account_closed";
    await I.krog();
    vr = (await pool.query("SELECT stanje, napaka FROM izplacila ORDER BY id")).rows;
    assert(vr[0].stanje === "ni_uspelo" && vr[0].napaka === "account_closed" && dnevnik.some((x) => /zavrnil \(account_closed\)/.test(x)), "Stripe failed -> ni_uspelo + POZOR", { vr, dnevnik });
    await ciste();
    await pool.query("INSERT INTO izplacila (club_id, stripe_account_id, livemode, znesek_cents, prevzeto_at) VALUES ($1, 'acct_k1', FALSE, 700, NOW() - INTERVAL '20 minutes')", [K1]);
    await I.krog();
    vr = (await pool.query("SELECT stanje FROM izplacila ORDER BY id")).rows;
    assert(vr[0].stanje === "ni_uspelo", "obviselo v_teku brez Stripovega izplacila: zaprto (ni_uspelo)", vr);

    // ---------- 9 backend ----------
    console.log("\n# 9 Backend: onboarding, account.updated, admin");
    await pool.query("TRUNCATE izplacila, izplacila_racuni, izplacila_odobritve, vracila, spori, admin_dejanja, stripe_events, club_members, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
    F.racuni = {}; F.klici = []; F.napakaUrnik = null;
    await new Promise((r) => jwksServer.listen(JWKS_PORT, r));
    const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test",
      STRIPE_SECRET_KEY: "sk_test_izplacila", STRIPE_WEBHOOK_SECRET: WHSEC, STRIPE_API_BASE: `http://127.0.0.1:${STRIPE_PORT}`, IZPLACILA_PO_DOGODKU: "1", IZPLACILA_ZAGON_MS: "3600000",
      APP_URL: "https://outly.test", TEST_PLACILA: "" }, stdio: ["ignore", "pipe", "pipe"] });
    let blog = ""; srv.stdout.on("data", (d) => blog += d); srv.stderr.on("data", (d) => blog += d);
    for (let i = 0; i < 80; i++) { try { await fetch(BASE + "/"); break; } catch { await pocakaj(100); } }
    try {
      const Z = { lastnik: zeton("lastnik@outly.si", uuid(1)), admin: zeton("admin@outly.si", uuid(2)) };
      for (const k of Object.keys(Z)) assert((await api("GET", "/me", Z[k])).status === 200, `GET /me ${k}`);
      await pool.query("UPDATE users SET role = 'business' WHERE email = 'lastnik@outly.si'");
      await pool.query("UPDATE users SET role = 'admin' WHERE email = 'admin@outly.si'");
      const kl = (await pool.query("INSERT INTO clubs (owner_user_id, name) VALUES ((SELECT id FROM users WHERE email = 'lastnik@outly.si'), 'Pure') RETURNING id")).rows[0].id;
      const ur = (await pool.query("INSERT INTO clubs (owner_user_id, name, is_official) VALUES ((SELECT id FROM users WHERE email = 'admin@outly.si'), 'Outly', TRUE) RETURNING id")).rows[0].id;
      r = await api("POST", "/business/stripe/onboard", Z.lastnik, {}, { "x-outly-club": String(kl) });
      const cr = klici("/v1/accounts", "POST");
      assert(r.status === 200 && cr.length === 1 && cr[0].p["settings[payouts][schedule][interval]"] === "manual", "onboarding z vklopom: nov Express racun z rocnimi izplacili", { r, p: cr[0] && cr[0].p });
      let ir = (await pool.query("SELECT stripe_account_id, club_id, rocno_at IS NOT NULL AS rocno FROM izplacila_racuni")).rows;
      assert(ir.length === 1 && ir[0].club_id === kl && ir[0].rocno, "izplacila_racuni: racun zapisan kot rocen", ir);
      // account.updated z drugim urnikom
      const acct = ir[0].stripe_account_id;
      F.racuni[acct].settings.payouts.schedule.interval = "daily"; F.racuni[acct].charges_enabled = true; F.racuni[acct].payouts_enabled = true;
      const dogodekWh = { id: "evt_acc_1", object: "event", type: "account.updated", livemode: false, created: Math.floor(Date.now() / 1000), data: { object: { id: acct, object: "account" } } };
      const telo = JSON.stringify(dogodekWh);
      const podpis = new Stripe("sk_test_x").webhooks.generateTestHeaderString({ payload: telo, secret: WHSEC });
      const wr = await fetch(BASE + "/stripe/webhook", { method: "POST", headers: { "content-type": "application/json", "stripe-signature": podpis }, body: telo });
      ir = (await pool.query("SELECT rocno_at IS NOT NULL AS rocno, napaka FROM izplacila_racuni")).rows;
      assert(wr.status === 200 && !ir[0].rocno && /daily/.test(ir[0].napaka) && /POZOR: klub \d+: Connect racun ima urnik izplacil »daily«/.test(blog), "account.updated z urnikom daily: racun gre v ponovno nastavitev + POZOR", { st: wr.status, ir });
      // admin: izplacaj prej
      const ev = (await pool.query("INSERT INTO events (club_id, title, start_at) VALUES ($1, 'Prihodnji', NOW() + INTERVAL '10 days') RETURNING id", [kl])).rows[0].id;
      const evUr = (await pool.query("INSERT INTO events (club_id, title, start_at) VALUES ($1, 'Outly', NOW() + INTERVAL '10 days') RETURNING id", [ur])).rows[0].id;
      r = await api("POST", `/admin/api/events/${ev}/payout-early`, Z.lastnik, { reason: "test razlog" });
      assert(r.status === 403 || r.status === 401, "lastnik kluba ne sme (samo admin)", r);
      r = await api("POST", `/admin/api/events/${ev}/payout-early`, Z.admin, { reason: "x" });
      assert(r.status === 400 && r.body.error === "invalid_reason", "razlog je obvezen (3-500 znakov)", r);
      r = await api("POST", `/admin/api/events/${evUr}/payout-early`, Z.admin, { reason: "lastni dogodek" });
      assert(r.status === 409 && r.body.error === "platform_event", "lastni dogodek Outly: 409", r);
      r = await api("POST", `/admin/api/events/999999/payout-early`, Z.admin, { reason: "ni ga" });
      assert(r.status === 404, "neobstojec dogodek: 404", r);
      r = await api("POST", `/admin/api/events/${ev}/payout-early`, Z.admin, { reason: "klub placa izvajalce vnaprej" });
      assert(r.status === 200 && r.body.ok === true && r.body.already === false && r.body.enabled === true, "admin odobri prej: 200", r);
      r = await api("POST", `/admin/api/events/${ev}/payout-early`, Z.admin, { reason: "se enkrat" });
      assert(r.status === 200 && r.body.already === true, "ponovno: already, brez nove sledi", r);
      const ad = (await pool.query("SELECT dejanje, cilj_tip, cilj_id, razlog, admin_user_id FROM admin_dejanja WHERE dejanje = 'event.payout_early'")).rows;
      assert(ad.length === 1 && ad[0].cilj_id === String(ev) && ad[0].razlog === "klub placa izvajalce vnaprej" && ad[0].admin_user_id !== null, "sled v admin_dejanja natanko enkrat, z razlogom in adminom", ad);
      r = await api("GET", `/admin/api/events/${ev}`, Z.admin);
      assert(r.status === 200 && r.body.stats && r.body.stats.payout_early_at, "GET /admin/api/events/:id: stats.payout_early_at", r.body && r.body.stats);
      r = await api("GET", "/admin/api/payouts", Z.admin);
      assert(r.status === 200 && r.body.enabled === true && r.body.days_after_event === 2 && Array.isArray(r.body.items) && r.body.accounts.length === 1, "GET /admin/api/payouts: nastavitve in racuni", r.body);
      r = await api("GET", "/admin/api/payouts", Z.lastnik);
      assert(r.status === 403 || r.status === 401, "GET /admin/api/payouts samo admin", r.status);
    } finally { srv.kill(); await new Promise((r) => srv.once("exit", r)).catch(() => {}); if (fail) console.log(blog.split("\n").slice(-30).join("\n")); }
  } finally {
    await pool.query("TRUNCATE izplacila, izplacila_racuni, izplacila_odobritve RESTART IDENTITY").catch(() => {});
    await pool.end(); stripeServer.close(); jwksServer.close();
  }
  console.log(`\n${ok} ok, ${fail} fail`);
  process.exit(fail ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(1); });
