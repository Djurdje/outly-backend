#!/usr/bin/env node
/**
 * Samodejna dnevna uskladitev Stripe <-> baza (Martin 27. 10. 2026, #374 tocka 2, migracija 073, invarianta I67; uskladitev_stripe.js). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_uskladitev_stripe.js
 * Pravi Stripe SDK proti lokalnemu lazneumu Stripe streznik (GET /v1/charges, /refunds, /disputes: filter `created`, stranjenje, payment_intent); nikoli pravi Stripe.
 *
 *   1  ujemanje -> `ok` (placilo, delno vracilo, staro placilo vrnjeno v D, spor z vrstico); izlocitve (0 EUR guest lista, testno narocilo, pending) niso razlika; vsote obeh strani
 *   2  razlike: placilo brez narocila; narocilo brez placila; razlika zneska; razlika valute; provizija; refunded_cents != Stripovo vracilo; spor brez vrstice; spor z drugim stanjem;
 *      placilo za testno narocilo; placilo za neplacano narocilo -> `razlike`, vsaka s svojo vrsto, JSON brez osebnih podatkov (e-naslov, ime)
 *   3  casovni pas: 23:30 Ljubljana = dan D (tudi poleti/pozimi, dan 25. 10. 2026 ima 25 ur); naboj ob polnoci v sosednjem dnevu NI razlika (`mejni_stevilo`)
 *   4  Stripe napaka (401) -> `napaka` + koda brez kljuca, brez izjeme; ponovni poskus pred 3 h ne teče, po 3 h uspe (poskusov 2); meja strani -> `napaka`
 *   5  ena izvedba na dan: dva hkratna zagona (ena in dve instanci) = ena vrstica in en sklop Stripovih klicev; zastarela `tece` se prevzame, zakasneli star proces ne povozi novejsega
 *   6  brez zivega kljuca (jeLive false) ali brez vklopa: krog ne naredi nicesar; kandidati: vceraj sele po 04:00, okno 7 dni, ZIVO_OD, ze opravljeni dnevi izpadejo; krog dohiti do 4 dni
 *   7  samo GET proti Stripu; v modulu ni skenPool; pisanje samo v stripe_uskladitve (orders/spori nespremenjeni)
 *   8  povezava iz poola (lazni pool): rok/napaka pri BEGIN, fn, COMMIT, ROLLBACK ali `error` na povezavi -> release(true) (povezava se unici, ne gre nazaj v glavni pool); samo cist konec -> release(false)
 *   2b naboj za preklicano/neuspelo narocilo, v celoti vrnjen (`inactive_order`) NI razlika; delno vrnjeno, brez vrstice `vracila`, drug razlog ali pending je razlika
 */
const http = require("http");
const fs = require("fs");
const path = require("path");
const { Pool } = require("pg");
const Stripe = require("stripe");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const STRIPE_PORT = 5851;
const KLJUC = "sk_live_tajni_kljuc_ne_sme_v_bazo";
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
const pocakaj = (ms) => new Promise((r) => setTimeout(r, ms));

// --- lazni Stripe ---
const F = { charges: [], refunds: [], disputes: [], zahtevki: [], napaka: 0, vedno_vec: false, drzi: 0, drzene: [] };
function resetF() { Object.assign(F, { charges: [], refunds: [], disputes: [], zahtevki: [], napaka: 0, vedno_vec: false, drzi: 0, drzene: [] }); }
let gen = 0;
function seznam(res, vsi, q) {
  if (F.vedno_vec === true) {   // Stripe, ki nikoli ne konca: vsaka stran 100 novih objektov
    const data = Array.from({ length: 100 }, () => ({ id: `ch_gen_${++gen}`, object: "charge", amount: 1, currency: "eur", status: "succeeded", paid: true, captured: true, created: sredina, payment_intent: `pi_gen_${gen}`, metadata: {}, amount_refunded: 0 }));
    return res.end(JSON.stringify({ object: "list", url: "/v1/x", data, has_more: true }));
  }
  if (F.vedno_vec === "prazno") return res.end(JSON.stringify({ object: "list", url: "/v1/x", data: [], has_more: true }));
  const gte = q.get("created[gte]") !== null ? Number(q.get("created[gte]")) : -Infinity, lt = q.get("created[lt]") !== null ? Number(q.get("created[lt]")) : Infinity;
  let v = vsi.filter((x) => x.created >= gte && x.created < lt && (!q.get("payment_intent") || x.payment_intent === q.get("payment_intent")));
  v.sort((a, b) => b.created - a.created || (a.id < b.id ? 1 : -1));
  const limit = Math.min(Number(q.get("limit") || 10), 100);
  const po = q.get("starting_after");
  if (po) { const i = v.findIndex((x) => x.id === po); v = i >= 0 ? v.slice(i + 1) : []; }
  const stran = v.slice(0, limit);
  res.end(JSON.stringify({ object: "list", url: "/v1/x", data: stran, has_more: F.vedno_vec ? true : v.length > limit }));
}
const stripeStreznik = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  const u = new URL(req.url, "http://x");
  F.zahtevki.push({ method: req.method, path: u.pathname, q: u.search });
  const obdelaj = () => {
    if (F.napaka) { res.statusCode = F.napaka; return res.end(JSON.stringify({ error: { type: "invalid_request_error", message: "Invalid API Key provided: " + KLJUC } })); }
    if (req.method !== "GET") { res.statusCode = 405; return res.end("{}"); }
    const q = u.searchParams;
    if (u.pathname === "/v1/charges") return seznam(res, F.charges, q);
    if (u.pathname === "/v1/refunds") return seznam(res, F.refunds, q);
    if (u.pathname === "/v1/disputes") return seznam(res, F.disputes, q);
    let m;
    if ((m = u.pathname.match(/^\/v1\/charges\/(.+)$/))) { const x = F.charges.find((c) => c.id === m[1]); if (x) return res.end(JSON.stringify(x)); }
    if ((m = u.pathname.match(/^\/v1\/disputes\/(.+)$/))) { const x = F.disputes.find((c) => c.id === m[1]); if (x) return res.end(JSON.stringify(x)); }
    res.statusCode = 404; return res.end(JSON.stringify({ error: { type: "invalid_request_error", code: "resource_missing", message: "No such object" } }));
  };
  if (F.drzi > 0) { F.drzi--; F.drzene.push(obdelaj); return; }   // zadrzi en zahtevek, dokler ga test ne sprosti
  obdelaj();
});

const sdk = new Stripe(KLJUC, { host: "127.0.0.1", port: STRIPE_PORT, protocol: "http", maxNetworkRetries: 0 });

// SQL_TESTNO_NAROCILO iz index.js (ena resnica, brez prepisa)
const SQL_TESTNO_NAROCILO = (() => {
  const m = fs.readFileSync(path.join(__dirname, "..", "index.js"), "utf8").match(/const SQL_TESTNO_NAROCILO = `([^`]*)`;/);
  return new Function("return `" + m[1] + "`")();
})();

// --- cas ---
// 2026-10-20 = poletni cas (UTC+2): D = [19. 10. 22:00Z, 20. 10. 22:00Z). 2026-10-25 = konec poletnega casa (25 ur). 2026-10-26 = zimski (UTC+1).
const Z = (iso) => Math.floor(Date.parse(iso) / 1000);
const D = "2026-10-20", T0 = Z("2026-10-19T22:00:00Z"), T1 = Z("2026-10-20T22:00:00Z");
const sredina = T0 + 12 * 3600;

async function main() {
  await new Promise((r) => stripeStreznik.listen(STRIPE_PORT, "127.0.0.1", r));
  const pool = new Pool({ connectionString: DB, max: 6 });
  const { ustvari } = require("../uskladitev_stripe");
  await pool.query("TRUNCATE stripe_uskladitve, spori, orders, events, clubs, users RESTART IDENTITY CASCADE");
  const u = (await pool.query("INSERT INTO users (email, username, role) VALUES ('lastnik@primer.si', 'lastnik', 'business') RETURNING id")).rows[0].id;
  const klub = (await pool.query("INSERT INTO clubs (owner_user_id, name) VALUES ($1, 'Klub Test') RETURNING id", [u])).rows[0].id;
  const dogodek = (await pool.query("INSERT INTO events (club_id, title, start_at) VALUES ($1, 'Dogodek', NOW() + INTERVAL '3 days') RETURNING id", [klub])).rows[0].id;

  let st = 1;
  // narocilo v bazi; `placano` = unix cas paid_at; vrne id
  const narocilo = async (p = {}) => {
    const o = { status: "paid", cena: 1500, qty: 1, fee: 150, refunded: 0, placano: sredina, pi: null, ses: null, valuta: "EUR", guest: false, ...p };
    const n = st++;
    const pi = o.pi === undefined || o.pi === null ? `pi_${n}` : o.pi;
    return (await pool.query(
      `INSERT INTO orders (public_ref, event_id, club_id, quantity, unit_price_cents, total_cents, currency, application_fee_cents, status, buyer_email, paid_at, refunded_cents,
                           stripe_payment_intent_id, stripe_checkout_session_id)
       VALUES ($1, $2, $3, $4::smallint, $5::int, ($4::smallint * $5::int), $6, $7, $8, 'kupec.zasebni@primer.si', CASE WHEN $9::bigint IS NULL THEN NULL ELSE to_timestamp($9::bigint) END, $10, $11, $12) RETURNING id`,
      ["OUT-USK-" + n, dogodek, klub, o.qty, o.cena, o.valuta, o.fee, o.status, o.placano, o.refunded, o.pi === false ? null : pi, o.ses])).rows[0].id;
  };
  // naboj v lazni Stripe (par narocila: isti PaymentIntent in metadata.order_id)
  const naboj = (n, p = {}) => {
    const c = { id: `ch_${n}`, object: "charge", amount: 1500, currency: "eur", status: "succeeded", paid: true, captured: true, created: sredina, payment_intent: `pi_${n}`,
      metadata: {}, application_fee_amount: 150, amount_refunded: 0, ...p };
    F.charges.push(c);
    return c;
  };
  const spor = (id, p = {}) => { const d = { id, object: "dispute", amount: 1500, currency: "eur", status: "needs_response", created: sredina, charge: "ch_1", ...p }; F.disputes.push(d); return d; };
  const vrstica = async (dan) => (await pool.query("SELECT * FROM stripe_uskladitve WHERE dan = $1::date", [dan])).rows[0];
  const vseVrstice = async () => (await pool.query("SELECT * FROM stripe_uskladitve")).rows;
  const cisto = async () => { resetF(); await pool.query("TRUNCATE stripe_uskladitve, spori, orders RESTART IDENTITY CASCADE"); st = 1; };
  const nov = (p = {}) => ustvari({ pool, SQL_TESTNO_NAROCILO, stripe: () => sdk, jeLive: () => true, log: { log() {}, error() {} }, ...p });
  const U = nov();
  const vrste = (r) => (r.razlike || []).map((x) => x.vrsta).sort();
  const pisanja = async () => (await pool.query("SELECT (SELECT COUNT(*) FROM orders)::int AS o, (SELECT COUNT(*) FROM spori)::int AS s, (SELECT COALESCE(SUM(refunded_cents),0) FROM orders)::int AS v")).rows[0];

  try {
    // ------------------------------------------------------------------ 1. ujemanje
    console.log("\n# 1. Ujemanje");
    await cisto();
    const n1 = await narocilo({ pi: "pi_1" }); naboj(1, { metadata: { order_id: String(n1) } });
    const n2 = await narocilo({ cena: 2000, fee: 200, refunded: 500, status: "partially_refunded", placano: sredina + 60 }); naboj(2, { amount: 2000, application_fee_amount: 200, amount_refunded: 500, created: sredina + 60 });
    F.refunds.push({ id: "re_2", amount: 500, status: "succeeded", created: sredina + 120, charge: "ch_2" });
    // staro placilo (prejsnji dan), vrnjeno v D: vracilo se preveri, placilo ne (je bilo na svoj dan)
    const n3 = await narocilo({ cena: 1000, fee: 100, refunded: 1000, status: "refunded", placano: T0 - 86400 }); naboj(3, { amount: 1000, application_fee_amount: 100, amount_refunded: 1000, created: T0 - 86400 });
    F.refunds.push({ id: "re_3", amount: 1000, status: "succeeded", created: sredina + 200, charge: "ch_3" });
    F.refunds.push({ id: "re_x", amount: 100, status: "failed", created: sredina + 300, charge: "ch_2" });   // zavrnjeno vracilo se ne steje
    // izlocitve: guest lista 0 EUR, testno narocilo, pending, neuspelo placilo v Stripu
    await narocilo({ cena: 0, fee: 0, pi: false });   // brezplacno (0 EUR) narocilo: ni promet
    await narocilo({ status: "paid", pi: "test_pi_x", ses: "cs_test_1" });
    await narocilo({ status: "pending", placano: null, pi: false });
    F.charges.push({ id: "ch_fail", amount: 999, currency: "eur", status: "failed", paid: false, captured: true, created: sredina, payment_intent: "pi_fail", metadata: {}, amount_refunded: 0 });
    F.charges.push({ id: "ch_nezajet", amount: 999, currency: "eur", status: "succeeded", paid: true, captured: false, created: sredina, payment_intent: "pi_nz", metadata: {}, amount_refunded: 0 });
    await pool.query("INSERT INTO spori (id, order_id, stanje, znesek_cents, valuta, ustvarjen_at) VALUES ('dp_1', $1, 'needs_response', 1500, 'EUR', to_timestamp($2))", [n1, sredina]);
    spor("dp_1", { charge: "ch_1" });
    const pred = await pisanja();
    const r1 = await U.obdelajDan(D);
    const v1 = await vrstica(D);
    assert(r1.stanje === "ok" && v1.stanje === "ok" && v1.razlike_stevilo === 0 && vrste(v1).length === 0, "ujemanje -> ok, brez razlik", { r1, razlike: v1 && v1.razlike });
    assert(v1.stripe_stevilo === 2 && v1.baza_stevilo === 2, "stevilo placil: Stripe 2 = baza 2 (guest lista, testno, pending, failed, ne-zajeto izlocene)", [v1.stripe_stevilo, v1.baza_stevilo]);
    assert(Number(v1.stripe_bruto_cents) === 3500 && Number(v1.baza_bruto_cents) === 3500, "bruto 3500 c na obeh straneh", [v1.stripe_bruto_cents, v1.baza_bruto_cents]);
    assert(Number(v1.stripe_provizija_cents) === 350 && Number(v1.baza_provizija_cents) === 350, "provizija 350 c na obeh straneh");
    assert(Number(v1.stripe_vrnjeno_cents) === 500 && Number(v1.baza_vrnjeno_cents) === 500, "vrnjeno (po naborih D) 500 c na obeh straneh", [v1.stripe_vrnjeno_cents, v1.baza_vrnjeno_cents]);
    assert(v1.stripe_vracila_stevilo === 2 && Number(v1.stripe_vracila_cents) === 1500, "Stripova vracila dneva: 2 (500 + 1000), zavrnjeno ne", [v1.stripe_vracila_stevilo, v1.stripe_vracila_cents]);
    assert(v1.stripe_spori_stevilo === 1 && v1.baza_spori_stevilo === 1, "spori: 1 = 1");
    assert(v1.poskusov === 1 && v1.izvedeno_at && v1.napaka_koda === null, "poskusov 1, izvedeno_at nastavljen, brez kode napake");
    const po = await pisanja();
    assert(po.o === pred.o && po.s === pred.s && po.v === pred.v, "orders/spori nespremenjeni (pisanje samo v stripe_uskladitve)", { pred, po });

    // ------------------------------------------------------------------ 2. razlike
    console.log("\n# 2. Razlike");
    const razlika = async (ime, pripravi, pricakovana, pregled) => {
      await cisto();
      await pripravi();
      await U.obdelajDan(D);
      const v = await vrstica(D);
      assert(v.stanje === "razlike" && JSON.stringify(vrste(v)) === JSON.stringify(pricakovana), `${ime}: ${pricakovana.join(", ")}`, { stanje: v.stanje, razlike: v.razlike });
      if (pregled) pregled(v);
      return v;
    };
    await razlika("placilo brez narocila", async () => { naboj(77, { metadata: { order_id: "999999" } }); }, ["placilo_brez_narocila"],
      (v) => assert(v.razlike[0].charge_id === "ch_77" && v.razlike[0].stripe_cents === 1500 && v.razlike_stevilo === 1, "razlika vsebuje charge_id in znesek v centih"));
    await razlika("narocilo brez placila", async () => { await narocilo({ pi: "pi_ni_v_stripu" }); }, ["naroceno_brez_placila"],
      (v) => assert(v.razlike[0].payment_intent === "pi_ni_v_stripu" && v.razlike[0].baza_cents === 1500, "razlika vsebuje narocilo in PaymentIntent"));
    await razlika("narocilo brez payment_intent", async () => { await narocilo({ pi: false }); }, ["naroceno_brez_placila"]);
    await razlika("razlika zneska", async () => { await narocilo({ pi: "pi_1", cena: 1400, fee: 140 }); naboj(1, { amount: 1500, application_fee_amount: 140 }); }, ["znesek_ali_valuta"],
      (v) => assert(v.razlike[0].stripe_cents === 1500 && v.razlike[0].baza_cents === 1400, "stripe_cents 1500 / baza_cents 1400"));
    await razlika("razlika valute (isti znesek)", async () => { await narocilo({ pi: "pi_1" }); naboj(1, { currency: "usd" }); }, ["znesek_ali_valuta"],
      (v) => assert(v.razlike[0].stripe_valuta === "USD" && v.razlike[0].baza_valuta === "EUR", "USD proti EUR"));
    await razlika("razlika provizije", async () => { await narocilo({ pi: "pi_1" }); naboj(1, { application_fee_amount: 120 }); }, ["provizija"]);
    await razlika("neujemanje vracila (Stripe vrnil, baza ne)", async () => { await narocilo({ pi: "pi_1" }); naboj(1, { amount_refunded: 500 }); }, ["vracilo"],
      (v) => assert(v.razlike[0].stripe_cents === 500 && v.razlike[0].baza_cents === 0, "stripe 500 / baza 0"));
    await razlika("neujemanje vracila (baza vrnila, Stripe ne)", async () => { await narocilo({ pi: "pi_1", refunded: 700, status: "partially_refunded" }); naboj(1); }, ["vracilo"]);
    await razlika("stari naboj, vrnjen v D, baza brez vracila", async () => {
      await narocilo({ pi: "pi_1", placano: T0 - 86400 }); naboj(1, { created: T0 - 86400, amount_refunded: 1500 });
      F.refunds.push({ id: "re_1", amount: 1500, status: "succeeded", created: sredina, charge: "ch_1" });
    }, ["vracilo"]);
    await razlika("spor brez vrstice v `spori`", async () => { const n = await narocilo({ pi: "pi_1" }); naboj(1); spor("dp_nov", { charge: "ch_1" }); }, ["spor_brez_vrstice"],
      (v) => assert(v.razlike[0].spor_id === "dp_nov" && v.razlike[0].stripe_stanje === "needs_response", "spor_id in stanje"));
    await razlika("spor z drugim stanjem", async () => {
      const n = await narocilo({ pi: "pi_1" }); naboj(1);
      await pool.query("INSERT INTO spori (id, order_id, stanje, znesek_cents, valuta, ustvarjen_at) VALUES ('dp_s', $1, 'needs_response', 1500, 'EUR', to_timestamp($2))", [n, sredina]);
      spor("dp_s", { status: "lost" });
    }, ["spor_stanje"]);
    await razlika("spor samo v bazi (Stripu neznan)", async () => {
      const n = await narocilo({ pi: "pi_1" }); naboj(1);
      await pool.query("INSERT INTO spori (id, order_id, stanje, znesek_cents, valuta, ustvarjen_at) VALUES ('dp_duh', $1, 'needs_response', 1500, 'EUR', to_timestamp($2))", [n, sredina]);
    }, ["spor_samo_v_bazi"]);
    await razlika("placilo za testno narocilo", async () => { await narocilo({ pi: "test_pi_1", ses: "cs_test_1" }); naboj(1, { payment_intent: "test_pi_1" }); }, ["placilo_za_testno_narocilo"]);
    await razlika("placilo za neplacano (pending) narocilo", async () => { await narocilo({ pi: "pi_1", status: "pending", placano: null }); naboj(1); }, ["placilo_brez_placanega_narocila"],
      (v) => assert(v.razlike[0].stanje_narocila === "pending", "stanje_narocila pending"));
    // ------------------------------------------------------------------ 2b. S2: placilo za preklicano narocilo, v celoti vrnjeno (inactive_order)
    console.log("\n# 2b. Preklicano narocilo, v celoti vrnjeno (inactive_order) ni razlika");
    const vracilo = (narociloId, razlog) => pool.query(
      "INSERT INTO vracila (order_id, event_id, razlog, znesek_cents, payment_intent_id, stripe_livemode, valuta) VALUES ($1, $2, $3, 1500, 'pi_1', TRUE, 'EUR')", [narociloId, dogodek, razlog]);
    for (const stanje of ["cancelled", "failed"]) {
      await cisto();
      const nc = await narocilo({ pi: "pi_1", status: stanje, placano: null }); await vracilo(nc, "inactive_order");
      naboj(1, { amount_refunded: 1500, metadata: { order_id: String(nc) } });
      F.refunds.push({ id: "re_c", amount: 1500, status: "succeeded", created: sredina + 10, charge: "ch_1" });
      const xc = await U.izracunaj(D);
      assert(xc.stanje === "ok" && xc.razlike_stevilo === 0 && xc.vrnjeno_neaktivno_stevilo === 1, `S2: ${stanje} + vrstica inactive_order + v celoti vrnjeno -> ok (informativni stevec 1)`, { stanje: xc.stanje, razlike: xc.razlike, st: xc.vrnjeno_neaktivno_stevilo });
      await U.obdelajDan(D);
      const vc = await vrstica(D);
      assert(vc.stanje === "ok" && vc.razlike_stevilo === 0, `S2: ${stanje}: vrstica dneva ok`, vc && vc.razlike);
    }
    await razlika("S2: preklicano + delno vrnjeno (700 od 1500)", async () => {
      const nc = await narocilo({ pi: "pi_1", status: "cancelled", placano: null }); await vracilo(nc, "inactive_order"); naboj(1, { amount_refunded: 700 });
    }, ["placilo_brez_placanega_narocila"], (v) => assert(v.razlike[0].stanje_narocila === "cancelled" && v.razlike[0].v_celoti_vrnjeno === false, "razlika: cancelled, ni v celoti vrnjeno"));
    await razlika("S2: preklicano + v celoti vrnjeno, a brez vrstice `vracila`", async () => {
      await narocilo({ pi: "pi_1", status: "cancelled", placano: null }); naboj(1, { amount_refunded: 1500 });
    }, ["placilo_brez_placanega_narocila"]);
    await razlika("S2: preklicano + v celoti vrnjeno, vrstica `vracila` z drugim razlogom", async () => {
      const nc = await narocilo({ pi: "pi_1", status: "cancelled", placano: null }); await vracilo(nc, "event_cancelled"); naboj(1, { amount_refunded: 1500 });
    }, ["placilo_brez_placanega_narocila"]);
    await razlika("S2: preklicano + brez vracila (kupec je placal, denar ni vrnjen)", async () => {
      const nc = await narocilo({ pi: "pi_1", status: "cancelled", placano: null }); await vracilo(nc, "inactive_order"); naboj(1, { amount_refunded: 0 });
    }, ["placilo_brez_placanega_narocila"]);
    await razlika("S2: pending (ne cancelled/failed) + v celoti vrnjeno + vrstica inactive_order", async () => {
      const nc = await narocilo({ pi: "pi_1", status: "pending", placano: null }); await vracilo(nc, "inactive_order"); naboj(1, { amount_refunded: 1500 });
    }, ["placilo_brez_placanega_narocila"]);

    // vec razlik hkrati + brez osebnih podatkov
    await cisto();
    const na = await narocilo({ pi: "pi_1", cena: 1400, fee: 140 }); naboj(1, { amount: 1500, application_fee_amount: 140, metadata: { order_id: String(na), ime: "Janez Novak", email: "janez@primer.si" }, billing_details: { email: "janez@primer.si", name: "Janez Novak" } });
    naboj(5); await narocilo({ pi: "pi_ni" }); spor("dp_x");
    await U.obdelajDan(D);
    const vv = await vrstica(D);
    const besedilo = JSON.stringify(vv);
    assert(vv.stanje === "razlike" && vv.razlike_stevilo === 4 && vv.razlike.length === 4, "vec razlik hkrati: stevilo = 4", { n: vv.razlike_stevilo, vrste: vrste(vv) });
    assert(!/@|primer\.si|Janez|Novak|kupec/i.test(besedilo), "vrstica uskladitve brez e-naslovov in imen", besedilo.slice(0, 300));
    assert(!besedilo.includes(KLJUC) && !/sk_live/.test(besedilo), "vrstica brez Stripovega kljuca");

    // omejitev seznama (100), stevilo ostane polno
    await cisto();
    for (let i = 1; i <= 105; i++) naboj(1000 + i, { payment_intent: `pi_brez_${i}`, created: sredina + i });
    await U.obdelajDan(D);
    const velik = await vrstica(D);
    assert(velik.razlike_stevilo === 105 && velik.razlike.length === 100, "105 razlik: razlike_stevilo 105, JSONB najvec 100", [velik.razlike_stevilo, velik.razlike.length]);
    assert(F.zahtevki.filter((z) => z.path === "/v1/charges" && /starting_after/.test(z.q)).length >= 1, "stranjenje: drugi klic z starting_after (limit 100)");

    // ------------------------------------------------------------------ 3. casovni pas
    console.log("\n# 3. Casovni pas Europe/Ljubljana");
    await cisto();
    const cas = async (iso, dan) => { const n = await narocilo({ placano: Z(iso), pi: `pi_c${st}` }); naboj(n, { created: Z(iso), payment_intent: `pi_c${n}`, id: `ch_c${n}` }); return n; };
    // poleti: 20. 10. 23:30 Ljubljana = 21:30Z (dan D), 21. 10. 00:30 = 22:30Z (dan D+1), 00:00 = 22:00Z (D+1)
    await cas("2026-10-20T21:30:00Z"); await cas("2026-10-20T22:30:00Z");
    const x = await U.izracunaj(D);
    assert(x.baza_stevilo === 1 && x.stripe_stevilo === 1 && x.stanje === "ok", "23:30 (CEST) je v dnevu D, 00:30 naslednjega dne ne", { b: x.baza_stevilo, s: x.stripe_stevilo, st: x.stanje });
    const x2 = await U.izracunaj("2026-10-21");
    assert(x2.baza_stevilo === 1 && x2.stripe_stevilo === 1, "00:30 (CEST) je v dnevu D+1");
    // konec poletnega casa: 25. 10. ima 25 ur (22:00Z 24. 10. .. 23:00Z 25. 10.); 23:30 CET (22:30Z) je se 25., 00:00 CET (23:00Z) je 26.
    await cisto();
    await cas("2026-10-24T22:00:00Z"); await cas("2026-10-25T22:30:00Z"); await cas("2026-10-25T23:00:00Z"); await cas("2026-10-24T21:59:59Z");
    const d25 = await U.izracunaj("2026-10-25");
    const d26 = await U.izracunaj("2026-10-26");
    assert(d25.baza_stevilo === 2 && d25.stripe_stevilo === 2 && d25.stanje === "ok", "25. 10. (25 ur): 00:00 CEST in 23:30 CET sta v tem dnevu, 23:00Z ne", { b: d25.baza_stevilo, s: d25.stripe_stevilo });
    assert(d26.baza_stevilo === 1 && d26.stripe_stevilo === 1, "26. 10.: polnoc CET je prvo narocilo dneva");
    // naboj ob polnoci v sosednjem dnevu (webhook zapise paid_at nekaj sekund pozneje): NI razlika
    await cisto();
    const nm = await narocilo({ pi: "pi_m", placano: T0 + 2 }); naboj(nm, { payment_intent: "pi_m", created: T0 - 3, id: "ch_m" });
    const dD = await U.izracunaj(D), dP = await U.izracunaj("2026-10-19");
    assert(dD.stanje === "ok" && dD.mejni_stevilo === 1 && dD.stripe_stevilo === 0 && dD.baza_stevilo === 1, "narocilo v D, naboj sekundo prej: ok + mejni_stevilo 1 (ciljano iskanje po PaymentIntentu)", dD);
    assert(dP.stanje === "ok" && dP.mejni_stevilo === 1 && dP.stripe_stevilo === 1 && dP.baza_stevilo === 0, "isti naboj na dan prej: ok + mejni_stevilo 1 (par najden izven dneva)", dP);
    // ... a mejni naboj z drugim zneskom je se vedno razlika
    F.charges[0].amount = 1600;
    const dR = await U.izracunaj(D);
    assert(dR.stanje === "razlike" && dR.razlike[0].vrsta === "znesek_ali_valuta", "mejni naboj z drugim zneskom = razlika");

    // ------------------------------------------------------------------ 4. napake
    console.log("\n# 4. Stripe napaka");
    await cisto();
    const na1 = await narocilo({ pi: "pi_1" }); naboj(1, { metadata: { order_id: String(na1) } });
    F.napaka = 401;
    let izjema = null, rN = null;
    try { rN = await U.obdelajDan(D); } catch (e) { izjema = e; }
    const vN = await vrstica(D);
    assert(!izjema && rN && rN.stanje === "napaka", "obdelajDan ob napaki ne vrze, vrne napaka", { izjema: izjema && izjema.message, rN });
    assert(vN.stanje === "napaka" && /^[A-Za-z0-9_.-]{1,60}$/.test(vN.napaka_koda || "") && !/sk_live|Invalid API Key/i.test(JSON.stringify(vN)), "vrstica napaka s kratko kodo, brez besedila napake in kljuca", vN.napaka_koda);
    assert(vN.stripe_stevilo === null && vN.razlike_stevilo === 0, "napaka NI »ni razlik«: vsote prazne, brez razlik");
    F.napaka = 0;
    const rBrez = await U.obdelajDan(D);
    assert(rBrez.preskoceno === "ima_drug_proces", "ponovni poskus pred 3 h ne teče", rBrez);
    await pool.query("UPDATE stripe_uskladitve SET izvedeno_at = NOW() - INTERVAL '4 hours'");
    const rPo = await U.obdelajDan(D);
    const vPo = await vrstica(D);
    assert(rPo.stanje === "ok" && vPo.stanje === "ok" && vPo.poskusov === 2 && vPo.napaka_koda === null, "po 3 h nov poskus uspe: ok, poskusov 2, koda napake pobrisana", { rPo, vPo: vPo.stanje, p: vPo.poskusov });
    assert((await vseVrstice()).length === 1, "se vedno ena vrstica na dan");
    // vsaka druga napaka: 500 brez izjeme
    await cisto(); F.napaka = 500;
    const r5 = await U.obdelajDan(D);
    assert(r5.stanje === "napaka", "Stripe 500 -> napaka brez izjeme");
    // meja strani
    await cisto(); naboj(1); F.vedno_vec = true;
    const rM = await U.obdelajDan(D);
    const vM = await vrstica(D);
    assert(rM.stanje === "napaka" && vM.napaka_koda === "meja_strani", "stran z vedno has_more -> napaka meja_strani (ne neskoncna zanka)", vM && vM.napaka_koda);
    assert(F.zahtevki.filter((z) => z.path === "/v1/charges").length <= 30, "najvec 30 strani");
    F.vedno_vec = "prazno"; await pool.query("TRUNCATE stripe_uskladitve");
    const rP = await U.obdelajDan(D);
    assert(rP.stanje === "napaka" && (await vrstica(D)).napaka_koda === "prazna_stran", "prazna stran z has_more -> napaka prazna_stran");
    F.vedno_vec = false;

    // ------------------------------------------------------------------ 5. ena izvedba na dan
    console.log("\n# 5. Ena izvedba na dan");
    await cisto();
    const nd = await narocilo({ pi: "pi_1" }); naboj(1, { metadata: { order_id: String(nd) } });
    await U.obdelajDan(D);
    const enKlic = F.zahtevki.length; F.zahtevki = [];
    await pool.query("TRUNCATE stripe_uskladitve");
    const [a, b] = await Promise.all([U.obdelajDan(D), U.obdelajDan(D)]);
    assert([a, b].filter((r) => r.stanje === "ok").length === 1 && [a, b].filter((r) => r.preskoceno).length === 1 && F.zahtevki.length === enKlic, "dva hkratna zagona (ista instanca): natanko eden obdela, Stripovi klici enkrat", [a, b, F.zahtevki.length, enKlic]);
    assert((await vseVrstice()).length === 1, "ena vrstica");
    await pool.query("TRUNCATE stripe_uskladitve"); F.zahtevki = [];
    const U2 = nov();
    const rr = await Promise.all([U.obdelajDan(D), U2.obdelajDan(D), U.obdelajDan(D), U2.obdelajDan(D)]);
    assert(rr.filter((r) => r.stanje === "ok").length === 1 && (await vseVrstice()).length === 1, "stirje hkratni zagoni iz dveh instanc (dva procesa): ena vrstica, en uspesen", rr);
    assert(enKlic > 0 && F.zahtevki.length === enKlic, "Stripovi klici samo enkrat (ne 4x)", [F.zahtevki.length, enKlic]);
    // ze opravljen dan se ne ponovi
    const ponovno = await U.obdelajDan(D);
    assert(ponovno.preskoceno === "ima_drug_proces", "ze opravljen dan (ok) se ne obdela znova", ponovno);
    // zastarela `tece` (proces umrl) se prevzame; zakasneli stari proces ne povozi novejsega
    await pool.query("TRUNCATE stripe_uskladitve"); F.zahtevki = [];
    const cakajDrzane = async (n) => { for (let i = 0; i < 100 && F.drzene.length < n; i++) await pocakaj(20); return F.drzene.length >= n; };
    F.drzi = 1;
    const stari = U.obdelajDan(D);          // zaseden: prvi Stripov zahtevek je zadrzan
    assert(await cakajDrzane(1) && (await vrstica(D)).stanje === "tece", "stari proces: vrstica `tece`, Stripe zadrzan");
    const nedavni = await U2.obdelajDan(D);
    assert(nedavni.preskoceno === "ima_drug_proces", "vrstica `tece` mlajsa od 15 min: drug proces je ne prevzame", nedavni);
    await pool.query("UPDATE stripe_uskladitve SET zacetek_at = NOW() - INTERVAL '20 minutes'");
    F.drzi = 1;
    const novi = U2.obdelajDan(D);          // prevzame zastarelo vrstico (poskusov 2), tudi njegov prvi zahtevek je zadrzan
    assert(await cakajDrzane(2) && (await vrstica(D)).poskusov === 2, "zastarela `tece` (> 15 min) se prevzame (poskusov 2)");
    F.drzene[0]();                          // stari proces dobi odgovor, ko novi se tece
    const starRez = await stari;
    const vMed = await vrstica(D);
    assert(starRez.preskoceno === "prevzel_drug_proces" && vMed.stanje === "tece" && vMed.poskusov === 2 && vMed.stripe_stevilo === null, "zakasneli stari proces ne povozi vrstice novejsega, ki se tece", { starRez, vMed: vMed.stanje, p: vMed.poskusov });
    F.drzene[1]();
    const noviRez = await novi;
    const vP = await vrstica(D);
    assert(noviRez.stanje === "ok" && vP.stanje === "ok" && vP.poskusov === 2 && vP.stripe_stevilo === 1, "novi proces zakljuci: ok, poskusov 2", { noviRez, vP: vP.stanje });

    // ------------------------------------------------------------------ 6. zivi nacin in kandidati
    console.log("\n# 6. Brez zivega kljuca, kandidati, dohitevanje");
    await cisto();
    const brezLive = nov({ jeLive: () => false });
    const rb = await brezLive.krog();
    assert(rb.preskoceno === "ni_zivo" && rb.obdelani.length === 0 && (await vseVrstice()).length === 0 && F.zahtevki.length === 0, "jeLive false (sandbox/lazni nacin): krog ne naredi nicesar, brez vrstice, brez Stripovih klicev", rb);
    const brezStripa = nov({ stripe: () => null });
    assert((await brezStripa.krog()).preskoceno === "ni_zivo", "brez kljuca: krog ne naredi nicesar");
    assert(nov({ vklopljena: () => false }).zazeni() === null, "brez vklopa (ni Render, ni STRIPE_USKLADITEV=1): zazeni() ne ustvari casovnika");
    const stari_env = { r: process.env.RENDER, n: process.env.NODE_ENV, s: process.env.STRIPE_USKLADITEV };
    delete process.env.RENDER; delete process.env.STRIPE_USKLADITEV; process.env.NODE_ENV = "test";
    assert(nov().zazeni() === null, "lokalno/CI (brez RENDER) privzeto izklopljeno");
    process.env.NODE_ENV = "production";
    assert(nov().zazeni() === null, "N1: NODE_ENV=production brez RENDER in brez STRIPE_USKLADITEV=1 NE vklopi delavca");
    process.env.NODE_ENV = "test";
    process.env.STRIPE_USKLADITEV = "1"; process.env.STRIPE_USKLADITEV_ZAGON_MS = "60000";
    const casEks = nov().zazeni();
    assert(casEks && typeof casEks.ustavi === "function", "N1: STRIPE_USKLADITEV=1 eksplicitno vklopi tudi brez RENDER");
    if (casEks) casEks.ustavi();
    delete process.env.STRIPE_USKLADITEV; delete process.env.STRIPE_USKLADITEV_ZAGON_MS;
    process.env.STRIPE_USKLADITEV = "0"; process.env.RENDER = "1";
    assert(nov().zazeni() === null, "STRIPE_USKLADITEV=0 izklopi tudi na Renderju");
    delete process.env.STRIPE_USKLADITEV;
    process.env.STRIPE_USKLADITEV_ZAGON_MS = "60000";
    const cas1 = nov().zazeni();
    assert(cas1 && typeof cas1.ustavi === "function", "na Renderju privzeto vklopljeno (casovnik z ustavi())");
    cas1.ustavi(); delete process.env.STRIPE_USKLADITEV_ZAGON_MS;
    for (const [k, v] of [["RENDER", stari_env.r], ["NODE_ENV", stari_env.n], ["STRIPE_USKLADITEV", stari_env.s]]) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }

    const zDanes = (danes, ura) => nov({ danes: async () => ({ danes, ura }) });
    let k = await zDanes("2026-10-27", 3).kandidati();
    assert(k.join() === "2026-10-20,2026-10-21,2026-10-22,2026-10-23,2026-10-24,2026-10-25" , "ob 03:00 vceraj (26. 10.) se ni na vrsti; okno 7 dni od 20. 10.", k);
    k = await zDanes("2026-10-27", 5).kandidati();
    assert(k.length === 7 && k[0] === "2026-10-20" && k[6] === "2026-10-26", "ob 05:00 je vceraj na vrsti (7 dni, najstarejsi najprej)", k);
    k = await zDanes("2026-10-22", 5).kandidati();
    assert(k.join() === "2026-10-19,2026-10-20,2026-10-21", "ni dnevov pred zacetkom zivega nacina (19. 10. 2026 je prvi)", k);
    k = await zDanes("2026-10-19", 5).kandidati();
    assert(k.length === 0, "na dan zacetka zivega nacina se se ni kaj usklajevati", k);
    const { veljavenDan } = require("../uskladitev_stripe");
    assert(veljavenDan("2026-10-20") && veljavenDan("2028-02-29") && !veljavenDan("2026-13-01") && !veljavenDan("2026-02-30") && !veljavenDan("2026-10-2") && !veljavenDan(null) && !veljavenDan("2026-10-20; DROP"), "veljavenDan: samo pravi koledarski datumi, brez izjeme za 2026-13-01");
    const neveljaven = await U.obdelajDan("2026-02-30");
    assert(neveljaven.preskoceno === "neveljaven_dan" && F.zahtevki.length === 0, "neveljaven dan: preskoceno, brez Stripovih klicev");
    // krog dohiti do 4 dni na krog; ze opravljeni dnevi izpadejo
    await cisto();
    const K = zDanes("2026-10-27", 5);
    const k1 = await K.krog();
    assert(k1.obdelani.length === 4 && k1.obdelani.every((r) => r.stanje === "ok") && k1.obdelani[0].dan === "2026-10-20", "prvi krog: 4 najstarejsi dnevi (dohitevanje po izpadu)", k1);
    const k2 = await K.krog();
    assert(k2.obdelani.length === 3 && k2.obdelani[2].dan === "2026-10-26", "drugi krog: preostali 3", k2);
    const k3 = await K.krog();
    assert(k3.obdelani.length === 0 && (await vseVrstice()).length === 7, "tretji krog: nic za delati, 7 vrstic", k3);
    // krog med krogom
    F.drzi = 1; await pool.query("TRUNCATE stripe_uskladitve"); F.zahtevki = [];
    const dolg = K.krog();
    await cakajDrzane(1);
    const vzporedni = await K.krog();
    assert(vzporedni.preskoceno === "tece", "krog, ki ze tece, se ne zacne se enkrat (isti proces)", vzporedni);
    F.drzene[0](); await dolg;
    // trajno neuspesni najstarejsi dnevi ne zasedejo kroga: `napaka` mlajsa od 3 h je ne na vrsti, `tece` mlajsa od 15 min tudi
    await cisto();
    await pool.query(`INSERT INTO stripe_uskladitve (dan, stanje, izvedeno_at, napaka_koda) VALUES ('2026-10-20', 'napaka', NOW() - INTERVAL '10 minutes', 'x'), ('2026-10-21', 'napaka', NOW() - INTERVAL '10 minutes', 'x'),
      ('2026-10-22', 'napaka', NOW() - INTERVAL '10 minutes', 'x'), ('2026-10-23', 'napaka', NOW() - INTERVAL '10 minutes', 'x')`);
    await pool.query("INSERT INTO stripe_uskladitve (dan, stanje, zacetek_at) VALUES ('2026-10-24', 'tece', NOW() - INTERVAL '2 minutes')");
    k = await K.kandidati();
    assert(k.join() === "2026-10-25,2026-10-26", "napaka < 3 h in sveza `tece` nista kandidata: novejsa dneva prideta na vrsto", k);
    const kk = await K.krog();
    assert(kk.obdelani.length === 2 && kk.obdelani.every((r) => r.stanje === "ok"), "krog obdela novejsa dneva, ceprav so starejsi v napaki", kk);
    await pool.query("UPDATE stripe_uskladitve SET izvedeno_at = NOW() - INTERVAL '4 hours' WHERE stanje = 'napaka'");
    k = await K.kandidati();
    assert(k.join() === "2026-10-20,2026-10-21,2026-10-22,2026-10-23", "po 3 h so dnevi z napako spet na vrsti (najstarejsi najprej)", k);
    // napaka ene dneva ne ustavi drugih
    await cisto();
    F.napaka = 401;
    const kn = await zDanes("2026-10-27", 5).krog();
    assert(kn.obdelani.length === 4 && kn.obdelani.every((r) => r.stanje === "napaka"), "Stripe napaka: krog ne vrze, vsi dnevi `napaka`", kn);
    F.napaka = 0;
    // baza nedosegljiva: krog ne vrze
    const slabaBaza = new Pool({ connectionString: "postgres://postgres:postgres@localhost:1/x", max: 1, connectionTimeoutMillis: 500 });
    slabaBaza.on("error", () => {});
    const kb = await ustvari({ pool: slabaBaza, SQL_TESTNO_NAROCILO, stripe: () => sdk, jeLive: () => true, log: { log() {}, error() {} } }).krog();
    assert(kb && Array.isArray(kb.obdelani) && !!kb.napaka, "baza nedosegljiva: krog ne vrze, vrne napako", kb);
    await slabaBaza.end().catch(() => {});

    // ------------------------------------------------------------------ 7. samo branje, glavni pool
    console.log("\n# 7. Samo branje Stripa, brez skenPool");
    const vsiZahtevki = [];
    await cisto();
    const nz = await narocilo({ pi: "pi_1" }); naboj(1, { metadata: { order_id: String(nz) } }); spor("dp_9", { charge: "ch_1" });
    await U.obdelajDan(D);
    vsiZahtevki.push(...F.zahtevki);
    assert(vsiZahtevki.length > 0 && vsiZahtevki.every((z) => z.method === "GET"), "vsi Stripovi klici so GET", [...new Set(vsiZahtevki.map((z) => z.method))]);
    const koda = fs.readFileSync(path.join(__dirname, "..", "uskladitev_stripe.js"), "utf8");
    assert(!/skenPool/.test(koda.replace(/\/\/.*$/gm, "")), "uskladitev_stripe.js ne uporablja skenPool (I16)");
    assert(!/\bs\.(charges|refunds|disputes|paymentIntents|transfers|accounts)\.(create|update|close|cancel|capture|confirm|del)\(/.test(koda), "v modulu ni Stripovih klicev za pisanje");

    // ------------------------------------------------------------------ 8. S1: povezava z neznanim stanjem se unici
    console.log("\n# 8. Povezava iz poola: neznano stanje transakcije -> release(true)");
    const EventEmitter = require("events");
    const NIKOLI = Symbol("nikoli");
    // skripta: (sql) => NIKOLI (poizvedba nikoli ne odgovori) | Error (zavrne) | objekt (odgovor)
    const lazni = (skripta) => {
      const rel = [], clients = [];
      const p = { connect: async () => { const c = new EventEmitter(); clients.push(c); c.query = (sql) => { const x = skripta(String(sql)); return x === NIKOLI ? new Promise(() => {}) : x instanceof Error ? Promise.reject(x) : Promise.resolve(x); }; c.release = (x) => { rel.push(x); }; return c; } };
      return { p, rel, clients };
    };
    const tih = { log() {}, error() {} };
    const mk = (L) => ustvari({ pool: L.p, dbRokMs: 40, SQL_TESTNO_NAROCILO: "FALSE", stripe: () => ({}), jeLive: () => true, log: tih });
    const zacetek = (q) => /^BEGIN/.test(q), konec = (q) => q === "COMMIT", povrni = (q) => q === "ROLLBACK";
    const pot = (U2) => { let h; U2.registriraj({ get: (_p, fn) => { h = fn; } }); return async () => { const o = { code: 200, body: null }; const res = { set() {}, status(c) { o.code = c; return res; }, json(b) { o.body = b; return res; } }; await h({ query: {} }, res); return o; }; };

    let L = lazni((q) => (zacetek(q) ? NIKOLI : { rows: [] }));
    let e1 = await mk(L).kandidati().then(() => null, (e) => e);
    assert(e1 && e1.koda === "db_rok" && L.rel.length === 1 && L.rel[0] === true, "S1: BEGIN nikoli ne odgovori (kandidati): release(true)", { koda: e1 && e1.koda, rel: L.rel });
    L = lazni((q) => (zacetek(q) ? NIKOLI : { rows: [] }));
    const o1 = await mk(L).obdelajDan("2026-10-20");
    assert(o1.stanje === "napaka" && L.rel.length >= 1 && L.rel.every((x) => x === true), "S1: BEGIN nikoli ne odgovori (obdelajDan / zahtevaj): vsi release(true), brez izjeme", { o1, rel: L.rel });
    L = lazni((q) => (zacetek(q) ? NIKOLI : { rows: [] }));
    const kr1 = await mk(L).krog();
    assert(kr1 && !!kr1.napaka && L.rel.length >= 1 && L.rel.every((x) => x === true), "S1: BEGIN nikoli ne odgovori (krog): krog ne vrze, release(true)", { kr1, rel: L.rel });
    L = lazni((q) => (zacetek(q) ? NIKOLI : { rows: [] }));
    let ro = await pot(mk(L))();
    assert(ro.code === 500 && L.rel.length === 1 && L.rel[0] === true, "S1: BEGIN nikoli ne odgovori (GET /admin/api/uskladitve): 500 in release(true)", { ro, rel: L.rel });
    L = lazni((q) => (zacetek(q) ? new Error("permission denied") : { rows: [] }));
    e1 = await mk(L).kandidati().then(() => null, (e) => e);
    assert(e1 && L.rel.length === 1 && L.rel[0] === true, "S1: BEGIN zavrnjen z napako (stanje povezave neznano): release(true)", L.rel);
    L = lazni((q) => (zacetek(q) || povrni(q) ? { rows: [] } : new Error("boom")));
    ro = await pot(mk(L))();
    assert(ro.code === 500 && L.rel.length === 1 && L.rel[0] === false, "napaka v fn, ROLLBACK uspe (cista povezava): release(false)", { ro, rel: L.rel });
    L = lazni((q) => (zacetek(q) ? { rows: [] } : povrni(q) ? NIKOLI : new Error("boom")));
    ro = await pot(mk(L))();
    assert(ro.code === 500 && L.rel.length === 1 && L.rel[0] === true, "napaka v fn, ROLLBACK nikoli ne odgovori: release(true)", L.rel);
    L = lazni((q) => (zacetek(q) ? { rows: [] } : povrni(q) ? new Error("rollback ni uspel") : new Error("boom")));
    ro = await pot(mk(L))();
    assert(ro.code === 500 && L.rel.length === 1 && L.rel[0] === true, "napaka v fn, ROLLBACK zavrnjen: release(true)", L.rel);
    L = lazni((q) => (zacetek(q) ? { rows: [] } : NIKOLI));
    ro = await pot(mk(L))();
    assert(ro.code === 500 && L.rel.length === 1 && L.rel[0] === true, "rok v fn (poizvedba nikoli ne odgovori): release(true)", L.rel);
    L = lazni((q) => (konec(q) ? NIKOLI : { rows: [] }));
    ro = await pot(mk(L))();
    assert(ro.code === 500 && L.rel.length === 1 && L.rel[0] === true, "COMMIT nikoli ne odgovori: release(true)", L.rel);
    L = lazni(() => ({ rows: [] }));
    ro = await pot(mk(L))();
    assert(ro.code === 200 && L.rel.length === 1 && L.rel[0] === false, "uspesna transakcija (BEGIN, SELECT, COMMIT): release(false), povezava gre nazaj v pool", { ro, rel: L.rel });
    L = lazni((q) => { if (/^SELECT/.test(q)) L.clients[0].emit("error", new Error("povezava prekinjena")); return { rows: [] }; });
    ro = await pot(mk(L))();
    assert(L.rel.length === 1 && L.rel[0] === true, "`error` na povezavi med transakcijo: release(true)", L.rel);
  } finally {
    await pool.query("TRUNCATE stripe_uskladitve, spori, orders").catch(() => {});   // druge teste (opozorila, Danes) ne smejo motiti ostanki
    await pool.end().catch(() => {});
    stripeStreznik.close();
  }
  console.log(`\n${ok} OK, ${fail} NAPAK`);
  process.exit(fail ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(1); });
