#!/usr/bin/env node
/**
 * Vracilo iz Stripove nadzorne plosce -> mail kupcu (issue #309, migracija 053). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_vracilo_iz_stripa.js
 * Vzorec kot test_potrdilo_kupcu.js: lokalni JWKS, lazni Stripe (STRIPE_API_BASE), lazni Resend (RESEND_BASE_URL), backend na svojem portu.
 *
 *   1  polno vracilo v plosci: natanko en mail na Stripovo vracilo (podvojen in ponovljen webhook ga ne podvojita), celoten znesek, vstopnice ne veljajo; gost dobi mail na svoj naslov
 *   2  vsako vracilo svoj mail (Martin 20. 10. 2026): znesek vracila + skupaj vrnjeno, delno = vstopnice veljavne, zadnje = »vrnjen celoten znesek«, vstopnice ne veljajo;
 *      dve vracili med izpadom Resenda = dva maila; socasna webhooka dveh vracil = natanko dva maila; naboj brez seznama vracil (nadomestna pot)
 *   3  nase vracilo (vrstica v `vracila`): mail o vracilu iz plosce NE gre (obvesca obdelovalec vracil); vrstica `preklicano` ga ne ustavi
 *   4  prodajalec platforma (I50): brez »posrednik« in brez »klub«
 *   5  mail ne blokira webhooka (Resend visi): webhook 200 takoj, mail pozneje natanko enkrat; Resend napaka: webhook 200
 *   6  izbrisan racun: brez maila, en alarm brez e-naslova
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");
const Stripe = require("stripe");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3361, JWKS_PORT = 3362, STRIPE_PORT = 3363, RESEND_PORT = 3364;
const BASE = `http://127.0.0.1:${PORT}`;
const WHSEC = "whsec_test_iz_stripa";
const stripeLokalno = new Stripe("sk_test_lokalno");

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-iz-stripa";
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
async function api(method, path, token, body) {
  const r = await fetch(BASE + path, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}
const pocakaj = (ms) => new Promise(r => setTimeout(r, ms));
async function cakaj(pogoj, ms = 8000) { const do_ = Date.now() + ms; while (Date.now() < do_) { if (await pogoj()) return true; await pocakaj(100); } return false; }

// ---------- lazni Resend ----------
const R = { poslano: [], napaka: false, drzi: false, zadrzani: [], zavrnjenih: 0, zavrni429: null };   // zavrni429: (mail) => true -> en odgovor 429 za ta mail   // zavrnjenih: zahtevki, ki jih je stub zavrnil (napaka = true)
const resendServer = http.createServer((req, res) => {
  let d = ""; req.on("data", x => d += x);
  req.on("end", () => {
    if (req.method === "POST" && req.url === "/emails") {
      if (R.napaka) { R.zavrnjenih++; res.writeHead(422, { "content-type": "application/json" }); return res.end(JSON.stringify({ name: "validation_error", message: "stub: zavrnjeno", statusCode: 422 })); }
      const m = JSON.parse(d);
      if (R.zavrni429 && R.zavrni429(m)) { R.zavrni429 = null; R.zavrnjenih++; res.writeHead(429, { "content-type": "application/json" }); return res.end(JSON.stringify({ name: "rate_limit_exceeded", message: "stub: 429", statusCode: 429 })); }
      const koncaj = () => { R.poslano.push(m); res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ id: "mail_" + R.poslano.length })); };
      if (R.drzi) { R.zadrzani.push(koncaj); return; }
      return koncaj();
    }
    res.writeHead(404, { "content-type": "application/json" }); res.end("{}");
  });
});
const sprosti = () => { R.drzi = false; for (const k of R.zadrzani.splice(0)) k(); };
const mailiNa = (email) => R.poslano.filter(m => m.to === email || (Array.isArray(m.to) && m.to.includes(email)));
const mailPo = (ref) => R.poslano.filter(m => String(m.subject).includes(ref));

// ---------- lazni Stripe (samo naboji: webhook prebere svez objekt) ----------
const S = { ch: {} };
const stripeServer = http.createServer((req, res) => {
  let d = ""; req.on("data", x => d += x);
  req.on("end", () => {
    const odg = (st, o) => { res.writeHead(st, { "content-type": "application/json", "request-id": "req_test" }); res.end(JSON.stringify(o)); };
    const u = req.url.split("?")[0];
    const m = u.match(/^\/v1\/charges\/(ch_\w+)$/);
    if (req.method === "GET" && m) {
      const ch = S.ch[m[1]];
      if (!ch) return odg(404, { error: { type: "invalid_request_error", message: "No such charge" } });
      const { vracila, brezSeznama, ...o } = ch;
      const razsiri = [...new URL(req.url, "http://x").searchParams].some(([k, v]) => /^expand/.test(k) && v === "refunds");
      return odg(200, razsiri && !brezSeznama ? { ...o, refunds: { object: "list", has_more: false, data: vracila } } : o);   // brezSeznama: kot stari lazni Stripe (nadomestna pot)
    }
    return odg(404, { error: { type: "invalid_request_error", message: "Lazni Stripe: neznana pot " + req.method + " " + u } });
  });
});
let stDogodka = 0;
async function webhook(objekt, id) {
  const d = { id: id || `evt_izs_${++stDogodka}`, object: "event", type: "charge.refunded", data: { object: objekt }, created: Math.floor(Date.now() / 1000) };
  const payload = JSON.stringify(d);
  const glava = stripeLokalno.webhooks.generateTestHeaderString({ payload, secret: WHSEC });
  const t0 = Date.now();
  const r = await fetch(BASE + "/stripe/webhook", { method: "POST", headers: { "content-type": "application/json", "stripe-signature": glava }, body: payload });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, ms: Date.now() - t0 };
}
// Vracilo v plosci: Stripe poveca amount_refunded naboja in poslje charge.refunded.
// Vracilo v plosci: Stripe ustvari vracilo re_… (brez nasega metadata), poveca amount_refunded naboja in poslje charge.refunded.
let stVracil = 0;
const vrniBrezWebhooka = (chId, skupajVrnjeno) => {
  const ch = S.ch[chId], znesek = skupajVrnjeno - ch.amount_refunded;
  ch.vracila.push({ id: "re_izs_" + (++stVracil), object: "refund", amount: znesek, status: "succeeded", charge: chId, created: 1760000000 + stVracil, metadata: {} });
  ch.amount_refunded = skupajVrnjeno; ch.refunded = skupajVrnjeno >= ch.amount;
};
const vrniVPlosci = (chId, skupajVrnjeno, id) => { vrniBrezWebhooka(chId, skupajVrnjeno); return webhook({ id: chId, object: "charge" }, id); };

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, stripe_events, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  await new Promise(r => stripeServer.listen(STRIPE_PORT, r));
  await new Promise(r => resendServer.listen(RESEND_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, QR_SECRET: "test", APP_URL: "https://outly.test",
    STRIPE_API_BASE: `http://127.0.0.1:${STRIPE_PORT}`, STRIPE_SECRET_KEY: "sk_test_lokalno", STRIPE_WEBHOOK_SECRET: WHSEC, STRIPE_POSPRAVI_MS: "3600000", TEST_PLACILA: "",
    RESEND_API_KEY: "re_test", RESEND_BASE_URL: `http://127.0.0.1:${RESEND_PORT}`, EMAIL_FROM: "Outly <test@outly.test>",
    GOST_POSTA_PONOVI_MS: "200", GOST_POSTA_TIMEOUT_MS: "400", GOST_POSTA_REZERVA_MS: "0", GOST_POSTA_PREMOR_MS: "100", VRACILA_TICK_MS: "0", JAVNI_PREDPOMNILNIK_MS: "0" },
    stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", x => log += x); srv.stderr.on("data", x => log += x);
  for (let i = 0; i < 80; i++) { try { await fetch(BASE + "/"); break; } catch { await pocakaj(100); } }

  try {
    const imena = ["lastnik", "ana", "bor", "cene"];
    const T = {}, U = {};
    imena.forEach((k, i) => { T[k] = zeton(`${k}@outly.si`, uuid(i + 1)); });
    for (const k of imena) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); U[k] = r.body.id; }
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city, address, contact_phone, contact_email) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Stripe Club', 'Ljubljana', 'Slovenska 1', '+38640111222', 'info@stripe-club.si')");
    await pool.query("UPDATE clubs SET stripe_account_id='acct_test1', stripe_charges_enabled=TRUE, stripe_payouts_enabled=TRUE WHERE id=1");
    const r0 = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Plosca noc", startAt: new Date(Date.now() + 24 * 3600 * 1000).toISOString(), ticketPriceCents: 2000, capacity: 500, minAge: 0 });
    assert(r0.status === 201, "dogodek", r0.body);
    const ev = r0.body.id;
    let stRef = 0;
    // Placano naroceno neposredno v bazi (nakupne poti pokrivajo drugi testi) + naboj v laznem Stripu.
    const narocilo = async ({ uporabnik = null, gost = null, kolicina = 1, cena = 2000, racun = "acct_test1", email }) => {
      const ref = "OUT-IZS" + String(++stRef).padStart(3, "0"), pi = "pi_izs_" + stRef, ch = "ch_izs_" + stRef, skupaj = kolicina * cena;
      const r = await pool.query(
        `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, currency, application_fee_cents, status, stripe_payment_intent_id, buyer_email, paid_at,
                             stripe_account_id, stripe_checkout_session_id, guest_email, guest_terms_version, guest_terms_accepted_at)
         VALUES ($1,$2,$3,1,$4,$5,$6,'EUR',$7,'paid',$8,$9,NOW(),$10,$11,$12,CASE WHEN $12::text IS NULL THEN NULL ELSE 'v1' END,CASE WHEN $12::text IS NULL THEN NULL ELSE NOW() END) RETURNING id`,
        [ref, uporabnik, ev, kolicina, cena, skupaj, racun === "platform" ? 0 : Math.round(skupaj * 0.1), pi, email || gost || `u${uporabnik}@outly.si`, racun, "cs_test_izs_" + stRef, gost]);
      const id = r.rows[0].id;
      await pool.query("INSERT INTO tickets (order_id, event_id) SELECT $1, $2 FROM generate_series(1, $3::int)", [id, ev, kolicina]);
      S.ch[ch] = { id: ch, object: "charge", payment_intent: pi, amount: skupaj, amount_refunded: 0, refunded: false, currency: "eur", metadata: { order_id: String(id) }, vracila: [] };
      return { id, ref, ch, email: email || gost || `u${uporabnik}@outly.si` };
    };
    const vrstica = async (id) => (await pool.query("SELECT status, refunded_cents FROM orders WHERE id=$1", [id])).rows[0];
    const zapisi = async (ch) => (await pool.query("SELECT * FROM vracila_iz_stripa WHERE charge_id=$1 ORDER BY skupaj_vrnjeno_cents", [ch])).rows;
    const zapis = async (ch) => (await zapisi(ch))[0];
    const vstopnice = async (id) => (await pool.query("SELECT status FROM tickets WHERE order_id=$1", [id])).rows.map(x => x.status);

    // ================================================================
    console.log("\n# 1. Polno vracilo v plosci: natanko en mail na vracilo");
    const O1 = await narocilo({ uporabnik: U.ana, kolicina: 2 });
    let w = await vrniVPlosci(O1.ch, 4000, "evt_izs_polno");
    assert(w.status === 200, "webhook charge.refunded: 200", w);
    let v = await vrstica(O1.id);
    assert(v.status === "refunded" && v.refunded_cents === 4000 && (await vstopnice(O1.id)).every(s => s === "refunded"), "naroceno refunded, vstopnice refunded (kot doslej)", v);
    assert(await cakaj(() => mailPo(O1.ref).length >= 1), "mail kupcu pride");
    w = await webhook({ id: O1.ch, object: "charge" }, "evt_izs_polno");   // isti dogodek
    assert(w.status === 200 && w.body.duplicate === true, "isti dogodek drugic: duplicate", w.body);
    w = await webhook({ id: O1.ch, object: "charge" });                    // nov dogodek za isti naboj (npr. charge.refunded po refund.updated)
    assert(w.status === 200, "drug dogodek za isti naboj: 200", w);
    await pocakaj(1200);
    let m = mailPo(O1.ref);
    assert(m.length === 1 && m[0].to === O1.email, "natanko en mail na vracilo (ponovljen in drug dogodek ga ne podvojita), na naslov narocila", m.map(x => x.to));
    const t1 = m[0] ? m[0].text : "";
    assert(m[0] && m[0].subject === `Vračilo / Refund: Plosca noc (${O1.ref})` && m[0].reply_to === "luka@outly.si", "zadeva dvojezicna, reply_to", m[0] && m[0].subject);
    assert(t1.includes("Vrnili smo vam celoten znesek 40,00 EUR") && t1.includes("We have refunded the full amount of 40.00 EUR") && t1.includes("Vstopnice tega naročila ne veljajo več.") && t1.includes("The tickets of this order are no longer valid."), "besedilo: celoten znesek iz Stripa (SL in EN), vstopnice ne veljajo", t1);
    assert(t1.includes(`Naročilo ${O1.ref}: 2 vstopnice`) && t1.includes("Glede dogodka se obrnite na klub (Stripe Club)") && !/odpovedan|cancelled/i.test(t1), "besedilo: narocilo, klub; NI »dogodek odpovedan«");
    assert(t1.indexOf("Vračilo opravljeno") < t1.indexOf("Refund completed"), "slovenski blok pred angleskim");
    const z1 = await zapis(O1.ch);
    assert(z1 && /^re_izs_/.test(z1.vracilo_id) && z1.znesek_cents === 4000 && z1.skupaj_vrnjeno_cents === 4000 && z1.valuta === "EUR" && z1.mail_poslano_at && z1.mail_poskusi === 1 && (await zapisi(O1.ch)).length === 1, "vracila_iz_stripa: ena vrstica (re_), 4000 c, EUR, poslano, en poskus", z1);
    assert(!log.includes(O1.email), "dnevnik brez e-naslova kupca");
    // gost (nakup brez racuna): mail na naslov nakupa
    const Og = await narocilo({ gost: "gost.plosca@example.com" });
    w = await vrniVPlosci(Og.ch, 2000);
    assert(w.status === 200 && await cakaj(() => mailiNa("gost.plosca@example.com").length === 1), "gost: mail o vracilu na naslov nakupa");

    // ================================================================
    console.log("\n# 2. Delna vracila: vsako vracilo svoj mail (Martin 20. 10. 2026), znesek vracila + skupaj vrnjeno");
    const O2 = await narocilo({ uporabnik: U.bor, kolicina: 3 });
    w = await vrniVPlosci(O2.ch, 1000);
    assert(w.status === 200 && (await vrstica(O2.id)).status === "partially_refunded", "delno: partially_refunded");
    assert(await cakaj(() => mailPo(O2.ref).length >= 1), "mail o prvem delnem vracilu");
    m = mailPo(O2.ref);
    assert(m[0].text.includes("Vrnili smo vam znesek 10,00 EUR") && m[0].text.includes("We have refunded the amount of 10.00 EUR") && !/celoten|full amount/.test(m[0].text), "delni znesek iz Stripa, brez »celoten«", m[0].text);
    assert(m[0].text.includes("Skupaj je za to naročilo vrnjeno 10,00 EUR od 60,00 EUR.") && m[0].text.includes("In total, 10.00 EUR of 60.00 EUR has been refunded"), "skupaj vrnjeno (SL in EN)", m[0].text);
    assert(m[0].text.includes("Vstopnice tega naročila ostanejo veljavne.") && (await vstopnice(O2.id)).every(s => s === "valid"), "delno: vstopnice ostanejo veljavne (besedilo = stanje)");
    w = await vrniVPlosci(O2.ch, 1500);
    assert(w.status === 200 && await cakaj(() => mailPo(O2.ref).length >= 2), "drugo delno vracilo: drugi mail");
    await pocakaj(1200);
    m = mailPo(O2.ref);
    assert(m.length === 2 && m[1].text.includes("Vrnili smo vam znesek 5,00 EUR") && m[1].text.includes("Skupaj je za to naročilo vrnjeno 15,00 EUR od 60,00 EUR.") && (await vrstica(O2.id)).refunded_cents === 1500, "drugi mail: 5 EUR tega vracila, skupaj 15 EUR; ni tretjega", m.map(x => x.text.slice(0, 90)));
    w = await vrniVPlosci(O2.ch, 6000);
    assert(w.status === 200 && await cakaj(() => mailPo(O2.ref).length >= 3), "tretje vracilo (ostanek): tretji mail");
    m = mailPo(O2.ref);
    assert(m[2].text.includes("Vrnili smo vam znesek 45,00 EUR") && m[2].text.includes("S tem je vrnjen celoten znesek naročila (60,00 EUR).") && m[2].text.includes("Vstopnice tega naročila ne veljajo več.") && m[2].text.includes("The tickets of this order are no longer valid.")
      && (await vstopnice(O2.id)).every(s => s === "refunded"), "zadnje vracilo: »vrnjen celoten znesek«, vstopnice ne veljajo (besedilo = stanje)", m[2].text);
    // dve vracili, preden mail odide (Resend je padel): dva maila, vsak s svojim zneskom
    R.napaka = true;
    const O3 = await narocilo({ uporabnik: U.bor, kolicina: 2 });
    const zavrnjeni3 = R.zavrnjenih;
    w = await vrniVPlosci(O3.ch, 500);
    assert(w.status === 200, "Resend zavrne: webhook vseeno 200", w);
    assert(await cakaj(() => R.zavrnjenih > zavrnjeni3), "prvi poskus: Resend ga je zavrnil", [R.zavrnjenih, zavrnjeni3]);
    w = await vrniVPlosci(O3.ch, 800);
    assert(w.status === 200 && (await zapisi(O3.ch)).map(x => [x.znesek_cents, x.skupaj_vrnjeno_cents]).join() === "500,500,300,800", "dve vrstici: 500 (skupaj 500) in 300 (skupaj 800)", await zapisi(O3.ch));
    R.napaka = false;
    assert(await cakaj(() => mailPo(O3.ref).length >= 2, 10000), "pospravljalec poslje oba, ko Resend spet dela");
    await pocakaj(1200);
    assert(mailPo(O3.ref).length === 2 && mailPo(O3.ref).some(x => x.text.includes("Vrnili smo vam znesek 5,00 EUR")) && mailPo(O3.ref).some(x => x.text.includes("Vrnili smo vam znesek 3,00 EUR") && x.text.includes("vrnjeno 8,00 EUR od 40,00 EUR")), "natanko dva maila (5 EUR in 3 EUR, skupaj 8)", mailPo(O3.ref).map(x => x.text.slice(0, 120)));
    assert(/Resend napaka \(vracilo iz Stripa/.test(log) && !log.includes(`u${U.bor}@outly.si`), "napaka Resenda v dnevniku brez e-naslova");
    // socasna webhooka dveh vracil (oba prebereta svez naboj z obema vraciloma) + ponovitev: natanko dva maila
    const O3b = await narocilo({ uporabnik: U.ana, kolicina: 1, cena: 2500 });
    vrniBrezWebhooka(O3b.ch, 1000); vrniBrezWebhooka(O3b.ch, 2500);
    const [wa, wb] = await Promise.all([webhook({ id: O3b.ch, object: "charge" }, "evt_izs_soc_a"), webhook({ id: O3b.ch, object: "charge" }, "evt_izs_soc_b")]);
    const wc = await webhook({ id: O3b.ch, object: "charge" }, "evt_izs_soc_a");
    assert(wa.status === 200 && wb.status === 200 && wc.body.duplicate === true, "socasna webhooka: oba 200, ponovitev duplicate", [wa.status, wb.status, wc.body]);
    assert(await cakaj(() => mailPo(O3b.ref).length >= 2), "dva maila");
    await pocakaj(1500);
    assert(mailPo(O3b.ref).length === 2 && (await zapisi(O3b.ch)).length === 2 && mailPo(O3b.ref).some(x => x.text.includes("Vrnili smo vam znesek 15,00 EUR") && x.text.includes("S tem je vrnjen celoten znesek")), "socasno: natanko dva maila (10 in 15 EUR), brez dvojnika", mailPo(O3b.ref).map(x => x.text.slice(0, 80)));
    // Vrstni red (I51): Resend zavrne mail STAREJSEGA vracila (429); novejse vracilo (s »vstopnice ne veljajo vec«) ne sme oditi pred njim, sicer bi kupec
    // kot zadnjega dobil »vstopnice ostanejo veljavne«, ceprav so vrnjene.
    const O3d = await narocilo({ uporabnik: U.ana, kolicina: 1, cena: 2500 });
    vrniBrezWebhooka(O3d.ch, 1000); vrniBrezWebhooka(O3d.ch, 2500);
    R.zavrni429 = (m) => String(m.subject).includes(O3d.ref) && /Vrnili smo vam znesek 10,00 EUR/.test(m.text || "");
    w = await webhook({ id: O3d.ch, object: "charge" });
    assert(w.status === 200 && await cakaj(() => mailPo(O3d.ref).length >= 2, 10000), "429 na prvem: oba maila odideta (pospravljalec ponovi)", mailPo(O3d.ref).length);
    await pocakaj(800);
    const m3d = mailPo(O3d.ref);
    assert(m3d.length === 2 && /znesek 10,00 EUR/.test(m3d[0].text) && /ostanejo veljavne/.test(m3d[0].text) && /znesek 15,00 EUR/.test(m3d[1].text) && /ne veljajo več/.test(m3d[1].text),
      "vrstni red po casu vracila: najprej 10 EUR (veljavne), nato 15 EUR (ne veljajo vec) - zadnji mail pove pravo stanje", m3d.map(x => x.text.slice(0, 80)));
    // naboj brez seznama vracil (nadomestna pot): vsako povecanje amount_refunded en mail
    const O3c = await narocilo({ uporabnik: U.ana, kolicina: 2 });
    S.ch[O3c.ch].brezSeznama = true;
    w = await vrniVPlosci(O3c.ch, 700);
    assert(w.status === 200 && await cakaj(() => mailPo(O3c.ref).length >= 1), "brez seznama: prvi mail");
    w = await webhook({ id: O3c.ch, object: "charge" });   // isti znesek (ponovljen dogodek za isto vracilo): ni novega vracila
    await pocakaj(800);
    w = await vrniVPlosci(O3c.ch, 1000);
    assert(w.status === 200 && await cakaj(() => mailPo(O3c.ref).length >= 2), "brez seznama: drugo povecanje, drugi mail");
    await pocakaj(800);
    assert(mailPo(O3c.ref).length === 2 && mailPo(O3c.ref)[1].text.includes("Vrnili smo vam znesek 3,00 EUR") && (await zapisi(O3c.ch)).map(x => x.vracilo_id).join() === `${O3c.ch}@700,${O3c.ch}@1000`, "brez seznama: 7 EUR in 3 EUR, kljuca <ch>@<skupaj>", (await zapisi(O3c.ch)).map(x => x.vracilo_id));

    // ================================================================
    console.log("\n# 3. Nase vracilo (vrstica v `vracila`): mail iz plosce NE gre");
    const O4 = await narocilo({ uporabnik: U.cene });
    await pool.query("INSERT INTO vracila (order_id, event_id, razlog, stanje, znesek_cents, stripe_vracilo_id, stripe_stanje) VALUES ($1, $2, 'event_cancelled', 'opravljeno', 2000, 're_nase', 'succeeded')", [O4.id, ev]);
    w = await vrniVPlosci(O4.ch, 2000);
    await pocakaj(1500);
    assert(w.status === 200 && (await vrstica(O4.id)).status === "refunded" && mailPo(O4.ref).length === 0, "nase vracilo: stanje narocila kot doslej, mail iz plosce ne gre (obvesca obdelovalec)", mailPo(O4.ref).length);
    assert(!(await zapis(O4.ch)), "nase vracilo: vrstice v vracila_iz_stripa ni (pospravljalec je ne pregleduje)");
    // vrstica `vracila` nastane PO vracilu v plosci (npr. odpoved dogodka med cakanjem na mail): mail se odlozi, poskus se ne porabi
    R.napaka = true;
    const O4b = await narocilo({ uporabnik: U.cene });
    const zavrnjenihPrej = R.zavrnjenih;
    w = await vrniVPlosci(O4b.ch, 1000);
    // Dogodek: stub je ZAVRNIL prvi zahtevek (stevec poskusov v bazi naraste ze ob rezervaciji, PRED klicem Resenda; zahtevek je tedaj se lahko na poti in bi uspel po R.napaka = false)
    assert(w.status === 200 && await cakaj(() => R.zavrnjenih > zavrnjenihPrej), "delno v plosci, prvi mail ne uspe (Resend zavrnil)", [R.zavrnjenih, zavrnjenihPrej]);
    await pool.query("INSERT INTO vracila (order_id, event_id, razlog, stanje) VALUES ($1, $2, 'event_cancelled', 'caka')", [O4b.id, ev]);
    const p4 = (await zapis(O4b.ch)).mail_poskusi;
    R.napaka = false;
    await pocakaj(1500);
    const z4 = await zapis(O4b.ch);
    assert(mailPo(O4b.ref).length === 0 && z4.mail_poslano_at === null && z4.mail_poskusi === p4, "vrstica `vracila` po vracilu v plosci: mail odlozen, poskus ni porabljen", [mailPo(O4b.ref).length, z4.mail_poskusi, p4]);
    const O5 = await narocilo({ uporabnik: U.cene });
    await pool.query("INSERT INTO vracila (order_id, event_id, razlog, stanje) VALUES ($1, $2, 'event_cancelled', 'preklicano')", [O5.id, ev]);
    w = await vrniVPlosci(O5.ch, 2000);
    assert(w.status === 200 && await cakaj(() => mailPo(O5.ref).length === 1), "vrstica `preklicano` (dogodek obnovljen, denar se ni premaknil): mail gre");

    // ================================================================
    console.log("\n# 4. Prodajalec platforma (I50)");
    const O6 = await narocilo({ uporabnik: U.ana, racun: "platform" });
    w = await vrniVPlosci(O6.ch, 2000);
    assert(w.status === 200 && await cakaj(() => mailPo(O6.ref).length === 1), "platforma: mail pride");
    const t6 = mailPo(O6.ref)[0].text;
    assert(!/posrednik|intermediary|klub|club|organizator|organiser/i.test(t6) && t6.includes(`navedite naročilo ${O6.ref}`), "platforma: brez »posrednik«, »klub« in »organizator«", t6);

    // ================================================================
    console.log("\n# 5. Mail ne blokira webhooka");
    R.drzi = true;
    const O7 = await narocilo({ uporabnik: U.ana });
    w = await vrniVPlosci(O7.ch, 2000);
    assert(w.status === 200 && w.ms < 1500, "Resend visi: webhook 200 takoj", w.ms);
    assert(await cakaj(() => R.zadrzani.length >= 1, 3000), "mail je v Resendu (po COMMIT-u)");
    await pocakaj(300);
    sprosti();
    await pocakaj(1500);
    assert(mailPo(O7.ref).length === 1, "natanko en mail po sprostitvi (pospravljalec med pocasnim Resendom ni poslal drugega)", mailPo(O7.ref).length);

    // ================================================================
    console.log("\n# 6. Izbrisan racun: brez maila, en alarm");
    const O8 = await narocilo({ uporabnik: U.cene, email: "izbrisan-99@outly.invalid" });
    w = await vrniVPlosci(O8.ch, 2000);
    assert(w.status === 200 && await cakaj(async () => ((await zapis(O8.ch)) || {}).mail_poskusi >= 8), "poskusi izcrpani (naslova ni)");
    await pocakaj(800);
    assert(mailPo(O8.ref).length === 0 && (log.match(/ni obvescen o vracilu iz Stripove plosce/g) || []).length === 1 && !/izbrisan-99/.test(log), "brez maila, natanko en alarm brez e-naslova", (log.match(/ni obvescen o vracilu/g) || []).length);
    assert(!/TypeError|ReferenceError|Unhandled/.test(log), "dnevnik brez nepricakovanih napak", log.slice(-500));
    // ZVPot-1 7(1) drugi stavek (pravnik 2026-10-20): VSAK mail ima celotno ime firme in sedez posiljatelja (noga, nogaMaila v index.js)
    {
      const FIRMA = "NEXT DIMENSIONS, družba za marketing, d.o.o., Trebče 81, 3256 Bistrica ob Sotli";
      const vsi = R.poslano.concat(R.zamudnjena || []);
      const brezNoge = vsi.filter(m => !String(m.text || "").includes("Pošiljatelj / Sender: " + FIRMA) || !String(m.html || "").includes(FIRMA));
      const vrste = [...new Set(vsi.map(m => String(m.subject).split(":")[0]))].join(" | ");
      assert(vsi.length > 0 && brezNoge.length === 0, `noga s firmo in sedezem v vseh ${vsi.length} mailih (${vrste})`, brezNoge.map(m => m.subject).slice(0, 5));
    }
  } catch (e) {
    fail++; console.log("  ✗ IZJEMA v testu:", e && e.stack || e);
  } finally {
    srv.kill();
    jwksServer.close(); stripeServer.close(); resendServer.close();
    await pool.end();
    console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
    process.exit(fail ? 1 : 0);
  }
})().catch((e) => { console.error(e); process.exit(1); });
