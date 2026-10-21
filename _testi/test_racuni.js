#!/usr/bin/env node
/**
 * Davcno potrjeni racuni za lastne dogodke Outly: skupni del (I52, migracija 054, racuni.js; Martin 21. 10. 2026). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_racuni.js
 * Vzorec kot test_outly_lastni_dogodki.js (lokalni JWKS, lazni Stripe) + lazni ponudnik racunov (RACUNI_PONUDNIK=lazni, RACUNI_LAZNI_URL) in lazni Resend.
 *
 *   0  ciste funkcije: QR podatek 60 stevk (FURS tehnicna dokumentacija v2.9, pogl. 11, primera 1 in 2), QR 25 x 25, izbira ponudnika (izklopljen privzeto,
 *      lazni v produkciji zavrnjen, neznan izklopljen), vsebina racuna (vse obvezne postavke 4.1, brez e-naslova), blok za mail, firma = FIRMA_PLATFORME
 *   1  ponudnik IZKLOPLJEN (proces B): platformno narocilo placano -> natanko ena vrstica `caka` v ISTI transakciji kot paid (pospravljalec ne tece),
 *      podvojen webhook ne podvoji; vracilo -> dobropis `caka`; ponudnik ni klican; brez napak v dnevniku
 *   2  lazni ponudnik (proces A): vrsta B se obdela; dobropis NIKOLI pred racunom (stevilka za racunom, klic ponudnika po potrjenem racunu, tudi ko racun ponavlja)
 *   3  natanko en racun (podvojeni webhooki, pospravljalec); navaden klub, 0 EUR, testni promet (test_, cs_test_) -> brez racuna; pospravljalec ujame manjkajoc racun
 *      in manjkajoc dobropis (+ POZOR)
 *   4  zacasna napaka -> ponovitev z istim message_id, naknadno = true, nato potrjen; trajna -> `napaka` + POZOR, brez ponavljanja
 *   5  dobropis ob vracilu v Stripovi plosci (natanko enkrat, tudi ob ponovljenem webhooku) in ob odpovedi dogodka (natanko enkrat, tudi ko pride se webhook)
 *   6  sprozilec: DELETE racuna, sprememba stevilke / casa izdaje / zneska / ZOI / EOR, vrnitev v `caka`, stevec +2 in brisanje stevca -> zavrnjeno
 *   7  ~200 hkratnih izdaj (tretjina razveljavljenih transakcij): stevilke 1..N brez vrzeli in brez dvojnikov; cas izdaje sledi stevilki
 *   8  I16: ponudnik visi -> webhook, nakup in sken ostanejo hitri, potrdilo kupcu pride, nobena povezava ne caka v transakciji med klicem ponudnika;
 *      vse stevilke A001-1 so na koncu neprekinjene
 *   9  rok klica ponudnika tece sele po mestu v semaforju (cakanje v vrsti ne porabi poskusa)
 *  10  S2: dobropis se izda sele za izvedeno vracilo: pending -> brez izdaje, succeeded -> izdaja, failed -> preklican + POZOR, ponovni poskus = nov dobropis
 *  11  S1: vpis dobropisa (FK) med odprto izdajo istega racuna ne caka; cakanje na stevec ne drzi vrstice racuna
 *  12  M1: ponudnik, ki se nikoli ne odzove, ne zasede semaforja (trd rok)
 */
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");
const Stripe = require("stripe");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT_A = 3381, PORT_B = 3382, JWKS_PORT = 3383, STRIPE_PORT = 3384, RESEND_PORT = 3385, PONUDNIK_PORT = 3386;
const WHSEC = "whsec_test_racuni";
const stripeLokalno = new Stripe("sk_test_lokalno");
const racuni = require("../racuni");

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-racuni";
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
  const p = b64u({ iss: `http://127.0.0.1:${JWKS_PORT}/auth/v1`, aud: "authenticated", sub, email, exp: now + 3600, iat: now,
    user_metadata: { email_verified: true, username: email.split("@")[0].replace(/[^a-z0-9_]/gi, "") } });
  const sig = crypto.sign("sha256", Buffer.from(h + "." + p), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return h + "." + p + "." + sig.toString("base64url");
}
const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra).slice(0, 600) : ""); } }
let ipStevec = 0;
async function api(baza, method, p, token, body, glave = {}) {
  const r = await fetch(baza + p, { method, headers: { "content-type": "application/json", "x-forwarded-for": `10.77.${(++ipStevec >> 8) & 255}.${(ipStevec & 255) + 1}`, ...(token ? { authorization: "Bearer " + token } : {}), ...glave },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, text: t };
}
const pocakaj = (ms) => new Promise((r) => setTimeout(r, ms));
async function cakaj(pogoj, ms = 15000) { const do_ = Date.now() + ms; while (Date.now() < do_) { if (await pogoj()) return true; await pocakaj(80); } return false; }

// ---------- lazni Resend ----------
const R = { poslano: [] };
const resendServer = http.createServer((req, res) => {
  let d = ""; req.on("data", (x) => d += x);
  req.on("end", () => {
    if (req.method === "POST" && req.url === "/emails") { R.poslano.push(JSON.parse(d)); res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify({ id: "mail_" + R.poslano.length })); }
    res.writeHead(404, { "content-type": "application/json" }); res.end("{}");
  });
});

// ---------- lazni ponudnik racunov (RACUNI_LAZNI_URL) ----------
// Nacin po narocilu (public_ref): ok (privzeto) | { zacasna: N } (N-krat 503, nato ok) | trajna (400) | visi (odgovor sele, ko test nacin spremeni ali po 10 s).
const P = { klici: [], nacin: {}, privzeto: "ok", visijo: [] };
const ponudnikServer = http.createServer((req, res) => {
  let d = ""; req.on("data", (x) => d += x);
  req.on("end", () => {
    let p = {}; try { p = JSON.parse(d); } catch (_) { /* prazno */ }
    const klic = { t: Date.now(), id: p.id, vrsta: p.vrsta, narocilo: p.narocilo, message_id: p.message_id, kljuc: req.headers["idempotency-key"], naknadno: p.naknadno, podatki: p };
    P.klici.push(klic);
    const nacin = P.nacin[p.narocilo] !== undefined ? P.nacin[p.narocilo] : P.privzeto;
    const odg = (st, o) => { if (res.writableEnded) return; res.writeHead(st, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
    const uspeh = () => odg(200, { eor: crypto.randomUUID(), zoi: crypto.createHash("md5").update(String(p.message_id)).digest("hex"), ponudnik_id: "doc-" + p.id });
    if (nacin && typeof nacin === "object" && nacin.zacasna > 0) { nacin.zacasna--; klic.izid = "zacasna"; return odg(503, { error: "busy" }); }
    if (nacin === "trajna") { klic.izid = "trajna"; return odg(400, { error: "invalid invoice" }); }
    if (nacin === "pocasi") { klic.izid = "ok"; return setTimeout(uspeh, 250); }
    if (nacin === "visi") {
      klic.izid = "visi";
      const t = setTimeout(() => odg(503, { error: "timeout" }), 10000);
      P.visijo.push(() => { clearTimeout(t); odg(503, { error: "late" }); });
      return;
    }
    klic.izid = "ok";
    return uspeh();
  });
});
const sprostiVisece = () => { const v = P.visijo.splice(0); for (const f of v) f(); };
const klicaZa = (ref) => P.klici.filter((k) => k.narocilo === ref);

// ---------- lazni Stripe (platforma: naboj brez transferja; navaden klub: destination charge) ----------
const S = { seje: {}, stSej: 0, pi: {}, ch: {}, refundi: [], reById: {}, idem: {}, stR: 0 };
const obrazec = (t) => { const o = {}; for (const [k, v] of new URLSearchParams(t)) o[k] = v; return o; };
const meta = (p) => { const md = {}; for (const [k, v] of Object.entries(p)) { const mm = k.match(/^metadata\[(\w+)\]$/); if (mm) md[mm[1]] = v; } return md; };
const stripeServer = http.createServer((req, res) => {
  let d = ""; req.on("data", (x) => d += x);
  req.on("end", () => {
    const url = new URL(req.url, "http://x");
    const u = url.pathname, p = obrazec(d), kljuc = req.headers["idempotency-key"];
    const odg = (st, o) => { res.writeHead(st, { "content-type": "application/json", "request-id": "req_test", "stripe-should-retry": "false" }); res.end(JSON.stringify(o)); };
    const napaka = (st, code, msg) => odg(st, { error: { type: "invalid_request_error", ...(code ? { code } : {}), message: msg } });
    let m;
    if (req.method === "POST" && u === "/v1/checkout/sessions") {
      const obst = Object.values(S.seje).find((s) => s._kljuc === kljuc);
      if (obst) return odg(200, obst);
      const id = "cs_live_r" + (++S.stSej);
      const kol = Number(p["line_items[0][quantity]"]), cena = Number(p["line_items[0][price_data][unit_amount]"]);
      S.seje[id] = { id, object: "checkout.session", livemode: true, _kljuc: kljuc, _platforma: !p["payment_intent_data[transfer_data][destination]"],
        url: `https://checkout.stripe.test/c/pay/${id}`, status: "open", payment_status: "unpaid", amount_total: kol * cena, currency: p["line_items[0][price_data][currency]"],
        client_reference_id: p.client_reference_id, metadata: { order_id: p["metadata[order_id]"] }, expires_at: Number(p.expires_at), payment_intent: null };
      return odg(200, S.seje[id]);
    }
    if (req.method === "GET" && (m = u.match(/^\/v1\/checkout\/sessions\/(cs_\w+)$/))) return S.seje[m[1]] ? odg(200, S.seje[m[1]]) : napaka(404, "resource_missing", "No such session");
    if (req.method === "GET" && (m = u.match(/^\/v1\/payment_intents\/(\w+)$/))) {
      const pi = S.pi[m[1]]; if (!pi) return napaka(404, "resource_missing", "No such payment_intent");
      const razsiri = [...url.searchParams].some(([k, v]) => /^expand/.test(k) && /^latest_charge/.test(v));
      return odg(200, razsiri ? { ...pi, latest_charge: S.ch[pi.latest_charge] } : pi);
    }
    if (req.method === "GET" && (m = u.match(/^\/v1\/charges\/(\w+)$/))) {
      const ch = S.ch[m[1]]; if (!ch) return napaka(404, "resource_missing", "No such charge");
      const razsiri = [...url.searchParams].some(([k, v]) => /^expand/.test(k) && v === "refunds");
      return odg(200, razsiri ? { ...ch, refunds: { object: "list", has_more: false, data: S.refundi.filter((x) => x.charge === ch.id).map((x) => S.reById[x.id]) } } : ch);
    }
    if (req.method === "GET" && (m = u.match(/^\/v1\/refunds\/(re_\w+)$/))) return S.reById[m[1]] ? odg(200, S.reById[m[1]]) : napaka(404, "resource_missing", "No such refund");
    if (req.method === "GET" && u === "/v1/refunds") return odg(200, { object: "list", has_more: false, data: S.refundi.filter((r) => r.payment_intent === url.searchParams.get("payment_intent")) });
    if (req.method === "POST" && u === "/v1/refunds") {
      if (kljuc && S.idem[kljuc]) return odg(200, S.idem[kljuc]);
      const pi = S.pi[p.payment_intent]; if (!pi) return napaka(404, "resource_missing", "No such payment_intent");
      const ch = S.ch[pi.latest_charge], ostane = ch.amount - ch.amount_refunded;
      if (!ch.transfer && (p.reverse_transfer !== undefined || p.refund_application_fee !== undefined)) return napaka(400, null, "This charge has no transfer or application fee.");
      if (ostane <= 0) return napaka(400, "charge_already_refunded", "Charge has already been refunded.");
      const re = vrni(pi.id, p.amount ? Number(p.amount) : ostane, meta(p));
      S.refundi[S.refundi.length - 1].kljuc = kljuc; if (kljuc) S.idem[kljuc] = re;
      return odg(200, re);
    }
    return napaka(404, null, "Lazni Stripe: neznana pot " + req.method + " " + u);
  });
});
function vrni(piId, znesek, metadata = {}, status = "succeeded") {
  const pi = S.pi[piId], ch = S.ch[pi.latest_charge];
  ch.amount_refunded += znesek;
  const re = { id: "re_r" + (++S.stR), object: "refund", amount: znesek, status, payment_intent: pi.id, charge: ch.id, metadata, created: Math.floor(Date.now() / 1000) + S.stR };
  S.reById[re.id] = re; S.refundi.push({ ...re });
  return re;
}
function placaj(sejaId) {
  const s = S.seje[sejaId], n = sejaId.replace(/\W/g, ""), pi = "pi_" + n;
  S.pi[pi] = { id: pi, object: "payment_intent", status: "succeeded", amount: s.amount_total, latest_charge: "ch_" + n, transfer_data: s._platforma ? null : { destination: "acct_ziv1" } };
  S.ch["ch_" + n] = { id: "ch_" + n, object: "charge", amount: s.amount_total, currency: "eur", amount_refunded: 0, payment_intent: pi, application_fee: null, transfer: s._platforma ? null : "tr_" + n };
  Object.assign(s, { status: "complete", payment_status: "paid", payment_intent: pi });
  return pi;
}
let stDogodka = 0;
async function webhook(baza, tip, objekt, id) {
  const dogodek = { id: id || `evt_r_${++stDogodka}`, object: "event", type: tip, data: { object: objekt }, created: Math.floor(Date.now() / 1000), livemode: true };
  const payload = JSON.stringify(dogodek);
  const glava = stripeLokalno.webhooks.generateTestHeaderString({ payload, secret: WHSEC });
  const t0 = Date.now();
  const r = await fetch(baza + "/stripe/webhook", { method: "POST", headers: { "content-type": "application/json", "stripe-signature": glava }, body: payload });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, id: dogodek.id, ms: Date.now() - t0 };
}

function zagon(port, okolje) {
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, QR_SECRET: "test", APP_URL: "https://outly.test",
    STRIPE_API_BASE: `http://127.0.0.1:${STRIPE_PORT}`, STRIPE_SECRET_KEY: "sk_live_lokalno", STRIPE_WEBHOOK_SECRET: WHSEC, TEST_PLACILA: "", JAVNI_PREDPOMNILNIK_MS: "0", PREVERI_OKNO_MS: "0",
    STRIPE_POSPRAVI_MS: "3600000", RESEND_API_KEY: "re_test", RESEND_BASE_URL: `http://127.0.0.1:${RESEND_PORT}`, EMAIL_FROM: "Outly <test@outly.test>", GOST_POSTA_PONOVI_MS: "0",
    VRACILA_MAIL_RAZMAK_MS: "0", RACUNI_PONUDNIK: "", RACUNI_LAZNI_URL: "", ...okolje }, stdio: ["ignore", "pipe", "pipe"] });
  const o = { srv, log: "" };
  srv.stdout.on("data", (d) => o.log += d); srv.stderr.on("data", (d) => o.log += d);
  return o;
}
async function cakajStreznik(baza) { for (let i = 0; i < 100; i++) { try { await fetch(baza + "/"); return; } catch { await pocakaj(100); } } }
async function ustavi(o) { if (!o || o.srv.exitCode !== null) return; const konec = new Promise((r) => o.srv.once("exit", r)); o.srv.kill("SIGTERM"); await Promise.race([konec, pocakaj(3000)]); }

(async () => {
  // ================================================================
  console.log("\n# 0. Ciste funkcije: QR (FURS pogl. 11), izbira ponudnika, vsebina racuna");
  {
    // FURS, Tehnicna dokumentacija v2.9 (25. 7. 2025), pogl. 11, str. 118-119: davcna 12345678, 15. 8. 2015 ob 10:13:32 (lokalni cas na racunu).
    const cas = new Date("2015-08-15T10:13:32+02:00");
    assert(racuni.qrPodatek("a7e5f55e1dbb48b799268e1a6d8618a3", "12345678", cas) === "223175087923687075112234402528973166755123456781508151013321",
      "QR primer 1 (FURS): 60 stevk, kontrolna stevka 1", racuni.qrPodatek("a7e5f55e1dbb48b799268e1a6d8618a3", "12345678", cas));
    assert(racuni.qrPodatek("3024e56bf1ddd2e7eeb5715c6859a913", "12345678", cas) === "063994519708649896901260100447252359443123456781508151013320",
      "QR primer 2 (FURS, vodilna nicla): kontrolna stevka 0", racuni.qrPodatek("3024e56bf1ddd2e7eeb5715c6859a913", "12345678", cas));
    assert(racuni.qrPodatek("A7E5F55E1DBB48B799268E1A6D8618A3", "12345678", cas).length === 60, "QR: velike crke ZOI enako, dolzina 60");
    const zim = racuni.qrPodatek("a7e5f55e1dbb48b799268e1a6d8618a3", "57469911", new Date("2026-01-05T23:30:00Z"));
    assert(zim.slice(39, 47) === "57469911" && zim.slice(47, 59) === "260106003000", "QR: cas izdaje v ljubljanskem casu (zima: 23:30 UTC = 6. 1. 00:30)", zim);
    let vrze = 0;
    for (const [z, ds] of [["xyz", "12345678"], ["a7e5f55e1dbb48b799268e1a6d8618a", "12345678"], ["a7e5f55e1dbb48b799268e1a6d8618a3", "SI123456"]]) { try { racuni.qrPodatek(z, ds, cas); } catch (_) { vrze++; } }
    assert(vrze === 3, "QR: napacen ZOI / davcna stevilka -> napaka");
    const m = racuni.qrMatrikaRacuna("223175087923687075112234402528973166755123456781508151013321");
    assert(m.n === 25 && typeof m.temen(0, 0) === "boolean" && m.temen(0, 0) === true, "QR matrika: 25 x 25 modulov (razlicica 2, popravljanje M), kot zahteva FURS", m.n);

    const iz = (env) => racuni.izberiPonudnika(env);
    assert(iz({}).ime === "izklopljen" && iz({}).ponudnik === null && iz({}).opozorilo === null, "brez RACUNI_PONUDNIK: izklopljen, brez opozorila");
    assert(iz({ RACUNI_PONUDNIK: "izklopljen" }).ponudnik === null, "RACUNI_PONUDNIK=izklopljen: izklopljen");
    assert(iz({ RACUNI_PONUDNIK: "lazni", RENDER: "true" }).ponudnik === null && /produkciji/.test(iz({ RACUNI_PONUDNIK: "lazni", RENDER: "true" }).opozorilo), "lazni ponudnik v produkciji (RENDER): izklopljen + opozorilo");
    assert(iz({ RACUNI_PONUDNIK: "lazni", NODE_ENV: "production" }).ponudnik === null, "lazni ponudnik ob NODE_ENV=production: izklopljen");
    assert(iz({ RACUNI_PONUDNIK: "e-racuni" }).ponudnik === null && /ne obstaja/.test(iz({ RACUNI_PONUDNIK: "e-racuni" }).opozorilo), "neznan / se ne narejen ponudnik: izklopljen + opozorilo (brez napake)");
    assert(iz({ RACUNI_PONUDNIK: "lazni" }).ime === "lazni" && typeof iz({ RACUNI_PONUDNIK: "lazni" }).ponudnik.potrdi === "function", "lazni ponudnik izven produkcije");

    const indeks = fs.readFileSync(path.join(__dirname, "..", "index.js"), "utf8");
    const fm = indeks.match(/const FIRMA_PLATFORME = "([^"]+)", SEDEZ_PLATFORME = "([^"]+)"/);
    assert(fm && fm[1] === racuni.IZDAJATELJ.firma && fm[2] === racuni.IZDAJATELJ.sedez, "izdajatelj racuna = FIRMA_PLATFORME / SEDEZ_PLATFORME (ena firma)", fm && fm.slice(1));
    assert(racuni.PLATFORMNI_RACUN === require("../placila_stripe").PLATFORMNI_RACUN, "oznaka platforme v racuni.js = placila_stripe.PLATFORMNI_RACUN");
    assert(!/skenPool\s*[.(,})]/.test(fs.readFileSync(path.join(__dirname, "..", "racuni.js"), "utf8").replace(/\/\/[^\n]*/g, "")), "racuni.js ne uporablja skenPool (I16; samo koda, brez komentarjev)");

    const vr = { vrsta: "racun", stevilka: 7, prostor: "A001", naprava: "1", izdan_at: new Date("2026-11-03T18:05:09Z"), znesek_cents: 3000, valuta: "EUR",
      eor: "a1b2c3d4-0000-4000-8000-000000000001", zoi: "a7e5f55e1dbb48b799268e1a6d8618a3" };
    const nr = { public_ref: "OUT-TEST1", quantity: 2, unit_price_cents: 1500, total_cents: 3000, title: "Outly Launch Party", start_at: new Date("2026-11-27T21:00:00Z"), buyer_email: "kupec@example.com" };
    const v = racuni.vsebinaRacuna(vr, nr);
    assert(v.stevilka === "A001-1-7" && v.datum_izdaje === "3. 11. 2026" && v.cas_izdaje === "19:05:09", "vsebina: stevilka A001-1-N, datum in CAS izdaje (ljubljanski)", [v.stevilka, v.datum_izdaje, v.cas_izdaje]);
    assert(v.izdajatelj.firma === "NEXT DIMENSIONS, družba za marketing, d.o.o." && v.izdajatelj.sedez === "Trebče 81, 3256 Bistrica ob Sotli" && v.izdajatelj.davcna === "57469911" && v.izdajatelj.maticna === "7238274000",
      "vsebina: izdajatelj s sedezem, davcna 57469911 (brez SI), maticna", v.izdajatelj);
    assert(v.postavke.length === 1 && v.postavke[0].opis === "Vstopnica: Outly Launch Party, 27. 11. 2026" && v.postavke[0].kolicina === 2 && v.postavke[0].cena_cents === 1500 && v.skupaj_cents === 3000,
      "vsebina: opis »Vstopnica: {dogodek}, {datum}«, kolicina, cena, skupaj", v.postavke);
    assert(v.ddv === "DDV ni obračunan na podlagi prvega odstavka 94. člena Zakona o davku na dodano vrednost (nismo zavezanci za DDV)." && v.ddv === racuni.DDV_KLAVZULA, "vsebina: klavzula DDV dobesedno (ena konstanta)");
    assert(v.nacin_placila === "plačilna kartica (Stripe)" && v.operater === "57469911" && v.eor === vr.eor && v.zoi === vr.zoi, "vsebina: nacin placila, oznaka operaterja = davcna, EOR, ZOI");
    assert(v.qr === racuni.qrPodatek(vr.zoi, "57469911", vr.izdan_at) && /^\d{60}$/.test(v.qr), "vsebina: QR podatek iz ZOI + davcne + casa izdaje", v.qr);
    assert(!JSON.stringify(v).includes("kupec@example.com"), "vsebina: BREZ e-naslova kupca (hramba 10 let)");
    assert(racuni.vsebinaRacuna({ ...vr, stevilka: null, izdan_at: null, stanje: "caka" }, nr) === null, "vsebina: racun brez stevilke (caka) -> null");
    const b = racuni.blokRacuna(v, { qrCid: "zoi-qr" });
    for (const [del, opis] of [["Račun št. A001-1-7", "stevilka"], ["3. 11. 2026 ob 19:05:09", "datum in cas"], ["Davčna številka: 57469911", "davcna"], [racuni.DDV_KLAVZULA, "klavzula"],
      ["Oznaka operaterja: 57469911", "operater"], ["EOR: " + vr.eor, "EOR"], ["ZOI: " + vr.zoi, "ZOI"], ["Način plačila: plačilna kartica (Stripe)", "nacin placila"]]) {
      assert(b.text.includes(del) && b.html.includes(del.replace(/&/g, "&amp;")), `blok za mail (besedilo in HTML): ${opis}`);
    }
    assert(!/SI\s?57469911/.test(b.text + b.html) && b.html.includes('src="cid:zoi-qr"'), "blok: davcna brez predpone SI, QR kot vgrajena slika (cid)");
    const xss = racuni.blokRacuna(racuni.vsebinaRacuna(vr, { ...nr, title: "<script>alert(1)</script>" }));
    assert(!xss.html.includes("<script>") && xss.html.includes("&lt;script&gt;"), "blok HTML: naslov dogodka je ubezen");
    const vd = racuni.vsebinaRacuna({ ...vr, vrsta: "dobropis", stevilka: 9, znesek_cents: -1500, ref_prostor: "A001", ref_naprava: "1", ref_stevilka: 7, ref_izdan_at: vr.izdan_at }, nr);
    assert(vd.naslov === "Dobropis" && vd.skupaj_cents === -1500 && vd.sklic && vd.sklic.stevilka === "A001-1-7" && vd.sklic.cas === "19:05:09" && /A001-1-7/.test(vd.postavke[0].opis),
      "vsebina dobropisa: negativen znesek, sklic na stevilko ter datum in cas izvirnega racuna", vd);
  }

  await new Promise((r) => jwksServer.listen(JWKS_PORT, r));
  await new Promise((r) => stripeServer.listen(STRIPE_PORT, r));
  await new Promise((r) => resendServer.listen(RESEND_PORT, r));
  await new Promise((r) => ponudnikServer.listen(PONUDNIK_PORT, r));
  const pool = new Pool({ connectionString: DB, max: 24 });
  await pool.query("TRUNCATE omejitve, stripe_events, ticket_transfers, club_invites, club_members, event_favorites, vracila, odpovedi_dogodkov, racuni, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await pool.query("TRUNCATE racuni_zaporedje");
  const nar = async (id) => (await pool.query("SELECT * FROM orders WHERE id=$1", [id])).rows[0];
  const racuniNarocila = async (oid) => (await pool.query("SELECT * FROM racuni WHERE order_id=$1 ORDER BY id", [oid])).rows;

  let A = null;
  const B = zagon(PORT_B, { RACUNI_TICK_MS: "200", VRACILA_TICK_MS: "0" });   // ponudnik izklopljen (RACUNI_PONUDNIK prazen), pospravljalec racunov ne tece (privzeti zamik 5 min)
  const bB = `http://127.0.0.1:${PORT_B}`, bA = `http://127.0.0.1:${PORT_A}`;
  await cakajStreznik(bB);
  try {
    const imena = ["lastnik", "lastnik2", "ana", "bor", "cene", "admin"];
    const T = {};
    imena.forEach((k, i) => { T[k] = zeton(`${k}@outly.si`, uuid(i + 1)); });
    for (const k of imena) { const r = await api(bB, "GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='business' WHERE email LIKE 'lastnik%@outly.si'");
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    const odrasel = new Date(Date.now() - 25 * 365.25 * 24 * 3600 * 1000).toISOString().slice(0, 10);
    for (const k of ["ana", "bor", "cene"]) await api(bB, "PATCH", "/me", T[k], { dateOfBirth: odrasel });
    const lastnik = (e) => `(SELECT id FROM users WHERE email='${e}@outly.si')`;
    const prod = (ime) => `'${ime}', 'Naslov 1, Ljubljana', '1234567000', 'SI12345678', TRUE, 'info@primer.si'`;
    const STOLPCI = "owner_user_id, name, city, address, legal_name, legal_address, registration_number, tax_number, vat_payer, contact_email";
    await pool.query(`INSERT INTO clubs (${STOLPCI}, stripe_account_id, stripe_charges_enabled, stripe_account_livemode) VALUES (${lastnik("lastnik")}, 'Navaden klub', 'Ljubljana', 'Slovenska 1', ${prod("Navaden klub d.o.o.")}, 'acct_ziv1', TRUE, TRUE)`);
    await pool.query(`INSERT INTO clubs (${STOLPCI}, is_official, is_organizer) VALUES (${lastnik("lastnik2")}, 'Outly', 'Ljubljana', 'Trg 2', ${prod("NEXT DIMENSIONS d.o.o.")}, TRUE, TRUE)`);
    const cez = (h) => new Date(Date.now() + h * 3600 * 1000).toISOString();
    const dogodek = async (klub, naslov, cena, h = 24) => (await pool.query(
      "INSERT INTO events (club_id, title, start_at, status, ticket_price_cents, capacity, min_age) VALUES ($1,$2,$3,'published',$4,500,0) RETURNING id", [klub, naslov, cez(h), cena])).rows[0].id;
    const evO = await dogodek(2, "Outly Launch Party", 1500), evO0 = await dogodek(2, "Outly brezplacno", 0), evOodp = await dogodek(2, "Outly odpoved", 1000);
    const evOsk = await dogodek(2, "Outly sken", 1000, 1), evN = await dogodek(1, "Navadna noc", 1000);
    const nakup = (baza, token, ev, kol = 1) => api(baza, "POST", `/events/${ev}/orders`, token, { quantity: kol });
    // Nakup + placilo + webhook (checkout.session.completed). Vrne { id, ref, pi, w }.
    async function kupiInPlacaj(baza, token, ev, kol = 1) {
      const r = await nakup(baza, token, ev, kol);
      if (r.status !== 201) { assert(false, "nakup 201", [r.status, r.body]); return null; }
      const o = await nar(r.body.order.id);
      const pi = placaj(o.stripe_checkout_session_id);
      const w = await webhook(baza, "checkout.session.completed", { id: o.stripe_checkout_session_id });
      return { id: o.id, ref: o.public_ref, pi, w, seja: o.stripe_checkout_session_id };
    }

    // ================================================================
    console.log("\n# 1. Ponudnik izklopljen (privzeto): dolg racuna v isti transakciji, nic se ne poslje");
    const X1 = await kupiInPlacaj(bB, T.ana, evO, 2);
    assert(X1.w.status === 200 && (await nar(X1.id)).status === "paid", "B: platformno narocilo placano (webhook 200)", X1.w);
    let rr = await racuniNarocila(X1.id);
    assert(rr.length === 1 && rr[0].vrsta === "racun" && rr[0].stanje === "caka" && rr[0].znesek_cents === 3000 && rr[0].stevilka === null && rr[0].valuta === "EUR",
      "B: natanko ena vrstica `caka` takoj po webhooku (zapisana v transakciji zakljuci, pospravljalec ne tece), znesek 3000, brez stevilke", rr);
    const w2 = await webhook(bB, "checkout.session.completed", { id: X1.seja });
    const w3 = await webhook(bB, "checkout.session.completed", { id: X1.seja }, X1.w.id);
    assert(w2.status === 200 && w3.body.duplicate === true && (await racuniNarocila(X1.id)).length === 1, "B: podvojen webhook (nov in isti id dogodka): se vedno en racun");
    // vracilo v Stripovi plosci pred izdajo racuna: dobropis `caka` (stevilko dobi sele za racunom)
    const reB = vrni(X1.pi, 1000);
    const wv = await webhook(bB, "charge.refunded", { id: S.pi[X1.pi].latest_charge });
    rr = await racuniNarocila(X1.id);
    assert(wv.status === 200 && rr.length === 2 && rr[1].vrsta === "dobropis" && rr[1].znesek_cents === -1000 && rr[1].vir === reB.id && Number(rr[1].ref_racun_id) === Number(rr[0].id) && rr[1].stanje === "caka" && rr[1].vracilo_uspelo === true,
      "B: vracilo 10 EUR v plosci -> dobropis -1000, vir = id Stripovega vracila, sklic na racun, `caka`", rr);
    await webhook(bB, "charge.refunded", { id: S.pi[X1.pi].latest_charge });
    assert((await racuniNarocila(X1.id)).length === 2, "B: ponovljen webhook charge.refunded: brez dvojnika dobropisa");
    await pocakaj(900);
    assert(P.klici.length === 0 && (await pool.query("SELECT COUNT(*)::int AS n FROM racuni WHERE stanje <> 'caka'")).rows[0].n === 0 && (await pool.query("SELECT COUNT(*)::int AS n FROM racuni_zaporedje")).rows[0].n === 0,
      "B: ponudnik ni klican, nobena vrstica nima stevilke, stevec ni ustvarjen", P.klici.length);
    assert(/\[racuni\] ponudnik izklopljen/.test(B.log) && !/\[racuni\] POZOR/.test(B.log) && !/TypeError|ReferenceError|Error: /.test(B.log.replace(/\[placila\] POZOR[^\n]*/g, "")),
      "B: zagon brez kljuca ponudnika brez napake (samo vrstica »izklopljen«)", B.log.split("\n").filter((l) => /racuni|Error/.test(l)).slice(0, 5));
    // racun, ki bo ob vklopu ponudnika dvakrat zacasno padel: dobropis mora vseeno pocakati na potrjen racun
    P.nacin[X1.ref] = { zacasna: 2 };
    await ustavi(B);

    // ================================================================
    console.log("\n# 2. Lazni ponudnik: vrsta se obdela, dobropis nikoli pred racunom");
    A = zagon(PORT_A, { RACUNI_PONUDNIK: "lazni", RACUNI_LAZNI_URL: `http://127.0.0.1:${PONUDNIK_PORT}/potrdi`, RACUNI_TICK_MS: "150", RACUNI_PREMOR_MS: "250", RACUNI_ODLOG_MS: "100",
      RACUNI_ROK_MS: "1200", RACUNI_POSPRAVI_MS: "400", RACUNI_POSPRAVI_ZAMIK_MS: "300", RACUNI_ZASTARELO_MS: "60000",
      VRACILA_TICK_MS: "200", VRACILA_RAZMAK_MS: "10", VRACILA_ZAMIK_S: "0", VRACILA_SWEEP_MS: "400", VRACILA_PREMOR_MS: "150" });
    await cakajStreznik(bA);
    assert(await cakaj(async () => (await racuniNarocila(X1.id)).every((x) => x.stanje === "potrjen"), 15000), "A: racun in dobropis iz vrste B potrjena", (await racuniNarocila(X1.id)).map((x) => [x.vrsta, x.stanje, x.zadnja_napaka]));
    rr = await racuniNarocila(X1.id);
    const kX = klicaZa(X1.ref);
    const prviDobropis = kX.findIndex((k) => k.vrsta === "dobropis"), uspehRacuna = kX.findIndex((k) => k.vrsta === "racun" && k.izid === "ok");
    assert(rr[0].stevilka !== null && rr[1].stevilka !== null && Number(rr[1].stevilka) > Number(rr[0].stevilka) && new Date(rr[1].izdan_at) >= new Date(rr[0].izdan_at),
      "dobropis ima stevilko ZA izvirnim racunom (isto zaporedje A001-1)", rr.map((x) => [x.vrsta, x.stevilka]));
    assert(uspehRacuna >= 0 && prviDobropis > uspehRacuna && kX.filter((k) => k.vrsta === "racun").length === 3, "dobropis gre ponudniku sele PO potrjenem racunu (racun: 2 zacasni napaki + uspeh)", kX.map((k) => [k.vrsta, k.izid]));
    assert(rr[0].naknadno === true && rr[0].poskusi === 2 && rr[1].naknadno === false && rr.every((x) => x.prostor === "A001" && x.naprava === "1"), "racun: naknadno = true po zacasnih napakah, poskusi 2; dobropis naknadno false", rr.map((x) => [x.naknadno, x.poskusi]));
    const dk = kX.find((k) => k.vrsta === "dobropis");
    assert(dk && dk.podatki.sklic && dk.podatki.sklic.stevilka_racuna === `A001-1-${rr[0].stevilka}` && dk.podatki.sklic.eor === rr[0].eor && dk.podatki.znesek_cents === -1000,
      "ponudnik dobi dobropis s sklicem na stevilko in EOR izvirnega racuna, negativen znesek", dk && dk.podatki);
    assert(kX.every((k) => !JSON.stringify(k.podatki).includes("ana@outly.si")) && kX[0].podatki.davcna_izdajatelja === "57469911" && kX[0].podatki.davcna_operaterja === "57469911",
      "podatki za ponudnika: brez e-naslova kupca, davcna izdajatelja in operaterja 57469911");

    // ================================================================
    console.log("\n# 3. Natanko en racun; brez racuna za klub, 0 EUR in testni promet; pospravljalec");
    const X2 = await kupiInPlacaj(bA, T.bor, evO, 1);
    assert(X2.w.status === 200 && await cakaj(async () => (await racuniNarocila(X2.id))[0]?.stanje === "potrjen", 8000), "A: novo platformno narocilo -> racun potrjen", await racuniNarocila(X2.id));
    await webhook(bA, "checkout.session.completed", { id: X2.seja });
    await webhook(bA, "checkout.session.async_payment_succeeded", { id: X2.seja });
    await pocakaj(900);   // vsaj en tek pospravljalca (400 ms)
    rr = await racuniNarocila(X2.id);
    assert(rr.length === 1 && rr[0].stanje === "potrjen" && /^[0-9a-f-]{36}$/.test(rr[0].eor) && /^[0-9a-f]{32}$/.test(rr[0].zoi) && rr[0].ponudnik === "lazni" && rr[0].ponudnik_id === "doc-" + rr[0].id && rr[0].potrjen_at,
      "podvojeni webhooki + pospravljalec: natanko en racun; EOR, ZOI, ponudnik, ponudnik_id zapisani", rr);
    assert(klicaZa(X2.ref).length === 1 && klicaZa(X2.ref)[0].kljuc === rr[0].message_id, "en klic ponudnika z message_id kot kljucem idempotence");
    const XN = await kupiInPlacaj(bA, T.ana, evN, 1);
    const n0 = await nakup(bA, T.cene, evO0, 1);
    assert(XN.w.status === 200 && (await nar(XN.id)).status === "paid" && (await nar(XN.id)).stripe_account_id === "acct_ziv1", "navaden klub: placano (Connect)");
    assert(n0.status === 201 && n0.body.order.status === "paid" && (await nar(n0.body.order.id)).stripe_account_id === "platform", "0 EUR platformno: placano takoj (oznaka platform)");
    // testni promet uradnega profila (lazni nacin test_ in sandbox seja cs_test_) in placano naroceno izpred 054 (paid_at pred migracijo)
    const vstavi = async (pi, seja, paidAt = "NOW()", ref = null) => (await pool.query(
      `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, paid_at, buyer_email, stripe_account_id, stripe_payment_intent_id, stripe_checkout_session_id)
       VALUES ($1, (SELECT id FROM users WHERE email='cene@outly.si'), $2, 2, 1, 1500, 1500, 'paid', ${paidAt}, 'cene@outly.si', 'platform', $3, $4) RETURNING id`,
      [ref || "OUT-R" + crypto.randomBytes(4).toString("hex").toUpperCase(), evO, pi, seja])).rows[0].id;
    const t1 = await vstavi("test_" + crypto.randomUUID(), null), t2 = await vstavi("pi_sand_1", "cs_test_sand1"), star = await vstavi("pi_star_1", "cs_live_star1", "NOW() - INTERVAL '30 days'");
    {
      const c = await pool.connect();
      try { assert((await racuni.vpisiDolgRacuna(c, t1)) === null && (await racuni.vpisiDolgRacuna(c, t2)) === null && (await racuni.vpisiDolgRacuna(c, XN.id)) === null && (await racuni.vpisiDolgRacuna(c, n0.body.order.id)) === null,
        "vpisiDolgRacuna: testni (test_), sandbox (cs_test_), navaden klub, 0 EUR -> nic"); } finally { c.release(); }
    }
    // pospravljalec: placano platformno narocilo BREZ racuna (npr. zapisano mimo zakljuci) -> racun + POZOR
    const izgubljen = await vstavi("pi_izg_1", "cs_live_izg1");
    assert(await cakaj(async () => (await racuniNarocila(izgubljen)).length === 1, 5000) && /\[racuni\] POZOR: 1 placanih platformnih narocil ni imelo racuna/.test(A.log), "pospravljalec: manjkajoc racun vpisan + [racuni] POZOR", A.log.split("\n").filter((l) => /racuni\] POZOR/.test(l)));
    await pocakaj(900);
    for (const [id, opis] of [[XN.id, "navaden klub"], [n0.body.order.id, "0 EUR"], [t1, "testni nacin test_"], [t2, "sandbox cs_test_"], [star, "placano pred 054 (ne za nazaj)"]]) {
      assert((await racuniNarocila(id)).length === 0, `${opis}: brez racuna (tudi po pospravljalcu)`);
    }
    const dvojni = (await pool.query("SELECT order_id, COUNT(*)::int AS n FROM racuni WHERE vrsta='racun' GROUP BY order_id HAVING COUNT(*) > 1")).rows;
    assert(dvojni.length === 0, "nobeno narocilo nima vec kot enega racuna", dvojni);

    // ================================================================
    console.log("\n# 4. Zacasna napaka -> ponovitev, trajna -> napaka");
    const r4 = await nakup(bA, T.cene, evO, 1);
    const o4 = await nar(r4.body.order.id);
    P.nacin[o4.public_ref] = { zacasna: 3 };
    placaj(o4.stripe_checkout_session_id);
    await webhook(bA, "checkout.session.completed", { id: o4.stripe_checkout_session_id });
    assert(await cakaj(async () => (await racuniNarocila(o4.id))[0]?.stanje === "potrjen", 10000), "zacasna napaka (3x 503): racun na koncu potrjen", await racuniNarocila(o4.id));
    const k4 = klicaZa(o4.public_ref), x4 = (await racuniNarocila(o4.id))[0];
    assert(k4.length === 4 && k4.every((k) => k.message_id === x4.message_id && k.kljuc === x4.message_id) && k4.slice(1).every((k) => k.naknadno === true) && k4[0].naknadno === false,
      "4 klici z ISTIM message_id; ponovitve z oznako naknadno", k4.map((k) => [k.izid, k.naknadno]));
    assert(x4.naknadno === true && x4.poskusi === 3 && x4.zadnja_napaka === null, "vrstica: naknadno, 3 poskusi, napaka pocisena ob uspehu", x4);
    const r5 = await nakup(bA, T.cene, evO, 1);
    const o5 = await nar(r5.body.order.id);
    P.nacin[o5.public_ref] = "trajna";
    placaj(o5.stripe_checkout_session_id);
    await webhook(bA, "checkout.session.completed", { id: o5.stripe_checkout_session_id });
    assert(await cakaj(async () => (await racuniNarocila(o5.id))[0]?.stanje === "napaka", 8000), "trajna zavrnitev (400): stanje napaka", await racuniNarocila(o5.id));
    await pocakaj(800);
    const x5 = (await racuniNarocila(o5.id))[0];
    assert(klicaZa(o5.public_ref).length === 1 && x5.stevilka !== null && x5.eor === null && /HTTP 400/.test(x5.zadnja_napaka), "trajna: en sam klic (brez ponavljanja), racun ima stevilko (izdan), brez EOR", x5);
    assert(new RegExp(`\\[racuni\\] POZOR: racun A001-1-${x5.stevilka} \\(narocilo ${o5.public_ref}\\) je ponudnik lazni ZAVRNIL`).test(A.log), "trajna: [racuni] POZOR s stevilko in narocilom (brez e-naslova)");

    // ================================================================
    console.log("\n# 5. Dobropis ob vracilu v plosci in ob odpovedi dogodka");
    const re1 = vrni(X2.pi, 500);
    let w = await webhook(bA, "charge.refunded", { id: S.pi[X2.pi].latest_charge });
    await webhook(bA, "charge.refunded", { id: S.pi[X2.pi].latest_charge });
    assert(w.status === 200 && await cakaj(async () => (await racuniNarocila(X2.id)).filter((x) => x.vrsta === "dobropis" && x.stanje === "potrjen").length === 1, 8000), "delno vracilo 5 EUR: en dobropis, potrjen", await racuniNarocila(X2.id));
    const re2 = vrni(X2.pi, 1000);
    await webhook(bA, "charge.refunded", { id: S.pi[X2.pi].latest_charge });
    assert(await cakaj(async () => (await racuniNarocila(X2.id)).filter((x) => x.vrsta === "dobropis" && x.stanje === "potrjen").length === 2, 8000), "drugo vracilo istega naboja: drug dobropis");
    rr = (await racuniNarocila(X2.id)).filter((x) => x.vrsta === "dobropis");
    assert(rr.length === 2 && rr[0].vir === re1.id && rr[0].znesek_cents === -500 && rr[1].vir === re2.id && rr[1].znesek_cents === -1000 && (await nar(X2.id)).status === "refunded",
      "dobropisa -500 in -1000, vir = re_..., vsota = placano, narocilo refunded", rr.map((x) => [x.vir, x.znesek_cents]));
    // odpoved dogodka: obdelovalec vracil (uveljaviLokalno) -> dobropis natanko enkrat; nato se webhook charge.refunded istega vracila -> brez dvojnika
    const O6 = await kupiInPlacaj(bA, T.ana, evOodp, 2), O7 = await kupiInPlacaj(bA, T.bor, evOodp, 1);
    assert(await cakaj(async () => (await racuniNarocila(O6.id))[0]?.stanje === "potrjen" && (await racuniNarocila(O7.id))[0]?.stanje === "potrjen", 8000), "odpoved: racuna obeh narocil potrjena");
    const del = await api(bA, "DELETE", `/events/${evOodp}`, T.lastnik2, undefined, { "x-outly-club": "2" });
    assert(del.status === 200 && del.body.refunds_queued === 2, "DELETE dogodka uradnega profila: 2 vracili v vrsti", [del.status, del.body]);
    assert(await cakaj(async () => (await pool.query("SELECT COUNT(*)::int AS n FROM vracila WHERE event_id=$1 AND stanje='opravljeno'", [evOodp])).rows[0].n === 2, 15000), "odpoved: obe vracili opravljeni");
    for (const x of [O6, O7]) await webhook(bA, "charge.refunded", { id: S.pi[x.pi].latest_charge });
    assert(await cakaj(async () => (await pool.query("SELECT COUNT(*)::int AS n FROM racuni r JOIN orders o ON o.id = r.order_id WHERE o.event_id=$1 AND r.vrsta='dobropis' AND r.stanje='potrjen'", [evOodp])).rows[0].n === 2, 8000),
      "odpoved: natanko en dobropis na narocilo (potrjen), tudi po webhooku charge.refunded");
    const d6 = (await racuniNarocila(O6.id)).filter((x) => x.vrsta === "dobropis"), vr6 = (await pool.query("SELECT stripe_vracilo_id FROM vracila WHERE order_id=$1", [O6.id])).rows[0];
    assert(d6.length === 1 && d6[0].znesek_cents === -2000 && d6[0].vir === vr6.stripe_vracilo_id, "odpoved: dobropis -2000 (2 x 10 EUR), vir = nase Stripovo vracilo", [d6, vr6]);
    // pospravljalec: refunded_cents povecan mimo uveljaviVracilo (npr. star zapis) -> dobropis z nadomestnim virom + POZOR
    await pool.query("UPDATE orders SET refunded_cents = 700, status = 'partially_refunded' WHERE id = $1", [o4.id]);
    assert(await cakaj(async () => (await racuniNarocila(o4.id)).some((x) => x.vrsta === "dobropis" && x.vir === `narocilo-${o4.id}@700` && x.znesek_cents === -700), 5000) && /\[racuni\] POZOR: 1 vracil ni imelo dobropisa/.test(A.log),
      "pospravljalec: manjkajoc dobropis (-700, vir narocilo-<id>@700) + POZOR", await racuniNarocila(o4.id));

    // ================================================================
    console.log("\n# 6. Sprozilec: hramba (ZDavP-2 38/8)");
    const izd = (await racuniNarocila(X2.id))[0];
    const zavrne = async (sql, par) => { try { await pool.query(sql, par); return false; } catch (e) { return e.code === "23001" ? true : e.message; } };
    assert(await zavrne("DELETE FROM racuni WHERE id=$1", [izd.id]) === true, "DELETE racuna -> zavrnjeno");
    assert(await zavrne("UPDATE racuni SET stevilka = stevilka + 1000 WHERE id=$1", [izd.id]) === true, "sprememba stevilke -> zavrnjeno");
    assert(await zavrne("UPDATE racuni SET izdan_at = izdan_at - INTERVAL '1 day' WHERE id=$1", [izd.id]) === true, "sprememba casa izdaje -> zavrnjeno");
    assert(await zavrne("UPDATE racuni SET znesek_cents = 1 WHERE id=$1", [izd.id]) === true, "sprememba zneska -> zavrnjeno");
    assert(await zavrne("UPDATE racuni SET zoi = '00000000000000000000000000000000' WHERE id=$1", [izd.id]) === true, "sprememba ZOI -> zavrnjeno");
    assert(await zavrne("UPDATE racuni SET eor = gen_random_uuid() WHERE id=$1", [izd.id]) === true, "sprememba EOR -> zavrnjeno");
    assert(await zavrne("UPDATE racuni SET stanje = 'izdan' WHERE id=$1", [izd.id]) === true, "potrjen -> izdan -> zavrnjeno");
    assert(await zavrne("UPDATE racuni SET message_id = gen_random_uuid() WHERE id=$1", [izd.id]) === true, "sprememba message_id -> zavrnjeno");
    assert(await zavrne("UPDATE racuni_zaporedje SET zadnja = zadnja + 2") === true, "stevec +2 (luknja) -> zavrnjeno");
    assert(await zavrne("UPDATE racuni_zaporedje SET zadnja = zadnja - 1") === true, "stevec navzdol -> zavrnjeno");
    assert(await zavrne("DELETE FROM racuni_zaporedje") === true, "brisanje stevca -> zavrnjeno");
    const napakaVr = (await racuniNarocila(o5.id))[0];
    assert(await zavrne("UPDATE racuni SET stanje = 'caka', stevilka = NULL, izdan_at = NULL, prostor = NULL, naprava = NULL, leto = NULL WHERE id=$1", [napakaVr.id]) === true, "izdan racun nazaj v caka (brez stevilke) -> zavrnjeno");
    assert(await zavrne("UPDATE racuni SET zadnja_napaka = 'opomba admina' WHERE id=$1", [napakaVr.id]) === false, "sprememba polja vrste dela (zadnja_napaka) je dovoljena");
    assert(await zavrne(`INSERT INTO racuni (order_id, vrsta, znesek_cents, stanje, prostor, naprava, leto, stevilka, izdan_at) VALUES ($1, 'racun', 100, 'izdan', 'A001', '1', 2026, 999, NOW())`, [n0.body.order.id]) === true,
      "INSERT racuna z ze dodeljeno stevilko (mimo stevca) -> zavrnjeno");
    assert(await zavrne("INSERT INTO racuni_zaporedje (prostor, naprava, leto, zadnja) VALUES ('Z9', '9', 2030, 5)") === true, "nov stevec, ki ne zacne z 0 -> zavrnjeno");
    {
      const caka = (await pool.query("INSERT INTO racuni (order_id, vrsta, znesek_cents, naslednji_poskus_at) VALUES ($1, 'racun', 100, NOW() + INTERVAL '30 days') RETURNING id", [star])).rows[0].id;
      const leto = (await pool.query("SELECT leto, zadnja FROM racuni_zaporedje WHERE prostor='A001' AND naprava='1' ORDER BY leto DESC LIMIT 1")).rows[0];
      assert(await zavrne("UPDATE racuni SET stanje='izdan', prostor='A001', naprava='1', leto=$2, stevilka=$3, izdan_at=NOW() WHERE id=$1", [caka, leto.leto, Number(leto.zadnja) + 5]) === true,
        "rocna dodelitev stevilke, ki ni vrednost stevca (luknja) -> zavrnjeno");
      assert(await zavrne("UPDATE racuni SET stanje='izdan', prostor='A001', naprava='1', leto=$2, stevilka=$3, izdan_at=NOW() WHERE id=$1", [caka, leto.leto, Number(leto.zadnja)]) !== false,
        "rocna dodelitev ze uporabljene stevilke stevca (dvojnik) -> zavrnjeno (unikat 23505)");
    }
    assert((await pool.query("SELECT 1 FROM racuni WHERE id=$1 AND stevilka=$2", [izd.id, izd.stevilka])).rowCount === 1, "racun ostane nespremenjen");

    // ================================================================
    console.log("\n# 7. ~200 hkratnih izdaj: brez vrzeli in brez dvojnikov (tretjina transakcij razveljavljena)");
    {
      const N = 200;
      const c0 = await pool.connect();
      let ids;
      try {
        await c0.query("BEGIN");
        const o = await c0.query(`INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, paid_at, buyer_email, stripe_account_id)
          SELECT 'OUT-H' || g, (SELECT id FROM users WHERE email='cene@outly.si'), $1, 2, 1, 100, 100, 'paid', NOW(), 'cene@outly.si', 'platform' FROM generate_series(1, $2::int) g RETURNING id`, [evO, N]);
        // naslednji_poskus_at dalec v prihodnosti: delavec procesa A teh vrstic ne prevzame (izdajo jih samo hkratni klici spodaj, v locenem zaporedju T200-9)
        ids = (await c0.query(`INSERT INTO racuni (order_id, vrsta, znesek_cents, naslednji_poskus_at) SELECT id, 'racun', 100, NOW() + INTERVAL '30 days' FROM unnest($1::bigint[]) id RETURNING id`,
          [o.rows.map((x) => x.id)])).rows.map((x) => Number(x.id));
        await c0.query("COMMIT");
      } finally { c0.release(); }
      let razveljavljenih = 0;
      const izdaj = async (id) => {
        for (let poskus = 0; poskus < 20; poskus++) {
          const c = await pool.connect();
          try {
            await c.query("BEGIN");
            const iz = await racuni.izdajVTransakciji(c, id, { prostor: "T200", naprava: "9" });
            if (iz.stanje === "izdan" && (id + poskus) % 3 === 0) { await c.query("ROLLBACK"); razveljavljenih++; continue; }   // npr. napaka po dodelitvi: stevilka se mora vrniti
            await c.query("COMMIT");
            return iz;
          } catch (e) { await c.query("ROLLBACK").catch(() => {}); throw e; } finally { c.release(); }
        }
        throw new Error("izdaja ni uspela");
      };
      const t0 = Date.now();
      const izidi = await Promise.all(ids.map((id) => izdaj(id)));
      const ms = Date.now() - t0;
      const vse = (await pool.query("SELECT stevilka, izdan_at FROM racuni WHERE prostor='T200' AND naprava='9' ORDER BY stevilka")).rows;
      const st = vse.map((x) => Number(x.stevilka));
      assert(izidi.every((x) => x.stanje === "izdan") && razveljavljenih > 30, `vseh ${N} izdanih, ${razveljavljenih} razveljavljenih transakcij vmes (${ms} ms)`);
      assert(st.length === N && st.every((s, i) => s === i + 1), "stevilke 1..200 BREZ VRZELI in brez dvojnikov kljub razveljavljenim transakcijam", st.slice(0, 5).concat(["..."], st.slice(-5)));
      assert(Number((await pool.query("SELECT zadnja FROM racuni_zaporedje WHERE prostor='T200' AND naprava='9'")).rows[0].zadnja) === N, "stevec = 200 (razveljavljene dodelitve niso porabile stevilke)");
      assert(vse.every((x, i) => i === 0 || new Date(x.izdan_at) >= new Date(vse[i - 1].izdan_at)), "cas izdaje narasca s stevilko");
      const c = await pool.connect();
      try {
        await c.query("BEGIN");
        assert((await racuni.izdajVTransakciji(c, ids[0], { prostor: "T200", naprava: "9" })).stanje === "izdan" && Number((await c.query("SELECT zadnja FROM racuni_zaporedje WHERE prostor='T200'")).rows[0].zadnja) === N,
          "ponovna izdaja ze izdanega racuna: nova stevilka se NE dodeli");
        await c.query("ROLLBACK");
      } finally { c.release(); }
      // dobropis, katerega izvirni racun se nima stevilke: odlozeno, stevec nedotaknjen
      const c2 = await pool.connect();
      try {
        await c2.query("BEGIN");
        const oc = (await c2.query(`INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, paid_at, buyer_email, stripe_account_id)
          VALUES ('OUT-ODL1', (SELECT id FROM users WHERE email='cene@outly.si'), $1, 2, 1, 100, 100, 'paid', NOW(), 'cene@outly.si', 'platform') RETURNING id`, [evO])).rows[0].id;
        const rc = (await c2.query("INSERT INTO racuni (order_id, vrsta, znesek_cents) VALUES ($1, 'racun', 100) RETURNING id", [oc])).rows[0].id;
        const dc = (await c2.query("INSERT INTO racuni (order_id, vrsta, ref_racun_id, vir, znesek_cents) VALUES ($1, 'dobropis', $2, 're_odl1', -100) RETURNING id", [oc, rc])).rows[0].id;
        const iz = await racuni.izdajVTransakciji(c2, Number(dc), { prostor: "T200", naprava: "9" });
        assert(iz.stanje === "odlozeno" && (await c2.query("SELECT stevilka FROM racuni WHERE id=$1", [dc])).rows[0].stevilka === null, "dobropis pred stevilko izvirnega racuna: odlozeno, brez stevilke");
        await c2.query("ROLLBACK");
      } finally { c2.release(); }
    }

    // ================================================================
    console.log("\n# 8. I16: ponudnik visi -> nakup, webhook in sken ostanejo hitri; potrdilo kupcu pride");
    {
      P.privzeto = "visi";
      const prejMaili = R.poslano.length;
      const casiW = [], casiN = [], kupljeni = [];
      for (let i = 0; i < 6; i++) {
        const t0 = Date.now();
        const r = await nakup(bA, [T.ana, T.bor, T.cene][i % 3], evOsk, 1);
        casiN.push(Date.now() - t0);
        const o = await nar(r.body.order.id);
        placaj(o.stripe_checkout_session_id);
        const w8 = await webhook(bA, "checkout.session.completed", { id: o.stripe_checkout_session_id });
        casiW.push(w8.ms);
        kupljeni.push(o.id);
      }
      assert(await cakaj(async () => P.visijo.length >= 4, 5000), "ponudnik visi: vsaj 4 hkratni klici v teku (RACUNI_VZPOREDNO)", P.visijo.length);
      const vTx = (await pool.query("SELECT COUNT(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND state LIKE 'idle in transaction%' AND pid <> pg_backend_pid()")).rows[0].n;
      assert(vTx === 0, "med klicem ponudnika nobena povezava ne caka v odprti transakciji", vTx);
      const serial = (await pool.query("SELECT serial FROM tickets WHERE order_id=$1 LIMIT 1", [kupljeni[0]])).rows[0].serial;
      const casiS = [];
      for (let i = 0; i < 5; i++) { const t0 = Date.now(); const s = await api(bA, "POST", "/business/tickets/scan", T.lastnik2, { serial }, { "x-outly-club": "2" }); casiS.push(Date.now() - t0); if (![200, 409].includes(s.status)) casiS.push(99999); }
      assert(Math.max(...casiN) < 1500 && Math.max(...casiW) < 1500, `nakup in webhook ne cakata na ponudnika (nakup max ${Math.max(...casiN)} ms, webhook max ${Math.max(...casiW)} ms; ponudnik visi do roka 1200 ms)`, [casiN, casiW]);
      assert(Math.max(...casiS) < 500, `sken med visecim ponudnikom < 500 ms (max ${Math.max(...casiS)} ms)`, casiS);
      assert(await cakaj(async () => R.poslano.length >= prejMaili + 6, 8000), "potrdila kupcem poslana, ceprav ponudnik racunov visi (I32 nespremenjen)", R.poslano.length - prejMaili);
      assert(await cakaj(async () => (await pool.query("SELECT COUNT(*)::int AS n FROM racuni WHERE order_id = ANY($1::bigint[]) AND stanje = 'izdan' AND naknadno", [kupljeni])).rows[0].n >= 4, 5000),
        "po roku klica (RACUNI_ROK_MS): racuni izdani (stevilka, cas), oznaceni za naknadno potrditev, brez EOR");
      P.privzeto = "ok"; sprostiVisece();
      assert(await cakaj(async () => (await pool.query("SELECT COUNT(*)::int AS n FROM racuni WHERE order_id = ANY($1::bigint[]) AND stanje = 'potrjen'", [kupljeni])).rows[0].n === kupljeni.length, 15000),
        "ponudnik spet odgovarja: vsi racuni potrjeni (naknadno)");
    }
    // vse stevilke A001-1 letosnjega leta (racuni in dobropisi skupaj): 1..N brez vrzeli
    {
      const vse = (await pool.query("SELECT leto, stevilka FROM racuni WHERE prostor='A001' AND naprava='1' ORDER BY leto, stevilka")).rows;
      const leta = [...new Set(vse.map((x) => x.leto))];
      const zap = await pool.query("SELECT leto, zadnja FROM racuni_zaporedje WHERE prostor='A001' AND naprava='1'");
      const okLeta = leta.every((l) => { const s = vse.filter((x) => x.leto === l).map((x) => Number(x.stevilka)); return s.every((n, i) => n === i + 1) && Number(zap.rows.find((z) => z.leto === l).zadnja) === s.length; });
      assert(vse.length >= 15 && okLeta, `A001-1: ${vse.length} racunov in dobropisov v enem zaporedju 1..N brez vrzeli, stevec = N`, vse.map((x) => x.stevilka));
      assert(!/TypeError|ReferenceError/.test(A.log), "A: v dnevniku ni izjem", A.log.split("\n").filter((l) => /TypeError|ReferenceError/.test(l)).slice(0, 3));
    }

    // ================================================================
    console.log("\n# 9. Rok klica tece sele po mestu v semaforju (regresija, pregled PR #315)");
    {
      await ustavi(A);   // delavec procesa A ne sme prevzemati teh vrstic
      // 3 racuni v vrsti, ponudnik odgovori v 250 ms, en hkraten klic, rok 400 ms: tretji caka v vrsti ~500 ms (> rok), a mora biti poslan in potrjen v PRVEM poskusu.
      const ref9 = [], id9 = [];
      for (let i = 0; i < 3; i++) {
        const o = (await pool.query(`INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, paid_at, buyer_email, stripe_account_id)
          VALUES ($1, (SELECT id FROM users WHERE email='cene@outly.si'), $2, 2, 1, 100, 100, 'paid', NOW(), 'cene@outly.si', 'platform') RETURNING id, public_ref`, ["OUT-SEM" + i, evO])).rows[0];
        await pool.query("INSERT INTO racuni (order_id, vrsta, znesek_cents) VALUES ($1, 'racun', 100)", [o.id]);
        ref9.push(o.public_ref); id9.push(o.id); P.nacin[o.public_ref] = "pocasi";
      }
      const w9 = racuni.ustvari({ pool, env: { RACUNI_PONUDNIK: "lazni", RACUNI_LAZNI_URL: `http://127.0.0.1:${PONUDNIK_PORT}/potrdi`, RACUNI_VZPOREDNO: "1", RACUNI_DB_VZPOREDNO: "3", RACUNI_ROK_MS: "400", RACUNI_TICK_MS: "0", RACUNI_PREMOR_MS: "60000" } });
      await w9.tek();
      const st9 = (await pool.query("SELECT stanje, poskusi, naknadno FROM racuni WHERE order_id = ANY($1::bigint[]) ORDER BY order_id", [id9])).rows;
      assert(st9.every((x) => x.stanje === "potrjen" && x.poskusi === 0 && x.naknadno === false) && ref9.every((r) => klicaZa(r).length === 1),
        "en hkraten klic, 3 racuni v vrsti: vsi potrjeni v prvem poskusu, vsak natanko en klic (rok ne tece med cakanjem v vrsti)", [st9, ref9.map((r) => klicaZa(r).length)]);
    }

    // ================================================================
    console.log("\n# 10. S2: dobropis se izda sele, ko je Stripovo vracilo izvedeno (pending -> ni izdaje, succeeded -> izdaja, failed -> preklican + POZOR)");
    {
      A = zagon(PORT_A, { RACUNI_PONUDNIK: "lazni", RACUNI_LAZNI_URL: `http://127.0.0.1:${PONUDNIK_PORT}/potrdi`, RACUNI_TICK_MS: "150", RACUNI_PREMOR_MS: "250", RACUNI_ODLOG_MS: "100",
        RACUNI_ROK_MS: "1200", RACUNI_POSPRAVI_MS: "0", VRACILA_TICK_MS: "0" });
      await cakajStreznik(bA);
      P.privzeto = "ok";
      const Y = await kupiInPlacaj(bA, T.ana, evO, 2), Z = await kupiInPlacaj(bA, T.bor, evO, 1);
      assert(await cakaj(async () => (await racuniNarocila(Y.id))[0]?.stanje === "potrjen" && (await racuniNarocila(Z.id))[0]?.stanje === "potrjen", 8000), "S2: izvirna racuna potrjena");
      const ch = (x) => S.pi[x.pi].latest_charge;
      // pending
      const reP = vrni(Y.pi, 1000, {}, "pending");
      await webhook(bA, "charge.refunded", { id: ch(Y) });
      await pocakaj(800);
      let d = (await racuniNarocila(Y.id)).filter((x) => x.vrsta === "dobropis");
      assert(d.length === 1 && d[0].vir === reP.id && d[0].vracilo_uspelo === null && d[0].stanje === "caka" && d[0].stevilka === null && klicaZa(Y.ref).filter((k) => k.vrsta === "dobropis").length === 0,
        "pending: dobropis vpisan, izid neznan, NI izdan (brez stevilke) in NI poslan ponudniku", d);
      // succeeded (webhook refund.updated -> svez objekt)
      S.reById[reP.id].status = "succeeded";
      await webhook(bA, "refund.updated", { id: reP.id });
      assert(await cakaj(async () => (await racuniNarocila(Y.id)).some((x) => x.vrsta === "dobropis" && x.stanje === "potrjen"), 8000), "succeeded (refund.updated): dobropis izdan in potrjen", await racuniNarocila(Y.id));
      // failed
      const reF = vrni(Z.pi, 1000, {}, "pending");
      await webhook(bA, "charge.refunded", { id: ch(Z) });
      S.reById[reF.id].status = "failed"; S.ch[ch(Z)].amount_refunded -= 1000;
      const prejLog = A.log.length;
      await webhook(bA, "refund.failed", { id: reF.id });
      assert(await cakaj(async () => (await racuniNarocila(Z.id)).some((x) => x.vir === reF.id && x.stanje === "preklican"), 5000), "failed (refund.failed): dobropis preklican pred izdajo", await racuniNarocila(Z.id));
      await webhook(bA, "charge.refunded", { id: ch(Z) });   // ponovljen webhook z zavrnjenim vracilom v seznamu
      await pocakaj(800);
      d = (await racuniNarocila(Z.id)).filter((x) => x.vrsta === "dobropis");
      assert(d.length === 1 && d[0].stevilka === null && d[0].vracilo_uspelo === false && klicaZa(Z.ref).filter((k) => k.vrsta === "dobropis").length === 0,
        "failed: dobropis NI izdan, ponudnik ga ni dobil, ponovljen webhook ne doda novega", d);
      assert(new RegExp(`\\[racuni\\] POZOR: Stripe vracilo ${reF.id} je failed: dobropis \\d+ \\(narocilo ${Z.id}\\) NI izdan`).test(A.log.slice(prejLog)), "failed: [racuni] POZOR");
      assert(await zavrne("UPDATE racuni SET stanje='caka' WHERE vir=$1", [reF.id]) === true && await zavrne("DELETE FROM racuni WHERE vir=$1", [reF.id]) === true, "preklican dobropis: ne nazaj v caka, ne izbris (sled)");
      // ponovni poskus vracila (novo Stripovo vracilo) -> natanko en nov dobropis, izdan
      const reS = vrni(Z.pi, 1000, {}, "succeeded");
      await webhook(bA, "charge.refunded", { id: ch(Z) });
      assert(await cakaj(async () => (await racuniNarocila(Z.id)).some((x) => x.vir === reS.id && x.stanje === "potrjen"), 8000), "ponovni poskus vracila: nov dobropis (nov vir) izdan in potrjen");
      d = (await racuniNarocila(Z.id)).filter((x) => x.vrsta === "dobropis");
      assert(d.length === 2 && d.filter((x) => x.stanje === "potrjen").length === 1 && d.filter((x) => x.stanje === "preklican").length === 1, "Z: en preklican + en potrjen dobropis, brez dvojnika", d.map((x) => [x.vir, x.stanje]));
      await ustavi(A);
    }

    // ================================================================
    console.log("\n# 11. S1: vpis dobropisa (webhook) ne caka na izdajo istega racuna; cakanje na stevec ne drzi vrstice racuna");
    {
      const oS = (await pool.query(`INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, paid_at, buyer_email, stripe_account_id)
        VALUES ('OUT-S1A', (SELECT id FROM users WHERE email='cene@outly.si'), $1, 2, 1, 500, 500, 'paid', NOW(), 'cene@outly.si', 'platform') RETURNING id`, [evO])).rows[0].id;
      const rS = Number((await pool.query("INSERT INTO racuni (order_id, vrsta, znesek_cents, naslednji_poskus_at) VALUES ($1, 'racun', 500, NOW() + INTERVAL '30 days') RETURNING id", [oS])).rows[0].id);
      const c1 = await pool.connect(), c2 = await pool.connect(), c0 = await pool.connect();
      try {
        // (a) izdaja istega racuna je odprta (stevilka zapisana, transakcija se ni potrjena), webhook vpise dobropis z FK na ta racun in drzi vrstico narocila
        await c1.query("BEGIN");
        const iz = await racuni.izdajVTransakciji(c1, rS, { prostor: "S1", naprava: "1" });
        await c2.query("BEGIN"); await c2.query("SET LOCAL lock_timeout = 1000");
        await c2.query("SELECT 1 FROM orders WHERE id = $1 FOR UPDATE", [oS]);
        const t0 = Date.now(); let napaka = null;
        try { await racuni.vpisiDobropis(c2, oS, 200, 200, "re_s1_a", true); } catch (e) { napaka = e.code || e.message; }
        const ms = Date.now() - t0;
        assert(iz.stanje === "izdan" && napaka === null && ms < 200, `vpis dobropisa med odprto izdajo racuna: brez lock_timeout (55P03), ${ms} ms (< 200 ms)`, [iz, napaka, ms]);
        await c2.query("ROLLBACK"); await c1.query("COMMIT");
        // (b) druga izdaja drzi stevec; izdaja racuna rS2 caka na stevec - vrstica rS2 pri tem NI zaklenjena (webhook jo lahko zaklene takoj)
        const oS3 = (await pool.query(`INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, paid_at, buyer_email, stripe_account_id)
          VALUES ('OUT-S1B', (SELECT id FROM users WHERE email='cene@outly.si'), $1, 2, 1, 300, 300, 'paid', NOW(), 'cene@outly.si', 'platform') RETURNING id`, [evO])).rows[0].id;
        const rS3 = Number((await pool.query("INSERT INTO racuni (order_id, vrsta, znesek_cents, naslednji_poskus_at) VALUES ($1, 'racun', 300, NOW() + INTERVAL '30 days') RETURNING id", [oS3])).rows[0].id);
        await c0.query("BEGIN");
        await c0.query("SELECT zadnja FROM racuni_zaporedje WHERE prostor = 'S1' AND naprava = '1' FOR UPDATE");   // druga izdaja drzi stevec
        await c1.query("BEGIN");
        const cakajoca = racuni.izdajVTransakciji(c1, rS3, { prostor: "S1", naprava: "1" });
        await pocakaj(150);
        await c2.query("BEGIN"); await c2.query("SET LOCAL lock_timeout = 300");
        const t1 = Date.now(); let n2 = null;
        try { await c2.query("SELECT 1 FROM racuni WHERE id = $1 FOR UPDATE", [rS3]); } catch (e) { n2 = e.code || e.message; }
        const ms2 = Date.now() - t1;
        await c2.query("ROLLBACK");
        assert(n2 === null && ms2 < 100, `izdaja caka na stevec, vrstica racuna pa je prosta (zaklep v ${ms2} ms)`, [n2, ms2]);
        await c0.query("ROLLBACK");
        const iz3 = await cakajoca; await c1.query("COMMIT");
        assert(iz3.stanje === "izdan" && iz3.stevilka === 2, "po sprostitvi stevca racun izdan z naslednjo stevilko (2)", iz3);
      } finally { for (const c of [c0, c1, c2]) { await c.query("ROLLBACK").catch(() => {}); c.release(); } }
    }

    // ================================================================
    console.log("\n# 12. M1: ponudnik, ki prezre signal in se nikoli ne odzove, ne zasede semaforja (trd rok)");
    {
      const id12 = [];
      for (let i = 0; i < 3; i++) {
        const o = (await pool.query(`INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, paid_at, buyer_email, stripe_account_id)
          VALUES ($1, (SELECT id FROM users WHERE email='cene@outly.si'), $2, 2, 1, 100, 100, 'paid', NOW(), 'cene@outly.si', 'platform') RETURNING id`, ["OUT-NIK" + i, evO])).rows[0].id;
        await pool.query("INSERT INTO racuni (order_id, vrsta, znesek_cents) VALUES ($1, 'racun', 100)", [o]);
        id12.push(o);
      }
      let klicev = 0;
      const nikoli = { ime: "nikoli", potrdi: () => { klicev++; return new Promise(() => {}); } };
      const w12 = racuni.ustvari({ pool, env: { RACUNI_VZPOREDNO: "1", RACUNI_ROK_MS: "300", RACUNI_TICK_MS: "0", RACUNI_PREMOR_MS: "60000" }, ponudnik: nikoli });
      const t0 = Date.now();
      const izid = await Promise.race([w12.tek().then(() => "koncan"), pocakaj(5000).then(() => "visi")]);
      const st = (await pool.query("SELECT stanje, poskusi, naknadno, zadnja_napaka FROM racuni WHERE order_id = ANY($1::bigint[])", [id12])).rows;
      assert(izid === "koncan" && Date.now() - t0 < 3000 && klicev === 3 && st.every((x) => x.stanje === "izdan" && x.poskusi === 1 && x.naknadno && /rok 300 ms/.test(x.zadnja_napaka)),
        `tek se konca v ${Date.now() - t0} ms: vsi 3 klici poslani (semafor 1 se sprosti ob roku), racuni izdani z oznako naknadno`, [izid, klicev, st]);
    }
  } catch (e) {
    fail++; console.error("NAPAKA TESTA:", e);
  } finally {
    sprostiVisece();
    await ustavi(B); await ustavi(A);
    if (fail && A) console.log("--- dnevnik A (zadnjih 40 vrstic) ---\n" + A.log.split("\n").slice(-40).join("\n"));
    if (fail) console.log("--- dnevnik B (zadnjih 20 vrstic) ---\n" + B.log.split("\n").slice(-20).join("\n"));
    await pool.end();
    for (const s of [jwksServer, stripeServer, resendServer, ponudnikServer]) s.close();
    console.log(`\n${ok} ok, ${fail} napak`);
    process.exit(fail ? 1 : 0);
  }
})();
