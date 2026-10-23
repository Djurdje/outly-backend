#!/usr/bin/env node
/**
 * Mnozicna dejanja nad dogodki (POST /admin/api/events/bulk, #329, nacrt admin panela 23. 10. 2026 razdelek 2.4, invarianta I60).
 * Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_admin_mnozicno.js
 * Vzorec kot test_prodaja_pavza.js: lokalni JWKS, lazni Stripe (STRIPE_API_BASE), backend na svojem portu, TRUNCATE na zacetku, brez sleep (cakanje na pogoj).
 *
 *  M1  pavza 3 dogodkov (pause): nakup (vstopnice) 409 na vseh, cakajoca narocila preklicana (I53), Stripove seje zaprte, odgovor po dogodkih, ena vrstica
 *      event.sales_pause z razlogom na dogodek; ponovna pavza = ok brez spremembe in brez nove vrstice; resume: nakup spet 201, vrstica event.sales_resume
 *  M2  draft: dogodek postane osnutek, placana vstopnica ostane veljavna, sken (POST /business/tickets/scan) deluje; vrstica event.unpublish; odpovedan dogodek 409
 *  M3  reschedule: dogodek brez prodaje se premakne (zacetek po ljubljanski uri tudi cez prehod poletnega casa, konec in okno prodaje za isti zamik), dogodek s placanim
 *      narocilom / narocilom v teku / vstopnico 409 has_sales in NESPREMENJEN, minil 409 event_finished, odpovedan 409 event_cancelled, v preteklost 400 start_in_past,
 *      neobstojec 404; ostali v istem klicu uspejo; vrstica event.update z razlogom samo za premaknjene
 *  M4  validacija: > 50 -> 400, prazen seznam, neveljavni id-ji, podvojeni id-ji (enkrat), cancel/delete -> 400 (nic spremenjeno), neznano dejanje, razlog (manjka, 2, 501 znakov,
 *      bidi/nicelna sirina/kontrolni znaki; 3 in 500 znakov, emoji = 1 znak), zamik_min (0, 1.5, niz, > 30 dni, pri drugem dejanju); po 400 NI vrstic v dnevniku
 *  M5  vloge: navaden uporabnik, poslovni, backup 403; brez zetona 401; zeton agenta 403; nic spremenjeno
 *  M6  napaka enega ne ustavi ostalih; transakcija na dogodek: sprozilec zavrne vpis v dnevnik za en dogodek -> ta ni spremenjen, ostali so
 *  M7  Stripe: 50 dogodkov hkrati v pavzi -> zapiranje sej nikoli ne preseze PAVZA_STRIPE_SKUPAJ hkratnih klicev (meja na proces, ne na dogodek); vse seje zaprte
 *  M8  zaklepi: dogodek z zaklepom vrstice (druga seja) -> 503 event_busy v mejah lock_timeout, ostali uspejo; sken ni blokiran z zaklepom dogodka
 *  M11 posamicna pavza NE caka za mnozicno (procesna meja Stripa velja samo za mnozicno pot): seja posamicnega dogodka se zapre hitro, medtem ko mnozicna se tece
 *  M12 prestavitev in nakup: nakup, ki ze drzi vrstico dogodka (vstavljeno narocilo), prestavitev ustavi -> has_sales, dogodek nespremenjen (cakanje na zaklep prek pg_stat_activity)
 *  M13 proracun klica: z ADMIN_MNOZICNO_PRORACUN_MS=1 je obdelan prvi dogodek, ostali not_processed (503), nespremenjeni; razlog PATCH »Med osnutke« se reze po znakih Unicode
 *  M9  izvorna koda: admin_mnozicno.js brez skenPool, brez poti odpovedi/brisanja, brez Promise.all
 *  M10 omejevalnik: 10 klicev na minuto na admina, 11. -> 429 (zadnji del testa)
 */
const crypto = require("crypto");
const http = require("http");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const { Pool, Client } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 6281, JWKS_PORT = 6282, STRIPE_PORT = 6283;
const BASE = `http://127.0.0.1:${PORT}`;
const SKUPAJ = 3;   // PAVZA_STRIPE_SKUPAJ v testu

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-mnozicno";
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
const pocakaj = (ms) => new Promise(r => setTimeout(r, ms));
async function cakajPogoj(f, ms = 10000) { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (await f()) return true; await pocakaj(25); } return false; }

let ipSt = 0;
async function api(method, p, token, body) {
  const r = await fetch(BASE + p, { method, headers: { "content-type": "application/json", "x-forwarded-for": `10.78.${(++ipSt >> 8) & 255}.${(ipSt & 255) + 1}`, ...(token ? { authorization: "Bearer " + token } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}

// Lazni Stripe: ustvari sejo, expire (belezi najvecje stevilo hkratnih klicev).
const S = { seje: {}, st: 0, potekle: [], hkrati: 0, najvec: 0, expireMs: 0 };
const stripeServer = http.createServer((req, res) => {
  let d = ""; req.on("data", x => d += x);
  req.on("end", () => {
    const p = Object.fromEntries(new URLSearchParams(d));
    const odg = (s, o) => { res.writeHead(s, { "content-type": "application/json", "request-id": "req_test" }); res.end(JSON.stringify(o)); };
    const u = req.url.split("?")[0];
    let m;
    if (req.method === "POST" && u === "/v1/checkout/sessions") {
      const id = "cs_test_m" + (++S.st);
      const kol = Number(p["line_items[0][quantity]"]), cena = Number(p["line_items[0][price_data][unit_amount]"]);
      S.seje[id] = { id, object: "checkout.session", url: `https://checkout.stripe.test/c/pay/${id}`, status: "open", payment_status: "unpaid", amount_total: kol * cena,
        currency: p["line_items[0][price_data][currency]"], livemode: false, metadata: { order_id: p["metadata[order_id]"] }, client_reference_id: p.client_reference_id, expires_at: Number(p.expires_at), payment_intent: null };
      return odg(200, S.seje[id]);
    }
    if (req.method === "POST" && (m = u.match(/^\/v1\/checkout\/sessions\/(cs_\w+)\/expire$/))) {
      S.hkrati++; S.najvec = Math.max(S.najvec, S.hkrati);
      return setTimeout(() => {
        S.hkrati--;
        const s = S.seje[m[1]];
        if (!s) return odg(404, { error: { type: "invalid_request_error", message: "No such checkout.session" } });
        if (s.status !== "open") return odg(400, { error: { type: "invalid_request_error", message: "Session is not open" } });
        S.potekle.push(m[1]); s.status = "expired"; return odg(200, s);
      }, S.expireMs);
    }
    if (req.method === "GET" && (m = u.match(/^\/v1\/checkout\/sessions\/(cs_\w+)$/))) return S.seje[m[1]] ? odg(200, S.seje[m[1]]) : odg(404, { error: { type: "invalid_request_error", message: "No such session" } });
    return odg(404, { error: { type: "invalid_request_error", message: "Lazni Stripe: neznana pot " + req.method + " " + u } });
  });
});

// Ljubljanski odmik od UTC v minutah (Intl) in prvi trenutek, od katerega 7 dni naprej prestopi prehod poletnega casa (kot test_admin_podvoji.js).
function odmikLj(ms) {
  const s = new Intl.DateTimeFormat("en-US", { timeZone: "Europe/Ljubljana", timeZoneName: "longOffset" }).formatToParts(new Date(ms)).find((p) => p.type === "timeZoneName").value;
  const m = /GMT([+-])(\d{2}):(\d{2})/.exec(s);
  return m ? (m[1] === "-" ? -1 : 1) * (Number(m[2]) * 60 + Number(m[3])) : 0;
}
function zacetekCezPrehod() {
  const dan = 864e5;
  const t0 = Math.floor((Date.now() + 8 * dan) / dan) * dan + 20 * 3600e3;   // 20:00 UTC; odpre = zacetek - 5 dni mora biti v prihodnosti ali preteklosti (vseeno), zacetek > zdaj
  for (let i = 0; i < 400; i++) { const t = t0 + i * dan; if (odmikLj(t) !== odmikLj(t + 7 * dan)) return t; }
  throw new Error("prehoda poletnega casa ni v naslednjih 400 dneh");
}
const ljUra = (ms) => new Intl.DateTimeFormat("sv-SE", { timeZone: "Europe/Ljubljana", hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).format(new Date(ms));

let srv = null, log = "";
(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE agent_zetoni, omejitve, admin_dejanja, vracila, stripe_events, club_event_notifications, club_follows, guest_list_members, guest_lists, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, event_tables, club_tables, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  await new Promise(r => stripeServer.listen(STRIPE_PORT, r));
  srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test",
    STRIPE_SECRET_KEY: "sk_test_lokalno", STRIPE_WEBHOOK_SECRET: "whsec_test_mnozicno", STRIPE_API_BASE: `http://127.0.0.1:${STRIPE_PORT}`, STRIPE_POSPRAVI_MS: "0", STRIPE_PREKLIC_PO_S: "1",
    APP_URL: "https://outly.test", TEST_PLACILA: "", GOST_NAKUP_TEST: "1", GOST_NAKUP_NA_URO: "1000", REZERVACIJE_CISCENJE_MS: "0", VRACILA_TICK_MS: "0", VRACILA_SWEEP_MS: "0", JAVNI_PREDPOMNILNIK_MS: "0",
    PAVZA_STRIPE_PREMOR_MS: "20", PAVZA_KMALU_MS: "400", PAVZA_PONOVNO_MS: "1500", PAVZA_STRIPE_SKUPAJ: String(SKUPAJ),
    ADMIN_MNOZICNO_ZAKLEP_MS: "500", ADMIN_MNOZICNO_PRORACUN_MS: "60000", ADMIN_NADZOR_PREDPOMNILNIK_MS: "0" }, stdio: ["ignore", "pipe", "pipe"] });
  srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 60; i++) { try { await fetch(BASE + "/"); break; } catch { await pocakaj(100); } }
  const lock = new Client({ connectionString: DB });

  try {
    const T = { admin: zeton("admin@outly.si", uuid(1)), navaden: zeton("navaden@outly.si", uuid(2)), lastnik: zeton("lastnik@outly.si", uuid(3)), kopija: zeton("kopija@outly.si", uuid(4)),
      ana: zeton("ana@outly.si", uuid(5)), bor: zeton("bor@outly.si", uuid(6)), cene: zeton("cene@outly.si", uuid(7)), dana: zeton("dana@outly.si", uuid(8)) };
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    await pool.query("UPDATE users SET role='backup' WHERE email='kopija@outly.si'");
    await pool.query("UPDATE users SET date_of_birth='1990-01-01'");
    await pool.query(`INSERT INTO clubs (owner_user_id, name, city, stripe_account_id, stripe_charges_enabled)
                      VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana', 'acct_test1', TRUE)`);
    await lock.connect();
    const uid = async (email) => (await pool.query("SELECT id FROM users WHERE email=$1", [email])).rows[0].id;
    const adminId = await uid("admin@outly.si"), anaId = await uid("ana@outly.si");

    const DAN = 864e5, H = 3600e3;
    const dogodek = async (naslov, polja = {}) => {
      const e = { status: "published", start: new Date(Date.now() + 10 * DAN), end: "auto", price: 1500, capacity: 100, open: null, close: null, ...polja };
      const konec = e.end === "auto" ? new Date(e.start.getTime() + 6 * H) : e.end;
      return (await pool.query(
        `INSERT INTO events (club_id, title, start_at, end_at, status, ticket_price_cents, capacity, min_age, sales_open_at, sales_close_at)
         VALUES (1, $1, $2, $3, $4, $5, $6, 0, $7, $8) RETURNING id`, [naslov, e.start, konec, e.status, e.price, e.capacity, e.open, e.close])).rows[0].id;
    };
    const dnevnik = async (ev) => (await pool.query("SELECT dejanje, prej, potem, razlog, admin_user_id FROM admin_dejanja WHERE cilj_tip='event' AND cilj_id=$1 ORDER BY id", [String(ev)])).rows;
    const stDnevnika = async () => (await pool.query("SELECT COUNT(*)::int AS n FROM admin_dejanja")).rows[0].n;
    const ev = async (id) => (await pool.query("SELECT status, sales_paused, start_at, end_at, sales_open_at, sales_close_at FROM events WHERE id=$1", [id])).rows[0];
    const narocilo = async (id) => (await pool.query("SELECT id, status, stripe_checkout_session_id AS seja FROM orders WHERE id=$1", [id])).rows[0];
    // Omejevalnik (M10) steje klice na admina: pred vsakim klicem ga pocistimo, razen v M10.
    const bulk = async (tok, telo, brezCiscenja = false) => { if (!brezCiscenja) await pool.query("TRUNCATE omejitve"); return api("POST", "/admin/api/events/bulk", tok, telo); };
    const kupi = (tok, e, kol = 1) => api("POST", `/events/${e}/orders`, tok, { quantity: kol });
    const RAZLOG = "Napaka na plakatu, ustavimo za vse";
    const PAVZA = /not on sale/i;

    // ---------------- M1: pavza in ponovni vklop ----------------
    console.log("\n# M1: pause 3 dogodkov");
    const [E1, E2, E3] = [await dogodek("Pavza 1"), await dogodek("Pavza 2"), await dogodek("Pavza 3")];
    const n1 = await kupi(T.ana, E1), n2 = await kupi(T.bor, E2), n3 = await kupi(T.cene, E3);
    assert(n1.status === 201 && n2.status === 201 && n3.status === 201 && n1.body.checkout_url, "priprava: tri cakajoca narocila z odprto Stripovo sejo", [n1.body, n2.body, n3.body]);
    const nar = [n1, n2, n3].map(n => n.body.order.id);
    const seje = await Promise.all(nar.map(async id => (await narocilo(id)).seja));
    let r = await bulk(T.admin, { ids: [E1, E2, E3], dejanje: "pause", razlog: RAZLOG });
    assert(r.status === 200 && r.body.dejanje === "pause" && r.body.results.length === 3 && r.body.results.every((x, i) => x.ok === true && x.spremenjeno === true && x.id === [E1, E2, E3][i]),
      "200, rezultat po dogodkih v vrstnem redu, vsi ok in spremenjeno", r.body);
    for (const e of [E1, E2, E3]) assert((await ev(e)).sales_paused === true, `dogodek ${e}: sales_paused`);
    for (const [i, id] of nar.entries()) assert((await narocilo(id)).status === "cancelled", `cakajoce narocilo ${i + 1} preklicano (I53)`);
    for (const [i, e] of [E1, E2, E3].entries()) {
      const k = await kupi(T.dana, e);
      assert(k.status === 409 && PAVZA.test(k.body), `nakup vstopnice na dogodku ${i + 1} -> 409 »not on sale«`, k);
    }
    assert(await cakajPogoj(() => seje.every(s => S.potekle.includes(s))), "Stripove seje treh narocil zaprte (v ozadju)", { seje, potekle: S.potekle });
    for (const e of [E1, E2, E3]) {
      const d = await dnevnik(e);
      assert(d.length === 1 && d[0].dejanje === "event.sales_pause" && d[0].razlog === RAZLOG && d[0].admin_user_id === adminId && d[0].potem.sales_paused === true, `dnevnik dogodka ${e}: ena vrstica event.sales_pause z razlogom`, d);
    }
    const prejDn = await stDnevnika();
    r = await bulk(T.admin, { ids: [E1, E2], dejanje: "pause", razlog: RAZLOG });
    assert(r.status === 200 && r.body.results.every(x => x.ok === true && x.spremenjeno === false) && await stDnevnika() === prejDn, "ponovna pavza: ok, spremenjeno false, brez nove vrstice v dnevniku", r.body);

    console.log("\n# M1b: resume");
    r = await bulk(T.admin, { ids: [E1, E2, E3], dejanje: "resume", razlog: "Plakat popravljen" });
    assert(r.status === 200 && r.body.results.every(x => x.ok === true && x.spremenjeno === true), "resume: vsi ok", r.body);
    for (const e of [E1, E2, E3]) {
      const d = await dnevnik(e);
      assert((await ev(e)).sales_paused === false && d.length === 2 && d[1].dejanje === "event.sales_resume" && d[1].razlog === "Plakat popravljen", `dogodek ${e}: prodaja tece, vrstica event.sales_resume z razlogom`, d);
    }
    const k1 = await kupi(T.dana, E1);
    assert(k1.status === 201, "nakup po ponovnem vklopu spet 201", k1);

    // ---------------- M2: draft ----------------
    console.log("\n# M2: draft (placane vstopnice ostanejo veljavne)");
    const E4 = await dogodek("Osnutek s kupci", { start: new Date(Date.now() + 2 * H), price: 0 });
    const E5 = await dogodek("Osnutek brez kupcev");
    const E6c = await dogodek("Odpovedan", { status: "cancelled" });
    const brezplacna = await kupi(T.ana, E4, 2);
    assert(brezplacna.status === 201 && brezplacna.body.tickets && brezplacna.body.tickets.length === 2, "priprava: brezplacno narocilo z 2 vstopnicama", brezplacna.body);
    r = await bulk(T.admin, { ids: [E4, E5, E6c], dejanje: "draft", razlog: "Skrijemo do potrditve gostitelja" });
    assert(r.status === 200 && r.body.results[0].ok === true && r.body.results[0].spremenjeno === true && r.body.results[1].ok === true &&
      r.body.results[2].ok === false && r.body.results[2].napaka === "event_cancelled" && r.body.results[2].status === 409, "draft: dva ok, odpovedan dogodek 409 event_cancelled", r.body);
    assert((await ev(E4)).status === "draft" && (await ev(E5)).status === "draft" && (await ev(E6c)).status === "cancelled", "stanja: osnutek, osnutek, odpovedan ostane odpovedan");
    const d4 = await dnevnik(E4);
    assert(d4.length === 1 && d4[0].dejanje === "event.unpublish" && d4[0].razlog === "Skrijemo do potrditve gostitelja" && (await dnevnik(E6c)).length === 0, "dnevnik: event.unpublish z razlogom; odpovedan brez vrstice", d4);
    const vst = (await pool.query("SELECT status FROM tickets WHERE event_id=$1", [E4])).rows;
    assert(vst.length === 2 && vst.every(v => v.status === "valid"), "placane vstopnice ostanejo veljavne", vst);
    const sk = await api("POST", "/business/tickets/scan", T.lastnik, { qr: brezplacna.body.tickets[0].qr });
    assert(sk.status === 200 && sk.body.result === "ok", "sken vstopnice dogodka v osnutku deluje", sk);
    r = await bulk(T.admin, { ids: [E5], dejanje: "draft", razlog: "Se enkrat" });
    assert(r.body.results[0].ok === true && r.body.results[0].spremenjeno === false && (await dnevnik(E5)).length === 1, "ponovni draft: ok brez spremembe in brez nove vrstice");

    // ---------------- M3: reschedule ----------------
    console.log("\n# M3: reschedule");
    const zac = zacetekCezPrehod();
    const sOd = new Date(zac), kon = new Date(zac + 6 * H), odpre = new Date(zac - 5 * DAN), zapre = new Date(zac - 1 * H);
    const R1 = await dogodek("Prestavi 1", { start: sOd, end: kon, open: odpre, close: zapre });
    const R2 = await dogodek("Prestavi 2 osnutek brez konca", { start: new Date(Date.now() + 4 * DAN), end: null, status: "draft" });
    const R3 = await dogodek("Prodan", { start: new Date(Date.now() + 5 * DAN) });
    const R4 = await dogodek("Narocilo v teku", { start: new Date(Date.now() + 6 * DAN) });
    const R5 = await dogodek("Samo vstopnica", { start: new Date(Date.now() + 7 * DAN) });
    const R6 = await dogodek("Minil", { start: new Date(Date.now() - 3 * H), end: new Date(Date.now() + 3 * H) });
    const R7 = await dogodek("Odpovedan", { status: "cancelled", start: new Date(Date.now() + 8 * DAN) });
    const placano = await kupi(T.bor, R3, 1);   // pending; naredi placano z SQL (kot po webhooku)
    await pool.query("UPDATE orders SET status='paid', paid_at=NOW() WHERE id=$1", [placano.body.order.id]);
    const tecoce = await kupi(T.cene, R4, 1);
    assert(placano.status === 201 && tecoce.status === 201, "priprava: placano narocilo (R3) in narocilo v teku (R4)", [placano.body, tecoce.body]);
    const oR5 = (await pool.query(
      `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, paid_at)
       VALUES ('OUT-MNOZ-1', $1, $2, 1, 1, 0, 0, 'refunded', 'ana@primer.si', NOW()) RETURNING id`, [anaId, R5])).rows[0].id;
    await pool.query("INSERT INTO tickets (order_id, event_id, status) VALUES ($1, $2, 'valid')", [oR5, R5]);
    const pred = {}; for (const e of [R1, R2, R3, R4, R5, R6, R7]) pred[e] = await ev(e);
    const ZAMIK = 7 * 1440;
    r = await bulk(T.admin, { ids: [R1, R2, R3, R4, R5, R6, R7, 2000000000], dejanje: "reschedule", zamik_min: ZAMIK, razlog: "Gostitelj je prestavil za teden dni" });
    const rez = Object.fromEntries((r.body.results || []).map(x => [x.id, x]));
    assert(r.status === 200 && r.body.results.length === 8, "200 in rezultat za vseh 8 dogodkov", r.body);
    assert(rez[R1].ok === true && rez[R2].ok === true, "dogodka brez prodaje: ok", [rez[R1], rez[R2]]);
    assert(rez[R3].ok === false && rez[R3].napaka === "has_sales" && rez[R3].status === 409, "placano narocilo: 409 has_sales", rez[R3]);
    assert(rez[R4].ok === false && rez[R4].napaka === "has_sales", "narocilo v teku (pending): 409 has_sales", rez[R4]);
    assert(rez[R5].ok === false && rez[R5].napaka === "has_sales", "veljavna vstopnica (tudi ob vrnjenem narocilu): 409 has_sales", rez[R5]);
    assert(rez[R6].ok === false && rez[R6].napaka === "event_finished" && rez[R6].status === 409, "ze zacet dogodek: 409 event_finished", rez[R6]);
    assert(rez[R7].ok === false && rez[R7].napaka === "event_cancelled", "odpovedan dogodek: 409 event_cancelled", rez[R7]);
    assert(rez[2000000000].ok === false && rez[2000000000].napaka === "event_not_found" && rez[2000000000].status === 404, "neobstojec id: 404 event_not_found, ostali uspejo", rez[2000000000]);
    const po1 = await ev(R1);
    const t0 = new Date(pred[R1].start_at).getTime(), t1 = new Date(po1.start_at).getTime(), delta = t1 - t0;
    assert(ljUra(t1) === ljUra(t0), `zacetek ostane na isti ljubljanski uri tudi cez prehod poletnega casa (${ljUra(t0)})`, [ljUra(t0), ljUra(t1)]);
    assert(Math.abs(delta - ZAMIK * 60000) === H, "absolutni zamik se razlikuje za 1 h (prehod casa), ne za 7 x 24 h", delta / 60000);
    assert(new Date(po1.end_at).getTime() - new Date(pred[R1].end_at).getTime() === delta && new Date(po1.sales_open_at).getTime() - new Date(pred[R1].sales_open_at).getTime() === delta &&
      new Date(po1.sales_close_at).getTime() - new Date(pred[R1].sales_close_at).getTime() === delta, "konec in okno prodaje premaknjena za ISTI absolutni zamik (trajanje in zamik okna od zacetka ostaneta)");
    const po2 = await ev(R2);
    assert(new Date(po2.start_at) > new Date(pred[R2].start_at) && po2.end_at === null && po2.sales_open_at === null && po2.status === "draft", "osnutek brez konca in okna: premaknjen, null ostane null, status nespremenjen", po2);
    for (const e of [R3, R4, R5, R6, R7]) assert(JSON.stringify(await ev(e)) === JSON.stringify(pred[e]), `dogodek ${e} NESPREMENJEN`);
    for (const e of [R1, R2]) {
      const d = await dnevnik(e);
      assert(d.length === 1 && d[0].dejanje === "event.update" && d[0].razlog === "Gostitelj je prestavil za teden dni" && d[0].potem.start_at && d[0].prej.start_at, `dnevnik dogodka ${e}: ena vrstica z razlogom in prej/potem`, d);
    }
    for (const e of [R3, R4, R5, R6, R7]) assert((await dnevnik(e)).length === 0, `dogodek ${e}: brez vrstice v dnevniku`);
    r = await bulk(T.admin, { ids: [R1, R2], dejanje: "reschedule", zamik_min: -60, razlog: "Eno uro prej" });
    assert(r.body.results.every(x => x.ok === true) && new Date((await ev(R1)).start_at).getTime() === t1 - H, "negativen zamik (-60 min) premakne zacetek nazaj");
    r = await bulk(T.admin, { ids: [R2], dejanje: "reschedule", zamik_min: -30 * 1440, razlog: "Preveč nazaj" });
    assert(r.status === 200 && r.body.results[0].ok === false && r.body.results[0].napaka === "start_in_past" && r.body.results[0].status === 400, "nov zacetek v preteklosti: per-dogodek 400 start_in_past", r.body);

    // ---------------- M4: validacija ----------------
    console.log("\n# M4: validacija");
    const pred4 = await stDnevnika();
    const veljaven = { ids: [E1], dejanje: "pause", razlog: RAZLOG };
    const slabo = async (ime, telo, koda) => {
      const x = await bulk(T.admin, telo);
      assert(x.status === 400 && x.body.error === koda && typeof x.body.message === "string", `${ime} -> 400 ${koda}`, x);
    };
    await slabo("51 id-jev", { ...veljaven, ids: Array.from({ length: 51 }, (_, i) => i + 1) }, "too_many");
    await slabo("brez ids", { dejanje: "pause", razlog: RAZLOG }, "invalid_ids");
    await slabo("prazen ids", { ...veljaven, ids: [] }, "invalid_ids");
    await slabo("ids ni seznam", { ...veljaven, ids: "1,2" }, "invalid_ids");
    for (const slab of ["abc", -1, 0, 1.5, 2147483648, null, {}, [1]]) await slabo(`id ${JSON.stringify(slab)}`, { ...veljaven, ids: [E1, slab] }, "invalid_ids");
    await slabo("cancel", { ...veljaven, dejanje: "cancel" }, "action_not_allowed");
    await slabo("delete", { ...veljaven, dejanje: "delete" }, "action_not_allowed");
    await slabo("neznano dejanje", { ...veljaven, dejanje: "publish" }, "invalid_action");
    await slabo("brez dejanja", { ids: [E1], razlog: RAZLOG }, "invalid_action");
    await slabo("brez razloga", { ids: [E1], dejanje: "pause" }, "invalid_reason");
    await slabo("razlog 2 znaka", { ...veljaven, razlog: "ab" }, "invalid_reason");
    await slabo("razlog samo presledki", { ...veljaven, razlog: "     " }, "invalid_reason");
    await slabo("razlog 501 znakov", { ...veljaven, razlog: "x".repeat(501) }, "invalid_reason");
    await slabo("razlog ni niz", { ...veljaven, razlog: 12345 }, "invalid_reason");
    for (const [ime, z] of [["bidi override U+202E", "ok ‮ gnp.exe"], ["nicelna sirina U+200B", "ok​ok"], ["BOM U+FEFF", "﻿razlog"], ["mehki vezaj U+00AD", "raz­log"], ["kontrolni znak", "raz\u0007log"], ["nova vrstica", "vrstica 1\nvrstica 2"], ["kontrolni znak na robu (pred trim)", "\nrazlog\u0007"], ["vodilna nova vrstica (surov niz)", "\nrazlog"]]) {
      await slabo(`razlog z ${ime}`, { ...veljaven, razlog: z }, "invalid_reason");
    }
    for (const z of [0, 1.5, "60", 43201, -43201, null]) await slabo(`reschedule z zamik_min ${JSON.stringify(z)}`, { ids: [R2], dejanje: "reschedule", zamik_min: z, razlog: RAZLOG }, "invalid_shift");
    await slabo("reschedule brez zamik_min", { ids: [R2], dejanje: "reschedule", razlog: RAZLOG }, "invalid_shift");
    await slabo("zamik_min pri pause", { ...veljaven, zamik_min: 60 }, "invalid_shift");
    assert(await stDnevnika() === pred4, "po vseh zavrnjenih klicih ni nobene nove vrstice v dnevniku");
    assert(!(await ev(E1)).sales_paused, "zavrnjen cancel/neveljaven klic ni spremenil dogodka");
    r = await bulk(T.admin, { ids: [E1], dejanje: "pause", razlog: "abc" });
    assert(r.status === 200 && r.body.results[0].ok === true, "razlog z natanko 3 znaki je veljaven");
    r = await bulk(T.admin, { ids: [E1], dejanje: "resume", razlog: "😀".repeat(500) });
    assert(r.status === 200 && r.body.results[0].ok === true, "razlog 500 emojijev (500 znakov Unicode) je veljaven");
    r = await bulk(T.admin, { ids: [E1], dejanje: "pause", reason: "Razlog prek polja reason" });
    assert(r.status === 200 && r.body.results[0].ok === true && (await dnevnik(E1)).slice(-1)[0].razlog === "Razlog prek polja reason", "polje `reason` (kot PATCH) je enakovreden `razlog`");
    await bulk(T.admin, { ids: [E1], dejanje: "resume", razlog: "nazaj" });
    r = await bulk(T.admin, { ids: [E2, E2, E1, E2, E1], dejanje: "pause", razlog: RAZLOG });
    assert(r.status === 200 && r.body.results.length === 2 && r.body.results[0].id === E2 && r.body.results[1].id === E1, "podvojeni id-ji: vsak dogodek enkrat, vrstni red prvega pojavljanja", r.body);
    assert((await dnevnik(E2)).filter(d => d.dejanje === "event.sales_pause").length === 2, "podvojeni id: samo ena nova vrstica dnevnika na dogodek", await dnevnik(E2));
    r = await bulk(T.admin, { ids: Array.from({ length: 50 }, (_, i) => 1000000 + i), dejanje: "pause", razlog: RAZLOG });
    assert(r.status === 200 && r.body.results.length === 50 && r.body.results.every(x => x.ok === false && x.napaka === "event_not_found"), "natanko 50 id-jev je dovoljeno (neobstojeci: 50 x 404)");
    await bulk(T.admin, { ids: [E1, E2], dejanje: "resume", razlog: "nazaj" });

    // ---------------- M5: vloge ----------------
    console.log("\n# M5: vloge");
    const telo5 = { ids: [E1], dejanje: "pause", razlog: RAZLOG };
    for (const k of ["navaden", "lastnik", "kopija", "ana"]) { const x = await bulk(T[k], telo5); assert(x.status === 403, `${k}: 403`, x); }
    let x = await bulk(null, telo5); assert(x.status === 401, "brez zetona: 401", x);
    const za = await api("POST", "/admin/api/agent-zetoni", T.admin, { ime: "Test mnozicno" });
    const agentZeton = za.body && za.body.zeton;
    assert(za.status === 201 && /^outly_agent_/.test(String(agentZeton)), "priprava: zeton agenta", za.body && za.status);
    const pred5 = await stDnevnika();   // po ustvarjanju zetona (to zapise svojo vrstico)
    x = await bulk(agentZeton, telo5); assert(x.status === 403, "zeton agenta (obseg beri): 403", x);
    assert(await stDnevnika() === pred5 && !(await ev(E1)).sales_paused, "zavrnjeni klici: nic spremenjeno");

    // ---------------- M6: napaka enega ne ustavi ostalih; transakcija na dogodek ----------------
    console.log("\n# M6: transakcija na dogodek");
    const [P1, P2, P3] = [await dogodek("Trigger 1"), await dogodek("Trigger 2"), await dogodek("Trigger 3")];
    await pool.query(`CREATE OR REPLACE FUNCTION test_mnozicno_zavrni() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.cilj_id = '${P2}' THEN RAISE EXCEPTION 'test: dnevnik zavrnjen'; END IF; RETURN NEW; END $$`);
    await pool.query("CREATE TRIGGER test_mnozicno_zavrni BEFORE INSERT ON admin_dejanja FOR EACH ROW EXECUTE FUNCTION test_mnozicno_zavrni()");
    r = await bulk(T.admin, { ids: [P1, P2, P3], dejanje: "pause", razlog: RAZLOG });
    await pool.query("DROP TRIGGER test_mnozicno_zavrni ON admin_dejanja");
    assert(r.status === 200 && r.body.results[0].ok === true && r.body.results[1].ok === false && r.body.results[1].napaka === "server_error" && r.body.results[1].status === 500 && r.body.results[2].ok === true,
      "zavrnjen vpis v dnevnik pri enem dogodku: ta 500 server_error, ostala dva ok", r.body);
    assert((await ev(P1)).sales_paused === true && (await ev(P2)).sales_paused === false && (await ev(P3)).sales_paused === true, "dogodek z zavrnjenim dnevnikom NI spremenjen (ni spremembe brez vrstice), ostala sta");
    assert((await dnevnik(P2)).length === 0 && (await dnevnik(P1)).length === 1 && (await dnevnik(P3)).length === 1, "dnevnik: vrstici samo za P1 in P3");

    // ---------------- M7: Stripe, 50 dogodkov hkrati ----------------
    console.log("\n# M7: 50 dogodkov v pavzi, meja hkratnih klicev Stripa");
    const mnozica = [];
    for (let i = 0; i < 50; i++) mnozica.push(await dogodek("Mnozica " + i, { capacity: 10 }));
    const sejeM = [];
    for (const [i, e] of mnozica.entries()) {
      const sid = "cs_test_mn" + i;
      S.seje[sid] = { id: sid, object: "checkout.session", status: "open", payment_status: "unpaid", livemode: false };
      await pool.query(
        `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, checkout_url, stripe_checkout_session_id)
         VALUES ($1, $2, $3, 1, 1, 1500, 1500, 'pending', 'ana@primer.si', $4, $5)`, ["OUT-MN-" + i, anaId, e, "https://checkout.stripe.test/c/pay/" + sid, sid]);
      sejeM.push(sid);
    }
    S.potekle.length = 0; S.najvec = 0; S.expireMs = 60;
    r = await bulk(T.admin, { ids: mnozica, dejanje: "pause", razlog: "Mnozicna pavza 50 dogodkov" });
    assert(r.status === 200 && r.body.results.length === 50 && r.body.results.every(x => x.ok === true && x.spremenjeno === true), "50 dogodkov v enem klicu: vsi ok", r.body.results && r.body.results.filter(x => !x.ok).slice(0, 3));
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE public_ref LIKE 'OUT-MN-%' AND status='cancelled'")).rows[0].n === 50, "vseh 50 cakajocih narocil preklicanih v transakcijah dogodkov");
    assert(await cakajPogoj(() => sejeM.every(s => S.potekle.includes(s)), 30000), "vseh 50 Stripovih sej zaprtih", { zaprtih: S.potekle.length });
    assert(S.najvec >= 2 && S.najvec <= SKUPAJ, `najvec hkratnih expire klicev Stripa: ${S.najvec} (meja na proces PAVZA_STRIPE_SKUPAJ = ${SKUPAJ}; brez nje do 50)`, S.najvec);
    S.expireMs = 0;
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM admin_dejanja WHERE dejanje='event.sales_pause' AND razlog='Mnozicna pavza 50 dogodkov'")).rows[0].n === 50, "natanko 50 vrstic dnevnika z istim razlogom");
    await bulk(T.admin, { ids: mnozica, dejanje: "resume", razlog: "Konec pavze" });

    // ---------------- M8: zaklepi ----------------
    console.log("\n# M8: zaklep vrstice, sken");
    const [Z1, Z2, Z3] = [await dogodek("Zaklep 1"), await dogodek("Zaklep 2"), await dogodek("Zaklep 3")];
    await lock.query("BEGIN");
    await lock.query("SELECT id FROM events WHERE id = ANY($1) FOR UPDATE", [[Z1, Z2]]);
    const t0m = Date.now();
    r = await bulk(T.admin, { ids: [Z1, Z3, Z2], dejanje: "pause", razlog: RAZLOG });
    const trajanje = Date.now() - t0m;
    assert(r.status === 200 && r.body.results[0].ok === false && r.body.results[0].napaka === "event_busy" && r.body.results[0].status === 503 && r.body.results[1].ok === true && r.body.results[2].napaka === "event_busy",
      "dogodka z zaklepom vrstice: 503 event_busy, prosti dogodek uspe", r.body);
    assert(trajanje < 8000, `klic ne visi (${trajanje} ms pri lock_timeout 500 ms na dogodek)`, trajanje);
    await lock.query("ROLLBACK");
    // sken ni blokiran z zaklepom vrstice dogodka (I16): vstopnica dogodka E4 med zaklepom vrstice E4
    await lock.query("BEGIN");
    await lock.query("SELECT id FROM events WHERE id = $1 FOR UPDATE", [E4]);
    const sk2 = await api("POST", "/business/tickets/scan", T.lastnik, { qr: brezplacna.body.tickets[1].qr });
    assert(sk2.status === 200 && sk2.body.result === "ok", "sken NI blokiran z zaklepom vrstice dogodka (I16)", sk2);
    const rE4 = await bulk(T.admin, { ids: [E4], dejanje: "resume", razlog: RAZLOG });
    assert(rE4.body.results[0].napaka === "event_busy", "bulk na dogodku z zaklepom: busy (bulk zaklene vrstico dogodka, sken je ne)", rE4.body);
    await lock.query("ROLLBACK");
    r = await bulk(T.admin, { ids: [Z1, Z2], dejanje: "pause", razlog: RAZLOG });
    assert(r.body.results.every(x => x.ok === true), "po sprostitvi zaklepa isti dogodki uspejo (nic ni obviselo)", r.body);


    // ---------------- M11: posamicna pavza ne caka za mnozicno ----------------
    console.log("\n# M11: posamicna pavza med mnozicno");
    const vrstaPending = async (naslov, i, pref) => {
      const e = await dogodek(naslov, { capacity: 10 });
      const sid = "cs_test_" + pref + i;
      S.seje[sid] = { id: sid, object: "checkout.session", status: "open", payment_status: "unpaid", livemode: false };
      await pool.query(`INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, checkout_url, stripe_checkout_session_id)
        VALUES ($1, $2, $3, 1, 1, 1500, 1500, 'pending', 'ana@primer.si', $4, $5)`, ["OUT-" + pref + i, anaId, e, "https://checkout.stripe.test/c/pay/" + sid, sid]);
      return { e, sid };
    };
    const velika = []; for (let i = 0; i < 20; i++) velika.push(await vrstaPending("Velika " + i, i, "VE"));
    const posamicen = await vrstaPending("Posamicen", 0, "PO");
    S.potekle.length = 0; S.expireMs = 300;
    r = await bulk(T.admin, { ids: velika.map(v => v.e), dejanje: "pause", razlog: "Velika pavza" });
    assert(r.status === 200 && r.body.results.every(v => v.ok), "priprava: mnozicna pavza 20 dogodkov s pocasnim Stripom");
    const tP = Date.now();
    r = await api("PATCH", `/events/${posamicen.e}`, T.admin, { salesPaused: true });
    assert(r.status === 200 && r.body.sales_paused === true, "posamicno stikalo takoj po mnozicni pavzi: 200");
    assert(await cakajPogoj(() => S.potekle.includes(posamicen.sid), 10000), "seja posamicnega dogodka zaprta");
    const dtP = Date.now() - tP, velikihZaprtih = velika.filter(v => S.potekle.includes(v.sid)).length;
    assert(dtP < 1200 && velikihZaprtih < 20, `posamicna seja zaprta v ${dtP} ms (ne caka za mnozicno), medtem ko je od 20 mnozicnih zaprtih ${velikihZaprtih}`, { dtP, velikihZaprtih });
    assert(await cakajPogoj(() => velika.every(v => S.potekle.includes(v.sid)), 30000), "vse mnozicne seje na koncu zaprte");
    S.expireMs = 0;
    await bulk(T.admin, { ids: velika.map(v => v.e), dejanje: "resume", razlog: "Konec" });

    // ---------------- M12: nakup drzi vrstico dogodka, prestavitev ga ne preskoci ----------------
    console.log("\n# M12: prestavitev in nakup");
    const Q = await dogodek("Dirka", { start: new Date(Date.now() + 5 * DAN) });
    const predQ = await ev(Q);
    await lock.query("BEGIN");
    await lock.query(`INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email)
      VALUES ('OUT-DIRKA', $1, $2, 1, 1, 1500, 1500, 'pending', 'ana@primer.si')`, [anaId, Q]);   // sprozilec rezerviraj_zalogo zdaj drzi vrstico dogodka
    const prestavljanje = bulk(T.admin, { ids: [Q], dejanje: "reschedule", zamik_min: 1440, razlog: "Dirka" });
    assert(await cakajPogoj(async () => (await pool.query("SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query ILIKE '%FOR NO KEY UPDATE%' AND pid <> pg_backend_pid()")).rows.length > 0, 5000),
      "prestavitev caka na zaklep vrstice, ki ga drzi nakup");
    await lock.query("COMMIT");
    r = await prestavljanje;
    assert(r.status === 200 && r.body.results[0].ok === false && r.body.results[0].napaka === "has_sales" && JSON.stringify(await ev(Q)) === JSON.stringify(predQ),
      "po commitu nakupa prestavitev vidi narocilo: 409 has_sales, dogodek nespremenjen", r.body);

    // ---------------- M13: proracun klica, razlog po znakih ----------------
    console.log("\n# M13: proracun klica");
    const srv2 = spawn("node", ["index.js"], { env: { ...process.env, PORT: "6284", SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test", STRIPE_SECRET_KEY: "", STRIPE_WEBHOOK_SECRET: "", TEST_PLACILA: "",
      ADMIN_MNOZICNO_PRORACUN_MS: "1", ADMIN_NADZOR_PREDPOMNILNIK_MS: "0" }, stdio: ["ignore", "ignore", "ignore"] });
    try {
      for (let i = 0; i < 60; i++) { try { await fetch("http://127.0.0.1:6284/"); break; } catch { await pocakaj(100); } }
      const [B1, B2, B3] = [await dogodek("Proracun 1"), await dogodek("Proracun 2"), await dogodek("Proracun 3")];
      const rr = await fetch("http://127.0.0.1:6284/admin/api/events/bulk", { method: "POST", headers: { "content-type": "application/json", authorization: "Bearer " + T.admin }, body: JSON.stringify({ ids: [B1, B2, B3], dejanje: "pause", razlog: "Proracun" }) });
      const jj = await rr.json();
      assert(rr.status === 200 && jj.results[0].ok === true && jj.results[1].ok === false && jj.results[1].napaka === "not_processed" && jj.results[1].status === 503 && jj.results[2].napaka === "not_processed",
        "proracun 1 ms: prvi dogodek obdelan, ostala not_processed (503)", jj);
      assert((await ev(B1)).sales_paused === true && (await ev(B2)).sales_paused === false && (await ev(B3)).sales_paused === false && (await dnevnik(B2)).length === 0, "not_processed: dogodka nespremenjena in brez vrstice v dnevniku");
    } finally { srv2.kill("SIGTERM"); }
    const dolgRazlog = "😀".repeat(600);
    r = await api("PATCH", `/admin/api/events/${E5}`, T.admin, { status: "published", reason: dolgRazlog });
    const rz = (await dnevnik(E5)).slice(-1)[0].razlog;
    assert(r.status === 200 && [...rz].length === 500 && !/�/.test(rz), "razlog PATCH »Med osnutke«/objava: odrezan na 500 znakov Unicode (emoji se ne razpolovi)", [...rz].length);

    // ---------------- M9: izvorna koda ----------------
    console.log("\n# M9: izvorna koda");
    const koda = fs.readFileSync(path.join(__dirname, "..", "admin_mnozicno.js"), "utf8").replace(/\/\/.*$/gm, "");
    assert(!/skenPool/.test(koda), "admin_mnozicno.js ne uporablja skenPool");
    assert(!/DELETE\s+FROM|status\s*=\s*'cancelled'|status:\s*"cancelled"/.test(koda), "admin_mnozicno.js nima poti odpovedi/brisanja dogodka");
    assert(!/Promise\.all/.test(koda), "dogodki tecejo zaporedno (brez Promise.all)");

    // ---------------- M10: omejevalnik (zadnji: ostane blokiran do konca okna) ----------------
    console.log("\n# M10: omejevalnik 10/min na admina");
    await pool.query("TRUNCATE omejitve");
    const stat = [];
    for (let i = 0; i < 11; i++) stat.push((await bulk(T.admin, { ids: [E1], dejanje: "cancel", razlog: RAZLOG }, true)).status);
    assert(stat.slice(0, 10).every(s => s === 400) && stat[10] === 429, "10 klicev obdelanih (400 action_not_allowed), 11. -> 429", stat);
    x = await bulk(T.navaden, telo5, true);
    assert(x.status === 403, "meja je na admina: drug uporabnik ni blokiran (403 zaradi vloge)", x);
  } catch (e) {
    fail++; console.log("  ✗ IZJEMA", e && e.stack || e);
  } finally {
    try { await lock.end(); } catch (_) {}
    srv.kill("SIGTERM");
    await new Promise(r => jwksServer.close(r)); await new Promise(r => stripeServer.close(r));
    await pool.end();
  }
  if (fail) console.log("\n--- dnevnik backenda (brez vrstic [pavza], zadnjih 3000 znakov) ---\n" + log.split("\n").filter(l => !l.startsWith("[pavza]")).join("\n").slice(-3000));
  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); try { srv && srv.kill("SIGTERM"); } catch (_) {} process.exit(1); });
