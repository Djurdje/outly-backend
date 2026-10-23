#!/usr/bin/env node
/**
 * Promo kode, SAMO STATISTIKA (migracija 065, invarianta I61; Martin 23. 10. 2026). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_promo_kode.js
 * Vzorec kot test_finance_admin.js / test_gost.js: lokalni JWKS (ES256), backend na svojem portu (lazni nacin brez Stripa).
 *
 *   1  admin poti: vloge (401/403), ustvarjanje (validacija, normalizacija, 409 podvojena koda), seznam, PATCH, dnevnik admin_dejanja
 *   2  nakup brez kode je kot prej; z veljavno kodo (velike/male crke, trim) ima narocilo promo_code_id, cena/provizija/zaloga so ENAKE kot brez kode (I61)
 *   3  neznana / neaktivna / tuj dogodek / napacen format / napacen tip -> 400 promo_code_invalid, narocilo NE nastane, zaloga se ne rezervira
 *   4  koda kluba velja za vse dogodke kluba, ne za tuje; koda dogodkov samo za izbrane
 *   5  idempotentni kljuc (prijavljen in gost): neveljavna koda -> 400 in kljuc NI zaseden; isti kljuc z veljavno kodo / brez kode -> uspeh;
 *      ponovitev po uspehu z drugo (tudi neveljavno) kodo vrne prvo narocilo
 *   6  gostujoci nakup s kodo
 *   7  VIP nakup s promo_code se ne zavrne in kode ne shrani
 *   8  statistika: samo placana, v celoti vrnjena ne stejejo v vstopnice, testni locen, enako kot GET /admin/api/finance
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 6411, JWKS_PORT = 6410;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-promo";
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
function uuid(n) { return `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`; }
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
async function api(method, path, token, body, glave = {}) {
  const r = await fetch(BASE + path, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}), ...glave }, body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, headers: r.headers };
}
const NEVELJAVNA = { error: "promo_code_invalid", message: "This promo code is not valid for this event." };
const jeNeveljavna = (r) => r.status === 400 && r.body && r.body.error === NEVELJAVNA.error && r.body.message === NEVELJAVNA.message;

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, creator_applications, users, admin_dejanja, promo_code_events, promo_codes RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test",
    GOST_NAKUP_TEST: "1", GOST_NAKUP_NA_URO: "1000", TEST_PLACILA: "" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 80; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  let nakupov = 0;
  const T = {
    admin: zeton("admin@outly.si", uuid(1)), lastnik: zeton("lastnik@outly.si", uuid(2)), lastnik2: zeton("lastnik2@outly.si", uuid(3)),
    kupec: zeton("kupec@outly.si", uuid(4)), navaden: zeton("navaden@outly.si", uuid(5)),
  };
  try {
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("UPDATE users SET role='business' WHERE email IN ('lastnik@outly.si','lastnik2@outly.si')");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana')");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik2@outly.si'), 'Drugi Klub', 'Maribor')");
    await pool.query("UPDATE users SET date_of_birth = (CURRENT_DATE - INTERVAL '25 years')::date WHERE email='kupec@outly.si'");
    const cezTeden = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
    const dogodek = async (lastnik, clubId, title, cena, capacity) => {
      const r = await api("POST", "/events", T[lastnik], { clubId, title, startAt: cezTeden, ticketPriceCents: cena, capacity, minAge: 0 });
      assert(r.status === 201, `dogodek »${title}« ustvarjen`, r.body);
      return r.body.id;
    };
    const E1 = await dogodek("lastnik", 1, "Noc ena", 1000, 100);
    const E2 = await dogodek("lastnik", 1, "Noc dve", 2000, 100);
    const E3 = await dogodek("lastnik2", 2, "Tuji klub", 1500, 100);
    const E4 = await dogodek("lastnik", 1, "Majhen", 1000, 2);

    // Nakup: vsakih 15 nakupov pocisti stevec omejevalnika (20/h na IP; stevec je v tabeli omejitve, ne v pomnilniku, dokler meja ni presezena).
    const pocistiMejo = async () => { if (++nakupov % 12 === 0) await pool.query("TRUNCATE omejitve"); };
    const kupi = async (ev, telo, glave) => { await pocistiMejo(); return api("POST", `/events/${ev}/orders`, T.kupec, telo, glave); };
    let gostStevec = 0;
    const kupiGost = async (ev, telo, glave) => { await pocistiMejo(); return api("POST", `/guest/events/${ev}/orders`, null, { email: `gost${++gostStevec}@example.com`, quantity: 1, accept_terms: true, terms_version: "2026-10-01", ...telo }, glave); };
    const stNarocil = async () => (await pool.query("SELECT COUNT(*)::int AS n FROM orders")).rows[0].n;
    const sold = async (ev) => (await pool.query("SELECT sold_count FROM events WHERE id=$1", [ev])).rows[0].sold_count;
    const promoId = async (oid) => (await pool.query("SELECT promo_code_id FROM orders WHERE id=$1", [oid])).rows[0].promo_code_id;
    const admDejanja = async (dejanje) => (await pool.query("SELECT * FROM admin_dejanja WHERE dejanje=$1 ORDER BY id", [dejanje])).rows;

    // ============================================================
    console.log("\n# 1. Admin poti: vloge");
    let r;
    for (const [m, p, b] of [["GET", "/admin/api/promo-codes"], ["POST", "/admin/api/promo-codes", { code: "ABC", label: "x", club_id: 1 }], ["PATCH", "/admin/api/promo-codes/1", { active: false }], ["GET", "/admin/api/promo-codes/1/stats"]]) {
      r = await api(m, p, null, b);
      assert(r.status === 401, `${m} ${p} brez zetona -> 401`, r.status);
      for (const k of ["navaden", "lastnik", "kupec"]) {
        r = await api(m, p, T[k], b);
        assert(r.status === 403, `${m} ${p} (${k}) -> 403`, r.status);
      }
    }
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM promo_codes")).rows[0].n === 0, "403/401 niso ustvarili kode");

    console.log("\n# 1b. Ustvarjanje: validacija");
    const slabo = async (opis, telo) => { const x = await api("POST", "/admin/api/promo-codes", T.admin, telo); assert(x.status === 400, `POST ${opis} -> 400`, [x.status, x.body]); };
    await slabo("koda prekratka", { code: "ab", label: "x", club_id: 1 });
    await slabo("koda predolga (33)", { code: "A".repeat(33), label: "x", club_id: 1 });
    await slabo("koda s presledkom v sredini", { code: "MA X", label: "x", club_id: 1 });
    await slabo("koda s sumniki", { code: "ČAS12", label: "x", club_id: 1 });
    await slabo("koda ni niz", { code: 12345, label: "x", club_id: 1 });
    await slabo("koda manjka", { label: "x", club_id: 1 });
    await slabo("oznaka manjka", { code: "LABELX", club_id: 1 });
    await slabo("oznaka prazna", { code: "LABELX", label: "  ", club_id: 1 });
    await slabo("oznaka 81 znakov", { code: "LABELX", label: "x".repeat(81), club_id: 1 });
    await slabo("oznaka z nadzornim znakom", { code: "LABELX", label: "a\u0000b", club_id: 1 });
    await slabo("brez kluba in dogodkov", { code: "LABELX", label: "x" });
    await slabo("prazen seznam dogodkov in brez kluba", { code: "LABELX", label: "x", event_ids: [] });
    await slabo("klub ne obstaja", { code: "LABELX", label: "x", club_id: 999 });
    await slabo("club_id ni stevilo", { code: "LABELX", label: "x", club_id: "abc" });
    await slabo("dogodek ne obstaja", { code: "LABELX", label: "x", event_ids: [E1, 9999] });
    await slabo("event_ids ni seznam", { code: "LABELX", label: "x", event_ids: "1" });
    await slabo("event_ids z nestevilom", { code: "LABELX", label: "x", event_ids: [E1, "x"] });
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM promo_codes")).rows[0].n === 0, "neveljavni zahtevki niso ustvarili kode");

    console.log("\n# 1c. Ustvarjanje: uspeh, normalizacija, podvojena koda");
    r = await api("POST", "/admin/api/promo-codes", T.admin, { code: "  max12 ", label: " Max ", event_ids: [E1, E1] });
    assert(r.status === 201, "POST MAX12 (dogodek E1) -> 201", r.body);
    const MAX = r.body;
    assert(MAX.code === "MAX12" && MAX.label === "Max" && MAX.active === true && MAX.club === null, "koda velike crke, trim, oznaka trim, aktivna, brez kluba", MAX);
    assert(Array.isArray(MAX.events) && MAX.events.length === 1 && MAX.events[0].id === E1 && MAX.events[0].title === "Noc ena" && typeof MAX.events[0].start_at === "string", "events: [{id, title, start_at}] (podvojen id enkrat)", MAX.events);
    assert(MAX.tickets_sold === 0 && MAX.orders === 0 && MAX.gross_cents === 0 && typeof MAX.created_at === "string" && Number.isInteger(MAX.id), "stevci 0, created_at, id", MAX);
    assert(Object.keys(MAX).sort().join() === "active,club,code,created_at,events,gross_cents,id,label,orders,test_orders,test_tickets_sold,tickets_sold", "oblika vrstice (dogovorjena polja + test_*)", Object.keys(MAX));
    r = await api("POST", "/admin/api/promo-codes", T.admin, { code: "Max12", label: "Drug", club_id: 1 });
    assert(r.status === 409 && r.body.error === "promo_code_exists", "podvojena koda (druge crke) -> 409 promo_code_exists", r);
    r = await api("POST", "/admin/api/promo-codes", T.admin, { code: "KLUB1", label: "Klub ena", club_id: 1 });
    assert(r.status === 201 && r.body.club && r.body.club.id === 1 && r.body.club.name === "Pure Club" && r.body.events.length === 0, "POST KLUB1 (klub 1) -> 201, club {id, name}", r.body);
    const KLUB = r.body;
    r = await api("POST", "/admin/api/promo-codes", T.admin, { code: "TUJ-3", label: "Tuj dogodek", event_ids: [E3] });
    assert(r.status === 201, "POST TUJ-3 (dogodek E3 drugega kluba) -> 201", r.body);
    const TUJ = r.body;
    const dnev = await admDejanja("promo.create");
    assert(dnev.length === 3 && dnev[0].cilj_tip === "promo_code" && dnev[0].cilj_id === String(MAX.id) && dnev[0].admin_user_id !== null && dnev[0].prej === null && dnev[0].potem.code === "MAX12" && JSON.stringify(dnev[0].potem.event_ids) === `[${E1}]`,
      "dnevnik admin_dejanja: promo.create za vsako kodo (cilj, admin, potem)", dnev[0]);
    assert(!JSON.stringify(dnev).includes("@"), "dnevnik brez e-naslovov");
    r = await api("GET", "/admin/api/promo-codes", T.admin);
    assert(r.status === 200 && Array.isArray(r.body) && r.body.length === 3 && r.body[0].code === "TUJ-3", "GET seznam: 3 kode, najnovejsa prva", r.body.map(x => x.code));

    // ============================================================
    console.log("\n# 2. Nakup brez kode je kot prej; koda ne spremeni zneska (I61)");
    const lastnosti = (o) => ({ q: o.quantity, unit: o.unit_price_cents, total: o.total_cents, fee: o.application_fee_cents, status: o.status, cur: o.currency });
    const sold0 = await sold(E1);
    r = await kupi(E1, { quantity: 2 });
    assert(r.status === 201 && r.body.order.total_cents === 2000 && r.body.order.status === "paid", "nakup BREZ kode: 201, 2 x 10 EUR", r.body);
    const brezKode = r.body.order;
    assert(await promoId(brezKode.id) === null, "brez kode: promo_code_id NULL");
    assert(!JSON.stringify(r.body).includes("promo"), "odgovor nakupa ne vsebuje polj o promo kodi (star odjemalec je ne rabi)");
    r = await kupi(E1, { quantity: 2, promo_code: "  max12  " });
    assert(r.status === 201, "nakup s kodo »  max12  « (male crke + trim) -> 201", r.body);
    const sKodo = r.body.order;
    assert(JSON.stringify(lastnosti(sKodo)) === JSON.stringify(lastnosti(brezKode)), "cena, provizija, kolicina, stanje in valuta ENAKI kot brez kode", [lastnosti(sKodo), lastnosti(brezKode)]);
    assert(await promoId(sKodo.id) === MAX.id, "narocilo ima promo_code_id kode MAX12");
    assert(await sold(E1) === sold0 + 4 && r.body.tickets.length === 2, "zaloga: vsako narocilo rezervira svoji 2 vstopnici (brez razlike zaradi kode)", await sold(E1));
    const dbA = (await pool.query("SELECT total_cents, application_fee_cents, unit_price_cents FROM orders WHERE id=ANY($1) ORDER BY id", [[brezKode.id, sKodo.id]])).rows;
    assert(JSON.stringify(dbA[0]) === JSON.stringify(dbA[1]), "v bazi enak znesek, provizija in cena enote", dbA);
    for (const [opis, v] of [["null", null], ["prazen niz", ""], ["samo presledki", "   "]]) {
      const pred = await stNarocil();
      r = await kupi(E1, { quantity: 1, promo_code: v });
      assert(r.status === 201 && await promoId(r.body.order.id) === null && await stNarocil() === pred + 1, `promo_code ${opis} = brez kode (201, promo_code_id NULL)`, r.body);
    }

    // ============================================================
    console.log("\n# 3. Neveljavna koda: 400 promo_code_invalid, narocilo ne nastane, zaloga se ne rezervira");
    const neveljavne = [
      ["neznana koda", "NOPE123"], ["koda dogodkov na drugem dogodku (E2)", "MAX12", E2], ["koda drugega kluba", "TUJ-3"], ["prekratka", "ab"], ["predolga", "A".repeat(33)],
      ["presledek v sredini", "MA X12"], ["posebni znaki", "MAX12!"], ["sumniki", "ČAS12"], ["Unicode ß, ki bi postal SS", "maß12"], ["pika (dotless i / long s)", "maxı"],
      ["stevilo", 12345], ["objekt", { a: 1 }], ["seznam", ["MAX12"]], ["true", true],
    ];
    for (const [opis, koda, ev = E1] of neveljavne) {
      const pred = await stNarocil(), zal = await sold(ev), tick = (await pool.query("SELECT COUNT(*)::int AS n FROM tickets")).rows[0].n;
      r = await kupi(ev, { quantity: 1, promo_code: koda });
      assert(jeNeveljavna(r) && await stNarocil() === pred && await sold(ev) === zal && (await pool.query("SELECT COUNT(*)::int AS n FROM tickets")).rows[0].n === tick,
        `${opis} -> 400 promo_code_invalid, brez narocila, vstopnic in zaloge`, [r.status, r.body]);
    }
    console.log("  -- neaktivna koda");
    r = await api("PATCH", `/admin/api/promo-codes/${MAX.id}`, T.admin, { active: false });
    assert(r.status === 200 && r.body.active === false && r.body.code === "MAX12", "PATCH active:false -> 200", r.body);
    let pred = await stNarocil();
    r = await kupi(E1, { quantity: 1, promo_code: "MAX12" });
    assert(jeNeveljavna(r) && await stNarocil() === pred, "neaktivna koda -> 400 promo_code_invalid", r);
    r = await api("PATCH", `/admin/api/promo-codes/${MAX.id}`, T.admin, { active: true });
    assert(r.status === 200 && r.body.active === true, "PATCH active:true -> 200");
    r = await kupi(E1, { quantity: 1, promo_code: "MAX12" });
    assert(r.status === 201 && await promoId(r.body.order.id) === MAX.id, "ponovno aktivna koda spet velja");
    const dnevU = await admDejanja("promo.update");
    assert(dnevU.length === 2 && JSON.stringify(dnevU[0].prej) === '{"active":true}' && JSON.stringify(dnevU[0].potem) === '{"active":false}', "dnevnik promo.update: prej/potem samo active", dnevU.map(x => [x.prej, x.potem]));
    console.log("  -- pomanjkanje zaloge ni skrito s kodo");
    r = await kupi(E4, { quantity: 3, promo_code: "KLUB1" });
    assert(r.status === 409 && /Only 2 tickets left/.test(r.body) && await sold(E4) === 0, "veljavna koda + premalo vstopnic -> 409 kot brez kode, zaloga 0", r);

    // ============================================================
    console.log("\n# 4. Koda kluba velja za vse dogodke kluba");
    for (const ev of [E1, E2, E4]) {
      r = await kupi(ev, { quantity: 1, promo_code: "klub1" });
      assert(r.status === 201 && await promoId(r.body.order.id) === KLUB.id, `KLUB1 velja za dogodek ${ev} kluba 1`, r.body);
    }
    pred = await stNarocil();
    r = await kupi(E3, { quantity: 1, promo_code: "KLUB1" });
    assert(jeNeveljavna(r) && await stNarocil() === pred, "KLUB1 ne velja za dogodek kluba 2", r);
    r = await kupi(E3, { quantity: 1, promo_code: "tuj-3" });
    assert(r.status === 201 && await promoId(r.body.order.id) === TUJ.id, "TUJ-3 (izbran dogodek E3) velja za E3");
    // PATCH: dodaj dogodek E2 kodi MAX12, odstrani E1 -> velja le E2
    r = await api("PATCH", `/admin/api/promo-codes/${MAX.id}`, T.admin, { event_ids: [E2, E3] });
    assert(r.status === 200 && r.body.events.map(e => e.id).join() === [E2, E3].join(), "PATCH event_ids zamenja seznam", r.body.events);
    pred = await stNarocil();
    r = await kupi(E1, { quantity: 1, promo_code: "MAX12" });
    assert(jeNeveljavna(r) && await stNarocil() === pred, "po PATCH koda MAX12 ne velja vec za E1", r);
    r = await kupi(E2, { quantity: 1, promo_code: "MAX12" });
    assert(r.status === 201 && await promoId(r.body.order.id) === MAX.id, "po PATCH MAX12 velja za E2");

    // ============================================================
    console.log("\n# 5. Idempotentni kljuc (prijavljen): neveljavna koda ne zasede kljuca");
    const K1 = crypto.randomUUID(), K2 = crypto.randomUUID(), K3 = crypto.randomUUID();
    pred = await stNarocil();
    r = await kupi(E2, { quantity: 1, promo_code: "NOPE123" }, { "Idempotency-Key": K1 });
    assert(jeNeveljavna(r) && await stNarocil() === pred && (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE idempotency_key=$1", [K1])).rows[0].n === 0, "kljuc K1 + neveljavna koda -> 400, narocila s kljucem ni", r);
    r = await kupi(E2, { quantity: 1, promo_code: "KLUB1" }, { "Idempotency-Key": K1 });
    assert(r.status === 201 && r.headers.get("idempotent-replayed") === null && await promoId(r.body.order.id) === KLUB.id, "isti K1, ista kolicina, veljavna koda -> 201 (ne 409/422)", [r.status, r.body]);
    const prvo = r.body.order.id;
    r = await kupi(E2, { quantity: 1, promo_code: "MAX12" }, { "Idempotency-Key": K1 });
    assert(r.status === 201 && r.headers.get("idempotent-replayed") === "true" && r.body.order.id === prvo && await promoId(prvo) === KLUB.id, "ponovitev K1 z DRUGO kodo -> prvo narocilo (Idempotent-Replayed), koda ostane KLUB1", [r.status, r.body.order && r.body.order.id]);
    r = await kupi(E2, { quantity: 1, promo_code: "NOPE123" }, { "Idempotency-Key": K1 });
    assert(r.status === 201 && r.body.order.id === prvo, "ponovitev K1 z NEVELJAVNO kodo -> prvo narocilo (koda ni del identitete)", [r.status, r.body]);
    r = await kupi(E2, { quantity: 1, promo_code: "ni veljavna!" }, { "Idempotency-Key": K1 });
    assert(r.status === 201 && r.body.order.id === prvo, "ponovitev K1 z napacnim FORMATOM kode -> prvo narocilo", [r.status, r.body]);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE idempotency_key=$1", [K1])).rows[0].n === 1, "natanko eno narocilo s kljucem K1");
    r = await kupi(E2, { quantity: 1, promo_code: "ni veljavna!" }, { "Idempotency-Key": K2 });
    assert(jeNeveljavna(r), "K2 + napacen format -> 400");
    r = await kupi(E2, { quantity: 1 }, { "Idempotency-Key": K2 });
    assert(r.status === 201 && await promoId(r.body.order.id) === null, "isti K2 BREZ kode -> 201, promo_code_id NULL", [r.status, r.body]);
    r = await kupi(E2, { quantity: 1, promo_code: "KLUB1" }, { "Idempotency-Key": K3 });
    assert(r.status === 201, "K3 uspe s kodo");
    r = await kupi(E2, { quantity: 1, promo_code: "NOPE123" }, { "Idempotency-Key": K3 });
    assert(r.status === 201 && r.headers.get("idempotent-replayed") === "true", "ponovitev K3 z neveljavno kodo -> replay, ne 400");
    // kljuc je prost tudi po 400 v transakciji pri drugi kolicini: ista kolicina je pogoj (422 pri drugi vsebini ostane kot prej)
    const K4 = crypto.randomUUID();
    r = await kupi(E2, { quantity: 2, promo_code: "NOPE123" }, { "Idempotency-Key": K4 });
    r = await kupi(E2, { quantity: 3, promo_code: "KLUB1" }, { "Idempotency-Key": K4 });
    assert(r.status === 201 && r.body.order.quantity === 3, "K4: po 400 lahko isti kljuc uporabi tudi druga kolicina (kljuc ni bil zapisan)", [r.status, r.body]);

    // ============================================================
    console.log("\n# 6. Gostujoci nakup s kodo");
    r = await kupiGost(E1, { quantity: 2 });
    assert(r.status === 201 && r.body.order.total_cents === 2000, "gost BREZ kode: 201, 2 x 10 EUR", r.body);
    const gostBrez = r.body.order;
    r = await kupiGost(E1, { quantity: 2, promo_code: " klub1 " });
    assert(r.status === 201 && JSON.stringify(lastnosti(r.body.order)) === JSON.stringify(lastnosti(gostBrez)), "gost s kodo: cena, provizija, kolicina ENAKI kot brez kode", r.body);
    const gostS = r.body.order;
    assert(await promoId(gostS.id) === KLUB.id && (await pool.query("SELECT user_id, guest_email FROM orders WHERE id=$1", [gostS.id])).rows[0].user_id === null, "gost: promo_code_id KLUB1, user_id NULL");
    pred = await stNarocil();
    for (const [opis, koda, ev = E1] of [["neznana", "NOPE123"], ["tuj dogodek", "TUJ-3"], ["napacen format", "x"], ["napacen tip", 7], ["koda dogodkov na drugem dogodku (E1)", "MAX12"]]) {
      const zal = await sold(ev);
      r = await kupiGost(ev, { quantity: 1, promo_code: koda });
      assert(jeNeveljavna(r) && await stNarocil() === pred && await sold(ev) === zal, `gost: ${opis} -> 400 promo_code_invalid, brez narocila in zaloge`, [r.status, r.body]);
    }
    const GE = "idem-gost@example.com", GK1 = crypto.randomUUID(), GK2 = crypto.randomUUID();
    const gostKljuc = (k, koda, q = 1) => kupiGost(E1, { email: GE, quantity: q, ...(koda === undefined ? {} : { promo_code: koda }) }, { "Idempotency-Key": k });
    r = await gostKljuc(GK1, "NOPE123");
    assert(jeNeveljavna(r) && (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE guest_email=$1", [GE])).rows[0].n === 0, "gost: kljuc GK1 + neveljavna koda -> 400, narocila ni", r);
    r = await gostKljuc(GK1, "KLUB1");
    assert(r.status === 201 && r.headers.get("idempotent-replayed") === null, "gost: isti GK1, veljavna koda -> 201 (ne 409/422)", [r.status, r.body]);
    const gprvo = r.body.order.id;
    r = await gostKljuc(GK1, "MAX12");
    assert(r.status === 201 && r.headers.get("idempotent-replayed") === "true" && r.body.order.id === gprvo && await promoId(gprvo) === KLUB.id, "gost: ponovitev GK1 z drugo kodo -> prvo narocilo", [r.status, r.body.order && r.body.order.id]);
    r = await gostKljuc(GK1, "NOPE123");
    assert(r.status === 201 && r.body.order.id === gprvo, "gost: ponovitev GK1 z neveljavno kodo -> prvo narocilo");
    r = await gostKljuc(GK2, "NOPE123");
    r = await gostKljuc(GK2);
    assert(r.status === 201 && await promoId(r.body.order.id) === null, "gost: GK2 po 400 isti kljuc BREZ kode -> 201", [r.status, r.body]);

    // ============================================================
    console.log("\n# 7. VIP miza: promo_code se ignorira (ne zavrne, ne shrani)");
    const PLAN = { width: 24, height: 16, elements: [{ type: "stage", x: 8, y: 0, w: 8, h: 3, label: "" }] };
    r = await api("PUT", "/business/vip", T.lastnik, { plan: PLAN, tables: [{ label: "T1", x: 2, y: 5, w: 2, h: 2, shape: "round", seats: 6, price_cents: 30000 }, { label: "T2", x: 6, y: 5, w: 2, h: 2, shape: "round", seats: 6, price_cents: 30000 }], packages: [] });
    assert(r.status === 200 && r.body.tables.length === 2, "tloris z 2 mizama", r.body);
    const [M1, M2] = r.body.tables.map(t => t.id);
    r = await api("PUT", `/business/events/${E1}/vip`, T.lastnik, { enabled: true });
    assert(r.status === 200 && r.body.enabled === true, "VIP vklopljen na E1", r.body);
    await pool.query("TRUNCATE omejitve");
    r = await api("POST", `/events/${E1}/tables/${M1}/orders`, T.kupec, { promo_code: "NOPE123" });
    assert(r.status === 201 && r.body.order.total_cents === 30000, "VIP nakup z NEVELJAVNO kodo se ne zavrne (201)", [r.status, r.body]);
    assert(await promoId(r.body.order.id) === null, "VIP: promo_code_id NULL");
    r = await api("POST", `/events/${E1}/tables/${M2}/orders`, T.kupec, { promo_code: "KLUB1" });
    assert(r.status === 201 && await promoId(r.body.order.id) === null, "VIP nakup z VELJAVNO kodo: 201, koda se ne shrani (samo navadne vstopnice)", [r.status, r.body]);

    // ============================================================
    console.log("\n# 8. Statistika (neto vstopnice kot GET /admin/api/finance)");
    // Cista tabela narocil: stevilke so predvidljive. Narocila s kodo MAX12 (E2, E3 po PATCH-u zgoraj) postavimo na znano stanje.
    await pool.query("TRUNCATE tickets, orders RESTART IDENTITY CASCADE");
    await pool.query("UPDATE events SET sold_count = 0");
    await pool.query("TRUNCATE omejitve");
    r = await api("PATCH", `/admin/api/promo-codes/${MAX.id}`, T.admin, { event_ids: [E1, E2, E3] });
    assert(r.status === 200 && r.body.events.length === 3, "MAX12 velja za E1, E2, E3");
    const nar = {};
    const stat = async (ime, ev, q, koda) => { const x = await kupi(ev, { quantity: q, ...(koda ? { promo_code: koda } : {}) }); assert(x.status === 201, `narocilo ${ime}`, x.body); nar[ime] = x.body.order.id; };
    await stat("A", E1, 2, "MAX12");      // pravo, placano
    await stat("B", E1, 3, "MAX12");      // pravo, v celoti vrnjeno
    await stat("D", E1, 1, "max12");      // pravo, delno vrnjeno (steje)
    await stat("C", E1, 1, "MAX12");      // testno (lazni nacin: test_<uuid>)
    await stat("P", E1, 1, "MAX12");      // pravo, a neplačano (pending)
    await stat("E", E3, 4, "MAX12");      // pravo na drugem dogodku (klub 2)
    await stat("N", E1, 5);               // pravo, BREZ kode (ne sme v statistiko kode)
    await stat("K", E1, 1, "KLUB1");      // druga koda
    const gA = await kupiGost(E1, { quantity: 2, promo_code: "MAX12" });
    assert(gA.status === 201, "gostujoce narocilo G s kodo MAX12", gA.body); nar.G = gA.body.order.id;
    let n = 0;
    for (const ime of ["A", "B", "D", "E", "N", "K", "G"]) {
      await pool.query("UPDATE orders SET stripe_payment_intent_id=$2, stripe_checkout_session_id=$3 WHERE id=$1", [nar[ime], "pi_live_" + (++n), "cs_live_" + n]);   // pravo (kot Stripe v zivo)
    }
    await pool.query("UPDATE orders SET status='refunded', refunded_cents=total_cents WHERE id=$1", [nar.B]);
    await pool.query("UPDATE orders SET status='partially_refunded', refunded_cents=500 WHERE id=$1", [nar.D]);
    try { await pool.query("UPDATE orders SET status='pending', paid_at=NULL WHERE id=$1", [nar.P]); }
    catch (e) { await pool.query("UPDATE orders SET status='pending', paid_at=NULL, stripe_payment_intent_id=NULL WHERE id=$1", [nar.P]).catch(() => {}); }
    assert((await pool.query("SELECT status FROM orders WHERE id=$1", [nar.P])).rows[0].status === "pending", "narocilo P je pending (neplacano)");
    await pool.query("UPDATE orders SET stripe_payment_intent_id='pi_live_p', stripe_checkout_session_id='cs_live_p' WHERE id=$1", [nar.P]);

    // pricakovano za MAX12: pravo: A (2 vstopnici, 2000), B (vrnjeno: 0 vstopnic, 1 narocilo, 3000), D (1, 1000), E (4, 6000), G (2, 2000);
    // C testno; P neplacano. E1: tickets 2+1+2=5, orders 4 (A,B,D,G), gross 2000+3000+1000+2000=8000; E3: 4, 1, 6000; E2: 0.
    r = await api("GET", `/admin/api/promo-codes/${MAX.id}/stats`, T.admin);
    assert(r.status === 200 && r.body.code.code === "MAX12" && r.body.code.id === MAX.id, "stats: koda v odgovoru", r.body.code);
    const poEv = Object.fromEntries((r.body.events || []).map(x => [x.event_id, x]));
    assert(Object.keys(r.body.events[0]).sort().join() === "club_name,event_id,gross_cents,orders,start_at,test_orders,test_tickets_sold,tickets_sold,title", "stats: oblika vrstice po dogodku", Object.keys(r.body.events[0]));
    assert(poEv[E1] && poEv[E1].tickets_sold === 5 && poEv[E1].orders === 4 && poEv[E1].gross_cents === 8000 && poEv[E1].club_name === "Pure Club" && poEv[E1].title === "Noc ena",
      "stats E1: 5 vstopnic (vrnjeno B ne steje), 4 narocila (B steje), bruto 8000; pending in testno ne", poEv[E1]);
    assert(poEv[E1].test_tickets_sold === 1 && poEv[E1].test_orders === 1, "stats E1: testno narocilo C loceno (1 vstopnica)", poEv[E1]);
    assert(poEv[E3] && poEv[E3].tickets_sold === 4 && poEv[E3].orders === 1 && poEv[E3].gross_cents === 6000 && poEv[E3].club_name === "Drugi Klub", "stats E3: 4 vstopnice, 1 narocilo, 6000", poEv[E3]);
    assert(poEv[E2] && poEv[E2].tickets_sold === 0 && poEv[E2].orders === 0 && poEv[E2].gross_cents === 0, "stats E2: izbran dogodek brez prodaje je v tabeli z ničlami", poEv[E2]);
    assert(r.body.total.tickets_sold === 9 && r.body.total.orders === 5 && r.body.total.gross_cents === 14000 && r.body.total.test_tickets_sold === 1 && r.body.total.test_orders === 1, "stats skupaj: 9 vstopnic, 5 narocil, 14000, testno 1", r.body.total);
    assert(!poEv[undefined] && r.body.events.length === 3, "stats: nobena druga koda ali narocilo brez kode ne pride v statistiko", r.body.events.map(x => x.event_id));
    r = await api("GET", "/admin/api/promo-codes", T.admin);
    const lMax = r.body.find(x => x.code === "MAX12"), lKlub = r.body.find(x => x.code === "KLUB1");
    assert(lMax.tickets_sold === 9 && lMax.orders === 5 && lMax.gross_cents === 14000 && lMax.test_tickets_sold === 1, "seznam: MAX12 enaki skupni stevci kot stats", lMax);
    assert(lKlub.tickets_sold === 1 && lKlub.orders === 1 && lKlub.gross_cents === 1000, "seznam: KLUB1 steje samo svoje narocilo (K)", lKlub);
    assert(lKlub.club && lKlub.club.id === 1 && lMax.club === null && lMax.events.length === 3, "seznam: club/events", [lKlub.club, lMax.events.length]);
    // enaka definicija kot finance: razlika med 'finance' vstopnicami dogodka in vsoto vseh kod+brez kode na pravih narocilih
    const fin = await api("GET", "/admin/api/finance", T.admin);
    const fE1 = fin.body.by_event.find(x => x.id === E1), fE3 = fin.body.by_event.find(x => x.id === E3);
    // E1 pravo: A2 + B(vrnjeno 0) + D1 + N5 + K1 + G2 = 11 vstopnic; od tega s kodo MAX12 5
    assert(fE1 && fE1.tickets_sold === 11 && fE3 && fE3.tickets_sold === 4, "finance by_event: E1 11 vstopnic, E3 4 (isto pravilo: vrnjeno ne steje)", [fE1 && fE1.tickets_sold, fE3 && fE3.tickets_sold]);
    assert(poEv[E3].tickets_sold === fE3.tickets_sold && poEv[E1].tickets_sold + 5 + 1 === fE1.tickets_sold, "stats = finance: E3 enako, E1 = MAX12 (5) + brez kode (5) + KLUB1 (1)", [poEv[E1].tickets_sold, fE1.tickets_sold]);
    r = await api("GET", "/admin/api/promo-codes/99999/stats", T.admin);
    assert(r.status === 404, "stats neobstojece kode -> 404", r.status);
    r = await api("GET", "/admin/api/promo-codes/abc/stats", T.admin);
    assert(r.status === 400, "stats z id 'abc' -> 400", r.status);

    // ============================================================
    console.log("\n# 9. PATCH: omejitve in dnevnik");
    const stDnev = (await admDejanja("promo.update")).length;
    r = await api("PATCH", `/admin/api/promo-codes/${MAX.id}`, T.admin, { code: "DRUGA" });
    assert(r.status === 400, "besedila kode ni mogoce spremeniti -> 400", r);
    r = await api("PATCH", `/admin/api/promo-codes/${MAX.id}`, T.admin, {});
    assert(r.status === 400, "prazen PATCH -> 400");
    r = await api("PATCH", `/admin/api/promo-codes/${MAX.id}`, T.admin, { active: "da" });
    assert(r.status === 400, "active ni boolean -> 400");
    r = await api("PATCH", `/admin/api/promo-codes/${MAX.id}`, T.admin, { label: "" });
    assert(r.status === 400, "prazna oznaka -> 400");
    r = await api("PATCH", `/admin/api/promo-codes/${MAX.id}`, T.admin, { event_ids: [] });
    assert(r.status === 400, "brez dogodkov in brez kluba -> 400 (koda mora biti nekam vezana)");
    r = await api("PATCH", `/admin/api/promo-codes/${MAX.id}`, T.admin, { event_ids: [E1, 9999] });
    assert(r.status === 400, "neobstojec dogodek -> 400");
    r = await api("PATCH", `/admin/api/promo-codes/${MAX.id}`, T.admin, { club_id: 999 });
    assert(r.status === 400, "neobstojec klub -> 400");
    r = await api("PATCH", "/admin/api/promo-codes/99999", T.admin, { active: false });
    assert(r.status === 404, "neobstojec id -> 404");
    r = await api("PATCH", `/admin/api/promo-codes/${MAX.id}`, T.admin, { label: "Max", active: true });
    assert(r.status === 200 && (await admDejanja("promo.update")).length === stDnev, "PATCH z enakimi vrednostmi: 200, brez nove vrstice dnevnika");
    r = await api("PATCH", `/admin/api/promo-codes/${MAX.id}`, T.admin, { label: "Max Novak", club_id: 1, event_ids: [E1] });
    assert(r.status === 200 && r.body.label === "Max Novak" && r.body.club.id === 1 && r.body.events.length === 1, "PATCH label + club_id + event_ids", r.body);
    const zad = (await admDejanja("promo.update")).pop();
    assert(zad.prej.label === "Max" && zad.potem.label === "Max Novak" && zad.potem.club_id === 1 && JSON.stringify(zad.prej.event_ids) === `[${E1},${E2},${E3}]` && JSON.stringify(zad.potem.event_ids) === `[${E1}]`, "dnevnik: prej/potem label, club_id, event_ids", zad);
    r = await api("PATCH", `/admin/api/promo-codes/${MAX.id}`, T.admin, { club_id: null, event_ids: [E1] });
    assert(r.status === 200 && r.body.club === null && r.body.events.length === 1, "PATCH club_id null (ostane dogodek E1)", r.body);
    r = await api("PATCH", `/admin/api/promo-codes/${TUJ.id}`, T.admin, { club_id: null });
    assert(r.status === 200, "TUJ-3: club_id null ob obstojecem dogodku -> 200");
    r = await api("PATCH", `/admin/api/promo-codes/${KLUB.id}`, T.admin, { club_id: null });
    assert(r.status === 400, "KLUB1: odstranitev kluba brez dogodkov -> 400");

    console.log("\n# 9b. Koda brez dogodkov (dogodek izbrisan) ostane upravljiva; razlog v dnevniku; PATCH ne ustavi nakupov s kodo");
    const E5 = await dogodek("lastnik", 1, "Za izbris", 1000, 10);
    r = await api("POST", "/admin/api/promo-codes", T.admin, { code: "SIROTA", label: "Sirota", event_ids: [E5], reason: "  Prva kampanja  " });
    assert(r.status === 201, "POST SIROTA (samo dogodek E5) -> 201", r.body);
    const SIROTA = r.body;
    assert((await admDejanja("promo.create")).pop().razlog === "Prva kampanja", "POST: reason (trim) v admin_dejanja.razlog");
    r = await api("POST", "/admin/api/promo-codes", T.admin, { code: "SIROTA2", label: "x", club_id: 1, reason: 5 });
    assert(r.status === 400, "POST: reason ni niz -> 400");
    r = await api("PATCH", `/admin/api/promo-codes/${SIROTA.id}`, T.admin, { active: false, reason: "x".repeat(501) });
    assert(r.status === 400, "PATCH: reason daljsi od 500 znakov -> 400");
    r = await api("DELETE", `/events/${E5}`, T.lastnik);
    assert(r.status === 200 && (await pool.query("SELECT COUNT(*)::int AS n FROM events WHERE id=$1", [E5])).rows[0].n === 0, "lastnik izbrise dogodek E5 (brez narocil)", r);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM promo_code_events WHERE promo_code_id=$1", [SIROTA.id])).rows[0].n === 0, "CASCADE: koda je ostala brez dogodkov");
    r = await api("GET", "/admin/api/promo-codes", T.admin);
    const sir = r.body.find(x => x.id === SIROTA.id);
    assert(r.status === 200 && sir && sir.club === null && sir.events.length === 0 && sir.tickets_sold === 0, "seznam: koda brez kluba in dogodkov se vrne (events [])", sir);
    r = await api("GET", `/admin/api/promo-codes/${SIROTA.id}/stats`, T.admin);
    assert(r.status === 200 && r.body.events.length === 0 && r.body.total.tickets_sold === 0, "stats take kode: prazen seznam, skupaj 0", r.body);
    r = await api("PATCH", `/admin/api/promo-codes/${SIROTA.id}`, T.admin, { active: false, reason: "Dogodek je izbrisan" });
    assert(r.status === 200 && r.body.active === false, "PATCH {active:false} na kodi brez dogodkov -> 200", r);
    assert((await admDejanja("promo.update")).pop().razlog === "Dogodek je izbrisan", "PATCH: reason v admin_dejanja.razlog");
    r = await api("PATCH", `/admin/api/promo-codes/${SIROTA.id}`, T.admin, { label: "Sirota 2" });
    assert(r.status === 200 && r.body.label === "Sirota 2", "PATCH {label} na kodi brez dogodkov -> 200");
    r = await api("PATCH", `/admin/api/promo-codes/${SIROTA.id}`, T.admin, { event_ids: [] });
    assert(r.status === 400, "PATCH, ki spreminja obseg v prazno (event_ids: []), je se vedno 400");
    r = await api("PATCH", `/admin/api/promo-codes/${SIROTA.id}`, T.admin, { club_id: null });
    assert(r.status === 400, "PATCH club_id null brez dogodkov je 400");
    r = await api("PATCH", `/admin/api/promo-codes/${SIROTA.id}`, T.admin, { event_ids: [E1] });
    assert(r.status === 200 && r.body.events.length === 1, "PATCH event_ids na kodi brez dogodkov -> 200");
    // zaklep vrstice kode: PATCH (FOR NO KEY UPDATE) ne sme cakati na nakup s kodo (ta vzame FOR KEY SHARE prek FK preverbe) in obratno.
    // Locena povezava odpre transakcijo, ki VSTAVI narocilo s promo_code_id (FK -> KEY SHARE na vrstici kode) in je ne zakljuci; PATCH mora vseeno uspeti.
    // Pri FOR UPDATE bi PATCH obvisel (mutacija: zamenjaj v PATCH FOR NO KEY UPDATE -> FOR UPDATE, test mora pasti).
    const drzalec = await pool.connect();
    try {
      await drzalec.query("BEGIN");
      await drzalec.query(`INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, currency, application_fee_cents, status, buyer_email, promo_code_id)
        VALUES ('OUT-ZAKLEP01', (SELECT id FROM users WHERE email='kupec@outly.si'), $1, 1, 1, 2000, 2000, 'EUR', 200, 'pending', 'kupec@outly.si', $2)`, [E2, KLUB.id]);
      const t0 = Date.now();
      const pat = await Promise.race([api("PATCH", `/admin/api/promo-codes/${KLUB.id}`, T.admin, { label: "Klub ena (zaklep)" }), new Promise(res => setTimeout(() => res("zatakne"), 4000))]);
      assert(pat !== "zatakne" && pat.status === 200 && pat.body.label === "Klub ena (zaklep)", `PATCH kode ne caka na odprto narocilo s to kodo (${Date.now() - t0} ms)`, pat.status);
    } finally { await drzalec.query("ROLLBACK").catch(() => {}); drzalec.release(); }
    r = await kupi(E2, { quantity: 1, promo_code: "KLUB1" });
    assert(r.status === 201 && await promoId(r.body.order.id) === KLUB.id, "po sprostitvi zaklepa nakup s kodo spet dela");

    console.log("\n# 10. Migracija: brez sprememb obstojecih podatkov");
    const shema = (await pool.query(`SELECT (SELECT COUNT(*)::int FROM pg_constraint WHERE conname='orders_promo_code_fk') AS fk,
      (SELECT indexdef FROM pg_indexes WHERE indexname='orders_promo_code_idx') AS idx`)).rows[0];
    assert(shema.fk === 1 && /WHERE \(promo_code_id IS NOT NULL\)/.test(shema.idx), "tuji kljuc orders.promo_code_id in DELNI indeks obstajata", shema);
    r = await api("GET", "/clubs"); assert(r.status === 200, "GET /clubs -> 200");
    r = await api("GET", "/events"); assert(r.status === 200, "GET /events -> 200");
    const javno = JSON.stringify((await api("GET", `/events/${E1}`)).body) + JSON.stringify((await api("GET", "/events")).body);
    assert(!/promo/i.test(javno), "javni odgovori dogodkov ne vsebujejo nic o promo kodah");
  } catch (e) {
    fail++; console.log("  ✗ izjema v testu:", e && e.stack || e);
  } finally {
    srv.kill();
    if (fail) console.log("\n--- dnevnik streznika (zadnjih 3000 znakov) ---\n" + log.slice(-3000));
    await pool.end().catch(() => {});
    jwksServer.close();
  }
  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  process.exit(fail ? 1 : 0);
})();
