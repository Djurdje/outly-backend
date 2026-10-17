#!/usr/bin/env node
/**
 * Demo klubi (migracija 050, Martinova odlocitev 13. 10. 2026 v pogovoru z menedzerjem): javna spletna aplikacija ne sme prodajati
 * (niti v testnem nacinu) vstopnic za izmisljene klube. Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_demo_nakup.js
 * Vzorec kot test_prodajalec_nakup.js: lokalni JWKS (ES256), lazni Stripe, dva backenda:
 *   TESTNI  brez Stripa (nakup = takoj placano)           port 3611
 *   ZIV     sk_live_ + klubi s popolnim Stripom/prodajalcem  port 3612 (dokaz: demo zavrnjen PRED Stripom; admin gre skozi Checkout)
 *
 *   1  migracija 050: na prazni bazi nic; po 022-podobnih podatkih oznaci SAMO pet demo klubov (ime + <ime>@example.com), ne dvojnikov
 *   2  javni odgovori imajo is_demo (GET /clubs, /clubs/:id, /clubs/map, /search, /events, /events?lite, /events?clubId, /events/:id,
 *      /events/:id/vip, /me/clubs/following, /me/favorites, /business/events, /business/clubs/me); payment_mode "unavailable" + razlog "demo_club"
 *   3  nakup na demo klubu (uporabnik, lastnik kluba, gost): vstopnice, 0 EUR, VIP miza, gost -> 409 { error: "demo_club", message } brez
 *      naroclila, vstopnice, spremembe sold_count in mize; z Idempotency-Key kljuc ni zapisan
 *   4  vloga admin sme kupovati (vstopnice, miza); njegova vstopnica se skenira, prenese; guest lista (admin) deluje; ostali so se vedno zavrnjeni
 *   5  navaden klub nespremenjen (is_demo false, payment_mode test, nakup 201); dogodek organizatorja pri demo prizoriscu je kupljiv
 *      (prodajalec = organizator), dogodek demo kluba pri pravem prizoriscu je zavrnjen
 *   6  admin stikalo: PATCH /admin/api/clubs/:id { isDemo } (+ snake_case), javni predpomnilnik se razveljavi, samo admin; lastnik ne more
 *   7  ZIV (sk_live_): demo zavrnjen PRED Checkoutom (Stripe 0 klicev), navaden klub 201 stripe, admin na demo klubu 201 stripe
 */
const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const path = require("path");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT_TEST = 3611, PORT_ZIV = 3612, JWKS_PORT = 3613, STRIPE_PORT = 3614;
const WHSEC = "whsec_test_demo";

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-demo-nakup";
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
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra).slice(0, 400) : ""); } }
let ipStevec = 0;
async function api(baza, method, p, token, body, glave = {}) {
  const r = await fetch(baza + p, { method, headers: { "content-type": "application/json", "x-forwarded-for": `10.61.${(++ipStevec >> 8) & 255}.${(ipStevec & 255) + 1}`, ...(token ? { authorization: "Bearer " + token } : {}), ...glave },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, text: t };
}
const pocakaj = (ms) => new Promise(r => setTimeout(r, ms));

// Isto kot migrate.js: brez vrstic BEGIN;/COMMIT; (zavijemo sami).
const brezTransakcije = (ime) => fs.readFileSync(path.join(__dirname, "..", "db", "migracije", ime), "utf8")
  .split("\n").filter(v => !/^\s*(BEGIN|COMMIT)\s*;\s*$/i.test(v)).join("\n");

// ---------- lazni Stripe (samo Checkout seje) ----------
const S = { stSej: 0, zahtevki: 0 };
const stripeServer = http.createServer((req, res) => {
  let d = ""; req.on("data", x => d += x);
  req.on("end", () => {
    const p = Object.fromEntries(new URLSearchParams(d));
    const odg = (status, o) => { res.writeHead(status, { "content-type": "application/json", "request-id": "req_test" }); res.end(JSON.stringify(o)); };
    if (req.method === "POST" && req.url.split("?")[0] === "/v1/checkout/sessions") {
      S.zahtevki++;
      const id = "cs_test_" + (++S.stSej);
      return odg(200, { id, object: "checkout.session", url: `https://checkout.stripe.test/c/pay/${id}`, status: "open", payment_status: "unpaid",
        client_reference_id: p.client_reference_id, expires_at: Number(p.expires_at), payment_intent: null, metadata: { order_id: p["metadata[order_id]"] } });
    }
    return odg(404, { error: { type: "invalid_request_error", message: "Lazni Stripe: neznana pot " + req.method + " " + req.url } });
  });
});

function zagon(port, okolje) {
  const srv = spawn("node", ["index.js"], { env: { ...process.env, GOST_NAKUP_TEST: "1", PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test",
    APP_URL: "https://outly.test", TEST_PLACILA: "", STRIPE_SECRET_KEY: "", STRIPE_WEBHOOK_SECRET: "", ...okolje }, stdio: ["ignore", "pipe", "pipe"] });
  const o = { srv, log: "" };
  srv.stdout.on("data", d => o.log += d); srv.stderr.on("data", d => o.log += d);
  return o;
}
async function cakajStreznik(baza) { for (let i = 0; i < 80; i++) { try { await fetch(baza + "/"); return; } catch { await pocakaj(100); } } }

const NAPAKA = { error: "demo_club", message: "This is a demo club. Tickets can't be bought." };
const jeDemoNapaka = (r) => r.status === 409 && r.body && typeof r.body === "object" && Object.keys(r.body).length === 2
  && r.body.error === NAPAKA.error && r.body.message === NAPAKA.message;

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, stripe_events, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");

  // ================================================================
  console.log("\n# 1. Migracija 050: oznaci samo prave demo klube");
  const SQL50 = brezTransakcije("050_demo_klubi_oznaka.sql");
  await pool.query("BEGIN"); await pool.query(SQL50); await pool.query("COMMIT");
  assert((await pool.query("SELECT COUNT(*)::int AS n FROM clubs")).rows[0].n === 0, "prazna baza: ni klubov, migracija ne naredi nicesar");
  const stolpec = (await pool.query("SELECT is_nullable, column_default, data_type FROM information_schema.columns WHERE table_name='clubs' AND column_name='is_demo'")).rows[0];
  assert(stolpec && stolpec.data_type === "boolean" && stolpec.is_nullable === "NO" && stolpec.column_default === "false", "clubs.is_demo BOOLEAN NOT NULL DEFAULT FALSE", stolpec);

  const imenaUporabnikov = ["admin", "lastnik_demo", "lastnik_pravi", "lastnik_org", "ana", "bor", "cene", "dana", "eva", "gina", "hana", "ivo", "jure", "kaja"];
  const T = {};
  imenaUporabnikov.forEach((k, i) => { T[k] = zeton(`${k}@outly.si`, uuid(i + 1)); });
  const bT = `http://127.0.0.1:${PORT_TEST}`, bZ = `http://127.0.0.1:${PORT_ZIV}`;
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  await new Promise(r => stripeServer.listen(STRIPE_PORT, r));
  const TEST = zagon(PORT_TEST, {});
  const ZIV = zagon(PORT_ZIV, { STRIPE_SECRET_KEY: "sk_live_lokalno", STRIPE_WEBHOOK_SECRET: WHSEC, STRIPE_API_BASE: `http://127.0.0.1:${STRIPE_PORT}`, GOST_NAKUP_LIVE: "1" });
  await Promise.all([bT, bZ].map(cakajStreznik));

  try {
    for (const k of imenaUporabnikov) { const r = await api(bT, "GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    const uid = async (k) => (await pool.query("SELECT id FROM users WHERE email=$1", [`${k}@outly.si`])).rows[0].id;
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("UPDATE users SET role='business' WHERE email IN ('lastnik_demo@outly.si','lastnik_pravi@outly.si','lastnik_org@outly.si')");

    // Stanje, kot ga pusti migracija 022: pet klubov z izmisljenimi imeni in <ime>@example.com. Poleg njih »dvojniki«, ki jih migracija NE sme oznaciti.
    let stLastnikov = 0;
    const tujLastnik = async () => (await pool.query("INSERT INTO users (email, username, role, email_verified) VALUES ($1, $2, 'business', TRUE) RETURNING id", [`tuj${++stLastnikov}@outly.si`, `tuj${stLastnikov}`])).rows[0].id;
    const klub = async (lastnik, ime, email, extra = {}) => (await pool.query(
      `INSERT INTO clubs (owner_user_id, name, city, address, contact_email, contact_phone, stripe_account_id, stripe_charges_enabled, stripe_account_livemode,
                          legal_name, legal_address, registration_number, tax_number, vat_payer, is_organizer)
       VALUES ($1,$2,'Ljubljana','Slovenska 1',$3,'+38640111222',$4,$5,$5,'Firma d.o.o.','Sedez 1, 1000 Ljubljana','1234567000','SI12345678',TRUE,$6) RETURNING id`,
      [lastnik === null ? await tujLastnik() : await uid(lastnik), ime, email, extra.stripe ? "acct_" + ime.replace(/\W/g, "") : null, !!extra.stripe, !!extra.organizator])).rows[0].id;
    const demo = {};
    demo.Velvet = await klub("lastnik_demo", "Velvet", "velvet@example.com", { stripe: true });
    for (const ime of ["Nexus", "Mirage", "Mansion", "Olie"]) demo[ime] = await klub(null, ime, `${ime.toLowerCase()}@example.com`);
    const pravi = await klub("lastnik_pravi", "Pravi Club", "info@pravi.si", { stripe: true });
    const dvojnik = await klub(null, "Velvet", "info@velvet-pravi.si");          // pravi klub z istim imenom, drug e-naslov
    const tujeIme = await klub(null, "Cirkus", "cirkus@example.com");            // example.com, a ime ni med petimi
    const velikaCrka = await klub(null, "Nexus", "NEXUS@example.com");          // 022 piše male crke: drugace ni »oni«
    const organizator = await klub("lastnik_org", "Organizator", "org@pravi.si", { stripe: true, organizator: true });
    await pool.query("BEGIN"); await pool.query(SQL50); await pool.query("COMMIT");
    let oznaceni = (await pool.query("SELECT id FROM clubs WHERE is_demo ORDER BY id")).rows.map(r => r.id);
    assert(JSON.stringify(oznaceni) === JSON.stringify(Object.values(demo).sort((a, b) => a - b)), "oznaceni so natanko Velvet, Nexus, Mirage, Mansion, Olie", oznaceni);
    assert(![pravi, dvojnik, tujeIme, velikaCrka, organizator].some(id => oznaceni.includes(id)), "pravi klub, dvojnik z istim imenom, drugo ime @example.com in NEXUS@ ostanejo neoznaceni");
    const vrstic = (await pool.query("SELECT COUNT(*)::int AS n FROM clubs")).rows[0].n;
    await pool.query("BEGIN"); await pool.query(SQL50); await pool.query("COMMIT");
    assert(JSON.stringify((await pool.query("SELECT id FROM clubs WHERE is_demo ORDER BY id")).rows.map(r => r.id)) === JSON.stringify(oznaceni) && (await pool.query("SELECT COUNT(*)::int AS n FROM clubs")).rows[0].n === vrstic, "ponovni zagon: isti rezultat");
    // Dvojnike pustimo (migracija jih ni dotaknila); za preostale sklope jih pocistimo, da ne motijo (imena v iskanju).
    await pool.query("DELETE FROM clubs WHERE id = ANY($1)", [[dvojnik, tujeIme, velikaCrka, demo.Nexus, demo.Mirage, demo.Mansion, demo.Olie]]);

    const ANA = await uid("ana");
    const cezDan = new Date(Date.now() + 24 * 3600 * 1000);
    const dogodek = async (klubId, naslov, cena, extra = {}) => (await pool.query(
      `INSERT INTO events (club_id, title, start_at, status, ticket_price_cents, capacity, min_age, vip_enabled, venue_club_id) VALUES ($1,$2,$3,'published',$4,100,0,$5,$6) RETURNING id`,
      [klubId, naslov, cezDan, cena, !!extra.vip, extra.prizorisce || null])).rows[0].id;
    const evDemo = await dogodek(demo.Velvet, "Velvet noc", 1500, { vip: true });
    const evDemoZastonj = await dogodek(demo.Velvet, "Velvet zastonj", 0);
    const evPravi = await dogodek(pravi, "Pravi noc", 1500, { vip: true });
    const evOrgPriDemo = await dogodek(organizator, "Organizator pri Velvetu", 1500, { prizorisce: demo.Velvet });   // prodajalec = organizator
    const evDemoPriPravem = await dogodek(demo.Velvet, "Velvet gostuje", 1500, { prizorisce: pravi });               // prodajalec = demo klub
    const miza = async (klubId, label, cena) => (await pool.query("INSERT INTO club_tables (club_id, label, x, y, w, h, seats, price_cents) VALUES ($1,$2,0,0,2,2,4,$3) RETURNING id", [klubId, label, cena])).rows[0].id;
    const mDemo1 = await miza(demo.Velvet, "D1", 20000), mDemo2 = await miza(demo.Velvet, "D2", 20000), mDemo3 = await miza(demo.Velvet, "D3", 20000);
    const mPravi1 = await miza(pravi, "P1", 20000), mPravi2 = await miza(pravi, "P2", 20000);
    await pool.query("UPDATE events SET vip_enabled = TRUE WHERE id = $1", [evDemoPriPravem]);

    const sticna = (ev) => pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id = ANY($1)", [[].concat(ev)]).then(r => r.rows[0].n);
    const prodano = (ev) => pool.query("SELECT COALESCE(SUM(sold_count),0)::int AS n FROM events WHERE id = ANY($1)", [[].concat(ev)]).then(r => r.rows[0].n);
    const TERMS = { accept_terms: true, terms_version: "2026-10-01" };
    const kupiVstopnico = (baza, tok, ev, k, kol = 1) => api(baza, "POST", `/events/${ev}/orders`, tok, { quantity: kol }, k ? { "idempotency-key": k } : {});
    const kupiMizo = (baza, tok, ev, mizaId, k) => api(baza, "POST", `/events/${ev}/tables/${mizaId}/orders`, tok, {}, k ? { "idempotency-key": k } : {});
    const kupiGost = (baza, ev, email) => api(baza, "POST", `/guest/events/${ev}/orders`, null, { email, quantity: 1, ...TERMS });

    // ================================================================
    console.log("\n# 2. Javni odgovori imajo is_demo");
    let r = await api(bT, "GET", "/clubs");
    assert(r.status === 200 && r.body.every(k => typeof k.is_demo === "boolean"), "GET /clubs: vsak klub ima boolean is_demo", r.body.map(k => k.is_demo));
    assert(r.body.find(k => k.id === demo.Velvet).is_demo === true && r.body.find(k => k.id === pravi).is_demo === false, "GET /clubs: Velvet true, Pravi Club false");
    r = await api(bT, "GET", `/clubs/${demo.Velvet}`);
    assert(r.status === 200 && r.body.is_demo === true, "GET /clubs/:id demo -> is_demo true", r.body.is_demo);
    r = await api(bT, "GET", `/clubs/${pravi}`);
    assert(r.status === 200 && r.body.is_demo === false, "GET /clubs/:id pravi -> is_demo false", r.body.is_demo);
    // zemljevid vrne samo klube s koordinatami: demo in pravemu damo koordinate (predpomnilnik se razveljavi ob zapisu prek API-ja, ne prek SQL: zato najprej, nato prvi klic)
    await pool.query("UPDATE clubs SET lat = 46.05, lng = 14.5 WHERE id = ANY($1)", [[demo.Velvet, pravi]]);
    r = await api(bT, "GET", "/clubs/map");
    assert(r.status === 200 && r.body.find(k => k.id === demo.Velvet)?.is_demo === true && r.body.find(k => k.id === pravi)?.is_demo === false, "GET /clubs/map: is_demo na pinu", r.body);
    r = await api(bT, "GET", "/search?q=Velvet");
    assert(r.status === 200 && r.body.clubs.length >= 1 && r.body.clubs.every(k => typeof k.is_demo === "boolean") && r.body.clubs.find(k => k.id === demo.Velvet).is_demo === true,
      "GET /search: klubi imajo is_demo", r.body.clubs);
    assert(r.body.events.length >= 1 && r.body.events.every(e => typeof e.is_demo === "boolean") && r.body.events.find(e => e.id === evDemo).is_demo === true,
      "GET /search: dogodki imajo is_demo (prodajalec)", r.body.events);
    r = await api(bT, "GET", "/search?q=Pravi");
    assert(r.status === 200 && r.body.clubs.find(k => k.id === pravi)?.is_demo === false && r.body.events.find(e => e.id === evPravi)?.is_demo === false, "GET /search: pravi klub in dogodek false", r.body);

    for (const [ime, pot] of [["GET /events", "/events"], ["GET /events?lite=true", "/events?lite=true"], [`GET /events?clubId=`, `/events?clubId=${demo.Velvet}`]]) {
      r = await api(bT, "GET", pot);
      const d = Array.isArray(r.body) ? r.body.find(e => e.id === evDemo) : null;
      assert(r.status === 200 && r.body.length > 0 && r.body.every(e => typeof e.is_demo === "boolean") && d && d.is_demo === true, `${ime}: vsak dogodek ima is_demo, demo true`, r.body);
      assert(d && d.payment_mode === "unavailable", `${ime}: demo dogodek payment_mode unavailable (razloga javno ni)`, d && [d.payment_mode, d.payment_unavailable_reason]);
    }
    r = await api(bT, "GET", "/events");
    const pr = r.body.find(e => e.id === evPravi), op = r.body.find(e => e.id === evOrgPriDemo), dp = r.body.find(e => e.id === evDemoPriPravem), dz = r.body.find(e => e.id === evDemoZastonj);
    assert(pr.is_demo === false && pr.payment_mode === "test", "pravi dogodek: is_demo false, payment_mode test", [pr.is_demo, pr.payment_mode, pr.payment_unavailable_reason]);
    assert(op.is_demo === false && op.payment_mode === "test", "dogodek organizatorja pri demo prizoriscu: is_demo false (prodajalec = organizator)", [op.is_demo, op.payment_mode]);
    assert(dp.is_demo === true && dp.payment_mode === "unavailable", "dogodek demo kluba pri pravem prizoriscu: is_demo true (prodajalec = demo klub)", [dp.is_demo, dp.payment_mode]);
    assert(dz.is_demo === true && dz.payment_mode === "unavailable", "brezplacen demo dogodek: tudi unavailable (nakup je zavrnjen tudi za 0 EUR)", [dz.payment_mode]);
    r = await api(bT, "GET", `/events/${evDemo}`);
    assert(r.status === 200 && r.body.is_demo === true && r.body.payment_mode === "unavailable", "GET /events/:id demo", r.body);
    r = await api(bT, "GET", `/events/${evPravi}`);
    assert(r.status === 200 && r.body.is_demo === false && r.body.payment_mode === "test", "GET /events/:id pravi", r.body);
    r = await api(bT, "GET", `/events/${evDemo}`, T.ana);
    assert(r.status === 200 && r.body.is_demo === true, "GET /events/:id prijavljen (osebni del) ohrani is_demo", r.body);
    r = await api(bT, "GET", `/events/${evDemo}/vip`);
    assert(r.status === 200 && r.body.is_demo === true && r.body.payment_mode === "unavailable", "GET /events/:id/vip demo: is_demo, unavailable, razlog", r.body);
    r = await api(bT, "GET", `/events/${evPravi}/vip`);
    assert(r.status === 200 && r.body.is_demo === false && r.body.payment_mode === "test", "GET /events/:id/vip pravi", r.body);
    {
      const besedila = [(await api(bT, "GET", "/events")).text, (await api(bT, "GET", `/events/${evDemo}`)).text, (await api(bT, "GET", `/events/${evDemo}/vip`)).text, (await api(bT, "GET", "/search?q=Velvet")).text];
      assert(besedila.every(t => !/payment_unavailable_reason|demo_club/.test(t)), "razloga (payment_unavailable_reason, demo_club) javni odgovori NE vsebujejo (I34: razlog samo lastniku v GET /business/sales)");
    }
    r = await api(bT, "PUT", `/me/favorites/${evDemo}`, T.ana);
    r = await api(bT, "GET", "/me/favorites", T.ana);
    assert(r.status === 200 && r.body.events.find(e => e.id === evDemo)?.is_demo === true, "GET /me/favorites: dogodek ima is_demo", r.body.events);
    r = await api(bT, "PUT", `/clubs/${demo.Velvet}/follow`, T.ana);
    r = await api(bT, "GET", "/me/clubs/following", T.ana);
    assert(r.status === 200 && r.body.clubs.find(k => k.id === demo.Velvet)?.is_demo === true, "GET /me/clubs/following: klub ima is_demo", r.body);
    r = await api(bT, "GET", "/business/events", T.lastnik_demo);
    assert(r.status === 200 && r.body.length > 0 && r.body.every(e => e.is_demo === true && e.payment_mode === "unavailable"), "GET /business/events (lastnik demo kluba)", r.body.map(e => [e.is_demo, e.payment_mode]));
    r = await api(bT, "GET", "/business/clubs/me", T.lastnik_demo);
    assert(r.status === 200 && r.body.is_demo === true, "GET /business/clubs/me: lastnik vidi is_demo", r.body.is_demo);
    r = await api(bT, "GET", "/business/sales", T.lastnik_demo);
    assert(r.status === 200 && r.body.payment_mode === "unavailable" && r.body.payment_unavailable_reason === "demo_club", "GET /business/sales: payment_unavailable_reason demo_club", [r.body.payment_mode, r.body.payment_unavailable_reason]);
    r = await api(bT, "GET", "/business/sales", T.lastnik_pravi);
    assert(r.status === 200 && r.body.payment_mode !== "unavailable" && r.body.payment_unavailable_reason === null, "GET /business/sales pravi klub: brez razloga", [r.body.payment_mode, r.body.payment_unavailable_reason]);

    // ================================================================
    console.log("\n# 3. Nakup na demo klubu je 409 demo_club (brez stranskih ucinkov)");
    const pred = { naroc: await sticna([evDemo, evDemoZastonj, evDemoPriPravem]), prod: await prodano([evDemo, evDemoZastonj, evDemoPriPravem]) };
    const vstopnicPred = (await pool.query("SELECT COUNT(*)::int AS n FROM tickets")).rows[0].n;
    r = await kupiVstopnico(bT, T.ana, evDemo);
    assert(jeDemoNapaka(r), "uporabnik, vstopnica (placljiva): 409 demo_club, natancna oblika", r);
    r = await kupiVstopnico(bT, T.bor, evDemo, null, 3);
    assert(jeDemoNapaka(r), "uporabnik, 3 vstopnice: 409 demo_club", r);
    r = await kupiVstopnico(bT, T.cene, evDemoZastonj);
    assert(jeDemoNapaka(r), "uporabnik, vstopnica za 0 EUR: 409 demo_club (tudi brezplacno ni dovoljeno)", r);
    r = await kupiVstopnico(bT, T.lastnik_demo, evDemo);
    assert(jeDemoNapaka(r), "lastnik demo kluba (business): 409 demo_club", r);
    r = await kupiMizo(bT, T.dana, evDemo, mDemo1);
    assert(jeDemoNapaka(r), "VIP miza: 409 demo_club", r);
    r = await kupiGost(bT, evDemo, "gost-demo@example.com");
    assert(jeDemoNapaka(r), "gostujoci nakup (placljiv): 409 demo_club", r);
    r = await kupiGost(bT, evDemoZastonj, "gost-demo0@example.com");
    assert(jeDemoNapaka(r), "gostujoci nakup (0 EUR): 409 demo_club", r);
    r = await kupiVstopnico(bT, T.eva, evDemoPriPravem);
    assert(jeDemoNapaka(r), "dogodek demo kluba pri pravem prizoriscu: prodajalec je demo klub -> 409 demo_club", r);
    r = await kupiMizo(bT, T.eva, evDemoPriPravem, mDemo1);
    assert(jeDemoNapaka(r), "VIP miza na dogodku demo kluba pri pravem prizoriscu: 409 demo_club", r);
    const k1 = crypto.randomUUID(), k2 = crypto.randomUUID();
    r = await kupiVstopnico(bT, T.gina, evDemo, k1);
    assert(jeDemoNapaka(r), "z Idempotency-Key: 409 demo_club", r);
    r = await kupiMizo(bT, T.gina, evDemo, mDemo2, k2);
    assert(jeDemoNapaka(r), "miza z Idempotency-Key: 409 demo_club", r);
    r = await kupiVstopnico(bT, T.gina, evDemo, k1);
    assert(jeDemoNapaka(r), "ponovitev istega kljuca: spet 409 demo_club (ne ponovitev starega odgovora)", r);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE idempotency_key = ANY($1::uuid[])", [[k1, k2]])).rows[0].n === 0, "kljuca nista zapisana");
    assert(await sticna([evDemo, evDemoZastonj, evDemoPriPravem]) === pred.naroc, "nobenega naroclila", await sticna([evDemo, evDemoZastonj, evDemoPriPravem]));
    assert(await prodano([evDemo, evDemoZastonj, evDemoPriPravem]) === pred.prod, "sold_count nespremenjen");
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM tickets")).rows[0].n === vstopnicPred, "nobene nove vstopnice");
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE table_id IS NOT NULL")).rows[0].n === 0, "nobena miza ni zasedena");
    r = await api(bT, "GET", `/events/${evDemo}/vip`);
    assert(r.body.tables.length === 3 && r.body.tables.every(t => t.available === true), "VIP mize na demo dogodku so se vedno proste", r.body.tables);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE guest_email LIKE 'gost-demo%'")).rows[0].n === 0, "gost: nobenega naroclila");
    // Napaka pri validaciji ostane napaka vhoda (400 pred 409 ni problem), neznan dogodek ostane 404.
    r = await kupiVstopnico(bT, T.ana, 999999);
    assert(r.status === 404, "neobstojec dogodek: se vedno 404", r.status);

    // ================================================================
    console.log("\n# 4. Vloga admin sme kupovati; ostalo nespremenjeno");
    r = await kupiVstopnico(bT, T.admin, evDemo, null, 2);
    assert(r.status === 201 && r.body.order && r.body.order.status === "paid" && r.body.tickets.length === 2, "admin: vstopnice na demo klubu 201 paid", r.body);
    const adminKarte = r.body.tickets;
    assert(await prodano([evDemo]) === 2, "sold_count se poveca za admina", await prodano([evDemo]));
    r = await kupiMizo(bT, T.admin, evDemo, mDemo1);
    assert(r.status === 201 && r.body.order && r.body.order.status === "paid", "admin: VIP miza na demo klubu 201 paid", r.body);
    r = await kupiVstopnico(bT, T.admin, evDemoZastonj);
    assert(r.status === 201 && r.body.order.status === "paid", "admin: brezplacna vstopnica 201", r.body);
    r = await kupiGost(bT, evDemo, "gost-po-adminu@example.com");
    assert(jeDemoNapaka(r), "gost je se vedno zavrnjen (vloga admin velja samo za prijavljene)", r);
    r = await kupiVstopnico(bT, T.ana, evDemo);
    assert(jeDemoNapaka(r), "navaden uporabnik je se vedno zavrnjen", r);
    r = await kupiMizo(bT, T.ana, evDemo, mDemo3);
    assert(jeDemoNapaka(r), "navaden uporabnik: miza se vedno zavrnjena", r);
    // Sken (vratar/lastnik) na demo klubu deluje kot prej.
    await pool.query("UPDATE events SET start_at = NOW() + INTERVAL '1 hour' WHERE id = $1", [evDemo]);
    r = await api(bT, "POST", "/business/tickets/scan", T.lastnik_demo, { qr: adminKarte[0].qr });
    assert(r.status === 200 && r.body.result === "ok", "sken vstopnice demo kluba: ok", r.body);
    // Prenos ze obstojece vstopnice prejemniku (navaden uporabnik, ne admin).
    r = await api(bT, "POST", `/tickets/${adminKarte[1].id}/transfer`, T.admin, { email: "jure@outly.si" });
    assert(r.status === 200 && r.body.ticket && r.body.ticket.transferred === true, "prenos obstojece vstopnice na navadnega uporabnika: 200", r.body);
    // Guest lista (admin API) na demo dogodku.
    r = await api(bT, "POST", "/admin/api/guest-lists", T.admin, { event_id: evDemoZastonj, user_id: ANA, spots: 2 });
    assert(r.status === 201, "guest lista (admin) na demo dogodku: 201", r.body);
    // payment_mode javnega dogodka ne zavisi od uporabnika (I17): admin vidi isto.
    r = await api(bT, "GET", `/events/${evDemo}`, T.admin);
    assert(r.status === 200 && r.body.is_demo === true && r.body.payment_mode === "unavailable", "GET /events/:id (admin): isti javni podatki kot za vse", r.body);

    // ================================================================
    console.log("\n# 5. Navaden klub nespremenjen; organizator pri demo prizoriscu je kupljiv");
    const predP = await prodano([evPravi]);
    r = await kupiVstopnico(bT, T.ana, evPravi);
    assert(r.status === 201 && r.body.order.status === "paid", "pravi klub: vstopnica 201 paid", r.body);
    r = await kupiMizo(bT, T.bor, evPravi, mPravi1);
    assert(r.status === 201 && r.body.order.status === "paid", "pravi klub: VIP miza 201 paid", r.body);
    r = await kupiGost(bT, evPravi, "gost-pravi@example.com");
    assert(r.status === 201 && r.body.order.status === "paid", "pravi klub: gostujoci nakup 201 paid", r.body);
    assert(await prodano([evPravi]) === predP + 2, "sold_count pravega kluba se poveca", await prodano([evPravi]));
    r = await kupiVstopnico(bT, T.cene, evOrgPriDemo);
    assert(r.status === 201 && r.body.order.status === "paid", "dogodek organizatorja pri demo prizoriscu: vstopnica 201 (prodajalec = organizator)", r.body);
    r = await kupiGost(bT, evOrgPriDemo, "gost-org@example.com");
    assert(r.status === 201, "dogodek organizatorja pri demo prizoriscu: gost 201", r.body);

    // ================================================================
    console.log("\n# 6. Admin stikalo");
    r = await api(bT, "GET", "/admin/api/clubs", T.admin);
    assert(r.status === 200 && r.body.every(k => typeof k.is_demo === "boolean") && r.body.find(k => k.id === demo.Velvet).is_demo === true && r.body.find(k => k.id === pravi).is_demo === false, "GET /admin/api/clubs: is_demo pri vsakem klubu", r.body.map(k => k.is_demo));
    for (const [k, ime] of [[T.ana, "navaden uporabnik"], [T.lastnik_pravi, "lastnik kluba"]]) {
      r = await api(bT, "PATCH", `/admin/api/clubs/${pravi}`, k, { isDemo: true });
      assert(r.status === 403, `PATCH /admin/api/clubs/:id (${ime}): 403`, r.status);
    }
    r = await api(bT, "PATCH", `/admin/api/clubs/${pravi}`, null, { isDemo: true });
    assert(r.status === 401, "brez zetona: 401", r.status);
    assert((await pool.query("SELECT is_demo FROM clubs WHERE id=$1", [pravi])).rows[0].is_demo === false, "klub po zavrnjenih poskusih nespremenjen");
    r = await api(bT, "PATCH", `/admin/api/clubs/${pravi}`, T.admin, { isDemo: "da" });
    assert(r.status === 400, "isDemo ni boolean: 400", r.body);
    r = await api(bT, "GET", `/clubs/${pravi}`);   // segrej predpomnilnik
    r = await api(bT, "GET", `/events/${evPravi}`);
    assert(r.body.is_demo === false && r.body.payment_mode === "test", "pred stikalom: javni odgovor (predpomnjen) is_demo false");
    r = await api(bT, "PATCH", `/admin/api/clubs/${pravi}`, T.admin, { isDemo: true });
    assert(r.status === 200 && r.body.is_demo === true, "admin: isDemo true -> 200, odgovor ima is_demo true", r.body.is_demo);
    r = await api(bT, "GET", `/clubs/${pravi}`);
    assert(r.body.is_demo === true, "javni /clubs/:id takoj kaze is_demo true (predpomnilnik razveljavljen)", r.body.is_demo);
    r = await api(bT, "GET", `/events/${evPravi}`);
    assert(r.body.is_demo === true && r.body.payment_mode === "unavailable", "javni /events/:id takoj: is_demo true, unavailable", r.body);
    r = await kupiVstopnico(bT, T.dana, evPravi);
    assert(jeDemoNapaka(r), "po stikalu je nakup na prej navadnem klubu 409 demo_club", r);
    r = await kupiMizo(bT, T.dana, evPravi, mPravi2);
    assert(jeDemoNapaka(r), "po stikalu: miza 409 demo_club", r);
    r = await api(bT, "PATCH", `/admin/api/clubs/${pravi}`, T.admin, { is_demo: false });
    assert(r.status === 200 && r.body.is_demo === false, "admin: is_demo false (snake_case) -> 200", r.body);
    r = await kupiVstopnico(bT, T.dana, evPravi);
    assert(r.status === 201, "po preklicu stikala je nakup spet 201", r);
    // Lastnik ne more sam spremeniti oznake (niti ugasniti pri demo klubu, niti prizgati pri svojem).
    r = await api(bT, "PATCH", "/business/clubs/me", T.lastnik_demo, { isDemo: false, is_demo: false, description: "Nov opis" });
    assert(r.status === 200 && (await pool.query("SELECT is_demo FROM clubs WHERE id=$1", [demo.Velvet])).rows[0].is_demo === true, "lastnik demo kluba ne more ugasniti oznake (PATCH /business/clubs/me jo ignorira)", r.body.is_demo);
    r = await api(bT, "PATCH", "/business/clubs/me", T.lastnik_pravi, { isDemo: true, is_demo: true, description: "Nov opis" });
    assert(r.status === 200 && (await pool.query("SELECT is_demo FROM clubs WHERE id=$1", [pravi])).rows[0].is_demo === false, "lastnik pravega kluba si oznake ne more prizgati", r.body.is_demo);
    r = await api(bT, "POST", "/admin/api/clubs", T.admin, { ownerEmail: "kaja@outly.si", name: "Nov demo", isDemo: true });
    assert(r.status === 201 && r.body.is_demo === true, "POST /admin/api/clubs z isDemo: true -> 201, is_demo true", r.body);
    await pool.query("UPDATE users SET role='business' WHERE email='jure@outly.si'");
    r = await api(bT, "POST", "/clubs", T.jure, { name: "Jurijev klub", city: "Ljubljana", isDemo: true, is_demo: true });
    assert(r.status === 201 && r.body.is_demo === false, "klub, ki ga ustvari lastnik (POST /clubs): is_demo vedno false, vhod ignoriran", [r.status, r.body.is_demo]);

    // ================================================================
    console.log("\n# 7. ZIV (sk_live_): demo zavrnjen PRED Stripom");
    await pool.query("UPDATE clubs SET is_demo = TRUE WHERE id = $1", [demo.Velvet]);
    await pool.query("UPDATE events SET start_at = $2 WHERE id = $1", [evDemo, cezDan]);
    const stripe0 = S.zahtevki, naroc0 = await sticna([evDemo, evDemoZastonj, evPravi]);
    r = await api(bZ, "GET", `/events/${evDemo}`);
    assert(r.status === 200 && r.body.payment_mode === "unavailable" && r.body.is_demo === true, "ZIV: demo dogodek payment_mode unavailable, razlog demo_club", r.body);
    r = await api(bZ, "GET", `/events/${evPravi}`);
    assert(r.status === 200 && r.body.payment_mode === "stripe" && r.body.is_demo === false, "ZIV: navaden dogodek payment_mode stripe", r.body);
    r = await kupiVstopnico(bZ, T.hana, evDemo);
    assert(jeDemoNapaka(r), "ZIV: vstopnica na demo klubu -> 409 demo_club", r);
    r = await kupiMizo(bZ, T.hana, evDemo, mDemo3);
    assert(jeDemoNapaka(r), "ZIV: VIP miza na demo klubu -> 409 demo_club", r);
    r = await kupiGost(bZ, evDemo, "gost-ziv-demo@example.com");
    assert(jeDemoNapaka(r), "ZIV: gost na demo klubu -> 409 demo_club", r);
    r = await kupiVstopnico(bZ, T.hana, evDemoZastonj);
    assert(jeDemoNapaka(r), "ZIV: 0 EUR na demo klubu -> 409 demo_club", r);
    assert(S.zahtevki === stripe0, "ZIV: Stripe se ni klical", S.zahtevki - stripe0);
    assert(await sticna([evDemo, evDemoZastonj, evPravi]) === naroc0, "ZIV: nobenega novega naroclila (tudi cakajocega)");
    r = await kupiVstopnico(bZ, T.ivo, evPravi);
    assert(r.status === 201 && r.body.mode === "stripe" && /^https:\/\/checkout\.stripe\.test\//.test(r.body.checkout_url || ""), "ZIV: navaden klub 201 stripe + checkout_url", r);
    r = await kupiVstopnico(bZ, T.admin, evDemo);
    assert(r.status === 201 && r.body.mode === "stripe" && r.body.checkout_url, "ZIV: admin na demo klubu 201 stripe + checkout_url", r);
    assert(S.zahtevki === stripe0 + 2, "ZIV: Stripe klican samo za navaden klub in admina", S.zahtevki - stripe0);
  } finally {
    for (const o of [TEST, ZIV]) { try { o.srv.kill(); } catch {} }
    stripeServer.close(); jwksServer.close(); await pool.end().catch(() => {});
  }
  console.log(`\n${ok} OK, ${fail} NAPAK`);
  process.exit(fail === 0 ? 0 : 1);
})().catch(e => { console.error(e); process.exit(1); });
