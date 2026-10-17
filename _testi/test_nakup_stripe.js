#!/usr/bin/env node
/**
 * Klic Stripa ne sme drzati semaforja nakupov in povezave z bazo (issue #274, I16).
 * Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_nakup_stripe.js
 *
 * Lazni Stripe odgovarja z zamikom (ZAMIK) in steje hkratne klice. Backend: NAKUP_VZPOREDNO=3, PG_POOL_MAX=4.
 *   S1  tri poti (vstopnice, VIP miza, gost) v Stripe nacinu zasedejo VSA tri dovoljenja; ker dovoljenja po COMMIT sprostijo,
 *       nakup v klubu brez Stripa (testni nacin) in brezplacen nakup uspeta TAKOJ (< 1 s), ne cakata na Stripe.
 *   S2  12 hkratnih Stripe nakupov s pocasnim Stripom (2 s) in NAKUP_CAKANJE_MS=3000: vsi 201 (ne 503 zaradi semaforja),
 *       Stripe vidi vec hkratnih klicev, kot je dovoljenj; pool z 4 povezavami ne zastane.
 *   S3  Stripe zavrne: 502, narocilo `failed`, zaloga sproscena, dovoljenje sproscena (naslednji nakup gre takoj).
 *   S4  idempotenca (I18): ponovitev istega kljuca med klicem Stripa vrne isto narocilo, en sam klic Stripa.
 *   S5  lasten semafor za Stripe (STRIPE_VZPOREDNO=2, STRIPE_CAKANJE_MS=1000): vec kot 2 hkratna klica Stripa nikoli;
 *       presezek dobi 503 Retry-After, narocilo `failed`, zaloga sproscena.
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3741, JWKS_PORT = 3742, STRIPE_PORT = 3743;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-nakup-stripe";
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
const pocakaj = (ms) => new Promise(r => setTimeout(r, ms));
async function cakajPogoj(f, ms = 10000) { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (await f()) return true; await pocakaj(50); } return false; }

let ipSt = 0;
async function api(method, path, token, body, glave = {}) {
  const t0 = performance.now();
  const r = await fetch(BASE + path, { method, headers: { "content-type": "application/json", "x-forwarded-for": `10.74.${(++ipSt >> 8) & 255}.${(ipSt & 255) + 1}`, ...(token ? { authorization: "Bearer " + token } : {}), ...glave }, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(40000) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, retryAfter: r.headers.get("retry-after"), ms: performance.now() - t0 };
}

// Lazni Stripe z nastavljivim zamikom in stevcem hkratnih klicev ustvarjanja seje.
let ZAMIK = 2000, NAPAKA = false, stSej = 0, vLetu = 0, najvecVLetu = 0, klicov = 0;
const seje = {};
const stripeServer = http.createServer((req, res) => {
  let d = ""; req.on("data", x => d += x);
  req.on("end", () => {
    const p = Object.fromEntries(new URLSearchParams(d));
    const odg = (s, o) => { res.writeHead(s, { "content-type": "application/json", "request-id": "req_test" }); res.end(JSON.stringify(o)); };
    const u = req.url.split("?")[0];
    let m;
    if (req.method === "POST" && u === "/v1/checkout/sessions") {
      klicov++; vLetu++; najvecVLetu = Math.max(najvecVLetu, vLetu);
      return setTimeout(() => {
        vLetu--;
        if (NAPAKA) return odg(400, { error: { type: "invalid_request_error", message: "zavrnjeno (test)" } });
        const id = "cs_test_" + (++stSej);
        seje[id] = { id, object: "checkout.session", url: `https://checkout.stripe.test/c/pay/${id}`, status: "open", payment_status: "unpaid",
          expires_at: Number(p.expires_at), metadata: { order_id: p["metadata[order_id]"] } };
        odg(200, seje[id]);
      }, ZAMIK);
    }
    if (req.method === "GET" && (m = u.match(/^\/v1\/checkout\/sessions\/(cs_\w+)$/))) return odg(200, seje[m[1]]);
    return odg(404, { error: { type: "invalid_request_error", message: "neznana pot " + u } });
  });
});

let srv = null, log = "";
async function zagon(okolje) {
  log = "";
  srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test",
    STRIPE_SECRET_KEY: "sk_test_lokalno", STRIPE_WEBHOOK_SECRET: "whsec_test", STRIPE_API_BASE: `http://127.0.0.1:${STRIPE_PORT}`,
    STRIPE_POSPRAVI_MS: "3600000", APP_URL: "https://outly.test", TEST_PLACILA: "", REZERVACIJE_CISCENJE_MS: "0",
    NAKUP_VZPOREDNO: "3", NAKUP_CAKANJE_MS: "3000", PG_POOL_MAX: "4", GOST_NAKUP_NA_URO: "1000", ...okolje }, stdio: ["ignore", "pipe", "pipe"] });
  srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); return; } catch { await pocakaj(100); } }
}
async function ustavi() { if (!srv) return; const s = srv; srv = null; await new Promise(r => { s.once("exit", r); s.kill(); }); }

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, stripe_events, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  await new Promise(r => stripeServer.listen(STRIPE_PORT, r));
  await zagon({});
  try {
    const T = { lastnik: zeton("lastnik@outly.si", uuid(1)) };
    const kupci = [];
    for (let i = 0; i < 20; i++) kupci.push(zeton(`kupec${i}@outly.si`, uuid(100 + i)));
    for (const t of [T.lastnik, ...kupci]) { const r = await api("GET", "/me", t); if (r.status !== 200) assert(false, "GET /me", r.body); }
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    // Klub 1: povezan Stripe (nacin "stripe"). Klub 2: brez Stripa + sandbox kljuc = testni nacin (takoj placano, Stripa ne kliče).
    await pool.query(`INSERT INTO clubs (owner_user_id, name, city, stripe_account_id, stripe_charges_enabled)
                      VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Stripe Club', 'Ljubljana', 'acct_test1', TRUE)`);
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Test Club', 'Maribor')");
    const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    const dogodek = async (klub, naslov, cena, kap = 1000) => (await pool.query(
      "INSERT INTO events (club_id, title, start_at, status, ticket_price_cents, capacity, min_age, vip_enabled) VALUES ($1,$2,$3,'published',$4,$5,0,TRUE) RETURNING id", [klub, naslov, cezDan, cena, kap])).rows[0].id;
    const E1 = await dogodek(1, "Stripe noc", 1000), E2 = await dogodek(2, "Testna noc", 1000), E3 = await dogodek(1, "Brezplacna noc", 0);
    const E4 = await dogodek(1, "Naval", 1000), E5 = await dogodek(1, "Zavrnjeno", 1000, 50), E6 = await dogodek(1, "Idempotenca", 1000), E7 = await dogodek(1, "Omejitev", 1000, 50);
    await pool.query("INSERT INTO club_tables (club_id, label, x, y, w, h, seats, price_cents) VALUES (1, 'A1', 10, 10, 10, 10, 4, 20000)");
    const sold = async (ev) => (await pool.query("SELECT sold_count FROM events WHERE id=$1", [ev])).rows[0].sold_count;
    const TERMS = { accept_terms: true, terms_version: "2026-10-01" };
    const gost = (ev, email) => api("POST", `/guest/events/${ev}/orders`, null, { email, quantity: 1, ...TERMS });

    console.log("# S1: tri poti zasedejo vsa dovoljenja, hiter nakup drugega kluba ne caka na Stripe");
    ZAMIK = 2000; najvecVLetu = 0;
    const t0 = performance.now();
    const pocasni = [
      api("POST", `/events/${E1}/orders`, kupci[0], { quantity: 1 }),
      api("POST", `/events/${E1}/tables/1/orders`, kupci[1], {}),
      gost(E1, "gost1@example.com"),
    ];
    await cakajPogoj(() => vLetu >= 3, 5000);
    // Vse tri poti so ze v Stripu (po COMMIT-u); stara koda tu se drzi vsa tri dovoljenja.
    assert(vLetu === 3, "vsi trije pocasni nakupi so v klicu Stripa", vLetu);
    const hitri = await api("POST", `/events/${E2}/orders`, kupci[2], { quantity: 1 });
    assert(hitri.status === 201 && hitri.body.mode === "test" && hitri.body.order.status === "paid", "nakup v klubu brez Stripa: 201 paid", hitri);
    assert(hitri.ms < 1000, "... in TAKOJ (< 1 s), ne caka na Stripe", Math.round(hitri.ms));
    const prost = await api("POST", `/events/${E3}/orders`, kupci[3], { quantity: 1 });
    assert(prost.status === 201 && prost.body.order.status === "paid" && prost.body.order.total_cents === 0, "brezplacen nakup: 201 paid", prost);
    assert(prost.ms < 1000, "... in TAKOJ (< 1 s)", Math.round(prost.ms));
    const gostHitri = await api("POST", `/guest/events/${E2}/orders`, null, { email: "gost2@example.com", quantity: 1, ...TERMS });
    assert(gostHitri.status === 201 && gostHitri.ms < 1000, "gostujoc nakup v testnem klubu: 201 takoj", { s: gostHitri.status, ms: Math.round(gostHitri.ms) });
    const odg = await Promise.all(pocasni);
    for (const [i, ime] of ["vstopnice", "VIP miza", "gost"].entries()) {
      const r = odg[i];
      assert(r.status === 201 && r.body.mode === "stripe" && /^https:\/\/checkout\.stripe\.test\//.test(r.body.checkout_url) && r.body.order.status === "pending",
        `pocasen nakup (${ime}): 201 pending s povezavo`, { s: r.status, b: r.body });
    }
    assert(!!odg[2].body.guest_token, "gost: guest_token v odgovoru");
    const seje1 = (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1 AND stripe_checkout_session_id IS NOT NULL AND checkout_url IS NOT NULL", [E1])).rows[0].n;
    assert(seje1 === 3, "v bazi imajo vsa tri narocila zapisano sejo in povezavo", seje1);
    console.log(`    (skupaj ${Math.round(performance.now() - t0)} ms)`);

    console.log("\n# S2: 12 hkratnih Stripe nakupov (2 s), NAKUP_VZPOREDNO=3, cakanje 3 s, pool 4");
    najvecVLetu = 0;
    const tS2 = performance.now();
    const naval = await Promise.all(kupci.slice(0, 12).map(t => api("POST", `/events/${E4}/orders`, t, { quantity: 1 })));
    const skupajMs = performance.now() - tS2;
    const stat = naval.map(r => r.status);
    assert(naval.every(r => r.status === 201 && r.body.checkout_url), "vseh 12 -> 201 s povezavo (nobenega 503 zaradi semaforja)", stat);
    assert(najvecVLetu > 3, "Stripe je videl vec hkratnih klicev, kot je dovoljenj nakupa (Stripe je zunaj semaforja)", najvecVLetu);
    assert(skupajMs < 5000, "skupaj < 5 s (stara koda: 4 valovi x 2 s)", Math.round(skupajMs));
    assert(await sold(E4) === 12, "zaloga: 12 rezerviranih", await sold(E4));
    const zdravje = await api("GET", "/clubs", null);
    assert(zdravje.status === 200 && zdravje.ms < 1000, "GET /clubs po navali: 200 hitro", { s: zdravje.status, ms: Math.round(zdravje.ms) });
    assert(!/timeout exceeded when trying to connect/i.test(log), "brez zastoja poola (timeout pri pool.connect)", log.slice(-300));

    console.log("\n# S3: Stripe zavrne -> 502, failed, zaloga sproscena, dovoljenje sproscena");
    NAPAKA = true; ZAMIK = 100;
    const zavr = await Promise.all(kupci.slice(0, 4).map(t => api("POST", `/events/${E5}/orders`, t, { quantity: 2 })));
    assert(zavr.every(r => r.status === 502), "4 hkratni nakupi: vsi 502", zavr.map(r => r.status));
    const st5 = (await pool.query("SELECT status, COUNT(*)::int AS n FROM orders WHERE event_id=$1 GROUP BY status", [E5])).rows;
    assert(st5.length === 1 && st5[0].status === "failed" && st5[0].n === 4, "vsa narocila `failed`", st5);
    assert(await sold(E5) === 0, "zaloga sproscena (sold_count 0)", await sold(E5));
    const po = await api("POST", `/events/${E2}/orders`, kupci[4], { quantity: 1 });
    assert(po.status === 201 && po.ms < 1000, "po neuspehu dovoljenje ni zaprto: naslednji nakup 201 takoj", { s: po.status, ms: Math.round(po.ms) });
    NAPAKA = false;

    console.log("\n# S4: idempotenca med klicem Stripa");
    ZAMIK = 1500; klicov = 0;
    const kljuc = crypto.randomUUID();
    const p1 = api("POST", `/events/${E6}/orders`, kupci[5], { quantity: 1 }, { "idempotency-key": kljuc });
    await cakajPogoj(() => vLetu >= 1, 5000);
    const p2 = api("POST", `/events/${E6}/orders`, kupci[5], { quantity: 1 }, { "idempotency-key": kljuc });
    const [a, b] = await Promise.all([p1, p2]);
    assert(a.status === 201 && (b.status === 201 || (b.status === 409 && b.body && b.body.error === "request_in_progress")), "izvirnik 201, ponovitev 201 ali 409 request_in_progress", { a: a.status, b: b.status });
    const c3 = await api("POST", `/events/${E6}/orders`, kupci[5], { quantity: 1 }, { "idempotency-key": kljuc });
    assert(c3.status === 201 && c3.body.order.id === a.body.order.id, "ponovitev po koncu: isto narocilo", c3);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1", [E6])).rows[0].n === 1, "eno narocilo");
    assert(klicov === 1, "en sam klic Stripa", klicov);

    await ustavi();
    console.log("\n# S5: lasten semafor za Stripe (STRIPE_VZPOREDNO=2, STRIPE_CAKANJE_MS=1000, zamik 2 s)");
    await zagon({ STRIPE_VZPOREDNO: "2", STRIPE_CAKANJE_MS: "1000" });
    ZAMIK = 2000; najvecVLetu = 0;
    const s5 = await Promise.all(kupci.slice(6, 10).map(t => api("POST", `/events/${E7}/orders`, t, { quantity: 1 })));
    const u5 = s5.filter(r => r.status === 201).length, z5 = s5.filter(r => r.status === 503);
    assert(u5 === 2 && z5.length === 2, "2 uspeta, 2 dobita 503", s5.map(r => r.status));
    assert(z5.every(r => r.retryAfter === "5"), "503 ima Retry-After", z5.map(r => r.retryAfter));
    assert(najvecVLetu === 2, "Stripe nikoli ne vidi vec kot 2 hkratna klica", najvecVLetu);
    const st7 = (await pool.query("SELECT status, COUNT(*)::int AS n FROM orders WHERE event_id=$1 GROUP BY status ORDER BY status", [E7])).rows;
    assert(JSON.stringify(st7) === JSON.stringify([{ status: "failed", n: 2 }, { status: "pending", n: 2 }]), "2 pending + 2 failed", st7);
    assert(await sold(E7) === 2, "zaloga: samo 2 rezervirani", await sold(E7));
  } finally {
    await ustavi(); stripeServer.close(); jwksServer.close(); await pool.end();
  }
  console.log(`\n${ok} uspelo, ${fail} padlo`);
  if (fail) { console.log("--- dnevnik ---\n" + log.slice(-3000)); process.exit(1); }
  process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
