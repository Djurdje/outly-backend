#!/usr/bin/env node
/**
 * Test zlorab, ki jih je nasel varnostni pregled 5. 10. 2026 (kaj lahko naredi kupec ali vratar, ki ne bi smel):
 *   1. cakajoca (neplacana) Stripe narocila: najvec 1 na dogodek in 3 skupaj na uporabnika (I20)
 *   2. vratar na seznamu vstopnic dogodka ne vidi e-naslovov kupcev/imetnikov (lastnik jih vidi)
 *   3. vstopnica odpovedanega dogodka na vratih ne velja: /scan in /scan-batch vrneta event_cancelled
 * Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_zloraba.js
 * Vzorec kot test_stripe.js: lokalni JWKS, lazni Stripe na svojem portu, backend na svojem portu.
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3171, JWKS_PORT = 3971, STRIPE_PORT = 3972;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-zloraba";
const jwksServer = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
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
  const r = await fetch(BASE + path, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}), ...glave }, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}
const pocakaj = (ms) => new Promise(r => setTimeout(r, ms));

// Lazni Stripe: samo ustvarjanje in branje Checkout seje.
let stSej = 0;
const seje = {};
const stripeServer = http.createServer((req, res) => {
  let d = ""; req.on("data", x => d += x);
  req.on("end", () => {
    const p = Object.fromEntries(new URLSearchParams(d));
    const odg = (s, o) => { res.writeHead(s, { "content-type": "application/json", "request-id": "req_test" }); res.end(JSON.stringify(o)); };
    const u = req.url.split("?")[0];
    let m;
    if (req.method === "POST" && u === "/v1/checkout/sessions") {
      const id = "cs_test_" + (++stSej);
      seje[id] = { id, object: "checkout.session", url: `https://checkout.stripe.test/c/pay/${id}`, status: "open", payment_status: "unpaid",
        expires_at: Number(p.expires_at), metadata: { order_id: p["metadata[order_id]"] } };
      return odg(200, seje[id]);
    }
    if (req.method === "GET" && (m = u.match(/^\/v1\/checkout\/sessions\/(cs_\w+)$/))) return odg(200, seje[m[1]]);
    return odg(404, { error: { type: "invalid_request_error", message: "neznana pot " + u } });
  });
});

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, stripe_events, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  await new Promise(r => stripeServer.listen(STRIPE_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test",
    STRIPE_SECRET_KEY: "sk_test_lokalno", STRIPE_WEBHOOK_SECRET: "whsec_test", STRIPE_API_BASE: `http://127.0.0.1:${STRIPE_PORT}`,
    STRIPE_POSPRAVI_MS: "3600000", APP_URL: "https://outly.test", TEST_PLACILA: "" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await pocakaj(100); } }

  try {
    const T = { lastnik: zeton("lastnik@outly.si", uuid(1)), vratar: zeton("vratar@outly.si", uuid(2)),
      ana: zeton("ana@outly.si", uuid(3)), bor: zeton("bor@outly.si", uuid(4)), manager: zeton("manager@outly.si", uuid(5)) };
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    // Klub s povezanim Stripom (sandbox kljuc + charges_enabled -> nacin "stripe", narocila so cakajoca).
    await pool.query(`INSERT INTO clubs (owner_user_id, name, city, stripe_account_id, stripe_charges_enabled)
                      VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana', 'acct_test1', TRUE)`);
    await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, (SELECT id FROM users WHERE email='vratar@outly.si'), 'doorman')");
    await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, (SELECT id FROM users WHERE email='manager@outly.si'), 'manager')");
    const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    const dogodki = [];
    for (let i = 1; i <= 5; i++) {
      const r = await api("POST", "/events", T.lastnik, { clubId: 1, title: `Noc ${i}`, startAt: cezDan, ticketPriceCents: 1000, capacity: 50, minAge: 0 });
      assert(r.status === 201, `dogodek ${i} ustvarjen`, r.body);
      dogodki.push(r.body.id);
    }
    const [ev1, ev2, ev3, ev4, ev5] = dogodki;
    const sold = async (ev) => (await pool.query("SELECT sold_count FROM events WHERE id=$1", [ev])).rows[0].sold_count;

    console.log("\n# 1. Cakajoca narocila: najvec 1 na dogodek");
    let r = await api("POST", `/events/${ev1}/orders`, T.ana, { quantity: 10 });
    assert(r.status === 201 && r.body.mode === "stripe" && r.body.order.status === "pending", "prvo narocilo: 201 pending", r.body);
    r = await api("POST", `/events/${ev1}/orders`, T.ana, { quantity: 10 });
    assert(r.status === 409 && /unfinished payment for this event/.test(r.body), "drugo cakajoce narocilo za isti dogodek -> 409", r);
    assert(await sold(ev1) === 10, "zaloga: zasedenih samo 10 (ne 20)", await sold(ev1));
    const kljuc = crypto.randomUUID();
    r = await api("POST", `/events/${ev2}/orders`, T.ana, { quantity: 1 }, { "idempotency-key": kljuc });
    const n2 = r.body.order && r.body.order.id;
    r = await api("POST", `/events/${ev2}/orders`, T.ana, { quantity: 1 }, { "idempotency-key": kljuc });
    assert(r.status === 201 && r.body.order.id === n2, "ponovitev z istim Idempotency-Key: isto narocilo (omejitev je ne zavrne)", r);
    r = await api("POST", `/events/${ev1}/orders`, T.bor, { quantity: 1 });
    assert(r.status === 201, "drug uporabnik za isti dogodek: 201 (omejitev je na uporabnika)", r);

    console.log("\n# 1b. Hkratni nakupi istega uporabnika");
    const hkratni = await Promise.all([1, 2, 3, 4, 5].map(() => api("POST", `/events/${ev5}/orders`, T.bor, { quantity: 1 })));
    const uspeli = hkratni.filter(x => x.status === 201).length;
    assert(uspeli === 1 && hkratni.filter(x => x.status === 409).length === 4, "5 hkratnih za isti dogodek: tocno 1 uspe, 4 dobijo 409", hkratni.map(x => x.status));

    console.log("\n# 1c. Najvec 3 cakajoca narocila skupaj");
    r = await api("POST", `/events/${ev3}/orders`, T.ana, { quantity: 1 });
    assert(r.status === 201, "tretje cakajoce (ev3): 201", r);
    r = await api("POST", `/events/${ev4}/orders`, T.ana, { quantity: 1 });
    assert(r.status === 409 && /too many unfinished payments/.test(r.body), "cetrto cakajoce (ev4): 409", r);
    await pool.query("UPDATE orders SET status='cancelled', cancelled_at=NOW() WHERE user_id=(SELECT id FROM users WHERE email='ana@outly.si') AND event_id=$1", [ev1]);
    r = await api("POST", `/events/${ev4}/orders`, T.ana, { quantity: 1 });
    assert(r.status === 201, "ko eno poteče (cancelled), gre spet", r);

    console.log("\n# 1d. VIP miza: isto pravilo");
    await pool.query("UPDATE events SET vip_enabled = TRUE WHERE id = ANY($1::int[])", [[ev1, ev2]]);
    await pool.query("INSERT INTO club_tables (club_id, label, x, y, w, h, seats, price_cents) VALUES (1, 'A1', 10, 10, 10, 10, 4, 20000), (1, 'A2', 30, 10, 10, 10, 4, 20000)");
    r = await api("POST", `/events/${ev1}/tables/1/orders`, T.bor, {});
    assert(r.status === 409 && /unfinished payment for this event/.test(r.body), "bor ima cakajoce narocilo za ev1 -> miza 409", r);
    const zasedena = (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE table_id IS NOT NULL")).rows[0].n;
    assert(zasedena === 0, "miza ni zasedena", zasedena);
    await pool.query("UPDATE orders SET status='cancelled', cancelled_at=NOW() WHERE user_id=(SELECT id FROM users WHERE email='bor@outly.si') AND event_id=$1", [ev1]);
    r = await api("POST", `/events/${ev1}/tables/1/orders`, T.bor, {});
    assert(r.status === 201 && r.body.mode === "stripe", "brez cakajocega: miza 201", r);
    r = await api("POST", `/events/${ev1}/tables/2/orders`, T.bor, {});
    assert(r.status === 409, "druga miza istega dogodka, prva se ni placana -> 409", r);

    console.log("\n# 2. Vratar ne vidi e-naslovov kupcev");
    // Placana vstopnica (kot da je prisel webhook): narocilo ane za ev2 placamo neposredno.
    await pool.query("UPDATE orders SET status='paid', paid_at=NOW() WHERE id=$1", [n2]);
    await pool.query("INSERT INTO tickets (order_id, event_id) VALUES ($1, $2)", [n2, ev2]);
    r = await api("GET", `/business/events/${ev2}/tickets`, T.vratar);
    assert(r.status === 200 && r.body.length === 1, "vratar: seznam vstopnic 200", r);
    const v = r.body[0] || {};
    assert(!("buyer_email" in v) && !("holder_email" in v), "vratar: brez buyer_email in holder_email", v);
    assert(typeof v.qr === "string" && v.qr.length > 0 && v.holder_username, "vratar: QR za rocni vstop in uporabnisko ime ostaneta", v);
    r = await api("GET", `/business/events/${ev2}/tickets`, T.manager);
    assert(r.status === 200 && r.body[0].buyer_email === "ana@outly.si", "manager: e-naslov kupca viden kot doslej", r.body[0]);
    r = await api("GET", `/business/events/${ev2}/tickets`, T.lastnik);
    assert(r.status === 200 && r.body[0].buyer_email === "ana@outly.si" && r.body[0].holder_email === "ana@outly.si", "lastnik: e-naslova vidna kot doslej", r.body[0]);

    console.log("\n# 3. Odpovedan dogodek: vstopnica na vratih ne velja");
    await pool.query("INSERT INTO tickets (order_id, event_id) VALUES ($1, $2)", [n2, ev2]);
    const ser = (await pool.query("SELECT serial FROM tickets WHERE order_id=$1 ORDER BY id", [n2])).rows.map(x => x.serial);
    const qr = (await api("GET", `/business/events/${ev2}/tickets`, T.lastnik)).body.map(x => x.qr);
    r = await api("PATCH", `/events/${ev2}`, T.lastnik, { status: "cancelled" });
    const st = (await pool.query("SELECT status FROM events WHERE id=$1", [ev2])).rows[0].status;
    if (st !== "cancelled") await pool.query("UPDATE events SET status='cancelled' WHERE id=$1", [ev2]);
    r = await api("POST", "/business/tickets/scan", T.vratar, { qr: qr[0] });
    assert(r.status === 409 && r.body.result === "event_cancelled", "/scan (QR): odpovedan dogodek -> 409 event_cancelled", r);
    r = await api("POST", "/business/tickets/scan", T.vratar, { serial: ser[0] });
    assert(r.status === 409 && r.body.result === "event_cancelled", "/scan (serial): odpovedan dogodek -> 409 event_cancelled", r);
    let t0 = (await pool.query("SELECT status FROM tickets WHERE serial=$1", [ser[0]])).rows[0].status;
    assert(t0 === "valid", "vstopnica ostane valid (ni porabljena)", t0);
    r = await api("POST", "/business/tickets/scan-batch", T.vratar, { device_id: crypto.randomUUID(),
      scans: [{ client_scan_id: crypto.randomUUID(), qr: qr[1], scanned_at: new Date().toISOString() }] });
    assert(r.status === 200 && r.body.results[0].result === "event_cancelled", "/scan-batch: event_cancelled", r.body);
    t0 = (await pool.query("SELECT status FROM tickets WHERE serial=$1", [ser[1]])).rows[0].status;
    assert(t0 === "valid", "batch: vstopnica ostane valid", t0);
  } catch (e) {
    fail++; console.error("NAPAKA TESTA:", e);
  } finally {
    srv.kill(); jwksServer.close(); stripeServer.close(); await pool.end();
    if (fail) console.log("\n--- dnevnik streznika ---\n" + log.split("\n").slice(-40).join("\n"));
    console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
    process.exit(fail ? 1 : 0);
  }
})();
