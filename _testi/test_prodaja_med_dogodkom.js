#!/usr/bin/env node
/**
 * Prodaja MED dogodkom (Martin 28. 11. 2026, DECISIONS 2026-11-28): nakup (vstopnice, gost, VIP miza) je mogoc od odprtja prodaje do KONCA dogodka
 * (KONEC_DOGODKA = COALESCE(end_at, start_at + 8 h)), ne do zacetka. Zagon:
 *   DATABASE_URL="postgres://postgres@localhost:5432/outly" node _testi/test_prodaja_med_dogodkom.js
 *  M1  zacel se je pred 1 h, se traja: vstopnice, gost, VIP miza 201; on_sale true (GET /events/:id, /events, /events/:id/vip)
 *  M2  koncan (end_at v preteklosti): 409 »already ended«, on_sale false
 *  M3  brez end_at, zacetek pred 9 h (konec = zacetek + 8 h): 409 »already ended«; pred 7 h: se se kupuje
 *  M4  sales_close_at v preteklosti med dogodkom: 409 »closed«, on_sale false
 *  M5  prihodnji dogodek: nakup se vedno 201 (pozitivna kontrola)
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 5861, JWKS_PORT = 5862, PLACILA_PORT = 5863;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-med";
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

let ipSt = 0;
async function api(method, p, token, body) {
  const r = await fetch(BASE + p, { method, headers: { "content-type": "application/json", "x-forwarded-for": `10.79.${(++ipSt >> 8) & 255}.${(ipSt & 255) + 1}`, ...(token ? { authorization: "Bearer " + token } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}

// Lazni placilni streznik: samo ustvari checkout sejo (pozitivna kontrola nakupa); expire sprejme.
let nSej = 0;
const placilaServer = http.createServer((req, res) => {
  let d = ""; req.on("data", x => d += x);
  req.on("end", () => {
    const p = Object.fromEntries(new URLSearchParams(d));
    const odg = (s, o) => { res.writeHead(s, { "content-type": "application/json", "request-id": "req_test" }); res.end(JSON.stringify(o)); };
    const u = req.url.split("?")[0];
    if (req.method === "POST" && u === "/v1/checkout/sessions") {
      const id = "cs_test_m" + (++nSej);
      return odg(200, { id, object: "checkout.session", url: `https://checkout.stripe.test/c/pay/${id}`, status: "open", payment_status: "unpaid",
        amount_total: Number(p["line_items[0][quantity]"]) * Number(p["line_items[0][price_data][unit_amount]"]), currency: p["line_items[0][price_data][currency]"],
        livemode: false, metadata: { order_id: p["metadata[order_id]"] }, client_reference_id: p.client_reference_id, expires_at: Number(p.expires_at), payment_intent: null });
    }
    if (req.method === "POST" && /\/expire$/.test(u)) return odg(200, { id: u.split("/")[4], object: "checkout.session", status: "expired" });
    return odg(404, { error: { type: "invalid_request_error", message: "Lazni streznik: neznana pot " + req.method + " " + u } });
  });
});

let srv = null, log = "";
(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, admin_dejanja, vracila, stripe_events, club_event_notifications, club_follows, guest_list_members, guest_lists, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, event_tables, club_tables, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  await new Promise(r => placilaServer.listen(PLACILA_PORT, r));
  srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test",
    STRIPE_SECRET_KEY: "sk_test_lokalno", STRIPE_WEBHOOK_SECRET: "whsec_test_okno", STRIPE_API_BASE: `http://127.0.0.1:${PLACILA_PORT}`, STRIPE_POSPRAVI_MS: "0", STRIPE_PREKLIC_PO_S: "1",
    APP_URL: "https://outly.test", TEST_PLACILA: "", GOST_NAKUP_TEST: "1", GOST_NAKUP_NA_URO: "1000", REZERVACIJE_CISCENJE_MS: "0",
    VRACILA_TICK_MS: "0", VRACILA_SWEEP_MS: "0", JAVNI_PREDPOMNILNIK_MS: "0" }, stdio: ["ignore", "pipe", "pipe"] });
  srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 60; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  try {
    const T = { lastnik: zeton("lastnik@outly.si", uuid(1)), tuj: zeton("tuj@outly.si", uuid(2)), admin: zeton("admin@outly.si", uuid(3)),
      ana: zeton("ana@outly.si", uuid(4)), bor: zeton("bor@outly.si", uuid(5)), cene: zeton("cene@outly.si", uuid(6)), dana: zeton("dana@outly.si", uuid(7)),
      vratar: zeton("vratar@outly.si", uuid(8)), manager: zeton("manager@outly.si", uuid(9)), erik: zeton("erik@outly.si", uuid(10)) };
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='business' WHERE email IN ('lastnik@outly.si','tuj@outly.si')");
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("UPDATE users SET date_of_birth='1990-01-01'");
    await pool.query(`INSERT INTO clubs (owner_user_id, name, city, stripe_account_id, stripe_charges_enabled)
                      VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana', 'acct_test1', TRUE)`);
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='tuj@outly.si'), 'Tuj Club', 'Maribor')");
    await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, (SELECT id FROM users WHERE email='vratar@outly.si'), 'doorman'), (1, (SELECT id FROM users WHERE email='manager@outly.si'), 'manager')");
    await pool.query("INSERT INTO club_tables (club_id, label, x, y, w, h, seats, price_cents) VALUES (1, 'A1', 10, 10, 10, 10, 4, 20000), (1, 'A2', 30, 10, 10, 10, 4, 20000), (1, 'A3', 50, 10, 10, 10, 4, 20000)");
    const ure = (h) => new Date(Date.now() + h * 3600 * 1000).toISOString();
    const nov = async (naslov, zacetek, konec) => (await pool.query("INSERT INTO events (club_id, title, start_at, end_at, status, ticket_price_cents, capacity, min_age, vip_enabled) VALUES (1,$1,$2,$3,'published',1500,100,0,TRUE) RETURNING id", [naslov, zacetek, konec])).rows[0].id;
    const kupiV = (E, tok) => api("POST", `/events/${E}/orders`, tok, { quantity: 1 });
    const kupiG = (E, email) => api("POST", `/guest/events/${E}/orders`, null, { email, quantity: 1, accept_terms: true, terms_version: "2026-10-01" });
    const kupiM = (E, tok, miza) => api("POST", `/events/${E}/tables/${miza}/orders`, tok, {});
    const KONCAN = /already ended/i;

    console.log("\n# M1: dogodek tece (zacel pred 1 h, konec cez 5 h)");
    const E1 = await nov("Tece", ure(-1), ure(5));
    let j = (await api("GET", `/events/${E1}`)).body;
    assert(j.on_sale === true && j.availability === "available" && j.time_status === "popular", "GET /events/:id: on_sale true, time_status ostane »popular« (pomen »ze zacet«)", { on_sale: j.on_sale, ts: j.time_status });
    let r = await api("GET", "/events");
    assert(r.status === 200 && r.body.some(x => x.id === E1 && x.on_sale === true), "GET /events: on_sale true", r.body.map(x => [x.id, x.on_sale]));
    r = await api("GET", `/events/${E1}/vip`);
    assert(r.status === 200 && r.body.on_sale === true, "GET /events/:id/vip: on_sale true", r.body.on_sale);
    let k = await kupiV(E1, T.ana);
    assert(k.status === 201 && k.body.checkout_url, "vstopnice med dogodkom -> 201", k);
    k = await kupiG(E1, "gost1@example.com");
    assert(k.status === 201 && k.body.checkout_url, "gost med dogodkom -> 201", k);
    k = await kupiM(E1, T.bor, 1);
    assert(k.status === 201 && k.body.checkout_url, "VIP miza med dogodkom -> 201", k);

    console.log("\n# M2: koncan (end_at v preteklosti)");
    const E2 = await nov("Koncan", ure(-6), ure(-1));
    j = (await api("GET", `/events/${E2}`)).body;
    assert(j.on_sale === false, "on_sale false", j.on_sale);
    r = await api("GET", `/events/${E2}/vip`);
    assert(r.status === 200 && r.body.on_sale === false, "VIP on_sale false", r.body.on_sale);
    k = await kupiV(E2, T.cene);
    assert(k.status === 409 && KONCAN.test(k.body), "vstopnice po koncu -> 409 »already ended«", k);
    k = await kupiG(E2, "gost2@example.com");
    assert(k.status === 409 && KONCAN.test(k.body), "gost po koncu -> 409", k);
    k = await kupiM(E2, T.dana, 2);
    assert(k.status === 409 && KONCAN.test(k.body), "VIP miza po koncu -> 409", k);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1", [E2])).rows[0].n === 0, "zavrnjeni nakupi niso ustvarili narocil");

    console.log("\n# M3: brez end_at (konec = zacetek + 8 h)");
    const E3 = await nov("Brez konca, pred 9 h", ure(-9), null);
    k = await kupiV(E3, T.cene);
    assert(k.status === 409 && KONCAN.test(k.body), "zacetek pred 9 h -> 409 »already ended«", k);
    j = (await api("GET", `/events/${E3}`)).body;
    assert(j.on_sale === false, "on_sale false", j.on_sale);
    const E3b = await nov("Brez konca, pred 7 h", ure(-7), null);
    k = await kupiV(E3b, T.cene);
    assert(k.status === 201, "zacetek pred 7 h -> 201", k);
    j = (await api("GET", `/events/${E3b}`)).body;
    assert(j.on_sale === true, "on_sale true", j.on_sale);

    console.log("\n# M4: sales_close_at med dogodkom");
    const E4 = await nov("Zaprta med dogodkom", ure(-2), ure(4));
    await pool.query("UPDATE events SET sales_close_at = $2 WHERE id = $1", [E4, ure(-1)]);
    k = await kupiV(E4, T.cene);
    assert(k.status === 409 && /closed/i.test(k.body), "vstopnice po sales_close_at -> 409 »closed«", k);
    k = await kupiG(E4, "gost3@example.com");
    assert(k.status === 409 && /closed/i.test(k.body), "gost -> 409 »closed«", k);
    k = await kupiM(E4, T.dana, 3);
    assert(k.status === 409 && /closed/i.test(k.body), "VIP miza -> 409 »closed«", k);
    j = (await api("GET", `/events/${E4}`)).body;
    assert(j.on_sale === false, "on_sale false", j.on_sale);
    r = await api("PATCH", `/events/${E4}`, T.lastnik, { salesCloseAt: ure(1) });
    assert(r.status === 200, "lastnik sme med dogodkom nastaviti zaprtje v prihodnost", r.body);
    k = await kupiV(E4, T.cene);
    assert(k.status === 201, "po novem oknu nakup 201", k);

    console.log("\n# M6: seznam upcoming (Martin: »seznam upcoming tud popravi da ne zgine po 6h«)");
    const ids = async (q) => (await api("GET", `/events?${q}`)).body.map(x => x.id);
    let up = await ids("upcoming=true"), po = await ids("upcoming=false");
    assert(up.includes(E1) && !po.includes(E1), "tecoc dogodek (zacel pred 1 h): v upcoming=true, ni v upcoming=false", { up, po });
    assert(up.includes(E3b) && !po.includes(E3b), "brez end_at, zacel pred 7 h: se v upcoming=true", { up, po });
    assert(!up.includes(E2) && po.includes(E2), "koncan (start pred 6 h, end pred 1 h): ni v upcoming=true, je v upcoming=false", { up, po });
    assert(!up.includes(E3) && po.includes(E3), "brez end_at, zacel pred 9 h: koncan -> upcoming=false", { up, po });

    console.log("\n# M5: prihodnji dogodek (pozitivna kontrola)");
    const E5 = await nov("Prihodnji", ure(24), null);
    k = await kupiV(E5, T.erik);
    assert(k.status === 201, "prihodnji -> 201", k);
    j = (await api("GET", `/events/${E5}`)).body;
    assert(j.on_sale === true && j.time_status === "coming_soon", "on_sale true, time_status coming_soon", j.time_status);
  } catch (e) { fail++; console.log("IZJEMA", e); }
  console.log(`\n${ok} OK, ${fail} NAPAKA`);
  srv.kill(); jwksServer.close(); placilaServer.close(); await pool.end();
  if (fail) { console.log(log.slice(-2000)); process.exit(1); }
  process.exit(0);
})();
