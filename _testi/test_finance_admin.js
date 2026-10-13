#!/usr/bin/env node
/**
 * Test admin financ in izvoza (/admin/api/finance, /admin/api/summary,
 * PATCH /admin/api/users/:id, GET /admin/api/export). Zagon (lokalno, PG16,
 * prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres@localhost:5432/outly" node _testi/test_finance_admin.js
 * Vzorec kot test_vabila.js: lokalni JWKS (3999), backend na svojem portu (3116).
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3116, JWKS_PORT = 3999;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-1";
const jwksServer = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url.startsWith("/auth/v1/user")) { try { const t = JSON.parse(Buffer.from(String(req.headers.authorization).split(".")[1], "base64url")); return res.end(JSON.stringify({ id: t.sub, email: t.email, email_confirmed_at: "2026-01-01T00:00:00Z" })); } catch (_) { res.statusCode = 401; return res.end("{}"); } }   // potrditev e-naslova pri viru (#222): stub potrdi vsak naslov iz zetona
  if (req.url.startsWith("/auth/v1/settings")) return res.end(JSON.stringify({ mailer_autoconfirm: false, external: { anonymous_users: false } }));   // nastavitve Supabase (#222): »Confirm email« vklopljen, brez anonimnih
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
async function api(method, path, token, body) {
  const r = await fetch(BASE + path, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, creator_applications, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  const T = {
    admin: zeton("admin@outly.si", uuid(1)),
    lastnik: zeton("lastnik@outly.si", uuid(2)),
    kupec: zeton("kupec@outly.si", uuid(3)),
    navaden: zeton("navaden@outly.si", uuid(4)),
  };
  for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }

  await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
  await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana')");
  await pool.query("UPDATE users SET date_of_birth = (CURRENT_DATE - INTERVAL '25 years')::date, genres='{house}' WHERE email='kupec@outly.si'");

  const cezTeden = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
  let r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Placan dogodek", startAt: cezTeden, ticketPriceCents: 1000, capacity: 50, minAge: 0 });
  assert(r.status === 201, "dogodek za promet ustvarjen", r.body);
  const dogodekId = r.body.id;

  r = await api("POST", `/events/${dogodekId}/orders`, T.kupec, { quantity: 3 });
  assert(r.status === 201, "kupec kupi 3 vstopnice (3000 centov)", r.body);
  const narocilo = r.body.order;
  assert(narocilo.total_cents === 3000, "total_cents = 3000", narocilo);
  assert(narocilo.application_fee_cents === 300, "provizija 10% = 300 centov", narocilo);

  // Promet treh vrst (#230). Backend v tem testu tece v lazni nacin (brez Stripa), zato vsako narocilo dobi `test_<uuid>`;
  // oznake, ki jih ob pravem Stripu zapise webhook (pi_... + seja cs_live_/cs_test_), nastavimo neposredno v bazi.
  //   O1 (3 x 10 EUR)  pravo:    pi_live + cs_live_
  //   O2 (1 x 10 EUR)  test:     lazni nacin, test_<uuid> (ostane, kot ga je zapisal backend)
  //   O3 (4 x 10 EUR)  test:     sandbox Stripe, pi_... + cs_test_ (BREZ test_ predpone: to je primer iz #230)
  //   O4 (2 x 0 EUR)   pravo:    brezplacno narocilo brez Stripa (pi NULL, seja NULL), 0 EUR
  //   O5 (1 x 0 EUR)   test:     brezplacno narocilo v laznem nacinu (test_<uuid>)
  await pool.query("UPDATE orders SET stripe_payment_intent_id='pi_live_1', stripe_checkout_session_id='cs_live_aaa' WHERE id=$1", [narocilo.id]);
  r = await api("POST", `/events/${dogodekId}/orders`, T.kupec, { quantity: 1 });
  assert(r.status === 201 && r.body.order.total_cents === 1000, "O2: testno (lazni nacin) narocilo 1000 centov", r.body);
  const o2 = r.body.order;
  r = await api("POST", `/events/${dogodekId}/orders`, T.kupec, { quantity: 4 });
  assert(r.status === 201 && r.body.order.total_cents === 4000, "O3: sandbox narocilo 4000 centov", r.body);
  const o3 = r.body.order;
  await pool.query("UPDATE orders SET stripe_payment_intent_id='pi_3SandboxAbc', stripe_checkout_session_id='cs_test_bbb' WHERE id=$1", [o3.id]);
  r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Brezplacen dogodek", startAt: cezTeden, ticketPriceCents: 0, capacity: 50, minAge: 0 });
  assert(r.status === 201, "brezplacen dogodek ustvarjen", r.body);
  const brezplacenId = r.body.id;
  r = await api("POST", `/events/${brezplacenId}/orders`, T.kupec, { quantity: 2 });
  assert(r.status === 201 && r.body.order.total_cents === 0, "O4: brezplacno narocilo 0 centov", r.body);
  const o4 = r.body.order;
  await pool.query("UPDATE orders SET stripe_payment_intent_id=NULL, stripe_checkout_session_id=NULL WHERE id=$1", [o4.id]);
  r = await api("POST", `/events/${brezplacenId}/orders`, T.kupec, { quantity: 1 });
  assert(r.status === 201 && r.body.order.total_cents === 0, "O5: brezplacno narocilo v laznem nacinu", r.body);
  const o5 = r.body.order;
  await pool.query("UPDATE orders SET refunded_cents = 500, status = 'partially_refunded' WHERE id = $1", [o3.id]);   // vracilo na SANDBOX narocilu

  console.log("\n# Vloge in dostop");
  r = await api("GET", "/admin/api/finance", null);
  assert(r.status === 401, "GET /admin/api/finance brez zetona -> 401", r.status);
  r = await api("GET", "/admin/api/finance", T.navaden);
  assert(r.status === 403, "GET /admin/api/finance navaden uporabnik -> 403", r.status);
  r = await api("GET", "/admin/api/finance", T.lastnik);
  assert(r.status === 403, "GET /admin/api/finance business vloga -> 403", r.status);
  r = await api("GET", "/admin/api/summary", null);
  assert(r.status === 401, "GET /admin/api/summary brez zetona -> 401", r.status);
  r = await api("GET", "/admin/api/summary", T.lastnik);
  assert(r.status === 403, "GET /admin/api/summary business vloga -> 403", r.status);
  r = await api("GET", "/admin/api/export", T.lastnik);
  assert(r.status === 403, "GET /admin/api/export business vloga -> 403", r.status);
  r = await api("GET", "/admin/api/export", null);
  assert(r.status === 401, "GET /admin/api/export brez zetona -> 401", r.status);

  console.log("\n# GET /admin/api/summary (admin)");
  r = await api("GET", "/admin/api/summary", T.admin);
  assert(r.status === 200, "admin -> 200", r.body);
  assert(typeof r.body.clubs === "number" && r.body.clubs >= 1, "summary vsebuje stevilo klubov", r.body);
  assert(typeof r.body.users === "number" && r.body.users >= 4, "summary vsebuje stevilo uporabnikov", r.body);
  assert(typeof r.body.events === "number" && r.body.events >= 1, "summary vsebuje stevilo dogodkov", r.body);

  console.log("\n# GET /admin/api/finance (admin) — bruto/provizija/neto");
  r = await api("GET", "/admin/api/finance", T.admin);
  assert(r.status === 200, "admin -> 200", r.body);
  assert(r.body.fee_percent === 10, "fee_percent = 10", r.body.fee_percent);
  assert(r.body.mode === "test", "mode = test (Stripe ni nastavljen)", r.body.mode);
  assert(r.body.summary.gross_cents === 3000, "bruto promet (privzeto obdobje) = 3000 (samo pravi promet; test 5000 ni zraven)", r.body.summary);
  assert(r.body.summary.fee_cents === 300, "provizija (10%) = 300", r.body.summary);
  assert(r.body.summary.clubs_net_cents === 3000 - 300 - 0, "neto klubom = bruto - provizija - vracila = 2700 (sandbox vracilo 500 ni zraven)", r.body.summary);
  assert(r.body.summary.tickets_sold === 5, "tickets_sold = 5 (3 placane + 2 brezplacni; testnih 6 ni zraven)", r.body.summary);
  assert(r.body.summary.orders === 2 && r.body.summary.buyers === 1 && r.body.summary.clubs_with_sales === 1, "summary: 2 pravi narocili (placano + 0 EUR), 1 kupec, 1 klub", r.body.summary);
  assert(r.body.summary.refunded_cents === 0, "pravi promet: vracil 0 (500 je na sandbox narocilu)", r.body.summary);
  assert(r.body.summary.test_orders === 3, "summary.test_orders (staro polje) = 3 testna narocila v obdobju (lazni + sandbox + 0 EUR lazni)", r.body.summary);
  assert(r.body.test_summary && r.body.test_summary.orders === 3 && r.body.test_summary.gross_cents === 5000 && r.body.test_summary.fee_cents === 500
    && r.body.test_summary.refunded_cents === 500 && r.body.test_summary.tickets_sold === 6, "test_summary: 3 narocila, bruto 5000, provizija 500, vracila 500, 6 vstopnic", r.body.test_summary);
  assert(r.body.all_time.gross_cents === 3000 && r.body.all_time.fee_cents === 300 && r.body.all_time.orders === 2 && r.body.all_time.tickets_sold === 5, "all_time = samo pravi promet", r.body.all_time);
  assert(r.body.all_time_test && r.body.all_time_test.orders === 3 && r.body.all_time_test.gross_cents === 5000 && r.body.all_time_test.fee_cents === 500
    && r.body.all_time_test.refunded_cents === 500, "all_time_test: 3 narocila, bruto 5000, provizija 500, vracila 500", r.body.all_time_test);
  const klub = r.body.by_club.find(c => c.name === "Pure Club");
  assert(klub && klub.gross_cents === 3000 && klub.net_cents === 2700 && klub.orders === 2 && klub.tickets_sold === 5 && klub.refunded_cents === 0, "by_club: Pure Club bruto 3000, neto 2700, 2 narocili, brez testnih", klub);
  assert(r.body.by_event.length === 2, "by_event: samo dogodka s pravim prometom", r.body.by_event.map(e => e.title));
  const dog1 = r.body.by_event.find(e => e.id === dogodekId), dog2 = r.body.by_event.find(e => e.id === brezplacenId);
  assert(dog1 && dog1.gross_cents === 3000 && dog1.fee_cents === 300 && dog1.tickets_sold === 3, "by_event: placan dogodek bruto 3000, 3 vstopnice (brez testnih)", dog1);
  assert(dog2 && dog2.gross_cents === 0 && dog2.tickets_sold === 2, "by_event: brezplacen dogodek 0 EUR, 2 vstopnici (pravo narocilo brez Stripa je pravi promet)", dog2);
  const danes = r.body.by_day.find(d => d.day === new Date().toISOString().slice(0, 10)) || r.body.by_day[r.body.by_day.length - 1];
  assert(danes && danes.gross_cents === 3000 && danes.fee_cents === 300 && danes.orders === 2 && danes.tickets === 5, "by_day: danes samo pravi promet", danes);
  assert(r.body.by_day.reduce((a, d) => a + d.gross_cents, 0) === 3000, "by_day: vsota bruto = 3000 (testnih ni)", r.body.by_day);
  assert(r.body.recent_orders.length === 5, "recent_orders vsebuje vseh 5 narocil (pravi in testni)", r.body.recent_orders.length);
  const znacke = Object.fromEntries(r.body.recent_orders.map(o => [o.id, o.is_test]));
  assert(znacke[narocilo.id] === false && znacke[o4.id] === false, "recent_orders: pravi (cs_live_) in 0 EUR brez Stripa NISTA test", znacke);
  assert(znacke[o2.id] === true && znacke[o3.id] === true && znacke[o5.id] === true, "recent_orders: test_ , cs_test_ + pi_ in 0 EUR lazni so test", znacke);

  console.log("\n# payments_mode (panel: lazni nacin / Stripe SANDBOX / v zivo)");
  assert(r.body.payments_mode === "fake" && r.body.mode === "test", "brez Stripa: payments_mode fake (mode test)", [r.body.payments_mode, r.body.mode]);
  // Dodatni backendi na isti bazi z drugim nacinom placil; samo GET /admin/api/finance (ob zagonu ne kličejo Stripa).
  const nacini = [[3231, { STRIPE_SECRET_KEY: "sk_test_lokalno" }, "sandbox", "live", "Stripe sandbox (sk_test_; mode je tu zgodovinsko live)"],
    [3232, { STRIPE_SECRET_KEY: "sk_live_lokalno" }, "live", "live", "Stripe v zivo (sk_live_)"],
    [3233, { STRIPE_SECRET_KEY: "sk_test_lokalno", TEST_PLACILA: "true" }, "fake", "test", "sandbox kljuc + TEST_PLACILA=true (vstopnice brez placila)"],
    [3234, { STRIPE_SECRET_KEY: "sk_live_lokalno", TEST_PLACILA: "true" }, "live", "live", "zivi kljuc + TEST_PLACILA=true: TEST_PLACILA se ignorira (I31)"]];
  for (const [port, okolje, pricakovan, mode, ime] of nacini) {
    const s2 = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test", STRIPE_POSPRAVI_MS: "3600000", ...okolje }, stdio: ["ignore", "pipe", "pipe"] });
    try {
      for (let i = 0; i < 50; i++) { try { await fetch(`http://127.0.0.1:${port}/`); break; } catch { await new Promise(r => setTimeout(r, 100)); } }
      const x = await fetch(`http://127.0.0.1:${port}/admin/api/finance`, { headers: { authorization: "Bearer " + T.admin } });
      const j = await x.json();
      assert(x.status === 200 && j.payments_mode === pricakovan && j.mode === mode, `${ime}: payments_mode ${pricakovan} (mode ${mode} ostane)`, [x.status, j.payments_mode, j.mode]);
    } finally { s2.kill(); }
  }

  console.log("\n# GET /admin/api/finance z vracilom");
  await pool.query("UPDATE orders SET refunded_cents = 500, status = 'partially_refunded' WHERE id = $1", [narocilo.id]);
  r = await api("GET", "/admin/api/finance", T.admin);
  assert(r.status === 200 && r.body.summary.refunded_cents === 500, "vracilo 500 centov je upostevano", r.body.summary);
  assert(r.body.summary.clubs_net_cents === 3000 - 300 - 500, "neto klubom upostevana vracila = 2200", r.body.summary);

  console.log("\n# GET /admin/api/finance filtri from/to");
  const jutri = new Date(Date.now() + 24 * 3600 * 1000).toISOString().slice(0, 10);
  const pojutrisnjem = new Date(Date.now() + 2 * 24 * 3600 * 1000).toISOString().slice(0, 10);
  r = await api("GET", `/admin/api/finance?from=${jutri}&to=${pojutrisnjem}`, T.admin);
  assert(r.status === 200 && r.body.summary.gross_cents === 0, "obdobje brez narocil (jutri-pojutrisnjem) -> gross 0", r.body.summary);
  assert(r.body.test_summary.gross_cents === 0 && r.body.test_summary.orders === 0 && r.body.summary.test_orders === 0, "obdobje brez narocil: tudi test blok 0", r.body.test_summary);
  assert(r.body.all_time_test.orders === 3, "all_time_test ne glede na obdobje", r.body.all_time_test);
  r = await api("GET", `/admin/api/finance?from=${pojutrisnjem}&to=${jutri}`, T.admin);
  assert(r.status === 400, "from > to -> 400", r.status);
  const privzetiOd = new Date(Date.now() - 29 * 24 * 3600 * 1000).toISOString().slice(0, 10);
  r = await api("GET", "/admin/api/finance?from=nekaj-narobe", T.admin);
  assert(r.status === 200 && r.body.from === privzetiOd, "neveljaven from se ignorira -> privzeto zadnjih 29 dni", r.body.from);

  console.log("\n# PATCH /admin/api/users/:id — vloga in odklep");
  const navadenId = (await pool.query("SELECT id FROM users WHERE email='navaden@outly.si'")).rows[0].id;
  r = await api("PATCH", `/admin/api/users/${navadenId}`, null, { role: "business" });
  assert(r.status === 401, "PATCH uporabnika brez zetona -> 401", r.status);
  r = await api("PATCH", `/admin/api/users/${navadenId}`, T.lastnik, { role: "business" });
  assert(r.status === 403, "PATCH uporabnika business vloga -> 403", r.status);
  r = await api("PATCH", `/admin/api/users/${navadenId}`, T.admin, { role: "business" });
  assert(r.status === 200 && r.body.role === "business", "admin spremeni vlogo navaden -> business", r.body);
  r = await api("PATCH", `/admin/api/users/${navadenId}`, T.admin, { role: "user" });
  assert(r.status === 200 && r.body.role === "user", "admin vrne vlogo nazaj na user", r.body);
  r = await api("PATCH", `/admin/api/users/${navadenId}`, T.admin, { role: "napacna" });
  assert(r.status === 400, "neveljavna vloga -> 400", r.status);

  await pool.query("UPDATE users SET failed_login_count=3, locked_until=NOW() + INTERVAL '1 hour' WHERE id=$1", [navadenId]);
  r = await api("PATCH", `/admin/api/users/${navadenId}`, T.admin, { unlock: true });
  assert(r.status === 200 && r.body.failed_login_count === 0 && r.body.locked_until === null, "unlock: true ponastavi zaklep", r.body);

  const adminId = (await pool.query("SELECT id FROM users WHERE email='admin@outly.si'")).rows[0].id;
  r = await api("PATCH", `/admin/api/users/${adminId}`, T.admin, { role: "user" });
  assert(r.status === 400, "admin si sam ne more odvzeti admin vloge -> 400", r.status);

  console.log("\n# GET /admin/api/export");
  r = await api("GET", "/admin/api/export", T.admin);
  assert(r.status === 200, "admin izvoz -> 200", r.status);
  assert(r.body.tables && typeof r.body.tables === "object", "izvoz vsebuje tables", Object.keys(r.body.tables || {}));
  for (const tab of ["users", "clubs", "events", "orders", "tickets"]) {
    assert(Array.isArray(r.body.tables[tab] && r.body.tables[tab].rows), `izvoz vsebuje tabelo ${tab}`, r.body.tables[tab]);
  }
  assert(r.body.tables.orders.count >= 1, "izvoz orders ima vsaj 1 vrstico", r.body.tables.orders.count);
  assert(Array.isArray(r.body.sequences), "izvoz vsebuje sequences", r.body.sequences);

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  const napake = log.split("\n").filter(l => /error|TypeError|Unhandled/i.test(l) && !/Server error\./.test(l) && !/Resend/i.test(l));
  if (napake.length) console.log("\nLog backenda (sumljivo):\n" + napake.join("\n"));
  srv.kill(); jwksServer.close(); await pool.end();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
