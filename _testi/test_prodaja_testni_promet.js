#!/usr/bin/env node
/**
 * Klubska prodaja (GET /business/sales) in admin GET /admin/api/events NE stejeta testnega prometa (#236, I39).
 * Testno narocilo = SQL_TESTNO_NAROCILO (lazni nacin `test_...` ALI Stripe sandbox seja `cs_test_...`); 0 EUR brez Stripa je PRAVO.
 * Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres@localhost:5432/outly" node _testi/test_prodaja_testni_promet.js
 * Vzorec kot test_vracila.js: lokalni JWKS, backend na svojem portu.
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 4521, JWKS_PORT = 4522;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-236";
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
async function api(method, path, token, body) {
  const r = await fetch(BASE + path, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, guest_list_members, guest_lists, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, club_tables, events, clubs, creator_applications, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  try {
    for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }
    const T = { admin: zeton("admin@outly.si", uuid(1)), lastnik: zeton("lastnik@outly.si", uuid(2)), kupec: zeton("kupec@outly.si", uuid(3)) };
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    await pool.query("UPDATE users SET date_of_birth = (CURRENT_DATE - INTERVAL '25 years')::date WHERE email='kupec@outly.si'");
    const kupecId = (await pool.query("SELECT id FROM users WHERE email='kupec@outly.si'")).rows[0].id;
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana')");
    // Drug klub z lastnim testnim prometom: test_summary tega kluba ga ne sme zajeti.
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='admin@outly.si'), 'Tuji Club', 'Maribor')");

    const cezTeden = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
    const dogodek = async (naslov, cena) => { const r = await api("POST", "/events", T.lastnik, { clubId: 1, title: naslov, startAt: cezTeden, ticketPriceCents: cena, capacity: 100, minAge: 0 }); assert(r.status === 201, `dogodek ${naslov}`, r.body); return r.body.id; };
    const E1 = await dogodek("Pravi in testni", 1000), E2 = await dogodek("Samo testni", 1000), E3 = await dogodek("Brezplacen", 0);
    const tuji = (await pool.query("INSERT INTO events (club_id, title, start_at, status, capacity) VALUES (2, 'Tuji dogodek', NOW() + INTERVAL '3 days', 'published', 50) RETURNING id")).rows[0].id;

    // Narocilo neposredno v bazi. sporoci: [event, club, kolicina, cena, pi, seja, status, vrnjeno, table_id, ob_casu]
    let n = 0;
    async function narocilo({ ev, klub = 1, kol = 1, cena, pi = null, seja = null, status = "paid", vrnjeno = 0, miza = null, pred = "0 days", provizija }) {
      n++;
      const skupaj = kol * cena;
      const fee = provizija !== undefined ? provizija : Math.round(skupaj / 10);
      const r = await pool.query(
        `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, application_fee_cents, status, buyer_email, paid_at, created_at,
                             stripe_payment_intent_id, stripe_checkout_session_id, refunded_cents, table_id, table_label, table_seats)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'kupec@outly.si', NOW() - $10::interval, NOW() - $10::interval, $11, $12, $13, $14, $15, $16) RETURNING id`,
        [`OUT-T236-${n}`, kupecId, ev, klub, kol, cena, skupaj, fee, status, pred, pi, seja, vrnjeno, miza, miza ? "M" + miza : null, miza ? 4 : null]);
      return r.rows[0].id;
    }
    // Lazni nacin: ena prava pot prek API-ja (backend sam zapise test_<uuid>), da ne testiramo samo svojih vstavkov.
    let r = await api("POST", `/events/${E1}/orders`, T.kupec, { quantity: 1 });
    assert(r.status === 201 && r.body.order.total_cents === 1000, "T1: nakup prek API-ja v laznem nacinu (test_<uuid>)", r.body);
    const T1 = r.body.order.id;
    const [mizaPrava, mizaTest] = (await Promise.all([1, 2].map(i => pool.query("INSERT INTO club_tables (club_id, label, x, y, w, h, seats, price_cents) VALUES (1,$1,0,0,2,2,4,20000) RETURNING id", ["M" + i])))).map(x => x.rows[0].id);

    //   P1  pravo:      E1 3 x 10 EUR, pi_live_1 + cs_live_a, DELNO VRNJENO 500 (partially_refunded)
    //   T2  test:       E1 4 x 10 EUR, sandbox pi_3Sand + cs_test_b, delno vrnjeno 500
    //   T3  test:       E2 2 x 10 EUR, lazni nacin test_
    //   Z0  pravo:      E3 2 x 0 EUR, brez Stripa (pi NULL, seja NULL)
    //   T4  test:       E3 1 x 0 EUR, lazni nacin test_
    //   T5  test:       E1 1 x 10 EUR, lazni nacin, pred 40 dnevi (testni_summary je »od zacetka«, izven 14 dni)
    //   M1  pravo:      E1 miza 200 EUR, pi_live_2 + cs_live_c
    //   M2  test:       E1 miza 200 EUR, sandbox pi_3Sand2 + cs_test_d
    //   G   guest lista E1 (ni nikjer)
    //   X   tuji klub:  test narocilo 1 x 10 EUR (ne sme v test_summary kluba 1)
    const P1 = await narocilo({ ev: E1, kol: 3, cena: 1000, pi: "pi_live_1", seja: "cs_live_a", status: "partially_refunded", vrnjeno: 500 });
    const T2 = await narocilo({ ev: E1, kol: 4, cena: 1000, pi: "pi_3Sand", seja: "cs_test_b", status: "partially_refunded", vrnjeno: 500 });
    const T3 = await narocilo({ ev: E2, kol: 2, cena: 1000, pi: "test_t3" });
    const Z0 = await narocilo({ ev: E3, kol: 2, cena: 0 });
    const T4 = await narocilo({ ev: E3, kol: 1, cena: 0, pi: "test_t4" });
    const T5 = await narocilo({ ev: E1, kol: 1, cena: 1000, pi: "test_t5", pred: "40 days" });
    const M1 = await narocilo({ ev: E1, kol: 1, cena: 20000, pi: "pi_live_2", seja: "cs_live_c", miza: mizaPrava });
    const M2 = await narocilo({ ev: E1, kol: 1, cena: 20000, pi: "pi_3Sand2", seja: "cs_test_d", miza: mizaTest });
    await narocilo({ ev: tuji, klub: 2, kol: 1, cena: 1000, pi: "test_tuji" });
    const gl = (await pool.query("INSERT INTO guest_lists (event_id, host_user_id, spots) VALUES ($1, $2, 1) RETURNING id", [E1, kupecId])).rows[0].id;
    await pool.query(`INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, paid_at, guest_list_id)
                      VALUES ('OUT-T236-GL', $1, $2, 1, 1, 0, 0, 'paid', 'kupec@outly.si', NOW(), $3)`, [kupecId, E1, gl]);

    console.log("\n# GET /business/sales — samo pravi promet");
    r = await api("GET", "/business/sales?range=week", T.lastnik);
    assert(r.status === 200, "GET /business/sales -> 200", r.body);
    const s = r.body.summary;
    // Pravi: P1 (3000, fee 300, vrnjeno 500), Z0 (0), M1 (20000, fee 2000)
    assert(s.gross_cents === 23000, "summary.gross_cents = 23000 (P1 3000 + M1 20000; testnih 28000 ni zraven)", s);
    assert(s.fee_cents === 2300, "summary.fee_cents = 2300", s);
    assert(s.net_cents === 23000 - 2300 - 500, "summary.net_cents = 20200 (upostevano pravo vracilo, brez sandbox vracila)", s);
    assert(s.tickets_sold === 5, "summary.tickets_sold = 5 (3 + 2 brezplacni, brez miz in testnih)", s);
    assert(s.orders === 3, "summary.orders = 3 (P1, Z0, M1)", s);
    assert(s.buyers === 1, "summary.buyers = 1", s);
    assert(s.gross_7d_cents === 23000 && s.tickets_7d === 5, "summary: 7d samo pravi", s);
    assert(s.tables_sold === 1 && s.tables_gross_cents === 20000, "summary: 1 prava miza (20000); testna miza ni zraven", s);

    const ev = Object.fromEntries(r.body.events.map(e => [e.id, e]));
    assert(r.body.events.length === 3, "events[]: vsi 3 dogodki kluba (tudi E2 brez pravega prometa), tuji dogodek ne", r.body.events.map(e => e.title));
    assert(ev[E1].gross_cents === 23000 && ev[E1].tickets_sold === 3 && ev[E1].tables_sold === 1 && ev[E1].tables_gross_cents === 20000, "events[E1]: pravi promet (3000 + miza 20000, 3 vstopnice, 1 miza)", ev[E1]);
    assert(ev[E2] && ev[E2].gross_cents === 0 && ev[E2].tickets_sold === 0 && ev[E2].tables_sold === 0 && ev[E2].tables_gross_cents === 0, "events[E2]: samo testno -> dogodek ostane, z nicelami", ev[E2]);
    assert(ev[E3].gross_cents === 0 && ev[E3].tickets_sold === 2, "events[E3]: 0 EUR pravo narocilo = 2 vstopnici (testna 1 ni zraven)", ev[E3]);
    assert(ev[E1].sold_count !== undefined && ev[E1].capacity === 100 && "checked_in" in ev[E1] && "interested_count" in ev[E1], "events[]: sold_count/capacity/checked_in/interested_count ostanejo", ev[E1]);

    const danes = r.body.sales_by_day[r.body.sales_by_day.length - 1];
    assert(r.body.sales_by_day.length === 14, "sales_by_day: 14 dni", r.body.sales_by_day.length);
    assert(danes.gross_cents === 23000 && danes.tickets === 5, "sales_by_day: danes samo pravi promet", danes);
    assert(r.body.sales_by_day.reduce((a, d) => a + d.gross_cents, 0) === 23000, "sales_by_day: vsota = 23000", r.body.sales_by_day);

    for (const range of ["week", "month", "year"]) {
      const x = await api("GET", `/business/sales?range=${range}`, T.lastnik);
      const g = x.body.series.reduce((a, d) => a + d.gross_cents, 0), t = x.body.series.reduce((a, d) => a + d.tickets, 0);
      assert(x.status === 200 && g === 23000 && t === 5, `series (${range}): samo pravi promet (23000 / 5 vstopnic)`, [g, t]);
    }
    const brez = await api("GET", "/business/sales", T.lastnik);
    assert(brez.status === 200 && brez.body.series === undefined && Array.isArray(brez.body.sales_by_day), "brez ?range= ni series (kot doslej)", Object.keys(brez.body));

    console.log("\n# test_summary + recent_orders");
    assert(r.body.test_summary && r.body.test_summary.orders === 6 && r.body.test_summary.gross_cents === 1000 + 4000 + 2000 + 0 + 1000 + 20000 && r.body.test_summary.tickets_sold === 9,
      "test_summary: 6 narocil (T1,T2,T3,T4,T5,M2), bruto 28000, 9 vstopnic (brez mize); tuji klub ni zraven, T5 (40 dni) je zraven", r.body.test_summary);
    assert(Object.keys(r.body.test_summary || {}).sort().join() === "gross_cents,orders,tickets_sold", "test_summary ima natanko tri polja", r.body.test_summary);
    const znacke = Object.fromEntries(r.body.recent_orders.map(o => [o.id, o]));
    assert(r.body.recent_orders.length === 9, "recent_orders: vseh 9 narocil kluba (pravih in testnih), guest liste ni", r.body.recent_orders.length);
    const tp = id => znacke[id] ? znacke[id].test_payment : undefined;
    assert(tp(T1) === true && tp(T2) === true && tp(T3) === true && tp(T4) === true && tp(T5) === true && tp(M2) === true, "test_payment = true: lazni (test_), sandbox (cs_test_), 0 EUR lazni, testna miza", Object.values(znacke).map(o => [o.id, o.test_payment]));
    assert(tp(P1) === false && tp(Z0) === false && tp(M1) === false, "test_payment = false: pravo (cs_live_), 0 EUR brez Stripa, prava miza", [tp(P1), tp(Z0), tp(M1)]);
    assert(znacke[T1]?.is_test === true && znacke[T3]?.is_test === true && znacke[T2]?.is_test === false && znacke[M2]?.is_test === false && znacke[P1]?.is_test === false,
      "is_test ostane v starem pomenu (lazni nacin: pi test_%; sandbox is_test=false)", [T1, T2, T3, M2, P1].map(i => znacke[i]?.is_test));

    console.log("\n# Klub brez testnega prometa: test_summary z nicelami");
    const t2 = await api("GET", "/business/sales", T.admin);
    assert(t2.status === 200 && t2.body.test_summary && t2.body.test_summary.orders === 1 && t2.body.test_summary.gross_cents === 1000, "drug klub vidi samo svoj testni promet (1 narocilo, 1000)", t2.body.test_summary);
    assert(t2.body.summary.gross_cents === 0 && t2.body.summary.orders === 0, "drug klub: pravega prometa 0", t2.body.summary);
    const KLJUCI_SUMMARY = "buyers,fee_cents,gross_7d_cents,gross_cents,net_cents,orders,tables_gross_cents,tables_sold,tickets_7d,tickets_sold";   // sortirano
    const samoNicle = (x) => !!x && Object.keys(x).sort().join() === KLJUCI_SUMMARY && Object.values(x).every(v => v === 0);   // stevilo 0, ne null/niz
    assert(samoNicle(t2.body.summary), "drug klub samo s testnim prometom: vseh 10 polj summary je stevilo 0 (ne null), natanko pricakovani kljuci", t2.body.summary);
    assert(t2.body.test_summary.tickets_sold === 1, "drug klub: test_summary.tickets_sold = 1", t2.body.test_summary);
    await pool.query("DELETE FROM orders WHERE club_id = 2");
    const t3 = await api("GET", "/business/sales", T.admin);
    assert(t3.status === 200 && t3.body.test_summary && t3.body.test_summary.orders === 0 && t3.body.test_summary.gross_cents === 0 && t3.body.test_summary.tickets_sold === 0, "brez testnega prometa: test_summary prisoten z nicelami", t3.body.test_summary);
    assert(samoNicle(t3.body.summary), "prazen klub: vseh 10 polj summary je stevilo 0 (ne null), natanko pricakovani kljuci", t3.body.summary);

    console.log("\n# GET /admin/api/events — paid_* pravi, test_paid_* testni");
    r = await api("GET", "/admin/api/events", T.admin);
    assert(r.status === 200 && Array.isArray(r.body), "admin events -> 200", r.status);
    const ae = Object.fromEntries(r.body.map(e => [e.id, e]));
    // E1: pravi P1 (3000 - 500 vrnjeno = 2500) + M1 (20000); testni T1 1000, T2 (4000 - 500), T5 1000, M2 20000
    assert(ae[E1].paid_orders === 2 && ae[E1].paid_cents === 2500 + 20000, "E1: paid_orders 2, paid_cents 22500 (net vracil, brez testnih)", [ae[E1].paid_orders, ae[E1].paid_cents]);
    assert(ae[E1].test_paid_orders === 4 && ae[E1].test_paid_cents === 1000 + 3500 + 1000 + 20000, "E1: test_paid_orders 4 (T1, T2, T5, M2), test_paid_cents 25500", [ae[E1].test_paid_orders, ae[E1].test_paid_cents]);
    assert(ae[E2].paid_orders === 0 && ae[E2].paid_cents === 0 && ae[E2].test_paid_orders === 1 && ae[E2].test_paid_cents === 2000, "E2: samo testno narocilo", [ae[E2].paid_orders, ae[E2].paid_cents, ae[E2].test_paid_orders, ae[E2].test_paid_cents]);
    assert(ae[E3].paid_orders === 1 && ae[E3].paid_cents === 0 && ae[E3].test_paid_orders === 1 && ae[E3].test_paid_cents === 0, "E3: 0 EUR brez Stripa je pravo (paid_orders 1), 0 EUR lazni je testno (1)", [ae[E3].paid_orders, ae[E3].test_paid_orders]);
  } finally {
    srv.kill(); jwksServer.close();
    await pool.end().catch(() => {});
  }
  console.log(`\n${ok} OK, ${fail} NAPAK`);
  if (fail) console.log(log.split("\n").slice(-15).join("\n"));
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
