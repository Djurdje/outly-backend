#!/usr/bin/env node
/**
 * Zapis sprejetih pogojev pri nakupu Z RACUNOM (issue #215, ostanek #96; migracija 044). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_pogoji_racun.js
 * Vzorec kot test_vabila.js / test_potrdilo_kupcu.js: lokalni JWKS (ES256), lazni Resend, backend na svojem portu, testni nacin placila.
 *
 *   1  vstopnice: brez polja -> terms_* NULL (star odjemalec); z veljavnim -> shranjeno + cas; null = brez polja
 *   2  neveljavna razlicica (prazen niz, presezen, nedovoljen znak, ne-niz) -> 400 "terms_version is invalid.", naroclia ne nastane
 *   3  idempotenca: ponovitev istega kljuca z/brez polja = isti nakup (ne 409 »drugacna vsebina«), razlicica prvega nakupa ostane
 *   4  VIP miza: enako kot pri vstopnicah (brez polja, veljavno, neveljavno 400 brez naroclia, idempotenca)
 *   5  potrdilo kupcu: vrstica z razlicico, ko je na naroclilu; sicer splosna vrstica kot doslej
 *   6  baza: CHECK (oblika razlicice; cas natanko takrat, ko je razlicica); gost nespremenjen (guest_terms_*, terms_* NULL)
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3231, JWKS_PORT = 3986, RESEND_PORT = 3985;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-pogoji";
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
const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const kljuc = () => crypto.randomUUID();
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
async function api(method, path, token, body, glave = {}) {
  const r = await fetch(BASE + path, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}), ...glave },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, text: t, headers: r.headers };
}
const pocakaj = (ms) => new Promise(r => setTimeout(r, ms));
async function cakaj(pogoj, ms = 8000) { const do_ = Date.now() + ms; while (Date.now() < do_) { if (await pogoj()) return true; await pocakaj(100); } return false; }

// ---------- lazni Resend ----------
const poslano = [];
const resendServer = http.createServer((req, res) => {
  let d = ""; req.on("data", x => d += x);
  req.on("end", () => {
    if (req.method === "POST" && req.url === "/emails") {
      poslano.push(JSON.parse(d));
      res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify({ id: "mail_" + poslano.length }));
    }
    res.writeHead(404, { "content-type": "application/json" }); res.end("{}");
  });
});
const mailiNa = (email) => poslano.filter(m => m.to === email || (Array.isArray(m.to) && m.to.includes(email)));

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, stripe_events, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  await new Promise(r => resendServer.listen(RESEND_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, GOST_NAKUP_TEST: "1", PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, QR_SECRET: "test", APP_URL: "https://outly.test",
    TEST_PLACILA: "", GOST_PREVZEM_MS: "0", RESEND_API_KEY: "re_test", RESEND_BASE_URL: `http://127.0.0.1:${RESEND_PORT}`, EMAIL_FROM: "Outly <test@outly.test>",
    GOST_POSTA_PONOVI_MS: "200", GOST_POSTA_TIMEOUT_MS: "2000", GOST_POSTA_REZERVA_MS: "0", GOST_POSTA_PREMOR_MS: "100" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 80; i++) { try { await fetch(BASE + "/"); break; } catch { await pocakaj(100); } }

  try {
    const imena = ["lastnik", "ana", "bor", "cene", "dana", "eva", "fran", "gina"];
    const T = {};
    imena.forEach((k, i) => { T[k] = zeton(`${k}@outly.si`, uuid(i + 1)); });
    for (const k of imena) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city, address, contact_phone, contact_email) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pogoji Club', 'Ljubljana', 'Slovenska 1', '+38640111222', 'info@pogoji-club.si')");
    const rojstvo = new Date(Date.now() - 25 * 365.25 * 24 * 3600 * 1000).toISOString().slice(0, 10);
    for (const k of imena) await api("PATCH", "/me", T[k], { dateOfBirth: rojstvo });
    const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    const dogodek = async (title, cena) => {
      const r = await api("POST", "/events", T.lastnik, { clubId: 1, title, startAt: cezDan, ticketPriceCents: cena, capacity: 50, minAge: 0 });
      assert(r.status === 201, `dogodek ${title}`, r.body); return r.body.id;
    };
    const evA = await dogodek("Pogoji A", 1500);
    const evB = await dogodek("Pogoji B", 1500);
    const vrstica = async (id) => (await pool.query("SELECT * FROM orders WHERE id=$1", [id])).rows[0];
    const stNarocil = async (email) => (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE user_id = (SELECT id FROM users WHERE email=$1)", [email])).rows[0].n;
    const nakup = (token, ev, telo, k = null) => api("POST", `/events/${ev}/orders`, token, telo, k ? { "idempotency-key": k } : {});

    // ================================================================
    console.log("\n# 1. Vstopnice: brez polja / z veljavnim poljem");
    let r = await nakup(T.ana, evA, { quantity: 1 });
    assert(r.status === 201 && r.body.order.status === "paid", "nakup brez terms_version (star odjemalec) uspe", r.body);
    let v = await vrstica(r.body.order.id);
    assert(v.terms_version === null && v.terms_accepted_at === null, "brez polja: terms_version in terms_accepted_at NULL", [v.terms_version, v.terms_accepted_at]);
    const mimo = Object.keys(r.body.order).join(",");
    assert(!/terms/.test(mimo), "odgovor API-ja brez novih polj (obstojeci odgovor nespremenjen)", mimo);

    const pred = Date.now();
    r = await nakup(T.bor, evA, { quantity: 2, terms_version: "1.1" });
    assert(r.status === 201 && r.body.tickets.length === 2, "nakup z terms_version 1.1 uspe", r.body);
    v = await vrstica(r.body.order.id);
    assert(v.terms_version === "1.1", "terms_version shranjen", v.terms_version);
    assert(v.terms_accepted_at && Math.abs(new Date(v.terms_accepted_at).getTime() - pred) < 15000, "terms_accepted_at = cas nakupa", v.terms_accepted_at);
    assert(v.guest_terms_version === null && v.guest_terms_accepted_at === null, "guest_terms_* ostaneta NULL pri nakupu z racunom");

    r = await nakup(T.cene, evA, { quantity: 1, terms_version: null });
    v = r.status === 201 ? await vrstica(r.body.order.id) : null;
    assert(r.status === 201 && v.terms_version === null && v.terms_accepted_at === null, "terms_version: null = polje ni podano", r.body);

    r = await nakup(T.dana, evA, { terms_version: "2026-10:a_b.c" });   // quantity privzeto 1; dovoljeni znaki . _ : -
    v = r.status === 201 ? await vrstica(r.body.order.id) : null;
    assert(r.status === 201 && v.terms_version === "2026-10:a_b.c" && v.quantity === 1, "razlicica z dovoljenimi znaki (. _ : -) in privzeta kolicina", r.body);
    r = await nakup(T.dana, evB, { quantity: 1, terms_version: "A".repeat(40) });
    assert(r.status === 201, "razlicica dolga natanko 40 znakov je veljavna", r.body);

    // ================================================================
    console.log("\n# 2. Neveljavna razlicica -> 400, brez narocila");
    await pool.query("TRUNCATE omejitve");   // omejevalnik nakupov (20/h) steje tudi zavrnjene zahtevke
    const slabe = [["prazen niz", ""], ["41 znakov", "A".repeat(41)], ["presledek", "1 1"], ["poševnica", "1/1"], ["unicode", "1.1š"], ["stevilo", 1.1], ["objekt", { v: "1.1" }], ["seznam", ["1.1"]], ["true", true]];
    const prej = await stNarocil("eva@outly.si");
    for (const [ime, vrednost] of slabe) {
      r = await nakup(T.eva, evA, { quantity: 1, terms_version: vrednost });
      assert(r.status === 400 && /terms_version is invalid/.test(String(r.text)), `neveljavno (${ime}) -> 400 "terms_version is invalid."`, [r.status, r.text]);
    }
    assert((await stNarocil("eva@outly.si")) === prej, "po zavrnjenih zahtevkih ni nobenega narocila");
    const sold = (await pool.query("SELECT sold_count FROM events WHERE id=$1", [evA])).rows[0].sold_count;
    assert(sold === 5, "zaloga ni porabljena zaradi zavrnjenih zahtevkov (1+2+1+1)", sold);

    // ================================================================
    console.log("\n# 3. Idempotenca: odtis vsebine nakupa se zaradi polja ne spremeni");
    const K1 = kljuc();
    r = await nakup(T.ana, evB, { quantity: 1 }, K1);
    assert(r.status === 201, "prvi nakup z kljucem (brez polja)", r.body);
    const o1 = r.body.order.id;
    r = await nakup(T.ana, evB, { quantity: 1, terms_version: "1.1" }, K1);
    assert(r.status === 201 && r.headers.get("idempotent-replayed") === "true" && r.body.order.id === o1, "ponovitev istega kljuca Z poljem = isto narocilo", [r.status, r.text.slice(0, 200)]);
    v = await vrstica(o1);
    assert(v.terms_version === null && v.terms_accepted_at === null, "ponovitev ne spremeni obstojecega narocila (razlicica ostane NULL)", v.terms_version);
    const K2 = kljuc();
    r = await nakup(T.ana, evB, { quantity: 1, terms_version: "1.1" }, K2);
    assert(r.status === 201 && !r.headers.get("idempotent-replayed"), "drugi kljuc: nov nakup z poljem", r.body);
    const o2 = r.body.order.id;
    r = await nakup(T.ana, evB, { quantity: 1 }, K2);
    assert(r.status === 201 && r.headers.get("idempotent-replayed") === "true" && r.body.order.id === o2, "ponovitev istega kljuca BREZ polja = isto narocilo", [r.status, r.text.slice(0, 200)]);
    r = await nakup(T.ana, evB, { quantity: 1, terms_version: "1.0" }, K2);
    assert(r.status === 201 && r.body.order.id === o2, "ponovitev z drugo razlicico = isto narocilo (razlicica ni del vsebine)", [r.status, r.text.slice(0, 200)]);
    v = await vrstica(o2);
    assert(v.terms_version === "1.1", "razlicica prvega nakupa ostane 1.1", v.terms_version);
    r = await nakup(T.ana, evB, { quantity: 2, terms_version: "1.1" }, K2);
    assert(r.status === 422 && r.body.error === "idempotency_key_reused", "druga KOLICINA z istim kljucem je se vedno zavrnjena (idempotency_key_reused; varovalo nespremenjeno)", [r.status, r.text.slice(0, 200)]);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE idempotency_key = ANY($1)", [[K1, K2]])).rows[0].n === 2, "dve narocili za dva kljuca");

    // ================================================================
    console.log("\n# 4. VIP miza");
    await pool.query("TRUNCATE omejitve");
    const miza = (await pool.query("INSERT INTO club_tables (club_id, label, x, y, w, h, seats, price_cents) VALUES (1,'T1',0,0,2,2,3,30000),(1,'T2',3,0,2,2,4,40000),(1,'T3',6,0,2,2,2,20000) RETURNING id")).rows.map(x => x.id);
    await pool.query("UPDATE events SET vip_enabled = TRUE WHERE id=$1", [evA]);
    const vip = (token, m, telo, k = null) => api("POST", `/events/${evA}/tables/${m}/orders`, token, telo, k ? { "idempotency-key": k } : {});
    r = await vip(T.fran, miza[0], {});
    assert(r.status === 201 && r.body.tickets.length === 3, "VIP brez polja uspe", r.body);
    v = await vrstica(r.body.order.id);
    assert(v.terms_version === null && v.terms_accepted_at === null, "VIP brez polja: NULL", [v.terms_version, v.terms_accepted_at]);
    r = await vip(T.gina, miza[1], { terms_version: "1.1" });
    assert(r.status === 201 && r.body.tickets.length === 4, "VIP z veljavnim poljem uspe", r.body);
    const ovip = r.body.order.id;
    v = await vrstica(ovip);
    assert(v.terms_version === "1.1" && v.terms_accepted_at && v.table_label === "T2", "VIP: razlicica + cas shranjena", [v.terms_version, v.terms_accepted_at]);
    r = await vip(T.gina, miza[2], { terms_version: "1 1" });
    assert(r.status === 400 && /terms_version is invalid/.test(String(r.text)), "VIP neveljavno -> 400 \"terms_version is invalid.\"", [r.status, r.text]);
    r = await vip(T.gina, miza[2], { terms_version: 7 });
    assert(r.status === 400, "VIP ne-niz -> 400", r.status);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE table_id = $1", [miza[2]])).rows[0].n === 0, "miza po zavrnjenih zahtevkih ni zasedena");
    const KV = kljuc();
    r = await vip(T.eva, miza[2], { terms_version: "1.1" }, KV);
    assert(r.status === 201, "VIP z kljucem in poljem", r.body);
    const ovip2 = r.body.order.id;
    r = await vip(T.eva, miza[2], {}, KV);
    assert(r.status === 201 && r.headers.get("idempotent-replayed") === "true" && r.body.order.id === ovip2, "VIP: ponovitev kljuca BREZ polja = isto narocilo (ne »miza ze zasedena«)", [r.status, r.text.slice(0, 200)]);
    r = await vip(T.eva, miza[2], { terms_version: "1.1" }, KV);
    assert(r.status === 201 && r.headers.get("idempotent-replayed") === "true" && r.body.order.id === ovip2, "VIP: ponovitev kljuca Z poljem = isto narocilo", [r.status, r.text.slice(0, 200)]);

    // ================================================================
    console.log("\n# 5. Potrdilo kupcu (#95)");
    assert(await cakaj(() => mailiNa("bor@outly.si").length >= 1 && mailiNa("gina@outly.si").length >= 1 && mailiNa("ana@outly.si").length >= 2), "potrdila prispejo");
    await pocakaj(600);
    let m = mailiNa("bor@outly.si");
    assert(m.length === 1, "bor: en mail", m.length);
    const t = m[0] ? m[0].text : "", h = m[0] ? m[0].html : "";
    // kratko potrdilo (20. 10. 2026, pravnik 6B): pogoji z razlicico so zadnji stavek drobnega tiska
    assert(t.includes("Outly terms of use, version 1.1: https://outly.si/terms"), "besedilo (en): vrstica z razlicico", t);
    assert(t.includes("Pogoji uporabe Outly, različica 1.1: https://outly.si/terms"), "besedilo (sl): vrstica z razlicico");
    assert(!t.includes("Outly terms of use: https://outly.si/terms") && !t.includes("Pogoji uporabe Outly: https://outly.si/terms"), "splosna vrstica je zamenjana, ne podvojena");
    assert(h.includes("version 1.1") && h.includes("različica 1.1") && h.includes("https://outly.si/terms"), "HTML: razlicica v obeh blokih (sl, en)");
    m = mailiNa("gina@outly.si");
    assert(m.length >= 1 && m.some(x => x.text.includes("version 1.1") && x.text.includes("VIP table T2")), "VIP potrdilo vsebuje razlicico", m.map(x => x.subject));
    m = mailiNa("cene@outly.si");
    assert(m.length === 1 && m[0].text.includes("Outly terms of use: https://outly.si/terms") && m[0].text.includes("Pogoji uporabe Outly: https://outly.si/terms") && !/terms of use, version|različica/.test(m[0].text), "narocilo brez razlicice: splosna vrstica kot doslej", m[0] && m[0].text.slice(0, 120));
    m = mailiNa("ana@outly.si").map(x => x.text);
    assert(m.some(x => x.includes("version 1.1")) && m.some(x => x.includes("Outly terms of use")), "ana: nakup brez polja ima splosno vrstico, nakup z poljem razlicico");
    assert(!/Resend napaka|\[potrdilo\] POZOR/.test(log), "brez napak v dnevniku", log.slice(-300));

    // ================================================================
    console.log("\n# 6. Baza: CHECK in gost nespremenjen");
    const poskus = async (tv, ta) => {
      try { await pool.query("UPDATE orders SET terms_version = $1, terms_accepted_at = $2 WHERE id = $3", [tv, ta, ovip]); return "ok"; }
      catch (e) { return e.constraint || e.code; }
    };
    assert(/orders_terms/.test(await poskus("1 1", new Date())), "CHECK: nedovoljena oblika razlicice");
    assert(/orders_terms/.test(await poskus("", new Date())), "CHECK: prazna razlicica");
    assert(/orders_terms/.test(await poskus("1.1", null)), "CHECK: razlicica brez casa");
    assert(/orders_terms/.test(await poskus(null, new Date())), "CHECK: cas brez razlicice");
    assert((await poskus(null, null)) === "ok", "NULL + NULL je dovoljeno");
    assert((await poskus("1.1", new Date())) === "ok", "razlicica + cas je dovoljeno");
    const g = await api("POST", `/guest/events/${evB}/orders`, null, { email: "gost-pogoji@example.com", quantity: 1, accept_terms: true, terms_version: "1.1" });
    assert(g.status === 201, "gostujoci nakup deluje kot doslej", g.body);
    const gv = (await pool.query("SELECT guest_terms_version, guest_terms_accepted_at, terms_version, terms_accepted_at FROM orders WHERE guest_email = 'gost-pogoji@example.com'")).rows[0];
    assert(gv.guest_terms_version === "1.1" && gv.guest_terms_accepted_at && gv.terms_version === null && gv.terms_accepted_at === null, "gost: guest_terms_* kot doslej, terms_* NULL", gv);
    const g2 = await api("POST", `/guest/events/${evB}/orders`, null, { email: "gost-pogoji@example.com", quantity: 1, accept_terms: true });
    assert(g2.status === 400, "gost brez terms_version je se vedno 400", [g2.status, g2.text]);
  } catch (e) {
    fail++; console.log("  ✗ IZJEMA v testu:", e && e.stack || e);
  } finally {
    srv.kill();
    jwksServer.close(); resendServer.close();
    await pool.end();
    console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
    process.exit(fail ? 1 : 0);
  }
})().catch((e) => { console.error(e); process.exit(1); });
