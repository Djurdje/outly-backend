#!/usr/bin/env node
/**
 * Opozorilo o razlicici pogojev (issue #260 N2). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_pogoji_razlicica.js
 * Vzorec kot test_pogoji_racun.js (lokalni JWKS, lazni Resend, testni nacin placila).
 *
 *   1  trenutna razlicica (TRENUTNI_POGOJI = 1.1.3) -> nakup uspe, brez opozorila
 *   2  druga razlicica / brez polja -> nakup USPE (201, odgovor brez novih polj), shranjeno kar je poslal odjemalec, opozorilo [pogoji]
 *      s potjo, razlicico in referenco narocila, BREZ e-naslova
 *   3  ista (pot, razlicica) drugic v oknu -> brez novega opozorila (dnevnik se ne poplavi); druga pot ali razlicica -> svoje opozorilo
 *   4  VIP miza in gost: enako
 *   5  meja pomnilnika: poplava razlicnih razlicic ne preseze meje vrstic v dnevniku, nakupi uspejo
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3243, JWKS_PORT = 3944, RESEND_PORT = 3945;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-pogoji-razlicica";
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
  // Okno opozoril 1 h: test ni odvisen od casovanja (vse zahteve so v istem oknu).
  const srv = spawn("node", ["index.js"], { env: { ...process.env, GOST_NAKUP_TEST: "1", PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, QR_SECRET: "test", APP_URL: "https://outly.test",
    TEST_PLACILA: "", GOST_PREVZEM_MS: "0", RESEND_API_KEY: "re_test", RESEND_BASE_URL: `http://127.0.0.1:${RESEND_PORT}`, EMAIL_FROM: "Outly <test@outly.test>",
    GOST_POSTA_PONOVI_MS: "200", GOST_POSTA_TIMEOUT_MS: "2000", GOST_POSTA_REZERVA_MS: "0", GOST_POSTA_PREMOR_MS: "100", POGOJI_OPOZORILO_MS: "3600000", GOST_NAKUP_NA_URO: "100000" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 80; i++) { try { await fetch(BASE + "/"); break; } catch { await pocakaj(100); } }
  const opozorila = () => log.split("\n").filter(l => l.startsWith("[pogoji]"));
  const z = (pot, del) => opozorila().filter(l => l.startsWith(`[pogoji] ${pot}:`) && l.includes(del));

  try {
    const imena = ["lastnik", "ana", "bor", "cene", "dana", "eva", "fran"];
    const T = {};
    imena.forEach((k, i) => { T[k] = zeton(`${k}@outly.si`, uuid(i + 1)); });
    for (const k of imena) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city, address, contact_phone, contact_email) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Razlicica Club', 'Ljubljana', 'Slovenska 1', '+38640111222', 'info@razlicica-club.si')");
    const rojstvo = new Date(Date.now() - 25 * 365.25 * 24 * 3600 * 1000).toISOString().slice(0, 10);
    for (const k of imena) await api("PATCH", "/me", T[k], { dateOfBirth: rojstvo });
    const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    const r0 = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Razlicica A", startAt: cezDan, ticketPriceCents: 1500, capacity: 500, minAge: 0 });
    assert(r0.status === 201, "dogodek", r0.body);
    const ev = r0.body.id;
    const vrstica = async (id) => (await pool.query("SELECT public_ref, terms_version, terms_accepted_at, guest_terms_version FROM orders WHERE id=$1", [id])).rows[0];
    const nakup = (token, telo) => api("POST", `/events/${ev}/orders`, token, telo);
    const P = "POST /events/:id/orders";

    // ================================================================
    console.log("\n# 1. Trenutna razlicica: brez opozorila");
    let r = await nakup(T.ana, { quantity: 1, terms_version: "1.1.3" });
    assert(r.status === 201, "nakup z 1.1.3 uspe", r.body);
    let v = await vrstica(r.body.order.id);
    assert(v.terms_version === "1.1.3" && v.terms_accepted_at, "1.1.3 shranjena", v);

    // ================================================================
    console.log("\n# 2. Druga razlicica / brez polja: nakup uspe + opozorilo");
    r = await nakup(T.bor, { quantity: 1, terms_version: "1.1" });
    assert(r.status === 201 && r.body.order.status === "paid", "nakup s starejso razlicico 1.1 uspe (ni zavrnjen)", r.body);
    assert(!/terms/.test(Object.keys(r.body.order).join(",")), "odgovor brez novih polj", Object.keys(r.body.order));
    v = await vrstica(r.body.order.id);
    assert(v.terms_version === "1.1", "shranjeno, kar je poslal odjemalec (1.1)", v.terms_version);
    const ref11 = v.public_ref;
    assert(await cakaj(() => z(P, '"1.1"').length >= 1, 3000), "opozorilo za 1.1 v dnevniku", opozorila());
    let l = z(P, '"1.1"')[0] || "";
    assert(l.includes(ref11) && l.includes("1.1.3"), "opozorilo vsebuje referenco narocila in trenutno razlicico", l);

    r = await nakup(T.cene, { quantity: 1 });
    assert(r.status === 201, "nakup brez terms_version uspe (star iOS)", r.body);
    v = await vrstica(r.body.order.id);
    assert(v.terms_version === null && v.terms_accepted_at === null, "brez polja: NULL kot doslej", v);
    assert(await cakaj(() => z(P, "manjka").length >= 1, 3000), "opozorilo za manjkajoco razlicico", opozorila());
    assert(z(P, "manjka")[0].includes(v.public_ref), "opozorilo (manjka) vsebuje referenco narocila", z(P, "manjka"));

    // ================================================================
    console.log("\n# 3. Brez poplave: ista pot + razlicica samo enkrat v oknu");
    for (const k of ["dana", "eva"]) { r = await nakup(T[k], { quantity: 1, terms_version: "1.1" }); assert(r.status === 201, `ponoven nakup z 1.1 (${k}) uspe`, r.body); }
    r = await nakup(T.dana, { quantity: 1 });
    assert(r.status === 201, "ponoven nakup brez polja uspe", r.body);
    r = await nakup(T.eva, { quantity: 1, terms_version: "1.0" });
    assert(r.status === 201, "nakup z 1.0 uspe", r.body);
    assert(await cakaj(() => z(P, '"1.0"').length >= 1, 3000), "druga razlicica (1.0) ima svoje opozorilo", opozorila());
    await pocakaj(300);
    assert(z(P, '"1.1"').length === 1, "1.1: natanko eno opozorilo za tri nakupe", z(P, '"1.1"'));
    assert(z(P, "manjka").length === 1, "manjka: natanko eno opozorilo za dva nakupa", z(P, "manjka"));

    // ================================================================
    console.log("\n# 4. VIP miza in gost");
    await pool.query("TRUNCATE omejitve");
    const miza = (await pool.query("INSERT INTO club_tables (club_id, label, x, y, w, h, seats, price_cents) VALUES (1,'T1',0,0,2,2,3,30000),(1,'T2',3,0,2,2,4,40000) RETURNING id")).rows.map(x => x.id);
    await pool.query("UPDATE events SET vip_enabled = TRUE WHERE id=$1", [ev]);
    const PV = "POST /events/:id/tables/:tableId/orders";
    r = await api("POST", `/events/${ev}/tables/${miza[0]}/orders`, T.fran, { terms_version: "1.1" });
    assert(r.status === 201, "VIP z 1.1 uspe", r.body);
    v = await vrstica(r.body.order.id);
    assert(v.terms_version === "1.1", "VIP: shranjena 1.1", v.terms_version);
    assert(await cakaj(() => z(PV, '"1.1"').length === 1, 3000), "VIP: svoje opozorilo (druga pot)", opozorila());
    assert(z(PV, '"1.1"')[0].includes(v.public_ref), "VIP opozorilo vsebuje referenco", z(PV, '"1.1"'));
    r = await api("POST", `/events/${ev}/tables/${miza[1]}/orders`, T.ana, { terms_version: "1.1.3" });
    assert(r.status === 201, "VIP z 1.1.3 uspe", r.body);

    const PG = "POST /guest/events/:id/orders";
    const g = await api("POST", `/guest/events/${ev}/orders`, null, { email: "gost-razlicica@example.com", quantity: 1, accept_terms: true, terms_version: "1.1" });
    assert(g.status === 201, "gost z 1.1 uspe", g.body);
    const gv = (await pool.query("SELECT public_ref, guest_terms_version FROM orders WHERE guest_email = 'gost-razlicica@example.com'")).rows[0];
    assert(gv && gv.guest_terms_version === "1.1", "gost: shranjena 1.1", gv);
    assert(await cakaj(() => z(PG, '"1.1"').length === 1, 3000), "gost: opozorilo", opozorila());
    assert(z(PG, '"1.1"')[0].includes(gv.public_ref), "gost opozorilo vsebuje referenco", z(PG, '"1.1"'));
    const g2 = await api("POST", `/guest/events/${ev}/orders`, null, { email: "gost-razlicica2@example.com", quantity: 1, accept_terms: true, terms_version: "1.1.3" });
    assert(g2.status === 201, "gost z 1.1.3 uspe", g2.body);

    await pocakaj(300);
    assert(!opozorila().some(l => l.includes('"1.1.3"')), "za trenutno razlicico 1.1.3 ni nobenega opozorila", opozorila());
    assert(!opozorila().some(l => l.includes("@")), "opozorila brez e-naslovov", opozorila());

    // ================================================================
    console.log("\n# 5. Meja pomnilnika (poplava razlicnih razlicic)");
    const pred = opozorila().length;
    let uspeli = 0;
    for (let i = 0; i < 230; i++) {
      const x = await api("POST", `/guest/events/${ev}/orders`, null, { email: `poplava${i}@example.com`, quantity: 1, accept_terms: true, terms_version: "p" + i });
      if (x.status === 201) uspeli++;
    }
    assert(uspeli === 230, "vsi nakupi z neznanimi razlicicami uspejo", uspeli);
    await pocakaj(300);
    const novih = opozorila().length - pred;
    assert(novih > 0 && novih <= 200, "opozoril najvec toliko, kolikor je meja kljucev (200)", novih);
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
