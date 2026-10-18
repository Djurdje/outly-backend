#!/usr/bin/env node
/**
 * Test: POTRDITEV CENE PRI NAKUPU VSTOPNIC (`expected_price_cents`, #277 N2, I46). Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_nakup_cena.js
 * Vzorec kot test_vratar_sken_email.js: lokalni JWKS (5784), backend na svojem portu (5783), TRUNCATE na zacetku.
 *
 * Pred popravkom je nakup vstopnic polje ignoriral (VIP miza ga je imela): kupec, ki je videl staro ceno, je kupil po novi.
 *  1  POST /events/:id/orders: ujemanje -> 201; neujemanje (vec, manj) -> 409 »The ticket price has changed.«, nic ni ustvarjeno (naročilo, vstopnica, sold_count)
 *  2  brez polja ali null: kot doslej (201); neveljavne vrednosti (negativno, necelo, niz, bool, polje, objekt) -> 400
 *  3  cena je cena ENE vstopnice (quantity 3: 1000 -> 201, 3000 -> 409)
 *  4  sprememba cene med ogledom in nakupom (PATCH /events/:id): stara cena 409, nova 201; brezplacen dogodek (0): 0 -> 201, 1000 -> 409
 *  5  vrstni red preverb: »Event is not on sale« / »no tickets on Outly« imata prednost pred neujemanjem cene; idempotenca: ponovitev s KLJUCEM vrne prvo narocilo (cena ni del identitete)
 *  6  POST /guest/events/:id/orders: isto (201 / 409 / 400), nic ustvarjeno ob 409
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 5783, JWKS_PORT = 5784;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-nakup-cena";
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
async function api(method, p, token, body, glave = {}) {
  const r = await fetch(BASE + p, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}), ...glave }, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, text: t, headers: r.headers };
}

let srv = null;
(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, guest_list_members, guest_lists, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test", GOST_NAKUP_TEST: "1", GOST_NAKUP_NA_URO: "1000", TEST_PLACILA: "", GOST_PREVZEM_MS: "0" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  try {
    const T = { lastnik: zeton("lastnik@outly.si", uuid(1)), ana: zeton("ana@outly.si", uuid(2)) };
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana')");

    const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    const dogodek = async (title, cena = 1000, dodatno = {}) => {
      const x = await api("POST", "/events", T.lastnik, { clubId: 1, title, startAt: cezDan, ticketPriceCents: cena, capacity: 500, minAge: 0, ...dodatno });
      assert(x.status === 201, `dogodek ${title} (${cena} c)`, x.body); return x.body.id;
    };
    const stanje = async (ev) => {
      const o = (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1", [ev])).rows[0].n;
      const t = (await pool.query("SELECT COUNT(*)::int AS n FROM tickets WHERE event_id=$1", [ev])).rows[0].n;
      const s = (await pool.query("SELECT sold_count FROM events WHERE id=$1", [ev])).rows[0].sold_count;
      return `${o}/${t}/${s}`;
    };
    const kupi = (ev, telo, glave) => api("POST", `/events/${ev}/orders`, T.ana, telo, glave);
    const SPREMENJENA = "The ticket price has changed.";
    const svez = () => pool.query("TRUNCATE omejitve");   // omejevalnik »nakup« je 20/h na IP in steje tudi zavrnjene poskuse

    const ev = await dogodek("Cena A", 1000);
    console.log("\n# 1. Ujemanje in neujemanje");
    let r = await kupi(ev, { quantity: 1, expected_price_cents: 1000 });
    assert(r.status === 201 && r.body.order.total_cents === 1000, "enaka cena -> 201", r.body);
    let pred = await stanje(ev);
    r = await kupi(ev, { quantity: 1, expected_price_cents: 900 });
    assert(r.status === 409 && r.body === SPREMENJENA, "cena nizja od dejanske -> 409 »The ticket price has changed.«", { status: r.status, body: r.body });
    r = await kupi(ev, { quantity: 1, expected_price_cents: 1100 });
    assert(r.status === 409 && r.body === SPREMENJENA, "cena visja od dejanske -> 409", { status: r.status, body: r.body });
    r = await kupi(ev, { quantity: 1, expected_price_cents: 0 });
    assert(r.status === 409 && r.body === SPREMENJENA, "pricakovana 0 pri placljivi vstopnici -> 409 (0 ni enako kot brez polja)", { status: r.status, body: r.body });
    assert(await stanje(ev) === pred, "ob 409 ni narocila, vstopnice ni, sold_count se ne spremeni", { pred, po: await stanje(ev) });

    await svez();
    console.log("\n# 2. Brez polja, null, neveljavne vrednosti");
    r = await kupi(ev, { quantity: 1 });
    assert(r.status === 201, "brez polja -> 201 kot doslej", r.body);
    r = await kupi(ev, { quantity: 1, expected_price_cents: null });
    assert(r.status === 201, "null -> 201 kot doslej", r.body);
    r = await kupi(ev, {});
    assert(r.status === 201, "prazno telo -> 201 kot doslej", r.body);
    pred = await stanje(ev);
    for (const slab of [-1, 10.5, "1000", true, [], {}]) {
      r = await kupi(ev, { quantity: 1, expected_price_cents: slab });
      assert(r.status === 400 && /expected_price_cents must be a non-negative integer/.test(r.body), `expected_price_cents ${JSON.stringify(slab)} -> 400`, { status: r.status, body: r.body });
    }
    assert(await stanje(ev) === pred, "ob 400 nic ustvarjeno");

    await svez();
    console.log("\n# 3. Cena je cena ene vstopnice");
    r = await kupi(ev, { quantity: 3, expected_price_cents: 1000 });
    assert(r.status === 201 && r.body.order.total_cents === 3000 && r.body.tickets.length === 3, "quantity 3, pricakovana 1000 (ena vstopnica) -> 201, skupaj 3000", r.body.order);
    pred = await stanje(ev);
    r = await kupi(ev, { quantity: 3, expected_price_cents: 3000 });
    assert(r.status === 409 && r.body === SPREMENJENA, "quantity 3, pricakovana 3000 (skupni znesek) -> 409", { status: r.status, body: r.body });
    assert(await stanje(ev) === pred, "nic ustvarjeno");

    await svez();
    console.log("\n# 4. Sprememba cene med ogledom in nakupom; brezplacen dogodek");
    const evP = await dogodek("Cena B", 1500);
    r = await api("PATCH", `/events/${evP}`, T.lastnik, { ticketPriceCents: 2500 });
    assert(r.status === 200, "lastnik dvigne ceno na 2500", r.body);
    r = await kupi(evP, { quantity: 1, expected_price_cents: 1500 });
    assert(r.status === 409 && r.body === SPREMENJENA, "kupec z staro ceno 1500 -> 409", { status: r.status, body: r.body });
    r = await kupi(evP, { quantity: 1, expected_price_cents: 2500 });
    assert(r.status === 201 && r.body.order.total_cents === 2500 && r.body.order.unit_price_cents === 2500, "po osvezitvi (2500) -> 201 po novi ceni", r.body.order);
    const evF = await dogodek("Cena zastonj", 0);
    r = await kupi(evF, { quantity: 1, expected_price_cents: 0 });
    assert(r.status === 201 && r.body.order.total_cents === 0, "brezplacen dogodek: pricakovana 0 -> 201", r.body.order);
    r = await kupi(evF, { quantity: 1, expected_price_cents: 1000 });
    assert(r.status === 409 && r.body === SPREMENJENA, "brezplacen dogodek: pricakovana 1000 -> 409", { status: r.status, body: r.body });

    await svez();
    console.log("\n# 5. Vrstni red preverb in idempotenca");
    const evBrez = await dogodek("Brez vstopnic", undefined, { ticketPriceCents: null });
    r = await kupi(evBrez, { quantity: 1, expected_price_cents: 1000 });
    assert(r.status === 409 && /no tickets on Outly/.test(r.body), "dogodek brez vstopnic Outly: najprej »no tickets on Outly«, ne cena", { status: r.status, body: r.body });
    const evOsnutek = await dogodek("Osnutek", 1000, { status: "draft" });
    r = await kupi(evOsnutek, { quantity: 1, expected_price_cents: 5 });
    assert(r.status === 409 && /not on sale/.test(r.body), "osnutek: »not on sale« ima prednost pred ceno", { status: r.status, body: r.body });
    const evId = await dogodek("Cena idem", 1000);
    const kljuc = crypto.randomUUID();
    r = await kupi(evId, { quantity: 1, expected_price_cents: 1000 }, { "Idempotency-Key": kljuc });
    assert(r.status === 201, "nakup s kljucem + pricakovano ceno -> 201", r.body);
    const prvo = r.body.order.id;
    await api("PATCH", `/events/${evId}`, T.lastnik, { ticketPriceCents: 1200 });
    r = await kupi(evId, { quantity: 1, expected_price_cents: 1000 }, { "Idempotency-Key": kljuc });
    assert(r.status === 201 && r.body.order.id === prvo && r.headers.get("idempotent-replayed") === "true", "ponovitev ISTEGA kljuca po spremembi cene vrne prvo narocilo (ne 409, ne drugo narocilo)", { status: r.status, body: r.body });
    r = await kupi(evId, { quantity: 1, expected_price_cents: 1000 }, { "Idempotency-Key": crypto.randomUUID() });
    assert(r.status === 409 && r.body === SPREMENJENA, "nov kljuc s staro ceno po spremembi -> 409", { status: r.status, body: r.body });

    console.log("\n# 6. Gostujoci nakup (POST /guest/events/:id/orders)");
    const evG = await dogodek("Cena gost", 1000);
    const TERMS = { accept_terms: true, terms_version: "2026-10-01" };
    const gost = (telo, email = "gost@example.com") => api("POST", `/guest/events/${evG}/orders`, null, { email, quantity: 1, ...TERMS, ...telo });
    pred = await stanje(evG);
    r = await gost({ expected_price_cents: 900 });
    assert(r.status === 409 && r.body === SPREMENJENA, "gost: neujemanje -> 409 »The ticket price has changed.«", { status: r.status, body: r.body });
    r = await gost({ expected_price_cents: 0 });
    assert(r.status === 409 && r.body === SPREMENJENA, "gost: pricakovana 0 pri placljivi -> 409", { status: r.status, body: r.body });
    for (const slab of [-1, 2.5, "1000", false, []]) {
      r = await gost({ expected_price_cents: slab });
      assert(r.status === 400 && /expected_price_cents must be a non-negative integer/.test(r.body), `gost: ${JSON.stringify(slab)} -> 400`, { status: r.status, body: r.body });
    }
    assert(await stanje(evG) === pred, "gost: ob 409 in 400 ni narocila ne vstopnice");
    r = await gost({ expected_price_cents: 1000 });
    assert(r.status === 201 && r.body.order.total_cents === 1000 && typeof r.body.guest_token === "string", "gost: ujemanje -> 201", r.body);
    r = await gost({}, "gost2@example.com");
    assert(r.status === 201, "gost: brez polja -> 201 kot doslej", r.body);
    r = await gost({ expected_price_cents: null }, "gost3@example.com");
    assert(r.status === 201, "gost: null -> 201 kot doslej", r.body);
    await api("PATCH", `/events/${evG}`, T.lastnik, { ticketPriceCents: 1400 });
    r = await gost({ expected_price_cents: 1000 }, "gost4@example.com");
    assert(r.status === 409 && r.body === SPREMENJENA, "gost: cena se je spremenila -> 409", { status: r.status, body: r.body });
    r = await gost({ expected_price_cents: 1400 }, "gost4@example.com");
    assert(r.status === 201 && r.body.order.total_cents === 1400, "gost: po osvezitvi -> 201 po novi ceni", r.body.order);
  } catch (e) {
    fail++; console.error("NAPAKA TESTA:", e);
  } finally {
    srv.kill(); jwksServer.close(); await pool.end();
    if (fail) console.log("\n--- dnevnik streznika ---\n" + log.split("\n").slice(-40).join("\n"));
    console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
    process.exit(fail ? 1 : 0);
  }
})();
