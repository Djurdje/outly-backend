#!/usr/bin/env node
/**
 * Test poslovnih invariant, ki jih druge skripte ne pokrivajo (glej
 * docs/ARCHITECTURE.md, razdelek "Poslovne invariante"):
 *
 *   I4  stripe_account_id (in ostale skrivnosti kluba) ne uhajajo v NOBEN odgovor API-ja.
 *   I10 Izpad Supabase Auth (JWKS nedosegljiv) vrne 503, nikoli 401 -> uporabnik ni odjavljen,
 *       javne poti pa delajo naprej.
 *
 * Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres@localhost:5433/outly" node _testi/test_invariante.js
 *
 * Skripta sama dvigne lokalni JWKS streznik (port 3999), podpise ES256 zetone in
 * zazene DVA backenda: enega z delujocim JWKS (port 3118) in enega, ki kaze na
 * mrtvo vrata (port 3119, JWKS na 3998 -> nihce ne poslusa).
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3118, JWKS_PORT = 3999;
const PORT_BREZ_JWKS = 3119, MRTVA_VRATA = 3998;
const BASE = `http://127.0.0.1:${PORT}`;
const BASE_BREZ_JWKS = `http://127.0.0.1:${PORT_BREZ_JWKS}`;

// Skrivnost, ki je v bazi in ne sme nikoli ven.
const TAJNI_ACCT = "acct_NIKOLI_V_ODGOVORU_1234567890";

// --- kljuc + JWKS ---
const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-1";
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

// Vrne tudi surovo besedilo odgovora: skrivnost iscemo v NJEM, ne v razclenjenem
// objektu — tako ujamemo tudi ugnezdena polja, ki jih test ne pozna vnaprej.
async function api(method, path, token, body, base = BASE) {
  const r = await fetch(base + path, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, tekst: t };
}

function dvigni(port, jwksPort) {
  return spawn("node", ["index.js"], {
    env: { ...process.env, PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${jwksPort}`, RESEND_API_KEY: "", QR_SECRET: "test" },
    stdio: ["ignore", "pipe", "pipe"],
  });
}
async function pockaj(base) {
  for (let i = 0; i < 50; i++) { try { await fetch(base + "/"); return true; } catch { await new Promise(r => setTimeout(r, 100)); } }
  return false;
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");

  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = dvigni(PORT, JWKS_PORT);
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  await pockaj(BASE);

  const T = {
    lastnik: zeton("lastnik@outly.si", uuid(1)),
    admin: zeton("admin@outly.si", uuid(2)),
    gost: zeton("gost@outly.si", uuid(3)),
  };
  for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
  await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
  await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");

  // Klub s Stripovim racunom in objavljen dogodek z vstopnicami.
  const klub = await pool.query(
    `INSERT INTO clubs (owner_user_id, name, city, lat, lng, stripe_account_id, stripe_charges_enabled, stripe_payouts_enabled, stripe_onboarded_at)
     VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana', 46.05, 14.5, $1, TRUE, TRUE, NOW()) RETURNING id`,
    [TAJNI_ACCT]
  );
  const klubId = klub.rows[0].id;
  const dog = await pool.query(
    `INSERT INTO events (club_id, title, start_at, status, ticket_price_cents, currency, min_age)
     VALUES ($1, 'Pure Night', NOW() + INTERVAL '3 days', 'published', 1500, 'EUR', 0) RETURNING id`, [klubId]
  );
  const dogId = dog.rows[0].id;
  // Kupec z vstopnico: preverimo tudi poti z narocili in vstopnicami.
  let r = await api("POST", `/events/${dogId}/orders`, T.gost, { quantity: 1 });
  assert(r.status === 201, "gost kupi vstopnico (priprava)", r.body);

  console.log("\n# I4 stripe_account_id ne uhaja v noben odgovor");
  // Kdor sme klicati pot -> njegov zeton; javne poti brez zetona.
  const poti = [
    ["GET", "/clubs", null],
    ["GET", `/clubs/${klubId}`, null],
    ["GET", "/clubs/map", null],
    ["GET", "/events", null],
    ["GET", `/events/${dogId}`, null],
    ["GET", "/search?q=Pure", null],
    ["GET", "/business/clubs/me", T.lastnik],
    ["GET", "/business/events", T.lastnik],
    ["GET", "/business/sales", T.lastnik],
    ["GET", "/me/orders", T.gost],
    ["GET", "/me/tickets", T.gost],
    ["GET", "/admin/api/clubs", T.admin],
    ["GET", "/admin/api/summary", T.admin],
    ["GET", "/admin/api/finance", T.admin],
  ];
  for (const [m, p, t] of poti) {
    const o = await api(m, p, t);
    assert(o.status === 200, `${m} ${p} -> 200`, o.status);
    assert(!o.tekst.includes(TAJNI_ACCT), `${p}: odgovor ne vsebuje stripe_account_id`, o.tekst.slice(0, 200));
    assert(!/"stripe_account_id"/.test(o.tekst), `${p}: odgovor nima kljuca stripe_account_id`, o.tekst.slice(0, 200));
    assert(!/"stripe_onboarded_at"/.test(o.tekst), `${p}: odgovor nima kljuca stripe_onboarded_at`, o.tekst.slice(0, 200));
  }
  // Izvoz baze je edina pot, ki sme videti vse — a samo admin, nihce drug.
  r = await api("GET", "/admin/api/export", T.lastnik);
  assert(r.status === 403, "GET /admin/api/export (business) -> 403", r.status);

  // Kontrola: seznam stolpcev je NAMENOMA ozek, ne po nesreci prazen.
  r = await api("GET", "/business/clubs/me", T.lastnik);
  assert(r.body && r.body.stripe_charges_enabled === true, "lastnik vidi stripe_charges_enabled (stanje, ne id)", r.body);
  r = await api("GET", `/clubs/${klubId}`, null);
  assert(r.body && r.body.name === "Pure Club" && r.body.bar_prices !== undefined, "javni klub vseeno vrne svoja javna polja", r.body);
  // In da je skrivnost res v bazi (sicer test ne dokazuje nicesar).
  const vBazi = await pool.query("SELECT stripe_account_id FROM clubs WHERE id=$1", [klubId]);
  assert(vBazi.rows[0].stripe_account_id === TAJNI_ACCT, "stripe_account_id JE v bazi (test ni prazen)", vBazi.rows[0]);

  console.log("\n# I10 izpad Supabase Auth: 503, ne 401");
  const srv2 = dvigni(PORT_BREZ_JWKS, MRTVA_VRATA);
  let log2 = ""; srv2.stdout.on("data", d => log2 += d); srv2.stderr.on("data", d => log2 += d);
  assert(await pockaj(BASE_BREZ_JWKS), "backend brez dosegljivega JWKS se je zagnal");

  r = await api("GET", "/me", T.lastnik, null, BASE_BREZ_JWKS);
  assert(r.status === 503, "GET /me pri nedosegljivem JWKS -> 503 (NE 401)", r.status);
  r = await api("GET", "/me/tickets", T.gost, null, BASE_BREZ_JWKS);
  assert(r.status === 503, "GET /me/tickets pri nedosegljivem JWKS -> 503", r.status);
  r = await api("POST", `/events/${dogId}/orders`, T.gost, { quantity: 1 }, BASE_BREZ_JWKS);
  assert(r.status === 503, "nakup pri nedosegljivem JWKS -> 503 (nakup se ne zgodi)", r.status);
  r = await api("GET", "/me", null, null, BASE_BREZ_JWKS);
  assert(r.status === 401, "brez zetona je se vedno 401 (manjkajoc zeton ni izpad)", r.status);
  r = await api("GET", "/clubs", null, null, BASE_BREZ_JWKS);
  assert(r.status === 200, "javne poti med izpadom Auth delajo naprej", r.status);
  assert(!r.tekst.includes(TAJNI_ACCT), "javne poti tudi med izpadom ne razkrijejo stripe_account_id");
  // Stevilo narocil se med izpadom ni spremenilo.
  const nar = await pool.query("SELECT COUNT(*)::int AS n FROM orders");
  assert(nar.rows[0].n === 1, "med izpadom Auth ni nastalo novo narocilo", nar.rows[0]);

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  const napake = (log + log2).split("\n").filter(l => /error|TypeError|Unhandled/i.test(l) && !/Server error\./.test(l) && !/Resend/i.test(l) && !/JWKS/i.test(l));
  if (napake.length) console.log("--- napake v logu streznika ---\n" + napake.join("\n"));
  srv.kill(); srv2.kill(); jwksServer.close(); await pool.end();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
