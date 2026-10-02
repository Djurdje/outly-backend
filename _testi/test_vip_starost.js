#!/usr/bin/env node
/**
 * Test starostne meje pri VIP mizi s paketom pijace (issue #102, ZOPA 7/1). Zagon (lokalno, PG16,
 * baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_vip_starost.js
 * Vzorec kot test_vip.js: lokalni JWKS (3999), backend na svojem portu (3125).
 *
 * Pravilo (glej docs/DECISIONS.md): bottle paket je po zasnovi pijaca (alkohol), zato velja za nakup mize
 * Z IZBRANIM PAKETOM in za prenos vsake vstopnice take mize starost >= max(min_age dogodka, 18) — na
 * strezniku, brez datuma rojstva -> 403 (kot pri min_age). Miza brez paketa (klub brez paketov) in navadne
 * vstopnice ostanejo pri min_age dogodka.
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3125, JWKS_PORT = 3999;
const BASE = `http://127.0.0.1:${PORT}`;

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
async function api(method, p, token, body) {
  const r = await fetch(BASE + p, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 80; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  const T = {
    lastnik: zeton("lastnik@outly.si", uuid(1)),
    lastnik2: zeton("lastnik2@outly.si", uuid(2)),
    odrasla: zeton("odrasla@outly.si", uuid(3)),      // 25 let
    tocno18: zeton("tocno18@outly.si", uuid(4)),      // danes dopolni 18 let
    sedemnajst: zeton("sedemnajst@outly.si", uuid(5)), // jutri dopolni 18 let (danes 17)
    brezdatuma: zeton("brezdatuma@outly.si", uuid(6)),
    devetnajst: zeton("devetnajst@outly.si", uuid(7)),
  };
  for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
  await pool.query("UPDATE users SET role='business' WHERE email IN ('lastnik@outly.si','lastnik2@outly.si')");
  // Datumi rojstva neposredno v bazi: tocno na mejo (starost = EXTRACT(YEAR FROM AGE(CURRENT_DATE, rojstvo))).
  await pool.query(`UPDATE users SET date_of_birth = (CURRENT_DATE - INTERVAL '25 years')::date WHERE email='odrasla@outly.si'`);
  await pool.query(`UPDATE users SET date_of_birth = (CURRENT_DATE - INTERVAL '18 years')::date WHERE email='tocno18@outly.si'`);
  await pool.query(`UPDATE users SET date_of_birth = (CURRENT_DATE - INTERVAL '18 years' + INTERVAL '1 day')::date WHERE email='sedemnajst@outly.si'`);
  await pool.query(`UPDATE users SET date_of_birth = (CURRENT_DATE - INTERVAL '19 years')::date WHERE email='devetnajst@outly.si'`);
  const leta = (await pool.query(`SELECT email, starost(date_of_birth) AS leta FROM users WHERE email IN ('tocno18@outly.si','sedemnajst@outly.si') ORDER BY email`)).rows;
  assert(leta[1].leta === 18 && leta[0].leta === 17, "izhodisce: tocno18 ima 18 let, sedemnajst 17", leta);

  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Klub s paketi', 'Ljubljana')");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik2@outly.si'), 'Klub brez paketov', 'Maribor')");
  async function dogodek(klub, naslov, minAge) {
    const r = await pool.query(
      `INSERT INTO events (club_id, title, poster_url, start_at, status, ticket_price_cents, capacity, min_age, vip_enabled)
       VALUES ($1,$2,'https://example.com/p.jpg', NOW() + INTERVAL '2 days', 'published', 1500, 100, $3, TRUE) RETURNING id`, [klub, naslov, minAge]);
    return r.rows[0].id;
  }
  const E0 = await dogodek(1, "Dogodek 0+", 0);
  const E16 = await dogodek(1, "Dogodek 16+", 16);
  const E21 = await dogodek(1, "Dogodek 21+", 21);
  const EBREZ = await dogodek(2, "Klub brez paketov 0+", 0);

  const PLAN = { width: 24, height: 16, elements: [{ type: "stage", x: 8, y: 0, w: 8, h: 3, label: "" }] };
  const mize = (n) => Array.from({ length: n }, (_, i) => ({ label: `T${i + 1}`, x: 1 + (i % 5) * 4, y: 5 + Math.floor(i / 5) * 3, w: 2, h: 2, shape: "round", seats: 4, price_cents: 20000 }));
  let r = await api("PUT", "/business/vip", T.lastnik, { plan: PLAN, tables: mize(10), packages: [{ name: "Jameson 0,7 l", description: "4x Red Bull" }] });
  assert(r.status === 200, "klub s paketi: 10 miz, 1 paket", r.body);
  const M = r.body.tables.map(t => t.id), P = r.body.packages[0].id;
  r = await api("PUT", "/business/vip", T.lastnik2, { plan: PLAN, tables: mize(2), packages: [] });
  assert(r.status === 200 && r.body.packages.length === 0, "klub brez paketov: 2 mizi, 0 paketov", r.body);
  const MB = r.body.tables.map(t => t.id);

  const brezNarocil = async (eid, mid) => (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1 AND table_id=$2", [eid, mid])).rows[0].n;
  const nakupMize = (eid, mid, tok, paket) => api("POST", `/events/${eid}/tables/${mid}/orders`, tok, paket === undefined ? {} : { package_id: paket });

  console.log("\n# Javni GET /events/:id/vip pove mejo za paket (dodano polje package_min_age)");
  r = await api("GET", `/events/${E0}/vip`);
  assert(r.status === 200 && r.body.enabled === true && r.body.package_min_age === 18, "dogodek 0+: package_min_age = 18", r.body.package_min_age);
  r = await api("GET", `/events/${E21}/vip`);
  assert(r.status === 200 && r.body.package_min_age === 21, "dogodek 21+: package_min_age = 21 (strozja meja dogodka)", r.body.package_min_age);

  console.log("\n# Nakup mize s paketom na dogodku 0+ (min_age dogodka ne zadostuje)");
  r = await nakupMize(E0, M[0], T.sedemnajst, P);
  assert(r.status === 403 && /at least 18/.test(r.body) && /bottle package/i.test(r.body), "17-letnik + paket na dogodku 0+ -> 403 (>= 18)", r.body);
  assert(await brezNarocil(E0, M[0]) === 0, "zavrnjen nakup ne pusti narocila, miza ostane prosta");
  r = await nakupMize(E0, M[0], T.brezdatuma, P);
  assert(r.status === 403 && /date of birth/i.test(r.body) && /bottle package/i.test(r.body), "brez datuma rojstva + paket na dogodku 0+ -> 403 (dodaj datum rojstva)", r.body);
  assert(await brezNarocil(E0, M[0]) === 0, "brez datuma: narocila ni");
  r = await nakupMize(E0, M[0], T.tocno18, P);
  assert(r.status === 201 && r.body.order.package_name === "Jameson 0,7 l" && r.body.tickets.length === 4, "tocno 18 let + paket -> 201 (meja je vkljucna)", r.body);
  r = await nakupMize(E0, M[1], T.odrasla, P);
  assert(r.status === 201, "25-letnica + paket -> 201", r.body);
  const narociloOdrasla = r.body;

  console.log("\n# Nakup mize s paketom: strozja meja dogodka ostane");
  r = await nakupMize(E16, M[2], T.sedemnajst, P);
  assert(r.status === 403 && /at least 18/.test(r.body), "17-letnik + paket na dogodku 16+ -> 403 (paket zahteva 18)", r.body);
  r = await nakupMize(E21, M[3], T.devetnajst, P);
  assert(r.status === 403 && /at least 21/.test(r.body), "19-letnik + paket na dogodku 21+ -> 403 (velja strozja meja dogodka, 21)", r.body);
  r = await nakupMize(E21, M[3], T.odrasla, P);
  assert(r.status === 201, "25-letnica + paket na dogodku 21+ -> 201", r.body);

  console.log("\n# Miza brez paketa in navadne vstopnice: meja ostane min_age dogodka (ni regresije)");
  r = await nakupMize(EBREZ, MB[0], T.sedemnajst);
  assert(r.status === 201 && r.body.order.package_name === null && r.body.tickets.length === 4, "17-letnik, klub brez paketov, miza brez paketa na dogodku 0+ -> 201", r.body);
  const mizaBrezPaketa = r.body;
  r = await api("POST", `/events/${E0}/orders`, T.sedemnajst, { quantity: 1 });
  assert(r.status === 201, "17-letnik kupi navadno vstopnico na dogodku 0+ -> 201", r.body);
  const navadna = r.body;

  console.log("\n# Prenos vstopnice mize s paketom");
  const vst = narociloOdrasla.tickets;
  r = await api("POST", `/tickets/${vst[0].id}/transfer`, T.odrasla, { email: "sedemnajst@outly.si" });
  assert(r.status === 403 && /at least 18/.test(r.body) && /bottle package/i.test(r.body), "prenos VIP vstopnice s paketom 17-letniku -> 403", r.body);
  r = await api("POST", `/tickets/${vst[0].id}/transfer`, T.odrasla, { email: "brezdatuma@outly.si" });
  assert(r.status === 403 && /date of birth/i.test(r.body) && /bottle package/i.test(r.body), "prenos VIP vstopnice s paketom osebi brez datuma rojstva -> 403", r.body);
  let imetnik = (await pool.query("SELECT holder_user_id FROM tickets WHERE id=$1", [vst[0].id])).rows[0].holder_user_id;
  assert(imetnik === null, "zavrnjen prenos ne spremeni imetnika", imetnik);
  const serialPrej = (await pool.query("SELECT serial FROM tickets WHERE id=$1", [vst[0].id])).rows[0].serial;
  r = await api("POST", `/tickets/${vst[0].id}/transfer`, T.odrasla, { email: "tocno18@outly.si" });
  assert(r.status === 200 && r.body.result === "ok", "prenos VIP vstopnice s paketom 18-letniku -> 200", r.body);
  const serialPotem = (await pool.query("SELECT serial FROM tickets WHERE id=$1", [vst[0].id])).rows[0].serial;
  assert(serialPrej !== serialPotem, "po uspesnem prenosu je serial nov (I7)");
  // Veriga: novi imetnik (18) ne sme naprej 17-letniku
  r = await api("POST", `/tickets/${vst[0].id}/transfer`, T.tocno18, { email: "sedemnajst@outly.si" });
  assert(r.status === 403 && /at least 18/.test(r.body), "novi imetnik ne sme vstopnice mize s paketom naprej 17-letniku -> 403", r.body);
  r = await api("POST", `/tickets/${vst[1].id}/transfer`, T.odrasla, { email: "devetnajst@outly.si" });
  assert(r.status === 200, "prenos druge vstopnice iste mize 19-letniku -> 200", r.body);

  console.log("\n# Prenos: strozja meja dogodka in vstopnice brez paketa");
  // 19-letnik prejme vstopnico mize s paketom na dogodku 0+, ne pa na dogodku 21+
  const e21 = (await pool.query("SELECT t.id FROM tickets t JOIN orders o ON o.id = t.order_id WHERE o.event_id=$1 ORDER BY t.id LIMIT 1", [E21])).rows[0].id;
  r = await api("POST", `/tickets/${e21}/transfer`, T.odrasla, { email: "devetnajst@outly.si" });
  assert(r.status === 403 && /at least 21/.test(r.body), "prenos vstopnice mize s paketom na dogodku 21+ 19-letniku -> 403 (21)", r.body);
  r = await api("POST", `/tickets/${mizaBrezPaketa.tickets[0].id}/transfer`, T.sedemnajst, { email: "devetnajst@outly.si" });
  assert(r.status === 200, "prenos vstopnice mize BREZ paketa (19 let, dogodek 0+) -> 200", r.body);
  r = await api("POST", `/tickets/${mizaBrezPaketa.tickets[1].id}/transfer`, T.sedemnajst, { email: "brezdatuma@outly.si" });
  assert(r.status === 200, "prenos vstopnice mize BREZ paketa osebi brez datuma rojstva na dogodku 0+ -> 200 (meja dogodka 0)", r.body);
  r = await api("POST", `/tickets/${navadna.tickets[0].id}/transfer`, T.sedemnajst, { email: "brezdatuma@outly.si" });
  assert(r.status === 200, "prenos navadne vstopnice na dogodku 0+ osebi brez datuma rojstva -> 200 (ni regresije)", r.body);

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  const napake = log.split("\n").filter(l => /error|TypeError|Unhandled/i.test(l) && !/Server error\./.test(l) && !/Resend/i.test(l));
  if (napake.length) console.log("\nLog backenda (sumljivo):\n" + napake.join("\n"));
  srv.kill(); jwksServer.close(); await pool.end();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
