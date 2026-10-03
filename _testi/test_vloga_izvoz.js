#!/usr/bin/env node
/**
 * Test vloge `backup` (issue #116): racun za dnevno varnostno kopijo sme SAMO GET /admin/api/export.
 * Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres@localhost:5432/outly" node _testi/test_vloga_izvoz.js
 * Vzorec kot test_finance_admin.js: lokalni JWKS (3965), backend na svojem portu (3126).
 *
 * Kaj dokazuje (invarianta I5, vloga pride iz baze ob vsakem klicu):
 *  1. Vloga `backup` je dovoljena v bazi (users_role_chk), druge vrednosti se vedno ne.
 *  2. backup -> GET /admin/api/export = 200 (tok, veljaven JSON, iste tabele kot pri adminu); admin -> 200 kot prej.
 *  3. backup -> VSAKA druga admin pot (branje in pisanje, vse metode) = 403; stanje v bazi se ne spremeni.
 *  4. backup -> navadne poti API-ja (/me, nakup, klub, sken, brisanje racuna ...) = 403 (privzeto zavrnjen povsod razen na izvozu),
 *     javne poti brez prijave (/clubs, /events) delujejo kot prej; neobvezna prijava ga obravnava kot neprijavljenega.
 *  5. Navaden uporabnik, business, brez zetona, ponarejen zeton: izvoz 403 / 403 / 401 / 401.
 *  6. Sprememba vloge velja takoj (vloga iz baze): backup -> user = izvoz 403; admin ga lahko postavi prek PATCH /admin/api/users/:id.
 *  7. backup ne more sam sebi dati vecjih pravic (PATCH /admin/api/users/:id = 403, vloga ostane).
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3126, JWKS_PORT = 3965;
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
async function api(method, path, token, body) {
  const r = await fetch(BASE + path, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, text: t };
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, creator_applications, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  try {
    const T = {
      admin: zeton("admin@outly.si", uuid(1)),
      lastnik: zeton("lastnik@outly.si", uuid(2)),
      navaden: zeton("navaden@outly.si", uuid(3)),
      kopija: zeton("kopija@outly.si", uuid(4)),
    };
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k} (vrstica nastane ob prvem klicu, vloga user)`, r.body); }
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana')");
    const cezTeden = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
    let r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Dogodek", startAt: cezTeden, ticketPriceCents: 1000, capacity: 50, minAge: 0 });
    assert(r.status === 201, "dogodek ustvarjen", r.body);
    const dogodekId = r.body.id;

    console.log("\n# 1. Baza: vloga backup dovoljena, druge vrednosti ne");
    let napaka = null;
    try { await pool.query("UPDATE users SET role='superadmin' WHERE email='navaden@outly.si'"); } catch (e) { napaka = e; }
    assert(napaka && napaka.code === "23514", "role='superadmin' zavrne users_role_chk (23514)", napaka && napaka.code);
    napaka = null;
    try { await pool.query("UPDATE users SET role='backup' WHERE email='kopija@outly.si'"); } catch (e) { napaka = e; }
    assert(!napaka, "role='backup' baza sprejme (migracija 029)", napaka && napaka.message);

    console.log("\n# 2. backup -> izvoz = 200; admin -> izvoz = 200 kot prej");
    r = await api("GET", "/admin/api/export", T.kopija);
    assert(r.status === 200, "backup: GET /admin/api/export -> 200", r.status);
    let izvozB = null; try { izvozB = JSON.parse(r.text); } catch (_) { /* spodaj */ }
    assert(izvozB !== null && izvozB.tables && izvozB.tables.users && Array.isArray(izvozB.sequences), "backup: odgovor je veljaven izvoz (tables, sequences)");
    assert(izvozB && izvozB.tables.users.count === 4 && izvozB.tables.clubs.count === 1, "backup: izvoz vsebuje vrstice (4 uporabniki, 1 klub)", izvozB && izvozB.tables.users.count);
    assert(izvozB && !("omejitve" in izvozB.tables), "backup: tabela omejitve ni v izvozu (kot pri adminu)");
    r = await api("GET", "/admin/api/export", T.admin);
    assert(r.status === 200, "admin: GET /admin/api/export -> 200 (kot prej)", r.status);
    let izvozA = null; try { izvozA = JSON.parse(r.text); } catch (_) { /* spodaj */ }
    assert(izvozA !== null && izvozB !== null && Object.keys(izvozA.tables).join() === Object.keys(izvozB.tables).join(), "admin in backup dobita iste tabele");
    r = await api("GET", "/admin/api/export?x=1", T.kopija);
    assert(r.status === 200, "backup: izvoz s poizvedbenim nizom -> 200 (ista pot)", r.status);
    r = await api("GET", "/admin/api/Export", T.kopija);
    assert(r.status === 200, "backup: /admin/api/Export (velike crke) -> 200 (Express ni obcutljiv, ista pot kot pri adminu)", r.status);

    console.log("\n# 3. backup -> vsaka druga admin pot = 403");
    const kopijaId = (await pool.query("SELECT id FROM users WHERE email='kopija@outly.si'")).rows[0].id;
    const navadenId = (await pool.query("SELECT id FROM users WHERE email='navaden@outly.si'")).rows[0].id;
    const prepovedane = [
      ["GET", "/admin/api/summary"],
      ["GET", "/admin/api/finance"],
      ["GET", "/admin/api/users"],
      ["GET", "/admin/api/users?q=outly"],
      ["GET", "/admin/api/clubs"],
      ["GET", "/admin/api/events"],
      ["GET", "/admin/api/creator-applications"],
      ["POST", "/admin/api/clubs", { name: "Hekerski klub", city: "Ljubljana" }],
      ["PATCH", "/admin/api/clubs/1", { hidden: true }],
      ["PATCH", `/admin/api/users/${kopijaId}`, { role: "admin" }],
      ["PATCH", `/admin/api/users/${navadenId}`, { role: "admin" }],
      ["PATCH", `/admin/api/users/${navadenId}`, { emailVerified: true }],
      ["PATCH", `/admin/api/events/${dogodekId}`, { status: "cancelled" }],
      ["POST", "/admin/api/creator-applications/1/approve", {}],
      ["POST", "/admin/api/creator-applications/1/reject", {}],
      ["POST", "/admin/api/export", {}],
      ["PUT", "/admin/api/export", {}],
      ["DELETE", "/admin/api/export"],
      ["GET", "/admin/api/export/dodatek"],
      ["GET", "/admin/api/neobstojec"],
    ];
    for (const [m, p, b] of prepovedane) {
      r = await api(m, p, T.kopija, b);
      assert(r.status === 403, `backup: ${m} ${p} -> 403`, r.status);
    }
    const stanje = (await pool.query("SELECT (SELECT role FROM users WHERE id=$1) AS kopija, (SELECT role FROM users WHERE id=$2) AS navaden, (SELECT hidden FROM clubs WHERE id=1) AS skrit, (SELECT status FROM events WHERE id=$3) AS dogodek, (SELECT COUNT(*)::int FROM clubs) AS klubi", [kopijaId, navadenId, dogodekId])).rows[0];
    assert(stanje.kopija === "backup" && stanje.navaden === "user" && stanje.skrit === false && stanje.dogodek === "published" && stanje.klubi === 1, "stanje v bazi po poskusih pisanja je nespremenjeno", stanje);

    console.log("\n# 4. backup -> navadne poti API-ja = 403; javne poti brez prijave delujejo");
    const navadne = [
      ["GET", "/me"],
      ["PATCH", "/me", { username: "hekerski" }],
      ["DELETE", "/me"],
      ["GET", "/me/orders"],
      ["GET", "/me/tickets"],
      ["GET", "/me/invites"],
      ["POST", `/events/${dogodekId}/orders`, { quantity: 1 }],
      ["POST", "/clubs", { name: "Moj klub", city: "Maribor" }],
      ["PUT", "/clubs/1/follow"],
      ["GET", "/business/clubs/me"],
      ["POST", "/business/tickets/scan", { serial: "00000000-0000-4000-8000-000000000000" }],
    ];
    for (const [m, p, b] of navadne) {
      r = await api(m, p, T.kopija, b);
      assert(r.status === 403, `backup: ${m} ${p} -> 403`, r.status);
    }
    const po = (await pool.query("SELECT (SELECT COUNT(*)::int FROM users WHERE id=$1) AS racun, (SELECT COUNT(*)::int FROM orders) AS narocila, (SELECT COUNT(*)::int FROM clubs) AS klubi, (SELECT username FROM users WHERE id=$1) AS ime", [kopijaId])).rows[0];
    assert(po.racun === 1 && po.narocila === 0 && po.klubi === 1 && po.ime === "kopija", "racun ni izbrisan, ni narocil, ni novih klubov, ime nespremenjeno", po);
    r = await api("GET", "/clubs", T.kopija);
    assert(r.status === 200, "javni GET /clubs z zetonom backup -> 200 (pot ne zahteva prijave, kot prej)", r.status);
    r = await api("GET", "/events", T.kopija);
    assert(r.status === 200, "javni GET /events z zetonom backup -> 200", r.status);
    r = await api("POST", "/creator-applications", T.kopija, { businessName: "Test bar", contactName: "Test Oseba", email: "kdorkoli@example.com" });
    assert(r.status === 201 || r.status === 200, "POST /creator-applications (neobvezna prijava) deluje kot za neprijavljenega", r.status + " " + r.text);
    const prosnja = (await pool.query("SELECT user_id, email FROM creator_applications ORDER BY id DESC LIMIT 1")).rows[0];
    assert(prosnja && prosnja.user_id === null && prosnja.email === "kdorkoli@example.com", "prosnja NI vezana na racun backup (user_id null, e-naslov iz telesa)", prosnja);

    console.log("\n# 5. Drugi klici izvoza");
    r = await api("GET", "/admin/api/export", null);
    assert(r.status === 401, "brez zetona -> 401", r.status);
    r = await api("GET", "/admin/api/export", "ni.zeton.sploh");
    assert(r.status === 401, "ponarejen zeton -> 401", r.status);
    r = await api("GET", "/admin/api/export", T.navaden);
    assert(r.status === 403, "navaden uporabnik -> 403", r.status);
    r = await api("GET", "/admin/api/export", T.lastnik);
    assert(r.status === 403, "business -> 403", r.status);

    console.log("\n# 6. Vloga iz baze ob vsakem klicu; admin jo lahko nastavi");
    await pool.query("UPDATE users SET role='user' WHERE id=$1", [kopijaId]);
    r = await api("GET", "/admin/api/export", T.kopija);
    assert(r.status === 403, "po vrnitvi na user izvoz takoj 403", r.status);
    r = await api("GET", "/me", T.kopija);
    assert(r.status === 200, "po vrnitvi na user spet deluje navadna prijava (/me 200)", r.status);
    r = await api("PATCH", `/admin/api/users/${kopijaId}`, T.admin, { role: "backup" });
    assert(r.status === 200 && r.body.role === "backup", "admin nastavi vlogo backup prek PATCH /admin/api/users/:id", r.body);
    r = await api("GET", "/admin/api/export", T.kopija);
    assert(r.status === 200, "izvoz takoj spet 200", r.status);
    r = await api("PATCH", `/admin/api/users/${kopijaId}`, T.admin, { role: "napacna" });
    assert(r.status === 400, "neveljavna vloga se vedno 400", r.status);
    r = await api("GET", "/admin/api/users", T.admin);
    assert(r.status === 200 && r.body.some(u => u.email === "kopija@outly.si" && u.role === "backup"), "admin v seznamu vidi vlogo backup", r.status);
    r = await api("GET", "/admin/api/summary", T.admin);
    assert(r.status === 200, "admin: summary se vedno 200", r.status);
    r = await api("PATCH", `/admin/api/users/${navadenId}`, T.admin, { role: "business" });
    assert(r.status === 200 && r.body.role === "business", "admin: PATCH vloga business se vedno dela", r.body);

    console.log("\n# 7. Brez nepricakovanih napak v dnevniku streznika");
    assert(!/TypeError|ReferenceError|unhandled/i.test(log), "dnevnik brez TypeError/ReferenceError/unhandled", log.slice(-400));
  } finally {
    srv.kill();
    jwksServer.close();
    await pool.end();
  }
  console.log(`\n${ok} ok, ${fail} napak`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
