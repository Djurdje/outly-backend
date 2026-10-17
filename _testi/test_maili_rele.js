#!/usr/bin/env node
/**
 * Test MAILOV KOT RELE (#275, 17. 10. 2026). Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres@localhost:5432/outly" node _testi/test_maili_rele.js
 * Vzorec kot test_potrdilo_kupcu.js: lokalni JWKS, lazni Resend (RESEND_BASE_URL), backend na svojem portu, TRUNCATE na zacetku.
 *
 *  1  POST /creator-applications brez prijave: odziv 201 kot prej, mail ekipi (z zadevo brez vnosa v glavah), potrdila prosilcu NI (niti na naslov iz telesa)
 *  2  prijavljen: potrdilo samo na naslov racuna (ne na naslov iz telesa), nevtralna zadeva brez contactName
 *  3  zadeva maila ekipi: nove vrstice in kontrolni znaki ven, dolzina omejena
 *  4  vabilo v ekipo: ime kluba ubezano v HTML, zadeva brez novih vrstic in omejena
 *  5  POST /business/team ima omejevalnik (31. klic v uri -> 429, po uporabniku)
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3341, JWKS_PORT = 3997, RESEND_PORT = 3998;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-maili-rele";
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
const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
async function api(method, p, token, body) {
  const r = await fetch(BASE + p, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, text: t };
}
const pocakaj = (ms) => new Promise(r => setTimeout(r, ms));
async function cakaj(pogoj, ms = 5000) { const do_ = Date.now() + ms; while (Date.now() < do_) { if (pogoj()) return true; await pocakaj(50); } return false; }

// lazni Resend: zapomni vse poslane maile
const poslano = [];
const resendServer = http.createServer((req, res) => {
  let d = ""; req.on("data", x => d += x);
  req.on("end", () => {
    if (req.method === "POST" && req.url === "/emails") { poslano.push(JSON.parse(d)); res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify({ id: "mail_" + poslano.length })); }
    res.writeHead(404, { "content-type": "application/json" }); res.end("{}");
  });
});
const naslovi = (m) => [].concat(m.to);
const mailiNa = (email) => poslano.filter(m => naslovi(m).includes(email));

let srv = null;
(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, creator_applications, club_invites, club_members, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  await new Promise(r => resendServer.listen(RESEND_PORT, r));
  srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, QR_SECRET: "test",
    RESEND_API_KEY: "re_test", RESEND_BASE_URL: `http://127.0.0.1:${RESEND_PORT}`, EMAIL_FROM: "Outly <test@outly.test>", TEAM_EMAIL: "ekipa@outly.test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await pocakaj(100); } }

  console.log("\n# 1. Brez prijave: samo mail ekipi, potrdila prosilcu ni");
  const telo = { businessName: "Klub Ena", contactName: "Zrtev, kliknite na http://phish.example", email: "zrtev@tuja.example", phone: "" };
  let r = await api("POST", "/creator-applications", null, telo);
  assert(r.status === 201 && r.body.id && r.body.status === "new" && r.body.createdAt && /Application received/.test(r.body.message), "odziv 201 enak kot prej (message, id, status, createdAt)", r.body);
  assert(await cakaj(() => mailiNa("ekipa@outly.test").length >= 1), "mail ekipi poslan");
  await pocakaj(400);
  assert(mailiNa("zrtev@tuja.example").length === 0, "potrdila na naslov iz telesa NI", poslano.map(m => m.to));
  assert(poslano.length === 1, "brez prijave natanko en mail (ekipi)", poslano.length);
  assert(!poslano.some(m => /phish|Zrtev/.test(m.subject)), "contactName ni v nobeni zadevi", poslano.map(m => m.subject));

  console.log("\n# 2. Prijavljen: potrdilo samo na naslov racuna");
  const T = { ana: zeton("ana@outly.si", uuid(1)), lastnik: zeton("lastnik@outly.si", uuid(2)), manager: zeton("manager@outly.si", uuid(3)), tarca: zeton("tarca@outly.si", uuid(4)) };
  for (const k of Object.keys(T)) { const x = await api("GET", "/me", T[k]); assert(x.status === 200, `GET /me ${k}`, x.body); }
  poslano.length = 0;
  r = await api("POST", "/creator-applications", T.ana, { businessName: "Klub <b>Dva</b>\r\nBcc: x@y.z", contactName: "Ana\r\nBcc: zrtev@tuja.example", email: "zrtev2@tuja.example" });
  assert(r.status === 201, "prijavljen: 201", r.body);
  assert(await cakaj(() => mailiNa("ana@outly.si").length >= 1), "potrdilo na naslov racuna ana@outly.si");
  await pocakaj(400);
  assert(mailiNa("zrtev2@tuja.example").length === 0, "potrdila na naslov iz telesa NI");
  const pot = mailiNa("ana@outly.si")[0];
  assert(pot && pot.subject === "We received your application", "nevtralna zadeva potrdila", pot && pot.subject);
  assert(pot && !/Ana/.test(pot.subject), "contactName ni v zadevi potrdila");
  assert(pot && /Klub &lt;b&gt;Dva&lt;\/b&gt;/.test(pot.html) && !/<b>Dva/.test(pot.html), "ime podjetja v HTML ubezano");

  console.log("\n# 3. Zadeva maila ekipi: brez novih vrstic, omejena");
  const ek = mailiNa("ekipa@outly.test")[0];
  assert(ek && !/[\r\n]/.test(ek.subject) && ek.subject.length <= 200, "zadeva ekipi brez novih vrstic", ek && ek.subject);
  assert(ek && /Nova prošnja ustvarjalca: Klub <b>Dva<\/b> Bcc: x@y\.z/.test(ek.subject), "vsebina zadeve ohranjena, vrstice strnjene", ek && ek.subject);

  console.log("\n# 4. Vabilo v ekipo: ime kluba ubezano");
  await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
  const zlo = "Klub <img src=x onerror=alert(1)> & <a href=\"https://phish.example\">klikni</a>\r\nBcc: zrtev@tuja.example " + "X".repeat(400);
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), $1, 'Ljubljana')", [zlo]);
  poslano.length = 0;
  r = await api("POST", "/business/team", T.lastnik, { email: "manager@outly.si", role: "manager" });
  assert(r.status === 201, "vabilo 201", r.body);
  assert(await cakaj(() => mailiNa("manager@outly.si").length >= 1), "mail vabila poslan");
  const v = mailiNa("manager@outly.si")[0];
  assert(v && !/<img|<a href/.test(v.html) && /&lt;img src=x onerror=alert\(1\)&gt;/.test(v.html) && /&amp;/.test(v.html), "ime kluba v HTML ubezano", v && v.html.slice(0, 400));
  assert(v && !/[\r\n]/.test(v.subject) && v.subject.length <= 200, "zadeva brez novih vrstic in omejena", v && [v.subject.length, v.subject.slice(0, 120)]);

  console.log("\n# 5. Omejevalnik na POST /business/team");
  let stevilo429 = 0, prvi429 = 0;
  for (let i = 0; i < 32; i++) {
    const x = await api("POST", "/business/team", T.lastnik, { email: `nihce${i}@outly.si`, role: "doorman" });
    if (x.status === 429) { stevilo429++; if (!prvi429) prvi429 = i + 2; }   // +1 za klic iz 4. sklopa, +1 za 1-indeks
  }
  assert(stevilo429 >= 1 && prvi429 === 31, "31. klic v uri -> 429 (30/uro)", { stevilo429, prvi429 });
  const drugi = await api("POST", "/business/team", T.manager, { email: "tarca@outly.si", role: "doorman" });
  assert(drugi.status !== 429, "omejitev je po uporabniku (drug uporabnik ni blokiran)", drugi.status);

  if (/error|Error/.test(log) && !/Resend/.test(log)) { console.log("\n--- log streznika ---\n" + log); }
  console.log(`\n${ok} OK, ${fail} napak`);
  srv.kill(); jwksServer.close(); resendServer.close(); await pool.end();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); if (srv) srv.kill(); process.exit(1); });
