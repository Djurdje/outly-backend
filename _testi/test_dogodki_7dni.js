#!/usr/bin/env node
/**
 * Test: pretekli dogodki so javno vidni samo 7 dni po zacetku (GET /events?upcoming=false).
 * Zagon (lokalno, PG16, baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_dogodki_7dni.js
 * Vzorec kot test_vabila.js: lokalni JWKS (3999), backend na 3114.
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3114, JWKS_PORT = 3999;
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
  return { status: r.status, body: j };
}
const naslovi = (r) => (Array.isArray(r.body) ? r.body.map(e => e.title) : r.body);

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  const T = { lastnik: zeton("lastnik@outly.si", uuid(1)) };
  let r = await api("GET", "/me", T.lastnik); assert(r.status === 200, "GET /me lastnik", r.body);
  await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana')");

  // Dogodki: pred 2 dnevoma (viden), pred 6 dnevi (viden), pred 8 dnevi (skrit), cez 1 dan (prihajajoci),
  // pred 1 dnevom a odpovedan (skrit, kot doslej).
  await pool.query(`INSERT INTO events (club_id, title, start_at, status) VALUES
    (1, 'pred 2 dni',   NOW() - INTERVAL '2 days', 'published'),
    (1, 'pred 6 dni',   NOW() - INTERVAL '6 days', 'published'),
    (1, 'pred 8 dni',   NOW() - INTERVAL '8 days', 'published'),
    (1, 'cez 1 dan',    NOW() + INTERVAL '1 day',  'published'),
    (1, 'odpovedan',    NOW() - INTERVAL '1 day',  'cancelled')`);
  const id8 = (await pool.query("SELECT id FROM events WHERE title='pred 8 dni'")).rows[0].id;

  console.log("\n# Pretekli dogodki (upcoming=false): samo zadnjih 7 dni");
  r = await api("GET", "/events?clubId=1&upcoming=false");
  assert(r.status === 200, "GET /events?clubId=1&upcoming=false -> 200", r.status);
  assert(Array.isArray(r.body) && r.body.length === 2 && naslovi(r).includes("pred 2 dni") && naslovi(r).includes("pred 6 dni"),
    "vrne samo 'pred 2 dni' in 'pred 6 dni'", naslovi(r));
  assert(!naslovi(r).includes("pred 8 dni"), "'pred 8 dni' ni vec na strani kluba", naslovi(r));
  assert(!naslovi(r).includes("odpovedan"), "odpovedan dogodek ni viden (kot doslej)", naslovi(r));
  r = await api("GET", "/events?upcoming=false");
  assert(r.status === 200 && r.body.length === 2 && !naslovi(r).includes("pred 8 dni"), "brez clubId (domaci zaslon) enako okno 7 dni", naslovi(r));

  console.log("\n# Prihajajoci (upcoming=true) nespremenjeni");
  r = await api("GET", "/events?clubId=1&upcoming=true");
  assert(r.status === 200 && r.body.length === 1 && r.body[0].title === "cez 1 dan", "vrne samo 'cez 1 dan'", naslovi(r));

  console.log("\n# Starejsi dogodek ostane v bazi in dosegljiv po id (vstopnice, lastnik)");
  r = await api("GET", `/events/${id8}`);
  assert(r.status === 200 && r.body.title === "pred 8 dni", "GET /events/:id za 'pred 8 dni' -> 200", r.status);
  r = await api("GET", "/business/events", T.lastnik);
  assert(r.status === 200 && naslovi(r).includes("pred 8 dni") && naslovi(r).includes("odpovedan"), "lastnik v GET /business/events vidi vse svoje dogodke", naslovi(r));
  const n = (await pool.query("SELECT COUNT(*)::int AS n FROM events")).rows[0].n;
  assert(n === 5, "v bazi je se vseh 5 dogodkov (nic ni izbrisano)", n);

  srv.kill(); jwksServer.close(); await pool.end();
  const napake = log.split("\n").filter(l => /error|TypeError|Unhandled/i.test(l) && !/Server error\./.test(l));
  if (napake.length) console.log("\nLog backenda (sumljivo):\n" + napake.join("\n"));
  console.log(`\n${ok} OK, ${fail} napak`);
  process.exit(fail ? 1 : 0);
})();
