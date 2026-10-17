#!/usr/bin/env node
/**
 * Podpis za nalaganje na Cloudinary (pregled 17. 10. 2026, S2; I15). Brez omejitve je vsak registriran uporabnik lahko v zanki
 * pridobival podpise in nalagal poljubne datoteke na Outlyjev Cloudinary. Pricakovano:
 *   P1  podpis = sha1("folder=..&public_id=..&timestamp=.." + secret), public_id = <folder>/u<id>/<ts>-<hex>; podpisana so NATANKO
 *       polja, ki jih odjemalca (iOS, splet) posljeta Cloudinaryju - razsirjen podpis bi podrl nalaganje (Invalid Signature).
 *   P2  meja na UPORABNIKA (PODPIS_CLOUDINARY_NA_URO): N+1. podpis -> 429 + Retry-After; stara pot GET /cloudinary/signature
 *       deli isto mejo; isti uporabnik z drugega IP-ja -> se vedno 429; drug uporabnik z istega IP-ja -> 200. Na stari kodi PADE.
 *   P3  privzeta meja 60/h: 60 podpisov gre skozi, 61. -> 429. Brez zetona 401 (omejevalnik ne steje anonimnih).
 * Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL=postgres://postgres:postgres@localhost:5432/outly node _testi/test_cloudinary_podpis.js
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3433, JWKS_PORT = 3434;
const BASE = `http://127.0.0.1:${PORT}`;
const SECRET = "testna-skrivnost-cloudinary";

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-cloudinary";
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
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra).slice(0, 400) : ""); } }
async function api(method, path, token, ip = "10.9.0.1") {
  const r = await fetch(BASE + path, { method, headers: { "x-forwarded-for": ip, ...(token ? { authorization: "Bearer " + token } : {}) }, signal: AbortSignal.timeout(15000) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, retryAfter: r.headers.get("retry-after") };
}

let srv = null;
(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  async function zagon(okolje = {}) {
    srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test", REZERVACIJE_CISCENJE_MS: "0",
      CLOUDINARY_CLOUD_NAME: "outly-test", CLOUDINARY_API_KEY: "123456", CLOUDINARY_API_SECRET: SECRET, CLOUDINARY_FOLDER: "outly", ...okolje }, stdio: ["ignore", "pipe", "pipe"] });
    srv.stdout.on("data", () => {}); srv.stderr.on("data", () => {});
    for (let i = 0; i < 100; i++) { try { await fetch(BASE + "/"); return; } catch { await new Promise(r => setTimeout(r, 100)); } }
    throw new Error("backend se ni zagnal");
  }
  async function ustavi() { if (!srv) return; const s = srv; srv = null; if (s.exitCode !== null) return; await new Promise(r => { s.once("exit", r); s.kill(); }); }

  const T = { ana: zeton("ana@outly.si", uuid(1)), bor: zeton("bor@outly.si", uuid(2)), cene: zeton("cene@outly.si", uuid(3)) };

  // ---------------------------------------------------------------- P1 + P2
  await zagon({ PODPIS_CLOUDINARY_NA_URO: "5" });
  for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
  const anaId = (await pool.query("SELECT id FROM users WHERE email='ana@outly.si'")).rows[0].id;

  console.log("\n# P1: vsebina podpisa (natanko polja, ki jih posljeta odjemalca)");
  let r = await api("POST", "/uploads/cloudinary-signature", T.ana);
  assert(r.status === 200, "POST /uploads/cloudinary-signature -> 200", r);
  const p = r.body;
  assert(p.cloudName === "outly-test" && p.apiKey === "123456" && p.folder === "outly" && Number.isInteger(p.timestamp), "odgovor: cloudName, apiKey, folder, timestamp", p);
  assert(new RegExp(`^outly/u${anaId}/${p.timestamp}-[0-9a-f]{8}$`).test(p.publicId), "public_id je vezan na uporabnika in cas", p.publicId);
  const pricakovan = crypto.createHash("sha1").update(`folder=${p.folder}&public_id=${p.publicId}&timestamp=${p.timestamp}${SECRET}`).digest("hex");
  assert(p.signature === pricakovan, "podpis = sha1(folder, public_id, timestamp + secret): odjemalca posljeta natanko ta polja");
  assert(!("api_secret" in p) && !JSON.stringify(p).includes(SECRET), "skrivnost ni v odgovoru");

  console.log("\n# P2: meja 5/h na uporabnika");
  for (let i = 2; i <= 5; i++) { r = await api(i % 2 ? "POST" : "GET", i % 2 ? "/uploads/cloudinary-signature" : "/cloudinary/signature", T.ana); if (r.status !== 200) break; }
  assert(r.status === 200, "podpisi 2-5 (obe poti) -> 200", r);
  r = await api("POST", "/uploads/cloudinary-signature", T.ana);
  assert(r.status === 429 && Number(r.retryAfter) > 0, "6. podpis -> 429 + Retry-After", r);
  r = await api("GET", "/cloudinary/signature", T.ana);
  assert(r.status === 429, "stara pot GET /cloudinary/signature deli isto mejo -> 429", r);
  r = await api("POST", "/uploads/cloudinary-signature", T.ana, "10.9.77.5");
  assert(r.status === 429, "isti uporabnik z drugega IP-ja -> se vedno 429 (meja na uporabnika, ne na IP)", r);
  r = await api("POST", "/uploads/cloudinary-signature", T.bor);
  assert(r.status === 200, "drug uporabnik z istega IP-ja -> 200 (NAT kluba ne deli meje)", r);
  r = await api("POST", "/uploads/cloudinary-signature", null);
  assert(r.status === 401, "brez zetona -> 401", r);
  await ustavi();

  // ---------------------------------------------------------------- P3
  console.log("\n# P3: privzeta meja 60/h");
  await zagon();
  let uspesnih = 0;
  for (let i = 0; i < 60; i++) { r = await api("POST", "/uploads/cloudinary-signature", T.cene); if (r.status === 200) uspesnih++; }
  assert(uspesnih === 60, `60 podpisov v uri -> vsi 200 (${uspesnih})`);
  r = await api("POST", "/uploads/cloudinary-signature", T.cene);
  assert(r.status === 429, "61. podpis -> 429", r);
  await ustavi();

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  jwksServer.close(); await pool.end();
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); if (srv) srv.kill(); process.exit(1); });
