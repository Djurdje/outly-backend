#!/usr/bin/env node
/**
 * Test cenika bara (migracija 014) in galerije/videa (015). Zagon (lokalno, PG16 na 5433, baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres@localhost:5433/outly?host=/tmp/pg" node _testi/test_cenik.js
 * Vzorec kot test_vabila.js: lokalni JWKS (3999), backend na 3113.
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3113, JWKS_PORT = 3999;
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

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  const T = { lastnik: zeton("lastnik@outly.si", uuid(1)), ana: zeton("ana@outly.si", uuid(2)), gost: zeton("gost@outly.si", uuid(3)) };
  for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
  await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana')");
  await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, (SELECT id FROM users WHERE email='ana@outly.si'), 'doorman')");

  console.log("\n# Privzeto");
  let r = await api("GET", "/clubs/1");
  assert(r.status === 200 && Array.isArray(r.body.bar_prices) && r.body.bar_prices.length === 0, "GET /clubs/:id vrne bar_prices = []", r.body.bar_prices);
  r = await api("GET", "/clubs");
  assert(r.status === 200 && Array.isArray(r.body[0].bar_prices), "GET /clubs vrne bar_prices", r.body[0]);
  r = await api("GET", "/business/clubs/me", T.lastnik);
  assert(r.status === 200 && Array.isArray(r.body.bar_prices), "GET /business/clubs/me vrne bar_prices", r.body);

  console.log("\n# Shranjevanje");
  const cenik = [
    { name: "Laško 0,5 l", price_cents: 400, category: "Beer" },
    { name: "  Union 0,3 l ", priceCents: 350, category: "Beer" },
    { name: "Gin tonic", price_cents: 800, category: "Cocktails" },
    { name: "Voda", price_cents: 0 },
  ];
  r = await api("PATCH", "/business/clubs/me", T.lastnik, { barPrices: cenik });
  assert(r.status === 200, "PATCH barPrices -> 200", r.body);
  assert(r.body.bar_prices.length === 4 && r.body.bar_prices[1].name === "Union 0,3 l" && r.body.bar_prices[1].price_cents === 350, "imena ociscena, priceCents -> price_cents", r.body.bar_prices);
  assert(r.body.bar_prices[3].category === undefined, "postavka brez kategorije nima kljuca category", r.body.bar_prices[3]);
  r = await api("GET", "/clubs/1");
  assert(r.body.bar_prices.length === 4 && r.body.bar_prices[2].name === "Gin tonic", "javno vidno v istem vrstnem redu", r.body.bar_prices);
  r = await api("PATCH", "/business/clubs/me", T.lastnik, { bar_prices: [{ name: "Kava", price_cents: 200 }] });
  assert(r.status === 200 && r.body.bar_prices.length === 1, "snake_case bar_prices zamenja cel seznam", r.body.bar_prices);
  r = await api("PATCH", "/business/clubs/me", T.lastnik, { description: "Nov opis" });
  assert(r.status === 200 && r.body.bar_prices.length === 1 && r.body.description === "Nov opis", "PATCH brez barPrices cenika ne dotakne", r.body);
  r = await api("PATCH", "/business/clubs/me", T.lastnik, { barPrices: [] });
  assert(r.status === 200 && r.body.bar_prices.length === 0, "prazen seznam = brez cenika", r.body.bar_prices);

  console.log("\n# Napacni vhodi");
  r = await api("PATCH", "/business/clubs/me", T.lastnik, { barPrices: "pivo 4" });
  assert(r.status === 400, "niz namesto seznama -> 400", r.status);
  r = await api("PATCH", "/business/clubs/me", T.lastnik, { barPrices: [{ name: "", price_cents: 100 }] });
  assert(r.status === 400, "prazno ime -> 400", r.status);
  r = await api("PATCH", "/business/clubs/me", T.lastnik, { barPrices: [{ name: "Pivo", price_cents: 4.5 }] });
  assert(r.status === 400, "cena s plavajoco vejico -> 400", r.status);
  r = await api("PATCH", "/business/clubs/me", T.lastnik, { barPrices: [{ name: "Pivo", price_cents: -1 }] });
  assert(r.status === 400, "negativna cena -> 400", r.status);
  r = await api("PATCH", "/business/clubs/me", T.lastnik, { barPrices: [{ name: "Pivo" }] });
  assert(r.status === 400, "brez cene -> 400", r.status);
  r = await api("PATCH", "/business/clubs/me", T.lastnik, { barPrices: ["Pivo"] });
  assert(r.status === 400, "niz kot postavka -> 400", r.status);
  r = await api("PATCH", "/business/clubs/me", T.lastnik, { barPrices: Array.from({ length: 61 }, (_, i) => ({ name: "P" + i, price_cents: 100 })) });
  assert(r.status === 400, "61 postavk -> 400", r.status);
  r = await api("PATCH", "/business/clubs/me", T.lastnik, { barPrices: [{ name: "X".repeat(61), price_cents: 100 }] });
  assert(r.status === 400, "ime 61 znakov -> 400", r.status);
  r = await api("GET", "/clubs/1");
  assert(r.body.bar_prices.length === 0, "po napakah cenik nespremenjen", r.body.bar_prices);

  console.log("\n# Galerija in video (migracija 015)");
  r = await api("GET", "/clubs/1");
  assert(Array.isArray(r.body.gallery_urls) && r.body.gallery_urls.length === 0 && r.body.video_url === "", "privzeto gallery_urls=[] video_url=''", r.body);
  r = await api("PATCH", "/business/clubs/me", T.lastnik, { galleryUrls: ["https://res.cloudinary.com/a/1.jpg", " https://res.cloudinary.com/a/2.jpg ", ""], videoUrl: "https://res.cloudinary.com/a/v.mp4" });
  assert(r.status === 200 && r.body.gallery_urls.length === 2 && r.body.gallery_urls[1] === "https://res.cloudinary.com/a/2.jpg" && r.body.video_url === "https://res.cloudinary.com/a/v.mp4", "PATCH galleryUrls (prazni preskoceni, trim) + videoUrl", r.body);
  r = await api("GET", "/clubs");
  assert(r.body[0].gallery_urls.length === 2, "GET /clubs vraca gallery_urls", r.body[0]);
  r = await api("PATCH", "/business/clubs/me", T.lastnik, { galleryUrls: ["https://a/1.jpg","https://a/2.jpg","https://a/3.jpg","https://a/4.jpg"] });
  assert(r.status === 400, "4 slike -> 400", r.status);
  r = await api("PATCH", "/business/clubs/me", T.lastnik, { galleryUrls: ["http://a/1.jpg"] });
  assert(r.status === 400, "http (ne https) -> 400", r.status);
  r = await api("PATCH", "/business/clubs/me", T.lastnik, { videoUrl: "javascript:alert(1)" });
  assert(r.status === 400, "videoUrl brez https -> 400", r.status);
  r = await api("PATCH", "/business/clubs/me", T.lastnik, { videoUrl: "", galleryUrls: [] });
  assert(r.status === 200 && r.body.video_url === "" && r.body.gallery_urls.length === 0, "prazno = odstrani", r.body);

  console.log("\n# Pravice");
  r = await api("PATCH", "/business/clubs/me", T.ana, { barPrices: [{ name: "Pivo", price_cents: 100 }] });
  assert(r.status === 403, "vratar ne more urejati -> 403", r.status);
  r = await api("PATCH", "/business/clubs/me", T.gost, { barPrices: [{ name: "Pivo", price_cents: 100 }] });
  assert(r.status === 403 || r.status === 404, "navaden uporabnik -> 403/404", r.status);
  r = await api("PATCH", "/business/clubs/me", null, { barPrices: [] });
  assert(r.status === 401, "brez zetona -> 401", r.status);

  srv.kill(); jwksServer.close(); await pool.end();
  const napake = log.split("\n").filter(l => /error|TypeError|Unhandled/i.test(l) && !/Server error\./.test(l));
  if (napake.length) console.log("\nLog backenda (sumljivo):\n" + napake.join("\n"));
  console.log(`\n${ok} OK, ${fail} napak`);
  process.exit(fail ? 1 : 0);
})();
