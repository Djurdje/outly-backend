#!/usr/bin/env node
/**
 * Izbris racuna za racun brez gesla (Google/Apple), DELETE /me { reauth: "provider" } (14. 11. 2026; ARCHITECTURE »Prijava z Googlom in Applom« tocka 8, I73).
 * Zagon: DATABASE_URL="postgres://postgres@localhost:5446/postgres" node _testi/test_izbris_ponudnik.js
 *
 * Lazni »Supabase« (JWKS, /auth/v1/user, /auth/v1/settings, /auth/v1/token?grant_type=password, /rest/v1/rpc/delete_my_account) na 3364, backend na 3363.
 * Oblika `amr` po supabase/auth (models/sessions.go:72-76 AMREntry {method, timestamp, provider?}; timestamp = updated_at zahtevka v mfa_amr_claims, ki ga
 * osvezitev zetona NE spremeni; `id_token` in PKCE prijava zapisujeta method "oauth", models/amr.go + token_oidc.go:346, external.go:109).
 * Varovalo: ukraden zeton (velja do ure) sam ne sme zadostovati za nepovraten izbris -> amr oauth mora biti mlajsi od 300 s.
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3363, STUB_PORT = 3364;
const BASE = `http://127.0.0.1:${PORT}`;
const kp = () => crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const { publicKey, privateKey } = kp();
const tuj = kp();
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-izbris";

const stub = { rpc: 0, geslo: 0, gesloOdgovor: 200 };
const stubServer = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url.startsWith("/auth/v1/user")) {
    let sub = "?", email = "?";
    try { const p = JSON.parse(Buffer.from(String(req.headers.authorization || "").split(".")[1], "base64url")); sub = p.sub; email = p.email; } catch (_) {}
    return res.end(JSON.stringify({ id: sub, email, email_confirmed_at: "2026-11-14T10:00:00Z" }));
  }
  if (req.url.startsWith("/auth/v1/settings")) return res.end(JSON.stringify({ mailer_autoconfirm: false, external: { anonymous_users: false } }));
  if (req.url.startsWith("/auth/v1/token")) { stub.geslo++; res.statusCode = stub.gesloOdgovor; return res.end("{}"); }
  if (req.url.startsWith("/rest/v1/rpc/delete_my_account")) { stub.rpc++; return res.end("{}"); }
  res.end(JSON.stringify({ keys: [{ ...jwk, kid: KID, alg: "ES256", use: "sig" }] }));
});

const b64u = (o) => Buffer.from(typeof o === "string" ? o : JSON.stringify(o)).toString("base64url");
function zeton(sub, email, amr, kljuc = privateKey) {
  const now = Math.floor(Date.now() / 1000);
  const h = b64u({ alg: "ES256", typ: "JWT", kid: KID });
  const p = b64u({ iss: `http://127.0.0.1:${STUB_PORT}/auth/v1`, aud: "authenticated", sub, email, role: "authenticated", exp: now + 3600, iat: now,
    app_metadata: { provider: "google", providers: ["google"] }, user_metadata: { email_verified: true }, amr, is_anonymous: false });
  const sig = crypto.sign("sha256", Buffer.from(h + "." + p), { key: kljuc, dsaEncoding: "ieee-p1363" });
  return h + "." + p + "." + sig.toString("base64url");
}
const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const zdaj = () => Math.floor(Date.now() / 1000);
const oauth = (pred) => [{ method: "oauth", timestamp: zdaj() - pred }];

let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise((r) => stubServer.listen(STUB_PORT, r));
  let log = "";
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${STUB_PORT}`,
    SUPABASE_PUBLISHABLE_KEY: "sb_publishable_testni_kljuc", RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  srv.stdout.on("data", (d) => log += d); srv.stderr.on("data", (d) => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise((r) => setTimeout(r, 100)); } }

  const api = async (method, path, token, body) => {
    await pool.query("TRUNCATE omejitve");   // omejevalnik DELETE /me: 5 na uro
    const r = await fetch(BASE + path, { method, headers: { authorization: "Bearer " + token, ...(body !== undefined ? { "content-type": "application/json" } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
    const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
    return { status: r.status, body: j };
  };
  // Nov Google racun: prvi GET /me ustvari vrstico.
  const racun = async (n, amr) => {
    const email = `u${n}@gmail.com`, sub = uuid(n);
    const r = await api("GET", "/me", zeton(sub, email, amr));
    if (r.status !== 200) throw new Error("GET /me " + JSON.stringify(r));
    return { sub, email, id: r.body.id };
  };
  const obstaja = async (id) => (await pool.query("SELECT 1 FROM users WHERE id=$1", [id])).rows.length === 1;
  const reset = () => { stub.rpc = 0; stub.geslo = 0; stub.gesloOdgovor = 200; };

  console.log("\n# (1) svez amr oauth + { reauth: \"provider\" } -> izbris kot pri geslu");
  reset();
  let u = await racun(1, oauth(20));
  let r = await api("DELETE", "/me", zeton(u.sub, u.email, oauth(20)), { reauth: "provider" });
  assert(r.status === 200 && r.body.message === "Account deleted.", "200 Account deleted.", r);
  assert(!(await obstaja(u.id)), "vrstica users izbrisana");
  assert(stub.rpc === 1 && stub.geslo === 0, "Supabase delete_my_account poklican enkrat, grant_type=password NE", { rpc: stub.rpc, geslo: stub.geslo });

  console.log("\n# (2) star amr oauth (> 300 s) -> 401 reauth_required, nic izbrisanega");
  reset();
  u = await racun(2, oauth(20));
  r = await api("DELETE", "/me", zeton(u.sub, u.email, oauth(3600)), { reauth: "provider" });
  assert(r.status === 401 && r.body.error === "reauth_required" && typeof r.body.message === "string", "401 { error: reauth_required, message }", r);
  assert(await obstaja(u.id) && stub.rpc === 0, "vrstica ostane, Supabase RPC ni poklican");
  r = await api("DELETE", "/me", zeton(u.sub, u.email, oauth(299)), { reauth: "provider" });
  assert(r.status === 200, "meja: 299 s star amr je se v redu", r);

  console.log("\n# (3) amr brez ponudnika ali neveljaven -> 401 reauth_required");
  reset();
  const primeri = [
    ["samo password (svez)", [{ method: "password", timestamp: zdaj() - 5 }]],
    ["svez token_refresh + star oauth", [{ method: "token_refresh", timestamp: zdaj() - 5 }, { method: "oauth", timestamp: zdaj() - 4000 }]],
    ["amr kot niz (stara oblika)", ["oauth"]],
    ["brez amr", undefined],
    ["timestamp v prihodnosti", [{ method: "oauth", timestamp: zdaj() + 3600 }]],
    ["timestamp kot niz", [{ method: "oauth", timestamp: String(zdaj()) }]],
    ["amr ni polje", { method: "oauth", timestamp: zdaj() }],
  ];
  let n = 10;
  for (const [ime, amr] of primeri) {
    u = await racun(n++, oauth(20));
    r = await api("DELETE", "/me", zeton(u.sub, u.email, amr), { reauth: "provider" });
    assert(r.status === 401 && r.body.error === "reauth_required" && await obstaja(u.id), `${ime}: 401 reauth_required, vrstica ostane`, r);
  }
  assert(stub.rpc === 0, "noben od teh ni poklical Supabase RPC");

  console.log("\n# (4) brez gesla in brez reauth -> 400 (obstojece besedilo); neznan reauth -> 400");
  u = await racun(30, oauth(5));
  r = await api("DELETE", "/me", zeton(u.sub, u.email, oauth(5)), {});
  assert(r.status === 400 && /Password required/.test(String(r.body)), "prazno telo -> 400 Password required to delete account.", r);
  r = await api("DELETE", "/me", zeton(u.sub, u.email, oauth(5)), { reauth: "password" });
  assert(r.status === 400, "reauth ≠ provider -> 400", r);
  r = await api("DELETE", "/me", zeton(u.sub, u.email, [{ method: "password", timestamp: zdaj() }]), { reauth: ["provider"] });
  assert(r.status === 400 && await obstaja(u.id), "reauth ni niz -> 400", r);

  console.log("\n# (5) pot z geslom je nespremenjena (star odjemalec; povezan racun z geslom ne rabi amr)");
  reset();
  u = await racun(40, [{ method: "password", timestamp: zdaj() - 99999 }]);
  r = await api("DELETE", "/me", zeton(u.sub, u.email, undefined), { password: "pravo" });
  assert(r.status === 200 && stub.geslo === 1 && stub.rpc === 1 && !(await obstaja(u.id)), "geslo -> 200, preverjeno pri Supabase", { r, geslo: stub.geslo });
  u = await racun(41, oauth(5));
  stub.gesloOdgovor = 400;
  r = await api("DELETE", "/me", zeton(u.sub, u.email, oauth(5)), { password: "napacno", reauth: "provider" });
  assert(r.status === 401 && r.body !== null && await obstaja(u.id), "napacno geslo (tudi s svezim amr in reauth): 401 Invalid credentials, vrstica ostane (geslo ima prednost)", r);

  console.log("\n# (6) ponarejen amr: podpis zetona ostane edini dokaz");
  reset();
  u = await racun(50, oauth(20));
  r = await api("DELETE", "/me", zeton(u.sub, u.email, oauth(0), tuj.privateKey), { reauth: "provider" });
  assert(r.status === 401 && await obstaja(u.id), "zeton s tujim kljucem -> 401", r);
  const dober = zeton(u.sub, u.email, oauth(3600)).split(".");
  const nov = [dober[0], b64u({ ...JSON.parse(Buffer.from(dober[1], "base64url")), amr: oauth(0) }), dober[2]].join(".");
  r = await api("DELETE", "/me", nov, { reauth: "provider" });
  assert(r.status === 401 && await obstaja(u.id) && stub.rpc === 0, "spremenjen amr brez ponovnega podpisa -> 401", r);

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  if (fail) console.log("\n--- log streznika ---\n" + log);
  srv.kill(); stubServer.closeAllConnections && stubServer.closeAllConnections(); stubServer.close(); await pool.end();
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
