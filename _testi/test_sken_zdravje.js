#!/usr/bin/env node
/**
 * skenPool: GET /healthz/sken in odjemalski rok poizvedbe (`query_timeout`, #265).
 * Zagon (lokalno, PG16):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_sken_zdravje.js
 *
 *   H1  GET /healthz/sken brez zetona: 200 { ok: true } (samo `ok`), Cache-Control no-store; povezave skenPool imajo jit=off.
 *   H2  baza nedosegljiva: 503 { ok: false } v < 5 s, proces tece.
 *   H3  zloraba: 60 hkratnih + 60 zaporednih klicev -> baza dobi najvec nekaj SELECT 1 (ena preverba naenkrat, rezultat velja 1 s).
 *   H4  pooler zavrne zagonski parameter `options` (posrednik posnema PgBouncer): /healthz 200, /healthz/sken 503, glavni pool 5xx.
 *   Q1  polodprt TCP (posrednik neha posredovati, povezava ostane odprta) na IZPOSOJENI povezavi skenPool:
 *       sken (POST /business/tickets/scan) dobi 503 + Retry-After v roku query_timeout (ne visi), po okrevanju omrezja spet dela
 *       (obvisela povezava je zavrzena, ne vrnjena v pool). Na kodi brez query_timeout sken visi in skenPool (max 1) ostane mrtev.
 *   Q2  query_timeout ni nikoli ozji od najvecje streznisko meje skenPool + 2 s (scan-list ne sme pasti zaradi odjemalskega roka).
 */
const crypto = require("crypto");
const http = require("http");
const net = require("net");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const JWKS_PORT = 3492;
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra).slice(0, 400) : ""); } }
const spi = (ms) => new Promise((r) => setTimeout(r, ms));

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-sken-zdravje";
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

async function zazeni(port, dbUrl, dodatniEnv = {}) {
  const srv = spawn("node", ["index.js"], { env: { ...process.env, REZERVACIJE_CISCENJE_MS: "0", PORT: String(port), DATABASE_URL: dbUrl,
    SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test", ...dodatniEnv }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", (d) => log += d); srv.stderr.on("data", (d) => log += d);
  for (let i = 0; i < 100; i++) { try { await fetch(`http://127.0.0.1:${port}/`); break; } catch { await spi(100); } }
  return { srv, log: () => log, ustavi: () => new Promise((r) => { if (srv.exitCode !== null) return r(); srv.once("exit", r); srv.kill(); }) };
}
async function klic(port, method, pot, token, body, rokMs = 15000) {
  const t0 = Date.now();
  try {
    const r = await fetch(`http://127.0.0.1:${port}${pot}`, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) },
      body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(rokMs) });
    const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
    return { status: r.status, body: j, ms: Date.now() - t0, cache: r.headers.get("cache-control"), retryAfter: r.headers.get("retry-after") };
  } catch (e) { return { status: "visi", body: String(e.message), ms: Date.now() - t0 }; }
}

// TCP posrednik pred bazo. `zamrznjeno` odvrze ves promet v obe smeri, povezave ostanejo odprte (polodprt TCP, izgubljeni paketi).
// `zavrniOptions` posnema pooler (PgBouncer brez ignore_startup_parameters): zagonski paket s parametrom `options` zavrne s FATAL.
// Steje stavke "SELECT 1" (protokol v3: 'Q' preprost stavek, 'P' Parse), ki jih backend poslje bazi.
function posrednik() {
  const st = { zamrznjeno: false, zavrniOptions: false, select1: 0, zavrnjenih: 0 };
  const srvP = net.createServer((odj) => {
    const u = new URL(DB);
    const gor = net.connect(Number(u.port) || 5432, u.hostname);
    let buf = Buffer.alloc(0), zagon = true;
    odj.on("data", (d) => {
      if (st.zamrznjeno) return;
      buf = Buffer.concat([buf, d]);
      if (zagon) {
        if (buf.length < 8 || buf.length < buf.readInt32BE(0)) return;   // zagonski paket se ni cel: ne posreduj
        const n = buf.readInt32BE(0);
        const deli = buf.subarray(8, n).toString("utf8").split("\0"); const par = {};
        for (let i = 0; i + 1 < deli.length; i += 2) if (deli[i]) par[deli[i]] = deli[i + 1];
        if (st.zavrniOptions && par.options) {
          st.zavrnjenih++;
          const polja = Buffer.from("SFATAL\0C08P01\0Munsupported startup parameter: options\0\0", "utf8");
          const e = Buffer.alloc(5); e[0] = 0x45; e.writeInt32BE(4 + polja.length, 1);
          odj.end(Buffer.concat([e, polja])); gor.destroy(); return;
        }
        gor.write(buf); buf = buf.subarray(n); zagon = false;
      } else gor.write(d);
      for (;;) {
        if (buf.length < 5) break;
        const n = buf.readInt32BE(1); if (buf.length < n + 1) break;
        if ((buf[0] === 0x51 || buf[0] === 0x50) && /SELECT 1(\0|$)/.test(buf.subarray(5, n + 1).toString("utf8"))) st.select1++;
        buf = buf.subarray(n + 1);
      }
    });
    gor.on("data", (d) => { if (!st.zamrznjeno) odj.write(d); });
    for (const x of [odj, gor]) { x.on("error", () => {}); x.on("close", () => { odj.destroy(); gor.destroy(); }); }
  });
  return new Promise((r) => srvP.listen(0, "127.0.0.1", () => {
    const u = new URL(DB); u.hostname = "localhost"; u.port = String(srvP.address().port);
    r({ url: u.toString(), st, zapri: () => srvP.close() });
  }));
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, table_service, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise((r) => jwksServer.listen(JWKS_PORT, r));

  // ---------------------------------------------------------------- H1
  console.log("# H1: GET /healthz/sken");
  let b = await zazeni(3493, DB);
  try {
    const r = await klic(3493, "GET", "/healthz/sken");
    assert(r.status === 200, "GET /healthz/sken brez zetona -> 200", r);
    assert(r.body && r.body.ok === true && Object.keys(r.body).join() === "ok", "telo je samo { ok: true } (brez podatkov)", r.body);
    assert(r.cache === "no-store", "Cache-Control: no-store", r.cache);
    assert(/\[skenPool\] .*query_timeout 12000 ms, jit=off/.test(b.log()), "zagon izpise query_timeout 12000 ms (privzeto) in jit=off", b.log().split("\n").find((l) => l.includes("[skenPool]")));
  } finally { await b.ustavi(); }

  // ---------------------------------------------------------------- Q2
  console.log("\n# Q2: query_timeout nikoli ozji od meje stavka + 2 s");
  b = await zazeni(3493, DB, { PG_SKEN_QUERY_TIMEOUT_MS: "1000" });
  try {
    assert(/\[skenPool\] .*query_timeout 12000 ms/.test(b.log()), "PG_SKEN_QUERY_TIMEOUT_MS=1000 pri scan-list 10 s -> 12000 ms", b.log().split("\n").find((l) => l.includes("[skenPool]")));
  } finally { await b.ustavi(); }
  b = await zazeni(3493, DB, { PG_SKEN_QUERY_TIMEOUT_MS: "1000", PG_SKEN_SEZNAM_STATEMENT_TIMEOUT_MS: "20000" });
  try {
    assert(/\[skenPool\] .*query_timeout 22000 ms/.test(b.log()), "scan-list 20 s -> query_timeout 22000 ms", b.log().split("\n").find((l) => l.includes("[skenPool]")));
  } finally { await b.ustavi(); }

  // ---------------------------------------------------------------- H2
  console.log("\n# H2: baza nedosegljiva");
  b = await zazeni(3494, "postgres://postgres:postgres@localhost:1/outly");
  try {
    const r = await klic(3494, "GET", "/healthz/sken");
    assert(r.status === 503 && r.body && r.body.ok === false, "GET /healthz/sken -> 503 { ok: false }", r);
    assert(r.ms < 5000, "odgovor v < 5 s (ne visi)", r.ms);
    const r2 = await klic(3494, "GET", "/");
    assert(r2.status === 200, "proces tece", r2.status);
  } finally { await b.ustavi(); }

  // ---------------------------------------------------------------- H3
  console.log("\n# H3: zloraba ne izcrpa skenPool");
  let pp = await posrednik();
  b = await zazeni(3495, pp.url);
  try {
    pp.st.select1 = 0;
    const hkrati = await Promise.all(Array.from({ length: 60 }, () => klic(3495, "GET", "/healthz/sken")));
    assert(hkrati.every((r) => r.status === 200), "60 hkratnih klicev: vsi 200", hkrati.map((r) => r.status).filter((s) => s !== 200));
    assert(pp.st.select1 === 1, `60 hkratnih klicev -> 1 SELECT 1 v bazi (izmerjeno ${pp.st.select1})`);
    pp.st.select1 = 0;
    const t0 = Date.now();
    for (let i = 0; i < 60; i++) await klic(3495, "GET", "/healthz/sken");
    const sekund = (Date.now() - t0) / 1000;
    assert(pp.st.select1 <= Math.ceil(sekund) + 1, `60 zaporednih klicev v ${sekund.toFixed(1)} s -> ${pp.st.select1} SELECT 1 (najvec 1 na s)`);
  } finally { await b.ustavi(); pp.zapri(); }

  // ---------------------------------------------------------------- H4
  console.log("\n# H4: pooler zavrne zagonski parameter options -> /healthz ostane 200, /healthz/sken 503");
  pp = await posrednik();
  pp.st.zavrniOptions = true;
  b = await zazeni(3496, pp.url, { PGOPTIONS: "" });
  try {
    const h = await klic(3496, "GET", "/healthz");
    const s = await klic(3496, "GET", "/healthz/sken");
    assert(h.status === 200, "/healthz (zdraviPool brez options) -> 200: Render health check tega NE vidi", h);
    assert(s.status === 503 && s.body && s.body.ok === false, "/healthz/sken -> 503 { ok: false }: Nadzor to ujame", s);
    assert(pp.st.zavrnjenih >= 1, `posrednik je zavrnil povezavo z options (${pp.st.zavrnjenih})`);
    const g = await klic(3496, "GET", "/events");
    assert(g.status >= 500, `glavni pool (jit=off v options) pade enako (GET /events ${g.status})`, g.status);
  } finally { await b.ustavi(); pp.zapri(); }

  // ---------------------------------------------------------------- Q1
  console.log("\n# Q1: polodprt TCP na izposojeni povezavi skenPool -> 503 v roku, nato okrevanje");
  // Meje stavkov na 1 s -> query_timeout = max(1, 1000 + 2000) = 3000 ms. PG_SKEN_POOL_MAX=1: ena obvisela povezava = mrtev sken.
  const QT = 3000;
  pp = await posrednik();
  b = await zazeni(3497, pp.url, { PG_SKEN_POOL_MAX: "1", PG_SKEN_STATEMENT_TIMEOUT_MS: "1000", PG_SKEN_SEZNAM_STATEMENT_TIMEOUT_MS: "1000",
    PG_SKEN_QUERY_TIMEOUT_MS: process.env.TEST_SKEN_QUERY_TIMEOUT_MS || "1" });
  try {
    assert(/\[skenPool\] .*query_timeout 3000 ms/.test(b.log()) || process.env.TEST_SKEN_QUERY_TIMEOUT_MS, "query_timeout 3000 ms", b.log().split("\n").find((l) => l.includes("[skenPool]")));
    const T = zeton("lastnik@outly.si", "00000000-0000-4000-8000-000000000001");
    let r = await klic(3497, "GET", "/me", T);
    assert(r.status === 200, "GET /me (ustvari uporabnika)", r);
    // Ogrej skenPool: povezava je odprta in mirujoca, naslednji sken jo izposodi (zamrznitev zadene POIZVEDBO, ne vzpostavitve).
    r = await klic(3497, "POST", "/business/tickets/scan", T, { qr: "neveljavna" });
    assert(typeof r.status === "number" && r.status < 500, `sken pred zamrznitvijo odgovori (${r.status})`, r);
    pp.st.zamrznjeno = true;
    r = await klic(3497, "POST", "/business/tickets/scan", T, { qr: "neveljavna" }, QT + 6000);
    assert(r.status === 503, "zamrznjena povezava: sken -> 503 (ne visi)", r);
    assert(r.retryAfter === "5", "Retry-After: 5", r.retryAfter);
    assert(r.status === 503 && r.ms >= QT - 200 && r.ms < QT + 1500, `503 po roku query_timeout (${r.ms} ms, rok ${QT} ms)`, r.ms);
    pp.st.zamrznjeno = false;
    // Obvisela povezava je zavrzena: naslednji sken odpre novo in uspe. Brez query_timeout bi ostala izposojena za vedno.
    let r2 = null;
    for (let i = 0; i < 10; i++) { r2 = await klic(3497, "POST", "/business/tickets/scan", T, { qr: "neveljavna" }, 8000); if (typeof r2.status === "number" && r2.status < 500) break; await spi(300); }
    assert(r2 && typeof r2.status === "number" && r2.status < 500, `po okrevanju omrezja sken spet odgovori (${r2 && r2.status}, ne 503/visi)`, r2);
    const h = await klic(3497, "GET", "/healthz/sken");
    assert(h.status === 200, "po okrevanju /healthz/sken 200", h);
    assert(/query read timeout/i.test(b.log()), "dnevnik: Query read timeout", b.log().slice(-600));
  } finally { await b.ustavi(); pp.zapri(); }

  console.log(`\n${ok} ok, ${fail} napak`);
  jwksServer.close(); await pool.end();
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
