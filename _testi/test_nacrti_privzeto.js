#!/usr/bin/env node
/**
 * »Prijatelji vidijo moje nacrte« je privzeto IZKLOPLJENO za NOVE uporabnike (migracija 045, I11; Martin 12. 10. 2026, izbira priporocila a).
 * Privolitev (politika zasebnosti) zahteva pritrdilno dejanje. Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_nacrti_privzeto.js
 * Vzorec kot test_prijatelji.js: lokalni JWKS (ES256), backend na svojem portu, testni nacin placila.
 *
 *   1  nov uporabnik (prvi klic /me): share_plans_with_friends = false; privzetek v bazi je false (tudi za vrstico, vstavljeno mimo kode)
 *   2  prijatelji NE vidijo nacrtov novega uporabnika (GET /events/:id friends_going/friends_interested, GET /me/friends/plans)
 *   3  pritrdilno dejanje: PATCH /me { share_plans_with_friends: true } -> prijatelj ga vidi; ponoven izklop -> spet ne
 *   4  obstojeca vrstica z vrednostjo true ostane true (privzetek velja samo za nove vrstice)
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3305, JWKS_PORT = 3306;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-nacrti";
const jwksServer = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url.startsWith("/auth/v1/user")) { try { const t = JSON.parse(Buffer.from(String(req.headers.authorization).split(".")[1], "base64url")); return res.end(JSON.stringify({ id: t.sub, email: t.email, email_confirmed_at: "2026-01-01T00:00:00Z" })); } catch (_) { res.statusCode = 401; return res.end("{}"); } }   // potrditev e-naslova pri viru (#222): stub potrdi vsak naslov iz zetona
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
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra).slice(0, 300) : ""); } }
async function api(method, p, token, body) {
  const r = await fetch(BASE + p, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, friend_requests, friendships, ticket_transfers, club_invites, club_members, event_favorites, event_interest, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test",
    STRIPE_SECRET_KEY: "", STRIPE_WEBHOOK_SECRET: "", TEST_PLACILA: "" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  try {
    const imena = ["lastnik", "ana", "bor", "cene"];
    const T = {};
    imena.forEach((k, i) => { T[k] = zeton(`${k}@outly.si`, uuid(i + 1)); });
    console.log("\n# 1. Nov uporabnik: deljenje nacrtov izklopljeno");
    for (const k of imena) {
      const r = await api("GET", "/me", T[k]);
      assert(r.status === 200 && r.body.share_plans_with_friends === false, `/me ${k}: share_plans_with_friends = false (prvi klic ustvari vrstico)`, r.body.share_plans_with_friends);
    }
    const def = (await pool.query("SELECT column_default FROM information_schema.columns WHERE table_name='users' AND column_name='share_plans_with_friends'")).rows[0].column_default;
    assert(def === "false", "privzetek stolpca v bazi je false", def);
    const mimo = (await pool.query("INSERT INTO users (email, username, email_verified) VALUES ('mimo@outly.si', 'mimo', true) RETURNING share_plans_with_friends")).rows[0];
    assert(mimo.share_plans_with_friends === false, "vrstica, vstavljena mimo kode (brez stolpca): false", mimo);

    console.log("\n# 2. Prijatelji nacrtov novega uporabnika ne vidijo");
    const id = {};
    for (const row of (await pool.query("SELECT id, email FROM users")).rows) id[row.email.split("@")[0]] = row.id;
    const par = (a, b) => (id[a] < id[b] ? [id[a], id[b]] : [id[b], id[a]]);
    for (const [a, b] of [["ana", "bor"], ["ana", "cene"]]) await pool.query("INSERT INTO friendships (user_a, user_b) VALUES ($1,$2)", par(a, b));
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ($1, 'Nacrti Club', 'Ljubljana')", [id.lastnik]);
    const cezTeden = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
    let r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Zabava", startAt: cezTeden, ticketPriceCents: 1000, capacity: 100, minAge: 0 });
    assert(r.status === 201, "dogodek ustvarjen", r.body);
    const ev = r.body.id;
    r = await api("POST", `/events/${ev}/orders`, T.bor, { quantity: 1 });
    assert(r.status === 201, "bor kupi vstopnico (going)", r.body);
    r = await api("PUT", `/events/${ev}/interest`, T.cene);
    assert(r.status === 200, "cene oznaci zanimanje (interested)", r.body);
    r = await api("GET", `/events/${ev}`, T.ana);
    assert(r.status === 200 && r.body.friends_going.length === 0 && r.body.friends_interested.length === 0, "ana: friends_going in friends_interested prazna (privzeto nic ne deli)", [r.body.friends_going, r.body.friends_interested]);
    r = await api("GET", "/me/friends/plans", T.ana);
    assert(r.status === 200 && r.body.events.length === 0, "ana: GET /me/friends/plans prazen", r.body);

    console.log("\n# 3. Pritrdilno dejanje vklopi deljenje");
    r = await api("PATCH", "/me", T.bor, { share_plans_with_friends: true });
    assert(r.status === 200 && r.body.share_plans_with_friends === true, "bor vklopi deljenje (PATCH /me)", r.body);
    r = await api("GET", `/events/${ev}`, T.ana);
    assert(r.body.friends_going.map(f => f.username).join(",") === "bor" && r.body.friends_interested.length === 0, "ana vidi bora (going); cene (se ni vklopil) ne", [r.body.friends_going, r.body.friends_interested]);
    r = await api("GET", "/me/friends/plans", T.ana);
    assert(r.body.events.length === 1 && r.body.events[0].friends.map(f => f.username).join(",") === "bor", "plans: samo bor", r.body);
    r = await api("PATCH", "/me", T.bor, { share_plans_with_friends: false });
    r = await api("GET", `/events/${ev}`, T.ana);
    assert(r.body.friends_going.length === 0, "ponoven izklop: bor spet ni viden", r.body.friends_going);

    console.log("\n# 4. Obstojeca vrstica z true ostane true");
    await pool.query("UPDATE users SET share_plans_with_friends = TRUE WHERE email='cene@outly.si'");   // posnema uporabnika iz casa pred 045
    const e = (await pool.query("SELECT share_plans_with_friends FROM users WHERE email='cene@outly.si'")).rows[0];
    r = await api("GET", "/me", T.cene);
    assert(e.share_plans_with_friends === true && r.body.share_plans_with_friends === true, "uporabnik, ki ima deljenje vklopljeno, ga ima se naprej (privzetek ne posega v obstojece)", r.body.share_plans_with_friends);
  } finally {
    try { srv.kill(); } catch {}
    jwksServer.close(); await pool.end().catch(() => {});
  }
  console.log(`\n${ok} OK, ${fail} NAPAK`);
  process.exit(fail === 0 ? 0 : 1);
})().catch(e => { console.error(e); process.exit(1); });
