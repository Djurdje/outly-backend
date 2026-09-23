#!/usr/bin/env node
/**
 * Test "I'm in" / zanimanja za dogodek (migracija 020): PUT/DELETE /events/:id/interest,
 * GET /events/:id (my_plan, friends_going, friends_interested), GET /me/friends/plans
 * (interested, my_plan, unija dogodkov) in GET /me/plans. Invarianta I11 (zasebnost).
 * Zagon (lokalno, PG16, baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_zanimanje.js
 * Vzorec kot test_prijatelji.js / test_sledenje.js: lokalni JWKS, backend na svojem portu.
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3117, JWKS_PORT = 3996;
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
  await pool.query("TRUNCATE event_interest, club_event_notifications, club_follows, club_invites, club_members, event_favorites, friendships, friend_requests, ticket_transfers, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  const T = {
    lastnik: zeton("lastnik@outly.si", uuid(1)),
    ana: zeton("ana@outly.si", uuid(2)),
    bor: zeton("bor@outly.si", uuid(3)),
    cene: zeton("cene@outly.si", uuid(4)),
    an_x: zeton("an_x@outly.si", uuid(5)),
  };
  for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
  const id = {};
  for (const row of (await pool.query("SELECT id, email FROM users")).rows) id[row.email.split("@")[0]] = row.id;

  await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ($1, 'Pure Club', 'Ljubljana')", [id.lastnik]);
  const polnoleten = new Date(Date.now() - 25 * 365.25 * 24 * 3600 * 1000).toISOString().slice(0, 10);
  for (const k of ["ana", "bor", "cene", "an_x"]) await api("PATCH", "/me", T[k], { dateOfBirth: polnoleten, genres: ["house"] });

  // ana <-> bor prijatelja, ana <-> cene prijatelja, an_x ni prijatelj z nikomer.
  async function sprijatelji(a, b) {
    const r = await api("POST", "/me/friends/requests", T[a], { user_id: id[b] });
    if (r.status === 201) await api("POST", `/me/friends/requests/${r.body.request.id}/accept`, T[b]);
  }
  await sprijatelji("ana", "bor");
  await sprijatelji("ana", "cene");

  const cezTeden = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
  let r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Zabava", startAt: cezTeden, ticketPriceCents: 1000, capacity: 100, minAge: 0 });
  assert(r.status === 201, "dogodek ustvarjen", r.body);
  const dogodek = r.body.id;

  await pool.query(`INSERT INTO events (club_id, title, start_at, end_at, status, sold_count) VALUES
    (1, 'koncan 10h', NOW() - INTERVAL '10 hours', NULL, 'published', 0)`);
  const koncanId = (await pool.query("SELECT id FROM events WHERE title='koncan 10h'")).rows[0].id;

  console.log("\n# PUT/DELETE /events/:id/interest — osnove in napake");
  r = await api("PUT", `/events/${dogodek}/interest`);
  assert(r.status === 401, "PUT brez zetona -> 401", r.status);
  r = await api("DELETE", `/events/${dogodek}/interest`);
  assert(r.status === 401, "DELETE brez zetona -> 401", r.status);
  r = await api("PUT", "/events/999999/interest", T.ana);
  assert(r.status === 404, "neobstojec dogodek -> 404", r.status);
  r = await api("PUT", `/events/${koncanId}/interest`, T.ana);
  assert(r.status === 409 && r.body.error === "event_ended", "koncan dogodek -> 409 event_ended", r.body);

  r = await api("PUT", `/events/${dogodek}/interest`, T.ana);
  assert(r.status === 200 && r.body.plan === "interested", "ana: PUT interest -> 200 plan interested", r.body);
  r = await api("PUT", `/events/${dogodek}/interest`, T.ana);
  assert(r.status === 200 && r.body.plan === "interested", "ponovni PUT je idempotenten", r.body);
  r = await api("DELETE", `/events/${dogodek}/interest`, T.ana);
  assert(r.status === 200 && r.body.plan === null, "DELETE -> 200 plan null", r.body);
  r = await api("DELETE", `/events/${dogodek}/interest`, T.ana);
  assert(r.status === 200 && r.body.plan === null, "ponovni DELETE brez napake", r.body);

  console.log("\n# GET /events/:id — my_plan, friends_going, friends_interested");
  r = await api("GET", `/events/${dogodek}`);
  assert(r.status === 200 && r.body.my_plan === null && Array.isArray(r.body.friends_going) && r.body.friends_going.length === 0
    && Array.isArray(r.body.friends_interested) && r.body.friends_interested.length === 0,
    "brez zetona: my_plan null, prazna seznama", r.body);

  await api("PUT", `/events/${dogodek}/interest`, T.ana);
  await api("PUT", `/events/${dogodek}/interest`, T.bor);
  r = await api("POST", `/events/${dogodek}/orders`, T.cene, { quantity: 1 });
  assert(r.status === 201, "cene kupi vstopnico (going)", r.body);
  await api("PUT", `/events/${dogodek}/interest`, T.cene); // cene: vstopnico IN zanimanje -> samo going
  await api("PUT", `/events/${dogodek}/interest`, T.an_x); // an_x ni prijatelj z ano

  r = await api("GET", `/events/${dogodek}`, T.ana);
  assert(r.body.my_plan === "interested", "ana: my_plan interested", r.body.my_plan);
  assert(r.body.friends_going.map(f => f.username).join(",") === "cene", "friends_going: samo cene", r.body.friends_going);
  assert(r.body.friends_interested.map(f => f.username).join(",") === "bor", "friends_interested: samo bor (cene je going, an_x ni prijatelj)", r.body.friends_interested);
  assert(r.body.friends_going.every(f => f.email === undefined) && r.body.friends_interested.every(f => f.email === undefined), "brez e-naslovov (I11)", r.body);

  r = await api("PATCH", "/me", T.bor, { share_plans_with_friends: false });
  assert(r.status === 200, "bor izklopi deljenje nacrtov", r.body);
  r = await api("GET", `/events/${dogodek}`, T.ana);
  assert(r.body.friends_interested.length === 0, "I11: bor z izklopljenim deljenjem ni vec v friends_interested", r.body.friends_interested);
  await api("PATCH", "/me", T.bor, { share_plans_with_friends: true });

  r = await api("POST", `/events/${dogodek}/orders`, T.ana, { quantity: 1 });
  assert(r.status === 201, "ana kupi vstopnico -> zdaj tudi sama going", r.body);
  r = await api("GET", `/events/${dogodek}`, T.ana);
  assert(r.body.my_plan === "going", "ana: my_plan going (vstopnica prevlada nad zanimanjem)", r.body.my_plan);

  console.log("\n# GET /me/friends/plans — unija going + interested, I11");
  r = await api("GET", "/me/friends/plans", T.ana);
  assert(r.status === 200, "GET /me/friends/plans", r.body);
  const zabava = r.body.events.find(e => e.id === dogodek);
  assert(!!zabava, "dogodek 'Zabava' je v seznamu (ima prijatelja SAMO z zanimanjem: bor)", r.body.events.map(e => e.id));
  assert(zabava.friends.map(f => f.username).join(",") === "cene", "friends (going): samo cene", zabava.friends);
  assert(zabava.interested.map(f => f.username).join(",") === "bor", "interested: samo bor", zabava.interested);
  assert(zabava.my_plan === "going", "my_plan (ana ima vstopnico): going", zabava.my_plan);

  r = await api("GET", "/me/friends/plans", T.an_x);
  assert(r.body.events.length === 0, "an_x brez prijateljev ne vidi nicesar", r.body.events);

  // Dogodek s prijateljem SAMO zanimanim (brez ikogar going) mora biti vkljucen (unija).
  r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Samo zanimanje", startAt: cezTeden, ticketPriceCents: 1000, capacity: 100, minAge: 0 });
  const samoZanimanje = r.body.id;
  await api("PUT", `/events/${samoZanimanje}/interest`, T.bor);
  r = await api("GET", "/me/friends/plans", T.ana);
  const sz = r.body.events.find(e => e.id === samoZanimanje);
  assert(!!sz && sz.friends.length === 0 && sz.interested.map(f => f.username).join(",") === "bor",
    "dogodek s prijateljem SAMO interested je v seznamu (unija)", r.body.events.map(e => e.id));
  assert(sz.my_plan === null, "ana na tem dogodku nima nacrta: my_plan null", sz.my_plan);

  console.log("\n# GET /me/plans");
  r = await api("GET", "/me/plans");
  assert(r.status === 401, "GET /me/plans brez zetona -> 401", r.status);
  r = await api("GET", "/me/plans", T.ana);
  assert(r.status === 200, "GET /me/plans ana", r.body);
  const idi = r.body.events.map(e => e.id).sort((a, b) => a - b);
  assert(idi.join(",") === [dogodek].sort((a, b) => a - b).join(","), "ana: /me/plans vsebuje samo 'Zabava' (going)", r.body.events.map(e => `${e.id}:${e.my_plan}`));
  assert(r.body.events[0].my_plan === "going" && r.body.events[0].club_name === "Pure Club", "my_plan going, s club_name", r.body.events[0]);

  r = await api("GET", "/me/plans", T.bor);
  assert(r.body.events.every(e => e.my_plan === "interested"), "bor: /me/plans, oba dogodka interested", r.body.events.map(e => `${e.id}:${e.my_plan}`));
  assert(r.body.events.map(e => e.id).sort((a, b) => a - b).join(",") === [dogodek, samoZanimanje].sort((a, b) => a - b).join(","), "bor: oba dogodka na seznamu", r.body.events.map(e => e.id));

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  if (/error|Error/.test(log) && !/Resend/.test(log)) { console.log("\n--- log streznika ---\n" + log); }
  srv.kill(); jwksServer.close(); await pool.end();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
