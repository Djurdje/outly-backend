#!/usr/bin/env node
/**
 * Test prijateljev (migracija 016): iskanje, prosnje, sprejem/zavrnitev/preklic,
 * odstranitev, "Your friends' plans" z zasebnostjo (share_plans_with_friends,
 * invarianta I11) in prenos vstopnice prijatelju po user_id.
 * Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_prijatelji.js
 *
 * Skripta sama dvigne lokalni JWKS streznik (port 3997), podpise ES256 zetone
 * in zazene backend na portu 3116. Resend ni nastavljen -> maili se ne posiljajo.
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3116, JWKS_PORT = 3997;
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
  await pool.query("TRUNCATE friend_requests, friendships, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");

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
    nepotrjen: zeton("nepotrjen@outly.si", uuid(6)),
  };
  for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
  const id = {};
  for (const row of (await pool.query("SELECT id, email FROM users")).rows) id[row.email.split("@")[0]] = row.id;
  await pool.query("UPDATE users SET email_verified=false WHERE email='nepotrjen@outly.si'");

  console.log("\n# /me: nova polja");
  let r = await api("GET", "/me", T.ana);
  assert(r.body.pending_friend_requests === 0, "/me vraca pending_friend_requests = 0", r.body.pending_friend_requests);
  assert(r.body.share_plans_with_friends === true, "/me vraca share_plans_with_friends = true (privzeto)", r.body.share_plans_with_friends);

  console.log("\n# Iskanje");
  r = await api("GET", "/users/search?q=a");
  assert(r.status === 401, "iskanje brez zetona -> 401", r.status);
  r = await api("GET", "/users/search?q=a", T.ana);
  assert(r.status === 400, "q krajsi od 2 -> 400", r.status);
  r = await api("GET", "/users/search?q=a%25", T.ana);
  assert(r.status === 400, "q z nedovoljenim znakom -> 400", r.status);
  r = await api("GET", "/users/search?q=AN", T.bor);
  assert(r.status === 200 && r.body.users.map(u => u.username).sort().join(",") === "an_x,ana", "q=AN (brez upostevanja velikosti) najde ana in an_x", r.body);
  assert(r.body.users.every(u => u.email === undefined && u.relation === "none"), "zadetki brez e-naslova, relation none", r.body.users);
  r = await api("GET", "/users/search?q=an_", T.bor);
  assert(r.status === 200 && r.body.users.length === 1 && r.body.users[0].username === "an_x", "q=an_ najde samo an_x ('_' ni nadomestni znak)", r.body);
  r = await api("GET", "/users/search?q=ana", T.ana);
  assert(r.status === 200 && r.body.users.length === 0, "sebe ne najde", r.body);
  r = await api("GET", "/users/search?q=nepot", T.ana);
  assert(r.status === 200 && r.body.users.length === 0, "nepotrjen racun se ne najde", r.body);

  console.log("\n# Prosnja");
  r = await api("POST", "/me/friends/requests", T.ana, {});
  assert(r.status === 400, "brez user_id/username -> 400", r.status);
  r = await api("POST", "/me/friends/requests", T.ana, { user_id: id.ana });
  assert(r.status === 400, "sebi -> 400", r.status);
  r = await api("POST", "/me/friends/requests", T.ana, { username: "nihce" });
  assert(r.status === 404 && r.body.error === "no_account", "neobstojec username -> 404 no_account", r.body);
  r = await api("POST", "/me/friends/requests", T.ana, { user_id: id.nepotrjen });
  assert(r.status === 404, "nepotrjen racun -> 404", r.status);
  r = await api("POST", "/me/friends/requests", T.ana, { username: "BOR" });
  assert(r.status === 201 && r.body.request && r.body.request.user.username === "bor", "ana -> bor (username, brez upostevanja velikosti) -> 201 request", r.body);
  const prosnja1 = r.body.request.id;
  r = await api("POST", "/me/friends/requests", T.ana, { user_id: id.bor });
  assert(r.status === 409 && r.body.error === "already_requested", "ponovna prosnja -> 409 already_requested", r.body);
  r = await api("GET", "/users/search?q=bo", T.ana);
  assert(r.body.users[0].relation === "request_sent", "iskanje: relation request_sent", r.body.users);
  r = await api("GET", "/users/search?q=an", T.bor);
  assert(r.body.users.find(u => u.username === "ana").relation === "request_received", "iskanje pri boru: relation request_received", r.body.users);
  r = await api("GET", "/me", T.bor);
  assert(r.body.pending_friend_requests === 1, "bor: /me pending_friend_requests = 1", r.body.pending_friend_requests);
  r = await api("GET", "/me/friends", T.bor);
  assert(r.body.friends.length === 0 && r.body.requests_in.length === 1 && r.body.requests_in[0].user.username === "ana" && r.body.requests_out.length === 0, "bor: requests_in [ana]", r.body);
  r = await api("GET", "/me/friends", T.ana);
  assert(r.body.requests_out.length === 1 && r.body.requests_out[0].user.username === "bor" && r.body.requests_in.length === 0, "ana: requests_out [bor]", r.body);

  console.log("\n# Tuja prosnja, zavrnitev, preklic");
  r = await api("POST", `/me/friends/requests/${prosnja1}/accept`, T.cene);
  assert(r.status === 404, "cene ne more sprejeti prosnje za bora -> 404", r.status);
  r = await api("POST", `/me/friends/requests/${prosnja1}/accept`, T.ana);
  assert(r.status === 404, "posiljatelj ne more sam sprejeti -> 404", r.status);
  r = await api("DELETE", `/me/friends/requests/${prosnja1}`, T.bor);
  assert(r.status === 404, "naslovnik ne more 'preklicati' (samo zavrniti) -> 404", r.status);
  r = await api("POST", `/me/friends/requests/${prosnja1}/decline`, T.bor);
  assert(r.status === 200, "bor zavrne -> 200", r.body);
  r = await api("GET", "/me", T.bor);
  assert(r.body.pending_friend_requests === 0, "po zavrnitvi pending 0", r.body.pending_friend_requests);
  r = await api("POST", "/me/friends/requests", T.ana, { user_id: id.bor });
  assert(r.status === 201, "po zavrnitvi lahko ana prosi znova -> 201", r.body);
  const prosnja2 = r.body.request.id;
  r = await api("DELETE", `/me/friends/requests/${prosnja2}`, T.ana);
  assert(r.status === 200, "ana preklice svojo prosnjo -> 200", r.body);
  r = await api("DELETE", `/me/friends/requests/${prosnja2}`, T.ana);
  assert(r.status === 404, "ponovni preklic -> 404", r.status);

  console.log("\n# Sprejem in nasprotna prosnja");
  r = await api("POST", "/me/friends/requests", T.ana, { user_id: id.bor });
  const prosnja3 = r.body.request.id;
  r = await api("POST", `/me/friends/requests/${prosnja3}/accept`, T.bor);
  assert(r.status === 200 && r.body.friend.username === "ana", "bor sprejme -> friend ana", r.body);
  r = await api("GET", "/me/friends", T.ana);
  assert(r.body.friends.length === 1 && r.body.friends[0].username === "bor" && r.body.friends[0].email === undefined, "ana: friends [bor], brez e-naslova", r.body);
  r = await api("GET", "/users/search?q=bo", T.ana);
  assert(r.body.users[0].relation === "friends", "iskanje: relation friends", r.body.users);
  r = await api("POST", "/me/friends/requests", T.bor, { user_id: id.ana });
  assert(r.status === 409 && r.body.error === "already_friends", "prosnja prijatelju -> 409 already_friends", r.body);
  // Nasprotni prosnji: cene prosi ano, ana prosi ceneta -> takoj prijatelja.
  r = await api("POST", "/me/friends/requests", T.cene, { user_id: id.ana });
  assert(r.status === 201, "cene -> ana 201", r.body);
  r = await api("POST", "/me/friends/requests", T.ana, { user_id: id.cene });
  assert(r.status === 200 && r.body.friend && r.body.friend.username === "cene", "ana -> cene, ko cene ze caka -> 200 friend (samodejni sprejem)", r.body);
  const st = await pool.query("SELECT status FROM friend_requests WHERE from_user_id=$1 AND to_user_id=$2", [id.cene, id.ana]);
  assert(st.rows[0].status === "accepted", "cenetova prosnja je accepted", st.rows);
  const fr = await pool.query("SELECT user_a, user_b FROM friendships ORDER BY user_a, user_b");
  assert(fr.rows.every(x => x.user_a < x.user_b) && fr.rows.length === 2, "friendships: 2 vrstici, user_a < user_b", fr.rows);

  console.log("\n# Your friends' plans (invarianta I11)");
  await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ($1, 'Pure Club', 'Ljubljana')", [id.lastnik]);
  const polnoleten = new Date(Date.now() - 25 * 365.25 * 24 * 3600 * 1000).toISOString().slice(0, 10);
  for (const k of ["ana", "bor", "cene", "an_x"]) await api("PATCH", "/me", T[k], { dateOfBirth: polnoleten, genres: ["house"] });
  const cezTeden = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
  r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Zabava", startAt: cezTeden, ticketPriceCents: 1000, capacity: 100, minAge: 0 });
  assert(r.status === 201, "dogodek ustvarjen", r.body);
  const dogodek = r.body.id;
  r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Druga", startAt: cezTeden, ticketPriceCents: 1000, capacity: 100, minAge: 0 });
  const dogodek2 = r.body.id;

  r = await api("GET", "/me/friends/plans", T.ana);
  assert(r.status === 200 && r.body.events.length === 0, "brez vstopnic prijateljev: events []", r.body);
  r = await api("POST", `/events/${dogodek}/orders`, T.bor, { quantity: 2 });
  assert(r.status === 201, "bor kupi 2 vstopnici", r.body);
  const borVstopnica = r.body.tickets[0].id;
  r = await api("POST", `/events/${dogodek}/orders`, T.cene, { quantity: 1 });
  r = await api("POST", `/events/${dogodek2}/orders`, T.an_x, { quantity: 1 });
  assert(r.status === 201, "an_x (ni prijatelj) kupi vstopnico za drug dogodek", r.body);

  r = await api("GET", "/me/friends/plans", T.ana);
  assert(r.status === 200 && r.body.events.length === 1 && r.body.events[0].id === dogodek, "ana vidi 1 dogodek (an_x ni prijatelj)", r.body);
  assert(r.body.events[0].friends.map(f => f.username).join(",") === "bor,cene", "na dogodku: bor, cene (bor enkrat kljub 2 vstopnicama)", r.body.events[0].friends);
  assert(r.body.events[0].friends.every(f => f.email === undefined) && r.body.events[0].club_name === "Pure Club", "brez e-naslovov, s club_name", r.body.events[0]);
  r = await api("GET", "/me/friends/plans", T.an_x);
  assert(r.body.events.length === 0, "an_x brez prijateljev ne vidi nicesar", r.body);

  r = await api("PATCH", "/me", T.cene, { share_plans_with_friends: "ne" });
  assert(r.status === 400, "share_plans_with_friends mora biti boolean -> 400", r.status);
  r = await api("PATCH", "/me", T.cene, { share_plans_with_friends: false });
  assert(r.status === 200 && r.body.share_plans_with_friends === false, "cene izklopi deljenje nacrtov", r.body);
  r = await api("GET", "/me/friends/plans", T.ana);
  assert(r.body.events[0].friends.map(f => f.username).join(",") === "bor", "I11: cene z izklopljenim deljenjem ni vec na seznamu", r.body.events[0].friends);
  r = await api("DELETE", `/me/friends/${id.bor}`, T.ana);
  assert(r.status === 200, "ana odstrani bora -> 200", r.body);
  r = await api("GET", "/me/friends/plans", T.ana);
  assert(r.body.events.length === 0, "po odstranitvi bora (in cene izklopljen): events []", r.body);
  r = await api("GET", "/me/friends", T.bor);
  assert(r.body.friends.length === 0, "odstranitev velja obojestransko", r.body);
  r = await api("DELETE", `/me/friends/${id.bor}`, T.ana);
  assert(r.status === 404, "ponovna odstranitev -> 404", r.status);

  console.log("\n# Prenos vstopnice prijatelju po user_id");
  r = await api("POST", `/tickets/${borVstopnica}/transfer`, T.bor, { user_id: id.ana });
  assert(r.status === 404, "bor in ana nista vec prijatelja -> prenos po user_id 404", r.status);
  r = await api("POST", `/tickets/${borVstopnica}/transfer`, T.bor, { user_id: "abc" });
  assert(r.status === 400, "neveljaven user_id -> 400", r.status);
  r = await api("POST", "/me/friends/requests", T.bor, { user_id: id.ana });
  const prosnja4 = r.body.request.id;
  await api("POST", `/me/friends/requests/${prosnja4}/accept`, T.ana);
  r = await api("POST", `/tickets/${borVstopnica}/transfer`, T.bor, { user_id: id.ana });
  assert(r.status === 200 && r.body.ticket.holder_username === "ana" && r.body.ticket.transferred === true, "prijatelju po user_id -> 200, imetnica ana", r.body);
  const tt = await pool.query("SELECT to_email FROM ticket_transfers WHERE ticket_id=$1", [borVstopnica]);
  assert(tt.rows[0] && tt.rows[0].to_email === "ana@outly.si", "ticket_transfers.to_email je prejemnikov e-naslov", tt.rows);
  r = await api("GET", "/me/tickets", T.ana);
  assert(r.body.some(t => t.id === borVstopnica), "ana vidi preneseno vstopnico", r.body.map(t => t.id));
  r = await api("POST", `/tickets/${borVstopnica}/transfer`, T.ana, { email: "cene@outly.si" });
  assert(r.status === 200, "prenos po e-naslovu dela kot prej -> 200", r.body);

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  if (/error|Error/.test(log) && !/Resend/.test(log)) { console.log("\n--- log streznika ---\n" + log); }
  srv.kill(); jwksServer.close(); await pool.end();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
