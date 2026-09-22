#!/usr/bin/env node
/**
 * Test sledenja klubu, obvestil o novem dogodku, stanja dogodka (ended) in posnetka
 * koncanega dogodka (migracija 019). Zagon (lokalno, PG16, baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_sledenje.js
 * Vzorec kot test_vabila.js: lokalni JWKS (3999), backend na 3115.
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3115, JWKS_PORT = 3999;
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
const VIDEO = "https://res.cloudinary.com/outly/video/upload/posnetek.mp4";

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE club_event_notifications, club_follows, club_invites, club_members, event_favorites, friendships, friend_requests, ticket_transfers, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  const T = { lastnik: zeton("lastnik@outly.si", uuid(1)), ana: zeton("ana@outly.si", uuid(2)), bor: zeton("bor@outly.si", uuid(3)) };
  for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
  await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
  await pool.query(`INSERT INTO clubs (owner_user_id, name, city) VALUES
    ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana'),
    ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Skriti klub', 'Maribor')`);
  await pool.query("UPDATE clubs SET hidden = TRUE WHERE id = 2");
  const idAna = (await pool.query("SELECT id FROM users WHERE email='ana@outly.si'")).rows[0].id;
  const idBor = (await pool.query("SELECT id FROM users WHERE email='bor@outly.si'")).rows[0].id;

  // ---------------------------------------------------------------- sledenje
  console.log("\n# Follow / unfollow");
  let r = await api("GET", "/clubs/1");
  assert(r.status === 200 && r.body.followers_count === 0, "GET /clubs/:id brez zetona -> followers_count 0", r.body.followers_count);
  assert(r.body.is_following === false, "brez zetona is_following = false", r.body.is_following);

  r = await api("PUT", "/clubs/1/follow", T.ana);
  assert(r.status === 200 && r.body.following === true && r.body.followers_count === 1, "PUT follow -> 200, 1 sledilec", r.body);
  r = await api("PUT", "/clubs/1/follow", T.ana);
  assert(r.status === 200 && r.body.followers_count === 1, "dvojni follow ne podvoji sledilca", r.body);

  r = await api("GET", "/clubs/1", T.ana);
  assert(r.body.is_following === true && r.body.followers_count === 1, "ana vidi is_following = true", r.body);
  r = await api("GET", "/clubs/1", T.bor);
  assert(r.body.is_following === false && r.body.followers_count === 1, "bor vidi is_following = false, stevec pa 1", r.body);
  r = await api("GET", "/clubs");
  assert(r.status === 200 && r.body[0].followers_count === 1, "GET /clubs vraca followers_count", r.body[0] && r.body[0].followers_count);
  r = await api("GET", "/business/clubs/me", T.lastnik);
  assert(r.status === 200 && r.body.followers_count === 1, "lastnik vidi followers_count", r.body.followers_count);

  r = await api("GET", "/me/clubs/following", T.ana);
  assert(r.status === 200 && r.body.ids.length === 1 && r.body.ids[0] === 1 && r.body.clubs[0].name === "Pure Club", "GET /me/clubs/following", r.body);
  r = await api("GET", "/me/clubs/following", T.bor);
  assert(r.status === 200 && r.body.ids.length === 0, "bor ne sledi nicemur", r.body);

  console.log("\n# Napacni vhodi in pravice");
  r = await api("PUT", "/clubs/1/follow");
  assert(r.status === 401, "follow brez zetona -> 401", r.status);
  r = await api("PUT", "/clubs/999/follow", T.ana);
  assert(r.status === 404, "follow neobstojecega kluba -> 404", r.status);
  r = await api("PUT", "/clubs/2/follow", T.ana);
  assert(r.status === 404, "follow skritega kluba -> 404", r.status);
  r = await api("PUT", "/clubs/abc/follow", T.ana);
  assert(r.status === 400, "follow z neveljavnim id -> 400", r.status);

  // -------------------------------------------------- obvestila o dogodkih
  console.log("\n# Obvestilo: klub, ki mu slediš, je objavil dogodek");
  r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Objavljen", startAt: new Date(Date.now() + 5 * 864e5).toISOString(), status: "published" });
  assert(r.status === 201, "POST /events (published) -> 201", r.body);
  const idObjavljen = r.body.id;

  r = await api("GET", "/me", T.ana);
  assert(r.body.pending_club_events === 1, "ana: pending_club_events = 1", r.body.pending_club_events);
  r = await api("GET", "/me", T.bor);
  assert(r.body.pending_club_events === 0, "bor (ne sledi) ne dobi obvestila", r.body.pending_club_events);

  r = await api("GET", "/me/club-events", T.ana);
  assert(r.status === 200 && r.body.notifications.length === 1, "GET /me/club-events -> 1 obvestilo", r.body);
  const obv = r.body.notifications[0];
  assert(obv.event_title === "Objavljen" && obv.club_name === "Pure Club" && obv.event_id === idObjavljen, "obvestilo nosi dogodek in klub", obv);

  r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Osnutek", startAt: new Date(Date.now() + 6 * 864e5).toISOString(), status: "draft" });
  assert(r.status === 201, "POST /events (draft) -> 201", r.body);
  const idOsnutek = r.body.id;
  r = await api("GET", "/me", T.ana);
  assert(r.body.pending_club_events === 1, "osnutek NE sprozi obvestila", r.body.pending_club_events);

  r = await api("PATCH", `/events/${idOsnutek}`, T.lastnik, { status: "published" });
  assert(r.status === 200, "PATCH osnutek -> published", r.body);
  r = await api("GET", "/me", T.ana);
  assert(r.body.pending_club_events === 2, "objava osnutka sprozi obvestilo", r.body.pending_club_events);
  r = await api("PATCH", `/events/${idOsnutek}`, T.lastnik, { title: "Objavljen osnutek" });
  r = await api("GET", "/me", T.ana);
  assert(r.body.pending_club_events === 2, "popravek ze objavljenega dogodka ne podvoji obvestila", r.body.pending_club_events);

  r = await api("GET", "/me/club-events", T.ana);
  const prviId = r.body.notifications[0].id;
  r = await api("POST", `/me/club-events/${prviId}/seen`, T.ana);
  assert(r.status === 200 && r.body.seen === true, "POST seen -> 200", r.body);
  r = await api("GET", "/me", T.ana);
  assert(r.body.pending_club_events === 1, "prebrano obvestilo ne steje vec", r.body.pending_club_events);
  r = await api("POST", `/me/club-events/${prviId}/seen`, T.bor);
  assert(r.status === 200 && r.body.seen === false, "tujega obvestila ni mogoce oznaciti", r.body);

  r = await api("DELETE", "/clubs/1/follow", T.ana);
  assert(r.status === 200 && r.body.following === false && r.body.followers_count === 0, "unfollow -> 0 sledilcev", r.body);
  r = await api("DELETE", "/clubs/1/follow", T.ana);
  assert(r.status === 200, "dvojni unfollow -> 200 (idempotentno)", r.status);
  r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Po unfollowu", startAt: new Date(Date.now() + 7 * 864e5).toISOString(), status: "published" });
  r = await api("GET", "/me", T.ana);
  assert(r.body.pending_club_events === 1, "po unfollowu novih obvestil ni", r.body.pending_club_events);

  // ------------------------------------------------------- stanje dogodka
  console.log("\n# Stanje dogodka: upcoming | live | ended");
  await pool.query("DELETE FROM club_event_notifications");
  await pool.query("DELETE FROM events");
  await pool.query(`INSERT INTO events (club_id, title, start_at, end_at, status, sold_count) VALUES
    (1, 'cez teden',     NOW() + INTERVAL '7 days', NULL,                      'published', 0),
    (1, 'tece zdaj',     NOW() - INTERVAL '1 hour', NULL,                      'published', 0),
    (1, 'koncan 10h',    NOW() - INTERVAL '10 hours', NULL,                    'published', 9),
    (1, 'koncan po end', NOW() - INTERVAL '3 hours', NOW() - INTERVAL '1 hour','published', 8),
    (1, 'star mesec',    NOW() - INTERVAL '30 days', NULL,                     'published', 7),
    (1, 'star cetrti',   NOW() - INTERVAL '40 days', NULL,                     'published', 6)`);
  const idPo = (t) => pool.query("SELECT id FROM events WHERE title=$1", [t]).then(x => x.rows[0].id);
  const eTeden = await idPo("cez teden"), eZdaj = await idPo("tece zdaj");
  const e10 = await idPo("koncan 10h"), eEnd = await idPo("koncan po end");
  const eMesec = await idPo("star mesec"), eCetrti = await idPo("star cetrti");

  const stanje = async (id) => (await api("GET", `/events/${id}`)).body.lifecycle;
  assert(await stanje(eTeden) === "upcoming", "dogodek cez teden -> upcoming");
  assert(await stanje(eZdaj) === "live", "dogodek, ki se je zacel pred uro, brez konca -> live");
  assert(await stanje(e10) === "ended", "dogodek pred 10 h brez konca -> ended (zacetek + 8 h)");
  assert(await stanje(eEnd) === "ended", "dogodek z vpisanim koncem pred uro -> ended");
  r = await api("GET", `/events/${eTeden}`);
  assert(r.body.time_status === "coming_soon", "time_status ostane nespremenjen (stari odjemalci)", r.body.time_status);
  assert(r.body.recap_video_url === "", "privzeti recap_video_url je prazen niz", r.body.recap_video_url);

  // ---------------------------------------------- popular + posnetek dogodka
  console.log("\n# Popular: najvec 3 koncani dogodki kluba");
  r = await api("GET", "/events?clubId=1&popular=true");
  assert(r.status === 200 && r.body.length === 3, "popular=true vrne najvec 3", r.body.map(e => e.title));
  assert(r.body.map(e => e.title).join(",") === "koncan 10h,koncan po end,star mesec", "urejeni po prodanih vstopnicah", r.body.map(e => `${e.title}:${e.sold_count}`));
  assert(r.body.every(e => e.lifecycle === "ended"), "vsi popularni so koncani", r.body.map(e => e.lifecycle));
  r = await api("GET", "/events?popular=true");
  assert(r.status === 400, "popular=true brez clubId -> 400", r.status);
  r = await api("GET", "/events?clubId=2&popular=true");
  assert(r.status === 200 && r.body.length === 0, "skriti klub nima javnih popularnih dogodkov", r.body);
  r = await api("GET", "/events?clubId=1&upcoming=false");
  const stariNaslovi = r.body.map(e => e.title);
  assert(!stariNaslovi.includes("star mesec") && !stariNaslovi.includes("star cetrti"),
    "stari ?upcoming=false se naprej drzi okna 7 dni", stariNaslovi);

  console.log("\n# Posnetek koncanega dogodka (recap_video_url)");
  r = await api("PATCH", `/events/${e10}`, T.lastnik, { recapVideoUrl: VIDEO });
  assert(r.status === 200 && r.body.recap_video_url === VIDEO, "posnetek na najbolj popularnem koncanem dogodku -> 200", r.body.recap_video_url);
  r = await api("GET", `/events/${e10}`);
  assert(r.body.recap_video_url === VIDEO, "posnetek je javno viden", r.body.recap_video_url);

  r = await api("PATCH", `/events/${eCetrti}`, T.lastnik, { recapVideoUrl: VIDEO });
  assert(r.status === 400 && r.body.error === "not_top_event", "posnetek na 4. koncanem dogodku -> 400 not_top_event", r.body);
  r = await api("PATCH", `/events/${eTeden}`, T.lastnik, { recapVideoUrl: VIDEO });
  assert(r.status === 400, "posnetek na prihajajocem dogodku -> 400", r.body);
  r = await api("PATCH", `/events/${eZdaj}`, T.lastnik, { recapVideoUrl: VIDEO });
  assert(r.status === 400, "posnetek na dogodku, ki se tece -> 400", r.body);
  r = await api("PATCH", `/events/${eEnd}`, T.lastnik, { recapVideoUrl: "http://a/v.mp4" });
  assert(r.status === 400, "posnetek brez https -> 400", r.status);
  r = await api("PATCH", `/events/${e10}`, T.lastnik, { recapVideoUrl: "" });
  assert(r.status === 200 && r.body.recap_video_url === "", "prazen niz odstrani posnetek", r.body.recap_video_url);
  r = await api("PATCH", `/events/${eCetrti}`, T.ana, { recapVideoUrl: VIDEO });
  assert(r.status === 403, "tujec ne more nalagati posnetka -> 403", r.status);

  console.log("\n# recap_allowed v GET /business/events");
  r = await api("GET", "/business/events", T.lastnik);
  const po = Object.fromEntries(r.body.map(e => [e.title, e.recap_allowed]));
  assert(po["koncan 10h"] === true && po["koncan po end"] === true && po["star mesec"] === true, "top 3 koncani -> recap_allowed true", po);
  assert(po["star cetrti"] === false && po["cez teden"] === false && po["tece zdaj"] === false, "ostali -> recap_allowed false", po);

  // ----------------------------------------------- nacrti prijateljev
  console.log("\n# Nacrti prijateljev: koncanih dogodkov ni na seznamu");
  await pool.query("INSERT INTO friendships (user_a, user_b) VALUES (LEAST($1::int,$2::int), GREATEST($1::int,$2::int))", [idAna, idBor]);
  for (const [eid, ref] of [[eTeden, "ref-1"], [eZdaj, "ref-2"], [e10, "ref-3"]]) {
    await pool.query(
      `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, paid_at)
       VALUES ($1, $2, $3, 1, 1, 1000, 1000, 'paid', 'bor@outly.si', NOW())`, [ref, idBor, eid]);
    await pool.query("INSERT INTO tickets (order_id, event_id, status) VALUES ((SELECT id FROM orders WHERE public_ref=$1), $2, 'valid')", [ref, eid]);
  }
  r = await api("GET", "/me/friends/plans", T.ana);
  const naslovi = r.body.events.map(e => e.title);
  assert(r.status === 200 && naslovi.includes("cez teden"), "prihajajoci dogodek prijatelja je na seznamu", naslovi);
  assert(naslovi.includes("tece zdaj"), "dogodek, ki tece nocoj, ostane na seznamu", naslovi);
  assert(!naslovi.includes("koncan 10h"), "koncanega dogodka NI na seznamu nacrtov", naslovi);

  srv.kill(); jwksServer.close(); await pool.end();
  const napake = log.split("\n").filter(l => /error|TypeError|Unhandled/i.test(l) && !/Server error\./.test(l));
  if (napake.length) console.log("\nLog backenda (sumljivo):\n" + napake.join("\n"));
  console.log(`\n${ok} OK, ${fail} napak`);
  process.exit(fail ? 1 : 0);
})();
