#!/usr/bin/env node
/**
 * Test OBVESTILA O VABILU NA GUEST LISTO (migracija 036, 8. 10. 2026). Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_guest_lista_obvestilo.js
 * Vzorec kot test_guest_lista.js: lokalni JWKS (3975), backend na svojem portu (3175), TRUNCATE na zacetku.
 *
 *  1  shema: seen_at brez DEFAULT, delni indeks; nova vabila nastanejo z NULL; vabilo pred migracijo (seen_at NOT NULL) ne steje
 *  2  vabilo: stevec pending_guest_list_invites v GET /me (samo povabljenec, ne gostitelj, ne tretji), vrstica v received z obliko iz pogodbe, brez e-naslovov
 *  3  vec vabil: najnovejsa prvo, stevec = stevilo vrstic, pending_received_tickets ostane neodvisen
 *  4  seen: 200 { ok: true }, stevec pade, idempotentno (seen_at se ne prepise), tuj/neobstojec id 404, neveljaven id 400, brez zetona 401, vstopnica ostane veljavna
 *  5  obvestilo izgine samo: odstranitev z liste, preklic liste (admin), izbris racuna gostitelja, void vstopnice, koncan dogodek (end_at in start_at + 8 h)
 *  6  ponovno vabilo po odstranitvi = novo neprebrano obvestilo; seen na odstranjenem (mojem) vabilu 200
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3175, JWKS_PORT = 3975;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-guest-lista-obvestilo";
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
async function api(method, p, token, body) {
  const r = await fetch(BASE + p, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, text: t };
}

let srv = null;
(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, guest_list_members, guest_lists, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users, friendships RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test", PRENOS_BREZ_RACUNA: "vsi" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  const imena = ["lastnik", "admin", "host", "host2", "host3", "host4", "host5", "host6", "ana", "bor", "cene", "dan", "ema", "fil", "tuj"];
  const T = {}; const U = {};
  imena.forEach((k, i) => { T[k] = zeton(`${k}@outly.si`, uuid(i + 1)); });
  for (const k of imena) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); U[k] = r.body.id; }
  await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
  await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana')");
  const polnoleten = new Date(Date.now() - 25 * 365.25 * 24 * 3600 * 1000).toISOString().slice(0, 10);
  for (const k of imena) {
    const r = await api("PATCH", "/me", T[k], { dateOfBirth: polnoleten, genres: ["house"] });
    assert(r.status === 200, `${k}: datum rojstva`, r.body);
  }
  const prijatelja = (a, b) => pool.query("INSERT INTO friendships (user_a, user_b) VALUES (LEAST($1::int,$2::int), GREATEST($1::int,$2::int)) ON CONFLICT DO NOTHING", [U[a], U[b]]);
  for (const h of ["host", "host2", "host3", "host4", "host5", "host6"]) for (const g of ["ana", "bor", "cene", "dan", "ema", "fil", "tuj"]) await prijatelja(h, g);

  const cezTeden = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
  const dogodek = async (title, extra = {}) => {
    const x = await api("POST", "/events", T.lastnik, { clubId: 1, title, startAt: cezTeden, ticketPriceCents: 1000, capacity: 100, minAge: 0, posterUrl: "https://example.com/p.jpg", ...extra });
    assert(x.status === 201, `dogodek ${title}`, x.body); return x.body.id;
  };
  const evA = await dogodek("Glavni");
  const evB = await dogodek("Drugi");
  const evC = await dogodek("Koncan kmalu");
  const evD = await dogodek("Brez konca");
  const lista = async (event, host, spots = 5) => {
    const r = await api("POST", "/admin/api/guest-lists", T.admin, { event_id: event, user_id: U[host], spots });
    assert(r.status === 201, `admin: lista ${host} na dogodku ${event}`, r.body); return r.body.guest_list.id;
  };
  const povabi = async (lid, host, gost) => {
    const r = await api("POST", `/me/guest-lists/${lid}/invites`, T[host], { user_ids: [U[gost]] });
    assert(r.status === 201, `${host} povabi ${gost}`, [r.status, r.body]); return r;
  };
  const stevec = async (k) => { const r = await api("GET", "/me", T[k]); return r.body.pending_guest_list_invites; };
  const prejeta = async (k) => api("GET", "/me/guest-list-invites/received", T[k]);
  const clanId = async (lid, gost) => Number((await pool.query("SELECT id FROM guest_list_members WHERE guest_list_id=$1 AND user_id=$2 ORDER BY id DESC LIMIT 1", [lid, U[gost]])).rows[0].id);   // pool testa nima parserja za BIGINT

  console.log("\n# 1. Shema in privzeto stanje");
  const col = (await pool.query("SELECT column_default, is_nullable, data_type FROM information_schema.columns WHERE table_name='guest_list_members' AND column_name='seen_at'")).rows[0];
  assert(col && col.column_default === null && col.is_nullable === "YES" && col.data_type === "timestamp with time zone", "guest_list_members.seen_at: TIMESTAMPTZ, nullable, brez DEFAULT", col);
  const idx = (await pool.query("SELECT indexdef FROM pg_indexes WHERE indexname='guest_list_members_neprebrana_idx'")).rows[0];
  assert(idx && /\(user_id\)/.test(idx.indexdef) && /seen_at IS NULL/.test(idx.indexdef) && /removed_at IS NULL/.test(idx.indexdef), "delni indeks guest_list_members_neprebrana_idx (user_id) WHERE seen_at/removed_at IS NULL", idx);
  let r = await api("GET", "/me", T.ana);
  assert(r.body.pending_guest_list_invites === 0 && Number.isInteger(r.body.pending_guest_list_invites), "GET /me brez vabil: pending_guest_list_invites = 0 (int)", r.body.pending_guest_list_invites);
  r = await prejeta("ana");
  assert(r.status === 200 && Array.isArray(r.body.invites) && r.body.invites.length === 0 && Object.keys(r.body).join() === "invites", "received brez vabil: 200 { invites: [] }", r.body);
  r = await api("GET", "/me/guest-list-invites/received", null);
  assert(r.status === 401, "received brez zetona: 401", r.status);
  r = await api("POST", "/me/guest-list-invites/received/1/seen", null);
  assert(r.status === 401, "seen brez zetona: 401", r.status);

  console.log("\n# 2. Vabilo: stevec in vrstica");
  const L1 = await lista(evA, "host");
  await pool.query("UPDATE users SET avatar_url = NULL WHERE id = $1", [U.host]);
  await povabi(L1, "host", "ana");
  const m1 = (await pool.query("SELECT id::int AS id, seen_at FROM guest_list_members WHERE guest_list_id=$1 AND user_id=$2", [L1, U.ana])).rows[0];
  assert(m1 && m1.seen_at === null, "novo vabilo nastane s seen_at NULL (brez DEFAULT)", m1);
  assert(await stevec("ana") === 1, "ana: pending_guest_list_invites = 1");
  assert(await stevec("host") === 0, "gostitelj (nima vabila): 0");
  assert(await stevec("bor") === 0 && await stevec("tuj") === 0, "tretji: 0");
  r = await prejeta("ana");
  const v1 = r.body.invites[0];
  assert(r.status === 200 && r.body.invites.length === 1, "ana: received ima 1 vrstico", r.body);
  const anaVst = (await api("GET", "/me/tickets", T.ana)).body.find(t => t.is_guest_list);
  assert(anaVst, "ana ima vstopnico guest liste v /me/tickets");
  assert(Object.keys(v1).sort().join() === "created_at,event,guest_list_id,host_avatar_url,host_username,id,ticket_id", "vrstica: natancno polja iz pogodbe", Object.keys(v1));
  assert(Object.keys(v1.event).sort().join() === "club_name,id,poster_url,start_at,title", "event: natancno polja iz pogodbe", Object.keys(v1.event));
  assert(v1.id === m1.id && typeof v1.id === "number" && v1.guest_list_id === L1 && typeof v1.guest_list_id === "number", "id = guest_list_members.id, guest_list_id = lista (stevili)", v1);
  assert(v1.ticket_id === anaVst.id && typeof v1.ticket_id === "number", "ticket_id = moja vstopnica (ista kot v GET /me/tickets)", [v1.ticket_id, anaVst.id]);
  assert(v1.host_username === "host" && v1.host_avatar_url === null, "host_username 'host', host_avatar_url null", v1);
  assert(!Number.isNaN(Date.parse(v1.created_at)) && /^\d{4}-\d\d-\d\dT/.test(v1.created_at), "created_at je ISO", v1.created_at);
  assert(v1.event.id === evA && v1.event.title === "Glavni" && v1.event.club_name === "Pure Club" && v1.event.poster_url === "https://example.com/p.jpg" && !Number.isNaN(Date.parse(v1.event.start_at)), "event: id, title, club_name, poster_url, start_at", v1.event);
  assert(!/@outly\.si|email/i.test(r.text), "odgovor ne vsebuje e-naslovov (I11)", r.text);
  await pool.query("UPDATE users SET avatar_url = 'https://example.com/a.png' WHERE id = $1", [U.host]);
  r = await prejeta("ana");
  assert(r.body.invites[0].host_avatar_url === "https://example.com/a.png", "host_avatar_url se prenese", r.body.invites[0]);
  assert(await stevec("ana") === 1, "ana: se vedno 1 (branje seznama ne oznaci prebranega)");
  const rt = (await api("GET", "/me", T.ana)).body;
  assert(rt.pending_received_tickets === 0 && rt.pending_club_events === 0, "pending_received_tickets in pending_club_events nespremenjena (0)", rt);

  console.log("\n# 3. Vec vabil: vrstni red, stevec");
  const L2 = await lista(evB, "host2");
  await new Promise(r => setTimeout(r, 20));
  await povabi(L2, "host2", "ana");
  assert(await stevec("ana") === 2, "ana: 2 vabili");
  r = await prejeta("ana");
  assert(r.body.invites.length === 2 && r.body.invites[0].guest_list_id === L2 && r.body.invites[0].host_username === "host2" && r.body.invites[1].guest_list_id === L1, "najnovejse vabilo prvo", r.body.invites.map(x => x.guest_list_id));
  // isti gostitelj, druga lista: vsak gostitelj ima eno aktivno listo na dogodek, a vec dogodkov
  assert(r.body.invites[0].event.id === evB && r.body.invites[1].event.id === evA, "vsaka vrstica ima svoj dogodek", r.body.invites.map(x => x.event.id));

  console.log("\n# 4. seen");
  const id1 = m1.id, id2 = r.body.invites[0].id;
  let s = await api("POST", `/me/guest-list-invites/received/${id1}/seen`, T.bor);
  assert(s.status === 404, "tuj id (bor): 404", [s.status, s.body]);
  assert(await stevec("ana") === 2, "tuj seen ne spremeni anine vrstice (se vedno 2)");
  assert((await pool.query("SELECT seen_at FROM guest_list_members WHERE id=$1", [id1])).rows[0].seen_at === null, "tuj seen: seen_at ostane NULL");
  s = await api("POST", `/me/guest-list-invites/received/${id1}/seen`, T.host);
  assert(s.status === 404, "gostitelj ni povabljenec: 404", s.status);
  s = await api("POST", "/me/guest-list-invites/received/999999/seen", T.ana);
  assert(s.status === 404, "neobstojec id: 404", s.status);
  s = await api("POST", "/me/guest-list-invites/received/99999999999999999999/seen", T.ana);
  assert(s.status === 404, "id prevelik za BIGINT: 404 (ne 500)", s.status);
  s = await api("POST", "/me/guest-list-invites/received/abc/seen", T.ana);
  assert(s.status === 400, "neveljaven id (abc): 400", s.status);
  s = await api("POST", `/me/guest-list-invites/received/${id1}/seen`, T.ana);
  assert(s.status === 200 && s.body && s.body.ok === true && Object.keys(s.body).join() === "ok", "ana seen: 200 { ok: true }", [s.status, s.body]);
  assert(await stevec("ana") === 1, "ana: stevec 2 -> 1");
  r = await prejeta("ana");
  assert(r.body.invites.length === 1 && r.body.invites[0].id === id2, "received: ostane samo neprebrano vabilo", r.body.invites);
  const seen1 = (await pool.query("SELECT seen_at FROM guest_list_members WHERE id=$1", [id1])).rows[0].seen_at;
  assert(seen1 instanceof Date, "seen_at je nastavljen v bazi", seen1);
  await new Promise(r => setTimeout(r, 30));
  s = await api("POST", `/me/guest-list-invites/received/${id1}/seen`, T.ana);
  assert(s.status === 200 && s.body.ok === true, "ponovni seen: 200 (idempotentno)", [s.status, s.body]);
  const seen1b = (await pool.query("SELECT seen_at FROM guest_list_members WHERE id=$1", [id1])).rows[0].seen_at;
  assert(seen1b.getTime() === seen1.getTime(), "ponovni seen ne prepise seen_at", [seen1, seen1b]);
  s = await api("POST", `/me/guest-list-invites/received/${id2}/seen`, T.ana);
  assert(s.status === 200 && await stevec("ana") === 0, "ana seen drugo vabilo: stevec 0");
  r = await prejeta("ana");
  assert(r.status === 200 && r.body.invites.length === 0, "received: prazno", r.body);
  const vst = (await api("GET", "/me/tickets", T.ana)).body.filter(t => t.is_guest_list);
  assert(vst.length === 2 && vst.every(t => t.status === "valid"), "seen ne spremeni vstopnic: obe ostaneta veljavni v /me/tickets", vst.map(t => t.status));
  const trans = await api("POST", "/me/tickets/received/999999/seen", T.ana);
  assert(trans.status === 404, "pot za prenose vstopnic (/me/tickets/received/:id/seen) je nespremenjena (404 za neobstojec id)", trans.status);

  console.log("\n# 5. Obvestilo izgine samo");
  // 5a odstranitev z liste
  const L3 = await lista(evA, "host3");
  await povabi(L3, "host3", "bor");
  assert(await stevec("bor") === 1, "bor: 1 neprebrano");
  let d = await api("DELETE", `/me/guest-lists/${L3}/invites/${U.bor}`, T.host3);
  assert(d.status === 200, "gostitelj odstrani bora", [d.status, d.body]);
  assert(await stevec("bor") === 0, "odstranitev z liste: stevec 0");
  r = await prejeta("bor");
  assert(r.body.invites.length === 0, "odstranitev z liste: received prazno", r.body);
  const mBorStari = await clanId(L3, "bor");
  s = await api("POST", `/me/guest-list-invites/received/${mBorStari}/seen`, T.bor);
  assert(s.status === 200 && s.body.ok === true, "seen na odstranjenem (mojem) vabilu: 200 (ni napaka)", [s.status, s.body]);
  // 6 ponovno vabilo po odstranitvi
  console.log("\n# 6. Ponovno vabilo po odstranitvi");
  await povabi(L3, "host3", "bor");
  const mBorNov = await clanId(L3, "bor");
  assert(mBorNov !== mBorStari, "ponovno vabilo = nova vrstica");
  assert(await stevec("bor") === 1, "ponovno vabilo: novo neprebrano obvestilo (stevec 1)");
  r = await prejeta("bor");
  assert(r.body.invites.length === 1 && r.body.invites[0].id === mBorNov, "received: nova vrstica", r.body.invites);
  s = await api("POST", `/me/guest-list-invites/received/${mBorNov}/seen`, T.bor);
  assert(s.status === 200 && await stevec("bor") === 0, "bor seen: 0");

  console.log("\n# 5b-f. Preklic liste, izbris gostitelja, void, koncan dogodek");
  // 5b preklic liste (admin)
  const L4 = await lista(evA, "host4");
  await povabi(L4, "host4", "cene");
  await povabi(L4, "host4", "dan");
  assert(await stevec("cene") === 1 && await stevec("dan") === 1, "cene in dan: po 1 neprebrano");
  d = await api("DELETE", `/admin/api/guest-lists/${L4}`, T.admin);
  assert(d.status === 200, "admin prekliche listo", [d.status, d.body]);
  assert(await stevec("cene") === 0 && await stevec("dan") === 0, "preklic liste: stevec 0 za oba");
  r = await prejeta("cene");
  assert(r.status === 200 && r.body.invites.length === 0, "preklic liste: received prazno", r.body);
  // 5c izbris racuna gostitelja
  const L5 = await lista(evB, "host5");
  await povabi(L5, "host5", "ema");
  assert(await stevec("ema") === 1, "ema: 1 neprebrano");
  d = await api("DELETE", "/me", T.host5, { password: "x" });
  assert(d.status === 200, "gostitelj (host5) izbrise racun", [d.status, d.body]);
  assert(await stevec("ema") === 0, "izbris gostitelja: stevec 0");
  r = await prejeta("ema");
  assert(r.status === 200 && r.body.invites.length === 0, "izbris gostitelja: received prazno", r.body);
  // 5d vstopnica void (npr. razveljavljena po drugi poti)
  const L6 = await lista(evA, "host6");
  await povabi(L6, "host6", "fil");
  assert(await stevec("fil") === 1, "fil: 1 neprebrano");
  await pool.query("UPDATE tickets SET status='void' WHERE id = (SELECT ticket_id FROM guest_list_members WHERE guest_list_id=$1 AND user_id=$2)", [L6, U.fil]);
  assert(await stevec("fil") === 0, "vstopnica void: stevec 0");
  r = await prejeta("fil");
  assert(r.body.invites.length === 0, "vstopnica void: received prazno", r.body);
  await pool.query("UPDATE tickets SET status='valid' WHERE id = (SELECT ticket_id FROM guest_list_members WHERE guest_list_id=$1 AND user_id=$2)", [L6, U.fil]);
  assert(await stevec("fil") === 1, "kontrola: vstopnica spet valid -> 1 (pogoj je v poizvedbi, ne v podatkih)");
  // 5e koncan dogodek
  const L7 = await lista(evC, "host", 3);
  const L8 = await lista(evD, "host2", 3);
  await povabi(L7, "host", "tuj");
  await povabi(L8, "host2", "tuj");
  assert(await stevec("tuj") === 2, "tuj: 2 neprebrani vabili (dogodka v prihodnosti)");
  await pool.query("UPDATE events SET start_at = NOW() - INTERVAL '10 hours', end_at = NOW() - INTERVAL '2 hours' WHERE id = $1", [evC]);
  assert(await stevec("tuj") === 1, "koncan dogodek (end_at v preteklosti): stevec 2 -> 1");
  r = await prejeta("tuj");
  assert(r.body.invites.length === 1 && r.body.invites[0].event.id === evD, "received: koncan dogodek odpade", r.body.invites.map(x => x.event.id));
  await pool.query("UPDATE events SET start_at = NOW() - INTERVAL '7 hours', end_at = NULL WHERE id = $1", [evD]);
  assert(await stevec("tuj") === 1, "brez end_at, zacel pred 7 h (< 8 h): dogodek traja, 1");
  await pool.query("UPDATE events SET start_at = NOW() - INTERVAL '9 hours', end_at = NULL WHERE id = $1", [evD]);
  assert(await stevec("tuj") === 0, "brez end_at, zacel pred 9 h (> 8 h): koncan, 0");
  r = await prejeta("tuj");
  assert(r.body.invites.length === 0, "received prazno", r.body);

  // gostitelj brez vrstice (host_user_id NULL, ON DELETE SET NULL): stevec in seznam morata biti usklajena (brez znacke brez vrstice)
  const L9 = await lista(evB, "host6", 3);
  await povabi(L9, "host6", "tuj");
  assert(await stevec("tuj") === 1 && (await prejeta("tuj")).body.invites.length === 1, "kontrola: vabilo z gostiteljem: stevec 1 in 1 vrstica");
  await pool.query("UPDATE guest_lists SET host_user_id = NULL WHERE id = $1", [L9]);
  r = await prejeta("tuj");
  assert(await stevec("tuj") === 0 && r.status === 200 && r.body.invites.length === 0, "lista brez gostitelja (host_user_id NULL): stevec 0 in seznam prazen (usklajena)", [r.status, r.body]);
  await pool.query("UPDATE guest_lists SET host_user_id = $2 WHERE id = $1", [L9, U.host6]);
  assert(await stevec("tuj") === 1, "kontrola: gostitelj spet nastavljen -> 1");
  await pool.query("UPDATE guest_lists SET revoked_at = NOW() WHERE id = $1", [L9]);   // samo revoked_at (brez void/removed_at): pogoj mora delovati sam zase
  r = await prejeta("tuj");
  assert(await stevec("tuj") === 0 && r.body.invites.length === 0, "preklicana lista (samo revoked_at): stevec 0 in seznam prazen", [r.status, r.body]);
  await pool.query("UPDATE guest_lists SET revoked_at = NULL WHERE id = $1", [L9]);
  await pool.query("UPDATE guest_list_members SET seen_at = NOW() WHERE guest_list_id = $1", [L9]);

  console.log("\n# 1b. Vabilo pred migracijo (seen_at NOT NULL) ne steje");
  await pool.query("UPDATE events SET start_at = $2, end_at = NULL WHERE id = $1", [evD, cezTeden]);
  await pool.query("UPDATE events SET start_at = $2, end_at = NULL WHERE id = $1", [evC, cezTeden]);
  assert(await stevec("tuj") === 2, "kontrola: dogodka spet v prihodnosti -> 2");
  await pool.query("UPDATE guest_list_members SET seen_at = NOW() WHERE user_id = $1", [U.tuj]);   // kot bi jih migracija 036 oznacila s DEFAULT NOW()
  assert(await stevec("tuj") === 0, "vabila z izpolnjenim seen_at (obstojeca pred 036): 0");
  r = await prejeta("tuj");
  assert(r.body.invites.length === 0, "received prazno", r.body);

  // GET /me ostane en sam odgovor z vsemi starimi polji
  const me = (await api("GET", "/me", T.ana)).body;
  for (const k of ["pending_invites", "pending_friend_requests", "pending_received_tickets", "pending_club_events", "pending_guest_list_invites", "can_transfer_to_guest", "clubs"]) {
    assert(k in me, `GET /me ima polje ${k}`);
  }

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  const napake = log.split("\n").filter(l => /error|TypeError|Unhandled/i.test(l) && !/Server error\./.test(l) && !/Resend/i.test(l));
  if (napake.length) console.log("\nLog backenda (sumljivo):\n" + napake.join("\n"));
  srv.kill(); jwksServer.close(); await pool.end();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); if (srv) srv.kill(); process.exit(1); });
