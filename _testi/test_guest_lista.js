#!/usr/bin/env node
/**
 * Test GUEST LISTE (migracija 035, 8. 10. 2026, invarianta I24). Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_guest_lista.js
 * Vzorec kot test_prenos.js: lokalni JWKS (3974), backend na svojem portu (3174), TRUNCATE na zacetku.
 *
 *  1  admin: ustvarjanje (vloga, validacija, dogodek/uporabnik, ena aktivna lista, model v bazi: narocilo total 0, brez Stripa)
 *  2  uporabnik: GET /me/guest-lists (oblika, samo moje, urejeno), vstopnica gostitelja v /me/tickets z is_guest_list
 *  3  vabila: prijatelj ok, ne-prijatelj/gostitelj 403, prevec/podvojen 409, vse ali nic, validacija 400, starost 400/403, socasna vabila
 *  4  odstranitev: void + mesto prosto, uporabljena 409, tuja lista 404, ponovno vabilo = nova vstopnica
 *  5  prenos 409 (po user_id in po e-naslovu), transferable false
 *  6  NI prodaja: sold_count/kapaciteta, GET /business/sales, GET /admin/api/finance, GET /me/orders, DB varovalo (CHECK) proti Stripu/vracilu
 *  7  vrata: sken (polja, brez e-naslovov, tudi vratar), scan-list, poslovni seznam vstopnic, void -> ni vstopa, odpovedan dogodek
 *  8  admin: PATCH (mesta pod stevilom povabljenih 409), preklic (void, uporabljene ostanejo), ponovni preklic, nova lista po preklicu
 *  9  izbris racuna povabljenca/gostitelja, izbris dogodka z listo, omejevalnik POST invites, XSS v admin panelu
 */
const crypto = require("crypto");
const http = require("http");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3174, JWKS_PORT = 3974;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-guest-lista";
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
  // Omejevalnik poti guest-lista je skupen (30/h/IP): med sklopi ga ponastavimo (v pomnilniku procesa se blokada zapomni samo ob preseganju).
  const resetLimit = () => pool.query("TRUNCATE omejitve");

  const imena = ["lastnik", "admin", "host", "ana", "bor", "cene", "mlad", "tuj", "kupec", "brisan", "host2", "prij2", "f1", "f2", "f3", "f4", "f5", "vratar"];
  const T = {}; const U = {};
  imena.forEach((k, i) => { T[k] = zeton(`${k}@outly.si`, uuid(i + 1)); });
  for (const k of imena) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); U[k] = r.body.id; }
  await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
  await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana')");
  await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, $1, 'doorman')", [U.vratar]);

  const polnoleten = new Date(Date.now() - 25 * 365.25 * 24 * 3600 * 1000).toISOString().slice(0, 10);
  const mladoleten = new Date(Date.now() - 16 * 365.25 * 24 * 3600 * 1000).toISOString().slice(0, 10);
  for (const k of ["host", "ana", "bor", "tuj", "kupec", "brisan", "host2", "prij2", "f1", "f2", "f3", "f4", "f5"]) {
    const r = await api("PATCH", "/me", T[k], { dateOfBirth: polnoleten, genres: ["house"] });
    assert(r.status === 200, `${k}: datum rojstva (polnoleten)`, r.body);
  }
  let r = await api("PATCH", "/me", T.mlad, { dateOfBirth: mladoleten, genres: ["house"] });
  assert(r.status === 200, "mlad: datum rojstva (16 let)", r.body);
  // cene NIMA datuma rojstva (starost: brez datuma rabi age_confirmed)
  const prijatelja = async (a, b) => pool.query("INSERT INTO friendships (user_a, user_b) VALUES (LEAST($1::int,$2::int), GREATEST($1::int,$2::int)) ON CONFLICT DO NOTHING", [U[a], U[b]]);
  for (const k of ["ana", "bor", "cene", "mlad", "brisan", "f1", "f2", "f3", "f4", "f5"]) await prijatelja("host", k);
  await prijatelja("host2", "prij2");
  // tuj ni prijatelj nikogar

  const cezTeden = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
  const cezDva = new Date(Date.now() + 14 * 24 * 3600 * 1000).toISOString();
  const dogodek = async (title, extra = {}) => {
    const x = await api("POST", "/events", T.lastnik, { clubId: 1, title, startAt: cezTeden, ticketPriceCents: 1000, capacity: 100, minAge: 0, ...extra });
    assert(x.status === 201, `dogodek ${title}`, x.body); return x.body.id;
  };
  const evA = await dogodek("Glavni", { capacity: 3 });          // kapaciteta 3: guest lista ne sme porabiti zaloge
  const ev18 = await dogodek("Osemnajst", { minAge: 18, startAt: cezDva });
  const evC = await dogodek("Odpoved");
  const evD = await dogodek("Samo lista");
  const evE2 = await dogodek("Gostitelj dva");
  const evPrazen = await dogodek("Brez liste");
  const evKoncan = await dogodek("Koncan");
  const evStari = await dogodek("Star");
  await pool.query("UPDATE events SET start_at = NOW() - INTERVAL '10 hours', end_at = NOW() - INTERVAL '2 hours' WHERE id = $1", [evKoncan]);
  await pool.query("UPDATE events SET start_at = NOW() - INTERVAL '40 hours', end_at = NOW() - INTERVAL '30 hours' WHERE id = $1", [evStari]);

  console.log("\n# 1. Admin: ustvarjanje");
  r = await api("POST", "/admin/api/guest-lists", null, { event_id: evA, user_id: U.host, spots: 3 });
  assert(r.status === 401, "brez zetona: 401", r.status);
  r = await api("POST", "/admin/api/guest-lists", T.host, { event_id: evA, user_id: U.host, spots: 3 });
  assert(r.status === 403, "navaden uporabnik (tudi gostitelj sam) ne more ustvariti liste: 403", r.status);
  r = await api("POST", "/admin/api/guest-lists", T.lastnik, { event_id: evA, user_id: U.host, spots: 3 });
  assert(r.status === 403, "lastnik kluba (business) ne more ustvariti liste: 403", r.status);
  for (const [naslov, telo] of [
    ["spots 21", { event_id: evA, user_id: U.host, spots: 21 }],
    ["spots -1", { event_id: evA, user_id: U.host, spots: -1 }],
    ["spots niz", { event_id: evA, user_id: U.host, spots: "3" }],
    ["spots 1.5", { event_id: evA, user_id: U.host, spots: 1.5 }],
    ["brez spots", { event_id: evA, user_id: U.host }],
    ["note 201 znakov", { event_id: evA, user_id: U.host, spots: 3, note: "x".repeat(201) }],
    ["note ni niz", { event_id: evA, user_id: U.host, spots: 3, note: 5 }],
    ["brez event_id", { user_id: U.host, spots: 3 }],
    ["event_id niz", { event_id: "1", user_id: U.host, spots: 3 }],
    ["brez user_id", { event_id: evA, spots: 3 }],
  ]) {
    r = await api("POST", "/admin/api/guest-lists", T.admin, telo);
    assert(r.status === 400, `neveljaven vhod (${naslov}): 400`, [r.status, r.body]);
  }
  r = await api("POST", "/admin/api/guest-lists", T.admin, { event_id: 99999, user_id: U.host, spots: 3 });
  assert(r.status === 404 && /Event not found/.test(r.body), "dogodek ne obstaja: 404", [r.status, r.body]);
  r = await api("POST", "/admin/api/guest-lists", T.admin, { event_id: evA, user_id: 99999, spots: 3 });
  assert(r.status === 404 && /User not found/.test(r.body), "uporabnik ne obstaja: 404", [r.status, r.body]);
  r = await api("POST", "/admin/api/guest-lists", T.admin, { event_id: evStari, user_id: U.host, spots: 3 });
  assert(r.status === 409, "dogodek se je ze koncal: 409", [r.status, r.body]);
  await api("PATCH", `/admin/api/events/${evPrazen}`, T.admin, { status: "draft" });
  r = await api("POST", "/admin/api/guest-lists", T.admin, { event_id: evPrazen, user_id: U.host, spots: 3 });
  assert(r.status === 409, "osnutek (ni objavljen): 409", [r.status, r.body]);
  await api("PATCH", `/admin/api/events/${evPrazen}`, T.admin, { status: "published" });

  r = await api("POST", "/admin/api/guest-lists", T.admin, { event_id: evA, user_id: U.host, spots: 3, note: "  Rojstni dan  " });
  assert(r.status === 201 && r.body.guest_list, "admin ustvari listo (3 mesta): 201", [r.status, r.body]);
  const L = r.body.guest_list;
  assert(L.spots === 3 && L.remaining === 3 && L.note === "Rojstni dan" && L.can_invite === true && Array.isArray(L.invited) && L.invited.length === 0, "admin oblika: mesta, remaining, opomba (trim), can_invite, invited []", L);
  assert(L.host && L.host.user_id === U.host && L.host.username === "host" && L.host.email === "host@outly.si" && L.revoked_at === null && L.event.id === evA && L.event.club_name === "Pure Club", "admin oblika: gostitelj, event, revoked_at null", L);
  r = await api("POST", "/admin/api/guest-lists", T.admin, { event_id: evA, user_id: U.host, spots: 5 });
  assert(r.status === 409, "isti uporabnik, isti dogodek: 409 (ena aktivna lista)", [r.status, r.body]);
  r = await api("POST", "/admin/api/guest-lists", T.admin, { event_id: evPrazen, user_id: U.ana, spots: 0 });
  assert(r.status === 201 && r.body.guest_list.spots === 0, "lista z 0 mesti je dovoljena (samo gostitelj)", [r.status, r.body]);
  const anaLista = r.body.guest_list.id;

  console.log("\n# 1b. Model v bazi: narocilo guest liste");
  const nar = (await pool.query("SELECT * FROM orders WHERE guest_list_id = $1", [L.id])).rows[0];
  assert(nar && nar.total_cents === 0 && nar.unit_price_cents === 0 && nar.quantity === 1 && nar.status === "paid" && nar.paid_at && nar.user_id === U.host
    && nar.buyer_email === "host@outly.si" && !nar.stripe_payment_intent_id && !nar.stripe_charge_id && !nar.stripe_checkout_session_id && !nar.stripe_account_id
    && nar.application_fee_cents === 0 && nar.refunded_cents === 0 && nar.table_id === null && nar.guest_email === null, "narocilo: total 0, unit 0, quantity 1, paid, brez Stripa, user = gostitelj, buyer_email = njegov", nar);
  const vst0 = (await pool.query("SELECT * FROM tickets WHERE order_id = $1", [nar.id])).rows;
  assert(vst0.length === 1 && vst0[0].holder_user_id === U.host && vst0[0].status === "valid", "ob ustvarjanju 1 vstopnica gostitelja (holder = gostitelj)", vst0);
  const hostVstopnica = Number(vst0[0].id);   // pg v tem procesu vraca BIGINT kot niz (backend ima setTypeParser)
  assert((await pool.query("SELECT sold_count FROM events WHERE id=$1", [evA])).rows[0].sold_count === 0, "sold_count ostane 0 (sprozilec preskoci narocilo guest liste)");

  console.log("\n# 2. Uporabnik: GET /me/guest-lists in vstopnica gostitelja");
  r = await api("GET", "/me/guest-lists", null);
  assert(r.status === 401, "brez zetona: 401", r.status);
  r = await api("GET", "/me/guest-lists", T.host);
  assert(r.status === 200 && r.body.guest_lists.length === 1, "gostitelj vidi svojo listo", r.body);
  const g = r.body.guest_lists[0];
  assert(g.id === L.id && g.spots === 3 && g.remaining === 3 && g.can_invite === true && g.note === "Rojstni dan" && g.my_ticket_id === hostVstopnica && Array.isArray(g.invited), "oblika: id, spots, remaining, can_invite, note, my_ticket_id, invited", g);
  assert(g.event.id === evA && g.event.title === "Glavni" && g.event.club_id === 1 && g.event.club_name === "Pure Club" && g.event.min_age === 0 && g.event.status === "published"
    && "start_at" in g.event && "end_at" in g.event && "poster_url" in g.event, "oblika: event {id,title,start_at,end_at,poster_url,club_id,club_name,min_age,status}", g.event);
  assert(g.host === undefined && g.revoked_at === undefined, "uporabniska oblika brez admin polj (host, revoked_at)", Object.keys(g));
  r = await api("GET", "/me/guest-lists", T.bor);
  assert(r.status === 200 && r.body.guest_lists.length === 0, "drug uporabnik ne vidi tuje liste (I3)", r.body);
  r = await api("GET", "/me/guest-lists", T.ana);
  assert(r.body.guest_lists.length === 1 && r.body.guest_lists[0].spots === 0 && r.body.guest_lists[0].remaining === 0, "ana vidi samo SVOJO listo (0 mest)", r.body);
  r = await api("GET", "/me/tickets", T.host);
  const hv = r.body.find(t => t.id === hostVstopnica);
  assert(hv && hv.is_guest_list === true && hv.guest_list_host_username === "host" && hv.transferable === false && hv.status === "valid" && typeof hv.qr === "string" && hv.qr.startsWith("o2."),
    "/me/tickets: gostiteljeva vstopnica z is_guest_list, guest_list_host_username (on sam), transferable false, QR", hv);

  console.log("\n# 3. Vabila");
  await resetLimit();
  const POST = (id, telo, tok = T.host) => api("POST", `/me/guest-lists/${id}/invites`, tok, telo);
  r = await POST(L.id, undefined);
  assert(r.status === 400, "brez telesa: 400", r.status);
  r = await POST(L.id, { user_ids: [] });
  assert(r.status === 400, "prazen seznam: 400", r.status);
  r = await POST(L.id, { user_ids: [U.ana, U.ana] });
  assert(r.status === 400, "podvojeni id-ji: 400", r.status);
  r = await POST(L.id, { user_ids: Array.from({ length: 21 }, (_, i) => 1000 + i) });
  assert(r.status === 400, "vec kot 20: 400", r.status);
  r = await POST(L.id, { user_ids: ["5"] });
  assert(r.status === 400, "id kot niz: 400", r.status);
  r = await POST(L.id, { user_ids: [U.ana], age_confirmed: "true" });
  assert(r.status === 400, "age_confirmed kot niz: 400", r.status);
  r = await api("POST", "/me/guest-lists/abc/invites", T.host, { user_ids: [U.ana] });
  assert(r.status === 400, "id liste ni stevilo: 400", r.status);
  r = await POST(L.id, { user_ids: [U.ana] }, T.bor);
  assert(r.status === 404, "tuja lista: 404 (bor ni gostitelj)", [r.status, r.body]);
  r = await POST(999999, { user_ids: [U.ana] });
  assert(r.status === 404 && /Guest list not found/.test(r.body), "lista ne obstaja: 404", [r.status, r.body]);
  r = await POST(L.id, { user_ids: [U.tuj] });
  assert(r.status === 403 && /You can only invite friends/.test(r.body), "ne-prijatelj: 403 'You can only invite friends.'", [r.status, r.body]);
  r = await POST(L.id, { user_ids: [U.host] });
  assert(r.status === 403 && /You can only invite friends/.test(r.body), "gostitelj sam: 403", [r.status, r.body]);
  r = await POST(L.id, { user_ids: [99999] });
  assert(r.status === 403, "neobstojec uporabnik: 403 (enako kot ne-prijatelj, ne razkrije obstoja)", [r.status, r.body]);
  r = await POST(L.id, { user_ids: [U.ana, U.tuj] });
  assert(r.status === 403, "ana + tuj: 403", r.status);
  assert((await pool.query("SELECT COUNT(*)::int AS n FROM guest_list_members WHERE guest_list_id=$1", [L.id])).rows[0].n === 0, "vse ali nic: ana NI dodana", null);

  r = await POST(L.id, { user_ids: [U.ana] });
  assert(r.status === 201 && Array.isArray(r.body.added) && r.body.added[0] === U.ana && r.body.guest_list, "povabi prijatelja ane: 201 { guest_list, added }", [r.status, r.body]);
  assert(r.body.guest_list.remaining === 2 && r.body.guest_list.invited.length === 1 && r.body.guest_list.invited[0].user_id === U.ana
    && r.body.guest_list.invited[0].username === "ana" && r.body.guest_list.invited[0].status === "valid" && "avatar_url" in r.body.guest_list.invited[0], "guest_list: remaining 2, invited [{user_id, username, avatar_url, status valid}]", r.body.guest_list);
  r = await api("GET", "/me/tickets", T.ana);
  const av = r.body.find(t => t.is_guest_list && t.event_id === evA);
  assert(av && av.guest_list_host_username === "host" && av.holder_username === "ana" && av.transferable === false && av.event_id === evA && typeof av.qr === "string", "ana: vstopnica v /me/tickets z is_guest_list, 'Invited by @host', brez prenosa, QR", av);
  const anaVstopnica = av && av.id;
  assert(av && av.holder_id === U.ana && av.serial && av.serial !== hv.serial, "ana ima SVOJ serial (svoja QR koda)", av);
  r = await api("GET", "/me/tickets", T.host);
  assert(!r.body.some(t => t.id === anaVstopnica) && r.body.filter(t => t.is_guest_list).length === 1, "gostitelj v /me/tickets vidi SAMO svojo vstopnico (ne Aninih)", r.body.map(t => t.id));
  r = await POST(L.id, { user_ids: [U.ana] });
  assert(r.status === 409 && /ana is already on your guest list/.test(r.body), "podvojeno vabilo: 409 'ana is already on your guest list.'", [r.status, r.body]);
  r = await POST(L.id, { user_ids: [U.bor, U.cene, U.mlad] });
  assert(r.status === 409 && /Only 2 spots left/.test(r.body), "prevec (3 > 2): 409 'Only 2 spots left.'", [r.status, r.body]);
  assert((await pool.query("SELECT COUNT(*)::int AS n FROM guest_list_members WHERE guest_list_id=$1", [L.id])).rows[0].n === 1, "vse ali nic: po 409 ni dodan nihce", null);
  r = await POST(L.id, { user_ids: [U.bor, U.cene] });
  assert(r.status === 201 && r.body.guest_list.remaining === 0 && r.body.guest_list.invited.length === 3, "bor + cene (min_age 0, brez datuma ni problem): 201, remaining 0", [r.status, r.body]);
  r = await POST(L.id, { user_ids: [U.mlad] });
  assert(r.status === 409 && /Only 0 spots left/.test(r.body), "lista polna: 409 'Only 0 spots left.'", [r.status, r.body]);
  r = await POST(anaLista, { user_ids: [U.bor] }, T.ana);
  assert(r.status === 403 || r.status === 409, "ana nima prijatelja bor (lista z 0 mesti): 403/409", [r.status, r.body]);
  assert((await pool.query("SELECT sold_count FROM events WHERE id=$1", [evA])).rows[0].sold_count === 0, "sold_count se po vabilih ni spremenil");
  const bor1 = Number((await pool.query("SELECT t.id FROM guest_list_members m JOIN tickets t ON t.id=m.ticket_id WHERE m.guest_list_id=$1 AND m.user_id=$2", [L.id, U.bor])).rows[0].id);

  console.log("\n# 3b. Starost (I8): dogodek 18+");
  await resetLimit();
  r = await api("POST", "/admin/api/guest-lists", T.admin, { event_id: ev18, user_id: U.host, spots: 4 });
  assert(r.status === 201, "lista na dogodku 18+", r.body);
  const L18 = r.body.guest_list.id;
  r = await POST(L18, { user_ids: [U.mlad] });
  assert(r.status === 403 && /mlad is under 18/.test(r.body), "znan datum pod mejo: 403 'mlad is under 18.'", [r.status, r.body]);
  r = await POST(L18, { user_ids: [U.mlad], age_confirmed: true });
  assert(r.status === 403 && /mlad is under 18/.test(r.body), "znan mladoletnik: 403 TUDI z age_confirmed", [r.status, r.body]);
  r = await POST(L18, { user_ids: [U.cene] });
  assert(r.status === 400 && r.body.error === "age_confirmation_required" && r.body.min_age === 18, "brez datuma, brez potrditve: 400 { error: age_confirmation_required, min_age: 18 }", [r.status, r.body]);
  r = await POST(L18, { user_ids: [U.cene, U.mlad], age_confirmed: true });
  assert(r.status === 403, "cene + mlad (potrjeno): 403 zaradi mladoletnika, nic ni dodano", [r.status, r.body]);
  r = await POST(L18, { user_ids: [U.ana] });
  assert(r.status === 201, "znan datum nad mejo: potrditev ni potrebna: 201", [r.status, r.body]);
  r = await POST(L18, { user_ids: [U.cene], age_confirmed: true });
  assert(r.status === 201 && r.body.guest_list.invited.some(x => x.user_id === U.cene), "brez datuma + age_confirmed: true: 201", [r.status, r.body]);
  r = await POST(L18, { user_ids: [U.bor, U.f1] });
  assert(r.status === 201 && r.body.guest_list.remaining === 0, "polnoletna brez potrditve: 201", [r.status, r.body]);

  console.log("\n# 3c. Socasna vabila: mesta se ne morejo preseci");
  await resetLimit();
  r = await api("POST", "/admin/api/guest-lists", T.admin, { event_id: evE2, user_id: U.host, spots: 2 });
  assert(r.status === 201, "lista (2 mesti) za tekmo", r.body);
  const Ltekma = r.body.guest_list.id;
  const rs = await Promise.all(["f1", "f2", "f3", "f4", "f5"].map(k => POST(Ltekma, { user_ids: [U[k]] })));
  assert(rs.filter(x => x.status === 201).length === 2 && rs.filter(x => x.status === 409).length === 3, "5 hkratnih vabil, 2 mesti: natanko 2 x 201 in 3 x 409", rs.map(x => x.status));
  const cnt = (await pool.query("SELECT COUNT(*)::int AS n FROM guest_list_members WHERE guest_list_id=$1 AND removed_at IS NULL", [Ltekma])).rows[0].n;
  assert(cnt === 2, "v bazi natanko 2 aktivna povabljenca", cnt);

  console.log("\n# 4. Odstranitev povabljenca");
  await resetLimit();
  const DEL = (id, uid, tok = T.host) => api("DELETE", `/me/guest-lists/${id}/invites/${uid}`, tok);
  r = await DEL(L.id, U.tuj);
  assert(r.status === 404 && /not on your guest list/.test(r.body), "ni na listi: 404", [r.status, r.body]);
  r = await DEL(L.id, U.bor, T.ana);
  assert(r.status === 404, "tuja lista (ana ni gostitelj): 404", [r.status, r.body]);
  r = await DEL(L.id, "abc");
  assert(r.status === 400, "uporabnik ni stevilo: 400", r.status);
  // ana vstopi (sken), nato jo gostitelj ne more odstraniti
  // Sken je mogoc v oknu od 12 h pred zacetkom do 6 h po koncu (I25, test_sken_okno.js): dogodek A zacne cez 2 h (vabila se vedno mogoca).
  await pool.query("UPDATE events SET start_at = NOW() + INTERVAL '2 hours' WHERE id = $1", [evA]);
  r = await api("GET", "/me/tickets", T.ana);
  const qrAna = r.body.find(t => t.id === anaVstopnica).qr;
  r = await api("POST", "/business/tickets/scan", T.lastnik, { qr: qrAna });
  assert(r.status === 200 && r.body.result === "ok", "sken Anine vstopnice guest liste: ok", [r.status, r.body]);
  r = await DEL(L.id, U.ana);
  assert(r.status === 409 && /Already checked in/.test(r.body), "uporabljena vstopnica: 409 'Already checked in.'", [r.status, r.body]);
  assert((await pool.query("SELECT status FROM tickets WHERE id=$1", [anaVstopnica])).rows[0].status === "used" && (await pool.query("SELECT removed_at FROM guest_list_members WHERE ticket_id=$1", [anaVstopnica])).rows[0].removed_at === null,
    "po 409: vstopnica je se used, ana je se na listi", null);
  // bor: odstranitev = void, mesto se sprosti
  r = await DEL(L.id, U.bor);
  assert(r.status === 200 && r.body.guest_list && r.body.guest_list.remaining === 1 && r.body.guest_list.invited.length === 2 && !r.body.guest_list.invited.some(x => x.user_id === U.bor), "odstranitev bora: 200 { guest_list }, mesto sproscen (remaining 1)", [r.status, r.body]);
  assert((await pool.query("SELECT status FROM tickets WHERE id=$1", [bor1])).rows[0].status === "void", "Borova vstopnica je void");
  r = await api("GET", "/me/tickets", T.bor);
  assert(!r.body.some(t => t.id === bor1), "bor: razveljavljene vstopnice guest liste ni v /me/tickets", r.body.map(t => [t.id, t.status]));
  r = await DEL(L.id, U.bor);
  assert(r.status === 404, "ponovna odstranitev bora: 404", r.status);
  r = await POST(L.id, { user_ids: [U.bor] });
  assert(r.status === 201, "ponovno vabilo bora po odstranitvi: 201", [r.status, r.body]);
  r = await api("GET", "/me/tickets", T.bor);
  const bor2 = r.body.find(t => t.is_guest_list && t.event_id === evA);
  assert(bor2 && bor2.id !== bor1 && bor2.serial && bor2.status === "valid", "bor dobi NOVO vstopnico (druga kot odstranjena)", bor2);

  console.log("\n# 5. Prenos vstopnice guest liste: 409");
  await prijatelja("ana", "bor");
  r = await api("POST", `/tickets/${bor2.id}/transfer`, T.bor, { user_id: U.ana });
  assert(r.status === 409 && /Guest list tickets can't be transferred/.test(r.body), "prenos po user_id (prijatelju): 409 'Guest list tickets can't be transferred.'", [r.status, r.body]);
  r = await api("POST", `/tickets/${bor2.id}/transfer`, T.bor, { email: "ana@outly.si" });
  assert(r.status === 409 && /Guest list tickets can't be transferred/.test(r.body), "prenos po e-naslovu (racun): 409", [r.status, r.body]);
  r = await api("POST", `/tickets/${bor2.id}/transfer`, T.bor, { email: "nekdo-brez-racuna@example.com", allow_guest: true, age_confirmed: true });
  assert(r.status === 409 && /Guest list tickets can't be transferred/.test(r.body), "prenos GOSTU po e-naslovu (allow_guest): 409", [r.status, r.body]);
  r = await api("POST", `/tickets/${hostVstopnica}/transfer`, T.host, { email: "nekdo-brez-racuna@example.com", allow_guest: true, age_confirmed: true });
  assert(r.status === 409 && /Guest list tickets can't be transferred/.test(r.body), "gostiteljeva vstopnica se tudi ne prenasa: 409", [r.status, r.body]);
  r = await api("POST", `/tickets/${bor2.id}/transfer`, T.f1, { user_id: U.ana });
  assert(r.status === 404, "tuja vstopnica guest liste: se vedno 404 (obstoja ne razkrijemo)", [r.status, r.body]);
  assert((await pool.query("SELECT holder_user_id, holder_is_guest FROM tickets WHERE id=$1", [bor2.id])).rows[0].holder_user_id === U.bor, "imetnik nespremenjen");
  assert((await pool.query("SELECT COUNT(*)::int AS n FROM ticket_transfers WHERE ticket_id = ANY($1::bigint[])", [[bor2.id, hostVstopnica, anaVstopnica]])).rows[0].n === 0, "v ticket_transfers ni zapisa");

  console.log("\n# 6. Guest lista NI prodaja");
  // kapaciteta dogodka evA = 3; guest lista ima ze 4 vstopnice (gostitelj + ana + bor + cene), prodaja vseeno dela
  r = await api("POST", `/events/${evA}/orders`, T.kupec, { quantity: 3 });
  assert(r.status === 201 && r.body.tickets.length === 3 && r.body.order.total_cents === 3000, "kupec kupi 3 vstopnice (kapaciteta 3): guest lista ni porabila zaloge", [r.status, r.body.order]);
  assert((await pool.query("SELECT sold_count FROM events WHERE id=$1", [evA])).rows[0].sold_count === 3, "sold_count = 3 (samo prodaja)");
  r = await api("POST", `/events/${evA}/orders`, T.f2, { quantity: 1 });
  assert(r.status === 409 && /Only 0 tickets left/.test(r.body), "razprodano: 409 (kapaciteto steje samo prodaja)", [r.status, r.body]);
  r = await api("GET", `/events/${evA}`, null);
  assert(r.status === 200 && r.body.sold_count === 3, "GET /events/:id sold_count 3", r.body.sold_count);

  r = await api("GET", "/business/sales", T.lastnik);
  assert(r.status === 200, "GET /business/sales", r.status);
  const s = r.body.summary;
  assert(s.orders === 1 && s.tickets_sold === 3 && s.gross_cents === 3000 && s.buyers === 1 && s.fee_cents === 300 && s.tickets_7d === 3,
    "sales.summary: orders 1, tickets_sold 3, gross 3000, buyers 1 (brez guest liste)", s);
  const sev = r.body.events.find(e => e.id === evA);
  assert(sev && sev.tickets_sold === 3 && sev.gross_cents === 3000 && sev.sold_count === 3, "sales.events[evA]: tickets_sold 3, gross 3000, sold_count 3", sev);
  assert(sev.checked_in === 1, "sales.events[evA].checked_in = 1 (sken vstopnice guest liste STEJE med prihode: to je vstop na vrata, ne prodaja)", sev.checked_in);
  assert(r.body.recent_orders.length === 1 && r.body.recent_orders.every(o => o.total_cents === 3000), "sales.recent_orders: samo prodaja", r.body.recent_orders.map(o => o.public_ref));
  assert(r.body.sales_by_day.reduce((a, d) => a + d.gross_cents, 0) === 3000 && r.body.sales_by_day.reduce((a, d) => a + d.tickets, 0) === 3, "sales_by_day: 3 vstopnice, 3000", null);
  for (const range of ["week", "month", "year"]) {
    const x = await api("GET", `/business/sales?range=${range}`, T.lastnik);
    assert(x.body.series.reduce((a, d) => a + d.tickets, 0) === 3 && x.body.series.reduce((a, d) => a + d.gross_cents, 0) === 3000, `sales.series (${range}): 3 vstopnice, brez guest liste`, x.body.series.slice(-2));
  }
  r = await api("GET", "/admin/api/finance", T.admin);
  assert(r.status === 200, "GET /admin/api/finance", r.status);
  assert(r.body.summary.orders === 1 && r.body.summary.tickets_sold === 3 && r.body.summary.gross_cents === 3000 && r.body.summary.buyers === 1, "finance.summary: orders 1, tickets_sold 3, gross 3000, buyers 1", r.body.summary);
  assert(r.body.all_time.orders === 1 && r.body.all_time.tickets_sold === 3 && r.body.all_time.gross_cents === 3000, "finance.all_time brez guest liste", r.body.all_time);
  assert(r.body.by_event.length === 1 && r.body.by_event[0].tickets_sold === 3 && r.body.by_club.find(k => k.id === 1).orders === 1, "finance.by_event / by_club: 1 narocilo", [r.body.by_event, r.body.by_club]);
  assert(r.body.by_day.reduce((a, d) => a + d.orders, 0) === 1 && r.body.recent_orders.length === 1, "finance.by_day / recent_orders: 1 narocilo", [r.body.by_day.length, r.body.recent_orders.length]);
  r = await api("GET", "/me/orders", T.host);
  assert(r.status === 200 && r.body.length === 0, "GET /me/orders gostitelja: guest lista NI nakup (prazno)", r.body.map(o => o.public_ref));
  r = await api("GET", "/me/orders", T.ana);
  assert(r.status === 200 && r.body.length === 0, "GET /me/orders povabljenca: prazno", r.body);
  r = await api("GET", "/me/orders", T.kupec);
  assert(r.status === 200 && r.body.length === 1 && r.body[0].tickets.length === 3, "GET /me/orders kupca nespremenjen", r.body.length);
  // DB varovalo: narocilo guest liste se ne more pretvoriti v denarno (Stripe vracilo/preklic se ne more zgoditi)
  for (const [naslov, sql] of [
    ["status refunded", "UPDATE orders SET status='refunded' WHERE guest_list_id IS NOT NULL"],
    ["status cancelled", "UPDATE orders SET status='cancelled' WHERE guest_list_id IS NOT NULL"],
    ["znesek", "UPDATE orders SET total_cents=1000, unit_price_cents=1000 WHERE guest_list_id IS NOT NULL"],
    ["Stripe PaymentIntent", "UPDATE orders SET stripe_payment_intent_id='pi_x' WHERE guest_list_id IS NOT NULL"],
    ["vrnjeni centi", "UPDATE orders SET refunded_cents=1 WHERE guest_list_id IS NOT NULL"],
  ]) {
    let napaka = null; try { await pool.query(sql); } catch (e) { napaka = e; }
    assert(napaka && napaka.code === "23514" && /orders_guest_lista_chk/.test(napaka.message), `DB varovalo (CHECK): ${naslov} zavrnjeno`, napaka && napaka.message);
  }
  // sprozilec: nobene spremembe sold_count (ni nikoli vracila/preklica narocila liste, a ce bi sel status v cancelled, sprozilec preskoci)
  assert((await pool.query("SELECT sold_count FROM events WHERE id=$1", [evA])).rows[0].sold_count === 3, "sold_count se po vseh poskusih ni spremenil");
  assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE guest_list_id IS NOT NULL AND (stripe_payment_intent_id IS NOT NULL OR total_cents <> 0 OR status <> 'paid')")).rows[0].n === 0, "nobeno narocilo guest liste nima Stripa/zneska/drugega stanja");

  console.log("\n# 7. Vrata");
  r = await api("GET", "/me/tickets", T.bor);
  const qrBor = r.body.find(t => t.id === bor2.id).qr;
  for (const [kdo, tok] of [["lastnik", T.lastnik], ["vratar", T.vratar]]) {
    const qr = kdo === "lastnik" ? qrBor : (await api("GET", "/me/tickets", T.host)).body.find(t => t.id === hostVstopnica).qr;
    r = await api("POST", "/business/tickets/scan", tok, { qr });
    assert(r.status === 200 && r.body.result === "ok" && r.body.ticket.is_guest_list === true && r.body.ticket.guest_list_host_username === "host", `sken (${kdo}): ok, ticket.is_guest_list true, guest_list_host_username host`, [r.status, r.body]);
    assert(!JSON.stringify(r.body).includes("@outly.si") && !("buyer_email" in r.body.ticket) && !("holder_email" in r.body.ticket), `sken (${kdo}): v odgovoru NI e-naslovov (gostitelj ne povabljenec)`, r.body.ticket);
  }
  r = await api("POST", "/business/tickets/scan", T.lastnik, { qr: qrBor });
  assert(r.status === 409 && r.body.result === "already_used", "dvojni sken: 409 already_used (I1 velja tudi za vstopnice guest liste)", [r.status, r.body.result]);
  assert(!JSON.stringify(r.body).includes("@outly.si"), "already_used: brez e-naslovov", r.body);
  r = await api("GET", `/business/events/${evA}/scan-list`, T.vratar);
  const sl = r.body.tickets.filter(t => t.is_guest_list);
  assert(r.status === 200 && sl.length === 5 && sl.every(t => t.guest_list_host_username === "host") && !/@/.test(r.text) , "scan-list: 5 vstopnic guest liste (gostitelj, ana, bor void, cene, bor) z is_guest_list, guest_list_host_username, brez e-naslovov", [r.status, sl.length]);
  assert(r.body.tickets.filter(t => !t.is_guest_list).length === 3 && r.body.tickets.filter(t => !t.is_guest_list).every(t => t.is_guest_list === false && t.guest_list_host_username === null), "scan-list: navadne vstopnice is_guest_list false, host null", null);
  const ceneSerial = (await api("GET", "/me/tickets", T.cene)).body.find(t => t.is_guest_list).serial;
  assert(sl.find(t => t.holder_username === "ana").status === "used" && sl.find(t => t.holder_username === "host").status === "used" && sl.find(t => t.serial === ceneSerial).status === "valid"
    && sl.filter(t => t.status === "void").length === 1, "scan-list: statusi (ana, host used; cene valid; Borova stara vstopnica void)", sl.map(t => [t.holder_username, t.status]));
  r = await api("GET", `/business/events/${evA}/tickets`, T.lastnik);
  const bt = r.body.filter(t => t.is_guest_list);
  assert(r.status === 200 && bt.length === 5 && bt.every(t => t.guest_list_host_username === "host" && !("buyer_email" in t) && !("holder_email" in t)), "poslovne vstopnice (lastnik): polja guest liste, e-naslovov gostitelja in povabljenih ni (nobena vloga)", bt[0]);
  const nav = r.body.filter(t => !t.is_guest_list);
  assert(nav.length === 3 && nav.every(t => t.is_guest_list === false && t.guest_list_host_username === null && t.buyer_email === "kupec@outly.si"), "poslovne vstopnice: navadne ohranijo buyer_email za lastnika (nespremenjeno)", nav[0]);
  r = await api("GET", `/business/events/${evA}/tickets`, T.vratar);
  assert(r.status === 200 && r.body.every(t => !("buyer_email" in t) && !("holder_email" in t)), "poslovne vstopnice (vratar): nikjer e-naslovov", null);

  console.log("\n# 8. Admin: seznam, PATCH, preklic");
  await resetLimit();
  r = await api("GET", `/admin/api/guest-lists?event_id=${evA}`, T.admin);
  assert(r.status === 200 && r.body.guest_lists.length === 1, "admin GET ?event_id: lista dogodka", r.body.guest_lists && r.body.guest_lists.length);
  const aL = r.body.guest_lists.find(x => x.id === L.id);
  assert(aL.invited.length === 3 && aL.remaining === 0 && aL.host.username === "host" && aL.created_at && aL.revoked_at === null, "admin GET: invited 3, remaining 0, host, created_at, revoked_at", aL);
  r = await api("GET", "/admin/api/guest-lists", T.admin);
  assert(r.status === 200 && r.body.guest_lists.length >= 4, "admin GET brez parametra: liste prihodnjih dogodkov", r.body.guest_lists && r.body.guest_lists.length);
  r = await api("GET", "/admin/api/guest-lists?event_id=abc", T.admin);
  assert(r.status === 400, "admin GET: event_id ni stevilo: 400", r.status);
  r = await api("GET", "/admin/api/guest-lists", T.host);
  assert(r.status === 403, "admin GET: navaden uporabnik 403", r.status);
  r = await api("PATCH", `/admin/api/guest-lists/${L.id}`, T.host, { spots: 10 });
  assert(r.status === 403, "PATCH: navaden uporabnik 403", r.status);
  r = await api("PATCH", `/admin/api/guest-lists/${L.id}`, T.admin, { spots: 2 });
  assert(r.status === 409 && /below the number of people already invited \(3\)/.test(r.body), "PATCH spots pod stevilo povabljenih (3): 409", [r.status, r.body]);
  r = await api("PATCH", `/admin/api/guest-lists/${L.id}`, T.admin, { spots: 21 });
  assert(r.status === 400, "PATCH spots 21: 400", r.status);
  r = await api("PATCH", `/admin/api/guest-lists/${L.id}`, T.admin, {});
  assert(r.status === 400, "PATCH brez polj: 400", r.status);
  r = await api("PATCH", `/admin/api/guest-lists/${L.id}`, T.admin, { note: "y".repeat(201) });
  assert(r.status === 400, "PATCH note predolg: 400", r.status);
  r = await api("PATCH", "/admin/api/guest-lists/999999", T.admin, { spots: 3 });
  assert(r.status === 404, "PATCH neobstojec: 404", r.status);
  r = await api("PATCH", `/admin/api/guest-lists/${L.id}`, T.admin, { spots: 5, note: "Nova opomba" });
  assert(r.status === 200 && r.body.guest_list.spots === 5 && r.body.guest_list.remaining === 2 && r.body.guest_list.note === "Nova opomba", "PATCH spots 5 + opomba: 200, remaining 2", [r.status, r.body]);
  r = await api("PATCH", `/admin/api/guest-lists/${L.id}`, T.admin, { note: "" });
  assert(r.status === 200 && r.body.guest_list.note === "" && r.body.guest_list.spots === 5, "PATCH samo opomba (prazna): spots ostane", [r.status, r.body]);
  r = await POST(L.id, { user_ids: [U.f1, U.f2] });
  assert(r.status === 201 && r.body.guest_list.remaining === 0, "gostitelj po povecanju mest povabi se 2", [r.status, r.body]);

  // preklic
  r = await api("GET", "/me/tickets", T.cene);
  const ceneV = r.body.find(t => t.is_guest_list && t.event_id === evA);
  r = await api("DELETE", `/admin/api/guest-lists/${L.id}`, T.host);
  assert(r.status === 403, "preklic: navaden uporabnik 403", r.status);
  r = await api("DELETE", "/admin/api/guest-lists/999999", T.admin);
  assert(r.status === 404, "preklic neobstojece: 404", r.status);
  r = await api("DELETE", `/admin/api/guest-lists/${L.id}`, T.admin);
  assert(r.status === 200 && r.body.guest_list.revoked_at, "admin prekliche listo: 200, revoked_at", [r.status, r.body]);
  const po = (await pool.query(
    `SELECT t.holder_user_id, t.status FROM tickets t JOIN orders o ON o.id = t.order_id WHERE o.guest_list_id = $1 ORDER BY t.id`, [L.id])).rows;
  assert(po.length === 7 && po.filter(t => t.status === "void").length === 4 && po.filter(t => t.status === "used").length === 3,
    "preklic: neuporabljene vstopnice void (bor1, cene, f1, f2), uporabljene (host, ana, bor) ostanejo used", po);
  r = await api("GET", "/me/guest-lists", T.host);
  assert(r.body.guest_lists.every(x => x.id !== L.id), "preklicana lista ni vec v GET /me/guest-lists", r.body.guest_lists.map(x => x.id));
  r = await api("GET", "/me/tickets", T.cene);
  assert(!r.body.some(t => t.id === ceneV.id), "cene: preklicana vstopnica ni v /me/tickets", null);
  r = await api("POST", "/business/tickets/scan", T.lastnik, { serial: ceneV.serial });
  assert(r.status === 409 && r.body.result === "void", "sken razveljavljene vstopnice: 409 void (ni vstopa)", [r.status, r.body]);
  r = await api("GET", `/business/events/${evA}/scan-list`, T.vratar);
  assert(r.body.tickets.find(t => t.serial === ceneV.serial).status === "void", "scan-list: razveljavljena vstopnica ima status void", null);
  r = await POST(L.id, { user_ids: [U.f3] });
  assert(r.status === 409 && /closed/.test(r.body), "vabilo na preklicano listo: 409 'This guest list is closed.'", [r.status, r.body]);
  r = await DEL(L.id, U.ana);
  assert(r.status === 409 && /closed/.test(r.body), "odstranitev na preklicani listi: 409 closed", [r.status, r.body]);
  r = await api("DELETE", `/admin/api/guest-lists/${L.id}`, T.admin);
  assert(r.status === 200 && r.body.guest_list.revoked_at, "ponovni preklic: 200 brez ucinka", [r.status, r.body]);
  r = await api("PATCH", `/admin/api/guest-lists/${L.id}`, T.admin, { spots: 3 });
  assert(r.status === 409 && /revoked/.test(r.body), "PATCH preklicane: 409", [r.status, r.body]);
  r = await api("POST", "/admin/api/guest-lists", T.admin, { event_id: evA, user_id: U.host, spots: 1 });
  assert(r.status === 201, "po preklicu je nova lista istega uporabnika na istem dogodku mogoca: 201", [r.status, r.body]);
  assert(r.body.guest_list.id !== L.id, "nova lista, nov id", null);
  r = await api("GET", "/me/guest-lists", T.host);
  assert(r.body.guest_lists.filter(x => x.event.id === evA).length === 1 && r.body.guest_lists[0].spots !== undefined, "gostitelj vidi samo novo listo na dogodku A", r.body.guest_lists.map(x => [x.id, x.event.id]));
  assert((await pool.query("SELECT sold_count FROM events WHERE id=$1", [evA])).rows[0].sold_count === 3, "sold_count po preklicu in novi listi: se vedno 3");

  console.log("\n# 8b. Dogodek: koncan (vidna 12 h), odpovedan, izbris dogodka z listo");
  r = await api("POST", "/admin/api/guest-lists", T.admin, { event_id: evC, user_id: U.host, spots: 2 });
  const LC = r.body.guest_list.id;
  r = await POST(LC, { user_ids: [U.f4] });
  assert(r.status === 201, "lista na dogodku C: vabilo ok", r.status);
  r = await api("GET", "/me/tickets", T.f4);
  const qrF4 = r.body.find(t => t.is_guest_list && t.event_id === evC).qr;
  r = await api("PATCH", `/events/${evC}`, T.lastnik, { status: "cancelled" });
  assert(r.status === 200, "klub odpove dogodek C", r.status);
  r = await api("GET", "/me/guest-lists", T.host);
  const lc = r.body.guest_lists.find(x => x.id === LC);
  assert(lc && lc.event.status === "cancelled" && lc.can_invite === false, "odpovedan dogodek: lista vidna, event.status cancelled, can_invite false", lc);
  r = await POST(LC, { user_ids: [U.f5] });
  assert(r.status === 409 && /closed/.test(r.body), "vabilo na odpovedan dogodek: 409 closed", [r.status, r.body]);
  r = await api("POST", "/business/tickets/scan", T.lastnik, { qr: qrF4 });
  assert(r.status === 409 && r.body.result === "event_cancelled", "sken na odpovedanem dogodku: 409 event_cancelled (I21)", [r.status, r.body.result]);
  // koncan dogodek (pred 2 h): lista vidna, brez vabil
  r = await api("POST", "/admin/api/guest-lists", T.admin, { event_id: evKoncan, user_id: U.host, spots: 2 });
  assert(r.status === 409, "admin: lista na ze koncanem dogodku: 409", [r.status, r.body]);
  await pool.query("UPDATE events SET start_at = NOW() + INTERVAL '3 days', end_at = NULL WHERE id = $1", [evKoncan]);
  r = await api("POST", "/admin/api/guest-lists", T.admin, { event_id: evKoncan, user_id: U.host, spots: 2 });
  assert(r.status === 201, "lista na (zdaj prihodnjem) dogodku", r.status);
  const LK = r.body.guest_list.id;
  await pool.query("UPDATE events SET start_at = NOW() - INTERVAL '10 hours', end_at = NOW() - INTERVAL '2 hours' WHERE id = $1", [evKoncan]);
  r = await api("GET", "/me/guest-lists", T.host);
  const lk = r.body.guest_lists.find(x => x.id === LK);
  assert(lk && lk.can_invite === false, "dogodek koncan pred 2 h: lista je se vidna (12 h), can_invite false", lk);
  r = await POST(LK, { user_ids: [U.f5] });
  assert(r.status === 409 && /closed/.test(r.body), "vabilo po koncu dogodka: 409 closed", [r.status, r.body]);
  await pool.query("UPDATE events SET start_at = NOW() - INTERVAL '40 hours', end_at = NOW() - INTERVAL '30 hours' WHERE id = $1", [evKoncan]);
  r = await api("GET", "/me/guest-lists", T.host);
  assert(!r.body.guest_lists.some(x => x.id === LK), "dogodek koncan pred 30 h: lista ni vec v GET /me/guest-lists", null);
  r = await api("POST", "/admin/api/guest-lists", T.admin, { event_id: evD, user_id: U.host, spots: 1 });
  assert(r.status === 201, "lista na dogodku D (brez prodaje)", r.status);
  r = await api("DELETE", `/events/${evD}`, T.lastnik);
  assert(r.status === 200 && r.body.event && r.body.event.status === "cancelled", "DELETE /events/:id dogodka s samo guest listo: 200, dogodek se odpove (ne brise; FK na vstopnice)", [r.status, r.body]);

  console.log("\n# 9. Izbris racuna");
  await resetLimit();
  r = await api("POST", "/admin/api/guest-lists", T.admin, { event_id: evPrazen, user_id: U.host, spots: 3 });
  const LP = r.body.guest_list.id;
  r = await POST(LP, { user_ids: [U.brisan, U.f1] });
  assert(r.status === 201, "lista na dogodku Prazen: povabljena brisan in f1", [r.status, r.body]);
  r = await api("GET", "/me/tickets", T.brisan);
  const brisanV = r.body.find(t => t.is_guest_list);
  r = await api("DELETE", "/me", T.brisan, { password: "x" });
  assert(r.status === 200, "povabljenec izbrise racun: 200", [r.status, r.body]);
  assert((await pool.query("SELECT status FROM tickets WHERE id=$1", [brisanV.id])).rows[0].status === "void", "izbris povabljenca: njegova vstopnica je void");
  assert((await pool.query("SELECT removed_at FROM guest_list_members WHERE ticket_id=$1", [brisanV.id])).rows[0].removed_at !== null, "izbris povabljenca: mesto je sproscen (removed_at)");
  r = await api("GET", "/me/tickets", T.host);
  assert(!r.body.some(t => t.id === brisanV.id), "gostitelj NE dobi vstopnice izbrisanega povabljenca (holder SET NULL ne zdrsne na gostitelja)", r.body.map(t => t.id));
  r = await api("GET", "/me/guest-lists", T.host);
  const lp = r.body.guest_lists.find(x => x.id === LP);
  assert(lp && lp.remaining === 2 && lp.invited.length === 1 && lp.invited[0].user_id === U.f1, "gostitelj: lista ima 2 prosti mesti, povabljen ostane f1", lp);
  r = await api("POST", "/admin/api/guest-lists", T.admin, { event_id: evPrazen, user_id: U.host2, spots: 2 });
  const LH2 = r.body.guest_list.id;
  r = await POST(LH2, { user_ids: [U.prij2] }, T.host2);
  assert(r.status === 201, "host2 povabi prij2", [r.status, r.body]);
  r = await api("GET", "/me/tickets", T.prij2);
  const prijV = r.body.find(t => t.is_guest_list);
  r = await api("DELETE", "/me", T.host2, { password: "x" });
  assert(r.status === 200, "gostitelj izbrise racun: 200", [r.status, r.body]);
  const l2 = (await pool.query("SELECT revoked_at FROM guest_lists WHERE id=$1", [LH2])).rows[0];
  assert(l2.revoked_at !== null, "izbris gostitelja: lista je preklicana");
  assert((await pool.query(`SELECT COUNT(*)::int AS n FROM tickets t JOIN orders o ON o.id=t.order_id WHERE o.guest_list_id=$1 AND t.status='valid'`, [LH2])).rows[0].n === 0, "izbris gostitelja: nobena vstopnica liste ni vec veljavna");
  r = await api("GET", "/me/tickets", T.prij2);
  assert(!r.body.some(t => t.id === prijV.id), "prij2: vstopnica preklicane liste ni vec v /me/tickets", null);
  const nar2 = (await pool.query("SELECT user_id, buyer_email FROM orders WHERE guest_list_id=$1", [LH2])).rows[0];
  assert(nar2.user_id === null && nar2.buyer_email.startsWith("izbrisan-"), "izbris gostitelja: narocilo liste anonimizirano (buyer_email), ostane", nar2);

  console.log("\n# 10. Omejevalnik POST invites in admin panel");
  await resetLimit();
  let zadnji = null;
  for (let i = 0; i < 31; i++) zadnji = await POST(LP, { user_ids: [] });
  assert(zadnji.status === 429, "31. zahtevek v eni uri (30/h/IP): 429", zadnji.status);
  r = await DEL(LP, U.f1);
  assert(r.status === 429, "isti kljuc velja tudi za odstranitev: 429", r.status);
  await resetLimit();

  const html = fs.readFileSync(path.join(__dirname, "..", "admin", "index.html"), "utf8");
  const od = html.indexOf("// ---------- guest lists");
  const do_ = html.indexOf("// ---------- zagon");
  assert(od > 0 && do_ > od && /data-z="guest"/.test(html) && /id="z-guest"/.test(html), "admin panel ima razdelek »Guest lists« (zavihek + sekcija + koda)", [od, do_]);
  const koda = html.slice(od, do_);
  assert(!/innerHTML|insertAdjacentHTML|outerHTML|document\.write/.test(koda), "admin panel: koda guest liste NE rabi innerHTML (podatki samo prek textContent, XSS)", null);
  assert(/\/admin\/api\/guest-lists/.test(koda) && /\/admin\/api\/users\?q=/.test(koda) && /\/admin\/api\/events/.test(koda) && /"PATCH"/.test(koda) && /"DELETE"/.test(koda), "admin panel: uporablja obstojece poti za uporabnike in dogodke ter PATCH/DELETE guest-lists", null);

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  const napake = log.split("\n").filter(l => /error|TypeError|Unhandled/i.test(l) && !/Server error\./.test(l) && !/Resend/i.test(l));
  if (napake.length) console.log("\nLog backenda (sumljivo):\n" + napake.join("\n"));
  srv.kill(); jwksServer.close(); await pool.end();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); if (srv) srv.kill(); process.exit(1); });
