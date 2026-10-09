#!/usr/bin/env node
/**
 * Test: ORGANIZATORJI BREZ PRIZORISCA (migracija 037, 9. 10. 2026, invarianta I26). Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_organizatorji.js
 * Vzorec kot test_vabila.js / test_gost.js: lokalni JWKS (3977), lazni Resend (3978), backend na svojem portu (3177), TRUNCATE na zacetku.
 *
 *  1  klub / organizator: POST /clubs z isOrganizer (brez mesta), is_official ga lastnik ne more nastaviti (POST, PATCH), star klub ima is_organizer=false
 *  2  admin: ustvari / uredi klub z isOrganizer in isOfficial (samo admin pot); neveljavna vrednost 400
 *  3  dogodek organizatorja: brez prizorisca 400, venueClubId (201), prosto prizorisce (201), lastni klub 400, neobstojec 404, skrit 404, koordinate
 *  4  PATCH dogodka: menjava prizorisca (gostitelj <-> prosto besedilo), brez prizorisca 400, naslov brez dotika prizorisca ostane
 *  5  javni seznami: GET /events, GET /events/:id, /events?clubId=: venue_* polja, club_name, hosted, osnutek/odpovedan se ne kaze gostitelju
 *  6  denar in sken (I26): prodajalec je organizator, ekipa gostitelja NE more skenirati (403 wrong_club), organizatorjeva lahko; scan-list gostitelju 404
 *  7  vstopnice: /me/tickets ima prizorisce; mail gosta (potrdilo) in PDF imata prizorisce gostitelja ali prosto vpisano, ne organizatorjevega naslova; prenos gostu
 *  8  zemljevid / iskanje: organizator brez koordinat ni pin; iskanje dogodkov vrne venue_*
 *  9  baza: CHECK venue_club_id <> club_id, koordinate v paru; izbris gostitelja -> venue_club_id NULL
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3177, JWKS_PORT = 3977, RESEND_PORT = 3978;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-organizatorji";
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
const pocakaj = (ms) => new Promise(r => setTimeout(r, ms));
async function cakaj(pogoj, ms = 6000) { const do_ = Date.now() + ms; while (Date.now() < do_) { if (await pogoj()) return true; await pocakaj(100); } return false; }

// ---------- lazni Resend ----------
const poslano = [];
const resendServer = http.createServer((req, res) => {
  let d = ""; req.on("data", x => d += x);
  req.on("end", () => {
    if (req.method === "POST" && req.url === "/emails") {
      poslano.push(JSON.parse(d));
      res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify({ id: "mail_" + poslano.length }));
    }
    res.writeHead(404, { "content-type": "application/json" }); res.end("{}");
  });
});
const poslanoNa = (email) => poslano.filter(m => m.to === email || (Array.isArray(m.to) && m.to.includes(email)));
const pdfIzMaila = (m) => { const p = (m.attachments || []).find(x => x.content_type === "application/pdf"); return p ? Buffer.from(p.content, "base64").toString("latin1") : ""; };

let srv = null;
(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, guest_list_members, guest_lists, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  await new Promise(r => resendServer.listen(RESEND_PORT, r));
  srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "re_test",
    RESEND_BASE_URL: `http://127.0.0.1:${RESEND_PORT}`, EMAIL_FROM: "Outly <test@outly.test>", QR_SECRET: "test", APP_URL: "https://outly.test", PRENOS_BREZ_RACUNA: "vsi", GOST_NAKUP_NA_URO: "1000" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await pocakaj(100); } }
  const sqlKoda = async (q, p) => { try { await pool.query(q, p); return null; } catch (e) { return e.code || String(e.message); } };

  try {
    const T = {};
    for (const [i, ime] of ["admin", "hostown", "hostdoor", "orgown", "orgdoor", "outlyown", "kupec", "drugi"].entries()) T[ime] = zeton(`${ime}@outly.si`, uuid(i + 1));
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("UPDATE users SET role='business' WHERE email IN ('hostown@outly.si','orgown@outly.si','outlyown@outly.si','drugi@outly.si')");
    const uid = async (ime) => (await pool.query("SELECT id FROM users WHERE email=$1", [`${ime}@outly.si`])).rows[0].id;
    // gostiteljski klub (star nacin: samo obstojeci stolpci)
    const host = (await pool.query(
      `INSERT INTO clubs (owner_user_id, name, city, address, lat, lng, logo_url) VALUES ($1, 'Gostitelj Klub', 'Ljubljana', 'Slovenska 1', 46.05, 14.5, 'https://img.test/host.png') RETURNING id`, [await uid("hostown")])).rows[0].id;
    const tuji = (await pool.query(`INSERT INTO clubs (owner_user_id, name, city) VALUES ($1, 'Drugi Klub', 'Maribor') RETURNING id`, [await uid("drugi")])).rows[0].id;
    await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES ($1, $2, 'doorman')", [host, await uid("hostdoor")]);

    // ============================================================
    console.log("\n# 1. Klub / organizator");
    let r = await api("GET", `/clubs/${host}`);
    assert(r.status === 200 && r.body.is_organizer === false && r.body.is_official === false, "star klub (brez novih podatkov): is_organizer=false, is_official=false", r.body);
    r = await api("GET", "/clubs");
    assert(r.status === 200 && r.body.length >= 2 && r.body.every(k => k.is_organizer === false && k.is_official === false), "GET /clubs: vsak klub ima obe polji (false)", r.body.map(k => [k.id, k.is_organizer, k.is_official]));

    r = await api("POST", "/clubs", T.orgown, { name: "Promotor X", isOrganizer: true, isOfficial: true });
    assert(r.status === 201 && r.body.is_organizer === true, "POST /clubs z isOrganizer (brez mesta in naslova) -> 201, is_organizer", r.body);
    assert(r.body.is_official === false, "POST /clubs z isOfficial:true -> is_official ostane false (samo admin)", r.body.is_official);
    assert(r.body.city === "" && r.body.address === "", "organizator: city in address prazna", [r.body.city, r.body.address]);
    const org = r.body.id;
    r = await api("POST", "/clubs", T.orgown, { name: "X", isOrganizer: "ja" });
    assert(r.status === 400, "POST /clubs: isOrganizer ni boolean -> 400", [r.status, r.body]);
    r = await api("GET", "/business/clubs/me", T.orgown);
    assert(r.status === 200 && r.body.is_organizer === true && r.body.is_official === false, "GET /business/clubs/me: is_organizer, is_official", r.body);
    r = await api("GET", `/clubs/${org}`);
    assert(r.status === 200 && r.body.is_organizer === true && r.body.is_official === false && r.body.lat === null, "GET /clubs/:id organizatorja: brez pina (lat null)", r.body);
    await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES ($1, $2, 'doorman')", [org, await uid("orgdoor")]);

    r = await api("PATCH", "/business/clubs/me", T.orgown, { isOfficial: true, is_official: true, description: "Opis" });
    assert(r.status === 200 && r.body.is_official === false && r.body.description === "Opis", "PATCH /business/clubs/me: isOfficial / is_official se NE sprejmeta (is_official false), ostalo se shrani", r.body);
    r = await api("PATCH", "/business/clubs/me", T.hostown, { is_official: true });
    assert(r.status === 200 && r.body.is_official === false, "PATCH /business/clubs/me (navaden klub): is_official ostane false", r.body);
    r = await api("PATCH", "/business/clubs/me", T.hostown, { is_organizer: true });
    assert(r.status === 200 && r.body.is_organizer === true, "PATCH /business/clubs/me: is_organizer (snake_case) se sprejme", r.body);
    r = await api("PATCH", "/business/clubs/me", T.hostown, { isOrganizer: false });
    assert(r.status === 200 && r.body.is_organizer === false, "PATCH /business/clubs/me: isOrganizer (camelCase) nazaj na false", r.body);
    r = await api("PATCH", "/business/clubs/me", T.hostown, { isOrganizer: "da" });
    assert(r.status === 400, "PATCH /business/clubs/me: isOrganizer ni boolean -> 400", [r.status, r.body]);
    r = await api("PATCH", "/business/clubs/me", T.orgown, { city: "", address: "", lat: null, lng: null });
    assert(r.status === 200 && r.body.is_organizer === true, "PATCH organizatorja s praznim mestom/naslovom je v redu", r.body);
    r = await api("GET", "/me/clubs/following", T.kupec);
    assert(r.status === 200 && r.body.clubs.every(k => "is_organizer" in k && "is_official" in k), "/me/clubs/following: klubi imajo novi polji", r.body);

    // ============================================================
    console.log("\n# 2. Admin: is_organizer in is_official");
    r = await api("POST", "/admin/api/clubs", T.admin, { ownerEmail: "outlyown@outly.si", name: "Outly", isOrganizer: true, isOfficial: true });
    assert(r.status === 201 && r.body.is_organizer === true && r.body.is_official === true, "admin POST /admin/api/clubs: isOrganizer + isOfficial -> oba true", r.body);
    const outly = r.body.id;
    r = await api("GET", `/clubs/${outly}`);
    assert(r.status === 200 && r.body.is_official === true && r.body.is_organizer === true, "GET /clubs/:id Outly: is_official, is_organizer", r.body);
    r = await api("GET", "/admin/api/clubs", T.admin);
    const aOutly = r.body.find && r.body.find(k => k.id === outly), aHost = r.body.find && r.body.find(k => k.id === host);
    assert(aOutly && aOutly.is_official === true && aOutly.is_organizer === true && aHost && aHost.is_official === false, "admin GET /admin/api/clubs: polji v seznamu", [aOutly, aHost]);
    r = await api("PATCH", `/admin/api/clubs/${org}`, T.admin, { isOfficial: true });
    assert(r.status === 200 && r.body.is_official === true, "admin PATCH: isOfficial -> true", r.body);
    r = await api("PATCH", `/admin/api/clubs/${org}`, T.admin, { is_official: false });
    assert(r.status === 200 && r.body.is_official === false && r.body.is_organizer === true, "admin PATCH: is_official (snake_case) -> false, is_organizer ostane", r.body);
    r = await api("PATCH", `/admin/api/clubs/${org}`, T.admin, { isOfficial: "ja" });
    assert(r.status === 400, "admin PATCH: isOfficial ni boolean -> 400", [r.status, r.body]);
    r = await api("PATCH", `/admin/api/clubs/${org}`, T.admin, { isOrganizer: 1 });
    assert(r.status === 400, "admin PATCH: isOrganizer ni boolean -> 400", [r.status, r.body]);
    r = await api("POST", "/admin/api/clubs", T.orgown, { ownerEmail: "orgown@outly.si", name: "Napad", isOfficial: true });
    assert(r.status === 403, "navaden uporabnik ne more na admin pot (is_official samo prek admina)", r.status);

    // ============================================================
    console.log("\n# 3. Dogodek organizatorja: prizorisce");
    const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    const cez2h = new Date(Date.now() + 2 * 3600 * 1000).toISOString();
    const nov = (tok, telo) => api("POST", "/events", tok, { clubId: org, title: "Org Dogodek", startAt: cezDan, ticketPriceCents: 1500, capacity: 100, minAge: 0, ...telo });
    r = await nov(T.orgown, {});
    assert(r.status === 400 && /Organizer events need a venue\./.test(r.text), "organizator brez prizorisca -> 400 »Organizer events need a venue.«", r);
    r = await nov(T.orgown, { venueName: "Lokal brez mesta" });
    assert(r.status === 400, "samo venueName (brez mesta) -> 400", r.status);
    r = await nov(T.orgown, { venueCity: "Maribor" });
    assert(r.status === 400, "samo venueCity (brez imena) -> 400", r.status);
    r = await nov(T.orgown, { venueClubId: org });
    assert(r.status === 400, "venueClubId = lastni klub -> 400", [r.status, r.body]);
    r = await nov(T.orgown, { venueClubId: 99999 });
    assert(r.status === 404, "neobstojec venueClubId -> 404", [r.status, r.body]);
    r = await nov(T.orgown, { venueClubId: "abc" });
    assert(r.status === 400, "venueClubId ni stevilo -> 400", [r.status, r.body]);
    r = await nov(T.orgown, { venueName: "Lokal", venueCity: "Maribor", venueLat: 46.5 });
    assert(r.status === 400, "venueLat brez venueLng -> 400", r.status);
    r = await nov(T.orgown, { venueName: "Lokal", venueCity: "Maribor", venueLat: 200, venueLng: 15 });
    assert(r.status === 400, "venueLat izven obsega -> 400", r.status);
    r = await nov(T.orgown, { venueName: "Lokal", venueCity: "Maribor", venueLat: "x", venueLng: "y" });
    assert(r.status === 400, "venueLat/venueLng nista stevili -> 400", r.status);
    await pool.query("UPDATE clubs SET hidden = TRUE WHERE id=$1", [tuji]);
    r = await nov(T.orgown, { venueClubId: tuji });
    assert(r.status === 404, "skrit klub kot prizorisce -> 404", [r.status, r.body]);
    await pool.query("UPDATE clubs SET hidden = FALSE WHERE id=$1", [tuji]);

    // dogodek znotraj okna skena (2 h) za test skena in mailov
    r = await nov(T.orgown, { title: "Org Noc", startAt: cez2h, venueClubId: host });
    assert(r.status === 201 && r.body.venue_club_id === host && r.body.club_id === org, "organizator + venueClubId -> 201 (venue_club_id gostitelj, club_id organizator)", r.body);
    assert(r.body.venue_club_name === "Gostitelj Klub" && r.body.venue_club_logo_url === "https://img.test/host.png", "odgovor POST: venue_club_name in venue_club_logo_url", r.body);
    assert(r.body.venue_name === "" && r.body.venue_address === "" && r.body.venue_city === "" && r.body.venue_lat === null && r.body.venue_lng === null, "gostitelj: prosta polja prazna / null", r.body);
    const evHost = r.body.id;
    r = await nov(T.orgown, { title: "Org Prosto", startAt: cez2h, venueName: "Lokal X", venueAddress: "Ulica 3", venueCity: "Maribor", venueLat: 46.55, venueLng: 15.64 });
    assert(r.status === 201 && r.body.venue_club_id === null && r.body.venue_name === "Lokal X" && r.body.venue_address === "Ulica 3" && r.body.venue_city === "Maribor"
      && r.body.venue_lat === 46.55 && r.body.venue_lng === 15.64 && r.body.venue_club_name === null, "prosto prizorisce -> 201, vsa polja venue_*", r.body);
    const evProsto = r.body.id;
    r = await nov(T.orgown, { title: "Org Oboje", venue_club_id: host, venue_name: "Ignoriraj", venue_city: "Celje", venue_lat: 46.2, venue_lng: 15.2 });
    assert(r.status === 201 && r.body.venue_club_id === host && r.body.venue_name === "" && r.body.venue_city === "" && r.body.venue_lat === null,
      "venue_club_id (snake_case) + prosta polja -> prosta se ignorirajo (prazna)", r.body);
    const evOboje = r.body.id;
    r = await nov(T.orgown, { title: "Org Osnutek", status: "draft", venueClubId: host });
    assert(r.status === 201 && r.body.status === "draft", "osnutek z gostiteljem -> 201", r.body);
    const evOsnutek = r.body.id;
    r = await nov(T.orgown, { title: "Org Odpovedan", status: "cancelled", venueClubId: host });
    const evOdp = r.body.id;
    r = await nov(T.orgown, { title: "Org Tretji", venueClubId: tuji });
    assert(r.status === 201 && r.body.venue_club_id === tuji, "organizator: drug gostitelj -> 201", r.body);
    const evTuji = r.body.id;

    // navaden klub: prizorisce ni obvezno, sme ga podati
    r = await api("POST", "/events", T.hostown, { clubId: host, title: "Moj Dogodek", startAt: cezDan, ticketPriceCents: 1000, capacity: 50, minAge: 0 });
    assert(r.status === 201 && r.body.venue_club_id === null && r.body.venue_name === "", "navaden klub brez prizorisca -> 201 (venue prazen)", r.body);
    const evMoj = r.body.id;
    r = await api("POST", "/events", T.hostown, { clubId: host, title: "Moj Gost", startAt: cezDan, ticketPriceCents: 1000, capacity: 50, minAge: 0, venueClubId: tuji });
    assert(r.status === 201 && r.body.venue_club_id === tuji, "navaden klub sme podati prizorisce -> 201", r.body);
    r = await api("POST", "/events", T.hostown, { clubId: host, title: "Moj Napaka", startAt: cezDan, venueClubId: host });
    assert(r.status === 400, "navaden klub: venueClubId = lastni klub -> 400", [r.status, r.body]);
    r = await api("POST", "/events", T.hostown, { clubId: org, title: "Tuj", startAt: cezDan, venueClubId: host });
    assert(r.status === 403, "ekipa gostitelja ne more ustvariti dogodka organizatorja -> 403", [r.status, r.body]);

    // ============================================================
    console.log("\n# 4. PATCH dogodka");
    r = await api("PATCH", `/events/${evHost}`, T.orgown, { title: "Org Noc (popravek)" });
    assert(r.status === 200 && r.body.title === "Org Noc (popravek)" && r.body.venue_club_id === host, "PATCH naslova: prizorisce ostane", r.body);
    r = await api("PATCH", `/events/${evHost}`, T.hostown, { title: "Hijack" });
    assert(r.status === 403, "ekipa gostitelja ne more urejati organizatorjevega dogodka -> 403", [r.status, r.body]);
    r = await api("PATCH", `/events/${evHost}`, T.orgown, { venueClubId: org });
    assert(r.status === 400, "PATCH venueClubId = lastni klub -> 400", [r.status, r.body]);
    r = await api("PATCH", `/events/${evHost}`, T.orgown, { venueClubId: 99999 });
    assert(r.status === 404, "PATCH neobstojec venueClubId -> 404", [r.status, r.body]);
    r = await api("PATCH", `/events/${evHost}`, T.orgown, { venueClubId: null });
    assert(r.status === 400 && /Organizer events need a venue\./.test(r.text), "PATCH venueClubId:null brez prostega prizorisca -> 400", r);
    r = await api("PATCH", `/events/${evHost}`, T.orgown, { venueClubId: tuji });
    assert(r.status === 200 && r.body.venue_club_id === tuji && r.body.venue_club_name === "Drugi Klub", "PATCH: nov gostitelj (odgovor ima venue_club_name)", r.body);
    r = await api("PATCH", `/events/${evHost}`, T.orgown, { venueName: "Klet", venueAddress: "Trg 1", venueCity: "Celje", venueLat: 46.23, venueLng: 15.26 });
    assert(r.status === 200 && r.body.venue_club_id === null && r.body.venue_name === "Klet" && r.body.venue_city === "Celje" && r.body.venue_lat === 46.23 && r.body.venue_club_name === null,
      "PATCH: prosto prizorisce brez venueClubId prepise gostitelja (venue_club_id null)", r.body);
    r = await api("PATCH", `/events/${evHost}`, T.orgown, { venueCity: "" });
    assert(r.status === 400, "PATCH: izbris mesta prostega prizorisca -> 400", [r.status, r.body]);
    r = await api("PATCH", `/events/${evHost}`, T.orgown, { venueClubId: host, venueName: "Ignoriraj" });
    assert(r.status === 200 && r.body.venue_club_id === host && r.body.venue_name === "" && r.body.venue_address === "" && r.body.venue_city === "" && r.body.venue_lat === null && r.body.venue_lng === null,
      "PATCH nazaj na gostitelja: prosta polja se pocistijo", r.body);
    // splet ob preklopu s kluba gostitelja na rocni vnos poslje venueClubId: null SKUPAJ s prostimi polji (in obratno prazna prosta polja z gostiteljem)
    r = await api("PATCH", `/events/${evHost}`, T.orgown, { venueClubId: null, venueName: "Rocni Lokal", venueAddress: "Cesta 7", venueCity: "Kranj", venueLat: 46.24, venueLng: 14.35 });
    assert(r.status === 200 && r.body.venue_club_id === null && r.body.venue_club_name === null && r.body.venue_name === "Rocni Lokal" && r.body.venue_address === "Cesta 7"
      && r.body.venue_city === "Kranj" && r.body.venue_lat === 46.24 && r.body.venue_lng === 14.35, "PATCH {venueClubId: null + prosta polja}: gostitelj izpraznjen, prosta polja shranjena", r.body);
    r = await api("GET", `/events/${evHost}`);
    assert(r.body.venue_club_id === null && r.body.venue_name === "Rocni Lokal", "GET /events/:id po preklopu na rocni vnos", r.body);
    r = await api("PATCH", `/events/${evHost}`, T.orgown, { venueClubId: host, venueName: "", venueAddress: "", venueCity: "", venueLat: null, venueLng: null });
    assert(r.status === 200 && r.body.venue_club_id === host && r.body.venue_club_name === "Gostitelj Klub" && r.body.venue_name === "" && r.body.venue_city === "" && r.body.venue_lat === null && r.body.venue_lng === null,
      "PATCH {venueClubId: gostitelj + prazna prosta polja}: nazaj na gostitelja", r.body);
    r = await api("PATCH", `/events/${evHost}`, T.orgown, { venueClubId: null, venueName: "", venueAddress: "", venueCity: "", venueLat: null, venueLng: null });
    assert(r.status === 400 && /Organizer events need a venue\./.test(r.text), "PATCH {venueClubId: null + prazna prosta polja} (organizator): 400", r);
    r = await api("PATCH", `/events/${evHost}`, T.orgown, { venueLat: 46.0, venueLng: 14.5 });
    assert(r.status === 200 && r.body.venue_club_id === host && r.body.venue_lat === null, "PATCH koordinat ob gostitelju se ignorira (null)", r.body);
    r = await api("PATCH", `/events/${evMoj}`, T.hostown, { venueName: "Zunaj", venueCity: "Kranj" });
    assert(r.status === 200 && r.body.venue_name === "Zunaj" && r.body.venue_city === "Kranj", "navaden klub: PATCH prostega prizorisca (brez zahteve po prizoriscu) -> 200", r.body);
    r = await api("PATCH", `/events/${evMoj}`, T.hostown, { venueClubId: host });
    assert(r.status === 400, "navaden klub: PATCH venueClubId = lastni klub -> 400", [r.status, r.body]);

    // ============================================================
    console.log("\n# 5. Javni seznami");
    r = await api("GET", "/events?upcoming=true");
    const vE = (id) => r.body.find(e => e.id === id);
    assert(r.status === 200 && vE(evHost) && vE(evHost).venue_club_id === host && vE(evHost).venue_club_name === "Gostitelj Klub" && vE(evHost).venue_club_logo_url === "https://img.test/host.png",
      "GET /events: dogodek organizatorja ima venue_club_id, venue_club_name, venue_club_logo_url", vE(evHost));
    assert(vE(evProsto) && vE(evProsto).venue_name === "Lokal X" && vE(evProsto).venue_city === "Maribor" && vE(evProsto).venue_lat === 46.55 && vE(evProsto).venue_club_name === null, "GET /events: prosto prizorisce (venue_*)", vE(evProsto));
    assert(vE(evMoj) && vE(evMoj).venue_club_id === null && vE(evMoj).venue_club_name === null && vE(evMoj).venue_club_logo_url === null && vE(evMoj).venue_lat === null, "GET /events: navaden dogodek: venue_club_* null", vE(evMoj));
    assert(!vE(evOsnutek) && !vE(evOdp), "osnutek in odpovedan dogodek se ne kazeta", r.body.map(e => e.id));
    r = await api("GET", "/events?upcoming=true&lite=true");
    assert(r.status === 200 && r.body.find(e => e.id === evHost).venue_club_name === "Gostitelj Klub" && !("description" in r.body[0]), "GET /events?lite=true: venue_* tudi v lahki razlicici", r.body.find(e => e.id === evHost));
    r = await api("GET", `/events/${evHost}`);
    assert(r.status === 200 && r.body.venue_club_id === host && r.body.venue_club_name === "Gostitelj Klub" && r.body.club_id === org, "GET /events/:id: venue_club_* + club_id organizatorja", r.body);
    r = await api("GET", `/events/${evMoj}`);
    assert(r.status === 200 && r.body.venue_club_id === null && r.body.venue_name === "Zunaj" && r.body.venue_club_name === null, "GET /events/:id navadnega dogodka (prosto prizorisce neobveznega kluba)", r.body);

    for (const pot of [`/events?clubId=${host}`, `/events?clubId=${host}&upcoming=true`]) {
      r = await api("GET", pot);
      const ids = Array.isArray(r.body) ? r.body.map(e => e.id) : [];
      const g = (id) => (Array.isArray(r.body) ? r.body : []).find(e => e.id === id);
      assert(r.status === 200 && g(evHost) && g(evHost).hosted === true && g(evHost).club_id === org && g(evHost).club_name === "Promotor X", `${pot}: gostovani dogodek je v seznamu gostitelja s hosted:true (club_id in club_name organizatorja)`, r.body);
      assert(g(evOboje) && g(evOboje).hosted === true, `${pot}: tudi drugi gostovani dogodek`, ids);
      assert(g(evMoj) && g(evMoj).hosted === false, `${pot}: lastni dogodek ima hosted:false`, g(evMoj));
      assert(!g(evOsnutek) && !g(evOdp), `${pot}: osnutek in odpovedan dogodek se gostitelju ne kazeta`, ids);
      assert(!g(evTuji), `${pot}: dogodek, ki ga gosti drug klub, ni v seznamu`, ids);
    }
    r = await api("GET", `/events?clubId=${host}&upcoming=true&lite=true`);
    assert(r.status === 200 && r.body.some(e => e.hosted === true) && !("description" in r.body[0]), "?clubId= podpira upcoming in lite (hosted tudi v lahki razlicici)", r.body.length);
    r = await api("GET", `/events?clubId=${org}`);
    assert(r.status === 200 && r.body.length >= 4 && r.body.every(e => e.club_id === org && e.hosted === false), "?clubId=organizator: samo lastni dogodki, hosted:false", r.body.map(e => [e.id, e.hosted]));
    r = await api("GET", `/events?clubId=${tuji}`);
    assert(r.status === 200 && r.body.some(e => e.id === evTuji && e.hosted === true) && !r.body.some(e => e.id === evHost), "?clubId=tuji: njegov gostovani dogodek, ne dogodek gostitelja host", r.body.map(e => [e.id, e.hosted]));
    r = await api("GET", "/events?upcoming=true");
    assert(r.status === 200 && r.body.every(e => typeof e.club_name === "string" && e.club_name.length > 0) && r.body.find(e => e.id === evHost).club_name === "Promotor X" && !("hosted" in r.body[0]),
      "GET /events (brez clubId): vsak dogodek ima club_name; hosted ni potreben", r.body.map(e => [e.id, e.club_name]));
    await pool.query("UPDATE clubs SET hidden = TRUE WHERE id=$1", [tuji]);
    r = await api("GET", `/events?clubId=${tuji}&upcoming=true`);
    assert(r.status === 200 && r.body.length === 0, "GET /events?clubId=skrit: prazno (tudi gostovani dogodki)", r.body.length);
    r = await api("GET", `/events/${evTuji}`);
    assert(r.status === 200 && r.body.venue_club_id === null && r.body.venue_club_name === null, "skrit gostitelj javno ne obstaja tudi kot prizorisce (venue_club_* null)", r.body);
    await pool.query("UPDATE clubs SET hidden = FALSE WHERE id=$1", [tuji]);
    r = await api("GET", "/business/events", T.orgown);
    assert(r.status === 200 && r.body.find(e => e.id === evOsnutek) && r.body.find(e => e.id === evHost).venue_club_name === "Gostitelj Klub", "GET /business/events (organizator): osnutek viden, venue_* polja", r.body.map(e => e.id));
    r = await api("GET", "/business/events", T.hostown);
    assert(r.status === 200 && !r.body.some(e => e.club_id === org), "GET /business/events (gostitelj): dogodki organizatorja NISO med njegovimi poslovnimi dogodki", r.body.map(e => [e.id, e.club_id]));

    // ============================================================
    console.log("\n# 6. Denar in sken (I26)");
    const k1 = await api("POST", `/events/${evHost}/orders`, T.kupec, { quantity: 2 });
    assert(k1.status === 201 && k1.body.tickets.length === 2, "kupec kupi 2 vstopnici na dogodek organizatorja (gostitelj Gostitelj Klub)", k1.body);
    const s = k1.body.tickets.map(t => t.serial);
    const ord = (await pool.query("SELECT club_id, event_id FROM orders WHERE id=$1", [k1.body.order.id])).rows[0];
    assert(ord.club_id === org && ord.event_id === evHost, "naročilo: prodajalec (club_id) = organizator, ne gostitelj", ord);
    r = await api("POST", "/business/tickets/scan", T.hostdoor, { serial: s[0] });
    assert(r.status === 403 && r.body.result === "wrong_club", "vratar GOSTITELJA ne more skenirati vstopnice organizatorjevega dogodka -> 403 wrong_club", r);
    r = await api("POST", "/business/tickets/scan", T.hostown, { serial: s[0] });
    assert(r.status === 403 && r.body.result === "wrong_club", "lastnik GOSTITELJA ne more skenirati -> 403 wrong_club", r);
    r = await api("POST", "/business/tickets/scan-batch", T.hostdoor, { device_id: crypto.randomUUID(), scans: [{ client_scan_id: crypto.randomUUID(), serial: s[0] }] });
    assert(r.status === 200 && r.body.results[0].result !== "ok" && r.body.results[0].result === "wrong_club", "scan-batch vratarja gostitelja: wrong_club", r.body);
    r = await api("GET", `/business/events/${evHost}/scan-list`, T.hostdoor);
    assert(r.status === 404, "scan-list organizatorjevega dogodka za vratarja gostitelja -> 404", r.status);
    r = await api("GET", `/business/events/${evHost}/tickets`, T.hostown);
    assert(r.status === 200 && r.body.length === 0, "GET /business/events/:id/tickets: lastnik gostitelja ne vidi kupcev organizatorja (prazen seznam)", [r.status, r.body.length]);
    assert((await pool.query("SELECT status FROM tickets WHERE serial=$1", [s[0]])).rows[0].status === "valid", "vstopnica ostane valid po zavrnjenih skenih gostitelja");
    r = await api("POST", "/business/tickets/scan", T.orgdoor, { serial: s[0] });
    assert(r.status === 200 && r.body.result === "ok", "vratar ORGANIZATORJA skenira: ok", r);
    r = await api("POST", "/business/tickets/scan", T.orgdoor, { serial: s[0] });
    assert(r.status === 409 && r.body.result === "already_used", "ponovni sken -> already_used", r.body);
    r = await api("POST", "/business/tickets/scan", T.orgown, { serial: s[1] });
    assert(r.status === 200 && r.body.result === "ok", "lastnik organizatorja skenira: ok", r);
    r = await api("GET", `/business/events/${evHost}/scan-list`, T.orgdoor);
    assert(r.status === 200 && r.body.tickets.length === 2, "scan-list organizatorjevega vratarja: 2 vstopnici", r.status);

    // ============================================================
    console.log("\n# 7. Vstopnice: /me/tickets, mail, PDF");
    await api("PATCH", "/business/clubs/me", T.orgown, { address: "Pisarna 5", city: "Kranj", contactPhone: "031 111 222" });   // organizator ima pisarno; na vstopnici NI prizorisce
    r = await api("GET", "/me/tickets", T.kupec);
    const vst = (r.body || []).find(t => t.event_id === evHost);
    assert(r.status === 200 && vst && vst.venue_club_id === host && vst.venue_club_name === "Gostitelj Klub" && vst.club_name === "Promotor X", "/me/tickets: vstopnica ima venue_club_name (gostitelj), club_name = organizator", vst);
    r = await api("GET", "/me/orders", T.kupec);
    assert(r.status === 200 && r.body.length >= 1, "/me/orders se ni pokvarilo", r.status);

    const TERMS = { accept_terms: true, terms_version: "2026-10-01" };
    const nakup = (ev, email) => api("POST", `/guest/events/${ev}/orders`, null, { email, quantity: 1, ...TERMS });
    r = await nakup(evHost, "gost1@example.com");
    assert(r.status === 201, "gostujoci nakup (dogodek z gostiteljem) -> 201", r);
    r = await nakup(evProsto, "gost2@example.com");
    assert(r.status === 201, "gostujoci nakup (prosto prizorisce) -> 201", r);
    assert(await cakaj(() => poslanoNa("gost1@example.com").length >= 1 && poslanoNa("gost2@example.com").length >= 1), "maila poslana");
    const m1 = poslanoNa("gost1@example.com")[0] || {}, m2 = poslanoNa("gost2@example.com")[0] || {};
    const razdelekDogodek = (m) => { const x = /EVENT\n([\s\S]*?)\n\n/.exec(m.text || ""); return x ? x[1] : ""; };
    const e1 = razdelekDogodek(m1), e2 = razdelekDogodek(m2);
    assert(/^Org Noc \(popravek\)\n.*\(Ljubljana time\)\nGostitelj Klub, Slovenska 1, Ljubljana\nNo age limit\.$/.test(e1), "mail (gostitelj): razdelek Event ima prizorisce gostitelja", e1);
    assert(!e1.includes("Pisarna 5") && !e1.includes("Kranj"), "mail (gostitelj): razdelek Event NIMA organizatorjevega naslova", e1);
    assert(/^Org Prosto\n.*\(Ljubljana time\)\nLokal X, Ulica 3, Maribor\nNo age limit\.$/.test(e2), "mail (prosto prizorisce): razdelek Event ima venue_name, naslov, mesto", e2);
    assert(/sold by the club: Promotor X, Pisarna 5, Kranj/.test(m1.text || ""), "mail: prodajalec je organizator (z njegovim naslovom/kontaktom)", (m1.text || "").slice(0, 100));
    const p1 = pdfIzMaila(m1), p2 = pdfIzMaila(m2);
    assert(p1.includes("(Gostitelj Klub, Slovenska 1, Ljubljana)") && !p1.includes("Pisarna") && !p1.includes("Kranj"), "PDF (gostitelj): prizorisce gostitelja, brez organizatorjevega naslova", p1.length);
    assert(p2.includes("(Lokal X, Ulica 3, Maribor)") && !p2.includes("Pisarna"), "PDF (prosto prizorisce): venue_*", p2.length);

    // gostovske poti (splet): address in city dogodka = PRIZORISCE, ne organizatorjev (prazen) naslov
    const gostZeton1 = (await api("POST", `/guest/events/${evHost}/orders`, null, { email: "gost4@example.com", quantity: 1, ...TERMS })).body.guest_token;
    const gostZeton2 = (await api("POST", `/guest/events/${evProsto}/orders`, null, { email: "gost5@example.com", quantity: 1, ...TERMS })).body.guest_token;
    const evPlain = (await api("POST", "/events", T.hostown, { clubId: host, title: "Navaden", startAt: cezDan, ticketPriceCents: 1000, capacity: 50, minAge: 0 })).body.id;
    const gostZeton3 = (await api("POST", `/guest/events/${evPlain}/orders`, null, { email: "gost6@example.com", quantity: 1, ...TERMS })).body.guest_token;
    const gostGet = async (pot, z) => { const x = await fetch(BASE + pot, { headers: { "x-guest-token": z } }); return { status: x.status, body: await x.json() }; };
    r = await gostGet("/guest/order", gostZeton1);
    assert(r.status === 200 && r.body.order.event.address === "Slovenska 1" && r.body.order.event.city === "Ljubljana" && r.body.order.event.club_name === "Promotor X", "GET /guest/order (gostitelj): event.address/city = prizorisce gostitelja, club_name organizator", r.body.order.event);
    assert(r.body.order.event.venue_club_name === "Gostitelj Klub" && r.body.tickets[0].address === "Slovenska 1" && r.body.tickets[0].city === "Ljubljana" && r.body.tickets[0].venue_club_id === host,
      "GET /guest/order: tudi vstopnice (address, city, venue_club_*) imajo prizorisce", r.body.tickets[0]);
    r = await gostGet("/guest/order", gostZeton2);
    assert(r.status === 200 && r.body.order.event.address === "Ulica 3" && r.body.order.event.city === "Maribor" && r.body.order.event.venue_name === "Lokal X" && r.body.tickets[0].address === "Ulica 3" && r.body.tickets[0].city === "Maribor",
      "GET /guest/order (prosto prizorisce): address/city = venue_address/venue_city", r.body.order.event);
    r = await gostGet("/guest/order", gostZeton3);
    assert(r.status === 200 && r.body.order.event.address === (await pool.query("SELECT address FROM clubs WHERE id=$1", [host])).rows[0].address && r.body.order.event.city === "Ljubljana" && r.body.order.event.venue_club_id === null,
      "GET /guest/order (dogodek brez prizorisca): address/city = naslov kluba kot doslej", r.body.order.event);
    r = await api("GET", "/me/tickets", T.kupec);
    const vst2 = r.body.find(t => t.event_id === evHost);
    assert(vst2 && vst2.address === "Slovenska 1" && vst2.city === "Ljubljana" && vst2.club_name === "Promotor X", "/me/tickets: address/city = prizorisce gostitelja", vst2 && [vst2.address, vst2.city]);

    // prenos gostu (mail prejemniku) ima isto prizorisce
    const k2 = await api("POST", `/events/${evHost}/orders`, T.kupec, { quantity: 1 });
    assert(k2.status === 201, "kupec kupi se eno vstopnico (za prenos)", k2.body);
    r = await api("POST", `/tickets/${k2.body.tickets[0].id}/transfer`, T.kupec, { email: "prejemnik@example.com", allow_guest: true });
    assert(r.status === 200 || r.status === 201, "prenos gostu", r);
    assert(await cakaj(() => poslanoNa("prejemnik@example.com").length >= 1), "mail prejemniku prenosa poslan");
    const m3 = poslanoNa("prejemnik@example.com")[0] || {};
    const e3 = razdelekDogodek(m3);
    assert(e3.includes("Gostitelj Klub, Slovenska 1, Ljubljana") && !e3.includes("Pisarna 5"), "mail prenosa: Event vrstica ima prizorisce gostitelja, ne organizatorjevega naslova", e3);
    assert(/Organiser: Promotor X/.test(m3.text || ""), "mail prenosa: organizator = Promotor X", (m3.text || "").slice(0, 200));
    assert(pdfIzMaila(m3).includes("(Gostitelj Klub, Slovenska 1, Ljubljana)"), "PDF prenosa: prizorisce gostitelja");
    const zt = /\/app\/guest\/ticket#t=([A-Za-z0-9_-]{43})/.exec(m3.text || "");
    r = zt ? await gostGet("/guest/ticket", zt[1]) : { status: 0, body: {} };
    assert(r.status === 200 && r.body.ticket.address === "Slovenska 1" && r.body.ticket.city === "Ljubljana" && r.body.event.address === "Slovenska 1" && r.body.event.city === "Ljubljana" && r.body.event.venue_club_name === "Gostitelj Klub",
      "GET /guest/ticket: ticket in event address/city = prizorisce gostitelja", r.body);

    // ============================================================
    console.log("\n# 8. Zemljevid in iskanje");
    r = await api("GET", "/clubs/map");
    assert(r.status === 200 && !r.body.some(k => k.id === org || k.id === outly) && r.body.some(k => k.id === host), "GET /clubs/map: organizator brez koordinat ni pin; gostitelj je", r.body.map(k => k.id));
    r = await api("GET", "/clubs?withCoords=true");
    assert(r.status === 200 && !r.body.some(k => k.id === org) && r.body.some(k => k.id === host), "GET /clubs?withCoords=true: organizatorja ni", r.body.map(k => k.id));
    r = await api("GET", "/search?q=Org");
    const sv = r.body && r.body.events && r.body.events.find(e => e.id === evHost);
    assert(r.status === 200 && sv && sv.venue_club_name === "Gostitelj Klub" && sv.venue_club_id === host, "GET /search: dogodek ima venue_club_*", r.body && r.body.events);
    r = await api("GET", "/search?q=Promotor");
    assert(r.status === 200 && r.body.clubs.some(k => k.id === org), "GET /search: organizator najden po imenu", r.body.clubs);
    r = await api("GET", "/me", T.hostown);
    assert(r.status === 200 && Array.isArray(r.body.clubs) && r.body.clubs[0].is_organizer === false, "GET /me clubs: is_organizer", r.body.clubs);
    r = await api("GET", "/me", T.orgown);
    assert(r.status === 200 && r.body.clubs[0].is_organizer === true, "GET /me clubs (organizator): is_organizer true", r.body.clubs);

    // ============================================================
    console.log("\n# 9. Baza");
    assert(await sqlKoda("UPDATE events SET venue_club_id = club_id WHERE id=$1", [evMoj]) === "23514", "CHECK: venue_club_id <> club_id");
    assert(await sqlKoda("UPDATE events SET venue_lat = 1, venue_lng = NULL WHERE id=$1", [evMoj]) === "23514", "CHECK: venue_lat brez venue_lng");
    assert(await sqlKoda("UPDATE events SET venue_lat = 100, venue_lng = 1 WHERE id=$1", [evMoj]) === "23514", "CHECK: venue_lat izven obsega");
    assert(await sqlKoda("UPDATE events SET venue_club_id = 99999 WHERE id=$1", [evMoj]) === "23503", "FK: venue_club_id mora obstajati");
    const gost = (await pool.query(`INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='kupec@outly.si'), 'Izbrisljiv', 'Koper') RETURNING id`)).rows[0].id;
    r = await api("POST", "/events", T.orgown, { clubId: org, title: "Org Izbris", startAt: cezDan, venueClubId: gost });
    assert(r.status === 201, "dogodek z gostiteljem Izbrisljiv", r.body);
    await pool.query("DELETE FROM clubs WHERE id=$1", [gost]);
    r = await api("GET", `/events/${r.body.id}`);
    assert(r.status === 200 && r.body.venue_club_id === null && r.body.venue_club_name === null, "izbris gostitelja: venue_club_id NULL (dogodek ostane)", r.body);
  } catch (e) {
    fail++; console.log("  ✗ IZJEMA v testu:", e && e.stack || e);
  } finally {
    if (srv) srv.kill();
    jwksServer.close(); resendServer.close();
  }
  console.log(`\n${ok} trditev v redu, ${fail} napak`);
  if (fail) { console.log("--- dnevnik streznika (zadnjih 3000 znakov) ---\n" + log.slice(-3000)); }
  process.exit(fail ? 1 : 0);
})();
