#!/usr/bin/env node
/**
 * Test: VLOGA BARTENDER + STREZBA VIP MIZ (migracija 038, invarianta I27, issue #176, Martin 9. 10. 2026).
 * Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_strezba.js
 * Vzorec kot test_vabila.js / test_vip.js: lokalni JWKS (3956), backend kot otrok proces na portu 3202, TRUNCATE na zacetku.
 * Pokriva: vabilo z vlogo bartender (201, clan, GET /me, ekipa), stara/neznana vloga 400, CHECK v bazi; nastanek strezbe SAMO iz skena
 * (POST /business/tickets/scan in scan-batch, ON CONFLICT: ena strezba na narocilo), navadna vstopnica in rezervacija po telefonu strezbe
 * ne sprozita; GET /business/events/:id/table-service (bartender/manager/lastnik; vratar 403; tuj klub 404) brez kakrsnihkoli podatkov kupca;
 * PUT /business/table-service/:id (delivered true/false, idempotentno, tuj klub 404); GET /me pending_table_service; GET /me/table-service;
 * natakar ne pride do poti s podatki kupcev (vstopnice dogodka, VIP rezervacije, sken).
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3202, JWKS_PORT = 3956;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-strezba";
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
let ipStevec = 0;
const novIp = () => `10.40.${(++ipStevec >> 8) & 255}.${(ipStevec & 255) + 1}`;
async function api(method, p, token, body, glave) {
  const r = await fetch(BASE + p, { method, headers: { "content-type": "application/json", "x-forwarded-for": novIp(), ...(token ? { authorization: "Bearer " + token } : {}), ...(glave || {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, besedilo: t };
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 100; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  try {
    const T = {
      lastnik: zeton("lastnik@outly.si", uuid(1)),
      manager: zeton("manager@outly.si", uuid(2)),
      doorman: zeton("doorman@outly.si", uuid(3)),
      natakar: zeton("natakar@outly.si", uuid(4)),
      natakar2: zeton("natakar2@outly.si", uuid(5)),
      kupecana: zeton("kupecana@outly.si", uuid(6)),
      kupecbor: zeton("kupecbor@outly.si", uuid(7)),
      drugi: zeton("drugi@outly.si", uuid(8)),
      tujnatakar: zeton("tujnatakar@outly.si", uuid(9)),
    };
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='business' WHERE email IN ('lastnik@outly.si','drugi@outly.si')");
    // Miza s paketom pijace zahteva datum rojstva (>= 18, #102).
    await pool.query("UPDATE users SET date_of_birth = (CURRENT_DATE - INTERVAL '30 years')::date WHERE email LIKE 'kupec%@outly.si'");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana')");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='drugi@outly.si'), 'Drugi Klub', 'Maribor')");
    await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, (SELECT id FROM users WHERE email='manager@outly.si'), 'manager')");
    await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, (SELECT id FROM users WHERE email='doorman@outly.si'), 'doorman')");
    await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (2, (SELECT id FROM users WHERE email='tujnatakar@outly.si'), 'bartender')");
    const uid = async (email) => (await pool.query("SELECT id FROM users WHERE email=$1", [email])).rows[0].id;
    let r;

    console.log("\n# Vabilo z vlogo bartender, ekipa, CHECK v bazi");
    r = await api("POST", "/business/team", T.lastnik, { email: "natakar@outly.si", role: "bartender" });
    assert(r.status === 201, "vabilo z vlogo bartender -> 201", r.body);
    assert(r.body.invites.length === 1 && r.body.invites[0].role === "bartender", "seznam vabil vrne vlogo bartender", r.body.invites);
    r = await api("POST", "/business/team", T.lastnik, { email: "natakar2@outly.si", role: "kuhar" });
    assert(r.status === 400, "stara/neznana vloga \"kuhar\" -> 400", [r.status, r.body]);
    r = await api("POST", "/business/team", T.lastnik, { email: "natakar2@outly.si", role: "" });
    assert(r.status === 400, "prazna vloga -> 400", r.status);
    assert(typeof (await api("POST", "/business/team", T.lastnik, { email: "natakar2@outly.si", role: "kuhar" })).body === "string", "400 ima berljivo sporocilo");
    r = await api("GET", "/me/invites", T.natakar);
    assert(r.body.invites.length === 1 && r.body.invites[0].role === "bartender", "GET /me/invites: vloga bartender", r.body);
    const invId = r.body.invites[0].id;
    r = await api("POST", `/me/invites/${invId}/accept`, T.natakar);
    assert(r.status === 200 && r.body.role === "bartender" && r.body.club.name === "Pure Club", "sprejem vabila -> clan z vlogo bartender", r.body);
    r = await api("GET", "/me", T.natakar);
    assert(r.body.club_role === "bartender" && r.body.clubs.length === 1 && r.body.clubs[0].role === "bartender", "GET /me: club_role bartender, clubs[0].role bartender", r.body.clubs);
    r = await api("GET", "/business/team", T.lastnik);
    const clan = r.body.members.find(m => m.role === "bartender");
    assert(r.status === 200 && clan && clan.username === "natakar", "GET /business/team: clan z vlogo bartender", r.body.members);
    r = await api("POST", "/business/team", T.manager, { email: "natakar2@outly.si", role: "bartender" });
    assert(r.status === 201, "manager sme povabiti natakarja (osebje kot vratar) -> 201", r.body);
    r = await api("POST", "/business/team", T.manager, { email: "kupecana@outly.si", role: "manager" });
    assert(r.status === 403, "manager se vedno ne sme povabiti managerja -> 403", r.status);
    const inv2 = (await api("GET", "/business/team", T.lastnik)).body.invites.find(i => i.role === "bartender");
    r = await api("DELETE", `/business/team/invites/${inv2.id}`, T.manager);
    assert(r.status === 200 && r.body.invites.length === 0, "manager prekliče vabilo natakarja -> 200", r.body);
    r = await api("POST", "/business/team", T.doorman, { email: "natakar2@outly.si", role: "bartender" });
    assert(r.status === 403, "vratar ne more vabiti -> 403", r.status);
    r = await api("POST", "/business/team", T.natakar, { email: "natakar2@outly.si", role: "bartender" });
    assert(r.status === 403, "natakar ne more vabiti -> 403", r.status);
    r = await api("GET", "/business/team", T.natakar);
    assert(r.status === 403, "natakar ekipe ne vidi (e-naslovi) -> 403", r.status);
    let dbNapaka = null;
    try { await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, $1, 'kuhar')", [await uid("kupecana@outly.si")]); } catch (e) { dbNapaka = e; }
    assert(dbNapaka && dbNapaka.code === "23514", "baza sama zavrne vlogo \"kuhar\" v club_members (CHECK)", dbNapaka && dbNapaka.code);
    dbNapaka = null;
    try { await pool.query("INSERT INTO club_invites (club_id, user_id, role) VALUES (1, $1, 'kuhar')", [await uid("kupecana@outly.si")]); } catch (e) { dbNapaka = e; }
    assert(dbNapaka && dbNapaka.code === "23514", "baza sama zavrne vlogo \"kuhar\" v club_invites (CHECK)", dbNapaka && dbNapaka.code);
    r = await api("DELETE", `/business/team/${await uid("natakar2@outly.si")}`, T.manager);
    assert(r.status === 404, "natakar2 ni clan (vabilo preklicano) -> 404", r.status);

    console.log("\n# Priprava: tloris, dogodek, nakupi (VIP mize s paketom, navadna vstopnica)");
    const PLAN = { width: 24, height: 16, elements: [{ type: "stage", x: 8, y: 0, w: 8, h: 3, label: "" }] };
    r = await api("PUT", "/business/vip", T.lastnik, { plan: PLAN, tables: [
      { label: "T1", x: 2, y: 5, w: 2, h: 2, shape: "round", seats: 6, price_cents: 30000 },
      { label: "T2", x: 6, y: 5, w: 3, h: 2, shape: "rect", seats: 4, price_cents: 20000 },
      { label: "T3", x: 12, y: 5, w: 2, h: 2, shape: "round", seats: 8, price_cents: 45000 },
    ], packages: [{ name: "Jameson 0,7 l", description: "4x Red Bull" }] });
    assert(r.status === 200 && r.body.tables.length === 3, "tloris (3 mize, 1 paket)", r.body);
    const [M1, M2, M3] = r.body.tables.map(t => t.id);
    const P1 = r.body.packages[0].id;
    r = await api("PUT", "/business/vip", T.drugi, { plan: PLAN, tables: [{ label: "D1", x: 1, y: 1, w: 2, h: 2, shape: "round", seats: 4, price_cents: 15000 }], packages: [{ name: "Tuji paket", description: "x" }] });
    const MD = r.body.tables[0].id, PD = r.body.packages[0].id;
    async function dogodek(klub, naslov) {
      return (await pool.query(
        `INSERT INTO events (club_id, title, poster_url, start_at, status, ticket_price_cents, capacity, vip_enabled)
         VALUES ($1,$2,'https://example.com/p.jpg', NOW() + INTERVAL '2 hours', 'published', 1500, 100, FALSE) RETURNING id`, [klub, naslov])).rows[0].id;
    }
    const E1 = await dogodek(1, "Strezba noc");
    const E2 = await dogodek(2, "Tuj dogodek");
    r = await api("PUT", `/business/events/${E1}/vip`, T.lastnik, { enabled: true });
    assert(r.status === 200, "VIP vklopljen na E1", r.body);
    r = await api("PUT", `/business/events/${E2}/vip`, T.drugi, { enabled: true });

    r = await api("POST", `/events/${E1}/tables/${M1}/orders`, T.kupecana, { package_id: P1 });
    assert(r.status === 201 && r.body.tickets.length === 6, "kupecana kupi T1 + paket (6 vstopnic)", r.body);
    const O_ANA = r.body.order.id;
    r = await api("POST", `/events/${E1}/tables/${M2}/orders`, T.kupecbor, { package_id: P1 });
    assert(r.status === 201 && r.body.tickets.length === 4, "kupecbor kupi T2 + paket (4 vstopnice)", r.body);
    const O_BOR = r.body.order.id;
    r = await api("POST", `/events/${E2}/tables/${MD}/orders`, T.kupecana, { package_id: PD });
    assert(r.status === 201, "kupecana kupi tujo mizo D1 na E2 (drugi klub)", r.body);
    const O_TUJ = r.body.order.id;
    r = await api("POST", `/events/${E1}/orders`, T.kupecana, { quantity: 2 });
    assert(r.status === 201 && r.body.tickets.length === 2, "kupecana kupi 2 navadni vstopnici", r.body);
    const O_NAV = r.body.order.id;
    const moje = async (tok) => (await api("GET", "/me/tickets", tok)).body;
    const anine = (await moje(T.kupecana)).filter(t => t.event_id === E1);
    const anineVip = anine.filter(t => t.is_vip), anineNav = anine.filter(t => !t.is_vip);
    const bore = (await moje(T.kupecbor)).filter(t => t.is_vip);
    const tuje = (await moje(T.kupecana)).filter(t => t.event_id === E2);
    assert(anineVip.length === 6 && anineNav.length === 2 && bore.length === 4 && tuje.length === 4 && anineVip.every(t => t.qr), "imamo QR kode: 6 VIP + 2 navadni (ana), 4 VIP (bor), 4 tuje", [anineVip.length, anineNav.length, bore.length]);
    // Rezervacija po telefonu (table_holds): strezbe ne sprozi.
    r = await api("POST", `/business/events/${E1}/tables/${M3}/hold`, T.lastnik, { guest_name: "Janez Telefonski" });
    assert(r.status === 201, "rezervacija T3 po telefonu -> 201", r.body);
    const stStrezb = async (where = "TRUE", p = []) => (await pool.query(`SELECT COUNT(*)::int AS n FROM table_service WHERE ${where}`, p)).rows[0].n;
    assert(await stStrezb() === 0, "pred skenom: 0 strezb (nakup in rezervacija po telefonu strezbe NE ustvarita)");

    console.log("\n# Pred skenom: prazen seznam, stevec 0");
    r = await api("GET", `/business/events/${E1}/table-service`, T.natakar);
    assert(r.status === 200 && Array.isArray(r.body.items) && r.body.items.length === 0, "natakar: prazen seznam", r.body);
    r = await api("GET", "/me", T.natakar);
    assert(r.body.pending_table_service === 0, "GET /me: pending_table_service = 0", r.body.pending_table_service);
    r = await api("GET", "/me/table-service", T.natakar);
    assert(r.status === 200 && Array.isArray(r.body.items) && r.body.items.length === 0, "GET /me/table-service: prazno", r.body);

    console.log("\n# Sken (POST /business/tickets/scan): strezba nastane ob PRVEM skenu VIP narocila");
    r = await api("POST", "/business/tickets/scan", T.doorman, { qr: anineNav[0].qr });
    assert(r.status === 200 && r.body.result === "ok", "vratar skenira navadno vstopnico -> ok", r.body);
    assert(r.body.table_service_created === false, "navadna vstopnica: table_service_created = false", r.body.table_service_created);
    assert(await stStrezb() === 0, "navadna vstopnica strezbe NE ustvari");
    r = await api("POST", "/business/tickets/scan", T.doorman, { qr: anineVip[0].qr });
    assert(r.status === 200 && r.body.result === "ok" && r.body.ticket.is_vip === true, "vratar skenira VIP vstopnico (T1) -> ok", r.body);
    assert(r.body.table_service_created === true, "odgovor skena: table_service_created = true", r.body.table_service_created);
    let ts = (await pool.query("SELECT * FROM table_service WHERE order_id=$1", [O_ANA])).rows;
    assert(ts.length === 1 && ts[0].event_id === E1 && ts[0].club_id === 1 && ts[0].table_label === "T1" && ts[0].table_seats === 6 && ts[0].package_name === "Jameson 0,7 l" && ts[0].package_description === "4x Red Bull" && ts[0].delivered_at === null && ts[0].delivered_by_user_id === null, "v bazi: miza T1, 6 sedezev, paket in opis, nedostavljeno", ts[0]);
    const usedAt = (await pool.query("SELECT used_at FROM tickets WHERE serial=$1", [anineVip[0].serial])).rows[0].used_at;
    assert(ts[0].scanned_at.getTime() === usedAt.getTime(), "scanned_at = cas skena vstopnice (used_at)");
    r = await api("POST", "/business/tickets/scan", T.doorman, { qr: anineVip[1].qr });
    assert(r.status === 200 && r.body.result === "ok" && r.body.table_service_created === false, "druga vstopnica ISTEGA narocila: ok, table_service_created = false", r.body);
    r = await api("POST", "/business/tickets/scan", T.doorman, { qr: anineVip[1].qr });
    assert(r.status === 409 && r.body.result === "already_used", "ponovni sken iste vstopnice -> 409 already_used", r.body);
    // Hkratni skeni treh preostalih vstopnic istega narocila: se vedno ena strezba.
    const hkrati = await Promise.all(anineVip.slice(2, 5).map(t => api("POST", "/business/tickets/scan", T.doorman, { qr: t.qr })));
    assert(hkrati.every(x => x.status === 200 && x.body.result === "ok" && x.body.table_service_created === false), "3 hkratni skeni istega narocila: vsi ok, nobeden ne ustvari nove strezbe", hkrati.map(x => x.body));
    assert(await stStrezb("order_id=$1", [O_ANA]) === 1, "narocilo kupecane ima se vedno TOCNO ENO strezbo (6 vstopnic, 5 skeniranih)");
    // Strezba druge ekipe/kluba: manager skenira tuj klub -> 403, strezbe ni.
    r = await api("POST", "/business/tickets/scan", T.doorman, { qr: tuje[0].qr });
    assert(r.status === 403 && r.body.result === "wrong_club", "sken tuje VIP vstopnice -> 403 wrong_club", r.body);
    assert(await stStrezb("order_id=$1", [O_TUJ]) === 0, "tuja miza: strezbe ni");

    console.log("\n# Sken brez povezave (scan-batch): enako, idempotentno");
    const dev = "telefon-strezba-1";
    let n = 0;
    const sken = (qr, device) => ({ client_scan_id: `cs-st-${++n}`, qr, scanned_at: new Date(Date.now() - 5 * 60000).toISOString(), device_id: device || dev });
    const paket = [sken(bore[0].qr), sken(bore[1].qr), sken(anineVip[5].qr), sken(anineNav[1].qr)];
    r = await api("POST", "/business/tickets/scan-batch", T.doorman, { scans: paket });
    assert(r.status === 200 && r.body.results.length === 4 && r.body.results.every(x => x.result === "ok"), "paket (2x bor T2, 1x ana T1, 1x navadna): vsi ok", r.body);
    assert(await stStrezb() === 2, "po paketu: 2 strezbi (T1 ana, T2 bor); 2. vstopnica bor in 6. ana ne podvojita, navadna ne ustvari", await stStrezb());
    ts = (await pool.query("SELECT * FROM table_service WHERE order_id=$1", [O_BOR])).rows;
    assert(ts.length === 1 && ts[0].table_label === "T2" && ts[0].table_seats === 4 && ts[0].package_name === "Jameson 0,7 l", "bor: strezba T2 / 4 sedezi / paket", ts[0]);
    const usedBor = (await pool.query("SELECT used_at FROM tickets WHERE serial=$1", [bore[0].serial])).rows[0].used_at;
    assert(ts[0].scanned_at.getTime() === usedBor.getTime(), "scanned_at v paketu = used_at prve skenirane vstopnice (isti cas kot sken)");
    assert(r.body.results[0].table_service_created === true && r.body.results[1].table_service_created === false, "scan-batch: table_service_created true pri prvem, false pri drugem", r.body.results.slice(0, 2));
    r = await api("POST", "/business/tickets/scan-batch", T.doorman, { scans: paket });
    assert(r.status === 200 && r.body.results.every(x => x.result === "ok"), "ponovitev ISTEGA paketa: se vedno ok (idempotenca I14)", r.body);
    assert(await stStrezb() === 2, "ponovitev paketa strezb ne podvoji (se vedno 2)");
    // Preostali vstopnici bor v drugem paketu.
    r = await api("POST", "/business/tickets/scan-batch", T.doorman, { scans: [sken(bore[2].qr, "telefon-strezba-2"), sken(bore[3].qr, "telefon-strezba-2")] });
    assert(r.body.results.every(x => x.result === "ok") && await stStrezb() === 2, "se 2 vstopnici bor z druge naprave: ok, se vedno 2 strezbi");
    assert(await stStrezb("order_id=$1", [O_NAV]) === 0 && await stStrezb("order_id=$1", [O_TUJ]) === 0, "navadno narocilo in tuja miza: brez strezbe");
    assert(await stStrezb("TRUE") === 2 && (await pool.query("SELECT COUNT(*)::int AS n FROM table_holds")).rows[0].n === 1, "rezervacija po telefonu (T3) je v table_holds, v table_service je ni");

    console.log("\n# GET /business/events/:id/table-service: vloge, tuj klub, brez podatkov kupca (I27)");
    const pot = (e) => `/business/events/${e}/table-service`;
    r = await api("GET", pot(E1), null);
    assert(r.status === 401, "brez zetona -> 401", r.status);
    r = await api("GET", pot(E1), T.doorman);
    assert(r.status === 403, "vratar seznama strezbe NE vidi -> 403", r.body);
    r = await api("GET", pot(E1), T.kupecana);
    assert(r.status === 403, "navaden uporabnik (ni clan kluba) -> 403", r.status);
    r = await api("GET", pot(E1), T.drugi);
    assert(r.status === 404, "lastnik drugega kluba na tujem dogodku -> 404", r.body);
    r = await api("GET", pot(E1), T.tujnatakar);
    assert(r.status === 404, "natakar drugega kluba na tujem dogodku -> 404", r.body);
    r = await api("GET", pot(E2), T.natakar);
    assert(r.status === 404, "natakar na dogodku drugega kluba -> 404", r.body);
    r = await api("GET", pot("abc"), T.natakar);
    assert(r.status === 400, "id dogodka niz -> 400", r.status);
    r = await api("GET", pot(999999), T.natakar);
    assert(r.status === 404, "dogodek ne obstaja -> 404", r.status);
    for (const [ime, tok] of [["natakar", T.natakar], ["manager", T.manager], ["lastnik", T.lastnik]]) {
      const x = await api("GET", pot(E1), tok);
      assert(x.status === 200 && x.body.items.length === 2, `${ime}: 200, 2 strezbi`, x.body);
    }
    r = await api("GET", pot(E1), T.natakar);
    const it = r.body.items;
    const KLJUCI = "delivered_at,delivered_by_username,id,order_id,package_description,package_name,scanned_at,table_label,table_seats";
    assert(it.every(x => Object.keys(x).sort().join() === KLJUCI), "vsak element ima TOCNO dogovorjena polja", it.map(x => Object.keys(x).join()));
    assert(it[0].table_label === "T1" && it[0].table_seats === 6 && it[0].package_name === "Jameson 0,7 l" && it[0].package_description === "4x Red Bull" && it[0].order_id === O_ANA && it[0].delivered_at === null && it[0].delivered_by_username === null, "prvi: T1, 6 sedezev, paket, opis (po scanned_at)", it[0]);
    assert(it[1].table_label === "T2" && it[1].table_seats === 4 && it[1].order_id === O_BOR, "drugi: T2, 4 sedezi", it[1]);
    assert(typeof it[0].scanned_at === "string" && !isNaN(Date.parse(it[0].scanned_at)), "scanned_at je ISO niz");
    for (const [ime, tok] of [["natakar", T.natakar], ["manager", T.manager], ["lastnik", T.lastnik]]) {
      const x = await api("GET", pot(E1), tok);
      assert(!/kupec|@|e-?mail|buyer|holder|phone|telefon|Janez|public_ref|user_id|serial|qr/i.test(x.besedilo), `${ime}: odgovor NE vsebuje imena, uporabniskega imena, e-naslova, telefona kupca ali gosta`, x.besedilo.slice(0, 300));
    }
    const sk = (await pool.query("SELECT column_name FROM information_schema.columns WHERE table_name='table_service'")).rows.map(c => c.column_name);
    assert(!sk.some(c => /email|phone|buyer|holder/.test(c)) && sk.filter(c => /user/.test(c)).join() === "delivered_by_user_id", "tabela kupca sploh ne hrani (edini uporabnik je dostavitelj)", sk);

    console.log("\n# Natakar ne pride do poti s podatki kupcev (I27 / I5)");
    r = await api("GET", `/business/events/${E1}/tickets`, T.natakar);
    assert(r.status === 403, "GET /business/events/:id/tickets (kupci, imetniki) -> 403", r.status);
    r = await api("GET", `/business/events/${E1}/vip`, T.natakar);
    assert(r.status === 403, "GET /business/events/:id/vip (kupci mize, ime gosta rezervacije) -> 403", r.status);
    r = await api("POST", "/business/tickets/scan", T.natakar, { qr: anineVip[0].qr });
    assert(r.status === 403, "POST /business/tickets/scan (bi vrnil imetnika) -> 403", r.status);
    r = await api("POST", "/business/tickets/scan-batch", T.natakar, { scans: [] });
    assert(r.status === 403, "POST /business/tickets/scan-batch -> 403", r.status);
    r = await api("GET", `/business/events/${E1}/scan-list`, T.natakar);
    assert(r.status === 403, "GET /business/events/:id/scan-list -> 403", r.status);
    r = await api("GET", "/business/scan-key", T.natakar);
    assert(r.status === 403, "GET /business/scan-key -> 403", r.status);
    for (const [m, p] of [["GET", "/business/sales"], ["GET", "/business/activity"], ["GET", "/business/vip"]]) {
      r = await api(m, p, T.natakar);
      assert(r.status === 403, `${m} ${p} -> 403`, r.status);
    }
    r = await api("GET", "/business/clubs/me", T.natakar);
    assert(r.status === 200 && r.body.my_role === "bartender", "GET /business/clubs/me: 200, my_role bartender (aplikacija pokaze svoj obraz)", r.body.my_role);
    r = await api("GET", "/business/events", T.natakar);
    assert(r.status === 200 && Array.isArray(r.body) && r.body.some(e => e.id === E1) && !r.body.some(e => e.id === E2), "GET /business/events: natakar vidi dogodke SVOJEGA kluba (izbirnik dogodka v Table service)", r.body.map && r.body.map(e => e.id));
    assert(!/@|kupec/i.test(JSON.stringify(r.body)), "GET /business/events brez podatkov kupcev");
    r = await api("GET", `/business/events/${E1}/tickets`, T.doorman);
    assert(r.status === 200, "vratar se vedno vidi vstopnice dogodka (ni regresije)", r.status);
    r = await api("GET", `/business/events/${E1}/vip`, T.doorman);
    assert(r.status === 200, "vratar se vedno vidi VIP rezervacije (ni regresije)", r.status);

    console.log("\n# PUT /business/table-service/:id: delivered true/false");
    const idA = it[0].id, idB = it[1].id;
    const put = (id, tok, telo) => api("PUT", `/business/table-service/${id}`, tok, telo);
    r = await put(idA, null, { delivered: true });
    assert(r.status === 401, "brez zetona -> 401", r.status);
    r = await put(idA, T.doorman, { delivered: true });
    assert(r.status === 403, "vratar -> 403", r.body);
    r = await put(idA, T.kupecana, { delivered: true });
    assert(r.status === 403, "navaden uporabnik -> 403", r.body);
    r = await put(idA, T.drugi, { delivered: true });
    assert(r.status === 404, "lastnik drugega kluba -> 404", r.body);
    r = await put(idA, T.tujnatakar, { delivered: true });
    assert(r.status === 404, "natakar drugega kluba -> 404", r.body);
    assert(await stStrezb("delivered_at IS NOT NULL") === 0, "zavrnjeni klici niso nicesar dostavili");
    for (const [opis, telo] of [["brez telesa", undefined], ["delivered manjka", {}], ["delivered niz", { delivered: "true" }], ["delivered 1", { delivered: 1 }], ["delivered null", { delivered: null }]]) {
      r = await put(idA, T.natakar, telo);
      assert(r.status === 400, `${opis} -> 400`, [r.status, r.body]);
    }
    r = await put("abc", T.natakar, { delivered: true });
    assert(r.status === 400, "id niz -> 400", r.status);
    r = await put(999999, T.natakar, { delivered: true });
    assert(r.status === 404, "neobstojec id -> 404", r.status);
    assert(await stStrezb("delivered_at IS NOT NULL") === 0, "neveljavni klici niso nicesar spremenili");

    r = await put(idA, T.natakar, { delivered: true });
    assert(r.status === 200 && r.body.id === idA && typeof r.body.delivered_at === "string" && r.body.delivered_by_username === "natakar" && Object.keys(r.body).sort().join() === KLJUCI, "natakar: delivered true -> 200, element z delivered_at in delivered_by_username", r.body);
    const dost1 = r.body.delivered_at;
    assert(r.besedilo.indexOf("kupec") < 0 && r.besedilo.indexOf("@") < 0, "odgovor PUT brez podatkov kupca");
    r = await put(idA, T.manager, { delivered: true });
    assert(r.status === 200 && r.body.delivered_at === dost1 && r.body.delivered_by_username === "natakar", "ponovni true (manager) je idempotenten: cas in dostavitelj ostaneta", r.body);
    r = await api("GET", pot(E1), T.manager);
    assert(r.body.items[0].id === idB && r.body.items[0].delivered_at === null && r.body.items[1].id === idA && r.body.items[1].delivered_at === dost1, "seznam: nedostavljena najprej, dostavljena na koncu", r.body.items.map(x => [x.id, x.delivered_at]));
    r = await put(idA, T.lastnik, { delivered: false });
    assert(r.status === 200 && r.body.delivered_at === null && r.body.delivered_by_username === null, "lastnik: delivered false (razveljavi) -> delivered_at null", r.body);
    assert(await stStrezb("delivered_at IS NOT NULL") === 0, "v bazi nic dostavljenega po razveljavitvi");
    r = await put(idA, T.natakar, { delivered: false });
    assert(r.status === 200 && r.body.delivered_at === null, "razveljavitev nedostavljenega je idempotentna -> 200", r.body);
    r = await api("GET", pot(E1), T.natakar);
    assert(r.body.items[0].id === idA && r.body.items[1].id === idB, "po razveljavitvi spet po scanned_at (T1, T2)", r.body.items.map(x => x.id));

    console.log("\n# GET /me pending_table_service in GET /me/table-service");
    for (const [ime, tok, pricakovano] of [["natakar", T.natakar, 2], ["manager", T.manager, 2], ["lastnik", T.lastnik, 2], ["vratar", T.doorman, 0], ["kupec", T.kupecana, 0], ["tuji natakar", T.tujnatakar, 0], ["lastnik drugega kluba", T.drugi, 0]]) {
      const x = await api("GET", "/me", tok);
      assert(x.body.pending_table_service === pricakovano, `GET /me ${ime}: pending_table_service = ${pricakovano}`, x.body.pending_table_service);
    }
    r = await api("GET", "/me/table-service", T.natakar);
    assert(r.status === 200 && r.body.items.length === 2, "GET /me/table-service natakar: 2 elementa", r.body);
    const ZK = "club_id,club_name,event_id,event_title,id,package_name,scanned_at,table_label";
    assert(r.body.items.every(x => Object.keys(x).sort().join() === ZK), "elementi imajo TOCNO dogovorjena polja", r.body.items.map(x => Object.keys(x).join()));
    assert(r.body.items[0].club_id === 1 && r.body.items[0].club_name === "Pure Club" && r.body.items[0].event_id === E1 && r.body.items[0].event_title === "Strezba noc" && r.body.items[0].table_label === "T1" && r.body.items[0].package_name === "Jameson 0,7 l" && r.body.items[0].id === idA, "prvi: Pure Club / Strezba noc / T1 / paket (po scanned_at)", r.body.items[0]);
    assert(!/kupec|@|e-?mail|buyer|holder|phone|telefon|Janez|public_ref|user_id/i.test(r.besedilo), "GET /me/table-service brez podatkov kupca");
    for (const [ime, tok] of [["vratar", T.doorman], ["kupec", T.kupecana], ["tuji natakar", T.tujnatakar], ["lastnik drugega kluba", T.drugi]]) {
      const x = await api("GET", "/me/table-service", tok);
      assert(x.status === 200 && x.body.items.length === 0, `GET /me/table-service ${ime}: prazno`, x.body);
    }
    r = await api("GET", "/me/table-service", null);
    assert(r.status === 401, "GET /me/table-service brez zetona -> 401", r.status);
    // Po dostavi ene strezbe: 1; po dostavi obeh: 0.
    await put(idA, T.natakar, { delivered: true });
    r = await api("GET", "/me", T.natakar);
    assert(r.body.pending_table_service === 1, "po dostavi T1: pending_table_service = 1", r.body.pending_table_service);
    r = await api("GET", "/me/table-service", T.manager);
    assert(r.body.items.length === 1 && r.body.items[0].table_label === "T2", "zvonec: ostane samo se T2", r.body);
    r = await api("GET", "/me", T.doorman);
    assert(r.body.pending_table_service === 0, "vratar se vedno 0", r.body.pending_table_service);
    await put(idB, T.natakar, { delivered: true });
    r = await api("GET", "/me", T.natakar);
    assert(r.body.pending_table_service === 0, "po dostavi obeh: pending_table_service = 0", r.body.pending_table_service);
    r = await api("GET", "/me/table-service", T.natakar);
    assert(r.body.items.length === 0, "po dostavi obeh: zvonec prazen", r.body);
    await put(idA, T.natakar, { delivered: false }); await put(idB, T.natakar, { delivered: false });

    console.log("\n# Okno dogodka za zvonec (start - 2 h .. end_at oz. start + 8 h)");
    const okno = async (sql, p = []) => { await pool.query(sql, p); const x = await api("GET", "/me", T.natakar); const y = await api("GET", "/me/table-service", T.natakar); return [x.body.pending_table_service, y.body.items.length]; };
    let o = await okno("UPDATE events SET start_at = NOW() + INTERVAL '3 hours', end_at = NULL WHERE id=$1", [E1]);
    assert(o[0] === 0 && o[1] === 0, "dogodek se zacne cez 3 h (pred oknom -2 h): 0", o);
    o = await okno("UPDATE events SET start_at = NOW() + INTERVAL '110 minutes' WHERE id=$1", [E1]);
    assert(o[0] === 2 && o[1] === 2, "dogodek se zacne cez 110 min (v oknu): 2", o);
    o = await okno("UPDATE events SET start_at = NOW() - INTERVAL '7 hours' WHERE id=$1", [E1]);
    assert(o[0] === 2 && o[1] === 2, "brez end_at: tece do start + 8 h (zacel pred 7 h): 2", o);
    o = await okno("UPDATE events SET start_at = NOW() - INTERVAL '9 hours' WHERE id=$1", [E1]);
    assert(o[0] === 0 && o[1] === 0, "brez end_at: zacel pred 9 h -> koncan: 0", o);
    o = await okno("UPDATE events SET start_at = NOW() - INTERVAL '9 hours', end_at = NOW() + INTERVAL '1 hour' WHERE id=$1", [E1]);
    assert(o[0] === 2 && o[1] === 2, "z end_at (cez 1 h): se tece: 2", o);
    o = await okno("UPDATE events SET start_at = NOW() - INTERVAL '9 hours', end_at = NOW() - INTERVAL '1 hour' WHERE id=$1", [E1]);
    assert(o[0] === 0 && o[1] === 0, "z end_at (pred 1 h): koncan: 0", o);
    o = await okno("UPDATE events SET start_at = NOW() - INTERVAL '1 hour', end_at = NULL, status='cancelled' WHERE id=$1", [E1]);
    assert(o[0] === 0 && o[1] === 0, "odpovedan dogodek: 0", o);
    o = await okno("UPDATE events SET start_at = NOW() + INTERVAL '2 hours', end_at = NULL, status='published' WHERE id=$1", [E1]);
    assert(o[0] === 2, "spet objavljen, v oknu: 2", o);
    // Seznam dogodka ni vezan na okno (natakar po koncu dogodka se vedno vidi, kaj je bilo dostavljeno).
    await pool.query("UPDATE events SET start_at = NOW() - INTERVAL '20 hours' WHERE id=$1", [E1]);
    r = await api("GET", pot(E1), T.natakar);
    assert(r.status === 200 && r.body.items.length === 2, "GET seznama dogodka deluje tudi po koncu dogodka (2)", r.body.items.length);
    r = await api("GET", "/me", T.natakar);
    assert(r.body.pending_table_service === 0, "koncan dogodek: znacka 0", r.body.pending_table_service);

    console.log("\n# Odvzem vloge velja takoj (I5) in tuj klub");
    r = await api("DELETE", `/business/team/${await uid("natakar@outly.si")}`, T.manager);
    assert(r.status === 200 && !r.body.members.some(m => m.role === "bartender"), "manager odstrani natakarja -> 200", r.body.members);
    r = await api("GET", pot(E1), T.natakar);
    assert(r.status === 403, "odstranjen natakar: seznam strezbe -> 403 (vloga se bere iz baze)", r.status);
    r = await api("GET", "/me", T.natakar);
    assert(r.body.pending_table_service === 0 && r.body.club_role === null, "odstranjen natakar: pending_table_service 0, club_role null", r.body);
    r = await api("GET", "/me/table-service", T.natakar);
    assert(r.status === 200 && r.body.items.length === 0, "odstranjen natakar: zvonec prazen", r.body);

    console.log("\n# Strezba pripada klubu dogodka");
    r = await pool.query("SELECT ts.club_id FROM table_service ts JOIN events e ON e.id = ts.event_id WHERE ts.club_id <> e.club_id");
    assert(r.rows.length === 0, "club_id strezbe = events.club_id povsod");
  } catch (e) {
    fail++; console.log("  ✗ IZJEMA:", e && e.stack || e);
  }

  srv.kill(); jwksServer.close(); await pool.end().catch(() => {});
  console.log(`\n${ok} OK, ${fail} napak`);
  if (fail) { console.log("--- dnevnik streznika (zadnjih 3000 znakov) ---\n" + log.slice(-3000)); process.exit(1); }
  process.exit(0);
})();
