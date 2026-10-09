#!/usr/bin/env node
/**
 * Test: RAZPORED VIP MIZ PO DOGODKU (migracija 039, invarianta I13/I28, issue #175, Martin 9. 10. 2026).
 * Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_razpored.js
 * Vzorec kot test_vabila.js / test_strezba.js: lokalni JWKS (3958), backend kot otrok proces na portu 3205, TRUNCATE na zacetku.
 *
 *  1  vir razporeda: GET /business/events/:id/vip-layout (privzeto club), venue_has_layout, vip_layout_source v GET /events
 *  2  vloge: brez zetona 401, vratar/natakar 403, tuj klub 404, neveljaven id 400
 *  3  validacija PUT (ista kot PUT /business/vip): source, mreza, meje, cene, podvojene oznake, tuji id; zavrnjen PUT ne spremeni nicesar
 *  4  copy_from_venue: brez gostitelja 400, gostitelj brez tlorisa 400, kopija (posnetek: sprememba gostitelja ne vpliva), ponovna kopija
 *  5  lasten razpored: ustvari / posodobi / zamenjaj oznaki / odstrani (brez narocil se brise); ista oznaka na dveh dogodkih je v redu
 *  6  izjeme po dogodku (PUT /business/events/:id/vip): vklop; izjeme (cena, izklop) veljajo tudi za mize dogodka, miza drugega dogodka 404; klubski PUT /business/vip se mize dogodka NE dotakne
 *  7  javni GET /events/:id/vip in vip_from_cents kazeta mize dogodka; nakup mize dogodka (vstopnic = seats), I13 (druga prodaja 409, 6 vzporednih -> 1)
 *  8  miza drugega dogodka / klubska miza pri razporedu dogodka -> 404; rezervacija po telefonu na mizi dogodka
 *  9  preklop nazaj na club: miza z narocilom arhivirana (narocilo veljavno, sken dela, strezba nastane), ostale pobrisane
 * 10  navaden klub: GET /events/:id/vip nespremenjen (regresija), klubski nakup dela, razpored dogodka mu je dovoljen, klubske mize ostanejo
 * 11  baza: FK CASCADE, unikatna oznaka po dogodku, CHECK vira, club_id mize dogodka = events.club_id
 * 12  tek: nakup mize proti odstranitvi mize iz razporeda (PUT vedno 200, nakup 201 ali 404; narocilo => arhivirana, sicer izbrisana)
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3205, JWKS_PORT = 3958;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-razpored";
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
const novIp = () => `10.50.${(++ipStevec >> 8) & 255}.${(ipStevec & 255) + 1}`;
async function api(method, p, token, body, glave) {
  const r = await fetch(BASE + p, { method, headers: { "content-type": "application/json", "x-forwarded-for": novIp(), ...(token ? { authorization: "Bearer " + token } : {}), ...(glave || {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, besedilo: t };
}
// Primerjava vrednosti brez vrstnega reda kljucev (JSONB hrani kljuce po svoje).
const uredi = (v) => Array.isArray(v) ? v.map(uredi) : v && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map(k => [k, uredi(v[k])])) : v;
const enako = (a, b) => JSON.stringify(uredi(a)) === JSON.stringify(uredi(b));
const nakup = (eid, mid, tok, telo) => api("POST", `/events/${eid}/tables/${mid}/orders`, tok, telo);

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 100; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }
  const sqlKoda = async (q, p) => { try { await pool.query(q, p); return null; } catch (e) { return e.code || String(e.message); } };

  try {
    const IMENA = ["hostown", "orgown", "orgmgr", "orgdoor", "orgbar", "klubown", "drugorg", "ana", "bor", "cene", "kupec4"];
    const T = {};
    for (const [i, ime] of IMENA.entries()) T[ime] = zeton(`${ime}@outly.si`, uuid(i + 1));
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='business' WHERE email IN ('hostown@outly.si','orgown@outly.si','klubown@outly.si','drugorg@outly.si')");
    await pool.query("UPDATE users SET date_of_birth = (CURRENT_DATE - INTERVAL '30 years')::date WHERE email IN ('ana@outly.si','bor@outly.si','cene@outly.si','kupec4@outly.si')");
    const uid = async (ime) => (await pool.query("SELECT id FROM users WHERE email=$1", [`${ime}@outly.si`])).rows[0].id;
    const klub = async (ime, lastnik, organizator, extra = "") => (await pool.query(
      `INSERT INTO clubs (owner_user_id, name, city, is_organizer) VALUES ($1, $2, $3, $4) RETURNING id`,
      [await uid(lastnik), ime, organizator ? "" : "Ljubljana", !!organizator])).rows[0].id;
    const HOST = await klub("Gostitelj Klub", "hostown", false);
    const HOST2 = (await pool.query(`INSERT INTO clubs (owner_user_id, name, city) VALUES ($1, 'Gostitelj Brez Plana', 'Celje') RETURNING id`, [await uid("hostown")])).rows[0].id;
    const ORG = await klub("Promotor", "orgown", true);
    const ORG2 = await klub("Drug Promotor", "drugorg", true);
    const KLUB = await klub("Navaden Klub", "klubown", false);
    await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES ($1,$2,'manager'), ($1,$3,'doorman'), ($1,$4,'bartender')", [ORG, await uid("orgmgr"), await uid("orgdoor"), await uid("orgbar")]);
    let r;

    // ---- gostitelj: tloris + 3 mize (kot pri PUT /business/vip) ----
    const PLAN_H = { width: 24, height: 16, elements: [{ type: "stage", x: 8, y: 0, w: 8, h: 3, label: "Oder" }, { type: "bar", x: 0, y: 12, w: 6, h: 2, label: "" }] };
    r = await api("PUT", "/business/vip", T.hostown, { plan: PLAN_H, tables: [
      { label: "H1", x: 2, y: 5, w: 2, h: 2, shape: "round", seats: 6, price_cents: 30000 },
      { label: "H2", x: 6, y: 5, w: 3, h: 2, shape: "rect", seats: 4, price_cents: 20000 },
      { label: "H3", x: 12, y: 5, w: 2, h: 2, shape: "round", seats: 8, price_cents: 45000 },
    ], packages: [{ name: "Tuji paket gostitelja", description: "ne sme se kopirati" }] });
    assert(r.status === 200 && r.body.tables.length === 3, "gostitelj: tloris + 3 mize", r.body);
    const HOST_MIZE = r.body.tables.map(t => t.id);
    // ---- organizator: paketi (cene steklenic so vedno organizatorjeve) ----
    r = await api("PUT", "/business/vip", T.orgown, { plan: null, tables: [], packages: [{ name: "Vodka 0,7 l", description: "4x Red Bull" }] });
    assert(r.status === 200 && r.body.tables.length === 0 && r.body.packages.length === 1, "organizator: samo paket, brez tlorisa in miz", r.body);
    const PAKET = r.body.packages[0].id;
    const PAKET_HOST = (await pool.query("SELECT id FROM bottle_packages WHERE club_id=$1", [HOST])).rows[0].id;
    // ---- navaden klub: lasten tloris ----
    const PLAN_K = { width: 20, height: 12, elements: [] };
    r = await api("PUT", "/business/vip", T.klubown, { plan: PLAN_K, tables: [
      { label: "T1", x: 1, y: 1, w: 2, h: 2, shape: "round", seats: 4, price_cents: 15000 },
      { label: "T2", x: 5, y: 1, w: 2, h: 2, shape: "round", seats: 6, price_cents: 25000 },
    ], packages: [{ name: "Klubski paket", description: "x" }] });
    assert(r.status === 200 && r.body.tables.length === 2, "navaden klub: tloris + 2 mize", r.body);
    const KLUB_MIZE = r.body.tables.map(t => t.id), KLUB_PAKET = r.body.packages[0].id;

    async function dogodek(clubId, naslov, { zacetek = "NOW() + INTERVAL '2 hours'", gostitelj = null, prosto = false } = {}) {
      return (await pool.query(
        `INSERT INTO events (club_id, title, poster_url, start_at, status, ticket_price_cents, capacity, vip_enabled, venue_club_id, venue_name, venue_city)
         VALUES ($1,$2,'https://example.com/p.jpg', ${zacetek}, 'published', 1500, 100, FALSE, $3, $4, $5) RETURNING id`,
        [clubId, naslov, gostitelj, prosto ? "Lokal X" : "", prosto ? "Maribor" : ""])).rows[0].id;
    }
    const EA = await dogodek(ORG, "Org noc A", { gostitelj: HOST });                                         // sken-okno (2 h), lasten razpored + nakupi
    const EB = await dogodek(ORG, "Org noc B", { gostitelj: HOST, zacetek: "NOW() + INTERVAL '3 days'" });    // kopija gostitelja
    const EC = await dogodek(ORG, "Org noc C", { prosto: true, zacetek: "NOW() + INTERVAL '3 days'" });       // prosto prizorisce (brez gostitelja)
    const ED = await dogodek(ORG, "Org noc D", { gostitelj: HOST2, zacetek: "NOW() + INTERVAL '3 days'" });   // gostitelj brez tlorisa
    const EG = await dogodek(ORG2, "Tuj organizator", { prosto: true, zacetek: "NOW() + INTERVAL '3 days'" });
    const EK = await dogodek(KLUB, "Klubski vecer");
    const EK2 = await dogodek(KLUB, "Klubski vecer 2", { zacetek: "NOW() + INTERVAL '3 days'" });

    // ============================================================
    console.log("\n# 1. Vir razporeda: privzeto club");
    r = await api("GET", `/business/events/${EA}/vip-layout`, T.orgown);
    assert(r.status === 200 && r.body.source === "club" && r.body.floor_plan === null && Array.isArray(r.body.tables) && r.body.tables.length === 0, "nov dogodek: source club, brez tlorisa in miz", r.body);
    assert(r.body.from_club_id === null && r.body.from_club_name === null, "brez kopije: from_club_id / from_club_name null", r.body);
    assert(r.body.venue_club_id === HOST && r.body.venue_club_name === "Gostitelj Klub" && r.body.venue_has_layout === true, "gostitelj dogodka + venue_has_layout = true", r.body);
    r = await api("GET", `/business/events/${EC}/vip-layout`, T.orgown);
    assert(r.status === 200 && r.body.venue_club_id === null && r.body.venue_club_name === null && r.body.venue_has_layout === false, "prosto prizorisce: venue_club_id null, venue_has_layout false", r.body);
    r = await api("GET", `/business/events/${ED}/vip-layout`, T.orgown);
    assert(r.status === 200 && r.body.venue_club_id === HOST2 && r.body.venue_has_layout === false, "gostitelj brez tlorisa: venue_has_layout false", r.body);
    r = await api("GET", `/events/${EA}`);
    assert(r.status === 200 && r.body.vip_layout_source === "club", "GET /events/:id: vip_layout_source = club (privzeto)", r.body.vip_layout_source);
    r = await api("GET", "/events");
    assert(r.status === 200 && r.body.length >= 6 && r.body.every(e => e.vip_layout_source === "club"), "GET /events: vsak dogodek ima vip_layout_source", r.body.map(e => e.vip_layout_source));

    // ============================================================
    console.log("\n# 2. Vloge in dostop");
    r = await api("GET", `/business/events/${EA}/vip-layout`);
    assert(r.status === 401, "brez zetona GET -> 401", r.status);
    r = await api("PUT", `/business/events/${EA}/vip-layout`, undefined, { source: "club" });
    assert(r.status === 401, "brez zetona PUT -> 401", r.status);
    for (const ime of ["orgdoor", "orgbar"]) {
      r = await api("GET", `/business/events/${EA}/vip-layout`, T[ime]);
      assert(r.status === 403, `${ime} GET -> 403`, r.status);
      r = await api("PUT", `/business/events/${EA}/vip-layout`, T[ime], { source: "club" });
      assert(r.status === 403, `${ime} PUT -> 403`, r.status);
    }
    r = await api("GET", `/business/events/${EA}/vip-layout`, T.ana);
    assert(r.status === 403, "navaden uporabnik (ni clan kluba) GET -> 403", r.status);
    r = await api("GET", `/business/events/${EG}/vip-layout`, T.orgown);
    assert(r.status === 404, "tuj dogodek (drug organizator) GET -> 404", r.status);
    r = await api("PUT", `/business/events/${EG}/vip-layout`, T.orgown, { source: "club" });
    assert(r.status === 404, "tuj dogodek PUT -> 404", r.status);
    r = await api("GET", `/business/events/99999/vip-layout`, T.orgown);
    assert(r.status === 404, "neobstojec dogodek -> 404", r.status);
    r = await api("GET", `/business/events/abc/vip-layout`, T.orgown);
    assert(r.status === 400, "neveljaven id -> 400", r.status);
    r = await api("PUT", `/business/events/99999999999/vip-layout`, T.orgown, { source: "club" });
    assert(r.status === 400, "id izven int4 -> 400 (ne 500)", r.status);
    r = await api("GET", `/business/events/${EA}/vip-layout`, T.orgmgr);
    assert(r.status === 200, "manager organizatorja GET -> 200", r.status);

    // ============================================================
    console.log("\n# 3. Validacija PUT (ista kot PUT /business/vip)");
    const P1 = { width: 24, height: 16, elements: [{ type: "stage", x: 8, y: 0, w: 8, h: 3, label: "Oder" }] };
    const M = (label, x = 2, y = 5, extra = {}) => ({ label, x, y, w: 2, h: 2, shape: "round", seats: 6, price_cents: 10000, ...extra });
    const nap = async (telo, msg) => { const x = await api("PUT", `/business/events/${EA}/vip-layout`, T.orgown, telo); assert(x.status === 400, msg, [x.status, x.besedilo]); };
    await nap(undefined, "brez telesa -> 400");
    await nap({}, "brez source -> 400");
    await nap({ source: "nekaj" }, "neznan source -> 400");
    await nap({ source: "event" }, "source event brez floor_plan, tables in copy_from_venue -> 400");
    await nap({ source: "event", floor_plan: P1 }, "source event brez tables -> 400");
    await nap({ source: "event", tables: [M("A")] }, "source event brez floor_plan -> 400");
    await nap({ source: "event", floor_plan: { width: 4, height: 16, elements: [] }, tables: [] }, "mreza premajhna (width 4) -> 400");
    await nap({ source: "event", floor_plan: { width: 24, height: 41, elements: [] }, tables: [] }, "mreza prevelika (height 41) -> 400");
    await nap({ source: "event", floor_plan: { ...P1, elements: [{ type: "ufo", x: 0, y: 0, w: 1, h: 1, label: "" }] }, tables: [] }, "neznan tip elementa -> 400");
    await nap({ source: "event", floor_plan: { ...P1, elements: Array.from({ length: 81 }, () => ({ type: "wall", x: 0, y: 0, w: 1, h: 1, label: "" })) }, tables: [] }, "81 elementov -> 400");
    await nap({ source: "event", floor_plan: P1, tables: [M("A", 23, 5)] }, "miza izven tlorisa (x + w > width) -> 400");
    await nap({ source: "event", floor_plan: P1, tables: [M("A", 2, 5, { seats: 0 })] }, "seats 0 -> 400");
    await nap({ source: "event", floor_plan: P1, tables: [M("A", 2, 5, { seats: 21 })] }, "seats 21 -> 400");
    await nap({ source: "event", floor_plan: P1, tables: [M("A", 2, 5, { price_cents: -1 })] }, "negativna cena -> 400");
    await nap({ source: "event", floor_plan: P1, tables: [M("A", 2, 5, { price_cents: 100.5 })] }, "necela cena (cent) -> 400");
    await nap({ source: "event", floor_plan: P1, tables: [M("A", 2, 5, { price_cents: "100" })] }, "cena kot niz -> 400");
    await nap({ source: "event", floor_plan: P1, tables: [M("A", 2, 5, { shape: "triangle" })] }, "neznana oblika -> 400");
    await nap({ source: "event", floor_plan: P1, tables: [M("A"), M("a", 6, 5)] }, "podvojena oznaka (brez razlike velikih/malih) -> 400");
    await nap({ source: "event", floor_plan: P1, tables: [M("")] }, "prazna oznaka -> 400");
    await nap({ source: "event", floor_plan: P1, tables: Array.from({ length: 61 }, (_, i) => M("Z" + i)) }, "61 miz -> 400");
    await nap({ source: "event", floor_plan: null, tables: [M("A")] }, "mize brez tlorisa (floor_plan null) -> 400");
    await nap({ source: "event", floor_plan: P1, tables: "ne" }, "tables ni seznam -> 400");
    await nap({ source: "event", floor_plan: P1, tables: [M("A", 2, 5, { id: "x" })] }, "id mize ni stevilo -> 400");
    await nap({ source: "event", floor_plan: P1, tables: [M("A", 2, 5, { id: KLUB_MIZE[0] })] }, "id tuje mize (druga klubska miza) -> 400");
    await nap({ source: "event", floor_plan: P1, tables: [M("A", 2, 5, { id: HOST_MIZE[0] })] }, "id mize gostitelja -> 400");
    await nap({ source: "event", floor_plan: P1, tables: [M("A", 2, 5, { id: 987654 })] }, "neobstojec id mize -> 400");
    r = await api("GET", `/business/events/${EA}/vip-layout`, T.orgown);
    assert(r.body.source === "club" && r.body.tables.length === 0, "zavrnjeni PUT-i niso ustvarili nicesar (source se club)", r.body);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM club_tables WHERE event_id=$1", [EA])).rows[0].n === 0, "v bazi nobene mize dogodka");
    // 60 miz je se dovoljenih
    r = await api("PUT", `/business/events/${EA}/vip-layout`, T.orgown, { source: "event", floor_plan: { width: 40, height: 40, elements: [] },
      tables: Array.from({ length: 60 }, (_, i) => M("Z" + i, (i % 10) * 3, Math.floor(i / 10) * 3, { seats: 2 })) });
    assert(r.status === 200 && r.body.tables.length === 60, "60 miz je se dovoljenih -> 200", [r.status, r.besedilo.slice(0, 200)]);
    r = await api("PUT", `/business/events/${EA}/vip-layout`, T.orgown, { source: "club" });
    assert(r.status === 200 && r.body.source === "club" && r.body.tables.length === 0 && r.body.released_holds === 0, "nazaj na club (60 miz brez narocil), released_holds 0", r.body);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM club_tables WHERE event_id=$1", [EA])).rows[0].n === 0, "mize brez narocil so pobrisane (ne arhivirane)");

    // ============================================================
    console.log("\n# 4. Kopija razporeda gostitelja (copy_from_venue)");
    r = await api("PUT", `/business/events/${EC}/vip-layout`, T.orgown, { source: "event", copy_from_venue: true });
    assert(r.status === 400, "dogodek brez venue_club_id + copy_from_venue -> 400", [r.status, r.besedilo]);
    r = await api("PUT", `/business/events/${ED}/vip-layout`, T.orgown, { source: "event", copy_from_venue: true });
    assert(r.status === 400, "gostitelj brez tlorisa + copy_from_venue -> 400", [r.status, r.besedilo]);
    r = await api("GET", `/business/events/${ED}/vip-layout`, T.orgown);
    assert(r.body.source === "club", "zavrnjena kopija: source ostane club", r.body.source);
    r = await api("PUT", `/business/events/${EB}/vip-layout`, T.orgown, { source: "event", copy_from_venue: "da" });
    assert(r.status === 400, "copy_from_venue ni boolean (ni true, ni floor_plan) -> 400", [r.status, r.besedilo]);

    r = await api("PUT", `/business/events/${EB}/vip-layout`, T.orgown, { source: "event", copy_from_venue: true });
    assert(r.status === 200 && r.body.source === "event", "kopija gostitelja -> 200, source event", r.body);
    assert(enako(r.body.floor_plan, { width: 24, height: 16, elements: PLAN_H.elements.map(e => ({ type: e.type, x: e.x, y: e.y, w: e.w, h: e.h, label: e.label })) }), "floor_plan je kopija tlorisa gostitelja", r.body.floor_plan);
    assert(r.body.tables.length === 3 && ["H1", "H2", "H3"].every(l => r.body.tables.some(t => t.label === l)), "3 mize iz gostitelja (oznake H1-H3)", r.body.tables);
    const kopija = r.body.tables;
    const h1 = kopija.find(t => t.label === "H1");
    assert(h1.price_cents === 30000 && h1.seats === 6 && h1.shape === "round" && h1.x === 2 && h1.y === 5 && h1.w === 2 && h1.h === 2, "cene in oblike se kopirajo kot privzete", h1);
    assert(Object.keys(h1).sort().join() === "archived,h,id,label,price_cents,seats,shape,w,x,y" && h1.archived === false, "miza v obliki GET /business/vip (id,label,x,y,w,h,shape,seats,price_cents) + archived: false", Object.keys(h1));
    assert(kopija.every(t => !HOST_MIZE.includes(t.id)), "mize dogodka so NOVE vrstice (drug id kot mize gostitelja)");
    assert(r.body.from_club_id === HOST && r.body.from_club_name === "Gostitelj Klub" && r.body.venue_club_id === HOST && r.body.venue_has_layout === true, "from_club_id / from_club_name / venue_*", r.body);
    let vr = (await pool.query("SELECT id, club_id, event_id, archived_at FROM club_tables WHERE event_id=$1", [EB])).rows;
    assert(vr.length === 3 && vr.every(t => t.club_id === ORG && t.archived_at === null), "v bazi: 3 mize z event_id, club_id = organizator", vr);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM club_tables WHERE club_id=$1 AND event_id IS NULL AND archived_at IS NULL", [HOST])).rows[0].n === 3, "mize gostitelja so nedotaknjene (3 aktivne)");
    const ev = (await pool.query("SELECT vip_layout_source, vip_layout_from_club_id, floor_plan IS NOT NULL AS plan FROM events WHERE id=$1", [EB])).rows[0];
    assert(ev.vip_layout_source === "event" && ev.vip_layout_from_club_id === HOST && ev.plan === true, "events: vip_layout_source, vip_layout_from_club_id, floor_plan", ev);
    r = await api("GET", `/business/events/${EB}/vip-layout`, T.orgown);
    assert(r.status === 200 && r.body.source === "event" && r.body.tables.length === 3 && r.body.from_club_id === HOST, "GET vrne isto kot PUT", r.body);
    assert((await api("GET", `/events/${EB}`)).body.vip_layout_source === "event", "GET /events/:id: vip_layout_source = event");

    // Posnetek: sprememba gostitelja kopije ne spremeni.
    const hostPlan2 = { ...PLAN_H, elements: [] };
    r = await api("PUT", "/business/vip", T.hostown, { plan: hostPlan2, tables: [
      { id: HOST_MIZE[0], label: "H1", x: 2, y: 5, w: 2, h: 2, shape: "round", seats: 10, price_cents: 99900 },
      { label: "H4", x: 15, y: 5, w: 2, h: 2, shape: "round", seats: 2, price_cents: 5000 },
    ], packages: [] });
    assert(r.status === 200 && r.body.tables.length === 2, "gostitelj uredi tloris (H1 cena/sedezi, H2 in H3 odstranjeni, H4 nova)", r.body);
    r = await api("GET", `/business/events/${EB}/vip-layout`, T.orgown);
    const h1b = r.body.tables.find(t => t.label === "H1");
    assert(r.body.tables.length === 3 && h1b.price_cents === 30000 && h1b.seats === 6 && r.body.floor_plan.elements.length === 2, "kopija je posnetek: sprememba gostitelja NE vpliva", r.body);
    assert(r.body.tables.every(t => t.id !== undefined) && (await pool.query("SELECT COUNT(*)::int AS n FROM club_tables WHERE event_id=$1 AND archived_at IS NULL", [EB])).rows[0].n === 3, "mize dogodka ostanejo aktivne po urejanju gostitelja");
    // Gostitelj ima ZDAJ drug tloris: ponovna kopija zamenja kopijo (stare brez narocil se pobrisejo).
    r = await api("PUT", `/business/events/${EB}/vip-layout`, T.orgown, { source: "event", copy_from_venue: true });
    assert(r.status === 200 && r.body.tables.length === 2 && ["H1", "H4"].every(l => r.body.tables.some(t => t.label === l)), "ponovna kopija: zdaj 2 mizi (H1, H4)", r.body.tables);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM club_tables WHERE event_id=$1", [EB])).rows[0].n === 2, "stare mize kopije (brez narocil) pobrisane: v bazi samo 2 vrstici");
    // Organizatorjev klubski PUT /business/vip mize dogodka NE sme arhivirati ali spremeniti.
    r = await api("PUT", "/business/vip", T.orgown, { plan: null, tables: [], packages: [{ id: PAKET, name: "Vodka 0,7 l", description: "4x Red Bull" }] });
    assert(r.status === 200 && r.body.tables.length === 0, "organizator: PUT /business/vip (prazen tloris) vrne prazne klubske mize", r.body);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM club_tables WHERE event_id=$1 AND archived_at IS NULL", [EB])).rows[0].n === 2, "PUT /business/vip NE arhivira miz dogodka");
    r = await api("PUT", "/business/vip", T.orgown, { plan: P1, tables: [{ label: "H1", x: 1, y: 1, w: 2, h: 2, shape: "round", seats: 4, price_cents: 100 }], packages: [{ id: PAKET, name: "Vodka 0,7 l", description: "4x Red Bull" }] });
    assert(r.status === 200 && r.body.tables.length === 1, "klubska miza z isto oznako kot miza dogodka (H1) je dovoljena (loceni obsegi)", r.body);
    const klubskaH1 = r.body.tables[0].id;
    r = await api("GET", "/business/vip", T.orgown);
    assert(r.body.tables.length === 1 && r.body.tables[0].id === klubskaH1, "GET /business/vip kaze samo klubske mize (ne mize dogodkov)", r.body.tables);
    r = await api("PUT", "/business/vip", T.orgown, { plan: P1, tables: [{ id: kopija[0].id, label: "X", x: 1, y: 1, w: 2, h: 2, shape: "round", seats: 4, price_cents: 100 }], packages: [] });
    assert(r.status === 400, "PUT /business/vip z id mize dogodka -> 400 (ne pripada klubu)", [r.status, r.besedilo]);
    r = await api("PUT", "/business/vip", T.orgown, { plan: null, tables: [], packages: [{ id: PAKET, name: "Vodka 0,7 l", description: "4x Red Bull" }] });
    assert(r.status === 200 && (await pool.query("SELECT COUNT(*)::int AS n FROM club_tables WHERE event_id=$1 AND archived_at IS NULL", [EB])).rows[0].n === 2, "izbris klubske H1 ne zadene miz dogodka");
    // Skrit gostitelj ni vec prizorisce: kopije ni.
    await pool.query("UPDATE clubs SET hidden = TRUE WHERE id=$1", [HOST]);
    r = await api("PUT", `/business/events/${EB}/vip-layout`, T.orgown, { source: "event", copy_from_venue: true });
    assert(r.status === 400, "skrit gostitelj + copy_from_venue -> 400 (javno ne obstaja)", [r.status, r.besedilo]);
    r = await api("GET", `/business/events/${EB}/vip-layout`, T.orgown);
    assert(r.body.venue_club_id === null && r.body.venue_has_layout === false && r.body.tables.length === 2, "skrit gostitelj: venue_club_id null, venue_has_layout false, razpored ostane", r.body);
    await pool.query("UPDATE clubs SET hidden = FALSE WHERE id=$1", [HOST]);

    // ============================================================
    console.log("\n# 5. Lasten razpored dogodka");
    const PLAN_A = { width: 24, height: 16, elements: [{ type: "dj", x: 9, y: 0, w: 6, h: 2, label: "DJ" }] };
    r = await api("PUT", `/business/events/${EA}/vip-layout`, T.orgown, { source: "event", floor_plan: PLAN_A, tables: [
      M("T1", 2, 5, { seats: 6, price_cents: 30000 }), M("T2", 6, 5, { seats: 4, price_cents: 20000 }), M("T3", 10, 5, { seats: 8, price_cents: 45000 }), M("T4", 14, 5, { seats: 2, price_cents: 9000 }),
    ] });
    assert(r.status === 200 && r.body.source === "event" && r.body.tables.length === 4, "lasten razpored: 4 mize -> 200", r.body);
    assert(enako(r.body.floor_plan, { width: 24, height: 16, elements: [{ type: "dj", x: 9, y: 0, w: 6, h: 2, label: "DJ" }] }), "floor_plan shranjen", r.body.floor_plan);
    assert(r.body.from_club_id === null, "lasten razpored: from_club_id null", r.body.from_club_id);
    const [A1, A2, A3, A4] = ["T1", "T2", "T3", "T4"].map(l => r.body.tables.find(t => t.label === l).id);
    // Posodobi z id, zamenjaj oznaki T1 <-> T2, odstrani T4, dodaj T5.
    r = await api("PUT", `/business/events/${EA}/vip-layout`, T.orgown, { source: "event", floor_plan: PLAN_A, tables: [
      { ...M("T2", 2, 5, { seats: 6, price_cents: 31000 }), id: A1 }, { ...M("T1", 6, 5, { seats: 4, price_cents: 21000 }), id: A2 },
      { ...M("T3", 10, 5, { seats: 8, price_cents: 45000 }), id: A3 }, M("T5", 18, 5, { seats: 10, price_cents: 60000 }),
    ] });
    assert(r.status === 200 && r.body.tables.length === 4, "posodobitev: zamenjava oznak T1 <-> T2 ne trci ob unikatnem indeksu", [r.status, r.besedilo.slice(0, 300)]);
    const po = Object.fromEntries(r.body.tables.map(t => [t.label, t]));
    assert(po.T2.id === A1 && po.T2.price_cents === 31000 && po.T1.id === A2 && po.T1.price_cents === 21000 && po.T3.id === A3, "id-ji ostanejo, oznake in cene posodobljene", r.body.tables);
    assert(!r.body.tables.some(t => t.label === "T4") && po.T5 && po.T5.id !== A4, "T4 odstranjena, T5 nova", r.body.tables);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM club_tables WHERE event_id=$1", [EA])).rows[0].n === 4, "odstranjena miza brez narocil je izbrisana (v bazi 4 vrstice)");
    // Isti oznaki T1 na dveh dogodkih organizatorja sta v redu.
    r = await api("PUT", `/business/events/${EB}/vip-layout`, T.orgown, { source: "event", floor_plan: PLAN_A, tables: [M("T1", 2, 5), M("T2", 6, 5)] });
    assert(r.status === 200 && r.body.tables.length === 2, "dogodek B: svoje T1 in T2 (isti imeni kot na dogodku A) -> 200", [r.status, r.besedilo]);
    assert(r.body.from_club_id === HOST && r.body.from_club_name === "Gostitelj Klub" && r.body.released_holds === 0, "rocno urejanje kopije: from_club_id ostane (zgodovina)", r.body);
    // Zavrnitev v transakciji (id druge mize dogodka) ne spremeni nicesar.
    const stanjeA = (await api("GET", `/business/events/${EA}/vip-layout`, T.orgown)).body;
    const idIzB = (await pool.query("SELECT id FROM club_tables WHERE event_id=$1 LIMIT 1", [EB])).rows[0].id;
    r = await api("PUT", `/business/events/${EA}/vip-layout`, T.orgown, { source: "event", floor_plan: PLAN_A, tables: [M("N", 2, 5), { ...M("T1", 6, 5), id: idIzB }] });
    assert(r.status === 400, "id mize drugega dogodka istega organizatorja -> 400", [r.status, r.besedilo]);
    { const po2 = (await api("GET", `/business/events/${EA}/vip-layout`, T.orgown)).body; delete stanjeA.released_holds; assert(enako(po2, stanjeA), "zavrnjen PUT (napaka sele v transakciji): razpored nespremenjen"); }
    // Prazen razpored: tloris brez miz.
    r = await api("PUT", `/business/events/${EC}/vip-layout`, T.orgown, { source: "event", floor_plan: PLAN_A, tables: [] });
    assert(r.status === 200 && r.body.source === "event" && r.body.tables.length === 0 && r.body.floor_plan.width === 24, "tloris brez miz je veljaven razpored", r.body);
    r = await api("PUT", `/business/events/${EC}/vip-layout`, T.orgown, { source: "event", floor_plan: null, tables: [] });
    assert(r.status === 200 && r.body.floor_plan === null, "floor_plan null + brez miz -> 200 (prazen razpored)", r.body);
    r = await api("PUT", `/business/events/${EC}/vip-layout`, T.orgown, { source: "club" });
    assert(r.status === 200 && r.body.source === "club", "EC nazaj na club");

    // ============================================================
    console.log("\n# 6. Izjeme po dogodku in klubski PUT");
    r = await api("PUT", `/business/events/${EA}/vip`, T.orgown, { enabled: true });
    assert(r.status === 200 && r.body.enabled === true, "VIP vklopljen na dogodku A", r.body);
    assert(enako(r.body.plan, { width: 24, height: 16, elements: [{ type: "dj", x: 9, y: 0, w: 6, h: 2, label: "DJ" }] }), "GET/PUT /business/events/:id/vip: plan = tloris DOGODKA", r.body.plan);
    assert(r.body.tables.length === 4 && r.body.tables.every(t => t.disabled === false && t.archived === false && t.default_price_cents === t.price_cents && t.booking === null && t.hold === null), "mize dogodka: default_price = price, ne izklopljene, brez rezervacij", r.body.tables);
    assert(r.body.packages.length === 1 && r.body.packages[0].id === PAKET, "paketi so organizatorjevi (ne gostiteljevi)", r.body.packages);
    const IDS_A = Object.fromEntries(r.body.tables.map(t => [t.label, t.id]));
    r = await api("PUT", `/business/events/${EA}/vip`, T.orgown, { enabled: true, tables: [
      { table_id: IDS_A.T3, price_cents: 40000, disabled: false }, { table_id: IDS_A.T5, disabled: true }] });
    const t3 = r.body.tables.find(t => t.label === "T3"), t5 = r.body.tables.find(t => t.label === "T5");
    assert(r.status === 200 && t3.price_cents === 40000 && t3.default_price_cents === 45000 && t3.disabled === false && t5.disabled === true, "izjeme (event_tables) VELJAJO za mize dogodka: cena T3 po dogodku, T5 izklopljena", [t3, t5]);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM event_tables WHERE event_id=$1", [EA])).rows[0].n === 2, "event_tables: 2 izjemi za mize dogodka");
    r = await api("GET", `/events/${EA}/vip`);
    assert(r.body.tables.length === 3 && !r.body.tables.some(t => t.id === IDS_A.T5) && r.body.tables.find(t => t.id === IDS_A.T3).price_cents === 40000, "javno: izklopljena T5 skrita, T3 s ceno po dogodku", r.body.tables);
    r = await nakup(EA, IDS_A.T5, T.cene, { package_id: PAKET });
    assert(r.status === 404, "nakup izklopljene mize dogodka -> 404", [r.status, r.besedilo]);
    r = await api("PUT", `/business/events/${EA}/vip`, T.orgown, { enabled: true, tables: [{ table_id: IDS_A.T3, price_cents: null, disabled: false }, { table_id: IDS_A.T5, price_cents: null, disabled: false }] });
    assert(r.status === 200 && (await pool.query("SELECT COUNT(*)::int AS n FROM event_tables WHERE event_id=$1", [EA])).rows[0].n === 0 && r.body.tables.find(t => t.label === "T3").price_cents === 45000, "izjeme pobrisane (cena null, disabled false)", r.body.tables);
    r = await api("PUT", `/business/events/${EA}/vip`, T.orgown, { enabled: true, tables: [{ table_id: HOST_MIZE[0], price_cents: 5, disabled: false }] });
    assert(r.status === 400, "izjema za mizo tujega kluba -> 400 (kot doslej)", [r.status, r.besedilo]);
    const idIzB2 = (await pool.query("SELECT id FROM club_tables WHERE event_id=$1 LIMIT 1", [EB])).rows[0].id;
    r = await api("PUT", `/business/events/${EA}/vip`, T.orgown, { enabled: true, tables: [{ table_id: idIzB2, price_cents: 5, disabled: false }] });
    assert(r.status === 404, "izjema za mizo DRUGEGA dogodka istega kluba -> 404", [r.status, r.besedilo]);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM event_tables WHERE table_id=$1", [idIzB2])).rows[0].n === 0, "zavrnjena izjema ni nicesar zapisala");
    r = await api("GET", `/business/events/${EA}/vip`, T.orgdoor);
    assert(r.status === 200 && r.body.tables.length === 4, "vratar vidi mize dogodka (rezervacije)", r.body.tables.length);
    r = await api("GET", `/business/events/${EA}/vip`, T.orgbar);
    assert(r.status === 403, "natakar GET /business/events/:id/vip -> 403 (I27 nespremenjen)", r.status);
    // Admin/lastnik: navaden klub z dvema dogodkoma lahko enega prestavi na event (preverjeno v 10.)

    // ============================================================
    console.log("\n# 7. Javni pogled in nakup mize dogodka");
    r = await api("GET", `/events/${EA}/vip`);
    assert(r.status === 200 && r.body.enabled === true && r.body.tables.length === 4, "javni GET /events/:id/vip: 4 mize dogodka", r.body);
    assert(enako(r.body.plan, { width: 24, height: 16, elements: [{ type: "dj", x: 9, y: 0, w: 6, h: 2, label: "DJ" }] }), "javni plan = tloris dogodka", r.body.plan);
    assert(Object.keys(r.body).sort().join() === "currency,enabled,event_id,on_sale,package_min_age,packages,plan,tables" && Object.keys(r.body.tables[0]).sort().join() === "available,h,id,label,price_cents,seats,shape,w,x,y",
      "oblika javnega odgovora nespremenjena (ista polja kot prej)", [Object.keys(r.body), Object.keys(r.body.tables[0])]);
    assert(r.body.tables.every(t => t.available === true), "vse mize proste", r.body.tables);
    assert(r.body.packages.length === 1 && r.body.packages[0].name === "Vodka 0,7 l", "javni paketi so organizatorjevi", r.body.packages);
    assert(!JSON.stringify(r.body).includes("Tuji paket gostitelja"), "paketi gostitelja se ne pokazejo");
    r = await api("GET", `/events/${EA}`);
    assert(r.body.vip_layout_source === "event" && r.body.vip_enabled === true, "GET /events/:id: vip_layout_source event, vip_enabled", [r.body.vip_layout_source, r.body.vip_enabled]);
    assert(r.body.vip_from_cents === 21000, "vip_from_cents = najnizja cena miz dogodka (T1 21000; T4 je odstranjena)", r.body.vip_from_cents);
    const lista = (await api("GET", "/events")).body.find(e => e.id === EA);
    assert(lista && lista.vip_from_cents === 21000 && lista.vip_enabled === true && lista.vip_layout_source === "event", "GET /events (seznam): ista polja", lista);

    r = await nakup(EA, IDS_A.T1, T.ana, {});
    assert(r.status === 400, "brez paketa (organizator ima paket) -> 400", [r.status, r.besedilo]);
    r = await nakup(EA, IDS_A.T1, T.ana, { package_id: PAKET_HOST });
    assert(r.status === 400, "paket gostitelja -> 400 (paketi so organizatorjevi)", [r.status, r.besedilo]);
    r = await nakup(EA, IDS_A.T1, T.ana, { package_id: PAKET, expected_price_cents: 1 });
    assert(r.status === 409, "napacna pricakovana cena -> 409", [r.status, r.besedilo]);
    r = await nakup(EA, IDS_A.T1, T.ana, { package_id: PAKET, expected_price_cents: 21000 });
    assert(r.status === 201 && r.body.tickets.length === 4, "nakup mize dogodka T1: 201, vstopnic = seats (4)", r.body);
    assert(r.body.order.table_label === "T1" && r.body.order.total_cents === 21000 && r.body.order.club_id === ORG, "narocilo: oznaka T1, cena mize dogodka, prodajalec = organizator", r.body.order);
    assert(r.body.tickets.every(t => t.is_vip === true && t.qr), "vstopnice so VIP z QR kodo", r.body.tickets[0]);
    const O_ANA = r.body.order.id;
    const ord = (await pool.query("SELECT table_id, club_id, event_id FROM orders WHERE id=$1", [O_ANA])).rows[0];
    assert(ord.table_id === IDS_A.T1 && ord.club_id === ORG && ord.event_id === EA, "orders.table_id = miza dogodka", ord);
    assert((await pool.query("SELECT sold_count FROM events WHERE id=$1", [EA])).rows[0].sold_count === 0, "mize ne stejejo v sold_count");
    r = await nakup(EA, IDS_A.T1, T.bor, { package_id: PAKET });
    assert(r.status === 409 && /already booked/.test(r.besedilo), "I13: druga prodaja iste mize dogodka -> 409", [r.status, r.besedilo]);
    r = await api("GET", `/events/${EA}/vip`);
    assert(r.body.tables.find(t => t.id === IDS_A.T1).available === false && r.body.tables.filter(t => t.available).length === 3, "javno: T1 zasedena, ostale proste", r.body.tables);
    assert(!JSON.stringify(r.body).includes("ana"), "javni odgovor ne razkrije kupca");
    r = await api("GET", `/business/events/${EA}/vip`, T.orgown);
    const bk = r.body.tables.find(t => t.id === IDS_A.T1).booking;
    assert(bk && bk.order_id === O_ANA && bk.buyer_username === "ana" && bk.guests === 4 && bk.checked_in === 0, "poslovni pogled: rezervacija kupca na mizi dogodka", bk);
    // 6 vzporednih nakupov iste mize: natanko 1
    const hk = await Promise.all([T.bor, T.cene, T.kupec4, T.bor, T.cene, T.kupec4].map(t => nakup(EA, IDS_A.T3, t, { package_id: PAKET })));
    assert(hk.filter(x => x.status === 201).length === 1 && hk.filter(x => x.status === 409).length === 5, "I13: natanko 1 od 6 vzporednih nakupov T3 uspe, 5 dobi 409", hk.map(x => x.status));
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1 AND table_id=$2 AND status IN ('pending','paid','partially_refunded')", [EA, IDS_A.T3])).rows[0].n === 1, "v bazi natanko 1 aktivno narocilo za T3");
    const dvojno = await sqlKoda(`INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, paid_at, table_id, table_label, table_seats)
      VALUES ('DUP1', 1, $1, $2, 1, 1, 1, 'paid', 'x@outly.si', NOW(), $3, 'T1', 4)`, [EA, ORG, IDS_A.T1]);
    assert(dvojno === "23505", "baza sama zavrne dvojno narocilo mize dogodka (unikaten indeks orders_miza_dogodek_key)", dvojno);

    // ============================================================
    console.log("\n# 8. Miza drugega dogodka / klubska miza: 404; rezervacija po telefonu");
    const MIZE_B = (await api("GET", `/business/events/${EB}/vip-layout`, T.orgown)).body.tables;
    await api("PUT", `/business/events/${EB}/vip`, T.orgown, { enabled: true });
    r = await nakup(EA, MIZE_B[0].id, T.cene, { package_id: PAKET });
    assert(r.status === 404, "nakup mize DRUGEGA dogodka (B) na dogodku A -> 404", [r.status, r.besedilo]);
    r = await nakup(EA, HOST_MIZE[0], T.cene, { package_id: PAKET });
    assert(r.status === 404, "nakup klubske mize gostitelja na dogodku z razporedom dogodka -> 404", [r.status, r.besedilo]);
    r = await nakup(EA, klubskaH1 || 1, T.cene, { package_id: PAKET });
    assert(r.status === 404, "nakup klubske mize (event_id NULL) na dogodku z razporedom dogodka -> 404", [r.status, r.besedilo]);
    r = await nakup(EG, MIZE_B[0].id, T.cene, { package_id: PAKET });
    assert(r.status === 404, "mize tujega dogodka -> 404", [r.status, r.besedilo]);
    // dogodek, ki ima razpored 'club': miza dogodka B zanj ne obstaja
    r = await nakup(EC, MIZE_B[0].id, T.cene, { package_id: PAKET });
    assert(r.status === 404, "dogodek z virom club: miza dogodka B -> 404", [r.status, r.besedilo]);
    // rezervacija po telefonu
    r = await api("POST", `/business/events/${EA}/tables/${IDS_A.T2}/hold`, T.orgown, { guest_name: "Janez Telefonski", note: "ob 23h" });
    assert(r.status === 201 && r.body.tables.find(t => t.id === IDS_A.T2).hold.guest_name === "Janez Telefonski", "rezervacija po telefonu na mizi dogodka -> 201", r.body.tables);
    r = await api("GET", `/events/${EA}/vip`);
    assert(r.body.tables.find(t => t.id === IDS_A.T2).available === false && !JSON.stringify(r.body).includes("Janez"), "javno: rezervirana miza zasedena, ime gosta se ne pokaze");
    r = await nakup(EA, IDS_A.T2, T.cene, { package_id: PAKET });
    assert(r.status === 409, "nakup rezervirane mize dogodka -> 409", [r.status, r.besedilo]);
    r = await api("POST", `/business/events/${EA}/tables/${IDS_A.T1}/hold`, T.orgown, { guest_name: "X" });
    assert(r.status === 409, "rezervacija kupljene mize -> 409", [r.status, r.besedilo]);
    r = await api("POST", `/business/events/${EA}/tables/${MIZE_B[0].id}/hold`, T.orgown, { guest_name: "X" });
    assert(r.status === 404, "rezervacija mize DRUGEGA dogodka -> 404", [r.status, r.besedilo]);
    r = await api("POST", `/business/events/${EA}/tables/${HOST_MIZE[0]}/hold`, T.orgown, { guest_name: "X" });
    assert(r.status === 404, "rezervacija mize gostitelja (tuj klub) -> 404", [r.status, r.besedilo]);
    r = await api("POST", `/business/events/${EA}/tables/${klubskaH1}/hold`, T.orgown, { guest_name: "X" });
    assert(r.status === 404, "rezervacija klubske mize pri razporedu dogodka -> 404", [r.status, r.besedilo]);
    r = await api("POST", `/business/events/${EB}/tables/${MIZE_B[0].id}/hold`, T.orgown, { guest_name: "Gost B" });
    assert(r.status === 201, "rezervacija mize na DOGODKU B (pravi dogodek) -> 201", [r.status, r.besedilo]);
    r = await api("DELETE", `/business/events/${EB}/tables/${MIZE_B[0].id}/hold`, T.orgown);
    assert(r.status === 200, "preklic rezervacije na B -> 200", r.status);
    // Rezervacija mize, ki jo organizator odstrani iz razporeda, se izbrise (released_holds)
    r = await api("POST", `/business/events/${EB}/tables/${MIZE_B[1].id}/hold`, T.orgown, { guest_name: "Gost B2" });
    assert(r.status === 201, "rezervacija druge mize na B", [r.status, r.besedilo]);
    r = await api("PUT", `/business/events/${EB}/vip-layout`, T.orgown, { source: "event", floor_plan: PLAN_A, tables: [{ ...M("T1", 2, 5), id: MIZE_B[0].id }] });
    assert(r.status === 200 && r.body.tables.length === 1 && r.body.released_holds === 1, "odstranitev rezervirane mize iz razporeda: released_holds = 1", r.body);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM table_holds WHERE event_id=$1", [EB])).rows[0].n === 0, "rezervacija odstranjene mize je izbrisana, miza pobrisana (brez narocil)");
    r = await api("PUT", `/business/events/${EB}/vip-layout`, T.orgown, { source: "event", floor_plan: PLAN_A, tables: [{ ...M("T1", 2, 5), id: MIZE_B[0].id }, M("T2", 6, 5)] });
    assert(r.status === 200 && r.body.tables.length === 2 && r.body.released_holds === 0, "B nazaj na 2 mizi (nova T2)", r.body);

    // ============================================================
    console.log("\n# 9. Preklop nazaj na club: miza z narocilom se arhivira");
    // A: T1 kupljena (ana), T3 kupljena (zmagovalec vzporednega nakupa), T2 rezervirana, T5 prosta
    const O_T3 = hk.find(x => x.status === 201).body.order.id;
    r = await api("PUT", `/business/events/${EA}/vip-layout`, T.orgown, { source: "club" });
    assert(r.status === 200 && r.body.source === "club" && r.body.floor_plan === null && r.body.released_holds === 1, "PUT source club -> 200, brez tlorisa, released_holds = 1 (rezervacija T2)", r.body);
    assert(r.body.tables.length === 2 && r.body.tables.every(t => t.archived === true) && r.body.tables.some(t => t.id === IDS_A.T1) && r.body.tables.some(t => t.id === IDS_A.T3), "odgovor vsebuje arhivirani mizi z narocilom (archived: true)", r.body.tables);
    const ostanek = (await pool.query("SELECT id, label, archived_at FROM club_tables WHERE event_id=$1 ORDER BY id", [EA])).rows;
    assert(ostanek.length === 2 && ostanek.every(t => t.archived_at !== null), "ostaneta SAMO mizi z narocilom (T1, T3), obe arhivirani", ostanek);
    assert(["T1", "T3"].every(l => ostanek.some(t => t.label === l)) && !ostanek.some(t => t.label === "T5" || t.label === "T2"), "T5 (prosta) in T2 (samo rezervacija) pobrisani", ostanek);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM table_holds WHERE event_id=$1", [EA])).rows[0].n === 0, "rezervacije miz dogodka izbrisane");
    r = await api("GET", `/business/events/${EA}/vip-layout`, T.orgown);
    assert(r.status === 200 && r.body.source === "club" && r.body.tables.length === 2 && r.body.tables.every(t => t.archived === true) && !("released_holds" in r.body), "GET vip-layout po preklopu: arhivirani mizi z archived: true, brez released_holds", r.body);
    const dogA = (await pool.query("SELECT vip_layout_source, floor_plan, vip_layout_from_club_id FROM events WHERE id=$1", [EA])).rows[0];
    assert(dogA.vip_layout_source === "club" && dogA.floor_plan === null && dogA.vip_layout_from_club_id === null, "events: source club, floor_plan NULL", dogA);
    assert((await pool.query("SELECT status FROM orders WHERE id=ANY($1::int[])", [[O_ANA, O_T3]])).rows.every(o => o.status === "paid"), "narocili ostaneta placani");
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM tickets WHERE order_id=$1 AND status='valid'", [O_ANA])).rows[0].n === 4, "vstopnice ane so se vedno veljavne");
    r = await api("GET", `/events/${EA}/vip`);
    assert(r.status === 200 && r.body.enabled === false && r.body.tables.length === 0 && r.body.plan === null, "javno po preklopu: organizator nima klubskega razporeda -> enabled false", r.body);
    r = await api("GET", `/events/${EA}`);
    assert(r.body.vip_layout_source === "club" && r.body.vip_enabled === false && r.body.vip_from_cents === null, "GET /events/:id: vip_layout_source club, brez vip_from_cents", [r.body.vip_layout_source, r.body.vip_enabled, r.body.vip_from_cents]);
    r = await api("GET", `/business/events/${EA}/vip`, T.orgown);
    const arhT1 = r.body.tables.find(t => t.id === IDS_A.T1);
    assert(arhT1 && arhT1.archived === true && arhT1.booking && arhT1.booking.order_id === O_ANA, "poslovni pogled: arhivirana miza z narocilom je se vedno vidna (booking)", r.body.tables);
    assert(r.body.tables.length === 2 && r.body.tables.every(t => t.hold === null && t.booking), "samo mizi z narocilom (T1, T3), rezervacij ni vec", r.body.tables.map(t => [t.label, t.archived]));
    r = await nakup(EA, IDS_A.T5 || 0, T.cene, { package_id: PAKET });
    assert(r.status === 400 || r.status === 404, "nakup pobrisane mize -> 4xx", r.status);
    r = await nakup(EA, IDS_A.T2, T.cene, { package_id: PAKET });
    assert(r.status === 404, "nakup arhivirane mize -> 404", [r.status, r.besedilo]);
    // Sken VIP vstopnice mize dogodka po preklopu: dela, strezba nastane.
    const moje = (await api("GET", "/me/tickets", T.ana)).body.filter(t => t.event_id === EA);
    assert(moje.length === 4 && moje.every(t => t.is_vip && t.table_label === "T1" && t.qr), "ana: 4 VIP vstopnice T1 z QR (posnetek oznake v narocilu)", moje.map(t => [t.is_vip, t.table_label]));
    r = await api("POST", "/business/tickets/scan", T.orgdoor, { qr: moje[0].qr });
    assert(r.status === 200 && r.body.result === "ok" && r.body.ticket.is_vip === true, "vratar organizatorja skenira VIP vstopnico mize dogodka (po preklopu) -> ok", r.body);
    assert(r.body.table_service_created === true, "strezba nastane (table_service_created)", r.body.table_service_created);
    const ts = (await pool.query("SELECT table_label, table_seats, package_name FROM table_service WHERE order_id=$1", [O_ANA])).rows;
    assert(ts.length === 1 && ts[0].table_label === "T1" && ts[0].table_seats === 4 && ts[0].package_name === "Vodka 0,7 l", "table_service: T1 / 4 / paket", ts);
    r = await api("GET", `/business/events/${EA}/table-service`, T.orgbar);
    assert(r.status === 200 && r.body.items.length === 1 && r.body.items[0].table_label === "T1", "natakar organizatorja vidi strezbo mize dogodka", r.body);
    // Ponovni preklop na event: nov razpored, stara arhivirana miza se ne zaplete
    r = await api("PUT", `/business/events/${EA}/vip-layout`, T.orgown, { source: "event", floor_plan: PLAN_A, tables: [M("T1", 2, 5), M("T2", 6, 5)] });
    assert(r.status === 200 && r.body.tables.filter(t => !t.archived).length === 2 && r.body.tables.filter(t => t.archived).length === 2, "ponovni preklop na event z isto oznako T1 kot arhivirana miza -> 200 (arhivirane niso v unikatnem indeksu)", [r.status, r.besedilo]);
    r = await api("GET", `/events/${EA}/vip`);
    assert(r.body.enabled === true && r.body.tables.length === 4 && r.body.tables.filter(t => t.available).length === 2 && r.body.tables.filter(t => !t.available).map(t => t.id).sort().join() === [IDS_A.T1, IDS_A.T3].sort().join(), "javno: 2 novi mizi prosti + prodani stari ostaneta Booked", r.body.tables);
    r = await api("GET", `/business/events/${EA}/vip`, T.orgown);
    assert(r.body.tables.length === 4 && r.body.tables.filter(t => t.booking).length === 2 && r.body.tables.filter(t => t.hold).length === 0, "poslovni pogled: 2 novi + 2 stari z narocilom", r.body.tables.map(t => [t.id, t.label, t.archived]));

    // ============================================================
    console.log("\n# 10. Navaden klub: regresija + razpored dogodka dovoljen");
    r = await api("GET", `/events/${EK}/vip`);
    assert(r.status === 200 && r.body.enabled === false && r.body.tables.length === 0, "navaden klub, VIP izklopljen: enabled false", r.body);
    r = await api("PUT", `/business/events/${EK}/vip`, T.klubown, { enabled: true, tables: [{ table_id: KLUB_MIZE[1], price_cents: 22222, disabled: false }] });
    assert(r.status === 200 && r.body.enabled === true && r.body.tables.length === 2, "klub: vklop VIP + izjema (cena T2 po dogodku)", r.body);
    assert(enako(r.body.plan, PLAN_K) && r.body.tables.find(t => t.id === KLUB_MIZE[1]).price_cents === 22222 && r.body.tables.find(t => t.id === KLUB_MIZE[1]).default_price_cents === 25000, "plan = klubski tloris; izjema za klubsko mizo dela", r.body.tables);
    r = await api("GET", `/events/${EK}/vip`);
    assert(r.status === 200 && r.body.enabled === true && r.body.tables.length === 2 && enako(r.body.plan, PLAN_K), "javni GET /events/:id/vip: klubske mize in tloris nespremenjeni", r.body);
    assert(Object.keys(r.body).sort().join() === "currency,enabled,event_id,on_sale,package_min_age,packages,plan,tables" && r.body.packages[0].id === KLUB_PAKET, "oblika odgovora enaka, paket kluba", Object.keys(r.body));
    assert(r.body.tables.find(t => t.id === KLUB_MIZE[1]).price_cents === 22222, "cena po dogodku se uporabi", r.body.tables);
    r = await api("GET", `/events/${EK}`);
    assert(r.body.vip_layout_source === "club" && r.body.vip_from_cents === 15000 && r.body.vip_enabled === true, "vip_from_cents navadnega kluba nespremenjen (15000)", [r.body.vip_layout_source, r.body.vip_from_cents]);
    r = await nakup(EK, KLUB_MIZE[1], T.ana, { package_id: KLUB_PAKET });
    assert(r.status === 201 && r.body.tickets.length === 6 && r.body.order.total_cents === 22222, "nakup klubske mize (cena po dogodku): 201, 6 vstopnic", r.body);
    r = await nakup(EK, KLUB_MIZE[1], T.bor, { package_id: KLUB_PAKET });
    assert(r.status === 409, "klubska miza: druga prodaja -> 409 (I13)", r.status);
    r = await nakup(EK, MIZE_B[0].id, T.cene, { package_id: KLUB_PAKET });
    assert(r.status === 404, "klubski dogodek: miza dogodka organizatorja -> 404", [r.status, r.besedilo]);
    r = await api("POST", `/business/events/${EK}/tables/${KLUB_MIZE[0]}/hold`, T.klubown, { guest_name: "Gost" });
    assert(r.status === 201, "klubska rezervacija po telefonu dela nespremenjeno", [r.status, r.besedilo]);
    // Navaden klub sme za posamezen dogodek izbrati razpored dogodka (odlocitev 5)
    const KLUBSKI_PLAN2 = { width: 16, height: 10, elements: [] };
    r = await api("PUT", `/business/events/${EK2}/vip-layout`, T.klubown, { source: "event", floor_plan: KLUBSKI_PLAN2, tables: [M("T1", 1, 1, { seats: 3, price_cents: 7000 })] });
    assert(r.status === 200 && r.body.source === "event" && r.body.tables.length === 1, "navaden klub: razpored dogodka -> 200", r.body);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM club_tables WHERE club_id=$1 AND event_id IS NULL AND archived_at IS NULL", [KLUB])).rows[0].n === 2, "klubske mize (T1, T2) ostanejo nedotaknjene; T1 dogodka je loceno");
    r = await api("GET", "/business/vip", T.klubown);
    assert(r.body.tables.length === 2 && enako(r.body.plan, PLAN_K), "GET /business/vip: klubski tloris nespremenjen", r.body);
    r = await api("PUT", "/business/vip", T.klubown, { plan: PLAN_K, tables: [{ id: KLUB_MIZE[0], label: "T1", x: 1, y: 1, w: 2, h: 2, shape: "round", seats: 4, price_cents: 15000 }], packages: [{ id: KLUB_PAKET, name: "Klubski paket", description: "x" }] });
    assert(r.status === 200 && r.body.tables.length === 1, "klubski PUT /business/vip (odstrani T2)", r.body);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM club_tables WHERE event_id=$1 AND archived_at IS NULL", [EK2])).rows[0].n === 1, "klubski PUT ne arhivira mize dogodka EK2");
    r = await api("GET", `/events/${EK}/vip`);
    assert(r.status === 200 && r.body.tables.some(t => t.id === KLUB_MIZE[1] && t.available === false), "prodana in arhivirana klubska miza je javno se vedno Booked (obstojece vedenje)", r.body.tables);
    r = await api("PUT", `/business/events/${EK2}/vip-layout`, T.klubown, { source: "club" });
    assert(r.status === 200 && r.body.source === "club", "klub: nazaj na club");
    // Kdor ni lastnik dogodka ne more spreminjati
    r = await api("PUT", `/business/events/${EK2}/vip-layout`, T.orgown, { source: "event", floor_plan: P1, tables: [] });
    assert(r.status === 404, "drug klub (organizator) -> 404 na tujem dogodku", r.status);
    r = await api("PUT", `/business/events/${EK2}/vip-layout`, T.klubown, { source: "event", copy_from_venue: true });
    assert(r.status === 400, "navaden klub brez gostitelja + copy_from_venue -> 400", [r.status, r.besedilo]);

    // ============================================================
    console.log("\n# 11. Baza");
    const E_DB = await dogodek(ORG, "Za brisanje", { gostitelj: HOST, zacetek: "NOW() + INTERVAL '5 days'" });
    r = await api("PUT", `/business/events/${E_DB}/vip-layout`, T.orgown, { source: "event", floor_plan: P1, tables: [M("X1", 2, 5), M("X2", 6, 5)] });
    assert(r.status === 200 && r.body.tables.length === 2, "dogodek za brisanje: 2 mizi dogodka", r.body);
    let k = await sqlKoda(`INSERT INTO club_tables (club_id, event_id, label, x, y, w, h, seats, price_cents) VALUES ($1,$2,'x1',0,0,1,1,2,1)`, [ORG, E_DB]);
    assert(k === "23505", "baza: dve mizi z isto oznako (brez razlike velikih/malih) na istem dogodku -> 23505 (club_tables_event_label_key)", k);
    k = await sqlKoda(`INSERT INTO club_tables (club_id, event_id, label, x, y, w, h, seats, price_cents) VALUES ($1,$2,'X1',0,0,1,1,2,1)`, [ORG, EA]);
    assert(k === null, "baza: ista oznaka na DRUGEM dogodku je v redu", k);
    k = await sqlKoda(`INSERT INTO club_tables (club_id, label, x, y, w, h, seats, price_cents) VALUES ($1,'DVA',0,0,1,1,2,1), ($1,'dva',0,0,1,1,2,1)`, [KLUB]);
    assert(k === "23505", "baza: klubske mize z isto oznako se vedno trcijo (club_tables_label_key)", k);
    k = await sqlKoda(`UPDATE events SET vip_layout_source='nekaj' WHERE id=$1`, [EA]);
    assert(k === "23514", "baza: vip_layout_source samo club | event (CHECK)", k);
    k = await sqlKoda(`UPDATE events SET floor_plan='[1,2]'::jsonb WHERE id=$1`, [EA]);
    assert(k === "23514", "baza: events.floor_plan mora biti objekt (CHECK)", k);
    k = await sqlKoda(`UPDATE events SET vip_layout_from_club_id=999999 WHERE id=$1`, [EA]);
    assert(k === "23503", "baza: vip_layout_from_club_id je tuji kljuc na clubs", k);
    k = await sqlKoda(`INSERT INTO club_tables (club_id, event_id, label, x, y, w, h, seats, price_cents) VALUES ($1,999999,'Q',0,0,1,1,2,1)`, [ORG]);
    assert(k === "23503", "baza: event_id je tuji kljuc na events", k);
    const slabe = (await pool.query("SELECT ct.id FROM club_tables ct JOIN events e ON e.id = ct.event_id WHERE ct.club_id <> e.club_id")).rows;
    assert(slabe.length === 0, "vse mize dogodka imajo club_id = events.club_id", slabe);
    await pool.query("DELETE FROM club_tables WHERE event_id=$1 AND label='X1' AND club_id=$2 AND event_id=$3", [EA, ORG, EA]);
    r = await api("DELETE", `/events/${E_DB}`, T.orgown);
    assert(r.status === 200, "izbris dogodka brez narocil -> 200", [r.status, r.besedilo]);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM club_tables WHERE event_id=$1", [E_DB])).rows[0].n === 0, "izbris dogodka pobrise njegove mize (ON DELETE CASCADE)");
    k = await sqlKoda(`DELETE FROM events WHERE id=$1`, [EA]);
    assert(k === "23503", "dogodek z narocili se ne da izbrisati (orders.event_id RESTRICT)", k);
    const dup = (await pool.query("SELECT table_id, event_id, COUNT(*)::int AS n FROM orders WHERE table_id IS NOT NULL AND status IN ('pending','paid','partially_refunded') GROUP BY 1, 2 HAVING COUNT(*) > 1")).rows;
    assert(dup.length === 0, "nobena miza ni prodana dvakrat na istem dogodku (I13)", dup);

    console.log("\n# 12. Tek: nakup mize proti odstranitvi mize iz razporeda (8 krogov)");
    let napacni = 0, pricakovano = 0, prodanih = 0;
    for (let i = 0; i < 8; i++) {
      const ET = await dogodek(ORG, "Tek " + i, { gostitelj: HOST, zacetek: "NOW() + INTERVAL '4 days'" });
      let x = await api("PUT", `/business/events/${ET}/vip-layout`, T.orgown, { source: "event", floor_plan: P1, tables: [M("R1", 2, 5)] });
      const mid = x.body.tables[0].id;
      await api("PUT", `/business/events/${ET}/vip`, T.orgown, { enabled: true });
      const [a1, a2] = await Promise.all([nakup(ET, mid, T.cene, { package_id: PAKET }), api("PUT", `/business/events/${ET}/vip-layout`, T.orgown, { source: "club" })]);
      const vrstica = (await pool.query("SELECT archived_at FROM club_tables WHERE id=$1", [mid])).rows[0];
      const narocil = (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE table_id=$1", [mid])).rows[0].n;
      if (a2.status !== 200 || ![201, 404].includes(a1.status)) napacni++;
      // 201: narocilo obstaja, miza je ostala (arhivirana); 404: nakupa ni, miza je pobrisana
      if ((a1.status === 201 && narocil === 1 && vrstica && vrstica.archived_at) || (a1.status === 404 && narocil === 0 && !vrstica)) pricakovano++;
      if (a1.status === 201) prodanih++;
    }
    assert(napacni === 0, "nobeden krog ni dal 500 / nepricakovanega statusa (PUT vedno 200, nakup 201 ali 404)", napacni);
    assert(pricakovano === 8, "v vseh krogih je stanje skladno: narocilo => miza arhivirana, brez narocila => miza pobrisana", [pricakovano, prodanih]);

    const nepricakovano = log.split("\n").filter(v => /TypeError|ReferenceError|SyntaxError|unhandled|Cannot read/i.test(v));
    assert(nepricakovano.length === 0, "dnevnik strezbe: brez programskih napak", nepricakovano.slice(0, 3));
  } catch (e) {
    fail++; console.log("  ✗ IZJEMA:", e && e.stack || e);
  } finally {
    srv.kill(); jwksServer.close(); await pool.end().catch(() => {});
    console.log(`\n${fail === 0 ? "VSE OK" : "NAPAKE"}: ${ok} uspesnih, ${fail} neuspesnih`);
    if (fail > 0) console.log(log.split("\n").slice(-15).join("\n"));
    process.exit(fail === 0 ? 0 : 1);
  }
})();
