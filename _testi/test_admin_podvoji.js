#!/usr/bin/env node
/**
 * Podvajanje dogodka (POST /admin/api/events/:id/duplicate) in pregled enega dogodka pred objavo (GET /admin/api/opozorila?dogodek=ID) (#328, »PR 5« nacrta admin panela 23. 10. 2026).
 * Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_admin_podvoji.js
 * Vzorec kot test_admin_opozorila.js: lokalni JWKS (6142), backend na svojem portu (6141), brez predpomnilnika opozoril. Backend tece v »zivem« nacinu placil
 * (lokalni kljuci, noben zunanji klic), da pogoja podatkov prodajalca in kluba brez placil delujeta.
 *
 *  P1  en osnutek: status draft, isti klub, kopirana polja (naslov, opis, plakat, starost, zanri, cena, valuta, kapaciteta, DDV, prizorisce z gostiteljskim klubom in koordinatami),
 *      sold_count 0, sales_paused false, vip_enabled false, recap '', trajanje ohranjeno, okno prodaje ohrani zamik od zacetka; mize dogodka (club_tables.event_id) NISO kopirane (I28)
 *  P2  tedenska vrsta n = 4 (zacetek vrste tik pred prehodom na zimski/poletni cas): vse osnutki, 7 koledarskih dni narazen, ura po ljubljansko ista, trajanje 6 h in zamik okna
 *      prodaje (po ljubljansko) ohranjena tudi cez prehod; brez konca / brez okna: null ostane null
 *  P3  neveljavno: n = 13, 0, 1.5, "3", ponovi razen weekly, n brez ponovi, start v preteklosti, brez obmocja, nemogoc datum, brez starta, neobstojec dogodek (404), neveljaven id -> 400, NIC ustvarjeno
 *  P4  vloge: user, business, backup 403; brez zetona 401; nic ustvarjeno
 *  P5  transakcija vse-ali-nic: sprozilec zavrne tretji vpis v dnevnik -> 500 in NOBEN osnutek (ne prva dva) ni ostal
 *  P6  dnevnik: natanko ena vrstica `event.duplicate` na osnutek (cilj_tip event, cilj_id = nov id, prej null, potem { iz, start_at }), admin kot avtor, brez e-naslovov; vidna v GET /admin/api/events/:id
 *  P7  brez zaklepanja: dokler druga seja drzi FOR UPDATE na izvoru, podvajanje uspe takoj; izvor se ne spremeni (sold_count, status, vip_enabled, mize)
 *  P8  admin ustvari osnutek v tujem klubu prek POST /events (clubId): 201 draft (korak 1 panela »Nov dogodek«); organizator brez prizorisca 400
 *  P10 POST /admin/api/events (korak 1 panela): admin, ki je SAM lastnik kluba A, ustvari osnutek za klub B -> 201 (POST /events bi mu odpovedal); status v telesu ne povozi drafta;
 *      ista validacija kot POST /events (neveljaven URL, neznan klub, organizator brez prizorisca); vrstica admin_dejanja event.create; ne-admin 403, brez zetona 401
 *  P11 kopija ne prenese neveljavnih URL-jev (javascript:, ftp: -> '') in zanrov izven ZANRI; veljavni ostanejo; startAt najvec 2 leti vnaprej (start_too_far); kršitev omejitve baze -> 400 duplicate_invalid in nic ustvarjeno
 *  P9  GET /admin/api/opozorila?dogodek=ID (samo opozorila tega dogodka, splosni razdelki racuni/vracila/spori/potrdila preskoceni): osnutek z nepopolnimi podatki prodajalca / klubom brez placil -> rdece; brezhiben osnutek brez opozoril; samo opozorila tega dogodka;
 *      globalni seznam osnutka se vedno NE steje (stara pogodba); neveljaven id 400; neobstojec 200 prazno; skrit klub vseeno; ne-admin 403, brez zetona 401
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool, Client } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 6141, JWKS_PORT = 6142;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-podvoji";
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
const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
async function api(method, path, token, telo) {
  const r = await fetch(BASE + path, { method, headers: { ...(token ? { authorization: "Bearer " + token } : {}), ...(telo !== undefined ? { "content-type": "application/json" } : {}) },
    body: telo === undefined ? undefined : JSON.stringify(telo) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, text: t };
}

// Ljubljanski odmik od UTC v minutah za trenutek (Intl, ni odvisen od casovnega pasu stroja).
function odmikLj(ms) {
  const s = new Intl.DateTimeFormat("en-US", { timeZone: "Europe/Ljubljana", timeZoneName: "longOffset" }).formatToParts(new Date(ms)).find((p) => p.type === "timeZoneName").value;
  const m = /GMT([+-])(\d{2}):(\d{2})/.exec(s);
  return m ? (m[1] === "-" ? -1 : 1) * (Number(m[2]) * 60 + Number(m[3])) : 0;
}
// Prvi dan (od +2 dni naprej), pri katerem se odmik v naslednjih 21 dneh spremeni: vrsta 4 tednov cez prehod poletnega casa.
function zacetekCezPrehod() {
  const dan = 864e5;
  const t0 = Math.floor((Date.now() + 2 * dan) / dan) * dan + 20 * 3600e3;   // 20:00 UTC
  for (let i = 0; i < 400; i++) {
    const t = t0 + i * dan;
    if (odmikLj(t) !== odmikLj(t + 21 * dan)) return new Date(t).toISOString();
  }
  throw new Error("prehoda poletnega casa ni v naslednjih 400 dneh");
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE admin_dejanja, omejitve, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, club_tables, events, clubs, creator_applications, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test",
    STRIPE_SECRET_KEY: "sk_live_lokalno", STRIPE_WEBHOOK_SECRET: "whsec_lokalno", STRIPE_API_BASE: "http://127.0.0.1:1", TEST_PLACILA: "", ADMIN_NADZOR_PREDPOMNILNIK_MS: "0" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }
  const lock = new Client({ connectionString: DB });

  try {
    const T = {
      admin: zeton("admin@outly.si", uuid(1)),
      navaden: zeton("navaden@outly.si", uuid(2)),
      lastnik: zeton("lastnik@outly.si", uuid(3)),
      kopija: zeton("kopija@outly.si", uuid(4)),
    };
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    await pool.query("UPDATE users SET role='backup' WHERE email='kopija@outly.si'");
    const adminId = (await pool.query("SELECT id FROM users WHERE email='admin@outly.si'")).rows[0].id;
    await lock.connect();

    // --- klubi ---
    let st = 100;
    const klub = async (ime, polja = {}) => {
      const moj = st++;
      const u = (await pool.query("INSERT INTO users (email, username, role) VALUES ($1, $2, 'business') RETURNING id", [`lastnik${moj}@primer.si`, `lastnik${moj}`])).rows[0].id;
      const k = { stripe: true, popoln: true, hidden: false, demo: false, organizer: false, ...polja };
      return (await pool.query(
        `INSERT INTO clubs (owner_user_id, name, hidden, is_demo, is_organizer, stripe_account_id, stripe_charges_enabled, stripe_payouts_enabled, stripe_account_livemode,
                            legal_name, legal_address, registration_number, tax_number, vat_payer, contact_email)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8, $9, $10, $11, $12, $13, $14) RETURNING id`,
        [u, ime, k.hidden, k.demo, k.organizer, k.stripe ? "acct_skrivni" + moj : null, k.stripe, k.stripe ? true : null,
         k.popoln ? "Klub d.o.o." : "", k.popoln ? "Ulica 1, 1000 Ljubljana" : "", k.popoln ? "1234567" : "", k.popoln ? "SI12345678" : "", k.popoln ? true : null,
         k.popoln ? "info@klub.si" : ""])).rows[0].id;
    };
    const K_A = await klub("Klub A");
    const K_B = await klub("Klub B");
    const K_GOST = await klub("Klub Gostitelj");
    const K_NEPOPOLN = await klub("Klub Nepopoln", { popoln: false });
    const K_BREZ_STRIPA = await klub("Klub Brez Stripa", { stripe: false });
    const K_SKRIT = await klub("Klub Skrit", { hidden: true, popoln: false, stripe: false });
    const K_ORG = await klub("Organizator", { organizer: true, stripe: false, popoln: false });

    const dogodek = async (klubId, naslov, polja = {}) => {
      const e = { status: "draft", start: "10 days", end: "10 days 6 hours", poster: "https://slike.test/p.jpg", price: 1500, capacity: 100, url: "", ...polja };
      return (await pool.query(
        `INSERT INTO events (club_id, title, status, start_at, end_at, poster_url, ticket_price_cents, capacity, ticket_url)
         VALUES ($1, $2, $3, NOW() + $4::interval, CASE WHEN $5::text IS NULL THEN NULL ELSE NOW() + $5::interval END, $6, $7, $8, $9) RETURNING id`,
        [klubId, naslov, e.status, e.start, e.end, e.poster, e.price, e.capacity, e.url])).rows[0].id;
    };
    const dogodkov = async () => Number((await pool.query("SELECT COUNT(*) FROM events")).rows[0].count);
    const duplikat = (id, telo, zeton_ = T.admin) => api("POST", `/admin/api/events/${id}/duplicate`, zeton_, telo);
    const lokalnoUra = (iso) => pool.query("SELECT to_char($1::timestamptz AT TIME ZONE 'Europe/Ljubljana', 'YYYY-MM-DD HH24:MI') AS t", [iso]).then((r) => r.rows[0].t);

    // --- izvorni dogodek z vsemi polji ---
    const S = await dogodek(K_A, "Izvorni dogodek »z vsem«", { status: "published", start: "10 days", end: "10 days 6 hours" });
    await pool.query(
      `UPDATE events SET description = 'Opis dogodka', min_age = 21, genres = ARRAY['house','techno']::text[], currency = 'EUR', ticket_url = '', vat_rate = 0.220,
              sold_count = 5, vip_enabled = true, sales_paused = true, recap_video_url = 'https://video.test/r.mp4',
              sales_open_at = start_at - INTERVAL '7 days', sales_close_at = start_at - INTERVAL '1 hour',
              venue_club_id = $2, venue_name = '', venue_address = 'Cesta 5', venue_city = 'Ljubljana', venue_lat = 46.05, venue_lng = 14.5,
              vip_layout_source = 'event', floor_plan = '{"w":10}'::jsonb
        WHERE id = $1`, [S, K_GOST]);
    await pool.query("INSERT INTO club_tables (club_id, label, x, y, w, h, seats, price_cents, event_id) VALUES ($1, 'T1', 1, 1, 2, 2, 4, 20000, $2), ($1, 'T2', 5, 1, 2, 2, 4, 20000, $2)", [K_A, S]);
    const mizeSkupaj = async () => Number((await pool.query("SELECT COUNT(*) FROM club_tables")).rows[0].count);
    const izvor0 = (await pool.query("SELECT * FROM events WHERE id = $1", [S])).rows[0];

    // ============ P1: en osnutek ============
    console.log("\n# P1 en osnutek");
    const cilj = new Date(Date.now() + 20 * 864e5); cilj.setUTCMinutes(0, 0, 0);
    const startIso = cilj.toISOString().replace("Z", "+00:00");   // zapis z odmikom namesto Z
    let r = await duplikat(S, { startAt: startIso });
    assert(r.status === 201 && Array.isArray(r.body.events) && r.body.events.length === 1, "201 in { events: [1 osnutek] }", r);
    const nov = r.body.events[0];
    assert(nov && Number.isInteger(nov.id) && nov.id !== S && nov.status === "draft" && nov.title === izvor0.title && new Date(nov.start_at).getTime() === cilj.getTime(),
      "odgovor { id, title, start_at, status }: draft, isti naslov, zacetek = zahtevani trenutek", nov);
    assert(Object.keys(nov).sort().join() === "id,start_at,status,title", "odgovor ima samo id, title, start_at, status (brez notranjih polj)", Object.keys(nov));
    let k = (await pool.query("SELECT * FROM events WHERE id = $1", [nov.id])).rows[0];
    assert(k.status === "draft" && k.club_id === izvor0.club_id, "status draft, isti klub");
    for (const polje of ["title", "description", "poster_url", "min_age", "currency", "ticket_url", "capacity", "ticket_price_cents", "venue_club_id", "venue_name", "venue_address", "venue_city", "venue_lat", "venue_lng"]) {
      assert(JSON.stringify(k[polje]) === JSON.stringify(izvor0[polje]), `kopirano: ${polje}`, [k[polje], izvor0[polje]]);
    }
    assert(JSON.stringify(k.genres) === JSON.stringify(izvor0.genres) && k.genres.length === 2, "kopirano: genres");
    assert(String(k.vat_rate) === String(izvor0.vat_rate) && Number(k.vat_rate) === 0.22, "kopirano: vat_rate (DDV stopnja)", k.vat_rate);
    assert(k.sold_count === 0 && k.sales_paused === false && k.vip_enabled === false && k.recap_video_url === "", "sold_count 0, sales_paused false, vip_enabled false, recap_video_url ''", k);
    assert(k.vip_layout_source === "club" && k.floor_plan === null, "razpored VIP se ne kopira (vip_layout_source club, brez tlorisa)", [k.vip_layout_source, k.floor_plan]);
    assert((new Date(k.end_at) - new Date(k.start_at)) === (new Date(izvor0.end_at) - new Date(izvor0.start_at)), "konec ohrani trajanje (6 h)");
    assert((new Date(k.start_at) - new Date(k.sales_open_at)) === (new Date(izvor0.start_at) - new Date(izvor0.sales_open_at)) &&
      (new Date(k.start_at) - new Date(k.sales_close_at)) === (new Date(izvor0.start_at) - new Date(izvor0.sales_close_at)), "okno prodaje ohrani zamik od zacetka (7 dni pred, 1 h pred)");
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM club_tables WHERE event_id = $1", [nov.id])).rows[0].n === 0 && await mizeSkupaj() === 2, "mize dogodka NISO kopirane (I28): nobena miza ni vezana na osnutek, skupaj se 2");
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id = $1", [nov.id])).rows[0].n === 0, "brez narocil");
    const izvor1 = (await pool.query("SELECT * FROM events WHERE id = $1", [S])).rows[0];
    assert(JSON.stringify(izvor1) === JSON.stringify(izvor0), "izvorni dogodek je nespremenjen");

    // ponovi weekly, n = 1 je en osnutek na zacetku
    r = await duplikat(S, { startAt: cilj.toISOString(), ponovi: "weekly", n: 1 });
    assert(r.status === 201 && r.body.events.length === 1, "ponovi weekly, n = 1: en osnutek", r);

    // ============ P2: tedenska vrsta cez prehod casa ============
    console.log("\n# P2 tedenska vrsta (n = 4) cez prehod poletnega/zimskega casa");
    const zacetekVrste = zacetekCezPrehod();
    r = await duplikat(S, { startAt: zacetekVrste, ponovi: "weekly", n: 4 });
    assert(r.status === 201 && r.body.events.length === 4, "201 in 4 osnutki", r.body);
    const vrsta = r.body.events;
    assert(vrsta.every((e) => e.status === "draft" && e.title === izvor0.title) && new Set(vrsta.map((e) => e.id)).size === 4, "vsi osnutki, razlicni id-ji");
    assert(vrsta.every((e, i) => i === 0 || new Date(vrsta[i - 1].start_at) < new Date(e.start_at)), "odgovor je urejen po zacetku");
    assert(new Date(vrsta[0].start_at).toISOString() === zacetekVrste, "prvi osnutek je na zahtevanem zacetku");
    const vrste = (await pool.query("SELECT * FROM events WHERE id = ANY($1) ORDER BY start_at", [vrsta.map((e) => e.id)])).rows;
    const lokalne = [];
    for (const e of vrste) lokalne.push(await lokalnoUra(e.start_at));
    assert(new Set(lokalne.map((x) => x.slice(11))).size === 1, "ura po ljubljansko je v vseh tednih ista (tudi po prehodu casa)", lokalne);
    const utcUre = new Set(vrste.map((e) => new Date(e.start_at).getUTCHours()));
    assert(utcUre.size === 2, "vrsta res prečka prehod casa (UTC ura se v vrsti spremeni; sicer test nic ne dokaze)", [...utcUre]);
    const dnevi = lokalne.map((x) => Date.UTC(+x.slice(0, 4), +x.slice(5, 7) - 1, +x.slice(8, 10)));
    assert(dnevi.every((d, i) => i === 0 || d - dnevi[i - 1] === 7 * 864e5), "koledarski dnevi so natanko 7 narazen", lokalne);
    assert(vrste.every((e) => e.end_at - e.start_at === 6 * 3600e3), "trajanje 6 h v vseh (absolutno, tudi cez prehod)");
    const okno = await pool.query(
      `SELECT to_char(sales_open_at AT TIME ZONE 'Europe/Ljubljana', 'HH24:MI') AS od, to_char(sales_close_at AT TIME ZONE 'Europe/Ljubljana', 'HH24:MI') AS do_,
              to_char(start_at AT TIME ZONE 'Europe/Ljubljana', 'HH24:MI') AS z,
              ((start_at AT TIME ZONE 'Europe/Ljubljana') - (sales_open_at AT TIME ZONE 'Europe/Ljubljana')) AS pred_od,
              ((start_at AT TIME ZONE 'Europe/Ljubljana') - (sales_close_at AT TIME ZONE 'Europe/Ljubljana')) AS pred_do
         FROM events WHERE id = ANY($1) ORDER BY start_at`, [vrsta.map((e) => e.id)]);
    assert(okno.rows.every((x) => x.pred_od.days === 7 && !x.pred_od.hours && !x.pred_od.minutes && x.pred_do.hours === 1 && !x.pred_do.days),
      "okno prodaje: po ljubljansko 7 dni oz. 1 h pred zacetkom v vseh tednih", okno.rows.map((x) => [x.pred_od, x.pred_do]));
    assert(vrste.every((e) => e.sold_count === 0 && e.sales_paused === false && e.vip_enabled === false && e.status === "draft"), "vsi: sold_count 0, sales_paused false, vip_enabled false");

    // brez konca in brez okna: null ostane null
    const S2 = await dogodek(K_B, "Brez konca in okna", { status: "published", end: null, price: null, capacity: null });
    r = await duplikat(S2, { startAt: new Date(Date.now() + 5 * 864e5).toISOString(), ponovi: "weekly", n: 2 });
    const k2 = (await pool.query("SELECT * FROM events WHERE id = ANY($1)", [r.body.events.map((e) => e.id)])).rows;
    assert(r.status === 201 && k2.length === 2 && k2.every((e) => e.end_at === null && e.sales_open_at === null && e.sales_close_at === null && e.ticket_price_cents === null && e.capacity === null && e.club_id === K_B),
      "brez konca / okna / cene / kapacitete: null ostane null; klub B", k2);
    // osnutek in odpovedan dogodek se tudi lahko podvojita (osnutek)
    await pool.query("UPDATE events SET status = 'cancelled' WHERE id = $1", [S2]);
    r = await duplikat(S2, { startAt: new Date(Date.now() + 6 * 864e5).toISOString() });
    assert(r.status === 201 && r.body.events[0].status === "draft", "odpovedan dogodek se podvoji v osnutek");

    // prvi osnutek natanko na zahtevanem trenutku tudi v dvoumni uri prehoda casa: najblizji prihodnji zadnji oktobrski nedeljski prehod, 02:30 +02:00 = 00:30Z
    // (po AT TIME ZONE bi postal 02:30 +01:00 = 01:30Z). Vedno v naslednjih ~12 mesecih, torej znotraj 2-letne meje.
    {
      let nocPrehoda = null, pricakovano = null;
      for (let leto = new Date().getUTCFullYear(); !nocPrehoda; leto++) {
        const d = new Date(Date.UTC(leto, 9, 31)); d.setUTCDate(31 - d.getUTCDay());   // zadnja nedelja oktobra
        const p = `${leto}-10-${String(d.getUTCDate()).padStart(2, "0")}`;
        if (Date.parse(`${p}T00:30:00Z`) > Date.now() + 36e5) { nocPrehoda = `${p}T02:30:00+02:00`; pricakovano = `${p}T00:30:00.000Z`; }
      }
      const SD = await dogodek(K_B, "Izvor za dvoumno uro", { status: "published" });
      const q = await duplikat(SD, { startAt: nocPrehoda, ponovi: "weekly", n: 2 });
      const zs = q.status === 201 ? q.body.events.map((e) => new Date(e.start_at).toISOString()) : q.body;
      assert(q.status === 201 && zs[0] === pricakovano, `startAt ${nocPrehoda}: prvi osnutek natanko ta trenutek (${pricakovano}), ne +1 h`, zs);
      const dbs = (await pool.query("SELECT start_at FROM events WHERE id = ANY($1) ORDER BY start_at", [q.body.events.map((e) => e.id)])).rows;
      assert(dbs[0].start_at.toISOString() === pricakovano, "tudi v bazi", dbs[0]);
    }

    // ============ P3: neveljavno ============
    console.log("\n# P3 neveljavni parametri");
    const pred = await dogodkov();
    const prihodnost = new Date(Date.now() + 9 * 864e5).toISOString();
    const slabi = [
      ["n = 13", { startAt: prihodnost, ponovi: "weekly", n: 13 }, 400, "invalid_count"],
      ["n = 0", { startAt: prihodnost, ponovi: "weekly", n: 0 }, 400, "invalid_count"],
      ["n = -1", { startAt: prihodnost, ponovi: "weekly", n: -1 }, 400, "invalid_count"],
      ["n = 1.5", { startAt: prihodnost, ponovi: "weekly", n: 1.5 }, 400, "invalid_count"],
      ["n = niz", { startAt: prihodnost, ponovi: "weekly", n: "3" }, 400, "invalid_count"],
      ["weekly brez n", { startAt: prihodnost, ponovi: "weekly" }, 400, "invalid_count"],
      ["n brez ponovi", { startAt: prihodnost, n: 3 }, 400, "invalid_count"],
      ["ponovi daily", { startAt: prihodnost, ponovi: "daily", n: 3 }, 400, "invalid_repeat"],
      ["start v preteklosti", { startAt: new Date(Date.now() - 3600e3).toISOString() }, 400, "start_in_past"],
      ["start pred tedenskim zamikom v preteklosti", { startAt: "2020-01-01T10:00:00Z", ponovi: "weekly", n: 3 }, 400, "start_in_past"],
      ["brez obmocja", { startAt: "2031-11-06T22:00:00" }, 400, "invalid_start"],
      ["nemogoc datum", { startAt: "2031-02-31T22:00:00Z" }, 400, "invalid_start"],
      ["nemogoc mesec", { startAt: "2031-13-01T22:00:00Z" }, 400, "invalid_start"],
      ["nemogoca ura", { startAt: "2031-03-01T24:00:00Z" }, 400, "invalid_start"],
      ["29. februar v neprestopnem letu", { startAt: "2031-02-29T10:00:00Z" }, 400, "invalid_start"],
      ["navaden niz", { startAt: "jutri" }, 400, "invalid_start"],
      ["stevilo", { startAt: 1893456000000 }, 400, "invalid_start"],
      ["brez starta", {}, 400, "invalid_start"],
    ];
    for (const [ime, telo, status, koda] of slabi) {
      const x = await duplikat(S, telo);
      assert(x.status === status && x.body && x.body.error === koda && typeof x.body.message === "string", `${ime} -> ${status} ${koda}`, x);
    }
    let x = await duplikat(S, [1, 2, 3]);
    assert(x.status === 400, "telo je seznam -> 400", x.status);
    x = await duplikat(987654, { startAt: prihodnost });
    assert(x.status === 404 && x.body.error === "event_not_found", "neobstojec dogodek -> 404 event_not_found", x);
    x = await duplikat("abc", { startAt: prihodnost });
    assert(x.status === 400 && x.body.error === "invalid_event_id", "id ni stevilo -> 400", x);
    x = await duplikat("99999999999", { startAt: prihodnost });
    assert(x.status === 400, "id izven int4 -> 400 (ne 500)", x.status);
    assert(await dogodkov() === pred, "po vseh zavrnitvah NIC ni ustvarjeno", [await dogodkov(), pred]);

    // ============ P4: vloge ============
    console.log("\n# P4 vloge");
    for (const [ime, tok] of [["navaden uporabnik", T.navaden], ["lastnik kluba (business)", T.lastnik], ["backup", T.kopija]]) {
      x = await duplikat(S, { startAt: prihodnost }, tok);
      assert(x.status === 403, `${ime} -> 403`, x.status);
    }
    x = await duplikat(S, { startAt: prihodnost }, null);
    assert(x.status === 401, "brez zetona -> 401", x.status);
    assert(await dogodkov() === pred, "po zavrnjenih vlogah nic ustvarjeno");

    // ============ P5: vse ali nic ============
    console.log("\n# P5 transakcija vse-ali-nic");
    // sprozilec zavrne tretji vpis `event.duplicate` od zdaj naprej (meja = stevilo vrstic pred klicem + 2)
    await pool.query("CREATE TABLE IF NOT EXISTS test_podvoji_meja (zacetno int)");
    await pool.query("DELETE FROM test_podvoji_meja");
    await pool.query("INSERT INTO test_podvoji_meja SELECT COUNT(*) FROM admin_dejanja WHERE dejanje = 'event.duplicate'");
    await pool.query(`CREATE OR REPLACE FUNCTION test_podvoji_zavrni() RETURNS trigger LANGUAGE plpgsql AS $f$
      BEGIN
        IF NEW.dejanje = 'event.duplicate' AND (SELECT COUNT(*) FROM admin_dejanja WHERE dejanje = 'event.duplicate') >= (SELECT zacetno + 2 FROM test_podvoji_meja LIMIT 1) THEN
          RAISE EXCEPTION 'test: zavrnjen vpis v dnevnik';
        END IF;
        RETURN NEW;
      END $f$`);
    await pool.query("CREATE TRIGGER test_podvoji_zavrni BEFORE INSERT ON admin_dejanja FOR EACH ROW EXECUTE FUNCTION test_podvoji_zavrni()");
    const predAtom = await dogodkov(), dnevnikPred = Number((await pool.query("SELECT COUNT(*) FROM admin_dejanja")).rows[0].count);
    x = await duplikat(S, { startAt: new Date(Date.now() + 40 * 864e5).toISOString(), ponovi: "weekly", n: 4 });
    assert(x.status === 500, "tretji vpis v dnevnik zavrnjen -> 500", x.status);
    assert(await dogodkov() === predAtom, "NOBEN osnutek ni ostal (tudi prva dva ne): vse ali nic", [await dogodkov(), predAtom]);
    assert(Number((await pool.query("SELECT COUNT(*) FROM admin_dejanja")).rows[0].count) === dnevnikPred, "tudi vrstice v dnevniku so se vrnile");
    await pool.query("DROP TRIGGER test_podvoji_zavrni ON admin_dejanja");
    await pool.query("DROP FUNCTION test_podvoji_zavrni()");
    await pool.query("DROP TABLE test_podvoji_meja");
    x = await duplikat(S, { startAt: new Date(Date.now() + 40 * 864e5).toISOString(), ponovi: "weekly", n: 4 });
    assert(x.status === 201 && x.body.events.length === 4, "po odstranitvi sprozilca isti klic uspe (4 osnutki)", x.status);

    // ============ P6: dnevnik ============
    console.log("\n# P6 dnevnik admin dejanj");
    const noviId = x.body.events.map((e) => e.id);
    const dn = await pool.query("SELECT * FROM admin_dejanja WHERE dejanje = 'event.duplicate' AND cilj_id = ANY($1::text[]) ORDER BY cilj_id::int", [noviId.map(String)]);
    assert(dn.rows.length === 4, "natanko ena vrstica na osnutek", dn.rows.length);
    assert(dn.rows.every((v) => v.cilj_tip === "event" && v.admin_user_id === adminId && v.prej === null && v.potem && v.potem.iz === S && typeof v.potem.start_at === "string"),
      "cilj_tip event, avtor admin, prej null, potem { iz: izvor, start_at }", dn.rows[0]);
    assert(dn.rows.every((v, i) => new Date(v.potem.start_at).getTime() === new Date(x.body.events.find((e) => String(e.id) === v.cilj_id).start_at).getTime()), "start_at v dnevniku = zacetek osnutka");
    assert(!/@/.test(JSON.stringify(dn.rows.map((v) => [v.prej, v.potem, v.razlog]))), "dnevnik brez e-naslovov");
    assert(Object.keys(dn.rows[0].potem).sort().join() === "iz,start_at", "potem ima samo iz in start_at", dn.rows[0].potem);
    const podr = await api("GET", `/admin/api/events/${noviId[0]}`, T.admin);
    assert(podr.status === 200 && podr.body.audit.some((a) => a.dejanje === "event.duplicate" && a.potem.iz === S), "dnevnik je viden v GET /admin/api/events/:id (zgodovina urejevalnika)");
    assert(podr.body.event.status === "draft" && podr.body.event.vip_enabled === false, "GET /admin/api/events/:id kaze osnutek brez VIP");

    // ============ P7: brez zaklepanja ============
    console.log("\n# P7 brez zaklepanja drugih dogodkov");
    await lock.query("BEGIN");
    await lock.query("SELECT id FROM events WHERE id = $1 FOR UPDATE", [S]);
    const t0 = Date.now();
    x = await duplikat(S, { startAt: new Date(Date.now() + 60 * 864e5).toISOString() });
    const trajanje = Date.now() - t0;
    await lock.query("ROLLBACK");
    assert(x.status === 201 && trajanje < 2000, "dokler druga seja drzi FOR UPDATE na izvoru, podvajanje uspe takoj", [x.status, trajanje]);
    const izvor2 = (await pool.query("SELECT * FROM events WHERE id = $1", [S])).rows[0];
    assert(JSON.stringify(izvor2) === JSON.stringify(izvor0) && izvor2.sold_count === 5 && izvor2.vip_enabled === true && await mizeSkupaj() === 2, "izvor po vseh podvajanjih nespremenjen (sold_count 5, vip_enabled, 2 mizi)");

    // ============ P8: korak 1 »Nov dogodek« ============
    console.log("\n# P8 admin ustvari osnutek v tujem klubu (POST /events)");
    const zac8 = new Date(Date.now() + 15 * 864e5);
    x = await api("POST", "/events", T.admin, { clubId: K_B, title: "Nov dogodek iz panela", startAt: zac8.toISOString(), endAt: new Date(zac8.getTime() + 6 * 3600e3).toISOString(), status: "draft", ticketPriceCents: 1200, capacity: 250 });
    assert(x.status === 201 && x.body.status === "draft" && x.body.club_id === K_B && x.body.ticket_price_cents === 1200 && x.body.capacity === 250, "admin + clubId tujega kluba + draft -> 201 draft", x);
    x = await api("POST", "/events", T.admin, { clubId: K_B, title: "Brez vstopnic", startAt: zac8.toISOString(), status: "draft" });
    assert(x.status === 201 && x.body.ticket_price_cents === null && x.body.capacity === null, "prazna cena in kapaciteta -> 201 (brez vstopnic na Outlyju)", x.body);
    x = await api("POST", "/events", T.admin, { clubId: K_ORG, title: "Organizator brez prizorisca", startAt: zac8.toISOString(), status: "draft" });
    assert(x.status === 400, "klub organizator brez prizorisca -> 400 (panel mora pokazati polji prizorisca)", x.status);
    x = await api("POST", "/events", T.admin, { clubId: K_ORG, title: "Organizator s prizoriscem", startAt: zac8.toISOString(), status: "draft", venueName: "Lokacija", venueCity: "Maribor" });
    assert(x.status === 201 && x.body.venue_name === "Lokacija" && x.body.venue_city === "Maribor", "klub organizator s prizoriscem -> 201", x.body);
    x = await api("POST", "/events", T.lastnik, { clubId: K_B, title: "Tuj klub", startAt: zac8.toISOString(), status: "draft" });
    assert(x.status === 403 || x.status === 404, "lastnik (business) brez clanstva v tujem klubu: zavrnjeno (403/404, nespremenjeno)", x.status);
    // osnutek se ne vidi javno
    const jav = await api("GET", "/events");
    assert(jav.status === 200 && !jav.body.some((e) => e.title === "Nov dogodek iz panela" || e.title === S), "osnutek ni v javnem GET /events");

    // ============ P9: pregled enega dogodka ============
    console.log("\n# P9 GET /admin/api/opozorila?dogodek=ID (pregled pred objavo)");
    const D = {};
    D.nepopoln = await dogodek(K_NEPOPOLN, "Osnutek nepopolnega");
    D.brezStripa = await dogodek(K_BREZ_STRIPA, "Osnutek kluba brez Stripa");
    D.ok = await dogodek(K_A, "Brezhiben osnutek", { start: "20 days", end: "20 days 6 hours" });
    D.brezplacen = await dogodek(K_NEPOPOLN, "Brezplacen pri nepopolnem", { price: 0 });
    D.brezCene = await dogodek(K_A, "Brez cene", { price: null, capacity: null });
    D.brezKapKonca = await dogodek(K_A, "Brez kapacitete in konca", { capacity: null, end: null });
    D.brezPlakata = await dogodek(K_A, "Brez plakata kmalu", { poster: "", start: "3 days", end: "3 days 6 hours" });
    D.skrit = await dogodek(K_SKRIT, "Osnutek skritega kluba");
    D.objavljen = await dogodek(K_NEPOPOLN, "Objavljen nepopolnega", { status: "published" });
    const pregled = (id, tok = T.admin) => api("GET", `/admin/api/opozorila?dogodek=${id}`, tok);
    const vrste_ = (b) => b.items.map((i) => i.vrsta).sort().join();
    r = await pregled(D.nepopoln);
    assert(r.status === 200 && r.body.items.some((i) => i.vrsta === "prodajalec_nepopoln" && i.resnost === "rdece" && i.cilj_tip === "dogodek" && i.cilj_id === D.nepopoln), "osnutek kluba z nepopolnimi podatki prodajalca: rdece prodajalec_nepopoln", r.body);
    assert(r.body.stevci.rdece === 1 && r.body.items.every((i) => i.cilj_id === D.nepopoln), "stevci rdece 1; samo opozorila tega dogodka", r.body);
    r = await pregled(D.brezStripa);
    assert(r.status === 200 && r.body.items.some((i) => i.vrsta === "placila_niso_pripravljena" && i.resnost === "rdece") && r.body.stevci.rdece === 1, "osnutek kluba brez Stripa: rdece placila_niso_pripravljena", r.body);
    r = await pregled(D.ok);
    assert(r.status === 200 && r.body.items.length === 0 && JSON.stringify(r.body.stevci) === JSON.stringify({ rdece: 0, oranzno: 0, rumeno: 0 }), "brezhiben osnutek: nobenega opozorila", r.body);
    r = await pregled(D.brezplacen);
    assert(r.status === 200 && r.body.stevci.rdece === 0, "brezplacen dogodek pri nepopolnem klubu: ni rdece", r.body);
    r = await pregled(D.brezCene);
    assert(r.status === 200 && vrste_(r.body) === "brez_cene" && r.body.items[0].resnost === "oranzno" && r.body.stevci.rdece === 0, "brez cene in zunanje prodaje: oranzno brez_cene, ne rdece", r.body);
    r = await pregled(D.brezKapKonca);
    assert(r.status === 200 && vrste_(r.body) === "brez_kapacitete,brez_konca" && r.body.stevci.rumeno === 2 && r.body.stevci.rdece === 0, "brez kapacitete in konca: dve rumeni", r.body);
    r = await pregled(D.brezPlakata);
    assert(r.status === 200 && vrste_(r.body) === "brez_plakata" && r.body.items[0].resnost === "oranzno", "brez plakata (zacetek v 14 dneh): oranzno", r.body);
    r = await pregled(D.skrit);
    assert(r.status === 200 && r.body.stevci.rdece === 1, "osnutek v skritem klubu se vseeno preveri (globalni seznam skrite klube izpusti)", r.body);
    r = await pregled(D.objavljen);
    assert(r.status === 200 && r.body.stevci.rdece === 1 && r.body.items[0].vrsta === "prodajalec_nepopoln", "objavljen dogodek: ista pot, ista opozorila kot v globalnem seznamu", r.body);
    const glob = await api("GET", "/admin/api/opozorila", T.admin);
    assert(glob.status === 200 && !glob.body.items.some((i) => i.cilj_id === D.nepopoln || i.cilj_id === D.brezStripa || i.cilj_id === D.brezCene), "globalni seznam osnutkov se vedno NE steje (stara pogodba: osnutek ima le opozorilo plakata)");
    assert(glob.body.items.some((i) => i.vrsta === "prodajalec_nepopoln" && i.cilj_id === D.objavljen), "globalni seznam ima objavljen dogodek kot prej");
    for (const [ime, pot, st_] of [["abc", "abc", 400], ["0", "0", 400], ["-3", "-3", 400], ["99999999999", "99999999999", 400], ["prazno", "", 400], ["1e3", "1e3", 400]]) {
      const q = await pregled(pot);
      assert(q.status === st_ && q.body.error === "invalid_event_id", `?dogodek=${ime} -> ${st_}`, q);
    }
    r = await pregled(424242);
    assert(r.status === 200 && r.body.items.length === 0, "neobstojec dogodek -> 200 prazno", r);
    for (const [ime, tok] of [["navaden uporabnik", T.navaden], ["business", T.lastnik], ["backup", T.kopija]]) {
      const q = await pregled(D.nepopoln, tok);
      assert(q.status === 403, `?dogodek: ${ime} -> 403`, q.status);
    }
    assert((await pregled(D.nepopoln, null)).status === 401, "?dogodek brez zetona -> 401");
    // pregled ne pise
    const stPred = (await pool.query("SELECT (SELECT COUNT(*) FROM events) AS e, (SELECT COUNT(*) FROM admin_dejanja) AS a")).rows[0];
    await pregled(D.nepopoln); await pregled(D.ok);
    const stPo = (await pool.query("SELECT (SELECT COUNT(*) FROM events) AS e, (SELECT COUNT(*) FROM admin_dejanja) AS a")).rows[0];
    assert(JSON.stringify(stPred) === JSON.stringify(stPo), "pregled je samo branje");

    // ============ P9b: ?dogodek ne dela splosnih poizvedb ============
    console.log("\n# P9b ?dogodek preskoci splosne razdelke");
    // racun v stanju napaka in neposlano potrdilo bi bila v globalnem seznamu; v ?dogodek ju NI, tudi ce tabele obstajajo (preskok = brez poizvedb, ne samo filter)
    const ordR = (await pool.query(
      `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, created_at, paid_at, receipt_mail_attempts)
       VALUES ('OUT-PODV-1', (SELECT id FROM users WHERE email='navaden@outly.si'), $1, $2, 1, 1500, 1500, 'paid', 'kupec@primer.si', NOW() - INTERVAL '3 hours', NOW() - INTERVAL '3 hours', 0) RETURNING id`, [D.objavljen, K_NEPOPOLN])).rows[0].id;
    const glob2 = await api("GET", "/admin/api/opozorila", T.admin);
    assert(glob2.body.items.some((i) => i.vrsta === "potrdila_neposlana"), "kontrola: globalni seznam ima potrdila_neposlana");
    r = await pregled(D.objavljen);
    assert(r.status === 200 && r.body.items.every((i) => i.cilj_tip === "dogodek" && i.cilj_id === D.objavljen) && !r.body.items.some((i) => ["potrdila_neposlana", "racun_zaostanek", "racun_napaka", "vracila_pozornost", "spori_odprti"].includes(i.vrsta)),
      "?dogodek: brez splosnih opozoril (potrdila, racuni, vracila, spori)", r.body);
    await pool.query("DELETE FROM orders WHERE id = $1", [ordR]);

    // ============ P10: POST /admin/api/events ============
    console.log("\n# P10 POST /admin/api/events");
    await pool.query("UPDATE clubs SET owner_user_id = $1 WHERE id = $2", [adminId, K_A]);   // admin je SAM lastnik kluba A
    const zac10 = new Date(Date.now() + 15 * 864e5).toISOString();
    x = await api("POST", "/events", T.admin, { clubId: K_B, title: "Prek stare poti", startAt: zac10, status: "draft" });
    assert(x.status === 403 || x.status === 404, "kontrola: admin, ki je lastnik kluba A, na POST /events za klub B NE uspe (zato admin pot)", x.status);
    const pred10 = await dogodkov();
    x = await api("POST", "/admin/api/events", T.admin, { clubId: K_B, title: "Osnutek za klub B", startAt: zac10, endAt: new Date(Date.parse(zac10) + 6 * 3600e3).toISOString(), ticketPriceCents: 1200, capacity: 300, status: "published" });
    assert(x.status === 201 && x.body.status === "draft" && x.body.club_id === K_B && x.body.ticket_price_cents === 1200 && x.body.capacity === 300 && x.body.title === "Osnutek za klub B",
      "admin (lastnik kluba A) ustvari osnutek za klub B -> 201 draft; status published v telesu je prezrt", x);
    const novId10 = x.body.id;
    const dn10 = (await pool.query("SELECT * FROM admin_dejanja WHERE dejanje = 'event.create' AND cilj_id = $1", [String(novId10)])).rows;
    assert(dn10.length === 1 && dn10[0].cilj_tip === "event" && dn10[0].admin_user_id === adminId && dn10[0].prej === null && dn10[0].potem.club_id === K_B && dn10[0].potem.status === "draft" && !/@/.test(JSON.stringify(dn10[0])),
      "admin_dejanja event.create (cilj event, avtor admin, potem { club_id, title, start_at, status }, brez e-naslovov)", dn10);
    assert((await api("GET", "/events", null)).body.every((e) => e.id !== novId10), "osnutek ni javen");
    x = await api("POST", "/admin/api/events", T.admin, { clubId: K_B, title: "Slab URL", startAt: zac10, posterUrl: "javascript:alert(1)" });
    assert(x.status === 400 && x.body.error === "invalid_url", "ista validacija: javascript: plakat -> 400 invalid_url", x);
    x = await api("POST", "/admin/api/events", T.admin, { clubId: 987654, title: "Neznan klub", startAt: zac10 });
    assert(x.status === 404, "neznan klub -> 404", x.status);
    x = await api("POST", "/admin/api/events", T.admin, { clubId: K_ORG, title: "Organizator brez prizorisca", startAt: zac10 });
    assert(x.status === 400, "klub organizator brez prizorisca -> 400", x.status);
    x = await api("POST", "/admin/api/events", T.admin, { clubId: K_B, startAt: zac10 });
    assert(x.status === 400, "brez naslova -> 400", x.status);
    const pred10b = await dogodkov();
    assert(pred10b === pred10 + 1, "po zavrnitvah ni novih dogodkov (samo en uspesen)", [pred10, pred10b]);
    for (const [ime, tok] of [["navaden uporabnik", T.navaden], ["business", T.lastnik], ["backup", T.kopija]]) {
      x = await api("POST", "/admin/api/events", tok, { clubId: K_B, title: "X", startAt: zac10 });
      assert(x.status === 403, `POST /admin/api/events: ${ime} -> 403`, x.status);
    }
    assert((await api("POST", "/admin/api/events", null, { clubId: K_B, title: "X", startAt: zac10 })).status === 401, "POST /admin/api/events brez zetona -> 401");
    assert(await dogodkov() === pred10b, "zavrnjeni klici niso ustvarili dogodka");
    // transakcija: zavrnjen vpis v dnevnik -> dogodka ni
    await pool.query("CREATE OR REPLACE FUNCTION test_ustvari_zavrni() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN IF NEW.dejanje = 'event.create' THEN RAISE EXCEPTION 'test: zavrnjen vpis'; END IF; RETURN NEW; END $f$");
    await pool.query("CREATE TRIGGER test_ustvari_zavrni BEFORE INSERT ON admin_dejanja FOR EACH ROW EXECUTE FUNCTION test_ustvari_zavrni()");
    x = await api("POST", "/admin/api/events", T.admin, { clubId: K_B, title: "Ne sme ostati", startAt: zac10 });
    await pool.query("DROP TRIGGER test_ustvari_zavrni ON admin_dejanja"); await pool.query("DROP FUNCTION test_ustvari_zavrni()");
    assert(x.status === 500 && await dogodkov() === pred10b, "vrstica dnevnika zavrnjena -> 500 in dogodek NI ostal (ena transakcija)", [x.status, await dogodkov()]);
    await pool.query("UPDATE clubs SET owner_user_id = (SELECT id FROM users WHERE email = 'lastnik100@primer.si') WHERE id = $1", [K_A]);

    // ============ P11: kopija ne prenese neveljavnega, omejitve ============
    console.log("\n# P11 neveljavni URL-ji, zanri, startAt predaleč, omejitev baze");
    const S3 = await dogodek(K_A, "Izvor z umazanimi polji", { status: "published" });
    await pool.query("UPDATE events SET poster_url = 'javascript:alert(1)', ticket_url = 'ftp://x.si/vstopnice', genres = ARRAY['house','<img src=x onerror=1>','neznan']::text[] WHERE id = $1", [S3]);
    r = await duplikat(S3, { startAt: new Date(Date.now() + 30 * 864e5).toISOString() });
    let kk = r.status === 201 && (await pool.query("SELECT poster_url, ticket_url, genres FROM events WHERE id = $1", [r.body.events[0].id])).rows[0];
    assert(kk && kk.poster_url === "" && kk.ticket_url === "" && JSON.stringify(kk.genres) === JSON.stringify(["house"]), "javascript: plakat in ftp: zunanja prodaja postaneta '', neznani zanri izpuscni", kk);
    await pool.query("UPDATE events SET poster_url = 'https://slike.test/ok.jpg', ticket_url = 'https://vstopnice.test/e', genres = ARRAY['house','techno']::text[] WHERE id = $1", [S3]);
    r = await duplikat(S3, { startAt: new Date(Date.now() + 31 * 864e5).toISOString() });
    kk = r.status === 201 && (await pool.query("SELECT poster_url, ticket_url, genres FROM events WHERE id = $1", [r.body.events[0].id])).rows[0];
    assert(kk && kk.poster_url === "https://slike.test/ok.jpg" && kk.ticket_url === "https://vstopnice.test/e" && kk.genres.length === 2, "veljavni URL-ji in zanri se kopirajo", kk);
    const pred11 = await dogodkov();
    x = await duplikat(S3, { startAt: new Date(Date.now() + 3 * 365 * 864e5).toISOString() });
    assert(x.status === 400 && x.body.error === "start_too_far", "startAt cez 2 leti vnaprej -> 400 start_too_far", x);
    x = await duplikat(S3, { startAt: new Date(Date.now() + 700 * 864e5).toISOString() });
    assert(x.status === 201, "startAt ~23 mesecev vnaprej se sprejme", x.status);
    await pool.query("ALTER TABLE events ADD CONSTRAINT test_podvoji_chk CHECK (status <> 'draft' OR title NOT LIKE 'ZAPRET%')");
    const SZ = await dogodek(K_A, "ZAPRET kopije", { status: "published" });
    const predZ = await dogodkov();
    x = await duplikat(SZ, { startAt: new Date(Date.now() + 30 * 864e5).toISOString(), ponovi: "weekly", n: 3 });
    await pool.query("ALTER TABLE events DROP CONSTRAINT test_podvoji_chk");
    assert(x.status === 400 && x.body.error === "duplicate_invalid" && await dogodkov() === predZ, "kršitev CHECK omejitve baze (23514) -> 400 duplicate_invalid in nic ustvarjeno", x);
  } catch (e) {
    fail++; console.error("NEPRICAKOVANA NAPAKA", e);
  } finally {
    await lock.end().catch(() => {});
    await pool.end().catch(() => {});
    srv.kill(); jwksServer.close();
  }
  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  if (fail) console.log("--- dnevnik streznika (zadnjih 3000 znakov) ---\n" + log.slice(-3000));
  process.exit(fail ? 1 : 0);
})();
