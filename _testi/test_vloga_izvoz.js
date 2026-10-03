#!/usr/bin/env node
/**
 * Test vloge `backup` (issue #116): racun za dnevno varnostno kopijo sme SAMO GET /admin/api/export.
 * Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres@localhost:5432/outly" node _testi/test_vloga_izvoz.js
 * Vzorec kot test_finance_admin.js: lokalni JWKS (3965), backend na svojem portu (3126).
 *
 * Kaj dokazuje (invarianta I5, vloga pride iz baze ob vsakem klicu):
 *  1. Vloga `backup` je dovoljena v bazi (users_role_chk), druge vrednosti se vedno ne.
 *  2. backup -> GET /admin/api/export = 200 (tok, veljaven JSON, iste tabele kot pri adminu); admin -> 200 kot prej.
 *  3. backup -> VSAKA druga admin pot (branje in pisanje, vse metode) = 403; stanje v bazi se ne spremeni.
 *  4. backup -> navadne poti API-ja (/me, nakup, klub, sken, brisanje racuna ...) = 403 (privzeto zavrnjen povsod razen na izvozu),
 *     javne poti brez prijave (/clubs, /events) delujejo kot prej; neobvezna prijava ga obravnava kot neprijavljenega.
 *  5. Navaden uporabnik, business, brez zetona, ponarejen zeton: izvoz 403 / 403 / 401 / 401.
 *  6. Sprememba vloge velja takoj (vloga iz baze): backup -> user = izvoz 403; admin ga lahko postavi prek PATCH /admin/api/users/:id.
 *  7. backup ne more sam sebi dati vecjih pravic (PATCH /admin/api/users/:id = 403, vloga ostane).
 *  8. Racun backup drugim ni viden: GET /users/search ga ne najde, prosnja za prijateljstvo nanj = enak 404 kot za neobstojec racun.
 *  9. HEAD /admin/api/export: Express usmeri HEAD na GET rocnik -> backup in admin dobita 200 (izvoz se izvede, telo se zavrze); HEAD na drugo admin pot = 403.
 * 10. Najvec 1 hkratni izvoz na proces: med zaklenjeno tabelo `tickets` drugi izvoz (admin ali backup) = 429 + Retry-After,
 *     po koncu (in po prekinitvi odjemalca) spet 200. Brez spanja: cakamo na pogoj (pg_stat_activity, ponavljanje).
 * 11. izvoz.sh (kopija) 429 ponovi in uspe.
 * 12. Izpad baze pri iskanju uporabnika (statement_timeout nad zaklenjeno tabelo users) = 503 + Retry-After 5, NE 403/401, tudi za backup.
 */
const crypto = require("crypto");
const http = require("http");
const { spawn, spawnSync } = require("child_process");
const path = require("path");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3126, PORT_B = 3127, PORT_IZVOZ_LAZNI = 3128, JWKS_PORT = 3965;
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
  return { status: r.status, body: j, text: t };
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, creator_applications, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = "", logB = "", srvB = null; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  try {
    const T = {
      admin: zeton("admin@outly.si", uuid(1)),
      lastnik: zeton("lastnik@outly.si", uuid(2)),
      navaden: zeton("navaden@outly.si", uuid(3)),
      kopija: zeton("kopija@outly.si", uuid(4)),
    };
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k} (vrstica nastane ob prvem klicu, vloga user)`, r.body); }
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana')");
    const cezTeden = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
    let r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Dogodek", startAt: cezTeden, ticketPriceCents: 1000, capacity: 50, minAge: 0 });
    assert(r.status === 201, "dogodek ustvarjen", r.body);
    const dogodekId = r.body.id;

    console.log("\n# 1. Baza: vloga backup dovoljena, druge vrednosti ne");
    let napaka = null;
    try { await pool.query("UPDATE users SET role='superadmin' WHERE email='navaden@outly.si'"); } catch (e) { napaka = e; }
    assert(napaka && napaka.code === "23514", "role='superadmin' zavrne users_role_chk (23514)", napaka && napaka.code);
    napaka = null;
    try { await pool.query("UPDATE users SET role='backup' WHERE email='kopija@outly.si'"); } catch (e) { napaka = e; }
    assert(!napaka, "role='backup' baza sprejme (migracija 029)", napaka && napaka.message);

    console.log("\n# 2. backup -> izvoz = 200; admin -> izvoz = 200 kot prej");
    r = await api("GET", "/admin/api/export", T.kopija);
    assert(r.status === 200, "backup: GET /admin/api/export -> 200", r.status);
    let izvozB = null; try { izvozB = JSON.parse(r.text); } catch (_) { /* spodaj */ }
    assert(izvozB !== null && izvozB.tables && izvozB.tables.users && Array.isArray(izvozB.sequences), "backup: odgovor je veljaven izvoz (tables, sequences)");
    assert(izvozB && izvozB.tables.users.count === 4 && izvozB.tables.clubs.count === 1, "backup: izvoz vsebuje vrstice (4 uporabniki, 1 klub)", izvozB && izvozB.tables.users.count);
    assert(izvozB && !("omejitve" in izvozB.tables), "backup: tabela omejitve ni v izvozu (kot pri adminu)");
    r = await api("GET", "/admin/api/export", T.admin);
    assert(r.status === 200, "admin: GET /admin/api/export -> 200 (kot prej)", r.status);
    let izvozA = null; try { izvozA = JSON.parse(r.text); } catch (_) { /* spodaj */ }
    assert(izvozA !== null && izvozB !== null && Object.keys(izvozA.tables).join() === Object.keys(izvozB.tables).join(), "admin in backup dobita iste tabele");
    r = await api("GET", "/admin/api/export?x=1", T.kopija);
    assert(r.status === 200, "backup: izvoz s poizvedbenim nizom -> 200 (ista pot)", r.status);
    r = await api("GET", "/admin/api/Export", T.kopija);
    assert(r.status === 200, "backup: /admin/api/Export (velike crke) -> 200 (Express ni obcutljiv, ista pot kot pri adminu)", r.status);

    console.log("\n# 3. backup -> vsaka druga admin pot = 403");
    const kopijaId = (await pool.query("SELECT id FROM users WHERE email='kopija@outly.si'")).rows[0].id;
    const navadenId = (await pool.query("SELECT id FROM users WHERE email='navaden@outly.si'")).rows[0].id;
    const prepovedane = [
      ["GET", "/admin/api/summary"],
      ["GET", "/admin/api/finance"],
      ["GET", "/admin/api/users"],
      ["GET", "/admin/api/users?q=outly"],
      ["GET", "/admin/api/clubs"],
      ["GET", "/admin/api/events"],
      ["GET", "/admin/api/creator-applications"],
      ["POST", "/admin/api/clubs", { name: "Hekerski klub", city: "Ljubljana" }],
      ["PATCH", "/admin/api/clubs/1", { hidden: true }],
      ["PATCH", `/admin/api/users/${kopijaId}`, { role: "admin" }],
      ["PATCH", `/admin/api/users/${navadenId}`, { role: "admin" }],
      ["PATCH", `/admin/api/users/${navadenId}`, { emailVerified: true }],
      ["PATCH", `/admin/api/events/${dogodekId}`, { status: "cancelled" }],
      ["POST", "/admin/api/creator-applications/1/approve", {}],
      ["POST", "/admin/api/creator-applications/1/reject", {}],
      ["POST", "/admin/api/export", {}],
      ["PUT", "/admin/api/export", {}],
      ["DELETE", "/admin/api/export"],
      ["GET", "/admin/api/export/dodatek"],
      ["GET", "/admin/api/neobstojec"],
    ];
    for (const [m, p, b] of prepovedane) {
      r = await api(m, p, T.kopija, b);
      assert(r.status === 403, `backup: ${m} ${p} -> 403`, r.status);
    }
    const stanje = (await pool.query("SELECT (SELECT role FROM users WHERE id=$1) AS kopija, (SELECT role FROM users WHERE id=$2) AS navaden, (SELECT hidden FROM clubs WHERE id=1) AS skrit, (SELECT status FROM events WHERE id=$3) AS dogodek, (SELECT COUNT(*)::int FROM clubs) AS klubi", [kopijaId, navadenId, dogodekId])).rows[0];
    assert(stanje.kopija === "backup" && stanje.navaden === "user" && stanje.skrit === false && stanje.dogodek === "published" && stanje.klubi === 1, "stanje v bazi po poskusih pisanja je nespremenjeno", stanje);

    console.log("\n# 4. backup -> navadne poti API-ja = 403; javne poti brez prijave delujejo");
    const navadne = [
      ["GET", "/me"],
      ["PATCH", "/me", { username: "hekerski" }],
      ["DELETE", "/me"],
      ["GET", "/me/orders"],
      ["GET", "/me/tickets"],
      ["GET", "/me/invites"],
      ["POST", `/events/${dogodekId}/orders`, { quantity: 1 }],
      ["POST", "/clubs", { name: "Moj klub", city: "Maribor" }],
      ["PUT", "/clubs/1/follow"],
      ["GET", "/business/clubs/me"],
      ["POST", "/business/tickets/scan", { serial: "00000000-0000-4000-8000-000000000000" }],
    ];
    for (const [m, p, b] of navadne) {
      r = await api(m, p, T.kopija, b);
      assert(r.status === 403, `backup: ${m} ${p} -> 403`, r.status);
    }
    const po = (await pool.query("SELECT (SELECT COUNT(*)::int FROM users WHERE id=$1) AS racun, (SELECT COUNT(*)::int FROM orders) AS narocila, (SELECT COUNT(*)::int FROM clubs) AS klubi, (SELECT username FROM users WHERE id=$1) AS ime", [kopijaId])).rows[0];
    assert(po.racun === 1 && po.narocila === 0 && po.klubi === 1 && po.ime === "kopija", "racun ni izbrisan, ni narocil, ni novih klubov, ime nespremenjeno", po);
    r = await api("GET", "/clubs", T.kopija);
    assert(r.status === 200, "javni GET /clubs z zetonom backup -> 200 (pot ne zahteva prijave, kot prej)", r.status);
    r = await api("GET", "/events", T.kopija);
    assert(r.status === 200, "javni GET /events z zetonom backup -> 200", r.status);
    r = await api("POST", "/creator-applications", T.kopija, { businessName: "Test bar", contactName: "Test Oseba", email: "kdorkoli@example.com" });
    assert(r.status === 201 || r.status === 200, "POST /creator-applications (neobvezna prijava) deluje kot za neprijavljenega", r.status + " " + r.text);
    const prosnja = (await pool.query("SELECT user_id, email FROM creator_applications ORDER BY id DESC LIMIT 1")).rows[0];
    assert(prosnja && prosnja.user_id === null && prosnja.email === "kdorkoli@example.com", "prosnja NI vezana na racun backup (user_id null, e-naslov iz telesa)", prosnja);

    console.log("\n# 5. Drugi klici izvoza");
    r = await api("GET", "/admin/api/export", null);
    assert(r.status === 401, "brez zetona -> 401", r.status);
    r = await api("GET", "/admin/api/export", "ni.zeton.sploh");
    assert(r.status === 401, "ponarejen zeton -> 401", r.status);
    r = await api("GET", "/admin/api/export", T.navaden);
    assert(r.status === 403, "navaden uporabnik -> 403", r.status);
    r = await api("GET", "/admin/api/export", T.lastnik);
    assert(r.status === 403, "business -> 403", r.status);

    console.log("\n# 6. Vloga iz baze ob vsakem klicu; admin jo lahko nastavi");
    await pool.query("UPDATE users SET role='user' WHERE id=$1", [kopijaId]);
    r = await api("GET", "/admin/api/export", T.kopija);
    assert(r.status === 403, "po vrnitvi na user izvoz takoj 403", r.status);
    r = await api("GET", "/me", T.kopija);
    assert(r.status === 200, "po vrnitvi na user spet deluje navadna prijava (/me 200)", r.status);
    r = await api("PATCH", `/admin/api/users/${kopijaId}`, T.admin, { role: "backup" });
    assert(r.status === 200 && r.body.role === "backup", "admin nastavi vlogo backup prek PATCH /admin/api/users/:id", r.body);
    r = await api("GET", "/admin/api/export", T.kopija);
    assert(r.status === 200, "izvoz takoj spet 200", r.status);
    r = await api("PATCH", `/admin/api/users/${kopijaId}`, T.admin, { role: "napacna" });
    assert(r.status === 400, "neveljavna vloga se vedno 400", r.status);
    r = await api("GET", "/admin/api/users", T.admin);
    assert(r.status === 200 && r.body.some(u => u.email === "kopija@outly.si" && u.role === "backup"), "admin v seznamu vidi vlogo backup", r.status);
    r = await api("GET", "/admin/api/summary", T.admin);
    assert(r.status === 200, "admin: summary se vedno 200", r.status);
    r = await api("PATCH", `/admin/api/users/${navadenId}`, T.admin, { role: "business" });
    assert(r.status === 200 && r.body.role === "business", "admin: PATCH vloga business se vedno dela", r.body);

    console.log("\n# 8. Racun backup drugim ni viden");
    r = await api("GET", "/users/search?q=kopija", T.navaden);
    assert(r.status === 200 && Array.isArray(r.body.users) && r.body.users.length === 0, "iskanje 'kopija' ne najde racuna backup", r.body);
    r = await api("GET", "/users/search?q=lastnik", T.navaden);
    assert(r.status === 200 && r.body.users.some(u => u.username === "lastnik"), "kontrola: iskanje navadnega uporabnika deluje", r.body);
    const neobstojec = await api("POST", "/me/friends/requests", T.navaden, { username: "ni_takega_uporabnika" });
    assert(neobstojec.status === 404 && neobstojec.body.error === "no_account", "kontrola: prosnja za neobstojecega = 404 no_account", neobstojec);
    r = await api("POST", "/me/friends/requests", T.navaden, { username: "kopija" });
    assert(r.status === 404 && JSON.stringify(r.body) === JSON.stringify(neobstojec.body), "prosnja za backup po imenu = isti 404 kot za neobstojec racun", r);
    r = await api("POST", "/me/friends/requests", T.navaden, { user_id: kopijaId });
    assert(r.status === 404 && JSON.stringify(r.body) === JSON.stringify(neobstojec.body), "prosnja za backup po user_id = isti 404", r);
    const prijateljstvo = (await pool.query("SELECT (SELECT COUNT(*)::int FROM friend_requests) AS prosnje, (SELECT COUNT(*)::int FROM friendships) AS prijatelji")).rows[0];
    assert(prijateljstvo.prosnje === 0 && prijateljstvo.prijatelji === 0, "v bazi ni nobene prosnje ali prijateljstva", prijateljstvo);
    await pool.query("UPDATE users SET role='user' WHERE id=$1", [kopijaId]);
    r = await api("GET", "/users/search?q=kopija", T.navaden);
    assert(r.status === 200 && r.body.users.length === 1, "kontrola: z vlogo user ga iskanje spet najde (skrije ga res vloga)", r.body);
    await pool.query("UPDATE users SET role='backup' WHERE id=$1", [kopijaId]);

    console.log("\n# 9. HEAD /admin/api/export");
    r = await api("HEAD", "/admin/api/export", T.kopija);
    assert(r.status === 200, "backup: HEAD /admin/api/export -> 200 (Express usmeri HEAD na GET rocnik; izvoz se izvede, telo se zavrze)", r.status);
    r = await api("HEAD", "/admin/api/export", T.admin);
    assert(r.status === 200, "admin: HEAD /admin/api/export -> 200 (enako)", r.status);
    r = await api("HEAD", "/admin/api/export", T.navaden);
    assert(r.status === 403, "navaden/business: HEAD /admin/api/export -> 403", r.status);
    r = await api("HEAD", "/admin/api/users", T.kopija);
    assert(r.status === 403, "backup: HEAD /admin/api/users -> 403", r.status);

    console.log("\n# 10. Najvec 1 hkratni izvoz na proces (429 + Retry-After)");
    const spi = (ms) => new Promise(res => setTimeout(res, ms));
    // Pocakaj na pogoj (do ~10 s), brez fiksnega spanja.
    async function cakajNa(pogoj, opis) {
      for (let i = 0; i < 200; i++) { if (await pogoj()) return true; await spi(50); }
      console.log("  (pogoj ni izpolnjen v roku:", opis, ")"); return false;
    }
    const izvozCaka = async () => (await pool.query(
      "SELECT COUNT(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query ILIKE '%\"tickets\"%'")).rows[0].n > 0;
    const izvozPoznejsi = async (zeton) => {          // poskusi izvoz, dokler ni 429 (izvoz se sprosti ob koncu `finally`)
      let k = null;
      const koncal = await cakajNa(async () => { k = await api("GET", "/admin/api/export", zeton); return k.status !== 429; }, "izvoz se je sprostil");
      return { koncal, k };
    };
    let zaklep = await pool.connect();
    await zaklep.query("BEGIN"); await zaklep.query("LOCK TABLE tickets IN ACCESS EXCLUSIVE MODE");
    const prvi = fetch(BASE + "/admin/api/export", { headers: { authorization: "Bearer " + T.admin } });   // admin drzi izvoz
    assert(await cakajNa(izvozCaka, "prvi izvoz caka na zaklep tickets"), "prvi izvoz (admin) tece in caka na zaklep tabele");
    const druga = await fetch(BASE + "/admin/api/export", { headers: { authorization: "Bearer " + T.kopija } });
    const drugaTelo = await druga.json();
    assert(druga.status === 429 && druga.headers.get("retry-after") === "30" && drugaTelo.error === "export_busy", "drugi hkratni izvoz (backup) -> 429 + Retry-After 30 + export_busy", { s: druga.status, ra: druga.headers.get("retry-after"), t: drugaTelo });
    r = await api("GET", "/admin/api/export", T.admin);
    assert(r.status === 429, "tretji hkratni izvoz (admin) -> 429", r.status);
    r = await api("GET", "/admin/api/summary", T.admin);
    assert(r.status === 200, "ostale admin poti med izvozom delujejo (429 velja samo za izvoz)", r.status);
    r = await api("GET", "/admin/api/export", T.navaden);
    assert(r.status === 403, "navaden uporabnik med izvozom dobi 403 (vloga se preveri pred omejitvijo)", r.status);
    await zaklep.query("ROLLBACK"); zaklep.release();
    const prviOdg = await prvi;
    let prviIzvoz = null; try { prviIzvoz = JSON.parse(await prviOdg.text()); } catch (_) { /* spodaj */ }
    assert(prviOdg.status === 200 && prviIzvoz && prviIzvoz.tables && prviIzvoz.tables.users, "prvi izvoz se po sprostitvi zaklepa konca z 200 in veljavnim JSON", prviOdg.status);
    let pozno = await izvozPoznejsi(T.kopija);
    assert(pozno.koncal && pozno.k.status === 200, "po koncu prvega izvoza backup spet dobi 200", pozno.k && pozno.k.status);

    // Prekinitev odjemalca sprosti omejitev (finally): izvoz caka na zaklep, odjemalec odide, po sprostitvi zaklepa je izvoz spet mogoc.
    zaklep = await pool.connect();
    await zaklep.query("BEGIN"); await zaklep.query("LOCK TABLE tickets IN ACCESS EXCLUSIVE MODE");
    const ac = new AbortController();
    const prekinjen = fetch(BASE + "/admin/api/export", { headers: { authorization: "Bearer " + T.admin }, signal: ac.signal }).catch(() => null);
    assert(await cakajNa(izvozCaka, "izvoz caka na zaklep (prekinitev)"), "izvoz za prekinitev caka na zaklep");
    ac.abort(); await prekinjen;
    r = await api("GET", "/admin/api/export", T.kopija);
    assert(r.status === 429, "dokler strezniski izvoz se tece (caka na zaklep), je omejitev se zasedena", r.status);
    await zaklep.query("ROLLBACK"); zaklep.release();
    pozno = await izvozPoznejsi(T.kopija);
    assert(pozno.koncal && pozno.k.status === 200, "po prekinitvi odjemalca se omejitev sprosti (izvoz spet 200)", pozno.k && pozno.k.status);
    const tx = (await pool.query("SELECT COUNT(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND state LIKE 'idle in transaction%' AND pid <> pg_backend_pid()")).rows[0].n;
    assert(tx === 0, "ni povezav 'idle in transaction' po izvozih", tx);

    console.log("\n# 11. izvoz.sh ponovi 429 (lazni streznik: prijava, prvi izvoz 429, drugi 200)");
    {
      let klicov = 0;
      const gorivo = JSON.stringify({ exported_at: new Date().toISOString(), postgres: "x", tables: { schema_migrations: { count: 1, columns: ["datoteka"], rows: [{ datoteka: "000" }] }, users: { count: 1, columns: ["id"], rows: [{ id: 1 }] } }, sequences: [] });
      const lazni = http.createServer((q, a) => {
        if (q.method === "POST" && q.url.startsWith("/auth/v1/token")) { q.resume(); a.setHeader("content-type", "application/json"); return a.end(JSON.stringify({ access_token: "lazni-zeton" })); }
        if (q.method === "GET" && q.url === "/admin/api/export") {
          klicov++;
          if (klicov === 1) { a.statusCode = 429; a.setHeader("Retry-After", "1"); return a.end('{"error":"export_busy"}'); }
          a.setHeader("content-type", "application/json"); return a.end(gorivo);
        }
        a.statusCode = 404; a.end();
      });
      await new Promise(res => lazni.listen(PORT_IZVOZ_LAZNI, res));
      const izhod = path.join(require("os").tmpdir(), `izvoz_test_${process.pid}.json`);
      // spawnSync bi blokiral zanko dogodkov in lazni streznik ne bi odgovarjal -> asinhrono
      const rc = await new Promise((resolve) => {
        const pr = spawn("bash", [path.join(__dirname, "..", "_orodja", "kopija", "izvoz.sh"), izhod], {
          env: { ...process.env, BACKUP_ADMIN_EMAIL: "kopija@outly.si", BACKUP_ADMIN_PASSWORD: "ni-pravo-geslo", BACKEND_URL: `http://127.0.0.1:${PORT_IZVOZ_LAZNI}`,
                 SUPABASE_URL: `http://127.0.0.1:${PORT_IZVOZ_LAZNI}`, SUPABASE_APIKEY: "x", IZVOZ_PAVZA_S: "1" }, stdio: ["ignore", "pipe", "pipe"] });
        let izpis = ""; pr.stdout.on("data", d => izpis += d); pr.stderr.on("data", d => izpis += d);
        pr.on("exit", (koda) => resolve({ koda, izpis }));
      });
      lazni.close();
      assert(rc.koda === 0 && klicov === 2, "izvoz.sh: 429 -> ponovi -> uspe (2 klica, izhod 0)", { koda: rc.koda, klicov, izpis: rc.izpis.slice(-300) });
      assert(/poskus 1\/3: curl koda 22, HTTP 429/.test(rc.izpis), "izvoz.sh izpise HTTP 429 (brez vsebine odgovora)", rc.izpis.slice(-300));
      try { require("fs").unlinkSync(izhod); } catch (_) { /* ni ostanka */ }
    }

    console.log("\n# 12. Izpad baze pri iskanju uporabnika -> 503 (ne 403/401), tudi za backup");
    srvB = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT_B), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test", PGOPTIONS: "-c statement_timeout=400" }, stdio: ["ignore", "pipe", "pipe"] });
    srvB.stdout.on("data", d => logB += d); srvB.stderr.on("data", d => logB += d);
    for (let i = 0; i < 50; i++) { try { await fetch(`http://127.0.0.1:${PORT_B}/`); break; } catch { await spi(100); } }
    const apiB = async (m, pot, zeton) => { const x = await fetch(`http://127.0.0.1:${PORT_B}${pot}`, { method: m, headers: { authorization: "Bearer " + zeton } }); await x.text(); return { status: x.status, retryAfter: x.headers.get("retry-after") }; };
    r = await apiB("GET", "/admin/api/export", T.kopija);
    assert(r.status === 200, "kontrola: drugi streznik, backup izvoz 200", r.status);
    const zaklepUsers = await pool.connect();
    await zaklepUsers.query("BEGIN"); await zaklepUsers.query("LOCK TABLE users IN ACCESS EXCLUSIVE MODE");
    r = await apiB("GET", "/admin/api/export", T.kopija);
    assert(r.status === 503 && r.retryAfter === "5", "backup: iskanje uporabnika prekinjeno (57014) -> 503 + Retry-After 5 (ne 403/401)", r);
    r = await apiB("GET", "/admin/api/export", T.admin);
    assert(r.status === 503 && r.retryAfter === "5", "admin: enako 503", r);
    r = await apiB("GET", "/admin/api/summary", T.kopija);
    assert(r.status === 503, "backup na drugi admin poti med izpadom: 503 (vloge ni mogoce ugotoviti), ne 200", r.status);
    await zaklepUsers.query("ROLLBACK"); zaklepUsers.release();
    r = await apiB("GET", "/admin/api/export", T.kopija);
    assert(r.status === 200, "po sprostitvi zaklepa backup izvoz spet 200", r.status);
    srvB.kill(); srvB = null;

    console.log("\n# 7. Brez nepricakovanih napak v dnevniku streznika");
    assert(!/TypeError|ReferenceError|unhandled/i.test(log), "dnevnik brez TypeError/ReferenceError/unhandled", log.slice(-400));
  } finally {
    srv.kill();
    if (srvB) srvB.kill();
    jwksServer.close();
    await pool.end();
  }
  console.log(`\n${ok} ok, ${fail} napak`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
