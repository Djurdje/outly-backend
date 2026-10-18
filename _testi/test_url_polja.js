#!/usr/bin/env node
/**
 * Streznik preverja URL polja, ki jih vpise lastnik kluba ali admin (outly-backend#269, prva alineja): ticket_url, poster_url (dogodek),
 * website, logo_url, banner_url, instagram (klub). Brez tega bi `javascript:` ali `data:` povezava prisla do vseh obiskovalcev.
 * Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_url_polja.js
 * Vzorec kot test_zanri_validacija.js: lokalni JWKS (ES256), backend na svojem portu.
 *
 *   1  PATCH /business/clubs/me: neveljavni URL -> 400 { error: "invalid_url", field, message }, NIC se ne zapise (tudi veljavna polja v istem zahtevku);
 *      veljavni: https/http, `www.klub.si` dobi https:// (website, instagram), @uporabnisko_ime ostane, null/"" brise
 *      `-` (website, instagram) = brisanje, kot ga bere iOS (ClubContact.cisto); `\\` v URL-ju je zavrnjen (WHATWG/RFC razlika gostitelja)
 *   1b manager sme, doorman 403, brez zetona 401 (PATCH /business/clubs/me)
 *   2  stari neveljavni zapis (vstavljen mimo API-ja): nespremenjena vrednost NE blokira shranjevanja drugih polj; sprememba v drugo neveljavno pa 400
 *   3  POST /clubs: logoUrl / bannerUrl / website / instagram; klub se ob zavrnitvi NE ustvari
 *   4  POST /events: ticketUrl / posterUrl (camelCase in snake_case); dogodek se ob zavrnitvi NE ustvari
 *   5  PATCH /events/:id: isto + stari zapis + recapVideoUrl/galerija/video (ze preverjeni https) ostanejo zavrnjeni
 *   6  admin: POST in PATCH /admin/api/clubs (logo, banner, website, instagram), stari zapis ob polnem obrazcu ne blokira
 *   7  kontrola: PATCH /me/avatar sprejme samo Cloudinary
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 4711, JWKS_PORT = 4712;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-url";
const jwksServer = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url.startsWith("/auth/v1/user")) { try { const t = JSON.parse(Buffer.from(String(req.headers.authorization).split(".")[1], "base64url")); return res.end(JSON.stringify({ id: t.sub, email: t.email, email_confirmed_at: "2026-01-01T00:00:00Z" })); } catch (_) { res.statusCode = 401; return res.end("{}"); } }   // potrditev e-naslova pri viru (#222)
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
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra).slice(0, 400) : ""); } }
async function api(method, p, token, body) {
  const r = await fetch(BASE + p, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}
const jeInvalidUrl = (r, polje) => r.status === 400 && r.body && r.body.error === "invalid_url" && r.body.field === polje && typeof r.body.message === "string" && r.body.message.length > 0;

// Neveljavne vrednosti: nobena ne sme priti v bazo.
const ZLI = [
  ["javascript:", "javascript:alert(document.domain)"],
  ["JavaScript: z velikimi crkami", "JaVaScRiPt:alert(1)"],
  ["data:", "data:text/html,<script>alert(1)</script>"],
  ["vbscript:", "vbscript:msgbox(1)"],
  ["ftp:", "ftp://klub.si/x"],
  ["mailto:", "mailto:a@b.si"],
  ["presledek v URL", "https://klub.si/a b"],
  ["nov vrstica v URL", "https://klub.si/\nx"],
  ["https brez gostitelja", "https:///x"],
  ["https: brez //", "https:klub.si"],
  ["uporabnik@ (prevara z naslovom)", "https://zaupanja.vredno.si@zlobna.si/x"],
  ["predolg (2049)", "https://klub.si/" + "a".repeat(2033)],
  ["protocol-relative", "//zlobna.si/x"],
  ["povratna poševnica (WHATWG gostitelj good.com, RFC evil.com)", "https://good.com\\@evil.com"],
  ["povratna poševnica v poti", "https://klub.si/a\\b"],
];
const ZLI_TIPI = [["stevilo", 5], ["objekt", { href: "https://klub.si" }], ["seznam", ["https://klub.si"]], ["boolean", true]];

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, friend_requests, friendships, ticket_transfers, club_invites, club_members, event_favorites, event_interest, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test",
    STRIPE_SECRET_KEY: "", STRIPE_WEBHOOK_SECRET: "", TEST_PLACILA: "", CLOUDINARY_CLOUD_NAME: "testoblak" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  try {
    const imena = ["lastnik", "novi1", "novi2", "admin", "klubi", "obiskovalec", "manager", "vratar"];
    const T = {};
    imena.forEach((k, i) => { T[k] = zeton(`${k}@outly.si`, uuid(i + 1)); });
    for (const k of imena) await api("GET", "/me", T[k]);   // prvi klic ustvari vrstico
    await pool.query("UPDATE users SET role='business' WHERE email IN ('lastnik@outly.si','novi1@outly.si','novi2@outly.si')");
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) SELECT id, 'Lastnikov klub', 'Ljubljana' FROM users WHERE email='lastnik@outly.si'");
    const klubId = (await pool.query("SELECT id FROM clubs WHERE name='Lastnikov klub'")).rows[0].id;
    await pool.query("INSERT INTO club_members (club_id, user_id, role) SELECT $1, id, 'manager' FROM users WHERE email='manager@outly.si'", [klubId]);
    await pool.query("INSERT INTO club_members (club_id, user_id, role) SELECT $1, id, 'doorman' FROM users WHERE email='vratar@outly.si'", [klubId]);
    const klub = async () => (await pool.query("SELECT name, logo_url, banner_url, website, instagram, gallery_urls, video_url FROM clubs WHERE id=$1", [klubId])).rows[0];
    const stKlubov = async () => (await pool.query("SELECT COUNT(*)::int AS n FROM clubs")).rows[0].n;
    const stDogodkov = async () => (await pool.query("SELECT COUNT(*)::int AS n FROM events")).rows[0].n;
    const dogodekVBazi = async (id) => (await pool.query("SELECT title, poster_url, ticket_url, recap_video_url FROM events WHERE id=$1", [id])).rows[0];
    const cezTeden = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();

    console.log("\n# 1. PATCH /business/clubs/me");
    const polja = [["logo_url", "logoUrl"], ["banner_url", "bannerUrl"], ["website", "website"], ["instagram", "instagram"]];
    let pred = JSON.stringify(await klub());
    for (const [stolpec, camel] of polja) {
      for (const [ime, v] of ZLI) {
        const r = await api("PATCH", "/business/clubs/me", T.lastnik, { [stolpec]: v });
        assert(jeInvalidUrl(r, stolpec), `${stolpec}: ${ime} -> 400 invalid_url`, r);
      }
      for (const [ime, v] of ZLI_TIPI) {
        const r = await api("PATCH", "/business/clubs/me", T.lastnik, { [stolpec]: v });
        assert(jeInvalidUrl(r, stolpec), `${stolpec}: ${ime} namesto niza -> 400 invalid_url`, r);
      }
    }
    for (const camel of ["logoUrl", "bannerUrl"]) {
      const r = await api("PATCH", "/business/clubs/me", T.lastnik, { [camel]: "javascript:alert(1)" });
      assert(jeInvalidUrl(r, camel === "logoUrl" ? "logo_url" : "banner_url"), `camelCase ${camel}: javascript: -> 400 invalid_url`, r);
    }
    let r = await api("PATCH", "/business/clubs/me", T.lastnik, { website: "N/A" });
    assert(jeInvalidUrl(r, "website"), "website `N/A` (brez piko v imenu gostitelja) -> 400", r);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { website: "klub.si\\@evil.com" });
    assert(jeInvalidUrl(r, "website"), "website brez sheme z `\\` -> 400", r);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { instagram: "<img src=x onerror=alert(1)>" });
    assert(jeInvalidUrl(r, "instagram"), "instagram z HTML -> 400", r);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { instagram: "a".repeat(31) });
    assert(jeInvalidUrl(r, "instagram"), "instagram: uporabnisko ime 31 znakov -> 400", r);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { name: "Ne sme se zapisati", city: "Maribor", website: "javascript:alert(1)" });
    assert(jeInvalidUrl(r, "website"), "veljavna polja + neveljaven website -> 400", r);
    assert(JSON.stringify(await klub()) === pred, "po zavrnjenih zahtevkih je klub nespremenjen", await klub());
    assert((await pool.query("SELECT city FROM clubs WHERE id=$1", [klubId])).rows[0].city === "Ljubljana", "mesto iz zavrnjenega zahtevka se ni zapisalo");

    // Ze preverjena polja (https, 500 znakov) ostanejo zavrnjena.
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { galleryUrls: ["javascript:alert(1)"] });
    assert(r.status === 400, "galleryUrls z javascript: -> 400 (ze prej)", r);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { videoUrl: "data:video/mp4;base64,AAAA" });
    assert(r.status === 400, "videoUrl z data: -> 400 (ze prej)", r);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { galleryUrls: ["http://klub.si/a.jpg"] });
    assert(r.status === 400, "galleryUrls samo https (http -> 400, kot doslej)", r);

    r = await api("PATCH", "/business/clubs/me", T.lastnik, { website: "https://www.klub.si/o-nas?a=1#b", logo_url: "https://res.cloudinary.com/testoblak/image/upload/v1/logo.jpg", bannerUrl: "http://stara.si/b.png", instagram: "@velvet.lj" });
    assert(r.status === 200 && r.body.website === "https://www.klub.si/o-nas?a=1#b" && r.body.logo_url.endsWith("/logo.jpg") && r.body.banner_url === "http://stara.si/b.png" && r.body.instagram === "@velvet.lj",
      "veljavni https/http URL-ji in @uporabnisko_ime se shranijo", r.body);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { website: "  www.klub.si  " });
    assert(r.status === 200 && r.body.website === "https://www.klub.si", "website `www.klub.si` (iOS ne preverja) -> https://www.klub.si", r.body);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { website: "klub.si:8080/x" });
    assert(r.status === 200 && r.body.website === "https://klub.si:8080/x", "website `klub.si:8080/x` je gostitelj z vrati, ne shema", r.body);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { instagram: "instagram.com/velvet.lj" });
    assert(r.status === 200 && r.body.instagram === "https://instagram.com/velvet.lj", "instagram `instagram.com/velvet.lj` -> https://", r.body);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { instagram: "https://instagram.com/velvet.lj" });
    assert(r.status === 200 && r.body.instagram === "https://instagram.com/velvet.lj", "instagram https povezava ostane", r.body);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { instagram: "velvet_lj" });
    assert(r.status === 200 && r.body.instagram === "velvet_lj", "instagram golo uporabnisko ime ostane, kot je (obstojeca logika)", r.body);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { website: null, logo_url: "", instagram: "" });
    assert(r.status === 200 && r.body.website === "" && r.body.logo_url === "" && r.body.instagram === "", "null in prazen niz brisata (shrani se \"\")", r.body);
    // iOS vnos »-« bere kot »kontakta ni« (ClubView ClubContact.cisto) in ga zapise lokalno pred klicem: strezniku pomeni brisanje, ne 400.
    await pool.query("UPDATE clubs SET website='https://klub.si', instagram='@velvet.lj' WHERE id=$1", [klubId]);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { website: " - ", instagram: "-", city: "Ljubljana" });
    assert(r.status === 200 && r.body.website === "" && r.body.instagram === "", "website in instagram `-` (po obrezovanju) = brisanje (\"\")", r.body);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { logo_url: "-" });
    assert(jeInvalidUrl(r, "logo_url"), "logo_url `-` ni »prazen znak« (samo website in instagram) -> 400", r);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { website: "—" });
    assert(jeInvalidUrl(r, "website"), "website `—` (iOS ga ne pozna kot prazen znak) -> 400", r);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { name: "Lastnikov klub", contact_email: "a@klub.si" });
    assert(r.status === 200, "zahtevek brez URL polj dela kot prej", r);

    console.log("\n# 2. Stari neveljavni zapis (mimo API-ja)");
    await pool.query("UPDATE clubs SET website='javascript:stari()', logo_url='data:image/png;base64,AAAA' WHERE id=$1", [klubId]);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { name: "Preimenovan", website: "javascript:stari()", logo_url: "data:image/png;base64,AAAA", instagram: "" });
    assert(r.status === 200 && r.body.name === "Preimenovan", "nespremenjen stari zapis NE blokira shranjevanja drugih polj (iOS ob vsakem shranjevanju posle vse)", r);
    assert((await klub()).website === "javascript:stari()", "stari zapis se ne cisti (brez migracije)", await klub());
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { website: "javascript:drug()" });
    assert(jeInvalidUrl(r, "website"), "sprememba stare vrednosti v drugo neveljavno -> 400", r);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { website: "klub.si" });
    assert(r.status === 200 && r.body.website === "https://klub.si", "popravek stare vrednosti v veljavno dela", r.body);

    console.log("\n# 3. POST /clubs");
    let klubovPred = await stKlubov();
    for (const [stolpec, camel] of polja) {
      for (const [ime, v] of ZLI.slice(0, 4)) {
        r = await api("POST", "/clubs", T.novi1, { name: "Zli klub", city: "Ljubljana", [camel]: v });
        assert(jeInvalidUrl(r, stolpec), `POST /clubs ${camel}: ${ime} -> 400 invalid_url`, r);
      }
    }
    r = await api("POST", "/clubs", T.novi1, { name: "Zli klub", city: "Ljubljana", logoUrl: 5 });
    assert(jeInvalidUrl(r, "logo_url"), "POST /clubs logoUrl: stevilo -> 400", r);
    assert(await stKlubov() === klubovPred, "zavrnjeni zahtevki niso ustvarili kluba", await stKlubov());
    r = await api("POST", "/clubs", T.novi1, { name: "Dober klub", city: "Maribor", logoUrl: "https://res.cloudinary.com/testoblak/image/upload/v1/l.jpg", bannerUrl: "", website: "www.dober.si", instagram: "@dober" });
    assert(r.status === 201 && r.body.website === "https://www.dober.si" && r.body.instagram === "@dober" && r.body.logo_url.endsWith("/l.jpg") && r.body.banner_url === "", "veljaven klub: website dobi https://", r.body);
    r = await api("POST", "/clubs", T.novi2, { name: "Brez URL-jev", city: "Maribor", website: "-", instagram: "-" });
    assert(r.status === 201 && r.body.website === "" && r.body.logo_url === "", "POST /clubs: website/instagram `-` = prazno, brez URL polj dela kot prej", r.body);

    console.log("\n# 3b. Vloge na PATCH /business/clubs/me (nova veja): manager sme, vratar 403, brez zetona 401");
    r = await api("PATCH", "/business/clubs/me", T.manager, { website: "javascript:alert(1)" });
    assert(jeInvalidUrl(r, "website"), "manager: neveljaven URL -> 400 invalid_url (vloga manager sme urejati)", r);
    r = await api("PATCH", "/business/clubs/me", T.manager, { website: "www.manager.si" });
    assert(r.status === 200 && r.body.website === "https://www.manager.si", "manager: veljaven website -> 200, normaliziran", r);
    r = await api("PATCH", "/business/clubs/me", T.vratar, { website: "https://vratar.si" });
    assert(r.status === 403, "vratar (doorman): 403, URL se ne zapise", r);
    r = await api("PATCH", "/business/clubs/me", T.vratar, { website: "javascript:alert(1)" });
    assert(r.status === 403, "vratar: neveljaven URL -> 403 (vloga pred validacijo)", r);
    r = await api("PATCH", "/business/clubs/me", null, { website: "https://anon.si" });
    assert(r.status === 401, "brez zetona: 401", r);
    assert((await klub()).website === "https://www.manager.si", "po 403/401 je website nespremenjen", await klub());

    console.log("\n# 4. POST /events");
    const dogodek = (extra) => ({ clubId: klubId, title: "Zabava", startAt: cezTeden, ...extra });
    let dogPred = await stDogodkov();
    for (const [ime, v] of ZLI) {
      r = await api("POST", "/events", T.lastnik, dogodek({ ticketUrl: v }));
      assert(jeInvalidUrl(r, "ticket_url"), `ticketUrl: ${ime} -> 400 invalid_url`, r);
      r = await api("POST", "/events", T.lastnik, dogodek({ posterUrl: v }));
      assert(jeInvalidUrl(r, "poster_url"), `posterUrl: ${ime} -> 400 invalid_url`, r);
    }
    for (const [ime, v] of ZLI_TIPI) {
      r = await api("POST", "/events", T.lastnik, dogodek({ ticket_url: v }));
      assert(jeInvalidUrl(r, "ticket_url"), `ticket_url (snake_case): ${ime} namesto niza -> 400`, r);
    }
    r = await api("POST", "/events", T.lastnik, dogodek({ ticket_url: "javascript:alert(1)", poster_url: "javascript:alert(2)" }));
    assert(jeInvalidUrl(r, "poster_url") || jeInvalidUrl(r, "ticket_url"), "snake_case ticket_url/poster_url z javascript: -> 400", r);
    r = await api("POST", "/events", T.lastnik, dogodek({ ticketUrl: "www.vstopnice.si" }));
    assert(jeInvalidUrl(r, "ticket_url"), "ticketUrl brez sheme -> 400 (iOS in splet ga ne pustita, strezniku ni treba ugibati)", r);
    assert(await stDogodkov() === dogPred, "zavrnjeni zahtevki niso ustvarili dogodka", await stDogodkov());
    r = await api("POST", "/events", T.lastnik, dogodek({ ticketUrl: " https://vstopnice.si/e/1?x=1 ", posterUrl: "https://res.cloudinary.com/testoblak/image/upload/v1/p.jpg" }));
    assert(r.status === 201 && r.body.ticket_url === "https://vstopnice.si/e/1?x=1" && r.body.poster_url.endsWith("/p.jpg"), "veljaven ticketUrl + posterUrl (trim)", r.body);
    const ev = r.body.id;
    r = await api("POST", "/events", T.lastnik, dogodek({ ticket_url: "http://vstopnice.si/e/2" }));
    assert(r.status === 201 && r.body.ticket_url === "http://vstopnice.si/e/2", "snake_case ticket_url, http", r.body);
    r = await api("POST", "/events", T.lastnik, dogodek({ ticketUrl: "", posterUrl: "" }));
    assert(r.status === 201 && r.body.ticket_url === "" && r.body.poster_url === "", "prazna niza dovoljena", r.body);
    r = await api("POST", "/events", T.lastnik, dogodek({}));
    assert(r.status === 201 && r.body.ticket_url === "" && r.body.poster_url === "", "brez URL polj dela kot prej", r.body);

    console.log("\n# 5. PATCH /events/:id");
    for (const [ime, v] of ZLI) {
      r = await api("PATCH", `/events/${ev}`, T.lastnik, { title: "Ne sme se zapisati", ticketUrl: v });
      assert(jeInvalidUrl(r, "ticket_url"), `ticketUrl: ${ime} -> 400 invalid_url`, r);
      r = await api("PATCH", `/events/${ev}`, T.lastnik, { poster_url: v });
      assert(jeInvalidUrl(r, "poster_url"), `poster_url: ${ime} -> 400 invalid_url`, r);
    }
    for (const [ime, v] of ZLI_TIPI) {
      r = await api("PATCH", `/events/${ev}`, T.lastnik, { posterUrl: v });
      assert(jeInvalidUrl(r, "poster_url"), `posterUrl: ${ime} namesto niza -> 400`, r);
    }
    let e = await dogodekVBazi(ev);
    assert(e.title === "Zabava" && e.ticket_url === "https://vstopnice.si/e/1?x=1", "zavrnjeni zahtevki niso nic zapisali", e);
    r = await api("PATCH", `/events/${ev}`, T.lastnik, { recapVideoUrl: "javascript:alert(1)" });
    assert(r.status === 400, "recapVideoUrl z javascript: -> 400 (ze prej)", r);
    r = await api("PATCH", `/events/${ev}`, T.lastnik, { title: "Nova zabava", ticketUrl: "https://vstopnice.si/e/3", posterUrl: "" });
    assert(r.status === 200 && r.body.title === "Nova zabava" && r.body.ticket_url === "https://vstopnice.si/e/3" && r.body.poster_url === "", "veljaven PATCH", r.body);
    r = await api("PATCH", `/events/${ev}`, T.lastnik, { ticketUrl: "" });
    assert(r.status === 200 && r.body.ticket_url === "", "ticketUrl \"\" brise", r.body);
    await pool.query("UPDATE events SET ticket_url='javascript:staro()', poster_url='data:image/png;base64,AAAA' WHERE id=$1", [ev]);
    r = await api("PATCH", `/events/${ev}`, T.lastnik, { title: "Spet nova", ticketUrl: "javascript:staro()", posterUrl: "data:image/png;base64,AAAA" });
    assert(r.status === 200 && r.body.title === "Spet nova", "nespremenjen stari zapis NE blokira urejanja dogodka", r);
    e = await dogodekVBazi(ev);
    assert(e.ticket_url === "javascript:staro()" && e.poster_url === "data:image/png;base64,AAAA", "stari zapis se ne cisti", e);
    r = await api("PATCH", `/events/${ev}`, T.lastnik, { ticketUrl: "javascript:drugo()" });
    assert(jeInvalidUrl(r, "ticket_url"), "sprememba stare vrednosti v drugo neveljavno -> 400", r);

    console.log("\n# 6. Admin");
    const stKlubovPredAdmin = await stKlubov();
    for (const [stolpec, camel] of polja) {
      for (const [ime, v] of ZLI.slice(0, 4)) {
        r = await api("POST", "/admin/api/clubs", T.admin, { ownerEmail: "novi2@outly.si", name: "Admin zli", [camel]: v });
        assert(jeInvalidUrl(r, stolpec), `POST /admin/api/clubs ${camel}: ${ime} -> 400 invalid_url`, r);
      }
    }
    r = await api("POST", "/admin/api/clubs", T.admin, { ownerEmail: "novi2@outly.si", name: "Admin zli", logo_url: "ftp://x.si/l.png" });
    assert(jeInvalidUrl(r, "logo_url"), "POST /admin/api/clubs logo_url (snake_case) ftp: -> 400", r);
    assert(await stKlubov() === stKlubovPredAdmin, "admin: zavrnjeni zahtevki niso ustvarili kluba", await stKlubov());
    // novi2 ima ze klub (Brez URL-jev) -> za veljavni POST rabimo uporabnika brez kluba
    r = await api("POST", "/admin/api/clubs", T.admin, { ownerEmail: "klubi@outly.si", name: "Admin dober", city: "Celje", website: "www.admin.si", logoUrl: "https://res.cloudinary.com/testoblak/image/upload/v1/a.jpg", instagram: "@admin" });
    assert(r.status === 201 && r.body.website === "https://www.admin.si" && r.body.instagram === "@admin", "admin POST: veljavni URL-ji, website dobi https://", r.body);
    const adminKlub = r.body.id;
    for (const [stolpec, camel] of polja) {
      for (const [ime, v] of ZLI.slice(0, 4)) {
        r = await api("PATCH", `/admin/api/clubs/${klubId}`, T.admin, { [camel]: v });
        assert(jeInvalidUrl(r, stolpec), `PATCH /admin/api/clubs ${camel}: ${ime} -> 400 invalid_url`, r);
      }
    }
    await pool.query("UPDATE clubs SET website='javascript:stari()', banner_url='javascript:banner()' WHERE id=$1", [adminKlub]);
    // Admin panel ob shranjevanju poslje cel obrazec, vkljucno s starimi vrednostmi.
    r = await api("PATCH", `/admin/api/clubs/${adminKlub}`, T.admin, { name: "Admin preimenovan", website: "javascript:stari()", bannerUrl: "javascript:banner()", logoUrl: "https://res.cloudinary.com/testoblak/image/upload/v1/a.jpg", instagram: "@admin" });
    assert(r.status === 200 && r.body.name === "Admin preimenovan", "admin: nespremenjen stari zapis ne blokira polnega obrazca", r);
    assert((await pool.query("SELECT website FROM clubs WHERE id=$1", [adminKlub])).rows[0].website === "javascript:stari()", "admin: stari zapis se ne cisti");
    r = await api("PATCH", `/admin/api/clubs/${adminKlub}`, T.admin, { website: "javascript:novo()" });
    assert(jeInvalidUrl(r, "website"), "admin: sprememba v drugo neveljavno -> 400", r);
    r = await api("PATCH", `/admin/api/clubs/${adminKlub}`, T.admin, { website: "admin.si", bannerUrl: null });
    assert(r.status === 200 && r.body.website === "https://admin.si" && r.body.banner_url === "", "admin: popravek v veljavno + null brise", r.body);

    console.log("\n# 7. Kontrola: PATCH /me/avatar");
    r = await api("PATCH", "/me/avatar", T.obiskovalec, { avatarUrl: "javascript:alert(1)" });
    assert(r.status === 400, "avatar: javascript: -> 400", r);
    r = await api("PATCH", "/me/avatar", T.obiskovalec, { avatarUrl: "https://zlobna.si/a.png" });
    assert(r.status === 400, "avatar: tuj https -> 400 (samo Cloudinary)", r);
    r = await api("PATCH", "/me/avatar", T.obiskovalec, { avatarUrl: "https://res.cloudinary.com/testoblak/image/upload/v1/a.png" });
    assert(r.status === 200, "avatar: Cloudinary -> 200", r);
  } catch (e) {
    fail++; console.log("  ✗ izjema:", e && e.stack || e); console.log(log.slice(-1500));
  } finally {
    // Pocakaj, da se proces res konca (sicer stari streznik na istem portu odgovarja naslednjemu zagonu in zavrne nove zetone).
    await new Promise(r => { if (srv.exitCode !== null) return r(); srv.once("exit", r); srv.kill(); setTimeout(r, 5000); });
    jwksServer.close(); await pool.end().catch(() => {});
  }
  console.log(`\n${ok} ✓, ${fail} ✗`);
  process.exit(fail ? 1 : 0);
})();
