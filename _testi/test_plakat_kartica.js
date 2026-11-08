#!/usr/bin/env node
/**
 * Drugi banner dogodka: majhen 3:4 `poster_card_url` (migracija 074, outly-backend#400). `poster_url` ostane velik banner 4:5.
 * Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres@localhost:5432/outly" node _testi/test_plakat_kartica.js
 * Vzorec kot test_vabila.js: lokalni JWKS (6451), backend na svojem portu (6450), testni nacin placil (brez Stripa).
 *
 *  K1  vnos: POST /events in PATCH /events/:id sprejmeta posterCardUrl in poster_card_url; preverjanje enako kot poster_url (javascript:, ftp:, presledki, neniz -> 400 invalid_url);
 *      '' in null brisata; izpuscen kljuc ne spremeni; urejanje poster_url ne dotakne poster_card_url; neveljaven PATCH ne spremeni nicesar
 *  K2  izhod: poster_card_url (niz, nikoli null) v GET /events, ?lite=true, GET /events/:id, GET /search, GET /business/events, GET /me/favorites, GET /me/orders, POST /events/:id/orders
 *      (order), GET /me/tickets, GET /admin/api/events (seznam) in GET /admin/api/events/:id
 *  K3  podvajanje (admin): kopija dobi poster_card_url izvora; neveljaven zapis v bazi se ne kopira ('')
 *  K4  stari zapisi (brez majhnega bannerja) dajo '' (ne null, ne izpuscenega polja)
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 6450, JWKS_PORT = 6451;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-plakat-kartica";
const jwksServer = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url.startsWith("/auth/v1/user")) { try { const t = JSON.parse(Buffer.from(String(req.headers.authorization).split(".")[1], "base64url")); return res.end(JSON.stringify({ id: t.sub, email: t.email, email_confirmed_at: new Date().toISOString() })); } catch { return res.end("{}"); } }
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
async function api(method, path, token, telo, glave) {
  const r = await fetch(BASE + path, { method, headers: { ...(token ? { authorization: "Bearer " + token } : {}), ...(telo !== undefined ? { "content-type": "application/json" } : {}), ...(glave || {}) },
    body: telo === undefined ? undefined : JSON.stringify(telo) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, text: t };
}

const VELIK = "https://res.cloudinary.com/outlytest/image/upload/v1/velik.jpg";
const KARTICA = "https://res.cloudinary.com/outlytest/image/upload/v1/kartica.jpg";
const KARTICA2 = "https://res.cloudinary.com/outlytest/image/upload/v2/kartica2.jpg";
const NEVELJAVNI = ["javascript:alert(1)", "data:text/html;base64,PHNjcmlwdD4=", "ftp://tuj.si/k.jpg", "https://dober.si/k.jpg x", "https://uporabnik:geslo@tuj.si/k.jpg", "//tuj.si/k.jpg", "https://tuj.si/" + "a".repeat(2100)];

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise((r) => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test", ADMIN_NADZOR_PREDPOMNILNIK_MS: "0" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", (d) => log += d); srv.stderr.on("data", (d) => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise((r) => setTimeout(r, 100)); } }

  try {
    const T = { lastnik: zeton("lastnik@outly.si", uuid(1)), ana: zeton("ana@outly.si", uuid(2)), admin: zeton("admin@outly.si", uuid(3)) };
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana')");
    const polnoleten = new Date(Date.now() - 25 * 365.25 * 24 * 3600 * 1000).toISOString().slice(0, 10);
    let r = await api("PATCH", "/me", T.ana, { dateOfBirth: polnoleten, genres: ["house"] });
    assert(r.status === 200, "ana nastavi datum rojstva", r.body);
    const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    const stolpec = async (id) => (await pool.query("SELECT poster_url, poster_card_url FROM events WHERE id = $1", [id])).rows[0];

    console.log("\n# K1 vnos: POST /events");
    r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Z obema", startAt: cezDan, ticketPriceCents: 1500, capacity: 100, minAge: 0, posterUrl: VELIK, posterCardUrl: KARTICA });
    assert(r.status === 201 && r.body.poster_url === VELIK && r.body.poster_card_url === KARTICA, "posterUrl + posterCardUrl (camelCase) shranjena", r.body);
    const E1 = r.body.id;
    r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Snake", startAt: cezDan, poster_url: VELIK, poster_card_url: KARTICA2 });
    assert(r.status === 201 && r.body.poster_card_url === KARTICA2, "poster_card_url (snake_case) shranjena", r.body);
    r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Brez kartice", startAt: cezDan, posterUrl: VELIK });
    assert(r.status === 201 && r.body.poster_card_url === "" && r.body.poster_url === VELIK, "brez posterCardUrl -> '' (niz, ne null)", r.body);
    const E_BREZ = r.body.id;
    r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Null kartica", startAt: cezDan, posterCardUrl: null });
    assert(r.status === 201 && r.body.poster_card_url === "", "posterCardUrl null -> ''", r.body);
    for (const slab of NEVELJAVNI) {
      const kartica = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Slab", startAt: cezDan, posterCardUrl: slab });
      const velik = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Slab", startAt: cezDan, posterUrl: slab });
      assert(kartica.status === 400 && velik.status === 400 && kartica.body.error === "invalid_url" && kartica.body.field === "poster_card_url" && velik.body.field === "poster_url" &&
        kartica.body.message === velik.body.message.replace("poster_url", "poster_card_url"), `POST: ${slab.slice(0, 40)} -> 400 invalid_url (enako kot poster_url, field poster_card_url)`, [kartica.status, kartica.body, velik.body]);
    }
    r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Neniz", startAt: cezDan, posterCardUrl: 123 });
    assert(r.status === 400 && r.body.error === "invalid_url" && r.body.field === "poster_card_url", "POST: posterCardUrl ni niz -> 400 invalid_url", r.body);
    r = await api("POST", "/events", T.ana, { clubId: 1, title: "Tuj", startAt: cezDan, posterCardUrl: KARTICA });
    assert(r.status === 403, "navaden uporabnik ne more ustvariti dogodka s karticami -> 403", r.status);
    assert((await pool.query("SELECT COUNT(*)::int AS n FROM events")).rows[0].n === 4, "neveljavni zahtevki niso ustvarili dogodkov (4 veljavni)");

    console.log("\n# K1 vnos: PATCH /events/:id");
    r = await api("PATCH", `/events/${E_BREZ}`, T.lastnik, { posterCardUrl: KARTICA });
    assert(r.status === 200 && r.body.poster_card_url === KARTICA && r.body.poster_url === VELIK, "PATCH posterCardUrl nastavi karticu, poster_url ostane", r.body);
    r = await api("PATCH", `/events/${E_BREZ}`, T.lastnik, { poster_card_url: KARTICA2 });
    assert(r.status === 200 && r.body.poster_card_url === KARTICA2, "PATCH poster_card_url (snake_case)", r.body);
    r = await api("PATCH", `/events/${E_BREZ}`, T.lastnik, { title: "Preimenovan" });
    assert(r.status === 200 && (await stolpec(E_BREZ)).poster_card_url === KARTICA2, "PATCH brez posterCardUrl ga ne spremeni");
    r = await api("PATCH", `/events/${E_BREZ}`, T.lastnik, { posterUrl: VELIK + "?x=1".replace("?", "") });
    assert(r.status === 200 && (await stolpec(E_BREZ)).poster_card_url === KARTICA2, "PATCH samo posterUrl ne dotakne poster_card_url");
    for (const slab of NEVELJAVNI) {
      r = await api("PATCH", `/events/${E_BREZ}`, T.lastnik, { posterCardUrl: slab, title: "Ne sme se spremeniti" });
      assert(r.status === 400 && r.body.error === "invalid_url" && r.body.field === "poster_card_url", `PATCH: ${slab.slice(0, 40)} -> 400 invalid_url`, [r.status, r.body]);
    }
    const po400 = (await pool.query("SELECT title, poster_card_url FROM events WHERE id = $1", [E_BREZ])).rows[0];
    assert(po400.title === "Preimenovan" && po400.poster_card_url === KARTICA2, "neveljaven PATCH ni spremenil nicesar", po400);
    r = await api("PATCH", `/events/${E_BREZ}`, T.lastnik, { posterCardUrl: "" });
    assert(r.status === 200 && r.body.poster_card_url === "" && (await stolpec(E_BREZ)).poster_card_url === "", "PATCH '' brise majhen banner");
    await api("PATCH", `/events/${E_BREZ}`, T.lastnik, { posterCardUrl: KARTICA });
    // null je v telesu PATCH enak kot pri poster_url (`??`): kljuc se obravnava kot izpuscen. Brisanje je '' (kot pri poster_url).
    const nullKartica = await api("PATCH", `/events/${E_BREZ}`, T.lastnik, { posterCardUrl: null });
    const nullVelik = await api("PATCH", `/events/${E_BREZ}`, T.lastnik, { posterUrl: null });
    assert(nullKartica.status === nullVelik.status && (await stolpec(E_BREZ)).poster_card_url === KARTICA, "PATCH null: enako kot pri posterUrl (brez spremembe)", [nullKartica.status, nullVelik.status]);
    await api("PATCH", `/events/${E_BREZ}`, T.lastnik, { posterCardUrl: "" });
    r = await api("PATCH", `/events/${E_BREZ}`, T.ana, { posterCardUrl: KARTICA });
    assert(r.status === 403 && (await stolpec(E_BREZ)).poster_card_url === "", "tuj uporabnik ne more urediti -> 403", [r.status, r.body]);
    r = await api("PATCH", `/events/${E_BREZ}`, T.admin, { posterCardUrl: KARTICA });
    assert(r.status === 200 && r.body.poster_card_url === KARTICA, "admin uredi posterCardUrl (PATCH /events/:id, pot admin panela)", r.body);
    const dn = (await pool.query("SELECT prej, potem FROM admin_dejanja WHERE cilj_tip = 'event' AND cilj_id = $1 ORDER BY id DESC LIMIT 1", [String(E_BREZ)])).rows[0];
    assert(dn && dn.potem && dn.potem.poster_card_url === KARTICA && dn.prej && dn.prej.poster_card_url === "", "admin dnevnik: prej '' -> potem URL", dn);

    console.log("\n# K2 izhod: javni seznami in podrobnosti");
    await pool.query("UPDATE events SET poster_card_url = $2 WHERE id = $1", [E1, KARTICA]);
    await pool.query("UPDATE events SET poster_card_url = '' WHERE id = $1", [E_BREZ]);
    const poId = (telo, id) => (Array.isArray(telo) ? telo : telo.events || telo.items || []).find((e) => e.id === id);
    r = await api("GET", "/events");
    let e = poId(r.body, E1), eb = poId(r.body, E_BREZ);
    assert(r.status === 200 && e && e.poster_card_url === KARTICA && e.poster_url === VELIK, "GET /events: poster_card_url (in poster_url nespremenjen)", e);
    assert(eb && eb.poster_card_url === "", "GET /events: dogodek brez majhnega bannerja -> ''", eb);
    assert(r.body.every ? r.body.every((x) => typeof x.poster_card_url === "string") : (r.body.events || []).every((x) => typeof x.poster_card_url === "string"), "GET /events: poster_card_url je pri vseh niz");
    r = await api("GET", "/events?lite=true");
    e = poId(r.body, E1);
    assert(r.status === 200 && e && e.poster_card_url === KARTICA, "GET /events?lite=true: poster_card_url", e);
    r = await api("GET", `/events/${E1}`);
    assert(r.status === 200 && r.body.poster_card_url === KARTICA && r.body.poster_url === VELIK, "GET /events/:id: poster_card_url", r.body);
    r = await api("GET", `/events/${E1}`, T.ana);
    assert(r.status === 200 && r.body.poster_card_url === KARTICA, "GET /events/:id (prijavljen): poster_card_url", r.body);
    r = await api("GET", `/events/${E_BREZ}`);
    assert(r.status === 200 && r.body.poster_card_url === "", "GET /events/:id brez majhnega: ''", r.body);
    r = await api("GET", "/search?q=Z%20obema");
    const najden = (r.body.events || []).find((x) => x.id === E1);
    assert(r.status === 200 && najden && najden.poster_card_url === KARTICA, "GET /search: poster_card_url", r.body);
    r = await api("PUT", `/me/favorites/${E1}`, T.ana, {});
    r = await api("GET", "/me/favorites", T.ana);
    assert(r.status === 200 && (r.body.events || []).some((x) => x.id === E1 && x.poster_card_url === KARTICA), "GET /me/favorites: poster_card_url", r.body);

    console.log("\n# K2 izhod: poslovni seznam");
    r = await api("GET", "/business/events", T.lastnik);
    e = poId(r.body, E1);
    assert(r.status === 200 && e && e.poster_card_url === KARTICA, "GET /business/events: poster_card_url", r.body);

    console.log("\n# K2 izhod: nakup, narocila, vstopnice");
    r = await api("POST", `/events/${E1}/orders`, T.ana, { quantity: 1 });
    assert(r.status === 201 && r.body.order.poster_card_url === KARTICA && r.body.order.poster_url === VELIK, "POST /events/:id/orders: order.poster_card_url", r.body.order);
    r = await api("GET", "/me/orders", T.ana);
    const nar = (r.body.orders || r.body)[0];
    assert(r.status === 200 && nar && nar.poster_card_url === KARTICA, "GET /me/orders: poster_card_url", nar);
    r = await api("GET", "/me/tickets", T.ana);
    const vst = (r.body.tickets || r.body)[0];
    assert(r.status === 200 && vst && vst.poster_card_url === KARTICA && typeof vst.poster_card_url === "string", "GET /me/tickets: poster_card_url", vst);

    console.log("\n# K2 izhod: admin");
    r = await api("GET", "/admin/api/events", T.admin);
    e = poId(r.body, E1);
    assert(r.status === 200 && e && e.poster_card_url === KARTICA, "GET /admin/api/events: poster_card_url", r.body && Object.keys(r.body));
    r = await api("GET", `/admin/api/events/${E1}`, T.admin);
    assert(r.status === 200 && r.body.event && r.body.event.poster_card_url === KARTICA, "GET /admin/api/events/:id: event.poster_card_url", r.body && Object.keys(r.body));

    console.log("\n# K3 podvajanje");
    r = await api("POST", `/admin/api/events/${E1}/duplicate`, T.admin, { startAt: new Date(Date.now() + 10 * 24 * 3600 * 1000).toISOString() });
    assert(r.status === 201 && r.body.events.length === 1, "podvajanje 201", r.body);
    let kopija = await stolpec(r.body.events[0].id);
    assert(kopija.poster_url === VELIK && kopija.poster_card_url === KARTICA, "kopija ima poster_url in poster_card_url izvora", kopija);
    await pool.query("UPDATE events SET poster_card_url = 'javascript:alert(1)' WHERE id = $1", [E1]);   // star neveljaven zapis (mimo poti)
    r = await api("POST", `/admin/api/events/${E1}/duplicate`, T.admin, { startAt: new Date(Date.now() + 11 * 24 * 3600 * 1000).toISOString() });
    kopija = await stolpec(r.body.events[0].id);
    assert(r.status === 201 && kopija.poster_url === VELIK && kopija.poster_card_url === "", "neveljaven poster_card_url se ne kopira ('')", kopija);
    await pool.query("UPDATE events SET poster_card_url = $2 WHERE id = $1", [E_BREZ, KARTICA]);
    r = await api("POST", `/admin/api/events/${E_BREZ}/duplicate`, T.admin, { startAt: new Date(Date.now() + 12 * 24 * 3600 * 1000).toISOString() });
    assert(r.status === 201 && (await stolpec(r.body.events[0].id)).poster_card_url === KARTICA, "kopija dogodka z majhnim bannerjem ga ohrani");

    console.log("\n# K4 stari zapisi");
    await pool.query("INSERT INTO events (club_id, title, poster_url, start_at, status) VALUES (1, 'Star', $1, NOW() + INTERVAL '2 days', 'published')", [VELIK]);
    const stari = (await pool.query("SELECT id FROM events WHERE title = 'Star'")).rows[0].id;
    r = await api("GET", `/events/${stari}`);
    assert(r.status === 200 && r.body.poster_card_url === "" && r.body.poster_url === VELIK, "dogodek, vpisan brez majhnega bannerja (stari zapis): poster_card_url ''", r.body);
  } finally {
    srv.kill();
    jwksServer.close();
    await pool.end().catch(() => {});
  }
  console.log(`\n${ok} ok, ${fail} napak`);
  if (fail) { console.log(log.slice(-1500)); process.exit(1); }
})().catch((e) => { console.error(e); process.exit(1); });
