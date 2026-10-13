#!/usr/bin/env node
/**
 * Streznik validira zanre proti ZANRI na vseh petih poteh, ki jih pisejo (outly-backend, pregled #238: stored XSS prek `genres`).
 * Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_zanri_validacija.js
 * Vzorec kot test_nacrti_privzeto.js: lokalni JWKS (ES256), backend na svojem portu.
 *
 *   1  POST /clubs: <img onerror> / neznan zanr / ne-niz / ne-seznam -> 400 (unknown_genres z `unknown` in `allowed`), klub se NE ustvari;
 *      veljavni z velikimi crkami in presledki -> shranjeni normalizirano (trim, lowercase, brez podvojenih); brez `genres` -> []
 *   2  POST /events: isto; brez `genres` -> podedovani zanri kluba; dogodek se ob zavrnitvi NE ustvari
 *   3  PATCH /events/:id: isto; PATCH brez `genres` zanrov ne spremeni; `genres: []` je dovoljen
 *   4  kontrola: PATCH /me in PATCH /business/clubs/me ostaneta enaka (400 unknown_genres, normalizacija)
 *   5  seznam je omejen na ZANRI.length (22 podvojenih -> 400 Too many genres)
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 4411, JWKS_PORT = 4412;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-zanri";
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
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra).slice(0, 300) : ""); } }
async function api(method, p, token, body) {
  const r = await fetch(BASE + p, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}

const XSS = "<img src=x onerror=alert(document.domain)>";
const ZLI = [
  ["XSS niz", [XSS]],
  ["XSS poleg veljavnega", ["rock", XSS]],
  ["neznan zanr", ["polka"]],
  ["zanr izven seznama (Hip-hop != hiphop)", ["Hip-hop"]],
];

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, friend_requests, friendships, ticket_transfers, club_invites, club_members, event_favorites, event_interest, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test",
    STRIPE_SECRET_KEY: "", STRIPE_WEBHOOK_SECRET: "", TEST_PLACILA: "" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  try {
    const imena = ["lastnik", "novi1", "novi2", "novi3", "novi4", "novi5", "novi6"];
    const T = {};
    imena.forEach((k, i) => { T[k] = zeton(`${k}@outly.si`, uuid(i + 1)); });
    for (const k of imena) await api("GET", "/me", T[k]);   // prvi klic ustvari vrstico
    await pool.query("UPDATE users SET role='business' WHERE email LIKE '%@outly.si'");
    const stKlubov = async () => (await pool.query("SELECT COUNT(*)::int AS n FROM clubs")).rows[0].n;
    const stDogodkov = async () => (await pool.query("SELECT COUNT(*)::int AS n FROM events")).rows[0].n;
    const zanriKluba = async (id) => (await pool.query("SELECT genres FROM clubs WHERE id=$1", [id])).rows[0].genres;
    const zanriDogodka = async (id) => (await pool.query("SELECT genres FROM events WHERE id=$1", [id])).rows[0].genres;
    const cezTeden = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();

    console.log("\n# 1. POST /clubs");
    const dovoljeni = (await api("GET", "/genres", null)).body.genres;
    assert(Array.isArray(dovoljeni) && dovoljeni.includes("hiphop"), "GET /genres vrne seznam", dovoljeni);
    let klubovPred = await stKlubov();
    for (const [ime, zanri] of ZLI) {
      const r = await api("POST", "/clubs", T.novi1, { name: "Zli klub", city: "Ljubljana", genres: zanri });
      assert(r.status === 400 && r.body && r.body.error === "unknown_genres", `${ime}: 400 unknown_genres`, r);
      assert(r.body && Array.isArray(r.body.unknown) && r.body.unknown.length >= 1 && JSON.stringify(r.body.allowed) === JSON.stringify(dovoljeni), `${ime}: odgovor ima unknown in allowed`, r.body);
    }
    for (const [ime, zanri] of [["niz namesto seznama", "rock"], ["objekt namesto seznama", { 0: "rock" }], ["stevilo v seznamu", [5]], ["null v seznamu", [null]], ["seznam v seznamu", [["rock"]]], ["objekt v seznamu", [{ x: 1 }]]]) {
      const r = await api("POST", "/clubs", T.novi1, { name: "Zli klub", city: "Ljubljana", genres: zanri });
      assert(r.status === 400, `${ime}: 400`, r);
    }
    assert(await stKlubov() === klubovPred, "zavrnjeni zahtevki niso ustvarili kluba", await stKlubov());
    let r = await api("POST", "/clubs", T.novi1, { name: "Dober klub", city: "Ljubljana", genres: ["  Rock ", "HOUSE", "rock", "HipHop"] });
    assert(r.status === 201 && JSON.stringify(r.body.genres) === JSON.stringify(["rock", "house", "hiphop"]), "veljavni z velikimi crkami/presledki/podvojenimi -> normalizirano", r.body.genres);
    assert(JSON.stringify(await zanriKluba(r.body.id)) === JSON.stringify(["rock", "house", "hiphop"]), "v bazi je normalizirano", await zanriKluba(r.body.id));
    r = await api("POST", "/clubs", T.novi2, { name: "Brez zanrov", city: "Maribor" });
    assert(r.status === 201 && Array.isArray(r.body.genres) && r.body.genres.length === 0, "brez `genres` -> []", r.body);
    r = await api("POST", "/clubs", T.novi3, { name: "Prazen seznam", city: "Maribor", genres: [] });
    assert(r.status === 201 && r.body.genres.length === 0, "genres: [] -> []", r.body);

    r = await api("POST", "/clubs", T.novi6, { name: "Null zanri", city: "Maribor", genres: null });
    assert(r.status === 201 && r.body.genres.length === 0, "genres: null -> [] (zdruzljivost: doslej sprejeto)", r.body);

    console.log("\n# 5. Omejitev dolzine seznama");
    r = await api("POST", "/clubs", T.novi4, { name: "Predolg", city: "Ljubljana", genres: Array(dovoljeni.length + 1).fill("rock") });
    assert(r.status === 400, "POST /clubs: ZANRI.length + 1 elementov -> 400", r);

    console.log("\n# 2. POST /events");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city, genres, min_age) SELECT id, 'Lastnikov klub', 'Ljubljana', '{techno,pop}', 18 FROM users WHERE email='lastnik@outly.si'");
    const klubId = (await pool.query("SELECT id FROM clubs WHERE name='Lastnikov klub'")).rows[0].id;
    const dogodek = (extra) => ({ clubId: klubId, title: "Zabava", startAt: cezTeden, ...extra });
    let dogPred = await stDogodkov();
    for (const [ime, zanri] of ZLI) {
      r = await api("POST", "/events", T.lastnik, dogodek({ genres: zanri }));
      assert(r.status === 400 && r.body && r.body.error === "unknown_genres" && Array.isArray(r.body.unknown) && JSON.stringify(r.body.allowed) === JSON.stringify(dovoljeni), `${ime}: 400 unknown_genres z unknown in allowed`, r);
    }
    for (const [ime, zanri] of [["niz namesto seznama", "rock"], ["stevilo v seznamu", [5]], ["null v seznamu", [null]], ["null namesto seznama", null], ["seznam v seznamu", [["rock"]]]]) {
      r = await api("POST", "/events", T.lastnik, dogodek({ genres: zanri }));
      assert(r.status === 400, `${ime}: 400`, r);
    }
    r = await api("POST", "/events", T.lastnik, dogodek({ genres: Array(dovoljeni.length + 1).fill("rock") }));
    assert(r.status === 400, "ZANRI.length + 1 elementov -> 400", r);
    assert(await stDogodkov() === dogPred, "zavrnjeni zahtevki niso ustvarili dogodka", await stDogodkov());
    r = await api("POST", "/events", T.lastnik, dogodek({ genres: [" TECHNO", "Rap  ", "techno"] }));
    assert(r.status === 201 && JSON.stringify(r.body.genres) === JSON.stringify(["techno", "rap"]), "veljavni z velikimi crkami/presledki -> normalizirano", r.body.genres);
    const ev = r.body.id;
    assert(JSON.stringify(await zanriDogodka(ev)) === JSON.stringify(["techno", "rap"]), "v bazi je normalizirano", await zanriDogodka(ev));
    r = await api("POST", "/events", T.lastnik, dogodek({}));
    assert(r.status === 201 && JSON.stringify(r.body.genres) === JSON.stringify(["techno", "pop"]), "brez `genres` -> zanri kluba", r.body.genres);
    r = await api("POST", "/events", T.lastnik, dogodek({ genres: [] }));
    assert(r.status === 201 && r.body.genres.length === 0, "genres: [] -> []", r.body.genres);

    console.log("\n# 3. PATCH /events/:id");
    for (const [ime, zanri] of ZLI) {
      r = await api("PATCH", `/events/${ev}`, T.lastnik, { genres: zanri });
      assert(r.status === 400 && r.body && r.body.error === "unknown_genres" && Array.isArray(r.body.unknown) && JSON.stringify(r.body.allowed) === JSON.stringify(dovoljeni), `${ime}: 400 unknown_genres z unknown in allowed`, r);
    }
    for (const [ime, zanri] of [["niz namesto seznama", "rock"], ["stevilo v seznamu", [5]], ["null v seznamu", [null]], ["null namesto seznama", null], ["seznam v seznamu", [["rock"]]]]) {
      r = await api("PATCH", `/events/${ev}`, T.lastnik, { genres: zanri });
      assert(r.status === 400, `${ime}: 400`, r);
    }
    r = await api("PATCH", `/events/${ev}`, T.lastnik, { genres: Array(dovoljeni.length + 1).fill("rock") });
    assert(r.status === 400, "ZANRI.length + 1 elementov -> 400", r);
    assert(JSON.stringify(await zanriDogodka(ev)) === JSON.stringify(["techno", "rap"]), "po zavrnjenih zahtevkih zanri dogodka nespremenjeni", await zanriDogodka(ev));
    r = await api("PATCH", `/events/${ev}`, T.lastnik, { genres: [" House ", "POP", "house"] });
    assert(r.status === 200 && JSON.stringify(r.body.genres) === JSON.stringify(["house", "pop"]), "veljavni z velikimi crkami/presledki -> normalizirano", r.body.genres);
    assert(JSON.stringify(await zanriDogodka(ev)) === JSON.stringify(["house", "pop"]), "v bazi je normalizirano", await zanriDogodka(ev));
    r = await api("PATCH", `/events/${ev}`, T.lastnik, { title: "Novo ime" });
    assert(r.status === 200 && r.body.title === "Novo ime", "PATCH brez genres: naslov spremenjen", r.body.title);
    assert(JSON.stringify(await zanriDogodka(ev)) === JSON.stringify(["house", "pop"]), "PATCH brez `genres` zanrov NE spremeni", await zanriDogodka(ev));
    r = await api("PATCH", `/events/${ev}`, T.lastnik, { genres: [] });
    assert(r.status === 200 && (await zanriDogodka(ev)).length === 0, "genres: [] izprazni zanre", await zanriDogodka(ev));

    console.log("\n# 4. Kontrola: obstojeci poti");
    r = await api("PATCH", "/me", T.novi5, { genres: [XSS] });
    assert(r.status === 400 && r.body.error === "unknown_genres", "PATCH /me: XSS -> 400 unknown_genres", r);
    r = await api("PATCH", "/me", T.novi5, { genres: [" Rock ", "HOUSE", "rock"] });
    assert(r.status === 200 && JSON.stringify(r.body.genres) === JSON.stringify(["rock", "house"]), "PATCH /me: normalizirano", r.body.genres);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { genres: [XSS] });
    assert(r.status === 400 && r.body.error === "unknown_genres", "PATCH /business/clubs/me: XSS -> 400 unknown_genres", r);
    r = await api("PATCH", "/business/clubs/me", T.lastnik, { genres: [" Rock ", "HOUSE", "rock"] });
    assert(r.status === 200 && JSON.stringify(r.body.genres) === JSON.stringify(["rock", "house"]), "PATCH /business/clubs/me: normalizirano", r.body.genres);
  } finally {
    try { srv.kill(); } catch {}
    jwksServer.close(); await pool.end().catch(() => {});
  }
  console.log(`\n${ok} OK, ${fail} NAPAK`);
  process.exit(fail === 0 ? 0 : 1);
})().catch(e => { console.error(e); process.exit(1); });
