#!/usr/bin/env node
/**
 * Najnizja starost za uporabniski racun = 18 let (Martin, 19. 10. 2026: »18+ in racun od 18«; prej 15, ZVOP-2 8. clen).
 * Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres@localhost:5432/outly" node _testi/test_starost_racun.js
 * Vzorec kot test_vabila.js: lokalni JWKS (5792), backend na svojem portu (5791).
 *
 * Kaj ta test lovi:
 *  0. Cista funkcija polnaLeta/danesLjubljana (starost_racuna.js): stetje po LJUBLJANSKEM koledarju (ne UTC), 29. 2. kot SQL AGE (preverjeno
 *     proti Postgresu), pomozna letaNazaj na 29. 2. (»tocno 18 let« = 28. 2. pred 18 leti).
 *  1. PATCH /me z dateOfBirth: 17 let in 364 dni -> 400 »You must be at least 18 years old.«, tocno 18 let -> 200 (koledarsko, ne 365,2425).
 *  2. Stara meja 15 ne velja vec (15, 16, 17 let -> 400); datum v prihodnosti, neresnicen datum in napacna oblika kot doslej.
 *  3. Obstojec racun, ki je vpisal datum rojstva, ko je veljalo 15 (vrstica v bazi, 16 let), NI blokiran: ime, zanri, isti datum
 *     (odjemalec ob shranjevanju profila poslje vsa polja) -> 200; drug datum pod 18 -> 400; datum >= 18 in brisanje datuma -> 200.
 *  4. Tak racun se po novem ne dotakne nakupa: dogodek brez omejitve (min_age 0) -> 201, dogodek 18+ -> 403 (I8, kot doslej).
 *  5. Racun brez datuma rojstva ostane brez datuma (400 ga ne nastavi, ni dokoncan: onboarded_at NULL), s 18 letmi se dokonca.
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");
const { danesLjubljana, polnaLeta } = require("../starost_racuna");   // isti izracun »danes« kot streznik

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 5791, JWKS_PORT = 5792;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-1";
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
function uuid(n) { return `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`; }
let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
async function api(method, path, token, body) {
  const r = await fetch(BASE + path, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}

// Datum rojstva »danes minus N let (+ dni)« po LJUBLJANSKEM koledarju (isti »danes« kot streznik, starost_racuna.js).
// Brez dni: oseba je danes TOCNO `leta` stara (ima rojstni dan). 29. 2.: v neprestopnem letu pred `leta` leti 29. 2. ni; tocno `leta`
// je stara oseba, rojena 28. 2. (rojena 1. 3. je se mlajsa: SQL AGE, polnaLeta), zato »tocno« = 28. 2., »+1 dan« = 1. 3.
const iso = (d) => d.toISOString().slice(0, 10);
const jePrestopno = (l) => (l % 4 === 0 && l % 100 !== 0) || l % 400 === 0;
const dodajDni = (datum, n) => { const [l, m, d] = datum.split("-").map(Number); return iso(new Date(Date.UTC(l, m - 1, d + n))); };
function letaNazaj(leta, dniNaprej = 0, danes = danesLjubljana()) {
  const [l, m, d] = danes.split("-").map(Number);
  const cilj = l - leta;
  const dan = (m === 2 && d === 29 && !jePrestopno(cilj)) ? 28 : d;
  return dodajDni(`${cilj}-${String(m).padStart(2, "0")}-${String(dan).padStart(2, "0")}`, dniNaprej);
}
// PATCH /me z datumom ob meji. Okno okoli polnoci: ce se ljubljanski dan zamenja med izracunom datuma in odgovorom, zahtevek ponovi s
// svezim datumom (najvec 3 poskusi). Vrne tudi datum, ki ga je streznik dejansko obdelal.
async function patchDatum(zeton, leta, dni, dodatno = {}, polje = "dateOfBirth") {
  for (let poskus = 1; ; poskus++) {
    const pred = danesLjubljana();
    const datum = letaNazaj(leta, dni, pred);
    const r = await api("PATCH", "/me", zeton, { [polje]: datum, ...dodatno });
    if (danesLjubljana() === pred || poskus >= 3) return { ...r, datum };
  }
}
const mejaBesedilo = /^You must be at least 18 years old\.$/;

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  try {
    console.log("\n# 0. Cista funkcija: ljubljanski koledar in 29. 2.");
    // N1: 18. rojstni dan, ko je v Ljubljani ze nov dan, v UTC pa se ne (22:30 UTC = 00:30 CEST / 23:30 UTC = 00:30 CET).
    const polnocPoleti = new Date("2026-10-18T22:30:00Z"), polnocPozimi = new Date("2026-12-31T23:30:00Z");
    assert(danesLjubljana(polnocPoleti) === "2026-10-19", "danesLjubljana: 22:30 UTC poleti = naslednji dan v Ljubljani", danesLjubljana(polnocPoleti));
    assert(danesLjubljana(polnocPozimi) === "2027-01-01", "danesLjubljana: 23:30 UTC pozimi = naslednji dan (novo leto) v Ljubljani", danesLjubljana(polnocPozimi));
    assert(danesLjubljana(new Date("2026-10-19T12:00:00Z")) === "2026-10-19", "danesLjubljana: poldne = isti dan");
    assert(polnaLeta("2008-10-19", danesLjubljana(polnocPoleti)) === 18, "18. rojstni dan ob 00:30 po ljubljanskem casu (22:30 UTC) = 18, ne 17");
    assert(polnaLeta("2008-10-20", danesLjubljana(polnocPoleti)) === 17, "dan pred 18. rojstnim dnem = 17");
    // 29. 2.: oseba, rojena 29. 2. 2008, dopolni 18 let v neprestopnem letu 1. 3. (kot SQL AGE)
    assert(polnaLeta("2008-02-29", "2026-02-28") === 17, "rojen 29. 2. 2008: 28. 2. 2026 = 17");
    assert(polnaLeta("2008-02-29", "2026-03-01") === 18, "rojen 29. 2. 2008: 1. 3. 2026 = 18");
    assert(polnaLeta("2008-02-29", "2028-02-29") === 20, "rojen 29. 2. 2008: 29. 2. 2028 = 20 (prestopno leto)");
    assert(polnaLeta("2010-02-28", "2028-02-29") === 18 && polnaLeta("2010-03-01", "2028-02-29") === 17, "danes 29. 2. 2028: rojen 28. 2. 2010 = 18, rojen 1. 3. 2010 = 17");
    // pomozna letaNazaj na 29. 2. in ob prehodu leta
    assert(letaNazaj(18, 0, "2028-02-29") === "2010-02-28", "letaNazaj(18) na 29. 2. 2028 = 28. 2. 2010 (ne 1. 3.)", letaNazaj(18, 0, "2028-02-29"));
    assert(letaNazaj(18, 1, "2028-02-29") === "2010-03-01", "letaNazaj(18, +1) na 29. 2. 2028 = 1. 3. 2010 (17 let in 364 dni)", letaNazaj(18, 1, "2028-02-29"));
    assert(letaNazaj(4, 0, "2028-02-29") === "2024-02-29", "letaNazaj(4) na 29. 2. 2028 = 29. 2. 2024 (prestopno ciljno leto)");
    assert(letaNazaj(18, 0, "2026-03-01") === "2008-03-01" && letaNazaj(18, 1, "2026-12-31") === "2009-01-01", "letaNazaj: 1. 3. in prehod leta");
    for (const [danes, leta] of [["2028-02-29", 18], ["2026-03-01", 18], ["2026-02-28", 18], ["2027-01-01", 18], ["2024-02-29", 4], ["2026-10-19", 18]]) {
      assert(polnaLeta(letaNazaj(leta, 0, danes), danes) === leta && polnaLeta(letaNazaj(leta, 1, danes), danes) === leta - 1,
        `meja ${danes}: letaNazaj(${leta}) je tocno ${leta}, +1 dan je ${leta - 1}`);
    }
    // polnaLeta se mora ujemati s SQL AGE (starost() v bazi), na robnih datumih vkljucno z 29. 2.
    const pari = [["2008-02-29", "2026-02-28"], ["2008-02-29", "2026-03-01"], ["2008-02-29", "2028-02-29"], ["2010-02-28", "2028-02-29"], ["2010-03-01", "2028-02-29"],
      ["2008-10-19", "2026-10-19"], ["2008-10-20", "2026-10-19"], ["2000-12-31", "2018-12-30"], ["2000-12-31", "2018-12-31"], ["2012-02-29", "2030-02-28"], ["2012-02-29", "2030-03-01"]];
    let razlike = [];
    for (const [rojstvo, danes] of pari) {
      const sql = (await pool.query("SELECT EXTRACT(YEAR FROM AGE($1::date, $2::date))::int AS leta", [danes, rojstvo])).rows[0].leta;
      if (sql !== polnaLeta(rojstvo, danes)) razlike.push({ rojstvo, danes, sql, js: polnaLeta(rojstvo, danes) });
    }
    assert(razlike.length === 0, `polnaLeta se ujema s SQL AGE na ${pari.length} robnih parih`, razlike);

    const T = {
      lastnik: zeton("lastnik@outly.si", uuid(1)),
      nov: zeton("nov@outly.si", uuid(2)),          // nov racun: datum rojstva se sele nastavlja
      star: zeton("star@outly.si", uuid(3)),        // obstojec racun, 16 let, vpisan ob meji 15
      odrasel: zeton("odrasel@outly.si", uuid(4)),
    };
    for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
    await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana')");
    const dobBaza = async (email) => (await pool.query("SELECT to_char(date_of_birth,'YYYY-MM-DD') AS d, onboarded_at FROM users WHERE email=$1", [email])).rows[0];

    console.log("\n# 1. Nov racun: meja 18 let (koledarsko)");
    let r = await patchDatum(T.nov, 18, 1, { genres: ["house"] });
    assert(r.status === 400 && mejaBesedilo.test(r.body), "17 let in 364 dni -> 400 »You must be at least 18 years old.«", r);
    let b = await dobBaza("nov@outly.si");
    assert(b.d === null && b.onboarded_at === null, "po zavrnitvi datum rojstva ni vpisan in racun ni dokoncan", b);
    r = await patchDatum(T.nov, 18, 0);
    assert(r.status === 200, "tocno 18 let (rojstni dan danes po ljubljanskem koledarju) -> 200", r);
    b = await dobBaza("nov@outly.si");
    assert(b.d === r.datum, "datum rojstva vpisan v bazo", [b, r.datum]);
    r = await api("PATCH", "/me", T.nov, { genres: ["house"] });
    assert(r.status === 200 && r.body.onboarded_at, "s 18 leti in zanrom je racun dokoncan (onboarded_at)", r.body);

    console.log("\n# 2. Stara meja 15 ne velja vec; ostali robni primeri kot doslej");
    for (const [leta, dni] of [[15, 0], [16, 0], [17, 0], [14, 0], [5, 0]]) {
      r = await api("PATCH", "/me", T.odrasel, { dateOfBirth: letaNazaj(leta, dni) });
      assert(r.status === 400 && mejaBesedilo.test(r.body), `${leta} let -> 400`, r);
    }
    r = await patchDatum(T.odrasel, 18, 1, {}, "date_of_birth");
    assert(r.status === 400 && mejaBesedilo.test(r.body), "snake_case date_of_birth: 17 let in 364 dni -> 400 (isto polje)", r);
    r = await api("PATCH", "/me", T.odrasel, { dateOfBirth: letaNazaj(17, 1) });
    assert(r.status === 400, "16 let in 364 dni -> 400", r);
    r = await api("PATCH", "/me", T.odrasel, { dateOfBirth: iso(new Date(Date.now() + 2 * 24 * 3600 * 1000)) });
    assert(r.status === 400 && /future/.test(r.body), "datum v prihodnosti -> 400 (kot doslej)", r);
    r = await api("PATCH", "/me", T.odrasel, { dateOfBirth: "2000-02-31" });
    assert(r.status === 400, "neresnicen koledarski datum (31. 2.) -> 400, ne 500", r);
    r = await api("PATCH", "/me", T.odrasel, { dateOfBirth: "13.01.2000" });
    assert(r.status === 400, "napacna oblika -> 400", r);
    b = await dobBaza("odrasel@outly.si");
    assert(b.d === null, "nobena zavrnitev ni vpisala datuma", b);
    r = await api("PATCH", "/me", T.odrasel, { dateOfBirth: letaNazaj(25), genres: ["house"] });
    assert(r.status === 200 && r.body.onboarded_at, "25 let -> 200, racun dokoncan", r.body);

    console.log("\n# 3. Obstojec racun pod 18 (vpisan ob meji 15) ni blokiran pri urejanju");
    const star = letaNazaj(16);
    await pool.query("UPDATE users SET date_of_birth=$1::date, genres=ARRAY['house'], onboarded_at=NOW() WHERE email='star@outly.si'", [star]);
    r = await api("GET", "/me", T.star);
    b = await dobBaza("star@outly.si");
    assert(r.status === 200 && b.d === star && r.body.date_of_birth, "GET /me star racun: datum 16 let ostane", [r.status, b]);
    r = await api("PATCH", "/me", T.star, { username: "star_novo" });
    assert(r.status === 200 && r.body.username === "star_novo", "PATCH /me samo ime -> 200 (meja velja samo ob datumu rojstva)", r);
    r = await api("PATCH", "/me", T.star, { genres: ["house", "techno"], country: "SI", share_plans_with_friends: true });
    assert(r.status === 200, "PATCH /me zanri + drzava -> 200", r);
    r = await api("PATCH", "/me", T.star, { username: "star_dva", dateOfBirth: star, genres: ["house"] });
    assert(r.status === 200 && r.body.username === "star_dva", "PATCH /me z ISTIM datumom rojstva (celoten profil) -> 200", r);
    r = await api("PATCH", "/me", T.star, { date_of_birth: star });
    assert(r.status === 200, "isti datum v snake_case -> 200", r);
    b = await dobBaza("star@outly.si");
    assert(b.d === star && b.onboarded_at, "datum rojstva in dokoncanost nespremenjena", b);
    r = await api("PATCH", "/me", T.star, { dateOfBirth: letaNazaj(17) });
    assert(r.status === 400 && mejaBesedilo.test(r.body), "DRUG datum pod 18 (17 let) -> 400", r);
    r = await api("PATCH", "/me", T.star, { dateOfBirth: letaNazaj(16, -1) });
    assert(r.status === 400, "drug datum pod 18 (en dan stejsi) -> 400", r);
    b = await dobBaza("star@outly.si");
    assert(b.d === star, "zavrnjena sprememba ni zamenjala datuma", b);

    console.log("\n# 4. Nakup obstojecega racuna pod 18: min_age 0 uspe, 18+ ostane zaprt (I8)");
    const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Za vse", startAt: cezDan, ticketPriceCents: 1500, capacity: 50, minAge: 0 });
    assert(r.status === 201, "dogodek min_age 0 ustvarjen", r.body);
    const dogodek0 = r.body.id;
    r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Osemnajst plus", startAt: cezDan, ticketPriceCents: 1500, capacity: 50, minAge: 18 });
    assert(r.status === 201, "dogodek min_age 18 ustvarjen", r.body);
    const dogodek18 = r.body.id;
    r = await api("POST", `/events/${dogodek0}/orders`, T.star, { quantity: 1 });
    assert(r.status === 201, "obstojec racun 16 let kupi vstopnico za dogodek brez omejitve -> 201", r);
    r = await api("POST", `/events/${dogodek18}/orders`, T.star, { quantity: 1 });
    assert(r.status === 403 && /at least 18/.test(r.body), "isti racun na dogodku 18+ -> 403 (kot doslej)", r);

    console.log("\n# 5. Obstojec racun pod 18 sme dvigniti datum nad mejo ali ga izbrisati");
    r = await patchDatum(T.star, 18, 1);
    assert(r.status === 400 && mejaBesedilo.test(r.body), "obstojec racun: 17 let in 364 dni -> 400", r);
    r = await patchDatum(T.star, 18, 0);
    assert(r.status === 200, "obstojec racun: tocno 18 let -> 200", r);
    // Nakup 18+ gleda SQL starost() (CURRENT_DATE baze, UTC): med 00:00 in 02:00 po ljubljanskem casu bi tocno 18 let se ne zadostovalo,
    // zato za nakup datum pomaknemo za dan nazaj (18 let in 1 dan).
    r = await patchDatum(T.star, 18, -1);
    assert(r.status === 200, "obstojec racun: 18 let in 1 dan -> 200", r);
    r = await api("POST", `/events/${dogodek18}/orders`, T.star, { quantity: 1 });
    assert(r.status === 201, "po popravku datuma (18 let) nakup 18+ uspe -> 201", r);
    r = await api("PATCH", "/me", T.odrasel, { date_of_birth: null });
    assert(r.status === 200 && r.body.date_of_birth === null, "izbris datuma rojstva (date_of_birth: null) -> 200 (kot doslej)", r);
  } catch (e) {
    fail++; console.log("  ✗ izjema v testu", e && e.stack || e);
  }

  srv.kill();
  await pool.end();
  jwksServer.close();
  if (fail > 0) console.log("\n--- dnevnik backenda ---\n" + log.split("\n").slice(-30).join("\n"));
  console.log(`\n${ok} ok, ${fail} fail`);
  process.exit(fail > 0 ? 1 : 0);
})();
