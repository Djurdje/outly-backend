#!/usr/bin/env node
/**
 * »Skip for later« pri dokoncanju racuna (Martin, 23. 10. 2026): PATCH /me z `complete_onboarding` (tudi `completeOnboarding`).
 * Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres@localhost:5432/outly" node _testi/test_onboarding_preskok.js
 * Vzorec kot test_vabila.js: lokalni JWKS (6292), backend na svojem portu (6291).
 *
 * Kaj ta test lovi:
 *  1. complete_onboarding: true z datumom rojstva v bazi, brez zanrov in drzave -> onboarded_at nastavljen (telo samo s tem poljem je veljavno).
 *  2. Brez datuma rojstva -> 400 { error: "date_of_birth_required" }, onboarded_at ostane NULL, nic se ne zapise (tudi ostala polja v istem klicu).
 *  3. true + dateOfBirth v istem klicu -> nastavljen; datum pod 18 let je se vedno 400 in racun ni dokoncan; dateOfBirth: null + true -> 400.
 *  4. Ze nastavljen onboarded_at se ne spremeni (ne ob true, ne ob staremu pravilu).
 *  5. Ne-boolean -> 400; samo { complete_onboarding: false } -> 400 »Nothing to update.« (kot prej); false z drugim poljem ne dokonca.
 *  6. Staro pravilo (datum + vsaj en zanr -> onboarded_at) deluje brez complete_onboarding (stari odjemalci); zanr brez datuma ne dokonca.
 *  7. Uporabnik brez zanrov in drzave (preskok) normalno bere GET /me, /events, /clubs, /me/invites; zanre in drzavo lahko pozneje doda.
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");
const { danesLjubljana, polnaLeta } = require("../starost_racuna");   // isti izracun »danes« kot streznik

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 6291, JWKS_PORT = 6292;
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
// Datum »danes minus N let (+ dni)« po ljubljanskem koledarju (kot test_starost_racun.js).
const iso = (d) => d.toISOString().slice(0, 10);
const jePrestopno = (l) => (l % 4 === 0 && l % 100 !== 0) || l % 400 === 0;
const dodajDni = (datum, n) => { const [l, m, d] = datum.split("-").map(Number); return iso(new Date(Date.UTC(l, m - 1, d + n))); };
function letaNazaj(leta, dniNaprej = 0, danes = danesLjubljana()) {
  const [l, m, d] = danes.split("-").map(Number);
  const cilj = l - leta;
  const dan = (m === 2 && d === 29 && !jePrestopno(cilj)) ? 28 : d;
  return dodajDni(`${cilj}-${String(m).padStart(2, "0")}-${String(dan).padStart(2, "0")}`, dniNaprej);
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  try {
    const imena = ["a", "b", "c", "d", "e", "f", "g", "h", "i"];
    const T = {};
    imena.forEach((k, i) => { T[k] = zeton(`${k}@outly.si`, uuid(i + 1)); });
    for (const k of imena) { const r = await api("GET", "/me", T[k]); assert(r.status === 200 && r.body.onboarded_at === null, `GET /me ${k}: nov racun, onboarded_at null`, r.body); }
    const baza = async (k) => (await pool.query("SELECT to_char(date_of_birth,'YYYY-MM-DD') AS d, genres, country, phone, onboarded_at FROM users WHERE email=$1", [`${k}@outly.si`])).rows[0];
    const odrasel = letaNazaj(25), mlad = letaNazaj(17, 1);
    const napaka = /^Date of birth is required\.$/;

    console.log("\n# 1. true z datumom rojstva v bazi, brez zanrov in drzave");
    let r = await api("PATCH", "/me", T.a, { dateOfBirth: odrasel });
    assert(r.status === 200 && r.body.onboarded_at === null, "korak 1 (samo datum): racun se ni dokoncan", r.body);
    r = await api("PATCH", "/me", T.a, { complete_onboarding: true });
    assert(r.status === 200 && r.body.onboarded_at, "{ complete_onboarding: true } samo s tem poljem -> 200 in onboarded_at", r);
    let b = await baza("a");
    assert(b.onboarded_at && b.genres.length === 0 && b.country === null && b.phone === null, "v bazi: onboarded_at nastavljen, zanri [], drzava in telefon NULL", b);
    assert(r.body.genres.length === 0 && r.body.country === null && r.body.date_of_birth, "odgovor ima isto obliko kot doslej (POLJA_UPORABNIKA), brez zanrov/drzave", r.body);
    const prvic = b.onboarded_at.getTime();

    console.log("\n# 2. Brez datuma rojstva -> 400 date_of_birth_required");
    r = await api("PATCH", "/me", T.b, { complete_onboarding: true });
    assert(r.status === 400 && r.body.error === "date_of_birth_required" && napaka.test(r.body.message), "400 { error: date_of_birth_required, message }", r);
    b = await baza("b");
    assert(b.onboarded_at === null && b.d === null, "onboarded_at ostane NULL", b);
    r = await api("PATCH", "/me", T.b, { complete_onboarding: true, country: "SI", genres: ["house"] });
    assert(r.status === 400 && r.body.error === "date_of_birth_required", "tudi z drzavo in zanri v istem klicu -> 400", r);
    b = await baza("b");
    assert(b.onboarded_at === null && b.country === null && b.genres.length === 0, "ob zavrnitvi se nic ne zapise (ne drzava, ne zanri)", b);
    r = await api("PATCH", "/me", T.b, { completeOnboarding: true });
    assert(r.status === 400 && r.body.error === "date_of_birth_required", "camelCase completeOnboarding enako -> 400", r);

    console.log("\n# 3. true v istem klicu z dateOfBirth");
    r = await api("PATCH", "/me", T.c, { dateOfBirth: odrasel, complete_onboarding: true });
    assert(r.status === 200 && r.body.onboarded_at && r.body.date_of_birth, "datum + true v istem klicu -> 200, onboarded_at nastavljen", r);
    r = await api("PATCH", "/me", T.d, { date_of_birth: odrasel, completeOnboarding: true });
    assert(r.status === 200 && r.body.onboarded_at, "snake_case datum + camelCase completeOnboarding -> 200", r);
    r = await api("PATCH", "/me", T.e, { dateOfBirth: mlad, complete_onboarding: true });
    assert(r.status === 400 && /at least 18/.test(r.body), "datum pod 18 let + true -> 400 (kot doslej)", r);
    b = await baza("e");
    assert(b.d === null && b.onboarded_at === null, "pod 18: datum ni vpisan, racun ni dokoncan", b);
    r = await api("PATCH", "/me", T.e, { date_of_birth: null, complete_onboarding: true });
    assert(r.status === 400 && r.body.error === "date_of_birth_required", "date_of_birth: null + true -> 400 date_of_birth_required", r);
    r = await api("PATCH", "/me", T.e, { dateOfBirth: null, complete_onboarding: true });
    assert(r.status === 400 && r.body === "dateOfBirth must be YYYY-MM-DD.", "dateOfBirth: null + true -> 400 »dateOfBirth must be YYYY-MM-DD.« (camelCase null je ze od prej 400 po stari poti)", r);
    for (const [datum, besedilo] of [["2000-02-31", /^Invalid dateOfBirth\.$/], [iso(new Date(Date.now() + 3 * 24 * 3600 * 1000)), /^dateOfBirth cannot be in the future\.$/]]) {
      r = await api("PATCH", "/me", T.e, { dateOfBirth: datum, complete_onboarding: true });
      b = await baza("e");
      assert(r.status === 400 && besedilo.test(r.body) && b.d === null && b.onboarded_at === null, `datum ${datum} + true -> 400 in onboarded_at ostane NULL`, [r, b]);
    }
    r = await api("PATCH", "/me", T.e, { dateOfBirth: "", complete_onboarding: true });
    assert(r.status === 400 && r.body.error === "date_of_birth_required", "dateOfBirth: \"\" + true -> 400 date_of_birth_required", r);
    await api("PATCH", "/me", T.a, { dateOfBirth: odrasel });
    r = await api("PATCH", "/me", T.a, { date_of_birth: null, complete_onboarding: true });
    b = await baza("a");
    assert(r.status === 400 && b.d === odrasel, "racun z datumom, brisanje datuma (date_of_birth: null) + true -> 400 in datum ostane", [r.status, b]);

    console.log("\n# 4. Ze nastavljen onboarded_at se ne spremeni");
    await new Promise(res => setTimeout(res, 50));
    r = await api("PATCH", "/me", T.a, { complete_onboarding: true });
    b = await baza("a");
    assert(r.status === 200 && b.onboarded_at.getTime() === prvic, "ponovni true: onboarded_at nespremenjen", [b.onboarded_at, prvic]);
    r = await api("PATCH", "/me", T.a, { genres: ["house"], complete_onboarding: true });
    b = await baza("a");
    assert(r.status === 200 && b.onboarded_at.getTime() === prvic && b.genres[0] === "house", "true + zanri po preskoku: zanri zapisani, onboarded_at nespremenjen", [r.status, b]);

    console.log("\n# 5. Neveljavne vrednosti in false");
    for (const v of ["true", 1, 0, null, "yes", {}, []]) {
      r = await api("PATCH", "/me", T.f, { dateOfBirth: odrasel, complete_onboarding: v });
      assert(r.status === 400 && /complete_onboarding must be true or false/.test(r.body), `complete_onboarding: ${JSON.stringify(v)} -> 400`, r);
    }
    r = await api("PATCH", "/me", T.f, { completeOnboarding: "true" });
    assert(r.status === 400, "completeOnboarding: \"true\" (niz) -> 400", r);
    b = await baza("f");
    assert(b.d === null && b.onboarded_at === null, "po zavrnitvah nic zapisano", b);
    r = await api("PATCH", "/me", T.f, { complete_onboarding: false });
    assert(r.status === 400 && r.body === "Nothing to update.", "samo { complete_onboarding: false } -> 400 »Nothing to update.« (kot prej)", r);
    r = await api("PATCH", "/me", T.f, { dateOfBirth: odrasel, complete_onboarding: false });
    assert(r.status === 200 && r.body.onboarded_at === null, "false z datumom: datum shranjen, racun ni dokoncan (brez zanra)", r.body);
    r = await api("PATCH", "/me", T.f, { complete_onboarding: false });
    assert(r.status === 400, "false ne dokonca racuna z datumom brez zanra (Nothing to update)", r);

    console.log("\n# 6. Staro pravilo (datum + zanr) deluje brez complete_onboarding");
    r = await api("PATCH", "/me", T.g, { dateOfBirth: odrasel, genres: ["house"] });
    assert(r.status === 200 && r.body.onboarded_at, "datum + zanr v istem klicu -> onboarded_at", r.body);
    r = await api("PATCH", "/me", T.h, { genres: ["house"] });
    assert(r.status === 200 && r.body.onboarded_at === null, "zanr brez datuma: ne dokonca", r.body);
    r = await api("PATCH", "/me", T.h, { dateOfBirth: odrasel });
    assert(r.status === 200 && r.body.onboarded_at, "nato se datum -> dokoncan (stari odjemalec v dveh korakih)", r.body);

    console.log("\n# 7. Uporabnik po preskoku (brez zanrov in drzave) normalno uporablja API");
    await pool.query("INSERT INTO users (email, username) SELECT 'lastnik@outly.si', 'lastnik' WHERE NOT EXISTS (SELECT 1 FROM users WHERE email='lastnik@outly.si')");
    r = await api("PATCH", "/me", T.i, { dateOfBirth: odrasel, complete_onboarding: true });
    assert(r.status === 200 && r.body.onboarded_at, "uporabnik i preskoci vse razen datuma", r);
    for (const pot of ["/me", "/me/invites", "/events", "/clubs", "/genres"]) {
      const rr = await api("GET", pot, T.i);
      assert(rr.status === 200, `GET ${pot} po preskoku -> 200`, [rr.status, typeof rr.body === "string" ? rr.body.slice(0, 100) : ""]);
    }
    r = await api("PATCH", "/me", T.i, { country: "SI", genres: ["techno"], phone: "+38641123456" });
    b = await baza("i");
    assert(r.status === 200 && b.country === "SI" && b.genres[0] === "techno" && b.phone === "+38641123456", "pozneje dopolni drzavo, zanre in telefon v profilu", [r.status, b]);
    assert(b.onboarded_at !== null, "onboarded_at ostane", b);
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
