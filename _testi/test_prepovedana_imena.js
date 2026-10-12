#!/usr/bin/env node
/**
 * Filter neprimernih uporabniskih imen (outly-backend#216 N9, Apple App Review 1.2: »a method for filtering
 * objectionable material from being posted to the app«). Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres@localhost:5448/outly" node _testi/test_prepovedana_imena.js
 *
 * Pokriva: (1) modul prepovedana_imena.js (zavrnjena z leetspeak/podcrtaji/ponovitvami, sprejeta vsakdanja imena in
 * »Scunthorpe« primeri), (2) PATCH /me (400 username_not_allowed, obstojece ime ostane in se sme ponovno shraniti),
 * (3) prvi klic z user_metadata.username (vrstica se ustvari, a z nadomestnim imenom), (4) da drugje v index.js ni poti,
 * ki bi nastavila username mimo filtra.
 * Skripta dvigne lokalni JWKS (port 3291) in backend na portu 3290.
 */
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3290, JWKS_PORT = 3291;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-pi";
const jwksServer = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url.startsWith("/auth/v1/user")) { try { const t = JSON.parse(Buffer.from(String(req.headers.authorization).split(".")[1], "base64url")); return res.end(JSON.stringify({ id: t.sub, email: t.email, email_confirmed_at: "2026-01-01T00:00:00Z" })); } catch (_) { res.statusCode = 401; return res.end("{}"); } }   // potrditev e-naslova pri viru (#222): stub potrdi vsak naslov iz zetona
  if (req.url.startsWith("/auth/v1/settings")) return res.end(JSON.stringify({ mailer_autoconfirm: false, external: { anonymous_users: false } }));   // nastavitve Supabase (#222): »Confirm email« vklopljen, brez anonimnih
  res.end(JSON.stringify({ keys: [{ ...jwk, kid: KID, alg: "ES256", use: "sig" }] }));
});

function b64u(o) { return Buffer.from(typeof o === "string" ? o : JSON.stringify(o)).toString("base64url"); }
// `ime` = user_metadata.username (kar aplikacija pošlje ob registraciji); undefined = brez.
function zeton(email, sub, ime) {
  const now = Math.floor(Date.now() / 1000);
  const h = b64u({ alg: "ES256", typ: "JWT", kid: KID });
  const meta = { email_verified: true };
  if (ime !== undefined) meta.username = ime;
  const p = b64u({ iss: `http://127.0.0.1:${JWKS_PORT}/auth/v1`, aud: "authenticated", sub, email, exp: now + 3600, iat: now, user_metadata: meta });
  const sig = crypto.sign("sha256", Buffer.from(h + "." + p), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return h + "." + p + "." + sig.toString("base64url");
}
function uuid(n) { return `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`; }

let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }

async function api(method, p, token, body) {
  const r = await fetch(BASE + p, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}

// --- (1) modul ---
const ZAVRNJENA = [
  // angleske kletvice in slurji
  "fuck", "Fuck", "FUCK", "fucker99", "mother_fucker", "f_u_c_k", "fuuuuck", "fu_ck_u", "sh1t", "5hit", "bullsh1t_fan", "b1tch", "bitchass",
  "c0cksucker", "cunt", "cunt_69", "the_cunt", "Asshole", "a55h0le", "d1ckhead", "pussy", "wh0re", "slut", "sluts_r_us", "w4nker", "porn_king",
  "n1gger", "nigga", "n_i_g_g_a", "faggot", "fag", "fags", "rapist", "rape", "nazi", "N4zi_1488", "hitler", "heil_hitler", "kys", "kill_yourself",
  "pedophile", "ass", "ass69", "_ass_", "cum", "sex", "dick", "tits",
  // slovenske, hrvaske, srbske
  "kurac", "Kurac", "k_u_r_a_c", "kur4c", "kurac123", "kurva", "kurba", "pizda", "p1zda", "pizdun", "picka", "jebem", "j3b3m_ti", "jebiga", "jebote",
  "govno", "govnar", "sranje", "kreten", "debil", "cigan", "cefur", "balija", "siptar", "pederast", "idiot",
  // zavajajoca imena (izdajanje za Outly)
  "admin", "Admin", "ADMIN", "adm1n", "admin123", "administrator", "the_admin", "outly", "Outly", "0utly", "outly_team", "outlysupport",
  "support", "Support", "official", "moderator", "mod", "staff", "helpdesk", "security", "verified", "ceo",
  // porn: koren ostane prepovedan (S1)
  "porn", "Porn", "porno", "pornhub", "xporn", "porn_star",
  // S2: 3+ ponovitev crke v korenu z dvojno crko
  "niggger", "nigggga", "pusssy", "asssshole", "assss", "fagggot", "pisss", "fuuuck", "bitchhh", "shhhit", "n1ggger",
  // N3: dodani koreni
  "kurc", "kurec", "Kurec", "fuk", "phuck", "fvck", "fcuk", "peder", "buzerant", "buzerant_99",
  // N4: zavajajoce kot administrator; N1: odlocitev menedzerja (Ciganovic ostane zavrnjen; Snigger zavrnjen, ker izjema odpre obid s_nigger)
  "Administracija", "Ciganovic", "s_nigger", "Snigger",
];
const SPREJETA = [
  // vsakdanja imena
  "martin", "Ana_Novak", "jure87", "marko_s", "sasa", "nina2000", "luka_k", "Tina", "DJ_Rok", "night_owl", "party_pete", "klemen99",
  "ZivaMaja", "grega_b", "mojca", "tadej_p", "outdoor_fan", "outlaw", "kurent", "pizza_lover", "hello_world", "shell",
  // »Scunthorpe«: kratek koren kot del navadne besede
  "Scunthorpe", "scunthorpe_fan", "Penistone", "classic", "Assassin", "passage", "bassist", "grape", "therapist", "analyst", "analog", "canal",
  "cocktail", "peacock", "Hancock", "Dickens", "Dickinson", "Essex", "Sussex", "Middlesex", "sextant", "Cumberland", "document", "rapeseed",
  "Nazir", "spicy", "Pakistan", "raccoon", "Wankel", "Slutsky", "Niggard", "Shiitake", "badminton", "badminton_ana", 
  "retardant", "debilitated", "Pickard", "supporter", "unofficial", "modern", "modem", "stafford", "titanic", "title", "assist",
  // S1: slovenske besede s korenom »porn«
  "upornik", "uporni_jan", "naporno", "naporna", "sporno", "sporna", "oporni", "opornik",
  // N1: lazni zadetki
  "Kurban", "kurban_bajram", "Slutnja", "slutim", "Kshitij", "Yoshitaka", "Ashita", "mishit", "push_it", "this_hit", "Tit",
  // S2: navadna imena z dvojno crko
  "Anna", "Matteo", "Ziggy", "Jessica", "Grassi", "Nigeria", "Hannah", "Bobbi",
  // N3: ne zadene obicajnih imen
  "Fukushima", "Kurcic", "Pedersen", "Peders", "Buzet",
];

let srv = null;   // proces backenda (da ga ob izjemi ali neuspelem zagonu ubijemo)
let F = null;
try { F = require("../prepovedana_imena"); } catch (e) { console.log("  (modul prepovedana_imena.js ne obstaja)"); }

(async () => {
  console.log("# Modul");
  assert(F && typeof F.jePrepovedanoIme === "function", "prepovedana_imena.js izvozi jePrepovedanoIme");
  if (F && F.jePrepovedanoIme) {
    const slabo = ZAVRNJENA.filter(i => !F.jePrepovedanoIme(i));
    assert(slabo.length === 0, `vseh ${ZAVRNJENA.length} prepovedanih imen je zavrnjenih`, slabo);
    const narobe = SPREJETA.filter(i => F.jePrepovedanoIme(i));
    assert(narobe.length === 0, `vseh ${SPREJETA.length} navadnih imen (tudi Scunthorpe) je sprejetih`, narobe);
    assert(F.jePrepovedanoIme("FUCK") === F.jePrepovedanoIme("fuck"), "velikost crk ne vpliva");
    assert(F.jePrepovedanoIme("") === false && F.jePrepovedanoIme(null) === false, "prazno / null ne pade");
  }

  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");

  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  let vstal = false;
  for (let i = 0; i < 50 && !vstal; i++) { try { await fetch(BASE + "/"); vstal = true; } catch { await new Promise(r => setTimeout(r, 100)); } }
  if (!vstal) { console.error("backend ni vstal v 5 s\n" + log); srv.kill(); process.exit(1); }

  const dbIme = async (email) => (await pool.query("SELECT username FROM users WHERE email=$1", [email])).rows[0]?.username;

  console.log("\n# PATCH /me");
  const T = { ana: zeton("ana@outly.si", uuid(1), "ana"), bor: zeton("bor@outly.si", uuid(2), "bor"), stari: zeton("stari@outly.si", uuid(3), "stari") };
  for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200 && r.body.username === k, `GET /me ${k}`, r.body); }

  // oblika napake: 400 JSON { error, message }; besedilo ne sme ujeti obstojecih podnizov odjemalcev (iOS APIErrorMessages / splet napake.js)
  let r = await api("PATCH", "/me", T.ana, { username: "fuck" });
  assert(r.status === 400 && r.body && r.body.error === "username_not_allowed" && /username not allowed/i.test(r.body.message || ""), "fuck -> 400 username_not_allowed + sporocilo", r);
  assert(!/username (invalid|too short|too long|already in use)/i.test(JSON.stringify(r.body)), "sporocilo ne ujame obstojecih pravil odjemalcev (username invalid …)", r.body);
  assert((await dbIme("ana@outly.si")) === "ana", "ime v bazi je nespremenjeno");

  for (const ime of ["Fuck", "sh1t", "f_u_c_k", "fuuuck", "k_u_r_a_c", "p1zda", "n1gger", "adm1n", "Admin", "outly_support", "0utly", "official", "support"]) {
    r = await api("PATCH", "/me", T.ana, { username: ime });
    assert(r.status === 400 && r.body.error === "username_not_allowed", `${ime} -> 400`, r);
  }
  assert((await dbIme("ana@outly.si")) === "ana", "po vseh zavrnitvah je ime se vedno »ana«");

  // vrstni red: oblika (stara sporocila) pred filtrom
  r = await api("PATCH", "/me", T.ana, { username: "ab" });
  assert(r.status === 400 && /Username too short/.test(r.body), "prekratko: staro sporocilo", r.body);
  r = await api("PATCH", "/me", T.ana, { username: "x".repeat(21) });
  assert(r.status === 400 && /Username too long/.test(r.body), "predolgo: staro sporocilo", r.body);
  r = await api("PATCH", "/me", T.ana, { username: "fuck you" });
  assert(r.status === 400 && /Username invalid/.test(r.body), "presledek: staro sporocilo (oblika pred filtrom)", r.body);

  // sprejeta imena
  for (const ime of ["Scunthorpe", "classic", "Hancock"]) {
    r = await api("PATCH", "/me", T.ana, { username: ime });
    assert(r.status === 200 && r.body.username === ime, `${ime} -> 200`, r);
  }
  assert((await dbIme("ana@outly.si")) === "Hancock", "ime v bazi se je spremenilo");
  r = await api("PATCH", "/me", T.bor, { username: "hancock" });
  assert(r.status === 409 && /Username already in use/.test(r.body), "zasedeno ime: se vedno 409 (staro sporocilo)", r.body);

  // obstojece ime (iz casov pred filtrom) ostane in se sme ponovno shraniti; tuj racun ga ne dobi
  await pool.query("UPDATE users SET username='Admin_Stari' WHERE email='stari@outly.si'");
  r = await api("GET", "/me", T.stari);
  assert(r.status === 200 && r.body.username === "Admin_Stari", "obstojece prepovedano ime v bazi ostane (GET /me)", r.body);
  r = await api("PATCH", "/me", T.stari, { username: "Admin_Stari", country: "SI" });
  assert(r.status === 200 && r.body.username === "Admin_Stari" && r.body.country === "SI", "isto ime ponovno shranjeno skupaj z drugim poljem -> 200", r);
  r = await api("PATCH", "/me", T.stari, { username: "admin_stari" });
  assert(r.status === 200 && r.body.username === "admin_stari", "samo druga velikost crk (isto ime) -> 200", r);
  r = await api("PATCH", "/me", T.stari, { username: "admin_stari2" });
  assert(r.status === 400 && r.body.error === "username_not_allowed", "drugo prepovedano ime istega uporabnika -> 400", r);
  r = await api("PATCH", "/me", T.bor, { username: "admin_stari" });
  assert(r.status === 400 && r.body.error === "username_not_allowed", "tuj uporabnik ne more prevzeti prepovedanega imena -> 400", r);
  r = await api("PATCH", "/me", T.stari, { username: "stari_ok" });
  assert(r.status === 200 && r.body.username === "stari_ok", "sprememba na primerno ime -> 200", r);
  r = await api("PATCH", "/me", T.stari, { country: "SI" });
  assert(r.status === 200, "PATCH brez username ni ovirano", r);

  console.log("\n# Prvi klic (user_metadata.username -> nova vrstica)");
  // Aplikacija ime pošlje Supabasu ob registraciji; backend vrstico ustvari ob prvem klicu. Prepovedano ime tam ne more dati 400
  // (uporabnik bi ostal brez seje), zato velja nadomestno ime »user« (ob prepovedanem imenu iz metapodatkov), sicer del e-naslova.
  const prvi = async (email, n, ime) => { const t = zeton(email, uuid(n), ime); const x = await api("GET", "/me", t); return { x, ime: await dbIme(email) }; };
  let p = await prvi("marko@outly.si", 10, "Scunthorpe");
  assert(p.x.status === 200 && p.ime === "Scunthorpe", "primerno ime iz metapodatkov se uporabi", p);
  p = await prvi("marko2@outly.si", 11, "fuck");
  assert(p.x.status === 200 && /^user(_\d{4})?$/.test(p.ime), "prepovedano ime iz metapodatkov: vrstica nastane (200), ime = »user« (del e-naslova NE, postal bi javno ime brez obvestila)", p);
  p = await prvi("sandra@outly.si", 16, "n1gger");
  assert(p.x.status === 200 && /^user(_\d{4})?$/.test(p.ime), "prepovedano ime iz metapodatkov, e-naslov primeren -> vseeno »user«", p);
  p = await prvi("zan@outly.si", 17, "ab");
  assert(p.x.status === 200 && p.ime === "zan", "neveljavno ime (prekratko): se vedno del e-naslova", p);
  p = await prvi("jebem@outly.si", 12, "k_u_r_a_c");
  assert(p.x.status === 200 && /^user(_\d{4})?$/.test(p.ime), "prepovedano ime IN prepovedan del e-naslova -> »user«", p);
  p = await prvi("admin@outly.si", 13, undefined);
  assert(p.x.status === 200 && /^user(_\d{4})?$/.test(p.ime), "brez metapodatkov, e-naslov admin@ -> »user« (ne izdaja se za Outly)", p);
  p = await prvi("petra@outly.si", 14, undefined);
  assert(p.x.status === 200 && p.ime === "petra", "brez metapodatkov: del e-naslova kot doslej", p);
  p = await prvi("tilen@outly.si", 15, "Tilen_99");
  assert(p.x.status === 200 && p.ime === "Tilen_99", "navadno ime kot doslej", p);

  console.log("\n# Source: ni druge poti, ki bi nastavila username mimo filtra");
  const src = fs.readFileSync(path.join(__dirname, "..", "index.js"), "utf8");
  assert((src.match(/INSERT INTO users/g) || []).length === 1, "v index.js je samo en INSERT INTO users (predlogImena)");
  assert(!/SET[^;`]*\busername\s*=/i.test(src.replace(/dodaj\("username"/g, "")), "nobenega UPDATE … SET username = zunaj PATCH /me (ta gre prek dodaj)");
  const iz = src.slice(src.indexOf("function predlogImena"), src.indexOf("async function uporabnikIzSupabase"));
  assert(/jePrepovedanoIme\(/.test(iz), "predlogImena kliče filter");
  const patch = src.slice(src.indexOf('app.patch("/me", requireAuth'), src.indexOf("// --- telefonska stevilka ---"));
  assert(/jePrepovedanoIme\(/.test(patch), "PATCH /me kliče filter");

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  if (/error|Error/.test(log) && !/Resend/.test(log)) { console.log("\n--- log streznika ---\n" + log); }
  srv.kill(); jwksServer.close(); await pool.end();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); try { if (srv) srv.kill(); } catch (_) {} process.exit(1); });
