#!/usr/bin/env node
/**
 * Test PRIJAVE ZLORABE IN BLOKIRANJA (migracija 041, 10. 10. 2026, issue #189, Apple App Review 1.2, invarianta I30). Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_prijave.js
 * Vzorec kot test_guest_lista.js: lokalni JWKS (3960), lazni Resend (3964), trije backendi (3262-3264), TRUNCATE na zacetku.
 *
 *  1  priprava: uporabniki, klubi (en skrit), dogodki (objavljen, osnutek, skrit klub), racun za kopije
 *  2  POST /reports: validacija (400), cilj ne obstaja ali ni javen (404), uspeh za vse 4 vrste (201), podvojena v 24 h (200 isti id), dnevna meja (429)
 *  3  mail adminu: samo ob novi prijavi, brez osebnih podatkov prijavitelja, Resend napaka/pocasen Resend ne podre odgovora, meja na uro, brez ADMIN_PRIJAVE_EMAIL ni maila
 *  4  admin: GET/PATCH /admin/api/reports (403 za ne-admina, filtri, razresitev, ponovno odprtje, opomba), zavihek Reports v panelu (brez innerHTML)
 *  5  blokiranje: POST/DELETE/GET /me/blocks, idempotenca, meja blokov, blok pobrise prijateljstvo in cakajoce prosnje, odblok ne obnovi
 *  6  ucinek bloka v obe smeri: iskanje, prosnja za prijateljstvo (enak odgovor kot za neobstojecega), prenos vstopnice (user_id, e-naslov, allow_guest),
 *     vabilo na guest listo (tudi ob zastarelem prijateljstvu), vabilo v ekipo
 *  7  tekmovanje: blokiranje proti prosnji / sprejemu prosnje (vedno blok, nikoli prijateljstvo, nikoli 500)
 *  8  izbris racuna (DELETE /me): bloki izginejo, prijave ostanejo anonimizirane, cilj izbrisan -> target_label null
 *  9  omejevalnik POST /reports (20/h/IP)
 */
const crypto = require("crypto");
const http = require("http");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT_A = 3262, PORT_B = 3263, PORT_C = 3264, JWKS_PORT = 3960, RESEND_PORT = 3964;
const A = `http://127.0.0.1:${PORT_A}`, B = `http://127.0.0.1:${PORT_B}`, C = `http://127.0.0.1:${PORT_C}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-prijave";
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
const pocakaj = (ms) => new Promise(r => setTimeout(r, ms));
async function cakaj(pogoj, ms = 6000) { const do_ = Date.now() + ms; while (Date.now() < do_) { if (await pogoj()) return true; await pocakaj(50); } return false; }
async function zahtevek(baza, method, p, token, body) {
  const r = await fetch(baza + p, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, text: t, headers: r.headers };
}
const api = (m, p, t, b) => zahtevek(A, m, p, t, b);

// ---------- lazni Resend ----------
const R = { poslano: [], napaka: false, zamik: 0 };
const resendServer = http.createServer((req, res) => {
  let d = ""; req.on("data", x => d += x);
  req.on("end", () => {
    if (req.method === "POST" && req.url === "/emails") {
      if (R.napaka) { res.writeHead(422, { "content-type": "application/json" }); return res.end(JSON.stringify({ name: "validation_error", message: "stub: zavrnjeno", statusCode: 422 })); }
      const m = JSON.parse(d);
      const koncaj = () => { R.poslano.push(m); res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ id: "mail_" + R.poslano.length })); };
      return R.zamik ? setTimeout(koncaj, R.zamik) : koncaj();
    }
    res.writeHead(404, { "content-type": "application/json" }); res.end("{}");
  });
});

function zagon(port, okolje) {
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, QR_SECRET: "test",
    RESEND_API_KEY: "re_test", RESEND_BASE_URL: `http://127.0.0.1:${RESEND_PORT}`, EMAIL_FROM: "Outly <test@outly.test>", ...okolje }, stdio: ["ignore", "pipe", "pipe"] });
  const s = { srv, log: "" };
  srv.stdout.on("data", d => s.log += d); srv.stderr.on("data", d => s.log += d);
  return s;
}
async function cakajStreznik(baza) { for (let i = 0; i < 80; i++) { try { await fetch(baza + "/"); return; } catch { await pocakaj(100); } } }

let sa = null, sb = null, sc = null;
(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, reports, user_blocks, guest_list_members, guest_lists, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users, friendships, friend_requests RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  await new Promise(r => resendServer.listen(RESEND_PORT, r));
  sa = zagon(PORT_A, { ADMIN_PRIJAVE_EMAIL: "admin1@outly.test, admin2@outly.test", PRIJAVE_NA_DAN: "6", BLOKI_NAJVEC: "3", PRIJAVE_MAIL_NA_URO: "100", PRENOS_BREZ_RACUNA: "vsi" });
  await cakajStreznik(A);
  const resetLimit = () => pool.query("TRUNCATE omejitve");

  const imena = ["lastnik", "skrbnik", "admin", "admin2", "ana", "bor", "cene", "dan", "evi", "fani", "pridni", "blokar"];
  const T = {}, U = {};
  imena.forEach((k, i) => { T[k] = zeton(`${k}@outly.si`, uuid(i + 1)); });
  console.log("\n# 1. Priprava");
  for (const k of imena) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); U[k] = r.body.id; }
  await pool.query("UPDATE users SET role='business' WHERE email IN ('lastnik@outly.si','skrbnik@outly.si')");
  await pool.query("UPDATE users SET role='admin' WHERE email IN ('admin@outly.si','admin2@outly.si')");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ($1, 'Pure Club', 'Ljubljana'), ($2, 'Skriti Klub', 'Maribor')", [U.lastnik, U.skrbnik]);
  const kopija = (await pool.query("INSERT INTO users (email, username, email_verified, role) VALUES ('kopija@outly.si', 'kopija', true, 'backup') RETURNING id")).rows[0].id;
  const cezTeden = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
  const dogodek = async (zeton_, klub, title) => {
    const x = await api("POST", "/events", zeton_, { clubId: klub, title, startAt: cezTeden, ticketPriceCents: 1000, capacity: 100, minAge: 0 });
    assert(x.status === 201, `dogodek ${title}`, x.body); return x.body.id;
  };
  const evA = await dogodek(T.lastnik, 1, "Glavni");
  const evB = await dogodek(T.lastnik, 1, "Drugi");
  const evOsnutek = await dogodek(T.lastnik, 1, "Osnutek");
  const evSkrit = await dogodek(T.skrbnik, 2, "V skritem klubu");
  await pool.query("UPDATE events SET status='draft' WHERE id=$1", [evOsnutek]);
  await pool.query("UPDATE clubs SET hidden = true WHERE id = 2");
  const prijatelja = async (a, b) => {
    let r = await api("POST", "/me/friends/requests", T[a], { user_id: U[b] });
    if (r.status !== 201) return r;
    return api("POST", `/me/friends/requests/${r.body.request.id}/accept`, T[b]);
  };
  const stPrijateljev = async (a, b) => (await pool.query("SELECT COUNT(*)::int AS n FROM friendships WHERE user_a = LEAST($1::int,$2::int) AND user_b = GREATEST($1::int,$2::int)", [U[a], U[b]])).rows[0].n;
  const stBlokov = async (a, b) => (await pool.query("SELECT COUNT(*)::int AS n FROM user_blocks WHERE blocker_id=$1 AND blocked_id=$2", [U[a], U[b]])).rows[0].n;
  const stCakajocih = async (a, b) => (await pool.query("SELECT COUNT(*)::int AS n FROM friend_requests WHERE status='pending' AND LEAST(from_user_id,to_user_id)=LEAST($1::int,$2::int) AND GREATEST(from_user_id,to_user_id)=GREATEST($1::int,$2::int)", [U[a], U[b]])).rows[0].n;
  const stPrijav = async () => (await pool.query("SELECT COUNT(*)::int AS n FROM reports")).rows[0].n;

  // ====================================================================================================
  console.log("\n# 2. POST /reports");
  let r = await api("POST", "/reports", null, { target_type: "club", target_id: 1, reason: "spam" });
  assert(r.status === 401, "brez zetona: 401", r.status);
  // Omejevalnik POST /reports je 20/h/IP: sklopi s po 15 klici ga ponastavimo (poseben odsek 9 ga preizkusi naravnost).
  let stKlicev = 0;
  const prijava = async (t, telo) => { if (++stKlicev % 15 === 0) await resetLimit(); return api("POST", "/reports", t, telo); };
  r = await prijava(T.ana, { target_type: "robot", target_id: 1, reason: "spam" });
  assert(r.status === 400 && r.body.error === "invalid_target_type" && r.body.message, "neveljaven target_type: 400 invalid_target_type + message", r.body);
  r = await prijava(T.ana, { target_id: 1, reason: "spam" });
  assert(r.status === 400 && r.body.error === "invalid_target_type", "brez target_type: 400 invalid_target_type", r.body);
  r = await prijava(T.ana, { target_type: "club", target_id: 1, reason: "dolgcas" });
  assert(r.status === 400 && r.body.error === "invalid_reason", "neveljaven reason: 400 invalid_reason", r.body);
  r = await prijava(T.ana, { target_type: "club", target_id: 1 });
  assert(r.status === 400 && r.body.error === "invalid_reason", "brez reason: 400 invalid_reason", r.body);
  for (const [naslov, id] of [["brez target_id", undefined], ["0", 0], ["-1", -1], ["1.5", 1.5], ["niz abc", "abc"], ["null", null], ["prevelik (nad int4)", 2147483648], ["objekt", {}]]) {
    r = await prijava(T.ana, { target_type: "club", target_id: id, reason: "spam" });
    assert(r.status === 400 && r.body.error === "invalid_target", `target_id ${naslov}: 400 invalid_target`, [r.status, r.body]);
  }
  r = await prijava(T.ana, { target_type: "club", target_id: 1, reason: "spam", details: 5 });
  assert(r.status === 400 && r.body.error === "invalid_details", "details ni niz: 400 invalid_details", r.body);
  r = await prijava(T.ana, { target_type: "club", target_id: 1, reason: "spam", details: "x".repeat(1001) });
  assert(r.status === 400 && r.body.error === "invalid_details", "details 1001 znakov: 400 invalid_details", r.body);
  r = await prijava(T.ana, { target_type: "club", target_id: 1, reason: "spam", details: "😀".repeat(1001) });
  assert(r.status === 400 && r.body.error === "invalid_details", "details 1001 kodnih tock (emoji): 400", r.body);
  r = await prijava(T.ana, null);
  assert(r.status === 400, "brez telesa: 400", r.status);
  r = await prijava(T.ana, { target_type: "user", target_id: U.ana, reason: "spam" });
  assert(r.status === 400 && r.body.error === "invalid_target", "prijava samega sebe: 400 invalid_target", r.body);
  assert((await stPrijav()) === 0, "po vseh zavrnitvah v bazi ni prijav");

  for (const [naslov, telo] of [
    ["uporabnik ne obstaja", { target_type: "user", target_id: 99999 }],
    ["klub ne obstaja", { target_type: "club", target_id: 99999 }],
    ["dogodek ne obstaja", { target_type: "event", target_id: 99999 }],
    ["slika neobstojecega kluba", { target_type: "media", target_id: 99999 }],
    ["racun za kopije (backup)", { target_type: "user", target_id: kopija }],
    ["skrit klub", { target_type: "club", target_id: 2 }],
    ["slika skritega kluba", { target_type: "media", target_id: 2 }],
    ["dogodek skritega kluba", { target_type: "event", target_id: evSkrit }],
    ["dogodek v osnutku", { target_type: "event", target_id: evOsnutek }],
  ]) {
    r = await prijava(T.ana, { ...telo, reason: "spam" });
    assert(r.status === 404 && r.body.error === "not_found", `${naslov}: 404 not_found`, [r.status, r.body]);
  }
  assert((await stPrijav()) === 0, "po vseh 404 v bazi ni prijav");

  r = await prijava(T.ana, { target_type: "user", target_id: U.bor, reason: "harassment", details: "  SECRET-DETAILS-123 zaplet  " });
  assert(r.status === 201 && r.body.ok === true && Number.isInteger(r.body.id), "prijava uporabnika: 201 { ok: true, id }", r.body);
  const idUser = r.body.id;
  let vrst = (await pool.query("SELECT * FROM reports WHERE id=$1", [idUser])).rows[0];
  assert(vrst.reporter_id === U.ana && vrst.target_type === "user" && vrst.target_id === U.bor && vrst.reason === "harassment" && vrst.status === "open"
    && vrst.details === "SECRET-DETAILS-123 zaplet" && vrst.resolved_at === null && vrst.note === null, "vrstica: prijavitelj iz zetona, cilj, razlog, details pristrizen, status open", vrst);
  r = await prijava(T.ana, { target_type: "club", target_id: 1, reason: "inappropriate" });
  assert(r.status === 201, "prijava kluba: 201", r.body); const idKlub = r.body.id;
  r = await prijava(T.ana, { target_type: "event", target_id: evA, reason: "illegal", details: "" });
  assert(r.status === 201, "prijava dogodka: 201", r.body); const idDogodek = r.body.id;
  assert((await pool.query("SELECT details FROM reports WHERE id=$1", [idDogodek])).rows[0].details === null, "prazen details se shrani kot NULL");
  r = await prijava(T.ana, { target_type: "media", target_id: 1, reason: "other", details: "https://res.cloudinary.test/pure/slika1.jpg" });
  assert(r.status === 201, "prijava slike (media: target_id = klub): 201", r.body); const idMedia = r.body.id;
  r = await prijava(T.ana, { target_type: "user", target_id: String(U.cene), reason: "spam" });
  assert(r.status === 201, "target_id kot niz stevk (\"" + U.cene + "\"): 201", r.body);
  r = await prijava(T.ana, { target_type: "user", target_id: U.dan, reason: "impersonation", details: "a\u0000b" });
  assert(r.status === 201, "NUL znak v details: 201 (odstranjen, ne 500)", r.body);
  assert((await pool.query("SELECT details FROM reports WHERE id=$1", [r.body.id])).rows[0].details === "ab", "NUL znak je odstranjen iz details");
  r = await prijava(T.fani, { target_type: "user", target_id: U.bor, reason: "spam", details: "😀".repeat(1000) });
  assert(r.status === 201, "details 1000 kodnih tock (emoji): 201", r.body);

  const pred = await stPrijav();
  r = await prijava(T.ana, { target_type: "user", target_id: U.bor, reason: "spam" });
  assert(r.status === 200 && r.body.ok === true && r.body.id === idUser, "ista prijava istega cilja v 24 h (drug razlog): 200 z ISTIM id", r.body);
  assert((await stPrijav()) === pred, "podvojena prijava ne doda vrstice");
  r = await prijava(T.cene, { target_type: "user", target_id: U.bor, reason: "harassment" });
  assert(r.status === 201 && r.body.id !== idUser, "drug prijavitelj istega cilja: 201 nova prijava", r.body);
  await pool.query("UPDATE reports SET created_at = NOW() - INTERVAL '25 hours' WHERE id = $1", [idUser]);
  r = await prijava(T.ana, { target_type: "user", target_id: U.bor, reason: "harassment" });
  assert(r.status === 201 && r.body.id !== idUser, "po 25 h je ista prijava spet nova: 201", r.body);

  console.log("\n# 2b. Dnevna meja prijav na uporabnika (PRIJAVE_NA_DAN=6)");
  await resetLimit();
  for (const k of ["lastnik", "admin", "ana", "bor", "cene", "dan"]) {
    r = await prijava(T.pridni, { target_type: "user", target_id: U[k], reason: "spam" });
    assert(r.status === 201, `pridni prijavi ${k}: 201`, r.body);
  }
  r = await prijava(T.pridni, { target_type: "club", target_id: 1, reason: "spam" });
  assert(r.status === 429 && r.body.error === "too_many_reports" && r.headers.get("retry-after"), "7. razlicna prijava v 24 h: 429 too_many_reports + Retry-After", [r.status, r.body]);
  r = await prijava(T.pridni, { target_type: "user", target_id: U.ana, reason: "other" });
  assert(r.status === 200, "ze prijavljen cilj ob polni dnevni meji: 200 (brez podvajanja, ne steje)", [r.status, r.body]);
  assert((await pool.query("SELECT COUNT(*)::int AS n FROM reports WHERE reporter_id=$1", [U.pridni])).rows[0].n === 6, "pridni ima natanko 6 prijav");
  console.log("  (8 vzporednih prijav fani proti dnevni meji)");
  await resetLimit();
  const vzp = await Promise.all(["lastnik", "admin", "ana", "bor", "cene", "dan", "evi", "pridni"].map(k => prijava(T.fani, { target_type: "user", target_id: U[k], reason: "spam" })));
  const st201 = vzp.filter(x => x.status === 201).length, st429 = vzp.filter(x => x.status === 429).length;
  const fani = (await pool.query("SELECT COUNT(*)::int AS n FROM reports WHERE reporter_id=$1", [U.fani])).rows[0].n;
  assert(fani <= 6 && st201 + st429 + vzp.filter(x => x.status === 200).length === 8 && !vzp.some(x => x.status >= 500), "socasne prijave: dnevna meja ne pade (nikoli 5xx, v bazi <= 6)", { fani, st201, st429, statusi: vzp.map(x => x.status) });

  // ====================================================================================================
  console.log("\n# 3. Mail adminu");
  await resetLimit();
  R.poslano.length = 0;
  r = await prijava(T.evi, { target_type: "event", target_id: evB, reason: "illegal", details: "SECRET-DETAILS-MAIL" });
  assert(r.status === 201, "prijava dogodka (evi): 201", r.body); const idMail = r.body.id;
  assert(await cakaj(() => R.poslano.length === 1), "mail adminu poslan (natanko 1)", R.poslano.length);
  const mail = R.poslano[0] || {};
  assert(Array.isArray(mail.to) && mail.to.length === 2 && mail.to.includes("admin1@outly.test") && mail.to.includes("admin2@outly.test"), "prejemnika sta oba naslova iz ADMIN_PRIJAVE_EMAIL", mail.to);
  assert(String(mail.subject).includes("#" + idMail), "zadeva vsebuje id prijave", mail.subject);
  const vsebina = (mail.html || "") + (mail.text || "") + (mail.subject || "");
  assert(vsebina.includes("evi") && vsebina.includes("Drugi (Pure Club)") && vsebina.includes("illegal"), "mail: uporabnisko ime prijavitelja, cilj, razlog", vsebina.slice(0, 300));
  assert(!vsebina.includes("evi@outly.si") && !vsebina.includes("@outly.si") && !vsebina.includes("SECRET-DETAILS-MAIL"), "mail NE vsebuje e-naslova prijavitelja ne prostega besedila prijave");
  r = await prijava(T.evi, { target_type: "event", target_id: evB, reason: "spam" });
  assert(r.status === 200, "podvojena prijava: 200", r.status);
  r = await prijava(T.evi, { target_type: "event", target_id: 99999, reason: "spam" });
  assert(r.status === 404, "prijava neobstojecega cilja: 404", r.status);
  // Negativne trditve brez fiksnega cakanja: za podvojeno in zavrnjeno prijavo posljemo NOVO veljavno prijavo in pocakamo na NJEN mail;
  // ker mailov ne izgubljamo in se posiljajo po vrsti prijav, prej bi prisel morebitni mail podvojene/zavrnjene prijave.
  r = await prijava(T.evi, { target_type: "user", target_id: U.dan, reason: "spam" });
  assert(r.status === 201, "nova veljavna prijava (evi -> dan): 201", r.body); const idSentinel = r.body.id;
  assert(await cakaj(() => R.poslano.length >= 2), "mail nove prijave je prisel", R.poslano.length);
  assert(R.poslano.length === 2 && String(R.poslano[1].subject).includes("#" + idSentinel) && String(R.poslano[0].subject).includes("#" + idMail),
    "podvojena in zavrnjena (404) prijava NISTA poslali maila: do maila nove prijave sta le mail 1. prijave in njen", R.poslano.map(m => m.subject));
  R.poslano.length = 0;

  R.napaka = true;
  r = await prijava(T.evi, { target_type: "club", target_id: 1, reason: "spam" });
  assert(r.status === 201, "Resend vrne { error }: prijava je vseeno 201", [r.status, r.body]);
  assert(await cakaj(() => /Resend napaka \(prijava zlorabe\)/.test(sa.log)), "napaka Resenda je zapisana v dnevnik (brez izjeme)");
  R.napaka = false;
  assert((await pool.query("SELECT COUNT(*)::int AS n FROM reports WHERE id=$1", [r.body.id])).rows[0].n === 1, "prijava je shranjena kljub napaki maila");
  R.zamik = 2500;
  await prijava(T.evi, { target_type: "club", target_id: 1, reason: "inappropriate" });   // isti cilj kot prej -> 200 (brez maila)
  const t0 = Date.now();
  r = await prijava(T.evi, { target_type: "media", target_id: 1, reason: "spam" });
  const trajanje = Date.now() - t0;
  const ob_odgovoru = R.poslano.length;
  assert(r.status === 201 && ob_odgovoru === 0 && trajanje < 2000, `pocasen Resend (zamik 2500 ms): odgovor pride PREJ kot mail (${trajanje} ms, mailov ob odgovoru: ${ob_odgovoru})`, [r.status, trajanje, ob_odgovoru]);
  assert(await cakaj(() => R.poslano.length === 1, 8000), "mail pride pozneje (po odgovoru)", R.poslano.length);
  R.zamik = 0;

  sb = zagon(PORT_B, { ADMIN_PRIJAVE_EMAIL: "admin1@outly.test", PRIJAVE_MAIL_NA_URO: "2" });
  sc = zagon(PORT_C, {});
  await cakajStreznik(B); await cakajStreznik(C);
  await resetLimit();
  R.poslano.length = 0;
  for (const k of ["lastnik", "admin", "ana", "bor"]) {
    r = await zahtevek(B, "POST", "/reports", T.blokar, { target_type: "user", target_id: U[k], reason: "spam" });
    assert(r.status === 201, `instanca B (meja 2 maila/h): prijava ${k}: 201`, r.body);
  }
  // Odlocitev o mailu pade sinhrono po odgovoru: ko sta v dnevniku 2 preskoka, je bilo obdelanih vseh 4 prijav, poslana pa morata biti 2 maila.
  assert(await cakaj(() => (sb.log.match(/mail za prijavo \d+ preskocen/g) || []).length === 2), "preskok maila je zapisan v dnevnik (2 od 4 prijav)");
  assert(await cakaj(() => R.poslano.length === 2), "meja PRIJAVE_MAIL_NA_URO=2: poslana natanko 2 maila od 4 prijav", R.poslano.length);
  R.poslano.length = 0;
  r = await zahtevek(C, "POST", "/reports", T.blokar, { target_type: "user", target_id: U.cene, reason: "spam" });
  assert(r.status === 201, "instanca C brez ADMIN_PRIJAVE_EMAIL: prijava 201", r.body); const idC = r.body.id;
  const rA = await api("POST", "/reports", T.blokar, { target_type: "user", target_id: U.dan, reason: "spam" });
  assert(rA.status === 201, "kontrolna prijava na instanci A (z naslovom): 201", rA.body);
  assert(await cakaj(() => R.poslano.length >= 1), "mail kontrolne prijave pride", R.poslano.length);
  assert(R.poslano.length === 1 && String(R.poslano[0].subject).includes("#" + rA.body.id) && !String(R.poslano[0].subject).includes("#" + idC),
    "instanca C brez ADMIN_PRIJAVE_EMAIL: mail NI poslan (do kontrolnega maila ni drugega)", R.poslano.map(m => m.subject));
  sb.srv.kill(); sc.srv.kill();

  // ====================================================================================================
  console.log("\n# 4. Admin");
  await resetLimit();
  r = await api("GET", "/admin/api/reports", null);
  assert(r.status === 401, "GET /admin/api/reports brez zetona: 401", r.status);
  r = await api("GET", "/admin/api/reports", T.ana);
  assert(r.status === 403, "navaden uporabnik: 403", r.status);
  r = await api("GET", "/admin/api/reports", T.lastnik);
  assert(r.status === 403, "lastnik kluba (business): 403", r.status);
  r = await api("PATCH", `/admin/api/reports/${idUser}`, T.ana, { status: "resolved" });
  assert(r.status === 403, "PATCH za navadnega uporabnika: 403", r.status);
  assert((await pool.query("SELECT status FROM reports WHERE id=$1", [idUser])).rows[0].status === "open", "403 ni spremenil prijave");

  r = await api("GET", "/admin/api/reports", T.admin);
  assert(r.status === 200 && Array.isArray(r.body.reports) && r.body.reports.length > 5, "admin: seznam odprtih prijav { reports: [...] }", r.status);
  const po = (id) => (r.body.reports || []).find(x => x.id === id);
  const kljuci = Object.keys(r.body.reports[0]).sort().join(",");
  assert(kljuci === "created_at,details,id,note,reason,reporter_username,resolved_at,status,target_id,target_label,target_type", "oblika vrstice po pogodbi", kljuci);
  assert(po(idKlub) && po(idKlub).target_label === "Pure Club" && po(idKlub).reporter_username === "ana" && po(idKlub).target_type === "club", "klub: target_label = ime kluba, reporter_username", po(idKlub));
  assert(po(idDogodek) && po(idDogodek).target_label === "Glavni (Pure Club)", "dogodek: target_label = naslov (klub)", po(idDogodek));
  assert(po(idMedia) && po(idMedia).target_label === "Pure Club" && po(idMedia).details.startsWith("https://"), "media: target_label = ime kluba, details = URL slike", po(idMedia));
  assert(r.body.reports.some(x => x.target_type === "user" && x.target_label === "bor"), "uporabnik: target_label = uporabnisko ime");
  assert(r.body.reports.every(x => x.status === "open"), "privzeto samo odprte");
  const casi = r.body.reports.map(x => new Date(x.created_at).getTime());
  assert(casi.every((c, i) => i === 0 || casi[i - 1] >= c), "najnovejse prve");
  assert(!/@/.test(JSON.stringify(r.body)), "seznam NE vsebuje nobenega e-naslova");
  r = await api("GET", "/admin/api/reports?status=resolved", T.admin);
  assert(r.status === 200 && r.body.reports.length === 0, "status=resolved: se nic");
  r = await api("GET", "/admin/api/reports?status=vse", T.admin);
  assert(r.status === 400 && r.body.error === "invalid_status", "neveljaven status: 400", r.body);
  const vseOdprte = (await api("GET", "/admin/api/reports", T.admin)).body.reports.length;

  r = await api("GET", "/admin/api/summary", T.admin);
  assert(r.status === 200 && r.body.open_reports === vseOdprte, "GET /admin/api/summary: open_reports = stevilo odprtih", [r.body.open_reports, vseOdprte]);

  r = await api("PATCH", `/admin/api/reports/${idUser}`, T.admin, { status: "resolved", note: "  Opozorjen, klub obvescen.  " });
  assert(r.status === 200 && r.body.report && r.body.report.id === idUser && r.body.report.status === "resolved" && r.body.report.note === "Opozorjen, klub obvescen." && r.body.report.resolved_at, "PATCH resolved + opomba: 200 { report }", r.body);
  vrst = (await pool.query("SELECT status, resolved_at, resolved_by, note FROM reports WHERE id=$1", [idUser])).rows[0];
  assert(vrst.resolved_by === U.admin && vrst.resolved_at !== null, "v bazi: resolved_by = admin, resolved_at nastavljen", vrst);
  r = await api("GET", "/admin/api/reports?status=resolved", T.admin);
  assert(r.body.reports.length === 1 && r.body.reports[0].id === idUser, "status=resolved vsebuje resene");
  r = await api("GET", "/admin/api/reports", T.admin);
  assert(!r.body.reports.some(x => x.id === idUser) && r.body.reports.length === vseOdprte - 1, "odprti seznam resene ne vsebuje vec");
  r = await api("GET", "/admin/api/reports?status=all", T.admin);
  assert(r.body.reports.some(x => x.id === idUser) && r.body.reports.length === vseOdprte, "status=all vsebuje odprte in resene");
  const cas1 = (await pool.query("SELECT resolved_at FROM reports WHERE id=$1", [idUser])).rows[0].resolved_at;
  await pocakaj(20);
  r = await api("PATCH", `/admin/api/reports/${idUser}`, T.admin2, { status: "resolved" });
  vrst = (await pool.query("SELECT resolved_at, resolved_by, note FROM reports WHERE id=$1", [idUser])).rows[0];
  assert(r.status === 200 && +vrst.resolved_at === +cas1 && vrst.resolved_by === U.admin && vrst.note === "Opozorjen, klub obvescen.", "ponovna razresitev (drug admin): cas in razresitelj ostaneta, opomba brez polja ostane", vrst);
  r = await api("PATCH", `/admin/api/reports/${idUser}`, T.admin, { status: "open", note: null });
  vrst = (await pool.query("SELECT status, resolved_at, resolved_by, note FROM reports WHERE id=$1", [idUser])).rows[0];
  assert(r.status === 200 && vrst.status === "open" && vrst.resolved_at === null && vrst.resolved_by === null && vrst.note === null, "ponovno odprtje + note null: resolved_at/by/note pocisceni", vrst);
  r = await api("PATCH", `/admin/api/reports/${idUser}`, T.admin, { status: "bogus" });
  assert(r.status === 400 && r.body.error === "invalid_status", "PATCH neveljaven status: 400", r.body);
  r = await api("PATCH", `/admin/api/reports/${idUser}`, T.admin, {});
  assert(r.status === 400, "PATCH brez statusa: 400", r.status);
  r = await api("PATCH", `/admin/api/reports/${idUser}`, T.admin, { status: "resolved", note: "x".repeat(1001) });
  assert(r.status === 400 && r.body.error === "invalid_note", "PATCH opomba 1001 znakov: 400", r.body);
  r = await api("PATCH", `/admin/api/reports/${idUser}`, T.admin, { status: "resolved", note: 7 });
  assert(r.status === 400 && r.body.error === "invalid_note", "PATCH opomba ni niz: 400", r.body);
  assert((await pool.query("SELECT status FROM reports WHERE id=$1", [idUser])).rows[0].status === "open", "zavrnjeni PATCH-i niso spremenili prijave");
  r = await api("PATCH", "/admin/api/reports/abc", T.admin, { status: "resolved" });
  assert(r.status === 400 && r.body.error === "invalid_id", "PATCH neveljaven id: 400", r.body);
  r = await api("PATCH", "/admin/api/reports/999999", T.admin, { status: "resolved" });
  assert(r.status === 404 && r.body.error === "not_found", "PATCH neobstojeca prijava: 404", r.body);
  r = await api("PATCH", `/admin/api/reports/${idKlub}`, T.admin, { status: "resolved", note: "<img src=x onerror=alert(1)>" });
  assert(r.status === 200 && r.body.report.note === "<img src=x onerror=alert(1)>", "opomba se shrani dobesedno (izpis je v panelu varen, glej spodaj)");
  await api("PATCH", `/admin/api/reports/${idKlub}`, T.admin, { status: "open", note: null });

  const html = fs.readFileSync(path.join(__dirname, "..", "admin", "index.html"), "utf8");
  const od = html.indexOf("// ---------- reports");
  const do_ = html.indexOf("// ---------- zagon");
  assert(od > 0 && do_ > od && /data-z="prijave"/.test(html) && /id="z-prijave"/.test(html) && /prijave: naloziPrijave/.test(html), "admin panel ima zavihek »Reports« (gumb + sekcija + koda)", [od, do_]);
  const koda = html.slice(od, do_);
  assert(!/innerHTML|insertAdjacentHTML|outerHTML|document\.write/.test(koda), "admin panel: koda Reports NE rabi innerHTML (podatki prijaviteljev samo prek textContent, XSS)", null);
  assert(/\/admin\/api\/reports/.test(koda) && /"PATCH"/.test(koda) && /status=/.test(koda), "admin panel: uporablja GET in PATCH /admin/api/reports", null);

  // ====================================================================================================
  console.log("\n# 5. Blokiranje: POST/DELETE/GET /me/blocks");
  await resetLimit();
  r = await api("POST", `/me/blocks/${U.bor}`, null);
  assert(r.status === 401, "POST /me/blocks brez zetona: 401", r.status);
  r = await api("GET", "/me/blocks", null);
  assert(r.status === 401, "GET /me/blocks brez zetona: 401", r.status);
  r = await api("DELETE", `/me/blocks/${U.bor}`, null);
  assert(r.status === 401, "DELETE /me/blocks brez zetona: 401", r.status);
  r = await api("POST", `/me/blocks/${U.ana}`, T.ana);
  assert(r.status === 400 && r.body.error === "invalid_target", "blokiranje sebe: 400 invalid_target", r.body);
  for (const id of ["abc", "0", "-3", "99999999999"]) {
    r = await api("POST", `/me/blocks/${id}`, T.ana);
    assert(r.status === 400 && r.body.error === "invalid_target", `POST /me/blocks/${id}: 400 invalid_target`, [r.status, r.body]);
  }
  r = await api("DELETE", "/me/blocks/abc", T.ana);
  assert(r.status === 400 && r.body.error === "invalid_target", "DELETE /me/blocks/abc: 400", r.body);
  r = await api("POST", "/me/blocks/99999", T.ana);
  assert(r.status === 404 && r.body.error === "not_found", "blokiranje neobstojecega: 404 not_found", r.body);
  r = await api("POST", `/me/blocks/${kopija}`, T.ana);
  assert(r.status === 404 && r.body.error === "not_found", "blokiranje racuna za kopije: 404", r.body);
  r = await api("GET", "/me/blocks", T.ana);
  assert(r.status === 200 && Array.isArray(r.body.blocks) && r.body.blocks.length === 0, "GET /me/blocks: prazen seznam { blocks: [] }", r.body);

  // Priprava: ana-bor prijatelja, ana->dan cakajoca prosnja, evi->ana cakajoca prosnja
  r = await prijatelja("ana", "bor");
  assert(r.status === 200 && (await stPrijateljev("ana", "bor")) === 1, "ana in bor sta prijatelja", r.body);
  r = await api("POST", "/me/friends/requests", T.ana, { user_id: U.dan });
  assert(r.status === 201, "ana -> dan cakajoca prosnja", r.body);
  r = await api("POST", "/me/friends/requests", T.evi, { user_id: U.ana });
  assert(r.status === 201, "evi -> ana cakajoca prosnja", r.body);
  const casPrej = Date.now();
  r = await api("POST", `/me/blocks/${U.bor}`, T.ana);
  assert(r.status === 204 && r.text === "", "ana blokira bora: 204", [r.status, r.text]);
  assert((await stBlokov("ana", "bor")) === 1 && (await stBlokov("bor", "ana")) === 0, "v bazi: blok ana -> bor (ena smer)");
  assert((await stPrijateljev("ana", "bor")) === 0, "prijateljstvo ana-bor je izginilo");
  r = await api("POST", `/me/blocks/${U.dan}`, T.ana);
  r = await api("POST", `/me/blocks/${U.evi}`, T.ana);
  assert(r.status === 204 && (await stCakajocih("ana", "dan")) === 0 && (await stCakajocih("ana", "evi")) === 0, "blok pobrise cakajoce prosnje v obe smeri (odhodna dan, dohodna evi)");
  const prosnje = (await pool.query("SELECT status FROM friend_requests WHERE (from_user_id=$1 AND to_user_id=$2) OR (from_user_id=$3 AND to_user_id=$1)", [U.ana, U.dan, U.evi])).rows;
  assert(prosnje.length === 2 && prosnje.every(x => x.status === "cancelled"), "prosnji sta oznaceni kot cancelled (ne izbrisani)", prosnje);
  r = await api("GET", "/me/friends", T.ana);
  assert(r.body.friends.length === 0 && r.body.requests_in.length === 0 && r.body.requests_out.length === 0, "GET /me/friends (ana): brez prijateljev in prosenj", r.body);
  r = await api("GET", "/me/friends", T.bor);
  assert(r.body.friends.length === 0, "GET /me/friends (bor): prijatelja ni vec", r.body);
  r = await api("GET", "/me/friends", T.dan);
  assert(r.body.requests_in.length === 0, "dan nima vec dohodne prosnje", r.body);
  r = await api("GET", "/me", T.dan);
  assert(r.body.pending_friend_requests === 0, "dan: pending_friend_requests = 0", r.body.pending_friend_requests);

  r = await api("POST", `/me/blocks/${U.bor}`, T.ana);
  assert(r.status === 204, "ponovno blokiranje istega: 204 (idempotentno)", r.status);
  assert((await pool.query("SELECT COUNT(*)::int AS n FROM user_blocks WHERE blocker_id=$1", [U.ana])).rows[0].n === 3, "ana ima 3 bloke (bor, dan, evi), podvojenega ni");
  r = await api("GET", "/me/blocks", T.ana);
  assert(r.status === 200 && r.body.blocks.length === 3, "GET /me/blocks: 3 vnosi", r.body);
  const bb = r.body.blocks.find(x => x.user_id === U.bor);
  assert(bb && bb.username === "bor" && "avatar_url" in bb && new Date(bb.blocked_at).getTime() >= casPrej - 2000 && Object.keys(bb).sort().join(",") === "avatar_url,blocked_at,user_id,username", "oblika vnosa: { user_id, username, avatar_url, blocked_at }", bb);
  assert(new Date(r.body.blocks[0].blocked_at) >= new Date(r.body.blocks[2].blocked_at), "najnovejsi blok prvi");
  r = await api("GET", "/me/blocks", T.bor);
  assert(r.status === 200 && r.body.blocks.length === 0, "bor (blokirani) v svojem seznamu ne vidi nicesar (kdo je blokiral njega se ne razkrije)", r.body);
  r = await api("GET", "/me", T.bor);
  assert(!/block/i.test(JSON.stringify(r.body)), "GET /me blokiranega NE omenja bloka");

  r = await api("DELETE", `/me/blocks/${U.dan}`, T.ana);
  assert(r.status === 204, "odblokiranje: 204", r.status);
  r = await api("DELETE", `/me/blocks/${U.dan}`, T.ana);
  assert(r.status === 204, "ponovno odblokiranje: 204 (idempotentno)", r.status);
  r = await api("DELETE", `/me/blocks/${U.cene}`, T.ana);
  assert(r.status === 204, "odblokiranje nikoli blokiranega: 204", r.status);
  assert((await stPrijateljev("ana", "dan")) === 0 && (await stCakajocih("ana", "dan")) === 0, "odblok NE obnovi prosnje ne prijateljstva");
  r = await api("DELETE", `/me/blocks/${U.bor}`, T.bor);
  assert(r.status === 204 && (await stBlokov("ana", "bor")) === 1, "bor ne more odstraniti Aninega bloka (brise samo svoje)");

  console.log("\n# 5b. Meja blokov (BLOKI_NAJVEC=3)");
  for (const k of ["ana", "bor", "cene"]) { r = await api("POST", `/me/blocks/${U[k]}`, T.blokar); assert(r.status === 204, `blokar blokira ${k}: 204`, r.status); }
  r = await api("POST", `/me/blocks/${U.dan}`, T.blokar);
  assert(r.status === 409 && r.body.error === "blocks_limit", "4. blok: 409 blocks_limit", r.body);
  r = await api("POST", `/me/blocks/${U.ana}`, T.blokar);
  assert(r.status === 204, "ponovni blok ob polni meji: 204 (idempotentno)", r.status);
  await api("DELETE", `/me/blocks/${U.ana}`, T.blokar);
  r = await api("POST", `/me/blocks/${U.dan}`, T.blokar);
  assert(r.status === 204, "po odblokiranju je mesto prosto: 204", r.status);
  await pool.query("DELETE FROM user_blocks WHERE blocker_id=$1", [U.blokar]);

  // ====================================================================================================
  console.log("\n# 6. Ucinek bloka v obe smeri (ana je blokirala bora)");
  await resetLimit();
  const isci = async (t, q) => { const x = await api("GET", `/users/search?q=${q}`, t); return x.status === 200 ? x.body.users.map(u => u.username) : x; };
  assert((await isci(T.ana, "bor")).length === 0, "iskanje: ana ne najde bora (blokirani)");
  assert((await isci(T.bor, "ana")).length === 0, "iskanje: bor ne najde ane (blokiral ga je ona; obratna smer)");
  assert((await isci(T.cene, "bor")).includes("bor") && (await isci(T.cene, "ana")).includes("ana"), "iskanje: cene (tretji) najde oba");
  assert((await isci(T.ana, "cene")).includes("cene"), "iskanje: ana se vedno najde druge");
  assert((await isci(T.ana, "bo")).length === 0, "iskanje po predponi »bo«: tudi nic");

  r = await api("POST", "/me/friends/requests", T.ana, { user_id: U.bor });
  const ana_bor = r;
  assert(r.status === 404 && r.body.error === "no_account", "ana -> bor (user_id): 404 no_account", [r.status, r.body]);
  r = await api("POST", "/me/friends/requests", T.bor, { user_id: U.ana });
  assert(r.status === 404 && r.body.error === "no_account", "bor -> ana (user_id, obratna smer): 404 no_account", [r.status, r.body]);
  r = await api("POST", "/me/friends/requests", T.bor, { username: "ana" });
  const neznan = await api("POST", "/me/friends/requests", T.bor, { username: "nihce_ni" });
  assert(r.status === 404 && JSON.stringify(r.body) === JSON.stringify(neznan.body) && neznan.status === 404, "bor -> ana (username): odgovor je ENAK kot za neobstojecega uporabnika (blokirani ne izve)", [r.body, neznan.body]);
  r = await api("POST", "/me/friends/requests", T.ana, { username: "bor" });
  assert(r.status === 404 && JSON.stringify(r.body) === JSON.stringify(neznan.body), "ana -> bor (username): enak odgovor", r.body);
  assert((await stPrijateljev("ana", "bor")) === 0 && (await stCakajocih("ana", "bor")) === 0, "po zavrnjenih prosnjah ni ne prijateljstva ne prosnje");
  r = await api("POST", "/me/friends/requests", T.cene, { user_id: U.ana });
  assert(r.status === 201, "tretji (cene) lahko poslje prosnjo ani: 201", r.body);

  // prenos vstopnice
  r = await api("POST", `/events/${evA}/orders`, T.ana, { quantity: 1 });
  assert(r.status === 201, "ana kupi vstopnico", r.body); const vstAna = r.body.tickets[0].id;
  r = await api("POST", `/events/${evA}/orders`, T.bor, { quantity: 1 });
  assert(r.status === 201, "bor kupi vstopnico", r.body); const vstBor = r.body.tickets[0].id;
  await pool.query("INSERT INTO friendships (user_a, user_b) VALUES (LEAST($1::int,$2::int), GREATEST($1::int,$2::int)) ON CONFLICT DO NOTHING", [U.ana, U.bor]);   // zastarelo prijateljstvo (obvod API-ja): blok ga vseeno prevlada
  const sporociloPrijatelj = "You can only send a ticket by user to one of your friends.";
  r = await api("POST", `/tickets/${vstAna}/transfer`, T.ana, { user_id: U.bor });
  assert(r.status === 404, "prenos ana -> bor (user_id, tudi ob zastarelem prijateljstvu): 404", [r.status, r.body]);
  r = await api("POST", `/tickets/${vstAna}/transfer`, T.ana, { email: "bor@outly.si" });
  assert(r.status === 404 && /No Outly account/.test(String(r.body)), "prenos ana -> bor (e-naslov): 404 »No Outly account«", [r.status, r.body]);
  r = await api("POST", `/tickets/${vstAna}/transfer`, T.ana, { email: "bor@outly.si", allow_guest: true });
  assert(r.status === 404, "prenos ana -> bor (e-naslov, allow_guest): 404 (gost ne obide bloka)", [r.status, r.body]);
  // IZRECNO ZAPISANO VEDENJE (DECISIONS 10. 10. 2026, ARCHITECTURE I30): pot allow_guest z e-naslovom RACUNA, ki je v bloku, vrne 404, za neznan e-naslov pa
  // gostujoci prenos uspe (200). Razlika razkrije blok SAMO tistemu, ki pozna tocen e-naslov blokirajocega. Navidezni 200 bi pustil vstopnico pri posiljatelju
  // (zavedel bi ga), prenos kot gost pa bi obsel blok. Ce kdo to spremeni, mora spremeniti tudi odlocitev in ta test.
  r = await api("POST", `/events/${evB}/orders`, T.ana, { quantity: 1 });
  assert(r.status === 201, "ana kupi se eno vstopnico (dogodek Drugi) za preizkus gostujocega prenosa", r.body); const vstAna2 = r.body.tickets[0].id;
  r = await api("POST", `/tickets/${vstAna2}/transfer`, T.ana, { email: "bor@outly.si", allow_guest: true });
  assert(r.status === 404, "allow_guest + e-naslov racuna v bloku: 404 (blok ni obvod)", [r.status, r.body]);
  r = await api("POST", `/tickets/${vstAna2}/transfer`, T.ana, { email: "nihce.znan@example.com", allow_guest: true });
  assert(r.status === 200 && r.body.result === "ok", "allow_guest + neznan e-naslov: 200 (gostujoci prenos) - znana razlika do 404 zgoraj, zavestno", [r.status, r.body]);
  r = await api("POST", `/tickets/${vstBor}/transfer`, T.bor, { user_id: U.ana });
  assert(r.status === 404, "prenos bor -> ana (user_id, obratna smer): 404", [r.status, r.body]);
  r = await api("POST", `/tickets/${vstBor}/transfer`, T.bor, { email: "ana@outly.si" });
  assert(r.status === 404, "prenos bor -> ana (e-naslov, obratna smer): 404", [r.status, r.body]);
  r = await api("POST", `/tickets/${vstBor}/transfer`, T.bor, { email: "ana@outly.si", allow_guest: true });
  assert(r.status === 404, "prenos bor -> ana (e-naslov, allow_guest, obratna smer): 404", [r.status, r.body]);
  assert((await pool.query("SELECT COUNT(*)::int AS n FROM ticket_transfers WHERE ticket_id IN ($1,$2)", [vstAna, vstBor])).rows[0].n === 0, "noben prenos ni zapisan");
  assert((await pool.query("SELECT holder_user_id FROM tickets WHERE id=$1", [vstAna])).rows[0].holder_user_id === null, "vstopnica ostane pri kupcu (ana)");
  r = await api("POST", `/tickets/${vstAna}/transfer`, T.ana, { email: "cene@outly.si" });
  assert(r.status === 200, "prenos tretjemu (cene) po e-naslovu deluje: 200 (blok ni splosna zavrnitev)", [r.status, r.body]);

  // guest lista
  r = await api("POST", "/admin/api/guest-lists", T.admin, { event_id: evA, user_id: U.ana, spots: 3 });
  assert(r.status === 201, "admin: guest lista gostitelja ana", [r.status, r.body]); const listaAna = r.body.guest_list.id;
  r = await api("POST", "/admin/api/guest-lists", T.admin, { event_id: evB, user_id: U.bor, spots: 3 });
  assert(r.status === 201, "admin: guest lista gostitelja bor", [r.status, r.body]); const listaBor = r.body.guest_list.id;
  await pool.query("INSERT INTO friendships (user_a, user_b) VALUES (LEAST($1::int,$2::int), GREATEST($1::int,$2::int)) ON CONFLICT DO NOTHING", [U.ana, U.cene]);
  r = await api("POST", `/me/guest-lists/${listaAna}/invites`, T.ana, { user_ids: [U.bor] });
  assert(r.status === 403, "ana povabi bora na listo (zastarelo prijateljstvo + blok): 403", [r.status, r.body]);
  r = await api("POST", `/me/guest-lists/${listaAna}/invites`, T.ana, { user_ids: [U.cene, U.bor] });
  assert(r.status === 403, "ana povabi cenetaa in bora: 403, vse ali nic", [r.status, r.body]);
  assert((await pool.query("SELECT COUNT(*)::int AS n FROM guest_list_members WHERE guest_list_id=$1", [listaAna])).rows[0].n === 0, "na listi ni nikogar (tudi cene ne)");
  r = await api("POST", `/me/guest-lists/${listaBor}/invites`, T.bor, { user_ids: [U.ana] });
  assert(r.status === 403, "bor povabi ano (obratna smer): 403", [r.status, r.body]);
  assert((await pool.query("SELECT COUNT(*)::int AS n FROM guest_list_members WHERE guest_list_id=$1", [listaBor])).rows[0].n === 0, "na Borovi listi ni nikogar");
  r = await api("POST", `/me/guest-lists/${listaAna}/invites`, T.ana, { user_ids: [U.cene] });
  assert(r.status === 201, "ana povabi cenetaa (prijatelj, brez bloka): 201", [r.status, r.body]);

  // vabilo v ekipo
  r = await api("POST", `/me/blocks/${U.lastnik}`, T.dan);
  assert(r.status === 204, "dan blokira lastnika kluba", r.status);
  r = await api("POST", "/business/team", T.lastnik, { email: "dan@outly.si", role: "doorman" });
  assert(r.status === 404 && r.body.error === "no_account", "lastnik vabi dana v ekipo (dan ga je blokiral): 404 no_account", [r.status, r.body]);
  r = await api("POST", `/me/blocks/${U.fani}`, T.lastnik);
  r = await api("POST", "/business/team", T.lastnik, { email: "fani@outly.si", role: "doorman" });
  assert(r.status === 404 && r.body.error === "no_account", "lastnik vabi fani (lastnik jo je blokiral): 404 no_account", [r.status, r.body]);
  r = await api("POST", "/business/team", T.lastnik, { email: "cene@outly.si", role: "doorman" });
  assert(r.status === 201, "vabilo neblokiranemu (cene): 201", [r.status, r.body]);
  await api("DELETE", `/me/blocks/${U.lastnik}`, T.dan);
  r = await api("POST", "/business/team", T.lastnik, { email: "dan@outly.si", role: "doorman" });
  assert(r.status === 201, "po odblokiranju vabilo dana: 201", [r.status, r.body]);
  await api("DELETE", `/me/blocks/${U.fani}`, T.lastnik);

  // odblok
  console.log("  (odblok)");
  r = await api("DELETE", `/me/blocks/${U.bor}`, T.ana);
  assert(r.status === 204, "ana odblokira bora: 204", r.status);
  await pool.query("DELETE FROM friendships WHERE user_a = LEAST($1::int,$2::int) AND user_b = GREATEST($1::int,$2::int)", [U.ana, U.bor]);
  assert((await isci(T.ana, "bor")).includes("bor") && (await isci(T.bor, "ana")).includes("ana"), "po odblokiranju se spet najdeta (obe smeri)");
  r = await api("POST", "/me/friends/requests", T.bor, { user_id: U.ana });
  assert(r.status === 201, "po odblokiranju: bor poslje prosnjo ani: 201", [r.status, r.body]);
  r = await api("POST", `/me/friends/requests/${r.body.request.id}/accept`, T.ana);
  assert(r.status === 200, "ana sprejme: 200", r.body);
  r = await api("POST", `/me/guest-lists/${listaAna}/invites`, T.ana, { user_ids: [U.bor] });
  assert(r.status === 201, "po odblokiranju in novem prijateljstvu: povabilo bora na listo: 201", [r.status, r.body]);
  r = await api("POST", `/tickets/${vstBor}/transfer`, T.bor, { user_id: U.ana });
  assert(r.status === 200, "po odblokiranju: prenos bor -> ana (user_id, prijatelja): 200", [r.status, r.body]);
  void ana_bor;

  // ====================================================================================================
  console.log("\n# 7. Tekmovanje: blokiranje proti prosnji / sprejemu");
  await resetLimit();
  const pocisti = async () => {
    await pool.query("DELETE FROM user_blocks WHERE blocker_id IN ($1,$2) AND blocked_id IN ($1,$2)", [U.ana, U.bor]);
    await pool.query("DELETE FROM friendships WHERE user_a = LEAST($1::int,$2::int) AND user_b = GREATEST($1::int,$2::int)", [U.ana, U.bor]);
    await pool.query("DELETE FROM friend_requests WHERE from_user_id IN ($1,$2) AND to_user_id IN ($1,$2)", [U.ana, U.bor]);
  };
  const dodajProsnjo = async (od, komu) => (await pool.query("INSERT INTO friend_requests (from_user_id, to_user_id) VALUES ($1,$2) RETURNING id", [U[od], U[komu]])).rows[0].id;
  let narobe = 0, pet = 0, skupaj = 0;
  for (let i = 0; i < 14; i++) {
    await pocisti();
    let rezultati;
    if (i % 2 === 0) {
      await dodajProsnjo("ana", "bor");   // nasprotna prosnja ze caka: prosnja bora jo sprejme (ustvari prijateljstvo)
      rezultati = await Promise.all([api("POST", `/me/blocks/${U.ana}`, T.bor), api("POST", "/me/friends/requests", T.bor, { user_id: U.ana })]);
    } else {
      const pid = await dodajProsnjo("bor", "ana");
      rezultati = await Promise.all([api("POST", `/me/blocks/${U.bor}`, T.ana), api("POST", `/me/friends/requests/${pid}/accept`, T.ana)]);
    }
    skupaj++;
    if (rezultati.some(x => x.status >= 500)) pet++;
    if (rezultati[0].status !== 204) narobe++;
    const koncno = { blok: (await pool.query("SELECT COUNT(*)::int AS n FROM user_blocks WHERE (blocker_id=$1 AND blocked_id=$2) OR (blocker_id=$2 AND blocked_id=$1)", [U.ana, U.bor])).rows[0].n,
      prij: await stPrijateljev("ana", "bor"), cak: await stCakajocih("ana", "bor") };
    if (koncno.blok !== 1 || koncno.prij !== 0 || koncno.cak !== 0) { narobe++; console.log("    krog", i, JSON.stringify(koncno), rezultati.map(x => x.status)); }
  }
  assert(narobe === 0 && pet === 0, `${skupaj} krogov (blok + prosnja/sprejem hkrati): vedno blok, NIKOLI prijateljstvo ali cakajoca prosnja, nikoli 5xx`, { narobe, pet });
  await pocisti();

  // ====================================================================================================
  console.log("\n# 8. Izbris racuna (DELETE /me)");
  await resetLimit();
  await pool.query("TRUNCATE reports RESTART IDENTITY");
  r = await api("POST", `/me/blocks/${U.cene}`, T.evi);
  assert(r.status === 204, "evi blokira cenetaa", r.status);
  r = await api("POST", `/me/blocks/${U.evi}`, T.bor);
  assert(r.status === 204, "bor blokira evi", r.status);
  r = await prijava(T.evi, { target_type: "club", target_id: 1, reason: "spam", details: "evi pise" });
  const idEvi1 = r.body.id;
  r = await prijava(T.evi, { target_type: "user", target_id: U.cene, reason: "harassment" });
  r = await prijava(T.ana, { target_type: "user", target_id: U.evi, reason: "impersonation", details: "o evi" });
  const idOEvi = r.body.id;
  r = await api("PATCH", `/admin/api/reports/${idEvi1}`, T.admin2, { status: "resolved", note: "ok" });
  assert(r.status === 200, "admin2 razresi prijavo", r.status);
  assert((await pool.query("SELECT COUNT(*)::int AS n FROM user_blocks WHERE blocker_id=$1 OR blocked_id=$1", [U.evi])).rows[0].n === 3, "pred izbrisom: 3 bloki evi (en narejen, dva prejeta: bor in ana)");
  r = await api("DELETE", "/me", T.evi, { password: "x" });
  assert(r.status === 200, "evi izbrise racun: 200 (z bloki in prijavami)", [r.status, r.body]);
  assert((await pool.query("SELECT COUNT(*)::int AS n FROM user_blocks WHERE blocker_id=$1 OR blocked_id=$1", [U.evi])).rows[0].n === 0, "po izbrisu: bloki evi (narejeni in prejeti) so izbrisani");
  assert((await pool.query("SELECT COUNT(*)::int AS n FROM user_blocks WHERE blocker_id=$1 AND blocked_id=$2", [U.evi, U.cene])).rows[0].n === 0, "blok evi -> cene ne obstaja vec");
  const prijaveEvi = (await pool.query("SELECT id, reporter_id, details FROM reports WHERE id = ANY($1::int[]) ORDER BY id", [[idEvi1, idEvi1 + 1]])).rows;
  assert(prijaveEvi.length === 2 && prijaveEvi.every(x => x.reporter_id === null), "prijave izbrisane evi ostanejo, prijavitelj je NULL (anonimizirano)", prijaveEvi);
  r = await api("GET", "/admin/api/reports?status=all", T.admin);
  const ev1 = r.body.reports.find(x => x.id === idEvi1), oEvi = r.body.reports.find(x => x.id === idOEvi);
  assert(ev1 && ev1.reporter_username === null && ev1.target_label === "Pure Club", "admin: prijava izbrisane prijaviteljice kaze reporter_username null", ev1);
  assert(oEvi && oEvi.target_label === null && oEvi.reporter_username === "ana" && oEvi.status === "open", "admin: prijava o izbrisani uporabnici ostane, target_label null", oEvi);
  r = await api("PATCH", `/admin/api/reports/${idOEvi}`, T.admin, { status: "resolved", note: "uporabnica je izbrisana" });
  assert(r.status === 200 && r.body.report.target_label === null, "prijavo o izbrisanem cilju je mogoce razresiti");
  r = await api("POST", `/me/blocks/${U.evi}`, T.ana);
  assert(r.status === 404, "blokiranje izbrisane uporabnice: 404", r.status);
  r = await api("DELETE", "/me", T.admin2, { password: "x" });
  assert(r.status === 200, "admin2 (ki je razresil prijavo) izbrise racun: 200", [r.status, r.body]);
  vrst = (await pool.query("SELECT status, resolved_by, resolved_at FROM reports WHERE id=$1", [idEvi1])).rows[0];
  assert(vrst.status === "resolved" && vrst.resolved_by === null && vrst.resolved_at !== null, "izbris admina: resolved_by NULL, prijava ostane resena", vrst);

  // ====================================================================================================
  console.log("\n# 9. Omejevalnik POST /reports");
  await resetLimit();
  let zadnji = null, st429b = 0;
  for (let i = 0; i < 21; i++) { zadnji = await api("POST", "/reports", T.ana, { target_type: "club", target_id: 1, reason: "spam" }); if (zadnji.status === 429) st429b++; }
  assert(zadnji.status === 429 && st429b === 1 && zadnji.headers.get("retry-after"), "21. zahtevek v eni uri (20/h/IP): 429 + Retry-After", [zadnji.status, st429b]);

  assert(!/TypeError|Unhandled|server_error|nepricakovana napaka/i.test(sa.log), "log backenda brez nepricakovanih napak", sa.log.split("\n").filter(l => /TypeError|Unhandled|nepricakovana/i.test(l)).slice(0, 5));
  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  for (const s of [sa, sb, sc]) { try { s && s.srv.kill(); } catch (e) {} }
  jwksServer.close(); resendServer.close(); await pool.end();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); for (const s of [sa, sb, sc]) { try { s && s.srv.kill(); } catch (_) {} } process.exit(1); });
