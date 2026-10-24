#!/usr/bin/env node
/**
 * Test ODZIVOV POD CLANKI POMOCI (migracija 049, 13. 10. 2026, »Was this helpful?« v iOS aplikaciji). Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_pomoc_odzivi.js
 * Vzorec kot test_prijave.js: lokalni JWKS (3966), backend na 3365, TRUNCATE na zacetku.
 *
 *  1  priprava: uporabniki (navadna, admin, poslovna)
 *  2  POST /help/feedback: 401 brez zetona, 400 invalid_article (oblika, dolzina, tip, manjka), 400 invalid_helpful (niz, stevilo, null, manjka), nic se ne zapise
 *  3  204 + upsert: dva glasova istega uporabnika za isti clanek = ena vrstica z zadnjo vrednostjo, updated_at se premakne, created_at ne; drug clanek / drug uporabnik = nova vrstica;
 *     neznan (nov) clanek je sprejet (strezniku seznam clankov ni znan); 40 znakov je se dovoljenih
 *  4  GET /admin/api/help-feedback: samo agregati (article, helpful, not_helpful, last_at; brez uporabnikov), urejeno po stevilu glasov padajoce, stevila so cela; 401 brez zetona, 403 za ne-admina
 *  5  izbris racuna (DELETE /me): glasovi izbrisanega uporabnika izginejo (CASCADE), glasovi drugih ostanejo, agregat se zmanjsa
 *  6  zavihek »Pomoc – odzivi« v admin/index.html (staticno): povezan v nav in v tabelo nalozi, brez innerHTML s podatki
 *  7  omejevalnik POST /help/feedback (120/h/IP): 121. zahtevek 429 + Retry-After
 */
const crypto = require("crypto");
const http = require("http");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT_A = 3365, JWKS_PORT = 3966;
const A = `http://127.0.0.1:${PORT_A}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-pomoc";
const jwksServer = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url.startsWith("/auth/v1/user")) { try { const t = JSON.parse(Buffer.from(String(req.headers.authorization).split(".")[1], "base64url")); return res.end(JSON.stringify({ id: t.sub, email: t.email, email_confirmed_at: "2026-01-01T00:00:00Z" })); } catch (_) { res.statusCode = 401; return res.end("{}"); } }   // potrditev e-naslova pri viru (#222)
  if (req.url.startsWith("/auth/v1/settings")) return res.end(JSON.stringify({ mailer_autoconfirm: false, external: { anonymous_users: false } }));
  res.end(JSON.stringify({ keys: [{ ...jwk, kid: KID, alg: "ES256", use: "sig" }] }));   // vse ostalo (tudi grant_type=password in rpc/delete_my_account ob DELETE /me) odgovori 200
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
async function zahtevek(baza, method, p, token, body) {
  const r = await fetch(baza + p, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, text: t, headers: r.headers };
}
const api = (m, p, t, b) => zahtevek(A, m, p, t, b);

function zagon(port, okolje) {
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, QR_SECRET: "test", ...okolje }, stdio: ["ignore", "pipe", "pipe"] });
  const s = { srv, log: "" };
  srv.stdout.on("data", d => s.log += d); srv.stderr.on("data", d => s.log += d);
  return s;
}
async function cakajStreznik(baza) { for (let i = 0; i < 80; i++) { try { await fetch(baza + "/"); return; } catch { await pocakaj(100); } } }

let sa = null;
(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, help_feedback, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  sa = zagon(PORT_A, {});
  await cakajStreznik(A);
  const resetLimit = () => pool.query("TRUNCATE omejitve");

  const imena = ["ana", "bor", "cene", "admin", "poslovna"];
  const T = {}, U = {};
  imena.forEach((k, i) => { T[k] = zeton(`${k}@outly.si`, uuid(i + 1)); });
  console.log("\n# 1. Priprava");
  for (const k of imena) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); U[k] = r.body.id; }
  await pool.query("UPDATE users SET role='admin' WHERE email = 'admin@outly.si'");
  await pool.query("UPDATE users SET role='business' WHERE email = 'poslovna@outly.si'");
  const stVrstic = async () => (await pool.query("SELECT COUNT(*)::int AS n FROM help_feedback")).rows[0].n;
  const vrstica = async (u, clanek) => (await pool.query("SELECT helpful, created_at, updated_at FROM help_feedback WHERE user_id=$1 AND article=$2", [u, clanek])).rows;

  // ====================================================================================================
  console.log("\n# 2. POST /help/feedback: validacija");
  let r = await api("POST", "/help/feedback", null, { article: "buy", helpful: true });
  assert(r.status === 401, "brez zetona: 401", r.status);
  const slabiClanki = [
    ["Buy", "velike crke"], ["buy_tickets", "podcrtaj"], ["buy tickets", "presledek"], ["", "prazen niz"], ["a".repeat(41), "41 znakov"],
    ["clanek!", "locilo"], ["članek", "sumnik"], ["buy/../x", "poševnica"], [123, "stevilo"], [null, "null"], [["buy"], "seznam"], [{ x: 1 }, "objekt"], [true, "boolean"],
  ];
  for (const [v, opis] of slabiClanki) {
    r = await api("POST", "/help/feedback", T.ana, { article: v, helpful: true });
    assert(r.status === 400 && r.body.error === "invalid_article" && r.body.message, `article ${opis}: 400 invalid_article + message`, [r.status, r.body]);
  }
  r = await api("POST", "/help/feedback", T.ana, { helpful: true });
  assert(r.status === 400 && r.body.error === "invalid_article", "brez article: 400 invalid_article", r.body);
  r = await api("POST", "/help/feedback", T.ana);
  assert(r.status === 400 && r.body.error === "invalid_article", "brez telesa: 400 invalid_article", r.body);
  for (const [v, opis] of [["true", "niz"], [1, "stevilo 1"], [0, "stevilo 0"], [null, "null"], [[], "seznam"], [{}, "objekt"]]) {
    r = await api("POST", "/help/feedback", T.ana, { article: "buy", helpful: v });
    assert(r.status === 400 && r.body.error === "invalid_helpful" && r.body.message, `helpful ${opis}: 400 invalid_helpful + message`, [r.status, r.body]);
  }
  r = await api("POST", "/help/feedback", T.ana, { article: "buy" });
  assert(r.status === 400 && r.body.error === "invalid_helpful", "brez helpful: 400 invalid_helpful", r.body);
  assert(await stVrstic() === 0, "po vseh zavrnjenih zahtevkih ni zapisano nic");

  // ====================================================================================================
  console.log("\n# 3. 204 + upsert");
  r = await api("POST", "/help/feedback", T.ana, { article: "buy", helpful: true });
  assert(r.status === 204 && r.text === "", "prvi glas: 204 brez telesa", [r.status, r.text]);
  let v = await vrstica(U.ana, "buy");
  assert(v.length === 1 && v[0].helpful === true, "zapisan glas ana/buy = koristno", v);
  const ustvarjen = v[0].created_at, posodobljen1 = v[0].updated_at;
  await pocakaj(30);
  r = await api("POST", "/help/feedback", T.ana, { article: "buy", helpful: false });
  assert(r.status === 204, "ponovni glas istega uporabnika: 204", r.status);
  v = await vrstica(U.ana, "buy");
  assert(v.length === 1 && v[0].helpful === false, "ponovni glas prepise: se vedno ena vrstica, vrednost = zadnja (ni koristno)", v);
  assert(+v[0].created_at === +ustvarjen && +v[0].updated_at > +posodobljen1, "created_at ostane, updated_at se premakne");
  r = await api("POST", "/help/feedback", T.ana, { article: "buy", helpful: false });
  assert(r.status === 204 && (await vrstica(U.ana, "buy")).length === 1, "enak glas znova: 204, se vedno ena vrstica");
  r = await api("POST", "/help/feedback", T.ana, { article: "transfer", helpful: true });
  assert(r.status === 204, "drug clanek istega uporabnika: 204", r.status);
  r = await api("POST", "/help/feedback", T.bor, { article: "buy", helpful: true });
  assert(r.status === 204, "isti clanek, drug uporabnik: 204", r.status);
  assert(await stVrstic() === 3, "skupaj 3 vrstice (ana/buy, ana/transfer, bor/buy)", await stVrstic());
  const nov = "club-scanner-2-nov-clanek";
  r = await api("POST", "/help/feedback", T.cene, { article: nov, helpful: true });
  assert(r.status === 204 && (await vrstica(U.cene, nov)).length === 1, "clanek, ki ga strezniku nihce ni naznanil, je sprejet (brez seznama clankov)", r.status);
  const dolg = "a".repeat(40);
  r = await api("POST", "/help/feedback", T.cene, { article: dolg, helpful: false });
  assert(r.status === 204 && (await vrstica(U.cene, dolg)).length === 1, "40 znakov je se dovoljenih", r.status);
  r = await api("POST", "/help/feedback", T.cene, { article: "1", helpful: false, drugo: "ignorirano" });
  assert(r.status === 204, "samo stevke in dodatna polja v telesu: 204", r.status);
  r = await api("POST", "/help/feedback", T.poslovna, { article: "club-scanner", helpful: true });
  assert(r.status === 204, "poslovni uporabnik tudi lahko glasuje: 204", r.status);
  r = await api("POST", "/help/feedback", T.admin, { article: "buy", helpful: true });
  assert(r.status === 204, "admin tudi lahko glasuje: 204", r.status);

  // ====================================================================================================
  console.log("\n# 4. GET /admin/api/help-feedback");
  r = await api("GET", "/admin/api/help-feedback", null);
  assert(r.status === 401 || r.status === 403, "brez zetona: zavrnjeno", r.status);
  for (const k of ["ana", "poslovna"]) {
    r = await api("GET", "/admin/api/help-feedback", T[k]);
    assert(r.status === 403, `ne-admin (${k}): 403`, r.status);
  }
  r = await api("GET", "/admin/api/help-feedback", T.admin);
  assert(r.status === 200 && Array.isArray(r.body.articles), "admin: 200 + articles[]", [r.status, r.body]);
  const clanki = r.body.articles;
  const buy = clanki.find(x => x.article === "buy"), transfer = clanki.find(x => x.article === "transfer");
  assert(buy && buy.helpful === 2 && buy.not_helpful === 1, "buy: 2 koristno (bor, admin), 1 ni koristno (ana, zadnji glas)", buy);
  assert(transfer && transfer.helpful === 1 && transfer.not_helpful === 0, "transfer: 1 koristno", transfer);
  assert(clanki.every(x => Number.isInteger(x.helpful) && Number.isInteger(x.not_helpful) && typeof x.article === "string" && !isNaN(Date.parse(x.last_at))), "stevci so cela stevila, last_at je cas", clanki);
  assert(clanki.every(x => Object.keys(x).sort().join() === "article,helpful,last_at,not_helpful"), "natanko polja article, helpful, not_helpful, last_at", clanki.map(x => Object.keys(x)));
  assert(clanki[0].article === "buy", "urejeno po stevilu glasov padajoce (buy = 3 glasovi prvi)", clanki.map(x => x.article));
  const glasovi = clanki.map(x => x.helpful + x.not_helpful);
  assert(glasovi.every((n, i) => i === 0 || glasovi[i - 1] >= n), "vrstni red nikoli ne narasca", glasovi);
  const vsebina = r.text;
  assert(!/outly\.si|user_id|email|ana|bor@/i.test(vsebina.replace(/"article":"[^"]*"/g, "")), "odgovor ne vsebuje uporabnikov ali e-naslovov");
  const lastBuy = (await pool.query("SELECT MAX(updated_at) AS m FROM help_feedback WHERE article='buy'")).rows[0].m;
  assert(+new Date(buy.last_at) === +lastBuy, "last_at = cas zadnjega glasu za clanek", [buy.last_at, lastBuy]);

  // ====================================================================================================
  console.log("\n# 5. Izbris racuna (DELETE /me)");
  const pred = await stVrstic();
  r = await api("DELETE", "/me", T.ana, { password: "x" });
  assert(r.status === 200, "ana izbrise racun: 200 (nova tabela ne podre izbrisa)", [r.status, r.body]);
  assert((await pool.query("SELECT COUNT(*)::int AS n FROM help_feedback WHERE user_id=$1", [U.ana])).rows[0].n === 0, "glasovi izbrisane uporabnice so pobrisani (CASCADE)");
  assert(await stVrstic() === pred - 2, "izbrisana sta natanko 2 glasova (buy, transfer); glasovi drugih ostanejo", [pred, await stVrstic()]);
  assert((await vrstica(U.bor, "buy")).length === 1, "glas bor/buy ostane");
  r = await api("GET", "/admin/api/help-feedback", T.admin);
  const buy2 = r.body.articles.find(x => x.article === "buy"), tr2 = r.body.articles.find(x => x.article === "transfer");
  assert(buy2 && buy2.helpful === 2 && buy2.not_helpful === 0 && !tr2, "agregat po izbrisu: buy 2/0, transfer izgine", r.body.articles);
  r = await api("DELETE", "/me", T.cene, { password: "x" });
  assert(r.status === 200, "cene (z dvema glasovoma) izbrise racun: 200", [r.status, r.body]);

  // ====================================================================================================
  console.log("\n# 6. Zavihek v admin panelu (staticno)");
  const html = fs.readFileSync(path.join(__dirname, "..", "admin", "index.html"), "utf8");
  assert(/<button data-z="pomoc">Pomoč – odzivi<\/button>/.test(html), "nav ima gumb »Pomoč – odzivi«");
  assert(/<section id="z-pomoc" class="skrito">/.test(html) && /id="po_tabela"/.test(html), "obstaja razdelek z-pomoc s tabelo");
  assert(/pomoc: naloziPomoc/.test(html), "zavihek je v tabeli nalozi");
  const fn = html.slice(html.indexOf("async function naloziPomoc"), html.indexOf("$(\"po_osvezi\").onclick"));
  assert(fn.length > 100 && fn.includes("/admin/api/help-feedback") && !/innerHTML/.test(fn), "naloziPomoc ne rabi innerHTML (podatki prek h() = textContent)");
  for (const g of ["Članek", "Koristno", "Ni koristno", "Delež koristnih", "Zadnji glas"]) assert(fn.includes(g), `stolpec »${g}«`);

  // ====================================================================================================
  console.log("\n# 7. Omejevalnik POST /help/feedback");
  await resetLimit();
  let zadnji = null, st429 = 0, st204 = 0;
  for (let i = 0; i < 121; i++) {
    zadnji = await api("POST", "/help/feedback", T.bor, { article: "buy", helpful: i % 2 === 0 });
    if (zadnji.status === 429) st429++; else if (zadnji.status === 204) st204++;
  }
  assert(zadnji.status === 429 && st429 === 1 && st204 === 120 && zadnji.headers.get("retry-after"), "121. zahtevek v eni uri (120/h/IP): 429 + Retry-After", [zadnji.status, st204, st429]);

  assert(!/TypeError|Unhandled|server_error|nepricakovana napaka/i.test(sa.log), "log backenda brez nepricakovanih napak", sa.log.split("\n").filter(l => /TypeError|Unhandled|nepricakovana/i.test(l)).slice(0, 5));
  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  try { sa && sa.srv.kill(); } catch (e) {}
  jwksServer.close(); await pool.end();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); try { sa && sa.srv.kill(); } catch (_) {} process.exit(1); });
