#!/usr/bin/env node
/**
 * Povezava racuna po e-naslovu in nov racun samo s potrditvijo PRI VIRU (outly-backend#222, invarianta I35).
 * Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres@localhost:5450/postgres" node _testi/test_povezava_racuna.js
 *
 * Skripta dvigne lokalni »Supabase« (JWKS + stub GET /auth/v1/user na portu 3342), podpise ES256 zetone in
 * zazene backend na portu 3341 s SUPABASE_URL=http://127.0.0.1:3342. Resend ni nastavljen.
 *
 * Dve plasti (B1 pregleda): (1) varovalo ob izklopu »Confirm email« je ZAVRNITEV (fail closed): javni
 * GET /auth/v1/settings, mailer_autoconfirm ali external.anonymous_users = true -> nobenih novih povezav ali vrstic
 * (503), ker GoTrue takrat sam nastavi email_confirmed_at in user_metadata.email_verified; (2) GET /auth/v1/user.
 *
 * Ozadje: user_metadata.email_verified v zetonu lahko prijavljen uporabnik spreminja sam (updateUser({data})).
 * Zato jo backend sme uporabiti le kot hitri filter; lastnistvo naslova potrdi z Supabasovim /auth/v1/user
 * (email_confirmed_at != null, enak e-naslov), in to samo ob prvem klicu racuna (uid brez lokalne vrstice).
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3341, STUB_PORT = 3342, PORT2 = 3343;
const BASE = `http://127.0.0.1:${PORT}`;
const KLJUC_API = "sb_publishable_testni_kljuc";

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-povezava";

// Stub: kaj vrne /auth/v1/user za posamezen sub (kljuc = sub iz zetona); stevec klicev po subu.
const stub = { odgovori: new Map(), klici: new Map(), glave: [], skupaj: 0,
  nastavitve: { status: 200, telo: { mailer_autoconfirm: false, external: { anonymous_users: false } } }, stNastavitev: 0, glaveNastavitev: [] };
function nastavi(sub, odgovor) { stub.odgovori.set(sub, odgovor); }
function klicev(sub) { return stub.klici.get(sub) || 0; }

const stubServer = http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url.startsWith("/auth/v1/user")) {
    stub.skupaj++;
    let sub = "?";
    try { sub = JSON.parse(Buffer.from(String(req.headers.authorization || "").split(".")[1], "base64url")).sub; } catch (_) {}
    stub.klici.set(sub, klicev(sub) + 1);
    stub.glave.push({ authorization: req.headers.authorization, apikey: req.headers.apikey, sub });
    const o = stub.odgovori.get(sub);
    if (!o) { res.statusCode = 404; return res.end(JSON.stringify({ msg: "ni" })); }
    if (o.visi) return;                          // nikoli ne odgovori (casovna omejitev backenda)
    res.statusCode = o.status || 200;
    return res.end(JSON.stringify(o.telo === undefined ? {} : o.telo));
  }
  if (req.url.startsWith("/auth/v1/settings")) {
    stub.stNastavitev++; stub.glaveNastavitev.push({ apikey: req.headers.apikey });
    if (stub.nastavitve.visi) return;
    res.statusCode = stub.nastavitve.status;
    return res.end(JSON.stringify(stub.nastavitve.telo));
  }
  res.end(JSON.stringify({ keys: [{ ...jwk, kid: KID, alg: "ES256", use: "sig" }] }));
});

function b64u(o) { return Buffer.from(typeof o === "string" ? o : JSON.stringify(o)).toString("base64url"); }
function zeton(email, sub, meta) {
  const now = Math.floor(Date.now() / 1000);
  const h = b64u({ alg: "ES256", typ: "JWT", kid: KID });
  const p = b64u({ iss: `http://127.0.0.1:${STUB_PORT}/auth/v1`, aud: "authenticated", sub, email, exp: now + 3600, iat: now,
    user_metadata: meta === undefined ? { email_verified: true } : meta });
  const sig = crypto.sign("sha256", Buffer.from(h + "." + p), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return h + "." + p + "." + sig.toString("base64url");
}
function uuid(n) { return `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`; }
const POTRJEN = (email, id) => ({ status: 200, telo: { id, email, email_confirmed_at: "2026-10-01T10:00:00Z" } });
const NEPOTRJEN = (email, id) => ({ status: 200, telo: { id, email, email_confirmed_at: null, confirmed_at: null } });

let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }

async function api(method, path, token, baza = BASE) {
  const r = await fetch(baza + path, { method, headers: token ? { authorization: "Bearer " + token } : {} });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, retryAfter: r.headers.get("retry-after") };
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  const vrstice = async (email) => (await pool.query("SELECT id, email, supabase_uid, password_hash FROM users WHERE lower(email)=$1", [email])).rows;
  const stVrstic = async () => Number((await pool.query("SELECT count(*) AS n FROM users")).rows[0].n);

  await new Promise(r => stubServer.listen(STUB_PORT, r));
  const zazeni = async (port) => {
    const o = { log: "" };
    o.srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${STUB_PORT}`,
      SUPABASE_PUBLISHABLE_KEY: KLJUC_API, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
    o.srv.stdout.on("data", d => o.log += d); o.srv.stderr.on("data", d => o.log += d);
    for (let i = 0; i < 50; i++) { try { await fetch(`http://127.0.0.1:${port}/`); break; } catch { await new Promise(r => setTimeout(r, 100)); } }
    return o;
  };
  const glavni = await zazeni(PORT);
  const srv = glavni.srv;
  const spi = (ms) => new Promise(r => setTimeout(r, ms));

  // Stare lokalne vrstice (iz casov lastne prijave, brez supabase_uid) in vrstica, ki ze kaze na DRUG uid.
  await pool.query("INSERT INTO users (email, password_hash, username, email_verified) VALUES ('stara@outly.si', 'hash', 'stara', true), ('zrtev@outly.si', 'hash', 'zrtev', true), ('stara2@outly.si', 'hash', 'stara_dve', true)");
  await pool.query("INSERT INTO users (email, password_hash, username, email_verified, supabase_uid) VALUES ('povezan@outly.si', NULL, 'povezan', true, $1)", [uuid(900)]);
  const zacetnoVrstic = await stVrstic();

  console.log("\n# (a) user_metadata.email_verified=true, a /user pravi, da naslov NI potrjen -> zavrnjeno");
  nastavi(uuid(1), NEPOTRJEN("napadalec@outly.si", uuid(1)));
  let r = await api("GET", "/me", zeton("napadalec@outly.si", uuid(1)));
  assert(r.status === 403, "nov racun z nepotrjenim naslovom -> 403", r);
  assert((await vrstice("napadalec@outly.si")).length === 0, "nova vrstica NI nastala");
  nastavi(uuid(2), NEPOTRJEN("stara@outly.si", uuid(2)));
  r = await api("GET", "/me", zeton("stara@outly.si", uuid(2)));
  assert(r.status === 403, "tuj stari racun z nepotrjenim naslovom -> 403", r);
  let v = await vrstice("stara@outly.si");
  assert(v.length === 1 && v[0].supabase_uid === null, "stara vrstica ostane brez supabase_uid (ni prevzema)", v);
  const k2 = klicev(uuid(2));
  r = await api("GET", "/me", zeton("stara@outly.si", uuid(2)));
  assert(r.status === 403 && klicev(uuid(2)) === k2, "ponovni poskus: spet 403, brez novega klica na /user (negativni predpomnilnik)", { r, k: klicev(uuid(2)), k2 });

  console.log("\n# (a2) user_metadata.email_verified manjka ali false -> zavrnjeno brez klica na /user");
  const pred = stub.skupaj;
  r = await api("GET", "/me", zeton("nihce@outly.si", uuid(3), {}));
  assert(r.status === 403, "brez email_verified -> 403", r);
  r = await api("GET", "/me", zeton("nihce@outly.si", uuid(3), { email_verified: false }));
  assert(r.status === 403, "email_verified=false -> 403", r);
  assert(stub.skupaj === pred, "hitri filter: nobenega klica na /user");

  console.log("\n# (b) potrjen naslov -> poveze staro vrstico");
  nastavi(uuid(4), POTRJEN("stara@outly.si", uuid(4)));
  stub.glave.length = 0;
  const tokB = zeton("stara@outly.si", uuid(4));
  r = await api("GET", "/me", tokB);
  assert(r.status === 200 && r.body.email === "stara@outly.si", "GET /me -> 200", r);
  v = await vrstice("stara@outly.si");
  assert(v.length === 1 && v[0].supabase_uid === uuid(4) && v[0].password_hash === "hash", "stara vrstica poveze z novim uid (ista vrstica, podatki ostanejo)", v);
  assert(stub.glave.length === 1 && stub.glave[0].authorization === "Bearer " + tokB && stub.glave[0].apikey === KLJUC_API,
    "klic /user z uporabnikovim zetonom (Bearer) in javnim kljucem (apikey)", stub.glave);

  console.log("\n# (b2) samo confirmed_at (generiran LEAST(email, phone)) NE zadostuje; velike crke v /user se ujemajo");
  nastavi(uuid(5), { status: 200, telo: { id: uuid(5), email: "stara2@outly.si", confirmed_at: "2026-10-01T10:00:00Z" } });
  r = await api("GET", "/me", zeton("stara2@outly.si", uuid(5)));
  v = await vrstice("stara2@outly.si");
  assert(r.status === 403 && v.length === 1 && v[0].supabase_uid === null, "samo confirmed_at -> 403, nepovezano", { r, v });
  nastavi(uuid(17), { status: 200, telo: { id: uuid(17).toUpperCase(), email: "Stara2@Outly.si", email_confirmed_at: "2026-10-01T10:00:00Z" } });
  r = await api("GET", "/me", zeton("stara2@outly.si", uuid(17)));
  v = await vrstice("stara2@outly.si");
  assert(r.status === 200 && v.length === 1 && v[0].supabase_uid === uuid(17), "email_confirmed_at zadostuje, primerjava e-naslova in id brez razlike v crkah", { r, v });

  console.log("\n# (c) nov uporabnik s potrjenim naslovom -> nova vrstica");
  nastavi(uuid(6), POTRJEN("nov@outly.si", uuid(6)));
  r = await api("GET", "/me", zeton("nov@outly.si", uuid(6)));
  v = await vrstice("nov@outly.si");
  assert(r.status === 200 && v.length === 1 && v[0].supabase_uid === uuid(6) && v[0].password_hash === null, "nova vrstica z uid", { r, v });

  console.log("\n# (d) izpad Supabase -> 503 (ne 401), nic zapisanega");
  const pred2 = await stVrstic();
  nastavi(uuid(7), { status: 500, telo: { msg: "boom" } });
  r = await api("GET", "/me", zeton("izpad@outly.si", uuid(7)));
  assert(r.status === 503 && r.retryAfter, "/user 500 -> 503 + Retry-After", r);
  const k7 = klicev(uuid(7));
  r = await api("GET", "/me", zeton("izpad@outly.si", uuid(7)));
  assert(r.status === 503 && r.retryAfter && klicev(uuid(7)) === k7, "S2: ponovitev takoj po izpadu istega zetona: se vedno 503, BREZ novega klica na /user (kratek negativni predpomnilnik)", { status: r.status, k: klicev(uuid(7)) - k7 });
  nastavi(uuid(8), { status: 403, telo: { msg: "User from sub claim in JWT does not exist" } });
  r = await api("GET", "/me", zeton("izpad@outly.si", uuid(8)));
  assert(r.status === 503, "/user 403 -> 503 (ne 401: ni ločljivo od napacnega kljuca; uporabnik ostane prijavljen)", r);
  nastavi(uuid(9), { status: 200, telo: "ni objekt" });
  r = await api("GET", "/me", zeton("izpad@outly.si", uuid(9)));
  assert(r.status === 503, "/user odgovor brez objekta -> 503", r);
  nastavi(uuid(10), { visi: true });
  const t0 = Date.now();
  r = await api("GET", "/me", zeton("izpad@outly.si", uuid(10)));
  const dt = Date.now() - t0;
  assert(r.status === 503 && dt >= 4500 && dt < 9000, "/user brez odgovora -> 503 po ~5 s", { status: r.status, dt });
  assert(await stVrstic() === pred2 && (await vrstice("izpad@outly.si")).length === 0, "po izpadih ni zapisano nic");
  nastavi(uuid(7), POTRJEN("izpad@outly.si", uuid(7)));
  await spi(1000);   // od prvega izpada tega zetona je ze > 5 s (casovna omejitev spodaj), negativni predpomnilnik je potekel
  r = await api("GET", "/me", zeton("izpad@outly.si", uuid(7)));
  assert(r.status === 200, "po izteku predpomnilnika in ko Supabase spet dela, isti uporabnik uspe (izpad ni trajna zavrnitev)", r);

  console.log("\n# (e) obstoječi uporabnik (vrstica po supabase_uid) -> NOBENEGA klica na /user");
  const sub = uuid(4);
  nastavi(sub, { status: 500, telo: {} });           // ce bi backend klical /user, bi dobil 500
  const pred3 = klicev(sub);
  const pred3s = stub.skupaj;
  for (let i = 0; i < 3; i++) { r = await api("GET", "/me", tokB); if (r.status !== 200) break; }
  assert(r.status === 200 && klicev(sub) === pred3 && stub.skupaj === pred3s, "3x GET /me po povezavi: 200 in 0 novih klicev na /user", { status: r.status, k: klicev(sub) - pred3 });
  r = await api("GET", "/me", zeton("povezan@outly.si", uuid(900), {}));
  assert(r.status === 200, "obstoječi uporabnik brez user_metadata.email_verified se prijavi kot doslej (filter velja samo za nove)", r);

  console.log("\n# (f) konflikt e-naslova z DRUGIM uid: brez potrditve ni prepisa");
  nastavi(uuid(11), NEPOTRJEN("povezan@outly.si", uuid(11)));
  r = await api("GET", "/me", zeton("povezan@outly.si", uuid(11)));
  v = await vrstice("povezan@outly.si");
  assert(r.status === 403 && v.length === 1 && v[0].supabase_uid === uuid(900), "nepotrjen napadalec NE prepise supabase_uid zrtve", { r, v });
  nastavi(uuid(12), { status: 500, telo: {} });
  r = await api("GET", "/me", zeton("povezan@outly.si", uuid(12)));
  v = await vrstice("povezan@outly.si");
  assert(r.status === 503 && v[0].supabase_uid === uuid(900), "izpad Supabase tudi ne prepise", { r, v });
  nastavi(uuid(13), POTRJEN("povezan@outly.si", uuid(13)));
  r = await api("GET", "/me", zeton("povezan@outly.si", uuid(13)));
  v = await vrstice("povezan@outly.si");
  assert(r.status === 200 && v.length === 1 && v[0].supabase_uid === uuid(13), "po potrditvi pri viru je prepis legitimen (lastnik naslova se je znova registriral)", { r, v });

  console.log("\n# (g) e-naslov v /user se ne ujema z zetonom -> zavrnjeno");
  nastavi(uuid(14), POTRJEN("drug@outly.si", uuid(14)));
  r = await api("GET", "/me", zeton("zrtev@outly.si", uuid(14)));
  v = await vrstice("zrtev@outly.si");
  assert(r.status === 403 && v.length === 1 && v[0].supabase_uid === null, "zeton trdi zrtev@, Supabase potrjuje drug@ -> 403, zrtev ni povezan", { r, v });
  nastavi(uuid(15), POTRJEN("zrtev@outly.si", uuid(99)));
  r = await api("GET", "/me", zeton("zrtev@outly.si", uuid(15)));
  v = await vrstice("zrtev@outly.si");
  assert(r.status === 403 && v[0].supabase_uid === null, "id v /user se ne ujema s sub zetona -> 403", { r, v });

  nastavi(uuid(18), { status: 200, telo: { email: "zrtev@outly.si", email_confirmed_at: "2026-10-01T10:00:00Z" } });
  r = await api("GET", "/me", zeton("zrtev@outly.si", uuid(18)));
  v = await vrstice("zrtev@outly.si");
  assert(r.status === 403 && v[0].supabase_uid === null, "N1: id manjka v /user -> 403", { r, v });

  console.log("\n# (h) vzporedni prvi klici istega racuna = en klic na Supabase");
  nastavi(uuid(16), POTRJEN("vzporedno@outly.si", uuid(16)));
  const tokH = zeton("vzporedno@outly.si", uuid(16));
  const rs = await Promise.all([1, 2, 3, 4, 5].map(() => api("GET", "/me", tokH)));
  assert(rs.every(x => x.status === 200), "vseh 5 vzporednih klicev -> 200", rs.map(x => x.status));
  assert(klicev(uuid(16)) === 1, "en sam klic na /user", klicev(uuid(16)));
  assert((await vrstice("vzporedno@outly.si")).length === 1, "ena vrstica");

  console.log("\n# (i) /auth/v1/settings: privzeto (Confirm email vklopljen) -> klic je predpomnjen 60 s");
  const st0 = stub.stNastavitev;
  for (let i = 0; i < 20; i++) {
    const e = `serija${i}@outly.si`, id = uuid(200 + i);
    nastavi(id, POTRJEN(e, id));
    r = await api("GET", "/me", zeton(e, id));
    if (r.status !== 200) break;
  }
  assert(r.status === 200, "20 zaporednih novih uporabnikov -> vsi 200", r);
  assert(stub.stNastavitev === 1, "v celi seji natanko 1 klic na /auth/v1/settings (predpomnilnik 60 s)", stub.stNastavitev);
  assert(stub.glaveNastavitev.every(g => g.apikey === KLJUC_API), "klic z javnim kljucem (apikey)");

  console.log("\n# Stevilo vrstic: samo legitimne spremembe");
  // zacetne 4 + stara/stara2 povezani (ista vrstica) + nov + izpad + vzporedno = 4 + 3
  assert(await stVrstic() === zacetnoVrstic + 3 + 20, "nove vrstice: nov, izpad, vzporedno + 20 iz serije (povezave starih vrstic niso nove)", { zdaj: await stVrstic(), zacetno: zacetnoVrstic });

  console.log("\n# (j) B1: »Confirm email« izklopljen (mailer_autoconfirm) ali anonimni uporabniki -> ZAVRNITEV novih povezav (fail closed)");
  // GoTrue ob izklopljenem »Confirm email« sam nastavi email_confirmed_at in user_metadata.email_verified, zato /user
  // v tem scenariju trdi »potrjen«. Varovalo je zavrnitev po javnih nastavitvah; vsak primer dobi svež proces (predpomnilnik 60 s).
  await pool.query("INSERT INTO users (email, password_hash, username, email_verified) VALUES ('zrtev3@outly.si', 'hash', 'zrtev3', true)");
  await pool.query("INSERT INTO users (email, password_hash, username, email_verified, supabase_uid) VALUES ('obstojec@outly.si', NULL, 'obstojec', true, $1)", [uuid(950)]);
  const primer = async (ime, nastavitve, id) => {
    stub.nastavitve = nastavitve;
    const p = await zazeni(PORT2), baza2 = `http://127.0.0.1:${PORT2}`;
    const vrstic0 = await stVrstic();
    // napadalec: /user (po GoTrue) pravi »potrjen«, user_metadata.email_verified = true
    nastavi(uuid(id), POTRJEN("zrtev3@outly.si", uuid(id)));
    let a = await api("GET", "/me", zeton("zrtev3@outly.si", uuid(id)), baza2);
    assert(a.status === 503 && a.retryAfter, `${ime}: prevzem stare vrstice -> 503 + Retry-After (ne 401)`, a);
    let vv = await vrstice("zrtev3@outly.si");
    assert(vv.length === 1 && vv[0].supabase_uid === null, `${ime}: stara vrstica ostane nepovezana`, vv);
    nastavi(uuid(id + 1), POTRJEN("nov-" + id + "@outly.si", uuid(id + 1)));
    a = await api("GET", "/me", zeton("nov-" + id + "@outly.si", uuid(id + 1)), baza2);
    assert(a.status === 503 && await stVrstic() === vrstic0 && (await vrstice("nov-" + id + "@outly.si")).length === 0, `${ime}: nov uid -> 503, nobene nove vrstice`, a);
    nastavi(uuid(id + 2), POTRJEN("povezan@outly.si", uuid(id + 2)));
    a = await api("GET", "/me", zeton("povezan@outly.si", uuid(id + 2)), baza2);
    vv = await vrstice("povezan@outly.si");
    assert(a.status === 503 && vv[0].supabase_uid === uuid(13), `${ime}: rezervni prepis supabase_uid tudi zavrnjen`, { a, vv });
    // vroca pot: obstojec uporabnik po uid brez klica na /settings in /user
    const s0 = stub.stNastavitev, u0 = stub.skupaj;
    a = await api("GET", "/me", zeton("obstojec@outly.si", uuid(950), {}), baza2);
    assert(a.status === 200 && stub.stNastavitev === s0 && stub.skupaj === u0, `${ime}: obstojeci uporabnik (po uid) -> 200 brez klica na /settings ali /user`, { status: a.status, s: stub.stNastavitev - s0, u: stub.skupaj - u0 });
    const alarmov = (p.log.match(/\[auth\] POZOR/g) || []).length;
    assert(alarmov === 1, `${ime}: glasen console.error, a najvec en zapis na 60 s (3 zavrnitve -> 1 zapis)`, { alarmov, log: p.log.slice(-300) });
    p.srv.kill(); await spi(300);
  };
  await primer("mailer_autoconfirm=true", { status: 200, telo: { mailer_autoconfirm: true, external: { anonymous_users: false } } }, 300);
  await primer("anonymous_users=true", { status: 200, telo: { mailer_autoconfirm: false, external: { anonymous_users: true } } }, 310);

  console.log("\n# (k) izpad ali pokvarjen odgovor /auth/v1/settings -> 503, nic zapisanega; okrevanje brez predpomnjene zavrnitve");
  {
    const vrstic0 = await stVrstic();
    const p = await zazeni(PORT2), baza2 = `http://127.0.0.1:${PORT2}`;
    for (const [ime, n] of [["500", { status: 500, telo: {} }], ["404", { status: 404, telo: {} }], ["slab JSON (brez polj)", { status: 200, telo: { keys: [] } }], ["mailer_autoconfirm ni boolean", { status: 200, telo: { mailer_autoconfirm: "false", external: { anonymous_users: false } } }], ["brez odgovora (5 s)", { visi: true }]]) {
      stub.nastavitve = n;
      nastavi(uuid(320), POTRJEN("zrtev3@outly.si", uuid(320)));
      const t0 = Date.now();
      const a = await api("GET", "/me", zeton("zrtev3@outly.si", uuid(320)), baza2);
      assert(a.status === 503 && a.retryAfter && (!n.visi || Date.now() - t0 >= 4500), `/settings ${ime} -> 503 + Retry-After`, { status: a.status, dt: Date.now() - t0 });
      const vv = await vrstice("zrtev3@outly.si");
      assert(vv[0].supabase_uid === null && await stVrstic() === vrstic0, `/settings ${ime}: nic zapisanega`);
    }
    stub.nastavitve = { status: 200, telo: { mailer_autoconfirm: false, external: { anonymous_users: false } } };
    await spi(5500);   // izteče tudi negativni predpomnilnik /user za uid 320 (ni bil klican, a za vsak slučaj)
    nastavi(uuid(321), POTRJEN("okrevanje@outly.si", uuid(321)));
    const a = await api("GET", "/me", zeton("okrevanje@outly.si", uuid(321)), baza2);
    assert(a.status === 200, "ko /settings spet dela, nov uporabnik uspe (izpad ni predpomnjen)", a);
    p.srv.kill(); await spi(300);
  }

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  if (fail) console.log("\n--- log streznika ---\n" + glavni.log);
  srv.kill(); stubServer.closeAllConnections && stubServer.closeAllConnections(); stubServer.close(); await pool.end();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
