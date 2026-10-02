#!/usr/bin/env node
/**
 * Idempotentni kljuc nakupa (issue #112, invarianta I18). Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL=postgres://postgres:postgres@localhost:5432/outly node _testi/test_idempotenca.js
 *
 * Glava `Idempotency-Key` (UUID) na POST /events/:id/orders in POST /events/:id/tables/:tableId/orders:
 *   1  neveljavna oblika -> 400; brez glave -> obnasanje kot prej (dve enaki zahtevi = dve narocili)
 *   2  ponovni poskus (zaporedno) vrne ISTO narocilo (201 + Idempotent-Replayed), zaloga se zmanjsa enkrat; velja tudi
 *      za razprodan dogodek in ne porablja nakupnih poskusov (omejevalnik 20/h)
 *   3  isti kljuc, druga vsebina (kolicina, dogodek, miza, paket, vrsta nakupa) -> 422
 *   4  kljuc je vezan na uporabnika (isti UUID drugega uporabnika = njegovo lastno narocilo)
 *   5  hkratni zahtevki z istim kljucem (en proces; dva procesa) -> natanko eno narocilo, vsi dobijo isto
 *   6  neuspeh se ne zapomni (409 pred prodajo, nato isti kljuc uspe)
 *   7  I2: zaloga drzi tudi pri podvojenih zahtevkih
 *   8  VIP mize: ponovitev, hkratnost (tudi dva procesa), 422, paket
 *   9  CORS: preflight dovoli Idempotency-Key, Retry-After in Idempotent-Replayed sta izpostavljena
 *   10 baza: delni unikaten indeks (user_id, idempotency_key)
 *   11 cakanje v pomnilniku: ponovitev ne zaseda mesta v semaforju; 409 request_in_progress po IDEMPOTENCA_CAKANJE_MS;
 *      odjemalec, ki odide, ne kupi (duh), ponovitev po prekinitvi sredi transakcije dobi isto narocilo
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const JWKS_PORT = 3981, PORT_A = 3982, PORT_B = 3983, PORT_S = 3984, PORT_T = 3985;
const A = `http://127.0.0.1:${PORT_A}`, B = `http://127.0.0.1:${PORT_B}`, S = `http://127.0.0.1:${PORT_S}`, T_ = `http://127.0.0.1:${PORT_T}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-idem";
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
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra).slice(0, 300) : ""); } }
const spi = (ms) => new Promise(r => setTimeout(r, ms));
const nov = () => crypto.randomUUID();

const procesi = {};
let ipStevec = 0;
const novIp = () => `10.20.${(++ipStevec >> 8) & 255}.${(ipStevec & 255) + 1}`;
async function api(base, method, path, token, body, opc = {}) {
  const t0 = performance.now();
  try {
    const r = await fetch(base + path, {
      method,
      headers: { "content-type": "application/json", "x-forwarded-for": opc.ip || novIp(), ...(token ? { authorization: "Bearer " + token } : {}), ...(opc.glave || {}) },
      body: body !== undefined ? JSON.stringify(body) : undefined, signal: opc.signal || AbortSignal.timeout(30000),
    });
    const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
    return { status: r.status, body: j, h: Object.fromEntries(r.headers), ms: performance.now() - t0 };
  } catch (e) { return { status: e.name === "AbortError" ? "prekinjeno" : "omrezje", body: String(e.message), h: {}, ms: performance.now() - t0 }; }
}
const kupi = (base, tok, ev, q, kljuc, opc = {}) =>
  api(base, "POST", `/events/${ev}/orders`, tok, q === undefined ? {} : { quantity: q }, { ...opc, glave: { ...(kljuc ? { "idempotency-key": kljuc } : {}), ...(opc.glave || {}) } });
const kupiMizo = (base, tok, ev, miza, kljuc, telo = {}, opc = {}) =>
  api(base, "POST", `/events/${ev}/tables/${miza}/orders`, tok, telo, { ...opc, glave: { ...(kljuc ? { "idempotency-key": kljuc } : {}), ...(opc.glave || {}) } });
const ponovljeno = (r) => r.h["idempotent-replayed"] === "true";

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await pool.query("TRUNCATE omejitve");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));

  let log = "";
  async function zagon(ime, port, okolje = {}) {
    const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(port), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test", ...okolje }, stdio: ["ignore", "pipe", "pipe"] });
    srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
    procesi[ime] = srv;
    for (let i = 0; i < 80; i++) { try { await fetch(`http://127.0.0.1:${port}/`); return; } catch { await spi(100); } }
  }
  async function ustavi(ime) { const s = procesi[ime]; if (!s) return; delete procesi[ime]; await new Promise(r => { s.once("exit", r); s.kill(); }); }

  await zagon("A", PORT_A);
  await zagon("B", PORT_B);

  const U = {
    lastnik: zeton("lastnik@outly.si", uuid(1)), ana: zeton("ana@outly.si", uuid(2)), bor: zeton("bor@outly.si", uuid(3)),
    cene: zeton("cene@outly.si", uuid(4)), dasa: zeton("dasa@outly.si", uuid(5)),
  };
  for (const k of Object.keys(U)) { const r = await api(A, "GET", "/me", U[k]); if (r.status !== 200) assert(false, `GET /me ${k}`, r.body); }
  await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
  await pool.query("UPDATE users SET date_of_birth = (CURRENT_DATE - INTERVAL '25 years')::date");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Idem Club', 'Ljubljana')");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Paketni Club', 'Ljubljana')");
  const uid = async (ime) => (await pool.query("SELECT id FROM users WHERE email=$1", [`${ime}@outly.si`])).rows[0].id;

  async function dogodek(naslov, kapaciteta, polja = {}) {
    return (await pool.query(
      `INSERT INTO events (club_id, title, start_at, status, ticket_price_cents, capacity, min_age, vip_enabled, sales_open_at)
       VALUES ($1,$2, NOW() + INTERVAL '2 days', 'published', 1500, $3, 0, $4, $5) RETURNING id`,
      [polja.klub || 1, naslov, kapaciteta, !!polja.vip, polja.odprtje || null])).rows[0].id;
  }
  const narocil = async (ev) => (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1", [ev])).rows[0].n;
  const prodano = async (ev) => (await pool.query("SELECT sold_count FROM events WHERE id=$1", [ev])).rows[0].sold_count;
  const stKljuca = async (k) => (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE idempotency_key=$1", [k])).rows[0].n;
  const ids = (rez) => [...new Set(rez.filter(r => r.status === 201).map(r => r.body.order.id))];
  const zakleni = async (dog) => {
    const c = await pool.connect();
    await c.query("BEGIN"); await c.query("SELECT id FROM events WHERE id=$1 FOR UPDATE", [dog]);
    return { sprosti: async () => { await c.query("ROLLBACK"); c.release(); } };
  };

  // ------------------------------------------------------------------ 1
  console.log("# 1: oblika glave, brez glave = kot prej");
  const E1 = await dogodek("Oblika", 20);
  const slabi = ["abc", "12345678-1234-1234-1234-12345678901", "12345678-1234-1234-1234-1234567890123", "1234567g-1234-1234-1234-123456789012",
    "{12345678-1234-1234-1234-123456789012}", "12345678123412341234123456789012", "", "12345678-1234-1234-1234-123456789012, 12345678-1234-1234-1234-123456789013"];
  for (const s of slabi) {
    const r = await kupi(A, U.ana, E1, 1, null, { glave: { "idempotency-key": s } });
    assert(r.status === 400 && r.body && r.body.error === "invalid_idempotency_key", `neveljavna glava ${JSON.stringify(s).slice(0, 40)} -> 400 invalid_idempotency_key`, r);
  }
  let r = await kupiMizo(A, U.ana, E1, 1, null, {}, { glave: { "idempotency-key": "abc" } });
  assert(r.status === 400 && r.body.error === "invalid_idempotency_key", "neveljavna glava na poti mize -> 400", r);
  r = await api(A, "POST", `/events/${E1}/orders`, null, { quantity: 1 }, { glave: { "idempotency-key": "abc" } });
  assert(r.status === 401, "brez zetona in z neveljavno glavo je najprej 401", r.status);
  assert(await narocil(E1) === 0 && await prodano(E1) === 0, "po neveljavnih glavah ni narocil in zaloga je nedotaknjena");

  const b1 = await kupi(A, U.ana, E1, 2), b2 = await kupi(A, U.ana, E1, 2);
  assert(b1.status === 201 && b2.status === 201 && b1.body.order.id !== b2.body.order.id, "brez glave: dve enaki zahtevi = dve narocili (obnasanje kot danes)", [b1.status, b2.status]);
  assert(!ponovljeno(b1) && !ponovljeno(b2), "brez glave ni Idempotent-Replayed");
  assert(await prodano(E1) === 4, "brez glave se zaloga zmanjsa dvakrat", await prodano(E1));
  assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1 AND idempotency_key IS NULL", [E1])).rows[0].n === 2, "narocila brez glave imajo idempotency_key NULL");

  // ------------------------------------------------------------------ 2
  console.log("\n# 2: zaporedna ponovitev vrne isto narocilo");
  const E2 = await dogodek("Ponovitev", 5);
  const K1 = nov();
  const p1 = await kupi(A, U.ana, E2, 2, K1);
  assert(p1.status === 201 && p1.body.order.quantity === 2 && p1.body.tickets.length === 2, "prvi nakup 201, 2 vstopnici", p1);
  assert(!ponovljeno(p1), "prvi nakup NI oznacen kot ponovitev");
  const p2 = await kupi(A, U.ana, E2, 2, K1);
  assert(p2.status === 201 && ponovljeno(p2), "ponovitev: 201 + Idempotent-Replayed: true", [p2.status, p2.h["idempotent-replayed"]]);
  assert(JSON.stringify(p2.body) === JSON.stringify(p1.body), "ponovitev vrne ISTO telo (narocilo, vstopnice, QR) kot prvic");
  assert(await narocil(E2) === 1 && await prodano(E2) === 2 && await stKljuca(K1) === 1, "eno narocilo, zaloga zmanjsana samo enkrat");
  const p3 = await kupi(A, U.ana, E2, 2, K1.toUpperCase());
  assert(p3.status === 201 && p3.body.order.id === p1.body.order.id, "velike crke istega UUID-ja = isti kljuc", p3.status);
  const p4 = await kupi(B, U.ana, E2, 2, K1);
  assert(p4.status === 201 && p4.body.order.id === p1.body.order.id, "ponovitev prek drugega procesa vrne isto narocilo", p4.status);
  const me = await api(A, "GET", "/me/orders", U.ana);
  assert(Array.isArray(me.body) && me.body.filter(o => o.event_id === E2).length === 1, "/me/orders: eno narocilo za dogodek");
  assert(!JSON.stringify(me.body).includes(K1) && !JSON.stringify(p1.body).includes(K1), "kljuc se ne vrne v odgovoru (ne v narocilu, ne v /me/orders)");

  // Privzeta kolicina (telo brez quantity) = quantity 1
  const Kd = nov();
  const d1 = await kupi(A, U.bor, E2, undefined, Kd), d2 = await kupi(A, U.bor, E2, 1, Kd);
  assert(d1.status === 201 && d2.status === 201 && d2.body.order.id === d1.body.order.id && ponovljeno(d2), "privzeta kolicina (1) in izrecna 1 sta ista vsebina", [d1.status, d2.status]);

  // Razprodano: bor+cene pokupita preostale; ponovitev ana K1 je se vedno 201, tuj kupec dobi 409
  const rest = await kupi(A, U.cene, E2, 2, nov());
  assert(rest.status === 201 && await prodano(E2) === 5, "preostale vstopnice pokupljene (razprodano)", [rest.status, await prodano(E2)]);
  const tuj = await kupi(A, U.dasa, E2, 1, nov());
  assert(tuj.status === 409, "tuj kupec na razprodanem dogodku dobi 409", tuj);
  const tuj2 = await kupi(A, U.dasa, E2, 1);
  assert(tuj2.status === 409, "(razprodano je zdaj tudi v kratkem spominu procesa)", tuj2.status);
  const p5 = await kupi(A, U.ana, E2, 2, K1);
  assert(p5.status === 201 && p5.body.order.id === p1.body.order.id, "ponovitev na razprodanem dogodku je 201 (isto narocilo), NE 409 »Only 0 tickets left«", p5);

  // Ponovitev ne porablja nakupnih poskusov (omejevalnik 20/h na IP)
  console.log("\n## ponovitev ne porabi nakupnega poskusa");
  const E2b = await dogodek("Omejevalnik", 200);
  const IP = "10.77.0.1";
  const KL = nov();
  const l1 = await kupi(A, U.ana, E2b, 1, KL, { ip: IP });
  assert(l1.status === 201, "prvi nakup z IP (porabi 1 od 20 poskusov)", l1.status);
  const ponovitve = await Promise.all(Array.from({ length: 30 }, () => kupi(A, U.ana, E2b, 1, KL, { ip: IP })));
  assert(ponovitve.every(x => x.status === 201 && x.body.order.id === l1.body.order.id), "30 ponovitev z istega IP: vse 201, isto narocilo (brez 429)", ponovitve.map(x => x.status).filter(s => s !== 201));
  let novi = 0;
  for (let i = 0; i < 19; i++) { const x = await kupi(A, U.ana, E2b, 1, nov(), { ip: IP }); if (x.status === 201) novi++; }
  assert(novi === 19, "po 30 ponovitvah je se vedno prostih 19 poskusov (20/h): 19 novih nakupov uspe", novi);
  const preseg = await kupi(A, U.ana, E2b, 1, nov(), { ip: IP });
  assert(preseg.status === 429, "21. poskus (nov kljuc) -> 429: omejevalnik za nove nakupe deluje", preseg.status);
  const se = await kupi(A, U.ana, E2b, 1, KL, { ip: IP });
  assert(se.status === 201 && ponovljeno(se), "ponovitev je ob prekoracenem omejevalniku se vedno 201 (narocilo ze obstaja)", se.status);

  // ------------------------------------------------------------------ 3
  console.log("\n# 3: isti kljuc, druga vsebina -> 422");
  const E3 = await dogodek("Vsebina", 30), E3b = await dogodek("Drug dogodek", 30);
  const K3 = nov();
  const v1 = await kupi(A, U.ana, E3, 2, K3);
  assert(v1.status === 201, "izvirni nakup 2x", v1.status);
  for (const [opis, rez] of [
    ["druga kolicina (3)", await kupi(A, U.ana, E3, 3, K3)],
    ["drug dogodek", await kupi(A, U.ana, E3b, 2, K3)],
    ["miza namesto vstopnic", await kupiMizo(A, U.ana, E3, 1, K3)],
  ]) {
    assert(rez.status === 422 && rez.body.error === "idempotency_key_reused", `${opis} -> 422 idempotency_key_reused`, rez);
  }
  assert(await narocil(E3) === 1 && await narocil(E3b) === 0 && await prodano(E3) === 2 && await prodano(E3b) === 0, "422 ni ustvaril narocila ne porabil zaloge");
  const v2 = await kupi(A, U.ana, E3, 2, K3);
  assert(v2.status === 201 && v2.body.order.id === v1.body.order.id, "po 422 izvirni kljuc se vedno vrne izvirno narocilo", v2.status);

  // ------------------------------------------------------------------ 4
  console.log("\n# 4: kljuc je vezan na uporabnika");
  const E4 = await dogodek("Uporabnik", 30), E4b = await dogodek("Uporabnik 2", 30);
  const K4 = nov();
  const u1 = await kupi(A, U.ana, E4, 1, K4);
  const u2 = await kupi(A, U.bor, E4, 1, K4);
  assert(u1.status === 201 && u2.status === 201 && u1.body.order.id !== u2.body.order.id && !ponovljeno(u2), "bor z anino vrednostjo kljuca dobi SVOJE novo narocilo (ne anine)", [u1.body.order && u1.body.order.id, u2.body.order && u2.body.order.id]);
  const bm = await api(A, "GET", "/me/orders", U.bor);
  assert(bm.body.filter(o => o.event_id === E4).length === 1 && bm.body.every(o => o.id !== u1.body.order.id), "bor ne vidi anine narocila (I3)");
  const u4 = await kupi(A, U.ana, E4b, 1, K4);
  assert(u4.status === 422, "isti kljuc pri ani na drugem dogodku -> 422 (njen kljuc je vezan na E4)", u4.status);
  const K4c = nov();
  const u5 = await kupi(A, U.ana, E4, 1, K4c);
  const u3 = await kupi(A, U.bor, E4b, 1, K4c);
  assert(u5.status === 201 && u3.status === 201 && !ponovljeno(u3) && u3.body.order.id !== u5.body.order.id && u3.body.order.event_id === E4b,
    "bor z anino vrednostjo kljuca na DRUGEM dogodku: novo narocilo (NE 422, anino narocilo ostane skrito)", [u5.status, u3.status]);
  const KP = nov();
  const par = await Promise.all([kupi(A, U.cene, E4, 1, KP), kupi(B, U.dasa, E4, 1, KP)]);
  assert(par.every(x => x.status === 201) && par[0].body.order.id !== par[1].body.order.id , "hkrati isti UUID pri dveh uporabnikih: dve loceni narocili", par.map(x => x.status));

  // ------------------------------------------------------------------ 5
  console.log("\n# 5: hkratni zahtevki z istim kljucem");
  const E5 = await dogodek("Hkrat A", 10);
  const K5 = nov();
  const h1 = await Promise.all(Array.from({ length: 12 }, () => kupi(A, U.ana, E5, 2, K5)));
  assert(h1.every(x => x.status === 201 || x.status === 409), "en proces, 12 hkrati: vsi 201 ali 409 (nikoli 500)", h1.map(x => x.status));
  assert(ids(h1).length === 1, "vsi 201 vsebujejo isto narocilo", ids(h1));
  assert(h1.every(x => x.status === 201), "(izbira: drugi cakajo v pomnilniku in dobijo isti rezultat, ne 409)", h1.map(x => x.status));
  assert(h1.filter(x => x.status === 201 && !ponovljeno(x)).length === 1, "natanko en odgovor NI ponovitev (ustvaril je narocilo)");
  assert(await narocil(E5) === 1 && await prodano(E5) === 2 && await stKljuca(K5) === 1, "natanko eno narocilo, zaloga zmanjsana enkrat");

  let kriz = 0, krizOk = true;
  for (let i = 0; i < 10; i++) {
    const Ek = await dogodek("Dva procesa " + i, 2), Kk = nov();
    const rez = await Promise.all([kupi(A, U.ana, Ek, 2, Kk), kupi(B, U.ana, Ek, 2, Kk), kupi(A, U.ana, Ek, 2, Kk), kupi(B, U.ana, Ek, 2, Kk)]);
    const dobro = rez.every(x => x.status === 201) && ids(rez).length === 1 && await narocil(Ek) === 1 && await prodano(Ek) === 2 && rez.filter(x => !ponovljeno(x)).length === 1;
    if (dobro) kriz++; else { krizOk = false; console.log("    krog", i, rez.map(x => x.status), await narocil(Ek), await prodano(Ek)); }
  }
  assert(krizOk, `dva procesa hkrati, dogodek z zalogo = kolicina: v vseh 10 krogih eno narocilo, vsi 201 isto (nobenega »Only 0 tickets left«): ${kriz}/10`);

  const E5c = await dogodek("Hkrat 40", 100);
  const K5c = nov();
  const h3 = await Promise.all(Array.from({ length: 40 }, (_, i) => kupi(i % 2 ? A : B, U.bor, E5c, 3, K5c)));
  assert(ids(h3).length === 1 && h3.every(x => x.status === 201) && await narocil(E5c) === 1 && await prodano(E5c) === 3, "40 hkratnih (dva procesa): eno narocilo, zaloga 3", [h3.map(x => x.status).filter(s => s !== 201), await narocil(E5c)]);

  // ------------------------------------------------------------------ 6
  console.log("\n# 6: neuspeh se ne zapomni");
  const E6 = await dogodek("Se ni odprto", 10, { odprtje: new Date(Date.now() + 3600 * 1000).toISOString() });
  const K6 = nov();
  const n1 = await kupi(A, U.ana, E6, 1, K6);
  assert(n1.status === 409 && !n1.h["idempotent-replayed"], "prodaja se ni odprta -> 409", n1);
  assert(await stKljuca(K6) === 0 && await narocil(E6) === 0, "neuspeli poskus ne pusti narocila ne kljuca");
  await pool.query("UPDATE events SET sales_open_at = NULL WHERE id=$1", [E6]);
  const n2 = await kupi(A, U.ana, E6, 1, K6);
  assert(n2.status === 201 && !ponovljeno(n2), "isti kljuc po popravku stanja uspe kot NOV nakup (ponovni poskus po napaki je dovoljen)", n2);
  assert(await stKljuca(K6) === 1 && await prodano(E6) === 1, "eno narocilo");

  // ------------------------------------------------------------------ 7
  console.log("\n# 7: I2 - zaloga drzi tudi pri podvojenih zahtevkih");
  const E7 = await dogodek("Zaloga 5", 5);
  const kljuci7 = Array.from({ length: 15 }, () => nov());
  const buyers = [U.ana, U.bor, U.cene];
  const zahtevki = [];
  kljuci7.forEach((k, i) => { const tok = buyers[i % 3]; zahtevki.push(kupi(A, tok, E7, 1, k), kupi(B, tok, E7, 1, k)); });
  const r7 = await Promise.all(zahtevki);
  assert(r7.every(x => x.status === 201 || x.status === 409), "samo 201 ali 409", r7.map(x => x.status));
  assert(await narocil(E7) === 5 && await prodano(E7) === 5, "natanko 5 narocil, sold_count == capacity (brez oversell)", [await narocil(E7), await prodano(E7)]);
  assert(ids(r7).length === 5, "5 razlicnih narocil med odgovori 201", ids(r7).length);
  assert((await pool.query("SELECT COUNT(*)::int AS n FROM (SELECT idempotency_key FROM orders WHERE event_id=$1 GROUP BY idempotency_key HAVING COUNT(*) > 1) x", [E7])).rows[0].n === 0, "noben kljuc nima vec kot enega narocila");

  // ------------------------------------------------------------------ 8
  console.log("\n# 8: VIP mize");
  const EV1 = await dogodek("VIP brez paketov", 100, { vip: true });
  const miza = async (klub, oznaka, sedezi, cena) => (await pool.query(
    "INSERT INTO club_tables (club_id, label, x, y, w, h, seats, price_cents) VALUES ($1,$2,0,0,2,2,$3,$4) RETURNING id", [klub, oznaka, sedezi, cena])).rows[0].id;
  const T1 = await miza(1, "T1", 4, 35000), T2 = await miza(1, "T2", 3, 30000), T3 = await miza(1, "T3", 2, 20000), T4 = await miza(1, "T4", 2, 20000);
  const m1K = nov();
  const m1 = await kupiMizo(A, U.ana, EV1, T1, m1K);
  assert(m1.status === 201 && m1.body.tickets.length === 4 && m1.body.order.table_id === T1, "nakup mize z ključem: 201, 4 vstopnice", m1);
  const m2 = await kupiMizo(A, U.ana, EV1, T1, m1K);
  assert(m2.status === 201 && ponovljeno(m2) && JSON.stringify(m2.body) === JSON.stringify(m1.body), "ponovitev nakupa mize: 201, isto telo, Idempotent-Replayed", [m2.status, m2.h["idempotent-replayed"]]);
  assert(await narocil(EV1) === 1, "ena rezervacija mize");
  const tujaMiza = await kupiMizo(A, U.bor, EV1, T1, nov());
  assert(tujaMiza.status === 409, "bor na isto mizo z drugim kljucem -> 409 (I13 velja)", tujaMiza);
  const m3 = await kupiMizo(A, U.ana, EV1, T1, m1K);
  assert(m3.status === 201 && m3.body.order.id === m1.body.order.id, "ponovitev ob že označeni zasedeni mizi (kratki spomin) je se vedno 201 isto narocilo, NE 409 »table already booked«", m3);

  const kT2 = nov();
  const mh = await Promise.all(Array.from({ length: 8 }, (_, i) => kupiMizo(i % 2 ? A : B, U.ana, EV1, T2, kT2)));
  assert(mh.every(x => x.status === 201) && ids(mh).length === 1 && mh.filter(x => !ponovljeno(x)).length === 1, "8 hkratnih (dva procesa) na isto mizo z istim kljucem: vsi 201, eno narocilo (NE 409 »already booked«)", mh.map(x => x.status));
  assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1 AND table_id=$2", [EV1, T2])).rows[0].n === 1, "v bazi ena rezervacija mize T2");

  const rv = await Promise.all([kupiMizo(A, U.ana, EV1, T3, nov()), kupiMizo(B, U.bor, EV1, T3, nov())]);
  assert(rv.filter(x => x.status === 201).length === 1 && rv.filter(x => x.status === 409).length === 1, "razlicna kljuca, ista miza: natanko en 201 in en 409 (I13)", rv.map(x => x.status));

  const r422 = await kupiMizo(A, U.ana, EV1, T4, m1K);
  assert(r422.status === 422 && r422.body.error === "idempotency_key_reused", "isti kljuc, druga miza -> 422", r422);
  const r422b = await kupi(A, U.ana, EV1, 1, m1K);
  assert(r422b.status === 422, "kljuc mize na poti vstopnic -> 422", r422b.status);
  assert(await narocil(EV1) === 3, "422 ne ustvari narocila (T1, T2, T3)", await narocil(EV1));

  // Paketi
  const EV2 = await dogodek("VIP s paketi", 100, { vip: true, klub: 2 });
  const P1 = (await pool.query("INSERT INTO bottle_packages (club_id, name) VALUES (2,'Paket 1') RETURNING id")).rows[0].id;
  const P2 = (await pool.query("INSERT INTO bottle_packages (club_id, name) VALUES (2,'Paket 2') RETURNING id")).rows[0].id;
  const TP = await miza(2, "P1", 4, 40000), TP2 = await miza(2, "P2", 4, 40000);
  const kp = nov();
  const pk1 = await kupiMizo(A, U.ana, EV2, TP, kp, { package_id: P1 });
  assert(pk1.status === 201 && pk1.body.order.package_name === "Paket 1", "miza s paketom 201", pk1);
  const pk2 = await kupiMizo(A, U.ana, EV2, TP, kp, { package_id: P1 });
  assert(pk2.status === 201 && ponovljeno(pk2) && pk2.body.order.id === pk1.body.order.id, "ponovitev istega paketa: isto narocilo", pk2.status);
  const pk3 = await kupiMizo(A, U.ana, EV2, TP, kp, { package_id: P2 });
  assert(pk3.status === 422, "isti kljuc, drug paket -> 422", pk3.status);
  const pk4 = await kupiMizo(A, U.ana, EV2, TP, kp, {});
  assert(pk4.status === 422, "isti kljuc, brez paketa -> 422", pk4.status);
  const pk5 = await kupiMizo(A, U.ana, EV2, TP2, kp, { package_id: P1 });
  assert(pk5.status === 422, "isti kljuc, druga miza (isti paket) -> 422", pk5.status);
  const pk6 = await kupiMizo(A, U.ana, EV2, TP, kp, { package_id: P1, expected_price_cents: 40000 });
  assert(pk6.status === 201 && pk6.body.order.id === pk1.body.order.id, "ponovitev z expected_price_cents je isto narocilo (cena ni del identitete)", pk6.status);
  assert(await narocil(EV2) === 1, "ena rezervacija s paketom");

  // ------------------------------------------------------------------ 9
  console.log("\n# 9: CORS");
  const pf = await fetch(`${A}/events/${E1}/orders`, { method: "OPTIONS", headers: { origin: "https://outly.si", "access-control-request-method": "POST", "access-control-request-headers": "authorization,content-type,idempotency-key,x-outly-club" } });
  const dovoli = (pf.headers.get("access-control-allow-headers") || "").toLowerCase();
  assert(pf.status === 204 && dovoli.includes("idempotency-key") && dovoli.includes("authorization"), "preflight dovoli Idempotency-Key (in Authorization)", [pf.status, dovoli]);
  assert((pf.headers.get("access-control-allow-origin") || "") !== "", "preflight ima Access-Control-Allow-Origin");
  const cr = await api(A, "POST", `/events/${E2}/orders`, U.ana, { quantity: 2 }, { glave: { origin: "https://outly.si", "idempotency-key": K1 } });
  const izpost = (cr.h["access-control-expose-headers"] || "").toLowerCase();
  assert(izpost.includes("retry-after") && izpost.includes("idempotent-replayed"), "odgovor izpostavi Retry-After in Idempotent-Replayed", izpost);
  const c503 = await api(A, "GET", "/clubs", null, undefined, { glave: { origin: "https://outly.si" } });
  assert((c503.h["access-control-expose-headers"] || "").toLowerCase().includes("retry-after"), "tudi javni GET izpostavi Retry-After (splet bere Retry-After ob 503/429)");

  // ------------------------------------------------------------------ 10
  console.log("\n# 10: baza");
  const ix = (await pool.query(`SELECT i.indisunique AS enolicen, pg_get_expr(i.indpred, i.indrelid) AS pogoj, pg_get_indexdef(i.indexrelid) AS def
       FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE c.relname='orders_idempotency_key'`)).rows[0];
  assert(ix && ix.enolicen && /user_id, idempotency_key/.test(ix.def) && /idempotency_key IS NOT NULL/.test(ix.pogoj), "delni unikaten indeks orders_idempotency_key (user_id, idempotency_key) WHERE idempotency_key IS NOT NULL", ix);
  const Edb = await dogodek("Baza", null);
  const anaId = await uid("ana"), borId = await uid("bor");
  const vstavi = (u, k, ref) => pool.query(
    `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, buyer_email, status, idempotency_key)
     VALUES ($1,$2,$3,1,1,1500,1500,'x@outly.si','pending',$4)`, [ref, u, Edb, k]);
  const Kdb = nov();
  await vstavi(anaId, Kdb, "DB-1");
  let napaka = null; try { await vstavi(anaId, Kdb, "DB-2"); } catch (e) { napaka = e; }
  assert(napaka && napaka.code === "23505" && napaka.constraint === "orders_idempotency_key", "baza sama zavrne drugo narocilo istega uporabnika z istim kljucem (23505)", napaka && [napaka.code, napaka.constraint]);
  let napaka2 = null; try { await vstavi(borId, Kdb, "DB-3"); } catch (e) { napaka2 = e; }
  assert(!napaka2, "isti kljuc pri drugem uporabniku je dovoljen", napaka2 && napaka2.message);
  let napaka3 = null; try { await vstavi(anaId, null, "DB-4"); await vstavi(anaId, null, "DB-5"); } catch (e) { napaka3 = e; }
  assert(!napaka3, "vec narocil z NULL kljucem istega uporabnika je dovoljeno", napaka3 && napaka3.message);

  // ------------------------------------------------------------------ 11
  console.log("\n# 11: cakanje v pomnilniku, 409 v obdelavi, duhovi (NAKUP_VZPOREDNO=2, IDEMPOTENCA_CAKANJE_MS=1500)");
  await zagon("S", PORT_S, { NAKUP_VZPOREDNO: "2", IDEMPOTENCA_CAKANJE_MS: "1500", NAKUP_CAKANJE_MS: "6000" });
  const Eb = await dogodek("Zaklenjen 1", 50), Ef = await dogodek("Prost 1", 50);
  let lk = await zakleni(Eb);
  const Kx = nov();
  const R1 = kupi(S, U.ana, Eb, 1, Kx);              // v transakciji, obvisi na zaklepu dogodka
  await spi(400);
  const R2 = kupi(S, U.ana, Eb, 1, Kx);              // ponovitev: ceka v pomnilniku, NE zaseda mesta v semaforju
  await spi(100);
  const R3 = await kupi(S, U.bor, Ef, 1, nov());
  assert(R3.status === 201 && R3.ms < 1000, "nakup drugega dogodka gre takoj skozi (ponovitev ne zaseda drugega mesta od dveh)", [R3.status, R3.ms]);
  const r2 = await R2;
  assert(r2.status === 409 && r2.body.error === "request_in_progress" && r2.h["retry-after"] === "2", "ponovitev, ki ne dobi rezultata v IDEMPOTENCA_CAKANJE_MS -> 409 request_in_progress + Retry-After 2", r2);
  assert(r2.ms >= 1400 && r2.ms < 4000, "409 pride po ~1,5 s", r2.ms);
  await lk.sprosti();
  const r1 = await R1;
  assert(r1.status === 201 && await stKljuca(Kx) === 1, "prvotni nakup se po sprostitvi zaklepa konca (201), eno narocilo", [r1.status, await stKljuca(Kx)]);
  const r4 = await kupi(S, U.ana, Eb, 1, Kx);
  assert(r4.status === 201 && ponovljeno(r4) && r4.body.order.id === r1.body.order.id, "ponovitev po 409 vrne isto narocilo", r4.status);

  // ponovitev dobi isti rezultat, ko prvotni konca znotraj okna
  lk = await zakleni(Eb);
  const Ky = nov();
  const Q1 = kupi(S, U.ana, Eb, 1, Ky);
  await spi(300);
  const Q2 = kupi(S, U.ana, Eb, 1, Ky);
  await spi(300);
  await lk.sprosti();
  const [q1, q2] = [await Q1, await Q2];
  assert(q1.status === 201 && q2.status === 201 && q1.body.order.id === q2.body.order.id && ponovljeno(q2) && !ponovljeno(q1), "ponovitev, ki caka, dobi ISTO narocilo, ko se prvotni konca", [q1.status, q2.status]);
  assert(await stKljuca(Ky) === 1, "eno narocilo");

  // odjemalec odide sredi transakcije (timeout), ponovitev dobi isto narocilo (to je namen ključa)
  lk = await zakleni(Eb);
  const Kz = nov();
  const ac = new AbortController();
  const Z1 = kupi(S, U.ana, Eb, 1, Kz, { signal: ac.signal });
  await spi(400);
  ac.abort();
  assert((await Z1).status === "prekinjeno", "odjemalec je prekinil zahtevek sredi transakcije");
  await spi(150);
  const Z2 = kupi(S, U.ana, Eb, 1, Kz);
  await spi(300);
  await lk.sprosti();
  const z2 = await Z2;
  assert(z2.status === 201 && ponovljeno(z2), "ponovitev po prekinitvi sredi transakcije: 201, isto narocilo (prvotni se je koncal brez odjemalca)", z2);
  assert(await stKljuca(Kz) === 1, "natanko eno narocilo (prekinjeni zahtevek ni ustvaril drugega)");
  await ustavi("S");

  console.log("\n## duhovi: odjemalec odide v vrsti semaforja (NAKUP_VZPOREDNO=1)");
  await zagon("T", PORT_T, { NAKUP_VZPOREDNO: "1", IDEMPOTENCA_CAKANJE_MS: "6000", NAKUP_CAKANJE_MS: "8000" });
  const Eg = await dogodek("Zaklenjen 2", 50), Eh = await dogodek("Vrsta", 50);
  lk = await zakleni(Eg);
  const Bl = kupi(T_, U.cene, Eg, 1, nov());               // drzi edino dovoljenje
  await spi(400);
  const Kg = nov(), Kg2 = nov();
  const ac1 = new AbortController(), ac2 = new AbortController();
  const G1 = kupi(T_, U.ana, Eh, 1, Kg, { signal: ac1.signal });    // v vrsti semaforja
  await spi(150);
  const G2 = kupi(T_, U.ana, Eh, 1, Kg);                              // ponovitev: ceka na G1 v pomnilniku
  const G4 = kupi(T_, U.bor, Eh, 1, Kg2, { signal: ac2.signal });  // v vrsti, odide in se ne vrne
  await spi(300);
  ac2.abort();
  ac1.abort();                                                        // G1 odide -> G2 prevzame (ne cakajoc na G1)
  assert((await G1).status === "prekinjeno" && (await G4).status === "prekinjeno", "G1 in G4 sta odsla iz vrste");
  await spi(300);
  await lk.sprosti();
  const g2 = await G2;
  assert(g2.status === 201 && !ponovljeno(g2), "G2 (ponovitev po G1, ki je odsel pred nakupom) opravi nakup sama (201)", g2);
  assert((await Bl).status === 201, "drzalec dovoljenja se konca");
  await spi(500);
  assert(await stKljuca(Kg) === 1, "natanko eno narocilo za kljuc G (odsli zahtevek ni kupil)");
  assert(await stKljuca(Kg2) === 0, "odsli cakalec s kljucem G4 NIMA narocila (ni duha)");
  await ustavi("T");

  await ustavi("A"); await ustavi("B");
  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  const napake = log.split("\n").filter(l => /TypeError|Unhandled|ReferenceError|Maximum call/i.test(l));
  if (napake.length) { console.log("\nLog backenda (sumljivo):\n" + napake.slice(0, 20).join("\n")); fail++; }
  jwksServer.close(); await pool.end();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); for (const s of Object.values(procesi)) s.kill(); process.exit(1); });
