#!/usr/bin/env node
/**
 * Test casovnega okna skena (Martin 8. 10. 2026, invarianta I25): POST /business/tickets/scan in scan-batch
 * uveljavljata isto okno kot odjemalca (iOS #68, splet #42): dogodek je aktiven, ce je zdaj med start - 12 h in
 * konec + 6 h (meji vkljuceni); konec = end_at (ce je po zacetku), sicer start + 12 h. Izven okna: 409 / element
 * "not_today", vstopnica ostane valid. Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL=postgres://postgres:postgres@localhost:5432/outly node _testi/test_sken_okno.js
 *
 * Skripta sama dvigne lokalni JWKS streznik (port 3986), podpise ES256 zetone in zazene backend na portu 3136.
 * Meje v integracijskih testih imajo rezervo 60 s (cas tece med nastavitvijo in zahtevo); natancno vkljucenost
 * mej (ms) preveri test ciste funkcije jeVOknuSkena().
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");
const { jeVOknuSkena, SKEN_OKNO_PRED_MS, SKEN_OKNO_PO_MS, SKEN_PRIVZETO_TRAJANJE_MS } = require("../sken_okno");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3136, JWKS_PORT = 3986;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-sken-okno";
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
async function api(method, path, token, body) {
  const r = await fetch(BASE + path, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}

const H = 3600 * 1000, MIN = 60 * 1000;
const PRED = SKEN_OKNO_PRED_MS, PO = SKEN_OKNO_PO_MS, TRAJANJE = SKEN_PRIVZETO_TRAJANJE_MS;

(async () => {
  console.log("# jeVOknuSkena(): cista funkcija, meje na ms natancno");
  assert(PRED === 12 * H && PO === 6 * H && TRAJANJE === 12 * H, "konstante: 12 h pred, 6 h po, privzeto trajanje 12 h");
  const S = Date.UTC(2026, 9, 10, 22, 0, 0);          // zacetek
  const E = S + 5 * H;                                // end_at
  assert(jeVOknuSkena(S, E, S) === true, "zacetek: v oknu");
  assert(jeVOknuSkena(S, E, S - PRED) === true, "tocno 12 h pred zacetkom: v oknu (meja vkljucena)");
  assert(jeVOknuSkena(S, E, S - PRED - 1) === false, "12 h + 1 ms pred zacetkom: izven");
  assert(jeVOknuSkena(S, E, E + PO) === true, "tocno 6 h po end_at: v oknu (meja vkljucena)");
  assert(jeVOknuSkena(S, E, E + PO + 1) === false, "6 h + 1 ms po end_at: izven");
  assert(jeVOknuSkena(S, null, S + TRAJANJE + PO) === true, "brez end_at: tocno start + 12 h + 6 h: v oknu");
  assert(jeVOknuSkena(S, null, S + TRAJANJE + PO + 1) === false, "brez end_at: +1 ms: izven");
  assert(jeVOknuSkena(S, undefined, S + TRAJANJE + PO) === true, "end_at undefined = brez end_at");
  assert(jeVOknuSkena(S, S, S + TRAJANJE + PO) === true && jeVOknuSkena(S, S, S + TRAJANJE + PO + 1) === false, "end_at == start (v bazi nemogoce): privzeto trajanje");
  assert(jeVOknuSkena(S, S - H, S + TRAJANJE + PO) === true && jeVOknuSkena(S, S - H, S + TRAJANJE + PO + 1) === false, "end_at < start (v bazi nemogoce): privzeto trajanje");
  assert(jeVOknuSkena(new Date(S), new Date(E), new Date(E + PO)) === true, "sprejme Date");
  assert(jeVOknuSkena(new Date(S).toISOString(), new Date(E).toISOString(), E + PO + 1) === false, "sprejme ISO niz");
  assert(jeVOknuSkena(null, null, S) === false && jeVOknuSkena("ni datum", null, S) === false, "neberljiv zacetek: false, brez izjeme");
  assert(jeVOknuSkena(S, "ni datum", S + TRAJANJE + PO) === true, "neberljiv end_at: privzeto trajanje, brez izjeme");
  assert(jeVOknuSkena(S, E, NaN) === false, "neberljiv cas: false, brez izjeme");
  assert(jeVOknuSkena(Date.now() - H, null) === true && jeVOknuSkena(Date.now() + 13 * H, null) === false, "privzeti cas = zdaj");

  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  const T = {
    lastnik: zeton("lastnik@outly.si", uuid(1)),
    vratar: zeton("vratar@outly.si", uuid(2)),
    ana: zeton("ana@outly.si", uuid(3)),
    bor: zeton("bor@outly.si", uuid(4)),
  };
  for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
  await pool.query("UPDATE users SET role='business' WHERE email = 'lastnik@outly.si'");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana')");
  await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, (SELECT id FROM users WHERE email='vratar@outly.si'), 'doorman')");

  // Nakup je mogoc samo pred zacetkom: dogodek ustvarimo v prihodnosti, kupimo, nato mu premaknemo cas (kot ob dogodku).
  let r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Okno", startAt: new Date(Date.now() + 24 * H).toISOString(), ticketPriceCents: 1000, capacity: 100, minAge: 0 });
  assert(r.status === 201, "dogodek ustvarjen", r.body);
  const dog = r.body.id;
  // nastavi(zacetekOdZdaj, konecOdZdaj | null): premakne dogodek (ms relativno na zdaj)
  const nastavi = async (zacetekMs, konecMs = null) => {
    const n = Date.now();
    await pool.query("UPDATE events SET start_at = $2::timestamptz, end_at = $3::timestamptz WHERE id = $1",
      [dog, new Date(n + zacetekMs).toISOString(), konecMs === null ? null : new Date(n + konecMs).toISOString()]);
  };
  const kupi = async (token, kolicina) => {
    const x = await api("POST", `/events/${dog}/orders`, token, { quantity: kolicina });
    if (x.status !== 201) throw new Error("nakup ni uspel: " + JSON.stringify(x.body));
    return x.body.tickets;
  };
  const ana = await kupi(T.ana, 10);
  const bor = await kupi(T.bor, 8);
  await pool.query("UPDATE tickets SET created_at = NOW() - INTERVAL '3 days'");   // scanned_at v testih je po nastanku vstopnice
  const stanje = async (serial) => (await pool.query("SELECT status, used_at, scan_device FROM tickets WHERE serial = $1", [serial])).rows[0];
  const SPOROCILO = "This ticket is not for today's event.";

  console.log("\n# POST /business/tickets/scan: okno");
  await nastavi(-1 * H);
  r = await api("POST", "/business/tickets/scan", T.vratar, { qr: ana[0].qr });
  assert(r.status === 200 && r.body.result === "ok", "v oknu (zacel pred 1 h): ok", r.body);

  await nastavi(PRED + 60 * 1000);   // vrata se odprejo cez 1 min
  r = await api("POST", "/business/tickets/scan", T.vratar, { qr: ana[1].qr });
  assert(r.status === 409 && r.body.result === "not_today" && r.body.message === SPOROCILO, "12 h + 1 min pred zacetkom: 409 not_today, tocno sporocilo", r.body);
  assert(r.body.ticket && r.body.ticket.serial === ana[1].serial && r.body.ticket.event_title === "Okno" && r.body.ticket.start_at, "odgovor vsebuje ticket (serial, event_title, start_at) za zaslon", r.body.ticket && Object.keys(r.body.ticket));
  let s = await stanje(ana[1].serial);
  assert(s.status === "valid" && s.used_at === null && s.scan_device === null, "vstopnica ostane valid (UPDATE se ni zgodil)", s);
  await nastavi(PRED - 60 * 1000);   // vrata so odprta ze 1 min
  r = await api("POST", "/business/tickets/scan", T.vratar, { qr: ana[1].qr });
  assert(r.status === 200 && r.body.result === "ok", "ista vstopnica, ko se okno odpre (12 h - 1 min pred zacetkom): ok", r.body);
  r = await api("POST", "/business/tickets/scan", T.vratar, { qr: ana[1].qr });
  assert(r.status === 409 && r.body.result === "already_used", "ponovni sken v oknu: already_used (I1 nespremenjen)", r.body);

  await nastavi(13 * H);
  r = await api("POST", "/business/tickets/scan", T.vratar, { serial: ana[2].serial });
  assert(r.status === 409 && r.body.result === "not_today" && r.body.message === SPOROCILO, "rocni vnos { serial } izven okna: 409 not_today", r.body);
  r = await api("POST", "/business/tickets/scan", T.lastnik, { serial: ana[2].serial.toUpperCase() });
  assert(r.status === 409 && r.body.result === "not_today", "rocni vnos (lastnik, velike crke) izven okna: 409 not_today", r.body);
  s = await stanje(ana[2].serial);
  assert(s.status === "valid", "rocni vnos: vstopnica ostane valid", s);
  await nastavi(13 * H - 2 * H);
  r = await api("POST", "/business/tickets/scan", T.vratar, { serial: ana[2].serial });
  assert(r.status === 200 && r.body.result === "ok", "rocni vnos v oknu: ok", r.body);

  // odpovedan dogodek: event_cancelled ima prednost pred not_today (tudi izven okna)
  await nastavi(30 * H);
  await pool.query("UPDATE events SET status = 'cancelled' WHERE id = $1", [dog]);
  r = await api("POST", "/business/tickets/scan", T.vratar, { qr: ana[3].qr });
  assert(r.status === 409 && r.body.result === "event_cancelled", "odpovedan dogodek IZVEN okna: event_cancelled (ne not_today)", r.body);
  await nastavi(-1 * H);
  r = await api("POST", "/business/tickets/scan", T.vratar, { qr: ana[3].qr });
  assert(r.status === 409 && r.body.result === "event_cancelled", "odpovedan dogodek v oknu: event_cancelled", r.body);
  s = await stanje(ana[3].serial);
  assert(s.status === "valid", "odpovedan dogodek: vstopnica ostane valid", s);
  await pool.query("UPDATE events SET status = 'published' WHERE id = $1", [dog]);

  // brez end_at: konec = start + 12 h, okno do start + 18 h
  await nastavi(-(TRAJANJE + PO) + 60 * 1000);
  r = await api("POST", "/business/tickets/scan", T.vratar, { qr: ana[4].qr });
  assert(r.status === 200 && r.body.result === "ok", "brez end_at: 18 h - 1 min po zacetku: ok", r.body);
  await nastavi(-(TRAJANJE + PO) - 60 * 1000);
  r = await api("POST", "/business/tickets/scan", T.vratar, { qr: ana[5].qr });
  assert(r.status === 409 && r.body.result === "not_today", "brez end_at: 18 h + 1 min po zacetku: not_today", r.body);

  // z end_at: konec = end_at, okno do end_at + 6 h
  await nastavi(-20 * H, -5 * H);
  r = await api("POST", "/business/tickets/scan", T.vratar, { qr: ana[5].qr });
  assert(r.status === 200 && r.body.result === "ok", "end_at pred 5 h (start pred 20 h; brez end_at bi bilo izven okna): ok", r.body);
  await nastavi(-20 * H, -(PO + 60 * 1000));
  r = await api("POST", "/business/tickets/scan", T.vratar, { qr: ana[6].qr });
  assert(r.status === 409 && r.body.result === "not_today", "end_at pred 6 h + 1 min: not_today", r.body);
  await nastavi(-20 * H, -(PO - 60 * 1000));
  r = await api("POST", "/business/tickets/scan", T.vratar, { qr: ana[6].qr });
  assert(r.status === 200 && r.body.result === "ok", "end_at pred 6 h - 1 min: ok (meja)", r.body);
  // dolg dogodek (end_at 30 h po zacetku): se vedno aktiven, ko je start + 12 h ze mimo
  await nastavi(-20 * H, 10 * H);
  r = await api("POST", "/business/tickets/scan", T.vratar, { qr: ana[7].qr });
  assert(r.status === 200 && r.body.result === "ok", "dolg dogodek (start pred 20 h, end_at cez 10 h): ok", r.body);

  // preverbe pred oknom ostanejo: tuj klub, neplacano
  await nastavi(30 * H);
  await pool.query("UPDATE orders SET status = 'pending' WHERE id = (SELECT order_id FROM tickets WHERE serial = $1)", [ana[8].serial]);
  r = await api("POST", "/business/tickets/scan", T.vratar, { qr: ana[8].qr });
  assert(r.status === 409 && r.body.result === "unpaid", "neplacano narocilo izven okna: unpaid (preverba pred oknom ostane)", r.body);
  await pool.query("UPDATE orders SET status = 'paid' WHERE id = (SELECT order_id FROM tickets WHERE serial = $1)", [ana[8].serial]);
  r = await api("POST", "/business/tickets/scan", T.vratar, { qr: ana[8].qr });
  assert(r.status === 409 && r.body.result === "not_today", "isto naročilo, placano, izven okna: not_today", r.body);
  r = await api("POST", "/business/tickets/scan", T.ana, { qr: ana[8].qr });
  assert(r.status === 403, "navaden uporabnik: se vedno 403", r.status);

  console.log("\n# POST /business/tickets/scan-batch: okno po casu skena");
  const D1 = "telefon-okno-1", D2 = "telefon-okno-2";
  let n = 0;
  const sken = (serial, scannedAt, device, extra) => {
    const o = { client_scan_id: `cs-okno-${++n}`, serial, device_id: device || D1, ...(extra || {}) };
    if (scannedAt !== undefined) o.scanned_at = scannedAt;
    return o;
  };
  const kdaj = (ms) => new Date(Date.now() - ms).toISOString();
  const paket = async (scans) => { const x = await api("POST", "/business/tickets/scan-batch", T.vratar, { scans }); return x; };

  // 1) okno je ODPRTO zdaj (zacel pred 1 h)
  await nastavi(-1 * H);
  const b0 = sken(bor[0].serial, kdaj(10 * MIN));
  r = await paket([b0]);
  assert(r.status === 200 && r.body.results[0].result === "ok" && r.body.results[0].used_at === b0.scanned_at, "okno odprto, scanned_at v oknu: ok, used_at = scanned_at", r.body.results[0]);
  r = await paket([sken(bor[1].serial, new Date(Date.now() + H).toISOString())]);
  assert(r.body.results[0].result === "ok" && new Date(r.body.results[0].used_at).getTime() <= Date.now(), "scanned_at v prihodnosti (nesmiseln) -> presoja po zdaj: ok, used_at ne v prihodnosti", r.body.results[0]);
  const predZacetkom = new Date(Date.now() - H - (PRED + H)).toISOString();   // start - 13 h
  r = await paket([sken(bor[2].serial, predZacetkom)]);
  assert(r.body.results[0].result === "ok" && Math.abs(new Date(r.body.results[0].used_at).getTime() - Date.now()) < 5000, "scanned_at 13 h pred zacetkom (nesmiseln) -> presoja po zdaj: ok, used_at = zdaj", r.body.results[0]);
  r = await paket([sken(bor[3].serial)]);
  assert(r.body.results[0].result === "ok", "brez scanned_at, okno odprto: ok (zdaj)", r.body.results[0]);

  // 2) okno je ZAPRTO zdaj (start pred 30 h, brez end_at: okno se je zaprlo pred 12 h), skeni so prisli s zamudo
  await nastavi(-30 * H);
  const b4 = sken(bor[4].serial, kdaj(20 * H));      // start + 10 h: znotraj
  r = await paket([b4]);
  assert(r.body.results[0].result === "ok" && r.body.results[0].used_at === b4.scanned_at, "sken v oknu, poslan 12 h po zaprtju okna: ok, used_at = scanned_at", r.body.results[0]);
  s = await stanje(bor[4].serial);
  assert(s.status === "used", "baza: vstopnica used", s);
  r = await paket([sken(bor[5].serial, kdaj(8 * H))]);   // start + 22 h: izven
  assert(r.body.results[0].result === "not_today" && r.body.results[0].used_at === null, "scanned_at izven okna: not_today, used_at null", r.body.results[0]);
  s = await stanje(bor[5].serial);
  assert(s.status === "valid" && s.used_at === null && s.scan_device === null, "baza: vstopnica ostane valid", s);
  r = await paket([sken(bor[5].serial)]);
  assert(r.body.results[0].result === "not_today", "brez scanned_at, okno zaprto: presoja po zdaj -> not_today", r.body.results[0]);
  r = await paket([sken(bor[5].serial, new Date(Date.now() + H).toISOString())]);
  assert(r.body.results[0].result === "not_today", "scanned_at v prihodnosti, okno zaprto: presoja po zdaj -> not_today (ni obhoda okna)", r.body.results[0]);
  r = await paket([sken(bor[5].serial, kdaj(40 * H))]);   // start - 10 h: v oknu (vstopnica nastala pred 3 dnevi)
  assert(r.body.results[0].result === "ok" && Math.abs(new Date(r.body.results[0].used_at).getTime() - (Date.now() - 40 * H)) < 5000, "scanned_at = start - 10 h (v oknu, okno zdaj zaprto): ok", r.body.results[0]);

  // mesan paket: vsak element svoja presoja; vrstni red rezultatov ostane
  r = await paket([sken(bor[6].serial, kdaj(8 * H)), sken(bor[7].serial, kdaj(25 * H)), sken("ni-uuid", kdaj(25 * H), D1)]);
  assert(r.body.results.map(x => x.result).join() === "not_today,ok,invalid", "mesan paket: not_today, ok, invalid po vrstnem redu", r.body.results);

  // ponovitev paketa po izteku okna: ze unovcena vstopnica z istim zaznamkom -> ok (idempotenca), drug zaznamek -> already_used
  r = await paket([b4, b0]);
  assert(r.body.results[0].result === "ok" && r.body.results[0].used_at === b4.scanned_at, "ponovitev paketa po izteku okna: ok z istim used_at (idempotenca ne glede na okno)", r.body.results[0]);
  assert(r.body.results[1].result === "ok" && r.body.results[1].used_at === b0.scanned_at, "ponovitev paketa (druga vstopnica, okno zdaj zaprto): ok z istim used_at", r.body.results[1]);
  r = await paket([sken(bor[4].serial, kdaj(20 * H), D2)]);
  assert(r.body.results[0].result === "already_used", "druga naprava, ze unovceno, okno zaprto: already_used (ne not_today)", r.body.results[0]);

  // vstopnica po not_today ostane unovcljiva: ko se okno odpre, isti element z novim client_scan_id uspe
  await nastavi(-1 * H);
  r = await paket([sken(bor[6].serial, kdaj(5 * MIN))]);
  assert(r.body.results[0].result === "ok", "vstopnica, ki je dobila not_today, je v oknu ok", r.body.results[0]);

  // okno se se ni odprlo (start cez 13 h): sken pred oknom
  const ana9 = ana[9];
  await nastavi(13 * H);
  r = await paket([sken(ana9.serial, kdaj(5 * MIN))]);
  assert(r.body.results[0].result === "not_today", "okno se ni odprto (start cez 13 h): not_today", r.body.results[0]);
  s = await stanje(ana9.serial);
  assert(s.status === "valid", "vstopnica ostane valid", s);

  // end_at v batchu: start pred 30 h, end_at pred 2 h -> okno do cez 4 h
  await nastavi(-30 * H, -2 * H);
  r = await paket([sken(ana9.serial)]);
  assert(r.body.results[0].result === "ok", "end_at pred 2 h (brez end_at bi bilo okno zaprto): sken zdaj ok", r.body.results[0]);

  // odpovedan dogodek izven okna v batchu: event_cancelled ima prednost
  const cancelled = await pool.query("SELECT serial FROM tickets WHERE status = 'valid' AND serial = ANY($1::uuid[])", [[ana[3].serial]]);
  await nastavi(-30 * H);
  await pool.query("UPDATE events SET status = 'cancelled' WHERE id = $1", [dog]);
  r = await paket([sken(cancelled.rows[0].serial, kdaj(8 * H))]);
  assert(r.body.results[0].result === "event_cancelled", "batch: odpovedan dogodek izven okna: event_cancelled", r.body.results[0]);
  await pool.query("UPDATE events SET status = 'published' WHERE id = $1", [dog]);

  // koncno stanje: unovcene natanko tiste, ki so dobile ok
  const used = (await pool.query("SELECT count(*)::int AS n FROM tickets WHERE status = 'used'")).rows[0].n;
  // ana: 0,1,2,4,5,6,7,9 = 8; bor: 0,1,2,3,4,5,6,7 = 8
  assert(used === 16, "v bazi je unovcenih natanko 16 vstopnic (ostale so dobile not_today / event_cancelled)", used);
  assert(!/at .*index\.js:\d+:\d+/.test(log), "backend ni zabelezil izjeme", log.split("\n").filter(l => /Error|at .*index\.js/.test(l)).slice(0, 3));

  srv.kill("SIGTERM");
  jwksServer.close();
  await pool.end();
  console.log(`\n${ok} ok, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
