#!/usr/bin/env node
/**
 * Test skena brez povezave (issue #86): QR v2 (Ed25519), GET /business/scan-key, GET /business/events/:id/scan-list,
 * POST /business/tickets/scan-batch. Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL=postgres://postgres:postgres@localhost:5432/outly node _testi/test_sken_brez_povezave.js
 *
 * Skripta sama dvigne lokalni JWKS streznik (port 3994), podpise ES256 zetone in zazene backend na portu 3123
 * z QR_SECRET=test. Kode v2 se preverjajo SAMO z javnim kljucem iz /business/scan-key (kot bi to naredil telefon),
 * brez znanja skrivnosti. Invarianta I14: dvojni sken iste vstopnice (tudi z dveh naprav, tudi sociasno) da na strezniku en "ok".
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3123, JWKS_PORT = 3994;
const BASE = `http://127.0.0.1:${PORT}`;

// --- kljuc + JWKS ---
const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-sken";
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
// Opomba: undici (fetch) ob If-None-Match sam doda Cache-Control: no-cache, zato 304 testiramo z izrecno glavo max-age.
async function api(method, path, token, body, headers) {
  const r = await fetch(BASE + path, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}), ...(headers || {}) }, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, headers: r.headers, text: t };
}

// --- kar naredi telefon: preveri kodo v2 samo z javnim kljucem (32 B surovo) ---
const SPKI_PREDPONA = Buffer.from("302a300506032b6570032100", "hex");
function javniKljucIzSurovega(surov) { return crypto.createPublicKey({ key: Buffer.concat([SPKI_PREDPONA, surov]), format: "der", type: "spki" }); }
function telefonPreveri(koda, javniKljuc) {
  const deli = String(koda).split(".");
  if (deli.length !== 3 || deli[0] !== "o2") return null;
  const veljaven = crypto.verify(null, Buffer.from(`${deli[0]}.${deli[1]}`, "utf8"), javniKljuc, Buffer.from(deli[2], "base64url"));
  return veljaven ? JSON.parse(Buffer.from(deli[1], "base64url").toString("utf8")) : null;
}
// stara koda v1 (HMAC), kot jo imajo uporabniki ze na telefonih
function kodaV1(serial, eventId, secret = "test") {
  const b = Buffer.from(JSON.stringify({ v: 1, t: serial, e: eventId, i: 1 })).toString("base64url");
  return `${b}.${crypto.createHmac("sha256", secret).update(b).digest("base64url").slice(0, 32)}`;
}

(async () => {
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
    cene: zeton("cene@outly.si", uuid(5)),
    drugi: zeton("drugi@outly.si", uuid(6)),
  };
  for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }
  await pool.query("UPDATE users SET role='business' WHERE email IN ('lastnik@outly.si','drugi@outly.si')");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana')");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='drugi@outly.si'), 'Drugi Klub', 'Maribor')");
  await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, (SELECT id FROM users WHERE email='vratar@outly.si'), 'doorman')");

  const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
  let r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Sken A", startAt: cezDan, ticketPriceCents: 1500, capacity: 100, minAge: 0 });
  assert(r.status === 201, "dogodek A (klub 1) ustvarjen", r.body);
  const dogA = r.body.id;
  // Dogodek A je ob skenih ze zacet (vrata odprta), pri nakupih in prenosih pa se ne (nakup/prenos po zacetku ni mogoc).
  const odpri = () => pool.query("UPDATE events SET start_at = NOW() + INTERVAL '1 day' WHERE id=$1", [dogA]);
  const zacni = () => pool.query("UPDATE events SET start_at = NOW() - INTERVAL '1 hour' WHERE id=$1", [dogA]);
  r = await api("POST", "/events", T.drugi, { clubId: 2, title: "Sken B", startAt: cezDan, ticketPriceCents: 1000, capacity: 100, minAge: 0 });
  assert(r.status === 201, "dogodek B (klub 2) ustvarjen", r.body);
  const dogB = r.body.id;

  // ana kupi 8 vstopnic na A (eno naročilo), bor 2 (za prenos), cene 1 na A (kasneje vrnjeno), drugi klub: ana 1 na B.
  r = await api("POST", `/events/${dogA}/orders`, T.ana, { quantity: 8 });
  assert(r.status === 201 && r.body.tickets.length === 8, "ana kupi 8 vstopnic na A", r.body);
  const anine = r.body.tickets;
  r = await api("POST", `/events/${dogA}/orders`, T.bor, { quantity: 2 });
  assert(r.status === 201, "bor kupi 2 vstopnici na A", r.body);
  const borove = r.body.tickets;
  r = await api("POST", `/events/${dogA}/orders`, T.cene, { quantity: 1 });
  assert(r.status === 201, "cene kupi 1 vstopnico na A (to naročilo bo vrnjeno)", r.body);
  const ceneteva = r.body.tickets[0]; const ceneNarocilo = r.body.order.id;
  r = await api("POST", `/events/${dogB}/orders`, T.ana, { quantity: 1 });
  assert(r.status === 201, "ana kupi 1 vstopnico na B (drug klub)", r.body);
  const tujaB = r.body.tickets[0];

  // Vstopnice so bile "kupljene" pred dnevi: scanned_at na telefonu mora biti po nastanku vstopnice (casovno okno za used_at).
  await pool.query("UPDATE tickets SET created_at = NOW() - INTERVAL '2 days'");
  await zacni();

  console.log("\n# GET /business/scan-key");
  r = await api("GET", "/business/scan-key", T.vratar);
  assert(r.status === 200 && r.body.alg === "Ed25519" && typeof r.body.kid === "string", "vratar dobi kljuc (alg Ed25519, kid)", r.body);
  const surov = Buffer.from(r.body.public_key, "base64url");
  assert(surov.length === 32, "public_key je 32 B surovo (base64url)", surov.length);
  const kid = r.body.kid;
  const javni = javniKljucIzSurovega(surov);
  r = await api("GET", "/business/scan-key", T.lastnik);
  assert(r.status === 200 && r.body.public_key === surov.toString("base64url"), "lastnik dobi isti kljuc", r.body);
  r = await api("GET", "/business/scan-key", T.drugi);
  assert(r.status === 200 && r.body.public_key === surov.toString("base64url"), "lastnik drugega kluba dobi isti kljuc (en par za vse)", r.body);
  r = await api("GET", "/business/scan-key", T.ana);
  assert(r.status === 403, "navaden uporabnik -> 403", r.status);
  r = await api("GET", "/business/scan-key", null);
  assert(r.status === 401, "brez zetona -> 401", r.status);
  // zasnova: kljuc je izpeljan iz QR_SECRET prek HKDF (brez nove okoljske spremenljivke)
  const seme = Buffer.from(crypto.hkdfSync("sha256", Buffer.from("test"), Buffer.alloc(0), "outly-qr-ed25519-v1", 32));
  const izpeljan = crypto.createPublicKey(crypto.createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seme]), format: "der", type: "pkcs8" }));
  assert(Buffer.from(izpeljan.export({ format: "jwk" }).x, "base64url").equals(surov), "javni kljuc = HKDF(QR_SECRET, info outly-qr-ed25519-v1) -> Ed25519");

  console.log("\n# QR v2: preverljiv samo z javnim kljucem");
  r = await api("GET", "/me/tickets", T.ana);
  const prva = r.body.find(t => t.id === anine[0].id);
  assert(prva && prva.qr.startsWith("o2.") && prva.qr.split(".").length === 3, "vstopnica ima kodo v2 (o2.telo.podpis)", prva && prva.qr);
  assert(prva.qr.length < 400, "koda v2 ni predolga za QR", prva.qr.length);
  const telo = telefonPreveri(prva.qr, javni);
  assert(telo !== null && telo.t === prva.serial && telo.e === dogA && telo.v === 2 && telo.k === kid, "crypto.verify z javnim kljucem uspe; telo: serial, dogodek, v 2, kid", telo);
  const deli = prva.qr.split(".");
  const popacenPodpis = `${deli[0]}.${deli[1]}.${(deli[2][0] === "A" ? "B" : "A") + deli[2].slice(1)}`;
  assert(telefonPreveri(popacenPodpis, javni) === null, "spremenjen podpis -> preverjanje pade");
  const drugoTelo = Buffer.from(JSON.stringify({ ...telo, t: anine[1].serial })).toString("base64url");
  assert(telefonPreveri(`o2.${drugoTelo}.${deli[2]}`, javni) === null, "spremenjeno telo (tuj serial) -> preverjanje pade");
  const tujKljuc = crypto.generateKeyPairSync("ed25519").publicKey;
  assert(telefonPreveri(prva.qr, tujKljuc) === null, "tuj javni kljuc kode ne preveri");
  r = await api("POST", "/business/tickets/scan", T.vratar, { qr: popacenPodpis });
  assert(r.status === 400 && r.body.result === "invalid", "/scan: spremenjen podpis v2 -> 400 invalid", r.body);
  r = await api("POST", "/business/tickets/scan", T.vratar, { qr: `o2.${drugoTelo}.${deli[2]}` });
  assert(r.status === 400 && r.body.result === "invalid", "/scan: spremenjeno telo v2 -> 400 invalid", r.body);
  r = await api("POST", "/business/tickets/scan", T.vratar, { qr: "o2.x.y" });
  assert(r.status === 400, "/scan: o2.x.y -> 400", r.status);
  r = await api("POST", "/business/tickets/scan", T.vratar, { qr: "o2." + "A".repeat(2000) });
  assert(r.status === 400, "/scan: predolga koda -> 400", r.status);

  console.log("\n# POST /business/tickets/scan: v2 in stara v1 (HMAC) delata");
  r = await api("POST", "/business/tickets/scan", T.vratar, { qr: anine[0].qr });
  assert(r.status === 200 && r.body.result === "ok", "/scan s kodo v2 -> ok", r.body);
  r = await api("POST", "/business/tickets/scan", T.vratar, { qr: anine[0].qr });
  assert(r.status === 409 && r.body.result === "already_used", "/scan: dvojni sken kode v2 -> 409 already_used", r.body);
  r = await api("POST", "/business/tickets/scan", T.vratar, { qr: kodaV1(anine[1].serial, dogA) });
  assert(r.status === 200 && r.body.result === "ok", "/scan s staro kodo v1 (HMAC) -> ok", r.body);
  r = await api("POST", "/business/tickets/scan", T.vratar, { qr: kodaV1(anine[2].serial, dogA, "napacna") });
  assert(r.status === 400 && r.body.result === "invalid", "/scan: v1 z napacno skrivnostjo -> 400", r.body);
  r = await api("POST", "/business/tickets/scan", T.vratar, { qr: kodaV1(anine[2].serial, dogA).replace(/.$/, c => (c === "a" ? "b" : "a")) });
  assert(r.status === 400, "/scan: v1 s spremenjenim podpisom -> 400", r.status);

  console.log("\n# GET /business/events/:id/scan-list");
  r = await api("GET", `/business/events/${dogA}/scan-list`, T.vratar);
  assert(r.status === 200, "vratar tega kluba -> 200", r.status);
  const seznam = r.body;
  assert(seznam.event_id === dogA && typeof seznam.generated_at === "string" && seznam.kid === kid && Array.isArray(seznam.tickets) && Array.isArray(seznam.transferred_serials), "oblika: event_id, generated_at, kid, tickets, transferred_serials", Object.keys(seznam));
  assert(seznam.tickets.length === 11, "11 vstopnic dogodka (8 + 2 + 1), vsa narocila placana", seznam.tickets.length);
  const sA0 = seznam.tickets.find(t => t.serial === anine[0].serial);
  assert(sA0 && sA0.status === "used" && sA0.used_at && sA0.holder_username === "ana" && sA0.is_vip === false, "unovcena vstopnica: status used, used_at, holder_username, is_vip false", sA0);
  assert(Object.keys(sA0).sort().join() === "holder_username,is_vip,package_name,serial,status,table_label,used_at", "tocno ta polja (brez id-jev in e-naslovov)", Object.keys(sA0));
  assert(!/@|email/i.test(r.text), "v odgovoru ni e-naslovov");
  const bSer = seznam.tickets.find(t => t.serial === borove[0].serial);
  assert(bSer && bSer.status === "valid" && bSer.used_at === null, "neunovcena vstopnica: valid, used_at null", bSer);
  r = await api("GET", `/business/events/${dogA}/scan-list`, T.lastnik);
  assert(r.status === 200 && r.body.tickets.length === 11, "lastnik -> 200");
  r = await api("GET", `/business/events/${dogA}/scan-list`, T.drugi);
  assert(r.status === 404, "lastnik drugega kluba -> 404 (dogodek ni njegov)", r.status);
  r = await api("GET", `/business/events/${dogB}/scan-list`, T.vratar);
  assert(r.status === 404, "vratar kluba 1 za dogodek kluba 2 -> 404", r.status);
  r = await api("GET", `/business/events/${dogA}/scan-list`, T.ana);
  assert(r.status === 403, "navaden uporabnik -> 403", r.status);
  r = await api("GET", `/business/events/${dogA}/scan-list`, null);
  assert(r.status === 401, "brez zetona -> 401", r.status);
  r = await api("GET", `/business/events/abc/scan-list`, T.vratar);
  assert(r.status === 400, "neveljaven id -> 400", r.status);
  r = await api("GET", `/business/events/999999/scan-list`, T.vratar);
  assert(r.status === 404, "neobstojec dogodek -> 404", r.status);

  // vstopnice nevplacanih/vrnjenih narocil so na seznamu s status "unpaid" (koda ima veljaven podpis, zato jo telefon
  // brez tega zapisa spusti kot "veljavna, ni na seznamu"); delno vrnjena ostanejo (z vrnjeno vstopnico)
  await pool.query("UPDATE orders SET status='refunded', refunded_cents=total_cents WHERE id=$1", [ceneNarocilo]);
  r = await api("GET", `/business/events/${dogA}/scan-list`, T.vratar);
  const cT = r.body.tickets.find(t => t.serial === ceneteva.serial);
  assert(r.body.tickets.length === 11 && cT && cT.status === "unpaid", "vstopnica vrnjenega narocila JE na seznamu s status unpaid (veljaven podpis, a ne placano)", cT);
  assert(cT && cT.used_at === null && cT.holder_username === "cene", "unpaid: used_at null, imetnik cene", cT);
  assert(Object.keys(cT || {}).sort().join() === "holder_username,is_vip,package_name,serial,status,table_label,used_at" && !/@|email/i.test(r.text), "unpaid: ista polja kot drugi, brez e-naslovov");
  // naročilo v teku (pending) -> unpaid; vstopnica sama void ostane void; po plačilu spet valid
  const borNar = (await pool.query("SELECT order_id FROM tickets WHERE serial=$1", [borove[1].serial])).rows[0].order_id;
  await pool.query("UPDATE orders SET status='pending' WHERE id=$1", [borNar]);
  r = await api("GET", `/business/events/${dogA}/scan-list`, T.vratar);
  assert(r.body.tickets.find(t => t.serial === borove[1].serial).status === "unpaid", "vstopnica neplacanega (pending) narocila -> unpaid", r.body.tickets.find(t => t.serial === borove[1].serial));
  await pool.query("UPDATE orders SET status='paid' WHERE id=$1", [borNar]);
  r = await api("GET", `/business/events/${dogA}/scan-list`, T.vratar);
  assert(r.body.tickets.find(t => t.serial === borove[1].serial).status === "valid", "po placilu narocila je vstopnica spet valid", r.body.tickets.find(t => t.serial === borove[1].serial));
  await pool.query("UPDATE tickets SET status='void' WHERE serial=$1", [ceneteva.serial]);
  r = await api("GET", `/business/events/${dogA}/scan-list`, T.vratar);
  assert(r.body.tickets.find(t => t.serial === ceneteva.serial).status === "void", "void vstopnica neplacanega narocila ostane void", r.body.tickets.find(t => t.serial === ceneteva.serial));
  await pool.query("UPDATE tickets SET status='refunded' WHERE serial=$1", [ceneteva.serial]);
  r = await api("GET", `/business/events/${dogA}/scan-list`, T.vratar);
  assert(r.body.tickets.find(t => t.serial === ceneteva.serial).status === "refunded", "refunded vstopnica vrnjenega narocila ostane refunded", r.body.tickets.find(t => t.serial === ceneteva.serial));
  await pool.query("UPDATE tickets SET status='valid' WHERE serial=$1", [ceneteva.serial]);
  r = await api("GET", `/business/events/${dogA}/scan-list`, T.vratar);
  const etag1 = r.headers.get("etag");
  assert(!!etag1, "odgovor ima ETag", etag1);
  r = await api("GET", `/business/events/${dogA}/scan-list`, T.vratar, null, { "if-none-match": etag1, "cache-control": "max-age=300" });
  assert(r.status === 304, "If-None-Match z istim ETag -> 304 (prihranek pri 1000+ telefonih)", r.status);
  await pool.query("UPDATE tickets SET status='refunded' WHERE serial=$1", [anine[7].serial]);
  await pool.query("UPDATE orders SET status='partially_refunded' WHERE id=(SELECT order_id FROM tickets WHERE serial=$1)", [anine[7].serial]);
  r = await api("GET", `/business/events/${dogA}/scan-list`, T.vratar, null, { "if-none-match": etag1, "cache-control": "max-age=300" });
  assert(r.status === 200 && r.body.tickets.find(t => t.serial === anine[7].serial).status === "refunded", "po spremembi seznam spet 200, vrnjena vstopnica ima status refunded", r.status);
  assert(r.headers.get("etag") !== etag1, "ETag se je spremenil");

  console.log("\n# POST /business/tickets/scan-batch: dostop in oblika");
  const D1 = "telefon-1", D2 = "telefon-2";
  const kdaj = (min) => new Date(Date.now() - min * 60000).toISOString();
  let n = 0;
  const sken = (qr, device, scannedAt, extra) => ({ client_scan_id: `cs-${++n}`, qr, scanned_at: scannedAt || kdaj(10), device_id: device || D1, ...(extra || {}) });
  r = await api("POST", "/business/tickets/scan-batch", null, { scans: [] });
  assert(r.status === 401, "brez zetona -> 401", r.status);
  r = await api("POST", "/business/tickets/scan-batch", T.ana, { scans: [] });
  assert(r.status === 403, "navaden uporabnik -> 403", r.status);
  r = await api("POST", "/business/tickets/scan-batch", T.vratar, {});
  assert(r.status === 400 && r.body.error === "invalid_scans", "brez scans -> 400 {error,message}", r.body);
  r = await api("POST", "/business/tickets/scan-batch", T.vratar, { scans: "x" });
  assert(r.status === 400, "scans ni seznam -> 400", r.status);
  r = await api("POST", "/business/tickets/scan-batch", T.vratar, { scans: [] });
  assert(r.status === 200 && Array.isArray(r.body.results) && r.body.results.length === 0, "prazen paket -> 200, prazni rezultati", r.body);
  r = await api("POST", "/business/tickets/scan-batch", T.vratar, { scans: new Array(501).fill({}) });
  assert(r.status === 400 && r.body.error === "too_many_scans", "501 skenov -> 400 too_many_scans", r.body);

  console.log("\n# scan-batch: osnovni sken, dvojni sken z dveh naprav, ponovitev paketa");
  const cas1 = kdaj(10);
  const paket1 = [sken(anine[3].qr, D1, cas1)];
  r = await api("POST", "/business/tickets/scan-batch", T.vratar, { scans: paket1 });
  assert(r.status === 200 && r.body.results.length === 1, "paket z 1 skenom -> 200", r.body);
  const r1 = r.body.results[0];
  assert(r1.client_scan_id === paket1[0].client_scan_id && r1.result === "ok" && r1.used_at === cas1, "prvi sken: ok, used_at = scanned_at (cas na telefonu)", r1);
  let db = (await pool.query("SELECT status, used_at, used_by_user_id, scan_device FROM tickets WHERE serial=$1", [anine[3].serial])).rows[0];
  assert(db.status === "used" && db.scan_device === `batch|${D1}|${paket1[0].client_scan_id}` && db.used_by_user_id === (await pool.query("SELECT id FROM users WHERE email='vratar@outly.si'")).rows[0].id, "baza: used, scan_device = zaznamek naprave, used_by = vratar", db);
  const usedPrej = db.used_at.toISOString();

  const paket2 = [sken(anine[3].qr, D2, kdaj(9))];
  r = await api("POST", "/business/tickets/scan-batch", T.vratar, { scans: paket2 });
  assert(r.body.results[0].result === "already_used" && r.body.results[0].used_at === cas1, "isti serial z druge naprave: already_used, used_at prvega skena", r.body.results[0]);

  r = await api("POST", "/business/tickets/scan-batch", T.vratar, { scans: paket1 });
  assert(r.body.results[0].result === "ok" && r.body.results[0].used_at === cas1, "ponovitev istega paketa: se vedno ok, isti used_at (idempotentno)", r.body.results[0]);
  db = (await pool.query("SELECT used_at, scan_device FROM tickets WHERE serial=$1", [anine[3].serial])).rows[0];
  assert(db.used_at.toISOString() === usedPrej && db.scan_device === `batch|${D1}|${paket1[0].client_scan_id}`, "baza ob ponovitvi nespremenjena (brez dvojnega zapisa)", db);
  const brez = [sken(anine[3].qr, D1, kdaj(8))];
  r = await api("POST", "/business/tickets/scan-batch", T.vratar, { scans: brez });
  assert(r.body.results[0].result === "already_used", "ista naprava, nov client_scan_id za ze unovceno vstopnico: already_used (pravi dvojni sken)", r.body.results[0]);

  console.log("\n# scan-batch: ze unovceno prek /scan");
  r = await api("POST", "/business/tickets/scan-batch", T.vratar, { scans: [sken(anine[0].qr), sken(kodaV1(anine[1].serial, dogA))] });
  assert(r.body.results[0].result === "already_used" && r.body.results[1].result === "already_used", "vstopnici, ze unovceni prek /scan (v2 in v1): already_used", r.body.results);

  console.log("\n# scan-batch: mesan paket (ena slaba koda ne podre paketa)");
  const veljavnaPoSerialu = { client_scan_id: "cs-serial", serial: anine[4].serial.toUpperCase(), scanned_at: kdaj(5), device_id: D1 };
  const mesan = [
    sken(anine[5].qr),                                               // 0 ok
    sken(popacenPodpis),                                             // 1 invalid (podpis)
    sken("smeti"),                                                   // 2 invalid
    { qr: anine[6].qr, scanned_at: kdaj(1), device_id: D1 },         // 3 invalid (brez client_scan_id)
    { client_scan_id: "cs-nodev", qr: anine[6].qr },                 // 4 invalid (brez device_id)
    { client_scan_id: "cs-ni-uuid", serial: "ni-uuid", device_id: D1 }, // 5 invalid (serial ni UUID)
    { client_scan_id: "cs-neznan", serial: uuid(777), device_id: D1 },  // 6 unknown
    sken(tujaB.qr),                                                  // 7 wrong_club
    veljavnaPoSerialu,                                               // 8 ok (po serialu, velike crke)
    sken(anine[5].qr, D2),                                           // 9 already_used (isti paket, druga naprava)
    null,                                                            // 10 invalid (ni objekt)
    { client_scan_id: "cs-pod", qr: kodaV1(anine[6].serial, dogB), device_id: D1 }, // 11 invalid (dogodek v kodi != dogodek vstopnice)
    sken(anine[6].qr, D1, "ni-datum"),                               // 12 ok (scanned_at neveljaven -> NOW)
    { client_scan_id: "cs-ev", qr: anine[7].qr, device_id: D1 },     // 13 refunded (status vstopnice)
  ];
  r = await api("POST", "/business/tickets/scan-batch", T.vratar, { scans: mesan });
  assert(r.status === 200 && r.body.results.length === mesan.length, "mesan paket: 200 in rezultat za VSAK element", r.body);
  const R = r.body.results.map(x => x.result);
  assert(R.join() === "ok,invalid,invalid,invalid,invalid,invalid,unknown,wrong_club,ok,already_used,invalid,invalid,ok,refunded", "rezultati po vrstnem redu", R);
  assert(r.body.results[8].client_scan_id === "cs-serial" && r.body.results[8].serial === anine[4].serial, "sken po serialu (velike crke) -> ok, serial v odgovoru", r.body.results[8]);
  const dbTuja = (await pool.query("SELECT status FROM tickets WHERE serial=$1", [tujaB.serial])).rows[0];
  assert(dbTuja.status === "valid", "tuja vstopnica (drug klub) ostane valid");
  assert(new Date(r.body.results[12].used_at).getTime() > Date.now() - 5000, "neveljaven scanned_at -> used_at = NOW()", r.body.results[12]);

  console.log("\n# scan-batch: casovno okno za used_at");
  await odpri();
  r = await api("POST", `/events/${dogA}/orders`, T.ana, { quantity: 4 });
  const nove = r.body.tickets;
  await zacni();
  const prihodnost = new Date(Date.now() + 3600 * 1000).toISOString();
  const pred = new Date(Date.now() - 30 * 24 * 3600 * 1000).toISOString();
  const predNastankom = new Date(Date.now() - 2 * 3600 * 1000).toISOString(); // vstopnica je bila ustvarjena sedaj
  await pool.query("UPDATE tickets SET created_at = NOW() - INTERVAL '1 day' WHERE serial=$1", [nove[3].serial]);
  const vcasi = [sken(nove[0].qr, D1, prihodnost), sken(nove[1].qr, D1, pred), sken(nove[2].qr, D1, predNastankom), sken(nove[3].qr, D1, kdaj(1))];
  const pred0 = Date.now();
  r = await api("POST", "/business/tickets/scan-batch", T.vratar, { scans: vcasi });
  const U = r.body.results.map(x => new Date(x.used_at).getTime());
  assert(r.body.results.every(x => x.result === "ok"), "vsi 4 ok", r.body.results);
  assert(U[0] <= Date.now() && U[0] >= pred0 - 1000, "scanned_at v prihodnosti -> used_at = NOW (ne v prihodnosti)", r.body.results[0]);
  assert(U[1] >= pred0 - 1000, "scanned_at star 30 dni -> NOW", r.body.results[1]);
  assert(U[2] >= pred0 - 1000, "scanned_at pred nastankom vstopnice -> NOW", r.body.results[2]);
  assert(Math.abs(U[3] - (pred0 - 60000)) < 5000, "razumen scanned_at (pred 1 min) se ohrani", r.body.results[3]);

  console.log("\n# scan-batch: prenesena vstopnica s staro kodo -> transferred");
  const staraKoda = borove[0].qr, staraSer = borove[0].serial;
  await odpri();
  r = await api("POST", `/tickets/${borove[0].id}/transfer`, T.bor, { email: "cene@outly.si" });
  await zacni();
  assert(r.status === 200, "bor prenese vstopnico Cenetu", r.body);
  r = await api("GET", "/me/tickets", T.cene);
  const novaKoda = r.body.find(t => t.id === borove[0].id);
  assert(novaKoda && novaKoda.serial !== staraSer && novaKoda.qr.startsWith("o2."), "cene dobi novo kodo v2 z novim serialom", novaKoda && novaKoda.serial);
  r = await api("GET", `/business/events/${dogA}/scan-list`, T.vratar);
  assert(r.body.transferred_serials.includes(staraSer) && !r.body.tickets.some(t => t.serial === staraSer) && r.body.tickets.some(t => t.serial === novaKoda.serial && t.holder_username === "cene"),
    "scan-list: stari serial v transferred_serials, nov serial na seznamu z novim imetnikom", r.body.transferred_serials);
  r = await api("POST", "/business/tickets/scan-batch", T.vratar, { scans: [sken(staraKoda), sken(novaKoda.qr)] });
  assert(r.body.results[0].result === "transferred", "stara koda prenesene vstopnice -> transferred", r.body.results[0]);
  assert(r.body.results[1].result === "ok", "nova koda istega imetnika -> ok", r.body.results[1]);
  r = await api("POST", "/business/tickets/scan-batch", T.drugi, { scans: [sken(staraKoda)] });
  assert(r.body.results[0].result === "unknown", "lastnik drugega kluba s staro kodo: unknown (ne razkrije)", r.body.results[0]);
  r = await api("POST", "/business/tickets/scan-batch", T.drugi, { scans: [sken(anine[0].qr)] });
  assert(r.body.results[0].result === "wrong_club", "lastnik drugega kluba: vstopnica kluba 1 -> wrong_club", r.body.results[0]);

  console.log("\n# scan-batch: neplačano naročilo");
  await odpri();
  r = await api("POST", `/events/${dogA}/orders`, T.ana, { quantity: 1 });
  await zacni();
  const nep = r.body.tickets[0];
  await pool.query("UPDATE orders SET status='refunded', refunded_cents=total_cents WHERE id=$1", [r.body.order.id]);
  r = await api("POST", "/business/tickets/scan-batch", T.vratar, { scans: [sken(nep.qr)] });
  assert(r.body.results[0].result === "unpaid", "vstopnica vrnjenega narocila -> unpaid", r.body.results[0]);

  console.log("\n# I14: dvojni sken tudi sociasno da en sam ok");
  await odpri();
  r = await api("POST", `/events/${dogA}/orders`, T.ana, { quantity: 3 });
  const tekma = r.body.tickets;
  r = await api("POST", `/events/${dogA}/orders`, T.ana, { quantity: 6 });
  const tekma2 = r.body.tickets;
  await zacni();
  await pool.query("UPDATE tickets SET created_at = NOW() - INTERVAL '2 days'");
  // 6 vstopnic x 20 naprav = 120 sociasnih paketov (pool ima 10 povezav, zato se zahtevki res prekrivajo)
  const napadi = [];
  for (const v of [tekma[0], ...tekma2]) for (let i = 0; i < 20; i++) napadi.push(api("POST", "/business/tickets/scan-batch", T.vratar, { scans: [sken(v.qr, `naprava-${i}`)] }).then(x => ({ serial: v.serial, rez: x.body.results[0].result })));
  const odg = await Promise.all(napadi);
  const poSerialu = {};
  for (const x of odg) { poSerialu[x.serial] = poSerialu[x.serial] || { ok: 0, already_used: 0, drugo: 0 }; poSerialu[x.serial][x.rez === "ok" ? "ok" : x.rez === "already_used" ? "already_used" : "drugo"]++; }
  assert(Object.values(poSerialu).every(c => c.ok === 1 && c.already_used === 19 && c.drugo === 0), "7 vstopnic x 20 naprav hkrati: za vsako natanko 1 ok, 19 already_used", poSerialu);
  // /scan (splet) in scan-batch (offline) hkrati
  const mesano = await Promise.all([
    api("POST", "/business/tickets/scan", T.vratar, { qr: tekma[1].qr }),
    api("POST", "/business/tickets/scan-batch", T.lastnik, { scans: [sken(tekma[1].qr, "d-x")] }),
    api("POST", "/business/tickets/scan", T.lastnik, { qr: tekma[1].qr }),
  ]);
  const okMesano = (mesano[0].body.result === "ok" ? 1 : 0) + (mesano[1].body.results[0].result === "ok" ? 1 : 0) + (mesano[2].body.result === "ok" ? 1 : 0);
  assert(okMesano === 1, "/scan in scan-batch hkrati: natanko 1 ok", mesano.map(x => x.body));
  // isti paket dvakrat sociasno: oba dobita ok (ponovitev), zapis je en
  const istiPaket = [sken(tekma[2].qr, D1, kdaj(2))];
  const dvakrat = await Promise.all([api("POST", "/business/tickets/scan-batch", T.vratar, { scans: istiPaket }), api("POST", "/business/tickets/scan-batch", T.vratar, { scans: istiPaket })]);
  assert(dvakrat.every(x => x.body.results[0].result === "ok") && dvakrat[0].body.results[0].used_at === dvakrat[1].body.results[0].used_at, "isti paket dvakrat hkrati: oba ok z istim used_at (idempotentno)", dvakrat.map(x => x.body));
  const stUp = (await pool.query("SELECT COUNT(*)::int AS n FROM tickets WHERE serial = ANY($1::uuid[]) AND status='used'", [tekma.map(t => t.serial)])).rows[0].n;
  assert(stUp === 3, "v bazi so unovcene natanko 3 vstopnice", stUp);

  console.log("\n# scan-batch: 500 elementov, telo > 100 kB");
  await odpri();
  r = await api("POST", `/events/${dogA}/orders`, T.ana, { quantity: 1 });
  await zacni();
  const velika = r.body.tickets[0];
  const velik = [];
  for (let i = 0; i < 500; i++) velik.push(sken(velika.qr, D1, kdaj(3)));
  const telesnaVelikost = JSON.stringify({ scans: velik }).length;
  r = await api("POST", "/business/tickets/scan-batch", T.vratar, { scans: velik });
  assert(telesnaVelikost > 100 * 1024, `telo paketa je ${Math.round(telesnaVelikost / 1024)} kB (nad privzetimi 100 kB)`, telesnaVelikost);
  assert(r.status === 200 && r.body.results.length === 500, "500 elementov -> 200 in 500 rezultatov", r.status);
  assert(r.body.results.filter(x => x.result === "ok").length === 1 && r.body.results.filter(x => x.result === "already_used").length === 499, "ista vstopnica 500-krat: 1 ok, 499 already_used", r.body.results.slice(0, 2));
  r = await api("POST", "/business/tickets/scan-batch", T.vratar, { scans: velik });
  assert(r.status === 200 && r.body.results[0].result === "ok" && r.body.results.filter(x => x.result === "ok").length === 1, "ponovitev 500 elementov: prvi ostane ok (idempotentno)", r.body.results.slice(0, 2));
  // ostale poti se vedno imajo privzeto omejitev
  r = await api("POST", "/business/tickets/scan", T.vratar, { serial: "x".repeat(150 * 1024) });
  assert(r.status === 413, "navadne poti: telo > 100 kB -> 413", r.status);

  console.log("\n# Popravki po pregledu PR #91");
  await odpri();
  r = await api("POST", `/events/${dogA}/orders`, T.ana, { quantity: 9 });
  const pp = r.body.tickets;
  await zacni();
  await pool.query("UPDATE tickets SET created_at = NOW() - INTERVAL '2 days'");

  // 1 (KRITICNO): v1 koda s podpisom z vec-bajtnimi znaki (32 znakov != 32 B) je vrgla izjemo -> 500 za cel paket
  const zlobnoTelo = Buffer.from(JSON.stringify({ v: 1, t: pp[0].serial, e: dogA, i: 1 })).toString("base64url");
  const zlobna = `${zlobnoTelo}.${"\u00e9".repeat(32)}`;
  r = await api("POST", "/business/tickets/scan", T.vratar, { qr: zlobna });
  assert(r.status === 400 && r.body.result === "invalid", "1: /scan: v1 s podpisom 'e-ostrivec' x 32 -> 400 invalid (ne 500)", { status: r.status, body: r.body });
  r = await api("POST", "/business/tickets/scan-batch", T.vratar, { scans: [sken(zlobna), sken(pp[0].qr), sken(zlobna, D2)] });
  assert(r.status === 200 && r.body.results.map(x => x.result).join() === "invalid,ok,invalid", "1: scan-batch: zlobna koda ne podre paketa (invalid,ok,invalid)", { status: r.status, body: r.body });
  r = await api("POST", "/business/tickets/scan-batch", T.vratar, { scans: [sken(pp[1].qr)] });
  assert(r.status === 200 && r.body.results[0].result === "ok", "1: naslednji paket normalno dela (sinhronizacija ni obtičala)", r.body);
  for (const zlobna2 of [`${zlobnoTelo}.${"\u{1F600}".repeat(16)}`, `${zlobnoTelo}.${"\u00e9".repeat(31)}`, `o2.${zlobnoTelo}.${"\u00e9".repeat(86)}`, `${"\u00e9".repeat(5)}.${"\u00e9".repeat(32)}`]) {
    const x = await api("POST", "/business/tickets/scan-batch", T.vratar, { scans: [sken(zlobna2)] });
    assert(x.status === 200 && x.body.results[0].result === "invalid", "1: druga zlobna oblika kode -> invalid", { status: x.status, body: x.body });
  }

  // 2: idempotentnost velja samo za istega uporabnika; drug clan ekipe z istim parom device_id + client_scan_id dobi already_used
  const tuj = { client_scan_id: "isti-par-1", qr: pp[2].qr, scanned_at: kdaj(5), device_id: "isti-telefon-1" };
  r = await api("POST", "/business/tickets/scan-batch", T.vratar, { scans: [tuj] });
  assert(r.body.results[0].result === "ok", "2: vratar: prvi sken ok", r.body.results[0]);
  r = await api("POST", "/business/tickets/scan-batch", T.lastnik, { scans: [tuj] });
  assert(r.body.results[0].result === "already_used", "2: drug clan ekipe z istim device_id + client_scan_id -> already_used (ne ok)", r.body.results[0]);
  r = await api("POST", "/business/tickets/scan-batch", T.vratar, { scans: [tuj] });
  assert(r.body.results[0].result === "ok", "2: isti vratar ponovi paket -> se vedno ok", r.body.results[0]);

  // 3: scanned_at, ki ga Date.parse sprejme, PostgreSQL pa ne (leto 0000, +010000) -> prej trajno "error"
  const slabiCasi = ["0000-01-01T00:00:00Z", "+010000-01-01T00:00:00Z", "9999-12-31T00:00:00Z", "-000001-01-01T00:00:00Z"];
  r = await api("POST", "/business/tickets/scan-batch", T.vratar, { scans: slabiCasi.map((c, i) => sken(pp[3 + i].qr, D1, c)) });
  assert(r.status === 200 && r.body.results.every(x => x.result === "ok"), "3: scanned_at izven razsodnega razpona (leto 0, +10000, 9999, -1) -> ok, ne error", r.body.results.map(x => x.result));
  assert(r.body.results.every(x => Math.abs(new Date(x.used_at).getTime() - Date.now()) < 10000), "3: used_at je v teh primerih NOW()", r.body.results.map(x => x.used_at));

  // 4: spodnja meja used_at = zacetek dogodka - 12 h (dogodek se je zacel pred 1 h -> meja 13 h nazaj), ne 7 dni
  const pred14h = new Date(Date.now() - 14 * 3600 * 1000).toISOString();
  const pred12h = new Date(Date.now() - 12 * 3600 * 1000).toISOString();
  r = await api("POST", "/business/tickets/scan-batch", T.vratar, { scans: [sken(pp[7].qr, D1, pred14h), sken(pp[8].qr, D1, pred12h)] });
  assert(r.body.results[0].result === "ok" && Math.abs(new Date(r.body.results[0].used_at).getTime() - Date.now()) < 10000, "4: scanned_at 14 h pred zacetkom-minus-rezerva -> NOW (ne 14 h nazaj)", r.body.results[0]);
  assert(r.body.results[1].result === "ok" && r.body.results[1].used_at === pred12h, "4: scanned_at pred 12 h (znotraj rezerve pred zacetkom) se ohrani", r.body.results[1]);

  // 5: opozorilo ob zagonu, ce je QR_SECRET prazna ali krajsa od 32 znakov (testi tecejo z QR_SECRET=test)
  assert(/QR_SECRET[^\n]*32/.test(log), "5: ob zagonu je v logu jasno opozorilo o prekratki/prazni QR skrivnosti", log.slice(0, 300));

  console.log("\n# Brez e-naslovov in skrivnosti v odgovorih");
  r = await api("GET", "/business/scan-key", T.vratar);
  assert(!/test/.test(r.body.public_key) && !/secret/i.test(r.text), "scan-key ne vsebuje skrivnosti");

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  if (fail) console.log("--- log strezniika ---\n" + log.slice(-3000));
  srv.kill(); jwksServer.close(); await pool.end();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
