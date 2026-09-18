#!/usr/bin/env node
/**
 * Test nakupa in skeniranja vstopnic (migracija 002 + 008). Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres@localhost:5432/outly" node _testi/test_vstopnice.js
 * Vzorec kot test_vabila.js: lokalni JWKS (3999), backend na svojem portu (3117).
 * Pozor: POST /events/:id/orders ima omejevalnik "nakup" 20/uro na req.ip (index.js), deljen med
 * VSEMI nakupi v tej datoteki (proces je svez, torej ni deljen z drugimi test datotekami). Ce dodajas
 * nove scenarije nakupa, sesteje stevilo klicev proti tej meji.
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3117, JWKS_PORT = 3999;
const BASE = `http://127.0.0.1:${PORT}`;

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = publicKey.export({ format: "jwk" });
const KID = "test-kid-1";
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

// HMAC preverjanje QR podpisa (QR_SECRET="test", glej index.js podpisiQr/preveriQr).
function preveriQrPodpisLokalno(qr, secret) {
  const deli = String(qr).split(".");
  if (deli.length !== 2) return null;
  const [b, s] = deli;
  const pricakovan = crypto.createHmac("sha256", secret).update(b).digest("base64url").slice(0, 32);
  if (s !== pricakovan) return null;
  return JSON.parse(Buffer.from(b, "base64url").toString("utf8"));
}

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  const T = {
    lastnik: zeton("lastnik@outly.si", uuid(1)),
    doorman: zeton("doorman@outly.si", uuid(2)),
    ana: zeton("ana@outly.si", uuid(3)),
    bor: zeton("bor@outly.si", uuid(4)),
    mladoletni: zeton("mladoletni@outly.si", uuid(5)),
    brezdatuma: zeton("brezdatuma@outly.si", uuid(6)),
    drugi: zeton("drugi@outly.si", uuid(7)),
  };
  for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }

  await pool.query("UPDATE users SET role='business' WHERE email IN ('lastnik@outly.si','drugi@outly.si')");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana')");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city, hidden) VALUES ((SELECT id FROM users WHERE email='drugi@outly.si'), 'Skriti Klub', 'Maribor', TRUE)");
  await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, (SELECT id FROM users WHERE email='doorman@outly.si'), 'doorman')");

  // Datumi rojstva: ana in bor polnoletna, mladoletni 16 let (>= 15, a < 18), brezdatuma brez datuma.
  const polnoleten = new Date(Date.now() - 25 * 365.25 * 24 * 3600 * 1000).toISOString().slice(0, 10);
  const mladoleten = new Date(Date.now() - 16 * 365.25 * 24 * 3600 * 1000).toISOString().slice(0, 10);
  let r = await api("PATCH", "/me", T.ana, { dateOfBirth: polnoleten, genres: ["house"] });
  assert(r.status === 200, "ana nastavi datum rojstva (polnoletna)", r.body);
  r = await api("PATCH", "/me", T.bor, { dateOfBirth: polnoleten, genres: ["house"] });
  assert(r.status === 200, "bor nastavi datum rojstva (polnoleten)", r.body);
  r = await api("PATCH", "/me", T.mladoletni, { dateOfBirth: mladoleten, genres: ["house"] });
  assert(r.status === 200, "mladoletni nastavi datum rojstva (16 let)", r.body);

  console.log("\n# Priprava dogodkov");
  const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
  const cezTeden = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
  r = await api("POST", "/events", T.lastnik, {
    clubId: 1, title: "Nakup OK", startAt: cezDan, ticketPriceCents: 1500, capacity: 100, minAge: 0,
  });
  assert(r.status === 201, "dogodek 1 ustvarjen (min_age 0)", r.body);
  const dogodekOk = r.body.id;

  r = await api("POST", "/events", T.drugi, {
    clubId: 2, title: "Skriti klub dogodek", startAt: cezDan, ticketPriceCents: 1000, capacity: 10, minAge: 0,
  });
  assert(r.status === 201, "dogodek na skritem klubu ustvarjen", r.body);
  const dogodekSkrit = r.body.id;

  r = await api("POST", "/events", T.lastnik, {
    clubId: 1, title: "18+", startAt: cezTeden, ticketPriceCents: 2000, capacity: 50, minAge: 18,
  });
  assert(r.status === 201, "dogodek 18+ ustvarjen", r.body);
  const dogodek18 = r.body.id;

  r = await api("POST", "/events", T.lastnik, {
    clubId: 1, title: "Okno prodaje", startAt: cezTeden, ticketPriceCents: 1000, capacity: 20, minAge: 0,
  });
  assert(r.status === 201, "dogodek z oknom prodaje ustvarjen", r.body);
  const dogodekOkno = r.body.id;
  // Okno prodaje: odpre se cez teden dni (se ni odprto) - nastavimo direktno v bazi (ni poti za to prek POST /events).
  await pool.query("UPDATE events SET sales_open_at = NOW() + INTERVAL '1 day' WHERE id=$1", [dogodekOkno]);

  r = await api("POST", "/events", T.lastnik, {
    clubId: 1, title: "Zaprto okno", startAt: cezTeden, ticketPriceCents: 1000, capacity: 20, minAge: 0,
  });
  const dogodekZaprt = r.body.id;
  await pool.query("UPDATE events SET sales_close_at = NOW() - INTERVAL '1 hour' WHERE id=$1", [dogodekZaprt]);

  r = await api("POST", "/events", T.lastnik, {
    clubId: 1, title: "Zaloga 3", startAt: cezTeden, ticketPriceCents: 500, capacity: 3, minAge: 0,
  });
  assert(r.status === 201, "dogodek z zalogo 3 ustvarjen", r.body);
  const dogodekZaloga = r.body.id;

  console.log("\n# Nakup: osnovni primeri");
  r = await api("POST", `/events/${dogodekOk}/orders`, T.ana, { quantity: 2 });
  assert(r.status === 201, "objavljen dogodek, viden klub -> 201", r.body);
  assert(r.body.mode === "test", "testni nacin: mode = test", r.body.mode);
  assert(r.body.order.total_cents === 3000, "total_cents = 2 x 1500 (celi centi)", r.body.order);
  assert(r.body.order.is_test === true, "is_test = true", r.body.order);
  assert(typeof r.body.order.public_ref === "string" && r.body.order.public_ref.startsWith("OUT-"), "public_ref oblika OUT-...", r.body.order.public_ref);
  assert(Array.isArray(r.body.tickets) && r.body.tickets.length === 2, "vrne 2 vstopnici", r.body.tickets);
  const narocilo1 = r.body.order.id;

  console.log("\n# Cena vedno iz baze, ne iz telesa");
  r = await api("POST", `/events/${dogodekOk}/orders`, T.bor, { quantity: 1, unitPriceCents: 1, ticketPriceCents: 1, price: 1 });
  assert(r.status === 201 && r.body.order.total_cents === 1500 && r.body.order.unit_price_cents === 1500,
    "poslana cena v telesu je ignorirana, uporabljena je cena iz baze (1500)", r.body.order);

  console.log("\n# Klub skrit -> zavrnjeno");
  r = await api("POST", `/events/${dogodekSkrit}/orders`, T.ana, { quantity: 1 });
  assert(r.status === 409, "dogodek objavljen, a klub skrit -> zavrnjeno", r.status);

  console.log("\n# Neobstojeci dogodek in napacna kolicina");
  r = await api("POST", `/events/999999/orders`, T.ana, { quantity: 1 });
  assert(r.status === 404, "neobstojeci dogodek -> 404", r.status);
  r = await api("POST", `/events/${dogodekOk}/orders`, T.ana, { quantity: 0 });
  assert(r.status === 400, "quantity 0 -> 400", r.status);
  r = await api("POST", `/events/${dogodekOk}/orders`, T.ana, { quantity: 11 });
  assert(r.status === 400, "quantity > 10 -> 400", r.status);
  r = await api("POST", `/events/${dogodekOk}/orders`, null, { quantity: 1 });
  assert(r.status === 401, "brez zetona -> 401", r.status);

  console.log("\n# Okno prodaje");
  r = await api("POST", `/events/${dogodekOkno}/orders`, T.ana, { quantity: 1 });
  assert(r.status === 409, "nakup pred odprtjem okna prodaje -> 409", r.status);
  r = await api("POST", `/events/${dogodekZaprt}/orders`, T.ana, { quantity: 1 });
  assert(r.status === 409, "nakup po zaprtju okna prodaje -> 409", r.status);

  console.log("\n# Meja starosti (min_age 18)");
  r = await api("POST", `/events/${dogodek18}/orders`, T.brezdatuma, { quantity: 1 });
  assert(r.status === 403, "brez datuma rojstva na dogodku 18+ -> 403", r.status);
  r = await api("POST", `/events/${dogodek18}/orders`, T.mladoletni, { quantity: 1 });
  assert(r.status === 403, "16-letnik na dogodku 18+ -> 403", r.status);
  r = await api("POST", `/events/${dogodek18}/orders`, T.ana, { quantity: 1 });
  assert(r.status === 201, "polnoletna uporabnica na dogodku 18+ -> 201", r.body);

  console.log("\n# Zaloga: 5 vzporednih nakupov na dogodek s capacity 3 (brez oversell)");
  const kupci5 = [T.ana, T.bor, T.mladoletni, T.drugi, T.lastnik].map((_, i) => zeton(`zaloga${i}@outly.si`, uuid(100 + i)));
  for (const t of kupci5) { const rr = await api("GET", "/me", t); assert(rr.status === 200, "priprava kupca za test zaloge", rr.body); }
  const rezultati = await Promise.all(kupci5.map(t => api("POST", `/events/${dogodekZaloga}/orders`, t, { quantity: 1 })));
  const uspesni = rezultati.filter(r => r.status === 201).length;
  const zavrnjeni = rezultati.filter(r => r.status === 409).length;
  assert(uspesni === 3, "natanko 3 od 5 vzporednih nakupov uspe", rezultati.map(r => r.status));
  assert(zavrnjeni === 2, "natanko 2 od 5 vzporednih nakupov zavrnjena (409)", rezultati.map(r => r.status));
  const koncnaZaloga = await pool.query("SELECT capacity, sold_count FROM events WHERE id=$1", [dogodekZaloga]);
  assert(koncnaZaloga.rows[0].sold_count === koncnaZaloga.rows[0].capacity, "sold_count == capacity, brez oversell", koncnaZaloga.rows[0]);
  const stevecVstopnic = await pool.query("SELECT COUNT(*)::int AS n FROM tickets WHERE event_id=$1", [dogodekZaloga]);
  assert(stevecVstopnic.rows[0].n === 3, "v bazi natanko 3 vstopnice za dogodek z zalogo 3", stevecVstopnic.rows[0]);

  console.log("\n# GET /me/orders");
  r = await api("GET", "/me/orders", T.ana);
  assert(r.status === 200 && Array.isArray(r.body), "GET /me/orders -> seznam", r.body);
  assert(r.body.length >= 2, "ana vidi vsaj 2 svoji narocili", r.body.length);
  // Neposredno preverimo, da bor NE vidi Aninega narocila.
  const anaOrders = r.body.map(o => o.id);
  const borOrders = (await api("GET", "/me/orders", T.bor)).body.map(o => o.id);
  assert(anaOrders.every(id => !borOrders.includes(id)), "bor ne vidi Aninih narocil (brez prekrivanja id-jev)", { anaOrders, borOrders });

  console.log("\n# GET /me/tickets + QR podpis (HMAC, QR_SECRET=test)");
  r = await api("GET", "/me/tickets", T.ana);
  assert(r.status === 200 && Array.isArray(r.body) && r.body.length > 0, "GET /me/tickets -> seznam vstopnic", r.body);
  const prvaVstopnica = r.body[0];
  assert(typeof prvaVstopnica.qr === "string" && prvaVstopnica.qr.includes("."), "vstopnica ima QR kodo oblike b64.podpis", prvaVstopnica.qr);
  const razclenjenQr = preveriQrPodpisLokalno(prvaVstopnica.qr, "test");
  assert(razclenjenQr !== null, "QR podpis je veljaven glede na QR_SECRET=test (HMAC preverjen lokalno)", prvaVstopnica.qr);
  assert(razclenjenQr && razclenjenQr.t === prvaVstopnica.serial, "QR vsebuje pravilen serial vstopnice", { razclenjenQr, serial: prvaVstopnica.serial });
  const ponarejenQr = preveriQrPodpisLokalno(prvaVstopnica.qr, "narobna-skrivnost");
  assert(ponarejenQr === null, "QR z napacno skrivnostjo se NE preveri (HMAC dela)", ponarejenQr);

  console.log("\n# Testni nacin: narocilo je takoj 'paid' s predpono test_");
  const testniPi = await pool.query("SELECT stripe_payment_intent_id, status FROM orders WHERE id=$1", [narocilo1]);
  assert(testniPi.rows[0].status === "paid", "narocilo v testnem nacinu je takoj 'paid'", testniPi.rows[0]);
  assert(testniPi.rows[0].stripe_payment_intent_id.startsWith("test_"), "stripe_payment_intent_id ima predpono test_", testniPi.rows[0]);

  console.log("\n# POST /business/tickets/scan");
  const vseVstopniceZaloga = await pool.query("SELECT id, serial FROM tickets WHERE event_id=$1 ORDER BY id LIMIT 1", [dogodekZaloga]);
  const skenSerial = vseVstopniceZaloga.rows[0].serial;
  r = await api("POST", "/business/tickets/scan", T.lastnik, { serial: skenSerial });
  assert(r.status === 200 && r.body.result === "ok", "veljavna vstopnica -> uspe (owner skenira)", r.body);
  r = await api("POST", "/business/tickets/scan", T.lastnik, { serial: skenSerial });
  assert(r.status === 409, "dvojni sken iste vstopnice -> 409", r.body);

  r = await api("POST", "/business/tickets/scan", T.doorman, { serial: skenSerial });
  assert(r.status === 409, "vratar prav tako dobi 409 na ze skenirano vstopnico", r.body);

  // Tuja vstopnica: vstopnica iz dogodkaOk (klub 1) poskusi skenirati lastnik drugega kluba.
  const tujaVstopnica = await pool.query("SELECT serial FROM tickets WHERE event_id=$1 LIMIT 1", [dogodekOk]);
  r = await api("POST", "/business/tickets/scan", T.drugi, { serial: tujaVstopnica.rows[0].serial });
  assert(r.status === 403, "tuja vstopnica (drugega kluba) -> zavrnjeno (403)", r.body);

  // Navaden uporabnik (ni clan kluba) ne sme skenirati.
  r = await api("POST", "/business/tickets/scan", T.ana, { serial: tujaVstopnica.rows[0].serial });
  assert(r.status === 403, "navaden uporabnik (ni clan kluba) ne sme skenirati -> 403", r.body);

  // Vratar SME skenirati (nova, se neuporabljena vstopnica).
  const svezaVstopnica = await pool.query(
    "SELECT t.serial FROM tickets t JOIN orders o ON o.id=t.order_id WHERE t.event_id=$1 AND t.status='valid' LIMIT 1",
    [dogodekOk]
  );
  r = await api("POST", "/business/tickets/scan", T.doorman, { serial: svezaVstopnica.rows[0].serial });
  assert(r.status === 200 && r.body.result === "ok", "vratar sme skenirati -> 200", r.body);

  // Neveljaven QR podpis.
  r = await api("POST", "/business/tickets/scan", T.lastnik, { qr: "ponarejen.qr" });
  assert(r.status === 400, "neveljaven QR (napacen podpis) -> 400", r.body);

  // Vrnjena vstopnica: najprej vrnjeno narocilo (vstopnica se 'valid'), nato se vstopnica sama.
  // Poti za vracilo se ni (Stripe), zato stanje nastavimo v bazi - skener mora oboje zavrniti.
  const zaVracilo = await pool.query(
    "SELECT t.id, t.serial, t.order_id FROM tickets t WHERE t.event_id=$1 AND t.status='valid' LIMIT 1", [dogodekOk]
  );
  const vr = zaVracilo.rows[0];
  await pool.query("UPDATE orders SET status='refunded', refunded_cents=total_cents WHERE id=$1", [vr.order_id]);
  r = await api("POST", "/business/tickets/scan", T.lastnik, { serial: vr.serial });
  assert(r.status === 409 && r.body.result === "unpaid", "vstopnica vrnjenega narocila -> 409 unpaid", r.body);
  // Delno vracilo: narocilo ostane veljavno (partially_refunded), vrnjena je samo ta vstopnica.
  await pool.query("UPDATE orders SET status='partially_refunded' WHERE id=$1", [vr.order_id]);
  await pool.query("UPDATE tickets SET status='refunded' WHERE id=$1", [vr.id]);
  r = await api("POST", "/business/tickets/scan", T.lastnik, { serial: vr.serial });
  assert(r.status === 409 && r.body.result === "refunded", "vrnjena vstopnica delno vrnjenega narocila -> 409 refunded", r.body);
  const seValid = await pool.query("SELECT status FROM tickets WHERE id=$1", [vr.id]);
  assert(seValid.rows[0].status === "refunded", "sken vrnjene vstopnice je ni oznacil kot uporabljeno", seValid.rows[0]);

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  const napake = log.split("\n").filter(l => /error|TypeError|Unhandled/i.test(l) && !/Server error\./.test(l) && !/Resend/i.test(l));
  if (napake.length) console.log("\nLog backenda (sumljivo):\n" + napake.join("\n"));
  srv.kill(); jwksServer.close(); await pool.end();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
