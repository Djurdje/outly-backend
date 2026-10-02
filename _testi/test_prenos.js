#!/usr/bin/env node
/**
 * Test prenosa vstopnice prijatelju (migracija 008). Zagon (lokalno, PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres@localhost:5432/outly" node _testi/test_prenos.js
 * Vzorec kot test_vabila.js: lokalni JWKS (3999), backend na svojem portu (3115).
 */
const crypto = require("crypto");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3115, JWKS_PORT = 3999;
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

(async () => {
  const pool = new Pool({ connectionString: DB });
  await pool.query("TRUNCATE omejitve, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  const srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let log = ""; srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  const T = {
    lastnik: zeton("lastnik@outly.si", uuid(1)),
    ana: zeton("ana@outly.si", uuid(2)),
    bor: zeton("bor@outly.si", uuid(3)),
    cene: zeton("cene@outly.si", uuid(4)),
    mladoletni: zeton("mladoletni@outly.si", uuid(5)),
    neveljaven: zeton("neveljaven@outly.si", uuid(6)),
  };
  for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }

  await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana')");

  const polnoleten = new Date(Date.now() - 25 * 365.25 * 24 * 3600 * 1000).toISOString().slice(0, 10);
  const mladoleten = new Date(Date.now() - 16 * 365.25 * 24 * 3600 * 1000).toISOString().slice(0, 10);
  for (const k of ["ana", "bor", "cene", "neveljaven"]) {
    const r = await api("PATCH", "/me", T[k], { dateOfBirth: polnoleten, genres: ["house"] });
    assert(r.status === 200, `${k} nastavi datum rojstva (polnoleten)`, r.body);
  }
  let r = await api("PATCH", "/me", T.mladoletni, { dateOfBirth: mladoleten, genres: ["house"] });
  assert(r.status === 200, "mladoletni nastavi datum rojstva (16 let)", r.body);

  // Prejemnik "neveljaven" ni potrjen (email_verified=false) - simulacija racuna, ki se ni potrdil e-naslova.
  await pool.query("UPDATE users SET email_verified=false WHERE email='neveljaven@outly.si'");

  console.log("\n# Priprava dogodkov");
  const cezDan = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
  const cezTeden = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();

  r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Prenosljiv", startAt: cezTeden, ticketPriceCents: 1000, capacity: 100, minAge: 0 });
  assert(r.status === 201, "dogodek (min_age 0) ustvarjen", r.body);
  const dogodekOsnovni = r.body.id;

  r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "18+", startAt: cezTeden, ticketPriceCents: 1000, capacity: 100, minAge: 18 });
  assert(r.status === 201, "dogodek 18+ ustvarjen", r.body);
  const dogodek18 = r.body.id;

  r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Bo se zacel", startAt: cezDan, ticketPriceCents: 1000, capacity: 100, minAge: 0 });
  assert(r.status === 201, "dogodek 'bo se zacel' ustvarjen", r.body);
  const dogodekZacel = r.body.id;

  console.log("\n# Osnovni prenos: samo trenutni imetnik lahko prenese");
  r = await api("POST", `/events/${dogodekOsnovni}/orders`, T.ana, { quantity: 1 });
  assert(r.status === 201, "ana kupi vstopnico", r.body);
  const vstopnicaAna = r.body.tickets[0].id;

  r = await api("POST", `/tickets/${vstopnicaAna}/transfer`, T.bor, { email: "cene@outly.si" });
  assert(r.status === 404, "bor (ni imetnik) ne more prenesti Anine vstopnice -> 404", r.status);

  r = await api("POST", `/tickets/${vstopnicaAna}/transfer`, T.ana, { email: "ana@outly.si" });
  assert(r.status === 400, "prenos samemu sebi -> 400", r.status);

  r = await api("POST", `/tickets/${vstopnicaAna}/transfer`, T.ana, { email: "ne-obstaja@outly.si" });
  assert(r.status === 404, "prejemnik brez Outly racuna -> 404", r.status);

  r = await api("POST", `/tickets/${vstopnicaAna}/transfer`, T.ana, { email: "neveljaven@outly.si" });
  assert(r.status === 409, "prejemnikov racun ni potrjen (email_verified=false) -> 409", r.status);

  r = await api("POST", `/tickets/${vstopnicaAna}/transfer`, T.ana, { email: "cene@outly.si" });
  assert(r.status === 200 && r.body.result === "ok", "ana prenese vstopnico Cenetu -> 200", r.body);
  assert(r.body.ticket.holder_username === "cene" && r.body.ticket.transferred === true, "odgovor vsebuje novega imetnika in transferred=true", r.body.ticket);

  console.log("\n# Po prenosu: stari imetnik izgubi, novi dobi");
  r = await api("GET", "/me/tickets", T.ana);
  assert(!r.body.some(t => t.id === vstopnicaAna), "ana (stari imetnik) vstopnice vec NE vidi v /me/tickets", r.body.map(t => t.id));
  r = await api("GET", "/me/tickets", T.cene);
  const priCenetu = r.body.find(t => t.id === vstopnicaAna);
  assert(!!priCenetu, "cene (novi imetnik) vidi vstopnico v /me/tickets", r.body.map(t => t.id));
  assert(priCenetu && priCenetu.transferred === true && priCenetu.holder_id === (await pool.query("SELECT id FROM users WHERE email='cene@outly.si'")).rows[0].id,
    "vstopnica pri Cenetu ima transferred=true in pravilen holder_id", priCenetu);

  console.log("\n# Obvestilo o prejeti vstopnici (migracija 017): prejemnik vidi, kdo mu je poslal");
  r = await api("GET", "/me", T.cene);
  assert(r.body.pending_received_tickets === 1, "cene: /me pending_received_tickets = 1", r.body.pending_received_tickets);
  r = await api("GET", "/me", T.ana);
  assert(r.body.pending_received_tickets === 0, "ana (posiljatelj): pending_received_tickets = 0", r.body.pending_received_tickets);
  r = await api("GET", "/me/tickets/received", T.cene);
  assert(r.status === 200 && Array.isArray(r.body.received) && r.body.received.length === 1, "GET /me/tickets/received: 1 neprebrana", r.body);
  const prejeta = r.body.received[0];
  assert(prejeta.ticket_id === vstopnicaAna && prejeta.event_title === "Prenosljiv", "prejeta ima ticket_id in event_title", prejeta);
  assert(prejeta.from && prejeta.from.username === "ana" && prejeta.from.email === undefined && prejeta.to_email === undefined,
    "posiljatelj samo id/username/avatar_url, brez e-naslovov", prejeta);
  r = await api("GET", "/me/tickets/received", T.ana);
  assert(r.status === 200 && r.body.received.length === 0, "ana nima prejetih", r.body);
  r = await api("POST", `/me/tickets/received/${prejeta.id}/seen`, T.ana);
  assert(r.status === 404, "ana ne more oznaciti Cenetovega obvestila -> 404", r.status);
  r = await api("POST", `/me/tickets/received/${prejeta.id}/seen`, T.cene);
  assert(r.status === 200, "cene oznaci kot prebrano -> 200", r.body);
  r = await api("GET", "/me/tickets/received", T.cene);
  assert(r.body.received.length === 0, "po oznaki seznam prazen", r.body);
  r = await api("GET", "/me", T.cene);
  assert(r.body.pending_received_tickets === 0, "cene: pending_received_tickets = 0 po oznaki", r.body.pending_received_tickets);
  r = await api("POST", `/me/tickets/received/${prejeta.id}/seen`, T.cene);
  assert(r.status === 200, "ponovna oznaka je neskodljiva -> 200", r.status);
  r = await api("POST", `/me/tickets/received/abc/seen`, T.cene);
  assert(r.status === 400, "neveljaven id obvestila -> 400", r.status);
  r = await api("GET", "/me/tickets/received", null);
  assert(r.status === 401, "prejete brez zetona -> 401", r.status);

  console.log("\n# Ponovni prenos (ana ni vec imetnik) -> 404");
  r = await api("POST", `/tickets/${vstopnicaAna}/transfer`, T.ana, { email: "bor@outly.si" });
  assert(r.status === 404, "ana po prenosu ni vec imetnik -> 404 na ponovni poskus", r.status);

  console.log("\n# Samo veljavna vstopnica (ne 'used') se lahko prenese");
  r = await api("POST", `/events/${dogodekOsnovni}/orders`, T.bor, { quantity: 1 });
  assert(r.status === 201, "bor kupi vstopnico za sken", r.body);
  const vstopnicaBor = r.body.tickets[0].id;
  const serialBor = (await pool.query("SELECT serial FROM tickets WHERE id=$1", [vstopnicaBor])).rows[0].serial;
  r = await api("POST", "/business/tickets/scan", T.lastnik, { serial: serialBor });
  assert(r.status === 200, "priprava: vstopnica skenirana (used)", r.body);
  r = await api("POST", `/tickets/${vstopnicaBor}/transfer`, T.bor, { email: "cene@outly.si" });
  assert(r.status === 409, "prenos ze uporabljene ('used') vstopnice -> 409", r.status);

  console.log("\n# Samo PRED zacetkom dogodka");
  r = await api("POST", `/events/${dogodekZacel}/orders`, T.ana, { quantity: 1 });
  assert(r.status === 201, "ana kupi vstopnico za dogodek, ki se bo kmalu zacel", r.body);
  const vstopnicaZacel = r.body.tickets[0].id;
  // Dogodek je ze potekel - neposredno v bazi (nakup po zacetku ni mogoc prek API-ja).
  await pool.query("UPDATE events SET start_at = NOW() - INTERVAL '1 hour' WHERE id=$1", [dogodekZacel]);
  r = await api("POST", `/tickets/${vstopnicaZacel}/transfer`, T.ana, { email: "cene@outly.si" });
  assert(r.status === 409, "prenos po zacetku dogodka -> 409", r.status);

  console.log("\n# Prejemnik mora izpolnjevati min_age dogodka");
  r = await api("POST", `/events/${dogodek18}/orders`, T.bor, { quantity: 1 });
  assert(r.status === 201, "bor (polnoleten) kupi vstopnico za dogodek 18+", r.body);
  const vstopnica18 = r.body.tickets[0].id;
  r = await api("POST", `/tickets/${vstopnica18}/transfer`, T.bor, { email: "mladoletni@outly.si" });
  assert(r.status === 403, "prenos mladoletnemu na dogodek 18+ -> 403", r.status);
  r = await api("POST", `/tickets/${vstopnica18}/transfer`, T.bor, { email: "cene@outly.si" });
  assert(r.status === 200, "prenos polnoletnemu na dogodek 18+ -> 200", r.body);

  console.log("\n# Napacni vhodi in vloge");
  r = await api("POST", `/tickets/${vstopnicaAna}/transfer`, T.cene, { email: "ni-email" });
  assert(r.status === 400, "neveljaven e-naslov -> 400", r.status);
  r = await api("POST", `/tickets/abc/transfer`, T.cene, { email: "ana@outly.si" });
  assert(r.status === 400, "neveljaven id vstopnice -> 400", r.status);
  r = await api("POST", `/tickets/999999/transfer`, T.cene, { email: "ana@outly.si" });
  assert(r.status === 404, "neobstojeca vstopnica -> 404", r.status);
  r = await api("POST", `/tickets/${vstopnicaAna}/transfer`, null, { email: "ana@outly.si" });
  assert(r.status === 401, "brez zetona -> 401", r.status);

  console.log("\n# Kupcev pogled narocil po prenosu (I7, issue #124): brez novega seriala in e-naslova prejemnika");
  // POST z Idempotency-Key (api() glav ne podpira) - ponovitev mora kupcu pokazati isto kot GET /me/orders.
  const kupiZKljucem = async (token, pot, kljuc, telo) => {
    const rs = await fetch(BASE + pot, { method: "POST", headers: { "content-type": "application/json", authorization: "Bearer " + token, "idempotency-key": kljuc }, body: JSON.stringify(telo) });
    const t = await rs.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
    return { status: rs.status, body: j, replayed: rs.headers.get("idempotent-replayed") };
  };
  const serialIzBaze = async (id) => (await pool.query("SELECT serial FROM tickets WHERE id=$1", [id])).rows[0].serial;
  // Kupcev pogled vstopnice po prenosu: serial je null (kljuc ostane), holder_email ni, drugo ostane.
  const preveriKupcevPogled = (t, pricakovanId, ime, kdaj) => {
    assert(t && t.id === pricakovanId, `${kdaj}: vstopnica ${pricakovanId} je v narocilu`, t);
    assert("serial" in t && t.serial === null, `${kdaj}: serial je null (kljuc ostane)`, t && t.serial);
    assert(!("holder_email" in t), `${kdaj}: brez holder_email prejemnika`, t);
    assert(t.transferred === true && t.holder_username === ime && t.status === "valid" && t.qr === null,
      `${kdaj}: transferred=true, holder_username=${ime}, status=valid, qr=null`, t);
  };
  const cezTri = new Date(Date.now() + 3 * 24 * 3600 * 1000).toISOString();
  r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Kupcev pogled", startAt: cezTri, ticketPriceCents: 1000, capacity: 100, minAge: 0 });
  assert(r.status === 201, "dogodek za kupcev pogled ustvarjen", r.body);
  const dogodekPogled = r.body.id;
  await pool.query("UPDATE events SET vip_enabled = TRUE WHERE id=$1", [dogodekPogled]);

  const kljucA = crypto.randomUUID();
  r = await kupiZKljucem(T.ana, `/events/${dogodekPogled}/orders`, kljucA, { quantity: 2 });
  assert(r.status === 201 && r.body.tickets.length === 2, "ana kupi 2 vstopnici z Idempotency-Key", r.body);
  const narociloA = r.body.order.id;
  const [vA1, vA2] = r.body.tickets.map(t => t.id);
  const serialA1Star = await serialIzBaze(vA1);
  assert(typeof r.body.tickets[0].serial === "string" && r.body.tickets[0].serial === serialA1Star && typeof r.body.tickets[0].qr === "string"
    && r.body.tickets[0].holder_email === "ana@outly.si" && r.body.tickets[0].transferred === false,
    "pred prenosom kupec vidi svoj serial, QR in svoj e-naslov", r.body.tickets[0]);

  r = await api("POST", `/tickets/${vA1}/transfer`, T.ana, { email: "cene@outly.si" });
  assert(r.status === 200 && r.body.result === "ok", "ana prenese prvo vstopnico Cenetu", r.body);
  const serialA1Novi = await serialIzBaze(vA1);
  assert(serialA1Novi && serialA1Novi !== serialA1Star, "prenos je vstopnici dodelil nov serial (I7)", [serialA1Star, serialA1Novi]);

  r = await api("GET", "/me/orders", T.ana);
  const narociloVSeznamu = r.body.find(o => o.id === narociloA);
  assert(r.status === 200 && narociloVSeznamu && narociloVSeznamu.tickets.length === 2, "GET /me/orders: narocilo z 2 vstopnicama", r.body);
  preveriKupcevPogled(narociloVSeznamu.tickets.find(t => t.id === vA1), vA1, "cene", "GET /me/orders");
  let ostala = narociloVSeznamu.tickets.find(t => t.id === vA2);
  assert(ostala && typeof ostala.serial === "string" && typeof ostala.qr === "string" && ostala.holder_email === "ana@outly.si" && ostala.transferred === false,
    "GET /me/orders: neprenesena vstopnica ima se serial, QR in kupcev e-naslov", ostala);
  let surovo = JSON.stringify(r.body);
  assert(!surovo.includes(serialA1Novi) && !surovo.includes("cene@outly.si"), "GET /me/orders nikjer ne vsebuje novega seriala ali e-naslova prejemnika");

  r = await kupiZKljucem(T.ana, `/events/${dogodekPogled}/orders`, kljucA, { quantity: 2 });
  assert(r.status === 201 && r.replayed === "true" && r.body.order.id === narociloA, "ponovitev nakupa z istim kljucem: 201 + Idempotent-Replayed, isto narocilo", [r.status, r.replayed]);
  preveriKupcevPogled(r.body.tickets.find(t => t.id === vA1), vA1, "cene", "ponovitev nakupa");
  ostala = r.body.tickets.find(t => t.id === vA2);
  assert(ostala && typeof ostala.serial === "string" && typeof ostala.qr === "string", "ponovitev nakupa: neprenesena vstopnica ima se serial in QR", ostala);
  surovo = JSON.stringify(r.body);
  assert(!surovo.includes(serialA1Novi) && !surovo.includes("cene@outly.si"), "ponovitev nakupa nikjer ne vsebuje novega seriala ali e-naslova prejemnika");

  // VIP miza: isti odgovor (POST /events/:id/tables/:tableId/orders), tudi ponovitev.
  const mizaId = (await pool.query("INSERT INTO club_tables (club_id, label, x, y, w, h, seats, price_cents) VALUES (1,'T1',0,0,2,2,3,30000) RETURNING id")).rows[0].id;
  const kljucV = crypto.randomUUID();
  r = await kupiZKljucem(T.ana, `/events/${dogodekPogled}/tables/${mizaId}/orders`, kljucV, {});
  assert(r.status === 201 && r.body.tickets.length === 3 && r.body.order.is_vip === true, "ana kupi VIP mizo z Idempotency-Key (3 vstopnice)", r.body);
  const [vV1, vV2] = r.body.tickets.map(t => t.id);
  r = await api("POST", `/tickets/${vV1}/transfer`, T.ana, { email: "bor@outly.si" });
  assert(r.status === 200, "ana prenese prvo VIP vstopnico Boru", r.body);
  const serialV1Novi = await serialIzBaze(vV1);
  r = await kupiZKljucem(T.ana, `/events/${dogodekPogled}/tables/${mizaId}/orders`, kljucV, {});
  assert(r.status === 201 && r.replayed === "true", "ponovitev nakupa mize: 201 + Idempotent-Replayed", [r.status, r.replayed]);
  preveriKupcevPogled(r.body.tickets.find(t => t.id === vV1), vV1, "bor", "VIP ponovitev");
  assert(typeof r.body.tickets.find(t => t.id === vV2).serial === "string", "VIP ponovitev: neprenesena vstopnica ima se serial");
  assert(!JSON.stringify(r.body).includes(serialV1Novi) && !JSON.stringify(r.body).includes("bor@outly.si"), "VIP ponovitev ne vsebuje novega seriala ali e-naslova prejemnika");
  r = await api("GET", "/me/orders", T.ana);
  const vipNarocilo = r.body.find(o => o.is_vip && o.tickets.some(t => t.id === vV1));
  preveriKupcevPogled(vipNarocilo && vipNarocilo.tickets.find(t => t.id === vV1), vV1, "bor", "VIP GET /me/orders");
  assert(!JSON.stringify(r.body).includes(serialV1Novi) && !JSON.stringify(r.body).includes("bor@outly.si"), "VIP GET /me/orders ne vsebuje novega seriala ali e-naslova prejemnika");

  console.log("\n# Prejemnik in klub serial se vedno imata (spremenjen je samo kupcev pogled narocil)");
  r = await api("GET", "/me/tickets", T.cene);
  const priCenetuPogled = r.body.find(t => t.id === vA1);
  assert(priCenetuPogled && priCenetuPogled.serial === serialA1Novi && typeof priCenetuPogled.qr === "string" && priCenetuPogled.transferred === true,
    "cene (prejemnik) v /me/tickets vidi nov serial in QR, transferred=true", priCenetuPogled);
  r = await api("GET", "/me/tickets", T.ana);
  assert(!r.body.some(t => t.id === vA1) && r.body.find(t => t.id === vA2) && typeof r.body.find(t => t.id === vA2).serial === "string",
    "ana v /me/tickets prenesene vstopnice nima, svoje neprenesene pa se (serial)", r.body.map(t => t.id));
  r = await api("GET", `/business/events/${dogodekPogled}/tickets`, T.lastnik);
  const vKlubu = r.status === 200 && r.body.find(t => t.id === vA1);
  assert(vKlubu && vKlubu.serial === serialA1Novi && typeof vKlubu.qr === "string" && vKlubu.holder_username === "cene" && vKlubu.holder_email === "cene@outly.si",
    "klub (GET /business/events/:id/tickets) vidi serial in imetnika prenesene vstopnice", r.body);
  r = await api("POST", "/business/tickets/scan", T.lastnik, { serial: serialA1Novi });
  assert(r.status === 200 && r.body.result === "ok", "vratar skenira nov serial prejemnika -> 200", r.body);

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  const napake = log.split("\n").filter(l => /error|TypeError|Unhandled/i.test(l) && !/Server error\./.test(l) && !/Resend/i.test(l));
  if (napake.length) console.log("\nLog backenda (sumljivo):\n" + napake.join("\n"));
  srv.kill(); jwksServer.close(); await pool.end();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
