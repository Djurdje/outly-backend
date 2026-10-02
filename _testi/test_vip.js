#!/usr/bin/env node
/**
 * Test VIP miz s tlorisom (migraciji 025 + 026). Zagon (lokalno, PG16, baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_vip.js
 * Vzorec kot test_vstopnice.js: lokalni JWKS (3999), backend na svojem portu (3122).
 * Pokriva: urejanje tlorisa (validacija, meje, unikatne oznake, arhiviranje, tuji id-ji), vloge (vratar ne sme urejati),
 * javni GET brez kupca, nakup mize (N vstopnic z is_vip + QR), I13 (vzporedni nakupi iste mize -> natanko 1),
 * mize ne stejejo v sold_count, izklopljena miza, paket obvezen/tuj, starost 18+, prenos VIP vstopnice, sken,
 * rezervacije za vratarja, cena po dogodku, vip_enabled/vip_from_cents, prodaja (tables_sold) in demo migracijo 026.
 * Pozor: POST .../orders ima omejevalnik "nakup" 20/uro na req.ip (od migracije 027 v tabeli omejitve, ne vec v pomnilniku
 * procesa). Zato test pred vecjimi skupinami nakupov izprazni tabelo in znova zazene backend (nakup() steje klice in ga po
 * potrebi osvezi).
 */
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const http = require("http");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3122, JWKS_PORT = 3999;
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
async function api(method, p, token, body, glave) {
  const r = await fetch(BASE + p, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}), ...(glave || {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j, besedilo: t };
}

// Backend kot otrok proces; restart() ga ugasne, izprazni omejitve (restart procesa jih ne ponastavi vec) in zazene znova.
let srv = null, log = "", nakupov = 0;
async function zazeni() {
  srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 80; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }
  nakupov = 0;
}
async function izprazniOmejitve() {
  const p = new Pool({ connectionString: DB });
  try { await p.query("TRUNCATE omejitve"); } finally { await p.end(); }
}
async function restart() {
  const s = srv;
  await new Promise(r => { s.once("exit", r); s.kill(); });
  await izprazniOmejitve();
  await zazeni();
}
// Nakup mize (steje proti omejitvi 20/uro; pred mejo osvezi proces).
async function nakup(eid, mid, tok, body) {
  if (nakupov >= 16) await restart();
  nakupov++;
  return api("POST", `/events/${eid}/tables/${mid}/orders`, tok, body);
}

// HMAC preverjanje QR podpisa (QR_SECRET="test").
// Koda v2 (Ed25519): podpis se preveri z javnim kljucem, izpeljanim iz QR_SECRET=test (HKDF, kot streznik).
const QR_JAVNI = crypto.createPublicKey(crypto.createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"),
  Buffer.from(crypto.hkdfSync("sha256", Buffer.from("test"), Buffer.alloc(0), "outly-qr-ed25519-v1", 32))]), format: "der", type: "pkcs8" }));
function preveriQr(qr) {
  const deli = String(qr).split(".");
  if (deli.length !== 3 || deli[0] !== "o2") return null;
  return crypto.verify(null, Buffer.from(`${deli[0]}.${deli[1]}`, "utf8"), QR_JAVNI, Buffer.from(deli[2], "base64url"))
    ? JSON.parse(Buffer.from(deli[1], "base64url").toString("utf8")) : null;
}

const brezTransakcije = (ime) => fs.readFileSync(path.join(__dirname, "..", "db", "migracije", ime), "utf8")
  .split("\n").filter(v => !/^\s*(BEGIN|COMMIT)\s*;\s*$/i.test(v)).join("\n");

(async () => {
  const pool = new Pool({ connectionString: DB });
  const TRUNC = "TRUNCATE omejitve, ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE";
  await pool.query(TRUNC);
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  await zazeni();

  const T = {
    lastnik: zeton("lastnik@outly.si", uuid(1)),
    manager: zeton("manager@outly.si", uuid(2)),
    doorman: zeton("doorman@outly.si", uuid(3)),
    ana: zeton("ana@outly.si", uuid(4)),
    bor: zeton("bor@outly.si", uuid(5)),
    cene: zeton("cene@outly.si", uuid(6)),
    mladoletni: zeton("mladoletni@outly.si", uuid(7)),
    brezdatuma: zeton("brezdatuma@outly.si", uuid(8)),
    drugi: zeton("drugi@outly.si", uuid(9)),
    skriti: zeton("skriti@outly.si", uuid(10)),
  };
  for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }

  await pool.query("UPDATE users SET role='business' WHERE email IN ('lastnik@outly.si','drugi@outly.si','skriti@outly.si')");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Pure Club', 'Ljubljana')");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='drugi@outly.si'), 'Drugi Klub', 'Maribor')");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city, hidden) VALUES ((SELECT id FROM users WHERE email='skriti@outly.si'), 'Skriti Klub', 'Celje', TRUE)");
  await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, (SELECT id FROM users WHERE email='manager@outly.si'), 'manager')");
  await pool.query("INSERT INTO club_members (club_id, user_id, role) VALUES (1, (SELECT id FROM users WHERE email='doorman@outly.si'), 'doorman')");

  const polnoleten = new Date(Date.now() - 25 * 365.25 * 24 * 3600 * 1000).toISOString().slice(0, 10);
  const mladoleten = new Date(Date.now() - 16 * 365.25 * 24 * 3600 * 1000).toISOString().slice(0, 10);
  for (const [k, d] of [["ana", polnoleten], ["bor", polnoleten], ["cene", polnoleten], ["mladoletni", mladoleten]]) {
    const r = await api("PATCH", "/me", T[k], { dateOfBirth: d, genres: ["house"] });
    assert(r.status === 200, `${k} nastavi datum rojstva`, r.body);
  }

  // Dogodki (neposredno v bazi, da imamo nadzor nad casi in okni prodaje).
  async function dogodek(klub, naslov, pomik, polja = {}) {
    const r = await pool.query(
      `INSERT INTO events (club_id, title, poster_url, start_at, status, ticket_price_cents, capacity, min_age, sales_open_at, sales_close_at)
       VALUES ($1,$2,'https://example.com/p.jpg', NOW() + $3::interval, $4, $5, $6, $7, $8, $9) RETURNING id`,
      [klub, naslov, pomik, polja.status || "published", polja.cena === undefined ? 1500 : polja.cena, polja.capacity === undefined ? 100 : polja.capacity,
       polja.minAge || 0, polja.odprtje || null, polja.zaprtje || null]);
    return r.rows[0].id;
  }
  const E1 = await dogodek(1, "VIP noc", "1 day");
  const E18 = await dogodek(1, "VIP 18+", "2 days", { minAge: 18, capacity: 50 });
  const ESTART = await dogodek(1, "Ze zacet", "-1 hour");
  const ECLOSED = await dogodek(1, "Prodaja zaprta", "3 days", { zaprtje: new Date(Date.now() - 3600 * 1000).toISOString() });
  const EOPEN = await dogodek(1, "Prodaja se ni odprta", "3 days", { odprtje: new Date(Date.now() + 24 * 3600 * 1000).toISOString() });
  const ENOVIP = await dogodek(1, "Brez VIP", "4 days");
  const EDRAFT = await dogodek(1, "Osnutek", "5 days", { status: "draft" });
  const ECAP = await dogodek(1, "Zaloga 2", "6 days", { capacity: 2, cena: 500 });
  const EPAR = await dogodek(1, "Vzporedno", "7 days");
  const E2 = await dogodek(2, "Drugi klub dogodek", "1 day");
  const EHID = await dogodek(3, "Skriti klub dogodek", "1 day");

  let r;
  console.log("\n# Tloris: urejanje (PUT /business/vip)");
  r = await api("GET", "/business/vip", T.lastnik);
  assert(r.status === 200 && r.body.plan === null && r.body.tables.length === 0 && r.body.packages.length === 0, "nov klub: brez tlorisa, miz in paketov", r.body);

  const PLAN = { width: 24, height: 16, elements: [
    { type: "stage", x: 8, y: 0, w: 8, h: 3, label: "" },
    { type: "bar", x: 0, y: 2, w: 3, h: 8, label: "Main bar" },
    { type: "entrance", x: 9, y: 15, w: 6, h: 1, label: "" },
  ] };
  const telo = () => ({
    plan: JSON.parse(JSON.stringify(PLAN)),
    tables: [
      { label: "T1", x: 2, y: 5, w: 2, h: 2, shape: "round", seats: 6, price_cents: 30000 },
      { label: "T2", x: 6, y: 5, w: 3, h: 2, shape: "rect", seats: 4, price_cents: 20000 },
      { label: "T3", x: 12, y: 5, w: 2, h: 2, shape: "round", seats: 8, price_cents: 45000 },
    ],
    packages: [
      { name: "Jameson 0,7 l", description: "4x Red Bull, 1 l orange juice" },
      { name: "Absolut 0,7 l", description: "" },
    ],
  });
  r = await api("PUT", "/business/vip", T.lastnik, telo());
  assert(r.status === 200, "lastnik shrani tloris, 3 mize in 2 paketa -> 200", r.body);
  const tl1 = r.body;
  assert(tl1.plan && tl1.plan.width === 24 && tl1.plan.elements.length === 3 && tl1.plan.elements[1].label === "Main bar", "odgovor vsebuje tloris z elementi", tl1.plan);
  assert(tl1.tables.length === 3 && tl1.tables.every(t => Number.isInteger(t.id) && t.price_cents > 0), "mize imajo id in ceno v centih", tl1.tables);
  assert(tl1.packages.length === 2 && tl1.packages[0].name === "Jameson 0,7 l" && tl1.packages[0].description === "4x Red Bull, 1 l orange juice", "paketi v vrstnem redu", tl1.packages);
  const [M1, M2, M3] = tl1.tables.map(t => t.id);
  const [P1, P2] = tl1.packages.map(p => p.id);
  r = await api("GET", "/business/vip", T.lastnik);
  assert(r.status === 200 && JSON.stringify(r.body) === JSON.stringify(tl1), "GET /business/vip vrne isto kot PUT", r.body);
  r = await api("GET", "/business/vip", T.manager);
  assert(r.status === 200 && r.body.tables.length === 3, "manager sme brati tloris", r.status);

  console.log("\n# Vloge: vratar in tujci ne smejo urejati (I5)");
  r = await api("PUT", "/business/vip", T.doorman, telo());
  assert(r.status === 403, "vratar ne more urejati tlorisa -> 403", r.body);
  r = await api("GET", "/business/vip", T.doorman);
  assert(r.status === 403, "vratar ne more brati urejevalnika -> 403", r.body);
  r = await api("PUT", "/business/vip", T.ana, telo());
  assert(r.status === 403, "navaden uporabnik (ni clan) -> 403", r.body);
  r = await api("PUT", "/business/vip", null, telo());
  assert(r.status === 401, "brez zetona -> 401", r.status);
  r = await api("PUT", "/business/vip", T.manager, { plan: tl1.plan, tables: tl1.tables, packages: tl1.packages });
  assert(r.status === 200 && r.body.tables.map(t => t.id).join() === [M1, M2, M3].join(), "manager sme urejati; id-ji miz ostanejo isti", r.body);
  r = await api("GET", "/business/vip", T.drugi);
  assert(r.status === 200 && r.body.tables.length === 0, "drugi klub vidi SVOJ (prazen) tloris, ne tujega", r.body);

  console.log("\n# Validacija tlorisa: 400 in stanje ostane nespremenjeno");
  const slabi = (opis, spremeni) => ({ opis, spremeni });
  const primeri = [
    slabi("manjka plan", b => { delete b.plan; }),
    slabi("plan.width 7 (< 8)", b => { b.plan.width = 7; }),
    slabi("plan.width 41 (> 40)", b => { b.plan.width = 41; }),
    slabi("plan.height niz", b => { b.plan.height = "16"; }),
    slabi("element z neznanim tipom", b => { b.plan.elements[0].type = "sofa"; }),
    slabi("element izven mreze (x + w > width)", b => { b.plan.elements[0].x = 20; }),
    slabi("element izven mreze (y + h > height)", b => { b.plan.elements[0].y = 14; }),
    slabi("element z w = 0", b => { b.plan.elements[0].w = 0; }),
    slabi("element z negativnim x", b => { b.plan.elements[0].x = -1; }),
    slabi("element z necelim x (1.5)", b => { b.plan.elements[0].x = 1.5; }),
    slabi("oznaka elementa daljsa od 30 znakov", b => { b.plan.elements[0].label = "x".repeat(31); }),
    slabi("vec kot 80 elementov", b => { b.plan.elements = Array.from({ length: 81 }, () => ({ type: "wall", x: 0, y: 0, w: 1, h: 1, label: "" })); }),
    slabi("miza izven mreze", b => { b.tables[0].x = 23; }),
    slabi("dvojna oznaka mize (brez razlike velikih/malih)", b => { b.tables[1].label = "t1"; }),
    slabi("prazna oznaka mize", b => { b.tables[0].label = "   "; }),
    slabi("oznaka mize daljsa od 20 znakov", b => { b.tables[0].label = "T".repeat(21); }),
    slabi("seats 0", b => { b.tables[0].seats = 0; }),
    slabi("seats 21", b => { b.tables[0].seats = 21; }),
    slabi("cena negativna", b => { b.tables[0].price_cents = -1; }),
    slabi("cena s plavajoco vejico (I9)", b => { b.tables[0].price_cents = 100.5; }),
    slabi("cena kot niz", b => { b.tables[0].price_cents = "30000"; }),
    slabi("oblika oval", b => { b.tables[0].shape = "oval"; }),
    slabi("vec kot 60 miz", b => { b.tables = Array.from({ length: 61 }, (_, i) => ({ label: "M" + i, x: 0, y: 0, w: 1, h: 1, shape: "rect", seats: 2, price_cents: 100 })); }),
    slabi("miza z id, ki ne obstaja", b => { b.tables[0].id = 999999; }),
    slabi("dvakrat isti id mize", b => { b.tables[0].id = M1; b.tables[1].id = M1; }),
    slabi("tables ni seznam", b => { b.tables = {}; }),
    slabi("tables manjka", b => { delete b.tables; }),
    slabi("tloris null, mize obstajajo", b => { b.plan = null; }),
    slabi("vec kot 30 paketov", b => { b.packages = Array.from({ length: 31 }, (_, i) => ({ name: "P" + i, description: "" })); }),
    slabi("prazno ime paketa", b => { b.packages[0].name = ""; }),
    slabi("ime paketa daljse od 60", b => { b.packages[0].name = "x".repeat(61); }),
    slabi("opis paketa daljsi od 200", b => { b.packages[0].description = "x".repeat(201); }),
    slabi("paket z id, ki ne obstaja", b => { b.packages[0].id = 999999; }),
    slabi("nadzorni znak (NUL) v oznaki", b => { b.tables[0].label = "T\u0000"; }),
  ];
  for (const p of primeri) {
    const b = telo(); p.spremeni(b);
    r = await api("PUT", "/business/vip", T.lastnik, b);
    assert(r.status === 400 && typeof r.body === "string" && r.body.length > 3, `${p.opis} -> 400 z berljivim sporocilom`, [r.status, r.body]);
  }
  r = await api("GET", "/business/vip", T.lastnik);
  assert(JSON.stringify(r.body) === JSON.stringify(tl1), "po vseh zavrnjenih shranjevanjih je stanje nespremenjeno", r.body);

  console.log("\n# Tuj id: miza/paket drugega kluba -> 400");
  r = await api("PUT", "/business/vip", T.drugi, { plan: PLAN, tables: [{ id: M1, label: "X1", x: 0, y: 0, w: 1, h: 1, shape: "rect", seats: 2, price_cents: 100 }], packages: [] });
  assert(r.status === 400, "drugi klub poskusi posodobiti tujo mizo -> 400", r.body);
  r = await api("PUT", "/business/vip", T.drugi, { plan: PLAN, tables: [], packages: [{ id: P1, name: "Ukradeno", description: "" }] });
  assert(r.status === 400, "drugi klub poskusi posodobiti tuj paket -> 400", r.body);
  const tujaMiza = await pool.query("SELECT label, price_cents FROM club_tables WHERE id=$1", [M1]);
  const tujPaket = await pool.query("SELECT name FROM bottle_packages WHERE id=$1", [P1]);
  assert(tujaMiza.rows[0].label === "T1" && tujaMiza.rows[0].price_cents === 30000 && tujPaket.rows[0].name === "Jameson 0,7 l", "tuja miza in tuj paket ostaneta nespremenjena", [tujaMiza.rows[0], tujPaket.rows[0]]);

  console.log("\n# Zamenjava oznak, arhiviranje, ponovna uporaba oznake");
  let b = telo();
  b.tables[0].id = M1; b.tables[1].id = M2; b.tables[2].id = M3;
  b.tables[0].label = "T2"; b.tables[1].label = "T1";           // T1 <-> T2 v enem shranjevanju
  b.packages[0].id = P1; b.packages[1].id = P2;
  b.packages[0].name = "Jameson 0,7 l (nov opis)";
  r = await api("PUT", "/business/vip", T.lastnik, b);
  assert(r.status === 200 && r.body.tables.find(t => t.id === M1).label === "T2" && r.body.tables.find(t => t.id === M2).label === "T1", "zamenjava oznak T1 <-> T2 v enem shranjevanju dela", r.body);
  assert(r.body.packages[0].id === P1 && r.body.packages[0].name === "Jameson 0,7 l (nov opis)", "paket z id se posodobi", r.body.packages);
  // Vrnemo oznake in arhiviramo T3.
  b = telo();
  b.tables = [{ id: M1, ...telo().tables[0] }, { id: M2, ...telo().tables[1] }];
  b.packages[0].id = P1; b.packages[1].id = P2;
  r = await api("PUT", "/business/vip", T.lastnik, b);
  assert(r.status === 200 && r.body.tables.length === 2 && !r.body.tables.some(t => t.id === M3), "miza, ki je ni na seznamu, izgine iz seznama (arhivirana)", r.body.tables);
  const arh = await pool.query("SELECT archived_at FROM club_tables WHERE id=$1", [M3]);
  assert(arh.rows.length === 1 && arh.rows[0].archived_at !== null, "miza ni izbrisana, ampak arhivirana (archived_at)", arh.rows);
  b = telo();
  b.tables = [{ id: M1, ...telo().tables[0] }, { id: M2, ...telo().tables[1] }, { label: "T3", x: 12, y: 5, w: 2, h: 2, shape: "round", seats: 8, price_cents: 45000 }];
  b.packages[0].id = P1; b.packages[1].id = P2;
  r = await api("PUT", "/business/vip", T.lastnik, b);
  const M3n = r.body.tables.find(t => t.label === "T3");
  assert(r.status === 200 && M3n && M3n.id !== M3, "oznaka arhivirane mize se lahko znova uporabi (nova miza z novim id)", r.body.tables);
  const M3novi = M3n.id;
  r = await api("PUT", "/business/vip", T.lastnik, { ...b, tables: [{ id: M3, label: "T9", x: 0, y: 0, w: 1, h: 1, shape: "rect", seats: 2, price_cents: 100 }] });
  assert(r.status === 400, "arhivirana miza se ne da posodobiti prek starega id -> 400", r.body);
  // Brez tlorisa (plan null) je dovoljen samo brez miz; nato vse znova.
  r = await api("PUT", "/business/vip", T.drugi, { plan: null, tables: [], packages: [] });
  assert(r.status === 200 && r.body.plan === null, "plan null brez miz je dovoljen", r.body);

  console.log("\n# Dogodek: vklop VIP, cena po dogodku, izklop mize (PUT /business/events/:id/vip)");
  r = await api("GET", `/business/events/${E1}/vip`, T.lastnik);
  assert(r.status === 200 && r.body.enabled === false && r.body.tables.length === 3 && r.body.currency === "EUR", "nov dogodek: VIP izklopljen, mize kluba na seznamu", r.body);
  assert(r.body.tables.every(t => t.booking === null && t.disabled === false && t.price_cents === t.default_price_cents), "mize brez rezervacije in brez izjem", r.body.tables);
  r = await api("PUT", `/business/events/${E1}/vip`, T.doorman, { enabled: true });
  assert(r.status === 403, "vratar ne more vklopiti VIP na dogodku -> 403", r.body);
  r = await api("PUT", `/business/events/${E1}/vip`, T.drugi, { enabled: true });
  assert(r.status === 404, "lastnik drugega kluba na tujem dogodku -> 404", r.body);
  r = await api("GET", `/business/events/${E1}/vip`, T.drugi);
  assert(r.status === 404, "GET /business/events/:id/vip na tujem dogodku -> 404", r.body);
  r = await api("PUT", `/business/events/${E1}/vip`, T.lastnik, { enabled: "da" });
  assert(r.status === 400, "enabled ni boolean -> 400", r.body);
  r = await api("PUT", `/business/events/${E1}/vip`, T.lastnik, { enabled: true, tables: [{ table_id: 999999 }] });
  assert(r.status === 400, "table_id, ki ne obstaja -> 400", r.body);
  r = await api("PUT", `/business/events/${E1}/vip`, T.lastnik, { enabled: true, tables: [{ table_id: M1, price_cents: 1.5 }] });
  assert(r.status === 400, "cena po dogodku s plavajoco vejico -> 400", r.body);
  r = await api("PUT", `/business/events/${E1}/vip`, T.lastnik, { enabled: true, tables: [{ table_id: M1 }, { table_id: M1 }] });
  assert(r.status === 400, "dvakrat ista miza -> 400", r.body);
  const mizaDrugega = (await api("PUT", "/business/vip", T.drugi, { plan: PLAN, tables: [{ label: "D1", x: 1, y: 1, w: 2, h: 2, shape: "round", seats: 4, price_cents: 15000 }], packages: [] })).body.tables[0];
  r = await api("PUT", `/business/events/${E1}/vip`, T.lastnik, { enabled: true, tables: [{ table_id: mizaDrugega.id }] });
  assert(r.status === 400, "miza drugega kluba na dogodku -> 400", r.body);

  r = await api("PUT", `/business/events/${E1}/vip`, T.manager, { enabled: true, tables: [{ table_id: M1, price_cents: 35000 }, { table_id: M2, disabled: true }] });
  assert(r.status === 200 && r.body.enabled === true, "manager vklopi VIP z izjemami", r.body);
  const t1 = r.body.tables.find(t => t.id === M1), t2 = r.body.tables.find(t => t.id === M2), t3 = r.body.tables.find(t => t.id === M3novi);
  assert(t1.price_cents === 35000 && t1.default_price_cents === 30000 && t1.disabled === false, "cena po dogodku (prepis) 35000, privzeta 30000", t1);
  assert(t2.disabled === true && t3.price_cents === 45000 && t3.disabled === false, "T2 izklopljena, T3 privzeta cena", [t2, t3]);

  console.log("\n# Javno: GET /events/:id/vip (brez zetona), vip_enabled, vip_from_cents");
  r = await api("GET", `/events/${E1}/vip`);
  assert(r.status === 200 && r.body.enabled === true && r.body.on_sale === true && r.body.currency === "EUR" && r.body.event_id === E1, "javni GET /events/:id/vip brez zetona", r.body);
  assert(r.body.plan && r.body.plan.width === 24 && r.body.plan.elements.length === 3, "tloris je v odgovoru", r.body.plan);
  assert(r.body.tables.length === 2 && !r.body.tables.some(t => t.id === M2), "izklopljena miza (M2) NI na seznamu", r.body.tables);
  assert(r.body.tables.find(t => t.id === M1).price_cents === 35000 && r.body.tables.every(t => t.available === true), "javna cena je cena po dogodku, vse proste", r.body.tables);
  assert(r.body.packages.length === 2 && Object.keys(r.body.packages[0]).sort().join() === "description,id,name", "paketi: id, name, description", r.body.packages);
  assert(!/buyer|username|email|user_id/i.test(r.besedilo), "odgovor ne vsebuje podatkov o kupcu", r.besedilo.slice(0, 200));
  r = await api("GET", `/events/${E1}`);
  assert(r.status === 200 && r.body.vip_enabled === true && r.body.vip_from_cents === 35000, "GET /events/:id: vip_enabled true, vip_from_cents 35000 (najnizja vklopljena)", [r.body.vip_enabled, r.body.vip_from_cents]);
  r = await api("GET", `/events/${ENOVIP}`);
  assert(r.status === 200 && r.body.vip_enabled === false && r.body.vip_from_cents === null, "dogodek brez VIP: vip_enabled false, vip_from_cents null", [r.body.vip_enabled, r.body.vip_from_cents]);
  r = await api("GET", "/events?upcoming=true");
  const vSeznamu = r.body.find(e => e.id === E1);
  assert(r.status === 200 && vSeznamu && vSeznamu.vip_enabled === true && vSeznamu.vip_from_cents === 35000, "GET /events vsebuje vip_enabled in vip_from_cents", vSeznamu);
  r = await api("GET", `/events/${ENOVIP}/vip`);
  assert(r.status === 200 && r.body.enabled === false && r.body.tables.length === 0 && r.body.packages.length === 0, "VIP izklopljen -> enabled false, tables [], packages []", r.body);
  r = await api("GET", `/events/${EDRAFT}/vip`);
  assert(r.status === 404, "osnutek dogodka -> 404", r.status);
  r = await api("GET", `/events/${EHID}/vip`);
  assert(r.status === 404, "dogodek skritega kluba -> 404", r.status);
  r = await api("GET", "/events/999999/vip");
  assert(r.status === 404, "dogodek ne obstaja -> 404", r.status);
  r = await api("GET", "/events/abc/vip");
  assert(r.status === 400, "neveljaven id -> 400", r.status);
  r = await api("GET", "/clubs");
  assert(r.status === 200 && !/floor_plan/.test(JSON.stringify(r.body)), "GET /clubs ne razkrije floor_plan (I4)", r.status);
  r = await api("GET", "/clubs/1");
  assert(r.status === 200 && !/floor_plan/.test(JSON.stringify(r.body)), "GET /clubs/:id ne razkrije floor_plan (I4)", r.status);

  console.log("\n# Nakup mize: osnovni tok");
  r = await nakup(E1, M1, null, { package_id: P1 });
  assert(r.status === 401, "brez zetona -> 401", r.status);
  r = await nakup(E1, M1, T.ana, {});
  assert(r.status === 400 && /package/i.test(r.body), "klub ima pakete, paket ni izbran -> 400", r.body);
  r = await nakup(E1, M1, T.ana, { package_id: "x" });
  assert(r.status === 400, "package_id ni celo stevilo -> 400", r.body);
  r = await nakup(E1, M1, T.ana, { package_id: 999999 });
  assert(r.status === 400, "paket, ki ne obstaja -> 400", r.body);
  const tujPaketId = (await api("PUT", "/business/vip", T.drugi, { plan: PLAN, tables: [{ id: mizaDrugega.id, label: "D1", x: 1, y: 1, w: 2, h: 2, shape: "round", seats: 4, price_cents: 15000 }], packages: [{ name: "Tuj paket", description: "x" }] })).body.packages[0].id;
  r = await nakup(E1, M1, T.ana, { package_id: tujPaketId });
  assert(r.status === 400, "paket drugega kluba -> 400", r.body);
  r = await nakup(E1, M2, T.ana, { package_id: P1 });
  assert(r.status === 404, "miza izklopljena na dogodku -> 404", r.body);
  r = await nakup(E1, mizaDrugega.id, T.ana, { package_id: P1 });
  assert(r.status === 404, "miza drugega kluba na tem dogodku -> 404", r.body);
  r = await nakup(E1, M3, T.ana, { package_id: P1 });
  assert(r.status === 404, "arhivirana miza -> 404", r.body);
  r = await nakup(E1, 999999, T.ana, { package_id: P1 });
  assert(r.status === 404, "miza ne obstaja -> 404", r.body);
  r = await nakup(E1, "abc", T.ana, { package_id: P1 });
  assert(r.status === 400, "neveljaven id mize -> 400", r.body);
  r = await nakup(ENOVIP, M1, T.ana, { package_id: P1 });
  assert(r.status === 404, "dogodek z izklopljenim VIP -> 404", r.body);
  r = await nakup(999999, M1, T.ana, { package_id: P1 });
  assert(r.status === 404, "dogodek ne obstaja -> 404", r.body);
  r = await nakup(EDRAFT, M1, T.ana, { package_id: P1 });
  assert(r.status === 409, "osnutek dogodka -> 409 Event is not on sale", r.body);

  const prej = (await pool.query("SELECT sold_count, capacity FROM events WHERE id=$1", [E1])).rows[0];
  r = await nakup(E1, M1, T.ana, { package_id: P1 });
  assert(r.status === 201 && r.body.mode === "test", "ana kupi mizo T1 s paketom -> 201, mode test", r.body);
  const o = r.body.order, vst = r.body.tickets;
  assert(o.is_vip === true && o.table_id === M1 && o.table_label === "T1" && o.table_seats === 6 && o.package_name === "Jameson 0,7 l" && o.package_description === "4x Red Bull, 1 l orange juice", "narocilo: is_vip, table_id, table_label, table_seats, paket", o);
  assert(o.quantity === 1 && o.unit_price_cents === 35000 && o.total_cents === 35000 && o.currency === "EUR", "quantity 1, cena = cena mize po dogodku (35000 centov)", o);
  assert(o.application_fee_cents === 3500 && o.status === "paid" && o.is_test === true, "provizija 10 % = 3500, status paid, test", o);
  assert(vst.length === 6, "6 vstopnic (table_seats)", vst.length);
  assert(vst.every(t => t.is_vip === true && t.table_label === "T1" && t.table_seats === 6 && t.package_name === o.package_name && t.package_description === o.package_description), "vsaka vstopnica nosi VIP polja", vst[0]);
  assert(new Set(vst.map(t => t.serial)).size === 6 && vst.every(t => { const q = preveriQr(t.qr); return q && q.t === t.serial; }), "vsaka vstopnica ima svojo veljavno QR kodo", vst.map(t => t.qr).slice(0, 1));
  const po = (await pool.query("SELECT sold_count, capacity FROM events WHERE id=$1", [E1])).rows[0];
  assert(po.sold_count === prej.sold_count && po.capacity === prej.capacity, "VIP vstopnice NE stejejo v sold_count / capacity", [prej, po]);
  const avail = await api("GET", `/events/${E1}/vip`);
  assert(avail.body.tables.find(t => t.id === M1).available === false && avail.body.tables.find(t => t.id === M3novi).available === true, "kupljena miza je zasedena, druga prosta", avail.body.tables);
  assert(!/ana/.test(avail.besedilo), "javni odgovor po nakupu ne razkrije kupca", avail.besedilo.slice(0, 120));
  r = await nakup(E1, M1, T.bor, { package_id: P2 });
  assert(r.status === 409 && /already booked/i.test(r.body), "ista miza drugic -> 409 This table is already booked", r.body);
  const stNar = (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE table_id=$1", [M1])).rows[0].n;
  const stVst = (await pool.query("SELECT COUNT(*)::int AS n FROM tickets WHERE order_id=$1", [o.id])).rows[0].n;
  assert(stNar === 1 && stVst === 6, "v bazi 1 narocilo in 6 vstopnic za mizo", [stNar, stVst]);

  console.log("\n# Mize ne stejejo v capacity (obstojeca zaloga je ostala nedotaknjena)");
  r = await api("PUT", `/business/events/${ECAP}/vip`, T.lastnik, { enabled: true });
  assert(r.status === 200, "VIP na dogodku z zalogo 2", r.status);
  for (let i = 0; i < 2; i++) {
    r = await api("POST", `/events/${ECAP}/orders`, T.bor, { quantity: 1 });
    assert(r.status === 201, `navadna vstopnica ${i + 1}/2 (capacity 2)`, r.body);
  }
  r = await api("POST", `/events/${ECAP}/orders`, T.bor, { quantity: 1 });
  assert(r.status === 409, "navadnih vstopnic je razprodanih (3. -> 409)", r.body);
  nakupov += 3;
  r = await nakup(ECAP, M3novi, T.ana, { package_id: P1 });
  assert(r.status === 201 && r.body.tickets.length === 8, "miza na razprodanem dogodku se vedno kupi (8 vstopnic)", r.body);
  const capSt = (await pool.query("SELECT sold_count, capacity FROM events WHERE id=$1", [ECAP])).rows[0];
  assert(capSt.sold_count === 2 && capSt.capacity === 2, "sold_count ostane 2 / 2 (miza ne steje)", capSt);
  // Preklic naroÄila mize ne sme zmanjsati sold_count (sprosti_zalogo preskoci mize).
  await pool.query("UPDATE orders SET status='cancelled', cancelled_at=NOW() WHERE id=$1", [r.body.order.id]);
  const capSt2 = (await pool.query("SELECT sold_count FROM events WHERE id=$1", [ECAP])).rows[0];
  assert(capSt2.sold_count === 2, "preklic narocila mize ne zmanjsa sold_count", capSt2);
  r = await nakup(ECAP, M3novi, T.bor, { package_id: P2 });
  assert(r.status === 201, "po preklicu je miza spet prosta za nakup (I13 indeks sprosti mizo)", r.body);

  console.log("\n# Nakup: okno prodaje in starost (isto kot vstopnice)");
  for (const [id, ime] of [[ESTART, "ze zacet"], [ECLOSED, "prodaja zaprta"], [EOPEN, "prodaja se ni odprta"]]) {
    r = await api("PUT", `/business/events/${id}/vip`, T.lastnik, { enabled: true });
    assert(r.status === 200, `VIP vklopljen (${ime})`, r.status);
    const kupec = await nakup(id, M1, T.ana, { package_id: P1 });
    assert(kupec.status === 409, `dogodek ${ime} -> 409`, kupec.body);
    const jav = await api("GET", `/events/${id}/vip`);
    assert(jav.status === 200 && jav.body.on_sale === false && jav.body.enabled === true && jav.body.tables.length === 3, `javno: ${ime} -> on_sale false, mize se vidijo`, jav.body.on_sale);
  }
  r = await api("PUT", `/business/events/${E18}/vip`, T.lastnik, { enabled: true });
  assert(r.status === 200, "VIP vklopljen na dogodku 18+", r.status);
  r = await nakup(E18, M1, T.mladoletni, { package_id: P1 });
  assert(r.status === 403 && /at least 18/.test(r.body), "16-letnik na dogodku 18+ -> 403 (I8)", r.body);
  r = await nakup(E18, M1, T.brezdatuma, { package_id: P1 });
  assert(r.status === 403 && /date of birth/i.test(r.body), "brez datuma rojstva na dogodku 18+ -> 403 (I8)", r.body);
  const brezNarocil = (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1", [E18])).rows[0].n;
  assert(brezNarocil === 0, "zavrnjen nakup ne pusti narocila", brezNarocil);
  r = await nakup(E18, M1, T.ana, { package_id: P1 });
  assert(r.status === 201, "polnoletna kupi mizo na dogodku 18+ -> 201", r.body);
  const nakupE18 = r.body;

  console.log("\n# Klub brez paketov: miza se kupi brez paketa");
  r = await api("PUT", `/business/events/${E2}/vip`, T.drugi, { enabled: true });
  assert(r.status === 200, "drugi klub vklopi VIP", r.status);
  const drugiTelo = { plan: PLAN, tables: [{ id: mizaDrugega.id, label: "D1", x: 1, y: 1, w: 2, h: 2, shape: "round", seats: 4, price_cents: 15000 }], packages: [] };
  r = await api("PUT", "/business/vip", T.drugi, drugiTelo);
  assert(r.status === 200 && r.body.packages.length === 0, "drugi klub odstrani vse pakete (arhivirani)", r.body);
  r = await api("GET", `/events/${E2}/vip`);
  assert(r.body.packages.length === 0 && r.body.tables.length === 1 && r.body.enabled === true, "klub brez paketov: packages [], 1 miza", r.body);
  r = await nakup(E2, mizaDrugega.id, T.ana, { package_id: tujPaketId });
  assert(r.status === 400, "arhiviran paket (klub nima aktivnih paketov) -> 400", r.body);
  r = await nakup(E2, mizaDrugega.id, T.ana);
  assert(r.status === 201 && r.body.order.package_name === null && r.body.order.package_description === null && r.body.tickets.length === 4, "brez paketa -> 201, package null, 4 vstopnice", r.body);
  const drugiPaket = await pool.query("SELECT package_id FROM orders WHERE id=$1", [r.body.order.id]);
  assert(drugiPaket.rows[0].package_id === null, "package_id v bazi je NULL", drugiPaket.rows[0]);

  console.log("\n# VIP vstopnice v /me/tickets, /me/orders, prenos");
  r = await api("GET", "/me/tickets", T.ana);
  const anaVip = r.body.filter(t => t.is_vip && t.event_id === E1);
  assert(r.status === 200 && anaVip.length === 6 && anaVip.every(t => t.table_label === "T1" && t.table_seats === 6 && t.package_name), "GET /me/tickets: 6 VIP vstopnic z mizo in paketom", anaVip.length);
  const navadna = (await api("POST", `/events/${E1}/orders`, T.ana, { quantity: 1 }));
  nakupov++;
  assert(navadna.status === 201 && navadna.body.order.is_vip === false && navadna.body.order.table_label === null && navadna.body.tickets[0].is_vip === false && navadna.body.tickets[0].table_seats === null && navadna.body.tickets[0].package_name === null, "navadna vstopnica: is_vip false, table_* in package_* null", navadna.body.tickets[0]);
  assert((await pool.query("SELECT sold_count FROM events WHERE id=$1", [E1])).rows[0].sold_count === 1, "navadna vstopnica poveca sold_count samo za 1 (ne za mizo)");
  r = await api("GET", "/me/orders", T.ana);
  const vipNar = r.body.find(x => x.id === o.id);
  assert(r.status === 200 && vipNar && vipNar.is_vip === true && vipNar.table_label === "T1" && vipNar.tickets.length === 6 && vipNar.tickets.every(t => t.is_vip), "GET /me/orders: narocilo mize z 6 VIP vstopnicami", vipNar && vipNar.tickets.length);

  const prenosVst = anaVip[0];
  r = await api("POST", `/tickets/${prenosVst.id}/transfer`, T.ana, { email: "cene@outly.si" });
  assert(r.status === 200 && r.body.result === "ok", "prenos VIP vstopnice prijatelju -> 200", r.body);
  r = await api("GET", "/me/tickets", T.cene);
  const ceneVip = r.body.find(t => t.id === prenosVst.id);
  assert(ceneVip && ceneVip.is_vip === true && ceneVip.table_label === "T1" && ceneVip.table_seats === 6 && ceneVip.package_name && ceneVip.serial !== prenosVst.serial, "prejemnik ima VIP vstopnico z mizo in paketom ter novim serialom", ceneVip);
  r = await api("GET", "/me/tickets", T.ana);
  assert(!r.body.some(t => t.id === prenosVst.id) && r.body.filter(t => t.is_vip && t.event_id === E1).length === 5, "ana prenesene vstopnice ne vidi vec (ostane 5)", r.body.length);

  console.log("\n# Sken VIP vstopnice in rezervacije");
  r = await api("POST", "/business/tickets/scan", T.doorman, { qr: ceneVip.qr });
  assert(r.status === 200 && r.body.result === "ok", "vratar skenira prenesen VIP QR -> 200", r.body);
  assert(r.body.ticket.is_vip === true && r.body.ticket.table_label === "T1" && r.body.ticket.table_seats === 6 && r.body.ticket.package_name === "Jameson 0,7 l" && r.body.ticket.package_description === "4x Red Bull, 1 l orange juice", "sken vrne VIP polja (miza, sedezi, paket)", r.body.ticket);
  r = await api("POST", "/business/tickets/scan", T.doorman, { qr: ceneVip.qr });
  assert(r.status === 409 && r.body.result === "already_used" && r.body.ticket.is_vip === true && r.body.ticket.table_label === "T1", "ponovni sken -> 409 already_used, ticket se vedno nosi VIP polja", r.body);
  r = await api("GET", `/business/events/${E1}/tickets`, T.doorman);
  assert(r.status === 200 && r.body.filter(t => t.is_vip).length === 6 && r.body.filter(t => t.is_vip).every(t => t.table_label === "T1" && t.package_name), "GET /business/events/:id/tickets nosi VIP polja", r.body.length);
  r = await api("GET", `/business/events/${E1}/vip`, T.doorman);
  assert(r.status === 200, "vratar sme brati rezervacije (GET /business/events/:id/vip)", r.status);
  const rez = r.body.tables.find(t => t.id === M1);
  assert(rez.booking && rez.booking.order_id === o.id && rez.booking.public_ref === o.public_ref && rez.booking.buyer_username === "ana" && rez.booking.package_name === "Jameson 0,7 l" && rez.booking.guests === 6 && rez.booking.checked_in === 1, "rezervacija: kupec ana, paket, guests 6, checked_in 1", rez.booking);
  assert(Object.keys(rez.booking).sort().join() === "buyer_username,checked_in,created_at,guests,order_id,package_description,package_name,public_ref", "rezervacija vsebuje samo dogovorjena polja (brez e-naslova)", Object.keys(rez.booking));
  assert(r.body.tables.filter(t => t.booking !== null).length === 1 && r.body.tables.find(t => t.id === M2).disabled === true, "samo ena miza ima rezervacijo, izklopljena kaze disabled", r.body.tables.map(t => [t.id, !!t.booking, t.disabled]));
  // Arhivirana miza z rezervacijo je na seznamu.
  await pool.query("UPDATE club_tables SET archived_at=NOW() WHERE id=$1", [M1]);
  r = await api("GET", `/business/events/${E1}/vip`, T.lastnik);
  assert(r.body.tables.some(t => t.id === M1 && t.booking), "arhivirana miza z rezervacijo je na seznamu dogodka", r.body.tables.map(t => t.id));
  r = await api("GET", `/events/${E1}/vip`);
  assert(r.body.tables.find(t => t.id === M1) && r.body.tables.find(t => t.id === M1).available === false, "javno: arhivirana miza z prodajo na tem dogodku ostane na seznamu kot zasedena", r.body.tables.map(t => [t.id, t.available]));
  await pool.query("UPDATE club_tables SET archived_at=NULL WHERE id=$1", [M1]);

  console.log("\n# Prodaja: tables_sold, tickets_sold brez miz, gross z mizami");
  r = await api("GET", "/business/sales", T.lastnik);
  const sold = r.body.events.find(e => e.id === E1);
  assert(r.status === 200 && sold.tables_sold === 1 && sold.tickets_sold === 1 && sold.gross_cents === 35000 + 1500, "events[]: tables_sold 1, tickets_sold 1 (brez mize), gross vkljucuje mizo", sold);
  assert(r.body.summary.tables_sold >= 3 && r.body.summary.tables_gross_cents > 0 && r.body.summary.gross_cents >= r.body.summary.tables_gross_cents, "summary: tables_sold, tables_gross_cents, gross vkljucuje mize", r.body.summary);
  const navadnih = (await pool.query("SELECT COALESCE(SUM(quantity),0)::int AS n FROM orders WHERE club_id=1 AND table_id IS NULL AND status IN ('paid','partially_refunded')")).rows[0].n;
  assert(r.body.summary.tickets_sold === navadnih, "summary.tickets_sold steje samo navadne vstopnice", [r.body.summary.tickets_sold, navadnih]);
  const vipNarSales = r.body.recent_orders.find(x => x.id === o.id);
  assert(vipNarSales && vipNarSales.is_vip === true && vipNarSales.table_label === "T1", "recent_orders nosi VIP polja", vipNarSales);
  r = await api("GET", "/business/sales?range=week", T.lastnik);
  assert(r.status === 200 && Array.isArray(r.body.series), "?range=week deluje se naprej", r.status);

  console.log("\n# Brez mrtve zanke: shranjevanje tlorisa med nakupi");
  await restart();
  const sprem = await api("GET", "/business/vip", T.lastnik);
  const delTelo = { plan: sprem.body.plan, tables: sprem.body.tables, packages: sprem.body.packages };
  await api("PUT", `/business/events/${EPAR}/vip`, T.lastnik, { enabled: true });
  const kupciMes = ["p1", "p2", "p3"].map((k, i) => zeton(`${k}@outly.si`, uuid(200 + i)));
  for (const t of kupciMes) await api("GET", "/me", t);
  // Miza s paketom pijace zahteva datum rojstva (>= 18, #102): ti kupci ga potrebujejo (glej test_vip_starost.js).
  await pool.query("UPDATE users SET date_of_birth = (CURRENT_DATE - INTERVAL '30 years')::date WHERE email LIKE 'p_@outly.si'");
  const vsi = await Promise.all([
    api("PUT", "/business/vip", T.lastnik, delTelo), api("PUT", "/business/vip", T.manager, delTelo), api("PUT", "/business/vip", T.lastnik, delTelo),
    ...[M1, M2, M3novi].map((m, i) => api("POST", `/events/${EPAR}/tables/${m}/orders`, kupciMes[i], { package_id: P1 })),
  ]);
  nakupov += 3;
  assert(vsi.slice(0, 3).every(x => x.status === 200), "3 hkratna shranjevanja tlorisa: vsa 200", vsi.slice(0, 3).map(x => x.status));
  // M2 je na EPAR privzeto vklopljena (izjema je samo na E1).
  assert(vsi.slice(3).every(x => x.status === 201), "3 vzporedni nakupi razlicnih miz med shranjevanjem: vsi 201 (brez 500 / mrtve zanke)", vsi.slice(3).map(x => x.status));
  assert(!/deadlock/i.test(log), "v logu ni 'deadlock'", log.split("\n").filter(l => /deadlock/i.test(l)).slice(0, 2));

  console.log("\n# I13: 12 vzporednih nakupov iste mize -> natanko 1 uspe");
  await restart();
  const EI13 = await dogodek(1, "I13", "8 days");
  await api("PUT", `/business/events/${EI13}/vip`, T.lastnik, { enabled: true });
  const kupci12 = Array.from({ length: 12 }, (_, i) => zeton(`i13_${i}@outly.si`, uuid(300 + i)));
  for (const t of kupci12) await api("GET", "/me", t);
  await pool.query("UPDATE users SET date_of_birth = (CURRENT_DATE - INTERVAL '30 years')::date WHERE email LIKE 'i13\\_%@outly.si'");
  const rez12 = await Promise.all(kupci12.map(t => api("POST", `/events/${EI13}/tables/${M3novi}/orders`, t, { package_id: P1 })));
  nakupov += 12;
  const ok201 = rez12.filter(x => x.status === 201).length, k409 = rez12.filter(x => x.status === 409).length;
  assert(ok201 === 1 && k409 === 11, "natanko 1 od 12 vzporednih nakupov iste mize uspe, 11 dobi 409", rez12.map(x => x.status));
  const nI13 = (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1 AND table_id=$2", [EI13, M3novi])).rows[0].n;
  const vI13 = (await pool.query("SELECT COUNT(*)::int AS n FROM tickets WHERE event_id=$1", [EI13])).rows[0].n;
  assert(nI13 === 1 && vI13 === 8, "v bazi natanko 1 narocilo in 8 vstopnic (M3 ima 8 sedezev)", [nI13, vI13]);
  const jav = await api("GET", "/", null);
  assert(jav.status === 200, "backend po vzporednem nakupu se odgovarja (pool ni zaseden)", jav.status);
  const indeksTest = await pool.query(
    `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, buyer_email, paid_at, table_id, table_label, table_seats)
     SELECT 'OUT-DUP', user_id, event_id, club_id, 1, 1, 1, 'paid', buyer_email, NOW(), table_id, table_label, table_seats FROM orders WHERE event_id=$1 AND table_id=$2`, [EI13, M3novi]).then(() => "vstavljeno", e => e.code + ":" + e.constraint);
  assert(indeksTest === "23505:orders_miza_dogodek_key", "baza sama zavrne dvojno rezervacijo (unikaten delni indeks I13)", indeksTest);
  // Vzporedno razlicne mize na istem dogodku: vsi uspejo.
  await restart();
  const EI13b = await dogodek(1, "I13b", "9 days");
  await api("PUT", `/business/events/${EI13b}/vip`, T.lastnik, { enabled: true });
  const trije = await Promise.all([M1, M2, M3novi].map((m, i) => api("POST", `/events/${EI13b}/tables/${m}/orders`, kupci12[i], { package_id: P1 })));
  assert(trije.every(x => x.status === 201), "vzporedni nakupi RAZLICNIH miz vsi uspejo", trije.map(x => x.status));

  console.log("\n# Regresija: navadni nakupi in zaloga");
  await restart();
  r = await api("POST", `/events/${E1}/orders`, T.bor, { quantity: 2 });
  assert(r.status === 201 && r.body.order.total_cents === 3000 && r.body.tickets.length === 2, "navaden nakup 2 vstopnic dela kot prej", r.body);
  assert((await pool.query("SELECT sold_count FROM events WHERE id=$1", [E1])).rows[0].sold_count === 3, "sold_count = 3 (1 + 2 navadne, mize ne stejejo)");
  await pool.query("UPDATE orders SET status='cancelled', cancelled_at=NOW() WHERE id=$1", [r.body.order.id]);
  assert((await pool.query("SELECT sold_count FROM events WHERE id=$1", [E1])).rows[0].sold_count === 1, "preklic navadnega narocila sprosti zalogo (sold_count 1)");

  console.log("\n# Popravki po pregledu: arhivirana rezervirana miza, javni seznam, potrditev cene");
  await restart();
  // (1) Arhivirana miza z rezervacijo na dogodku: GET jo vrne (archived: true), PUT dogodka z vsemi mizami iz GET ne sme pasti.
  r = await nakup(E1, M3novi, T.bor, { package_id: P1 });
  assert(r.status === 201, "bor kupi M3 na E1 (za test izklopa prodane mize)", r.body);
  const klubVip = (await api("GET", "/business/vip", T.lastnik)).body;
  r = await api("PUT", "/business/vip", T.lastnik, { plan: klubVip.plan, tables: klubVip.tables.filter(t => t.id !== M1), packages: klubVip.packages });
  assert(r.status === 200 && !r.body.tables.some(t => t.id === M1), "klub arhivira rezervirano mizo M1", r.body);
  r = await api("GET", `/business/events/${E1}/vip`, T.doorman);
  const arhM1 = r.body.tables.find(t => t.id === M1);
  assert(arhM1 && arhM1.booking && arhM1.archived === true && r.body.tables.filter(t => t.id !== M1).every(t => t.archived === false), "GET /business/events/:id/vip: arhivirana miza z rezervacijo ima archived true, ostale false", r.body.tables.map(t => [t.id, t.archived]));
  const vseMize = r.body.tables.map(t => ({ table_id: t.id, price_cents: t.price_cents, disabled: t.disabled }));
  r = await api("PUT", `/business/events/${E1}/vip`, T.lastnik, { enabled: true, tables: vseMize });
  assert(r.status === 200 && r.body.tables.some(t => t.id === M1 && t.booking), "PUT dogodka z vsemi mizami iz GET (tudi arhivirano) -> 200", r.body);
  r = await api("PUT", `/business/events/${E1}/vip`, T.lastnik, { enabled: true, tables: [{ table_id: mizaDrugega.id }] });
  assert(r.status === 400, "tuja miza se vedno -> 400", r.body);
  // (5) Prodana miza, ki jo klub izklopi (ali arhivira), ostane v javnem seznamu kot zasedena.
  r = await api("PUT", `/business/events/${E1}/vip`, T.lastnik, { enabled: true, tables: [{ table_id: M3novi, disabled: true }] });
  assert(r.status === 200, "klub izklopi prodano mizo M3 na dogodku", r.status);
  r = await api("GET", `/events/${E1}/vip`);
  const jM3 = r.body.tables.find(t => t.id === M3novi), jM1 = r.body.tables.find(t => t.id === M1), jM2 = r.body.tables.find(t => t.id === M2);
  assert(jM3 && jM3.available === false && jM1 && jM1.available === false, "javno: prodana + izklopljena in prodana + arhivirana miza ostaneta z available false", r.body.tables.map(t => [t.id, t.available]));
  assert(!jM2, "javno: izklopljena NEprodana miza je se vedno skrita", r.body.tables.map(t => t.id));
  assert(r.body.tables.every(t => t.available === false) && r.body.enabled === true, "enabled ostane true (kupci vidijo Booked)", r.body.tables.length);
  r = await nakup(E1, M3novi, T.cene, { package_id: P1 });
  assert(r.status === 404, "izklopljene (prodane) mize se ne da kupiti -> 404", r.body);
  await api("PUT", `/business/events/${E1}/vip`, T.lastnik, { enabled: true, tables: [{ table_id: M3novi, disabled: false }] });
  await pool.query("UPDATE club_tables SET archived_at=NULL WHERE id=$1", [M1]);

  // (2) Potrditev cene: expected_price_cents.
  const EPR = await dogodek(1, "Potrditev cene", "10 days");
  await api("PUT", `/business/events/${EPR}/vip`, T.lastnik, { enabled: true });
  const cenaM1 = (await api("GET", `/events/${EPR}/vip`)).body.tables.find(t => t.id === M1).price_cents;
  for (const slab of ["30000", 1.5, -1, true]) {
    r = await nakup(EPR, M1, T.ana, { package_id: P1, expected_price_cents: slab });
    assert(r.status === 400, `expected_price_cents ${JSON.stringify(slab)} -> 400`, r.body);
  }
  r = await nakup(EPR, M1, T.ana, { package_id: P1, expected_price_cents: cenaM1 - 1 });
  assert(r.status === 409 && r.body === "The table price has changed.", "expected_price_cents != cena -> 409 The table price has changed.", r.body);
  assert((await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1", [EPR])).rows[0].n === 0, "zavrnjena potrditev cene ne pusti narocila");
  await api("PUT", `/business/events/${EPR}/vip`, T.lastnik, { enabled: true, tables: [{ table_id: M1, price_cents: cenaM1 + 1000 }] });
  r = await nakup(EPR, M1, T.ana, { package_id: P1, expected_price_cents: cenaM1 });
  assert(r.status === 409, "klub je med tem dvignil ceno -> stara potrjena cena -> 409", r.body);
  r = await nakup(EPR, M1, T.ana, { package_id: P1, expected_price_cents: cenaM1 + 1000 });
  assert(r.status === 201 && r.body.order.total_cents === cenaM1 + 1000, "expected_price_cents == cena -> 201 po tej ceni", r.body);
  r = await nakup(EPR, M2, T.ana, { package_id: P1, expected_price_cents: null });
  assert(r.status === 201, "expected_price_cents null (ali brez polja) deluje kot prej", r.body);

  // (3) Osamljen surrogat (neveljaven UTF-16) -> 400, ne 500.
  const kl = (await api("GET", "/business/vip", T.lastnik)).body;
  const surr = "\ud800";
  for (const [opis, spremeni] of [
    ["oznaka mize", b => { b.tables[0].label = "T" + surr; }],
    ["oznaka elementa tlorisa", b => { b.plan.elements[0].label = surr; }],
    ["ime paketa", b => { b.packages[0].name = "P" + surr; }],
    ["opis paketa", b => { b.packages[0].description = surr + "x"; }],
    ["obrnjen surrogat", b => { b.tables[0].label = "\udc00T"; }],
  ]) {
    const b = JSON.parse(JSON.stringify({ plan: kl.plan, tables: kl.tables, packages: kl.packages }));
    spremeni(b);
    r = await api("PUT", "/business/vip", T.lastnik, b);
    assert(r.status === 400, `osamljen surrogat (${opis}) -> 400`, [r.status, r.body]);
  }
  { const b = JSON.parse(JSON.stringify({ plan: kl.plan, tables: kl.tables, packages: kl.packages }));
    b.packages[0].description = "Party 🎉";
    r = await api("PUT", "/business/vip", T.lastnik, b);
    assert(r.status === 200 && r.body.packages[0].description === "Party 🎉", "veljaven par surrogatov (emoji) se shrani", r.status);
    b.packages[0].description = kl.packages[0].description; await api("PUT", "/business/vip", T.lastnik, b); }

  // (4) Prevelik id (> 2147483647) -> 400, ne 500.
  const VELIK = 2147483648;
  const velikiId = [
    ["GET", `/events/${VELIK}/vip`, null, undefined], ["POST", `/events/${VELIK}/tables/${M1}/orders`, T.ana, {}],
    ["POST", `/events/${E1}/tables/${VELIK}/orders`, T.ana, {}], ["POST", `/events/${E1}/tables/${M1}/orders`, T.ana, { package_id: VELIK }],
    ["GET", `/business/events/${VELIK}/vip`, T.lastnik, undefined], ["PUT", `/business/events/${VELIK}/vip`, T.lastnik, { enabled: true }],
    ["PUT", `/business/events/${E1}/vip`, T.lastnik, { enabled: true, tables: [{ table_id: VELIK }] }],
    ["PUT", "/business/vip", T.lastnik, { plan: kl.plan, tables: [{ id: VELIK, label: "Z", x: 0, y: 0, w: 1, h: 1, shape: "rect", seats: 2, price_cents: 1 }], packages: [] }],
    ["PUT", "/business/vip", T.lastnik, { plan: kl.plan, tables: [], packages: [{ id: VELIK, name: "Z", description: "" }] }],
  ];
  for (const [m, pot, tok, telo] of velikiId) {
    if (m === "POST") { if (nakupov >= 16) await restart(); nakupov++; }
    r = await api(m, pot, tok, telo);
    assert(r.status === 400, `prevelik id: ${m} ${pot.replace(String(VELIK), "VELIK")} -> 400 (ne 500)`, [r.status, r.body]);
  }
  assert(!/out of range/i.test(log), "v logu ni 'out of range' (napak baze zaradi velikih id-jev)", log.split("\n").filter(l => /out of range/i.test(l)).slice(0, 2));

  // (6) Matrika vlog.
  for (const [m, pot, telo] of [["GET", "/business/vip"], ["PUT", "/business/vip", kl], ["GET", `/business/events/${E1}/vip`], ["PUT", `/business/events/${E1}/vip`, { enabled: true }]]) {
    r = await api(m, pot, null, telo);
    assert(r.status === 401, `brez zetona: ${m} ${pot.replace(String(E1), ":id")} -> 401`, r.status);
  }
  r = await api("GET", `/business/events/${E1}/vip`, T.ana);
  assert(r.status === 403, "navaden uporabnik brez clanstva: GET /business/events/:id/vip -> 403", r.status);
  r = await api("PUT", `/business/events/${E1}/vip`, T.ana, { enabled: true });
  assert(r.status === 403, "navaden uporabnik brez clanstva: PUT /business/events/:id/vip -> 403", r.status);
  await pool.query("UPDATE users SET role='admin' WHERE email='bor@outly.si'");
  for (const [m, pot, telo] of [["GET", "/business/vip"], ["PUT", "/business/vip", kl], ["GET", `/business/events/${E1}/vip`], ["PUT", `/business/events/${E1}/vip`, { enabled: true }]]) {
    r = await api(m, pot, T.bor, telo);
    assert(r.status === 404, `admin brez kluba: ${m} ${pot.replace(String(E1), ":id")} -> 404`, r.status);
  }
  await pool.query("UPDATE users SET role='user' WHERE email='bor@outly.si'");

  console.log("\n# Migracija 026: demo tloris, mize, paketi");
  await restart();
  await pool.query(TRUNC);
  const lastniki = ["Velvet", "Nexus", "Mirage", "Mansion", "Olie", "Tuj"].map((ime) => ime);
  for (const ime of lastniki) await pool.query("INSERT INTO users (email, username, role, email_verified) VALUES ($1,$2,'business',TRUE)", [`${ime.toLowerCase()}@outly.si`, ime.toLowerCase()]);
  for (let i = 0; i < lastniki.length; i++) {
    await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ($1,$2,'Ljubljana')", [i + 1, lastniki[i]]);
  }
  // Nexus ima ze svoj tloris - migracija ga ne sme dotakniti.
  await pool.query(`UPDATE clubs SET floor_plan = '{"width":10,"height":10,"elements":[]}'::jsonb WHERE name='Nexus'`);
  for (const [klub, st, pomik, status] of [[1, "Velvet prihodnji A", "10 days", "published"], [1, "Velvet prihodnji B", "40 days", "published"], [1, "Velvet pretekli", "-10 days", "published"],
    [1, "Velvet osnutek", "20 days", "draft"], [2, "Nexus prihodnji", "10 days", "published"], [5, "Olie prihodnji", "5 days", "published"], [6, "Tuj prihodnji", "5 days", "published"]]) {
    await pool.query(`INSERT INTO events (club_id, title, poster_url, start_at, status) VALUES ($1,$2,'https://example.com/p.jpg', NOW() + $3::interval, $4)`, [klub, st, pomik, status]);
  }
  const SQL26 = brezTransakcije("026_vip_demo.sql");
  for (const krog of [1, 2]) {
    await pool.query("BEGIN"); await pool.query(SQL26); await pool.query("COMMIT");
    const st = async (ime) => (await pool.query(
      `SELECT (SELECT COUNT(*)::int FROM club_tables t WHERE t.club_id=c.id AND t.archived_at IS NULL) AS mize,
              (SELECT COUNT(*)::int FROM bottle_packages p WHERE p.club_id=c.id AND p.archived_at IS NULL) AS paketi,
              (c.floor_plan IS NOT NULL) AS plan FROM clubs c WHERE c.name=$1`, [ime])).rows[0];
    const v = await st("Velvet"), n = await st("Nexus"), m = await st("Mirage"), ma = await st("Mansion"), ol = await st("Olie"), tuj = await st("Tuj");
    assert(v.mize === 10 && v.paketi === 6 && v.plan, `zagon ${krog}: Velvet 10 miz, 6 paketov, tloris`, v);
    assert(m.mize === 7 && m.paketi === 4 && ma.mize === 9 && ma.paketi === 6 && ol.mize === 6 && ol.paketi === 4, `zagon ${krog}: Mirage 7/4, Mansion 9/6, Olie 6/4`, [m, ma, ol]);
    assert(n.mize === 0 && n.paketi === 0, `zagon ${krog}: Nexus z lastnim tlorisom ostane nedotaknjen`, n);
    assert(tuj.mize === 0 && tuj.paketi === 0 && !tuj.plan, `zagon ${krog}: klub z drugim imenom ostane nespremenjen`, tuj);
    const ev = Object.fromEntries((await pool.query("SELECT title, vip_enabled FROM events")).rows.map(e => [e.title, e.vip_enabled]));
    assert(ev["Velvet prihodnji A"] && ev["Velvet prihodnji B"] && ev["Olie prihodnji"], `zagon ${krog}: prihajajoci objavljeni dogodki demo klubov imajo VIP`, ev);
    assert(!ev["Velvet pretekli"] && !ev["Velvet osnutek"] && !ev["Nexus prihodnji"] && !ev["Tuj prihodnji"], `zagon ${krog}: pretekli, osnutek, klub s tlorisom in tuji klub brez VIP`, ev);
  }
  const demo = (await pool.query("SELECT label, seats, price_cents, shape FROM club_tables WHERE club_id=1 ORDER BY id")).rows;
  assert(demo.every(t => t.seats >= 4 && t.seats <= 10 && t.price_cents >= 20000 && t.price_cents <= 80000), "demo mize: 4-10 oseb, 200-800 EUR", demo);
  const pak = (await pool.query("SELECT name, description FROM bottle_packages WHERE club_id=1 ORDER BY sort")).rows;
  assert(pak[0].name === "Jameson 0,7 l" && pak[0].description === "4x Red Bull, 1 l orange juice", "demo paket: Jameson z opisom", pak[0]);
  const tipi = (await pool.query("SELECT DISTINCT e->>'type' AS t FROM clubs c, jsonb_array_elements(c.floor_plan->'elements') e WHERE c.name='Velvet'")).rows.map(x => x.t).sort().join();
  assert(tipi === "bar,dancefloor,dj,entrance,label,stage,wc", "demo tloris: bar, oder, DJ, plesisce, vhod, WC (+ napis)", tipi);
  // Demo podatki gredo skozi isto validacijo kot urejevalnik: GET -> PUT nespremenjeno -> 200.
  const velvetTok = zeton("velvet@outly.si", uuid(401));
  r = await api("GET", "/me", velvetTok);
  await pool.query("UPDATE users SET role='business' WHERE email='velvet@outly.si'");
  r = await api("GET", "/business/vip", velvetTok);
  assert(r.status === 200 && r.body.tables.length === 10, "lastnik Velvet vidi demo tloris", r.status);
  const demoTelo = { plan: r.body.plan, tables: r.body.tables, packages: r.body.packages };
  r = await api("PUT", "/business/vip", velvetTok, demoTelo);
  assert(r.status === 200 && JSON.stringify(r.body) === JSON.stringify(demoTelo), "demo tloris je veljaven za PUT (isto kot urejevalnik)", r.status);
  const demoEv = (await pool.query("SELECT id FROM events WHERE title='Velvet prihodnji A'")).rows[0].id;
  r = await api("GET", `/events/${demoEv}/vip`);
  assert(r.status === 200 && r.body.enabled && r.body.tables.length === 10 && r.body.packages.length === 6, "demo dogodek: javni GET /events/:id/vip", r.body.tables && r.body.tables.length);
  r = await api("GET", `/events/${demoEv}`);
  assert(r.body.vip_enabled === true && r.body.vip_from_cents === 20000, "demo dogodek: vip_from_cents 20000", [r.body.vip_enabled, r.body.vip_from_cents]);

  console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
  const napake = log.split("\n").filter(l => /error|TypeError|Unhandled|deadlock/i.test(l) && !/Server error\./.test(l) && !/Resend/i.test(l));
  if (napake.length) console.log("\nLog backenda (sumljivo):\n" + napake.slice(0, 20).join("\n"));
  srv.kill(); jwksServer.close();
  await pool.query(TRUNC);
  await pool.end();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); try { srv && srv.kill(); } catch (_) {} process.exit(1); });
