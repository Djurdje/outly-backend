#!/usr/bin/env node
/**
 * Test obnove izvoza (db/obnovi_izvoz.js) — dokaže, da se GET /admin/api/export
 * da obnoviti nazaj v prazno, z migracijami pripravljeno bazo. Zagon (lokalno,
 * PG16, prazna izvorna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_obnova.js
 * Vzorec kot test_finance_admin.js: lokalni JWKS, backend na svojem portu.
 * Ustvari tudi drugo bazo "outly_obnova" na istem strežniku (izbriše jo, če
 * že obstaja) — nanjo se obnovi izvoz. Ob koncu (tudi ob napaki) pobriše
 * outly_obnova in ustavi svoj backend/JWKS, da ne pušča procesov za naslednji zagon.
 */
const crypto = require("crypto");
const http = require("http");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn, spawnSync } = require("child_process");
const { Pool, Client } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const PORT = 3120, JWKS_PORT = 3999;
const BASE = `http://127.0.0.1:${PORT}`;
const KORENSKA_MAPA = path.join(__dirname, "..");

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
function poganjajNode(args, env, casovnaOmejitevMs) {
  const r = spawnSync(process.execPath, args, { cwd: KORENSKA_MAPA, env: { ...process.env, ...env }, encoding: "utf8", timeout: casovnaOmejitevMs || 60000 });
  return { koda: r.status, stdout: r.stdout || "", stderr: r.stderr || "" };
}

const pool = new Pool({ connectionString: DB });
const vzdrzevalnaUrl = new URL(DB); vzdrzevalnaUrl.pathname = "/postgres";
const obnovaUrl = new URL(DB); obnovaUrl.pathname = "/outly_obnova";
let obnovljeniPool = null;
let potIzvoza = null;
let srv = null;
let log = "";

async function pobrisiObnovoBazo() {
  const c = new Client({ connectionString: vzdrzevalnaUrl.toString() });
  await c.connect();
  await c.query("DROP DATABASE IF EXISTS outly_obnova WITH (FORCE)");
  await c.end();
}

async function telo() {
  console.log("\n# Priprava podatkov v izvorni bazi");
  const T = {
    admin: zeton("admin@outly.si", uuid(1)),
    lastnik: zeton("lastnik@outly.si", uuid(2)),
    kupec: zeton("kupec@outly.si", uuid(3)),
  };
  for (const k of Object.keys(T)) { const r = await api("GET", "/me", T[k]); assert(r.status === 200, `GET /me ${k}`, r.body); }

  await pool.query("UPDATE users SET role='admin' WHERE email='admin@outly.si'");
  await pool.query("UPDATE users SET role='business' WHERE email='lastnik@outly.si'");
  await pool.query("INSERT INTO clubs (owner_user_id, name, city) VALUES ((SELECT id FROM users WHERE email='lastnik@outly.si'), 'Obnova Club', 'Ljubljana')");
  await pool.query("UPDATE users SET date_of_birth = (CURRENT_DATE - INTERVAL '25 years')::date WHERE email='kupec@outly.si'");
  // JSONB (bar_prices) in text[] (gallery_urls) — preveri, da obnovi_izvoz.js oba
  // tipa prenese pravilno (CLAUDE.md tocka 7: JSONB kot JSON.stringify()::jsonb,
  // ARRAY kot JS seznam, nikoli obratno).
  await pool.query(
    "UPDATE clubs SET bar_prices = $1::jsonb, gallery_urls = $2 WHERE name = 'Obnova Club'",
    [JSON.stringify([{ item: "pivo", price_cents: 400 }, { item: "gin tonic", price_cents: 800 }]), ["https://a.example/1.jpg", "https://a.example/2.jpg"]]
  );

  const cezTeden = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
  let r = await api("POST", "/events", T.lastnik, { clubId: 1, title: "Dogodek za obnovo", startAt: cezTeden, ticketPriceCents: 1000, capacity: 3, minAge: 0 });
  assert(r.status === 201, "dogodek ustvarjen (zmogljivost 3)", r.body);
  const dogodekId = r.body.id;
  const klubId = r.body.club_id || 1;

  r = await api("POST", `/events/${dogodekId}/orders`, T.kupec, { quantity: 3 });
  assert(r.status === 201, "kupec zapolni celotno zmogljivost (3 vstopnice)", r.body);

  const izvornoStanjeDogodka = await pool.query("SELECT capacity, sold_count FROM events WHERE id=$1", [dogodekId]);
  assert(izvornoStanjeDogodka.rows[0].sold_count === 3, "sold_count v izvorni bazi = 3 (zapolnjeno)", izvornoStanjeDogodka.rows[0]);
  const izvornaVsotaNarocil = await pool.query("SELECT COALESCE(SUM(total_cents),0)::int AS vsota FROM orders");

  console.log("\n# GET /admin/api/export");
  r = await api("GET", "/admin/api/export", T.admin);
  assert(r.status === 200, "izvoz -> 200", r.status);
  assert(r.body.tables && typeof r.body.tables === "object", "izvoz vsebuje tables", Object.keys(r.body.tables || {}));
  assert(Array.isArray(r.body.sequences) && r.body.sequences.length > 0, "izvoz vsebuje sequences", r.body.sequences);
  const izvoz = r.body;

  potIzvoza = path.join(os.tmpdir(), `outly_izvoz_test_${Date.now()}.json`);
  fs.writeFileSync(potIzvoza, JSON.stringify(izvoz));

  console.log("\n# Priprava ciljne baze outly_obnova");
  const vzdrzevalniOdjemalec = new Client({ connectionString: vzdrzevalnaUrl.toString() });
  await vzdrzevalniOdjemalec.connect();
  await vzdrzevalniOdjemalec.query("DROP DATABASE IF EXISTS outly_obnova WITH (FORCE)");
  await vzdrzevalniOdjemalec.query("CREATE DATABASE outly_obnova");
  await vzdrzevalniOdjemalec.end();

  console.log("\n# npm run migrate na outly_obnova");
  let izidMigracij = poganjajNode(["db/migrate.js"], { DATABASE_URL: obnovaUrl.toString() });
  assert(izidMigracij.koda === 0, "migracije na prazni outly_obnova -> 0", izidMigracij.stdout + izidMigracij.stderr);

  // Migracija 007 vstavi servisni racun agent@outly.si (glej db/migracije/007_servisni_admin.sql)
  // — edini seed podatek med vsemi migracijami. obnovi_izvoz.js po nacrtu zahteva
  // POPOLNOMA prazno bazo (brez izjeme, glej tocko 1 zahtev), zato ga pred pravo
  // obnovo pobrisemo — enako bi moral narediti Martin pred obnovo prave baze
  // (glej opombo v docs/STATE.md).
  const obnovaOdjemalec = new Client({ connectionString: obnovaUrl.toString() });
  await obnovaOdjemalec.connect();
  await obnovaOdjemalec.query("DELETE FROM users");
  await obnovaOdjemalec.end();

  console.log("\n# node db/obnovi_izvoz.js na outly_obnova");
  let izidObnove = poganjajNode(["db/obnovi_izvoz.js", potIzvoza], { DATABASE_URL: obnovaUrl.toString() });
  assert(izidObnove.koda === 0, "obnova izvoza -> 0", izidObnove.stdout + izidObnove.stderr);
  assert(/Obnova končana/.test(izidObnove.stdout), "izpis vsebuje 'Obnova končana'", izidObnove.stdout);

  obnovljeniPool = new Pool({ connectionString: obnovaUrl.toString() });

  console.log("\n# (a) stevilo vrstic po tabelah enako izvozu");
  for (const tabela of Object.keys(izvoz.tables)) {
    const stev = await obnovljeniPool.query(`SELECT count(*)::int AS n FROM "${tabela}"`);
    assert(stev.rows[0].n === izvoz.tables[tabela].count, `tabela ${tabela}: ${stev.rows[0].n} == ${izvoz.tables[tabela].count}`, stev.rows[0]);
  }

  console.log("\n# (b) sold_count dogodka enak izvornemu (sprozilec ni tekel dvakrat)");
  const obnovljenDogodek = await obnovljeniPool.query("SELECT capacity, sold_count FROM events WHERE id=$1", [dogodekId]);
  assert(obnovljenDogodek.rows[0].sold_count === izvornoStanjeDogodka.rows[0].sold_count, "sold_count v obnovljeni bazi = izvorni sold_count", { obnovljen: obnovljenDogodek.rows[0], izvorni: izvornoStanjeDogodka.rows[0] });

  console.log("\n# (c) vsota total_cents narocil enaka izvorni");
  const obnovljenaVsota = await obnovljeniPool.query("SELECT COALESCE(SUM(total_cents),0)::int AS vsota FROM orders");
  assert(obnovljenaVsota.rows[0].vsota === izvornaVsotaNarocil.rows[0].vsota, "vsota total_cents v obnovljeni bazi = izvorna vsota", { obnovljena: obnovljenaVsota.rows[0], izvorna: izvornaVsotaNarocil.rows[0] });

  console.log("\n# JSONB in text[] po obnovi (bar_prices, gallery_urls)");
  const izvorniKlub = await pool.query("SELECT bar_prices, gallery_urls FROM clubs WHERE name = 'Obnova Club'");
  const obnovljenKlub = await obnovljeniPool.query("SELECT bar_prices, gallery_urls FROM clubs WHERE name = 'Obnova Club'");
  assert(JSON.stringify(obnovljenKlub.rows[0].bar_prices) === JSON.stringify(izvorniKlub.rows[0].bar_prices), "bar_prices (jsonb) po obnovi enak izvornemu", { obnovljen: obnovljenKlub.rows[0].bar_prices, izvorni: izvorniKlub.rows[0].bar_prices });
  assert(JSON.stringify(obnovljenKlub.rows[0].gallery_urls) === JSON.stringify(izvorniKlub.rows[0].gallery_urls), "gallery_urls (text[]) po obnovi enak izvornemu", { obnovljen: obnovljenKlub.rows[0].gallery_urls, izvorni: izvorniKlub.rows[0].gallery_urls });

  console.log("\n# (d) zaporedja delujejo: nov uporabnik brez trka s primarnim kljucem");
  let napakaVstavitve = null;
  let novId = null;
  try {
    const vstavljen = await obnovljeniPool.query(
      "INSERT INTO users (email, username, role, email_verified) VALUES ($1,$2,'user',true) RETURNING id",
      ["nov.po.obnovi@outly.si", "nov_po_obnovi"]
    );
    novId = vstavljen.rows[0].id;
  } catch (e) { napakaVstavitve = e; }
  assert(napakaVstavitve === null, "vstavitev novega uporabnika po obnovi ne trci s primarnim kljucem", napakaVstavitve && napakaVstavitve.message);
  assert(typeof novId === "number" || typeof novId === "string", "nov uporabnik je dobil id iz zaporedja", novId);

  console.log("\n# (e) sprozilci so spet vklopljeni: narocilo cez zmogljivost dogodka pade");
  let napakaCezZmogljivost = null;
  try {
    await obnovljeniPool.query(
      `INSERT INTO orders (public_ref, event_id, club_id, quantity, unit_price_cents, total_cents, buyer_email)
       VALUES ('PONOVITEV-TEST-OBNOVA', $1, $2, 1, 1000, 1000, 'preveri@outly.si')`,
      [dogodekId, klubId]
    );
  } catch (e) { napakaCezZmogljivost = e; }
  assert(napakaCezZmogljivost !== null && napakaCezZmogljivost.code === "23514", "narocilo cez zmogljivost po obnovi -> check_violation (23514)", napakaCezZmogljivost && { code: napakaCezZmogljivost.code, message: napakaCezZmogljivost.message });

  console.log("\n# (f) obnova v bazo, ki ze ima podatke, je zavrnjena");
  let izidPonovneObnove = poganjajNode(["db/obnovi_izvoz.js", potIzvoza], { DATABASE_URL: obnovaUrl.toString() });
  assert(izidPonovneObnove.koda !== 0, "obnova v neprazno bazo -> izhodna koda != 0", izidPonovneObnove.stdout + izidPonovneObnove.stderr);
  assert(/ni prazen/i.test(izidPonovneObnove.stderr), "sporocilo omeni, da cilj ni prazen", izidPonovneObnove.stderr);

  console.log("\n# (g) obnova brez localhost v URL-ju brez zastavice je zavrnjena PRED povezavo");
  const zacetek = Date.now();
  let izidTujegaGostitelja = poganjajNode(["db/obnovi_izvoz.js", potIzvoza], { DATABASE_URL: "postgres://x@primer.invalid/x" }, 5000);
  const trajanjeMs = Date.now() - zacetek;
  assert(izidTujegaGostitelja.koda !== 0, "obnova brez localhost brez zastavice -> izhodna koda != 0", izidTujegaGostitelja.stdout + izidTujegaGostitelja.stderr);
  assert(trajanjeMs < 3000, `zavrnitev je bila hitra (${trajanjeMs} ms) — brez poskusa povezave`, trajanjeMs);
  assert(/localhost/i.test(izidTujegaGostitelja.stderr), "sporocilo omeni localhost/zastavico", izidTujegaGostitelja.stderr);
}

(async () => {
  await pool.query("TRUNCATE ticket_transfers, club_invites, club_members, event_favorites, tickets, orders, events, clubs, creator_applications, users RESTART IDENTITY CASCADE");
  await new Promise(r => jwksServer.listen(JWKS_PORT, r));
  srv = spawn("node", ["index.js"], { env: { ...process.env, PORT: String(PORT), SUPABASE_URL: `http://127.0.0.1:${JWKS_PORT}`, RESEND_API_KEY: "", QR_SECRET: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  srv.stdout.on("data", d => log += d); srv.stderr.on("data", d => log += d);
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + "/"); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

  try {
    await telo();
  } finally {
    console.log(`\nSkupaj: ${ok} OK, ${fail} napak`);
    const napake = log.split("\n").filter(l => /error|TypeError|Unhandled/i.test(l) && !/Server error\./.test(l) && !/Resend/i.test(l));
    if (napake.length) console.log("\nLog backenda (sumljivo):\n" + napake.join("\n"));

    if (srv) srv.kill();
    jwksServer.close();
    await pool.end().catch(() => {});
    if (obnovljeniPool) await obnovljeniPool.end().catch(() => {});
    if (potIzvoza) { try { fs.unlinkSync(potIzvoza); } catch (_) {} }
    try { await pobrisiObnovoBazo(); } catch (_) {}
  }
  process.exit(fail ? 1 : 0);
})().catch(async e => {
  console.error(e);
  if (srv) srv.kill();
  try { jwksServer.close(); } catch (_) {}
  try { await pool.end(); } catch (_) {}
  if (obnovljeniPool) { try { await obnovljeniPool.end(); } catch (_) {} }
  try { await pobrisiObnovoBazo(); } catch (_) {}
  process.exit(1);
});
