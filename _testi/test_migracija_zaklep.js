#!/usr/bin/env node
/**
 * Test: migracija, ki ne dobi zaklepa, PADE (lock_timeout), namesto da ustavi vsa branja in skene tabele (issue #115).
 *
 * Scenarij iz produkcije: dolgo branje tabele tickets (npr. izvoz za varnostno kopijo) drzi ACCESS SHARE. Migracija z
 * ALTER TABLE tickets caka na ACCESS EXCLUSIVE, za njo pa se v vrsto postavijo VSA nova branja (tudi sken na vratih).
 * Pricakovano: migrate.js po lock_timeout (privzeto 5 s) odneha, izide s kodo 1, v schema_migrations ni vnosa,
 * branja tabele med cakanjem niso blokirana dlje od meje, po sprostitvi zaklepa ponovni zagon uspe.
 * Isto za statement_timeout in za neveljavno vrednost env.
 *
 * Zagon (lokalno, PG16; ustvari lastno bazo outly_zaklep, ostalih ne dotakne):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_migracija_zaklep.js
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn, spawnSync } = require("child_process");
const { Client } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const KOREN = path.join(__dirname, "..");
const IME_BAZE = "outly_zaklep";
const vzdrzevalnaUrl = new URL(DB); vzdrzevalnaUrl.pathname = "/postgres";
const ciljnaUrl = new URL(DB); ciljnaUrl.pathname = "/" + IME_BAZE;
const ssl = DB.includes("localhost") ? false : { rejectUnauthorized: false };

let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
const spi = (ms) => new Promise((r) => setTimeout(r, ms));

// Zagon migrate.js kot otrok; ob preseganju roka ga ubijemo (stara koda bi visela v nedogled), pid je samo nas.
function zaganjajMigracijo(env, rokMs) {
  const t0 = Date.now();
  const otrok = spawn(process.execPath, ["db/migrate.js"], {
    cwd: KOREN, env: { ...process.env, DATABASE_URL: ciljnaUrl.toString(), ...env }, stdio: ["ignore", "pipe", "pipe"],
  });
  let izpis = "";
  otrok.stdout.on("data", (d) => izpis += d); otrok.stderr.on("data", (d) => izpis += d);
  const izid = new Promise((resolve) => {
    let ubit = false;
    const rok = setTimeout(() => { ubit = true; otrok.kill("SIGKILL"); }, rokMs);
    otrok.on("exit", (koda) => { clearTimeout(rok); resolve({ koda, ubit, izpis, trajanjeMs: Date.now() - t0 }); });
  });
  return izid;
}

async function odjemalec(url) {
  const c = new Client({ connectionString: url.toString(), ssl });
  c.on("error", () => {});
  await c.connect();
  return c;
}

(async () => {
  const mapa = fs.mkdtempSync(path.join(os.tmpdir(), "outly-zaklep-"));
  const vzd = await odjemalec(vzdrzevalnaUrl);
  let drzalec = null, bralec = null, ctrl = null;
  try {
    console.log("\n# Priprava: sveza baza outly_zaklep + vse prave migracije");
    await vzd.query(`DROP DATABASE IF EXISTS ${IME_BAZE} WITH (FORCE)`);
    await vzd.query(`CREATE DATABASE ${IME_BAZE}`);
    const polna = spawnSync(process.execPath, ["db/migrate.js"], { cwd: KOREN, env: { ...process.env, DATABASE_URL: ciljnaUrl.toString() }, encoding: "utf8", timeout: 120000 });
    assert(polna.status === 0, "npm run migrate na prazni bazi -> 0", (polna.stdout + polna.stderr).slice(-400));

    ctrl = await odjemalec(ciljnaUrl);
    const vnos = async (datoteka) => (await ctrl.query("SELECT 1 FROM schema_migrations WHERE datoteka=$1", [datoteka])).rowCount;
    const stolpec = async (ime) => (await ctrl.query("SELECT 1 FROM information_schema.columns WHERE table_name='tickets' AND column_name=$1", [ime])).rowCount;

    // Testna migracija v zacasni mapi (900_ je nad pravimi). Brez BEGIN/COMMIT (oblika VSE_MIGRACIJE) – migrate.js ju tako ali tako odstrani.
    fs.writeFileSync(path.join(mapa, "900_test_zaklep.sql"), "ALTER TABLE tickets ADD COLUMN zaklep_test_a INT;\nALTER TABLE tickets ADD COLUMN zaklep_test_b INT;\n");
    const env = { MIGRACIJE_MAPA: mapa };

    console.log("\n# 1. Dolgo branje drzi zaklep na tickets, migracija ALTER TABLE tickets caka (lock_timeout 1 s)");
    drzalec = await odjemalec(ciljnaUrl);
    await drzalec.query("BEGIN");
    await drzalec.query("LOCK TABLE tickets IN ACCESS SHARE MODE");

    const migracija = zaganjajMigracijo({ ...env, MIGRACIJA_LOCK_TIMEOUT: "1s" }, 20000);
    // Med cakanjem migracije novo branje tickets obvisi za njo (ACCESS SHARE caka za cakajocim ACCESS EXCLUSIVE) – to je tezava.
    await spi(500);
    bralec = await odjemalec(ciljnaUrl);
    await bralec.query("SET statement_timeout = 8000"); // varovalo testa: na stari kodi bi branje viselo, dokler drzalec ne spusti
    const t0 = Date.now();
    let beriNapaka = null;
    await bralec.query("SELECT count(*) FROM tickets").catch((e) => { beriNapaka = e; });
    const beriMs = Date.now() - t0;
    // Na stari kodi migracija visi, dokler je ne ubijemo; zaklep spustimo sele po koncu branja in migracije.
    const izid = await migracija;
    assert(!izid.ubit, "migracija sama izide (ni obvisela, ubita po 20 s)", { trajanjeMs: izid.trajanjeMs, izpis: izid.izpis.slice(-300) });
    assert(izid.koda === 1, "migracija izide s kodo 1", izid.koda);
    assert(izid.trajanjeMs < 6000, `migracija odneha v ~lock_timeout (${izid.trajanjeMs} ms < 6000)`, izid.trajanjeMs);
    assert(beriNapaka === null && beriMs < 3000, `branje tickets med cakanjem migracije ni blokirano dlje kot lock_timeout (${beriMs} ms)`, { beriMs, beriNapaka: beriNapaka && beriNapaka.message });
    assert(/lock timeout/i.test(izid.izpis) && /ni dobila zaklepa/.test(izid.izpis), "izpis pove, da je zaklep razlog", izid.izpis.slice(-400));
    assert(/ob naslednjem deployu/.test(izid.izpis), "izpis pove, da se poskusi znova ob naslednjem deployu", izid.izpis.slice(-400));
    assert((await vnos("900_test_zaklep.sql")) === 0, "v schema_migrations ni vnosa");
    assert((await stolpec("zaklep_test_a")) === 0 && (await stolpec("zaklep_test_b")) === 0, "nobena sprememba sheme ni ostala");

    console.log("\n# 2. Po sprostitvi zaklepa ponovni zagon uspe");
    await drzalec.query("ROLLBACK");
    const znova = await zaganjajMigracijo(env, 30000);
    assert(znova.koda === 0, "ponovni zagon -> 0", znova.izpis.slice(-300));
    assert((await vnos("900_test_zaklep.sql")) === 1, "vnos v schema_migrations je zdaj zapisan");
    assert((await stolpec("zaklep_test_a")) === 1 && (await stolpec("zaklep_test_b")) === 1, "oba ALTER-ja sta uveljavljena");

    console.log("\n# 3. Privzeta meja lock_timeout (brez env) je ~5 s, delna migracija se vrne nazaj");
    fs.writeFileSync(path.join(mapa, "901_test_zaklep_privzeto.sql"),
      "BEGIN;\nALTER TABLE tickets ADD COLUMN zaklep_test_c INT;\nALTER TABLE tickets ADD COLUMN zaklep_test_d INT;\nCOMMIT;\n");
    await drzalec.query("BEGIN");
    await drzalec.query("LOCK TABLE tickets IN ACCESS SHARE MODE");
    const privzeta = await zaganjajMigracijo(env, 20000);
    assert(!privzeta.ubit && privzeta.koda === 1, "brez env migracija pade s kodo 1", { koda: privzeta.koda, ubit: privzeta.ubit });
    assert(privzeta.trajanjeMs >= 4500 && privzeta.trajanjeMs < 9000, `privzeti lock_timeout je ~5 s (${privzeta.trajanjeMs} ms)`, privzeta.trajanjeMs);
    assert((await vnos("901_test_zaklep_privzeto.sql")) === 0 && (await stolpec("zaklep_test_c")) === 0, "ni vnosa in ni delnega ucinka");
    await drzalec.query("ROLLBACK");
    const znova2 = await zaganjajMigracijo(env, 30000);
    assert(znova2.koda === 0 && (await vnos("901_test_zaklep_privzeto.sql")) === 1, "po sprostitvi uspe (z BEGIN/COMMIT v datoteki)", znova2.izpis.slice(-300));

    console.log("\n# 4. statement_timeout prekine predolgo migracijo; ze opravljeni ALTER se vrne nazaj");
    fs.writeFileSync(path.join(mapa, "902_test_pocasna.sql"), "ALTER TABLE tickets ADD COLUMN zaklep_test_e INT;\nSELECT pg_sleep(8);\n");
    const pocasna = await zaganjajMigracijo({ ...env, MIGRACIJA_STATEMENT_TIMEOUT: "1s" }, 20000);
    assert(!pocasna.ubit && pocasna.koda === 1, "pocasna migracija pade s kodo 1", { koda: pocasna.koda, ubit: pocasna.ubit });
    assert(pocasna.trajanjeMs < 6000, `prekinjena po ~statement_timeout (${pocasna.trajanjeMs} ms)`, pocasna.trajanjeMs);
    assert(/statement timeout/i.test(pocasna.izpis) && /tekla predolgo/.test(pocasna.izpis), "izpis pove, da je razlog cas izvajanja", pocasna.izpis.slice(-300));
    assert((await vnos("902_test_pocasna.sql")) === 0 && (await stolpec("zaklep_test_e")) === 0, "ni vnosa in ni delnega ucinka");

    console.log("\n# 5. Neveljavna vrednost env zavrne zagon se pred dotikom baze");
    for (const [ime, v] of [["MIGRACIJA_LOCK_TIMEOUT", "hitro"], ["MIGRACIJA_STATEMENT_TIMEOUT", "-5"]]) {
      const r = await zaganjajMigracijo({ ...env, [ime]: v }, 20000);
      assert(r.koda === 1 && r.izpis.includes(ime), `${ime}=${v} -> koda 1 z jasnim sporocilom`, r.izpis.slice(-200));
    }
    assert((await vnos("902_test_pocasna.sql")) === 0, "neveljavna vrednost ni nic zapisala");
  } finally {
    for (const c of [drzalec, bralec, ctrl]) if (c) await c.end().catch(() => {});
    await vzd.query(`DROP DATABASE IF EXISTS ${IME_BAZE} WITH (FORCE)`).catch(() => {});
    await vzd.end().catch(() => {});
    fs.rmSync(mapa, { recursive: true, force: true });
  }

  console.log(`\n${ok} ok, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error("Nepricakovana napaka testa:", e); process.exit(1); });
