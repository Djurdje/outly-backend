#!/usr/bin/env node
/**
 * Test: migracija, ki ne dobi zaklepa, PADE (lock_timeout), namesto da ustavi vsa branja in skene tabele (issue #115).
 *
 * Scenarij iz produkcije: dolgo branje tabele tickets (npr. izvoz za varnostno kopijo) drzi ACCESS SHARE. Migracija z
 * ALTER TABLE tickets caka na ACCESS EXCLUSIVE, za njo pa se v vrsto postavijo VSA nova branja (tudi sken na vratih).
 * Pricakovano: migrate.js po lock_timeout (privzeto 5 s) odneha (po MIGRACIJA_PONOVITVE ponovnih poskusih), izide s
 * kodo 1, v schema_migrations ni vnosa, branja tabele med cakanjem niso blokirana dlje od meje, po sprostitvi zaklepa
 * ponovni zagon uspe. Isto za statement_timeout, advisory lock in neveljaven env; MIGRACIJE_MAPA je v produkciji zavrnjena.
 *
 * Zagon (lokalno, PG16; ustvari lastno bazo outly_zaklep_<pid>, ostalih ne dotakne):
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
const IME_BAZE = `outly_zaklep_${process.pid}`; // unikatno: vzporedni zagoni (drugi agenti, CI) si baze ne delijo
const KLJUCAVNICA = 8274100; // enako kot v db/migrate.js
const vzdrzevalnaUrl = new URL(DB); vzdrzevalnaUrl.pathname = "/postgres";
const ciljnaUrl = new URL(DB); ciljnaUrl.pathname = "/" + IME_BAZE;
const ssl = DB.includes("localhost") ? false : { rejectUnauthorized: false };

let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }
const spi = (ms) => new Promise((r) => setTimeout(r, ms));

// Zagon migrate.js kot otrok; ob preseganju roka ga ubijemo (stara koda bi visela v nedogled), pid je samo nas.
// NODE_ENV=test: MIGRACIJE_MAPA je dovoljena samo zunaj produkcije. PONOVITVE=0, razen kjer test preskusa ponovne poskuse.
function zaganjajMigracijo(env, rokMs, argumenti = []) {
  const t0 = Date.now();
  const otrok = spawn(process.execPath, ["db/migrate.js", ...argumenti], {
    cwd: KOREN, env: { ...process.env, NODE_ENV: "test", MIGRACIJA_PONOVITVE: "0", DATABASE_URL: ciljnaUrl.toString(), ...env }, stdio: ["ignore", "pipe", "pipe"],
  });
  let izpis = "";
  otrok.stdout.on("data", (d) => izpis += d); otrok.stderr.on("data", (d) => izpis += d);
  return new Promise((resolve) => {
    let ubit = false;
    const rok = setTimeout(() => { ubit = true; otrok.kill("SIGKILL"); }, rokMs);
    otrok.on("exit", (koda) => { clearTimeout(rok); resolve({ koda, ubit, izpis, trajanjeMs: Date.now() - t0 }); });
  });
}

async function odjemalec(url) {
  const c = new Client({ connectionString: url.toString(), ssl });
  c.on("error", () => {});
  await c.connect();
  return c;
}

// Pocaka, da pogoj postane resnicen (poll); vrne true/false.
async function pocakaj(fn, rokMs) {
  const t0 = Date.now();
  while (Date.now() - t0 < rokMs) { if (await fn()) return true; await spi(50); }
  return false;
}

(async () => {
  const mapa = fs.mkdtempSync(path.join(os.tmpdir(), "outly-zaklep-"));
  const vzd = await odjemalec(vzdrzevalnaUrl);
  let drzalec = null, bralec = null, ctrl = null;
  try {
    console.log(`\n# Priprava: sveza baza ${IME_BAZE} + vse prave migracije`);
    await vzd.query(`CREATE DATABASE ${IME_BAZE}`);
    const polna = spawnSync(process.execPath, ["db/migrate.js"], { cwd: KOREN, env: { ...process.env, DATABASE_URL: ciljnaUrl.toString() }, encoding: "utf8", timeout: 120000 });
    assert(polna.status === 0, "npm run migrate na prazni bazi -> 0", (polna.stdout + polna.stderr).slice(-400));
    assert(/lock_timeout 5s, statement_timeout 120s \(na stavek\), ponovitve 2 po 10s, čakanje na advisory lock 60s/.test(polna.stdout),
      "privzete meje: lock 5s, statement 120s, 2 ponovitvi po 10s, advisory lock 60s", polna.stdout.slice(0, 200));

    ctrl = await odjemalec(ciljnaUrl);
    const vnos = async (datoteka) => (await ctrl.query("SELECT 1 FROM schema_migrations WHERE datoteka=$1", [datoteka])).rowCount;
    const stolpec = async (ime) => (await ctrl.query("SELECT 1 FROM information_schema.columns WHERE table_name='tickets' AND column_name=$1", [ime])).rowCount;
    const zadrzi = async () => { await drzalec.query("BEGIN"); await drzalec.query("LOCK TABLE tickets IN ACCESS SHARE MODE"); };
    const sprosti = async () => { await drzalec.query("ROLLBACK"); };
    const piši = (ime, sql) => fs.writeFileSync(path.join(mapa, ime), sql);
    const env = { MIGRACIJE_MAPA: mapa };
    drzalec = await odjemalec(ciljnaUrl);

    console.log("\n# 1. Dolgo branje drzi zaklep na tickets, migracija ALTER TABLE tickets caka (lock_timeout 2 s)");
    // Brez BEGIN/COMMIT (oblika VSE_MIGRACIJE) – migrate.js ju tako ali tako odstrani.
    piši("900_test_zaklep.sql", "ALTER TABLE tickets ADD COLUMN zaklep_test_a INT;\nALTER TABLE tickets ADD COLUMN zaklep_test_b INT;\n");
    await zadrzi();
    bralec = await odjemalec(ciljnaUrl);
    await bralec.query("SET statement_timeout = 10000"); // varovalo testa: na stari kodi bi branje viselo, dokler drzalec ne spusti
    const bralecPid = (await bralec.query("SELECT pg_backend_pid() AS p")).rows[0].p;

    const migracija = zaganjajMigracijo({ ...env, MIGRACIJA_LOCK_TIMEOUT: "2s" }, 25000);
    // Dokaz 1: migracija res caka na zaklep (seja z njenim ALTER-jem je v wait_event_type = Lock).
    let migPid = null;
    const migCaka = await pocakaj(async () => {
      const r = await ctrl.query(
        "SELECT pid FROM pg_stat_activity WHERE datname=$1 AND pid <> pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%zaklep_test_a%'", [IME_BAZE]);
      if (r.rowCount) migPid = r.rows[0].pid;
      return r.rowCount > 0;
    }, 10000);
    assert(migCaka, "migracija ALTER TABLE tickets res caka na zaklep (pg_stat_activity: Lock)");
    // Dokaz 2: novo branje tickets se postavi ZA migracijo in je blokirano (to je tezava iz #115).
    const t0 = Date.now();
    let beriNapaka = null;
    const branje = bralec.query("SELECT count(*) FROM tickets").catch((e) => { beriNapaka = e; });
    const bralecCaka = await pocakaj(async () => (await ctrl.query(
      "SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock'", [bralecPid])).rowCount > 0, 5000);
    assert(bralecCaka, "novo branje tickets res caka (v vrsti za cakajoco migracijo)");
    const blokira = (await ctrl.query("SELECT $1::int = ANY(pg_blocking_pids($2)) AS b", [migPid, bralecPid])).rows[0].b;
    assert(blokira, "branje blokira cakajoca migracija (pg_blocking_pids)");
    await branje;
    const beriMs = Date.now() - t0;
    const izid = await migracija;
    assert(!izid.ubit, "migracija sama izide (ni obvisela, ubita po 25 s)", { trajanjeMs: izid.trajanjeMs, izpis: izid.izpis.slice(-300) });
    assert(izid.koda === 1, "migracija izide s kodo 1", izid.koda);
    assert(izid.trajanjeMs < 7000, `migracija odneha v ~lock_timeout (${izid.trajanjeMs} ms < 7000)`, izid.trajanjeMs);
    assert(beriNapaka === null && beriMs < 3500, `blokirano branje se sprosti, ko migracija odneha (${beriMs} ms, meja lock_timeout 2 s)`, { beriMs, beriNapaka: beriNapaka && beriNapaka.message });
    assert(/lock timeout/i.test(izid.izpis) && /ni dobila zaklepa/.test(izid.izpis), "izpis pove, da je zaklep razlog", izid.izpis.slice(-400));
    assert(/ob\s+naslednjem deployu/.test(izid.izpis) && /NI živa/.test(izid.izpis), "izpis pove, da je stara razlicica ostala in da se poskusi znova ob naslednjem deployu", izid.izpis.slice(-400));
    assert((await vnos("900_test_zaklep.sql")) === 0, "v schema_migrations ni vnosa");
    assert((await stolpec("zaklep_test_a")) === 0 && (await stolpec("zaklep_test_b")) === 0, "nobena sprememba sheme ni ostala");

    console.log("\n# 2. Po sprostitvi zaklepa ponovni zagon uspe");
    await sprosti();
    const znova = await zaganjajMigracijo(env, 30000);
    assert(znova.koda === 0, "ponovni zagon -> 0", znova.izpis.slice(-300));
    assert((await vnos("900_test_zaklep.sql")) === 1, "vnos v schema_migrations je zdaj zapisan");
    assert((await stolpec("zaklep_test_a")) === 1 && (await stolpec("zaklep_test_b")) === 1, "oba ALTER-ja sta uveljavljena");

    console.log("\n# 3. Privzeti lock_timeout (brez env) je ~5 s; delna migracija se vrne nazaj (datoteka z BEGIN/COMMIT)");
    piši("901_test_zaklep_privzeto.sql", "BEGIN;\nALTER TABLE tickets ADD COLUMN zaklep_test_c INT;\nALTER TABLE tickets ADD COLUMN zaklep_test_d INT;\nCOMMIT;\n");
    await zadrzi();
    const privzeta = await zaganjajMigracijo(env, 25000);
    assert(!privzeta.ubit && privzeta.koda === 1, "brez env migracija pade s kodo 1", { koda: privzeta.koda, ubit: privzeta.ubit });
    assert(privzeta.trajanjeMs >= 4500 && privzeta.trajanjeMs < 9000, `privzeti lock_timeout je ~5 s (${privzeta.trajanjeMs} ms)`, privzeta.trajanjeMs);
    assert((await vnos("901_test_zaklep_privzeto.sql")) === 0 && (await stolpec("zaklep_test_c")) === 0, "ni vnosa in ni delnega ucinka");
    await sprosti();
    const znova2 = await zaganjajMigracijo(env, 30000);
    assert(znova2.koda === 0 && (await vnos("901_test_zaklep_privzeto.sql")) === 1, "po sprostitvi uspe", znova2.izpis.slice(-300));

    console.log("\n# 4. Kratek izvoz ne podre deploya: ponovni poskusi po premoru");
    piši("902_test_ponovitve.sql", "ALTER TABLE tickets ADD COLUMN zaklep_test_e INT;\n");
    await zadrzi();
    setTimeout(() => { sprosti().catch(() => {}); }, 1800); // zaklep se sprosti po ~1,8 s, drugi poskus (po 1 s + 1,5 s premora) uspe
    const ponov = await zaganjajMigracijo({ ...env, MIGRACIJA_LOCK_TIMEOUT: "1s", MIGRACIJA_PONOVITVE: "2", MIGRACIJA_PREMOR: "1500ms" }, 30000);
    assert(ponov.koda === 0, "migracija uspe v ponovnem poskusu (koda 0)", ponov.izpis.slice(-400));
    assert(/poskus 1\/3/.test(ponov.izpis) && /poskus 2\)/.test(ponov.izpis), "izpis: prvi poskus zaseden, uspeh v poskusu 2", ponov.izpis.slice(-400));
    assert((await vnos("902_test_ponovitve.sql")) === 1 && (await stolpec("zaklep_test_e")) === 1, "migracija uveljavljena");

    piši("903_test_trajen_zaklep.sql", "ALTER TABLE tickets ADD COLUMN zaklep_test_f INT;\n");
    await zadrzi();
    const trajen = await zaganjajMigracijo({ ...env, MIGRACIJA_LOCK_TIMEOUT: "1s", MIGRACIJA_PONOVITVE: "1", MIGRACIJA_PREMOR: "300ms" }, 30000);
    assert(!trajen.ubit && trajen.koda === 1, "ce zaklep ostane, po vseh poskusih koda 1", { koda: trajen.koda, ubit: trajen.ubit });
    assert(trajen.trajanjeMs >= 2200 && trajen.trajanjeMs < 8000, `poskusa sta dva (1 s + 0,3 s premor + 1 s; ${trajen.trajanjeMs} ms)`, trajen.trajanjeMs);
    assert(/v 2 poskusih/.test(trajen.izpis), "izpis pove stevilo poskusov", trajen.izpis.slice(-300));
    assert((await vnos("903_test_trajen_zaklep.sql")) === 0 && (await stolpec("zaklep_test_f")) === 0, "ni vnosa in ni delnega ucinka");
    await sprosti();
    fs.rmSync(path.join(mapa, "903_test_trajen_zaklep.sql")); // neuspela migracija ostane "cakajoca" in bi motila naslednje zagone

    console.log("\n# 5. statement_timeout prekine predolg stavek; ze opravljeni ALTER se vrne nazaj");
    piši("904_test_pocasna.sql", "ALTER TABLE tickets ADD COLUMN zaklep_test_g INT;\nSELECT pg_sleep(8);\n");
    const pocasna = await zaganjajMigracijo({ ...env, MIGRACIJA_STATEMENT_TIMEOUT: "1s" }, 20000);
    assert(!pocasna.ubit && pocasna.koda === 1, "pocasna migracija pade s kodo 1", { koda: pocasna.koda, ubit: pocasna.ubit });
    assert(pocasna.trajanjeMs < 6000, `prekinjena po ~statement_timeout (${pocasna.trajanjeMs} ms)`, pocasna.trajanjeMs);
    assert(/statement timeout/i.test(pocasna.izpis) && /tekla predolgo/.test(pocasna.izpis), "izpis pove, da je razlog cas izvajanja", pocasna.izpis.slice(-300));
    assert((await vnos("904_test_pocasna.sql")) === 0 && (await stolpec("zaklep_test_g")) === 0, "ni vnosa in ni delnega ucinka");
    fs.rmSync(path.join(mapa, "904_test_pocasna.sql"));
    // statement_timeout je na stavek, ne na datoteko: trije stavki po 0,7 s skupaj presezejo 1 s, a noben sam.
    piši("905_test_stavki.sql", "SELECT pg_sleep(0.7);\nSELECT pg_sleep(0.7);\nSELECT pg_sleep(0.7);\n");
    const stavki = await zaganjajMigracijo({ ...env, MIGRACIJA_STATEMENT_TIMEOUT: "1s" }, 20000);
    assert(stavki.koda === 0 && (await vnos("905_test_stavki.sql")) === 1, "statement_timeout velja na stavek, ne na datoteko", stavki.izpis.slice(-300));

    console.log("\n# 6. Viseca seja drzi advisory lock: migrate.js ne caka za vedno");
    piši("906_test_advisory.sql", "ALTER TABLE tickets ADD COLUMN zaklep_test_h INT;\n");
    await drzalec.query("SELECT pg_advisory_lock($1)", [KLJUCAVNICA]);
    const adv = await zaganjajMigracijo({ ...env, MIGRACIJA_KLJUCAVNICA_TIMEOUT: "1s" }, 20000);
    assert(!adv.ubit && adv.koda === 1, "migrate.js pade s kodo 1, ne visi", { koda: adv.koda, ubit: adv.ubit });
    assert(adv.trajanjeMs < 6000 && /Migracijskega zaklepa ni bilo mogoče dobiti/.test(adv.izpis), `jasno sporocilo po ~1 s (${adv.trajanjeMs} ms)`, adv.izpis.slice(-300));
    assert((await vnos("906_test_advisory.sql")) === 0, "ni vnosa");
    await drzalec.query("SELECT pg_advisory_unlock($1)", [KLJUCAVNICA]);
    const poAdv = await zaganjajMigracijo({ ...env, MIGRACIJA_KLJUCAVNICA_TIMEOUT: "1s" }, 20000);
    assert(poAdv.koda === 0 && (await vnos("906_test_advisory.sql")) === 1, "po sprostitvi advisory locka uspe", poAdv.izpis.slice(-300));

    console.log("\n# 7. Neveljaven env in MIGRACIJE_MAPA v produkciji");
    for (const [ime, v] of [["MIGRACIJA_LOCK_TIMEOUT", "hitro"], ["MIGRACIJA_STATEMENT_TIMEOUT", "-5"], ["MIGRACIJA_PONOVITVE", "x"], ["MIGRACIJA_PREMOR", "1h"]]) {
      const r = await zaganjajMigracijo({ ...env, [ime]: v }, 20000);
      assert(r.koda === 1 && r.izpis.includes(ime), `${ime}=${v} -> koda 1 z jasnim sporocilom`, r.izpis.slice(-200));
    }
    piši("907_test_env.sql", "ALTER TABLE tickets ADD COLUMN zaklep_test_i INT;\n");
    for (const [ime, v] of [["NODE_ENV", "production"], ["RENDER", "true"]]) {
      const r = await zaganjajMigracijo({ ...env, [ime]: v }, 20000);
      assert(r.koda === 1 && /MIGRACIJE_MAPA je dovoljena samo v testih/.test(r.izpis), `MIGRACIJE_MAPA z ${ime}=${v} -> zavrnjena (koda 1)`, r.izpis.slice(-200));
    }
    assert((await vnos("907_test_env.sql")) === 0 && (await stolpec("zaklep_test_i")) === 0, "nic od tega se ni dotaknilo baze");
  } finally {
    for (const c of [drzalec, bralec, ctrl]) if (c) await c.end().catch(() => {});
    await vzd.query(`DROP DATABASE IF EXISTS ${IME_BAZE} WITH (FORCE)`).catch(() => {});
    await vzd.end().catch(() => {});
    fs.rmSync(mapa, { recursive: true, force: true });
  }

  console.log(`\n${ok} ok, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error("Nepricakovana napaka testa:", e); process.exit(1); });
