#!/usr/bin/env node
/**
 * Zaganjalnik migracij za Outly.
 *
 * Zakaj obstaja: migracije je treba nekako spraviti na živo bazo. Kopiranje
 * povezovalnega niza z gesli naokoli je nepotrebno tveganje — ta skripta teče
 * TAM, kjer DATABASE_URL že je (na Renderju), zato geslo nikoli ne zapusti
 * okolja.
 *
 * Kaj počne:
 *   – prebere db/migracije/NNN_*.sql po vrstnem redu imen,
 *   – vodi evidenco v tabeli schema_migrations,
 *   – vsako neuporabljeno migracijo požene v svoji transakciji,
 *   – zavrne zagon, če je bila že uporabljena datoteka pozneje spremenjena,
 *   – uporabi ključavnico, da si dve instanci ne skačeta v besedo,
 *   – vsaki migraciji nastavi lock_timeout in statement_timeout (glej spodaj).
 *
 * Časovne meje (issue #115): ALTER TABLE rabi ACCESS EXCLUSIVE zaklep. Če tabelo takrat bere dolga transakcija (izvoz,
 * poročilo), migracija čaka, za njo pa se v vrsto postavijo VSA nova branja in pisanja te tabele — tudi sken vstopnic
 * na vratih. Zato migracija ne sme čakati:
 *   – MIGRACIJA_LOCK_TIMEOUT (privzeto 5s): kako dolgo sme ena migracija čakati na zaklep tabele. Ob preteku se vrne nazaj
 *     in se poskusi še MIGRACIJA_PONOVITVE-krat (privzeto 2) z MIGRACIJA_PREMOR (privzeto 10s) premora, da kratek izvoz ne
 *     podre deploya. Če zaklepa ni tudi po tem, migrate.js izide s kodo 1: deploy pade, Render obdrži staro različico,
 *     migracija se poskusi znova ob naslednjem deployu (v schema_migrations se zapiše šele ob uspehu).
 *   – MIGRACIJA_STATEMENT_TIMEOUT (privzeto 120s): najdaljši čas ENEGA stavka migracije (statement_timeout velja na stavek,
 *     ne na datoteko), da počasen stavek ne drži zaklepa dolgo, ko ga enkrat dobi.
 *   – MIGRACIJA_KLJUCAVNICA_TIMEOUT (privzeto 60s): koliko čaka na advisory lock drugega migrate.js; viseča prejšnja seja
 *     tako ne zatakne deploya za vedno.
 * Vrednost časa: število milisekund ali število s priponko ms|s|min (npr. 5s, 2min); 0 = brez meje.
 *
 * Zagon:
 *   node db/migrate.js            – uporabi vse neuporabljene
 *   node db/migrate.js --stanje   – samo pokaže stanje, ničesar ne spremeni
 *   node db/migrate.js --do 003   – uporabi do vključno 003 in se ustavi
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");

// MIGRACIJE_MAPA: samo za teste (_testi/test_migracija_zaklep.js), da lahko preskusijo migracijo v zacasni mapi.
// V produkciji (RENDER ali NODE_ENV=production) je zavrnjena: napacna ali prazna mapa bi pomenila zagon brez migracij z izhodom 0.
if (process.env.MIGRACIJE_MAPA && (process.env.RENDER || process.env.NODE_ENV === "production")) {
  console.error("✖ MIGRACIJE_MAPA je dovoljena samo v testih (nastavljen je RENDER ali NODE_ENV=production). Odstrani jo iz okolja.");
  process.exit(1);
}
const MAPA = process.env.MIGRACIJE_MAPA ? path.resolve(process.env.MIGRACIJE_MAPA) : path.join(__dirname, "migracije");
const KLJUCAVNICA = 8274100; // poljubna, a stalna številka za pg_advisory_lock

const PRIVZETI_LOCK_TIMEOUT = "5s";
const PRIVZETI_STATEMENT_TIMEOUT = "120s";
const PRIVZETI_KLJUCAVNICA_TIMEOUT = "60s";
const PRIVZETE_PONOVITVE = 2;
const PRIVZETI_PREMOR = "10s";

// Prebere časovno mejo iz okolja in jo preveri, PREDEN se dotaknemo baze (napačna vrednost = jasna napaka, ne tihi privzetek).
function casovnaMeja(ime, privzeto) {
  const v = (process.env[ime] ?? "").trim();
  if (v === "") return privzeto;
  if (!/^\d+(ms|s|min)?$/.test(v)) {
    console.error(`✖ ${ime}="${v}" ni veljavna vrednost. Dovoljeno: število ms ali število s priponko ms|s|min (npr. 5s, 2min), 0 = brez meje.`);
    process.exit(1);
  }
  return v;
}
const lockTimeout = casovnaMeja("MIGRACIJA_LOCK_TIMEOUT", PRIVZETI_LOCK_TIMEOUT);
const statementTimeout = casovnaMeja("MIGRACIJA_STATEMENT_TIMEOUT", PRIVZETI_STATEMENT_TIMEOUT);
const kljucavnicaTimeout = casovnaMeja("MIGRACIJA_KLJUCAVNICA_TIMEOUT", PRIVZETI_KLJUCAVNICA_TIMEOUT);
const premor = casovnaMeja("MIGRACIJA_PREMOR", PRIVZETI_PREMOR);
const ponovitve = (() => {
  const v = (process.env.MIGRACIJA_PONOVITVE ?? "").trim();
  if (v === "") return PRIVZETE_PONOVITVE;
  if (!/^\d{1,2}$/.test(v)) {
    console.error(`✖ MIGRACIJA_PONOVITVE="${v}" ni veljavna vrednost. Dovoljeno: celo število 0–99 (število ponovnih poskusov po lock timeoutu).`);
    process.exit(1);
  }
  return Number(v);
})();
function vMs(meja) {
  const m = /^(\d+)(ms|s|min)?$/.exec(meja);
  return Number(m[1]) * (m[2] === "s" ? 1000 : m[2] === "min" ? 60000 : 1);
}
const spi = (ms) => new Promise((r) => setTimeout(r, ms));

const args = process.argv.slice(2);
const samoStanje = args.includes("--stanje");
const doIndex = args.indexOf("--do");
const doVkljucno = doIndex >= 0 ? args[doIndex + 1] : null;

if (!process.env.DATABASE_URL) {
  console.error("✖ DATABASE_URL ni nastavljen. Skripto poženi tam, kjer je (na Renderju).");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost") ? false : { rejectUnauthorized: false },
});
// Prekinjena povezava (ponovni zagon baze med deployem) naj da jasno napako, ne "Unhandled 'error' event".
// Poizvedba, ki je tekla, tako ali tako zavrne obljubo; glavno() to ujame in konča z izhodno kodo 1.
pool.on("error", (e) => console.error("[pool] povezava s bazo prekinjena:", e && e.message));
pool.on("connect", (odjemalec) => {
  odjemalec.on("error", (e) => console.error("[pool] povezava s bazo prekinjena:", e && e.message));
});

function odtis(besedilo) {
  return crypto.createHash("sha256").update(besedilo).digest("hex").slice(0, 16);
}

// Migracije imajo svoj BEGIN/COMMIT. Odstranimo ju, da lahko zavijemo tako
// samo migracijo kot vpis v evidenco v ENO transakcijo — sicer bi se lahko
// zgodilo, da se migracija uporabi, vpis pa ne.
// Pozor: ujamemo samo vrstici, ki sta točno "BEGIN;" oziroma "COMMIT;" na
// začetku vrstice. Telesa funkcij plpgsql se s tem ne dotaknemo, ker je tam
// BEGIN brez podpičja.
function breztransakcije(sql) {
  return sql
    .split("\n")
    .filter((v) => !/^\s*(BEGIN|COMMIT)\s*;\s*$/i.test(v))
    .join("\n");
}

async function glavno() {
  console.log(`Meje: lock_timeout ${lockTimeout}, statement_timeout ${statementTimeout} (na stavek), ponovitve ${ponovitve} po ${premor}, čakanje na advisory lock ${kljucavnicaTimeout}`);
  const odjemalec = await pool.connect();
  let zaklenjeno = false;

  try {
    await odjemalec.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        datoteka   TEXT PRIMARY KEY,
        odtis      TEXT        NOT NULL,
        uporabljen TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    // Meja za cakanje na advisory lock: viseca seja prejsnjega deploya ne sme zatakniti tega za vedno.
    await odjemalec.query("SELECT set_config('lock_timeout', $1, false)", [kljucavnicaTimeout]);
    try {
      await odjemalec.query("SELECT pg_advisory_lock($1)", [KLJUCAVNICA]);
    } catch (e) {
      if (e.code !== "55P03") throw e;
      console.error(`\n✖ Migracijskega zaklepa ni bilo mogoče dobiti v ${kljucavnicaTimeout}: druga seja (prejšnji deploy ali ročni zagon) ga še drži.`);
      console.error("   Deploy pade, Render obdrži staro različico. Poišči sejo (pg_locks, locktype='advisory', objid=" + KLJUCAVNICA + ") in jo končaj, nato znova sproži deploy.\n");
      process.exitCode = 1;
      return;
    }
    zaklenjeno = true;
    await odjemalec.query("RESET lock_timeout"); // naprej velja samo SET LOCAL po migracijah

    const datoteke = fs.readdirSync(MAPA)
      .filter((d) => /^\d{3}_.*\.sql$/.test(d))
      .sort();

    if (datoteke.length === 0) {
      console.log("V mapi db/migracije ni nobene migracije.");
      return;
    }

    const ze = await odjemalec.query("SELECT datoteka, odtis, uporabljen FROM schema_migrations");
    const evidenca = new Map(ze.rows.map((v) => [v.datoteka, v]));

    // --- preveri, ali se je katera že uporabljena datoteka spremenila ---
    const spremenjene = [];
    for (const d of datoteke) {
      const zapis = evidenca.get(d);
      if (!zapis) continue;
      const sedanji = odtis(fs.readFileSync(path.join(MAPA, d), "utf8"));
      if (zapis.odtis !== sedanji) spremenjene.push({ d, bil: zapis.odtis, je: sedanji });
    }

    if (spremenjene.length > 0) {
      console.error("\n✖ Že uporabljena migracija je bila spremenjena:\n");
      for (const s of spremenjene) console.error(`    ${s.d}   evidenca: ${s.bil}   datoteka: ${s.je}`);
      console.error(`
  Migracija, ki je že stekla na bazi, se ne sme popravljati — baza je ne bo
  pognala znova, zato bi se stanje kode in stanje baze tiho razšla.
  Popravek zapiši kot NOVO migracijo z naslednjo številko.
`);
      process.exitCode = 1;
      return;
    }

    // --- izpis stanja ---
    console.log("\nStanje migracij:\n");
    for (const d of datoteke) {
      const zapis = evidenca.get(d);
      console.log(zapis
        ? `  ✓ ${d}   uporabljena ${new Date(zapis.uporabljen).toISOString().slice(0, 16).replace("T", " ")}`
        : `  · ${d}   NI uporabljena`);
    }

    const cakajo = datoteke.filter((d) => !evidenca.has(d));
    if (cakajo.length === 0) {
      console.log("\nBaza je usklajena, ničesar ni za narediti.\n");
      return;
    }

    if (samoStanje) {
      console.log(`\nČaka ${cakajo.length} migracij. Zagon brez --stanje jih bo uporabil.\n`);
      return;
    }

    // --- uporabi ---
    console.log("");
    for (const d of cakajo) {
      if (doVkljucno && d.slice(0, 3) > doVkljucno) {
        console.log(`  ⏸ ustavljam se pred ${d} (--do ${doVkljucno})`);
        break;
      }

      const vsebina = fs.readFileSync(path.join(MAPA, d), "utf8");
      const zacetek = Date.now();
      process.stdout.write(`  → ${d} ... `);

      for (let poskus = 0; ; poskus++) {
        try {
          await odjemalec.query("BEGIN");
          // set_config(..., true) = samo za to transakcijo (kot SET LOCAL); ob COMMIT/ROLLBACK se meji vrneta na prejšnji vrednosti.
          // To deluje, ker migrate.js sam zavije migracijo v transakcijo (BEGIN/COMMIT iz datoteke odstrani, glej breztransakcije).
          await odjemalec.query(
            "SELECT set_config('lock_timeout', $1, true), set_config('statement_timeout', $2, true)",
            [lockTimeout, statementTimeout]
          );
          await odjemalec.query(breztransakcije(vsebina));
          await odjemalec.query(
            "INSERT INTO schema_migrations (datoteka, odtis) VALUES ($1,$2)",
            [d, odtis(vsebina)]
          );
          await odjemalec.query("COMMIT");
          console.log(`v redu (${Date.now() - zacetek} ms${poskus > 0 ? `, poskus ${poskus + 1}` : ""})`);
          break;
        } catch (e) {
          await odjemalec.query("ROLLBACK").catch(() => {});
          if (e.code === "55P03" && poskus < ponovitve) {
            // Kratek izvoz ali poročilo naj ne podre deploya: počakamo in poskusimo znova (migracija je bila vrnjena nazaj).
            console.log(`zaklep zaseden (lock timeout ${lockTimeout}), poskus ${poskus + 1}/${ponovitve + 1}; počakam ${premor}`);
            await spi(vMs(premor));
            process.stdout.write(`  → ${d} ... `);
            continue;
          }
          console.log("PADLA");
          console.error(`\n✖ ${d} ni šla skozi. Baza je ostala nespremenjena.\n`);
          console.error(`   ${e.message}`);
          if (e.code === "55P03") {
            console.error(`
     Migracija ni dobila zaklepa v ${lockTimeout} (lock timeout) niti v ${ponovitve + 1} poskusih: tabelo je ves čas uporabljala
     dolga transakcija (npr. izvoz baze ali poročilo). Čakanje bi ustavilo vsa nova branja te tabele, zato je migracija odnehala.
     Deploy pade, Render obdrži staro različico (backend teče naprej, nova koda NI živa); migracija se poskusi znova ob
     naslednjem deployu (vpisa v schema_migrations ni). Poišči dolgo transakcijo (pg_stat_activity), počakaj, da se konča, in znova sproži deploy.`);
          } else if (e.code === "57014") {
            console.error(`
     Migracija je tekla predolgo (statement timeout ${statementTimeout}) in je bila prekinjena, da ne bi dolgo držala zaklepa.
     Deploy pade, Render obdrži staro različico. Počasno migracijo razdeli na manjše korake ali (če je res nujno)
     za en deploy dvigni MIGRACIJA_STATEMENT_TIMEOUT na Renderju.`);
          }
          if (e.detail) console.error(`   ${e.detail}`);
          if (e.hint) console.error(`   Namig: ${e.hint}`);
          console.error("");
          process.exitCode = 1;
          return;
        }
      }
    }

    console.log("\nKončano.\n");
  } finally {
    if (zaklenjeno) await odjemalec.query("SELECT pg_advisory_unlock($1)", [KLJUCAVNICA]).catch(() => {});
    odjemalec.release();
    await pool.end();
  }
}

glavno().catch((e) => {
  console.error("\n✖ Nepričakovana napaka:", e.message, "\n");
  process.exit(1);
});
