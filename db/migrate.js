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
 *   – uporabi ključavnico, da si dve instanci ne skačeta v besedo.
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

const MAPA = path.join(__dirname, "migracije");
const KLJUCAVNICA = 8274100; // poljubna, a stalna številka za pg_advisory_lock

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

    await odjemalec.query("SELECT pg_advisory_lock($1)", [KLJUCAVNICA]);
    zaklenjeno = true;

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

      try {
        await odjemalec.query("BEGIN");
        await odjemalec.query(breztransakcije(vsebina));
        await odjemalec.query(
          "INSERT INTO schema_migrations (datoteka, odtis) VALUES ($1,$2)",
          [d, odtis(vsebina)]
        );
        await odjemalec.query("COMMIT");
        console.log(`v redu (${Date.now() - zacetek} ms)`);
      } catch (e) {
        await odjemalec.query("ROLLBACK").catch(() => {});
        console.log("PADLA");
        console.error(`\n✖ ${d} ni šla skozi. Baza je ostala nespremenjena.\n`);
        console.error(`   ${e.message}`);
        if (e.detail) console.error(`   ${e.detail}`);
        if (e.hint) console.error(`   Namig: ${e.hint}`);
        console.error("");
        process.exitCode = 1;
        return;
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
