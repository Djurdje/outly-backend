#!/usr/bin/env node
/**
 * Pomoc za preizkus obnove (workflow »Varnostna kopija baze«, skill obnova-baze).
 *   node _orodja/kopija/stevila.js pocisti-seed         izbrise edini seed migracij (users: agent@outly.si),
 *                                                        da je cilj za db/obnovi_izvoz.js res prazen (STATE.md, past)
 *   node _orodja/kopija/stevila.js povzetek <izvoz>     BREZ baze: izpise cas izvoza, tabele in stevila vrstic
 *                                                        (hitri mesecni preizkus po desifriranju)
 *   node _orodja/kopija/stevila.js primerjaj <izvoz>     neodvisno od obnovi_izvoz.js primerja za VSAKO tabelo:
 *                                                        .count v izvozu == dolzina .rows == stevilo vrstic v bazi;
 *                                                        tabele v bazi brez izvoza ne smejo imeti vrstic;
 *                                                        seznam migracij (datoteka + odtis) mora biti enak
 * DATABASE_URL = ciljna lokalna baza. Izpis: samo imena tabel in stevila (dnevnik je javen).
 * Ce je nastavljen GITHUB_STEP_SUMMARY, doda tudi tabelo v povzetek zagona.
 */
const fs = require("fs");
const { Client } = require("pg");

const [, , ukaz, potIzvoza] = process.argv;
const URL_BAZE = process.env.DATABASE_URL;

if (ukaz === "povzetek") {
  if (!potIzvoza) { console.error("Uporaba: stevila.js povzetek <izvoz.json>"); process.exit(2); }
  let izvoz;
  try { izvoz = JSON.parse(fs.readFileSync(potIzvoza, "utf8")); } catch (e) { console.error("Datoteka ni veljaven JSON (ali je ni)."); process.exit(1); }
  const imena = Object.keys(izvoz.tables || {}).sort();
  if (!imena.length) { console.error("V izvozu ni nobene tabele."); process.exit(1); }
  console.log(`Izvoz z dne ${izvoz.exported_at}, ${imena.length} tabel:`);
  let slabo = 0;
  for (const ime of imena) {
    const t = izvoz.tables[ime];
    const ok = t.rows.length === t.count;
    if (!ok) slabo++;
    console.log(`  ${ok ? "OK " : "NAPAKA"} ${ime}: ${t.count} vrstic`);
  }
  console.log(`Migracij: ${izvoz.tables.schema_migrations ? izvoz.tables.schema_migrations.count : "(manjka)"}`);
  console.log(slabo ? "\nIZVOZ NI CEL." : "\nIzvoz je cel (stevila vrstic se ujemajo).");
  process.exit(slabo ? 1 : 0);
}

if (!URL_BAZE || new URL(URL_BAZE).hostname !== "localhost") {
  console.error("DATABASE_URL mora kazati na localhost.");
  process.exit(1);
}
const q = (ime) => `"${ime.replace(/"/g, '""')}"`;

async function glavno() {
  const c = new Client({ connectionString: URL_BAZE, ssl: false });
  await c.connect();
  try {
    if (ukaz === "pocisti-seed") {
      const r = await c.query("DELETE FROM users WHERE email = 'agent@outly.si'");
      console.log(`Seed agent@outly.si pobrisan (${r.rowCount} vrstica)`);
      return 0;
    }
    if (ukaz !== "primerjaj" || !potIzvoza) {
      console.error("Uporaba: stevila.js pocisti-seed | primerjaj <izvoz.json>");
      return 2;
    }
    const izvoz = JSON.parse(fs.readFileSync(potIzvoza, "utf8"));
    const tabeleBaze = (await c.query(
      "SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'"
    )).rows.map((r) => r.table_name);
    const napake = [];
    const vrstice = [];
    for (const ime of Object.keys(izvoz.tables).sort()) {
      const t = izvoz.tables[ime];
      const vBazi = tabeleBaze.includes(ime)
        ? (await c.query(`SELECT count(*)::int AS n FROM ${q(ime)}`)).rows[0].n
        : null;
      const ok = vBazi === t.count && t.rows.length === t.count;
      if (!ok) napake.push(`${ime}: izvoz.count=${t.count}, izvoz.rows=${t.rows.length}, baza=${vBazi === null ? "(tabele ni)" : vBazi}`);
      vrstice.push([ime, t.count, vBazi, ok]);
    }
    for (const ime of tabeleBaze.filter((t) => !(t in izvoz.tables)).sort()) {
      const n = (await c.query(`SELECT count(*)::int AS n FROM ${q(ime)}`)).rows[0].n;
      if (n > 0) napake.push(`${ime}: tabele ni v izvozu, v bazi pa ima ${n} vrstic`);
    }
    // seznam migracij: datoteka + odtis
    const mig = (a) => new Set(a.map((m) => `${m.datoteka}:${m.odtis}`));
    const izvozMig = mig(izvoz.tables.schema_migrations.rows);
    const bazaMig = mig((await c.query("SELECT datoteka, odtis FROM schema_migrations")).rows);
    const razlika = [...izvozMig].filter((x) => !bazaMig.has(x)).length + [...bazaMig].filter((x) => !izvozMig.has(x)).length;
    if (razlika) napake.push(`schema_migrations: seznam se razlikuje v ${razlika} vnosih`);

    for (const [ime, n, b, ok] of vrstice) console.log(`  ${ok ? "OK " : "NAPAKA"} ${ime}: izvoz ${n}, baza ${b}`);
    console.log(`Migracij: izvoz ${izvozMig.size}, baza ${bazaMig.size}`);

    if (process.env.GITHUB_STEP_SUMMARY) {
      const md = ["", "| tabela | izvoz | po obnovi | |", "|---|---:|---:|---|",
        ...vrstice.map(([ime, n, b, ok]) => `| ${ime} | ${n} | ${b} | ${ok ? "ok" : "**napaka**"} |`),
        "", `Migracije: izvoz ${izvozMig.size}, po obnovi ${bazaMig.size}.`, ""].join("\n");
      fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, md);
    }
    if (napake.length) {
      console.error("\n✖ Primerjava ni uspela:\n  " + napake.join("\n  "));
      return 1;
    }
    console.log("\nPrimerjava: vse tabele se ujemajo.");
    return 0;
  } finally {
    await c.end();
  }
}
glavno().then((k) => process.exit(k), (e) => { console.error(`Napaka: ${e.code || "neznana"}`); process.exit(1); });
