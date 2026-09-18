#!/usr/bin/env node
/**
 * Obnovitev logičnega izvoza (glej GET /admin/api/export v index.js) v prazno,
 * z migracijami pripravljeno bazo. Render brezplačni načrt lastnih kopij baze
 * nima — izvoz + ta skripta sta edina pot nazaj.
 *
 * Zagon:
 *   node db/obnovi_izvoz.js <pot-do-izvoza.json> [--cilj-ni-localhost]
 *
 * Cilj je DATABASE_URL iz okolja. Iz varnosti je privzeto dovoljen samo cilj,
 * ki v povezovalnem nizu vsebuje "localhost"; za obnovo v drugo (novo, prazno)
 * bazo je treba dodati zastavico --cilj-ni-localhost (npr. obnova v svežo
 * Render bazo z Martinovega računalnika).
 *
 * Skripta NE briše in NE prepisuje ničesar: če ima cilj že kakršne koli
 * podatke (razen evidence migracij), se zavrne brez izjeme.
 */

const fs = require("fs");
const { Client } = require("pg");

class Zavrnitev extends Error {}

function izpisNapake(sporocilo) {
  console.error(`\n✖ ${sporocilo}\n`);
}

// --- argumenti in osnovne varnostne preverbe (PRED vsako povezavo) ---

const args = process.argv.slice(2);
const zastavicaNiLocalhost = args.includes("--cilj-ni-localhost");
const potIzvoza = args.find((a) => !a.startsWith("--"));

if (!potIzvoza) {
  izpisNapake("Manjka pot do izvoza. Uporaba: node db/obnovi_izvoz.js <pot-do-izvoza.json> [--cilj-ni-localhost]");
  process.exit(1);
}

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  izpisNapake("DATABASE_URL ni nastavljen. Skripto poženi tam, kjer kaže na cilj obnove.");
  process.exit(1);
}

if (!DATABASE_URL.includes("localhost") && !zastavicaNiLocalhost) {
  izpisNapake(
    'DATABASE_URL ne vsebuje "localhost" — obnova v cilj, ki ni lokalna baza, je zavrnjena.\n' +
      "  Za obnovo v novo (prazno) bazo izven localhost dodaj zastavico --cilj-ni-localhost."
  );
  process.exit(1);
}

let izvoz;
try {
  izvoz = JSON.parse(fs.readFileSync(potIzvoza, "utf8"));
} catch (e) {
  izpisNapake(`Izvoza ni mogoče prebrati ali razčleniti: ${e.message}`);
  process.exit(1);
}

if (!izvoz || typeof izvoz.tables !== "object" || izvoz.tables === null) {
  izpisNapake("Datoteka ni videti kot izvoz (manjka polje tables).");
  process.exit(1);
}

// Povezava se odpre šele zdaj — SSL logika enaka db/migrate.js: izklopljena
// samo, če je v povezovalnem nizu "localhost".
const client = new Client({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes("localhost") ? false : { rejectUnauthorized: false },
});

function golo(regclassIme) {
  // pg_constraint vrne ...::regclass::text, kar je lahko "tabela" ali
  // "public.tabela" ali citirano ime — poenoti na golo ime tabele.
  let ime = regclassIme;
  if (ime.startsWith("public.")) ime = ime.slice("public.".length);
  return ime.replace(/^"(.*)"$/, "$1");
}

async function vstaviVrstice(tabela, stolpci, vrstice, stolpecInfo) {
  if (vrstice.length === 0) return;

  const identitetni = stolpci.some((c) => stolpecInfo.get(c).is_identity === "YES");
  const overriding = identitetni ? "OVERRIDING SYSTEM VALUE " : "";

  function pretvoriVrednost(stolpec, vrednost) {
    if (vrednost === null || vrednost === undefined) return null;
    const info = stolpecInfo.get(stolpec);
    if (info.data_type === "json" || info.data_type === "jsonb") return JSON.stringify(vrednost);
    // text[] in podobna polja: pg zna JS seznam sam pretvoriti v niz —
    // stringify bi ga namesto tega poslal kot Postgres ARRAY literal narobe.
    return vrednost;
  }

  const VELIKOST_PAKETA = 500;
  const imeStolpcev = stolpci.map((c) => `"${c.replace(/"/g, '""')}"`).join(", ");
  const imeTabele = `"${tabela.replace(/"/g, '""')}"`;

  for (let zacetek = 0; zacetek < vrstice.length; zacetek += VELIKOST_PAKETA) {
    const paket = vrstice.slice(zacetek, zacetek + VELIKOST_PAKETA);
    const vrednosti = [];
    const skupine = [];
    let stevec = 1;
    for (const vrstica of paket) {
      const mesta = [];
      for (const stolpec of stolpci) {
        vrednosti.push(pretvoriVrednost(stolpec, vrstica[stolpec]));
        mesta.push(`$${stevec++}`);
      }
      skupine.push(`(${mesta.join(", ")})`);
    }
    const poizvedba = `INSERT INTO ${imeTabele} (${imeStolpcev}) ${overriding}VALUES ${skupine.join(", ")}`;
    await client.query(poizvedba, vrednosti);
  }
}

async function glavno() {
  await client.connect();

  // --- 1. cilj mora biti pripravljen z migracijami ---
  const tabeleCiljaRes = await client.query(
    `SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'`
  );
  const imenaCilja = new Set(tabeleCiljaRes.rows.map((r) => r.table_name));

  if (!imenaCilja.has("schema_migrations")) {
    throw new Zavrnitev("Cilj nima tabele schema_migrations — to ni baza, pripravljena z migracijami (poženi npm run migrate).");
  }

  // --- 2. cilj mora biti prazen (razen evidence migracij) ---
  for (const tabela of imenaCilja) {
    if (tabela === "schema_migrations") continue;
    const r = await client.query(`SELECT count(*)::int AS n FROM "${tabela.replace(/"/g, '""')}"`);
    if (r.rows[0].n > 0) {
      throw new Zavrnitev(
        `Cilj ni prazen: tabela "${tabela}" že ima ${r.rows[0].n} vrstic. Obnova v bazo, ki ima podatke, je zavrnjena — brez izjeme, ne glede na zastavice.`
      );
    }
  }

  // --- 3. seznam migracij mora biti enak izvozu ---
  const migracijeIzvoza = izvoz.tables.schema_migrations;
  if (!migracijeIzvoza || !Array.isArray(migracijeIzvoza.rows)) {
    throw new Zavrnitev("Izvoz ne vsebuje tabele schema_migrations — ni mogoče preveriti ujemanja sheme.");
  }
  const migracijeIzvozaMap = new Map(migracijeIzvoza.rows.map((v) => [v.datoteka, v.odtis]));
  const migracijeCiljaRes = await client.query("SELECT datoteka, odtis FROM schema_migrations");
  const migracijeCiljaMap = new Map(migracijeCiljaRes.rows.map((v) => [v.datoteka, v.odtis]));

  const vseDatoteke = new Set([...migracijeIzvozaMap.keys(), ...migracijeCiljaMap.keys()]);
  const razlike = [];
  for (const datoteka of [...vseDatoteke].sort()) {
    const a = migracijeIzvozaMap.get(datoteka);
    const b = migracijeCiljaMap.get(datoteka);
    if (a !== b) razlike.push(`  ${datoteka}   izvoz: ${a ?? "(manjka)"}   cilj: ${b ?? "(manjka)"}`);
  }
  if (razlike.length > 0) {
    throw new Zavrnitev(
      "Seznam migracij v cilju se ne ujema z izvozom — obnova v drugačno shemo je nevarna:\n" + razlike.join("\n")
    );
  }

  // --- 4. stolpci morajo obstajati; zberi tudi njihove tipe za vstavljanje ---
  const tabeleZaObnovitev = Object.keys(izvoz.tables).filter((t) => t !== "schema_migrations");
  const stolpciCilja = {};
  for (const tabela of tabeleZaObnovitev) {
    if (!imenaCilja.has(tabela)) {
      throw new Zavrnitev(`Tabela "${tabela}" iz izvoza v cilju ne obstaja.`);
    }
    const colsRes = await client.query(
      `SELECT column_name, data_type, is_identity FROM information_schema.columns WHERE table_schema='public' AND table_name=$1`,
      [tabela]
    );
    const zemljevid = new Map(colsRes.rows.map((c) => [c.column_name, c]));
    stolpciCilja[tabela] = zemljevid;
    for (const stolpec of izvoz.tables[tabela].columns) {
      if (!zemljevid.has(stolpec)) {
        throw new Zavrnitev(`Stolpec "${tabela}.${stolpec}" iz izvoza v cilju ne obstaja.`);
      }
    }
  }

  // --- 5. vrstni red vstavljanja: topološko po tujih ključih (pg_constraint) ---
  const fkRes = await client.query(`
    SELECT conrelid::regclass::text AS otrok, confrelid::regclass::text AS stars
    FROM pg_constraint c
    JOIN pg_namespace n ON n.oid = c.connamespace
    WHERE c.contype = 'f' AND n.nspname = 'public'
  `);

  const samoNaSe = new Set(); // tabele s tujim ključem nase (potrebujejo vrstni red po id)
  const sosedje = new Map(tabeleZaObnovitev.map((t) => [t, []]));
  const vhodnaStopnja = new Map(tabeleZaObnovitev.map((t) => [t, 0]));

  for (const vrstica of fkRes.rows) {
    const stars = golo(vrstica.stars);
    const otrok = golo(vrstica.otrok);
    if (stars === otrok) {
      samoNaSe.add(stars);
      continue; // sklic nase ni krog med tabelami, uredimo z id namesto z vrstnim redom tabel
    }
    if (!tabeleZaObnovitev.includes(stars) || !tabeleZaObnovitev.includes(otrok)) continue;
    sosedje.get(stars).push(otrok);
    vhodnaStopnja.set(otrok, vhodnaStopnja.get(otrok) + 1);
  }

  const cakajoNaVstavitev = tabeleZaObnovitev.filter((t) => vhodnaStopnja.get(t) === 0).sort();
  const vrstniRed = [];
  while (cakajoNaVstavitev.length > 0) {
    const tabela = cakajoNaVstavitev.shift();
    vrstniRed.push(tabela);
    for (const sosed of sosedje.get(tabela)) {
      vhodnaStopnja.set(sosed, vhodnaStopnja.get(sosed) - 1);
      if (vhodnaStopnja.get(sosed) === 0) cakajoNaVstavitev.push(sosed);
    }
  }
  if (vrstniRed.length !== tabeleZaObnovitev.length) {
    const preostale = tabeleZaObnovitev.filter((t) => !vrstniRed.includes(t));
    throw new Zavrnitev(
      `Med tabelami je krog tujih ključev, vrstnega reda vstavljanja ni mogoče določiti: ${preostale.join(", ")}`
    );
  }

  // --- 6.–8. ena transakcija: izklop sprožilcev, vstavljanje, vklop, zaporedja, preverba ---
  await client.query("BEGIN");
  let potrjeno = false;
  try {
    for (const tabela of vrstniRed) {
      await client.query(`ALTER TABLE "${tabela.replace(/"/g, '""')}" DISABLE TRIGGER USER`);
    }

    for (const tabela of vrstniRed) {
      const podatki = izvoz.tables[tabela];
      const stolpci = podatki.columns;
      let vrstice = podatki.rows;
      if (samoNaSe.has(tabela) && stolpci.includes("id")) {
        vrstice = [...vrstice].sort((a, b) => {
          const ai = BigInt(a.id);
          const bi = BigInt(b.id);
          return ai < bi ? -1 : ai > bi ? 1 : 0;
        });
      }
      await vstaviVrstice(tabela, stolpci, vrstice, stolpciCilja[tabela]);
    }

    for (const tabela of vrstniRed) {
      await client.query(`ALTER TABLE "${tabela.replace(/"/g, '""')}" ENABLE TRIGGER USER`);
    }

    for (const zaporedje of izvoz.sequences || []) {
      if (zaporedje.last_value === null || zaporedje.last_value === undefined) continue;
      await client.query("SELECT setval($1::regclass, $2, true)", [`public.${zaporedje.name}`, zaporedje.last_value]);
    }

    console.log("");
    const neujemanja = [];
    for (const tabela of Object.keys(izvoz.tables)) {
      const r = await client.query(`SELECT count(*)::int AS n FROM "${tabela.replace(/"/g, '""')}"`);
      const pricakovano = izvoz.tables[tabela].count;
      if (r.rows[0].n !== pricakovano) {
        neujemanja.push(`  ${tabela}: pričakovano ${pricakovano}, dejansko ${r.rows[0].n}`);
      } else {
        console.log(`  ${tabela}: ${r.rows[0].n} vrstic`);
      }
    }
    if (neujemanja.length > 0) {
      throw new Zavrnitev("Število vrstic po obnovi se ne ujema z izvozom:\n" + neujemanja.join("\n"));
    }

    await client.query("COMMIT");
    potrjeno = true;
    console.log("\nObnova končana.\n");
  } finally {
    if (!potrjeno) {
      await client.query("ROLLBACK").catch(() => {});
    }
  }
}

glavno()
  .then(() => client.end())
  .then(() => process.exit(0))
  .catch(async (e) => {
    if (e instanceof Zavrnitev) {
      izpisNapake(e.message);
    } else {
      izpisNapake(`Nepričakovana napaka: ${e.message}`);
      if (e.stack) console.error(e.stack);
    }
    try { await client.end(); } catch (_) {}
    process.exit(1);
  });
