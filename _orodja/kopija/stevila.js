#!/usr/bin/env node
/**
 * Pomoc za preizkus obnove in preverbe kopije (workflow »Varnostna kopija baze«, skill obnova-baze).
 *   node _orodja/kopija/stevila.js pocisti-seed         izbrise edini seed migracij (users: agent@outly.si),
 *                                                        da je cilj za db/obnovi_izvoz.js res prazen (STATE.md, past)
 *   node _orodja/kopija/stevila.js primerjaj <izvoz>     neodvisno od obnovi_izvoz.js, za VSAKO tabelo:
 *                                                        .count v izvozu == dolzina .rows == vrstice v bazi po obnovi;
 *                                                        VSAKA tabela migrirane sheme mora biti v izvozu (tudi s 0 vrsticami);
 *                                                        seznam migracij (datoteka + odtis) mora biti enak
 *   node _orodja/kopija/stevila.js padec <izvoz> <stevila.json>
 *                                                        BREZ baze: users/orders/tickets ne smejo pasti za > 20 % glede na
 *                                                        prejsnji zagon (<stevila.json>: izhodisce, ki ga _orodja/kopija/padec.sh hrani SIFRIRANO v actions/cache); nato zapise nova stevila.
 *                                                        PADEC_POTRJEN=true: padec je namerno, nova stevila postanejo izhodisce.
 *   node _orodja/kopija/stevila.js povzetek <izvoz>     BREZ baze: izpise cas izvoza, tabele in stevila vrstic (hitri
 *                                                        mesecni preizkus po desifriranju, LOKALNO pri Martinu)
 * DATABASE_URL = ciljna lokalna baza (primerjaj, pocisti-seed).
 *
 * JAVNI DNEVNIK: v zagonu Actions (primerjaj, padec) se izpisujejo SAMO imena tabel in OK/NAPAKA - stevila uporabnikov,
 * narocil in vstopnic so poslovna informacija. Stevila vidi samo povzetek (lokalno) in sifrirano izhodisce v cachu (padec.sh).
 */
const fs = require("fs");

const [, , ukaz, potIzvoza, potStevil] = process.argv;
const GLAVNE = ["users", "orders", "tickets"];
const PRAG_PADCA = 0.2;
const q = (ime) => `"${ime.replace(/"/g, '""')}"`;

function preberiIzvoz(pot) {
  try { return JSON.parse(fs.readFileSync(pot, "utf8")); }
  catch (e) { console.error("Izvoz ni veljaven JSON (ali ga ni)."); process.exit(1); } // sporocilo JSON.parse bi vsebovalo kos podatkov
}

if (ukaz === "povzetek") {
  if (!potIzvoza) { console.error("Uporaba: stevila.js povzetek <izvoz.json>"); process.exit(2); }
  const izvoz = preberiIzvoz(potIzvoza);
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

if (ukaz === "padec") {
  if (!potIzvoza || !potStevil) { console.error("Uporaba: stevila.js padec <izvoz.json> <stevila.json>"); process.exit(2); }
  const izvoz = preberiIzvoz(potIzvoza);
  const zdaj = {};
  for (const [ime, t] of Object.entries(izvoz.tables || {})) zdaj[ime] = t.count;
  let prej = null;
  try { prej = JSON.parse(fs.readFileSync(potStevil, "utf8")); } catch (_) { /* prvi zagon ali cache pretekel */ }
  const potrjen = process.env.PADEC_POTRJEN === "true";
  const padle = [];
  if (!prej) {
    console.log("Prejsnjih stevil ni (prvi zagon ali cache pretekel): preverba padca preskocena, nova stevila shranjena.");
  } else {
    for (const ime of GLAVNE) {
      const a = prej[ime], b = zdaj[ime];
      if (typeof b !== "number") { padle.push(`${ime}: tabele ni v izvozu`); continue; }
      // pod 20 vrsticami je odstotek brez pomena (en izbrisan testni uporabnik)
      if (typeof a === "number" && a >= 20 && b < a * (1 - PRAG_PADCA)) padle.push(`${ime}: padec za vec kot ${PRAG_PADCA * 100} %`);
    }
    for (const ime of GLAVNE) console.log(`  ${padle.some((p) => p.startsWith(ime + ":")) ? "NAPAKA" : "OK    "} ${ime}`);
  }
  fs.mkdirSync(require("path").dirname(potStevil), { recursive: true });
  if (!padle.length || potrjen) fs.writeFileSync(potStevil, JSON.stringify(zdaj));
  if (padle.length && !potrjen) {
    console.error("\n✖ Sumljiv padec glede na prejsnji zagon:\n  " + padle.join("\n  ") +
      "\n  Kopija je shranjena. Ce je padec namerno (ciscenje podatkov), zazeni workflow rocno s potrdi_padec = true.");
    process.exit(1);
  }
  if (padle.length) console.log("Padec potrjen (potrdi_padec = true): nova stevila so izhodisce.");
  process.exit(0);
}

const { Client } = require("pg");
const URL_BAZE = process.env.DATABASE_URL;
if (!URL_BAZE || new URL(URL_BAZE).hostname !== "localhost") {
  console.error("DATABASE_URL mora kazati na localhost.");
  process.exit(1);
}

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
      console.error("Uporaba: stevila.js pocisti-seed | primerjaj <izvoz.json> | padec <izvoz> <stevila.json> | povzetek <izvoz>");
      return 2;
    }
    const izvoz = preberiIzvoz(potIzvoza);
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
      if (!ok) napake.push(`${ime}: stevilo vrstic se ne ujema (izvoz.count, izvoz.rows, baza)` + (vBazi === null ? "; tabele ni v bazi" : ""));
      vrstice.push([ime, ok]);
    }
    // POPOLNOST: vsaka tabela migrirane sheme mora biti v izvozu (tudi prazna). Tabela, ki je izvoz ne vsebuje, bi tiho manjkala po obnovi.
    const manjkajoce = tabeleBaze.filter((t) => !(t in izvoz.tables)).sort();
    for (const ime of manjkajoce) {
      napake.push(`${ime}: tabela migrirane sheme MANJKA v izvozu`);
      vrstice.push([ime, false]);
    }
    // seznam migracij: datoteka + odtis
    const mig = (a) => new Set(a.map((m) => `${m.datoteka}:${m.odtis}`));
    const izvozMig = mig(izvoz.tables.schema_migrations.rows);
    const bazaMig = mig((await c.query("SELECT datoteka, odtis FROM schema_migrations")).rows);
    const razlika = [...izvozMig].filter((x) => !bazaMig.has(x)).length + [...bazaMig].filter((x) => !izvozMig.has(x)).length;
    if (razlika) napake.push("schema_migrations: seznam migracij se razlikuje");

    vrstice.sort((a, b) => (a[0] < b[0] ? -1 : 1));
    for (const [ime, ok] of vrstice) console.log(`  ${ok ? "OK    " : "NAPAKA"} ${ime}`);
    console.log(`Migracije: ${razlika ? "NAPAKA" : "OK"} (${izvozMig.size})`);

    if (process.env.GITHUB_STEP_SUMMARY) {
      const md = ["", "| tabela | obnova |", "|---|---|", ...vrstice.map(([ime, ok]) => `| ${ime} | ${ok ? "OK" : "**NAPAKA**"} |`),
        "", `Migracije: ${razlika ? "**NAPAKA**" : "OK"} (${izvozMig.size}).`, ""].join("\n");
      fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, md);
    }
    if (napake.length) {
      console.error("\n✖ Primerjava ni uspela:\n  " + napake.join("\n  "));
      return 1;
    }
    console.log("\nPrimerjava: vse tabele so v izvozu in se ujemajo.");
    return 0;
  } finally {
    await c.end();
  }
}
glavno().then((k) => process.exit(k), (e) => { console.error(`Napaka: ${e.code || "neznana"}`); process.exit(1); });
