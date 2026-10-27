#!/usr/bin/env node
/**
 * Test I65: vsak tuj kljuc ima uporaben indeks z vodilnimi stolpci kljuca (issue #374, migracije 068–072).
 *
 * Zakaj: brez indeksa na otroski tabeli mora vsak DELETE v starsevski tabeli (brisanje dogodka/kluba I63, DELETE /me) zaporedno prebrati
 * otroka po tem stolpcu. Test pogleda KATALOG (pg_constraint/pg_index) baze, na kateri so pognane migracije — nova migracija z novim tujim
 * kljucem brez indeksa pade tu, ne sele v produkciji.
 *
 * Kaj velja za »uporaben indeks«: veljaven (indisvalid) indeks, ki se zacne z natanko stolpci kljuca (v istem vrstnem redu), in je ali navaden ali
 * delni z `WHERE stolpec IS NOT NULL` (kontrola kljuca `WHERE stolpec = $1` ta pogoj implicira; to test dokaze z EXPLAIN). Delni indeks z drugim
 * pogojem (status = 'pending', archived_at IS NULL ...) kljuca NE pokrije.
 *
 * Zagon (baza z migracijami; test ne spreminja podatkov, vse poskuse naredi v transakciji, ki jo razveljavi):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_indeksi_fk.js
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { Client } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const KOREN = path.join(__dirname, "..");

// IZJEME: tuj kljuc brez indeksa je dovoljen samo, ce je tu izrecno naveden z razlogom (ime omejitve -> razlog).
// Zdaj prazno: vsi starsi so veliki (users, clubs, events), nobena otroska tabela ni sifrant z desetimi vrsticami.
const IZJEME = {};

// SKUPAJ_PISANE: tabele, ki jih katerakoli transakcija aplikacije (ali sprozilec, ali en sam stavek s CTE) pise SKUPAJ; popis poti je v uvodu migracije 068.
// CREATE INDEX vzame SHARE zaklep do COMMIT migracije: ce bi bili dve taki tabeli v ISTI migraciji, nastane mrtva zanka 40P01 z aplikacijo, ki ju pise v
// nasprotnem vrstnem redu (STATE.md past 3b; najdba pregleda PR #376: nakup `orders` -> sprozilec `events` proti migraciji events -> orders = 503 NAKUP_ZASEDEN).
// Vsaka skupina = tabele iz ene transakcije; vsak par iz skupine ne sme biti v isti migraciji. Nov zapis dodaj, ko nova pot pise dve tabeli z indeksom skupaj.
const SKUPAJ_PISANE = [
  ["orders", "events", "tickets"],                          // nakup, Stripe webhook (sprozilec rezerviraj_zalogo / sprosti_zalogo), pavza prodaje
  ["orders", "tickets", "guest_lists"],                     // guest lista (guestListaVhod), preklic liste
  ["tickets", "table_service"],                             // sken: UPDATE tickets + INSERT table_service v enem stavku (STREZBA_CTE)
  ["tickets", "ticket_transfers", "orders"],                // prenos vstopnice, prevzem gostujocih narocil ob prijavi (CTE)
  ["tickets", "guest_list_members", "guest_lists"],         // guest lista: povabila, odstranitev, preklic, izbris gostitelja
  ["club_tables", "table_holds", "events"],                 // PUT /business/events/:id/vip-layout
  ["club_tables", "bottle_packages"],                       // PUT /business/vip
  ["club_members", "club_invites"],                         // POST /me/invites/:id/accept
];
// Vroce tabele: vsaka v svoji migraciji (zahteva pregleda #376), tudi ce bi bil par kdaj odstranjen iz SKUPAJ_PISANE.
const VROCE = ["events", "orders", "tickets"];
// Prva migracija te razdelitve; vse od nje naprej, ki ustvarjajo indekse, preverimo (tudi poznejse, ki jih ta test ne pozna).
const PRVA_MIGRACIJA = 68;

// Tabele, na katerih migracija ustvari indekse (CREATE INDEX [IF NOT EXISTS] ime ON [ONLY] tabela ...). Komentarji (-- ...) se preskocijo.
function tabeleIndeksovMigracije(vsebina) {
  const brezKomentarjev = vsebina.split("\n").filter((v) => !/^\s*--/.test(v)).join("\n");
  const t = new Set();
  for (const m of brezKomentarjev.matchAll(/CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?\w+\s+ON\s+(?:ONLY\s+)?(?:public\.)?(\w+)/gi)) t.add(m[1].toLowerCase());
  return t;
}
// Kršitve razdelitve v mapi migracij: [{ datoteka, tabele }] — migracije, ki zaklenejo dve vroci tabeli ali par iz SKUPAJ_PISANE.
function krsitveRazdelitve(migracije) {
  const kr = [];
  for (const [datoteka, vsebina] of migracije) {
    const t = tabeleIndeksovMigracije(vsebina);
    const vroce = VROCE.filter((x) => t.has(x));
    if (vroce.length >= 2) kr.push({ datoteka, tabele: vroce, razlog: "dve vroci tabeli" });
    for (const sk of SKUPAJ_PISANE) {
      const skupne = sk.filter((x) => t.has(x));
      if (skupne.length >= 2) kr.push({ datoteka, tabele: skupne, razlog: "tabeli se pisejo skupaj" });
    }
  }
  return kr;
}

let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra) : ""); } }

// Tuji kljuci sheme public brez uporabnega indeksa (ista logika kot v migraciji 068).
const SQL_BREZ_INDEKSA = `
WITH fk AS (
  SELECT c.conrelid, c.conname, c.conkey, c.confrelid,
    (SELECT string_agg(a.attname, ',' ORDER BY k.ord)
       FROM unnest(c.conkey) WITH ORDINALITY k(attnum, ord)
       JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum) AS stolpci
  FROM pg_constraint c
  WHERE c.contype = 'f' AND c.connamespace = 'public'::regnamespace)
SELECT fk.conrelid::regclass::text AS tabela, fk.conname, fk.stolpci, fk.confrelid::regclass::text AS ref
FROM fk
WHERE NOT EXISTS (
  SELECT 1 FROM pg_index i
  WHERE i.indrelid = fk.conrelid AND i.indisvalid
    AND (i.indkey::int2[])[0:cardinality(fk.conkey)-1] = fk.conkey
    AND (i.indpred IS NULL OR pg_get_expr(i.indpred, i.indrelid) = '(' || fk.stolpci || ' IS NOT NULL)'))
ORDER BY 1, 2`;

async function main() {
  const c = new Client({ connectionString: DB, ssl: DB.includes("localhost") ? false : { rejectUnauthorized: false } });
  await c.connect();
  try {
    console.log("\n# 1. Noben tuj kljuc ni brez indeksa");
    const st = (await c.query("SELECT COUNT(*)::int AS n FROM pg_constraint WHERE contype = 'f' AND connamespace = 'public'::regnamespace")).rows[0].n;
    const brez = (await c.query(SQL_BREZ_INDEKSA)).rows.filter((r) => !(r.conname in IZJEME));
    assert(st >= 81, `v shemi je ${st} tujih kljucev (test ni prazen)`);
    assert(brez.length === 0, `vsak od ${st} tujih kljucev ima indeks z vodilnim stolpcem`, brez.map((r) => `${r.tabela}.${r.stolpci} (${r.conname})`));
    for (const [ime, razlog] of Object.entries(IZJEME)) assert(typeof razlog === "string" && razlog.length >= 20, `izjema ${ime} ima razlog`);

    console.log("\n# 2. Zaznavalec ni prazen: kljuc brez indeksa in kljuc z napacnim delnim indeksom se najdeta");
    await c.query("BEGIN");
    try {
      await c.query("CREATE TABLE zz_stars (id int PRIMARY KEY)");
      await c.query("CREATE TABLE zz_otrok (id int PRIMARY KEY, a int REFERENCES zz_stars(id), b int REFERENCES zz_stars(id), c int REFERENCES zz_stars(id), d int REFERENCES zz_stars(id), arhiv timestamptz)");
      await c.query("CREATE INDEX zz_b ON zz_otrok (b) WHERE b IS NOT NULL");          // pokrije
      await c.query("CREATE INDEX zz_c ON zz_otrok (c) WHERE arhiv IS NULL");           // delni z drugim pogojem: NE pokrije
      await c.query("CREATE INDEX zz_d ON zz_otrok (id, d)");                           // stolpec ni vodilni: NE pokrije
      const najdeni = (await c.query(SQL_BREZ_INDEKSA)).rows.filter((r) => r.tabela === "zz_otrok").map((r) => r.stolpci).sort();
      assert(JSON.stringify(najdeni) === JSON.stringify(["a", "c", "d"]), "najdeni so a (brez indeksa), c (delni z drugim pogojem), d (ni vodilni); b je pokrit", najdeni);
    } finally { await c.query("ROLLBACK"); }

    console.log("\n# 3. Delni indeks `WHERE stolpec IS NOT NULL` planer res uporabi za kontrolo kljuca (generic plan, kot v RI sprozilcu)");
    await c.query("BEGIN");
    try {
      await c.query("SET LOCAL enable_seqscan = off");
      await c.query("SET LOCAL plan_cache_mode = force_generic_plan");
      const primeri = [
        ["tickets", "used_by_user_id", "tickets_used_by_idx"],
        ["orders", "package_id", "orders_package_idx"],
        ["table_service", "event_id", "table_service_event_idx"],
        ["view_counts", "event_id", "view_counts_event_idx"],
        ["club_event_notifications", "event_id", "club_event_notifications_event_idx"],
      ];
      for (const [t, col, idx] of primeri) {
        await c.query(`PREPARE ri_${t} (int) AS SELECT 1 FROM ONLY ${t} x WHERE ${col} OPERATOR(pg_catalog.=) $1 FOR KEY SHARE OF x`);
        const plan = (await c.query(`EXPLAIN EXECUTE ri_${t}(1)`)).rows.map((r) => r["QUERY PLAN"]).join("\n");
        assert(plan.includes(idx) && !/Seq Scan/.test(plan), `${t}.${col}: kontrola kljuca uporabi ${idx}`, plan);
      }
    } finally { await c.query("ROLLBACK"); }

    console.log("\n# 4. Migracije indeksov so evidentirane, dopisane v VSE_MIGRACIJE.sql in vidne v schema.sql");
    const mapa = path.join(KOREN, "db", "migracije");
    const vse = fs.readFileSync(path.join(KOREN, "db", "VSE_MIGRACIJE.sql"), "utf8");
    const sheme = fs.readFileSync(path.join(KOREN, "db", "schema.sql"), "utf8");
    const migracije = fs.readdirSync(mapa).filter((f) => /^\d{3}_.*\.sql$/.test(f) && Number(f.slice(0, 3)) >= PRVA_MIGRACIJA).sort()
      .map((f) => [f, fs.readFileSync(path.join(mapa, f), "utf8")]);
    const indeksne = migracije.filter(([, v]) => tabeleIndeksovMigracije(v).size > 0);
    assert(indeksne.length >= 5, `migracij z indeksi od ${PRVA_MIGRACIJA} naprej je ${indeksne.length} (068–072)`, indeksne.map(([f]) => f));
    const imenaIndeksov = [];
    for (const [ime, vsebina] of indeksne) {
      const odtis = crypto.createHash("sha256").update(vsebina).digest("hex").slice(0, 16);
      const zapis = (await c.query("SELECT odtis FROM schema_migrations WHERE datoteka = $1", [ime])).rows;
      assert(zapis.length === 1 && zapis[0].odtis === odtis, `${ime}: v schema_migrations z odtisom datoteke`, { zapis, odtis });
      assert(vse.includes(`('${ime}', '${odtis}')`), `${ime}: odtis je dopisan v db/VSE_MIGRACIJE.sql`, odtis);
      const blok = vsebina.split("\n").filter((v) => !/^\s*(BEGIN|COMMIT)\s*;\s*$/i.test(v)).join("\n").replace(/^\n+|\n+$/g, "");
      assert(vse.includes("\n" + blok + "\n"), `${ime}: blok v db/VSE_MIGRACIJE.sql je enak datoteki (brez BEGIN/COMMIT)`);
      imenaIndeksov.push(...[...vsebina.matchAll(/CREATE INDEX IF NOT EXISTS (\w+)/g)].map((m) => m[1]));
    }
    assert(imenaIndeksov.length >= 26, `migracije ustvarijo ${imenaIndeksov.length} indeksov`);
    assert(new Set(imenaIndeksov).size === imenaIndeksov.length, "noben indeks ni v dveh migracijah", imenaIndeksov.filter((n, k) => imenaIndeksov.indexOf(n) !== k));
    const manjkajo = imenaIndeksov.filter((n) => !new RegExp(`CREATE INDEX ${n} ON `).test(sheme));
    assert(manjkajo.length === 0, "vsi indeksi migracij so v db/schema.sql", manjkajo);
    const glava = /vse migracije 000.(\d{3})/.exec(sheme);
    const zadnja = migracije[migracije.length - 1][0].slice(0, 3);
    assert(glava && glava[1] === zadnja, "glava db/schema.sql navaja zadnjo migracijo", { glava: glava && glava[1], zadnja });

    console.log("\n# 5. Nobena migracija ne zaklene dveh tabel, ki ju aplikacija pise skupaj (mrtva zanka 40P01 z nakupom)");
    const kr = krsitveRazdelitve(indeksne);
    assert(kr.length === 0, "vroce tabele (events, orders, tickets) so vsaka v svoji migraciji in noben par iz SKUPAJ_PISANE ni v isti", kr);
    // (Ne preverjamo "natanko ena migracija na vroco tabelo": prihodnja migracija s svojim indeksom na orders ni krsitev - varovalo je krsitveRazdelitve.)
    // Razclenjevalnik ni prazen: stara 068 (vse v eni transakciji) in par iz SKUPAJ_PISANE morata pasti; komentar z imenom tabele ne steje.
    const stara = ["-- komentar: CREATE INDEX IF NOT EXISTS x ON tickets (a)", "BEGIN;", "CREATE INDEX IF NOT EXISTS a ON events (x) WHERE x IS NOT NULL;",
      "CREATE INDEX IF NOT EXISTS b ON public.orders (y);", "CREATE INDEX IF NOT EXISTS c ON tickets (z);", "COMMIT;"].join("\n");
    const kr1 = krsitveRazdelitve([["stara.sql", stara]]);
    assert(kr1.some((k) => k.razlog === "dve vroci tabeli" && k.tabele.join() === "events,orders,tickets"), "razclenjevalnik ujame tri vroce tabele v eni migraciji", kr1);
    const kr2 = krsitveRazdelitve([["par.sql", "CREATE INDEX IF NOT EXISTS a ON club_tables (c);\nCREATE INDEX IF NOT EXISTS b ON bottle_packages (c);"]]);
    assert(kr2.length === 1 && kr2[0].razlog === "tabeli se pisejo skupaj", "razclenjevalnik ujame par iz SKUPAJ_PISANE (club_tables + bottle_packages)", kr2);
    const kr3 = krsitveRazdelitve([["ok.sql", "-- CREATE INDEX a ON events (x)\nCREATE INDEX IF NOT EXISTS b ON orders (y);"]]);
    assert(kr3.length === 0, "ena vroca tabela + komentar z drugo ni krsitev", kr3);
  } finally {
    await c.end();
  }
  console.log(`\n${ok} OK, ${fail} napak`);
  process.exit(fail ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(1); });
