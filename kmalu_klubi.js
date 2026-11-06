// Klubi »Coming soon« (Martin 6. 11. 2026): javni GET /coming-soon vrne seznam iz podatki/kmalu_klubi.json.
// Klubi NISO vrstice v tabeli `clubs` (brez migracije, brez baze, brez prijave). Seznam ureja agent na Martinov ukaz (PR).
// Pogodba: docs/ARCHITECTURE.md »Klubi Coming soon«. Neveljavna datoteka NE sesuje procesa (izpad bi odjavil/podrl vse):
// odgovor je prazen seznam (odjemalca sekcijo skrijeta), napaka gre v dnevnik; datoteko strogo preveri _testi/test_kmalu_klubi.js (CI).
const fs = require("fs");
const path = require("path");

const POLJA = ["slug", "name", "city", "address", "logo_url", "cover_url", "website", "instagram"];
const URL_POLJA = ["logo_url", "cover_url", "website"];

function validiraj(vsebina) {
  const napake = [];
  if (!vsebina || typeof vsebina !== "object" || !Array.isArray(vsebina.clubs)) return ["manjka clubs[]"];
  const videni = new Set();
  vsebina.clubs.forEach((c, i) => {
    const oz = `clubs[${i}]`;
    if (!c || typeof c !== "object" || Array.isArray(c)) { napake.push(`${oz}: ni objekt`); return; }
    for (const p of Object.keys(c)) if (!POLJA.includes(p)) napake.push(`${oz}: neznano polje ${p}`);
    for (const p of POLJA) if (typeof c[p] !== "string") napake.push(`${oz}.${p}: ni niz`);
    if (typeof c.slug === "string") {
      if (!/^[a-z0-9-]+$/.test(c.slug)) napake.push(`${oz}.slug: ne ustreza ^[a-z0-9-]+$`);
      if (videni.has(c.slug)) napake.push(`${oz}.slug: podvojen (${c.slug})`);
      videni.add(c.slug);
    }
    if (typeof c.name === "string" && !c.name.trim()) napake.push(`${oz}.name: prazen`);
    for (const p of URL_POLJA) {
      if (typeof c[p] === "string" && c[p] !== "" && !/^https:\/\/[^\s\\]+$/.test(c[p])) napake.push(`${oz}.${p}: samo https:// ali prazen`);
    }
    if (typeof c.instagram === "string" && c.instagram !== "" && !/^[A-Za-z0-9._]+$/.test(c.instagram)) napake.push(`${oz}.instagram: brez @ in /`);
  });
  return napake;
}

function nalozi() {
  try {
    const vsebina = JSON.parse(fs.readFileSync(path.join(__dirname, "podatki", "kmalu_klubi.json"), "utf8"));
    const napake = validiraj(vsebina);
    if (napake.length) { console.error("[kmalu_klubi] neveljavna datoteka, vracam prazen seznam:", napake.join("; ")); return []; }
    // Samo znana polja v dogovorjenem vrstnem redu.
    return vsebina.clubs.map((c) => Object.fromEntries(POLJA.map((p) => [p, c[p]])));
  } catch (e) {
    console.error("[kmalu_klubi] datoteke ni mogoce prebrati, vracam prazen seznam:", e.code || e.name);
    return [];
  }
}

const telo = JSON.stringify({ clubs: nalozi() });

// Brez prijave in brez baze: Authorization se ne bere.
function obravnava(req, res) {
  res.set("Cache-Control", "public, max-age=300");
  res.type("application/json").send(telo);
}

module.exports = { obravnava, validiraj };
