// Orodja dnevne kopije (_orodja/kopija/, workflowa kopija.yml in obnova-preizkus.yml): preizkusi brez baze in brez omrezja.
// Ujame napake, ki jih sicer odkrijemo sele cez noc v produkciji:
//   1. ime okoljske spremenljivke za potrditev padca se mora ujemati med workflowom in stevila.js (#109: POTRDI_PADEC vs PADEC_POTRJEN)
//   2. ime kopije (kot ga sestavi workflow) mora ustrezati regexom v cisti_stare.sh in obnova-preizkus.yml
//   3. stevila.js padec: padec > 20 % = napaka, POTRDI_PADEC=true ga potrdi in nova stevila postanejo izhodisce
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const koren = path.join(__dirname, "..");
const beri = (p) => fs.readFileSync(path.join(koren, p), "utf8");
let napake = 0;
const preveri = (ok, opis) => { console.log(`${ok ? "OK    " : "NAPAKA"} ${opis}`); if (!ok) napake++; };

const kopija = beri(".github/workflows/kopija.yml");
const stevila = beri("_orodja/kopija/stevila.js");

// 1. Okoljska spremenljivka za potrditev padca
const korak = (ime) => {
  const i = kopija.indexOf(`id: ${ime}\n`);
  if (i < 0) return "";
  const j = kopija.indexOf("\n      - name:", i);
  return kopija.slice(i, j < 0 ? undefined : j);
};
const padec = korak("padec");
const bere = (stevila.match(/process\.env\.([A-Z_]+)\s*===\s*"true"/) || [])[1];
preveri(bere === "POTRDI_PADEC", `stevila.js bere POTRDI_PADEC (bere: ${bere})`);
preveri(/^\s+POTRDI_PADEC:\s*\$\{\{\s*github\.event\.inputs\.potrdi_padec/m.test(padec), "korak »padec« dobi POTRDI_PADEC iz vnosa potrdi_padec");
preveri(/^\s{6}potrdi_padec:/m.test(kopija), "workflow_dispatch ima vnos potrdi_padec");

// 2. Imena kopij
const regexIz = (p) => {
  const m = beri(p).match(/\$'\^kopije\/([^\n]*?)\\t'/);
  if (!m) return null;
  return new RegExp("^kopije/" + m[1].replace(/\\\\/g, "\\") + "\\t");
};
const imeIzWorkflowa = (kopija.match(/IME="(outly-db-\$DATUM-r\$OZNAKA\.json\.gz\.age)"/) || [])[1];
preveri(!!imeIzWorkflowa, "workflow sestavi ime iz DATUM in OZNAKA");
const oznakaIzWorkflowa = (kopija.match(/OZNAKA="([^"]*)"/) || [])[1] || "";
preveri(/github\.run_id/.test(oznakaIzWorkflowa) && /github\.run_attempt/.test(oznakaIzWorkflowa), "OZNAKA vsebuje run_id in run_attempt");
const ime = "outly-db-2026-10-02-r123456789-2.json.gz.age";
const staro = "outly-db-2026-10-02-r1.json.gz.age";
for (const p of ["_orodja/kopija/cisti_stare.sh", ".github/workflows/obnova-preizkus.yml"]) {
  const re = regexIz(p);
  preveri(!!re, `${p}: regex imena kopije najden`);
  if (!re) continue;
  preveri(re.test(`kopije/2026/10/${ime}\t`), `${p}: sprejme novo ime (run_id-poskus)`);
  preveri(re.test(`kopije/2026/10/${ime}.sha256\t`) === p.endsWith(".sh"), `${p}: .sha256 ${p.endsWith(".sh") ? "sprejme" : "zavrne"}`);
  preveri(re.test(`kopije/2026/10/${staro}\t`), `${p}: sprejme staro ime (-rN)`);
  preveri(!re.test(`kopije/stanje/stevila.enc\t`) && !re.test(`kopije/stanje/brez-izhodisca\t`), `${p}: ne zadene kopije/stanje/`);
}

// 3. stevila.js padec (brez baze)
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "kopija-test-"));
try {
  const tabele = (n) => ({ tables: { users: { count: n, rows: [] }, orders: { count: 100, rows: [] }, tickets: { count: 100, rows: [] } } });
  const izvoz = path.join(tmp, "izvoz.json");
  const pot = path.join(tmp, "stevila.json");
  const zazeni = (okolje) => spawnSync("node", [path.join(koren, "_orodja/kopija/stevila.js"), "padec", izvoz, pot],
    { env: { PATH: process.env.PATH, ...okolje }, encoding: "utf8" });
  fs.writeFileSync(pot, JSON.stringify({ users: 100, orders: 100, tickets: 100 }));
  fs.writeFileSync(izvoz, JSON.stringify(tabele(50)));
  let r = zazeni({});
  preveri(r.status === 1, "padec users 100 -> 50 brez potrditve: izhodna koda 1");
  preveri(JSON.parse(fs.readFileSync(pot, "utf8")).users === 100, "ob padcu brez potrditve izhodisce ostane staro");
  r = zazeni({ POTRDI_PADEC: "true" });
  preveri(r.status === 0, "z POTRDI_PADEC=true: izhodna koda 0");
  preveri(JSON.parse(fs.readFileSync(pot, "utf8")).users === 50, "po potrditvi so nova stevila izhodisce");
  r = zazeni({ PADEC_POTRJEN: "true" });
  preveri(r.status === 0, "(kontrola) 50 -> 50 je brez padca");
  fs.writeFileSync(pot, JSON.stringify({ users: 100, orders: 100, tickets: 100 }));
  r = zazeni({ PADEC_POTRJEN: "true" });
  preveri(r.status === 1, "staro ime PADEC_POTRJEN padca ne potrdi");
  preveri(!/\b50\b|\b100\b/.test(r.stdout + r.stderr), "izpis ne vsebuje stevil vrstic (javni dnevnik)");
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}

if (napake) { console.error(`\n${napake} napak`); process.exit(1); }
console.log("\nVse OK");
