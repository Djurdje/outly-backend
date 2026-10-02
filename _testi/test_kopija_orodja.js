// Orodja dnevne kopije (_orodja/kopija/, workflowa kopija.yml in obnova-preizkus.yml): preizkusi brez baze in brez omrezja.
// Ujame napake, ki jih sicer odkrijemo sele cez noc v produkciji:
//   1. ime okoljske spremenljivke za potrditev padca se mora ujemati med workflowom in stevila.js (#109: POTRDI_PADEC vs PADEC_POTRJEN)
//   2. ime kopije (kot ga sestavi workflow) mora ustrezati regexom v cisti_stare.sh in obnova-preizkus.yml
//   3. stevila.js padec: padec > 20 % = napaka, POTRDI_PADEC=true ga potrdi in nova stevila postanejo izhodisce
//   4. sifriranje z geslom (gpg): krog sifriraj -> odsifriraj, napacno geslo, spremenjena datoteka (MDC), prekratko geslo,
//      geslo nikoli v izpisu; BACKUP_GESLO samo v `env:` korakov (nikoli v ukazni vrstici `run:`); nobenih ostankov age/BACKUP_STEVILA_KLJUC
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
const imeIzWorkflowa = (kopija.match(/IME="(outly-db-\$DATUM-r\$OZNAKA\.json\.gz\.gpg)"/) || [])[1];
preveri(!!imeIzWorkflowa, "workflow sestavi ime iz DATUM in OZNAKA");
const oznakaIzWorkflowa = (kopija.match(/OZNAKA="([^"]*)"/) || [])[1] || "";
preveri(/github\.run_id/.test(oznakaIzWorkflowa) && /github\.run_attempt/.test(oznakaIzWorkflowa), "OZNAKA vsebuje run_id in run_attempt");
const ime = "outly-db-2026-10-02-r123456789-2.json.gz.gpg";
const staro = "outly-db-2026-10-02-r1.json.gz.gpg";
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

// 4. gpg
const wf2 = beri(".github/workflows/obnova-preizkus.yml");
for (const [ime, vsebina] of [["kopija.yml", kopija], ["obnova-preizkus.yml", wf2]]) {
  const vrstice = vsebina.split("\n");
  const vRun = vrstice.filter((v) => /\$\{\{\s*secrets\.BACKUP_GESLO\s*\}\}/.test(v) && !/^\s*[A-Z_]+:\s*\$\{\{\s*secrets\.BACKUP_GESLO\s*\}\}\s*$/.test(v));
  preveri(vRun.length === 0, `${ime}: BACKUP_GESLO se pojavi samo kot vrednost v env: (ne v ukazni vrstici)`);
  preveri(!/BACKUP_STEVILA_KLJUC|BACKUP_AGE_PUBLIC_KEYS|age-keygen/.test(vsebina), `${ime}: brez ostankov age / BACKUP_STEVILA_KLJUC`);
}
for (const p of ["sifriraj.sh", "odsifriraj.sh", "gpg_skupno.sh", "nalozi_r2.sh", "padec.sh"]) {
  const t = beri("_orodja/kopija/" + p);
  preveri(!/--passphrase\s|--passphrase=|-pass pass:|--batch .*\$BACKUP_GESLO/.test(t.replace(/--passphrase-fd|--passphrase-file/g, "")), `${p}: geslo ni v ukazni vrstici`);
  preveri(!/STEVILA_KLJUC|\bage\b -|age-keygen|openssl enc/.test(t), `${p}: brez ostankov age / openssl`);
}
const gpgOk = spawnSync("gpg", ["--version"]).status === 0;
if (!gpgOk) {
  console.log("PRESKOCENO gpg preizkusi (gpg ni nameščen)");
} else {
  const mapa = fs.mkdtempSync(path.join(os.tmpdir(), "kopija-gpg-"));
  try {
    const geslo = "T3stn0-G3slo-" + "x".repeat(30) + "!#$&'\"";
    const okolje = (g) => ({ PATH: process.env.PATH, BACKUP_GESLO: g });
    const sh = (skripta, args, g) => spawnSync("bash", [path.join(koren, "_orodja/kopija", skripta), ...args], { env: okolje(g), encoding: "utf8" });
    const izvoz = path.join(mapa, "izvoz.json");
    const vsebina = JSON.stringify({ exported_at: "2026-10-02T00:00:00Z", tables: { users: { count: 1, rows: [{ email: "tajno.ime@primer.si" }] } } });
    fs.writeFileSync(izvoz, vsebina);
    const kopija_ = path.join(mapa, "outly-db-2026-10-02-r1-1.json.gz.gpg");
    let r = sh("sifriraj.sh", [izvoz, kopija_], geslo);
    preveri(r.status === 0 && fs.existsSync(kopija_ + ".sha256"), "sifriraj.sh: uspe, naredi .sha256");
    preveri(!(r.stdout + r.stderr).includes(geslo) && !(r.stdout + r.stderr).includes("tajno.ime"), "sifriraj.sh: v izpisu ni gesla ne podatkov");
    preveri(!fs.readFileSync(kopija_).includes("tajno.ime"), "sifrirana datoteka ne vsebuje golega besedila");
    const nazaj = path.join(mapa, "nazaj.json");
    r = sh("odsifriraj.sh", [kopija_, nazaj], geslo);
    preveri(r.status === 0 && fs.readFileSync(nazaj, "utf8") === vsebina, "odsifriraj.sh: krog je bajt za bajtom enak");
    preveri(!(r.stdout + r.stderr).includes(geslo), "odsifriraj.sh: v izpisu ni gesla");
    const napacno = path.join(mapa, "napacno.json");
    r = sh("odsifriraj.sh", [kopija_, napacno], geslo + "x");
    preveri(r.status !== 0 && !fs.existsSync(napacno), "napacno geslo: odsifriranje pade, nic ne nastane");
    const pokvarjena = path.join(mapa, "pokvarjena.gpg");
    const bajti = fs.readFileSync(kopija_);
    bajti[Math.floor(bajti.length * 0.6)] ^= 0x01;
    fs.writeFileSync(pokvarjena, bajti);
    r = sh("odsifriraj.sh", [pokvarjena, path.join(mapa, "p.json")], geslo);
    preveri(r.status !== 0 && !fs.existsSync(path.join(mapa, "p.json")), "spremenjen bajt: odsifriranje pade (integriteta)");
    const prekratko = sh("sifriraj.sh", [izvoz, path.join(mapa, "k.gpg")], "kratko-geslo");
    preveri(prekratko.status !== 0, "geslo < 32 znakov: sifriranje zavrnjeno");
    const novaVrsta = sh("sifriraj.sh", [izvoz, path.join(mapa, "n.gpg")], geslo + "\nXX");
    preveri(novaVrsta.status !== 0, "geslo z novo vrstico: zavrnjeno");
  } finally {
    fs.rmSync(mapa, { recursive: true, force: true });
  }
}

if (napake) { console.error(`\n${napake} napak`); process.exit(1); }
console.log("\nVse OK");
