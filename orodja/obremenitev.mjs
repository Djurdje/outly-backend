#!/usr/bin/env node
// Obremenitev javnih poti: navidezni uporabniki z realnim tokom  /events -> /events/:id -> /clubs/:id  (brez prijave,
// brez pisanja v bazo). Issue #89. Brez odvisnosti (Node 22, vgrajen fetch).
//
// Uporaba:
//   node orodja/obremenitev.mjs [URL] [--users 1000] [--duration 120] [--think 1500]
//                                [--loop] [--max-napak 0] [--max-p95 1000] [--timeout 15000]
//
//   URL           cilj; privzeto http://localhost:3000 (lokalni backend z lokalno bazo)
//   --users N     stevilo navideznih uporabnikov (privzeto 1000)
//   --duration S  odprti model (privzeto): uporabniki PRIDEJO enakomerno razporejeni cez S sekund, vsak odigra eno
//                 kratko sejo (3 zahtevki) in odide. "1000 uporabnikov v ~2 min" = --users 1000 --duration 120.
//                 Z --loop: zaprti model - vseh N uporabnikov je HKRATI aktivnih S sekund in sejo ponavlja
//                 (to je zgornja meja, ne realna poraba; za iskanje strehe strezniske zmogljivosti).
//                 Navala (npr. odprtje prodaje): --users 1000 --duration 10.
//   --think MS    povprecen premor "branja" med koraki seje (vsak 0,5x-1,5x, enakomerno), privzeto 1500
//   --max-napak P najvecji dovoljen delez napak v % (privzeto 0); izhodna koda 1, ce presezeno
//   --max-p95 MS  najvecji dovoljen p95 vseh zahtevkov (privzeto 1000); izhodna koda 1, ce presezeno
//   --timeout MS  casovna meja enega zahtevka; zamuda se steje kot napaka (privzeto 15000)
//
// Seja: GET /events?upcoming=true  ->  nakljucen dogodek: GET /events/:id  ->  GET /clubs/:club_id  (premor med koraki).
// Izpis: stevilo zahtevkov, napake po statusu, p50/p95/p99 po poti in skupaj, req/s, trajanje sej.
//
// !!! NIKOLI proti produkciji brez Martinovega DA (zaradi obremenitve prave baze in Render paketa). Skripta zavrne
// cilje outly-backend-*.onrender.com, onrender.com in outly.si, razen ce je v okolju OUTLY_MARTIN_DA=DA.
// Lokalni testni podatki (30 klubov, 200 dogodkov) in postopek: orodja/obremenitev-podatki.sql

const args = process.argv.slice(2);
const pozicijski = args.filter((a, i) => !a.startsWith("--") && !(i > 0 && /^--(users|duration|think|max-napak|max-p95|timeout)$/.test(args[i - 1])));
function opcija(ime, privzeto) {
  const i = args.indexOf("--" + ime);
  if (i < 0) return privzeto;
  const v = Number(args[i + 1]);
  if (!Number.isFinite(v) || v < 0) { console.error(`Neveljavna vrednost za --${ime}`); process.exit(2); }
  return v;
}
const osnova = (pozicijski[0] || "http://localhost:3000").replace(/\/+$/, "");
const UPORABNIKOV = Math.floor(opcija("users", 1000));
const TRAJANJE = opcija("duration", 120);
const PREMOR = opcija("think", 1500);
const MAX_NAPAK = opcija("max-napak", 0);
const MAX_P95 = opcija("max-p95", 1000);
const MEJA_CASA = opcija("timeout", 15000);
const ZANKA = args.includes("--loop");

let gostitelj;
try { gostitelj = new URL(osnova).hostname; } catch { console.error("Neveljaven URL:", osnova); process.exit(2); }
if (/(^|\.)onrender\.com$|(^|\.)outly\.si$/i.test(gostitelj) && process.env.OUTLY_MARTIN_DA !== "DA") {
  console.error(`Zavrnjeno: ${gostitelj} je produkcija. Obremenitev proti produkciji rabi Martinov DA (nato OUTLY_MARTIN_DA=DA).`);
  process.exit(2);
}
if (UPORABNIKOV < 1 || TRAJANJE < 1) { console.error("--users in --duration morata biti >= 1"); process.exit(2); }

const spi = (ms) => new Promise((r) => setTimeout(r, ms));
const premor = () => spi(PREMOR * (0.5 + Math.random()));

// Meritve po "poti" (vzorec brez id-jev) in skupaj.
const casi = { "/events": [], "/events/:id": [], "/clubs/:id": [], vse: [] };
const statusi = {};
const seje = [];
let napakeSkupaj = 0;

async function poizvedi(vzorec, pot) {
  const t0 = performance.now();
  let status, telo = null;
  try {
    const r = await fetch(osnova + pot, { headers: { "X-Nadzor": "outly-obremenitev" }, signal: AbortSignal.timeout(MEJA_CASA) });
    const besedilo = await r.text();
    status = r.status;
    if (status === 200) { try { telo = JSON.parse(besedilo); } catch { status = "neveljaven-json"; } }
  } catch (e) {
    status = e.name === "TimeoutError" ? "timeout" : "omrezje";
  }
  const ms = performance.now() - t0;
  casi[vzorec].push(ms); casi.vse.push(ms);
  statusi[status] = (statusi[status] || 0) + 1;
  if (status !== 200) napakeSkupaj++;
  return { status, telo, ms };
}

async function seja() {
  const t0 = performance.now();
  const sez = await poizvedi("/events", "/events?upcoming=true");
  const dogodki = Array.isArray(sez.telo) ? sez.telo : [];
  if (dogodki.length) {
    const d = dogodki[Math.floor(Math.random() * dogodki.length)];
    await premor();
    const ev = await poizvedi("/events/:id", `/events/${d.id}`);
    const klubId = ev.telo && ev.telo.club_id != null ? ev.telo.club_id : d.club_id;
    if (klubId != null) {
      await premor();
      await poizvedi("/clubs/:id", `/clubs/${klubId}`);
    }
  }
  seje.push(performance.now() - t0);
}

function pc(sortirano, p) { return sortirano.length ? sortirano[Math.min(sortirano.length - 1, Math.floor(sortirano.length * p))] : NaN; }
const f = (x) => (Number.isFinite(x) ? x.toFixed(0) : "-");

async function main() {
  console.log(`Cilj ${osnova} | ${UPORABNIKOV} uporabnikov | ${ZANKA ? "zaprti model (hkrati, ponavljajo seje)" : "odprti model (prihodi cez " + TRAJANJE + " s)"} | ${TRAJANJE} s | premor ~${PREMOR} ms`);
  // Ogrevanje: en zahtevek, da hladni zagon ne gre v meritev.
  try { await fetch(osnova + "/events?upcoming=true", { signal: AbortSignal.timeout(60000) }); } catch (e) { console.error("Cilj ni dosegljiv:", e.message); process.exit(2); }

  const t0 = Date.now();
  const konec = t0 + TRAJANJE * 1000;
  let delavci;
  if (ZANKA) {
    delavci = Array.from({ length: UPORABNIKOV }, async () => {
      await spi(Math.random() * Math.min(5000, TRAJANJE * 1000 / 4));   // rahel razmik zagona, da ni umetne sinhronizacije
      while (Date.now() < konec) { await seja(); await premor(); }
    });
  } else {
    delavci = Array.from({ length: UPORABNIKOV }, async () => { await spi(Math.random() * TRAJANJE * 1000); await seja(); });
  }
  const tik = !process.stdout.isTTY ? null : setInterval(() => {
    const s = (Date.now() - t0) / 1000;
    process.stdout.write(`\r  ${s.toFixed(0)} s | zahtevkov ${casi.vse.length} | napak ${napakeSkupaj}   `);
  }, 1000);
  await Promise.all(delavci);
  if (tik) clearInterval(tik);
  const sekund = (Date.now() - t0) / 1000;

  console.log(`\n\nTrajanje ${sekund.toFixed(1)} s | zahtevkov ${casi.vse.length} | ${(casi.vse.length / sekund).toFixed(1)} req/s`);
  const napakProcent = casi.vse.length ? (napakeSkupaj / casi.vse.length) * 100 : 100;
  console.log(`Napake: ${napakeSkupaj} (${napakProcent.toFixed(2)} %) | statusi ${JSON.stringify(statusi)}`);
  console.log("\npot               n      p50    p95    p99    max   (ms)");
  for (const [ime, v] of Object.entries(casi)) {
    const s = [...v].sort((a, b) => a - b);
    console.log(`${ime.padEnd(15)} ${String(s.length).padStart(6)} ${f(pc(s, 0.5)).padStart(6)} ${f(pc(s, 0.95)).padStart(6)} ${f(pc(s, 0.99)).padStart(6)} ${f(s[s.length - 1]).padStart(6)}`);
  }
  const sSeje = [...seje].sort((a, b) => a - b);
  console.log(`\nSeje: ${sSeje.length} | trajanje seje p50 ${f(pc(sSeje, 0.5))} ms, p95 ${f(pc(sSeje, 0.95))} ms (vkljucuje premore ~${PREMOR} ms)`);

  const vse = [...casi.vse].sort((a, b) => a - b);
  const p95 = pc(vse, 0.95);
  const pade = [];
  if (napakProcent > MAX_NAPAK) pade.push(`napak ${napakProcent.toFixed(2)} % > ${MAX_NAPAK} %`);
  if (p95 > MAX_P95) pade.push(`p95 ${f(p95)} ms > ${MAX_P95} ms`);
  console.log(pade.length ? `\nPADLO: ${pade.join("; ")}` : `\nOK: napak <= ${MAX_NAPAK} %, p95 <= ${MAX_P95} ms`);
  process.exit(pade.length ? 1 : 0);
}
main();
