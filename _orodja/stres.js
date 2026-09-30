// Stresni test produkcije: samo javne GET poti (brez prijave, brez pisanja v bazo).
// Uporaba: node _orodja/stres.js [osnova] [vzporedno] [sekunde]
//   osnova     privzeto https://outly-backend-roy3.onrender.com
//   vzporedno  stevilo hkratnih "uporabnikov" (1-100), privzeto 40 (kot test 11. 9. 2026)
//   sekunde    trajanje (5-120), privzeto 30
// Izhod: req/s, zakasnitve p50/p95/p99, napake po statusu. Izhodna koda 1, ce je napak
// vec kot 1 % ali p95 nad 2000 ms (meji iz okolja: STRES_MAX_NAPAK, STRES_MAX_P95).
// Brez odvisnosti: vgrajen fetch (Node 18+).

const osnova = (process.argv[2] || "https://outly-backend-roy3.onrender.com").replace(/\/$/, "");
const vzporedno = meja(parseInt(process.argv[3] || "40", 10), 1, 100);
const sekunde = meja(parseInt(process.argv[4] || "30", 10), 5, 120);
const MAX_NAPAK = parseFloat(process.env.STRES_MAX_NAPAK || "1");   // v %
const MAX_P95 = parseInt(process.env.STRES_MAX_P95 || "2000", 10);  // v ms

function meja(n, lo, hi) { return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : lo; }

async function poizvedi(pot) {
  const t0 = performance.now();
  try {
    const r = await fetch(osnova + pot, { headers: { "X-Nadzor": "outly-stres" }, signal: AbortSignal.timeout(15000) });
    await r.arrayBuffer();
    return { status: r.status, ms: performance.now() - t0 };
  } catch (e) {
    return { status: e.name === "TimeoutError" ? "timeout" : "omrezje", ms: performance.now() - t0 };
  }
}

async function main() {
  // Ogrevanje (Render hladni zagon) in izbira ID-jev za podrobne strani.
  const poti = ["/clubs", "/events", "/events?upcoming=true", "/search?q=a"];
  try {
    const kl = await (await fetch(osnova + "/clubs", { signal: AbortSignal.timeout(60000) })).json();
    const k = Array.isArray(kl) ? kl : kl.clubs || [];
    if (k[0]?.id != null) poti.push(`/clubs/${k[0].id}`);
    const ev = await (await fetch(osnova + "/events", { signal: AbortSignal.timeout(60000) })).json();
    const e = Array.isArray(ev) ? ev : ev.events || [];
    if (e[0]?.id != null) poti.push(`/events/${e[0].id}`);
  } catch (e) {
    console.log("Ogrevanje ni uspelo:", e.message);
  }
  console.log(`Cilj ${osnova} | ${vzporedno} vzporedno | ${sekunde} s | poti: ${poti.join(", ")}`);

  const casi = [];
  const statusi = {};
  const konec = Date.now() + sekunde * 1000;
  let i = 0;
  async function delavec() {
    while (Date.now() < konec) {
      const { status, ms } = await poizvedi(poti[i++ % poti.length]);
      statusi[status] = (statusi[status] || 0) + 1;
      casi.push(ms);
    }
  }
  const t0 = Date.now();
  await Promise.all(Array.from({ length: vzporedno }, delavec));
  const trajanje = (Date.now() - t0) / 1000;

  casi.sort((a, b) => a - b);
  const pct = (p) => Math.round(casi[Math.min(casi.length - 1, Math.floor((p / 100) * casi.length))] || 0);
  const skupaj = casi.length;
  const napake = Object.entries(statusi).filter(([s]) => s !== "200").reduce((n, [, c]) => n + c, 0);
  const odstotek = skupaj ? (napake / skupaj) * 100 : 100;

  const porocilo = [
    `Zahtevkov: ${skupaj} v ${trajanje.toFixed(1)} s = ${(skupaj / trajanje).toFixed(1)} req/s`,
    `Zakasnitev ms: p50 ${pct(50)} | p95 ${pct(95)} | p99 ${pct(99)} | max ${Math.round(casi[skupaj - 1] || 0)}`,
    `Statusi: ${JSON.stringify(statusi)}`,
    `Napake: ${odstotek.toFixed(2)} % (meja ${MAX_NAPAK} %), p95 meja ${MAX_P95} ms`,
  ].join("\n");
  console.log(porocilo);
  if (process.env.GITHUB_STEP_SUMMARY) {
    require("fs").appendFileSync(process.env.GITHUB_STEP_SUMMARY, "## Stresni test\n\n```\n" + porocilo + "\n```\n");
  }
  if (odstotek > MAX_NAPAK || pct(95) > MAX_P95) {
    console.log("PADLO: backend pod to obremenitvijo ne zdrzi meja.");
    process.exit(1);
  }
  console.log("OK: backend zdrzi to obremenitev.");
}

main();
