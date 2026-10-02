#!/usr/bin/env node
/**
 * Lokalno merjenje prepustnosti omejevalnika poskusov (POST /views z nakljucnim IP v X-Forwarded-For, zato vsak klic zadene bazo).
 * Zagon: node _orodja/merjenje_omejevalnika.js <port> <skupaj klicev> <vzporednih>   npr.  ... 3000 30000 1000
 * Backend zazeni lokalno z DATABASE_URL (localhost) in migracijami; rezultat NI meritev Renderjeve baze.
 */
const http = require("http");
const [,, port, total, conc] = process.argv;
const agent = new http.Agent({ keepAlive: true, maxSockets: Number(conc) });
let done = 0, started = 0, st = {}, lat = [];
const t0 = Date.now();
function one() {
  return new Promise((res) => {
    const i = started++;
    const ip = `10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`;
    const s = Date.now();
    const r = http.request({ port, method: "POST", path: "/views", agent, headers: { "content-type": "application/json", "x-forwarded-for": ip, "content-length": 2 } }, (rs) => {
      rs.resume(); rs.on("end", () => { st[rs.statusCode] = (st[rs.statusCode] || 0) + 1; lat.push(Date.now() - s); res(); });
    });
    r.on("error", () => { st.err = (st.err || 0) + 1; res(); });
    r.end("{}");
  });
}
async function worker() { while (started < Number(total)) await one(); }
(async () => {
  await Promise.all(Array.from({ length: Number(conc) }, worker));
  const s = (Date.now() - t0) / 1000; lat.sort((a, b) => a - b);
  console.log(JSON.stringify({ rps: Math.round(total / s), st, p50: lat[lat.length >> 1], p99: lat[Math.floor(lat.length * 0.99)], max: lat[lat.length - 1] }));
})();
