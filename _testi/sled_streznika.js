// Diagnostika (issue #139): predalo za proces STREZNIKA (node --require). Samo za _testi/test_obremenitev.js; produkcija ga ne nalaga.
// Zapise (cas sprejema povezave, zahtevka sken, konec odgovora, zastoj zanke dogodkov) na vsake 250 ms dopolni v datoteko
// SLED_STREZNIK (JSON po vrsticah); test jo prebere in za pocasne skene izpise, kje se je cas izgubil.
const fs = require("fs"), http = require("http"), { monitorEventLoopDelay, performance } = require("perf_hooks");
const POT = process.env.SLED_STREZNIK;
if (POT) {
  let buf = [];
  const z = (o) => buf.push(JSON.stringify({ t: Date.now(), ...o }));
  let sprejetih = 0, zadnjiSprejetih = 0, elu0 = performance.eventLoopUtilization();
  const povezave = new Map();   // remotePort -> cas sprejema
  const emit = http.Server.prototype.emit;
  http.Server.prototype.emit = function (ev, a, b) {
    if (ev === "connection") { sprejetih++; povezave.set(a.remotePort, Date.now()); a.on("close", () => povezave.delete(a.remotePort)); }
    if (ev === "request" && a.url.includes("/scan")) {
      const port = a.socket.remotePort, zacetek = Date.now();
      a.socket._sledZahtevkov = (a.socket._sledZahtevkov || 0) + 1;
      z({ k: "req", port, connT: povezave.get(port), n: a.socket._sledZahtevkov });
      b.on("finish", () => z({ k: "fin", port, ms: Date.now() - zacetek }));
    }
    return emit.apply(this, arguments);
  };
  const h = monitorEventLoopDelay({ resolution: 10 }); h.enable();
  setInterval(() => {
    const elu = performance.eventLoopUtilization(elu0); elu0 = performance.eventLoopUtilization();
    z({ k: "loop", max: Math.round(h.max / 1e6), sprejetih: sprejetih - zadnjiSprejetih, elu: Math.round(elu.utilization * 100) / 100 }); zadnjiSprejetih = sprejetih; h.reset(); try { fs.appendFileSync(POT, buf.join("\n") + "\n"); } catch { /* sled ni kriticen */ } buf = []; }, 250).unref();
}
