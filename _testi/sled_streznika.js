// Diagnostika (issue #139): predalo za proces STREZNIKA (node --require). Samo za _testi/test_obremenitev.js; produkcija ga ne nalaga.
// Na vsake 250 ms v datoteko SLED_STREZNIK (JSON po vrsticah) dopise stevilo sprejetih povezav, zasedenost zanke dogodkov (0-1)
// in najvecji zastoj zanke; test jo prebere in izpise casovnico. Vzorec ob zasedeni zanki: ~1 sprejeta povezava na obdelan zahtevek.
const fs = require("fs"), http = require("http"), { monitorEventLoopDelay, performance } = require("perf_hooks");
const POT = process.env.SLED_STREZNIK;
if (POT) {
  let sprejetih = 0, zadnjiSprejetih = 0, elu0 = performance.eventLoopUtilization();
  const emit = http.Server.prototype.emit;
  http.Server.prototype.emit = function (ev) {
    if (ev === "connection") sprejetih++;
    return emit.apply(this, arguments);
  };
  const zastoj = monitorEventLoopDelay({ resolution: 10 }); zastoj.enable();
  setInterval(() => {
    const elu = performance.eventLoopUtilization(elu0); elu0 = performance.eventLoopUtilization();
    const vrstica = JSON.stringify({ t: Date.now(), sprejetih: sprejetih - zadnjiSprejetih, elu: Math.round(elu.utilization * 100) / 100, max: Math.round(zastoj.max / 1e6) });
    zadnjiSprejetih = sprejetih; zastoj.reset();
    try { fs.appendFileSync(POT, vrstica + "\n"); } catch { /* sled ni kriticen */ }
  }, 250).unref();
}
