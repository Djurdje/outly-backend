// Dnevnik povezav (issue #139): enkrat na okno (privzeto 60 s) EN kratek zapis o prometu na http.Server, da je iz Render logov
// (`list_logs`, iskanje `[povezave]`) razvidno, ali Renderjev proxy odpira nove povezave do Node ali uporablja bazen
// vzdrzevanih, in kako zasicena je zanka dogodkov. Samo stevci, nobenih IP-jev, poti ali drugih osebnih podatkov.
// Zapis: [povezave] 60 s: novih N, zahtevkov M, odprtih K, zamik zanke p99 X ms, max Y ms
//  - novih: povezave, ki jih je Node sprejel v oknu ('connection'); zahtevkov: zahtevki v oknu ('request');
//  - odprtih: odprte povezave ob koncu okna (vkljucno z mirujocimi vzdrzevanimi);
//  - zamik zanke: monitorEventLoopDelay (perf_hooks), p99 in max v oknu v ms, nad resolucijo vzorcenja (0 = zanka ni zamujala).
// Okno brez novih povezav in brez zahtevkov se ne izpise (ne zasipamo logov). Izklop: DNEVNIK_POVEZAV_MS=0.
const { monitorEventLoopDelay } = require("perf_hooks");

const RESOLUCIJA_MS = 10;
const NAJKRAJSE_OKNO_MS = 100;

function nalepkaOkna(ms) { return ms % 1000 === 0 ? `${ms / 1000} s` : `${ms} ms`; }
function ms1(ns, odmikMs) { return Math.max(0, ns / 1e6 - odmikMs).toFixed(1); }

// Vrne { ustavi() } ali null, ce je izklopljeno (oknoMs 0). `izpis` je vstavljiv zaradi testov.
function zagoniDnevnikPovezav(streznik, oknoMs, izpis = console.log) {
  if (!Number.isFinite(oknoMs) || oknoMs <= 0) return null;
  const okno = Math.max(NAJKRAJSE_OKNO_MS, Math.floor(oknoMs));
  let noviVOknu = 0, zahtevkiVOknu = 0, odprte = 0;
  streznik.on("connection", (socket) => {
    noviVOknu++; odprte++;
    socket.once("close", () => { odprte--; });
  });
  streznik.on("request", () => { zahtevkiVOknu++; });
  const zanka = monitorEventLoopDelay({ resolution: RESOLUCIJA_MS });
  zanka.enable();
  // Branje v setImmediate, ne v casovniku: po daljsem zastoju zanke se casovnik okna lahko izvede PRED vzorcem histograma
  // (oba sta v isti fazi casovnikov), reset() pa zavrze naslednji vzorec - zastoj bi izpadel iz dnevnika. Faza `check`
  // pride po vseh casovnikih te iteracije, zato je vzorec zastoja ze v histogramu. Znana nenatancnost: reset() zavrze prvi
  // vzorec po sebi (~10 ms na okno), zastoj, ki bi zacel v teh 10 ms, bi izpadel.
  const izpisiOkno = () => {
    const novih = noviVOknu, zahtevkov = zahtevkiVOknu;
    noviVOknu = 0; zahtevkiVOknu = 0;
    const p99 = zanka.percentile(99), max = zanka.max;
    zanka.reset();
    if (novih === 0 && zahtevkov === 0) return;
    // Histogram belezi cas med dvema vzorcema (>= resolucija), zato odstejemo resolucijo: 0 ms = zanka je tekla brez zamude.
    izpis(`[povezave] ${nalepkaOkna(okno)}: novih ${novih}, zahtevkov ${zahtevkov}, odprtih ${odprte}, zamik zanke p99 ${ms1(p99, RESOLUCIJA_MS)} ms, max ${ms1(max, RESOLUCIJA_MS)} ms`);
  };
  const t = setInterval(() => setImmediate(izpisiOkno), okno);
  t.unref();
  return { ustavi() { clearInterval(t); zanka.disable(); } };
}

module.exports = { zagoniDnevnikPovezav };
