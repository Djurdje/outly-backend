"use strict";
// Srcni utrip periodicnih delavcev + redki alarmi (#403, I70). Danes obvisel `await` delavca tiho ustavi delo (zastavica `tece` ostane true) in nihce ne izve.
//  - vsak delavec ob zagonu `registriraj(ime, { periodaMs, zamikMs })` (delavec, ki se ne zazene - ni kljuca, izklop po okolju, perioda 0 - se NE registrira,
//    zato ne more sprozati laznega alarma); ob koncu VSAKEGA kroga (uspeh ALI obvladana napaka) pokliche `k.konec()` -> `zadnjiKrog` v pomnilniku procesa
//  - `zacetek(sprosti)` na zacetku kroga: casovnik `rok` (privzeto max(5 min, 3 x perioda), `DELAVCI_ROK_MS` samo za teste). Ob izteku: `[delavci] POZOR` (Sentry)
//    in, ce je delavec podal `sprosti`, se zastavica kroga sprosti, da naslednji krog lahko tece (stari krog se lahko vseeno konca pozneje: `konec()` vrne false,
//    delavec zastavice NE sme spet spustiti, ker pripada novemu krogu). Brez `sprosti` (denar: vracila, racuni - tam ne vemo, da stari krog ne dela vec) se zastavica
//    NE sprosti, alarm pa vseeno steje (zaostal).
//  - delavec je `zaostal`, ce od zadnjega kroga (ali od zagona + zamik, ce se ni tekel) mine vec kot max(3 x perioda, rok): krog, ki je dalj od perioda v teku,
//    NI zaostal, dokler ne preseze roka (sicer bi dolg legitimen krog sprozil alarm)
//  - `pozorRedko(kljuc, sporocilo)`: console.error z oznako POZOR najvec 1x na 10 min na kljuc in proces (Sentry ne zasuje, dnevnik ne raste)
const POZOR_MED_MS = 10 * 60 * 1000;
const ROK_MIN_MS = 5 * 60 * 1000;
// Rocaj brez ucinka: privzetek, dokler delavec ni zagnan (npr. test pokliče krog neposredno), in za izklopljene delavce.
const BREZ = { zacetek: () => ({ konec: () => true }), opravljen: () => {} };

function ustvari(dep = {}) {
  const log = dep.log || console;
  const zdaj = dep.zdaj || Date.now;
  const okolje = dep.env || process.env;
  const delavci = new Map();    // ime -> stanje
  const pozori = new Map();     // kljuc -> cas zadnjega izpisa

  function rokZa(periodaMs) {
    const e = Number.parseInt(okolje.DELAVCI_ROK_MS, 10);
    if (Number.isInteger(e) && e >= 50 && e <= 86400000) return e;
    return Math.max(ROK_MIN_MS, 3 * periodaMs);
  }

  function pozorRedko(kljuc, sporocilo, drugLog) {
    const t = zdaj(), prej = pozori.get(kljuc);
    if (prej !== undefined && t - prej < POZOR_MED_MS) return false;
    pozori.set(kljuc, t);
    (drugLog || log).error(`[alarm] POZOR: ${sporocilo}`);
    return true;
  }

  function registriraj(ime, { periodaMs, zamikMs = 0 } = {}) {
    if (!Number.isFinite(periodaMs) || periodaMs <= 0) return BREZ;   // izklopljen: brez registracije
    const d = { ime, periodaMs, zamikMs: Math.max(0, zamikMs || 0), zagon: zdaj(), zadnjiKrog: null, rok: rokZa(periodaMs) };
    delavci.set(ime, d);   // ponovna registracija (drug primerek v istem procesu, npr. test) nadomesti staro
    const zabelezi = () => { if (delavci.get(ime) === d) d.zadnjiKrog = zdaj(); };
    return {
      opravljen: zabelezi,
      zacetek(sprosti) {
        const k = { sproscen: false, konec: null };
        const casovnik = setTimeout(() => {
          pozorRedko(`delavec:${ime}`, `delavec ${ime} ze vec kot ${Math.round(d.rok / 1000)} s ne konca kroga (obvisel await?)${typeof sprosti === "function" ? "; zastavica kroga sproscena, naslednji krog lahko tece" : ""}`);
          if (typeof sprosti === "function") { k.sproscen = true; try { sprosti(); } catch (_) { /* sprostitev ne sme podreti procesa */ } }
        }, d.rok);
        if (casovnik.unref) casovnik.unref();
        // true = zastavica kroga je se vedno tega kroga (delavec jo sme spustiti); false = jo je ze sprostil casovnik, pripada morebitnemu novemu krogu
        k.konec = () => { clearTimeout(casovnik); zabelezi(); return !k.sproscen; };
        return k;
      },
    };
  }

  function zaostali() {
    const t = zdaj(), r = [];
    for (const d of delavci.values()) {
      const ref = d.zadnjiKrog !== null ? d.zadnjiKrog : d.zagon + d.zamikMs;
      if (t - ref > Math.max(3 * d.periodaMs, d.rok)) r.push(d.ime);
    }
    return r;
  }
  function stanje() {
    const t = zdaj();
    return [...delavci.values()].map((d) => ({ ime: d.ime, periodaMs: d.periodaMs, zadnjiKrog: d.zadnjiKrog, staroMs: d.zadnjiKrog === null ? null : t - d.zadnjiKrog, zaostal: zaostali().includes(d.ime) }));
  }
  return { registriraj, zaostali, stanje, pozorRedko, rokZa };
}

const skupni = ustvari();
module.exports = { ustvari, ...skupni, POZOR_MED_MS, BREZ };
