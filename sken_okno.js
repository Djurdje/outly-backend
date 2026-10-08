// Casovno okno skena vstopnic (Martin 8. 10. 2026, docs/DECISIONS.md »Skener brez izbire dogodka«, invarianta I25).
// Dogodek je za sken AKTIVEN, ce je zdaj med (zacetek - 12 h) in (konec + 6 h), meji vkljuceni.
// Konec = end_at, ce obstaja in je po zacetku, sicer zacetek + 12 h. Isto pravilo uveljavljata odjemalca
// (iOS outly-app #68, splet outly_webpage #42); strezniku zaupa tisti, ki ima edino pravo vrata (I1, I14).
//
// NAMENOMA locena konstanta od KONEC_DOGODKA v index.js (start + 8 h za lifecycle `ended`): tam gre za prikaz
// »dogodek je koncan«, tu za to, kdaj vratar se sme skenirati (zamuda, podaljsek, pospravljanje).
// Cista funkcija: brez baze, brez izjem, brez dodatne poizvedbe (sken na vratih mora ostati hiter, I16).

const SKEN_OKNO_PRED_MS = 12 * 3600 * 1000;         // vrata se odprejo 12 h pred zacetkom
const SKEN_OKNO_PO_MS = 6 * 3600 * 1000;            // vstopnica velja se 6 h po koncu
const SKEN_PRIVZETO_TRAJANJE_MS = 12 * 3600 * 1000; // brez end_at: konec = zacetek + 12 h

// startAt, endAt: Date | ISO niz | stevilo (ms) | null; cas: ms (privzeto zdaj).
// Neberljiv zacetek -> false (zaprto okno); v bazi je start_at NOT NULL, torej ne more nastati.
function jeVOknuSkena(startAt, endAt, cas = Date.now()) {
  const zacetek = startAt === null || startAt === undefined ? NaN : new Date(startAt).getTime();
  const t = new Date(cas).getTime();
  if (!Number.isFinite(zacetek) || !Number.isFinite(t)) return false;
  const k = endAt === null || endAt === undefined ? NaN : new Date(endAt).getTime();
  const konec = Number.isFinite(k) && k > zacetek ? k : zacetek + SKEN_PRIVZETO_TRAJANJE_MS;
  return t >= zacetek - SKEN_OKNO_PRED_MS && t <= konec + SKEN_OKNO_PO_MS;
}

module.exports = { jeVOknuSkena, SKEN_OKNO_PRED_MS, SKEN_OKNO_PO_MS, SKEN_PRIVZETO_TRAJANJE_MS };
