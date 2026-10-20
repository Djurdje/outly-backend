// Pomozni modul za _testi/test_potrdilo_kupcu.js (zagon backenda z `node -r`): priprava PDF vstopnice vedno pade, da test preveri,
// da potrdilo kupcu odide tudi brez priloge (pravnik 20. 10. 2026, T4). Ni del produkcije in ni v `npm test` (ni testna skripta).
const pot = require.resolve("../vstopnica_priloge");
const pravi = require(pot);
require.cache[pot].exports = { ...pravi, pdfVstopnice: async () => { throw new Error("test: PDF ni nastal"); } };
