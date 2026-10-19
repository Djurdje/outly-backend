"use strict";
/**
 * Starost za uporabniski racun (Martin, 19. 10. 2026: »18+ in racun od 18«; DECISIONS »Najnizja starost za uporabniski racun«).
 * Cist modul brez stranskih ucinkov: uporabljata ga `index.js` (PATCH /me) in `_testi/test_starost_racun.js` (isti izracun »danes«).
 *
 * Starost se steje po LJUBLJANSKEM koledarju (Europe/Ljubljana), ne po UTC: odjemalca (iOS, splet) stejeta lokalno, zato bi sicer
 * 18-letnik na svoj rojstni dan med 00:00 in 01:00/02:00 po ljubljanskem casu dobil 400. Natancno kot SQL `starost()` (AGE):
 * rojen 29. 2. dopolni leto v neprestopnem letu sele 1. 3.
 */
const NAJMANJ_LET_RACUN = 18;

const LJUBLJANA = new Intl.DateTimeFormat("en-CA", { timeZone: "Europe/Ljubljana", year: "numeric", month: "2-digit", day: "2-digit" });

// »Danes« kot YYYY-MM-DD po ljubljanskem koledarju. Ce bi Node brez podatkov o casovnih pasovih vrnil drugo obliko, velja UTC (varno ob meji: kvecjemu 2 uri zamika).
function danesLjubljana(zdaj = new Date()) {
  const s = LJUBLJANA.format(zdaj);
  return /^\d{4}-\d{2}-\d{2}$/.test(s) ? s : zdaj.toISOString().slice(0, 10);
}

// Polna leta od datuma rojstva (YYYY-MM-DD) do `danes` (YYYY-MM-DD; privzeto danes po ljubljanskem koledarju).
function polnaLeta(datumRojstva, danes = danesLjubljana()) {
  const [l, m, d] = datumRojstva.split("-").map(Number);
  const [dl, dm, dd] = danes.split("-").map(Number);
  let leta = dl - l;
  if (dm < m || (dm === m && dd < d)) leta--;
  return leta;
}

module.exports = { NAJMANJ_LET_RACUN, danesLjubljana, polnaLeta };
