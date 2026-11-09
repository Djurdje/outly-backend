"use strict";
// Zasedenost diska baze (Render outly-db: disk 1 GB, storage autoscaling vklopljen 8. 11. 2026; racuni_pdf hrani PDF-je v bazi). Poln disk = baza stoji = tudi sken na vratih.
// GET /healthz/baza (index.js), opozorilo `baza_disk` (admin_nadzor.js) in dnevnik POZOR (Sentry) uporabljajo ISTO meritev:
//  - disk_pct = round(pg_database_size(current_database()) / (diskMb MiB) * 100); pg_database_size NE steje WAL in drugih datotek zunaj baze,
//    zato je prava zasedenost diska nekoliko vecja od izmerjene (zato je meja opozorila 70 %, ne 90 %, ko Render sam poveca disk)
//  - rezultat velja `veljaMs` (privzeto 5 min); sočasni klici in klici med meritvijo si delijo isto obljubo = najvec ena poizvedba na rok
//  - GLAVNI pool (ne skenPool, ne zdraviPool), ena kratka READ ONLY transakcija z mejami; ODJEMALSKI rok `rokMs` (~3 s): obvisela ali pozna
//    povezava se UNICI (release(true)), nikoli vrne v pool; napaka/rok = null (proces ne pade), napaka se obdrzi samo kratek cas (min(veljaMs, 15 s))
//  - POZOR v dnevnik (console.error -> Sentry) najvec 1x na 6 h na proces
const POZOR_MED_MS = 6 * 3600 * 1000;
const NAPAKA_VELJA_MS = 15000;

function ustvari(dep) {
  const { pool } = dep;
  const log = dep.log || console;
  const diskMb = dep.diskMb;
  const opozoriloPct = dep.opozoriloPct;
  const veljaMs = Number.isInteger(dep.veljaMs) && dep.veljaMs > 0 ? dep.veljaMs : 5 * 60 * 1000;   // samo za teste (krajsi rok); produkcija vedno 5 min
  const rokMs = Number.isInteger(dep.rokMs) && dep.rokMs > 0 ? dep.rokMs : 3000;
  const zdaj = dep.zdaj || Date.now;

  let zadnja = null;      // { pct (celo stevilo ali null), do }
  let tece = null;        // tekoca meritev (Promise<number|null>)
  let zadnjiPozor = null;

  async function poizvedi() {
    let koncano = false, drzim = null, sproscena = false;
    const naNapako = () => {};
    const sprosti = (c, unici) => {
      if (sproscena) return;
      sproscena = true;
      c.off("error", naNapako);                      // poslusalec se ne kopici na odjemalcu, ki se vrne v pool (MaxListenersExceededWarning)
      if (unici) c.on("error", () => {});            // pozen 'error' zavrzene povezave ne sme sesuti procesa
      c.release(unici);
    };
    let casovnik;
    const delo = (async () => {
      const c = await pool.connect();
      drzim = c;
      if (koncano) { sprosti(c, true); return null; }   // pool je povezavo dal prepozno: brez poizvedbe, povezava se unici
      c.on("error", naNapako);
      await c.query("BEGIN READ ONLY; SET LOCAL statement_timeout = '2s'; SET LOCAL idle_in_transaction_session_timeout = '5s'");
      const r = await c.query("SELECT pg_database_size(current_database()) AS bajti");
      await c.query("COMMIT");
      const bajti = Number(r.rows[0].bajti);
      if (!koncano) sprosti(c, false);
      return bajti;
    })();
    delo.catch(() => {});   // zakasnela napaka po roku ne sme postati neujeta zavrnitev
    try {
      return await Promise.race([delo, new Promise((_, no) => { casovnik = setTimeout(() => no(new Error("baza_disk: rok")), rokMs); })]);
    } finally {
      koncano = true;
      clearTimeout(casovnik);
      if (drzim) sprosti(drzim, true);   // po uspehu je ze sproscena (no-op); ob roku/napaki se povezava unici
    }
  }

  async function meri() {
    let pct = null;
    try {
      const bajti = await poizvedi();
      if (bajti !== null && Number.isFinite(bajti)) pct = Math.round(bajti / (diskMb * 1048576) * 100);
    } catch (e) {
      log.error(`[baza_disk] meritev ni uspela: ${String((e && e.message) || e).slice(0, 120)}`);
    }
    zadnja = { pct, do: zdaj() + (pct === null ? Math.min(veljaMs, NAPAKA_VELJA_MS) : veljaMs) };
    if (pct !== null && pct >= opozoriloPct && (zadnjiPozor === null || zdaj() - zadnjiPozor >= POZOR_MED_MS)) {
      zadnjiPozor = zdaj();
      log.error(`[baza_disk] POZOR: disk baze ${pct} % (meja ${opozoriloPct} %, disk ${diskMb} MB): povecaj disk na Renderju in popravi BAZA_DISK_MB`);
    }
    return pct;
  }

  // Celo stevilo odstotkov ali null (baza nedosegljiva / rok). Nikoli ne vrze izjeme.
  function izmeri() {
    if (zadnja && zadnja.do > zdaj()) return Promise.resolve(zadnja.pct);
    if (!tece) tece = meri().finally(() => { tece = null; });
    return tece;
  }
  return { izmeri, opozoriloPct, diskMb, veljaMs };
}

module.exports = { ustvari };
