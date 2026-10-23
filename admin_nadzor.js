"use strict";
// Admin: opozorila, seznam racunov in nadzorna plosca »Danes« (23. 10. 2026, issue #326; nacrt outly-hq docs/ideje/2026-10-23-admin-panel-nadgradnja.md 2.1, 2.3).
// Poti na adminskem routerju (requireAuth + requireRole("admin") ze na routerju): GET /opozorila, GET /racuni, GET /danes. SAMO BRANJE.
//
// Meje (ARCHITECTURE »Opozorila in nadzorna plosca (admin)«):
//  - vsaka pot: ENA povezava glavnega poola, BEGIN READ ONLY + SET LOCAL statement_timeout = 2000, `c.on("error")`, release v finally;
//    NIKOLI skenPool (sken na vratih ne sme cakati za nadzorno plosco, I16). Ob 57014 (rok) -> 503 + Retry-After; panel podaljsa premor.
//    Vsaka poizvedba ima se ODJEMALSKI rok (obvisela povezava: glavni pool nima query_timeout): ob izteku povezava zavrzena, semafor prost, 503 admin_busy.
//  - opozorila in »danes« so v pomnilniku procesa ADMIN_NADZOR_PREDPOMNILNIK_MS (privzeto 10 s): vec zavihkov/adminov = ena poizvedba;
//    sočasni klici si delijo isto obljubo. 0 = brez predpomnilnika (testi).
//  - brez e-naslovov, imen kupcev, telefonov in Stripovih ID-jev v nobenem odgovoru.
// Odvisnosti iz index.js so podane ob ustvari() (en sam pogoj I34/I36/I49: razlogNerazpolozljivosti, ne podvajamo ga).

const ROK_STAVKA_MS = 2000;
const ROK_MIRUJOCE_MS = 5000;         // idle_in_transaction_session_timeout (STATE past »Vsak pool.connect() z dolgo transakcijo«)
const SEMAFOR_CAKANJE_MS = 2000;      // koliko dolgo drugacen izracun caka na edino povezavo, nato 503 admin_busy
const RDECA_VELJA_MS = 60000;         // koliko casa summary uporabi zadnje izracunano stevilo rdecih opozoril
const NAJVEC_ZNAKOV_NAPAKE = 300;
const NAJVEC_VRSTIC_NAPAKA = 100;     // racunov v stanju napaka, ki jih opozorila naštejejo posamično (stevci vedno stejejo vse)
const NAJVEC_OPOZORIL = 500;          // zgornja meja odgovora (stevci stejejo vse)
const OKNO_PLAKATA_DNI = 14;
const STANJA_RACUNOV = ["caka", "izdan", "potrjen", "napaka", "preklican"];
const RESNOST_VRSTNI_RED = { rdece: 0, oranzno: 1, rumeno: 2 };

// Besedilo napake izdajatelja racunov brez e-naslovov: ponudnik lahko v sporocilo vpise naslov kupca. Najprej zamenjamo e-naslove,
// nato vsak preostali @ (ne sme ga biti v odgovoru), sele nato skrajsamo (odrezan naslov bi sicer pustil del naslova).
function ociscenaNapaka(s) {
  if (s === null || s === undefined) return null;
  return String(s)
    .slice(0, 2000)   // zgornja meja vhoda pred regexi (SQL ze reze na 2000)
    .replace(/[^\s@<>"',;:()[\]]{1,64}@[A-Za-z0-9.-]{1,255}/g, "[e-naslov]")   // omejeni kvantifikatorji: neomejen `+` pred `@` je kvadraticen (ReDoS, #330 K1)
    .replace(/@\S*/g, "[e-naslov]")
    .slice(0, NAJVEC_ZNAKOV_NAPAKE);
}

// Prodajno stanje nocojsnjega dogodka: isti vrstni red kot v panelu dogodkov (dogodki.js, prodaja()).
function prodajnoStanje(e, zdaj) {
  if (e.sales_paused === true) return "ustavljena";
  const brezVstopnic = e.ticket_price_cents === null || e.ticket_price_cents === undefined;
  const samoVip = brezVstopnic && e.vip_from_cents !== null && e.vip_from_cents !== undefined;   // dogodek samo z VIP mizami (aktivna miza): prodaja miz, prostih miz ne stejemo
  if (brezVstopnic && !samoVip) return "zaprta";   // brez vstopnic in miz na Outlyju (zunanja prodaja ali nic)
  if (!brezVstopnic && e.capacity !== null && e.capacity !== undefined && e.sold_count >= e.capacity) return "razprodano";
  if (new Date(e.start_at).getTime() <= zdaj) return "zaprta";
  if (e.sales_open_at && new Date(e.sales_open_at).getTime() > zdaj) return "zaprta";
  if (e.sales_close_at && new Date(e.sales_close_at).getTime() < zdaj) return "zaprta";
  return "tece";
}

function ustvari(dep) {
  const { pool, router, SQL_TESTNO_NAROCILO, razlogNerazpolozljivosti, nacinPlacilaZ, sqlKlubStripePripravljen, VIP_OD_CENTOV, odgovoriNaNapako } = dep;
  const env = dep.env || process.env;
  const predpomnilnikMs = (() => {
    const n = Number.parseInt(env.ADMIN_NADZOR_PREDPOMNILNIK_MS, 10);
    return Number.isInteger(n) && n >= 0 && n <= 600000 ? n : 10000;
  })();

  // --- predpomnilnik (proces): kljuc -> { do, obljuba }; rok `do` se steje od RAZRESITVE izracuna (med izracunom velja Infinity: sočasni klici
  // dobijo isto obljubo, pocasen izracun ne sprozi vzporednega); neuspeh se ne obdrzi ---
  const predpomnilnik = new Map();
  function predpomni(kljuc, fn) {
    if (predpomnilnikMs === 0) return fn();
    const v = predpomnilnik.get(kljuc);
    if (v && v.do > Date.now()) return v.obljuba;
    const zapis = { do: Infinity, obljuba: null };
    zapis.obljuba = fn().then(
      (r) => { zapis.do = Date.now() + predpomnilnikMs; return r; },
      (e) => { if (predpomnilnik.get(kljuc) === zapis) predpomnilnik.delete(kljuc); throw e; });
    predpomnilnik.set(kljuc, zapis);
    return zapis.obljuba;
  }

  // --- semafor: NAJVEC ENA povezava glavnega poola za vse poti tega modula (admin z vec zavihki ali vec adminov ne zaseda poola, ki ga rabi nakup).
  // Cakajoci drugacni izracun caka najvec SEMAFOR_CAKANJE_MS, nato napaka ADMIN_BUSY -> 503 admin_busy + Retry-After. Enak izracun si deli obljubo (predpomni). ---
  let semaforZaseden = false;
  const semaforCakajoci = [];
  function semaforVstopi() {
    if (!semaforZaseden) { semaforZaseden = true; return Promise.resolve(); }
    return new Promise((resolve, reject) => {
      const c = { resolve: null, rok: null };
      c.resolve = () => { clearTimeout(c.rok); resolve(); };
      c.rok = setTimeout(() => {
        const i = semaforCakajoci.indexOf(c);
        if (i >= 0) semaforCakajoci.splice(i, 1);
        reject(Object.assign(new Error("admin_nadzor: povezava je zasedena"), { code: "ADMIN_BUSY" }));
      }, SEMAFOR_CAKANJE_MS);
      semaforCakajoci.push(c);
    });
  }
  function semaforIzstopi() {
    const n = semaforCakajoci.shift();
    if (n) n.resolve(); else semaforZaseden = false;
  }

  // --- ena povezava, READ ONLY, rok stavka, rok mirujoce transakcije, ODJEMALSKI rok vsake poizvedbe ---
  // Glavni pool nima `query_timeout`, `statement_timeout` pa tece na strezniku: na polodprti TCP povezavi (baza ali omrezje ne odgovori in
  // povezave ne zapre) bi `c.query` visel za vedno, semafor bi ostal zaseden in vse poti tega modula bi obvisele. Zato ima VSAKA poizvedba
  // svoj odjemalski rok (strezniski rok + 1 s: ob zakoniti 57014 odgovori najprej baza). Ob roku: poizvedba se zavrne (ADMIN_QUERY_TIMEOUT),
  // povezava se ZAVRZE (release(true), brez ROLLBACK: ta bi na obviseli povezavi visel se enkrat) in semafor se sprosti -> 503 admin_busy.
  const ROK_ODJEMALCA_MS = ROK_STAVKA_MS + 1000;
  function poizvedbaZRokom(c, sql, params) {
    return new Promise((resolve, reject) => {
      const rok = setTimeout(() => reject(Object.assign(new Error("admin_nadzor: poizvedba timed out (odjemalski rok)"), { code: "ADMIN_QUERY_TIMEOUT" })), ROK_ODJEMALCA_MS);
      let p;
      try { p = params === undefined ? c.query(sql) : c.query(sql, params); } catch (e) { clearTimeout(rok); reject(e); return; }
      Promise.resolve(p).then((r) => { clearTimeout(rok); resolve(r); }, (e) => { clearTimeout(rok); reject(e); });
    });
  }
  // Tovarna bralca: `vstopi`/`izstopi` sta semafor (admin: skupni semafor modula; agent_api.js: brez, ker agent drzi LASTEN semafor skozi cel zahtevek, #330 S1),
  // `imeAplikacije` se vidi v pg_stat_activity samo znotraj transakcije.
  function ustvariBralca(vstopi, izstopi, imeAplikacije) {
  return async function beri(fn) {
    await vstopi();
    let c;
    try { c = await pool.connect(); } catch (e) { izstopi(); throw e; }
    let pokvarjena = false, koncano = false;
    const naNapako = (e) => { pokvarjena = true; console.error("[admin-nadzor] povezava s bazo prekinjena:", e && e.message); };
    try {
      c.on("error", naNapako);
      // fn dobi ovoj, ne povezave: po izteku roka (povezava je ze zavrzena) poznejsa poizvedba ne sme na mrtvo povezavo
      const q = (sql, params) => {
        if (koncano) return Promise.reject(Object.assign(new Error("admin_nadzor: povezava je zavrzena"), { code: "ADMIN_QUERY_TIMEOUT" }));
        return poizvedbaZRokom(c, sql, params).catch((e) => { if (e && e.code === "ADMIN_QUERY_TIMEOUT") koncano = true; throw e; });
      };
      try {
        // en sam krog do baze; application_name samo znotraj transakcije (pg_stat_activity: test semaforja)
        await q(`BEGIN READ ONLY; SET LOCAL statement_timeout = ${ROK_STAVKA_MS}; SET LOCAL idle_in_transaction_session_timeout = ${ROK_MIRUJOCE_MS}; SET LOCAL application_name = '${imeAplikacije}'`);
        const r = await fn({ query: q });
        await q("COMMIT");
        return r;
      } catch (e) {
        // Kot skenBranje (index.js): baza je odgovorila z napako (SQLSTATE: pet znakov, vsaj ena stevka, npr. 57014) -> povezava je ziva,
        // ROLLBACK jo pocisti. Brez SQLSTATE (odjemalski rok, prekinjena povezava): povezava je mrtva ali visi, ROLLBACK ne poskusimo, zavrzemo jo.
        const koda = String((e && e.code) || "");
        if (/^[0-9A-Z]{5}$/.test(koda) && /[0-9]/.test(koda)) await poizvedbaZRokom(c, "ROLLBACK").catch(() => { pokvarjena = true; });
        else pokvarjena = true;
        throw e;
      }
    } finally {
      // semafor se sprosti TUDI, ce off/on/release vrzejo
      try {
        c.off("error", naNapako);
        if (pokvarjena) c.on("error", () => {});   // pozen 'error' zavrzene povezave ne sme sesuti procesa
        c.release(pokvarjena);
      } finally {
        izstopi();
      }
    }
  };
  }
  const beriReadOnly = ustvariBralca(semaforVstopi, semaforIzstopi, "admin_nadzor");
  const brezSemaforja = () => Promise.resolve();
  // Bralec za agenta (#330): BREZ admin semaforja (agent nikoli ne caka na Martinovo plosco in ona ne na agenta); agent_api.js zagotovi najvec ENO povezavo z lastnim semaforjem.
  const beriAgent = ustvariBralca(brezSemaforja, () => {}, "agent_api");

  function odgovoriNapaka(res, e, kje) {
    if (e && (e.code === "57014" || e.code === "ADMIN_QUERY_TIMEOUT" || e.code === "ADMIN_BUSY")) {
      const zaseden = e.code === "ADMIN_BUSY";
      console.error(`[admin-nadzor] ${kje}: ${zaseden ? "povezava zasedena (semafor)" : e.code === "57014" ? `preseglo statement_timeout ${ROK_STAVKA_MS} ms` : `preseglo odjemalski rok ${ROK_ODJEMALCA_MS} ms (povezava zavrzena)`}`);
      return res.status(503).set("Retry-After", "5").json({ error: "admin_busy",
        message: zaseden ? "The dashboard is busy, try again shortly." : "The dashboard query timed out. Try again in a few seconds." });
    }
    return odgovoriNaNapako(res, e, kje);
  }

  // =====================================================================================================================
  // OPOZORILA
  // =====================================================================================================================
  // `dogodekId` (neobvezno, samo GET /opozorila?dogodek=ID, #328): preverjanje enega dogodka PRED objavo. Isti pogoji, a tudi za osnutek (sicer se osnutek
  // preskoci: plakat je edino opozorilo osnutka), brez filtra skritosti/konca; vrne SAMO opozorila tega dogodka. Ne gre v predpomnilnik in ne v `zadnjiRdeci`.
  async function izracunajOpozorila(dogodekId = null, bere = beriReadOnly) {
    return bere(async (c) => {
      const items = [];
      const dodaj = (vrsta, resnost, cilj_tip, cilj_id, besedilo, cas) =>
        items.push({ vrsta, resnost, cilj_tip, cilj_id, besedilo, ...(cas ? { cas: new Date(cas).toISOString() } : {}) });
      const dodatno = { rdece: 0, oranzno: 0, rumeno: 0 };   // vrstice, ki jih meja odgovora ne pokaze posamicno, a so v stevcih

      // 1. racuni (ne glede na skritost kluba: davcna obveznost je Outlyjeva)
      if (dogodekId === null) {   // pregled enega dogodka (#328) preskoci splosne razdelke 1 in 3 (brez poizvedb); notranjost ni zamaknjena, da diff ostane majhen
      const napakaSt = (await c.query("SELECT COUNT(*)::int AS n FROM racuni WHERE stanje = 'napaka'")).rows[0].n;
      const napake = (await c.query("SELECT id, order_id, created_at FROM racuni WHERE stanje = 'napaka' ORDER BY id DESC LIMIT $1", [NAJVEC_VRSTIC_NAPAKA])).rows;
      for (const r of napake) {
        dodaj("racun_napaka", "rdece", "racun", r.id,
          `Račun ${r.id} (naročilo ${r.order_id}) je v stanju napaka: davčna potrditev ni uspela. Ročni postopek: docs/STATE.md »Davčno potrjeni računi lastnih dogodkov« (najprej preveri v e-računih, popravek je migracija z Martinovim DA).`,
          r.created_at);
      }
      dodatno.rdece += Math.max(0, napakaSt - napake.length);
      const zaostanek = (await c.query(
        `SELECT COUNT(*)::int AS n, MIN(created_at) AS najstarejsi FROM racuni WHERE stanje = 'caka' AND created_at < NOW() - INTERVAL '1 hour'`)).rows[0];
      if (zaostanek.n > 0) dodaj("racun_zaostanek", "oranzno", "racuni", null, `${zaostanek.n} računov čaka na izdajo več kot 1 uro (zakonski rok: 2 delovna dneva).`, zaostanek.najstarejsi);
      }

      // 2. dogodki (skriti klubi izpuščeni); stolpci in izracun placilnega nacina so isti kot v javnem GET /events (razlogNerazpolozljivosti)
      const dogodki = (await c.query(
        `SELECT events.id, left(events.title, 80) AS title, events.status, events.start_at, events.end_at, left(events.poster_url, 1) AS poster_url, events.ticket_price_cents, left(events.ticket_url, 1) AS ticket_url,
                events.capacity, events.sales_paused, left(c.name, 60) AS club_name, c.is_demo AS club_is_demo,
                ${VIP_OD_CENTOV} AS vip_from_cents, ${sqlKlubStripePripravljen()}
           FROM events JOIN clubs c ON c.id = events.club_id
          WHERE CASE WHEN $1::int IS NULL
                     THEN NOT c.hidden AND events.status IN ('published', 'draft') AND COALESCE(events.end_at, events.start_at + INTERVAL '18 hours') > NOW()
                     ELSE events.id = $1::int END
          ORDER BY events.start_at, events.id LIMIT 1000`, [dogodekId])).rows;
      const zdaj = Date.now();
      for (const e of dogodki) {
        const objavljen = e.status === "published";
        const ime = `»${String(e.title).slice(0, 80)}« (${String(e.club_name).slice(0, 60)})`;
        const zacetek = new Date(e.start_at).getTime();
        const cena = e.ticket_price_cents === null || e.ticket_price_cents === undefined ? null : Number(e.ticket_price_cents);
        const vip = e.vip_from_cents === null || e.vip_from_cents === undefined ? null : Number(e.vip_from_cents);
        if (e.poster_url === "" && zacetek > zdaj && zacetek <= zdaj + OKNO_PLAKATA_DNI * 864e5) {
          dodaj("brez_plakata", "oranzno", "dogodek", e.id, `${ime}: brez plakata, začetek v manj kot ${OKNO_PLAKATA_DNI} dneh${objavljen ? "" : " (osnutek)"}.`, e.start_at);
        }
        if (!objavljen && dogodekId === null) continue;   // pregled enega dogodka (#328) preveri tudi osnutek: kaj bi veljalo ob objavi
        if (e.sales_paused === true) dodaj("prodaja_ustavljena", "oranzno", "dogodek", e.id, `${ime}: prodaja je ustavljena.`, e.start_at);
        if (cena === null && e.ticket_url === "" && vip === null) {
          dodaj("brez_cene", "oranzno", "dogodek", e.id, `${ime}: objavljen brez cene vstopnice in brez zunanje prodaje.`, e.start_at);
        }
        if (cena !== null && cena > 0 && (e.capacity === null || e.capacity === undefined)) {
          dodaj("brez_kapacitete", "rumeno", "dogodek", e.id, `${ime}: plačljiv, a brez kapacitete (neomejena prodaja).`, e.start_at);
        }
        if (e.end_at === null || e.end_at === undefined) {
          dodaj("brez_konca", "rumeno", "dogodek", e.id, `${ime}: brez konca; sken na vratih naslednji dan ne bo veljal (privzeto trajanje 12 ur).`, e.start_at);
        }
        if (e.club_is_demo === true) {
          dodaj("demo_objavljen", "rumeno", "dogodek", e.id, `${ime}: objavljen dogodek demo kluba (viden v aplikaciji, nakup zavrnjen).`, e.start_at);
        } else {
          // Isti izracun kot dodajNacinPlacila (index.js): odloca vstopnica, sicer najcenejsa miza; samo placljivo (najvec > 0, brez ponudbe za 0 EUR).
          const najvec = cena !== null ? cena : (vip || 0);
          const brezplacno = cena !== null ? cena === 0 : vip === 0;
          if (najvec > 0 && !brezplacno) {
            const nacin = nacinPlacilaZ(e.club_stripe_ready === true);
            const razlog = razlogNerazpolozljivosti(nacin, e.club_seller_raw || {}, najvec, brezplacno);
            if (razlog === "seller_incomplete") {
              dodaj("prodajalec_nepopoln", "rdece", "dogodek", e.id, `${ime}: podatki prodajalca niso popolni, nakup je zavrnjen (409 seller_incomplete).`, e.start_at);
            } else if (razlog === "stripe_not_ready" || razlog === "payments_not_configured") {
              dodaj("placila_niso_pripravljena", "rdece", "dogodek", e.id,
                razlog === "stripe_not_ready" ? `${ime}: klub nima dokončanega Stripa, plačljiv nakup je zavrnjen.` : `${ime}: plačila v sistemu niso nastavljena, nakup je zavrnjen (503).`,
                e.start_at);
            }
          }
        }
      }

      // 3. obstojeci stevci (kot v /summary) + neposlana potrdila kupcem (I32)
      if (dogodekId === null) {
      const s = (await c.query(
        `SELECT (SELECT COUNT(*)::int FROM vracila WHERE stanje IN ('ni_uspelo','rocno')) AS vracila,
                (SELECT COUNT(*)::int FROM spori WHERE zaprt_at IS NULL) AS spori,
                (SELECT COUNT(*)::int FROM spori WHERE povrnitev_stanje IN ('ni_uspelo','rocno')) AS povrnitve`)).rows[0];
      if (s.vracila > 0) dodaj("vracila_pozornost", "rdece", "vracila", null, `${s.vracila} vračil kupcem je ostalo brez denarja (ni uspelo ali ročno).`);
      if (s.povrnitve > 0) dodaj("povrnitve_sporov", "rdece", "spori", null, `${s.povrnitve} povrnitev izgubljenih sporov od klubov ni uspelo (ni uspelo ali ročno).`);
      if (s.spori > 0) dodaj("spori_odprti", "oranzno", "spori", null, `${s.spori} odprtih Stripovih sporov (vstopnice med sporom na vratih ne veljajo).`);
      const potrdila = (await c.query(
        `SELECT COUNT(*)::int AS n, MIN(paid_at) AS najstarejse FROM orders
          WHERE receipt_mail_attempts IS NOT NULL AND receipt_mail_sent_at IS NULL AND status = 'paid' AND user_id IS NOT NULL
            AND buyer_email !~* '@outly\\.invalid$' AND paid_at < NOW() - INTERVAL '1 hour' AND paid_at > NOW() - INTERVAL '30 days'`)).rows[0];
      if (potrdila.n > 0) dodaj("potrdila_neposlana", "oranzno", "narocila", null, `${potrdila.n} potrdil o nakupu kupcem ni poslanih več kot 1 uro (zadnjih 30 dni).`, potrdila.najstarejse);
      }

      if (dogodekId !== null) {   // samo opozorila tega dogodka (racuni, vracila ... so splosna); stevci stejejo samo ta opozorila
        const moja = items.filter((o) => o.cilj_tip === "dogodek" && o.cilj_id === dogodekId);
        const st = { rdece: 0, oranzno: 0, rumeno: 0 };
        for (const o of moja) st[o.resnost]++;
        return { items: moja, stevci: st };
      }
      const stevci = { rdece: dodatno.rdece, oranzno: dodatno.oranzno, rumeno: dodatno.rumeno };
      for (const o of items) stevci[o.resnost]++;
      items.sort((a, b) => RESNOST_VRSTNI_RED[a.resnost] - RESNOST_VRSTNI_RED[b.resnost]);   // sort je stabilen: znotraj resnosti ostane vrstni red (cas dogodka)
      return { items: items.slice(0, NAJVEC_OPOZORIL), stevci };
    });
  }
  // Zadnje izracunano stevilo rdecih (summary ga vzame brez lastnega izracuna in brez cakanja: sicer null).
  let zadnjiRdeci = null;
  const izracunajOpozorilaZapomni = async () => {
    const r = await izracunajOpozorila(null, beriReadOnly);
    zadnjiRdeci = { n: r.stevci.rdece, ob: Date.now() };
    return r;
  };
  const opozorila = () => predpomni("opozorila", izracunajOpozorilaZapomni);
  const rdeceStevilo = () => (zadnjiRdeci && Date.now() - zadnjiRdeci.ob < RDECA_VELJA_MS ? zadnjiRdeci.n : null);

  router.get("/opozorila", async (req, res) => {
    try {
      res.set("Cache-Control", "no-store");
      if (req.query.dogodek !== undefined) {   // #328: pregled enega dogodka pred objavo (brez predpomnilnika: admin je pravkar shranil)
        const id = /^\d{1,10}$/.test(String(req.query.dogodek)) ? Number(req.query.dogodek) : 0;
        if (id < 1 || id > 2147483647) return res.status(400).json({ error: "invalid_event_id", message: "dogodek must be an event id." });
        return res.json(await izracunajOpozorila(id));
      }
      return res.json(await opozorila());
    } catch (e) { return odgovoriNapaka(res, e, "GET /admin/api/opozorila"); }
  });

  // =====================================================================================================================
  // RACUNI (davcno potrjeni racuni lastnih dogodkov, I52): seznam po stanju, brez kupca
  // =====================================================================================================================
  // Skupna logika za admin pot in /agent/api/racuni (agent_api.js): isti izracun, ista omejitev (ena povezava, READ ONLY, rok 2 s), brez kupca.
  // Vrne { stevci, limit, items }; neveljavno stanje je napaka s kodo NEVELJAVNO_STANJE (klicatelj odgovori 400).
  async function racuniSeznam(stanjeVhod, limitVhod, bere = beriReadOnly) {
    const stanje = stanjeVhod === undefined || stanjeVhod === null ? null : String(stanjeVhod);
    if (stanje !== null && !STANJA_RACUNOV.includes(stanje)) throw Object.assign(new Error("stanje must be one of: " + STANJA_RACUNOV.join(", ") + "."), { code: "NEVELJAVNO_STANJE" });
    const limit = Math.min(Math.max(Number.parseInt(limitVhod, 10) || 50, 1), 200);
    const r = await bere(async (c) => {
      const stevila = await c.query("SELECT stanje, COUNT(*)::int AS n FROM racuni GROUP BY stanje");
      const vrstice = await c.query(
        `SELECT id, order_id, vrsta, stanje, znesek_cents, valuta, stevilka, ponudnik_stevilka, izdan_at, potrjen_at, poskusi,
                left(zadnja_napaka, 2000) AS zadnja_napaka, created_at
           FROM racuni WHERE ($1::text IS NULL OR stanje = $1) ORDER BY id DESC LIMIT $2`, [stanje, limit]);
      return { stevila, vrstice };
    });
    const stevci = Object.fromEntries(STANJA_RACUNOV.map((x) => [x, 0]));
    for (const x of r.stevila.rows) stevci[x.stanje] = x.n;
    const items = r.vrstice.rows.map((x) => ({ ...x, valuta: String(x.valuta).trim(), zadnja_napaka: ociscenaNapaka(x.zadnja_napaka) }));
    return { stevci, limit, items };
  }

  router.get("/racuni", async (req, res) => {
    try {
      res.set("Cache-Control", "no-store");
      return res.json(await racuniSeznam(req.query.stanje, req.query.limit));
    } catch (e) {
      if (e && e.code === "NEVELJAVNO_STANJE") return res.status(400).send(e.message);
      return odgovoriNapaka(res, e, "GET /admin/api/racuni");
    }
  });

  // =====================================================================================================================
  // DANES
  // =====================================================================================================================
  // »Danes« po ljubljanskem koledarju (Europe/Ljubljana; »7 dni« = danes in prejsnjih 6 koledarskih dni). Pravi in testni promet LOCENO (SQL_TESTNO_NAROCILO, I39).
  // Vrnjena narocila (#310): stejejo SAMO status paid + partially_refunded (kot GET /admin/api/events); v celoti vrnjeno narocilo (refunded) v »danes« ni,
  // delno vrnjeno je v celoti (bruto = total_cents, brez odbitka vracil). /finance tece drugace (steje tudi refunded); to je namenoma preprostejsa nadzorna slika.
  // Guest lista (o.guest_list_id) ni prodaja (I24). Čas naročila = orders.created_at (kot /finance po dnevih).
  // `zdajVhod`: neobvezen fiksen trenutek (samo testi, _testi/test_admin_danes.js); sicer ura baze (NOW()). Vse poizvedbe so vezane na ISTI trenutek.
  async function izracunajDanes(zdajVhod = null, bere = beriReadOnly, opozorilaFn = opozorila) {
    let rdeca = null;
    try { rdeca = (await opozorilaFn()).stevci.rdece; }   // PRED povezavo za »danes«: nista hkrati dve povezavi iste poti
    catch (e) {
      if (e && e.code === "ADMIN_QUERY_TIMEOUT") throw e;   // povezava obvisi: drugi poskus za »danes« bi cakal se en odjemalski rok brez upanja
      console.error("[admin-nadzor] danes: opozorila niso na voljo:", e && e.message);
    }
    return bere(async (c) => {
      const T = SQL_TESTNO_NAROCILO;
      const t = (await c.query(
        `WITH z AS (SELECT COALESCE($1::timestamptz, NOW()) AS cas)
         SELECT cas,
                (date_trunc('day', cas AT TIME ZONE 'Europe/Ljubljana') AT TIME ZONE 'Europe/Ljubljana') AS danes_od,
                ((date_trunc('day', cas AT TIME ZONE 'Europe/Ljubljana') + INTERVAL '1 day') AT TIME ZONE 'Europe/Ljubljana') AS jutri_od,
                ((date_trunc('day', cas AT TIME ZONE 'Europe/Ljubljana') - INTERVAL '6 days') AT TIME ZONE 'Europe/Ljubljana') AS dni7_od
           FROM z`, [zdajVhod])).rows[0];
      const p = (await c.query(
        `SELECT COUNT(*) FILTER (WHERE NOT ${T} AND o.created_at >= $1)::int AS d_n,
                COALESCE(SUM(o.total_cents) FILTER (WHERE NOT ${T} AND o.created_at >= $1), 0)::bigint AS d_b,
                COALESCE(SUM(o.quantity) FILTER (WHERE NOT ${T} AND o.created_at >= $1 AND o.table_id IS NULL), 0)::bigint AS d_v,
                COUNT(*) FILTER (WHERE NOT ${T})::int AS w_n,
                COALESCE(SUM(o.total_cents) FILTER (WHERE NOT ${T}), 0)::bigint AS w_b,
                COALESCE(SUM(o.quantity) FILTER (WHERE NOT ${T} AND o.table_id IS NULL), 0)::bigint AS w_v,
                COUNT(*) FILTER (WHERE ${T} AND o.created_at >= $1)::int AS t_n,
                COALESCE(SUM(o.total_cents) FILTER (WHERE ${T} AND o.created_at >= $1), 0)::bigint AS t_b,
                COALESCE(SUM(o.quantity) FILTER (WHERE ${T} AND o.created_at >= $1 AND o.table_id IS NULL), 0)::bigint AS t_v
           FROM orders o
          WHERE o.status IN ('paid', 'partially_refunded') AND o.guest_list_id IS NULL AND o.created_at >= $2 AND o.created_at < $3`,
        [t.danes_od, t.dni7_od, t.jutri_od])).rows[0];
      const prodaja = {
        danes: { narocila: p.d_n, bruto_cents: p.d_b, vstopnice: p.d_v },
        dni7: { narocila: p.w_n, bruto_cents: p.w_b, vstopnice: p.w_v },
        testno_danes: { narocila: p.t_n, bruto_cents: p.t_b, vstopnice: p.t_v },
      };

      // nocoj = objavljeni dogodki, katerih okno skena je danes: zacetek med zdaj-12 h in zdaj+24 h ali v teku (konec ali zacetek + 12 h, kot sken_okno.js)
      const ev = (await c.query(
        `SELECT events.id, left(events.title, 200) AS title, left(cl.name, 200) AS club_name, events.start_at, events.end_at, events.sold_count, events.capacity, events.sales_paused,
                events.ticket_price_cents, events.sales_open_at, events.sales_close_at, ${VIP_OD_CENTOV} AS vip_from_cents
           FROM events JOIN clubs cl ON cl.id = events.club_id
          WHERE events.status = 'published' AND NOT cl.hidden
            AND ((events.start_at >= $1::timestamptz - INTERVAL '12 hours' AND events.start_at <= $1::timestamptz + INTERVAL '24 hours')
              OR (events.start_at <= $1::timestamptz AND COALESCE(events.end_at, events.start_at + INTERVAL '12 hours') > $1::timestamptz))
          ORDER BY events.start_at, events.id LIMIT 50`, [t.cas])).rows;
      const vstopi = new Map();
      if (ev.length) {
        const v = await c.query(
          `SELECT t.event_id, COUNT(*)::int AS vstopi, COUNT(*) FILTER (WHERE t.used_at > $2::timestamptz - INTERVAL '15 minutes')::int AS vstopi_15min
             FROM tickets t WHERE t.event_id = ANY($1::int[]) AND t.status = 'used' GROUP BY t.event_id`, [ev.map((e) => e.id), t.cas]);
        for (const x of v.rows) vstopi.set(x.event_id, x);
      }
      const zdaj = new Date(t.cas).getTime();
      const nocoj = ev.map((e) => {
        const x = vstopi.get(e.id);
        return { id: e.id, naslov: e.title, klub: e.club_name, start_at: new Date(e.start_at).toISOString(), prodano: e.sold_count, kapaciteta: e.capacity,
          vstopi: x ? x.vstopi : 0, vstopi_15min: x ? x.vstopi_15min : 0, prodaja: prodajnoStanje(e, zdaj) };
      });

      const r = (await c.query(
        `SELECT COUNT(*) FILTER (WHERE izdan_at >= $1 AND izdan_at < $2)::int AS izdani_danes,
                COUNT(*) FILTER (WHERE stanje = 'caka')::int AS caka, COUNT(*) FILTER (WHERE stanje = 'napaka')::int AS napaka FROM racuni`,
        [t.danes_od, t.jutri_od])).rows[0];
      return { cas: new Date(t.cas).toISOString(), prodaja, nocoj, racuni: r, opozorila_rdeca: rdeca };
    });
  }
  const danes = () => predpomni("danes", izracunajDanes);

  router.get("/danes", async (req, res) => {
    try {
      res.set("Cache-Control", "no-store");
      return res.json(await danes());
    } catch (e) { return odgovoriNapaka(res, e, "GET /admin/api/danes"); }
  });

  // Za agenta (agent_api.js, #330): ISTI izracun, a prek LASTNEGA bralca (brez admin semaforja) in z LASTNIM predpomnilnikom (kljuc »agent:…«): agent nikoli ne zasede
  // povezave plosce in je ne caka. Stranskega ucinka »zadnji rdeci« (summary) agent ne sprozi.
  // `kavlji.zacni/konec`: agent_api.js steje tekoca branja (semafor agenta se sprosti sele, ko se vsa branja zakljucijo).
  function zaAgenta(kavlji = {}) {
    const bere = (fn) => {
      if (kavlji.zacni) kavlji.zacni();
      return Promise.resolve(beriAgent(fn)).finally(() => { if (kavlji.konec) kavlji.konec(); });
    };
    const opozorilaAgent = () => predpomni("agent:opozorila", () => izracunajOpozorila(null, bere));
    return {
      beri: bere,
      opozorila: opozorilaAgent,
      danes: () => predpomni("agent:danes", () => izracunajDanes(null, bere, opozorilaAgent)),
      racuni: (stanje, limit) => racuniSeznam(stanje, limit, bere),
      odgovoriNapaka,
    };
  }
  return { opozorila, danes, danesNaCas: izracunajDanes, rdeceStevilo, racuni: racuniSeznam, zaAgenta };
}

module.exports = { ustvari, ociscenaNapaka, prodajnoStanje, STANJA_RACUNOV };
