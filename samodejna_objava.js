"use strict";
// Samodejna objava osnutka ob casu (#327, migracija 062, invarianta I59; nacrt outly-hq docs/ideje/2026-10-23-admin-panel-nadgradnja.md 2.5).
//
// Delavec vsako minuto (SAMODEJNA_OBJAVA_MS, 0 = izklop) objavi osnutke, katerih `events.publish_at` je minil. Pravila (vsako ima test v test_samodejna_objava.js):
//  - ENA kratka poizvedba za kandidate (delni indeks events_publish_at_idx), nato na kandidata ena transakcija: `FOR NO KEY UPDATE SKIP LOCKED` + UPDATE v ENEM stavku.
//    Vec instanc (Render ob deployu, vec procesov): vrstico objavi natanko ena, ostale jo preskocijo ali ji ob COMMIT-u vidijo status 'published' (READ COMMITTED
//    ponovno oceni pogoj). Vrstica, ki jo drzi nakup, PATCH ali odpoved, se PRESKOCI (ne caka: SKIP LOCKED) in pride na vrsto v naslednjem krogu.
//  - SAMO glavni `pool`, NIKOLI `skenPool` (I16): vsaka transakcija ima lock_timeout 1 s, statement_timeout 5 s, idle_in_transaction_session_timeout, vsaka poizvedba
//    pa se odjemalski rok (obvisela TCP povezava se zavrze, ne zasede poola). Najvec KANDIDATOV_NA_KROG dogodkov na krog.
//  - Objavi se SAMO tisto, kar bi se lahko objavilo rocno: status 'draft' (odpovedan in izbrisan dogodek ne), dogodek se NI zacel (zacetek v preteklosti: nobenega
//    »novega dogodka« za nekaj, kar ze poteka; prodaja se ob zacetku tako ali tako zapre), in pregled »Pred objavo« (isti izracun kot GET /admin/api/opozorila?dogodek=ID)
//    nima rdece ovire (isto pravilo kot gumb »Objavi« v panelu). Ce pregled ne uspe (napaka, rok), dogodek OSTANE osnutek (fail-closed). Neobjavljen dogodek javlja rdece
//    opozorilo `objava_zamujena` v /admin/api/opozorila (admin_nadzor.js), dokler publish_at ne izbrisemo, dogodka ne objavimo ali ne mine.
//  - Po COMMIT-u (kot rocna objava): izpraznitev predpomnilnikov in obvestilo sledilcem. Napaka obvestila ali pusha dogodka NE vrne v osnutek (I29): dogodek je ze objavljen.
//  - admin_dejanja `event.publish_auto` v ISTI transakciji kot objava (brez admina: admin_user_id NULL).
//  - Odjemalci in javni odgovori publish_at ne vidijo.

const KANDIDATOV_NA_KROG = 20;
const ROK_ODJEMALCA_MS = 8000;       // odjemalski rok ene poizvedbe (strezniski rok je 5 s); po izteku se povezava zavrze
const OPOMBA_PONOVI_MS = 10 * 60 * 1000;   // isti razlog zavrnitve istega dogodka se v dnevnik zapise najvec enkrat na 10 min

function ustvari(dep) {
  const { pool, opozorilaDogodka, zapisiAdminDejanje, naObjavljen } = dep;
  const log = dep.log || console;
  const opombe = new Map();   // "id|razlog" -> cas zadnjega zapisa

  function opomba(id, razlog) {
    const k = id + "|" + razlog, zdaj = Date.now();
    if (opombe.size > 500) opombe.clear();
    if (opombe.has(k) && zdaj - opombe.get(k) < OPOMBA_PONOVI_MS) return;
    opombe.set(k, zdaj);
    log.log(`[samodejna-objava] dogodek ${id} ostane osnutek: ${razlog}`);
  }

  // Poizvedba z odjemalskim rokom; ob izteku vrne napako z oznako `rok`, klicatelj povezavo zavrze (release(true)).
  function qRok(c, sql, params) {
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(Object.assign(new Error("samodejna objava: poizvedba timed out (odjemalski rok)"), { rok: true })), ROK_ODJEMALCA_MS);
      let p;
      try { p = params === undefined ? c.query(sql) : c.query(sql, params); } catch (e) { clearTimeout(t); reject(e); return; }
      Promise.resolve(p).then((r) => { clearTimeout(t); resolve(r); }, (e) => { clearTimeout(t); reject(e); });
    });
  }

  // Ena transakcija z mejami. fn dobi { q }. Vrne rezultat fn; napake se propagirajo (COMMIT/ROLLBACK urejen tu).
  async function vTransakciji(fn) {
    const c = await pool.connect();
    let pokvarjena = false;
    const naNapako = () => { pokvarjena = true; };
    c.on("error", naNapako);
    try {
      await qRok(c, "BEGIN; SET LOCAL lock_timeout = '1s'; SET LOCAL statement_timeout = '5s'; SET LOCAL idle_in_transaction_session_timeout = '10s'");
      try {
        const r = await fn((sql, params) => qRok(c, sql, params));
        await qRok(c, "COMMIT");
        return r;
      } catch (e) {
        if (e && e.rok) pokvarjena = true;
        else await qRok(c, "ROLLBACK").catch(() => { pokvarjena = true; });
        throw e;
      }
    } catch (e) {
      if (e && e.rok) pokvarjena = true;
      throw e;
    } finally {
      c.off("error", naNapako);
      if (pokvarjena) c.on("error", () => {});
      c.release(pokvarjena);
    }
  }

  // Kandidati: osnutki z minulim publish_at (delni indeks). Navadno branje: ne caka na zaklepe vrstic, caka le na ACCESS EXCLUSIVE (migracija; lock_timeout).
  async function kandidati() {
    return vTransakciji(async (q) => (await q(
      `SELECT id FROM events WHERE status = 'draft' AND publish_at IS NOT NULL AND publish_at <= NOW() ORDER BY publish_at, id LIMIT ${KANDIDATOV_NA_KROG}`)).rows.map((r) => r.id));
  }

  // Pregled »Pred objavo«: true = je rdeca ovira ali pregled ni uspel (dogodek ostane osnutek).
  async function ovira(id) {
    let odg;
    try { odg = await opozorilaDogodka(id); }
    catch (e) { return `pregled pred objavo ni uspel (${String((e && (e.code || e.message)) || e).slice(0, 80)})`; }
    if (!odg || !Array.isArray(odg.items)) return "pregled pred objavo je vrnil neveljaven odgovor";
    const rdeca = odg.items.filter((o) => o && o.resnost === "rdece");
    return rdeca.length ? `rdeca ovira pred objavo (${rdeca.map((o) => o.vrsta).slice(0, 3).join(", ")})` : null;
  }

  // Atomarna objava enega kandidata. Vrne { id, club_id, ... } ali null (zaklenjen, ze objavljen, preklican, zacet). Pogoji so v ISTEM stavku kot UPDATE.
  async function objavi(id) {
    return vTransakciji(async (q) => {
      const r = await q(
        `WITH k AS (
           SELECT id, club_id, publish_at FROM events
            WHERE id = $1 AND status = 'draft' AND publish_at IS NOT NULL AND publish_at <= NOW() AND start_at > NOW()
              FOR NO KEY UPDATE SKIP LOCKED)
         UPDATE events e SET status = 'published', publish_at = NULL FROM k WHERE e.id = k.id
         RETURNING e.id, e.club_id, k.publish_at AS prej_objava`, [id]);
      if (!r.rows.length) return null;
      const x = r.rows[0];
      // brez admina: req.user brez userId -> admin_user_id NULL; brez predloga agenta
      const prejCas = x.prej_objava instanceof Date ? x.prej_objava.toISOString() : x.prej_objava;
      await zapisiAdminDejanjeSistem(q, "event.publish_auto", x.id, { status: "draft", publish_at: prejCas }, { status: "published", publish_at: null });
      return x;
    });
  }
  // zapisiAdminDejanje (index.js) sprejme povezavo z .query(); tu imamo q(sql, params) z rokom.
  const zapisiAdminDejanjeSistem = (q, dejanje, id, prej, potem) =>
    zapisiAdminDejanje({ query: q }, { user: {}, predlog: null }, dejanje, "event", id, prej, potem);

  let tece = false;
  // En krog delavca. Vrne { objavljenih, preskocenih } (test). Nikoli ne vrze.
  async function krog() {
    if (tece) return { objavljenih: 0, preskocenih: 0, tece: true };
    tece = true;
    let objavljenih = 0, preskocenih = 0;
    try {
      let ids;
      try { ids = await kandidati(); }
      catch (e) { log.error("[samodejna-objava] kandidatov ni mogoce prebrati:", (e && (e.code || e.message)) || e); return { objavljenih, preskocenih, napaka: true }; }
      for (const id of ids) {
        try {
          const razlog = await ovira(id);
          if (razlog) { opomba(id, razlog); preskocenih++; continue; }
          const x = await objavi(id);
          if (!x) { opomba(id, "zaklenjen, ze objavljen, preklican ali zacet"); preskocenih++; continue; }   // zaklenjen (nakup/PATCH v teku), ze objavljen drugje, preklican ali zacet: naslednji krog
          objavljenih++;
          log.log(`[samodejna-objava] dogodek ${x.id} objavljen (nacrtovana objava ob ${x.prej_objava instanceof Date ? x.prej_objava.toISOString() : x.prej_objava})`);
          // PO COMMIT-u, kot rocna objava; napaka ne vrne dogodka v osnutek (I29)
          try { await naObjavljen(x.id, x.club_id); }
          catch (e) { log.error("[samodejna-objava] obvestilo po objavi ni uspelo (dogodek ostane objavljen):", (e && e.message) || e); }
        } catch (e) {
          preskocenih++;
          log.error(`[samodejna-objava] dogodek ${id}: ${(e && (e.code || e.message)) || e}`);   // zaklep (55P03), rok, povezava: naslednji krog
        }
      }
    } finally { tece = false; }
    return { objavljenih, preskocenih };
  }

  // Zagon z intervalom; prvi krog ne takoj po zagonu (glavni pool je takrat najbolj zaseden: prvi nakupi, health check) in z nakljucnim zamikom (vec instanc).
  function zazeni(ms) {
    if (!(ms > 0)) return null;
    let interval = null;
    const prvi = setTimeout(() => { void krog(); interval = setInterval(() => { void krog(); }, ms); interval.unref(); },
      Math.min(ms, 20000) + Math.round(Math.random() * Math.min(ms, 10000)));
    prvi.unref();
    return { ustavi: () => { clearTimeout(prvi); if (interval) clearInterval(interval); } };
  }

  return { krog, zazeni, kandidati, ovira, objavi };
}

module.exports = { ustvari, KANDIDATOV_NA_KROG };
