"use strict";
// Samodejna dnevna uskladitev Stripe <-> baza (Martin 27. 10. 2026, nadaljevanje #374 tocka 2; migracija 073, invarianta I67).
//
// Kaj: enkrat na dan primerja ZAPRT dan (koledarski dan po Europe/Ljubljana) -- Stripove naboje (charges), vracila (refunds) in spore (disputes) z bazo (orders, spori) --
// in rezultat zapise v `stripe_uskladitve` (ena vrstica na dan). Razlika = rdece opozorilo `stripe_razlika`, izpad Stripa = oranzno `stripe_uskladitev_napaka`
// (admin_nadzor.js, isti izracun za /admin/api/opozorila, /danes in /agent/api/opozorila). Pise SAMO v svojo tabelo; Stripu nikoli ne pise (samo GET).
//
// Kdaj: delavec s korakom 30 min (STRIPE_USKLADITEV_TIK_MS), prvi krog 2-10 min po zagonu procesa (nakljucen zamik: vec instanc, ob deployu ne obremeni zagona).
// Vsak krog obdela najvec 4 dni izmed zadnjih 7 (OKNO_DNI) brez uspesne uskladitve, najstarejsi najprej: vceraj sele po 04:00 ljubljanskega casa (webhooki in
// pospravljalec so takrat ze poravnali dan), starejsi manjkajoci dnevi takoj (dohitevanje po izpadu/deployu). Nikoli dan pred zacetkom zivega nacina (ZIVO_OD, 19. 10. 2026).
// Teče samo, ko je Stripe kljuc ZIV (jeLive(): sandbox/lazni nacin ni promet) in je delavec vklopljen: na Renderju (RENDER, ga nastavi Render sam) ali STRIPE_USKLADITEV=1;
// STRIPE_USKLADITEV=0 izklopi. NODE_ENV=production sam ne vklopi (eksplicitno je varneje: lokalen/CI zagon s production + zivim kljucem ne sme sam klicati Stripa).
//
// Ena izvedba na dan, tudi ob vec instancah: zahtevek vrstice dneva je en atomaren stavek (INSERT ... ON CONFLICT DO UPDATE ... WHERE): zmaga natanko en proces, ostali
// dobijo 0 vrstic. Vrstica je 'tece'; zastarela (> 15 min, proces je umrl) ali 'napaka' starejsa od 3 h se prevzame. Konec zapisa je pogojen s stevilko poskusa, zato
// zakasnel stari proces ne povozi novejsega. Namenoma NE pg_advisory_lock: sejna kljucavnica bi morala ves cas Stripovih klicev drzati eno povezavo glavnega poola (in
// ne preživi pooler v transakcijskem nacinu); vrstica dela isto brez povezave.
//
// Ne sme ogroziti skena in nakupov (outly-hq »Zanesljivost«, I16): SAMO glavni pool (nikoli skenPool), vsaka DB transakcija je kratka (READ ONLY, statement_timeout 5 s, lock_timeout 1 s,
// odjemalski rok 8 s) in ne drzi zaklepov vrstic; Stripovi klici tecejo ZUNAJ transakcije in brez povezave iz poola, vsak z rokom (15 s), najvec 150 klicev in 4 min na krog,
// najvec 30 strani po 100 na seznam. Napaka ali izpad Stripa = vrstica 'napaka' (koda, nikoli besedilo napake) + nov poskus po 3 h; krog NIKOLI ne vrze (proces ne sme pasti).
//
// Primerjava dneva D (naboji so na platformnem racunu: Connect destination charges in lastni dogodki Outly, I50):
//  - Stripe: naboji `succeeded` in ne-zadrzani, ustvarjeni v D (created); vracila in spori, ustvarjeni v D.
//  - Baza: narocila `paid|partially_refunded|refunded`, brez guest liste, brez 0 EUR, brez testnega prometa (SQL_TESTNO_NAROCILO, I39), `paid_at` v D.
//    Cas = paid_at (ne created_at kot v /finance): narocilo nastane ob zacetku Checkouta in placilo pride do 30 min pozneje, Stripov `created` pa je trenutek placila;
//    paid_at ga zadene na sekundo natancno. Naboj ob polnoci se lahko zapise v sosednji dan (webhook je nekaj sekund pozneje): zato se vsak naboj in vsako narocilo, ki ga v D
//    nima par, iskanje po PaymentIntentu (ne po dnevu); najdeni par izven D je `mejni_stevilo`, ne razlika.
//  - Po narocilu (par prek payment_intent <-> orders.stripe_payment_intent_id, sicer prek metadata.order_id): (a) placilo brez placanega narocila, (b) placano narocilo brez
//    placila, (c) znesek/valuta/provizija (c), (d) refunded_cents proti charge.amount_refunded (tudi za stare naboje, vrnjene v D), (e) spor v Stripu brez vrstice v `spori`
//    (in obratno, in razlicno stanje/znesek).
//    Izjema od (a): naboj za narocilo, ki ga je zakljuci() preklical in v CELOTI vrnil (`cancelled|failed` + vrstica `vracila` z razlogom `inactive_order`, stanje `opravljeno`, isti PI + amount_refunded >= amount),
//    je pricakovan izid, ne razlika (steje se v `vrnjeno_neaktivno_stevilo` rezultata in dnevniku). Delno vrnjeno ali brez vrstice `vracila` ostane razlika.
//  - Vsote (informativno): stevilo, bruto, vrnjeno, provizija; Stripova vracila in spori dneva.

const ZIVO_OD = /^\d{4}-\d{2}-\d{2}$/.test(process.env.STRIPE_USKLADITEV_OD || "") ? process.env.STRIPE_USKLADITEV_OD : "2026-10-19";
const OKNO_DNI = 7;
const PO_URI = 4;                       // vceraj se uskladi sele po 04:00 ljubljanskega casa
const DNI_NA_KROG = 4;
const NAJVEC_STRANI = 30;
const NAJVEC_KLICEV = 150;
const NAJVEC_DODATNIH = 100;            // stari naboji, vrnjeni v D
const NAJVEC_PREVERB = 50;              // ciljana iskanja po PaymentIntentu / sporu
const NAJVEC_RAZLIK = 100;              // vrstic v JSONB (razlike_stevilo je polno)
const STRIPE_ROK_MS = 15000;
const KROG_ROK_MS = 4 * 60 * 1000;      // celoten dan
const DB_ROK_MS = 8000;                 // odjemalski rok ene poizvedbe (strezniski rok je 5 s)
const PONOVI_NAPAKO_URE = 3;
const PREVZEM_MIN = 15;
const PLACANO = ["paid", "partially_refunded", "refunded"];
const VRACILO_ZAVRNJENO = ["failed", "canceled"];
const LJ = "Europe/Ljubljana";

const koda = (k) => Object.assign(new Error(k), { koda: k });
const ociscena = (v) => String(v).replace(/[^A-Za-z0-9_.-]/g, "_").slice(0, 60);
// Kratka koda napake brez besedila (Stripovo besedilo lahko vsebuje del kljuca).
function kodaNapake(e) {
  if (!e) return "neznana";
  if (e.koda) return ociscena(e.koda);
  const t = e.type || e.rawType || e.code || e.name;
  return ociscena(`${t || "napaka"}${Number.isInteger(e.statusCode) ? "_" + e.statusCode : ""}`);
}
const idOd = (v) => (typeof v === "string" ? v : (v && v.id) || null);
const celo = (v) => (Number.isFinite(Number(v)) ? Math.round(Number(v)) : 0);
const veljavenDan = (s) => {
  if (typeof s !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const t = Date.parse(s + "T00:00:00Z");
  return Number.isFinite(t) && new Date(t).toISOString().slice(0, 10) === s;   // 2026-13-01 ali 2026-02-30: Invalid Date ali preliv v naslednji mesec
};

function ustvari(dep) {
  const { pool, SQL_TESTNO_NAROCILO: T } = dep;
  const stripe = dep.stripe;
  const jeLive = dep.jeLive;
  const log = dep.log || console;
  const odgovoriNaNapako = dep.odgovoriNaNapako;
  const dbRok = Number.isInteger(dep.dbRokMs) && dep.dbRokMs > 0 ? dep.dbRokMs : DB_ROK_MS;   // samo za teste (lazni pool); produkcija vedno DB_ROK_MS
  const vklopljena = dep.vklopljena || (() => process.env.STRIPE_USKLADITEV === "1" || (process.env.STRIPE_USKLADITEV !== "0" && !!process.env.RENDER));

  // --- baza: kratke transakcije z mejami; odjemalski rok (obvisela povezava se zavrze, ne zasede poola) ---
  function qRok(c, sql, params) {
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(Object.assign(new Error("uskladitev: poizvedba timed out"), { koda: "db_rok", rok: true })), dbRok);
      let p;
      try { p = params === undefined ? c.query(sql) : c.query(sql, params); } catch (e) { clearTimeout(t); reject(e); return; }
      Promise.resolve(p).then((r) => { clearTimeout(t); resolve(r); }, (e) => { clearTimeout(t); reject(e); });
    });
  }
  // Povezava gre nazaj v glavni pool (release(false)) SAMO, ko je zanesljivo znano, da je cista: transakcija se je koncala z COMMIT ali ROLLBACK, ki je uspel.
  // Vsaka druga pot (rok ali napaka ze pri BEGIN/SET, rok pri fn/COMMIT/ROLLBACK, `error` na povezavi) = release(true): povezava se uniči. Prej je bila privzeta
  // vrednost »cista«, zato je rok pri BEGIN (prvi stavek je viselo) vrnil povezavo z odprto/neznano transakcijo v pool, kjer jo je lahko dobil nakup ali webhook.
  async function vTx(fn, pisi = false) {
    const c = await pool.connect();
    let pokvarjena = false, cista = false;
    const naNapako = () => { pokvarjena = true; };
    c.on("error", naNapako);
    try {
      await qRok(c, `BEGIN${pisi ? "" : " READ ONLY"}; SET LOCAL statement_timeout = '5s'; SET LOCAL lock_timeout = '1s'; SET LOCAL idle_in_transaction_session_timeout = '10s'`);
      try {
        const r = await fn((sql, params) => qRok(c, sql, params));
        await qRok(c, "COMMIT");
        cista = true;
        return r;
      } catch (e) {
        if (!(e && e.rok)) { try { await qRok(c, "ROLLBACK"); cista = true; } catch (_) { /* ostane cista = false */ } }
        throw e;
      }
    } finally {
      c.removeListener("error", naNapako);
      c.release(pokvarjena || !cista);
    }
  }

  // --- Stripe: samo GET, vsak klic z rokom, stevec klicev in skupen rok dneva ---
  function novaSeja() {
    const s = { klicev: 0, rok: Date.now() + KROG_ROK_MS };
    s.klic = async (fn) => {
      if (++s.klicev > NAJVEC_KLICEV) throw koda("meja_klicev");
      if (Date.now() > s.rok) throw koda("rok_dneva");
      return fn({ timeout: STRIPE_ROK_MS, maxNetworkRetries: 1 });
    };
    s.strani = async (klicSeznama, params) => {
      const vse = [];
      let po = null;
      for (let i = 0; i < NAJVEC_STRANI; i++) {
        const r = await s.klic((o) => klicSeznama({ ...params, limit: 100, ...(po ? { starting_after: po } : {}) }, o));
        const data = r && Array.isArray(r.data) ? r.data : [];
        vse.push(...data);
        if (!r || !r.has_more) return vse;
        if (!data.length) throw koda("prazna_stran");
        po = data[data.length - 1].id;
      }
      throw koda("meja_strani");
    };
    return s;
  }

  const jePlacan = (ch) => !!ch && ch.status === "succeeded" && ch.paid !== false && ch.captured !== false;

  // Preverba enega naboja proti narocilu. `polno` = tudi znesek/valuta/provizija; vedno vracilo (d). Doda razlike v `r`.
  function preveri(ch, o, polno, r) {
    const osnova = { narocilo_id: Number(o.id), charge_id: ch.id };
    if (polno) {
      const valutaS = String(ch.currency || "").toUpperCase(), valutaB = String(o.currency || "").trim().toUpperCase();
      if (celo(ch.amount) !== celo(o.total_cents) || valutaS !== valutaB) {
        r({ vrsta: "znesek_ali_valuta", ...osnova, stripe_cents: celo(ch.amount), baza_cents: celo(o.total_cents), stripe_valuta: valutaS, baza_valuta: valutaB });
      }
      if (typeof ch.application_fee_amount === "number" && ch.application_fee_amount !== celo(o.application_fee_cents)) {
        r({ vrsta: "provizija", ...osnova, stripe_cents: ch.application_fee_amount, baza_cents: celo(o.application_fee_cents) });
      }
    }
    // Baza hrani refunded_cents <= total_cents (CHECK), zato Stripov znesek omejimo na znesek narocila.
    const vrnjenoS = Math.min(celo(ch.amount_refunded), celo(o.total_cents));
    if (vrnjenoS !== celo(o.refunded_cents)) r({ vrsta: "vracilo", ...osnova, stripe_cents: vrnjenoS, baza_cents: celo(o.refunded_cents) });
  }

  // Izracun enega dne (brez zapisa). Vrne { stanje, razlike, vsote... }. Vrze samo z `koda` (Stripe/baza/meje).
  async function izracunaj(dan) {
    const S = novaSeja();
    const s = stripe();
    if (!s) throw koda("brez_stripa");
    const m = (await vTx((q) => q(
      `SELECT extract(epoch FROM ($1::date)::timestamp AT TIME ZONE '${LJ}')::float8 AS t0,
              extract(epoch FROM (($1::date + 1))::timestamp AT TIME ZONE '${LJ}')::float8 AS t1`, [dan]))).rows[0];
    const t0 = Math.round(m.t0), t1 = Math.round(m.t1);
    const created = { gte: t0, lt: t1 };

    // 1. faza (Stripe, zunaj transakcije)
    const naboji = (await S.strani((p, o) => s.charges.list(p, o), { created })).filter(jePlacan);
    const vracila = (await S.strani((p, o) => s.refunds.list(p, o), { created })).filter((v) => !VRACILO_ZAVRNJENO.includes(v.status));
    const spori = await S.strani((p, o) => s.disputes.list(p, o), { created });
    const znani = new Set(naboji.map((x) => x.id));
    const dodatniIds = [...new Set(vracila.map((v) => idOd(v.charge)).filter((id) => id && !znani.has(id)))];
    if (dodatniIds.length > NAJVEC_DODATNIH) throw koda("meja_dodatnih");
    const dodatni = [];
    for (const id of dodatniIds) {
      const ch = await S.klic((o) => s.charges.retrieve(id, {}, o));
      if (jePlacan(ch)) dodatni.push(ch);
    }

    // 2. faza (baza, ena kratka READ ONLY transakcija)
    const pis = [...new Set([...naboji, ...dodatni].map((x) => idOd(x.payment_intent)).filter(Boolean))];
    const oids = [...new Set([...naboji, ...dodatni].map((x) => x.metadata && /^\d{1,15}$/.test(String(x.metadata.order_id || "")) ? String(x.metadata.order_id) : null).filter(Boolean))];
    const sporIds = spori.map((x) => x.id).filter(Boolean);
    const baza = await vTx(async (q) => {
      const B = await q(
        `SELECT o.id, o.status, o.total_cents, o.currency, o.refunded_cents, o.application_fee_cents, o.stripe_payment_intent_id AS pi
           FROM orders o
          WHERE o.status IN ('paid','partially_refunded','refunded') AND o.guest_list_id IS NULL AND o.total_cents > 0 AND NOT ${T}
            AND o.paid_at >= to_timestamp($1) AND o.paid_at < to_timestamp($2)
          ORDER BY o.id`, [t0, t1]);
      const O = await q(
        `SELECT o.id, o.status, o.total_cents, o.currency, o.refunded_cents, o.application_fee_cents, o.stripe_payment_intent_id AS pi,
                (o.paid_at >= to_timestamp($3) AND o.paid_at < to_timestamp($4)) AS v_dnevu, ${T} AS testno,
                (SELECT vr.payment_intent_id FROM vracila vr WHERE vr.order_id = o.id AND vr.razlog = 'inactive_order' AND vr.stanje = 'opravljeno') AS vrnjeno_neaktivno_pi
           FROM orders o WHERE o.stripe_payment_intent_id = ANY($1::text[]) OR o.id = ANY($2::bigint[])`, [pis, oids, t0, t1]);
      const P = await q(
        `SELECT id, stanje, znesek_cents, valuta, (ustvarjen_at >= to_timestamp($2) AND ustvarjen_at < to_timestamp($3)) AS v_dnevu
           FROM spori WHERE id = ANY($1::text[]) OR (ustvarjen_at >= to_timestamp($2) AND ustvarjen_at < to_timestamp($3))`, [sporIds, t0, t1]);
      return { B: B.rows, O: O.rows, P: P.rows };
    });

    // 3. izracun
    const razlike = [];
    let razlikeSkupaj = 0, mejni = 0, vrnjenoNeaktivno = 0;
    const r = (x) => { razlikeSkupaj++; if (razlike.length < NAJVEC_RAZLIK) razlike.push(x); };
    const poPi = new Map(), poId = new Map();
    for (const o of baza.O) { if (o.pi) poPi.set(o.pi, o); poId.set(String(o.id), o); }
    const poIdB = new Map(baza.B.map((o) => [String(o.id), o]));
    const sparjena = new Set();   // id narocil iz D, ki so dobila par med naboji D

    for (const ch of naboji) {
      const pi = idOd(ch.payment_intent);
      const oid = ch.metadata && /^\d{1,15}$/.test(String(ch.metadata.order_id || "")) ? String(ch.metadata.order_id) : null;
      const o = (pi && poPi.get(pi)) || (oid && poId.get(oid)) || null;
      const osnova = { charge_id: ch.id, ...(pi ? { payment_intent: pi } : {}) };
      if (!o) { r({ vrsta: "placilo_brez_narocila", ...osnova, ...(oid ? { metadata_narocilo_id: Number(oid) } : {}), stripe_cents: celo(ch.amount), stripe_valuta: String(ch.currency || "").toUpperCase() }); continue; }
      if (!PLACANO.includes(o.status)) {
        // Nasa avtomatika (placila_stripe.js zakljuci() -> vrniNeaktivno(), vracila_stripe.js): placilo za preklicano/neuspelo narocilo je bilo v CELOTI vrnjeno
        // (vrstica `vracila` z razlogom `inactive_order` + Stripov amount_refunded >= amount). To je pricakovan izid, ne razlika. Delno vrnjeno, vrstice `vracila` ali
        // drugo stanje narocila (npr. pending) ostane razlika. Vrstica mora biti `opravljeno` (nase vracilo je uspelo; rocno vracilo v Stripu ali `caka`/`ni_uspelo` ostane
        // razlika) in za ISTI PaymentIntent kot naboj (drug PI istega narocila ni pokrit z naso vrstico). UNIQUE (order_id, razlog) -> najvec ena vrstica.
        if (["cancelled", "failed"].includes(o.status) && pi && o.vrnjeno_neaktivno_pi === pi && celo(ch.amount) > 0 && celo(ch.amount_refunded) >= celo(ch.amount)) { vrnjenoNeaktivno++; continue; }
        r({ vrsta: "placilo_brez_placanega_narocila", ...osnova, narocilo_id: Number(o.id), stanje_narocila: o.status, stripe_cents: celo(ch.amount), stripe_valuta: String(ch.currency || "").toUpperCase(),
            v_celoti_vrnjeno: celo(ch.amount_refunded) >= celo(ch.amount) });
        continue;
      }
      if (o.testno === true) { r({ vrsta: "placilo_za_testno_narocilo", ...osnova, narocilo_id: Number(o.id), stripe_cents: celo(ch.amount) }); continue; }
      sparjena.add(String(o.id));
      if (o.v_dnevu !== true) mejni++;
      preveri(ch, o, true, r);
    }

    // narocila iz D brez para med naboji D: ciljano iskanje po PaymentIntentu (naboj iz sosednjega dne ob polnoci, odlozeno placilo)
    const brezPara = baza.B.filter((o) => !sparjena.has(String(o.id)));
    let preverb = 0;
    for (const o of brezPara) {
      if (!o.pi) { r({ vrsta: "naroceno_brez_placila", narocilo_id: Number(o.id), baza_cents: celo(o.total_cents), razlog: "brez_payment_intent" }); continue; }
      if (preverb >= NAJVEC_PREVERB) { r({ vrsta: "naroceno_brez_placila", narocilo_id: Number(o.id), payment_intent: o.pi, baza_cents: celo(o.total_cents), razlog: "nepreverjeno_meja" }); continue; }
      preverb++;
      const najdeni = (await S.klic((opt) => s.charges.list({ payment_intent: o.pi, limit: 10 }, opt)));
      const ch = najdeni && Array.isArray(najdeni.data) ? najdeni.data.find(jePlacan) : null;
      if (!ch) { r({ vrsta: "naroceno_brez_placila", narocilo_id: Number(o.id), payment_intent: o.pi, baza_cents: celo(o.total_cents) }); continue; }
      mejni++;
      preveri(ch, o, true, r);
    }

    // stari naboji, vrnjeni v D: samo vracilo (d); placilo je bilo preverjeno na svoj dan
    for (const ch of dodatni) {
      const pi = idOd(ch.payment_intent);
      const oid = ch.metadata && /^\d{1,15}$/.test(String(ch.metadata.order_id || "")) ? String(ch.metadata.order_id) : null;
      const o = (pi && poPi.get(pi)) || (oid && poId.get(oid)) || null;
      if (!o) { r({ vrsta: "placilo_brez_narocila", charge_id: ch.id, ...(pi ? { payment_intent: pi } : {}), stripe_cents: celo(ch.amount), stripe_valuta: String(ch.currency || "").toUpperCase(), ob_vracilu: true }); continue; }
      if (!PLACANO.includes(o.status) || o.testno === true) continue;
      preveri(ch, o, false, r);
    }

    // spori (e)
    const sporBaza = new Map(baza.P.map((p) => [p.id, p]));
    const vStripu = new Set();
    for (const dp of spori) {
      vStripu.add(dp.id);
      const p = sporBaza.get(dp.id);
      if (!p) { r({ vrsta: "spor_brez_vrstice", spor_id: dp.id, charge_id: idOd(dp.charge), stripe_stanje: String(dp.status || ""), stripe_cents: celo(dp.amount) }); continue; }
      const valutaS = String(dp.currency || "").toUpperCase(), valutaB = p.valuta ? String(p.valuta).trim().toUpperCase() : null;
      if (p.stanje !== String(dp.status || "unknown").slice(0, 40) || celo(p.znesek_cents) !== celo(dp.amount) || (valutaB && valutaB !== valutaS)) {
        r({ vrsta: "spor_stanje", spor_id: dp.id, stripe_stanje: String(dp.status || ""), baza_stanje: p.stanje, stripe_cents: celo(dp.amount), baza_cents: celo(p.znesek_cents) });
      }
    }
    let sporPreverb = 0;
    for (const p of baza.P) {
      if (p.v_dnevu !== true || vStripu.has(p.id)) continue;
      if (sporPreverb++ >= NAJVEC_PREVERB) { r({ vrsta: "spor_samo_v_bazi", spor_id: p.id, razlog: "nepreverjeno_meja" }); continue; }
      try { await S.klic((o) => s.disputes.retrieve(p.id, {}, o)); }
      catch (e) {
        if (e && e.statusCode === 404 || (e && e.code === "resource_missing")) { r({ vrsta: "spor_samo_v_bazi", spor_id: p.id, baza_stanje: p.stanje, baza_cents: celo(p.znesek_cents) }); continue; }
        throw e;
      }
      // obstaja, a ga seznam za D ni vrnil (npr. `created` v drugem dnevu): ni razlika
    }

    const vsota = (a, f) => a.reduce((n, x) => n + f(x), 0);
    return {
      stanje: razlikeSkupaj ? "razlike" : "ok", razlike, razlike_stevilo: razlikeSkupaj, mejni_stevilo: mejni, vrnjeno_neaktivno_stevilo: vrnjenoNeaktivno,
      stripe_stevilo: naboji.length, stripe_bruto_cents: vsota(naboji, (x) => celo(x.amount)), stripe_vrnjeno_cents: vsota(naboji, (x) => celo(x.amount_refunded)),
      stripe_provizija_cents: vsota(naboji, (x) => (typeof x.application_fee_amount === "number" ? x.application_fee_amount : 0)),
      stripe_vracila_stevilo: vracila.length, stripe_vracila_cents: vsota(vracila, (x) => celo(x.amount)), stripe_spori_stevilo: spori.length,
      baza_stevilo: baza.B.length, baza_bruto_cents: vsota(baza.B, (x) => celo(x.total_cents)), baza_vrnjeno_cents: vsota(baza.B, (x) => celo(x.refunded_cents)),
      baza_provizija_cents: vsota(baza.B, (x) => celo(x.application_fee_cents)), baza_spori_stevilo: baza.P.filter((p) => p.v_dnevu === true).length,
    };
  }

  // Zahtevek dneva (atomaren): vrne stevilko poskusa ali null (drug proces ga ima / je ze opravljen).
  async function zahtevaj(dan) {
    const r = await vTx((q) => q(
      `INSERT INTO stripe_uskladitve AS u (dan, stanje, poskusov, zacetek_at) VALUES ($1::date, 'tece', 1, NOW())
       ON CONFLICT (dan) DO UPDATE SET stanje = 'tece', poskusov = u.poskusov + 1, zacetek_at = NOW()
        WHERE (u.stanje = 'napaka' AND u.izvedeno_at < NOW() - ($2::int * INTERVAL '1 hour'))
           OR (u.stanje = 'tece' AND u.zacetek_at < NOW() - ($3::int * INTERVAL '1 minute'))
       RETURNING u.poskusov`, [dan, PONOVI_NAPAKO_URE, PREVZEM_MIN]), true);
    return r.rows.length ? r.rows[0].poskusov : null;
  }
  async function zapisi(dan, poskus, x) {
    const r = await vTx((q) => q(
      `UPDATE stripe_uskladitve SET stanje = $3, izvedeno_at = NOW(), napaka_koda = NULL,
              stripe_stevilo = $4, stripe_bruto_cents = $5, stripe_vrnjeno_cents = $6, stripe_provizija_cents = $7, stripe_vracila_stevilo = $8, stripe_vracila_cents = $9, stripe_spori_stevilo = $10,
              baza_stevilo = $11, baza_bruto_cents = $12, baza_vrnjeno_cents = $13, baza_provizija_cents = $14, baza_spori_stevilo = $15,
              mejni_stevilo = $16, razlike_stevilo = $17, razlike = $18::jsonb
        WHERE dan = $1::date AND stanje = 'tece' AND poskusov = $2 RETURNING dan`,
      [dan, poskus, x.stanje, x.stripe_stevilo, x.stripe_bruto_cents, x.stripe_vrnjeno_cents, x.stripe_provizija_cents, x.stripe_vracila_stevilo, x.stripe_vracila_cents, x.stripe_spori_stevilo,
       x.baza_stevilo, x.baza_bruto_cents, x.baza_vrnjeno_cents, x.baza_provizija_cents, x.baza_spori_stevilo, x.mejni_stevilo, x.razlike_stevilo, JSON.stringify(x.razlike)]), true);
    return r.rows.length > 0;
  }
  async function zapisiNapako(dan, poskus, k) {
    await vTx((q) => q(
      "UPDATE stripe_uskladitve SET stanje = 'napaka', izvedeno_at = NOW(), napaka_koda = $3 WHERE dan = $1::date AND stanje = 'tece' AND poskusov = $2", [dan, poskus, k]), true);
  }

  // Obdela en dan. Nikoli ne vrze. Vrne { dan, stanje } (ali { dan, preskoceno }).
  async function obdelajDan(dan) {
    if (!veljavenDan(dan)) return { dan, preskoceno: "neveljaven_dan" };
    let poskus = null;
    try {
      poskus = await zahtevaj(dan);
      if (poskus === null) return { dan, preskoceno: "ima_drug_proces" };
      const x = await izracunaj(dan);
      const zapisano = await zapisi(dan, poskus, x);
      if (!zapisano) return { dan, preskoceno: "prevzel_drug_proces" };
      if (x.stanje === "razlike") {
        const vrste = {};
        for (const z of x.razlike) vrste[z.vrsta] = (vrste[z.vrsta] || 0) + 1;
        log.error(`[uskladitev-stripe] POZOR: dan ${dan}: ${x.razlike_stevilo} razlik med Stripom in bazo (${Object.entries(vrste).map(([k, n]) => `${k}: ${n}`).join(", ")}); Stripe ${x.stripe_stevilo} placil / ${x.stripe_bruto_cents} c, baza ${x.baza_stevilo} narocil / ${x.baza_bruto_cents} c. Podrobnosti: GET /admin/api/uskladitve, vrstica v INCIDENTI.`);
      } else {
        log.log(`[uskladitev-stripe] dan ${dan}: ujemanje (Stripe ${x.stripe_stevilo} placil / ${x.stripe_bruto_cents} c, baza ${x.baza_stevilo} narocil / ${x.baza_bruto_cents} c, vrnjeno ${x.stripe_vrnjeno_cents}/${x.baza_vrnjeno_cents} c${x.vrnjeno_neaktivno_stevilo ? `, v celoti vrnjenih placil za neaktivno narocilo (inactive_order): ${x.vrnjeno_neaktivno_stevilo}` : ""})`);
      }
      return { dan, stanje: x.stanje };
    } catch (e) {
      const k = kodaNapake(e);
      log.error(`[uskladitev-stripe] dan ${dan}: ni uspelo (${k}); nov poskus cez ${PONOVI_NAPAKO_URE} h`);
      if (poskus !== null) { try { await zapisiNapako(dan, poskus, k); } catch (e2) { log.error(`[uskladitev-stripe] dan ${dan}: napake ni bilo mogoce zapisati (${kodaNapake(e2)})`); } }
      return { dan, stanje: "napaka", koda: k };
    }
  }

  // Kateri dnevi so na vrsti (najstarejsi najprej).
  async function kandidati() {
    const k = dep.danes ? await dep.danes() : null;
    return vTx(async (q) => {
      const d = k || (await q(`SELECT to_char((NOW() AT TIME ZONE '${LJ}')::date, 'YYYY-MM-DD') AS danes, extract(hour FROM NOW() AT TIME ZONE '${LJ}')::int AS ura`)).rows[0];
      const dnevi = (await q(
        `SELECT to_char(d, 'YYYY-MM-DD') AS dan FROM generate_series($1::date - $2::int, $1::date - 1, '1 day') AS g(d) ORDER BY d`, [d.danes, OKNO_DNI])).rows.map((x) => x.dan);
      const zadnji = dnevi[dnevi.length - 1];
      // Ne na vrsti: opravljen dan, `napaka` mlajsa od 3 h in sveza `tece` (sicer bi trajno neuspesni najstarejsi dnevi zasedli vseh 4 mest kroga in stradali novejse).
      const ze = new Set((await q(
        `SELECT to_char(dan, 'YYYY-MM-DD') AS dan FROM stripe_uskladitve
          WHERE dan >= $1::date - $2::int
            AND (stanje IN ('ok','razlike')
                 OR (stanje = 'napaka' AND izvedeno_at >= NOW() - ($3::int * INTERVAL '1 hour'))
                 OR (stanje = 'tece' AND zacetek_at >= NOW() - ($4::int * INTERVAL '1 minute')))`, [d.danes, OKNO_DNI, PONOVI_NAPAKO_URE, PREVZEM_MIN])).rows.map((x) => x.dan));
      return dnevi.filter((dan) => dan >= ZIVO_OD && !ze.has(dan) && !(dan === zadnji && d.ura < PO_URI));
    });
  }

  let tece = false;
  // En krog delavca. Nikoli ne vrze. Vrne { obdelani: [...], preskoceno? }.
  async function krog() {
    if (tece) return { obdelani: [], preskoceno: "tece" };
    tece = true;
    const obdelani = [];
    try {
      if (!jeLive() || !stripe()) return { obdelani, preskoceno: "ni_zivo" };
      const dnevi = (await kandidati()).slice(0, DNI_NA_KROG);
      for (const dan of dnevi) obdelani.push(await obdelajDan(dan));
      return { obdelani };
    } catch (e) {
      log.error(`[uskladitev-stripe] krog: ${kodaNapake(e)}`);   // baza nedosegljiva ipd.: naslednji krog
      return { obdelani, napaka: kodaNapake(e) };
    } finally { tece = false; }
  }

  function zazeni() {
    if (!vklopljena()) return null;
    const tik = Number.isInteger(Number(process.env.STRIPE_USKLADITEV_TIK_MS)) && Number(process.env.STRIPE_USKLADITEV_TIK_MS) >= 100 ? Number(process.env.STRIPE_USKLADITEV_TIK_MS) : 30 * 60 * 1000;
    const zagon = process.env.STRIPE_USKLADITEV_ZAGON_MS !== undefined && Number.isInteger(Number(process.env.STRIPE_USKLADITEV_ZAGON_MS)) && Number(process.env.STRIPE_USKLADITEV_ZAGON_MS) >= 0
      ? Number(process.env.STRIPE_USKLADITEV_ZAGON_MS) : 120000 + Math.round(Math.random() * 480000);
    let interval = null;
    const prvi = setTimeout(() => { void krog(); interval = setInterval(() => { void krog(); }, tik); interval.unref(); }, zagon);
    prvi.unref();
    return { ustavi: () => { clearTimeout(prvi); if (interval) clearInterval(interval); } };
  }

  // GET /admin/api/uskladitve?od=YYYY-MM-DD&do=YYYY-MM-DD (admin; samo branje, privzeto zadnjih 30 dni, najvec 93 dni). Samo vsote, razlike (ID-ji in centi) in stanje.
  function registriraj(router) {
    router.get("/uskladitve", async (req, res) => {
      try {
        res.set("Cache-Control", "no-store");
        const danes = new Date().toISOString().slice(0, 10);
        const do_ = req.query.do === undefined ? danes : req.query.do;
        const od = req.query.od === undefined ? new Date(Date.parse(do_) - 29 * 864e5).toISOString().slice(0, 10) : req.query.od;
        if (!veljavenDan(do_)) return res.status(400).json({ error: "invalid_to", message: "do must be a date YYYY-MM-DD." });
        if (!veljavenDan(od)) return res.status(400).json({ error: "invalid_from", message: "od must be a date YYYY-MM-DD." });
        if (od > do_) return res.status(400).json({ error: "invalid_range", message: "od must not be after do." });
        if ((Date.parse(do_) - Date.parse(od)) / 864e5 > 92) return res.status(400).json({ error: "range_too_large", message: "The range must be at most 93 days." });
        const rows = (await vTx((q) => q(
          `SELECT to_char(dan, 'YYYY-MM-DD') AS dan, stanje, poskusov, izvedeno_at, stripe_stevilo, stripe_bruto_cents, stripe_vrnjeno_cents, stripe_provizija_cents, stripe_vracila_stevilo,
                  stripe_vracila_cents, stripe_spori_stevilo, baza_stevilo, baza_bruto_cents, baza_vrnjeno_cents, baza_provizija_cents, baza_spori_stevilo, mejni_stevilo, razlike_stevilo,
                  razlike, napaka_koda
             FROM stripe_uskladitve WHERE dan >= $1::date AND dan <= $2::date ORDER BY dan DESC`, [od, do_]))).rows;
        const stevilo = (v) => (v === null || v === undefined ? null : Number(v));
        const items = rows.map((x) => {
          const o = { ...x };
          for (const k of Object.keys(o)) if (/(_cents|_stevilo)$/.test(k) || k === "poskusov") o[k] = stevilo(o[k]);
          o.izvedeno_at = x.izvedeno_at ? new Date(x.izvedeno_at).toISOString() : null;
          return o;
        });
        return res.json({ od, do: do_, items });
      } catch (e) {
        if (odgovoriNaNapako) return odgovoriNaNapako(res, e, "GET /admin/api/uskladitve");
        return res.status(500).json({ error: "internal_error", message: "Internal error." });
      }
    });
  }

  return { krog, zazeni, obdelajDan, izracunaj, kandidati, registriraj };
}

module.exports = { ustvari, ZIVO_OD, OKNO_DNI, veljavenDan, kodaNapake };
