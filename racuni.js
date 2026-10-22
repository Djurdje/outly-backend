// Davcno potrjeni racuni za LASTNE dogodke Outly (ZDavPR; Martin 21. 10. 2026, DECISIONS »Davcno potrjevanje racunov: skupni del«; ARCHITECTURE I52, migracija 054).
//
// Kdo dobi racun: SAMO narocilo, ki ga je prodala platforma (I50: orders.stripe_account_id = 'platform', prodajalec NEXT DIMENSIONS), z denarjem (total_cents > 0),
// ne testni promet (PI `test_`, sandbox seja `cs_test_`), ne guest lista. Dogodki klubov (Stripe Connect, prodajalec je klub) racuna od nas NE dobijo.
//
// Tok (racun nikoli ni v poti nakupa ali skena, I16):
//   1. DOLG: v ISTI transakciji, v kateri narocilo postane `paid` (placila_stripe.js zakljuci), en INSERT vrstice `caka` (vpisiDolgRacuna, brez omrezja).
//      Pospravljalec (pospravi) ujame placano platformno narocilo brez vrstice (in manjkajoc dobropis) + `[racuni] POZOR`.
//   2. DOBROPIS: v ISTI transakciji kot refunded_cents (placila_stripe.js uveljaviVracilo) vrstica vrste `dobropis` z negativno delto; `vir` = id Stripovega vracila
//      (UNIQUE: ponovljen webhook ne naredi dvojnika). Dobropis dobi stevilko sele, ko jo ima izvirni racun, in gre ponudniku sele, ko je izvirni racun potrjen.
//   3. DELAVEC (ta modul): kratka transakcija dodeli stevilko A001-1-N iz `racuni_zaporedje` (zaklep vrstice stevca, BREZ LUKENJ: ne SEQUENCE) in zamrzne cas izdaje;
//      nato ZUNAJ transakcije (brez drzane povezave) klic ponudnika `potrdi(podatki) -> { eor, zoi?, ponudnik_id? }` pod lastnim semaforjem in rokom.
//      Zacasna napaka -> ponovitev z narascajocim premorom (isti message_id); trajna -> `napaka` + POZOR.
//
// Ponudniki (RACUNI_PONUDNIK):
//   - `izklopljen` (privzeto; tudi v produkciji): delavec NE tece, nic se ne poslje, vrstice ostanejo `caka` (dolg je zapisan, stevilk ni). Brez napake ob zagonu.
//   - `lazni` (samo testi; v produkciji zavrnjen): HTTP na RACUNI_LAZNI_URL ali lokalni nakljucni EOR; stevilko dodeli NAS stevec (A001-1-N).
//   - `eracuni` (e-racuni.com PREMIUM, WS API; Martin 21. 10. 2026): e-racuni SAM dodeli davcno stevilko (`fiscalNumber`) po blagajni, davcno potrdi in vrne EOR/ZOI.
//     API stevilke ne sprejme kot vhod, zato je pri tem ponudniku MERODAJNA STEVILKA PONUDNIKA: nas stevec se za ta prostor/napravo ne uporablja (migracija 056,
//     `stevilka_vir = 'ponudnik'`); ENO zaporedje, brez razhajanja. Brez poverilnic ali ob napacni nastavitvi: izklopljen + opozorilo (zagon ne pade).
// Izracun ZOI (RSA-SHA256 z namenskim potrdilom .p12) tu NI: pri `eracuni` ga naredi in vrne e-racuni (potrdilo je naloženo pri njih).
//
// Zanesljivost (I16): nikoli `skenPool`; vsak korak drzi najvec eno povezavo iz glavnega poola za nekaj ms; klic ponudnika ne drzi povezave; delavec ima svoj semafor
// (RACUNI_VZPOREDNO), loceno od nakupDovoljenje in STRIPE_VZPOREDNO, in najvec RACUNI_DB_VZPOREDNO hkratnih transakcij.
"use strict";
const crypto = require("crypto");
const qrcode = require("qrcode-generator");

const celo = (env, ime, privzeto, najmanj, najvec) => { const n = Number.parseInt(env[ime], 10); return Number.isInteger(n) && n >= najmanj && n <= najvec ? n : privzeto; };

// --- Podatki izdajatelja in racuna (ENO mesto; interni akt, odgovori racunovodkinje 21. 10. 2026) ---
// Firma in sedez sta ista kot FIRMA_PLATFORME / SEDEZ_PLATFORME v index.js (test_racuni.js preveri, da se ujemata).
const IZDAJATELJ = Object.freeze({
  firma: "NEXT DIMENSIONS, družba za marketing, d.o.o.",
  sedez: "Trebče 81, 3256 Bistrica ob Sotli",
  davcna: "57469911",          // BREZ predpone SI: druzba ni identificirana za DDV (racunovodkinja 21. 10. 2026)
  maticna: "7238274000",
});
// Klavzula o DDV (racunovodkinja 21. 10. 2026, dobesedno). Pravnik predlaga »nismo identificirani za namene DDV«: odloci Martin; spremeni SAMO tu.
const DDV_KLAVZULA = "DDV ni obračunan na podlagi prvega odstavka 94. člena Zakona o davku na dodano vrednost (nismo zavezanci za DDV).";
const PROSTOR = "A001";            // poslovni prostor (interni akt 3. clen)
const NAPRAVA = "1";               // elektronska naprava (interni akt 4. clen; samo stevke)
const OPERATER = IZDAJATELJ.davcna; // samodejna izdaja: oznaka operaterja = davcna stevilka zavezanca (ZDavPR 5/3, FURS vpr. 317; Martin 21. 10. 2026)
const NACIN_PLACILA = "plačilna kartica (Stripe)";
const CASOVNI_PAS = "Europe/Ljubljana";
const PLATFORMNI_RACUN = "platform";   // = placila_stripe.js PLATFORMNI_RACUN (ta modul ga ne uvaza, da ni krozne odvisnosti; test preveri enakost)

// Narocilo, za katero NEXT DIMENSIONS dolguje racun. `a` = alias tabele orders. Ena definicija za zakljuci() in pospravljalca.
const SQL_RACUN_DOLGOVAN = (a = "o") => `(${a}.stripe_account_id = '${PLATFORMNI_RACUN}' AND ${a}.total_cents > 0 AND ${a}.guest_list_id IS NULL
   AND NOT COALESCE(${a}.stripe_payment_intent_id LIKE 'test\\_%', FALSE) AND NOT COALESCE(${a}.stripe_checkout_session_id LIKE 'cs\\_test\\_%', FALSE))`;

// Dolg racuna v transakciji klicatelja (c), ki je narocilo pravkar oznacila `paid`. En INSERT, brez omrezja; ON CONFLICT: ponovljen webhook / pospravljalec ne podvoji.
async function vpisiDolgRacuna(c, orderId) {
  const r = await c.query(
    `INSERT INTO racuni (order_id, vrsta, znesek_cents, valuta)
     SELECT o.id, 'racun', o.total_cents, o.currency FROM orders o
      WHERE o.id = $1 AND o.status IN ('paid', 'partially_refunded', 'refunded') AND ${SQL_RACUN_DOLGOVAN("o")}
     ON CONFLICT (order_id) WHERE vrsta = 'racun' DO NOTHING RETURNING id`, [orderId]);
  return r.rows.length ? r.rows[0].id : null;
}

// Izid Stripovega vracila -> racuni.vracilo_uspelo (pregled PR #315, S2): dobropis se IZDA sele, ko je vracilo izvedeno (succeeded). Do takrat NULL (pending,
// requires_action, neznano), delavec ga ne prevzame. Zavrnjeno (failed/canceled) pred izdajo -> `preklican` + POZOR (dokument ni nikoli izdan).
const VRACILO_ZAVRNJENO = ["failed", "canceled"];
const izidIzStanja = (st) => (st === "succeeded" ? true : (VRACILO_ZAVRNJENO.includes(st) ? false : null));

// Dobropis v transakciji klicatelja, ki je pravkar povecal refunded_cents (vrstica narocila zaklenjena). delta > 0 (centi), vir = id Stripovega vracila ali null,
// uspelo = izid vracila (true | null). Brez izvirnega racuna (navaden klub, test, 0 EUR, narocilo izpred 054) se ne zgodi nic. Nadomestni vir
// 'narocilo-<id>@<skupaj vrnjeno>' (izid neznan: dobropis ostane neizdan, alarm pospravljalca) je enolicen: povecanje refunded_cents na isto vsoto natanko enkrat.
async function vpisiDobropis(c, orderId, deltaCents, skupajVrnjeno, virVracila, uspelo = null) {
  const delta = Math.trunc(Number(deltaCents) || 0);
  if (delta <= 0) return null;
  const imaVir = virVracila && /^[\w@.:-]{1,120}$/.test(String(virVracila));
  const vir = imaVir ? String(virVracila) : `narocilo-${orderId}@${Math.trunc(Number(skupajVrnjeno) || 0)}`;
  const r = await c.query(
    `INSERT INTO racuni (order_id, vrsta, ref_racun_id, vir, znesek_cents, valuta, vracilo_uspelo)
     SELECT r.order_id, 'dobropis', r.id, $2, -LEAST($3::int, r.znesek_cents), r.valuta, $4 FROM racuni r WHERE r.order_id = $1 AND r.vrsta = 'racun'
     ON CONFLICT (vir) DO NOTHING RETURNING id`, [orderId, vir, delta, imaVir && uspelo === true ? true : null]);
  return r.rows.length ? r.rows[0].id : null;
}

// Izid vracila za dobropis z virom `reId` (webhook charge.refunded z razsirjenim seznamom, refund.updated / refund.failed, preverba obdelovalca vracil).
// db = transakcija klicatelja ali pool (en kratek UPDATE po UNIQUE viru, brez omrezja). Vrne 'uspelo' | 'preklican' | 'izdan_zavrnjen' | null.
async function izidVracila(db, reId, stanje) {
  const izid = izidIzStanja(String(stanje || ""));
  if (!reId || izid === null) return null;
  if (izid) {
    const u = await db.query(`UPDATE racuni SET vracilo_uspelo = TRUE, naslednji_poskus_at = NOW() WHERE vir = $1 AND vrsta = 'dobropis' AND stanje = 'caka' AND vracilo_uspelo IS NULL RETURNING id`, [String(reId)]);
    return u.rows.length ? "uspelo" : null;
  }
  const p = await db.query(
    `UPDATE racuni SET vracilo_uspelo = FALSE, stanje = 'preklican', zadnja_napaka = $2, prevzeto_at = NULL
      WHERE vir = $1 AND vrsta = 'dobropis' AND stanje = 'caka' AND stevilka IS NULL AND poslano_at IS NULL RETURNING id, order_id`, [String(reId), `Stripe vracilo ${String(reId).slice(0, 60)}: ${stanje}`]);
  if (p.rows.length) {
    console.error(`[racuni] POZOR: Stripe vracilo ${reId} je ${stanje}: dobropis ${p.rows[0].id} (narocilo ${p.rows[0].order_id}) NI izdan in je preklican (kupec denarja ni dobil). Ce bo vracilo narejeno znova, dobropis nastane za novo vracilo.`);
    return "preklican";
  }
  const z = await db.query(`SELECT id, order_id, stanje FROM racuni WHERE vir = $1 AND vrsta = 'dobropis' AND (stevilka IS NOT NULL OR poslano_at IS NOT NULL)`, [String(reId)]);
  if (z.rows.length) {
    console.error(`[racuni] POZOR: Stripe vracilo ${reId} je ${stanje}, dobropis ${z.rows[0].id} (narocilo ${z.rows[0].order_id}) pa je ze IZDAN ali poslan ponudniku (${z.rows[0].stanje}): kupec denarja ni dobil, dobropis ostane - uredi rocno z racunovodkinjo.`);
    return "izdan_zavrnjen";
  }
  return null;
}

// Webhook charge.refunded s seznamom Stripovih vracil (svezObjekt: expand refunds): en dobropis na Stripovo vracilo (vir = re_..., UNIQUE) z njegovim zneskom
// in izidom; zavrnjena vracila preklicejo se neizdan dobropis. Vsota neprekljicanih dobropisov nikoli ne preseze racuna (preklican se ne steje, zato vracilo,
// narejeno znova po zavrnjenem, dobi svoj dobropis). Vrstica narocila je zaklenjena (klicatelj), zato sta webhook in obdelovalec vracil zaporedna.
async function dobropisiZaVracila(c, orderId, seznam) {
  const vracila = (Array.isArray(seznam) ? seznam : []).filter((x) => x && x.id && Number(x.amount) > 0)
    .sort((x, y) => (Number(x.created) || 0) - (Number(y.created) || 0) || String(x.id).localeCompare(String(y.id)));
  for (const x of vracila) {
    const izid = izidIzStanja(String(x.status || ""));
    if (izid === false) { await izidVracila(c, x.id, x.status); continue; }
    const r = await c.query(
      `INSERT INTO racuni (order_id, vrsta, ref_racun_id, vir, znesek_cents, valuta, vracilo_uspelo)
       SELECT r.order_id, 'dobropis', r.id, $2, -$3::int, r.valuta, $4 FROM racuni r
        WHERE r.order_id = $1 AND r.vrsta = 'racun' AND NOT EXISTS (SELECT 1 FROM racuni x WHERE x.vir = $2)
          AND COALESCE((SELECT -SUM(d.znesek_cents) FROM racuni d WHERE d.ref_racun_id = r.id AND d.stanje <> 'preklican'), 0) + $3::int <= r.znesek_cents
       ON CONFLICT (vir) DO NOTHING RETURNING id`, [orderId, String(x.id), Math.trunc(Number(x.amount)), izid]);
    if (!r.rows.length) {
      const ze = await c.query("SELECT 1 FROM racuni WHERE vir = $1", [String(x.id)]);
      if (ze.rows.length) { if (izid) await izidVracila(c, x.id, x.status); }
      else if ((await c.query("SELECT 1 FROM racuni WHERE order_id = $1 AND vrsta = 'racun'", [orderId])).rows.length) {
        console.error(`[racuni] POZOR: Stripovo vracilo ${x.id} (${x.amount} c, narocilo ${orderId}) bi preseglo znesek racuna z ze vpisanimi dobropisi: dobropis NI vpisan, preveri rocno.`);
      }
    }
  }
}

// --- Cas in stevilka ---
const DELI_CASA = new Intl.DateTimeFormat("en-GB", { timeZone: CASOVNI_PAS, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" });
function deliCasa(t) {
  const d = t instanceof Date ? t : new Date(t);
  if (Number.isNaN(d.getTime())) throw new Error("neveljaven cas");
  const o = {};
  for (const x of DELI_CASA.formatToParts(d)) if (x.type !== "literal") o[x.type] = x.value;
  return { leto: o.year, mesec: o.month, dan: o.day, ura: o.hour, minuta: o.minute, sekunda: o.second };
}
const stevilkaRacuna = (prostor, naprava, stevilka) => `${prostor}-${naprava}-${String(stevilka)}`;
const datumSl = (t) => { const d = deliCasa(t); return `${Number(d.dan)}. ${Number(d.mesec)}. ${d.leto}`; };
const casSl = (t) => { const d = deliCasa(t); return `${d.ura}:${d.minuta}:${d.sekunda}`; };
const znesekSl = (centi, valuta) => {
  const n = Math.trunc(Number(centi) || 0), abs = Math.abs(n);
  return `${n < 0 ? "-" : ""}${Math.floor(abs / 100)},${String(abs % 100).padStart(2, "0")} ${String(valuta || "EUR").trim()}`;
};

// --- Koda QR za ZOI (FURS, Tehnicna dokumentacija v2.9, pogl. 11) ---
// 60 stevk: ZOI iz sestnajstiskega v desetiski zapis (39, vodilne nicle) + davcna stevilka (8) + cas izdaje LLMMDDUUMMSS (12, lokalni cas na racunu)
// + kontrolna stevka (vsota vseh 59 stevk mod 10). Preverjeno s primeroma 1 in 2 iz specifikacije (test_racuni.js).
function qrPodatek(zoiHex, davcna, izdanAt) {
  const zoi = String(zoiHex || "").toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(zoi)) throw new Error("ZOI mora imeti 32 sestnajstiskih znakov");
  const ds = String(davcna || "");
  if (!/^\d{8}$/.test(ds)) throw new Error("davcna stevilka mora imeti 8 stevk");
  const desetisko = BigInt("0x" + zoi).toString(10).padStart(39, "0");
  const d = deliCasa(izdanAt);
  const brez = desetisko + ds + d.leto.slice(2) + d.mesec + d.dan + d.ura + d.minuta + d.sekunda;
  let vsota = 0;
  for (const z of brez) vsota += z.charCodeAt(0) - 48;
  return brez + String(vsota % 10);
}
// QR po FURS: 25 x 25 modulov (razlicica 2), popravljanje napak M, stevilski nacin. Vrne { n, temen(v, s) } za izris (PNG/PDF naredi naslednji korak).
function qrMatrikaRacuna(podatek) {
  if (!/^\d{60}$/.test(String(podatek))) throw new Error("podatek QR mora imeti 60 stevk");
  const qr = qrcode(2, "M");
  qr.addData(String(podatek), "Numeric");
  qr.make();
  return { n: qr.getModuleCount(), temen: (v, s) => qr.isDark(v, s) };
}

// --- Vsebina racuna (vse obvezne postavke, pravna analiza 20. 10. 2026, razdelek 4.1) ---
// r: vrstica `racuni` (+ ref_stevilka, ref_prostor, ref_naprava, ref_izdan_at za dobropis); n: narocilo + dogodek { public_ref, quantity, unit_price_cents, total_cents,
// table_label, title, start_at }. Vrne null, dokler racun nima stevilke (`caka`). E-naslova in imena kupca na racunu NI (hramba 10 let).
// Postavke racuna (ena definicija za vsebino racuna, mail in zahtevek ponudniku). Ne potrebuje stevilke racuna.
function postavkeRacuna(r, n) {
  const dogodek = `${String((n && n.title) || "").trim()}${n && n.start_at ? ", " + datumSl(n.start_at) : ""}`;
  const znesek = Number(r.znesek_cents);
  if (r.vrsta === "dobropis") {
    return [{ opis: `Vračilo za račun ${stevilkaRacuna(r.ref_prostor, r.ref_naprava, r.ref_stevilka)} (vstopnica: ${dogodek})`, kolicina: 1, cena_cents: znesek, skupaj_cents: znesek }];
  }
  if (n && n.table_label) {
    return [{ opis: `VIP miza ${String(n.table_label).trim()}: ${dogodek}`, kolicina: 1, cena_cents: znesek, skupaj_cents: znesek }];
  }
  const kol = Number(n && n.quantity), cena = Number(n && n.unit_price_cents);
  return Number.isInteger(kol) && kol > 0 && Number.isInteger(cena) && kol * cena === znesek
    ? [{ opis: `Vstopnica: ${dogodek}`, kolicina: kol, cena_cents: cena, skupaj_cents: znesek }]
    : [{ opis: `Vstopnica: ${dogodek}`, kolicina: 1, cena_cents: znesek, skupaj_cents: znesek }];
}
function vsebinaRacuna(r, n) {
  if (!r || r.stevilka === null || r.stevilka === undefined || !r.izdan_at) return null;
  const valuta = String(r.valuta || "EUR").trim();
  const znesek = Number(r.znesek_cents);
  const postavke = postavkeRacuna(r, n);
  const zoi = r.zoi ? String(r.zoi).toLowerCase() : null;
  return {
    vrsta: r.vrsta,
    naslov: r.vrsta === "dobropis" ? "Dobropis" : "Račun",
    stevilka: stevilkaRacuna(r.prostor, r.naprava, r.stevilka),
    datum_izdaje: datumSl(r.izdan_at),
    cas_izdaje: casSl(r.izdan_at),
    izdajatelj: { ...IZDAJATELJ },
    postavke,
    skupaj_cents: znesek,
    valuta,
    ddv: DDV_KLAVZULA,
    nacin_placila: NACIN_PLACILA,
    operater: OPERATER,
    eor: r.eor ? String(r.eor) : null,
    zoi,
    qr: zoi ? qrPodatek(zoi, IZDAJATELJ.davcna, r.izdan_at) : null,
    sklic: r.vrsta === "dobropis" && r.ref_stevilka !== null && r.ref_stevilka !== undefined
      ? { stevilka: stevilkaRacuna(r.ref_prostor, r.ref_naprava, r.ref_stevilka), datum: r.ref_izdan_at ? datumSl(r.ref_izdan_at) : null, cas: r.ref_izdan_at ? casSl(r.ref_izdan_at) : null }
      : null,
    narocilo: n && n.public_ref ? String(n.public_ref) : null,
  };
}

// Blok racuna za mail (HTML + besedilo). NI vkljucen v potrdilo kupcu (I32) v tem koraku: vkljuci ga naslednji korak, ko bo izvedba potrjevanja izbrana.
// qrCid (neobvezno): id vgrajene slike QR (PNG priponka s content_id), ki jo pripravi klicatelj iz qrMatrikaRacuna(v.qr).
const esc = (s) => String(s === null || s === undefined ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
function blokRacuna(v, { qrCid } = {}) {
  if (!v) return null;
  const vr = [];
  vr.push(`${v.naslov} št. ${v.stevilka}`);
  vr.push(`Datum in čas izdaje: ${v.datum_izdaje} ob ${v.cas_izdaje}`);
  vr.push(`Izdajatelj: ${v.izdajatelj.firma}, ${v.izdajatelj.sedez}. Davčna številka: ${v.izdajatelj.davcna}. Matična številka: ${v.izdajatelj.maticna}.`);
  if (v.sklic) vr.push(`Sklic na račun: ${v.sklic.stevilka}${v.sklic.datum ? `, izdan ${v.sklic.datum} ob ${v.sklic.cas}` : ""}`);
  for (const p of v.postavke) vr.push(`${p.opis} | količina ${p.kolicina} | cena ${znesekSl(p.cena_cents, v.valuta)} | skupaj ${znesekSl(p.skupaj_cents, v.valuta)}`);
  vr.push(`Skupaj za plačilo: ${znesekSl(v.skupaj_cents, v.valuta)}`);
  vr.push(v.ddv);
  vr.push(`Način plačila: ${v.nacin_placila}`);
  vr.push(`Oznaka operaterja: ${v.operater}`);
  if (v.narocilo) vr.push(`Naročilo: ${v.narocilo}`);
  vr.push(`EOR: ${v.eor || "(še ni dodeljen)"}`);
  if (v.zoi) vr.push(`ZOI: ${v.zoi}`);
  const text = vr.join("\n");
  const st = 'style="margin:0 0 4px;font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:1.5;color:#222"';
  const vrstice = v.postavke.map((p) => `<tr><td style="padding:2px 8px 2px 0">${esc(p.opis)}</td><td style="padding:2px 8px;text-align:right">${esc(p.kolicina)}</td>`
    + `<td style="padding:2px 8px;text-align:right;white-space:nowrap">${esc(znesekSl(p.cena_cents, v.valuta))}</td><td style="padding:2px 0 2px 8px;text-align:right;white-space:nowrap">${esc(znesekSl(p.skupaj_cents, v.valuta))}</td></tr>`).join("");
  const html = `<div style="margin:16px 0;padding:12px 0;border-top:1px solid #ddd">`
    + `<p ${st}><strong>${esc(v.naslov)} št. ${esc(v.stevilka)}</strong></p>`
    + `<p ${st}>Datum in čas izdaje: ${esc(v.datum_izdaje)} ob ${esc(v.cas_izdaje)}</p>`
    + `<p ${st}>Izdajatelj: ${esc(v.izdajatelj.firma)}, ${esc(v.izdajatelj.sedez)}. Davčna številka: ${esc(v.izdajatelj.davcna)}. Matična številka: ${esc(v.izdajatelj.maticna)}.</p>`
    + (v.sklic ? `<p ${st}>Sklic na račun: ${esc(v.sklic.stevilka)}${v.sklic.datum ? `, izdan ${esc(v.sklic.datum)} ob ${esc(v.sklic.cas)}` : ""}</p>` : "")
    + `<table style="border-collapse:collapse;font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#222;margin:4px 0">`
    + `<tr><th style="text-align:left;padding:2px 8px 2px 0">Opis</th><th style="padding:2px 8px">Količina</th><th style="padding:2px 8px">Cena</th><th style="padding:2px 0 2px 8px">Skupaj</th></tr>${vrstice}</table>`
    + `<p ${st}><strong>Skupaj za plačilo: ${esc(znesekSl(v.skupaj_cents, v.valuta))}</strong></p>`
    + `<p ${st}>${esc(v.ddv)}</p>`
    + `<p ${st}>Način plačila: ${esc(v.nacin_placila)} · Oznaka operaterja: ${esc(v.operater)}${v.narocilo ? ` · Naročilo: ${esc(v.narocilo)}` : ""}</p>`
    + `<p ${st}>EOR: ${esc(v.eor || "(še ni dodeljen)")}</p>`
    + (v.zoi ? `<p ${st}>ZOI: ${esc(v.zoi)}</p>` : "")
    + (v.zoi && qrCid ? `<p style="margin:4px 0"><img src="cid:${esc(qrCid)}" alt="ZOI ${esc(v.zoi)}" width="100" height="100" style="display:block;width:100px;height:100px"></p>` : "")
    + `</div>`;
  return { html, text };
}

// --- Ponudnik (tanka plast) ---
// Ponudnik, ki stevilko dodeli NAS stevec (`lazni`): potrdi(podatki, { signal }) -> { eor, zoi?, ponudnik_id? }.
// Ponudnik, ki stevilko dodeli SAM (`eracuni`, stevilcenje = "ponudnik"): ustvari(podatki, { signal }) -> { ponudnik_id, ponudnik_stevilka },
//   poisci(podatki, { signal }) -> { ponudnik_id, ponudnik_stevilka } | null (iskanje po referenci = message_id), preberi(ref, { signal }) -> { stevilka, eor, zoi, ... }.
// Napaka NapakaPonudnika: `trajna` (zavrnitev, ponovitev ne pomaga -> `napaka` + POZOR), `konfiguracija` (poverilnice/nastavitev: pocasna ponovitev + POZOR, vrstica NI `napaka`),
// `neznan` (zahtevek je lahko ze obdelan: pred novo izdajo najprej iskanje po referenci). Privzeto neznan = !trajna.
// `neposlano` (DOKAZANO, da zahtevek ni prisel do ponudnika: HTTP 429 po statusni kodi, napaka povezave pred posiljanjem telesa, lokalna zavrnitev pred klicem): edini primer,
// v katerem sme delavec pobrisati `poslano_at`. Besedilo napake NIKOLI ni dokaz (ponudnik lahko dokument ustvari, nato pa vrne napako, npr. pri fiskalizaciji).
// `nejasno` (iskanje po referenci brez zanesljivega izida: neprepoznana, okrnjena ali nepopolna oblika seznama) -> NI »dokument ne obstaja«.
class NapakaPonudnika extends Error {
  constructor(sporocilo, { trajna = false, konfiguracija = false, neznan, neposlano = false, nejasno = false } = {}) {
    super(sporocilo); this.name = "NapakaPonudnika"; this.trajna = !!trajna; this.konfiguracija = !!konfiguracija; this.neposlano = !!neposlano; this.nejasno = !!nejasno;
    this.neznan = neznan === undefined ? (!trajna && !neposlano) : !!neznan;
  }
}
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function lazniPonudnik(env) {
  const url = env.RACUNI_LAZNI_URL || "";
  return {
    ime: "lazni",
    async potrdi(p, { signal } = {}) {
      if (!url) return { eor: crypto.randomUUID(), ponudnik_id: `lazni-${p.id}` };
      let res;
      try {
        res = await fetch(url, { method: "POST", headers: { "content-type": "application/json", "idempotency-key": p.message_id }, body: JSON.stringify(p), signal });
      } catch (e) { throw new NapakaPonudnika(`omrezje: ${e && e.name === "AbortError" ? "rok potekel" : (e && e.message) || e}`); }
      const besedilo = await res.text();
      if (res.ok) { try { return JSON.parse(besedilo); } catch (_) { throw new NapakaPonudnika("odgovor ni JSON"); } }
      const trajna = res.status >= 400 && res.status < 500 && ![408, 409, 425, 429].includes(res.status);
      throw new NapakaPonudnika(`HTTP ${res.status}: ${besedilo.slice(0, 200)}`, { trajna });
    },
  };
}

// --- e-racuni.com (WS API, JSON; dokumentacija: https://e-racuni.com/WikiDoc/WikiPage-1002DAD in https://e-racuni.com/obracuni/ApiDocumentation) ---
// Kdo dodeli stevilko: E-RACUNI. SalesInvoiceCreate prejme blagajno (`cashRegisterCode`) in poslovno enoto (`businessUnit`), dokument davcno potrdi »povsem samodejno«
// (»outside of control of the user or the API«) in mu dodeli davcno (fiskalno) zaporedno stevilko (`fiscalNumber`, v odgovoru SalesInvoiceGet skupaj z `eor` in `zoi`);
// stevilka je v enem zaporedju za racune, dobropise in storno po blagajni ali poslovni enoti (wiki »Davcno potrjevanje dokumentov« 1.2, 1.9). API stevilke ne sprejme.
// Meje: najvec 1 zahtevek/s v povprecju na IP (hip 4), SOCASNIH ZAHTEVKOV ISTEGA API UPORABNIKA NI (API reference) -> en klic naenkrat in razmak med zahtevki.
// Idempotence API NIMA (SalesInvoiceCreate ne pozna kljuca; SalesInvoiceList nima filtra po referenci): `orderReference` = message_id nase vrstice, pred ponovitvijo po
// nejasnem izidu delavec pobere seznam dokumentov obdobja (SalesInvoiceList / CreditNoteList) in poisce dokument s to referenco.
const ERACUNI_URL_PRIVZETO = "https://e-racuni.com/WebServicesSI/API";
const ERACUNI_ZAHTEVANI = ["ERACUNI_USERNAME", "ERACUNI_SECRET_KEY", "ERACUNI_TOKEN"];
// Vzorca razvrscata napako samo za PREMOR in opozorilo. Iz besedila NE sledi, da dokument ni nastal: `poslano_at` ostane (iskanje po referenci pred vsako novo izdajo).
const VZOREC_OMEJITEV = /too many|rate.?limit|throttl|concurrent|try again|retry|temporar|busy|prevec zahtev|zasedeno|poskusite/i;
const VZOREC_KONFIGURACIJA = /access denied|privilege|unauthori[sz]|authenticat|credential|invalid (user|login|token|secret|password|api)|wrong (user|password|token)|login|api.{0,20}(not|disabled|inactive)|web ?services?.{0,20}(not|disabled)|cash ?register|business ?unit|certificat|certifikat|fiscaliz.{0,25}(not|disabled|inactive|failed)|not (set ?up|configured|activated|registered|found)/i;
const skrij = (besedilo, tajno) => { let t = String(besedilo); for (const x of tajno) if (x && x.length >= 4) t = t.split(x).join("***"); return t; };
const jeObjekt = (x) => x && typeof x === "object";
const vrhnji = (o, ime) => { if (!jeObjekt(o) || Array.isArray(o)) return undefined; const k = Object.keys(o).find((x) => x.toLowerCase() === ime.toLowerCase()); return k === undefined ? undefined : o[k]; };

// Prvi skalar z danim imenom (brez razlike velikosti) v poljubni globini, plitvo najprej (odgovor je lahko {status, ...} ali ovit v response/SalesInvoice).
function iskaniKljuc(koren, imena) {
  const iskana = imena.map((x) => x.toLowerCase());
  const vrsta = [koren];
  for (let n = 0; vrsta.length && n < 5000; n++) {
    const o = vrsta.shift();
    if (!jeObjekt(o)) continue;
    if (!Array.isArray(o)) for (const k of Object.keys(o)) if (iskana.includes(k.toLowerCase()) && o[k] !== null && !jeObjekt(o[k]) && String(o[k]).trim() !== "") return o[k];
    for (const v of Array.isArray(o) ? o : Object.values(o)) if (jeObjekt(v)) vrsta.push(v);
  }
  return undefined;
}
// Napake povezave, ki DOKAZUJEJO, da telo zahtevka ni bilo poslano (DNS, zavrnjena povezava, rok za vzpostavitev povezave, napaka TLS pri rokovanju). ECONNRESET, »fetch failed«
// brez kode in rok po vzpostavitvi povezave tega NE dokazujejo.
const KODE_NEPOSLANO = new Set(["ENOTFOUND", "ECONNREFUSED", "EAI_AGAIN", "ENETUNREACH", "EHOSTUNREACH", "UND_ERR_CONNECT_TIMEOUT"]);
function neposlanoPriPovezavi(e) {
  const kode = [e && e.code, e && e.cause && e.cause.code].filter(Boolean).map(String);
  return kode.some((k) => KODE_NEPOSLANO.has(k) || /^(ERR_TLS_|CERT_|UNABLE_TO_|DEPTH_ZERO_|SELF_SIGNED_)/.test(k));
}
const niz = (x) => (x === undefined || x === null ? null : (String(x).trim() || null));
const datumIso = (t) => { const d = deliCasa(t); return `${d.leto}-${d.mesec}-${d.dan}`; };
// Obdobje iskanja po referenci: dokument nastane med `poslano_at` in nekaj deset sekund pozneje (rok klica), zato +-15 min (en ali dva dneva, ljubljanski cas).
const oknoIskanja = (poslanoAt) => { const t = new Date(poslanoAt).getTime(); return { od: datumIso(new Date(t - 15 * 60000)), do: datumIso(new Date(t + 15 * 60000)) }; };
const pocakajSignal = (ms, signal) => new Promise((resolve, reject) => {
  if (ms <= 0) return resolve();
  const t = setTimeout(resolve, ms);
  if (signal) signal.addEventListener("abort", () => { clearTimeout(t); reject(new NapakaPonudnika("rok potekel (cakanje na razmak med zahtevki)", { neznan: false, neposlano: true })); }, { once: true });
});

function eracuniPonudnik(env) {
  const url = String(env.ERACUNI_URL || "").trim() || ERACUNI_URL_PRIVZETO;
  const username = String(env.ERACUNI_USERNAME || "").trim(), secretKey = String(env.ERACUNI_SECRET_KEY || "").trim(), token = String(env.ERACUNI_TOKEN || "").trim();
  const prostor = String(env.ERACUNI_POSLOVNA_ENOTA || "").trim() || PROSTOR, naprava = String(env.ERACUNI_BLAGAJNA || "").trim() || NAPRAVA;
  const nacinPlacila = String(env.ERACUNI_NACIN_PLACILA || "").trim() || "Stripe";
  const vrstaProdaje = celo(env, "ERACUNI_VRSTA_PRODAJE", 7, 0, 200);   // 7 = »Neobdavcen promet - ne gre v DDV evidence« (NEXT DIMENSIONS ni zavezanec za DDV), preveri v e-racuni
  const kupec = String(env.ERACUNI_KUPEC || "").trim();                  // neobvezna oznaka kupca na poenostavljenem racunu (NI ime osebe); privzeto brez
  const razmak = celo(env, "ERACUNI_RAZMAK_MS", 1000, 0, 60000);        // najmanj toliko med zacetkoma dveh zahtevkov (meja 1/s)
  // Pomen SalesInvoiceList (po katerem datumu filtrira, velikost strani, ali elementi vsebujejo orderReference in cashRegisterCode) NI preverjen z zivim klicem. Dokler
  // Martin po preverbi ne nastavi ERACUNI_SEZNAM_PREVERJEN=1, iskanje brez najdbe nikoli ne vodi v novo izdajo, ampak v `napaka` (rocni pregled v e-racuni).
  const seznamPreverjen = String(env.ERACUNI_SEZNAM_PREVERJEN || "").trim() === "1";
  const SEZNAM_MEJA = celo(env, "ERACUNI_SEZNAM_MEJA", 100, 2, 100000); // seznam z toliko ali vec elementi je ob iskanju po referenci sumljiv (morda okrnjen): brez negativnega izida
  const tajno = [username, secretKey, token];
  let naslednji = 0;

  async function klic(metoda, parametri, signal, namen = null) {
    const zdaj = Date.now(); const cakaj = Math.max(0, naslednji - zdaj); naslednji = Math.max(zdaj, naslednji) + razmak;
    await pocakajSignal(cakaj, signal);
    const napaka = (sporocilo, opcije) => new NapakaPonudnika(skrij(sporocilo, tajno), opcije);
    let res, besedilo;
    try {
      res = await fetch(url, { method: "POST", headers: { "content-type": "application/json", accept: "application/json", ...(namen ? { "x-outly-namen": namen } : {}) }, body: JSON.stringify({ username, secretKey, token, method: metoda, parameters: parametri }), signal, redirect: "error" });
      besedilo = await res.text();
    } catch (e) {
      const prekinjen = e && e.name === "AbortError";
      const dokazano = !prekinjen && neposlanoPriPovezavi(e);
      throw napaka(`${metoda}: omrezje: ${prekinjen ? "rok potekel" : (e && e.message) || e}${dokazano ? " (zahtevek ni bil poslan)" : ""}`, dokazano ? { neznan: false, neposlano: true } : { neznan: true });
    }
    if (res.status === 429) throw napaka(`${metoda}: HTTP 429 (omejitev klicev)`, { neznan: false, neposlano: true });   // po STATUSNI KODI, ne po besedilu
    if (res.status === 408 || res.status >= 500) throw napaka(`${metoda}: HTTP ${res.status}`, { neznan: true });
    if (res.status === 401 || res.status === 403 || res.status === 404 || res.status === 405) throw napaka(`${metoda}: HTTP ${res.status} (poverilnice, pravice ali naslov)`, { konfiguracija: true, neznan: false });
    let j = null;
    try { j = JSON.parse(besedilo); } catch (_) { j = null; }
    if (!jeObjekt(j)) {
      if (!res.ok) throw napaka(`${metoda}: HTTP ${res.status}: ${besedilo.slice(0, 160)}`, { trajna: true, neznan: false });
      throw napaka(`${metoda}: odgovor ni JSON`, { neznan: true });
    }
    const odg = jeObjekt(vrhnji(j, "response")) ? vrhnji(j, "response") : j;
    const st = String(vrhnji(odg, "status") ?? vrhnji(j, "status") ?? "").toLowerCase();
    const err = vrhnji(odg, "error") ?? vrhnji(j, "error");
    const vOdgovoru = err !== undefined && err !== null && err !== "" && err !== false;
    if (st === "error" || vOdgovoru || !res.ok) {
      const opis = niz(jeObjekt(err) ? (vrhnji(err, "description") ?? vrhnji(err, "message")) : (typeof err === "string" ? err : (vrhnji(odg, "description") ?? vrhnji(odg, "message") ?? vrhnji(odg, "errorDescription"))));
      const t = `${metoda}: ${opis || `HTTP ${res.status}`}`;
      if (VZOREC_OMEJITEV.test(opis || "")) throw napaka(t.slice(0, 300), { neznan: false });
      if (VZOREC_KONFIGURACIJA.test(opis || "")) throw napaka(t.slice(0, 300), { konfiguracija: true, neznan: false });
      throw napaka(t.slice(0, 300), { trajna: true, neznan: false });
    }
    return j;
  }

  const sklicDokumenta = (dok) => ({ ponudnik_id: niz(iskaniKljuc(dok, ["documentID", "documentId"])), ponudnik_stevilka: niz(iskaniKljuc(dok, ["number"])) });

  return {
    ime: "eracuni", stevilcenje: "ponudnik", prostor, naprava,
    najvecVzporednih: 1,   // API: socasnih zahtevkov istega uporabnika ni
    seznamPreverjen,
    rokMs: 30000,          // klic vkljuci FURS; privzeti rok 5 s bi poslal vsak racun v nejasen izid
    paket: 5,              // kolikor vrstic naenkrat »prevzame« delavec (paket x (rok + razmak) < zastaranje prevzema)
    zastarelo: 300000,     // prevzem vrstice zastara po 5 min (paket 5 x klici do 30 s); poleg tega najem in zeton prevzema (racuni.js, K2)
    async ustvari(p, { signal } = {}) {
      // Lokalne zavrnitve pred klicem: nic ni poslano (`neposlano`), zato se oznaka `poslano_at` pobrise.
      if (String(p.valuta || "EUR").trim() !== "EUR") throw new NapakaPonudnika(`valuta ${String(p.valuta).slice(0, 5)} ni podprta (samo EUR)`, { trajna: true, neznan: false, neposlano: true });
      if (!Array.isArray(p.postavke) || !p.postavke.length) throw new NapakaPonudnika("racun brez postavk", { trajna: true, neznan: false, neposlano: true });
      const dobropis = p.vrsta === "dobropis";
      const datumDobave = /^\d{4}-\d{2}-\d{2}$/.test(String(p.datum_dobave || "")) ? p.datum_dobave : datumIso(new Date());   // M1: datum placila (dobropis: vracila), ne dan izdaje
      const skupno = {
        dateOfSupplyFrom: datumDobave, type: "Retail", methodOfPayment: nacinPlacila, businessUnit: prostor, cashRegisterCode: naprava, orderReference: p.message_id,
        documentLanguage: "Slovene", remarks: p.ddv_klavzula,
        ...(kupec ? { buyerName: kupec } : {}),   // BREZ e-naslova, imena, naslova in davcne stevilke kupca (poenostavljen racun potrosniku, pravna analiza 4.1/12)
        // Cene so KONCNE (Retail, z morebitnimi davki): cele centi / 100 (najblizje decimalno stevilo; dobropis ima v e-racuni pozitivne zneske).
        Items: p.postavke.map((x) => ({ description: x.opis, quantity: x.kolicina, unit: "kos", price: Math.abs(Math.trunc(Number(x.cena_cents))) / 100, vatTransactionType: vrstaProdaje })),
      };
      if (dobropis) {
        // Sklic je STEVILKA izvirnega dokumenta pri ponudniku (salesInvoiceRef: »2022-00005«); oznaka dokumenta (documentID) ni sklic.
        const ref = p.sklic && p.sklic.ponudnik_stevilka;
        if (!ref) throw new NapakaPonudnika("dobropis brez stevilke izvirnega dokumenta pri ponudniku", { trajna: true, neznan: false, neposlano: true });
        const j = await klic("CreditNoteCreate", { CreditNote: { ...skupno, salesInvoiceRef: ref } }, signal);
        return sklicDokumenta(j);
      }
      const j = await klic("SalesInvoiceCreate", { SalesInvoice: skupno }, signal);
      return sklicDokumenta(j);
    },
    // Bralni preizkus PRED izdajo (pregled #318, 3. krog): poverilnice, uporabnik in naslov delujejo, preden gre v svet prvi Create. Nic ne izda in ne spremeni; oblike odgovora
    // NE preverja (samo da klic uspe): pomen seznama ni zivo preverjen. Napacen kljuc bi sicer pustil `poslano_at` na vsaki vrstici zaostanka (besedilo napake ni dokaz, da dokument
    // ni nastal), po popravku kljuca pa bi vsaka morala skozi iskanje po referenci.
    async preizkusi({ signal } = {}) {
      const danes = datumIso(new Date());
      await klic("SalesInvoiceList", { dateFrom: danes, dateTo: danes }, signal, "preizkus");   // glava samo za sled v testih/posrednikih, API je ne rabi
      return true;
    },
    // Iskanje po referenci (= pred novo izdajo): seznam dokumentov v ozkem obdobju okoli `poslano_at`, filter po `orderReference` v odjemalcu. API nima filtra po referenci in
    // oblike seznama (omejitev, strani) dokumentacija ne opisuje, zato je NEGATIVEN izid (return null) dovoljen SAMO, ce je seznam dokazljivo popoln:
    //   (1) prepoznan zabojnik seznama (SalesInvoices / CreditNotes); prazen odgovor, `{}` in `{status: ok}` NISO »prazen seznam«;
    //   (2) manj kot ERACUNI_SEZNAM_MEJA elementov (ob mejni dolzini seznam morda okrnjen);
    //   (3) vsak element na nasi blagajni ima `orderReference` v obliki UUID (nespremenjen, ne okrnjen); ostale blagajne se ne stejejo;
    //   (4) seznam vsebuje VSE dokumente, za katere v bazi ze vemo, da obstajajo v istem obdobju (`p.znani`): manjka kateri -> seznam je okrnjen ali zamaknjen.
    // Sicer NapakaPonudnika({ nejasno }): ni trditve »dokumenta ni«. Vec dokumentov z isto referenco = ze nastal dvojnik (trajna napaka, rocna obravnava).
    async poisci(p, { signal } = {}) {
      const dobropis = p.vrsta === "dobropis";
      const okno = p.okno && p.okno.od && p.okno.do ? p.okno : { od: datumIso(new Date(Date.now() - 24 * 3600 * 1000)), do: datumIso(new Date(Date.now() + 24 * 3600 * 1000)) };
      const j = await klic(dobropis ? "CreditNoteList" : "SalesInvoiceList", { dateFrom: okno.od, dateTo: okno.do }, signal);
      const nejasno = (kaj) => new NapakaPonudnika(`iskanje po referenci ne da zanesljivega izida: ${kaj}`, { neznan: true, nejasno: true });
      const imeZabojnika = dobropis ? "creditnotes" : "salesinvoices", imeElementa = dobropis ? "creditnote" : "salesinvoice";
      const odg = jeObjekt(vrhnji(j, "response")) ? vrhnji(j, "response") : j;
      const zab = Object.keys(odg).find((k) => k.toLowerCase() === imeZabojnika);
      if (zab === undefined) throw nejasno("oblika seznama ni prepoznana");
      let vsebina = odg[zab];
      if (jeObjekt(vsebina) && !Array.isArray(vsebina)) {   // XML v JSON: {SalesInvoice: [...]} ali {SalesInvoice: {...}}
        const k = Object.keys(vsebina).find((x) => x.toLowerCase() === imeElementa);
        vsebina = k === undefined ? undefined : vsebina[k];
        if (jeObjekt(vsebina) && !Array.isArray(vsebina)) vsebina = [vsebina];
      }
      if (!Array.isArray(vsebina)) throw nejasno("seznam je prazen ali v neznani obliki");
      const elementi = vsebina.map((x) => (jeObjekt(x) && !Array.isArray(x) && Object.keys(x).length === 1 && Object.keys(x)[0].toLowerCase() === imeElementa ? x[Object.keys(x)[0]] : x));
      if (elementi.some((x) => !jeObjekt(x) || Array.isArray(x))) throw nejasno("element seznama ni objekt");
      if (elementi.length >= SEZNAM_MEJA) throw nejasno(`seznam ima ${elementi.length} elementov (meja ${SEZNAM_MEJA}): morda je okrnjen`);
      const referenca = (x) => { const v = iskaniKljuc(x, ["orderReference"]); return v === undefined ? null : String(v).trim(); };
      const nasi = elementi.filter((x) => { const bl = iskaniKljuc(x, ["cashRegisterCode"]); return bl === undefined || String(bl).trim() === naprava; });
      for (const x of nasi) {
        const r = referenca(x);
        if (r === null || !UUID.test(r)) throw nejasno("element seznama nima nespremenjene reference (orderReference)");
      }
      const prisotne = new Set(elementi.map(referenca).filter(Boolean));
      const znani = Array.isArray(p.znani) ? p.znani : [];
      const manjka = znani.filter((x) => !prisotne.has(x));
      if (manjka.length) throw nejasno(`v seznamu manjka ${manjka.length} dokumentov, za katere vemo, da obstajajo (seznam okrnjen ali zamaknjen)`);
      const najdeni = elementi.filter((x) => referenca(x) === p.message_id);
      if (najdeni.length > 1) throw new NapakaPonudnika(`pri ponudniku obstaja ${najdeni.length} dokumentov z isto referenco ${p.message_id}: DVOJNIK, rocna obravnava (storno)`, { trajna: true, neznan: false });
      return najdeni.length ? sklicDokumenta(najdeni[0]) : null;
    },
    async preberi(ref, { signal } = {}) {
      const dobropis = ref.vrsta === "dobropis";
      // Dokumentirano je branje po STEVILKI dokumenta (»by document number«); oznaka dokumenta (documentID) je rezerva, ce stevilke nimamo. Dveh polj ne mesamo.
      const iskano = ref.ponudnik_stevilka ? { number: ref.ponudnik_stevilka } : (ref.ponudnik_id ? { documentID: ref.ponudnik_id } : null);
      if (!iskano) throw new NapakaPonudnika("dokument pri ponudniku nima ne stevilke ne oznake", { trajna: true, neznan: false, neposlano: true });
      const j = await klic(dobropis ? "CreditNoteGet" : "SalesInvoiceGet", iskano, signal);
      const bu = niz(iskaniKljuc(j, ["businessUnit"])), bl = niz(iskaniKljuc(j, ["cashRegisterCode"]));
      if ((bu !== null && bu !== prostor) || (bl !== null && bl !== naprava)) {
        throw new NapakaPonudnika(`dokument je izdan na drugi poslovni enoti/blagajni (${String(bu).slice(0, 20)}/${String(bl).slice(0, 20)}, pricakovano ${prostor}/${naprava})`, { konfiguracija: true, neznan: false });
      }
      const fn = Number(iskaniKljuc(j, ["fiscalNumber"]));
      const datum = niz(iskaniKljuc(j, ["date"]));
      const cas = niz(iskaniKljuc(j, ["dateTimeOfIssue", "issueDateTime", "fiscalDateTime", "issuedAt"]));
      const izdan = cas && !Number.isNaN(new Date(cas).getTime()) ? new Date(cas) : null;
      return {
        stevilka: Number.isInteger(fn) && fn >= 1 ? fn : null, eor: niz(iskaniKljuc(j, ["eor"])), zoi: niz(iskaniKljuc(j, ["zoi"])),
        datum: datum && /^\d{4}-\d{2}-\d{2}/.test(datum) ? datum.slice(0, 10) : null, izdan_at: izdan, ponudnik_stevilka: niz(iskaniKljuc(j, ["number"])),
      };
    },
  };
}
const PONUDNIKI = { lazni: lazniPonudnik, eracuni: eracuniPonudnik };

// Izbira prek RACUNI_PONUDNIK. Prazno ali `izklopljen` = izklopljen. `lazni` v produkciji (RENDER / NODE_ENV=production) NE velja (lazni EOR na pravem racunu bi bil
// prekrsek): izklopljen + opozorilo. `eracuni` brez katerega koli kljuca (ERACUNI_USERNAME, ERACUNI_SECRET_KEY, ERACUNI_TOKEN), z neveljavno poslovno enoto/blagajno
// ali naslovom, ki ni https (v produkciji), je izklopljen + opozorilo (samo IMENA spremenljivk, nikoli vrednosti). Neznano ime = izklopljen + opozorilo. Nikoli napaka ob zagonu.
function izberiPonudnika(env = process.env) {
  const ime = String(env.RACUNI_PONUDNIK || "").trim().toLowerCase();
  if (!ime || ime === "izklopljen") return { ime: "izklopljen", ponudnik: null, opozorilo: null };
  const produkcija = !!env.RENDER || env.NODE_ENV === "production";
  const izklop = (razlog) => ({ ime: "izklopljen", ponudnik: null, opozorilo: `${razlog}: ponudnik IZKLOPLJEN, racuni ostanejo v vrsti` });
  if (ime === "lazni" && produkcija) return izklop("RACUNI_PONUDNIK=lazni v produkciji ni dovoljen (lazni EOR)");
  if (!PONUDNIKI[ime]) return izklop(`RACUNI_PONUDNIK=${ime.slice(0, 40)} ne obstaja`);
  if (ime === "eracuni") {
    const manjka = ERACUNI_ZAHTEVANI.filter((k) => !String(env[k] || "").trim());
    if (manjka.length) return izklop(`RACUNI_PONUDNIK=eracuni, a manjka ${manjka.join(", ")}`);
    const ID = /^[0-9A-Za-z]{1,20}$/;
    if (!ID.test(String(env.ERACUNI_POSLOVNA_ENOTA || PROSTOR).trim()) || !ID.test(String(env.ERACUNI_BLAGAJNA || NAPRAVA).trim())) return izklop("ERACUNI_POSLOVNA_ENOTA / ERACUNI_BLAGAJNA smeta vsebovati samo crke in stevke (najvec 20)");
    let u;
    try { u = new URL(String(env.ERACUNI_URL || "").trim() || ERACUNI_URL_PRIVZETO); } catch (_) { return izklop("ERACUNI_URL ni veljaven naslov"); }
    const lokalno = ["localhost", "127.0.0.1"].includes(u.hostname);
    if (u.protocol !== "https:" && !(u.protocol === "http:" && lokalno && !produkcija)) return izklop("ERACUNI_URL mora biti https (poverilnice gredo v telesu zahtevka)");
    if (u.username || u.password) return izklop("ERACUNI_URL ne sme vsebovati uporabnika ali gesla");
  }
  return { ime, ponudnik: PONUDNIKI[ime](env), opozorilo: null };
}

// Preprost semafor (cakalci v pomnilniku, brez povezave).
function semafor(n) {
  let prosto = n; const vrsta = [];
  return async (fn) => {
    if (prosto > 0) prosto--; else await new Promise((r) => vrsta.push(r));
    try { return await fn(); } finally { const nasl = vrsta.shift(); if (nasl) nasl(); else prosto++; }
  };
}

// Stevilka racuna v transakciji klicatelja (c ze v BEGIN). Vrne { stanje: 'izdan', stevilka, izdan_at } | { stanje: 'odlozeno' } | { stanje: <obstojece> }.
// Vrstni red zaklepov (pregled PR #315, S1): (0) preverba BREZ zaklepa (neizdajljiv dobropis ne vzame stevca), (1) vrstica stevca, (2) sele nato vrstica racuna
// (FOR NO KEY UPDATE) s ponovno preverbo. Cakanje na stevec (serializirana izdaja) tako ne drzi vrstice racuna: webhook, ki ji spremeni izid vracila, caka najvec
// ms. Zapis stevilke ne potrebuje polnega zaklepa (racuni_stevilka_key je delni indeks, ne UNIQUE omejitev), zato INSERT dobropisa (FK KEY SHARE) ne caka nikoli.
// Nihce drug ne zaklepa najprej racuna in nato stevca (brez mrtve zanke). Stevec se poveca za 1 v isti transakciji, v kateri se zapise stevilka: ROLLBACK vrne
// oboje (brez lukenj). Cas izdaje = ura PO zaklepu stevca, zato si stevilke in casi sledijo v istem vrstnem redu.
const SQL_IZDAJLJIV = `SELECT r.id, r.vrsta, r.stanje, r.vracilo_uspelo, ref.stevilka AS ref_stevilka FROM racuni r LEFT JOIN racuni ref ON ref.id = r.ref_racun_id WHERE r.id = $1`;
function razlogNeizdaje(r) {
  if (!r) return "ni";
  if (r.stanje !== "caka") return r.stanje;
  if (r.vrsta === "dobropis" && (r.ref_stevilka === null || r.ref_stevilka === undefined)) return "odlozeno";   // nikoli pred izvirnim racunom
  if (r.vrsta === "dobropis" && r.vracilo_uspelo !== true) return "odlozeno";   // S2: samo za izvedeno vracilo
  return null;
}
async function izdajVTransakciji(c, id, { prostor = PROSTOR, naprava = NAPRAVA } = {}) {
  const pred = razlogNeizdaje((await c.query(SQL_IZDAJLJIV, [id])).rows[0]);
  if (pred) return { stanje: pred };
  for (let i = 0; i < 2; i++) {
    const leto = (await c.query(`SELECT EXTRACT(YEAR FROM clock_timestamp() AT TIME ZONE '${CASOVNI_PAS}')::int AS leto`)).rows[0].leto;
    await c.query("INSERT INTO racuni_zaporedje (prostor, naprava, leto) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING", [prostor, naprava, leto]);
    await c.query("SELECT zadnja FROM racuni_zaporedje WHERE prostor = $1 AND naprava = $2 AND leto = $3 FOR UPDATE", [prostor, naprava, leto]);
    const zdaj = razlogNeizdaje((await c.query(SQL_IZDAJLJIV + " FOR NO KEY UPDATE OF r", [id])).rows[0]);   // stanje se je lahko spremenilo med cakanjem na stevec
    if (zdaj) return { stanje: zdaj };
    const cas = (await c.query(`SELECT clock_timestamp() AS cas, EXTRACT(YEAR FROM clock_timestamp() AT TIME ZONE '${CASOVNI_PAS}')::int AS leto`)).rows[0];
    if (cas.leto !== leto) continue;   // novo leto med cakanjem na zaklep: stevilka iz novega zaporedja (zaklep starega se ob COMMIT sprosti, stevec ni spremenjen)
    const z = (await c.query("UPDATE racuni_zaporedje SET zadnja = zadnja + 1 WHERE prostor = $1 AND naprava = $2 AND leto = $3 RETURNING zadnja", [prostor, naprava, leto])).rows[0].zadnja;
    await c.query("UPDATE racuni SET prostor = $2, naprava = $3, leto = $4, stevilka = $5, izdan_at = $6, stanje = 'izdan' WHERE id = $1", [id, prostor, naprava, leto, z, cas.cas]);
    return { stanje: "izdan", stevilka: Number(z), izdan_at: cas.cas };
  }
  throw new Error("menjava leta med izdajo racuna");
}

function ustvari({ pool, env = process.env, ponudnik: vstavljen = null }) {   // vstavljen: samo testi (lastna implementacija ponudnika)
  const izbira = vstavljen ? { ime: vstavljen.ime || "test", ponudnik: vstavljen, opozorilo: null } : izberiPonudnika(env);
  const ponudnik = izbira.ponudnik;
  const stevilcenjePonudnik = !!(ponudnik && ponudnik.stevilcenje === "ponudnik");   // ponudnik sam dodeli davcno stevilko (e-racuni): nas stevec se ne uporablja
  const TICK_MS = celo(env, "RACUNI_TICK_MS", 2000, 0, 3600000);                 // 0 = delavec ne tece (tudi ob izbranem ponudniku)
  const VZPOREDNO = Math.min(celo(env, "RACUNI_VZPOREDNO", 4, 1, 50), (ponudnik && ponudnik.najvecVzporednih) || 50);   // hkratni klici ponudnika (e-racuni: 1)
  const DB_VZPOREDNO = celo(env, "RACUNI_DB_VZPOREDNO", 2, 1, 10);               // hkratne kratke transakcije delavca (stevilcenje je tako ali tako zaporedno)
  const ROK_MS = celo(env, "RACUNI_ROK_MS", (ponudnik && ponudnik.rokMs) || 5000, 100, 120000);   // rok enega klica ponudnika
  const PAKET = celo(env, "RACUNI_PAKET", (ponudnik && ponudnik.paket) || 50, 1, 1000);
  const PREMOR_MS = celo(env, "RACUNI_PREMOR_MS", 0, 0, 86400000);              // stalen premor (testi); 0 = narascajoc
  const NEZNAN_PREMOR_MS = celo(env, "RACUNI_NEZNAN_PREMOR_MS", 120000, 0, 86400000);   // izid klica neznan (rok, 5xx, omrezje): najmanj toliko do iskanja po referenci in nove izdaje
  const KONFIG_PREMOR_MS = celo(env, "RACUNI_KONFIG_PREMOR_MS", 600000, 0, 86400000);   // poverilnice/nastavitev pri ponudniku: pocasna ponovitev (+ POZOR), vrstica ni `napaka`
  const ODLOG_MS = celo(env, "RACUNI_ODLOG_MS", 30000, 0, 3600000);             // dobropis caka na stevilko oz. potrditev izvirnega racuna
  const ZASTARELO_MS = celo(env, "RACUNI_ZASTARELO_MS", (ponudnik && ponudnik.zastarelo) || 120000, 1000, 3600000); // prevzeto brez zakljucka (proces ugasnjen) se prevzame znova (isti message_id)
  const NAJEM_MS = celo(env, "RACUNI_NAJEM_MS", 90000, 1000, 3600000);          // najem delavca e-racuni (en delavec v celem sistemu): daljsi od roka klica, podaljsa se pred vsakim klicem
  const ISKANJE_RAZMAK_MS = celo(env, "RACUNI_ISKANJE_RAZMAK_MS", 600000, 0, 86400000);   // najmanj toliko med dvema stetima iskanjema po referenci; nova izdaja sele po 2 neuspesnih iskanjih
  const ISKANJE_NEJASNO_MAX = celo(env, "RACUNI_ISKANJE_NEJASNO_MAX", 4, 1, 100);   // toliko iskanj brez zanesljivega izida -> `napaka` (rocna obravnava), nikoli nova izdaja
  const ID_NAJEMA = crypto.randomUUID();
  const POSPRAVI_MS = celo(env, "RACUNI_POSPRAVI_MS", 600000, 0, 86400000);     // pospravljalec (0 = izklopljen)
  const POSPRAVI_ZAMIK_MS = celo(env, "RACUNI_POSPRAVI_ZAMIK_MS", 300000, 0, 86400000);
  const ALARM_PO_MS = celo(env, "RACUNI_ALARM_PO_MS", 24 * 3600000, 1000, 30 * 86400000);   // racun ni potrjen toliko casa -> POZOR (zakonski rok: 2 delovna dneva)
  const LUKNJA_PO_MS = celo(env, "RACUNI_LUKNJA_PO_MS", 3600000, 0, 30 * 86400000);   // stevilka ponudnika, ki manjka, a je naslednja stara toliko -> POZOR (luknja v zaporedju)
  const PRORACUN_MS = 45000;
  const PREMORI = [5e3, 30e3, 120e3, 600e3, 1800e3, 3600e3];

  const klici = semafor(VZPOREDNO);
  const baza = semafor(DB_VZPOREDNO);
  const premor = (poskusi) => (PREMOR_MS > 0 ? PREMOR_MS : PREMORI[Math.min(Math.max(poskusi, 1), PREMORI.length) - 1]);
  const kratko = (e) => `${e && e.name ? e.name : "Error"}: ${e && e.message ? e.message : String(e)}`.replace(/\s+/g, " ").slice(0, 300);

  async function vTransakciji(fn) {
    return baza(async () => {
      const c = await pool.connect();
      try {
        await c.query("BEGIN");
        await c.query("SELECT set_config('lock_timeout', '3000', true), set_config('statement_timeout', '5000', true)");
        const rez = await fn(c);
        await c.query("COMMIT");
        return rez;
      } catch (e) { await c.query("ROLLBACK").catch(() => {}); throw e; } finally { c.release(); }
    });
  }
  const poizvedba = (sql, par) => baza(() => pool.query(sql, par));
  // Z zetonom: sprosti samo, ce vrstico se drzi NAS prevzem (po zastaranju jo je lahko prevzel drug in njegovega prevzema ne smemo sprostiti).
  const sprosti = (id, dodatno = "", par = [], zeton = null) => (zeton
    ? poizvedba(`UPDATE racuni SET prevzeto_at = NULL${dodatno} WHERE id = $1 AND prevzem_zeton = $${par.length + 2}`, [id, ...par, zeton])
    : poizvedba(`UPDATE racuni SET prevzeto_at = NULL${dodatno} WHERE id = $1`, [id, ...par]));

  // Zapis delavca pri ponudniku s svojim prevzemom: vrstica mora biti PREVZETA in z NASIM zetonom (K2: prevzem po zastaranju ali prekrivanje instanc ob deployu ne sme
  // podvojiti izdaje). Mesta v `nastavi` in `pogoj` se zacnejo pri $3 ($1 = id, $2 = zeton). Vrne stevilo spremenjenih vrstic.
  async function uredi(id, zeton, nastavi, par, pogoj = "TRUE") {
    const r = await poizvedba(`UPDATE racuni SET ${nastavi} WHERE id = $1 AND prevzem_zeton = $2 AND prevzeto_at IS NOT NULL AND ${pogoj}`, [id, zeton, ...par]);
    return r.rowCount;
  }

  // Najem »samo en delavec e-racuni v celem sistemu« (K2): API ne dovoli socasnih zahtevkov istega uporabnika, ob deployu pa tecejo dve instanci. Pridobi ali podaljsa;
  // ne uspe samo, ce ga drzi drug lastnik, ki mu se ni potekel. Pred VSAKIM klicem ponudniku podaljsan na NAJEM_MS (> rok klica), zato po zrusitvi instance drugi pocaka najvec toliko.
  async function najemi() {
    const r = await poizvedba(
      `INSERT INTO racuni_najem (ime, lastnik, potece_at) VALUES ($1, $2, NOW() + ($3::bigint * INTERVAL '1 millisecond'))
       ON CONFLICT (ime) DO UPDATE SET lastnik = EXCLUDED.lastnik, potece_at = EXCLUDED.potece_at
        WHERE racuni_najem.lastnik = EXCLUDED.lastnik OR racuni_najem.potece_at < NOW() RETURNING lastnik`, [ponudnik.ime, ID_NAJEMA, NAJEM_MS]);
    return r.rows.length === 1;
  }
  const spustiNajem = () => poizvedba("UPDATE racuni_najem SET potece_at = NOW() WHERE ime = $1 AND lastnik = $2", [ponudnik.ime, ID_NAJEMA]).catch(() => {});
  const obstajaDelo = async () => (await poizvedba(
    `SELECT 1 FROM racuni WHERE stanje IN ('caka', 'izdan') AND naslednji_poskus_at <= NOW() AND (vrsta = 'racun' OR vracilo_uspelo IS TRUE)
        AND (prevzeto_at IS NULL OR prevzeto_at < NOW() - ($1::bigint * INTERVAL '1 millisecond')) LIMIT 1`, [ZASTARELO_MS])).rows.length > 0;

  // Opozorila delavca se zberejo in izpisejo ENKRAT na tek (en izpis na vrsto dogodka, ne na vrstico): sicer zaostanek stotin racunov izcrpa urni proracun opozoril v sentry.js
  // in zakrije druga opozorila (placila).
  let zbir = [];
  const objavi = (tip, oznaka, besedilo) => { zbir.push({ tip, oznaka, besedilo }); };
  function izpisiZbir() {
    const v = zbir; zbir = [];
    const skupine = new Map();
    for (const x of v) { if (!skupine.has(x.tip)) skupine.set(x.tip, []); skupine.get(x.tip).push(x); }
    const NASLOVI = {
      trajna: (n) => `POZOR: ponudnik ${ponudnik.ime} je ZAVRNIL ${n} racunov/dobropisov (stanje napaka, NISO potrjeni; popravi in ponovi rocno, zakonski rok 2 delovna dneva)`,
      konfiguracija: (n) => `POZOR: nastavitev pri ponudniku ${ponudnik.ime} (poverilnice, poslovna enota, blagajna) - ${n} racunov caka`,
      ponovitev: (n) => `${n} racunov: klic ponudniku ${ponudnik.ime} ni uspel, ponovim`,
      iskanje: (n) => `${n} racunov: izid prejsnjega zahtevka ponudniku ${ponudnik.ime} je neznan, iskanje po referenci se ni zakljucilo (nova izdaja je blokirana)`,
      obdelava: (n) => `POZOR: obdelava ${n} racunov ni uspela`,
    };
    for (const [tip, sez] of skupine) {
      const primeri = sez.slice(0, 3).map((x) => `${x.oznaka}: ${x.besedilo}`).join(" | ");
      console.error(`[racuni] ${(NASLOVI[tip] || ((n) => `${n} dogodkov (${tip})`))(sez.length)}. ${primeri}${sez.length > 3 ? ` (in se ${sez.length - 3})` : ""}`);
    }
  }

  const SQL_PODATKI_RACUNA = `SELECT r.*, ref.prostor AS ref_prostor, ref.naprava AS ref_naprava, ref.stevilka AS ref_stevilka, ref.izdan_at AS ref_izdan_at, ref.stanje AS ref_stanje,
              ref.eor AS ref_eor, ref.ponudnik_id AS ref_ponudnik_id, ref.ponudnik_stevilka AS ref_ponudnik_stevilka, o.public_ref, o.quantity, o.unit_price_cents, o.total_cents, o.table_label, e.title, e.start_at,
              o.paid_at AS placano_at, r.poslano_at::text AS poslano_niz,
              (EXTRACT(EPOCH FROM (NOW() - r.iskanje_ne_at)) * 1000)::float8 AS iskanje_pred_ms
         FROM racuni r JOIN orders o ON o.id = r.order_id JOIN events e ON e.id = o.event_id LEFT JOIN racuni ref ON ref.id = r.ref_racun_id WHERE r.id = $1`;

  // Podatki za ponudnika (brez e-naslova in imena kupca). Isti message_id ob vsaki ponovitvi.
  async function podatkiZaPotrditev(id) {
    const r = (await poizvedba(
      SQL_PODATKI_RACUNA, [id])).rows[0];
    if (!r) return null;
    const v = vsebinaRacuna(r, r);
    return {
      vrstica: r,
      podatki: {
        id: String(r.id), message_id: r.message_id, vrsta: r.vrsta, naknadno: !!r.naknadno,
        stevilka_racuna: v.stevilka, prostor: r.prostor, naprava: r.naprava, zaporedna: Number(r.stevilka), izdan_at: new Date(r.izdan_at).toISOString(),
        davcna_izdajatelja: IZDAJATELJ.davcna, davcna_operaterja: OPERATER, znesek_cents: Number(r.znesek_cents), valuta: v.valuta,
        postavke: v.postavke, ddv_klavzula: DDV_KLAVZULA, nacin_placila: NACIN_PLACILA, narocilo: r.public_ref,
        sklic: r.vrsta === "dobropis" ? { stevilka_racuna: v.sklic && v.sklic.stevilka, izdan_at: r.ref_izdan_at ? new Date(r.ref_izdan_at).toISOString() : null, eor: r.ref_eor || null, ponudnik_id: r.ref_ponudnik_id || null } : null,
      },
    };
  }

  // Klic ponudnika pod semaforjem, BREZ drzane povezave. Rok tece sele, ko klic dobi mesto v semaforju (sicer bi klic, ki caka v vrsti dlje od roka, padel, preden bi bil poslan).
  // Trd rok (pregled #315, M1): Promise.race s casovnikom. Ponudnik, ki signal prezre in se nikoli ne odzove, NE zasede semaforja za vedno (mesto se sprosti ob roku).
  // Po roku je izid klica NEZNAN (`neznan`): pri ponudniku s svojim stevilcenjem sledi najprej iskanje po referenci.
  function izvediKlic(fn) {
    return klici(async () => {
      const ctl = new AbortController();
      let t;
      const klic = Promise.resolve().then(() => fn(ctl.signal));
      klic.catch(() => {});   // pozen odgovor/napaka po roku se zavrze (brez unhandledRejection)
      const rok = new Promise((_, zavrni) => { t = setTimeout(() => { ctl.abort(); zavrni(new NapakaPonudnika(`rok ${ROK_MS} ms potekel`, { neznan: true })); }, ROK_MS); });
      try { return await Promise.race([klic, rok]); } finally { clearTimeout(t); }
    });
  }

  async function potrdi(id) {
    const pz = await podatkiZaPotrditev(id);
    if (!pz || pz.vrstica.stanje !== "izdan") { await sprosti(id); return; }
    const r = pz.vrstica;
    if (r.vrsta === "dobropis" && r.ref_stanje !== "potrjen") {   // dobropis gre ponudniku sele po potrjenem izvirnem racunu
      // izvirni racun v `napaka` (rocna obravnava): dobropis caka redkeje (alarm za racun ze tece), sicer ODLOG_MS
      await sprosti(id, ", naslednji_poskus_at = NOW() + ($2::bigint * INTERVAL '1 millisecond')", [r.ref_stanje === "napaka" ? Math.max(ODLOG_MS, 600000) : ODLOG_MS]);
      return;
    }
    let izid;
    try {
      izid = await izvediKlic((signal) => ponudnik.potrdi(pz.podatki, { signal }));
    } catch (e) { izid = { napaka: e }; }
    if (!izid || izid.napaka) {
      const e = (izid && izid.napaka) || new Error("prazen odgovor");
      const trajna = e instanceof NapakaPonudnika && e.trajna;
      if (trajna) {
        await poizvedba("UPDATE racuni SET stanje = 'napaka', poskusi = poskusi + 1, zadnja_napaka = $2, prevzeto_at = NULL WHERE id = $1 AND stanje = 'izdan'", [id, kratko(e)]);
        console.error(`[racuni] POZOR: ${r.vrsta} ${pz.podatki.stevilka_racuna} (narocilo ${r.public_ref}) je ponudnik ${ponudnik.ime} ZAVRNIL: ${kratko(e)}. Racun je izdan, a NI potrjen; popravi in potrdi rocno (zakonski rok 2 delovna dneva).`);
        return;
      }
      await poizvedba(
        `UPDATE racuni SET poskusi = poskusi + 1, naknadno = TRUE, zadnja_napaka = $2, prevzeto_at = NULL,
                naslednji_poskus_at = NOW() + ($3::bigint * INTERVAL '1 millisecond') WHERE id = $1 AND stanje = 'izdan'`, [id, kratko(e), premor(Number(r.poskusi) + 1)]);
      console.error(`[racuni] ${r.vrsta} ${pz.podatki.stevilka_racuna}: potrditev ni uspela (poskus ${Number(r.poskusi) + 1}), ponovim: ${kratko(e)}`);
      return;
    }
    const eor = typeof izid.eor === "string" && UUID.test(izid.eor) ? izid.eor.toLowerCase() : null;
    const zoi = typeof izid.zoi === "string" && /^[0-9a-f]{32}$/i.test(izid.zoi) ? izid.zoi.toLowerCase() : null;
    const pid = typeof izid.ponudnik_id === "string" && izid.ponudnik_id.length >= 1 && izid.ponudnik_id.length <= 200 ? izid.ponudnik_id : null;
    if (!eor || (izid.zoi !== undefined && izid.zoi !== null && !zoi)) {
      await poizvedba("UPDATE racuni SET stanje = 'napaka', zadnja_napaka = $2, prevzeto_at = NULL WHERE id = $1 AND stanje = 'izdan'", [id, "neveljaven odgovor ponudnika (EOR/ZOI)"]);
      console.error(`[racuni] POZOR: ${r.vrsta} ${pz.podatki.stevilka_racuna} (narocilo ${r.public_ref}): ponudnik ${ponudnik.ime} je vrnil neveljaven EOR/ZOI; preveri pri ponudniku, ali je racun potrjen.`);
      return;
    }
    await poizvedba(
      `UPDATE racuni SET stanje = 'potrjen', eor = $2, zoi = COALESCE(zoi, $3), ponudnik = $4, ponudnik_id = COALESCE(ponudnik_id, $5), potrjen_at = NOW(),
              zadnja_napaka = NULL, prevzeto_at = NULL WHERE id = $1 AND stanje = 'izdan'`, [id, eor, zoi, ponudnik.ime, pid]);
  }

  // ---------------------------------------------------------------------------------------------------------------------------------------------------------
  // Ponudnik, ki SAM dodeli davcno stevilko (e-racuni). Racun ima stanje `caka` (brez stevilke) do trenutka, ko ponudnik vrne `fiscalNumber`; ENO zaporedje je njegovo.
  //   S1 izdaja:   (ce je zahtevek ze bil poslan, a stevilke ni: NAJPREJ iskanje po referenci = message_id; nova izdaja sele po 2 veljavnih neuspesnih iskanjih ~10 min narazen)
  //                -> poslano_at -> ustvari -> ponudnik_id, ponudnik_stevilka
  //   S2 stevilka: preberi -> fiscalNumber (+ EOR, ZOI) -> stevilka, prostor, naprava, leto, izdan_at (samo ce ga ponudnik vrne), stevilka_vir = 'ponudnik' (+ `potrjen`, ce je EOR znan)
  //   S3 potrditev: izdan brez EOR -> preberi -> eor, zoi -> `potrjen`
  // Nikoli nova izdaja, dokler izid prejsnjega zahtevka ni znan (API nima idempotence): dvojnik bi bil drug davcni racun za isto prodajo in ga ni mogoce izbrisati.
  // Varovala: (a) `poslano_at` se po posiljanju NE brise, razen ob HTTP 429 ali dokazani napaki povezave pred posiljanjem (NapakaPonudnika.neposlano) - nikoli po besedilu napake;
  // (b) en delavec e-racuni v celem sistemu (najem v bazi) in zeton prevzema vrstice na vsakem zapisu; (c) iskanje po referenci brez zanesljivega izida ni »ni najden«.
  async function podatkiZaPonudnika(id) {
    const r = (await poizvedba(SQL_PODATKI_RACUNA, [id])).rows[0];
    if (!r) return null;
    const dobropis = r.vrsta === "dobropis";
    const refStevilka = dobropis && r.ref_stevilka !== null && r.ref_stevilka !== undefined ? stevilkaRacuna(r.ref_prostor, r.ref_naprava, r.ref_stevilka) : null;
    return {
      vrstica: r,
      podatki: {
        id: String(r.id), message_id: r.message_id, vrsta: r.vrsta, naknadno: !!r.naknadno, poslano_at: r.poslano_at ? new Date(r.poslano_at).toISOString() : null,
        znesek_cents: Number(r.znesek_cents), valuta: String(r.valuta || "EUR").trim(), postavke: refStevilka || !dobropis ? postavkeRacuna(r, r) : [],
        ddv_klavzula: DDV_KLAVZULA, nacin_placila: NACIN_PLACILA, narocilo: r.public_ref,
        datum_dobave: datumIso(!dobropis && r.placano_at ? r.placano_at : r.created_at),   // M1: dan placila (dobropis: dan vracila), ne dan izdaje
        sklic: dobropis ? { stevilka_racuna: refStevilka, ponudnik_id: r.ref_ponudnik_id || null, ponudnik_stevilka: r.ref_ponudnik_stevilka || null, eor: r.ref_eor || null } : null,
      },
    };
  }

  // Podatki za iskanje po referenci: obdobje okoli `poslano_at` in referenca vseh dokumentov iste vrste, za katere ze vemo, da pri ponudniku obstajajo (dokaz popolnosti seznama).
  async function podatkiZaIskanje(r, poslanoAt) {
    const okno = oknoIskanja(poslanoAt);
    const znani = (await poizvedba(
      `SELECT message_id::text AS m FROM racuni WHERE vrsta = $1 AND id <> $2 AND (ponudnik_id IS NOT NULL OR ponudnik_stevilka IS NOT NULL) AND poslano_at IS NOT NULL
          AND (poslano_at AT TIME ZONE 'Europe/Ljubljana')::date BETWEEN $3::date AND $4::date ORDER BY poslano_at DESC LIMIT 100`, [r.vrsta, r.id, okno.od, okno.do])).rows.map((x) => x.m);
    return { okno, znani };
  }

  // Vrstica se TRAJNO zaklene pred novo izdajo (`napaka`, brez ponovitve): ponudnik je dokument ze ustvaril ali pa izida ne moremo zanesljivo ugotoviti.
  async function zakleni(r, zeton, sporocilo) {
    const s = String(sporocilo).slice(0, 300);
    await uredi(r.id, zeton, "stanje = 'napaka', poskusi = poskusi + 1, zadnja_napaka = $3, prevzeto_at = NULL", [s], "stanje IN ('caka', 'izdan', 'napaka')");
    objavi("trajna", `${r.vrsta} (narocilo ${r.public_ref}, vrstica ${r.id})`, s);
  }

  // Bralni preizkus pred prvim Create v teku (en klic na tek, ne na vrstico). Pade -> Create se ne poslje (`neposlano`), vrstica ostane `caka`, POZOR. Ne-konfiguracijska
  // `trajna` napaka (npr. List ne pozna parametra) NE blokira izdaje: ne govori o poverilnicah, seznam pa ni zivo preverjen.
  let preizkusTek = null, preizkusNapaka = null;
  async function preizkusPredIzdajo(klicPonudniku) {
    if (!ponudnik.preizkusi) return;
    if (!preizkusTek) preizkusTek = klicPonudniku((signal) => ponudnik.preizkusi({ signal })).then(() => null, (e) => { if (!(e instanceof NapakaPonudnika)) throw e; return e; });
    const e = await preizkusTek;
    if (e && !preizkusNapaka && (e.konfiguracija || !e.trajna)) preizkusNapaka = e;
  }
  const brezIzdajeZaradiPreizkusa = () => new NapakaPonudnika(`bralni preizkus pred izdajo ni uspel, racun ni poslan: ${String(preizkusNapaka.message || preizkusNapaka).slice(0, 200)}`, { konfiguracija: !!preizkusNapaka.konfiguracija, neznan: false, neposlano: true });

  async function napakaPriPonudniku(r, e, korak, zeton) {
    const oznaka = `${r.vrsta} (narocilo ${r.public_ref}, vrstica ${r.id})`;
    // `poslano_at` se pobrise SAMO, ce je DOKAZANO, da zahtevek ni prisel do ponudnika (429 po statusni kodi, napaka povezave pred posiljanjem, lokalna zavrnitev), je ta poskus
    // sam nastavil `poslano_at` (prej ni bil poslan noben zahtevek) in gre za izdajo. Besedilo napake ni dokaz (K1: ponudnik lahko dokument ustvari in nato javi napako).
    const pobrisi = !!(e.neposlano && korak === "ustvari" && !r.poslano_at);
    const nejasnih = Number(r.iskanja_nejasna) + (e.nejasno ? 1 : 0);
    if (e.trajna || (e.nejasno && nejasnih >= ISKANJE_NEJASNO_MAX)) {
      const sporocilo = e.nejasno
        ? `iskanje po referenci ${nejasnih}x brez zanesljivega izida (${kratko(e)}); v e-racuni preveri, ali obstaja dokument z referenco ${r.message_id}, PREDEN racun ponovis`
        : `${korak} ZAVRNJEN: ${kratko(e)}${korak === "ustvari" && !pobrisi ? `; zahtevek je bil poslan, zato v e-racuni preveri, ali obstaja dokument z referenco ${r.message_id}` : ""}`;
      await uredi(r.id, zeton,
        "stanje = 'napaka', poskusi = poskusi + 1, zadnja_napaka = $3, prevzeto_at = NULL, iskanja_nejasna = $5, poslano_at = CASE WHEN $4::boolean AND ponudnik_id IS NULL AND stevilka IS NULL THEN NULL ELSE poslano_at END",
        [sporocilo.slice(0, 300), pobrisi, nejasnih], "stanje IN ('caka', 'izdan')");
      objavi("trajna", oznaka, sporocilo.slice(0, 300));
      return;
    }
    // Create zavrnjen zaradi nastavitve/poverilnic: ostalim vrsticam v tem teku Create ne gre (preizkus je bil uspel, kljuc je odpovedal vmes)
    if (e.konfiguracija && korak === "ustvari" && !preizkusNapaka) preizkusNapaka = e;
    const premorMs = Math.max(premor(Number(r.poskusi) + 1), e.neznan ? NEZNAN_PREMOR_MS : 0, e.konfiguracija ? KONFIG_PREMOR_MS : 0);
    await uredi(r.id, zeton,
      `poskusi = poskusi + 1, naknadno = TRUE, zadnja_napaka = $3, prevzeto_at = NULL, iskanja_nejasna = $5,
       poslano_at = CASE WHEN $6::boolean AND ponudnik_id IS NULL AND stevilka IS NULL THEN NULL ELSE poslano_at END,
       naslednji_poskus_at = NOW() + ($4::bigint * INTERVAL '1 millisecond')`,
      [kratko(e), premorMs, nejasnih, pobrisi], "stanje IN ('caka', 'izdan')");
    objavi(e.konfiguracija ? "konfiguracija" : "ponovitev", oznaka, `${korak}${e.neznan ? ", izid neznan" : ""}: ${kratko(e)}`);
  }

  async function obdelajPonudnik(id, zeton) {
    const pz = await podatkiZaPonudnika(id);
    const odpri = (dodatno = "", par = []) => sprosti(id, dodatno, par, zeton);
    if (!pz) { await odpri(); return; }
    const r = pz.vrstica;
    if (r.stanje !== "caka" && r.stanje !== "izdan") { await odpri(); return; }
    const odlozi = (ms) => odpri(", naslednji_poskus_at = NOW() + ($2::bigint * INTERVAL '1 millisecond')", [ms]);
    if (r.vrsta === "dobropis") {
      if (r.stevilka === null && r.vracilo_uspelo !== true) { await odlozi(ODLOG_MS); return; }   // S2: samo za izvedeno vracilo
      // dobropis gre ponudniku sele po potrjenem izvirnem racunu (ima stevilko in oznako dokumenta pri ponudniku); izvirni racun v `napaka`: redkeje
      if (r.ref_stanje !== "potrjen") { await odlozi(r.ref_stanje === "napaka" ? Math.max(ODLOG_MS, 600000) : ODLOG_MS); return; }
    }
    // Vsak klic ponudniku: najprej najem (en delavec v sistemu), nato semafor + rok. Brez najema klic NI poslan.
    const klicPonudniku = (fn) => izvediKlic(async (signal) => {
      if (!(await najemi())) throw new NapakaPonudnika("najem delavca za ponudnika drzi drug proces (klic ni poslan)", { neznan: false, neposlano: true });
      return fn(signal);
    });
    let korak = "ustvari";
    try {
      let pid = r.ponudnik_id, pst = r.ponudnik_stevilka;
      if (r.stevilka === null && !pid && !pst) {
        if (r.poslano_at) {   // izid prejsnjega zahtevka neznan: NAJPREJ poisci
          korak = "iskanje";
          const ip = await podatkiZaIskanje(r, r.poslano_at);
          const najden = await klicPonudniku((signal) => ponudnik.poisci({ ...pz.podatki, ...ip }, { signal }));
          if (najden && (najden.ponudnik_id || najden.ponudnik_stevilka)) { pid = najden.ponudnik_id; pst = najden.ponudnik_stevilka; }
          else if (ponudnik.seznamPreverjen === false) {
            await zakleni(r, zeton, `iskanje po referenci dokumenta ni nasla, a seznam e-racuni se NI zivo preverjen (ERACUNI_SEZNAM_PREVERJEN); v e-racuni preveri, ali obstaja dokument z referenco ${r.message_id}, PREDEN racun ponovis`);
            return;
          } else {
            // Veljavno negativno iskanje. Nova izdaja sele po DVEH takih iskanjih, med njima najmanj ISKANJE_RAZMAK_MS (dokument je lahko v seznamu viden z zamikom).
            const steje = r.iskanje_ne_at === null || r.iskanje_ne_at === undefined || Number(r.iskanje_pred_ms) >= ISKANJE_RAZMAK_MS;
            const n = Number(r.iskanja_ne) + (steje ? 1 : 0);
            if (n < 2) {
              await uredi(id, zeton,
                `iskanja_ne = $3, iskanje_ne_at = CASE WHEN $4::boolean THEN NOW() ELSE iskanje_ne_at END, iskanja_nejasna = 0, prevzeto_at = NULL,
                 zadnja_napaka = $5, naslednji_poskus_at = NOW() + ($6::bigint * INTERVAL '1 millisecond')`,
                [n, steje, `zahtevek je bil poslan, izid neznan: iskanje ${n}/2 dokumenta ni nasla`, Math.max(ISKANJE_RAZMAK_MS, 5000)], "stanje = 'caka'");
              objavi("iskanje", `${r.vrsta} (narocilo ${r.public_ref}, vrstica ${id})`, `iskanje ${n}/2 dokumenta ni nasla, naslednje cez ${Math.round(ISKANJE_RAZMAK_MS / 1000)} s`);
              return;
            }
          }
        }
        if (!pid && !pst) {
          korak = "ustvari";
          await preizkusPredIzdajo(klicPonudniku);
          if (preizkusNapaka) throw brezIzdajeZaradiPreizkusa();
          const o = await klicPonudniku(async (signal) => {
            if (preizkusNapaka) throw brezIzdajeZaradiPreizkusa();   // v istem teku je kljuc ze odpovedal (preizkus ali Create): ostalim vrsticam Create ne gre
            // Varovalo (K2): zapis »poslano« velja samo ob nasem prevzemu IN ob nespremenjenem prejsnjem poslano_at; sicer klic NI poslan.
            const ok = await uredi(id, zeton, "poslano_at = NOW(), iskanja_ne = 0, iskanje_ne_at = NULL, iskanja_nejasna = 0", [r.poslano_niz],
              "stanje = 'caka' AND stevilka IS NULL AND ponudnik_id IS NULL AND ponudnik_stevilka IS NULL AND poslano_at IS NOT DISTINCT FROM $3::timestamptz");
            if (!ok) throw new NapakaPonudnika("vrstico je medtem prevzel ali spremenil drug proces (zahtevek ni poslan)", { neznan: false, neposlano: true });
            return ponudnik.ustvari(pz.podatki, { signal });
          });
          pid = o && o.ponudnik_id; pst = o && o.ponudnik_stevilka;
          if (!pid && !pst) {   // izdano (ponudnik je potrdil uspeh), a odgovor brez oznake dokumenta: poisci ga po referenci; ce ga ne najdemo, vrstica NIKOLI ne gre v novo izdajo
            korak = "iskanje";
            // Zastavica »ustvarjeno pri ponudniku«: vrstica je `napaka` ze PRED iskanjem (prevzem ostane nas). Ce se proces ustavi (deploy, padec) med Create in koncem iskanja, vrstice
            // nihce vec ne prevzame in po restartu ne gre v novo izdajo, tudi ob ERACUNI_SEZNAM_PREVERJEN=1 (seznam je lahko viden z zamikom).
            const zakljucena = await uredi(id, zeton, "stanje = 'napaka', zadnja_napaka = $3", ["Create je uspel, a odgovor ni vseboval oznake dokumenta; poteka iskanje po referenci"], "stanje = 'caka'");
            if (!zakljucena) throw new NapakaPonudnika("vrstico je medtem prevzel ali spremenil drug proces", { neznan: false, neposlano: true });
            let najden = null;
            try {
              const ip = await podatkiZaIskanje(r, new Date());
              najden = await klicPonudniku((signal) => ponudnik.poisci({ ...pz.podatki, ...ip, poslano_at: new Date().toISOString() }, { signal }));
            } catch (e) { if (!(e instanceof NapakaPonudnika)) throw e; }
            if (!najden || !(najden.ponudnik_id || najden.ponudnik_stevilka)) {
              await zakleni(r, zeton, `Create je uspel, a odgovor ni vseboval oznake dokumenta in ga iskanje po referenci ne najde; v e-racuni poisci dokument z referenco ${r.message_id} in ga poveži rocno, PREDEN racun ponovis (nova izdaja = dvojnik davcnega racuna)`);
              return;
            }
            pid = najden.ponudnik_id; pst = najden.ponudnik_stevilka;
          }
        }
        // Oznaka in stevilka dokumenta sta LOCENI polji (S1): nikoli ena namesto druge.
        const zapisano = await uredi(id, zeton, "ponudnik = $3, ponudnik_id = $4, ponudnik_stevilka = $5, stanje = 'caka', zadnja_napaka = NULL", [ponudnik.ime, pid || null, pst || null],
          "stanje IN ('caka', 'napaka') AND stevilka IS NULL AND ponudnik_id IS NULL AND ponudnik_stevilka IS NULL");
        if (!zapisano) {
          objavi("obdelava", `${r.vrsta} (narocilo ${r.public_ref}, vrstica ${id})`, `dokument ${pid || pst} pri ponudniku je nastal, a vrstice ni bilo mogoce posodobiti (prevzel jo je drug proces); nadaljuje ta, najde ga z iskanjem po referenci`);
          return;
        }
      }
      korak = "branje";
      const st = await klicPonudniku((signal) => ponudnik.preberi({ vrsta: r.vrsta, ponudnik_id: pid, ponudnik_stevilka: pst }, { signal }));
      const eor = st && typeof st.eor === "string" && UUID.test(st.eor) ? st.eor.toLowerCase() : null;
      const zoi = st && typeof st.zoi === "string" && /^[0-9a-f]{32}$/i.test(st.zoi) ? st.zoi.toLowerCase() : null;
      const neveljaven = !!st && ((st.eor && !eor) || (st.zoi && !zoi));
      const stDokumenta = st && st.ponudnik_stevilka && st.ponudnik_stevilka.length <= 100 ? st.ponudnik_stevilka : null;   // S2: stevilka dokumenta za sklic dobropisa
      const izdanAt = st && st.izdan_at instanceof Date ? st.izdan_at : null;   // S3: cas izdaje SAMO ce ga je ponudnik vrnil, nikoli izmisljen
      if (r.stevilka === null) {
        if (!st || !st.stevilka) throw new NapakaPonudnika("davcna stevilka dokumenta pri ponudniku se ni dodeljena", { neznan: false });
        const leto = st.datum ? Number(st.datum.slice(0, 4)) : Number(deliCasa(izdanAt || new Date()).leto);
        const stanje = neveljaven ? "napaka" : (eor ? "potrjen" : "izdan");
        let u;
        try {
          u = await uredi(id, zeton,
            `prostor = $3, naprava = $4, leto = $5, stevilka = $6, izdan_at = $7, stevilka_vir = 'ponudnik', stanje = $8::text, eor = $9::uuid, zoi = COALESCE(zoi, $10),
             ponudnik_stevilka = COALESCE(ponudnik_stevilka, $11), potrjen_at = CASE WHEN $8::text = 'potrjen' THEN NOW() END, zadnja_napaka = $12, prevzeto_at = NULL`,
            [ponudnik.prostor, ponudnik.naprava, leto, st.stevilka, izdanAt, stanje, neveljaven ? null : eor, neveljaven ? null : zoi, stDokumenta, neveljaven ? "neveljaven odgovor ponudnika (EOR/ZOI)" : null],
            "stanje = 'caka' AND stevilka IS NULL");
        } catch (e) {
          if (e && (e.code === "23505" || e.code === "23001")) {   // stevilka ze obstaja ali sprozilec zavrne (npr. v prostoru so ze stevilke drugega vira): ne ponavljaj
            await uredi(id, zeton, "stanje = 'napaka', zadnja_napaka = $3, prevzeto_at = NULL", [`stevilka ${st.stevilka} pri ponudniku ni sprejeta: ${kratko(e)}`.slice(0, 300)], "stanje = 'caka'");
            console.error(`[racuni] POZOR: ${r.vrsta} (narocilo ${r.public_ref}, vrstica ${id}): ponudnik ${ponudnik.ime} je dodelil stevilko ${st.stevilka} (dokument ${pid || pst}), a je ni mogoce zapisati: ${kratko(e)}. Zaporedji se RAZHAJATA - preveri rocno.`);
            return;
          }
          throw e;
        }
        if (!u) console.error(`[racuni] POZOR: ${r.vrsta} (narocilo ${r.public_ref}, vrstica ${id}): dokument ${pid || pst} pri ponudniku ima stevilko ${st.stevilka}, vrstica pa ni vec v stanju caka ali je ni vec nas prevzem - preveri rocno.`);
        else if (neveljaven) objavi("trajna", `${r.vrsta} (narocilo ${r.public_ref}, vrstica ${id})`, "ponudnik je vrnil neveljaven EOR/ZOI; preveri pri ponudniku, ali je racun potrjen");
        return;
      }
      // S3: stevilka je znana, EOR se ne
      if (neveljaven) {
        await uredi(id, zeton, "stanje = 'napaka', zadnja_napaka = $3, prevzeto_at = NULL", ["neveljaven odgovor ponudnika (EOR/ZOI)"], "stanje = 'izdan'");
        objavi("trajna", `${r.vrsta} (narocilo ${r.public_ref}, vrstica ${id})`, "ponudnik je vrnil neveljaven EOR/ZOI; preveri pri ponudniku, ali je racun potrjen");
        return;
      }
      if (!eor) throw new NapakaPonudnika("EOR se ni na voljo (davcno potrjevanje pri ponudniku se ni koncano)", { neznan: false });
      await uredi(id, zeton,
        `stanje = 'potrjen', eor = $3, zoi = COALESCE(zoi, $4), izdan_at = COALESCE(izdan_at, $5), ponudnik_stevilka = COALESCE(ponudnik_stevilka, $6),
         potrjen_at = NOW(), zadnja_napaka = NULL, prevzeto_at = NULL`, [eor, zoi, izdanAt, stDokumenta], "stanje = 'izdan'");
    } catch (e) {
      if (e instanceof NapakaPonudnika) { await napakaPriPonudniku(r, e, korak, zeton); return; }
      throw e;
    }
  }

  async function obdelaj(id, zeton) {
    try {
      if (stevilcenjePonudnik) { await obdelajPonudnik(id, zeton); return; }
      const iz = await vTransakciji((c) => izdajVTransakciji(c, id));
      if (iz.stanje === "odlozeno") { await sprosti(id, ", naslednji_poskus_at = NOW() + ($2::bigint * INTERVAL '1 millisecond')", [ODLOG_MS]); return; }
      if (iz.stanje !== "izdan") { await sprosti(id); return; }
      await potrdi(id);
    } catch (e) {
      if (stevilcenjePonudnik) objavi("obdelava", `racun ${id}`, kratko(e)); else console.error(`[racuni] obdelava racuna ${id}:`, kratko(e));
      await sprosti(id, ", naslednji_poskus_at = NOW() + ($2::bigint * INTERVAL '1 millisecond')", [premor(1)], stevilcenjePonudnik ? zeton : null).catch(() => {});
    }
  }

  async function prevzemi(n, zeton) {
    const r = await poizvedba(
      `UPDATE racuni SET prevzeto_at = NOW(), prevzem_zeton = $3
        WHERE id IN (SELECT id FROM racuni WHERE stanje IN ('caka', 'izdan') AND naslednji_poskus_at <= NOW() AND (vrsta = 'racun' OR vracilo_uspelo IS TRUE)
                       AND (prevzeto_at IS NULL OR prevzeto_at < NOW() - ($2::bigint * INTERVAL '1 millisecond'))
                     ORDER BY id LIMIT $1 FOR NO KEY UPDATE SKIP LOCKED)
        RETURNING id`, [n, ZASTARELO_MS, zeton]);
    return r.rows.map((x) => Number(x.id)).sort((a, b) => a - b);
  }

  let tece = false;
  async function tek() {
    if (tece || !ponudnik) return 0;
    tece = true;
    let skupaj = 0, imamNajem = false;
    try {
      if (stevilcenjePonudnik) {   // samo ce je delo, in samo en delavec v celem sistemu (K2)
        if (!(await obstajaDelo())) return 0;
        imamNajem = await najemi();
        if (!imamNajem) return 0;
      }
      const zeton = crypto.randomUUID();
      preizkusTek = null; preizkusNapaka = null;   // preizkus velja en tek
      const konec = Date.now() + PRORACUN_MS;
      for (;;) {
        const ids = await prevzemi(PAKET, zeton);
        if (!ids.length) break;
        skupaj += ids.length;
        await Promise.all(ids.map((id) => obdelaj(id, zeton)));
        if (Date.now() > konec) break;
      }
    } catch (e) { console.error("[racuni] tek:", kratko(e)); }
    finally {
      tece = false;
      if (imamNajem) await spustiNajem();
      if (zbir.length) izpisiZbir();
    }
    return skupaj;
  }

  // Pospravljalec: (1) placano platformno narocilo brez racuna, (2) vrnjen znesek brez dobropisa, (3) alarm za racune, ki predolgo niso potrjeni.
  // Samo narocila, placana PO uvedbi 054 (schema_migrations): racuna za nazaj ne izdajamo (pravna analiza 20. 10. 2026, razdelek 6; odloci Martin/racunovodkinja).
  let zadnjiAlarm = 0, zadnjaLuknja = 0;
  async function pospravi() {
    try {
      const od = `(SELECT uporabljen FROM schema_migrations WHERE datoteka = '054_racuni.sql')`;
      const a = await poizvedba(
        `INSERT INTO racuni (order_id, vrsta, znesek_cents, valuta)
         SELECT o.id, 'racun', o.total_cents, o.currency FROM orders o
          WHERE o.status IN ('paid', 'partially_refunded', 'refunded') AND ${SQL_RACUN_DOLGOVAN("o")} AND o.paid_at >= ${od}
            AND NOT EXISTS (SELECT 1 FROM racuni r WHERE r.order_id = o.id AND r.vrsta = 'racun')
          LIMIT 500
         ON CONFLICT (order_id) WHERE vrsta = 'racun' DO NOTHING RETURNING order_id`);
      if (a.rows.length) console.error(`[racuni] POZOR: ${a.rows.length} placanih platformnih narocil ni imelo racuna (narocila ${a.rows.slice(0, 10).map((x) => x.order_id).join(", ")}); vpisana v vrsto. Preveri, zakaj zakljuci() racuna ni zapisal.`);
      const b = await poizvedba(
        `INSERT INTO racuni (order_id, vrsta, ref_racun_id, vir, znesek_cents, valuta)
         SELECT r.order_id, 'dobropis', r.id, 'narocilo-' || o.id || '@' || o.refunded_cents, -(o.refunded_cents - d.vrnjeno), r.valuta
           FROM racuni r JOIN orders o ON o.id = r.order_id
           CROSS JOIN LATERAL (SELECT COALESCE(-SUM(x.znesek_cents), 0)::int AS vrnjeno FROM racuni x WHERE x.ref_racun_id = r.id AND x.vrsta = 'dobropis') d
          WHERE r.vrsta = 'racun' AND o.refunded_cents > d.vrnjeno AND o.refunded_cents <= r.znesek_cents
          LIMIT 500
         ON CONFLICT (vir) DO NOTHING RETURNING order_id`);
      if (b.rows.length) console.error(`[racuni] POZOR: ${b.rows.length} vracil ni imelo dobropisa (narocila ${b.rows.slice(0, 10).map((x) => x.order_id).join(", ")}); vpisana kot dobropis z NEZNANIM izidom vracila (se ne izda, dokler izida ne potrdi clovek).`);
      if (Date.now() - zadnjiAlarm > 6 * 3600000) {
        const c = (await poizvedba(
          `SELECT COUNT(*) FILTER (WHERE stanje IN ('caka', 'izdan') AND created_at < NOW() - ($1::bigint * INTERVAL '1 millisecond'))::int AS stari,
                  COUNT(*) FILTER (WHERE stanje = 'napaka')::int AS napake,
                  COUNT(*) FILTER (WHERE vrsta = 'dobropis' AND stanje = 'caka' AND vracilo_uspelo IS NULL AND created_at < NOW() - ($1::bigint * INTERVAL '1 millisecond'))::int AS neznani
             FROM racuni WHERE stanje NOT IN ('potrjen', 'preklican')`, [ALARM_PO_MS])).rows[0];
        if (c.stari > 0 || c.napake > 0) {
          zadnjiAlarm = Date.now();
          console.error(`[racuni] POZOR: ${c.stari} racunov/dobropisov ni potrjenih ze vec kot ${Math.round(ALARM_PO_MS / 3600000)} h (od tega ${c.neznani} dobropisov z neznanim izidom Stripovega vracila), ${c.napake} v stanju napaka (ponudnik: ${izbira.ime}). Zakonski rok za naknadno potrditev sta 2 delovna dneva (ZDavPR 9).`);
        }
      }
      // Stevilke ponudnika: luknja v zaporedju (manjka N-1, ceprav N obstaja ze dalj casa) = ponudnik je stevilko porabil za dokument, ki ga nimamo (rocni racun na isti
      // blagajni, dvojnik, napaka pri ponudniku). Zaporedje je njegovo, zato samo opozorilo (ZDavPR 5/5): najmanjsa stevilka vsake vrste (prostor, naprava, leto) je izhodisce.
      // Omejitev (M3, ni popravljeno): stevilcenje je od 22. 10. 2026 NEPREKINJENO (interni akt 6/2), poizvedba pa deli po `leto`, zato luknje na prehodu leta (zadnja
      // stevilka starega leta : prva novega) ne zazna. Cena poizvedbe raste s stevilom racunov (indeks po prostoru/napravi/letu/stevilki jo drzi poceni, a ni omejena).
      if (Date.now() - zadnjaLuknja > 6 * 3600000) {
        const l = (await poizvedba(
          `SELECT g.prostor, g.naprava, g.leto, g.stevilka - 1 AS manjka FROM racuni g
            WHERE g.stevilka_vir = 'ponudnik' AND g.stevilka > 1 AND COALESCE(g.izdan_at, g.potrjen_at, g.poslano_at, g.created_at) < NOW() - ($1::bigint * INTERVAL '1 millisecond')
              AND g.stevilka > (SELECT MIN(m.stevilka) FROM racuni m WHERE m.prostor = g.prostor AND m.naprava = g.naprava AND m.leto = g.leto AND m.stevilka_vir = 'ponudnik')
              AND NOT EXISTS (SELECT 1 FROM racuni p WHERE p.prostor = g.prostor AND p.naprava = g.naprava AND p.leto = g.leto AND p.stevilka = g.stevilka - 1)
            ORDER BY g.leto, g.stevilka LIMIT 10`, [LUKNJA_PO_MS])).rows;
        if (l.length) {
          zadnjaLuknja = Date.now();
          console.error(`[racuni] POZOR: v zaporedju stevilk ponudnika manjka ${l.map((x) => `${x.prostor}-${x.naprava}-${x.manjka} (${x.leto})`).join(", ")}: dokument s to stevilko pri ponudniku ni v nasi bazi. Preveri v e-racuni (rocni racun na isti blagajni? dvojnik?) in z racunovodkinjo (ZDavPR 5/5).`);
        }
      }
    } catch (e) { console.error("[racuni] pospravljanje:", kratko(e)); }
  }

  function zazeni() {
    if (izbira.opozorilo) console.error(`[racuni] POZOR: ${izbira.opozorilo}.`);
    if (!ponudnik) console.log("[racuni] ponudnik izklopljen (RACUNI_PONUDNIK): racuni lastnih dogodkov se zapisujejo kot dolg (caka), stevilk in potrditev ni.");
    else console.log(`[racuni] ponudnik ${izbira.ime}${stevilcenjePonudnik ? ` (davcno stevilko dodeli ponudnik: ${ponudnik.prostor}-${ponudnik.naprava}-N, nas stevec se ne uporablja)` : ""}, delavec vsakih ${TICK_MS} ms, ${VZPOREDNO} hkratnih klicev, rok ${ROK_MS} ms.`);
    if (ponudnik && TICK_MS > 0) setInterval(() => { tek(); }, TICK_MS).unref();
    if (POSPRAVI_MS > 0) setTimeout(() => { pospravi(); setInterval(() => { pospravi(); }, POSPRAVI_MS).unref(); }, POSPRAVI_ZAMIK_MS).unref();
  }

  return { zazeni, tek, pospravi, ponudnik: izbira.ime };
}

module.exports = {
  ustvari, izdajVTransakciji, postavkeRacuna, eracuniPonudnik, vpisiDolgRacuna, vpisiDobropis, dobropisiZaVracila, izidVracila, vsebinaRacuna, blokRacuna, qrPodatek, qrMatrikaRacuna, stevilkaRacuna, izberiPonudnika, NapakaPonudnika,
  SQL_RACUN_DOLGOVAN, IZDAJATELJ, DDV_KLAVZULA, PROSTOR, NAPRAVA, OPERATER, NACIN_PLACILA, PLATFORMNI_RACUN,
};
