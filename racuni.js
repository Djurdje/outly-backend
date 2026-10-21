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
// Kdo dodeli EOR (e-racuni.com, Space Invoices ali lastna povezava s FURS) SE NI IZBRANO. Danes sta ponudnika samo:
//   - `izklopljen` (privzeto; tudi v produkciji): delavec NE tece, nic se ne poslje, vrstice ostanejo `caka` (dolg je zapisan, stevilk ni). Brez napake ob zagonu.
//   - `lazni` (samo testi; v produkciji zavrnjen): HTTP na RACUNI_LAZNI_URL ali lokalni nakljucni EOR.
// Izracun ZOI (RSA-SHA256 podpis z namenskim potrdilom .p12) tu NI: odvisen je od izbire izvedbe (ponudnik ga vrne ali ga izracuna nasa FURS povezava).
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

// Dobropis v transakciji klicatelja, ki je pravkar povecal refunded_cents (vrstica narocila zaklenjena). delta > 0 (centi), vir = id Stripovega vracila ali null.
// Brez izvirnega racuna (navaden klub, test, 0 EUR, narocilo izpred 054) se ne zgodi nic. Nadomestni vir 'narocilo-<id>@<skupaj vrnjeno>' je enolicen: povecanje
// refunded_cents na isto vsoto se zgodi natanko enkrat (nikoli navzdol, uveljaviVracilo).
async function vpisiDobropis(c, orderId, deltaCents, skupajVrnjeno, virVracila) {
  const delta = Math.trunc(Number(deltaCents) || 0);
  if (delta <= 0) return null;
  const vir = virVracila && /^[\w@.:-]{1,120}$/.test(String(virVracila)) ? String(virVracila) : `narocilo-${orderId}@${Math.trunc(Number(skupajVrnjeno) || 0)}`;
  const r = await c.query(
    `INSERT INTO racuni (order_id, vrsta, ref_racun_id, vir, znesek_cents, valuta)
     SELECT r.order_id, 'dobropis', r.id, $2, -LEAST($3::int, r.znesek_cents), r.valuta FROM racuni r WHERE r.order_id = $1 AND r.vrsta = 'racun'
     ON CONFLICT (vir) DO NOTHING RETURNING id`, [orderId, vir, delta]);
  return r.rows.length ? r.rows[0].id : null;
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
function vsebinaRacuna(r, n) {
  if (!r || r.stevilka === null || r.stevilka === undefined || !r.izdan_at) return null;
  const valuta = String(r.valuta || "EUR").trim();
  const dogodek = `${String((n && n.title) || "").trim()}${n && n.start_at ? ", " + datumSl(n.start_at) : ""}`;
  const znesek = Number(r.znesek_cents);
  let postavke;
  if (r.vrsta === "dobropis") {
    postavke = [{ opis: `Vračilo za račun ${stevilkaRacuna(r.ref_prostor, r.ref_naprava, r.ref_stevilka)} (vstopnica: ${dogodek})`, kolicina: 1, cena_cents: znesek, skupaj_cents: znesek }];
  } else if (n && n.table_label) {
    postavke = [{ opis: `VIP miza ${String(n.table_label).trim()}: ${dogodek}`, kolicina: 1, cena_cents: znesek, skupaj_cents: znesek }];
  } else {
    const kol = Number(n && n.quantity), cena = Number(n && n.unit_price_cents);
    postavke = Number.isInteger(kol) && kol > 0 && Number.isInteger(cena) && kol * cena === znesek
      ? [{ opis: `Vstopnica: ${dogodek}`, kolicina: kol, cena_cents: cena, skupaj_cents: znesek }]
      : [{ opis: `Vstopnica: ${dogodek}`, kolicina: 1, cena_cents: znesek, skupaj_cents: znesek }];
  }
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

// --- Ponudnik (tanka plast): potrdi(podatki, { signal }) -> { eor, zoi?, ponudnik_id? }; napaka NapakaPonudnika z `trajna` ---
class NapakaPonudnika extends Error {
  constructor(sporocilo, { trajna = false } = {}) { super(sporocilo); this.name = "NapakaPonudnika"; this.trajna = !!trajna; }
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
const PONUDNIKI = { lazni: lazniPonudnik };

// Izbira prek RACUNI_PONUDNIK. Prazno ali `izklopljen` = izklopljen. `lazni` v produkciji (RENDER / NODE_ENV=production) NE velja (lazni EOR na pravem racunu bi bil
// prekrsek): izklopljen + opozorilo. Neznano ime (npr. izvedba, ki se ni narejena) = izklopljen + opozorilo. Nikoli napaka ob zagonu.
function izberiPonudnika(env = process.env) {
  const ime = String(env.RACUNI_PONUDNIK || "").trim().toLowerCase();
  if (!ime || ime === "izklopljen") return { ime: "izklopljen", ponudnik: null, opozorilo: null };
  const produkcija = !!env.RENDER || env.NODE_ENV === "production";
  if (ime === "lazni" && produkcija) return { ime: "izklopljen", ponudnik: null, opozorilo: "RACUNI_PONUDNIK=lazni v produkciji ni dovoljen (lazni EOR): ponudnik IZKLOPLJEN, racuni ostanejo v vrsti" };
  if (!PONUDNIKI[ime]) return { ime: "izklopljen", ponudnik: null, opozorilo: `RACUNI_PONUDNIK=${ime.slice(0, 40)} ne obstaja (izvedba potrjevanja se ni narejena): ponudnik IZKLOPLJEN, racuni ostanejo v vrsti` };
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
// Vrstni red zaklepov je vedno: vrstica racuna -> vrstica stevca (brez mrtve zanke). Stevec se poveca za 1 v isti transakciji, v kateri se zapise stevilka:
// ROLLBACK vrne oboje (brez lukenj). Cas izdaje = ura PO zaklepu stevca, zato si stevilke in casi sledijo v istem vrstnem redu.
async function izdajVTransakciji(c, id, { prostor = PROSTOR, naprava = NAPRAVA } = {}) {
  const r = (await c.query(
    `SELECT r.id, r.vrsta, r.stanje, ref.stevilka AS ref_stevilka FROM racuni r LEFT JOIN racuni ref ON ref.id = r.ref_racun_id WHERE r.id = $1 FOR NO KEY UPDATE OF r`, [id])).rows[0];   // NO KEY: ne caka na / ne blokira FK (KEY SHARE) ob vpisu dobropisa v webhooku
  if (!r) return { stanje: "ni" };
  if (r.stanje !== "caka") return { stanje: r.stanje };
  if (r.vrsta === "dobropis" && (r.ref_stevilka === null || r.ref_stevilka === undefined)) return { stanje: "odlozeno" };   // nikoli pred izvirnim racunom
  for (let i = 0; i < 2; i++) {
    const leto = (await c.query(`SELECT EXTRACT(YEAR FROM clock_timestamp() AT TIME ZONE '${CASOVNI_PAS}')::int AS leto`)).rows[0].leto;
    await c.query("INSERT INTO racuni_zaporedje (prostor, naprava, leto) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING", [prostor, naprava, leto]);
    await c.query("SELECT zadnja FROM racuni_zaporedje WHERE prostor = $1 AND naprava = $2 AND leto = $3 FOR UPDATE", [prostor, naprava, leto]);
    const cas = (await c.query(`SELECT clock_timestamp() AS cas, EXTRACT(YEAR FROM clock_timestamp() AT TIME ZONE '${CASOVNI_PAS}')::int AS leto`)).rows[0];
    if (cas.leto !== leto) continue;   // novo leto med cakanjem na zaklep: stevilka iz novega zaporedja (zaklep starega se ob COMMIT sprosti, stevec ni spremenjen)
    const z = (await c.query("UPDATE racuni_zaporedje SET zadnja = zadnja + 1 WHERE prostor = $1 AND naprava = $2 AND leto = $3 RETURNING zadnja", [prostor, naprava, leto])).rows[0].zadnja;
    await c.query("UPDATE racuni SET prostor = $2, naprava = $3, leto = $4, stevilka = $5, izdan_at = $6, stanje = 'izdan' WHERE id = $1", [id, prostor, naprava, leto, z, cas.cas]);
    return { stanje: "izdan", stevilka: Number(z), izdan_at: cas.cas };
  }
  throw new Error("menjava leta med izdajo racuna");
}

function ustvari({ pool, env = process.env }) {
  const TICK_MS = celo(env, "RACUNI_TICK_MS", 2000, 0, 3600000);                 // 0 = delavec ne tece (tudi ob izbranem ponudniku)
  const VZPOREDNO = celo(env, "RACUNI_VZPOREDNO", 4, 1, 50);                     // hkratni klici ponudnika
  const DB_VZPOREDNO = celo(env, "RACUNI_DB_VZPOREDNO", 2, 1, 10);               // hkratne kratke transakcije delavca (stevilcenje je tako ali tako zaporedno)
  const ROK_MS = celo(env, "RACUNI_ROK_MS", 5000, 100, 60000);                   // rok enega klica ponudnika
  const PAKET = celo(env, "RACUNI_PAKET", 50, 1, 1000);
  const PREMOR_MS = celo(env, "RACUNI_PREMOR_MS", 0, 0, 86400000);              // stalen premor (testi); 0 = narascajoc
  const ODLOG_MS = celo(env, "RACUNI_ODLOG_MS", 30000, 0, 3600000);             // dobropis caka na stevilko oz. potrditev izvirnega racuna
  const ZASTARELO_MS = celo(env, "RACUNI_ZASTARELO_MS", 120000, 1000, 3600000); // prevzeto brez zakljucka (proces ugasnjen) se prevzame znova (isti message_id)
  const POSPRAVI_MS = celo(env, "RACUNI_POSPRAVI_MS", 600000, 0, 86400000);     // pospravljalec (0 = izklopljen)
  const POSPRAVI_ZAMIK_MS = celo(env, "RACUNI_POSPRAVI_ZAMIK_MS", 300000, 0, 86400000);
  const ALARM_PO_MS = celo(env, "RACUNI_ALARM_PO_MS", 24 * 3600000, 1000, 30 * 86400000);   // racun ni potrjen toliko casa -> POZOR (zakonski rok: 2 delovna dneva)
  const PRORACUN_MS = 45000;
  const PREMORI = [5e3, 30e3, 120e3, 600e3, 1800e3, 3600e3];

  const izbira = izberiPonudnika(env);
  const ponudnik = izbira.ponudnik;
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
  const sprosti = (id, dodatno = "", par = []) => poizvedba(`UPDATE racuni SET prevzeto_at = NULL${dodatno} WHERE id = $1`, [id, ...par]);

  // Podatki za ponudnika (brez e-naslova in imena kupca). Isti message_id ob vsaki ponovitvi.
  async function podatkiZaPotrditev(id) {
    const r = (await poizvedba(
      `SELECT r.*, ref.prostor AS ref_prostor, ref.naprava AS ref_naprava, ref.stevilka AS ref_stevilka, ref.izdan_at AS ref_izdan_at, ref.stanje AS ref_stanje,
              ref.eor AS ref_eor, ref.ponudnik_id AS ref_ponudnik_id, o.public_ref, o.quantity, o.unit_price_cents, o.total_cents, o.table_label, e.title, e.start_at
         FROM racuni r JOIN orders o ON o.id = r.order_id JOIN events e ON e.id = o.event_id LEFT JOIN racuni ref ON ref.id = r.ref_racun_id WHERE r.id = $1`, [id])).rows[0];
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
      // Brez drzane povezave. Rok tece sele, ko klic dobi mesto v semaforju (sicer bi klic, ki caka v vrsti dlje od roka, padel, preden bi bil poslan).
      izid = await klici(async () => {
        const ctl = new AbortController();
        const t = setTimeout(() => ctl.abort(), ROK_MS);
        try { return await ponudnik.potrdi(pz.podatki, { signal: ctl.signal }); } finally { clearTimeout(t); }
      });
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

  async function obdelaj(id) {
    try {
      const iz = await vTransakciji((c) => izdajVTransakciji(c, id));
      if (iz.stanje === "odlozeno") { await sprosti(id, ", naslednji_poskus_at = NOW() + ($2::bigint * INTERVAL '1 millisecond')", [ODLOG_MS]); return; }
      if (iz.stanje !== "izdan") { await sprosti(id); return; }
      await potrdi(id);
    } catch (e) {
      console.error(`[racuni] obdelava racuna ${id}:`, kratko(e));
      await sprosti(id, ", naslednji_poskus_at = NOW() + ($2::bigint * INTERVAL '1 millisecond')", [premor(1)]).catch(() => {});
    }
  }

  async function prevzemi(n) {
    const r = await poizvedba(
      `UPDATE racuni SET prevzeto_at = NOW()
        WHERE id IN (SELECT id FROM racuni WHERE stanje IN ('caka', 'izdan') AND naslednji_poskus_at <= NOW()
                       AND (prevzeto_at IS NULL OR prevzeto_at < NOW() - ($2::bigint * INTERVAL '1 millisecond'))
                     ORDER BY id LIMIT $1 FOR NO KEY UPDATE SKIP LOCKED)
        RETURNING id`, [n, ZASTARELO_MS]);
    return r.rows.map((x) => Number(x.id)).sort((a, b) => a - b);
  }

  let tece = false;
  async function tek() {
    if (tece || !ponudnik) return 0;
    tece = true;
    let skupaj = 0;
    try {
      const konec = Date.now() + PRORACUN_MS;
      for (;;) {
        const ids = await prevzemi(PAKET);
        if (!ids.length) break;
        skupaj += ids.length;
        await Promise.all(ids.map((id) => obdelaj(id)));
        if (Date.now() > konec) break;
      }
    } catch (e) { console.error("[racuni] tek:", kratko(e)); }
    finally { tece = false; }
    return skupaj;
  }

  // Pospravljalec: (1) placano platformno narocilo brez racuna, (2) vrnjen znesek brez dobropisa, (3) alarm za racune, ki predolgo niso potrjeni.
  // Samo narocila, placana PO uvedbi 054 (schema_migrations): racuna za nazaj ne izdajamo (pravna analiza 20. 10. 2026, razdelek 6; odloci Martin/racunovodkinja).
  let zadnjiAlarm = 0;
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
      if (b.rows.length) console.error(`[racuni] POZOR: ${b.rows.length} vracil ni imelo dobropisa (narocila ${b.rows.slice(0, 10).map((x) => x.order_id).join(", ")}); vpisana v vrsto.`);
      if (Date.now() - zadnjiAlarm > 6 * 3600000) {
        const c = (await poizvedba(
          `SELECT COUNT(*) FILTER (WHERE stanje IN ('caka', 'izdan') AND created_at < NOW() - ($1::bigint * INTERVAL '1 millisecond'))::int AS stari,
                  COUNT(*) FILTER (WHERE stanje = 'napaka')::int AS napake FROM racuni WHERE stanje <> 'potrjen'`, [ALARM_PO_MS])).rows[0];
        if (c.stari > 0 || c.napake > 0) {
          zadnjiAlarm = Date.now();
          console.error(`[racuni] POZOR: ${c.stari} racunov/dobropisov ni potrjenih ze vec kot ${Math.round(ALARM_PO_MS / 3600000)} h, ${c.napake} v stanju napaka (ponudnik: ${izbira.ime}). Zakonski rok za naknadno potrditev sta 2 delovna dneva (ZDavPR 9).`);
        }
      }
    } catch (e) { console.error("[racuni] pospravljanje:", kratko(e)); }
  }

  function zazeni() {
    if (izbira.opozorilo) console.error(`[racuni] POZOR: ${izbira.opozorilo}.`);
    if (!ponudnik) console.log("[racuni] ponudnik izklopljen (RACUNI_PONUDNIK): racuni lastnih dogodkov se zapisujejo kot dolg (caka), stevilk in potrditev ni.");
    else console.log(`[racuni] ponudnik ${izbira.ime}, delavec vsakih ${TICK_MS} ms, ${VZPOREDNO} hkratnih klicev, rok ${ROK_MS} ms.`);
    if (ponudnik && TICK_MS > 0) setInterval(() => { tek(); }, TICK_MS).unref();
    if (POSPRAVI_MS > 0) setTimeout(() => { pospravi(); setInterval(() => { pospravi(); }, POSPRAVI_MS).unref(); }, POSPRAVI_ZAMIK_MS).unref();
  }

  return { zazeni, tek, pospravi, ponudnik: izbira.ime };
}

module.exports = {
  ustvari, izdajVTransakciji, vpisiDolgRacuna, vpisiDobropis, vsebinaRacuna, blokRacuna, qrPodatek, qrMatrikaRacuna, stevilkaRacuna, izberiPonudnika, NapakaPonudnika,
  SQL_RACUN_DOLGOVAN, IZDAJATELJ, DDV_KLAVZULA, PROSTOR, NAPRAVA, OPERATER, NACIN_PLACILA, PLATFORMNI_RACUN,
};
