#!/usr/bin/env node
/**
 * Racuni: ponudnik e-racuni.com (I52, migracija 056, racuni.js; Martin 21. 10. 2026). Zagon (PG16, prazna baza z vsemi migracijami):
 *   DATABASE_URL="postgres://postgres:postgres@localhost:5432/outly" node _testi/test_racuni_eracuni.js
 * Brez backenda in Stripa: delavec racuni.ustvari({ pool, env }).tek() na pravi bazi + LAZNI strežnik e-racuni (JSON, WS API: SalesInvoiceCreate/Get/List,
 * CreditNoteCreate/Get/List; oblika odgovorov je IZ DOKUMENTACIJE in nepreverjena z zivim klicem - glej STATE).
 *
 *   0  izbira ponudnika: brez katerega koli kljuca izklopljen + opozorilo z IMENI spremenljivk (nikoli vrednostmi), https v produkciji, neveljavna blagajna;
 *      zagon in tek() brez kljucev ne padeta in ne poslata nicesar; zneski v centih -> decimalno stevilo brez plavajoce napake (200000 vrednosti)
 *   1  uspeh: stevilka = davcna stevilka e-racuni (NE nas stevec, racuni_zaporedje ostane prazen), A001-1-N, ZOI/EOR/ponudnik_id/ponudnik_stevilka; zahtevek: Retail, Stripe,
 *      blagajna/enota, orderReference = message_id, postavka, znesek, klavzula DDV, BREZ kupca (e-naslov, ime) in brez poverilnic v dnevniku
 *   2  zacasna napaka PRED obdelavo (503): ponovitev najprej poisce po referenci, nato izda eno; brez dvojnika
 *   3  izguba odgovora PO obdelavi (503 po izdaji): ponovitev NAJDE dokument po referenci, nova izdaja se NE zgodi
 *   4  timeout po poslanem zahtevku (izid neznan): isto - brez dvojnika
 *   5  429 (zagotovo ni obdelano): poslano se pobrise, ponovitev brez iskanja
 *   6  trajna napaka (validacija): `napaka` brez stevilke + POZOR, brez ponavljanja; rocna ponovitev napaka -> caka gre skozi iskanje po referenci
 *   7  napacne poverilnice/nastavitev: vrstica OSTANE `caka` (ne `napaka`), pocasna ponovitev + POZOR
 *   8  odgovor izdaje brez oznake dokumenta: iskanje po referenci; seznam v neprepoznani obliki ne pomeni »ni najden« (brez nove izdaje)
 *   9  EOR zamuja: stevilka se zapise (`izdan`), kasneje `potrjen` s ISTO stevilko; brez nove izdaje
 *  10  dobropis: samo po uspelem vracilu in po potrjenem izvirnem racunu; CreditNoteCreate s salesInvoiceRef, pozitiven znesek, orderReference; stevilka e-racuni
 *  11  en klic naenkrat in razmak med zahtevki (omejitev API); stevilke zaporedne, brez dvojnikov
 *  12  luknja v zaporedju ponudnika (rocni dokument na isti blagajni): pospravljalec javi POZOR; brez luknje brez opozorila
 *  13  sprozilec: stevilka ponudnika brez dokumenta, mesanje virov, dvojnik, sprememba vira, napaka s stevilko ne nazaj, INSERT s poslano_at, DELETE
 *  14  izid vracila med izdajo: dobropis, ki je ze poslan ponudniku, se NE preklice tiho (POZOR); neposlan se preklice
 *  22  preizkus pred izdajo: napacen kljuc ob vklopu ne spravi zaostanka v `napaka` (oba nacina zastavice seznama)
 *  23  rocni postopek za vrstico v `napaka` (povezava obstojecega dokumenta, ponovitev): isti SQL kot v STATE
 *  24  zastavica »ustvarjeno pri ponudniku«: vrstica je `napaka` ze med iskanjem po uspehu Create brez oznake
 *  25  fail-closed: katerakoli napaka bralnega preizkusa ustavi Create; po zavrnjenem Create se Create ustavi za cel proces
 *  26  preizkus pred izdajo z 5xx/timeoutom: POZOR (3x zapored ali dlje kot cas), omejeno na okno
 *  27  PDF racuna: pridobitev po `potrjen`, stroga preverba, racuni_pdf, ponovitev + POZOR
 *  15  poverilnice nikoli v dnevniku ali zadnja_napaka
 */
const http = require("http");
const crypto = require("crypto");
const { Pool } = require("pg");

const DB = process.env.DATABASE_URL;
if (!DB) { console.error("DATABASE_URL manjka"); process.exit(1); }
const racuni = require("../racuni");
const PORT = 3391;
const TAJNO = { user: "test_uporabnik_eracuni", key: "test_skrivni_kljuc_123456", token: "TESTTOKEN1234567890" };
const KUPEC_EMAIL = "kupec.skrivnost@example.com";

let ok = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { ok++; console.log("  ✓", msg); } else { fail++; console.log("  ✗", msg, extra !== undefined ? JSON.stringify(extra).slice(0, 700) : ""); } }
const pocakaj = (ms) => new Promise((r) => setTimeout(r, ms));
async function dokler(pogoj, ms = 8000) { const do_ = Date.now() + ms; while (Date.now() < do_) { if (await pogoj()) return true; await pocakaj(40); } return false; }

// ---------- dnevnik (console.error/log) ----------
const LOG = [];
for (const k of ["error", "log"]) { const o = console[k].bind(console); console[k] = (...a) => { const t = a.map((x) => (typeof x === "string" ? x : (x && x.message) || String(x))).join(" "); if (/^\[racuni\]/.test(t)) LOG.push(t); o(...a); }; }
const logOd = (n) => LOG.slice(n);

// ---------- lazni e-racuni ----------
const F = {
  docs: [], klici: [], preizkusi: [], pdfKlici: [], pdfOblika: "ok", stevec: 41, ndoc: 0, inflight: 0, maxInflight: 0, zacetki: [],
  vedenje: null,        // { ustvari: 'ok'|'503pred'|'503po'|'timeoutpo'|'429'|'napaka'|'konfig'|'brezOznake', preostalo: n }
  zamudaEor: 0,         // koliko Get klicev pred pojavom EOR
  listOblika: "ok",     // 'ok' | 'neznana' | 'prazno' ({status:ok}) | 'prazenNiz' (SalesInvoices: "") | 'prazenSeznam' ([]) | 'brezRef' | 'okrnjenRef' | 'dvojnik' | 'manjkaZnan'
  opisAvt: "Access denied. Invalid credentials",   // pravo besedilo napake avtentikacije pri e-racuni NI znano
  listStatus: null,   // npr. 503: seznam (tudi bralni preizkus) ne dela
  listZamik: 0, casIzdaje: null, poverilnice: true, vrniBlagajno: null,
};
const dan = () => new Intl.DateTimeFormat("en-CA", { timeZone: "Europe/Ljubljana", year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date());
const dokJSON = (d, vrsta) => ({ documentID: d.id, number: d.number, date: d.date, businessUnit: d.businessUnit, cashRegisterCode: F.vrniBlagajno || d.cashRegisterCode, orderReference: d.orderReference,
  fiscalNumber: d.fiscalNumber, status: "issuedInvoice", ...(d.getov >= F.zamudaEorDo ? { eor: d.eor, zoi: d.zoi } : {}), ...(F.casIzdaje ? { dateTimeOfIssue: F.casIzdaje } : {}), vrsta });
const streznik = http.createServer((req, res) => {
  let tel = ""; req.on("data", (x) => tel += x);
  req.on("end", async () => {
    F.inflight++; F.maxInflight = Math.max(F.maxInflight, F.inflight); F.zacetki.push(Date.now());
    const konec = (st, obj, zamik = 0) => setTimeout(() => { F.inflight--; try { res.writeHead(st, { "content-type": "application/json" }); res.end(typeof obj === "string" ? obj : JSON.stringify(obj)); } catch (_) { /* odjemalec je prekinil */ } }, zamik);
    let z; try { z = JSON.parse(tel); } catch (_) { return konec(400, "{}"); }
    if (req.headers["x-outly-namen"] === "preizkus") F.preizkusi.push({ method: z.method, parameters: z.parameters }); else if (/GetPDF$/.test(z.method)) F.pdfKlici.push({ method: z.method, parameters: z.parameters }); else F.klici.push({ method: z.method, parameters: z.parameters, telo: tel });
    if (!F.poverilnice || z.username !== TAJNO.user || z.secretKey !== TAJNO.key || z.token !== TAJNO.token) return konec(200, { status: "error", error: { description: F.opisAvt } });
    const p = z.parameters || {};
    const ved = F.vedenje && F.vedenje.preostalo > 0 ? F.vedenje.ustvari : "ok";
    const poraba = () => { if (F.vedenje && F.vedenje.preostalo > 0) F.vedenje.preostalo--; };
    const ustvari = (kljuc, vrsta) => {
      const s = p[kljuc];
      const d = { id: `60:${1000 + (++F.ndoc)}`, number: `2026-${String(F.ndoc).padStart(5, "0")}`, date: dan(), businessUnit: s.businessUnit, cashRegisterCode: s.cashRegisterCode, orderReference: s.orderReference,
        fiscalNumber: ++F.stevec, eor: crypto.randomUUID(), zoi: crypto.randomBytes(16).toString("hex"), vrsta, params: s, getov: 0 };
      F.docs.push(d); return d;
    };
    if (z.method === "SalesInvoiceCreate" || z.method === "CreditNoteCreate") {
      const vrsta = z.method === "SalesInvoiceCreate" ? "racun" : "dobropis";
      const kljuc = vrsta === "racun" ? "SalesInvoice" : "CreditNote";
      if (ved === "503pred") { poraba(); return konec(503, "{}"); }
      if (ved === "429") { poraba(); return konec(429, "{}"); }
      // e-racuni vrne 500 za VSE aplikacijske napake (zivo 23. 10. 2026), telo {"response": {"status": "error", "apiMethod": ..., "description": "Error nr: N #koda - besedilo"}}
      if (ved === "500opis") { const besedilo = F.vedenje.besedilo; poraba(); return konec(500, { response: { status: "error", apiMethod: z.method, description: besedilo } }); }
      if (ved === "napaka") { poraba(); return konec(200, { status: "error", error: { description: "Invalid value for field price" } }); }
      if (ved === "konfig") { poraba(); return konec(200, { status: "error", error: { description: "Access denied. User account does not have sufficient privileges for the given request" } }); }
      const d = ustvari(kljuc, vrsta);
      if (ved === "503po") { poraba(); return konec(503, "{}"); }
      if (ved === "dokInNapaka") { const besedilo = F.vedenje.besedilo; poraba(); return konec(200, { status: "error", error: { description: besedilo } }); }   // dokument NASTAL, odgovor je napaka (pregled #318, K1)
      if (ved === "prekini") { poraba(); F.inflight--; return req.socket.destroy(); }                                                                           // povezava prekinjena PO prejemu telesa
      if (ved === "brezStevilke") { poraba(); return konec(200, { status: "ok", documentID: d.id }); }                                                          // Create vrne samo oznako dokumenta (S2)
      if (ved === "pocasno") { poraba(); return konec(200, { status: "ok", number: d.number, date: d.date, documentID: d.id }, 1500); }
      if (ved === "timeoutpo") { poraba(); return konec(200, { status: "ok", number: d.number, date: d.date, documentID: d.id }, 1500); }
      if (ved === "brezOznake") { poraba(); return konec(200, { status: "ok" }); }
      return konec(200, { status: "ok", number: d.number, date: d.date, documentID: d.id });
    }
    if (z.method === "SalesInvoiceGet" || z.method === "CreditNoteGet") {
      const d = F.docs.find((x) => (p.documentID && x.id === p.documentID) || (p.number && x.number === p.number));
      if (!d) return konec(200, { status: "error", error: { description: "document could not be found" } });
      d.getov++;
      return konec(200, { status: "ok", [z.method === "SalesInvoiceGet" ? "SalesInvoice" : "CreditNote"]: { ...dokJSON(d, d.vrsta) } });
    }
    if (z.method === "SalesInvoiceGetPDF" || z.method === "CreditNoteGetPDF") {
      const dob = z.method === "SalesInvoiceGetPDF";
      const d = F.docs.find((x) => (p.documentID && x.id === p.documentID) || (p.number && x.number === p.number));
      if (F.pdfOblika === "503") return konec(503, "{}");
      if (!d) return konec(200, { status: "error", error: { description: "document could not be found" } });
      const pdf = Buffer.from(`%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n% ${dob ? "racun" : "dobropis"} ${d.number} ${"x".repeat(80)}\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n`);
      if (F.pdfOblika === "brezPdf") return konec(200, { status: "ok", PDF: Buffer.from("To ni PDF, ampak neka HTML stran za prijavo ".repeat(5)).toString("base64") });
      if (F.pdfOblika === "prazno") return konec(200, { status: "ok" });
      if (F.pdfOblika === "dva") return konec(200, { status: "ok", PDF: pdf.toString("base64"), kopija: Buffer.from(pdf.toString() + " drugi").toString("base64") });
      if (F.pdfOblika === "okrnjen") return konec(200, { status: "ok", PDF: pdf.subarray(0, pdf.length - 20).toString("base64") });
      const MEJA = 2 * 1024 * 1024;   // = PDF_NAJVEC_BAJTOV v racuni.js
      const velikPdf = (n) => Buffer.concat([Buffer.from("%PDF-1.4\n% velik "), Buffer.alloc(n - 40, 65), Buffer.from("\n%%EOF\n")]);
      if (F.pdfOblika === "prevelik") return konec(200, { status: "ok", PDF: velikPdf(MEJA + 1024).toString("base64") });
      if (F.pdfOblika === "velik") return konec(200, { status: "ok", PDF: velikPdf(MEJA - 1024).toString("base64") });
      if (F.pdfOblika === "gnezdeno") return konec(200, { status: "ok", Document: { file: { content: pdf.toString("base64") } } });
      return konec(200, { status: "ok", PDF: pdf.toString("base64") });
    }
    if (z.method === "SalesInvoiceList" || z.method === "CreditNoteList") {
      const vrsta = z.method === "SalesInvoiceList" ? "racun" : "dobropis";
      const el = vrsta === "racun" ? "SalesInvoice" : "CreditNote", zab = vrsta === "racun" ? "SalesInvoices" : "CreditNotes";
      F.listParametri = p;
      if (F.listStatus) return konec(F.listStatus, "{}");
      // E-racuni (zivo preverjeno 22. 10. 2026): seznam brez dokumentov v obdobju = HTTP 500, status »error«, description s kodo #noDocumentsFound
      const NI_DOK = { status: "error", description: "Error nr: 1 #noDocumentsFound - No documents were found matching search criteria!" };
      if (F.listOblika === "ni_dokumentov" && !F.docs.some((x) => x.vrsta === vrsta)) return konec(500, NI_DOK, F.listZamik);
      if (F.listOblika === "ni_dokumentov_vedno") return konec(500, NI_DOK, F.listZamik);   // (napacen) odgovor kljub dokumentom: ne sme voditi v novo izdajo
      if (F.listOblika === "ni_dokumentov_gnezdeno") return konec(500, { status: "error", error: { description: NI_DOK.description } }, F.listZamik);
      if (F.listOblika === "napaka500") return konec(500, { status: "error", description: "Error nr: 7 #internalError - Something went wrong" }, F.listZamik);
      if (F.listOblika === "ni_dokumentov_brez_kode") return konec(500, { status: "error", description: "No documents were found matching search criteria!" }, F.listZamik);   // brez kode: NI prepoznano
      if (F.listOblika === "neznana") return konec(200, { status: "ok", nekaj: { drugega: 1 } }, F.listZamik);
      if (F.listOblika === "prazno") return konec(200, { status: "ok" }, F.listZamik);
      if (F.listOblika === "prazenNiz") return konec(200, { status: "ok", [zab]: "" }, F.listZamik);
      let docs = F.docs.filter((x) => x.vrsta === vrsta);
      let sez = docs.map((x) => ({ [el]: dokJSON(x, vrsta) }));
      if (F.listOblika === "prazenSeznam") sez = [];
      if (F.listOblika === "brezRef") sez.push({ [el]: { documentID: "60:9999", number: "2026-99999", cashRegisterCode: "1", businessUnit: "A001" } });   // rocni dokument na nasi blagajni (brez reference)
      if (F.listOblika === "okrnjenRef") sez = docs.map((x) => ({ [el]: { ...dokJSON(x, vrsta), orderReference: String(x.orderReference).slice(0, 20) } }));
      if (F.listOblika === "dvojnik" && docs.length) sez.push({ [el]: dokJSON(docs[docs.length - 1], vrsta) });
      if (F.listOblika === "manjkaZnan" && sez.length) sez = sez.slice(1);
      return konec(200, { status: "ok", [zab]: sez }, F.listZamik);
    }
    return konec(200, { status: "error", error: { description: "unknown method" } });
  });
});
F.zamudaEorDo = 0;
const klicov = (m) => F.klici.filter((k) => k.method === m).length;
const nastavi = (v, n = 1) => { F.vedenje = v ? { ustvari: v, preostalo: n } : null; };

const ENV = { RACUNI_PONUDNIK: "eracuni", ERACUNI_URL: `http://127.0.0.1:${PORT}/WebServicesSI/API`, ERACUNI_USERNAME: TAJNO.user, ERACUNI_SECRET_KEY: TAJNO.key, ERACUNI_TOKEN: TAJNO.token,
  ERACUNI_RAZMAK_MS: "20", RACUNI_TICK_MS: "0", RACUNI_POSPRAVI_MS: "0", RACUNI_PREMOR_MS: "50", RACUNI_NEZNAN_PREMOR_MS: "0", RACUNI_KONFIG_PREMOR_MS: "400", RACUNI_ROK_MS: "600",
  RACUNI_ODLOG_MS: "50", RACUNI_LUKNJA_PO_MS: "0", RACUNI_ISKANJE_RAZMAK_MS: "0", ERACUNI_SEZNAM_PREVERJEN: "1" };

(async () => {
  await new Promise((r) => streznik.listen(PORT, r));
  const pool = new Pool({ connectionString: DB, max: 12 });
  await pool.query("TRUNCATE omejitve, stripe_events, ticket_transfers, club_invites, club_members, event_favorites, vracila, odpovedi_dogodkov, racuni, tickets, orders, events, clubs, users RESTART IDENTITY CASCADE");
  await pool.query("TRUNCATE racuni_zaporedje");
  const uid = (await pool.query("INSERT INTO users (email, username) VALUES ('lastnik@outly.si', 'lastnik') RETURNING id")).rows[0].id;
  const klub = (await pool.query("INSERT INTO clubs (owner_user_id, name, is_official) VALUES ($1, 'Outly', TRUE) RETURNING id", [uid])).rows[0].id;
  const ev = (await pool.query("INSERT INTO events (club_id, title, start_at, status, ticket_price_cents, capacity, min_age) VALUES ($1, 'Outly Launch Party', '2026-12-24T20:00:00+01:00', 'published', 1999, 500, 0) RETURNING id", [klub])).rows[0].id;
  let nref = 0;
  async function nov(kol = 3, cena = 1999) {
    const o = (await pool.query(`INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, status, paid_at, buyer_email, stripe_account_id)
      VALUES ($1, $2, $3, $4, $5, $6, $7, 'paid', NOW(), $8, 'platform') RETURNING id, public_ref`, ["OUT-ER" + (++nref), uid, ev, klub, kol, cena, kol * cena, KUPEC_EMAIL])).rows[0];
    const r = (await pool.query("INSERT INTO racuni (order_id, vrsta, znesek_cents) VALUES ($1, 'racun', $2) RETURNING id", [o.id, kol * cena])).rows[0];
    return { oid: o.id, ref: o.public_ref, id: r.id };
  }
  const vrstica = async (id) => (await pool.query("SELECT * FROM racuni WHERE id = $1", [id])).rows[0];
  const deloven = (env = {}) => racuni.ustvari({ pool, env: { ...ENV, ...env } });
  // pospesi: odlozene vrstice (iskanje po referenci, pocasna ponovitev) gredo takoj naprej; vrstice, odlozene za > 2 uri (izkljucene iz testa), ostanejo.
  async function tek(w, n = 1, cakaj = 130, pospesi = false) {
    for (let i = 0; i < n; i++) {
      if (pospesi) await pool.query("UPDATE racuni SET naslednji_poskus_at = NOW() WHERE stanje IN ('caka', 'izdan') AND naslednji_poskus_at > NOW() AND naslednji_poskus_at < NOW() + INTERVAL '2 hours'");
      await w.tek(); if (i < n - 1) await pocakaj(cakaj);
    }
  }
  const leto = Number(new Intl.DateTimeFormat("en-GB", { timeZone: "Europe/Ljubljana", year: "numeric" }).format(new Date()));

  try {
    // ================================================================
    console.log("\n# 0. Izbira ponudnika, zagon brez kljucev, zneski");
    {
      const iz = (e) => racuni.izberiPonudnika(e);
      const vse = iz(ENV);
      assert(vse.ime === "eracuni" && vse.ponudnik && vse.ponudnik.stevilcenje === "ponudnik" && vse.ponudnik.prostor === "A001" && vse.ponudnik.naprava === "1" && vse.opozorilo === null,
        "vsi kljuci: ponudnik eracuni, stevilko dodeli ponudnik, privzeto A001 / 1", vse.opozorilo);
      for (const k of ["ERACUNI_USERNAME", "ERACUNI_SECRET_KEY", "ERACUNI_TOKEN"]) {
        const e = { ...ENV }; delete e[k]; const r = iz(e);
        assert(r.ponudnik === null && r.ime === "izklopljen" && r.opozorilo.includes(k) && !Object.values(TAJNO).some((t) => r.opozorilo.includes(t)),
          `brez ${k}: izklopljen + opozorilo z imenom spremenljivke, brez vrednosti`, r.opozorilo);
        const prazen = iz({ ...ENV, [k]: "   " });
        assert(prazen.ponudnik === null, `prazen ${k}: izklopljen`);
      }
      assert(iz({ RACUNI_PONUDNIK: "eracuni" }).ponudnik === null, "eracuni brez vseh kljucev: izklopljen");
      assert(iz({ ...ENV, ERACUNI_URL: "http://e-racuni.com/WebServicesSI/API" }).ponudnik === null, "http naslov (ne lokalni): izklopljen");
      assert(iz({ ...ENV, RENDER: "1" }).ponudnik === null && /https/.test(iz({ ...ENV, RENDER: "1" }).opozorilo), "v produkciji tudi lokalni http ni dovoljen");
      assert(iz({ ...ENV, ERACUNI_URL: "https://uporabnik:geslo@e-racuni.com/x" }).ponudnik === null, "naslov z uporabnikom/geslom: izklopljen");
      assert(iz({ ...ENV, ERACUNI_URL: "" , RENDER: "1" }).ponudnik !== null && iz({ ...ENV, ERACUNI_URL: "", RENDER: "1" }).ime === "eracuni", "privzeti naslov (https) v produkciji velja");
      assert(iz({ ...ENV, ERACUNI_BLAGAJNA: "1 2" }).ponudnik === null && iz({ ...ENV, ERACUNI_POSLOVNA_ENOTA: "A-001" }).ponudnik === null, "neveljavna blagajna / poslovna enota: izklopljen");
      const n0 = F.klici.length, l0 = LOG.length;
      const brez = racuni.ustvari({ pool, env: { RACUNI_PONUDNIK: "eracuni", RACUNI_TICK_MS: "0", RACUNI_POSPRAVI_MS: "0" } });
      let padel = false; try { brez.zazeni(); } catch (_) { padel = true; }
      const R0 = await nov();
      assert(!padel && (await brez.tek()) === 0 && F.klici.length === n0 && (await vrstica(R0.id)).stanje === "caka" && logOd(l0).some((l) => /POZOR.*manjka ERACUNI_USERNAME, ERACUNI_SECRET_KEY, ERACUNI_TOKEN/.test(l)),
        "zagon brez kljucev ne pade, nic se ne poslje, vrstica ostane caka, v dnevniku je POZOR z imeni spremenljivk", logOd(l0));
      await pool.query("UPDATE racuni SET naslednji_poskus_at = NOW() + INTERVAL '1 day' WHERE id = $1", [R0.id]);   // ta vrstica ne sme v naslednje teste
      let napacen = 0;
      for (let c = 1; c <= 200000; c++) {
        const pricakovano = `${Math.floor(c / 100)}.${String(c % 100).padStart(2, "0")}`.replace(/0+$/, "").replace(/\.$/, "");
        if (JSON.stringify(Math.trunc(c) / 100) !== pricakovano) napacen++;
      }
      assert(napacen === 0, "cene: centi / 100 se v JSON zapisejo kot natancno decimalno stevilo (200000 vrednosti)", napacen);
    }

    // ================================================================
    console.log("\n# 1. Uspeh: stevilka je od ponudnika, zahtevek brez kupca");
    let R1;
    {
      F.stevec = 41; R1 = await nov(3, 1999);
      const w = deloven(); const n0 = F.klici.length, l0 = LOG.length;
      await tek(w);
      const r = await vrstica(R1.id); const d = F.docs[0];
      assert(r.stanje === "potrjen" && Number(r.stevilka) === 42 && r.prostor === "A001" && r.naprava === "1" && r.leto === leto && r.stevilka_vir === "ponudnik",
        "potrjen s stevilko e-racuni (42), A001-1-N, vir ponudnik", r);
      assert(r.eor === d.eor && r.zoi === d.zoi && r.ponudnik === "eracuni" && r.ponudnik_id === d.id && r.ponudnik_stevilka === d.number && r.potrjen_at && r.poskusi === 0 && !r.naknadno,
        "EOR, ZOI, ponudnik_id (documentID), ponudnik_stevilka shranjeni", r);
      assert((await pool.query("SELECT COUNT(*)::int AS n FROM racuni_zaporedje")).rows[0].n === 0, "nas stevec racuni_zaporedje se NI dotaknil (ena zaporedja, ponudnikovo)");
      const k = F.klici.slice(n0);
      assert(k.length === 2 && k[0].method === "SalesInvoiceCreate" && k[1].method === "SalesInvoiceGet" && k[1].parameters.number === d.number && k[1].parameters.documentID === undefined,
        "klici: SalesInvoiceCreate, nato SalesInvoiceGet po STEVILKI dokumenta (S1: documentID in number nista zamenljiva)", k.map((x) => x.method));
      const s = k[0].parameters.SalesInvoice;
      assert(s.type === "Retail" && s.methodOfPayment === "Stripe" && s.cashRegisterCode === "1" && s.businessUnit === "A001" && s.orderReference === r.message_id,
        "Retail, Stripe, blagajna 1, enota A001, orderReference = message_id", s);
      assert(s.Items.length === 1 && s.Items[0].quantity === 3 && s.Items[0].price === 19.99 && s.Items[0].description === "Vstopnica: Outly Launch Party, 24. 12. 2026" && s.Items[0].vatTransactionType === 7,
        "postavka: Vstopnica: dogodek, datum; 3 x 19,99 (koncna cena, ne 59,97 na enoto); vrsta prodaje 7", s.Items);
      assert(s.remarks === racuni.DDV_KLAVZULA && s.dateOfSupplyFrom === dan(), "klavzula o DDV v opombi, datum opravljene storitve", [s.remarks, s.dateOfSupplyFrom]);
      assert(!/buyer/i.test(k[0].telo) && !k[0].telo.includes(KUPEC_EMAIL) && !k[0].telo.includes("lastnik@outly.si") && !k[0].telo.includes("lastnik\""),
        "v zahtevku NI e-naslova, imena ali kakega polja kupca (buyer*)");
      assert(k[0].telo.includes(TAJNO.user) && k[0].telo.includes(TAJNO.key) && k[0].telo.includes(TAJNO.token), "poverilnice so v telesu zahtevka (WS API), ne v naslovu");
      assert(!logOd(l0).some((l) => /POZOR/.test(l)), "brez POZOR v dnevniku", logOd(l0));
      assert(r.izdan_at === null, "S3: ponudnik v odgovoru ni vrnil casa izdaje -> izdan_at je NULL (cas se NE izmisli)", r.izdan_at);
      const v = racuni.vsebinaRacuna(r, { ...r, quantity: 3, unit_price_cents: 1999, title: "Outly Launch Party", start_at: "2026-12-24T19:00:00Z", public_ref: R1.ref });
      assert(v === null && racuni.stevilkaRacuna(r.prostor, r.naprava, r.stevilka) === "A001-1-42", "blok racuna brez casa izdaje ni izdelan (I32 ostane izklopljen); stevilka je A001-1-42", v);
    }

    // ================================================================
    console.log("\n# 2. Zacasna napaka PRED obdelavo (503): iskanje po referenci, potem ena izdaja");
    {
      const R = await nov(1, 1500); const w = deloven(); const n0 = F.klici.length, d0 = F.docs.length;
      nastavi("503pred", 1);
      await tek(w, 5, 130, true);
      const r = await vrstica(R.id); const k = F.klici.slice(n0).map((x) => x.method);
      assert(r.stanje === "potrjen" && F.docs.length === d0 + 1 && r.naknadno === true && r.poskusi === 1, "po ponovitvi potrjen, natanko ENA izdaja, naknadno = true", [r.stanje, r.poskusi, F.docs.length - d0]);
      assert(k.join() === "SalesInvoiceCreate,SalesInvoiceList,SalesInvoiceList,SalesInvoiceCreate,SalesInvoiceGet", "zaporedje: Create (503), List (ni najden 1/2), List (ni najden 2/2), Create, Get", k);
    }

    // ================================================================
    console.log("\n# 3. Odgovor izgubljen PO obdelavi (503 po izdaji): dokument se najde, nova izdaja se NE zgodi");
    {
      const R = await nov(2, 1000); const w = deloven(); const n0 = F.klici.length, d0 = F.docs.length;
      nastavi("503po", 1);
      await tek(w, 3, 130, true);
      const r = await vrstica(R.id); const k = F.klici.slice(n0).map((x) => x.method);
      const doc = F.docs[d0];
      assert(F.docs.length === d0 + 1 && r.stanje === "potrjen" && r.ponudnik_id === doc.id && Number(r.stevilka) === doc.fiscalNumber && doc.orderReference === r.message_id,
        "natanko en dokument pri ponudniku, nasa vrstica ima njegovo stevilko in id", [F.docs.length - d0, r.stanje]);
      assert(k.filter((m) => m === "SalesInvoiceCreate").length === 1 && k.includes("SalesInvoiceList"), "samo en Create; ponovitev je naredila List", k);
    }

    // ================================================================
    console.log("\n# 4. Timeout po poslanem zahtevku (izid neznan): brez dvojnika");
    {
      const R = await nov(1, 2000); const w = deloven(); const n0 = F.klici.length, d0 = F.docs.length, l0 = LOG.length;
      nastavi("timeoutpo", 1);
      await tek(w);
      const r1 = await vrstica(R.id);
      assert(r1.stanje === "caka" && r1.stevilka === null && r1.poslano_at && r1.poskusi === 1 && r1.naknadno === true && F.docs.length === d0 + 1, "po timeoutu: caka, brez stevilke, poslano_at zapisan, dokument pri ponudniku ze obstaja", r1);
      assert(logOd(l0).some((l) => /izid neznan/.test(l)), "dnevnik: izid neznan -> najprej iskanje po referenci");
      await pocakaj(120);
      await tek(w, 3, 130, true);
      const r = await vrstica(R.id); const k = F.klici.slice(n0).map((x) => x.method);
      assert(r.stanje === "potrjen" && F.docs.length === d0 + 1 && r.ponudnik_id === F.docs[d0].id && k.filter((m) => m === "SalesInvoiceCreate").length === 1,
        "ponovitev najde dokument po referenci: potrjen, ENA izdaja skupaj", [r.stanje, F.docs.length - d0, k]);
      await pocakaj(1500);   // lazni strežnik se je se odzival v prazno
    }

    // ================================================================
    console.log("\n# 5. 429 (zagotovo ni obdelano): poslano_at se pobrise, ponovitev brez iskanja");
    {
      const R = await nov(1, 1000); const w = deloven(); const n0 = F.klici.length, d0 = F.docs.length;
      nastavi("429", 1);
      await tek(w);
      const r1 = await vrstica(R.id);
      assert(r1.stanje === "caka" && r1.poslano_at === null && r1.poskusi === 1 && F.docs.length === d0, "429: caka, poslano_at pobrisan, nic izdanega", r1);
      await pocakaj(100);
      await tek(w, 2);
      const r = await vrstica(R.id); const k = F.klici.slice(n0).map((x) => x.method);
      assert(r.stanje === "potrjen" && F.docs.length === d0 + 1 && !k.includes("SalesInvoiceList"), "ponovitev: izdaja brez iskanja, potrjen, ena izdaja", k);
    }

    // ================================================================
    console.log("\n# 6. Trajna napaka (validacija): napaka brez stevilke + POZOR; rocna ponovitev gre skozi iskanje");
    {
      const R = await nov(1, 1000); const w = deloven(); const n0 = F.klici.length, d0 = F.docs.length, l0 = LOG.length, stevec0 = F.stevec;
      nastavi("napaka", 1);
      await tek(w);
      const r = await vrstica(R.id);
      assert(r.stanje === "napaka" && r.stevilka === null && r.ponudnik_id === null && /Invalid value/.test(r.zadnja_napaka) && F.docs.length === d0 && F.stevec === stevec0, "napaka brez stevilke; ponudnik ni porabil stevilke", r);
      assert(logOd(l0).some((l) => /POZOR/.test(l) && /ZAVRNIL/.test(l)), "POZOR v dnevniku");
      const m1 = F.klici.length; await pocakaj(150); await tek(w, 2);
      assert(F.klici.length === m1, "napaka se ne ponavlja (brez novih klicev)");
      assert(r.poslano_at !== null, "K1: po poslanem zahtevku z napako v odgovoru poslano_at OSTANE (ponudnik je dokument morda ustvaril)", r.poslano_at);
      await pool.query("UPDATE racuni SET stanje = 'caka', naslednji_poskus_at = NOW() WHERE id = $1", [R.id]);   // rocna ponovitev (z Martinovim DA prek migracije)
      const n1 = F.klici.length;
      await tek(w, 5, 130, true);
      const r2 = await vrstica(R.id); const k = F.klici.slice(n1).map((x) => x.method);
      assert(r2.stanje === "potrjen" && k.join() === "SalesInvoiceList,SalesInvoiceList,SalesInvoiceCreate,SalesInvoiceGet" && F.docs.length === d0 + 1, "rocna ponovitev: najprej DVA iskanja po referenci (poslano_at), nato izdaja, potrjen", k);
    }

    // ================================================================
    console.log("\n# 7. Napacne poverilnice / nastavitev: vrstica ostane `caka`, pocasna ponovitev + POZOR; preizkus pred izdajo (pregled #318, 3. krog)");
    for (const [ime, okolje] of [["ERACUNI_SEZNAM_PREVERJEN=1", {}], ["zastavica izklopljena (privzeto v produkciji)", { ERACUNI_SEZNAM_PREVERJEN: "" }]]) {
      const R = await nov(1, 1000); const w = deloven(okolje); const l0 = LOG.length, d0 = F.docs.length, c0 = klicov("SalesInvoiceCreate");
      F.poverilnice = false;
      const t0 = Date.now();
      await tek(w);
      const r = await vrstica(R.id);
      const odlog = new Date(r.naslednji_poskus_at).getTime() - t0;
      assert(r.stanje === "caka" && r.stevilka === null && r.poskusi === 1 && /Access denied/.test(r.zadnja_napaka) && odlog >= 300 && F.docs.length === d0, `[${ime}] caka (NE napaka), ponovitev po >= 400 ms (RACUNI_KONFIG_PREMOR_MS)`, [r.stanje, odlog]);
      assert(klicov("SalesInvoiceCreate") === c0 && r.poslano_at === null, `[${ime}] napacen kljuc: Create se NE poslje (bralni preizkus pade), poslano_at ostane prazen`, [klicov("SalesInvoiceCreate") - c0, r.poslano_at]);
      assert(logOd(l0).some((l) => /POZOR.*nastavitev pri ponudniku/.test(l)), `[${ime}] POZOR: nastavitev pri ponudniku`);
      F.poverilnice = true;
      await pocakaj(500);
      await tek(w, 5, 130, true);
      const r1 = await vrstica(R.id);
      assert(r1.stanje === "potrjen" && F.docs.length === d0 + 1 && klicov("SalesInvoiceCreate") === c0 + 1, `[${ime}] po popravku poverilnic racun gre naprej BREZ iskanja po referenci: ena izdaja, potrjen`, [r1.stanje, F.docs.length - d0, klicov("SalesInvoiceCreate") - c0]);
    }
    {
      // dokument na drugi blagajni: konfiguracija, ne napaka
      const R2 = await nov(1, 1000); const w2 = deloven();
      F.vrniBlagajno = "9";   // ponudnik vrne dokument z drugo blagajno, kot smo jo zahtevali
      await tek(w2);
      F.vrniBlagajno = null;
      const r2 = await vrstica(R2.id);
      assert(r2.stanje === "caka" && r2.ponudnik_id && r2.stevilka === null && /drugi poslovni enoti\/blagajni/.test(r2.zadnja_napaka), "dokument izdan na drugi blagajni (ponudnik jo dolocil drugace): stevilka se NE sprejme, caka + POZOR", r2);
      await pool.query("UPDATE racuni SET naslednji_poskus_at = NOW() + INTERVAL '1 day', poslano_at = NOW() - INTERVAL '3 days' WHERE id = $1", [R2.id]);
      F.docs.pop(); F.stevec -= 1;   // ta dokument ne sodi v zaporedje blagajne 1 (ostali testi preverjajo luknje); vrstica ni vec »znan dokument tega obdobja«
    }

    // ================================================================
    console.log("\n# 8. Odgovor izdaje brez oznake dokumenta; seznam v neprepoznani obliki");
    {
      const R = await nov(1, 1000); const w = deloven(); const d0 = F.docs.length, n0 = F.klici.length;
      nastavi("brezOznake", 1);
      await tek(w, 2);
      const r = await vrstica(R.id); const k = F.klici.slice(n0).map((x) => x.method);
      assert(r.stanje === "potrjen" && F.docs.length === d0 + 1 && k.filter((m) => m === "SalesInvoiceCreate").length === 1 && k.includes("SalesInvoiceList"), "izdaja uspela brez oznake: dokument najden po referenci, ena izdaja", k);
      const R2 = await nov(1, 1000); const d1 = F.docs.length;
      nastavi("503po", 1);
      await tek(w);
      F.listOblika = "neznana";
      await pocakaj(100); await tek(w, 2, 130, true);
      const r2 = await vrstica(R2.id);
      assert(r2.stanje === "caka" && r2.stevilka === null && F.docs.length === d1 + 1 && /ne da zanesljivega izida/.test(r2.zadnja_napaka) && r2.iskanja_nejasna === 2, "seznam v neprepoznani obliki: ne trdimo »ni najden«, NOVE izdaje ni", [r2.stanje, r2.zadnja_napaka, F.docs.length - d1, r2.iskanja_nejasna]);
      F.listOblika = "ok";
      await pocakaj(100); await tek(w, 3, 130, true);
      assert((await vrstica(R2.id)).stanje === "potrjen" && F.docs.length === d1 + 1, "ko seznam spet deluje: najden, potrjen, se vedno ena izdaja");
    }

    // ================================================================
    console.log("\n# 9. EOR zamuja: stevilka se zapise, kasneje potrjen z isto stevilko");
    {
      const R = await nov(1, 1000); const w = deloven(); const d0 = F.docs.length; const n0 = F.klici.length;
      F.zamudaEorDo = 3;   // EOR se pokaze sele od tretjega Get dalje (get stevilka: d.getov)
      await tek(w);
      const r1 = await vrstica(R.id);
      assert(r1.stanje === "izdan" && Number(r1.stevilka) === F.docs[d0].fiscalNumber && r1.eor === null && r1.potrjen_at === null && r1.stevilka_vir === "ponudnik", "stevilka zapisana, brez EOR: izdan", r1);
      await pocakaj(100); await tek(w, 3);
      const r = await vrstica(R.id); const k = F.klici.slice(n0).map((x) => x.method);
      assert(r.stanje === "potrjen" && Number(r.stevilka) === Number(r1.stevilka) && r.eor === F.docs[d0].eor && F.docs.length === d0 + 1 && k.filter((m) => m === "SalesInvoiceCreate").length === 1,
        "kasneje potrjen z ISTO stevilko, brez nove izdaje", [r.stanje, k]);
      F.zamudaEorDo = 0;
    }

    // ================================================================
    console.log("\n# 10. Dobropis: po uspelem vracilu in po potrjenem izvirnem racunu");
    {
      const w = deloven();
      // (a) izvirni racun se ni potrjen -> dobropis caka
      const A = await nov(2, 1500);
      const ra = (await pool.query("SELECT id FROM racuni WHERE order_id = $1", [A.oid])).rows[0].id;
      await pool.query("UPDATE racuni SET naslednji_poskus_at = NOW() + INTERVAL '1 day' WHERE id = $1", [ra]);
      const dA = (await pool.query("INSERT INTO racuni (order_id, vrsta, ref_racun_id, vir, znesek_cents, vracilo_uspelo) VALUES ($1, 'dobropis', $2, 're_a1', -1500, TRUE) RETURNING id", [A.oid, ra])).rows[0].id;
      const n0 = F.klici.length;
      await tek(w);
      assert(klicov("CreditNoteCreate") === 0 && (await vrstica(dA)).stanje === "caka" && (await vrstica(dA)).poslano_at === null, "izvirni racun brez stevilke: dobropis NE gre ponudniku");
      // (b) izvirni racun potrjen, vracilo se ni izvedeno -> ni izdaje
      await pool.query("UPDATE racuni SET naslednji_poskus_at = NOW() WHERE id = $1", [ra]);
      await pool.query("UPDATE racuni SET vracilo_uspelo = NULL WHERE id = $1", [dA]);
      await tek(w, 2);
      const rA = await vrstica(ra);
      assert(rA.stanje === "potrjen" && klicov("CreditNoteCreate") === 0 && (await vrstica(dA)).stevilka === null, "vracilo se ni izvedeno (izid neznan): dobropis ni izdan", await vrstica(dA));
      // (c) vracilo izvedeno -> CreditNoteCreate
      await pool.query("UPDATE racuni SET vracilo_uspelo = TRUE, naslednji_poskus_at = NOW() WHERE id = $1", [dA]);
      const n1 = F.klici.length;
      await tek(w, 2);
      const d = await vrstica(dA); const k = F.klici.slice(n1); const cn = k.find((x) => x.method === "CreditNoteCreate");
      assert(d.stanje === "potrjen" && Number(d.stevilka) === Number(rA.stevilka) + 1 && d.stevilka_vir === "ponudnik" && d.eor && d.ponudnik_id, "dobropis potrjen, stevilka = naslednja v ENEM zaporedju e-racuni", [d.stanje, d.stevilka, rA.stevilka]);
      assert(cn && cn.parameters.CreditNote.salesInvoiceRef === rA.ponudnik_stevilka && cn.parameters.CreditNote.orderReference === d.message_id
        && cn.parameters.CreditNote.Items.length === 1 && cn.parameters.CreditNote.Items[0].price === 15 && cn.parameters.CreditNote.Items[0].quantity === 1
        && cn.parameters.CreditNote.Items[0].description === `Vračilo za račun A001-1-${rA.stevilka} (vstopnica: Outly Launch Party, 24. 12. 2026)`
        && !/buyer/i.test(cn.telo) && cn.parameters.CreditNote.cashRegisterCode === "1" && cn.parameters.CreditNote.businessUnit === "A001",
        "CreditNoteCreate: salesInvoiceRef = stevilka izvirnika pri ponudniku, orderReference, pozitiven znesek 15, brez kupca", cn && cn.parameters);
      assert(k.map((x) => x.method).join() === "CreditNoteCreate,CreditNoteGet", "klici: CreditNoteCreate, CreditNoteGet");
      // (d) dobropis z zacasno napako: brez dvojnika (ista pot kot racun)
      const B = await nov(1, 1000); await tek(w);
      const rb = (await pool.query("SELECT id FROM racuni WHERE order_id = $1", [B.oid])).rows[0].id;
      const dB = (await pool.query("INSERT INTO racuni (order_id, vrsta, ref_racun_id, vir, znesek_cents, vracilo_uspelo) VALUES ($1, 'dobropis', $2, 're_b1', -1000, TRUE) RETURNING id", [B.oid, rb])).rows[0].id;
      const c0 = F.docs.filter((x) => x.vrsta === "dobropis").length;
      nastavi("503po", 1);
      await tek(w, 4);
      assert((await vrstica(dB)).stanje === "potrjen" && F.docs.filter((x) => x.vrsta === "dobropis").length === c0 + 1, "dobropis, odgovor izgubljen: najden po referenci (CreditNoteList), ENA izdaja");
    }

    // ================================================================
    console.log("\n# 11. En klic naenkrat, razmak med zahtevki, zaporedne stevilke");
    {
      const w = deloven({ RACUNI_VZPOREDNO: "4", ERACUNI_RAZMAK_MS: "60", RACUNI_ROK_MS: "5000" });
      const ids = []; for (let i = 0; i < 7; i++) ids.push((await nov(1, 1000 + i)).id);
      const od = F.zacetki.length; F.maxInflight = 0;
      await tek(w, 3, 50);
      const st = (await pool.query("SELECT stanje, stevilka FROM racuni WHERE id = ANY($1::bigint[]) ORDER BY id", [ids])).rows;
      const z = F.zacetki.slice(od); let najmanj = 1e9; for (let i = 1; i < z.length; i++) najmanj = Math.min(najmanj, z[i] - z[i - 1]);
      assert(st.every((x) => x.stanje === "potrjen"), "vseh 7 potrjenih", st);
      assert(F.maxInflight === 1, "nikoli dva hkratna zahtevka (API tega ne dovoli)", F.maxInflight);
      assert(najmanj >= 50, "razmak med zacetki zahtevkov >= 60 ms (mejo 1/s zagotovi ERACUNI_RAZMAK_MS)", najmanj);
      const sv = st.map((x) => Number(x.stevilka)).sort((a, b) => a - b);
      assert(new Set(sv).size === 7 && sv.every((x, i) => i === 0 || x === sv[i - 1] + 1), "stevilke (po vrstnem redu izdaje pri ponudniku) zaporedne, brez dvojnikov", sv);
    }

    // ================================================================
    console.log("\n# 12. Luknja v zaporedju ponudnika");
    {
      const w = deloven();
      const l0 = LOG.length;
      await w.pospravi();
      assert(!logOd(l0).some((l) => /manjka/.test(l)), "brez luknje: brez opozorila", logOd(l0));
      F.stevec += 1;   // rocni dokument na isti blagajni vzame stevilko
      const R = await nov(1, 1234); await tek(w);
      const r = await vrstica(R.id);
      const w2 = deloven();
      const l1 = LOG.length;
      await w2.pospravi();
      assert(r.stanje === "potrjen" && logOd(l1).some((l) => /POZOR/.test(l) && new RegExp(`A001-1-${Number(r.stevilka) - 1} `).test(l)), `luknja (manjka ${Number(r.stevilka) - 1}) -> POZOR`, logOd(l1));
      F.stevec += 1; await tek(w);
    }

    // ================================================================
    console.log("\n# 13. Sprozilec (056)");
    {
      const poskusi = async (sql, par) => { try { await pool.query(sql, par); return null; } catch (e) { return e; } };
      const R = await nov(1, 777);
      const ime = (e) => (e ? `${e.code}:${String(e.message).slice(0, 80)}` : "ni napake");
      let e = await poskusi("UPDATE racuni SET prostor='A001', naprava='1', leto=$2, stevilka=9001, izdan_at=NOW(), stevilka_vir='ponudnik', stanje='izdan' WHERE id=$1", [R.id, leto]);
      assert(e && e.code === "23001" && /ponudnik/.test(e.message), "stevilka od ponudnika brez ponudnika in dokumenta: zavrnjeno", ime(e));
      e = await poskusi("UPDATE racuni SET ponudnik='eracuni', ponudnik_id='60:9', prostor='A001', naprava='1', leto=$2, stevilka=9001, izdan_at=NOW(), stanje='izdan' WHERE id=$1", [R.id, leto]);
      assert(e && e.code === "23001" && /stevca/.test(e.message), "vir `nas` s stevilko mimo stevca: zavrnjeno", ime(e));
      const r0 = await vrstica(R.id);
      e = await poskusi("UPDATE racuni SET ponudnik='eracuni', ponudnik_id='60:9', prostor='A001', naprava='1', leto=$2, stevilka=$3, izdan_at=NOW(), stevilka_vir='ponudnik', stanje='izdan' WHERE id=$1", [R.id, leto, (await pool.query("SELECT stevilka FROM racuni WHERE stevilka IS NOT NULL LIMIT 1")).rows[0].stevilka]);
      assert(e && e.code === "23505", "dvojnik stevilke v istem (prostor, naprava, leto): zavrnjeno (unikatni indeks)", ime(e));
      await pool.query("INSERT INTO racuni_zaporedje (prostor, naprava, leto) VALUES ('A001', '1', $1) ON CONFLICT DO NOTHING", [leto]);
      await pool.query("UPDATE racuni_zaporedje SET zadnja = zadnja + 1 WHERE prostor='A001' AND naprava='1' AND leto=$1", [leto]);
      const stCtr = (await pool.query("SELECT zadnja FROM racuni_zaporedje WHERE prostor='A001' AND naprava='1' AND leto=$1", [leto])).rows[0].zadnja;
      e = await poskusi("UPDATE racuni SET prostor='A001', naprava='1', leto=$2, stevilka=$3, izdan_at=NOW(), stanje='izdan' WHERE id=$1", [R.id, leto, stCtr]);
      assert(e && e.code === "23001" && /drugega vira/.test(e.message), "nas stevec v prostoru, kjer so ze stevilke ponudnika (dve zaporedji): zavrnjeno", ime(e));
      const P = (await pool.query("SELECT id FROM racuni WHERE stevilka_vir='ponudnik' AND stanje='potrjen' LIMIT 1")).rows[0].id;
      // S3: cas izdaje pri ponudniku sme iz NULL postati cas ENKRAT, potem je zamrznjen; pri `nas` ostane vezan na stevilko
      e = await poskusi("UPDATE racuni SET izdan_at = '2026-10-22T14:03:05+02:00' WHERE id=$1 AND izdan_at IS NULL", [P]);
      const izd = (await vrstica(P)).izdan_at;
      assert(!e && izd && new Date(izd).toISOString() === "2026-10-22T12:03:05.000Z", "izdan_at pri ponudniku: NULL -> cas dovoljeno (enkrat)", ime(e));
      e = await poskusi("UPDATE racuni SET izdan_at = NOW() WHERE id=$1", [P]); assert(e && e.code === "23001", "izdan_at se po zapisu ne spremeni vec", ime(e));
      e = await poskusi("UPDATE racuni SET izdan_at = NULL WHERE id=$1", [P]); assert(e && e.code === "23001", "izdan_at se ne more vrniti na NULL", ime(e));
      e = await poskusi("UPDATE racuni SET stevilka_vir='nas' WHERE id=$1", [P]); assert(e && e.code === "23001" && /vira/.test(e.message), "vir stevilke se po dodelitvi ne spremeni", ime(e));
      e = await poskusi("UPDATE racuni SET ponudnik_stevilka='x' WHERE id=$1", [P]); assert(e && e.code === "23001", "ponudnik_stevilka se po zapisu ne spremeni", ime(e));
      e = await poskusi("UPDATE racuni SET stevilka = stevilka + 1000 WHERE id=$1", [P]); assert(e && e.code === "23001", "stevilka potrjenega racuna se ne spremeni", ime(e));
      e = await poskusi("DELETE FROM racuni WHERE id=$1", [P]); assert(e && e.code === "23001", "brisanje se vedno zavrnjeno", ime(e));
      e = await poskusi("INSERT INTO racuni (order_id, vrsta, znesek_cents, poslano_at) VALUES ($1, 'racun', 5, NOW())", [(await nov(1, 5)).oid]);
      assert(e && (e.code === "23001" || e.code === "23505"), "INSERT s poslano_at ali drugim racunom za isto narocilo: zavrnjeno", ime(e));
      // napaka S stevilko ne sme nazaj v caka
      e = await poskusi("UPDATE racuni SET stanje='napaka' WHERE id=$1", [P]);
      const napakaZ = (await pool.query("SELECT id FROM racuni WHERE id=$1 AND stanje='napaka'", [P])).rows.length;
      assert(e && e.code === "23001" && napakaZ === 0, "potrjen racun ne more v napako (koncno stanje)", ime(e));
      const X = await nov(1, 888);
      await pool.query("UPDATE racuni SET stanje='napaka', zadnja_napaka='test' WHERE id=$1", [X.id]);
      e = await poskusi("UPDATE racuni SET stanje='caka' WHERE id=$1", [X.id]);
      assert(!e, "napaka BREZ stevilke sme nazaj v caka (rocna ponovitev)", ime(e));
      await pool.query("UPDATE racuni SET naslednji_poskus_at = NOW() + INTERVAL '1 day' WHERE id=$1", [X.id]);
      await pool.query("DELETE FROM racuni_zaporedje").catch(() => {});   // sprozilec brisanja stevca zavrne
      await pool.query("TRUNCATE racuni_zaporedje");
      void r0;
    }

    // ================================================================
    console.log("\n# 14. Izid vracila med izdajo dobropisa");
    {
      const A = await nov(1, 1000); await tek(deloven());
      const ra = (await pool.query("SELECT id FROM racuni WHERE order_id = $1", [A.oid])).rows[0].id;
      const poslan = (await pool.query("INSERT INTO racuni (order_id, vrsta, ref_racun_id, vir, znesek_cents) VALUES ($1, 'dobropis', $2, 're_p1', -400) RETURNING id", [A.oid, ra])).rows[0].id;
      await pool.query("UPDATE racuni SET poslano_at = NOW() WHERE id = $1", [poslan]);
      const neposlan = (await pool.query("INSERT INTO racuni (order_id, vrsta, ref_racun_id, vir, znesek_cents) VALUES ($1, 'dobropis', $2, 're_p2', -300) RETURNING id", [A.oid, ra])).rows[0].id;
      const l0 = LOG.length;
      const i1 = await racuni.izidVracila(pool, "re_p1", "failed");
      const i2 = await racuni.izidVracila(pool, "re_p2", "failed");
      assert(i1 === "izdan_zavrnjen" && (await vrstica(poslan)).stanje === "caka" && logOd(l0).some((l) => /POZOR.*re_p1/.test(l)), "dobropis, ki je ze poslan ponudniku, se NE preklice tiho: POZOR (rocno)", [i1, logOd(l0)]);
      assert(i2 === "preklican" && (await vrstica(neposlan)).stanje === "preklican", "neposlan dobropis se preklice kot doslej", i2);
    }


    // ================================================================
    console.log("\n# 16. K1: poslano_at se po poslanem zahtevku NE brise glede na BESEDILO napake");
    {
      for (const besedilo of ["Fiscalization failed: certificate expired", "FURS temporarily unavailable, try again", "Document not found, please retry later"]) {
        const R = await nov(1, 1100); const w = deloven(); const d0 = F.docs.length;
        nastavi("dokInNapaka", 1); F.vedenje.besedilo = besedilo;
        await tek(w);
        const r1 = await vrstica(R.id);
        assert(r1.stanje === "caka" && r1.poslano_at !== null && F.docs.length === d0 + 1, `»${besedilo.slice(0, 32)}…«: dokument je nastal, vrstica caka, poslano_at OSTANE`, [r1.stanje, r1.poslano_at, F.docs.length - d0]);
        await tek(w, 6, 130, true);
        const r = await vrstica(R.id);
        assert(r.stanje === "potrjen" && F.docs.filter((x) => x.orderReference === r.message_id).length === 1, "ponovitev najde dokument po referenci: potrjen, ENA izdaja pri ponudniku", [r.stanje, F.docs.filter((x) => x.orderReference === r.message_id).length]);
      }
      // napaka povezave PRED posiljanjem telesa (zavrnjena povezava): dokazano ni poslano -> poslano_at pobrisan
      const R = await nov(1, 1111); const wMrtev = deloven({ ERACUNI_URL: "http://127.0.0.1:3392/WebServicesSI/API" }); const d0 = F.docs.length;
      await tek(wMrtev);
      const r1 = await vrstica(R.id);
      assert(r1.stanje === "caka" && r1.poslano_at === null && r1.poskusi === 1 && /ni bil poslan/.test(r1.zadnja_napaka) && F.docs.length === d0, "zavrnjena povezava: dokazano ni poslano -> poslano_at pobrisan", r1);
      const n0 = F.klici.length; await tek(deloven(), 2, 130, true);
      assert((await vrstica(R.id)).stanje === "potrjen" && F.klici.slice(n0).map((x) => x.method).join() === "SalesInvoiceCreate,SalesInvoiceGet", "ponovitev: izdaja brez iskanja (nic ni bilo poslano)");
      // povezava prekinjena PO prejemu telesa: izid neznan -> poslano_at ostane, dokument najden po referenci
      const R2 = await nov(1, 1122); const w = deloven(); const d1 = F.docs.length;
      nastavi("prekini", 1);
      await tek(w);
      const r2 = await vrstica(R2.id);
      assert(r2.stanje === "caka" && r2.poslano_at !== null && F.docs.length === d1 + 1, "prekinjena povezava po posiljanju: poslano_at OSTANE", [r2.stanje, r2.poslano_at]);
      await tek(w, 5, 130, true);
      assert((await vrstica(R2.id)).stanje === "potrjen" && F.docs.length === d1 + 1, "najden po referenci, ENA izdaja");
    }

    // ================================================================
    console.log("\n# 17. K2: en delavec e-racuni v celem sistemu (najem) + zeton prevzema na vsakem zapisu");
    {
      // (a) dve instanci, prevzem zastara (RACUNI_ZASTARELO_MS), izdaja pocasna: druga instanca NE sme poslati nicesar
      const R = await nov(1, 1200);
      await pool.query("UPDATE racuni SET poslano_at = NOW() - INTERVAL '5 minutes', iskanja_ne = 1, iskanje_ne_at = NOW() - INTERVAL '5 minutes' WHERE id = $1", [R.id]);
      const env = { RACUNI_ZASTARELO_MS: "1000", RACUNI_ROK_MS: "5000" };
      const w1 = deloven(env), w2 = deloven(env); const c0 = klicov("SalesInvoiceCreate"), d0 = F.docs.length, m0 = F.klici.length;
      nastavi("pocasno", 1);
      const p1 = w1.tek(); await pocakaj(1200);
      const n2 = await w2.tek(); await p1;
      const najem = (await pool.query("SELECT lastnik, potece_at <= NOW() AS sproscen FROM racuni_najem WHERE ime = 'eracuni'")).rows[0];
      assert(n2 === 0 && klicov("SalesInvoiceCreate") === c0 + 1 && F.docs.length === d0 + 1 && (await vrstica(R.id)).stanje === "potrjen",
        "druga instanca ob zastarelem prevzemu ne dobi najema: ENA izdaja, nobenega klica", [n2, klicov("SalesInvoiceCreate") - c0, F.docs.length - d0]);
      assert(najem && najem.sproscen === true, "najem je po koncu teka sproscen (naslednja instanca ne caka)", najem);
      void m0;
      // (b) najem drzi drug proces: nic se ne poslje; ko poteče, delo gre naprej
      const R2 = await nov(1, 1210); const w = deloven(); const m1 = F.klici.length;
      await pool.query("INSERT INTO racuni_najem (ime, lastnik, potece_at) VALUES ('eracuni', 'tuja-instanca', NOW() + INTERVAL '1 hour') ON CONFLICT (ime) DO UPDATE SET lastnik = 'tuja-instanca', potece_at = NOW() + INTERVAL '1 hour'");
      const n3 = await w.tek();
      assert(n3 === 0 && F.klici.length === m1 && (await vrstica(R2.id)).stanje === "caka" && (await vrstica(R2.id)).prevzeto_at === null, "najem drzi drug proces: nic se ne prevzame, nic se ne poslje");
      await pool.query("UPDATE racuni_najem SET potece_at = NOW() - INTERVAL '1 second' WHERE ime = 'eracuni'");
      await tek(w, 2);
      assert((await vrstica(R2.id)).stanje === "potrjen", "ko najem poteče, delavec prevzame delo");
      // (c) zeton prevzema: vrstico med iskanjem prevzame drug proces -> zapis »poslano« in klic odpadeta (brez najema, da preverimo samo zeton)
      const R3 = await nov(1, 1220);
      await pool.query("UPDATE racuni SET poslano_at = NOW() - INTERVAL '5 minutes', iskanja_ne = 1, iskanje_ne_at = NOW() - INTERVAL '5 minutes' WHERE id = $1", [R3.id]);
      const c1 = klicov("SalesInvoiceCreate"), d1 = F.docs.length;
      F.listZamik = 700;
      const p = deloven().tek(); await pocakaj(300);
      await pool.query("UPDATE racuni SET prevzem_zeton = 'tuj-zeton' WHERE id = $1", [R3.id]);
      await p; F.listZamik = 0;
      const r3 = await vrstica(R3.id);
      assert(klicov("SalesInvoiceCreate") === c1 && F.docs.length === d1 && r3.prevzem_zeton === 'tuj-zeton' && r3.prevzeto_at !== null && r3.poskusi === 0,
        "po izgubljenem prevzemu (drug zeton) Create NI poslan, vrstica ostane prevzemniku", [klicov("SalesInvoiceCreate") - c1, r3.prevzem_zeton, r3.poskusi]);
      await pool.query("UPDATE racuni SET prevzeto_at = NULL, naslednji_poskus_at = NOW() + INTERVAL '1 day' WHERE id = $1", [R3.id]);
    }

    // ================================================================
    console.log("\n# 18. K3: iskanje po referenci je stroga (nikoli »ni najden« iz neprepoznanega, praznega ali okrnjenega odgovora)");
    {
      const mid = crypto.randomUUID();
      const prov = racuni.eracuniPonudnik({ ...ENV, ERACUNI_RAZMAK_MS: "0", ERACUNI_SEZNAM_MEJA: "1000" });
      const okno = { od: dan(), do: dan() };
      const znaniPrva = [F.docs[0].orderReference];
      const poskusi = async (oblika, p, p2 = prov) => { F.listOblika = oblika; try { return { izid: await p2.poisci({ vrsta: "racun", message_id: mid, okno, znani: [], ...p }) }; } catch (e) { return { e }; } };
      for (const [oblika, opis] of [["neznana", "neprepoznana oblika"], ["prazno", "prazen odgovor {status: ok}"], ["prazenNiz", "SalesInvoices: \"\""], ["brezRef", "element brez orderReference na nasi blagajni"], ["okrnjenRef", "okrnjena referenca"]]) {
        const r = await poskusi(oblika, {});
        assert(r.e && r.e.nejasno === true && r.izid === undefined, `${opis}: NEJASNO (ne »ni najden«)`, r.e ? r.e.message : r.izid);
      }
      let r = await poskusi("manjkaZnan", { znani: znaniPrva });
      assert(r.e && r.e.nejasno === true && /manjka/.test(r.e.message), "v seznamu manjka dokument, za katerega vemo, da obstaja: NEJASNO (seznam okrnjen ali zamaknjen)", r.e && r.e.message);
      r = await poskusi("prazenSeznam", { znani: znaniPrva });
      assert(r.e && r.e.nejasno === true, "prazen seznam, a v bazi vemo za dokumente tega obdobja: NEJASNO");
      r = await poskusi("prazenSeznam", {});
      assert(r.izid === null, "izrecno prazen seznam [] brez znanih dokumentov: veljaven negativen izid");
      r = await poskusi("ok", { znani: znaniPrva });
      assert(r.izid === null, "popoln seznam, referenca ne obstaja: veljaven negativen izid (null)", r);
      const najdi = F.docs[F.docs.length - 1];
      r = await poskusi("ok", { message_id: najdi.orderReference, znani: znaniPrva });
      assert(r.izid && r.izid.ponudnik_id === najdi.id && r.izid.ponudnik_stevilka === najdi.number, "referenca najdena: oznaka in stevilka dokumenta", r);
      assert(F.listParametri && F.listParametri.dateFrom === okno.od && F.listParametri.dateTo === okno.do, "obdobje iskanja je ozko (dateFrom/dateTo), ne vec dni nazaj", F.listParametri);
      r = await poskusi("dvojnik", { message_id: najdi.orderReference });
      assert(r.e && r.e.trajna === true && /DVOJNIK/.test(r.e.message), "dva dokumenta z isto referenco = ze nastal dvojnik: trajna napaka, rocna obravnava", r.e && r.e.message);
      const kratka = racuni.eracuniPonudnik({ ...ENV, ERACUNI_RAZMAK_MS: "0", ERACUNI_SEZNAM_MEJA: "5" });
      r = await poskusi("ok", {}, kratka);
      assert(r.e && r.e.nejasno === true && /okrnjen/.test(r.e.message), "seznam doseze mejo (ERACUNI_SEZNAM_MEJA): morda okrnjen -> NEJASNO", r.e && r.e.message);
      F.listOblika = "ok";

      // v delavcu: iskanje brez zanesljivega izida nikoli ne vodi v novo izdajo; po ISKANJE_NEJASNO_MAX gre vrstica v `napaka` z navodilom
      const R = await nov(1, 1300); const w = deloven(); const c0 = klicov("SalesInvoiceCreate"), d0 = F.docs.length;
      await pool.query("UPDATE racuni SET poslano_at = NOW() - INTERVAL '1 hour' WHERE id = $1", [R.id]);
      F.listOblika = "neznana";
      await tek(w, 5, 100, true);
      F.listOblika = "ok";
      const rr = await vrstica(R.id);
      assert(rr.stanje === "napaka" && rr.stevilka === null && rr.iskanja_nejasna === 4 && new RegExp(rr.message_id).test(rr.zadnja_napaka) && klicov("SalesInvoiceCreate") === c0 && F.docs.length === d0,
        "4x iskanje brez izida: `napaka` + navodilo (referenca), NOBENE izdaje", [rr.stanje, rr.iskanja_nejasna, rr.zadnja_napaka]);
      // dve neuspesni iskanji med razmakom: ob razmaku, krajsem od ISKANJE_RAZMAK_MS, drugo iskanje se ne steje
      const R2 = await nov(1, 1310); const w2 = deloven({ RACUNI_ISKANJE_RAZMAK_MS: "3600000" }); const c1 = klicov("SalesInvoiceCreate");
      await pool.query("UPDATE racuni SET poslano_at = NOW() - INTERVAL '1 hour' WHERE id = $1", [R2.id]);
      await tek(w2, 3, 100, true);
      const r2 = await vrstica(R2.id);
      assert(r2.stanje === "caka" && r2.iskanja_ne === 1 && klicov("SalesInvoiceCreate") === c1, "drugo iskanje pred potekom razmaka se ne steje (1/2): izdaje ni", [r2.stanje, r2.iskanja_ne]);
      await pool.query("UPDATE racuni SET naslednji_poskus_at = NOW() + INTERVAL '1 day' WHERE id = $1", [R2.id]);
    }

    // ================================================================
    console.log("\n# 19. S2, S3, M1: stevilka dokumenta iz Get, cas izdaje samo ce ga vrne ponudnik, datum dobave = dan placila");
    {
      const w = deloven();
      // S2: Create vrne samo oznako dokumenta
      const A = await nov(1, 1400); const dA = F.docs.length;
      nastavi("brezStevilke", 1);
      await tek(w, 2);
      const ra = await vrstica(A.id);
      assert(ra.stanje === "potrjen" && ra.ponudnik_id === F.docs[dA].id && ra.ponudnik_stevilka === F.docs[dA].number, "S2: Create brez stevilke -> ponudnik_stevilka iz Get (sklic dobropisa bo pravilen)", [ra.ponudnik_id, ra.ponudnik_stevilka]);
      const dob = (await pool.query("INSERT INTO racuni (order_id, vrsta, ref_racun_id, vir, znesek_cents, vracilo_uspelo) VALUES ($1, 'dobropis', $2, 're_s2', -1400, TRUE) RETURNING id", [A.oid, A.id])).rows[0].id;
      const n0 = F.klici.length; await tek(w, 2);
      const cn = F.klici.slice(n0).find((x) => x.method === "CreditNoteCreate");
      assert(cn && cn.parameters.CreditNote.salesInvoiceRef === F.docs[dA].number && (await vrstica(dob)).stanje === "potrjen", "dobropis: salesInvoiceRef = STEVILKA dokumenta (ne documentID)", cn && cn.parameters.CreditNote.salesInvoiceRef);
      // S3: cas izdaje samo, ce ga ponudnik vrne
      F.casIzdaje = "2026-10-22T14:03:05+02:00";
      const B = await nov(1, 1410); await tek(w);
      F.casIzdaje = null;
      const rb = await vrstica(B.id);
      const v = racuni.vsebinaRacuna(rb, { ...rb, quantity: 1, unit_price_cents: 1410, title: "Outly Launch Party", start_at: "2026-12-24T19:00:00Z", public_ref: B.ref });
      assert(new Date(rb.izdan_at).toISOString() === "2026-10-22T12:03:05.000Z" && v && /^A001-1-\d+$/.test(v.stevilka), "S3: cas izdaje iz odgovora ponudnika se zapise; blok racuna je mogoc", rb.izdan_at);
      // M1: datum dobave = dan placila (ljubljanski cas), ne dan izdaje
      const C = await nov(1, 1420);
      await pool.query("UPDATE orders SET paid_at = NOW() - INTERVAL '3 days' WHERE id = $1", [C.oid]);
      const n1 = F.klici.length; await tek(w);
      const sc = F.klici.slice(n1).find((x) => x.method === "SalesInvoiceCreate").parameters.SalesInvoice;
      const pricakovan = new Intl.DateTimeFormat("en-CA", { timeZone: "Europe/Ljubljana", year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date(Date.now() - 3 * 86400000));
      assert(sc.dateOfSupplyFrom === pricakovan && sc.dateOfSupplyFrom !== dan(), "M1: dateOfSupplyFrom = dan placila (paid_at), ne danasnji dan", [sc.dateOfSupplyFrom, pricakovan]);
    }

    // ================================================================
    console.log("\n# 20. M2: eno zbirno opozorilo na tek (ne na vrstico)");
    {
      const w = deloven({ RACUNI_PREMOR_MS: "60000" });
      const ids = []; for (let i = 0; i < 6; i++) ids.push((await nov(1, 1500 + i)).id);
      const l0 = LOG.length;
      nastavi("503pred", 6);
      await tek(w);
      const vrstice = logOd(l0).filter((l) => /klic ponudniku eracuni ni uspel/.test(l));
      assert(vrstice.length === 1 && /6 racunov/.test(vrstice[0]) && /in se 3/.test(vrstice[0]), "6 neuspelih klicev -> ENA vrstica v dnevniku (3 primeri + »in se 3«)", logOd(l0));
      // konfiguracija: prav tako ena vrstica
      await pool.query("UPDATE racuni SET naslednji_poskus_at = NOW() WHERE id = ANY($1::bigint[])", [ids]);
      const l1 = LOG.length; F.poverilnice = false;
      await tek(w); F.poverilnice = true;
      const k = logOd(l1).filter((l) => /POZOR.*nastavitev pri ponudniku/.test(l));
      assert(k.length === 1 && /6 racunov/.test(k[0]), "napacna nastavitev pri 6 racunih -> ENA vrstica POZOR", logOd(l1));
      await pool.query("UPDATE racuni SET naslednji_poskus_at = NOW() + INTERVAL '1 day' WHERE id = ANY($1::bigint[])", [ids]);
    }


    // ================================================================
    console.log("\n# 21. Uspeh brez oznake dokumenta + prazen seznam: NIKOLI druga izdaja (pregled #318, 2. krog); seznam brez zivega preverjanja ne vodi v izdajo");
    {
      // brez znanih dokumentov v obdobju (prazen seznam je tedaj »veljaven«), kot v reprodukciji pregledovalca
      await pool.query("UPDATE racuni SET poslano_at = poslano_at - INTERVAL '10 days' WHERE poslano_at IS NOT NULL");
      const R = await nov(1, 2100); const w = deloven(); const c0 = klicov("SalesInvoiceCreate"), d0 = F.docs.length;
      nastavi("brezOznake", 50); F.listOblika = "prazenSeznam";
      await tek(w, 12, 40, true);
      nastavi(null); F.listOblika = "ok";
      const r = await vrstica(R.id);
      assert(klicov("SalesInvoiceCreate") === c0 + 1 && F.docs.length === d0 + 1, "natanko 1 Create (ne 6 davcnih racunov za eno prodajo)", [klicov("SalesInvoiceCreate") - c0, F.docs.length - d0]);
      assert(r.stanje === "napaka" && r.stevilka === null && /oznake dokumenta/.test(r.zadnja_napaka) && new RegExp(r.message_id).test(r.zadnja_napaka), "vrstica gre v `napaka` z navodilom (referenca), ne caka naprej", [r.stanje, r.zadnja_napaka]);
      // seznam ni zivo preverjen (ERACUNI_SEZNAM_PREVERJEN ni 1): veljavno prazno iskanje NE vodi v novo izdajo, ampak v `napaka`
      const R2 = await nov(1, 2110); const w2 = deloven({ ERACUNI_SEZNAM_PREVERJEN: "" }); const c1 = klicov("SalesInvoiceCreate");
      nastavi("503po", 1);
      await tek(w2);
      await pool.query("UPDATE racuni SET poslano_at = NOW() - INTERVAL '10 days' WHERE poslano_at IS NOT NULL AND id <> $1", [R2.id]);
      F.listOblika = "prazenSeznam";
      await tek(w2, 4, 40, true);
      F.listOblika = "ok";
      const r2 = await vrstica(R2.id);
      assert(klicov("SalesInvoiceCreate") === c1 + 1 && r2.stanje === "napaka" && /ni zivo preverjen|ERACUNI_SEZNAM_PREVERJEN/.test(r2.zadnja_napaka), "seznam ni zivo preverjen: iskanje brez najdbe -> `napaka` (rocno), nikoli nova izdaja", [r2.stanje, r2.zadnja_napaka, klicov("SalesInvoiceCreate") - c1]);
      // 503 PRED obdelavo (zahtevek ni dosegel ponudnika) pri nepreverjenem seznamu: tudi to gre v rocno obravnavo (izid se ne da ločiti od izgube odgovora)
      await pool.query("UPDATE racuni SET naslednji_poskus_at = NOW() + INTERVAL '1 day' WHERE id = ANY($1::bigint[])", [[R.id, R2.id]]);
    }

    // ================================================================
    console.log("\n# 22. Preizkus pred izdajo (pregled #318, 3. krog): napacen kljuc ob vklopu ne spravi zaostanka v `napaka`");
    {
      for (const [ime, okolje] of [["ERACUNI_SEZNAM_PREVERJEN=1", {}], ["zastavica izklopljena (privzeto)", { ERACUNI_SEZNAM_PREVERJEN: "" }]]) {
        const rs = []; for (let i = 0; i < 4; i++) rs.push(await nov(1, 1500 + i));
        const ids = rs.map((x) => x.id); const w = deloven(okolje);
        const c0 = klicov("SalesInvoiceCreate"), l0 = klicov("SalesInvoiceList"), p0 = F.preizkusi.length, d0 = F.docs.length;
        F.poverilnice = false;
        await tek(w, 3, 450, true);
        const v = (await pool.query("SELECT stanje, poslano_at, poskusi FROM racuni WHERE id = ANY($1::bigint[])", [ids])).rows;
        assert(klicov("SalesInvoiceCreate") === c0 && v.every((x) => x.stanje === "caka" && x.poslano_at === null), `[${ime}] zaostanek 4 racunov, napacen kljuc, 3 teki: NOBEN Create, vse caka, poslano_at prazen`, [klicov("SalesInvoiceCreate") - c0, v.map((x) => x.stanje)]);
        assert(F.preizkusi.length - p0 === 3 && klicov("SalesInvoiceList") === l0, `[${ime}] en bralni preizkus na tek (ne na vrstico): ${F.preizkusi.length - p0} preizkusov v 3 tekih`);
        F.poverilnice = true;
        await tek(w, 6, 130, true);
        const v2 = (await pool.query("SELECT stanje, stevilka FROM racuni WHERE id = ANY($1::bigint[])", [ids])).rows;
        assert(v2.every((x) => x.stanje === "potrjen" && x.stevilka !== null) && klicov("SalesInvoiceCreate") === c0 + 4 && F.docs.length === d0 + 4, `[${ime}] po popravku kljuca se vseh 4 izda, vsak natanko enkrat`, [v2.map((x) => x.stanje), klicov("SalesInvoiceCreate") - c0]);
      }
      // »Access denied« na sam Create po uspelem preizkusu (kljuc preklican med tekom): ostalim vrsticam v istem teku Create ne gre; poslano_at ostane le pri tisti, ki je bila poslana
      // (ne moremo dokazati, da e-racuni ob zavrnjeni avtentikaciji dokumenta ne ustvari -> iskanje po referenci pred vsako novo izdajo)
      const rs = []; for (let i = 0; i < 3; i++) rs.push(await nov(1, 1700 + i));
      const ids = rs.map((x) => x.id); const w = deloven();
      const c1 = klicov("SalesInvoiceCreate"), d1 = F.docs.length;
      nastavi("konfig", 1);
      await tek(w);
      nastavi(null);
      const v = (await pool.query("SELECT stanje, poslano_at FROM racuni WHERE id = ANY($1::bigint[])", [ids])).rows;
      assert(klicov("SalesInvoiceCreate") === c1 + 1 && F.docs.length === d1, "Access denied na Create: ostali dve vrstici v istem teku ne dobita Create (en poskus, ne trije)", [klicov("SalesInvoiceCreate") - c1]);
      assert(v.every((x) => x.stanje === "caka") && v.filter((x) => x.poslano_at !== null).length === 1, "poslano_at ostane samo pri poslani vrstici; vse `caka`, ne `napaka`", v);
      await tek(w, 6, 130, true);
      const v2 = (await pool.query("SELECT stanje FROM racuni WHERE id = ANY($1::bigint[])", [ids])).rows;
      assert(v2.every((x) => x.stanje === "potrjen") && F.docs.length === d1 + 3, "po koncu izpada se vse tri izdajo (poslana vrstica prek iskanja po referenci, nato izdaja)", [v2.map((x) => x.stanje), F.docs.length - d1]);
    }

    // ================================================================
    console.log("\n# 23. Rocni postopek za vrstico v `napaka` (STATE): isti SQL kot v dokumentaciji (migracija, ki spreminja produkcijske podatke = Martinov DA)");
    {
      const w = deloven();
      // A: Create je uspel, odgovor brez oznake -> `napaka`; dokument pri ponudniku obstaja -> POVEZAVA
      const RA = await nov(1, 1810); const d0 = F.docs.length;
      nastavi("brezOznake", 1); F.listOblika = "prazenSeznam";
      await tek(w, 3, 40, true);
      nastavi(null); F.listOblika = "ok";
      const a1 = await vrstica(RA.id); const dok = F.docs[F.docs.length - 1];
      assert(a1.stanje === "napaka" && F.docs.length === d0 + 1, "A: izhodisce: `napaka`, dokument pri ponudniku obstaja (1)", [a1.stanje, F.docs.length - d0]);
      const povezi = `UPDATE racuni SET ponudnik = 'eracuni', ponudnik_stevilka = $2, stanje = 'caka', naslednji_poskus_at = NOW()
                       WHERE id = $1 AND stanje = 'napaka' AND stevilka IS NULL AND ponudnik_id IS NULL AND ponudnik_stevilka IS NULL`;
      assert((await pool.query(povezi, [RA.id, dok.number])).rowCount === 1, "A: SQL za povezavo (po STATE) se izvede na eni vrstici");
      await tek(w, 3, 40, true);
      const a2 = await vrstica(RA.id);
      assert(a2.stanje === "potrjen" && Number(a2.stevilka) === dok.fiscalNumber && a2.ponudnik_stevilka === dok.number && F.docs.length === d0 + 1, "A: po povezavi potrjen s stevilko obstojecega dokumenta, NOVEGA dokumenta ni", [a2.stanje, a2.stevilka, F.docs.length - d0]);
      // B: izdaja zavrnjena (dokumenta ni) -> PONOVITEV
      const RB = await nov(1, 1820); const d1 = F.docs.length;
      nastavi("napaka", 1);
      await tek(w);
      const b1 = await vrstica(RB.id);
      assert(b1.stanje === "napaka" && b1.poslano_at !== null && F.docs.length === d1, "B: izhodisce: `napaka`, poslano_at zapisan, dokumenta ni", [b1.stanje, F.docs.length - d1]);
      const ponovi = `UPDATE racuni SET stanje = 'caka', poslano_at = NULL, naslednji_poskus_at = NOW()
                       WHERE id = $1 AND stanje = 'napaka' AND stevilka IS NULL AND ponudnik_id IS NULL AND ponudnik_stevilka IS NULL`;
      assert((await pool.query(ponovi, [RB.id])).rowCount === 1, "B: SQL za ponovitev (po STATE) se izvede na eni vrstici");
      const c1 = klicov("SalesInvoiceList");
      await pocakaj(450);   // zavrnjen Create (B) ustavi Create v procesu za RACUNI_KONFIG_PREMOR_MS (400 ms)
      await tek(w, 3, 40, true);
      const b2 = await vrstica(RB.id);
      assert(b2.stanje === "potrjen" && F.docs.length === d1 + 1 && klicov("SalesInvoiceList") === c1, "B: po ponovitvi izda natanko en dokument, brez iskanja (poslano_at je bil prazen)", [b2.stanje, F.docs.length - d1]);
    }

    // ================================================================
    console.log("\n# 24. Zastavica »ustvarjeno pri ponudniku«: ob uspehu Create brez oznake je vrstica zaklenjena ze MED iskanjem (restart v tem oknu ne vodi v novo izdajo)");
    {
      const R = await nov(1, 1830); const w = deloven(); const w2 = deloven(); const c0 = klicov("SalesInvoiceCreate"), d0 = F.docs.length;
      nastavi("brezOznake", 1); F.listZamik = 400;
      const tek1 = w.tek();
      let videl = null;
      assert(await dokler(async () => { const r = await vrstica(R.id); if (r.stanje === "napaka" && /poteka iskanje/.test(r.zadnja_napaka || "")) { videl = r; return true; } return false; }, 6000), "med iskanjem po referenci je vrstica ze `napaka` (ni vec `caka`, ki bi jo po restartu znova izdali)", videl);
      await w2.tek();   // drug primerek (npr. po deployu): vrstice ne prevzame, Create ne gre
      assert(klicov("SalesInvoiceCreate") === c0 + 1 && F.docs.length === d0 + 1, "drug primerek med iskanjem ne izda nic", [klicov("SalesInvoiceCreate") - c0]);
      await tek1; F.listZamik = 0; nastavi(null);
      const r = await vrstica(R.id);
      assert(r.stanje === "potrjen" && r.ponudnik_stevilka && F.docs.length === d0 + 1 && r.zadnja_napaka === null, "iskanje najde dokument: vrstica nazaj v obdelavo, potrjen, ena izdaja, brez ostanka sporocila", [r.stanje, r.zadnja_napaka]);
    }

    // ================================================================
    console.log("\n# 25. Fail-closed (pregled #321): KATERAKOLI napaka bralnega preizkusa ustavi Create; po zavrnjenem Create se Create ustavi za CEL proces");
    {
      const besedila = ["Authorization failed for user", "Unknown user", "Napacno uporabnisko ime ali geslo", "Something unexpected happened (code 77)"];
      for (const besedilo of besedila) {
        const R = await nov(1, 1900); const w = deloven(); const c0 = klicov("SalesInvoiceCreate"), l0 = LOG.length;
        F.poverilnice = false; F.opisAvt = besedilo;
        await tek(w, 2, 60, true);
        const r = await vrstica(R.id);
        assert(klicov("SalesInvoiceCreate") === c0 && r.stanje === "caka" && r.poslano_at === null, `neprepoznano besedilo napake preizkusa (»${besedilo}«): 0 Create, caka, poslano_at prazen`, [klicov("SalesInvoiceCreate") - c0, r.stanje]);
        assert(logOd(l0).some((l) => /POZOR/.test(l) && l.includes(besedilo)) && !logOd(l0).some((l) => [TAJNO.user, TAJNO.key, TAJNO.token].some((t) => l.includes(t))), "POZOR z besedilom napake, brez poverilnic");
        F.poverilnice = true; F.opisAvt = "Access denied. Invalid credentials";
        await pocakaj(450); await tek(w, 3, 60, true);
        assert((await vrstica(R.id)).stanje === "potrjen", "po popravku kljuca se izda");
      }
      // »List dela, Create nima pravic«: po prvem zavrnjenem Create nobenih novih Create za RACUNI_KONFIG_PREMOR_MS (400 ms), tudi ce so vrstice »takoj na vrsti«
      for (const [ime, vedenje] of [["konfiguracija (Access denied)", "konfig"], ["trajna zavrnitev", "napaka"]]) {
        const rs = []; for (let i = 0; i < 4; i++) rs.push(await nov(1, 1910 + i));
        const ids = rs.map((x) => x.id); const w = deloven(); const c0 = klicov("SalesInvoiceCreate"), d0 = F.docs.length;
        nastavi(vedenje, 50);
        await tek(w, 1, 0, true); await tek(w, 1, 0, true); await tek(w, 1, 0, true);
        assert(klicov("SalesInvoiceCreate") === c0 + 1, `[${ime}] po prvem zavrnjenem Create ostale vrstice v tem procesu ne gredo (3 teki, takoj na vrsti): ${klicov("SalesInvoiceCreate") - c0} Create`, klicov("SalesInvoiceCreate") - c0);
        nastavi(null);
        await pocakaj(450);
        await tek(w, 1, 0, true);
        assert(klicov("SalesInvoiceCreate") > c0 + 1, `[${ime}] po poteku RACUNI_KONFIG_PREMOR_MS Create spet gre`, klicov("SalesInvoiceCreate") - c0);
        // pospravi: vse naj bo potrjeno ali odlozeno
        await pool.query("UPDATE racuni SET stanje = 'caka', poslano_at = NULL, naslednji_poskus_at = NOW() WHERE id = ANY($1::bigint[]) AND stanje = 'napaka' AND stevilka IS NULL AND ponudnik_id IS NULL AND ponudnik_stevilka IS NULL", [ids]);
        await pocakaj(450); await tek(w, 8, 60, true);
        const st = (await pool.query("SELECT stanje FROM racuni WHERE id = ANY($1::bigint[])", [ids])).rows.map((x) => x.stanje);
        assert(st.every((x) => x === "potrjen") && F.docs.length === d0 + 4, `[${ime}] po koncu izpada se vseh 4 izda enkrat`, [st, F.docs.length - d0]);
      }
    }

    // ================================================================
    console.log("\n# 26. Preizkus pred izdajo, ki pade z 5xx/timeoutom, javi POZOR (3x zapored ALI dlje kot cas), najvec enkrat na casovno okno (pregled #321)");
    {
      const imaPozor = (l0) => logOd(l0).filter((l) => /POZOR.*bralni preizkus pred izdajo/.test(l) && /zapored|ze \d/.test(l));
      // (a) 3x zapored
      const R = await nov(1, 1930); const w = deloven({ RACUNI_PREIZKUS_POZOR_RAZMAK_MS: "700", RACUNI_PREIZKUS_PO_MS: "3600000" }); const l0 = LOG.length, c0 = klicov("SalesInvoiceCreate");
      F.listStatus = 503;
      await tek(w, 2, 20, true);
      assert(imaPozor(l0).length === 0 && klicov("SalesInvoiceCreate") === c0, "preizkus 503: po 2 tekih se brez POZOR (samo »ponovim«), 0 izdaj", [imaPozor(l0).length]);
      await tek(w, 1, 20, true);
      assert(imaPozor(l0).length === 1 && /3x zapored/.test(imaPozor(l0)[0]) && klicov("SalesInvoiceCreate") === c0, "3. zaporedni neuspeh: POZOR (enkrat), 0 izdaj", imaPozor(l0));
      assert(![TAJNO.user, TAJNO.key, TAJNO.token].some((t) => imaPozor(l0).join().includes(t)), "POZOR brez poverilnic");
      await tek(w, 3, 20, true);
      assert(imaPozor(l0).length === 1, "omejitev ponavljanja: v oknu (700 ms) ni drugega POZOR", imaPozor(l0).length);
      await pocakaj(750);
      await tek(w, 1, 20, true);
      assert(imaPozor(l0).length === 2, "po izteku okna POZOR spet", imaPozor(l0).length);
      // uspeh pobrise zaporedje
      F.listStatus = null;
      await tek(w, 4, 60, true);
      assert((await vrstica(R.id)).stanje === "potrjen", "ko seznam spet dela, se racun izda");
      // (b) dlje kot cas, ceprav manj kot 3 zapored
      const R2 = await nov(1, 1940); const w2 = deloven({ RACUNI_PREIZKUS_PO_MS: "300", RACUNI_PREIZKUS_POZOR_RAZMAK_MS: "3600000" }); const l1 = LOG.length;
      F.listStatus = 503;
      await tek(w2, 1, 20, true);
      assert(imaPozor(l1).length === 0, "1. neuspeh: se brez POZOR");
      await pocakaj(350);
      await tek(w2, 1, 20, true);
      assert(imaPozor(l1).length === 1 && /ze \d/.test(imaPozor(l1)[0]), "2. neuspeh po izteku casa (RACUNI_PREIZKUS_PO_MS): POZOR", imaPozor(l1));
      F.listStatus = null;
      await tek(w2, 4, 60, true);
      assert((await vrstica(R2.id)).stanje === "potrjen", "po popravku se izda");
    }

    // ================================================================
    console.log("\n# 27. PDF racuna (Issue #319): delavec ga dobi od ponudnika po `potrjen`, strogo preveri in shrani v racuni_pdf; napaka = ponovitev + POZOR, brez PDF mail ne gre");
    {
      const w = deloven({ RACUNI_PDF_POZOR_PO: "3" });
      const R = await nov(1, 2200); const l0 = LOG.length;
      await tek(w, 3, 40, true);
      const r = await vrstica(R.id);
      assert(r.stanje === "potrjen" && r.pdf_prejet === true && r.pdf_poskusi === 0 && r.pdf_napaka === null, "potrjen racun: PDF prejet", [r.stanje, r.pdf_prejet]);
      const pdf = (await pool.query("SELECT pdf, sha256, octet_length(pdf) AS n FROM racuni_pdf WHERE racun_id = $1", [R.id])).rows[0];
      assert(pdf && pdf.pdf.subarray(0, 5).toString() === "%PDF-" && pdf.sha256 === crypto.createHash("sha256").update(pdf.pdf).digest("hex"), "PDF v bazi, sha256 ustreza vsebini", pdf && pdf.n);
      const k = F.pdfKlici.filter((x) => x.parameters.documentID === r.ponudnik_id);
      assert(k.length === 1 && k[0].method === "SalesInvoiceGetPDF" && k[0].parameters.markDocumentAsSent === undefined && k[0].parameters.documentID === r.ponudnik_id, "SalesInvoiceGetPDF po documentID, brez markDocumentAsSent; natanko en klic", F.pdfKlici.length);
      await tek(w, 2, 40, true);
      assert(F.pdfKlici.filter((x) => x.parameters.documentID === r.ponudnik_id).length === 1, "PDF se ne pridobiva znova");
      assert((await pool.query("SELECT COUNT(*)::int AS n FROM racuni_pdf WHERE racun_id = $1", [R.id])).rows[0].n === 1, "natanko ena vrstica racuni_pdf");
      let nedovoljeno = null; try { await pool.query("UPDATE racuni_pdf SET sha256 = repeat('0', 64) WHERE racun_id = $1", [R.id]); } catch (e) { nedovoljeno = e; }
      let nedovoljeno2 = null; try { await pool.query("DELETE FROM racuni_pdf WHERE racun_id = $1", [R.id]); } catch (e) { nedovoljeno2 = e; }
      assert(nedovoljeno && nedovoljeno2 && nedovoljeno.code === "23001" && nedovoljeno2.code === "23001", "racuni_pdf: UPDATE in DELETE zavrne sprozilec (hramba 10 let)", [nedovoljeno && nedovoljeno.code]);
      // dobropis: CreditNoteGetPDF po stevilki dokumenta
      const dop = await pool.query(`INSERT INTO racuni (order_id, vrsta, ref_racun_id, vir, znesek_cents, valuta) VALUES ($1, 'dobropis', $2, 'test-pdf-1', -500, 'EUR') RETURNING id`, [R.oid, R.id]);
      await pool.query("UPDATE racuni SET vracilo_uspelo = TRUE WHERE id = $1", [dop.rows[0].id]);
      await tek(w, 6, 40, true);
      const d = await vrstica(dop.rows[0].id);
      const kd = F.pdfKlici.filter((x) => x.method === "CreditNoteGetPDF" && x.parameters.number === d.ponudnik_stevilka);
      assert(d.stanje === "potrjen" && d.pdf_prejet === true && kd.length === 1 && kd[0].parameters.number === d.ponudnik_stevilka && kd[0].parameters.documentID === undefined, "dobropis: PDF prek CreditNoteGetPDF po stevilki dokumenta", [d.stanje, d.pdf_prejet, kd.map((x) => x.parameters)]);
      // neveljavni odgovori: PDF se NE shrani, vrstica ostane brez PDF, POZOR po N neuspehih
      for (const oblika of ["brezPdf", "prazno", "dva", "okrnjen", "503", "prevelik"]) {
        const Rn = await nov(1, 2210); const wn = deloven({ RACUNI_PDF_POZOR_PO: "3" }); const ln = LOG.length;
        F.pdfOblika = oblika;
        for (let i = 0; i < 5; i++) { await pool.query("UPDATE racuni SET pdf_naslednji_at = NULL WHERE id = $1", [Rn.id]); await tek(wn, 1, 0, true); }
        const rn = await vrstica(Rn.id);
        const nasel = (await pool.query("SELECT COUNT(*)::int AS n FROM racuni_pdf WHERE racun_id = $1", [Rn.id])).rows[0].n;
        assert(rn.stanje === "potrjen" && !rn.pdf_prejet && nasel === 0 && rn.pdf_poskusi >= 3 && rn.pdf_napaka, `[${oblika}] odgovor ni prepoznan PDF: ni shranjen, poskusi se stejejo, napaka zapisana`, [rn.pdf_prejet, rn.pdf_poskusi, rn.pdf_napaka]);
        assert(logOd(ln).some((l) => /POZOR.*PDF/.test(l)) && !logOd(ln).some((l) => [TAJNO.user, TAJNO.key, TAJNO.token].some((t) => l.includes(t))), `[${oblika}] po 3 neuspehih POZOR (brez poverilnic)`);
        F.pdfOblika = "ok";
        await pool.query("UPDATE racuni SET pdf_naslednji_at = NULL WHERE id = $1", [Rn.id]);
        await tek(wn, 3, 30, true);
        assert((await vrstica(Rn.id)).pdf_prejet === true, `[${oblika}] ko ponudnik spet vrne PDF, se shrani`);
      }
      // meja velikosti 2 MB (izvoz baze in pomnilnik procesa s skenom, I16): tik pod mejo se shrani, nad mejo napaka z jasnim sporocilom
      {
        const Rv = await nov(1, 2225); const wv = deloven(); F.pdfOblika = "velik";
        await tek(wv, 4, 30, true);
        assert((await vrstica(Rv.id)).pdf_prejet === true, "PDF tik pod mejo 2 MB se shrani");
        const Rb = await nov(1, 2226); const wb = deloven(); F.pdfOblika = "prevelik";
        await tek(wb, 2, 0, true);
        const rb = await vrstica(Rb.id);
        assert(!rb.pdf_prejet && rb.pdf_poskusi >= 1 && /presega|meja|2 MB/i.test(rb.pdf_napaka || ""), "PDF nad mejo 2 MB: ni shranjen, napaka pove, da presega mejo", [rb.pdf_prejet, rb.pdf_napaka]);
        F.pdfOblika = "ok";
      }
      // PDF v gnezdenem odgovoru (ime polja ni znano): strogo po vsebini
      const Rg = await nov(1, 2220); const wg = deloven();
      F.pdfOblika = "gnezdeno";
      await tek(wg, 4, 30, true);
      F.pdfOblika = "ok";
      assert((await vrstica(Rg.id)).pdf_prejet === true, "ime polja s PDF ni pomembno: prepoznan base64 PDF (%PDF- ... %%EOF) kjerkoli v odgovoru");
      // meja poskusov: vrstica po izcrpanju NE obvisi v zanki (pdf_poskusi bi sicer prebil CHECK 10000 in vsak tek bi padel); izcrpano = POZOR, ponovitev samo rocno
      {
        const Rm = await nov(1, 2230); const wm = deloven({ RACUNI_PDF_POZOR_PO: "2", RACUNI_PDF_NAJVEC_POSKUSOV: "4" }); const lm = LOG.length;
        F.pdfOblika = "brezPdf";
        for (let i = 0; i < 9; i++) { await pool.query("UPDATE racuni SET pdf_naslednji_at = NULL WHERE id = $1", [Rm.id]); await tek(wm, 1, 0, true); }
        const rm = await vrstica(Rm.id);
        const klicov = F.pdfKlici.filter((x) => x.parameters.documentID === rm.ponudnik_id).length;
        assert(rm.stanje === "potrjen" && !rm.pdf_prejet && rm.pdf_poskusi === 4 && klicov === 4, "meja poskusov (4): po izcrpanju ni vec klicev ponudniku, stevec se ne povecuje", [rm.pdf_poskusi, klicov]);
        assert(/izcrpan/i.test(rm.pdf_napaka || ""), "pdf_napaka pove, da so poskusi izcrpani", rm.pdf_napaka);
        assert(logOd(lm).some((l) => /POZOR.*PDF.*izcrpan/i.test(l)), "POZOR: poskusi pridobitve PDF izcrpani (kupec racuna ne dobi)");
        await pool.query("UPDATE racuni SET pdf_poskusi = 0, pdf_napaka = NULL, pdf_naslednji_at = NULL WHERE id = $1", [Rm.id]);   // rocna ponovitev (STATE)
        F.pdfOblika = "ok";
        await tek(wm, 3, 30, true);
        assert((await vrstica(Rm.id)).pdf_prejet === true, "po rocni ponastavitvi stevca se PDF pridobi");
        // pospravljalec javi izcrpano vrstico tudi, ko jo tek ne obdeluje vec
        F.pdfOblika = "brezPdf";
        const Rp = await nov(1, 2231); const wp = deloven({ RACUNI_PDF_NAJVEC_POSKUSOV: "4" }); await tek(wp, 3, 30, true); const lp = LOG.length;
        F.pdfOblika = "ok";
        await pool.query("UPDATE racuni SET pdf_poskusi = 4, pdf_napaka = 'IZCRPANO: test' WHERE id = $1 AND NOT pdf_prejet", [Rp.id]);
        await wp.pospravi();
        assert(logOd(lp).some((l) => /POZOR.*PDF.*izcrpan/i.test(l)), "pospravljalec: POZOR za potrjen racun, ki mu PDF ni mogoce pridobiti (izcrpani poskusi)");
      }
      // ponudnik brez PDF (lazni): nobenega klica, racun ostane brez PDF
    }

    // ================================================================
    console.log("\n# 15. Poverilnice nikoli v dnevniku ali zadnja_napaka");
    {
      const vse = LOG.join("\n");
      const napake = (await pool.query("SELECT string_agg(COALESCE(zadnja_napaka, ''), ' ') AS t FROM racuni")).rows[0].t || "";
      assert(![TAJNO.user, TAJNO.key, TAJNO.token].some((t) => vse.includes(t) || napake.includes(t)), "uporabnik, skrivni kljuc in zeton niso v dnevniku racunov ne v zadnja_napaka");
      // ponudnik, ki v sporocilu napake vrne poverilnice nazaj (odmev), jih skrije
      const p = racuni.eracuniPonudnik({ ...ENV, ERACUNI_URL: `http://127.0.0.1:${PORT}/WebServicesSI/API` });
      F.poverilnice = false;
      let sporocilo = ""; try { await p.preberi({ vrsta: "racun", ponudnik_id: "60:1" }); } catch (e) { sporocilo = e.message; }
      F.poverilnice = true;
      assert(sporocilo && ![TAJNO.user, TAJNO.key, TAJNO.token].some((t) => sporocilo.includes(t)), "sporocilo napake ponudnika ne vsebuje poverilnic", sporocilo);
    }
    // ================================================================
    console.log("\n# 28. Seznam brez dokumentov (e-racuni: HTTP 500 + #noDocumentsFound) je PRAZEN SEZNAM, ne napaka (produkcija 23. 10. 2026: kokos-jajce, noben racun se ni izdal)");
    {
      await pool.query("TRUNCATE racuni CASCADE");   // brez znanih dokumentov (dokaz popolnosti seznama): kot na dan prvega racuna
      F.docs.length = 0; F.pdfKlici.length = 0;
      // (a) bralni preizkus pred izdajo: vrstica v `caka` brez poslano_at dobi natanko 1 Create
      F.listOblika = "ni_dokumentov";
      const Ra = await nov(1, 2400); const wa = deloven(); const la = LOG.length, ca = klicov("SalesInvoiceCreate"), pa = F.preizkusi.length;
      await tek(wa, 4, 40, true);
      const ra = await vrstica(Ra.id);
      assert(F.preizkusi.length > pa && klicov("SalesInvoiceCreate") - ca === 1 && ra.stanje === "potrjen" && ra.poskusi === 0, "preizkus dobi 500 #noDocumentsFound: preizkus uspe, natanko 1 Create, racun potrjen", [F.preizkusi.length - pa, klicov("SalesInvoiceCreate") - ca, ra.stanje]);
      assert(!logOd(la).some((l) => /bralni preizkus pred izdajo ni uspel/.test(l)), "v dnevniku ni »bralni preizkus ni uspel«");
      // (b) vsaka druga napaka 500 ostane napaka (preizkus fail-closed): 0 Create
      for (const oblika of ["napaka500", "ni_dokumentov_brez_kode"]) {
        F.listOblika = oblika;
        const Rb = await nov(1, 2410); const wb = deloven(); const cb = klicov("SalesInvoiceCreate");
        await tek(wb, 3, 40, true);
        const rb = await vrstica(Rb.id);
        assert(klicov("SalesInvoiceCreate") === cb && rb.stanje === "caka" && rb.poslano_at === null, `[${oblika}] 500 brez kode #noDocumentsFound ostane napaka: 0 Create, vrstica caka`, [klicov("SalesInvoiceCreate") - cb, rb.stanje]);
      }
      // (c) gnezden description (error.description) je prav tako prepoznan
      F.listOblika = "ni_dokumentov_gnezdeno"; F.docs.length = 0;
      await pool.query("TRUNCATE racuni CASCADE");
      const Rc = await nov(1, 2420); const wc = deloven(); const cc = klicov("SalesInvoiceCreate");
      await tek(wc, 4, 40, true);
      assert(klicov("SalesInvoiceCreate") - cc === 1 && (await vrstica(Rc.id)).stanje === "potrjen", "error.description z #noDocumentsFound: natanko 1 Create");
      // (d) iskanje po referenci: prazen seznam je veljaven negativen izid po obstojecih pravilih (dve iskanji, ni znanih dokumentov) -> ponovna izdaja
      F.listOblika = "ni_dokumentov"; F.docs.length = 0;
      await pool.query("TRUNCATE racuni CASCADE");
      const Rd = await nov(1, 2430); const wd = deloven(); const cd = klicov("SalesInvoiceCreate"), ld = klicov("SalesInvoiceList");
      nastavi("503pred", 1);
      await tek(wd, 6, 130, true);
      const rd = await vrstica(Rd.id);
      assert(rd.stanje === "potrjen" && klicov("SalesInvoiceCreate") - cd === 2 && F.docs.length === 1 && klicov("SalesInvoiceList") - ld === 2, "iskanje po 503 pred obdelavo: #noDocumentsFound = prazen seznam, po dveh iskanjih ena ponovna izdaja, en dokument", [rd.stanje, klicov("SalesInvoiceCreate") - cd, F.docs.length]);
      // (e) #noDocumentsFound, ceprav vemo, da dokument obstaja (znan dokument iz (d)): seznam ni popoln -> NIKOLI nova izdaja
      F.listOblika = "ni_dokumentov_vedno";
      const Re = await nov(1, 2440); const we = deloven(); const ce = klicov("SalesInvoiceCreate"), de = F.docs.length;
      nastavi("503pred", 1);
      await tek(we, 6, 130, true);
      const re = await vrstica(Re.id);
      assert(klicov("SalesInvoiceCreate") - ce === 1 && F.docs.length === de && re.stanje !== "potrjen", "500 #noDocumentsFound ob znanem dokumentu: seznam ni popoln, brez druge izdaje", [klicov("SalesInvoiceCreate") - ce, F.docs.length - de, re.stanje]);
      F.listOblika = "ok";
    }
    // ================================================================
    console.log("\n# 29. Dnevnik napak e-racuni: apiMethod + description iz telesa ob vsakem ne-2xx; struktura prvega zahtevka Create (brez poverilnic); vedenje nespremenjeno");
    {
      F.listOblika = "ok";
      const R1 = await nov(1, 2500), R2 = await nov(1, 2510); const w = deloven(); const l0 = LOG.length;
      nastavi("500opis", 1); F.vedenje.besedilo = `Error nr: 12 #invalidPaymentMethod - Payment method Stripe is not supported (token ${TAJNO.token})`;
      await tek(w, 1, 40, true);
      const r1 = await vrstica(R1.id);
      const dn = logOd(l0).join("\n");
      assert(/apiMethod=SalesInvoiceCreate/.test(dn) && /#invalidPaymentMethod/.test(dn) && /Payment method Stripe is not supported/.test(dn), "dnevnik vsebuje apiMethod in description iz telesa 500", dn.slice(0, 400));
      assert(![TAJNO.user, TAJNO.key, TAJNO.token].some((t) => dn.includes(t) || (r1.zadnja_napaka || "").includes(t)), "poverilnice (tudi ce jih ponudnik odmeva v description) niso v dnevniku ne v zadnja_napaka");
      assert(/#invalidPaymentMethod/.test(r1.zadnja_napaka || "") && (r1.zadnja_napaka || "").length <= 400, "zadnja_napaka vsebuje description (skrajsan)", r1.zadnja_napaka);
      // vedenje NESPREMENJENO: 500 na Create = izid neznan (zahtevek poslan), vrstica ostane v postopku, naprej samo prek iskanja po referenci
      assert(r1.poslano_at !== null && r1.stanje === "caka" && r1.poskusi === 1 && r1.naknadno === true && /izid neznan/.test(dn), "vedenje nespremenjeno: 500 = izid neznan, poslano_at ostane, ponovitev prek iskanja", [r1.stanje, r1.poskusi, r1.poslano_at]);
      // struktura prvega zahtevka Create: ENKRAT na zagon (ne na vrstico), brez poverilnic
      const struktura = logOd(l0).filter((l) => /struktura zahtevka SalesInvoiceCreate/.test(l));
      assert(struktura.length === 1, "struktura zahtevka Create izpisana natanko enkrat (dva racuna, en zagon)", struktura.length);
      const st = struktura[0] || "";
      assert(/"methodOfPayment":"Stripe"/.test(st) && /"cashRegisterCode":"1"/.test(st) && /"businessUnit":"A001"/.test(st) && /"type":"Retail"/.test(st) && /"vatTransactionType":7/.test(st) && /"Items"/.test(st), "struktura vsebuje polja (nacin placila, blagajna, enota, vrsta, vatTransactionType, postavke)", st.slice(0, 400));
      assert(![TAJNO.user, TAJNO.key, TAJNO.token].some((t) => st.includes(t)) && !/secretKey|username|"token"/.test(st) && !/buyer/i.test(st), "struktura brez poverilnic in brez podatkov kupca", st.slice(0, 200));
      // 500 z drugo kodo na Get/List (ne-2xx nasploh): tudi tam opis
      const l1 = LOG.length;
      F.listOblika = "napaka500";
      await pool.query("UPDATE racuni SET naslednji_poskus_at = NOW() WHERE id = $1", [R1.id]);
      await tek(w, 2, 40, true);
      assert(logOd(l1).some((l) => /SalesInvoiceList: HTTP 500 \(.*#internalError/.test(l)), "tudi bralni preizkus/List ob 500 izpise description (#internalError)", logOd(l1).slice(0, 3));
      F.listOblika = "ok";
    }

    // ================================================================
    console.log("\n# 30. Migracija 061: racun za OUT-TTWH2V4Q (Create je dal 500, ker nacin placila Stripe ni bil vklopljen) nazaj v izdajo; varno za caka (izid neznan) IN napaka; natanko 1 Create");
    {
      const fs = require("fs"), path = require("path");
      const sql = fs.readFileSync(path.join(__dirname, "..", "db", "migracije", "061_racun_ttwh2v4q_ponovitev.sql"), "utf8");
      const zaganjaj = async () => { const c = await pool.connect(); const note = []; c.on("notice", (n) => note.push(n.message)); try { await c.query(sql); } finally { c.release(); } return note; };
      const REF = "OUT-TTWH2V4Q";
      const priprava = async (stanje, { poslanoPrej = "3 hours", napaka = "SalesInvoiceCreate: HTTP 500" } = {}) => {
        await pool.query("TRUNCATE racuni CASCADE"); await pool.query("UPDATE orders SET public_ref = 'OUT-STARO-' || id WHERE public_ref = $1", [REF]);
        F.docs.length = 0; F.listOblika = "ok";
        const R = await nov(1, 2600);
        await pool.query("UPDATE orders SET public_ref = $2 WHERE id = $1", [R.oid, REF]);
        // kot v produkciji: Create je padel (500), poslano_at je star, iskanje je padlo zaradi izpada, vrstica caka z napako ali je ze `napaka`
        await pool.query(`UPDATE racuni SET poslano_at = NOW() - $2::interval, poskusi = 3, naknadno = TRUE, iskanja_ne = 1, iskanje_ne_at = NOW() - INTERVAL '2 hours', iskanja_nejasna = 2, zadnja_napaka = $3,
                            naslednji_poskus_at = NOW() + INTERVAL '30 minutes' WHERE id = $1`, [R.id, poslanoPrej, napaka]);
        if (stanje === "napaka") await pool.query("UPDATE racuni SET stanje = 'napaka' WHERE id = $1", [R.id]);
        return R;
      };
      for (const stanje of ["caka", "napaka"]) {
        const R = await priprava(stanje);
        // tujo vrstico (drugo narocilo) migracija ne sme spremeniti
        const T = await nov(1, 2610); await pool.query("UPDATE racuni SET poslano_at = NOW() - INTERVAL '5 hours', poskusi = 2, zadnja_napaka = 'tuja' WHERE id = $1", [T.id]);
        const note = await zaganjaj();
        const r = await vrstica(R.id), t = await vrstica(T.id);
        assert(r.stanje === "caka" && r.poslano_at === null && r.poskusi === 0 && r.iskanja_ne === 0 && r.iskanje_ne_at === null && r.iskanja_nejasna === 0 && r.zadnja_napaka === null && r.prevzeto_at === null && r.prevzem_zeton === null
          && new Date(r.naslednji_poskus_at).getTime() <= Date.now() + 1000, `[${stanje}] vrstica je po migraciji v izdaji (caka, poslano_at/stevci/napaka pocisceni, takoj na vrsti)`, r);
        assert(t.poskusi === 2 && t.zadnja_napaka === "tuja" && t.poslano_at !== null, `[${stanje}] tuja vrstica nespremenjena`);
        assert(note.some((x) => /061/.test(x)), `[${stanje}] migracija izpise obvestilo`, note);
        const w = deloven(); const c0 = klicov("SalesInvoiceCreate"), l0 = klicov("SalesInvoiceList");
        await pool.query("UPDATE racuni SET poslano_at = poslano_at WHERE id = $1", [T.id]);
        await pool.query("UPDATE racuni SET naslednji_poskus_at = NOW() + INTERVAL '3 hours' WHERE id = $1", [T.id]);   // tuje vrstice ta test ne izdaja
        await tek(w, 4, 40);
        const r2 = await vrstica(R.id);
        assert(klicov("SalesInvoiceCreate") - c0 === 1 && klicov("SalesInvoiceList") === l0 && r2.stanje === "potrjen" && F.docs.length === 1, `[${stanje}] po migraciji natanko 1 Create (brez iskanja), racun potrjen, en dokument`, [klicov("SalesInvoiceCreate") - c0, r2.stanje, F.docs.length]);
        // ponovni zagon migracije (ne bi se smel zgoditi): vrstica je potrjena -> nic, obvestilo
        const note2 = await zaganjaj();
        assert((await vrstica(R.id)).stanje === "potrjen" && note2.some((x) => /061/.test(x)), `[${stanje}] ponovni zagon: potrjena vrstica ostane, obvestilo`, note2);
        await tek(w, 2, 40);
        assert(klicov("SalesInvoiceCreate") - c0 === 1, `[${stanje}] ponovni zagon ne sprozi nove izdaje`);
      }
      // ne ustreza pogoju -> nic + obvestilo
      for (const [ime, popravi] of [
        ["poslano_at mlajsi od 10 min (zahtevek je lahko se v teku)", async (id) => { await pool.query("UPDATE racuni SET poslano_at = NOW() - INTERVAL '2 minutes' WHERE id = $1", [id]); }],
        ["vrstica ima ponudnik_stevilka (dokument obstaja)", async (id) => { await pool.query("UPDATE racuni SET ponudnik = 'eracuni', ponudnik_stevilka = '2026-00001' WHERE id = $1", [id]); }],
      ]) {
        const R = await priprava("caka"); await popravi(R.id);
        const pred = await vrstica(R.id); const note = await zaganjaj(); const po = await vrstica(R.id);
        assert(JSON.stringify(po) === JSON.stringify(pred) && note.some((x) => /061/.test(x)), `ne ustreza pogoju (${ime}): nic ne spremeni, izpise obvestilo`, [note, po.stanje]);
      }
      await pool.query("TRUNCATE racuni CASCADE"); await pool.query("UPDATE orders SET public_ref = 'OUT-STARO-' || id WHERE public_ref = $1", [REF]);
      const noteBrez = await zaganjaj();
      assert(noteBrez.some((x) => /061/.test(x)), "narocila ni (prazna baza, druga okolja): migracija ne naredi nic in ne pade", noteBrez);
      // prekrivanje instanc ob deployu: stara instanca drzi prevzem; migracija ga prekine, njen zapis (zeton) ne spremeni nic, nov delavec izda natanko enkrat
      const Ro = await priprava("caka");
      await pool.query("UPDATE racuni SET prevzeto_at = NOW(), prevzem_zeton = 'zeton-stare-instance' WHERE id = $1", [Ro.id]);
      await zaganjaj();
      const staroPisanje = await pool.query("UPDATE racuni SET poslano_at = NOW() WHERE id = $1 AND prevzem_zeton = 'zeton-stare-instance' AND prevzeto_at IS NOT NULL", [Ro.id]);
      assert(staroPisanje.rowCount === 0 && (await vrstica(Ro.id)).poslano_at === null, "stara instanca po migraciji ne more vec zapisati (prevzem_zeton), poslano_at ostane prazen");
      const co = klicov("SalesInvoiceCreate"), w1 = deloven(), w2 = deloven();
      await Promise.all([tek(w1, 3, 30), tek(w2, 3, 30)]);   // dve instanci hkrati (najem + zeton)
      assert(klicov("SalesInvoiceCreate") - co === 1 && (await vrstica(Ro.id)).stanje === "potrjen" && F.docs.length === 1, "dve instanci hkrati: natanko 1 Create", [klicov("SalesInvoiceCreate") - co, F.docs.length]);
    }

  } catch (e) {
    fail++; console.log("  ✗ IZJEMA:", e && e.stack || e);
  } finally {
    streznik.close(); await pool.end().catch(() => {});
  }
  console.log(`\n${ok} ok, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
