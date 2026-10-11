// Sentry za backend (issue #87, brezplacni paket: 5.000 napak/mesec skupaj za vse projekte, presezek se zavrze).
//
// VKLOPLJENO SAMO ce je v okolju SENTRY_DSN (Render). Brez njega ta datoteka ne naloži NICESAR: paket @sentry/node se ne require-a,
// console.error ostane nedotaknjen, v Express se ne doda noben vmesni program - testi, CI in lokalni zagon so enaki kot prej.
// DSN je samo v okolju, nikoli v kodi. Paket se naloži znotraj try: ce nalaganje pade, aplikacija vseeno deluje (samo brez Sentryja).
//
// Kaj se poslje: neujete izjeme (po flushu proces konca kot prej), unhandledRejection (lastni poslusalec: flush, nato exit(1) = proces konca kot privzeto v Node 22),
// napake v asinhronih rocnikih (napakaRocnik), skenske poti (odgovoriNaNapako), iskanje kluba pri vlogah, in VSAK odgovor 500 ne glede na pot
// (vmesni program ovije res.status; sklad napake vzamemo iz console.error(e), ki ga poti ze kličejo tik pred 500, sicer samo sporocilo
// »500 METODA /pot/:vzorec«). Opozorila »POZOR« iz dnevnika gredo kot sporocilo stopnje warning.
//
// Kaj se NE poslje: noben zahtevek (glave, telo, piskotki, query, URL, IP), noben uporabnik, nobeni breadcrumbi, noben osebni podatek
// (e-naslovi, zetoni, dolgi identifikatorji se v besedilih zamenjajo). Brez performance/OpenTelemetry: nobena instrumentacija
// http/pg/express/fetch ni vklopljena (defaultIntegrations: false + samo stirje izrecni vgrajeni obravnavalniki), tracesSampleRate ni nastavljen.
// Omejitev stevila: isti kljuc najvec enkrat na 15 min, skupaj najvec SENTRY_NAJVEC_NA_URO (privzeto 30) dogodkov na uro (neujete
// izjeme in zavrnitve gredo vedno skozi), da naval napak ne porabi mesecne kvote v minutah.

"use strict";

const OKNO_KLJUCA_MS = 15 * 60 * 1000;
const URA_MS = 60 * 60 * 1000;

let Sentry = null;            // naloženi paket (samo ob DSN)
let zagnan = false;
let zadnjaNapaka = null;      // zadnji Error iz console.error v TEM sinhronem koraku (glej opazi)
const zadnjiPoKljucu = new Map();
const ura = { napake: { zacetek: 0, stevec: 0 }, opozorila: { zacetek: 0, stevec: 0 } };   // loceni urni proracun: 500/izjeme in POZOR

// ---------------------------------------------------------------------------------------------------------------------------
// Ciscenje besedil (brez osebnih podatkov). Izvozeno za test.
// ---------------------------------------------------------------------------------------------------------------------------
// Vsa besedila gredo skozi ociscenje SAMO ob omejeni dolzini: pg 22P02 ponovi vrednost odjemalca (lahko 15 KB), regexi pa so nad dolgim nizom
// kvadraticni (230 ms CPU na zahtevek, K1). Zato: (1) odreži na 1000 znakov, (2) pg vrednosti v narekovajih odstrani prve (linearno),
// (3) regexi za zetone nimajo zgornjih mej (dolg zeton se zamenja v celoti), a so linearni ali omejeni z vhodom 1000 znakov, (4) rezultat ima najvec 300 znakov.
const OCISCENJE_VHOD = 1000;
const OCISCENJE_IZHOD = 300;
function ociscenje(besedilo) {
  if (typeof besedilo !== "string") return besedilo;
  const odrezano = besedilo.length > OCISCENJE_VHOD;
  let b = odrezano ? besedilo.slice(0, OCISCENJE_VHOD) : besedilo;
  b = b
    .replace(/(invalid input (?:syntax|value) for [^:\n]{0,80}):[\s\S]*/g, "$1: [x]")                      // pg 22P02 ponovi vrednost odjemalca
    .replace(/\b(value|zone|syntax|input|name|string|identifier)\s+"[^"]*(?:"|$)/gi, '$1 "[x]"')            // 22003, 22008, »time zone«: vrednost v narekovajih (tudi nezakljucena)
    .replace(/[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}/g, "[email]")                      // e-naslovi
    .replace(/eyJ[A-Za-z0-9_.-]{5,}/g, "[jwt]")                                                              // JWT (cel, brez zgornje meje: vhod je ze omejen)
    .replace(/\b(Bearer|Basic)\s+\S+/gi, "$1 [x]")                                                   // Authorization
    .replace(/\b(?:cs|pi|ch|evt|acct|re|cus|sub|in|po|tr|ba|card|whsec|sk|pk|rk)_[A-Za-z0-9_]{6,}/g, "[id]")   // identifikatorji tretjih
    .replace(/\b(?:OUT|test)[-_][A-Za-z0-9]{6,12}\b/g, "[ref]")                                             // public_ref narocila
    .replace(/\b(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{24,}\b/g, "[id]");                                // dolgi zetoni, kode (s stevko; imena omejitev brez stevk ostanejo)
  return b.length > OCISCENJE_IZHOD ? b.slice(0, OCISCENJE_IZHOD) + "…" : (odrezano ? b + "…" : b);
}

// Ključ omejitve: BREZ uporabniske vsebine (vrednosti v narekovajih, stevila): isti vzrok = isti kljuc, tuja vsebina ga ne more razmnoziti.
function normaliziraj(besedilo) {
  return String(besedilo === undefined || besedilo === null ? "" : besedilo).slice(0, 200).replace(/"[^"]*"?/g, '"?"').replace(/\d+/g, "#").slice(0, 60);
}

// beforeSend: odstrani vse, kar je lahko osebno ali skrivnost. Vrne dogodek (spremenjen) ali null.
function ocisti(dogodek) {
  if (!dogodek) return null;
  delete dogodek.request;          // glave (Authorization, Cookie, X-Guest-Token, X-Outly-*), telo, piskotki, query_string, url
  delete dogodek.user;             // vkljucno z ip_address
  delete dogodek.server_name;
  delete dogodek.modules;
  dogodek.breadcrumbs = [];
  if (dogodek.contexts) { delete dogodek.contexts.request; delete dogodek.contexts.trace; }
  if (dogodek.extra) {
    const dovoljeno = {};
    if (dogodek.extra.unhandledPromiseRejection) dovoljeno.unhandledPromiseRejection = true;
    dogodek.extra = dovoljeno;
  }
  if (typeof dogodek.message === "string") dogodek.message = ociscenje(dogodek.message);
  if (dogodek.logentry && typeof dogodek.logentry.message === "string") dogodek.logentry.message = ociscenje(dogodek.logentry.message);
  const vrednosti = dogodek.exception && Array.isArray(dogodek.exception.values) ? dogodek.exception.values : [];
  for (const v of vrednosti) {
    if (typeof v.value === "string") v.value = ociscenje(v.value);
    if (v.stacktrace && Array.isArray(v.stacktrace.frames)) for (const f of v.stacktrace.frames) delete f.vars;
  }
  // Oznake: samo kratki nizi brez osebnih podatkov (nastavimo jih sami: kontekst, metoda, vzorec poti)
  if (dogodek.tags) for (const k of Object.keys(dogodek.tags)) dogodek.tags[k] = ociscenje(String(dogodek.tags[k])).slice(0, 120);
  // Skupna ura omejitev: neujete izjeme/zavrnitve (handled === false) gredo vedno skozi.
  const neujeta = vrednosti.some((v) => v.mechanism && v.mechanism.handled === false) || dogodek.level === "fatal";
  if (!neujeta && !znotrajUrnegaProracuna(dogodek.level === "warning" ? "opozorila" : "napake")) return null;
  return dogodek;
}

function znotrajUrnegaProracuna(razred) {
  const p = ura[razred];
  const zdaj = Date.now();
  if (zdaj - p.zacetek > URA_MS) { p.zacetek = zdaj; p.stevec = 0; }
  const surova = razred === "napake" ? process.env.SENTRY_NAJVEC_NA_URO : undefined;
  const najvec = surova === undefined || surova === "" ? NaN : Number(surova);
  const meja = Number.isFinite(najvec) && najvec >= 0 ? najvec : (razred === "napake" ? 30 : 10);
  if (p.stevec >= meja) return false;
  p.stevec++;
  return true;
}

// Isti kljuc najvec enkrat na 15 min (v pomnilniku, omejen na 500 kljucev).
function prepocasi(kljuc) {
  const zdaj = Date.now();
  const prej = zadnjiPoKljucu.get(kljuc);
  if (prej !== undefined && zdaj - prej < OKNO_KLJUCA_MS) return true;
  if (zadnjiPoKljucu.size >= 500) {
    for (const [k, t] of zadnjiPoKljucu) if (zdaj - t >= OKNO_KLJUCA_MS) zadnjiPoKljucu.delete(k);
    if (zadnjiPoKljucu.size >= 500) zadnjiPoKljucu.delete(zadnjiPoKljucu.keys().next().value);
  }
  zadnjiPoKljucu.set(kljuc, zdaj);
  return false;
}

// Vzorec poti (npr. "/events/:id"), nikoli prava pot z identifikatorji ali zetoni v njej.
function vzorecPoti(req) {
  try {
    if (req && req.route && req.route.path !== undefined) return String((req.baseUrl ? req.baseUrl.replace(/\/\d+(?=\/|$)/g, "/:n") : "") + req.route.path).slice(0, 120);
  } catch (_) { /* ni vzorca */ }
  return "?";
}
const metodaZ = (req) => String((req && req.method) || "?").slice(0, 10);

// Zahtevek je ze porocan (preprecimo dvojno porocanje: eksplicitni klic + ovoj res.status).
function oznaci(req, res) {
  const r = res || (req && req.res);
  if (r && r.locals) r.locals.sentryPoslano = true;
}
function jeOznacen(res) { return !!(res && res.locals && res.locals.sentryPoslano); }

// ---------------------------------------------------------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------------------------------------------------------
function vklopljen() { return Sentry !== null; }

// Poroci napako (Error). `kontekst` = kratka oznaka mesta (npr. "sken"), `req` neobvezen (vzorec poti, oznaka »ze porocano«).
function porociNapako(e, kontekst, req, res) {
  if (!Sentry) return;
  try {
    req = req || (res && res.req);
    oznaci(req, res);
    const napaka = e instanceof Error ? e : new Error(typeof e === "string" ? e : "neznana napaka");
    const metoda = metodaZ(req), pot = vzorecPoti(req);
    if (prepocasi(`n|${kontekst || ""}|${metoda}|${pot}|${napaka.code || ""}|${normaliziraj(napaka.constraint)}|${normaliziraj(napaka.column)}|${normaliziraj(napaka.message)}`)) return;
    const ctx = { level: "error", tags: { kontekst: kontekst || "", metoda, pot } };
    // constraint/column (identifikatorja sheme, ne vrednosti): razlicne omejitve iste poti so loceni problemi (tudi za dedupe in grupiranje v Sentryju)
    if (napaka.constraint || napaka.column) ctx.fingerprint = ["{{ default }}", String(napaka.constraint || "").slice(0, 80), String(napaka.column || "").slice(0, 80)];
    Sentry.captureException(napaka, ctx);
  } catch (_) { /* porocanje nikoli ne sme podreti zahtevka */ }
}

// Opozorilo brez izjeme (npr. vrstica »POZOR« iz dnevnika). Besedilo se ociscene, kljuc omejitve je zacetek besedila.
function porociOpozorilo(besedilo, kontekst) {
  if (!Sentry) return;
  try {
    const b = ociscenje(String(besedilo));
    if (prepocasi(`o|${kontekst || ""}|${normaliziraj(b)}`)) return;
    Sentry.captureMessage(b, { level: "warning", tags: { kontekst: kontekst || "" } });
  } catch (_) { /* nikoli ne podre zahtevka */ }
}

// Odgovor 500 iz poti (poklice se ob res.status(500)): sklad iz console.error(e) tik pred tem, sicer samo sporocilo.
function javi500(req, res) {
  if (!Sentry || jeOznacen(res)) return;
  const e = zadnjaNapaka; zadnjaNapaka = null;
  if (e) { porociNapako(e, "odgovor-500", req, res); return; }
  try {
    oznaci(req, res);
    const metoda = metodaZ(req), pot = vzorecPoti(req);
    if (prepocasi(`5|${metoda}|${pot}`)) return;
    Sentry.captureMessage(`500 ${metoda} ${pot}`, { level: "error", tags: { kontekst: "odgovor-500", metoda, pot } });
  } catch (_) { /* nikoli ne podre zahtevka */ }
}

// Express vmesni program: ovije res.status, da vsak 500 (ne 503 = zacasna tezava povezave, I10) pride v Sentry. Odgovor ostane nespremenjen.
function vmesnik(req, res, next) {
  const izvirni = res.status;
  res.status = function status(koda) {
    if (koda === 500) javi500(req, res);
    return izvirni.apply(this, arguments);
  };
  next();
}

// console.error(e) pred 500 hrani Error za javi500 (samo do konca tega sinhronega koraka, da se ne pripise tujemu zahtevku);
// vrstice »POZOR« gredo kot opozorilo. Izvirni console.error se vedno poklice prvi in nespremenjen.
function opazi(args) {
  for (const a of args) {
    if (a instanceof Error) {
      zadnjaNapaka = a;
      const ta = a;
      queueMicrotask(() => { if (zadnjaNapaka === ta) zadnjaNapaka = null; });
      break;
    }
  }
  if (typeof args[0] === "string" && /\bPOZOR\b/.test(args[0])) porociOpozorilo(args[0], "pozor");
}

function zagon() {
  if (zagnan) return Sentry !== null;
  zagnan = true;
  const dsn = process.env.SENTRY_DSN;
  if (!dsn) return false;
  try {
    const S = require("@sentry/node");   // znotraj pogoja: brez DSN se paket ne naloži
    S.init({
      dsn,
      environment: process.env.RENDER ? "production" : "development",
      release: process.env.RENDER_GIT_COMMIT || undefined,
      sendDefaultPii: false,
      // Brez performance: tracesSampleRate NI nastavljen (= sledenje izklopljeno), OpenTelemetry se ne postavi.
      skipOpenTelemetrySetup: true,
      maxBreadcrumbs: 0,
      defaultIntegrations: false,
      integrations: [
        S.linkedErrorsIntegration(),
        S.dedupeIntegration(),
        S.onUncaughtExceptionIntegration({ exitEvenIfOtherHandlersAreRegistered: true }),   // flush (najvec 2 s), nato exit(1) - kot brez Sentryja
      ],
      beforeSend: ocisti,
    });
    Sentry = S;
    // Lastni poslusalec namesto S.onUnhandledRejectionIntegration: ta ima vgrajen seznam prezrtih napak (AbortError ...), ki ga ni mogoce izklopiti
    // (`ignore: []` jih ohrani), proces pa bi ob taksni zavrnitvi ostal zivi, kar Node 22 brez Sentryja ne naredi (I10). Tu: zabelezi, flush (najvec 2 s), exit(1).
    let koncujem = false;
    process.on("unhandledRejection", (razlog) => {
      if (koncujem) return;
      koncujem = true;
      try {
        S.captureException(razlog, { level: "fatal", mechanism: { handled: false, type: "onunhandledrejection" } });
        console.error("[sentry] neujeta zavrnitev:", (razlog && razlog.stack) || razlog);
      } catch (_) { /* izstop se vedno zgodi */ }
      const izstop = () => process.exit(1);
      setTimeout(izstop, 3000);   // varnostna mreza, ce obljuba close nikoli ne razresi (brez unref: proces mora izstopiti)
      try { S.close(2000).then(izstop, izstop); } catch (_) { izstop(); }
    });
    const izvirni = console.error;
    console.error = function (...args) {
      izvirni.apply(console, args);
      try { opazi(args); } catch (_) { /* nikoli ne podre klica */ }
    };
    console.log(`[sentry] vklopljen (environment=${process.env.RENDER ? "production" : "development"})`);
    return true;
  } catch (e) {
    Sentry = null;
    console.error("[sentry] nalaganje ni uspelo, aplikacija tece brez njega:", e && e.message);
    return false;
  }
}

module.exports = { zagon, vklopljen, vmesnik, porociNapako, porociOpozorilo, ociscenje, ocisti };
