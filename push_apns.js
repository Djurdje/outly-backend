"use strict";
// Potisna obvestila prek APNs (issue #183, migracija 040, invarianta I29). Brez novih odvisnosti: vgrajena `http2` in `crypto`.
//
// Kaj dela: ena dolgozivna HTTP/2 seja do APNs (ponovna vzpostavitev ob napaki/GOAWAY/izteku), JWT ES256 (kid = APNS_KEY_ID, iss = APNS_TEAM_ID,
// iat) predpomnjen in osvezen na 50 min (Apple: JWT starejsi od 60 min je zavrnjen, osvezevanje pogosteje kot na 20 min tudi), po ena
// zahteva na zeton. Brez APNS_KEY_ID, APNS_TEAM_ID in APNS_KEY_P8 je push IZKLOPLJEN (ena vrstica ob zagonu), vse funkcije so no-op.
//
// Pravila (I29): modul NIKOLI ne vrze izjeme navzven; vsak zahtevek ima casovno omejitev; socasnost je omejena (sledilci kluba so lahko tisoci);
// kljuca, JWT in zetonov naprav ne zapise v dnevnik. Klicatelj (index.js) ga klice PO commitu, brez await, zato napaka ali izpad APNs
// nikoli ne podre ali upocasni zahtevka (se posebej ne skena na vratih, I16).
//
// PAST: ES256 podpis za JWT mora biti v formatu `ieee-p1363` (r || s, 64 bajtov), NE DER (privzeto v Node `crypto.sign`): z DER APNs odgovori
// 403 InvalidProviderToken in push ne dela, ne da bi karkoli drugega javilo napako.
const http2 = require("http2");
const crypto = require("crypto");

// Razlogi 400, pri katerih zeton nikoli vec ne bo veljal (410 je neveljaven vedno). DeviceTokenNotForTopic NI med njimi: to je napaka
// NASTAVITVE (APNS_TOPIC ne ustreza bundle ID-ju), ne zetona; oznacitev bi ob napacnem topicu pobila vse zetone (opozorilo v dnevnik).
const NEVELJAVNI_RAZLOGI = new Set(["BadDeviceToken", "Unregistered"]);
const TIMEOUTOV_ZA_NOVO_SEJO = 3;      // toliko zaporednih zahtevkov brez odgovora, preden se seja zavrze (en visec stream seje ne ubije)
const VELJA_PRIVZETO_S = 24 * 3600;    // apns-expiration za vsa obvestila, razen kjer je izrecno drugace (strezba 1 h)
const ZETON_VZOREC = /^[0-9a-fA-F]{64,200}$/;
const JWT_OSVEZI_S = 50 * 60;          // Apple zavrne JWT starejsi od 60 min; osvezevanje pogosteje kot na 20 min tudi
const JWT_NAJMANJ_OSVEZITEV_S = 20 * 60;
const LOC_ARG_NAJVEC = 200;            // znakov; payload ima mejo 4 KB

function celo(vrednost, privzeto, min, max) {
  const v = Number.parseInt(vrednost, 10);
  return Number.isInteger(v) && v >= min && v <= max ? v : privzeto;
}

// APNS_KEY_P8: base64 cele .p8 datoteke; sprejmemo tudi surov PEM (z dejanskimi ali dobesednimi \n).
function preberiKljuc(surov) {
  let pem = String(surov).trim();
  if (!pem.includes("-----BEGIN")) pem = Buffer.from(pem, "base64").toString("utf8");
  pem = pem.replace(/\\n/g, "\n");
  const kljuc = crypto.createPrivateKey(pem);
  if (kljuc.asymmetricKeyType !== "ec" || (kljuc.asymmetricKeyDetails && kljuc.asymmetricKeyDetails.namedCurve !== "prime256v1")) {
    throw new Error("kljuc ni EC P-256");
  }
  return kljuc;
}

const b64u = (o) => Buffer.from(typeof o === "string" ? o : JSON.stringify(o)).toString("base64url");

// Telo obvestila po dogovoru (DOGOVOR_push): loc-key je angleski niz (enak kljucu v iOS Localizable.xcstrings; brez prevoda iOS pokaze angleski niz),
// outly.type + outly.id povesta aplikaciji, kam ob dotiku. Vsebina nikoli ne nosi e-naslova ali imena kupca/gosta (I27).
function sestaviObvestilo({ tip, id, naslov, kljuc, argumenti = [], velja = VELJA_PRIVZETO_S }) {
  const telo = {
    aps: {
      alert: { "title-loc-key": naslov, "loc-key": kljuc, "loc-args": argumenti.map((a) => String(a ?? "").slice(0, LOC_ARG_NAJVEC)) },
      sound: "default",
    },
    outly: { type: tip, id },
  };
  return { telo: JSON.stringify(telo), velja };
}

function ustvariApns(okolje = process.env, dnevnik = console) {
  const keyId = (okolje.APNS_KEY_ID || "").trim();
  const teamId = (okolje.APNS_TEAM_ID || "").trim();
  const p8 = (okolje.APNS_KEY_P8 || "").trim();
  const izklopljen = {
    vklopljen: false,
    poslji: async () => ({ ok: false, preskoceno: true }),
    posljiVsem: async () => [],
    zapri: () => {},
  };
  if (!keyId || !teamId || !p8) {
    const manjka = [!keyId && "APNS_KEY_ID", !teamId && "APNS_TEAM_ID", !p8 && "APNS_KEY_P8"].filter(Boolean).join(", ");
    dnevnik.log(`[push] izklopljen (manjka ${manjka}); brez potisnih obvestil, vse ostalo dela`);
    return izklopljen;
  }
  let kljuc;
  try { kljuc = preberiKljuc(p8); }
  catch (e) {
    dnevnik.error(`[push] izklopljen: APNS_KEY_P8 ni veljaven zasebni kljuc P-256 (${e && e.message}); preveri, da je base64 cele .p8 datoteke`);
    return izklopljen;
  }
  let origin;
  try {
    const u = new URL(okolje.APNS_HOST || "https://api.push.apple.com");
    if (u.protocol !== "https:") throw new Error("APNS_HOST mora biti https");
    origin = u.origin;
  } catch (e) {
    dnevnik.error(`[push] izklopljen: APNS_HOST ni veljaven naslov (${e && e.message})`);
    return izklopljen;
  }
  const topic = (okolje.APNS_TOPIC || "si.outly.app").trim();
  const timeoutMs = celo(okolje.APNS_TIMEOUT_MS, 10000, 200, 60000);
  const socasno = celo(okolje.APNS_SOCASNO, 20, 1, 200);
  const vrstaNajvec = celo(okolje.APNS_VRSTA_NAJVEC, 20000, 1, 1000000);

  // --- JWT (predpomnjen) ---
  let jwtZeton = null, jwtIat = 0;
  function jwt(sile = false) {
    const zdaj = Math.floor(Date.now() / 1000);
    const starost = zdaj - jwtIat;
    if (!jwtZeton || starost >= JWT_OSVEZI_S || (sile && starost >= JWT_NAJMANJ_OSVEZITEV_S)) {
      const glava = b64u({ alg: "ES256", kid: keyId });
      const telo = b64u({ iss: teamId, iat: zdaj });
      const podpis = crypto.sign("sha256", Buffer.from(glava + "." + telo), { key: kljuc, dsaEncoding: "ieee-p1363" });
      jwtZeton = glava + "." + telo + "." + podpis.toString("base64url");
      jwtIat = zdaj;
    }
    return jwtZeton;
  }

  // Dnevnik: isti razlog najvec enkrat na minuto (izpad APNs ne sme zaliti dnevnika s tisoci vrsticami).
  const zadnjiDnevnik = new Map();
  function opozori(kljucDnevnika, sporocilo) {
    const zdaj = Date.now();
    if (zdaj - (zadnjiDnevnik.get(kljucDnevnika) || 0) < 60000) return;
    zadnjiDnevnik.set(kljucDnevnika, zdaj);
    if (zadnjiDnevnik.size > 200) zadnjiDnevnik.clear();
    dnevnik.error(sporocilo);
  }

  // --- HTTP/2 seja ---
  let seja = null;
  let zaporednihTimeoutov = 0;           // zahtevki brez odgovora zapored; vsak prejet odgovor ga ponastavi
  function pozabi(s) { if (seja === s) seja = null; }
  function dobiSejo() {
    if (seja && !seja.closed && !seja.destroyed) return seja;
    const s = http2.connect(origin);
    s.setTimeout(0);
    s.on("error", (e) => { pozabi(s); opozori("seja", `[push] seja do APNs prekinjena: ${e && (e.code || e.message)}`); });
    s.on("close", () => pozabi(s));
    s.on("goaway", () => { pozabi(s); try { s.close(); } catch { /* ze zaprta */ } });
    if (typeof s.unref === "function") s.unref();   // seja sama ne sme drzati procesa pri zivljenju
    seja = s;
    return s;
  }

  // Ena zahteva; resolve vedno (nikoli reject). omrezna = napaka seje/povezave (vredno enega ponovnega poskusa), timeout = brez odgovora.
  function enaZahteva(zeton, obvestilo, sile) {
    return new Promise((resolve) => {
      let konec = false, req = null, timer = null, uporabljena = null;
      // omrezna napaka nosi sejo, na kateri se je zgodila: ponovni poskus je ne sme dobiti nazaj (seja se lahko zapira, a se ni »closed«).
      const koncaj = (r) => { if (konec) return; konec = true; clearTimeout(timer); if (r.omrezna) r.seja = uporabljena; resolve(r); };
      timer = setTimeout(() => {
        koncaj({ ok: false, status: 0, razlog: "timeout", timeout: true });
        try { if (req) req.close(http2.constants.NGHTTP2_CANCEL); } catch { /* ignoriraj */ }
        // Samo ta stream je obvisel: zapremo ga, seja (in do 19 drugih zdravih zahtevkov na njej) ostane. Seja je mrtva (polodprt TCP) sele,
        // ko jih ni odgovorilo vec zaporednih: tedaj jo zavrzemo in naslednji zahtevek odpre novo.
        zaporednihTimeoutov++;
        if (zaporednihTimeoutov >= TIMEOUTOV_ZA_NOVO_SEJO) {
          zaporednihTimeoutov = 0;
          try { const s = seja; if (s) { pozabi(s); s.destroy(); } } catch { /* ignoriraj */ }
        }
      }, timeoutMs);
      try {
        const glave = {
          ":method": "POST",
          ":path": "/3/device/" + zeton,
          authorization: "bearer " + jwt(sile),
          "apns-topic": topic,
          "apns-push-type": "alert",
          "apns-priority": "10",
          "content-type": "application/json",
        };
        if (obvestilo.velja) glave["apns-expiration"] = String(Math.floor(Date.now() / 1000) + obvestilo.velja);
        uporabljena = dobiSejo();
        req = uporabljena.request(glave);
        let status = 0, telo = "";
        req.setEncoding("utf8");
        req.on("response", (h) => { status = Number(h[":status"]) || 0; zaporednihTimeoutov = 0; });
        req.on("data", (d) => { if (telo.length < 4096) telo += d; });
        req.on("end", () => {
          let razlog = null;
          if (telo) { try { razlog = JSON.parse(telo).reason || null; } catch { /* ni JSON */ } }
          // Zaključek brez prejetega :status (seja zavrzena, stream zaprt med prenosom) je omrežna napaka: en ponovni poskus.
          if (!status) return koncaj({ ok: false, status: 0, razlog: "brez_odgovora", omrezna: true });
          koncaj({ ok: status === 200, status, razlog });
        });
        req.on("error", (e) => koncaj({ ok: false, status: 0, razlog: e && (e.code || e.message) || "napaka", omrezna: true }));
        req.on("close", () => koncaj({ ok: false, status: 0, razlog: "zaprto", omrezna: true }));
        req.end(obvestilo.telo);
      } catch (e) {
        koncaj({ ok: false, status: 0, razlog: e && (e.code || e.message) || "napaka", omrezna: true });
      }
    });
  }

  // --- omejena socasnost (skupna za vse klice v procesu) ---
  let aktivnih = 0;
  const vrsta = [];
  function vstopi() {
    if (aktivnih < socasno) { aktivnih++; return Promise.resolve(true); }
    if (vrsta.length >= vrstaNajvec) return Promise.resolve(false);
    return new Promise((r) => vrsta.push(r));
  }
  function izstopi() { const n = vrsta.shift(); if (n) n(true); else aktivnih--; }

  async function poslji(zeton, obvestilo) {
    try {
      if (!ZETON_VZOREC.test(String(zeton))) return { ok: false, status: 0, razlog: "zeton", neveljaven: false };
      if (!(await vstopi())) { opozori("vrsta", `[push] vrsta polna (${vrstaNajvec}): obvestila zavrzena`); return { ok: false, status: 0, razlog: "vrsta_polna", neveljaven: false }; }
      try {
        let r = await enaZahteva(zeton, obvestilo, false);
        if (r.omrezna) {                                                 // prekinjena seja: ponovni poskus VEDNO na novi (stara se zapre, drugi zahtevki na njej se dokoncajo)
          if (r.seja) { pozabi(r.seja); try { r.seja.close(); } catch { /* ze zaprta */ } }
          r = await enaZahteva(zeton, obvestilo, false);
        }
        if (r.status === 403 && r.razlog === "ExpiredProviderToken") r = await enaZahteva(zeton, obvestilo, true);
        const neveljaven = r.status === 410 || (r.status === 400 && NEVELJAVNI_RAZLOGI.has(r.razlog));
        if (!r.ok && !neveljaven) {
          const namig = r.status === 403 ? " (preveri APNS_KEY_ID, APNS_TEAM_ID in APNS_KEY_P8 na Renderju; ob preklicu kljuca je treba nov kljuc)"
            : r.razlog === "DeviceTokenNotForTopic" ? ` (preveri APNS_TOPIC = bundle ID aplikacije, zdaj ${topic}; zetonov NE oznacujem kot neveljavnih)` : "";
          opozori("zavrnitev:" + r.status + ":" + r.razlog, `[push] APNs: status ${r.status || "brez odgovora"} razlog ${r.razlog || "?"}${namig}`);
        }
        return { ok: r.ok, status: r.status, razlog: r.razlog || null, neveljaven };
      } finally { izstopi(); }
    } catch (e) {
      opozori("izjema", `[push] nepricakovana napaka: ${e && e.message}`);
      return { ok: false, status: 0, razlog: "izjema", neveljaven: false };
    }
  }

  // Vsem zetonom: omejeno stevilo delavcev (ne vse hkrati), rezultati v istem vrstnem redu { zeton, ok, status, razlog, neveljaven }.
  async function posljiVsem(zetoni, obvestilo) {
    const rezultati = new Array(zetoni.length);
    let naslednji = 0;
    const delavec = async () => {
      while (naslednji < zetoni.length) {
        const i = naslednji++;
        rezultati[i] = { zeton: zetoni[i], ...(await poslji(zetoni[i], obvestilo)) };
      }
    };
    try { await Promise.all(Array.from({ length: Math.min(socasno, zetoni.length) }, delavec)); }
    catch (e) { opozori("izjema", `[push] nepricakovana napaka: ${e && e.message}`); }
    return rezultati.filter(Boolean);
  }

  function zapri() { try { if (seja) seja.destroy(); } catch { /* ignoriraj */ } seja = null; }

  dnevnik.log(`[push] vklopljen: ${origin}, topic ${topic}, najvec ${socasno} hkrati, rok ${timeoutMs} ms`);
  return { vklopljen: true, poslji, posljiVsem, zapri };
}

module.exports = { ustvariApns, sestaviObvestilo, ZETON_VZOREC, NEVELJAVNI_RAZLOGI };
