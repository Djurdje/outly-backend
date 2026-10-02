"use strict";
/**
 * Kratek predpomnilnik JAVNIH seznamov (GET /events, GET /clubs, javni del GET /events/:id in /clubs/:id).
 * Issue #114. Zakaj: pri 1000 hkratnih ogledih bi vsak zahtevek znova pognal poizvedbo (0,1 CPU baza) in serializiral
 * ~100-180 kB JSON (enonitni Node) - predpomnimo ze serializiran odgovor.
 *
 * Kaj je v predpomnilniku in kaj NE (invarianta I17, docs/ARCHITECTURE.md):
 *  - SAMO odgovori, ki ne zavisijo od uporabnika. Kljuc je sestavljen iz poti in kanonicnih poizvedbenih parametrov
 *    (to naredi klicalec v index.js), NIKOLI iz zetona, glave ali IP-ja. Osebna polja (my_plan, friends_*, is_following)
 *    se dodajo po branju iz predpomnilnika, v svoji kopiji, in se ne vrnejo vanj.
 *  - Samo status 200; napake in 404 se ne hranijo.
 *
 * Lastnosti:
 *  - TTL (privzeto 3 s), omejeno stevilo kljucev in bajtov (LRU: najdlje neuporabljen gre prvi) - napadalec z nakljucnimi
 *    parametri ne napihne pomnilnika.
 *  - Single-flight: hkratni zahtevki za isti manjkajoci kljuc sprozijo eno poizvedbo.
 *  - ETag (sha256 serializiranega telesa) + 304, brez ponovne serializacije.
 *  - Razveljavitev: vsak uspesen (ali negotov, 5xx) zapis (POST/PUT/PATCH/DELETE) v ISTEM procesu izprazni vse, PRED
 *    posiljanjem odgovora pisalcu. Druge instance zaostanejo najvec TTL (sprejeto).
 */
const crypto = require("crypto");

const NAJVEC_TELO = 1024 * 1024;           // vecjega odgovora ne hranimo (200 dogodkov z opisi ~ 180 kB)
const NAJVEC_BAJTOV = 32 * 1024 * 1024;    // skupen proracun vsebine (instanca ima 512 MB)
const REZIJA_VNOSA = 512;                  // priblizek za kljuc, objekte in objekt `podatki`

function etagTelesa(telo) {
  return 'W/"' + crypto.createHash("sha256").update(telo).digest("base64url").slice(0, 27) + '"';
}

/**
 * ttlMs: 0 ali manj = izklopljeno (poizvedba ob vsakem zahtevku, brez single-flight, kot pred #114).
 * ura: za teste.
 */
function ustvariPredpomnilnik({ ttlMs = 3000, najvecKljucev = 300, najvecBajtov = NAJVEC_BAJTOV, ura = Date.now } = {}) {
  const omogoceno = ttlMs > 0 && najvecKljucev > 0;
  const vnosi = new Map();   // kljuc -> vnos; vrstni red vstavljanja = LRU (najdlje neuporabljen prvi)
  const vLetu = new Map();   // kljuc -> obljuba poizvedbe, ki tece (single-flight)
  let bajti = 0;
  let rod = 0;               // narasca ob razveljavitvi; poizvedba, ki se je zacela pred njo, rezultata ne shrani
  const stat = { zadetki: 0, zgresitve: 0, zdruzeno: 0, izpodrivi: 0, razveljavitve: 0, neshranjeno: 0 };

  /** Rezultat poizvedbe -> vnos s ze serializiranim telesom. `json` ali `besedilo` (za napake). */
  function pripravi(r) {
    const status = r.status || 200;
    let telo, tip;
    if (r.json !== undefined) {
      telo = Buffer.from(JSON.stringify(r.json));
      tip = "application/json; charset=utf-8";
    } else {
      telo = Buffer.from(String(r.besedilo ?? ""));
      tip = "text/html; charset=utf-8";
    }
    return {
      status, telo, tip,
      etag: status === 200 ? etagTelesa(telo) : null,
      glave: r.glave || null,
      podatki: r.podatki,            // neobvezno: izvorna vrstica, iz katere klicalec gradi osebno razlicico (ne spreminjaj!)
      velikost: telo.length + REZIJA_VNOSA,
      doKdaj: 0,
    };
  }

  function odstrani(kljuc, vnos) {
    if (vnosi.get(kljuc) === vnos) { vnosi.delete(kljuc); bajti -= vnos.velikost; }
  }

  function shrani(kljuc, vnos, zdaj) {
    // Potekle vnose z zacetka seznama sproti odstranimo (seznam ni urejen po poteku, zato le oportunistično).
    for (const [k, v] of vnosi) { if (v.doKdaj > zdaj) break; odstrani(k, v); }
    const star = vnosi.get(kljuc);
    if (star) odstrani(kljuc, star);
    vnosi.set(kljuc, vnos);
    bajti += vnos.velikost;
    while (vnosi.size > najvecKljucev || bajti > najvecBajtov) {
      const [k, v] = vnosi.entries().next().value;
      odstrani(k, v);
      stat.izpodrivi++;
    }
  }

  /**
   * Vrne { vnos, stanje }; stanje: "zadetek" | "zgresitev" | "zdruzeno" | "izklopljen".
   * kljuc === null = tega zahtevka ne predpomnimo (nenavadni parametri) -> neposredna poizvedba.
   * Ce `izracunaj` vrze, vrze tudi dobi() (vsem cakajocim); klicalec odgovori s 500, kot prej.
   */
  async function dobi(kljuc, izracunaj) {
    if (!omogoceno || kljuc === null || kljuc === undefined) {
      return { vnos: pripravi(await izracunaj()), stanje: "izklopljen" };
    }
    const zdaj = ura();
    const v = vnosi.get(kljuc);
    if (v) {
      if (v.doKdaj > zdaj) {
        vnosi.delete(kljuc); vnosi.set(kljuc, v);        // LRU: nazadnje uporabljen gre na konec
        stat.zadetki++;
        return { vnos: v, stanje: "zadetek" };
      }
      odstrani(kljuc, v);
    }
    const poteka = vLetu.get(kljuc);
    if (poteka) { stat.zdruzeno++; return { vnos: await poteka, stanje: "zdruzeno" }; }

    const mojRod = rod;
    const obljuba = (async () => pripravi(await izracunaj()))();
    vLetu.set(kljuc, obljuba);
    try {
      const vnos = await obljuba;
      stat.zgresitve++;
      if (vnos.status === 200 && rod === mojRod && vnos.velikost <= NAJVEC_TELO) {
        vnos.doKdaj = zdaj + ttlMs;                       // staranje se steje od zacetka poizvedbe (posnetek podatkov)
        shrani(kljuc, vnos, zdaj);
      } else {
        stat.neshranjeno++;
      }
      return { vnos, stanje: "zgresitev" };
    } finally {
      if (vLetu.get(kljuc) === obljuba) vLetu.delete(kljuc);
    }
  }

  /** Izprazni vse. Poizvedbe v teku se ne shranijo (rod) in jim novi zahtevki ne pridruzijo (vLetu.clear). */
  function razveljavi() {
    rod++;
    stat.razveljavitve++;
    vnosi.clear();
    vLetu.clear();
    bajti = 0;
  }

  /** Posljiv odgovor iz vnosa: ETag/304, Content-Length, brez ponovne serializacije. */
  function poslji(req, res, vnos, stanje) {
    res.set("X-Predpomnilnik", stanje);
    if (vnos.glave) for (const [k, v] of Object.entries(vnos.glave)) res.set(k, v);
    if (vnos.etag) {
      res.set("ETag", vnos.etag);
      res.status(vnos.status);
      if (req.fresh) return res.status(304).end();       // If-None-Match ustreza (Express: GET/HEAD, ni "Cache-Control: no-cache")
    }
    res.status(vnos.status);
    res.set("Content-Type", vnos.tip);
    res.set("Content-Length", String(vnos.telo.length));
    return res.end(vnos.telo);
  }

  /**
   * Express vmesna programska oprema: zapis v ta proces razveljavi predpomnilnik PREJ, ko odgovor odide pisalcu
   * (read-your-writes), in se enkrat ob zaprtju zveze (ce odgovor ni sel). 4xx nima ucinka (zapisa ni bilo) -
   * tako neprijavljeni/neveljavni zahtevki predpomnilnika ne morejo izprazniti.
   * `izjeme`: [{ metoda, pot: RegExp }] - pogosti zapisi, ki ne vplivajo na javne sezname (ogledi, skeniranje).
   */
  function razveljaviOdPisanja(izjeme = []) {
    return (req, res, next) => {
      const m = req.method;
      if (m === "GET" || m === "HEAD" || m === "OPTIONS") return next();
      if (izjeme.some((i) => i.metoda === m && i.pot.test(req.path))) return next();
      let koncano = false;
      const writeHead = res.writeHead;
      res.writeHead = function (...a) {
        koncano = true;
        const koda = typeof a[0] === "number" ? a[0] : this.statusCode;
        if (!(koda >= 400 && koda < 500)) razveljavi();
        return writeHead.apply(this, a);
      };
      res.once("close", () => { if (!koncano) razveljavi(); });
      next();
    };
  }

  return {
    omogoceno, ttlMs, najvecKljucev,
    dobi, poslji, pripravi, razveljavi, razveljaviOdPisanja,
    statistika: () => ({ ...stat, kljucev: vnosi.size, bajtov: bajti, vLetu: vLetu.size }),
  };
}

module.exports = { ustvariPredpomnilnik, etagTelesa };
