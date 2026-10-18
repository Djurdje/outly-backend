// Preverjanje URL polj, ki jih vpise lastnik kluba ali admin (outly-backend#269): ticket_url, poster_url (dogodek),
// website, logo_url, banner_url, instagram (klub). Brez tega bi strezniku lahko podtaknil `javascript:` ali `data:` povezavo,
// ki bi jo aplikacija ali splet pokazala vsem obiskovalcem (splet jo sicer filtrira z varenUrl, iOS od outly-app#107 za ticket_url).
//
// Pravilo (dodano, oblika odgovorov se ne spreminja):
//  - undefined = polja ni v zahtevku (ne spreminjaj), null ali prazen niz = brisanje (shrani se ""), kot doslej;
//  - sicer niz do 2048 znakov, brez presledkov, kontrolnih znakov in `\`, absoluten URL s shemo http: ali https: (razclenjen z `new URL`,
//    NE samo regex), z imenom gostitelja in brez uporabnika/gesla (`https://zaupanja.vredno.si@zlobna.si` je klasicna prevara);
//  - `-` (website, instagram) = brisanje (iOS ga razume kot »ni kontakta«);
//  - `normaliziraj` (website, instagram): vnos brez sheme (`www.klub.si`) dobi `https://` (iOS ClubInfoView pri spletni strani
//    ne preverja ničesar in vsako shranjevanje posle vse polja), a mora imeti ime gostitelja s piko;
//  - `instagram`: golo uporabnisko ime (`@velvet.lj`, brez `:` in `/`; crke, stevke, piko, podcrtaj, do 30 znakov) se sprejme kot doslej, vse ostalo je URL;
//  - `stara` (vrednost, ki je ze v bazi): ce je vnos enak, se NE preverja. Odjemalca ob vsakem shranjevanju posljeta vsa polja
//    (iOS saveClub, admin panel, splet pri dogodku), zato bi star neveljaven zapis sicer za vedno blokiral urejanje drugih polj.
//    Stari zapisi se ne ciscijo (brez migracije); novih neveljavnih ni mogoce vpisati.
// Napaka: 400 { error: "invalid_url", field, message }. Besedilo `message` namenoma ne vsebuje nizov, ki jih iOS APIErrorMessages
// in splet napake.js prepoznata po podnizu, zato odjemalca pokazeta splosno »Please check what you entered and try again.«.

const NAJVEC_DOLZINA_URL = 2048;

const napakaUrl = (polje) => ({
  error: "invalid_url",
  field: polje,
  message: `${polje} must be a web link starting with http:// or https://.`,
});

// Ima niz shemo (`javascript:`, `https:`, `mailto:`)? `klub.si:8080/x` je gostitelj z vrati, ne shema.
const IMA_SHEMO = /^[a-z][a-z0-9+.-]*:/i;
const GOSTITELJ_Z_VRATI = /^[^/:?#]+:\d+([/?#]|$)/;

// Vrne { vrednost } (vrednost je string, ali undefined = polja ni) ali { napaka }.
function preveriUrl(surova, polje, opcije = {}) {
  const { normaliziraj = false, instagram = false, stara } = opcije;
  if (surova === undefined) return { vrednost: undefined };
  if (surova === null) return { vrednost: "" };
  if (typeof surova !== "string") return { napaka: napakaUrl(polje) };
  let v = surova.trim();
  if (v === "") return { vrednost: "" };
  // iOS (ClubView ClubContact.cisto) vnos »-« razume kot »kontakta ni«; lokalno ga zapise pred klicem, zato ga mora strezniku brisati, ne zavrniti
  // (sicer bi vsako naslednje shranjevanje kluba dobilo 400). Druge »prazne« znake iOS ne pozna (»—« je samo prikaz).
  if ((normaliziraj || instagram) && v === "-") return { vrednost: "" };
  if (typeof stara === "string" && v === stara.trim()) return { vrednost: v };   // nespremenjeno: stari zapis ne blokira shranjevanja
  if (v.length > NAJVEC_DOLZINA_URL) return { napaka: napakaUrl(polje) };
  if (instagram && !v.includes(":") && !v.includes("/")) {   // @uporabnisko_ime (kot iOS InstagramVnos: crke, stevke, piko, podcrtaj; do 30 znakov)
    return /^@?[A-Za-z0-9._]{1,30}$/.test(v) ? { vrednost: v } : { napaka: napakaUrl(polje) };
  }
  // Poleg presledkov in kontrolnih znakov tudi `\`: WHATWG (`new URL`, brskalnik) `https://good.com\@evil.com` bere kot gostitelja good.com,
  // RFC 3986 razclenjevalnik (iOS `URL`) pa kot evil.com.
  if (/[\s\u0000-\u001f\u007f\\]/.test(v)) return { napaka: napakaUrl(polje) };
  let predponaDodana = false;
  if (normaliziraj && (!IMA_SHEMO.test(v) || GOSTITELJ_Z_VRATI.test(v)) && !v.startsWith("/")) {
    v = "https://" + v;
    predponaDodana = true;
  }
  if (!/^https?:\/\/[^/?#]/i.test(v)) return { napaka: napakaUrl(polje) };   // `https:example.com`, `https:///x`, `javascript:…`
  let u;
  try { u = new URL(v); } catch { return { napaka: napakaUrl(polje) }; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return { napaka: napakaUrl(polje) };
  if (!u.hostname || u.username || u.password) return { napaka: napakaUrl(polje) };
  if (predponaDodana && !u.hostname.includes(".")) return { napaka: napakaUrl(polje) };
  return { vrednost: v };
}

// Vec polj naenkrat. `polja`: [[ime_stolpca, surova, opcije?], ...]; `stare`: vrstica iz baze (ali undefined).
// Vrne { vrednosti: { ime_stolpca: vrednost (samo poslana polja) } } ali { napaka } (prva napaka).
function preveriUrlPolja(polja, stare) {
  const vrednosti = {};
  for (const [ime, surova, opcije] of polja) {
    const r = preveriUrl(surova, ime, { ...opcije, stara: stare ? stare[ime] : undefined });
    if (r.napaka) return { napaka: r.napaka };
    if (r.vrednost !== undefined) vrednosti[ime] = r.vrednost;
  }
  return { vrednosti };
}

module.exports = { preveriUrl, preveriUrlPolja, NAJVEC_DOLZINA_URL };
