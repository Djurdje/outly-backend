"use strict";
/**
 * Filter neprimernih uporabniških imen (outly-backend#216 N9; Apple App Review 1.2: »a method for filtering
 * objectionable material from being posted to the app«). Uporablja ga SAMO `index.js` na poteh, kjer ime izbere
 * uporabnik sam: PATCH /me (username) in predlogImena() (user_metadata.username ob prvem klicu po registraciji).
 *
 * Namen je ujeti OČITNO, ne cenzurirati. Zato je seznam kratek, primerjava pa previdna:
 *   - ime se normalizira: male črke, brez diakritike, `_` in nepomenjene števke odpadejo, števke namesto črk se
 *     preslikajo (0->o 1->i 3->e 4->a 5->s 7->t), ponovitve 3+ iste črke se skrčijo (»fuuuck«), dvojni samoglasniki
 *     se skrčijo (»fuuck«, samo za podnize);
 *   - PODNIZ: koren (>= 4 črke) je prepovedan kjerkoli v imenu (»bigfucker«);
 *   - CELO: kratek koren (<= 3 črke) ali dvoumen koren je prepoveden samo, če je CELO ime (po normalizaciji, tudi
 *     brez števk na začetku/koncu: »ass69«). Tako »classic«, »passage«, »Hancock«, »Dickens«, »Sussex« ostanejo;
 *   - SPREJETO: znane nedolžne besede, ki vsebujejo koren iz PODNIZ (»Scunthorpe«, »badminton«), se pred iskanjem
 *     izrežejo.
 * Vzdrževanje: nov koren dodaj v ustrezen seznam (male črke, brez diakritike, brez števk). Za vsak dodan koren
 * dopiši v `_testi/test_prepovedana_imena.js` en zavrnjen primer in, če je mogoč lažen zadetek, en sprejet.
 * Obstoječa imena v bazi se NE preverjajo (pravilo velja za nova imena in spremembe).
 *
 * Seznam NE pokriva slik/avatarjev in prostega besedila (opisi klubov, dogodkov): zanje veljata Report + admin pregled (I30).
 */

// Prepovedano kjerkoli v imenu (>= 4 črke).
const PODNIZ = [
  // angleško
  "fuck", "shit", "bitch", "cunt", "asshole", "arsehole", "dickhead", "pussy", "whore", "slut", "wanker", "bollocks",
  "cocksuck", "blowjob", "handjob", "jerkoff", "cumshot", "dildo", "porn", "nigger", "nigga", "faggot", "tranny",
  "shemale", "wetback", "towelhead", "raghead", "hitler", "siegheil", "whitepower", "pedophile", "paedophile",
  "molester", "killyourself", "incest",
  // slovensko, hrvaško, srbsko
  "kurac", "kurca", "kurcina", "kurcev", "kurva", "kurvi", "kurvin", "kurba", "pizd", "jebem", "jebes", "jebi",
  "jebat", "jebac", "jebote", "govn", "sranje", "kreten", "idiot", "cigan", "cefur", "balija", "siptar",
  "pederast", "pedofil",
  // zavajajoča imena (izdajanje za Outly ali njegovo ekipo)
  "admin", "administrator", "outly", "moderator", "helpdesk",
];

// Prepovedano samo kot CELO ime (kratki ali dvoumni koreni).
const CELO = [
  // angleško
  "ass", "arse", "anus", "anal", "cum", "sex", "tit", "tits", "dick", "cock", "penis", "vagina", "piss", "twat", "wank",
  "fag", "fags", "kike", "spic", "chink", "gook", "coon", "paki", "beaner", "retard", "retarded", "rape", "rapes",
  "rapist", "nazi", "nazis", "kkk", "kys", "pedo", "paedo",
  // slovensko, hrvaško, srbsko
  "picka", "debil",
  // zavajajoča imena
  "support", "official", "mod", "mods", "staff", "team", "help", "security", "system", "verified", "root", "ceo",
];

// Nedolžne besede, ki vsebujejo koren iz PODNIZ; izrežejo se pred iskanjem.
const SPREJETO = [
  "scunthorpe", "penistone", "badminton", "padmini", "administrac", "outlying", "pussycat", "slutsky", "niggard", "shiitake",
];

const LEET = { 0: "o", 1: "i", 3: "e", 4: "a", 5: "s", 7: "t" };

const zdruziPonovitve = (s) => s.replace(/(.)\1{2,}/g, "$1");        // fuuuck -> fuck
const zdruziSamoglasnike = (s) => s.replace(/([aeiou])\1+/g, "$1");   // fuuck -> fuck

function osnova(ime) {
  return String(ime).normalize("NFKD").replace(/[̀-ͯ]/g, "").toLowerCase()
    .replace(/đ/g, "d").replace(/ß/g, "ss");
}

// Različice imena za primerjavo. celo: brez skrčenja samoglasnikov (»coon« bi sicer postal »con«).
function razlicice(ime) {
  const o = osnova(ime);
  const leet = (c) => LEET[c] || c;
  const A = o.replace(/[0-9]/g, leet).replace(/[^a-z]/g, "");            // števke kot črke
  const B = o.replace(/[^a-z]/g, "");                                     // števke odpadejo
  const C = o.replace(/^[0-9_]+|[0-9_]+$/g, "").replace(/[0-9]/g, leet).replace(/[^a-z]/g, "");   // brez števk na robu: »nazi_1488«
  const celo = [...new Set([A, B, C].map(zdruziPonovitve))];
  const podniz = [...new Set([...celo, ...celo.map(zdruziSamoglasnike)])];
  return { celo, podniz };
}

const SPREJETO_RE = new RegExp([...new Set([...SPREJETO, ...SPREJETO.map(zdruziSamoglasnike)])].join("|"), "g");
const CELO_MNOZICA = new Set(CELO);

/** true, če je ime očitno neprimerno ali zavajajoče. Ne vrže izjeme (null/prazno -> false). */
function jePrepovedanoIme(ime) {
  if (ime === null || ime === undefined) return false;
  const { celo, podniz } = razlicice(ime);
  if (celo.some((c) => c && CELO_MNOZICA.has(c))) return true;
  return podniz.some((c) => {
    const s = c.replace(SPREJETO_RE, ".");
    return PODNIZ.some((k) => s.includes(k));
  });
}

module.exports = { jePrepovedanoIme, PODNIZ, CELO, SPREJETO };
