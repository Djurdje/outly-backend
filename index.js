const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const crypto = require("crypto");
const net = require("net");
const { Resend } = require("resend");
const { qrPng, pdfVstopnice } = require("./vstopnica_priloge");   // QR (PNG, vgrajen v mail) in PDF vstopnice (priloga); migracija 034
const path = require("path");
// Express 4 ne ujame zavrnjenih obljub asinhronih rocnikov: neujet `await pool.connect()` je sesul CEL proces (issue #129).
// Ovoj (asinhroni_rocniki.js) zavrnitev preusmeri v next(err); napakaRocnik na koncu datoteke jo prevede v 503/500.
const { namestiAsinhroniOvoj, napakaRocnik } = require("./asinhroni_rocniki");
namestiAsinhroniOvoj();

const app = express();
// Render stoji za proxyjem. Brez tega je req.ip naslov proxyja in bi
// omejevanje veljalo za vse uporabnike skupaj.
app.set("trust proxy", 1);

// CORS: allowedHeaders namenoma ni nastavljen - paket `cors` tedaj ponovi glave iz preflighta (Access-Control-Request-Headers),
// zato brskalnik sme poslati Authorization, X-Outly-Club in Idempotency-Key (test_idempotenca.js to preveri).
// exposedHeaders: brez tega JavaScript v brskalniku Retry-After (503/429/409) NE vidi; Idempotent-Replayed pove, da je odgovor ponovitev.
app.use(cors({ exposedHeaders: ["Retry-After", "Idempotent-Replayed"] }));

// Javni predpomnilnik (issue #114, invarianta I17): kratek predpomnilnik ze serializiranih javnih seznamov. TTL v ms
// (JAVNI_PREDPOMNILNIK_MS, privzeto 3000, 0 = izklopljeno), najvec JAVNI_PREDPOMNILNIK_KLJUCEV kljucev (privzeto 300).
const { ustvariPredpomnilnik } = require("./javni_predpomnilnik");
function stevilkaIzOkolja(ime, privzeto, najvec) {
  const surova = process.env[ime];
  if (surova === undefined || surova === "") return privzeto;
  const n = Number(surova);
  if (!Number.isFinite(n) || n < 0) { console.error(`[okolje] ${ime}="${surova}" ni veljavno, uporabljam ${privzeto}`); return privzeto; }
  return Math.min(Math.floor(n), najvec);
}
const javniPredpomnilnik = ustvariPredpomnilnik({
  ttlMs: stevilkaIzOkolja("JAVNI_PREDPOMNILNIK_MS", 3000, 60000),
  najvecKljucev: stevilkaIzOkolja("JAVNI_PREDPOMNILNIK_KLJUCEV", 300, 5000),
  // Obviselo poizvedbo vodje kljuc spusti po tem casu (ms); cakajoci poskusijo sami. 0 = privzeto.
  cakanjeMs: stevilkaIzOkolja("JAVNI_PREDPOMNILNIK_CAKANJE_MS", 8000, 60000) || 8000,
});
// Dnevnik stevcev (brez osebnih podatkov) na minuto, samo ce je bilo kaj prometa: po deployu vidno v Render logih.
setInterval(() => {
  const p = javniPredpomnilnik.porocilo();
  if (p.zadetki + p.zgresitve + p.zdruzeno + p.razveljavitve > 0) {
    console.log(`[predpomnilnik] 60 s: zadetki=${p.zadetki} zgresitve=${p.zgresitve} zdruzeno=${p.zdruzeno} razveljavitve=${p.razveljavitve} izpodrivi=${p.izpodrivi} casovneMeje=${p.casovneMeje} kljucev=${p.kljucev}`);
  }
}, 60 * 1000).unref();
// Vsak zapis v tem procesu izprazni predpomnilnik; izjeme so pogosti zapisi, ki javnih seznamov ne spremenijo.
app.use(javniPredpomnilnik.razveljaviOdPisanja([
  { metoda: "POST", pot: /^\/views$/ },
  { metoda: "POST", pot: /^\/business\/tickets\/scan(-batch)?$/ },
  { metoda: "POST", pot: /^\/me\/(club-events|tickets\/received)\/[^/]+\/seen$/ },
  { metoda: "POST", pot: /^\/uploads\/cloudinary-signature$/ },
  // Zapisi, ki ne vplivajo na nobeno polje predpomnjenih odgovorov (dogodek: stolpci events + sold_count iz orders +
  // interested_count + VIP; klub: stolpci clubs + followers_count). Preverjeno po tabelah: users, friendships,
  // friend_requests, event_favorites, ticket_transfers/tickets. NE sem: interest, follow (stevca), nakupi, DELETE /me.
  { metoda: "PATCH", pot: /^\/me(\/avatar)?$/ },
  { metoda: "POST", pot: /^\/me\/friends\/requests(\/\d+\/(accept|decline))?$/ },
  { metoda: "DELETE", pot: /^\/me\/friends\/(requests\/)?\d+$/ },
  { metoda: "PUT", pot: /^\/me\/favorites\/\d+$/ },
  { metoda: "DELETE", pot: /^\/me\/favorites\/\d+$/ },
  { metoda: "POST", pot: /^\/tickets\/\d+\/transfer$/ },
]));
// Privzeta omejitev telesa (100 kB) povsod, razen pri paketu skenov brez povezave (do 500 elementov, ima svoj razčlenjevalnik).
// Stripe webhook rabi SUROVO telo (podpis se preverja nad bajti), zato ga JSON razclenjevalnik preskoci.
const jsonPrivzeti = express.json();
app.use((req, res, next) => (req.path === "/business/tickets/scan-batch" || req.path === "/stripe/webhook" ? next() : jsonPrivzeti(req, res, next)));

// BIGINT (OID 20) pride iz pg kot niz ("1"); orders.id in tickets.id sta BIGSERIAL
// in aplikacija ju dekodira kot Int. Vrednosti so daleč pod 2^53, zato je varno.
const pgTipi = require("pg").types;
pgTipi.setTypeParser(20, (v) => (v === null ? null : parseInt(v, 10)));

// Celo stevilo iz okolja z varnim privzetkom (neveljavna ali izven mej -> privzeto).
function okoljeCelo(ime, privzeto, min, max) {
  const v = Number.parseInt(process.env[ime], 10);
  return Number.isInteger(v) && v >= min && v <= max ? v : privzeto;
}
const PG_POOL_MAX = okoljeCelo("PG_POOL_MAX", 10, 1, 100);            // glavni pool (vse poti razen skena)
const PG_SKEN_POOL_MAX = okoljeCelo("PG_SKEN_POOL_MAX", 3, 1, 20);    // loceni pool samo za sken na vratih
const PG_CONNECT_TIMEOUT_MS = okoljeCelo("PG_CONNECT_TIMEOUT_MS", 10000, 100, 60000);
// Sken: kratek rok (telefon ob 503 hitro preklopi na preverjanje brez povezave), ne 10 s.
const PG_SKEN_CONNECT_TIMEOUT_MS = okoljeCelo("PG_SKEN_CONNECT_TIMEOUT_MS", 2500, 100, 60000);

function novPool(max, connectMs, dodatno = {}) {
  const p = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL?.includes("localhost") ? false : { rejectUnauthorized: false },
    max,
    // Varovalka: če zahtevek čaka na prosto povezavo (pool je zaseden ali se je zaklenil), dobi napako
    // namesto večnega čakanja. Brez tega bi en hrošč tipa "pool.query med držanjem odjemalca" obesil cel strežnik.
    connectionTimeoutMillis: connectMs,
    ...dodatno,
  });
  // Baza lahko prekine povezavo, ki jo pool drzi (vzdrzevanje ali ponovni zagon baze na Renderju, izpad omrezja).
  // node-postgres odda 'error' na poolu (mirujoca povezava) oziroma na odjemalcu (izposojena povezava); brez
  // poslusalca je to "Unhandled 'error' event" in CEL proces pade (tudi skeniranje na vratih, nakupi).
  // Pokvarjenega odjemalca pool sam zavrze in ob naslednjem zahtevku odpre novega; mi samo zapisemo v dnevnik.
  // Poslusalec na vsakem odjemalcu pokrije tudi izposojene povezave (transakcije v potekah), ne le mirujoce.
  p.on("error", (e) => console.error("[pool] mirujoca povezava s bazo prekinjena:", e && e.message));
  p.on("connect", (odjemalec) => {
    odjemalec.on("error", (e) => console.error("[pool] povezava s bazo prekinjena:", e && e.message));
  });
  return p;
}
const pool = novPool(PG_POOL_MAX, PG_CONNECT_TIMEOUT_MS);
// Sken vstopnic na vratih ne sme nikoli cakati v vrsti za drugim prometom (nakupi, branje seznamov): ima svoj majhen
// pool, ki ga uporabljajo SAMO POST /business/tickets/scan, scan-batch, GET .../scan-list in scan-key, vkljucno
// z requireAuthSken / requireClubSken (iskanje uporabnika in kluba gre prek istega poola). Issue #89.
const skenPool = novPool(PG_SKEN_POOL_MAX, PG_SKEN_CONNECT_TIMEOUT_MS);
// GET /healthz (Renderjev Health Check Path) ima LASTEN pool z eno povezavo: ob navali nakupov je glavni pool zaseden, zdravje
// v njegovi vrsti ne dobi povezave v roku, vrne 503 in Render instanco ponovno zazene - ravno med navalom (issue #117).
// Ena povezava je dovolj (en SELECT 1 naenkrat; ostali zahtevki za zdravje cakajo kratek rok) in steje proti max_connections
// baze (glej .env.example). Kratka roka: baza, ki ne odgovori v ~2 s, je za zdravje res nedosegljiva.
// `query_timeout` je ODJEMALSKI rok: ce povezava obvisi (polodprt TCP, baza je ne zapre), `statement_timeout` na strezniku
// nikoli ne steče; ob izteku pg poizvedbo zavrne, pool.query pa povezavo UNICI (release(err)), zato naslednji klic dobi novo.
// Brez tega bi edina povezava obvisela za vedno in /healthz bi ostal 503 tudi po okrevanju (pregled PR #127).
const zdraviPool = novPool(1, 2000, { statement_timeout: 2500, query_timeout: 2500, idleTimeoutMillis: 30000 });

// ZASTOJ poola (puscanje povezav, obvisele transakcije) JE nezdrava instanca: restart ga popravi. PREOBREMENITEV ni: ob dolgem
// navalu pool normalno krozi (povezave se ves cas vracajo), cakalna vrsta je lahko vseskozi neprazna - restart sredi navala
// bi bil ista skoda kot #117 (pregled PR #127: simulacija max 4, 11 s od 12 s "zasicenosti" pri 936 uspesnih poizvedbah).
// Zato signal NAPREDKA, ne dolzina vrste: pool.on("release") zapise `zadnjiNapredek`. Zastoj = vse povezave poola izposojene
// (totalCount >= max IN idleCount == 0; ni pomembno, ali kdo caka - tudi pool brez prometa z vsemi puscenimi povezavami je
// pokvarjen) IN od zacetka tega stanja ter od zadnje vrnjene povezave je minilo vec kot ZDRAVJE_ZASICEN_MS. Krozece povezave
// (release vsakih nekaj ms) casovnik vedno ponastavijo. Privzeto 60 s: nakupna transakcija ima lock/statement timeout 10 s,
// poizvedbe so kratke, zato 60 s brez ENE vrnjene povezave pri vseh izposojenih ni nobena legitimna obremenitev; hkrati je
// dovolj dolgo, da kratek zastoj (restart baze, izpad omrezja z okrevanjem) ne sprozi restarta. Vzorci: vsakih 500 ms
// in ob vsakem klicu /healthz. Nadzorovana sta glavni pool IN skenPool (sken na vratih je najkriticnejsa pot; sken je
// ena kratka poizvedba, zato zastoj v njem pomeni puscanje in samo restart povrne sken; cena je en kratek restart, med
// katerim telefon preklopi na sken brez povezave).
const ZDRAVJE_ZASICEN_MS = okoljeCelo("ZDRAVJE_ZASICEN_MS", 60000, 100, 3600000);
function nadzorZastoja(p, max) {
  const st = { zadnjiNapredek: Date.now(), zasicenOd: null };
  p.on("release", () => { st.zadnjiNapredek = Date.now(); });
  // Vrne ms, odkar pool ni napredoval, medtem ko so vse povezave izposojene; 0, ce pool ni zasicen.
  st.vzorci = () => {
    const zasicen = p.totalCount >= max && p.idleCount === 0;
    if (!zasicen) { st.zasicenOd = null; return 0; }
    if (st.zasicenOd === null) st.zasicenOd = Date.now();
    return Date.now() - Math.max(st.zasicenOd, st.zadnjiNapredek);
  };
  return st;
}
const zastojGlavni = nadzorZastoja(pool, PG_POOL_MAX);
const zastojSken = nadzorZastoja(skenPool, PG_SKEN_POOL_MAX);
setInterval(() => { zastojGlavni.vzorci(); zastojSken.vzorci(); }, 500).unref();

// Hkratnost nakupov (issue #89, obremenitveni test). Nakup drzi povezavo z bazo od BEGIN do COMMIT, vsi nakupi
// istega dogodka pa se v sprozilcu rezerviraj_zalogo() vrstijo na isti zaklenjeni vrstici. Ob navali (300 kupcev
// naenkrat) bi zato vsi zahtevki zasedli glavni pool in branje bi cakalo za celo navalo. Semafor spusti v
// transakcijo najvec NAKUP_VZPOREDNO nakupov hkrati, ostali cakajo v pomnilniku (brez povezave). Vrstni red je
// FIFO; cakanje je omejeno (NAKUP_CAKANJE_MS, nato 503 Retry-After). Cakalec, ki ga odjemalec med cakanjem
// prekine, takoj izstopi iz vrste (sicer bi "duh" kupil vstopnico, ki je kupec nikoli ne vidi).
const NAKUP_VZPOREDNO = okoljeCelo("NAKUP_VZPOREDNO", 4, 1, 100);
const NAKUP_CAKANJE_MS = okoljeCelo("NAKUP_CAKANJE_MS", 15000, 10, 120000);
// Zgornja meja za zaklep in stavek v nakupni transakciji: obvisela transakcija ne sme drzati dovoljenja za vedno.
const NAKUP_DB_TIMEOUT_MS = okoljeCelo("NAKUP_DB_TIMEOUT_MS", 10000, 100, 120000);
// Kratek spomin "razprodano": zavrne 409 PRED semaforjem, da razprodan hit ne zadrzuje kupcev drugih klubov
// v skupni FIFO vrsti. Laz je omejena na NAKUP_RAZPRODANO_MS (0 = izklopljeno); sprememba capacity ga takoj pozabi.
const NAKUP_RAZPRODANO_MS = okoljeCelo("NAKUP_RAZPRODANO_MS", 3000, 0, 60000);
const nakupVrsta = []; let nakupAktivnih = 0;
// Vrne "ok" (dovoljenje pridobljeno), "cas" (cakanje potekla) ali "preklic" (odjemalec je odsel med cakanjem).
function nakupVstopi(res) {
  if (res.destroyed) return Promise.resolve("preklic");
  if (nakupAktivnih < NAKUP_VZPOREDNO) { nakupAktivnih++; return Promise.resolve("ok"); }
  return new Promise((resolve) => {
    const cak = {};
    const izVrste = () => { const i = nakupVrsta.indexOf(cak); if (i >= 0) nakupVrsta.splice(i, 1); };
    cak.pocisti = () => { clearTimeout(cak.timer); res.off("close", cak.naZaprtje); };
    cak.naZaprtje = () => { izVrste(); cak.pocisti(); resolve("preklic"); };
    cak.timer = setTimeout(() => { izVrste(); cak.pocisti(); resolve("cas"); }, NAKUP_CAKANJE_MS);
    cak.dodeli = () => { cak.pocisti(); resolve("ok"); };
    res.once("close", cak.naZaprtje);
    nakupVrsta.push(cak);
  });
}
function nakupIzstopi() {
  const naslednji = nakupVrsta.shift();
  if (naslednji) naslednji.dodeli(); else nakupAktivnih--;
}
// Pridobi dovoljenje za nakup. true = dovoljenje drzimo (klicatelj MORA poklicati nakupIzstopi()); false = odgovor je
// ze poslan (503) ali odjemalca ni vec, dovoljenja ne drzimo.
async function nakupDovoljenje(req, res) {
  const r = await nakupVstopi(res);
  if (r === "cas") { res.status(503).set("Retry-After", "5").send("Too many purchases at once. Please try again."); return false; }
  if (r === "preklic") return false;
  if (req.aborted || res.destroyed || res.writableEnded) { nakupIzstopi(); return false; }   // prekinjeno tik pred dodelitvijo
  return true;
}
const NAKUP_ZASEDEN = "Server busy. Please try again.";
function napakaZasedenosti(err) { return !!err && (err.code === "55P03" || err.code === "57014"); }   // lock_timeout / statement_timeout
// Middleware PRED omeji(): razprodan dogodek/miza dobi 409 brez porabe nakupnih poskusov (20/uro na IP) in brez semaforja.
function zavrniRazprodano(req, res, next) {
  const id = celoId(req.params.id);
  if (id && razprodanoJe("v:" + id)) return res.status(409).send("Only 0 tickets left.");
  next();
}
function zavrniRazprodanoMizo(req, res, next) {
  const id = vipId(req.params.id), mizaId = vipId(req.params.tableId);
  if (id && mizaId && razprodanoJe("m:" + id + ":" + mizaId)) return res.status(409).send("This table is already booked.");
  next();
}
// Zacetek nakupne transakcije z zgornjo mejo za zaklep in stavek (glej NAKUP_DB_TIMEOUT_MS).
function nakupZacni(c) {
  return c.query(`BEGIN; SET LOCAL lock_timeout = ${NAKUP_DB_TIMEOUT_MS}; SET LOCAL statement_timeout = ${NAKUP_DB_TIMEOUT_MS}`);
}
const razprodano = new Map();   // kljuc -> do kdaj (ms). "v:<dogodek>" vstopnice, "m:<dogodek>:<miza>" VIP miza.
function razprodanoJe(k) {
  const do_ = razprodano.get(k);
  if (do_ === undefined) return false;
  if (do_ <= Date.now()) { razprodano.delete(k); return false; }
  return true;
}
function razprodanoOznaci(k) {
  if (!NAKUP_RAZPRODANO_MS) return;
  if (razprodano.size >= 5000) {
    const zdaj = Date.now();
    for (const [kk, v] of razprodano) if (v <= zdaj) razprodano.delete(kk);
    if (razprodano.size >= 5000) return;
  }
  razprodano.set(k, Date.now() + NAKUP_RAZPRODANO_MS);
}
function razprodanoPozabi(k) { razprodano.delete(k); }

// Resend init
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

// ---------------------------
// Lastna prijava (bcrypt + HS256 JWT, verifikacijske kode, osveževalni žetoni)
// je bila odstranjena 11. 9. 2026: identiteta je Supabase Auth (glej spodaj).
// Tabele refresh_tokens, email_verification_codes in password_reset_codes
// ostanejo v bazi prazne/nedotaknjene do čistilne migracije.
// ---------------------------

// ---------------------------
// Omejevanje pogostosti (S-02, invarianta I15)
// ---------------------------
// Stevec poskusov je v PostgreSQL (tabela omejitve, migracija 027), zato meja velja cez vse instance backenda
// in preživi restart/deploy (issue #24). En poskus = en kratek INSERT ... ON CONFLICT DO UPDATE ... RETURNING
// (atomicen, brez transakcije in brez locenega branja); okno se zacne ob prvem poskusu in traja oknoSekund,
// po izteku se stevec ponastavi - enako kot prej v pomnilniku. Racun je poleg tega zascisten se z zaklepom
// v tabeli users, ki NI odvisen od IP naslova.
//
// Zmogljivost: omejevalnik ima LASTEN majhen pool (OMEJEVALNIK_POOL_MAX, privzeto 2) s kratkimi casovnimi
// omejitvami, zato ne zaseda povezav glavnega poola in ne caka za dolgimi poizvedbami (npr. izvoz). Ko je
// kljuc prekoracen, se "blokiran do" zapomni se v pomnilniku procesa (negativni predpomnilnik): napadalec, ki
// bije v ze blokiran kljuc, baze ne obremenjuje vec. DB ostane vir resnice - predpomnilnik le skrajsa pot do
// 429 in poteče najkasneje ob koncu okna.
//
// Okvara omejevalnika (baza nedosegljiva, poizvedba pocasna/napacna) - odlocitev PO POTI (priNapaki):
//   "odpri" (fail-open)  - ogled, iskanje: majhna skoda ob izpadu (steje se ogled, isci uporabnike), poleg tega pot
//                          brez baze tako ali tako ne naredi nic koristnega; ne smemo pa jih zavreti zaradi
//                          pomocnega sistema.
//   "lokalno" (degradirano) - nakup (obe poti), prenos: ob okvari velja STARO vedenje, stevec v pomnilniku procesa
//                          (iste meje, brez skupnega stanja). Fail-closed bi tu ob navalu (zasicen/pocasen
//                          pool omejevalnika) zavrnil kupce, ceprav glavni pool dela; fail-open bi pustil
//                          neomejeno rezerviranje zaloge. Lokalni stevec je vmes: zalogo se varuje, prodaja tece.
//   "zapri" (fail-closed, privzeto) - brisanje racuna, prosnje (ustvarjalec, prijatelji): nepovraten izbris in
//                          posiljanje mailov; tu je 503 + Retry-After bolje kot neomejeno ali lokalno stetje.
// Skeniranje vstopnic omejevalnika NIMA na poti (test_omejevalnik.js to preverja) - ne more pasti zaradi njega.
const OMEJEVALNIK_CISCENJE_MS = Number(process.env.OMEJEVALNIK_CISCENJE_MS) || 2 * 60 * 1000;
const limiterPool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("localhost") ? false : { rejectUnauthorized: false },
  max: Number(process.env.OMEJEVALNIK_POOL_MAX) || 2,
  // Hitro odpove ali odpade: obvisel omejevalnik ne sme zadrzati zahtevka dlje kot ~3,5 s (nato velja priNapaki).
  // Povezava je z Renderjevo bazo v isti regiji (TLS ~deset ms), zato 2 s za vzpostavitev ni pretesno.
  connectionTimeoutMillis: 2000,
  statement_timeout: 1500,
  idleTimeoutMillis: 30000,
});
limiterPool.on("error", (e) => console.error("[omejevalnik] mirujoca povezava s bazo prekinjena:", e && e.message));
limiterPool.on("connect", (odjemalec) => {
  odjemalec.on("error", (e) => console.error("[omejevalnik] povezava s bazo prekinjena:", e && e.message));
});

// Kljuc v bazi = HMAC-SHA256(pot:najvec:okno:IP) s kljucem, izpeljanim (HKDF) iz QR_SECRET/JWT_SECRET: IP je osebni podatek,
// golo sha256 pa bi se z naštevanjem vseh 2^32 IPv4 naslovov razbilo v minutah. Ista skrivnost je na vseh instancah
// istega servisa (okolje na Renderju), zato se kljuci ujemajo; zamenjava skrivnosti enkrat ponastavi meje.
// Brez skrivnosti (samo lokalni razvoj) velja stalen niz - tam IP-ji niso realni.
// V ključ sta všteta tudi meja in okno: dve poti z istim imenom, a drugačno mejo, nikoli ne delita vrstice (druga bi lahko
// števec "zmanjšala" z LEAST(...) ali podedovala tujo blokado), v bazi pa števec zato nikoli ne pade, dokler okno teče.
// IP: IPv4 polno, IPv6 na predponi /64 (en uporabnik/priključek dobi cel /64, sicer bi mejo obšel s sosednjimi naslovi).
let omejevalnikHmac = null;
function predponaIp(ip) {
  if (typeof ip !== "string" || !ip) return String(ip);
  const preslikan = ip.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
  if (preslikan) return preslikan[1];
  const brezCone = ip.split("%")[0];
  if (!net.isIPv6(brezCone) || brezCone.includes(".")) return ip;
  const deli = brezCone.split("::");
  const levo = deli[0] ? deli[0].split(":") : [];
  const desno = deli.length > 1 && deli[1] ? deli[1].split(":") : [];
  const sredina = deli.length > 1 ? Array(Math.max(0, 8 - levo.length - desno.length)).fill("0") : [];
  const hextets = [...levo, ...sredina, ...desno].map((h) => h.toLowerCase().padStart(4, "0"));
  return hextets.slice(0, 4).join(":") + "::/64";
}
function kljucOmejitve(pot, najvec, oknoSekund, ip) {
  if (!omejevalnikHmac) {
    omejevalnikHmac = Buffer.from(crypto.hkdfSync("sha256", qrSkrivnost() || "outly-brez-skrivnosti", "", "outly-omejevalnik-v1", 32));
  }
  return crypto.createHmac("sha256", omejevalnikHmac).update(`${pot}:${najvec}:${oknoSekund}:${predponaIp(ip)}`).digest("hex").slice(0, 32);
}

// Negativni predpomnilnik: kljuc -> ms (Date.now), do katerega je kljuc zagotovo blokiran.
const blokiraniKljuci = new Map();
const BLOKIRANI_NAJVEC = 50000;
// Lokalni stevec (priNapaki "lokalno"): staro vedenje ob okvari omejevalnika. id -> { n, doKdaj }.
const lokalniStevci = new Map();
const LOKALNI_NAJVEC = 100000;
setInterval(() => {
  const zdaj = Date.now();
  for (const [k, doKdaj] of blokiraniKljuci) if (doKdaj <= zdaj) blokiraniKljuci.delete(k);
  for (const [k, v] of lokalniStevci) if (v.doKdaj <= zdaj) lokalniStevci.delete(k);
}, 60 * 1000).unref();
// Vrne 0 (v mejah) ali sekunde do konca okna (prekoraceno).
function lokalnoPreseglo(id, najvec, oknoSekund) {
  const zdaj = Date.now();
  const v = lokalniStevci.get(id);
  if (!v || v.doKdaj <= zdaj) {
    if (v || lokalniStevci.size < LOKALNI_NAJVEC) lokalniStevci.set(id, { n: 1, doKdaj: zdaj + oknoSekund * 1000 });
    return 0;
  }
  v.n += 1;
  return v.n > najvec ? Math.max(1, Math.ceil((v.doKdaj - zdaj) / 1000)) : 0;
}

// Dnevnik okvar omejevalnika: najvec ena vrstica na 10 s (sicer bi izpad zalil dnevnik z 1000 vrsticami/s).
let omejevalnikZadnjiDnevnik = 0, omejevalnikIzpuscenih = 0;
function dnevnikOmejevalnika(e) {
  omejevalnikIzpuscenih++;
  const zdaj = Date.now();
  if (zdaj - omejevalnikZadnjiDnevnik < 10000) return;
  console.error(`[omejevalnik] poizvedba ni uspela (${omejevalnikIzpuscenih}x od zadnjega zapisa): ${e && e.message}`);
  omejevalnikZadnjiDnevnik = zdaj; omejevalnikIzpuscenih = 0;
}

// Atomicen korak: nov kljuc -> stevec 1; kljuc z veljavnim oknom -> stevec + 1 (najvec do najvec + 1, da se int ne
// prekorači, tudi ce kdo bije dlje casa); kljuc z izteklim oknom -> stevec 1 in novo okno. preostalo = sekunde do
// konca okna, izracunane v bazi (ura procesa in baze se lahko razlikujeta).
const OMEJEVALNIK_SQL = `
  INSERT INTO omejitve AS o (kljuc, okno_do, stevec)
  VALUES ($1, now() + make_interval(secs => $2::double precision), 1)
  ON CONFLICT (kljuc) DO UPDATE SET
    stevec  = CASE WHEN o.okno_do <= now() THEN 1 ELSE LEAST(o.stevec + 1, $3::int + 1) END,
    okno_do = CASE WHEN o.okno_do <= now() THEN now() + make_interval(secs => $2::double precision) ELSE o.okno_do END
  RETURNING stevec, GREATEST(1, CEIL(EXTRACT(EPOCH FROM (o.okno_do - now()))))::int AS preostalo`;

function omeji({ kljuc, najvec, oknoSekund, priNapaki = "zapri" }) {
  return async (req, res, next) => {
    const id = kljucOmejitve(kljuc, najvec, oknoSekund, req.ip);
    const zdaj = Date.now();
    const blokiranDo = blokiraniKljuci.get(id);
    if (blokiranDo && blokiranDo > zdaj) {
      res.set("Retry-After", String(Math.max(1, Math.ceil((blokiranDo - zdaj) / 1000))));
      return res.status(429).send("Too many requests. Please try again later.");
    }

    let vrstica;
    try {
      vrstica = (await limiterPool.query(OMEJEVALNIK_SQL, [id, oknoSekund, najvec])).rows[0];
    } catch (e) {
      dnevnikOmejevalnika(e);
      if (priNapaki === "odpri") return next();
      if (priNapaki === "lokalno") {
        const preostaloLokalno = lokalnoPreseglo(id, najvec, oknoSekund);
        if (!preostaloLokalno) return next();
        res.set("Retry-After", String(preostaloLokalno));
        return res.status(429).send("Too many requests. Please try again later.");
      }
      res.set("Retry-After", "5");
      return res.status(503).send("Service temporarily unavailable. Please try again shortly.");
    }

    if (vrstica.stevec > najvec) {
      if (vrstica.preostalo > 1 && blokiraniKljuci.size < BLOKIRANI_NAJVEC) {
        blokiraniKljuci.set(id, Date.now() + (vrstica.preostalo - 1) * 1000);
      }
      res.set("Retry-After", String(vrstica.preostalo));
      return res.status(429).send("Too many requests. Please try again later.");
    }
    next();
  };
}

// Ciscenje izteklih vrstic: vsaka instanca na svoji periodi (zamik ob zagonu je nakljucen), brez cron storitve.
// Iztekla vrstica je ze nepomembna (naslednji poskus ji ponastavi okno), zato brisanje ne more spremeniti meje.
// Zunanji pogoj okno_do < now() se pri sočasni posodobitvi vrstice (reset okna) ponovno preveri (READ COMMITTED) -
// sveze ponastavljena vrstica se ne izbrise. Serija 5000, da en klic ne zadrzi ključavnic dolgo; dokler serija izbrise
// polnih 5000, se ponovi (najvec 20 s na zagon), da poplava kljucev (botnet, mnogo IPv6 predpon) ne raste v nedogled.
const CISCENJE_SERIJA = 5000;
let ciscenjeTece = false;
async function pocistiOmejitve() {
  if (ciscenjeTece) return;
  ciscenjeTece = true;
  const zacetek = Date.now();
  try {
    let r;
    do {
      r = await limiterPool.query(
        `DELETE FROM omejitve WHERE okno_do < now()
           AND kljuc IN (SELECT kljuc FROM omejitve WHERE okno_do < now() ORDER BY okno_do LIMIT ${CISCENJE_SERIJA})`
      );
    } while (r.rowCount >= CISCENJE_SERIJA && Date.now() - zacetek < 20000);
  } catch (e) {
    dnevnikOmejevalnika(e);
  } finally {
    ciscenjeTece = false;
  }
}
setTimeout(() => {
  pocistiOmejitve();
  setInterval(pocistiOmejitve, OMEJEVALNIK_CISCENJE_MS).unref();
}, Math.round(Math.random() * Math.min(OMEJEVALNIK_CISCENJE_MS, 60 * 1000))).unref();

// ---------------------------
// Supabase Auth (migracija 010) — edina identiteta aplikacije in spletne strani
// ---------------------------
// Supabase izda ES256 JWT; javni ključ je na /auth/v1/.well-known/jwks.json.
// Preverjamo ga sami z vgrajenim crypto (brez nove odvisnosti): podpis JWT
// pri ES256 je surov r||s (IEEE P1363), ne DER.
// SUPABASE_URL in objavljeni ključ (sb_publishable_…) sta JAVNA podatka — ista
// sta v supabase-config.js na outly.si. Skrivnosti (service_role) tu NI in
// je ne sme biti.
const SUPABASE_URL = (process.env.SUPABASE_URL || "https://zbewqcxnvrwebxonvebx.supabase.co").replace(/\/+$/, "");
const SUPABASE_KEY = process.env.SUPABASE_PUBLISHABLE_KEY || "sb_publishable_NzgXZhG7RGs0mZMjGYtyig_XfOvepXS";
const SUPABASE_ISS = SUPABASE_URL + "/auth/v1";

const jwks = { kljuci: new Map(), nalozeno: 0 };
const JWKS_OSVEZI_MS = 10 * 60 * 1000;

async function naloziJwks(prisilno) {
  const zdaj = Date.now();
  if (!prisilno && jwks.kljuci.size && zdaj - jwks.nalozeno < JWKS_OSVEZI_MS) return;
  // Vrtenje ključa je redko; brez tega bi neveljaven žeton z izmišljenim kid
  // sprožil klic na Supabase ob vsakem poskusu.
  if (prisilno && zdaj - jwks.nalozeno < 60 * 1000) return;
  let novi;
  try {
    const r = await fetch(SUPABASE_ISS + "/.well-known/jwks.json", { signal: AbortSignal.timeout(5000) });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const telo = await r.json();
    novi = new Map();
    for (const k of telo.keys || []) {
      if (k.kty !== "EC" || k.crv !== "P-256" || !k.kid) continue;
      novi.set(k.kid, crypto.createPublicKey({ key: k, format: "jwk" }));
    }
    if (!novi.size) throw new Error("empty");
  } catch (e) {
    // Supabase nedosegljiv: stari ključi ostanejo v uporabi (vrtenje je redko),
    // brez ključev pa klicatelj dobi 503, ne 401 (401 bi aplikacijo odjavil).
    if (jwks.kljuci.size) { jwks.nalozeno = zdaj - JWKS_OSVEZI_MS + 60 * 1000; return; }
    const n = new Error("JWKS " + (e && e.message)); n.jwks = true; throw n;
  }
  jwks.kljuci = novi;
  jwks.nalozeno = zdaj;
}

function b64urlJson(del) {
  return JSON.parse(Buffer.from(del, "base64url").toString("utf8"));
}

// Vrne payload ali vrže napako. Preveri: obliko, alg ES256, kid, podpis,
// izdajatelja, občinstvo 'authenticated', exp/nbf.
async function preveriSupabaseZeton(token) {
  const deli = token.split(".");
  if (deli.length !== 3) throw new Error("oblika");
  const glava = b64urlJson(deli[0]);
  if (glava.alg !== "ES256" || !glava.kid) throw new Error("alg");

  await naloziJwks(false);
  let kljuc = jwks.kljuci.get(glava.kid);
  if (!kljuc) { await naloziJwks(true); kljuc = jwks.kljuci.get(glava.kid); }
  if (!kljuc) throw new Error("kid");

  let ok = false;
  try {
    ok = crypto.verify(
      "sha256",
      Buffer.from(deli[0] + "." + deli[1]),
      { key: kljuc, dsaEncoding: "ieee-p1363" },
      Buffer.from(deli[2], "base64url")
    );
  } catch (_) { ok = false; }
  if (!ok) throw new Error("podpis");

  const p = b64urlJson(deli[1]);
  const zdaj = Math.floor(Date.now() / 1000);
  if (p.iss !== SUPABASE_ISS) throw new Error("iss");
  const aud = Array.isArray(p.aud) ? p.aud : [p.aud];
  if (!aud.includes("authenticated")) throw new Error("aud");
  if (typeof p.exp !== "number" || p.exp <= zdaj) throw new Error("exp");
  if (typeof p.nbf === "number" && p.nbf > zdaj + 60) throw new Error("nbf");
  if (typeof p.sub !== "string" || !/^[0-9a-f-]{36}$/i.test(p.sub)) throw new Error("sub");
  if (typeof p.email !== "string" || !p.email.includes("@")) throw new Error("email");
  if (p.is_anonymous === true) throw new Error("anon");
  return p;
}

// Računi, izbrisani v tej instanci (DELETE /me): Supabasov žeton je brez stanja
// in velja še do ure, zato bi ga ponovljen klic (npr. GET /me v aplikaciji)
// sicer obudil kot prazen nov račun. Ključ = sub, vrednost = exp žetona.
const izbrisaniSub = new Map();
setInterval(() => {
  const zdaj = Math.floor(Date.now() / 1000);
  for (const [k, exp] of izbrisaniSub) if (exp <= zdaj) izbrisaniSub.delete(k);
}, 5 * 60 * 1000).unref();

const POLJA_SEJE = "id, email, username, role";

// Uporabniško ime za novo vrstico: iz user_metadata.username (aplikacija ga
// pošlje ob registraciji), sicer iz dela e-naslova pred @. Pravila kot pri
// PATCH /me: 3–20 znakov, črke/številke/podčrtaj.
function predlogImena(p) {
  const meta = p.user_metadata || {};
  const zeljeno = typeof meta.username === "string" ? meta.username.trim() : "";
  if (/^[a-zA-Z0-9_]{3,20}$/.test(zeljeno)) return zeljeno;
  const osnova = String(p.email).split("@")[0].replace(/[^a-zA-Z0-9_]/g, "").slice(0, 16);
  return (osnova.length >= 3 ? osnova : "user") ;
}

// Lokalna vrstica za Supabasov račun:
//   1. po supabase_uid,
//   2. po e-naslovu (obstoječi račun iz časov lastne prijave → poveže se; Supabase
//      e-naslov potrdi pred izdajo seje, zato je lastništvo naslova dokazano),
//   3. sicer nova vrstica (email_verified = true, brez gesla).
async function uporabnikIzSupabase(p, db = pool) {
  const uid = p.sub.toLowerCase();
  const email = String(p.email).trim().toLowerCase();

  if (izbrisaniSub.has(uid)) throw new Error("izbrisan");

  const r1 = await db.query(`SELECT ${POLJA_SEJE} FROM users WHERE supabase_uid=$1`, [uid]);
  if (r1.rows.length) return r1.rows[0];

  // Povezava po e-naslovu in nov račun samo s POTRJENIM e-naslovom. Supabase
  // ga s "Confirm email" potrdi pred prvo sejo in to zapiše v user_metadata;
  // če bi kdo to nastavitev izklopil, bi sicer vsak lahko prevzel tuj stari
  // račun z vpisom tujega e-naslova.
  if (!(p.user_metadata && p.user_metadata.email_verified === true)) throw new Error("email_unverified");

  const r2 = await db.query(
    `UPDATE users SET supabase_uid=$1, email_verified=true, failed_login_count=0, locked_until=NULL
     WHERE email=$2 AND supabase_uid IS NULL RETURNING ${POLJA_SEJE}`,
    [uid, email]
  );
  if (r2.rows.length) return r2.rows[0];

  const ime = predlogImena(p);
  for (let poskus = 0; poskus < 4; poskus++) {
    const kandidat = poskus === 0 ? ime : `${ime.slice(0, 14)}_${crypto.randomInt(1000, 9999)}`;
    try {
      const r3 = await db.query(
        `INSERT INTO users (email, password_hash, username, email_verified, supabase_uid)
         VALUES ($1, NULL, $2, true, $3) RETURNING ${POLJA_SEJE}`,
        [email, kandidat, uid]
      );
      return r3.rows[0];
    } catch (e) {
      if (e && e.code === "23505") {
        // Isto ime že obstaja → nov poskus s pripono. Isti e-naslov ali uid
        // (tekma dveh prvih klicev) → poišči še enkrat.
        const c = String(e.constraint || "");
        if (c.includes("supabase")) {
          const r4 = await db.query(`SELECT ${POLJA_SEJE} FROM users WHERE supabase_uid=$1`, [uid]);
          if (r4.rows.length) return r4.rows[0];
        }
        if (c.includes("email")) {
          // Vrstica s tem e-naslovom že kaže na drug (star) Supabasov uid —
          // isti lastnik naslova se je pri Supabase registriral znova.
          const r4 = await db.query(
            `UPDATE users SET supabase_uid=$1 WHERE email=$2 RETURNING ${POLJA_SEJE}`, [uid, email]
          );
          if (r4.rows.length) return r4.rows[0];
        }
        continue;
      }
      throw e;
    }
  }
  throw new Error("username");
}

// ---------------------------
// Auth middleware
// ---------------------------
// Sprejme samo Supabasov žeton (ES256). req.user = { userId, email, username,
// role, auth: 'supabase', supabaseToken, supabaseSub, supabaseExp }. Vloga pride
// iz baze ob vsakem klicu (ni v žetonu), zato sprememba vloge velja takoj.
async function razberiUporabnika(token, db = pool) {
  let p;
  try { p = await preveriSupabaseZeton(token); }
  catch (e) {
    if (e && e.jwks) throw e;                         // izpad Supabase JWKS -> 503 (I10)
    const n = new Error("zeton"); n.zeton = true; throw n;   // vsaka napaka pri branju/preverjanju zetona = slab zeton
  }
  const u = await uporabnikIzSupabase(p, db);
  return { userId: u.id, email: u.email, username: u.username, role: u.role, auth: "supabase",
           supabaseToken: token, supabaseSub: p.sub.toLowerCase(), supabaseExp: p.exp };
}

// Skupna logika; `db` je pool, prek katerega gre iskanje uporabnika (glavni pool ali skenPool za poti skena).
// 401 SAMO za znano napako zetona (oblika, podpis, potek, izbrisan racun): aplikacija ob 401 uporabnika odjavi
// (SessionStore). Vse drugo - izpad Supabase, izpad baze, izcrpan pool, prekinjena povezava, kakrsnakoli napaka brez
// kode - je zacasna tezava streznika: 503 + Retry-After, uporabnik ostane prijavljen (invarianta I10).
//
// Vloga `backup` (issue #116, migracija 029) je racun za dnevno varnostno kopijo in sme SAMO GET /admin/api/export.
// Zato je privzeto ZAVRNJENA na vsaki poti, ki gre skozi requireAuth/requireAuthSken (403); edina izjema je izvoz
// (requireAuthIzvoz). Nova pot je tako varna brez dodatnega dela: pozabljen requireRole ne odpre poti racunu backup.
async function requireAuthNa(db, req, res, next, dovoliBackup = false) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).send("Missing token.");
  try {
    req.user = await razberiUporabnika(token, db);
    if (req.user.role === "backup" && !dovoliBackup) return res.status(403).send("Forbidden.");
    return next();
  } catch (err) {
    if (err && err.jwks) {
      console.error(err.message);
      return res.status(503).set("Retry-After", "5").send("Auth service unavailable.");
    }
    if (err && err.message === "email_unverified") return res.status(403).send("Email not verified.");
    if (err && (err.zeton || err.message === "izbrisan")) return res.status(401).send("Invalid token.");
    console.error("[auth] zacasna napaka pri iskanju uporabnika:", err && err.message);
    return res.status(503).set("Retry-After", "5").send("Service temporarily unavailable. Please try again.");
  }
}
function requireAuth(req, res, next) { return requireAuthNa(pool, req, res, next); }
function requireAuthSken(req, res, next) { return requireAuthNa(skenPool, req, res, next); }
// Samo za GET /admin/api/export: spusti tudi vlogo `backup` (requireRole("admin", "backup") nato presoja vlogo).
function requireAuthIzvoz(req, res, next) { return requireAuthNa(pool, req, res, next, true); }

// ---------------------------
// Role middleware
// ---------------------------
function requireRole(...allowed) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).send("Unauthorized.");
    if (!allowed.includes(req.user.role)) return res.status(403).send("Forbidden.");
    next();
  };
}

// ---------------------------
// Klub uporabnika in vloga v njem (migracija 009)
// ---------------------------
// Lastnik: clubs.owner_user_id -> 'owner'. Član ekipe: club_members ->
// 'manager' ali 'doorman'. Vsak uporabnik ima največ en klub.
// Vrne null, če uporabnik nima kluba.
// Od migracije 018 je oseba lahko v vec ekipah: `zeljeni` (glava X-Outly-Club ali ?club_id=)
// izbere klub; brez njega prvo clanstvo (najstarejse), da star odjemalec dela kot prej.
async function klubUporabnika(userId, zeljeni = null, db = pool) {
  const l = await db.query("SELECT id FROM clubs WHERE owner_user_id=$1 ORDER BY id LIMIT 1", [userId]);
  if (l.rows.length && (!zeljeni || Number(l.rows[0].id) === Number(zeljeni))) return { clubId: l.rows[0].id, role: "owner" };
  const m = zeljeni
    ? await db.query("SELECT club_id, role FROM club_members WHERE user_id=$1 AND club_id=$2", [userId, zeljeni])
    : await db.query("SELECT club_id, role FROM club_members WHERE user_id=$1 ORDER BY created_at, id LIMIT 1", [userId]);
  if (m.rows.length) return { clubId: m.rows[0].club_id, role: m.rows[0].role };
  return null;
}

// Vsa clanstva uporabnika (lastnistvo + ekipe) za GET /me `clubs` — aplikacija kaze seznam My Clubs.
async function klubiUporabnika(userId) {
  const r = await pool.query(
    `SELECT c.id AS club_id, c.name AS club_name, c.logo_url AS club_logo_url, 'owner' AS role, 0 AS vrstni
       FROM clubs c WHERE c.owner_user_id = $1
     UNION ALL
     SELECT c.id, c.name, c.logo_url, m.role, 1
       FROM club_members m JOIN clubs c ON c.id = m.club_id WHERE m.user_id = $1
     ORDER BY 5, 1`, [userId]
  );
  return r.rows.map(x => ({ club_id: x.club_id, club_name: x.club_name, club_logo_url: x.club_logo_url || "", role: x.role }));
}

// Klub, ki ga zeli odjemalec: glava X-Outly-Club ali ?club_id= (celo stevilo), sicer null.
function zeljeniKlub(req) {
  const v = req.get("x-outly-club") || (req.query && req.query.club_id) || "";
  return celoId(v);
}

// Middleware za poslovne poti: req.klub = { clubId, role }.
// Brez argumentov spusti vsako vlogo v klubu; z argumenti samo naštete.
// Admin brez lastnega kluba dobi { clubId: null, role: 'admin' } — poti, ki
// rabijo klub, mu vrnejo 404 kot do zdaj; poti za urejanje dogodkov ga spustijo.
// Vratar (doorman) sme SAMO skenirati in gledati vstopnice dogodka.
const INT4_MAX = 2147483647;
const { jeVOknuSkena, SKEN_OKNO_PRED_MS } = require("./sken_okno");   // casovno okno skena (I25)
const { jeNapakaPovezave, odgovoriNaNapako } = require("./napaka_povezave");   // 503 samo za napake povezave/baze, ostalo 500
function requireClubNa(db, vloge) {
  return async (req, res, next) => {
    try {
      if (!req.user) return res.status(401).send("Unauthorized.");
      const zeljeni = zeljeniKlub(req);
      // Izrecno zahtevan klub izven obsega int4 ne obstaja (poizvedba bi sicer padla z 22003 -> 500).
      if (zeljeni !== null && zeljeni > INT4_MAX) return res.status(404).send("Club not found.");
      let k = await klubUporabnika(req.user.userId, zeljeni, db);
      if (!k) {
        // Izrecno zahtevan klub, v katerem uporabnik ni: 404 (ne razkrivamo, ali obstaja).
        if (zeljeni) return res.status(404).send("Club not found.");
        if (req.user.role === "admin") k = { clubId: null, role: "admin" };
        else if (req.user.role === "business") return res.status(404).send("Club not found.");
        else return res.status(403).send("Forbidden.");
      }
      if (vloge.length && k.role !== "admin" && !vloge.includes(k.role)) {
        return res.status(403).send("Your role in the club does not allow this.");
      }
      req.klub = k;
      next();
    } catch (e) {
      // Kot requireAuthNa (I10): napaka povezave/baze (izcrpan pool, prekinjena povezava, timeout) je zacasna tezava streznika,
      // ne napaka zahtevka. Na sken poteh (requireClubSken) mora vratar dobiti 503 + Retry-After (telefon preklopi na sken brez
      // povezave), ne 500 (issue #125). Vse drugo (programska/podatkovna napaka) ostane 500 s polnim skladom v dnevniku.
      if (jeNapakaPovezave(e)) {
        console.error("[klub] zacasna napaka pri iskanju kluba:", e && e.message);
        return res.status(503).set("Retry-After", "5").send("Service temporarily unavailable. Please try again.");
      }
      console.error("[klub] nepricakovana napaka:", e);
      return res.status(500).send("Server error.");
    }
  };
}
function requireClub(...vloge) { return requireClubNa(pool, vloge); }
// Isto prek skenPool (poti skena na vratih).
function requireClubSken(...vloge) { return requireClubNa(skenPool, vloge); }

// test endpoint
app.get("/", (req, res) => {
  res.send("Outly backend OK");
});

// Render Health Check Path: Render novo kodo spusti v promet sele, ko ta pot vrne 2xx.
// Preveri tudi bazo (SELECT 1) - backend brez baze ne streze nicesar. Gre prek LASTNEGA poola `zdraviPool` (ne glavnega):
// preobremenjen glavni pool ni nezdrava instanca (I10, issue #117). Nedosegljiva baza je se vedno 503. Omejeno na 3 s,
// da obvisela povezava ne zadrzi odgovora cez Renderjev rok.
// `commit` = prvih 12 znakov RENDER_GIT_COMMIT (javni SHA, ni skrivnost): s tem se vidi, KATERA koda teče. Padel deploy
// (npr. migracija brez zaklepa, #115) pusti staro različico živo in vrača 200, zato 200 sam ne dokaže, da teče nova koda.
const COMMIT_KRATEK = (process.env.RENDER_GIT_COMMIT || "").slice(0, 12) || null;
app.get("/healthz", async (req, res) => {
  res.set("Cache-Control", "no-store");
  let casovnik;
  try {
    for (const [ime, z, p] of [["glavni pool", zastojGlavni, pool], ["skenPool", zastojSken, skenPool]]) {
      const zastojMs = z.vzorci();
      if (zastojMs > ZDRAVJE_ZASICEN_MS) {
        // Vse povezave izposojene in nobena se ne vraca (puscanje, obviseli zaklepi) -> naj Render instanco ponovno zazene.
        console.error(`[zdravje] ${ime}: zastoj ${Math.round(zastojMs / 1000)} s brez vrnjene povezave (meja ${Math.round(ZDRAVJE_ZASICEN_MS / 1000)} s; ` +
          `povezav ${p.totalCount}, cakajocih ${p.waitingCount}) -> 503`);
        return res.status(503).json({ ok: false, commit: COMMIT_KRATEK });
      }
    }
    await Promise.race([
      zdraviPool.query("SELECT 1"),
      new Promise((_, zavrni) => { casovnik = setTimeout(() => zavrni(new Error("timeout")), 3000); }),
    ]);
    res.json({ ok: true, commit: COMMIT_KRATEK });
  } catch (e) {
    console.error("[zdravje] baza ni dosegljiva ->", 503, e && e.message);
    res.status(503).json({ ok: false, commit: COMMIT_KRATEK });
  } finally {
    clearTimeout(casovnik);
  }
});

// Admin panel: statična stran v mapi admin/ (en HTML + JS, brez ogrodja).
// Sama stran ne razkrije ničesar — vsi podatki pridejo prek poti /admin/api/*,
// ki zahtevajo vlogo admin.
app.use("/admin", express.static(path.join(__dirname, "admin"), { index: "index.html" }));

// ---------------------------
// ME (protected)
// ---------------------------
// Stikalo za prenos vstopnice prijatelju BREZ racuna (Martin, 5. 10. 2026): do objave pogojev 1.2 in politike 2.5 SAMO za vlogo admin
// (ekipa testira v produkciji); PRENOS_BREZ_RACUNA=vsi vklopi za vse (to naredi Martin na Renderju). Vloga je iz baze ob vsakem klicu (I5).
// Velja samo za posiljanje GOSTU; potrditev starosti posiljatelja (age_confirmed) pri prenosu na racun NI vezana na stikalo.
function mozenPrenosGostu(vloga) { return process.env.PRENOS_BREZ_RACUNA === "vsi" || vloga === "admin"; }

app.get("/me", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT ${POLJA_UPORABNIKA} FROM users WHERE id=$1`,
      [req.user.userId]
    );

    if (result.rows.length === 0) return res.status(404).send("User not found.");
    await prevzemiGostujocaNarocila(req.user.userId);
    // Klub in vloga v njem (lastnik ali član ekipe, migracija 009). Aplikacija
    // po club_role pokaže poslovni obraz — tudi vratarju, ki ima users.role 'user'.
    const k = await klubUporabnika(req.user.userId);
    // Čakajoča vabila v ekipo (migracija 013) — značka na zvoncu v "My clubs".
    const v = await pool.query("SELECT COUNT(*)::int AS n FROM club_invites WHERE user_id=$1 AND status='pending'", [req.user.userId]);
    // Čakajoče prošnje za prijateljstvo (migracija 016) — obvestila v aplikaciji.
    const pf = await pool.query("SELECT COUNT(*)::int AS n FROM friend_requests WHERE to_user_id=$1 AND status='pending'", [req.user.userId]);
    // Neprebrane prejete vstopnice (migracija 017) — obvestilo "X ti je poslal vstopnico" — in neprebrana vabila na guest listo (migracija 036):
    // en poizvedbeni krog za oba stevca (GET /me tece ob vsakem zagonu aplikacije; indeksa ticket_transfers_to_unseen_idx, guest_list_members_neprebrana_idx).
    const pv = await pool.query(
      `SELECT (SELECT COUNT(*)::int FROM ticket_transfers WHERE to_user_id=$1 AND seen_at IS NULL) AS n,
              (SELECT COUNT(*)::int ${GUEST_LISTA_NEPREBRANA_IZ} ${GUEST_LISTA_NEPREBRANA_KJE}) AS vabil`, [req.user.userId]);
    // Neprebrana obvestila "klub, ki mu slediš, je objavil dogodek" (migracija 019).
    const pk = await pool.query(
      `SELECT COUNT(*)::int AS n FROM club_event_notifications n
        JOIN events e ON e.id = n.event_id
        JOIN clubs c ON c.id = e.club_id
       WHERE n.user_id=$1 AND n.seen_at IS NULL
         AND e.status='published' AND NOT c.hidden`,
      [req.user.userId]
    );
    // Vsa clanstva (migracija 018): club_id/club_role ostaneta prvo clanstvo za stare odjemalce.
    const klubi = await klubiUporabnika(req.user.userId);
    return res.status(200).json({
      ...result.rows[0],
      club_id: k ? k.clubId : null,
      club_role: k ? k.role : null,
      clubs: klubi,
      pending_invites: v.rows[0] ? v.rows[0].n : 0,
      pending_friend_requests: pf.rows[0] ? pf.rows[0].n : 0,
      pending_received_tickets: pv.rows[0] ? pv.rows[0].n : 0,
      pending_guest_list_invites: pv.rows[0] ? pv.rows[0].vabil : 0,
      pending_club_events: pk.rows[0] ? pk.rows[0].n : 0,
      can_transfer_to_guest: mozenPrenosGostu(result.rows[0].role),
    });
  } catch (err) {
    console.error(err);
    return res.status(500).send("Server error.");
  }
});

// ---------------------------
// PATCH /me/avatar (protected)
// ---------------------------
// Aplikacija to pot klice od zacetka, backend je ni imel -> vsako shranjevanje
// profilne slike je vracalo 404. Popravek najdbe P-02.
app.patch("/me/avatar", requireAuth, async (req, res) => {
  try {
    const avatarUrl = req.body.avatarUrl ?? req.body.avatar_url;

    if (typeof avatarUrl !== "string" || !avatarUrl.trim()) {
      return res.status(400).send("Missing avatarUrl.");
    }

    // Sprejmemo samo naslove iz NASEGA Cloudinaryja. Brez tega bi lahko
    // kdorkoli za svojo profilno sliko nastavil poljuben tuj URL in ga
    // servirali vsem uporabnikom (sledenje, phishing, neprimerna vsebina).
    const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
    if (!cloudName) return res.status(500).send("Cloudinary env vars not set.");

    const dovoljenaPredpona = `https://res.cloudinary.com/${cloudName}/`;
    if (!avatarUrl.startsWith(dovoljenaPredpona)) {
      return res.status(400).send("avatarUrl must be a Cloudinary URL from this account.");
    }
    if (avatarUrl.length > 500) {
      return res.status(400).send("avatarUrl too long.");
    }

    const r = await pool.query(
      `UPDATE users SET avatar_url=$1 WHERE id=$2
       RETURNING id, email, username, role, avatar_url, email_verified, created_at`,
      [avatarUrl, req.user.userId]
    );

    if (r.rows.length === 0) return res.status(404).send("User not found.");
    return res.status(200).json(r.rows[0]);
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

// ---------------------------
// PROFIL: dokoncanje racuna (zaslona "complete acc" in "complete acc 2")
// ---------------------------

// 21 zanrov iz Figme. Seznam je zaprt namenoma: brez tega bi v bazo priseli
// poljubni nizi in "Suggestions" ne bi imel po cem grupirati.
const ZANRI = [
  "electronic","hiphop","pop","rnb","rock","metal","punk","afrobeat","balkan",
  "latino","country","hardcore","70s","80s","90s","rap","2000s","house",
  "garage","trap","techno"
];

app.get("/genres", (req, res) => res.status(200).json({ genres: ZANRI }));

// Polja, ki jih vrnemo o uporabniku. Na enem mestu, da se GET /me, PATCH /me
// in PATCH /me/avatar ne razidejo.
const POLJA_UPORABNIKA = `id, email, username, role, avatar_url, email_verified,
  phone, phone_verified, date_of_birth, country, genres, onboarded_at, created_at,
  share_plans_with_friends`;

app.patch("/me", requireAuth, async (req, res) => {
  try {
    const b = req.body || {};
    const sets = [];
    const vrednosti = [];
    const dodaj = (stolpec, vrednost) => {
      vrednosti.push(vrednost);
      sets.push(`${stolpec} = $${vrednosti.length}`);
    };

    // --- uporabnisko ime ---
    if (b.username !== undefined) {
      const ime = String(b.username).trim();
      if (ime.length < 3)  return res.status(400).send("Username too short.");
      if (ime.length > 20) return res.status(400).send("Username too long.");
      if (!/^[a-zA-Z0-9_]+$/.test(ime)) {
        return res.status(400).send("Username invalid. Use letters, numbers, underscore.");
      }
      // Primerjava brez upostevanja velikosti crk: "Martin" in "martin" sta
      // isto ime. Registracija tega doslej ni preverjala.
      const zasedeno = await pool.query(
        "SELECT id FROM users WHERE LOWER(username)=LOWER($1) AND id<>$2", [ime, req.user.userId]
      );
      if (zasedeno.rows.length > 0) return res.status(409).send("Username already in use.");
      dodaj("username", ime);
    }

    // --- telefonska stevilka ---
    if (b.phone !== undefined) {
      if (b.phone === null || b.phone === "") {
        dodaj("phone", null);
        dodaj("phone_verified", false);
      } else {
        const tel = String(b.phone).replace(/[\s\-()]/g, "");
        if (!/^\+[1-9][0-9]{7,14}$/.test(tel)) {
          return res.status(400).send("Phone must be in E.164 format, e.g. +38641123456.");
        }
        const zasedena = await pool.query(
          "SELECT id FROM users WHERE phone=$1 AND id<>$2", [tel, req.user.userId]
        );
        if (zasedena.rows.length > 0) return res.status(409).send("Phone number already in use.");
        dodaj("phone", tel);
        // Vsaka sprememba stevilke razveljavi prejsnjo potrditev.
        dodaj("phone_verified", false);
      }
    }

    // --- datum rojstva ---
    if (b.dateOfBirth !== undefined || b.date_of_birth !== undefined) {
      const d = b.dateOfBirth ?? b.date_of_birth;
      if (d === null || d === "") {
        dodaj("date_of_birth", null);
      } else {
        if (!/^\d{4}-\d{2}-\d{2}$/.test(String(d))) {
          return res.status(400).send("dateOfBirth must be YYYY-MM-DD.");
        }
        const dat = new Date(d + "T00:00:00Z");
        if (Number.isNaN(dat.getTime())) return res.status(400).send("Invalid dateOfBirth.");
        const let_ = (Date.now() - dat.getTime()) / (365.2425 * 24 * 3600 * 1000);
        if (let_ <= 0)  return res.status(400).send("dateOfBirth cannot be in the future.");
        if (let_ > 120) return res.status(400).send("dateOfBirth is not plausible.");
        // Meja za veljavno privolitev otroka v Sloveniji je 15 let (ZVOP-2, 8. clen).
        // Aplikacija to preveri ze pred posiljanjem; streznik je zadnja obramba.
        if (let_ < 15)  return res.status(400).send("You must be at least 15 years old.");
        dodaj("date_of_birth", d);
      }
    }

    // --- drzava ---
    if (b.country !== undefined) {
      if (b.country === null || b.country === "") {
        dodaj("country", null);
      } else {
        const dr = String(b.country).trim().toUpperCase();
        if (!/^[A-Z]{2}$/.test(dr)) return res.status(400).send("country must be a 2-letter ISO code, e.g. SI.");
        dodaj("country", dr);
      }
    }

    // --- zanri ---
    if (b.genres !== undefined) {
      if (!Array.isArray(b.genres)) return res.status(400).send("genres must be an array.");
      if (b.genres.length > ZANRI.length) return res.status(400).send("Too many genres.");
      const izbrani = [...new Set(b.genres.map(g => String(g).trim().toLowerCase()))];
      const neznani = izbrani.filter(g => !ZANRI.includes(g));
      if (neznani.length > 0) {
        return res.status(400).json({ error: "unknown_genres", unknown: neznani, allowed: ZANRI });
      }
      dodaj("genres", izbrani);
    }

    // --- prijatelji vidijo moje nacrte (migracija 016) ---
    if (b.share_plans_with_friends !== undefined || b.sharePlansWithFriends !== undefined) {
      const v = b.share_plans_with_friends ?? b.sharePlansWithFriends;
      if (typeof v !== "boolean") return res.status(400).send("share_plans_with_friends must be true or false.");
      dodaj("share_plans_with_friends", v);
    }

    if (sets.length === 0) return res.status(400).send("Nothing to update.");

    // Racun velja za dokoncan, ko ima datum rojstva in vsaj en zanr.
    sets.push(`onboarded_at = CASE
        WHEN onboarded_at IS NOT NULL THEN onboarded_at
        WHEN date_of_birth IS NOT NULL AND COALESCE(array_length(genres,1),0) > 0 THEN NOW()
        ELSE NULL END`);

    vrednosti.push(req.user.userId);
    const r = await pool.query(
      `UPDATE users SET ${sets.join(", ")} WHERE id = $${vrednosti.length}
       RETURNING ${POLJA_UPORABNIKA}`,
      vrednosti
    );

    if (r.rows.length === 0) return res.status(404).send("User not found.");

    // Drugi prehod, da onboarded_at upostevа vrednosti, ki so bile pravkar vpisane.
    const r2 = await pool.query(
      `UPDATE users SET onboarded_at = NOW()
       WHERE id=$1 AND onboarded_at IS NULL
         AND date_of_birth IS NOT NULL AND COALESCE(array_length(genres,1),0) > 0
       RETURNING ${POLJA_UPORABNIKA}`,
      [req.user.userId]
    );

    const me = r2.rows[0] || r.rows[0];
    return res.status(200).json({ ...me, can_transfer_to_guest: mozenPrenosGostu(me.role) });
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

// ---------------------------
// BRISANJE RAČUNA (Apple 5.1.1(v), najdba A-01)
// ---------------------------
// Apple od junija 2022 zahteva, da uporabnik racun izbrise ZNOTRAJ aplikacije.
// Brez tega je oddaja zavrnjena.
// Supabasov račun: geslo je preverila aplikacija tik pred klicem (ponovna
// prijava pri Supabase), mi ga nimamo. Po izbrisu lokalnih podatkov pokličemo
// še Supabasov RPC delete_my_account (shema 10 spletne strani) Z UPORABNIKOVIM
// žetonom — izbriše auth.users vrstico in prijavo na waitlisti. Brez tega bi
// se ob naslednji prijavi ustvaril prazen lokalni račun.
async function izbrisiSupabaseRacun(token) {
  const r = await fetch(SUPABASE_URL + "/rest/v1/rpc/delete_my_account", {
    method: "POST",
    headers: { apikey: SUPABASE_KEY, Authorization: "Bearer " + token, "Content-Type": "application/json" },
    body: "{}",
    signal: AbortSignal.timeout(8000),
  });
  if (!r.ok) throw new Error("delete_my_account " + r.status + " " + (await r.text()).slice(0, 200));
}

app.delete("/me", requireAuth, omeji({ kljuc: "delete", najvec: 5, oknoSekund: 3600 }), async (req, res) => {
  try {
    const { password } = req.body || {};
    const supabase = true;

    if (typeof password !== "string" || !password) {
      return res.status(400).send("Password required to delete account.");
    }

    {
      // Ponovna prijava pri Supabase s trenutnim geslom: ukraden žeton (velja
      // do ure) sam ne sme zadostovati za nepovraten izbris.
      const r = await fetch(SUPABASE_ISS + "/token?grant_type=password", {
        method: "POST",
        headers: { apikey: SUPABASE_KEY, "Content-Type": "application/json" },
        body: JSON.stringify({ email: req.user.email, password }),
        signal: AbortSignal.timeout(8000),
      }).catch(() => null);
      if (!r) return res.status(503).send("Auth service unavailable.");
      if (r.status === 400 || r.status === 401 || r.status === 403) return res.status(401).send("Invalid credentials.");
      if (!r.ok) return res.status(503).send("Auth service unavailable.");
    }

    // Brez tabele orders (pred migracijo 002) je izbris preprost.
    if (!obstajajoNarocila) {
      if (supabase) { await izbrisiSupabaseRacun(req.user.supabaseToken); izbrisaniSub.set(req.user.supabaseSub, req.user.supabaseExp); }
      await pool.query("DELETE FROM users WHERE id=$1", [req.user.userId]);
      return res.status(200).json({ message: "Account deleted." });
    }

    // Od migracije 002 naprej sta v igri dve nasprotujoci si zahtevi:
    // Apple hoce, da uporabnik racun izbrise; davcni predpisi hocejo, da se
    // racun o nakupu ohrani. Resitev je anonimizacija, ne izbris naracil.
    const odjemalec = await pool.connect();
    try {
      await odjemalec.query("BEGIN");

      // 1. Lastnik kluba, ki ima narocila, racuna ne more izbrisati — klub
      //    mora najprej dobiti drugega lastnika. Baza bi to zavrnila tako ali
      //    tako, a s tem uporabnik dobi razumljivo sporocilo namesto napake 500.
      const klubi = await odjemalec.query(
        `SELECT c.id, c.name, COUNT(o.id) AS narocil
         FROM clubs c LEFT JOIN orders o ON o.club_id = c.id
         WHERE c.owner_user_id = $1
         GROUP BY c.id, c.name
         HAVING COUNT(o.id) > 0`,
        [req.user.userId]
      );

      if (klubi.rows.length > 0) {
        await odjemalec.query("ROLLBACK");
        return res.status(409).json({
          error: "club_has_orders",
          message: "Your club has sold tickets. Transfer club ownership before deleting your account.",
          clubs: klubi.rows.map(k => ({ id: k.id, name: k.name, orders: Number(k.narocil) })),
        });
      }

      // 1b. Guest lista (035, I24): gostiteljeve liste se preklicejo (neuporabljene vstopnice void), vstopnice, ki jih izbrisani uporabnik drzi kot
      //     povabljenec, so void in mesto se sprosti. Brez tega bi vstopnica z izbrisanim imetnikom (holder_user_id SET NULL) zdrsnila na gostitelja.
      await guestListaPocistiUporabnika(odjemalec, req.user.userId);

      // 2. Osebni podatki na naracilih se odvezejo. Znesek, datum in dogodek
      //    ostanejo, ker so racunovodski podatek; e-naslov ni.
      //    Prevzeta gostujoca narocila (migracija 033): tudi guest_email in zetoni pogleda (kdor ima povezavo, ne vidi vec nicesar).
      await odjemalec.query(
        `UPDATE orders
         SET buyer_email = 'izbrisan-' || id || '@outly.invalid', guest_email = NULL
         WHERE user_id = $1`,
        [req.user.userId]
      );
      await odjemalec.query(
        "DELETE FROM gost_zetoni WHERE order_id IN (SELECT id FROM orders WHERE user_id = $1)",
        [req.user.userId]
      );

      // 3. Izbris uporabnika. orders.user_id je ON DELETE SET NULL, zato
      //    naracila ostanejo, a niso vec vezana na osebo.
      await odjemalec.query("DELETE FROM users WHERE id=$1", [req.user.userId]);

      // 4. Supabasov račun — PRED potrditvijo transakcije: če Supabase odpove,
      //    ostane vse, kot je bilo, in uporabnik lahko poskusi znova.
      if (supabase) {
        try { await izbrisiSupabaseRacun(req.user.supabaseToken); }
        catch (e) {
          await odjemalec.query("ROLLBACK");
          console.error(e);
          return res.status(502).send("Could not delete the account at the identity provider. Please try again.");
        }
      }

      await odjemalec.query("COMMIT");
      if (supabase) izbrisaniSub.set(req.user.supabaseSub, req.user.supabaseExp);
      return res.status(200).json({ message: "Account deleted." });
    } catch (e) {
      await odjemalec.query("ROLLBACK").catch(() => {});
      throw e;
    } finally {
      odjemalec.release();
    }
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

// ---------------------------
// CLUBS (public + business create)
// ---------------------------
// owner_user_id NI tu (issue #113, I4): notranji ID uporabnika ne sodi na javno pot, nobena
// aplikacija ga ne bere; lastnika pove `my_role` / `GET /me`, admin ga dobi iz ADMIN_STOLPCI_KLUBA.
// Stolpci, ki smejo ven javno. NAMENOMA ni "SELECT *": migracija 002 je
// klubom dodala stripe_account_id, ki z zvezdico ni bil viden nikomur v
// pregledu, javno pa bi ga vrnil vsak klic /clubs. Vsak nov stolpec je
// treba tu dodati zavestno.
const JAVNI_STOLPCI_KLUBA = `id, name, logo_url, banner_url, description,
  contact_email, contact_phone, instagram, website, address, city, country,
  lat, lng, min_age, genres, created_at, bar_prices, gallery_urls, video_url,
  (SELECT COUNT(*)::int FROM club_follows cf WHERE cf.club_id = clubs.id) AS followers_count`;

// Cenik bara (migracija 014): seznam postavk, ki ga klub ureja v celoti.
// Vrne ocisceno kopijo ali niz z napako. Cene v centih, kot pri vstopnicah.
const CENIK_NAJVEC_POSTAVK = 60;
function preveriCenik(vhod) {
  if (!Array.isArray(vhod)) return { napaka: "barPrices must be an array." };
  if (vhod.length > CENIK_NAJVEC_POSTAVK) return { napaka: `barPrices: at most ${CENIK_NAJVEC_POSTAVK} items.` };
  const postavke = [];
  for (const p of vhod) {
    if (!p || typeof p !== "object" || Array.isArray(p)) return { napaka: "barPrices: each item must be an object." };
    const name = String(p.name ?? "").trim();
    if (name.length < 1 || name.length > 60) return { napaka: "barPrices: name must be 1-60 characters." };
    const cents = p.price_cents ?? p.priceCents;
    if (!Number.isInteger(cents) || cents < 0 || cents > 100000) {
      return { napaka: "barPrices: price_cents must be an integer between 0 and 100000." };
    }
    const category = String(p.category ?? "").trim().slice(0, 30);
    const postavka = { name, price_cents: cents };
    if (category) postavka.category = category;
    postavke.push(postavka);
  }
  return { postavke };
}

// Lastnik vidi še stanje vidnosti in Stripa, ne pa stripe_account_id.
const STOLPCI_KLUBA_LASTNIKA = `${JAVNI_STOLPCI_KLUBA}, hidden, stripe_charges_enabled, stripe_payouts_enabled`;

function stevilo(vrednost, privzeto, najvec) {
  const n = parseInt(vrednost, 10);
  if (Number.isNaN(n) || n < 0) return privzeto;
  return Math.min(n, najvec);
}
// Kljuc javnega predpomnilnika (I17): SAMO kanonicni parametri poizvedbe, nikoli zeton/glava/IP. JSON.stringify seznama je
// injektiven (brez zlepljanja "a|b" + "c" = "a" + "b|c"). null = nenavadni parametri (seznam, objekt, predolg niz) ->
// zahtevek gre mimo predpomnilnika, kot pred #114.
function nenavadniParametri(vrednosti, najdaljsiNiz = 100) {
  return vrednosti.some((v) => v !== undefined && (typeof v !== "string" || v.length > najdaljsiNiz));
}
// Osebna razlicica odgovora (prijavljen uporabnik): "private" + "Vary: Authorization", da skupni predpomnilnik (CDN, proxy)
// osebnih polj nikoli ne shrani; javna razlicica (gost) ima samo Vary, da se loci od osebne.
const GLAVE_OSEBNO = { "Cache-Control": "private", Vary: "Authorization" };
function kljucId(vrsta, id) {
  return id.length > 15 ? null : JSON.stringify([vrsta, id]);
}
function kljucKlubov(q) {
  const { limit, offset, city, q: iskanje, withCoords } = q;
  if (nenavadniParametri([limit, offset, city, iskanje, withCoords])) return null;
  if (iskanje) return null;   // prosto iskanje se ne predpomni: poplava razlicnih iskalnih nizov ne sme izpodrivati vrocih kljucev
  return JSON.stringify(["clubs", stevilo(limit, 100, 200), stevilo(offset, 0, 100000), city || null, withCoords === "true"]);
}

app.get("/clubs", async (req, res) => {
  try {
    // city je prosto besedilo: loceni majhen proracun (`prosto`), da poplava mest ne izpodrine vrocih kljucev.
    const { vnos, stanje } = await javniPredpomnilnik.dobi(kljucKlubov(req.query), async () => {
    const limit  = stevilo(req.query.limit, 100, 200);
    const offset = stevilo(req.query.offset, 0, 100000);

    const pogoji = [];
    const p = [];

    if (req.query.city) { p.push(req.query.city); pogoji.push(`city ILIKE $${p.length}`); }
    if (req.query.q) {
      p.push(`%${String(req.query.q).trim()}%`);
      pogoji.push(`(name ILIKE $${p.length} OR city ILIKE $${p.length} OR description ILIKE $${p.length})`);
    }
    // Zemljevid potrebuje samo klube s koordinatami.
    if (req.query.withCoords === "true") pogoji.push("lat IS NOT NULL AND lng IS NOT NULL");
    // Skriti klubi (admin panel, migracija 006) javno ne obstajajo.
    pogoji.push("hidden = FALSE");

    const kje = pogoji.length ? "WHERE " + pogoji.join(" AND ") : "";

    const skupaj = await pool.query(`SELECT COUNT(*)::int AS n FROM clubs ${kje}`, p);

    p.push(limit); p.push(offset);
    const r = await pool.query(
      `SELECT ${JAVNI_STOLPCI_KLUBA} FROM clubs ${kje}
       ORDER BY created_at DESC LIMIT $${p.length - 1} OFFSET $${p.length}`,
      p
    );

    // Skupno stevilo v glavi, da telo ostane navaden seznam in se aplikaciji
    // ni treba spreminjati. Dekoder v Swiftu pricakuje [APIClub].
    return { status: 200, json: r.rows, glave: { "X-Total-Count": String(skupaj.rows[0].n) } };
    }, { prosto: !!req.query.city });
    return javniPredpomnilnik.poslji(req, res, vnos, stanje);
  } catch (e) {
    console.error(e);
    res.status(500).send("Server error.");
  }
});

// Lahek seznam za zemljevid. MapView je doslej risal EN sam klub, ker je
// izbiral najblizjega; poleg tega je /clubs vracal celotne zapise s polnimi
// opisi. Ta pot vrne samo to, kar pin potrebuje.
app.get("/clubs/map", async (req, res) => {
  try {
    const p = [];
    const pogoji = ["lat IS NOT NULL", "lng IS NOT NULL", "hidden = FALSE"];

    // Neobvezni okvir zemljevida: minLat,minLng,maxLat,maxLng
    const b = req.query.bbox;
    if (b) {
      const d = String(b).split(",").map(Number);
      if (d.length !== 4 || d.some(Number.isNaN)) {
        return res.status(400).send("bbox must be minLat,minLng,maxLat,maxLng.");
      }
      p.push(d[0], d[2], d[1], d[3]);
      pogoji.push("lat BETWEEN $1 AND $2", "lng BETWEEN $3 AND $4");
    }

    const r = await pool.query(
      `SELECT id, name, lat, lng, logo_url, city, min_age, genres
       FROM clubs WHERE ${pogoji.join(" AND ")} ORDER BY id LIMIT 1000`,
      p
    );
    res.json(r.rows);
  } catch (e) {
    console.error(e);
    res.status(500).send("Server error.");
  }
});

// neobveznaPrijava: brez zetona pot dela naprej (javna stran kluba), z zetonom pove
// se `is_following` — da gumb Follow ob odprtju ne utripa iz "Follow" v "Following".
app.get("/clubs/:id", neobveznaPrijava, async (req, res) => {
  try {
    if (!/^\d+$/.test(req.params.id)) return res.status(400).send("Invalid club id.");
    // Predpomnimo samo javni del (vrstica kluba); is_following je osebno polje in se doda po branju (I17).
    const { vnos, stanje } = await javniPredpomnilnik.dobi(kljucId("club", req.params.id), async () => {
      const r = await pool.query(
        `SELECT ${JAVNI_STOLPCI_KLUBA} FROM clubs WHERE id=$1 AND hidden = FALSE`, [req.params.id]
      );
      if (r.rows.length === 0) return { status: 404, besedilo: "Club not found." };
      return { status: 200, json: { ...r.rows[0], is_following: false }, podatki: r.rows[0], glave: { Vary: "Authorization" } };
    });
    if (vnos.status !== 200 || !req.user) return javniPredpomnilnik.poslji(req, res, vnos, stanje);

    const f = await pool.query(
      "SELECT 1 FROM club_follows WHERE club_id=$1 AND user_id=$2",
      [req.params.id, req.user.userId]
    );
    return javniPredpomnilnik.poslji(req, res,
      javniPredpomnilnik.pripravi({ status: 200, json: { ...vnos.podatki, is_following: f.rowCount > 0 }, glave: GLAVE_OSEBNO }), stanje);
  } catch (e) {
    console.error(e);
    res.status(500).send("Server error.");
  }
});

app.post("/clubs", requireAuth, requireRole("business", "admin"), async (req, res) => {
  try {
    const {
      name,
      logoUrl,
      bannerUrl,
      description,
      contactEmail,
      contactPhone,
      instagram,
      website,
      address,
      city,
      country,
      lat,
      lng,
      minAge,
      genres
    } = req.body;

    if (!name) return res.status(400).send("Missing name.");

    const r = await pool.query(
      `INSERT INTO clubs
      (owner_user_id, name, logo_url, banner_url, description,
       contact_email, contact_phone, instagram, website,
       address, city, country, lat, lng, min_age, genres)
       VALUES
      ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
       RETURNING ${STOLPCI_KLUBA_LASTNIKA}`,
      [
        req.user.userId,
        name,
        logoUrl || "",
        bannerUrl || "",
        description || "",
        contactEmail || "",
        contactPhone || "",
        instagram || "",
        website || "",
        address || "",
        city || "",
        country || "",
        lat ?? null,
        lng ?? null,
        minAge ?? 18,
        Array.isArray(genres) ? genres : []
      ]
    );

    res.status(201).json(r.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).send("Server error.");
  }
});

// ---------------------------
// SLEDENJE KLUBU (migracija 019)
// ---------------------------
// "Follow" na strani kluba: sledilec dobi obvestilo, ko klub objavi dogodek.
// Obe poti sta idempotentni (dvakrat follow = en zapis, unfollow brez sledenja = 200),
// da gumb v aplikaciji ob podvojenem dotiku ne pokaze napake.
// Lajkanja kluba ni: srcek ostane samo na dogodkih (event_favorites, migracija 012).
async function steviloSledilcev(clubId) {
  const r = await pool.query("SELECT COUNT(*)::int AS n FROM club_follows WHERE club_id=$1", [clubId]);
  return r.rows[0] ? r.rows[0].n : 0;
}

// Klub mora obstajati in ne sme biti skrit (skritega klub javno ni, zato mu ni mogoce slediti).
async function vidnoKlubId(req, res) {
  if (!/^\d+$/.test(req.params.id)) { res.status(400).send("Invalid club id."); return null; }
  const r = await pool.query("SELECT id FROM clubs WHERE id=$1 AND hidden = FALSE", [req.params.id]);
  if (r.rows.length === 0) { res.status(404).send("Club not found."); return null; }
  return r.rows[0].id;
}

app.put("/clubs/:id/follow", requireAuth, async (req, res) => {
  try {
    const clubId = await vidnoKlubId(req, res);
    if (!clubId) return;
    await pool.query(
      "INSERT INTO club_follows (club_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING",
      [clubId, req.user.userId]
    );
    return res.status(200).json({ following: true, followers_count: await steviloSledilcev(clubId) });
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

app.delete("/clubs/:id/follow", requireAuth, async (req, res) => {
  try {
    const clubId = await vidnoKlubId(req, res);
    if (!clubId) return;
    await pool.query("DELETE FROM club_follows WHERE club_id=$1 AND user_id=$2", [clubId, req.user.userId]);
    return res.status(200).json({ following: false, followers_count: await steviloSledilcev(clubId) });
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

// Katerim klubom sledim. `ids` je tu zato, da aplikaciji ni treba brati celih klubov,
// ko hoce samo vedeti, ali je gumb "Following".
app.get("/me/clubs/following", requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT ${JAVNI_STOLPCI_KLUBA} FROM clubs
        WHERE hidden = FALSE
          AND id IN (SELECT club_id FROM club_follows WHERE user_id=$1)
        ORDER BY name LIMIT 200`,
      [req.user.userId]
    );
    return res.status(200).json({ ids: r.rows.map(c => c.id), clubs: r.rows });
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

// Neprebrana obvestila "klub, ki mu slediš, je objavil dogodek" (zvonec na domacem zaslonu).
// Odpovedani dogodki in skriti klubi izpadejo — obvestilo o necem, cesar ni vec, je smet.
app.get("/me/club-events", requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT n.id, n.created_at, n.event_id,
              e.title AS event_title, e.start_at, e.poster_url,
              c.id AS club_id, c.name AS club_name, c.logo_url AS club_logo_url
         FROM club_event_notifications n
         JOIN events e ON e.id = n.event_id
         JOIN clubs c ON c.id = e.club_id
        WHERE n.user_id = $1 AND n.seen_at IS NULL
          AND e.status = 'published' AND NOT c.hidden
        ORDER BY n.created_at DESC
        LIMIT 50`,
      [req.user.userId]
    );
    return res.status(200).json({ notifications: r.rows });
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

// Obvestilo prebrano. Samo lastnik obvestila (WHERE user_id iz zetona) — tuje se ne da oznaciti.
app.post("/me/club-events/:id/seen", requireAuth, async (req, res) => {
  try {
    if (!/^\d+$/.test(req.params.id)) return res.status(400).send("Invalid notification id.");
    const r = await pool.query(
      "UPDATE club_event_notifications SET seen_at = NOW() WHERE id=$1 AND user_id=$2 AND seen_at IS NULL RETURNING id",
      [req.params.id, req.user.userId]
    );
    // Ze prebrano ali tuje -> 200, da dvojni dotik v aplikaciji ne pokaze napake.
    return res.status(200).json({ seen: r.rowCount > 0 });
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

// ---------------------------
// Cloudinary signature (protected)
// ---------------------------
function cloudinarySignature(paramsToSign, apiSecret) {
  // Cloudinary: sort params by key, join key=value with &, append api_secret, sha1
  const sortedKeys = Object.keys(paramsToSign).sort();
  const toSign = sortedKeys
    .map((k) => `${k}=${paramsToSign[k]}`)
    .join("&") + apiSecret;

  return crypto.createHash("sha1").update(toSign).digest("hex");
}

// Skupna logika za obe poti.
// Poleg timestamp in folder podpisemo tudi public_id, vezan na uporabnika.
// Ker je public_id del podpisa, ga odjemalec ne more zamenjati -> nihce ne more
// pisati cez tuje slike. Popravek najdbe S-04.
async function izdajPodpis(req, res) {
  try {
    const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
    const apiKey = process.env.CLOUDINARY_API_KEY;
    const apiSecret = process.env.CLOUDINARY_API_SECRET;

    if (!cloudName || !apiKey || !apiSecret) {
      return res.status(500).send("Cloudinary env vars not set.");
    }

    const timestamp = Math.floor(Date.now() / 1000);
    const folder = process.env.CLOUDINARY_FOLDER || "outly";

    // npr. outly/u42/1757193600-3f9a1c2b
    const publicId = `${folder}/u${req.user.userId}/${timestamp}-${crypto.randomBytes(4).toString("hex")}`;

    const paramsToSign = { folder, public_id: publicId, timestamp };
    const signature = cloudinarySignature(paramsToSign, apiSecret);

    return res.status(200).json({
      timestamp,
      signature,
      apiKey,
      cloudName,
      folder,
      publicId
    });
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
}

// Kanonicna pot. Aplikacija je od zacetka klicala prav to, backend pa je
// streg samo GET /cloudinary/signature -> nalaganje slik je vracalo 404.
// Popravek najdbe P-01.
app.post("/uploads/cloudinary-signature", requireAuth, izdajPodpis);

// Stara pot. Ohranjena, da nic ne odpove med prehodom. Odstrani jo, ko bo
// v obtoku samo se nova razlicica aplikacije.
app.get("/cloudinary/signature", requireAuth, izdajPodpis);

// ---------------------------
// BUSINESS: my club (owner-only)
// ---------------------------
app.get("/business/clubs/me", requireAuth, requireClub(), async (req, res) => {
  try {
    if (!req.klub.clubId) return res.status(404).send("Club not found.");
    const r = await pool.query(
      `SELECT ${STOLPCI_KLUBA_LASTNIKA} FROM clubs WHERE id=$1`,
      [req.klub.clubId]
    );

    if (r.rows.length === 0) return res.status(404).send("Club not found.");
    return res.status(200).json({ ...r.rows[0], my_role: req.klub.role });
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

app.patch("/business/clubs/me", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  try {
    if (!req.klub.clubId) return res.status(404).send("Club not found.");
    const clubId = req.klub.clubId;

    // whitelist fields (snake_case) + allow camelCase inputs too
    const body = req.body || {};

    const incoming = {
      name: body.name,
      description: body.description,
      logo_url: body.logo_url ?? body.logoUrl,
      banner_url: body.banner_url ?? body.bannerUrl,
      contact_email: body.contact_email ?? body.contactEmail,
      contact_phone: body.contact_phone ?? body.contactPhone,
      instagram: body.instagram,
      website: body.website,
      address: body.address,
      city: body.city,
      country: body.country,
      lat: body.lat,
      lng: body.lng,
      // Doslej ju lastnik ni mogel nastaviti (samo admin) — ClubInfoView ju rabi.
      genres: body.genres,
      min_age: body.min_age ?? body.minAge,
      // Cenik bara (migracija 014). Poslje se cel seznam; prazen seznam = brez cenika.
      bar_prices: body.bar_prices ?? body.barPrices,
      // Slideshow (do 3 slike) in predstavitveni video (migracija 015).
      gallery_urls: body.gallery_urls ?? body.galleryUrls,
      video_url: body.video_url ?? body.videoUrl
    };

    // URL slike/videa: https, brez presledkov, razumna dolzina. Prazen niz je dovoljen (odstrani).
    const veljavenUrl = (u) => typeof u === "string" && u.length <= 500 && /^https:\/\/\S+$/.test(u);
    if (incoming.gallery_urls !== undefined) {
      if (!Array.isArray(incoming.gallery_urls)) return res.status(400).send("galleryUrls must be an array.");
      const g = incoming.gallery_urls.map(u => String(u ?? "").trim()).filter(u => u.length > 0);
      if (g.length > 3) return res.status(400).send("galleryUrls: at most 3 images.");
      if (!g.every(veljavenUrl)) return res.status(400).send("galleryUrls: each item must be an https URL.");
      incoming.gallery_urls = g;
    }
    if (incoming.video_url !== undefined) {
      const v = String(incoming.video_url ?? "").trim();
      if (v !== "" && !veljavenUrl(v)) return res.status(400).send("videoUrl must be an https URL.");
      incoming.video_url = v;
    }

    if (incoming.bar_prices !== undefined) {
      const c = preveriCenik(incoming.bar_prices);
      if (c.napaka) return res.status(400).send(c.napaka);
      // pg bi JS seznam poslal kot Postgresov ARRAY, ne kot JSON -> vedno JSON.stringify + ::jsonb.
      incoming.bar_prices = JSON.stringify(c.postavke);
    }

    if (incoming.genres !== undefined) {
      if (!Array.isArray(incoming.genres)) return res.status(400).send("genres must be an array.");
      incoming.genres = [...new Set(incoming.genres.map(g => String(g).trim().toLowerCase()))];
      const neznani = incoming.genres.filter(g => !ZANRI.includes(g));
      if (neznani.length) return res.status(400).json({ error: "unknown_genres", unknown: neznani, allowed: ZANRI });
    }
    if (incoming.min_age !== undefined) {
      const n = Number(incoming.min_age);
      if (!Number.isInteger(n) || n < 0 || n > 99) return res.status(400).send("minAge must be between 0 and 99.");
      incoming.min_age = n;
    }

    // build dynamic UPDATE only for provided keys
    const sets = [];
    const values = [];
    let idx = 1;

    for (const [k, v] of Object.entries(incoming)) {
      if (v === undefined) continue;
      sets.push(k === "bar_prices" ? `${k} = $${idx++}::jsonb` : `${k} = $${idx++}`);
      values.push(v);
    }

    if (sets.length === 0) {
      // nothing to update -> return current club
      const cur = await pool.query(`SELECT ${STOLPCI_KLUBA_LASTNIKA} FROM clubs WHERE id=$1`, [clubId]);
      return res.status(200).json(cur.rows[0]);
    }

    if (incoming.name !== undefined && String(incoming.name).trim().length === 0) {
      return res.status(400).send("Club name is required.");
    }
    // Koordinati v paru; posamezno ju baza zavrne (clubs_coords_chk).
    if ((incoming.lat === undefined) !== (incoming.lng === undefined)) {
      return res.status(400).send("lat and lng must be sent together.");
    }

    values.push(clubId);
    const sql = `UPDATE clubs SET ${sets.join(", ")} WHERE id = $${idx} RETURNING ${STOLPCI_KLUBA_LASTNIKA}`;

    const updated = await pool.query(sql, values);
    return res.status(200).json(updated.rows[0]);
  } catch (e) {
    // Omejitev v bazi (prazno ime, koordinate izven obsega, min_age ...) -> 400, ne 500.
    if (e && e.code === "23514") return res.status(400).send("Invalid club data: " + (e.constraint || "constraint"));
    if (e && e.code === "22P02") return res.status(400).send("Invalid value type.");
    console.error(e);
    return res.status(500).send("Server error.");
  }
});


// ---------------------------
// EVENTS (updated: upcoming true/false + time_status + ticket fields)
// ---------------------------
// Kdaj je dogodek KONCAN (Martin, 22. 9. 2026). Klubski vecer se skoraj nikoli ne konca
// ob uri zacetka, konca pa klubi pogosto ne vpisejo — zato: konec, ce je vpisan, sicer
// zacetek + 8 h. Ta izraz je en sam vir resnice za "ended" (stanje dogodka, nacrti
// prijateljev, dovoljenje za posnetek) — ce se spremeni, se spremeni na enem mestu.
const KONEC_DOGODKA = `COALESCE(end_at, start_at + INTERVAL '8 hours')`;

// Najnizja efektivna cena vklopljene mize dogodka (NULL = dogodek brez VIP miz). Podpoizvedba se
// sklicuje na tabelo `events` (brez vzdevka), zato jo smejo uporabljati samo poizvedbe FROM events.
const VIP_OD_CENTOV = `(SELECT MIN(COALESCE(vet.price_cents, vct.price_cents))::int
          FROM club_tables vct LEFT JOIN event_tables vet ON vet.event_id = events.id AND vet.table_id = vct.id
         WHERE events.vip_enabled AND vct.club_id = events.club_id AND vct.archived_at IS NULL
           AND NOT COALESCE(vet.disabled, FALSE))`;

// Stolpci dogodka na enem mestu (javni GET /events, GET /events/:id, GET /business/events).
const STOLPCI_DOGODKA = `
        id,
        club_id,
        title,
        description,
        poster_url,
        start_at,
        end_at,
        min_age,
        genres,
        status,
        created_at,
        ticket_price_cents,
        currency,
        ticket_url,
        capacity,
        sold_count,
        -- Zaloga za oznake v aplikaciji ("Sold out", "Few left"). sold_count vodi
        -- sprozilec iz migracije 002; capacity NULL = brez omejitve.
        CASE
          WHEN ticket_price_cents IS NULL THEN 'external'
          WHEN capacity IS NOT NULL AND sold_count >= capacity THEN 'sold_out'
          WHEN capacity IS NOT NULL AND capacity - sold_count <= GREATEST(5, capacity / 10) THEN 'few_left'
          ELSE 'available'
        END AS availability,
        CASE
          WHEN start_at > NOW() THEN 'coming_soon'
          ELSE 'popular'
        END AS time_status,
        -- Posnetek "kako je bilo" na koncanem dogodku (migracija 019). Prazen niz = brez videa.
        recap_video_url,
        -- Stanje dogodka (migracija 019). DODANO polje: time_status ostane, kot je bil,
        -- ker ga aplikacije na telefonih se berejo (pravilo "spremembe API-ja so samo dodajanje").
        -- upcoming = se ni zacel | live = tece | ended = koncan.
        CASE
          WHEN ${KONEC_DOGODKA} <= NOW() THEN 'ended'
          WHEN start_at > NOW() THEN 'upcoming'
          ELSE 'live'
        END AS lifecycle,
        -- Koliko oseb je oznacilo "I'm in" (migracija 020). DODANO polje.
        (SELECT COUNT(*)::int FROM event_interest ei WHERE ei.event_id = events.id) AS interested_count,
        -- VIP mize (migracija 025). DODANI polji: dogodek ima VIP vklopljen IN vsaj eno vklopljeno
        -- aktivno mizo; vip_from_cents = najnizja efektivna cena (prepis dogodka, sicer privzeta).
        ${VIP_OD_CENTOV} IS NOT NULL AS vip_enabled,
        ${VIP_OD_CENTOV} AS vip_from_cents`;

// Lahka razlicica seznama (GET /events?lite=true, #114): brez `description` (pri 200 dogodkih je to vecina teze odgovora).
// Polje je IZPUSCENO (ne null). Privzeti odgovor ostane nespremenjen (pravilo "spremembe API-ja so samo dodajanje").
const STOLPCI_DOGODKA_LAHKI = STOLPCI_DOGODKA.replace(/^\s*description,\s*$/m, "");
if (STOLPCI_DOGODKA_LAHKI === STOLPCI_DOGODKA) throw new Error("STOLPCI_DOGODKA_LAHKI: stolpca description ni mogoce izlociti");

// Vsi dogodki lastnega kluba, tudi osnutki in odpovedani. Samo za lastnika.
app.get("/business/events", requireAuth, requireClub(), async (req, res) => {
  try {
    if (!req.klub.clubId) return res.status(404).send("Club not found.");

    // recap_allowed pove aplikaciji, na katerem dogodku sme klub ponuditi nalaganje
    // posnetka: koncan IN med tremi najbolj popularnimi (migracija 019). Isto pravilo
    // uveljavi PATCH /events/:id — to je samo zato, da aplikaciji ni treba ugibati.
    const top = await popularniDogodkiKluba(req.klub.clubId);
    const r = await pool.query(
      `SELECT e.*, (e.id = ANY($2::int[])) AS recap_allowed
         FROM (SELECT ${STOLPCI_DOGODKA} FROM events WHERE club_id=$1) e
        ORDER BY e.start_at DESC LIMIT 500`,
      [req.klub.clubId, top]
    );
    return res.status(200).json(r.rows);
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

// Koliko koncanih dogodkov kluba je "popular" (in sme imeti posnetek). Luka/Martin, 22. 9. 2026:
// na strani kluba so vidni najvec trije — vec videov bi stran nalagalo brez konca.
const NAJVEC_POPULARNIH = 3;

// Top N koncanih objavljenih dogodkov kluba: po prodanih vstopnicah, ob izenacenju najnovejsi.
// Vrne seznam id-jev (prvi je najbolj popularen).
async function popularniDogodkiKluba(clubId, najvec = NAJVEC_POPULARNIH) {
  const r = await pool.query(
    `SELECT id FROM events
      WHERE club_id = $1 AND status = 'published' AND ${KONEC_DOGODKA} <= NOW()
      ORDER BY sold_count DESC, start_at DESC
      LIMIT $2`,
    [clubId, najvec]
  );
  return r.rows.map(x => x.id);
}

// Kljuc predpomnilnika za /events (I17): samo kanonicni parametri; clubId mora biti kratek niz.
function kljucDogodkov(q) {
  const { clubId, upcoming, popular, lite } = q;
  if (nenavadniParametri([clubId, upcoming, popular, lite], 20)) return null;
  const pop = popular === "true";
  return JSON.stringify(["events", clubId || null, pop ? null : (upcoming === "true" || upcoming === "false" ? upcoming : null), pop, lite === "true"]);
}

app.get("/events", async (req, res) => {
  try {
    const { clubId, upcoming, popular } = req.query;
    const stolpci = req.query.lite === "true" ? STOLPCI_DOGODKA_LAHKI : STOLPCI_DOGODKA;

    const { vnos, stanje } = await javniPredpomnilnik.dobi(kljucDogodkov(req.query), async () => {
    // ?clubId=..&popular=true -> najvec 3 koncani dogodki kluba po prodanih vstopnicah
    // (stran kluba, razdelek "Popular"). Brez omejitve na 7 dni, ki velja za ?upcoming=false:
    // posnetek dogodka je smiseln tudi cez mesec dni. Nova pot, stara ostane nespremenjena.
    if (popular === "true") {
      if (!clubId || !/^\d+$/.test(String(clubId))) return { status: 400, besedilo: "popular=true requires clubId." };
      const skriti = await pool.query("SELECT 1 FROM clubs WHERE id=$1 AND hidden", [clubId]);
      if (skriti.rowCount > 0) return { status: 200, json: [] };
      const ids = await popularniDogodkiKluba(clubId);
      if (ids.length === 0) return { status: 200, json: [] };
      const r = await pool.query(
        `SELECT ${stolpci} FROM events WHERE id = ANY($1::int[])
          ORDER BY sold_count DESC, start_at DESC`,
        [ids]
      );
      return { status: 200, json: r.rows };
    }

    const params = [];
    const where = [];

    if (clubId) {
      params.push(clubId);
      where.push(`club_id = $${params.length}`);
    }

    // coming soon vs popular. Pretekli dogodki so javno vidni samo 7 dni po zacetku
    // (Martin, 16. 9. 2026): stran kluba in "hit tedna" na domacem zaslonu kazeta samo
    // zadnji teden, starejsi izginejo. V bazi ostanejo (vstopnice, narocila, zgodovina
    // kluba v GET /business/events); GET /events/:id jih se vrne (povezava z vstopnice).
    if (upcoming === "true") where.push(`start_at > NOW()`);
    if (upcoming === "false") where.push(`start_at <= NOW() AND start_at > NOW() - INTERVAL '7 days'`);

    // Javno so vidni SAMO objavljeni dogodki. Osnutki in odpovedani so bili
    // doslej vidni vsakomur; lastnik jih vidi prek GET /business/events.
    where.push(`status = 'published'`);
    // Dogodki skritih klubov javno niso vidni (migracija 006).
    where.push(`club_id NOT IN (SELECT id FROM clubs WHERE hidden)`);

    const sql = `
      SELECT ${stolpci}
      FROM events
      WHERE ${where.join(" AND ")}
      ORDER BY start_at ASC
      LIMIT 200
    `;

    const r = await pool.query(sql, params);
    return { status: 200, json: r.rows };
    });
    return javniPredpomnilnik.poslji(req, res, vnos, stanje);
  } catch (e) {
    console.error(e);
    res.status(500).send("Server error.");
  }
});

// neobveznaPrijava: brez zetona pot dela naprej (javna stran dogodka), z zetonom pove
// se moj_plan in nacrte prijateljev (glej ZANIMANJE ZA DOGODEK spodaj, migracija 020).
// Predpomnimo samo javni del (vrstica dogodka); my_plan, friends_going, friends_interested so osebni in se
// izracunajo po branju iz predpomnilnika, v svoji kopiji (I17, I11).
app.get("/events/:id", neobveznaPrijava, async (req, res) => {
  try {
    if (!/^\d+$/.test(req.params.id)) return res.status(400).send("Invalid event id.");
    const { vnos, stanje } = await javniPredpomnilnik.dobi(kljucId("event", req.params.id), async () => {
      const r = await pool.query(
        `SELECT ${STOLPCI_DOGODKA} FROM events
         WHERE id=$1 AND status='published'
           AND club_id NOT IN (SELECT id FROM clubs WHERE hidden)`,
        [req.params.id]
      );
      if (r.rows.length === 0) return { status: 404, besedilo: "Event not found." };
      return { status: 200, json: { ...r.rows[0], my_plan: null, friends_going: [], friends_interested: [] }, podatki: r.rows[0], glave: { Vary: "Authorization" } };
    });
    if (vnos.status !== 200 || !req.user) return javniPredpomnilnik.poslji(req, res, vnos, stanje);

    const my_plan = await mojNacrtNaDogodku(req.params.id, req.user.userId);
    const f = await pool.query(
      `WITH pr AS (
         SELECT CASE WHEN user_a=$2 THEN user_b ELSE user_a END AS id
           FROM friendships WHERE user_a=$2 OR user_b=$2
       ), gredo AS (
         SELECT DISTINCT ${IMETNIK} AS uid
           FROM tickets t JOIN orders o ON o.id=t.order_id
          WHERE t.event_id=$1 AND t.status='valid' AND o.status IN ('paid','partially_refunded')
            AND ${IMETNIK} IN (SELECT id FROM pr)
       ), zanimajo AS (
         -- Oseba z vstopnico IN v event_interest je samo v gredo (going), ne dvakrat.
         SELECT ei.user_id AS uid FROM event_interest ei
          WHERE ei.event_id=$1 AND ei.user_id IN (SELECT id FROM pr)
            AND ei.user_id NOT IN (SELECT uid FROM gredo)
       )
       SELECT
         (SELECT COALESCE(jsonb_agg(jsonb_build_object('id', u.id, 'username', u.username, 'avatar_url', u.avatar_url) ORDER BY LOWER(u.username)), '[]'::jsonb)
            FROM gredo g JOIN users u ON u.id = g.uid WHERE u.share_plans_with_friends) AS friends_going,
         (SELECT COALESCE(jsonb_agg(jsonb_build_object('id', u.id, 'username', u.username, 'avatar_url', u.avatar_url) ORDER BY LOWER(u.username)), '[]'::jsonb)
            FROM zanimajo z JOIN users u ON u.id = z.uid WHERE u.share_plans_with_friends) AS friends_interested`,
      [req.params.id, req.user.userId]
    );
    return javniPredpomnilnik.poslji(req, res, javniPredpomnilnik.pripravi({
      status: 200,
      json: { ...vnos.podatki, my_plan, friends_going: f.rows[0].friends_going, friends_interested: f.rows[0].friends_interested },
      glave: GLAVE_OSEBNO,
    }), stanje);
  } catch (e) {
    console.error(e);
    res.status(500).send("Server error.");
  }
});

// ---------------------------
// ZANIMANJE ZA DOGODEK / "I'm in" (migracija 020)
// ---------------------------
// Uporabnik na dogodku oznaci "I'm in" (zanimanje). "Going" se NE shranjuje - izpelje
// se iz veljavne vstopnice (isti IMETNIK kot v /me/friends/plans). Shranjuje se SAMO
// "interested" (event_interest). Odlocil Martin, 23. 9. 2026.

// Ali ima uporabnik veljavno vstopnico ali zanimanje za dogodek -> 'going' | 'interested' | null.
async function mojNacrtNaDogodku(eventId, userId) {
  const g = await pool.query(
    `SELECT 1 FROM tickets t JOIN orders o ON o.id=t.order_id
      WHERE t.event_id=$1 AND t.status='valid' AND o.status IN ('paid','partially_refunded')
        AND ${IMETNIK}=$2 LIMIT 1`,
    [eventId, userId]
  );
  if (g.rowCount > 0) return "going";
  const i = await pool.query("SELECT 1 FROM event_interest WHERE event_id=$1 AND user_id=$2", [eventId, userId]);
  return i.rowCount > 0 ? "interested" : null;
}

// Dogodek mora obstajati, biti objavljen, klub ne skrit in dogodek se ne sme biti koncan
// (isti pogoj kot povsod drugod, KONEC_DOGODKA). Vrne id ali sama poslje napako in vrne null.
async function veljavenDogodekZaNacrt(id, res) {
  if (!/^\d+$/.test(String(id))) { res.status(400).send("Invalid event id."); return null; }
  const r = await pool.query(
    `SELECT e.id, e.status, c.hidden, (${KONEC_DOGODKA} <= NOW()) AS ended
       FROM events e JOIN clubs c ON c.id = e.club_id
      WHERE e.id = $1`,
    [id]
  );
  if (r.rows.length === 0 || r.rows[0].status !== "published" || r.rows[0].hidden) {
    res.status(404).send("Event not found.");
    return null;
  }
  if (r.rows[0].ended) {
    res.status(409).json({ error: "event_ended", message: "This event has already ended." });
    return null;
  }
  return r.rows[0].id;
}

app.put("/events/:id/interest", requireAuth, async (req, res) => {
  try {
    const id = await veljavenDogodekZaNacrt(req.params.id, res);
    if (!id) return;
    await pool.query(
      "INSERT INTO event_interest (event_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING",
      [id, req.user.userId]
    );
    return res.status(200).json({ plan: await mojNacrtNaDogodku(id, req.user.userId) });
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

app.delete("/events/:id/interest", requireAuth, async (req, res) => {
  try {
    if (!/^\d+$/.test(String(req.params.id))) return res.status(400).send("Invalid event id.");
    await pool.query("DELETE FROM event_interest WHERE event_id=$1 AND user_id=$2", [req.params.id, req.user.userId]);
    return res.status(200).json({ plan: await mojNacrtNaDogodku(req.params.id, req.user.userId) });
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

// ---------------------------
// OGLEDI / "Check activity" (migracija 021)
// ---------------------------
// Javna pot brez zetona (kliknejo tudi neprijavljeni obiskovalci) — omejena po IP, da ene
// naprave ne moreta napihniti stevila. GDPR: view_counts nima IP-ja, uporabnika ne casa
// posameznega klika, samo agregiran dnevni stevec. Neveljaven id -> 204 tiho (aplikacija
// klic po odprtju zaslona sprozi "fire and forget" in ne sme dobiti napake, ki bi jo prikazala).
app.post("/views", omeji({ kljuc: "ogled", najvec: 600, oknoSekund: 3600, priNapaki: "odpri" }), async (req, res) => {
  try {
    const b = req.body || {};
    const eventId = b.event_id !== undefined ? celoId(b.event_id) : null;
    const clubIdVhod = b.club_id !== undefined ? celoId(b.club_id) : null;
    if (!eventId && !clubIdVhod) return res.status(204).end();

    let clubId = null;
    let dogodekId = null;
    if (eventId) {
      const r = await pool.query(
        `SELECT e.id, e.club_id FROM events e JOIN clubs c ON c.id = e.club_id
          WHERE e.id = $1 AND c.hidden = FALSE`,
        [eventId]
      );
      if (r.rows.length === 0) return res.status(204).end();
      clubId = r.rows[0].club_id;
      dogodekId = r.rows[0].id;
    } else {
      const r = await pool.query("SELECT id FROM clubs WHERE id=$1 AND hidden = FALSE", [clubIdVhod]);
      if (r.rows.length === 0) return res.status(204).end();
      clubId = r.rows[0].id;
    }

    await pool.query(
      `INSERT INTO view_counts (club_id, event_id, day, count) VALUES ($1, $2, CURRENT_DATE, 1)
       ON CONFLICT (club_id, COALESCE(event_id, 0), day) DO UPDATE SET count = view_counts.count + 1`,
      [clubId, dogodekId]
    );
    return res.status(204).end();
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

// POST /events (updated: accepts camelCase + snake_case, includes ticket fields)
app.post("/events", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  try {
    // accept both formats
    const clubId = req.body.clubId ?? req.body.club_id;
    const title = req.body.title;
    const description = req.body.description ?? "";
    const posterUrl = req.body.posterUrl ?? req.body.poster_url ?? "";
    const startAt = req.body.startAt ?? req.body.start_at;
    const endAt = req.body.endAt ?? req.body.end_at ?? null;
    const minAge = req.body.minAge ?? req.body.min_age;
    const genres = req.body.genres;
    const status = req.body.status ?? "published";

    const ticketPriceCents = req.body.ticketPriceCents ?? req.body.ticket_price_cents ?? null;
    const currency = (req.body.currency ?? "EUR").toString();
    const ticketUrl = (req.body.ticketUrl ?? req.body.ticket_url ?? "").toString();
    const capacity = req.body.capacity ?? null;
    if (capacity !== null) {
      const c = Number(capacity);
      if (!Number.isInteger(c) || c < 1 || c > 100000) return res.status(400).send("capacity must be a positive integer.");
    }

    if (!clubId || !title || !startAt) return res.status(400).send("Missing clubId, title or startAt.");
    if (!/^\d+$/.test(String(clubId))) return res.status(400).send("Invalid clubId.");
    if (String(title).trim().length === 0) return res.status(400).send("Title is required.");
    if (Number.isNaN(new Date(startAt).getTime())) return res.status(400).send("startAt must be a valid date.");
    if (endAt !== null && Number.isNaN(new Date(endAt).getTime())) return res.status(400).send("endAt must be a valid date.");
    if (!["draft", "published", "cancelled"].includes(status)) {
      return res.status(400).send("status must be draft, published or cancelled.");
    }
    if (ticketPriceCents !== null) {
      const c = Number(ticketPriceCents);
      if (!Number.isInteger(c) || c < 0) return res.status(400).send("ticketPriceCents must be a non-negative integer.");
    }
    if (genres !== undefined && !Array.isArray(genres)) return res.status(400).send("genres must be an array.");
    if (minAge !== undefined && minAge !== null) {
      const a = Number(minAge);
      if (!Number.isInteger(a) || a < 0 || a > 99) return res.status(400).send("minAge must be between 0 and 99.");
    }

    const clubR = await pool.query("SELECT id, owner_user_id, min_age, genres FROM clubs WHERE id=$1", [clubId]);
    if (clubR.rows.length === 0) return res.status(404).send("Club not found.");

    const club = clubR.rows[0];

    if (req.klub.role !== "admin" && Number(club.id) !== Number(req.klub.clubId)) {
      return res.status(403).send("You can only create events for your own club.");
    }

    const finalMinAge = (minAge ?? club.min_age ?? 18);
    const finalGenres = Array.isArray(genres) ? genres : (club.genres || []);

    const r = await pool.query(
      `INSERT INTO events
      (
        club_id, title, description, poster_url, start_at, end_at,
        min_age, genres, status,
        ticket_price_cents, currency, ticket_url, capacity
      )
      VALUES
      ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
      RETURNING *`,
      [
        clubId,
        title,
        description,
        posterUrl,
        startAt,
        endAt,
        finalMinAge,
        finalGenres,
        status,
        ticketPriceCents,
        currency,
        ticketUrl,
        capacity
      ]
    );

    // Sledilci kluba dobijo obvestilo (migracija 019). Samo objavljeni dogodki:
    // osnutka in odpovedanega ni smisla oznanjati. Napaka pri obvescanju NE sme
    // podreti ustvarjanja dogodka — ta je ze v bazi.
    if (r.rows[0].status === "published") {
      try { await obvestiSledilce(r.rows[0].id, clubId); }
      catch (e) { console.error("Obvescanje sledilcev ni uspelo:", e.message); }
    }

    res.status(201).json(r.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).send("Server error.");
  }
});

// Vsakemu sledilcu kluba vstavi obvestilo o dogodku. UNIQUE (user_id, event_id) poskrbi,
// da ponovna objava (draft -> published -> draft -> published) ne podvoji zvonca.
async function obvestiSledilce(eventId, clubId) {
  await pool.query(
    `INSERT INTO club_event_notifications (user_id, event_id)
     SELECT f.user_id, $1 FROM club_follows f WHERE f.club_id = $2
     ON CONFLICT (user_id, event_id) DO NOTHING`,
    [eventId, clubId]
  );
}

// Ali je migracija 002 (placila) ze pognana? Od nje naprej se racun ne sme
// vec trdo izbrisati, ker so narocila racunovodski dokumenti.
let obstajajoNarocila = false;
pool.query("SELECT to_regclass('public.orders') IS NOT NULL AS obstaja")
  .then(r => {
    obstajajoNarocila = r.rows[0].obstaja;
    console.log(obstajajoNarocila
      ? "Tabela orders obstaja -> brisanje racuna anonimizira"
      : "Tabele orders se ni -> brisanje racuna je trd izbris");
  })
  .catch(e => console.error("Ne morem preveriti tabele orders:", e.message));

// ---------------------------
// DOGODKI: urejanje in odpoved
// ---------------------------
// Doslej je obstajal samo POST /events. Klub dogodka ni mogel ne popraviti
// ne umakniti — niti ce je vpisal napacen datum ali ceno.

// Preveri, da dogodek obstaja in da ga sme urejati prijavljeni uporabnik.
async function dogodekZaUrejanje(req, res) {
  if (!/^\d+$/.test(req.params.id)) { res.status(400).send("Invalid event id."); return null; }

  const r = await pool.query(
    `SELECT e.id, e.club_id, e.status, c.owner_user_id,
            (COALESCE(e.end_at, e.start_at + INTERVAL '8 hours') <= NOW()) AS je_koncan
     FROM events e JOIN clubs c ON c.id = e.club_id
     WHERE e.id = $1`,
    [req.params.id]
  );
  if (r.rows.length === 0) { res.status(404).send("Event not found."); return null; }

  const d = r.rows[0];
  if (req.klub.role !== "admin" && Number(d.club_id) !== Number(req.klub.clubId)) {
    res.status(403).send("You can only manage events of your own club.");
    return null;
  }
  return d;
}

app.patch("/events/:id", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  try {
    const d = await dogodekZaUrejanje(req, res);
    if (!d) return;

    const b = req.body || {};
    const dovoljeno = {
      title:              b.title,
      description:        b.description,
      poster_url:         b.posterUrl        ?? b.poster_url,
      start_at:           b.startAt          ?? b.start_at,
      end_at:             b.endAt            ?? b.end_at,
      min_age:            b.minAge           ?? b.min_age,
      genres:             b.genres,
      status:             b.status,
      ticket_price_cents: b.ticketPriceCents ?? b.ticket_price_cents,
      currency:           b.currency,
      ticket_url:         b.ticketUrl        ?? b.ticket_url,
      capacity:           b.capacity,
      // Posnetek koncanega dogodka (migracija 019). Prazen niz = odstrani.
      recap_video_url:    b.recapVideoUrl    ?? b.recap_video_url,
    };

    // Posnetek sme dobiti SAMO koncan dogodek, ki je med tremi najbolj popularnimi
    // dogodki svojega kluba (po prodanih vstopnicah). Brez te meje bi stran kluba
    // nalagala poljubno mnogo videov — zato je meja na strezniku, ne samo v aplikaciji.
    if (dovoljeno.recap_video_url !== undefined) {
      const v = String(dovoljeno.recap_video_url ?? "").trim();
      if (v !== "" && !(v.length <= 500 && /^https:\/\/\S+$/.test(v))) {
        return res.status(400).send("recapVideoUrl must be an https URL.");
      }
      if (v !== "") {
        if (!d.je_koncan) return res.status(400).send("Recap video can only be added to an event that has ended.");
        const top = await popularniDogodkiKluba(d.club_id);
        if (!top.map(Number).includes(Number(d.id))) {
          return res.status(400).json({
            error: "not_top_event",
            message: `Recap video is allowed only on the club's top ${NAJVEC_POPULARNIH} past events by tickets sold.`,
          });
        }
      }
      dovoljeno.recap_video_url = v;
    }

    if (dovoljeno.capacity !== undefined && dovoljeno.capacity !== null) {
      const c = Number(dovoljeno.capacity);
      if (!Number.isInteger(c) || c < 1 || c > 100000) return res.status(400).send("capacity must be a positive integer.");
    }
    if (dovoljeno.status !== undefined &&
        !["draft","published","cancelled"].includes(dovoljeno.status)) {
      return res.status(400).send("status must be draft, published or cancelled.");
    }
    if (dovoljeno.genres !== undefined && !Array.isArray(dovoljeno.genres)) {
      return res.status(400).send("genres must be an array.");
    }
    if (dovoljeno.ticket_price_cents !== undefined && dovoljeno.ticket_price_cents !== null) {
      const c = Number(dovoljeno.ticket_price_cents);
      if (!Number.isInteger(c) || c < 0) return res.status(400).send("ticketPriceCents must be a non-negative integer.");
    }

    const sets = [], vrednosti = [];
    for (const [k, v] of Object.entries(dovoljeno)) {
      if (v === undefined) continue;
      vrednosti.push(v);
      sets.push(`${k} = $${vrednosti.length}`);
    }
    if (sets.length === 0) return res.status(400).send("Nothing to update.");

    vrednosti.push(d.id);
    const r = await pool.query(
      `UPDATE events SET ${sets.join(", ")} WHERE id = $${vrednosti.length} RETURNING *`,
      vrednosti
    );
    razprodanoPozabi("v:" + d.id);   // capacity ali status se je morda spremenil

    // Dogodek je sele zdaj postal objavljen -> sledilci kluba dobijo obvestilo (migracija 019).
    if (d.status !== "published" && r.rows[0].status === "published") {
      try { await obvestiSledilce(r.rows[0].id, d.club_id); }
      catch (e) { console.error("Obvescanje sledilcev ni uspelo:", e.message); }
    }

    return res.status(200).json(r.rows[0]);
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

app.delete("/events/:id", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  try {
    const d = await dogodekZaUrejanje(req, res);
    if (!d) return;

    // Ce so na dogodek prodane vstopnice, se NE brise. Kupci imajo vstopnice,
    // ki morajo ostati veljavne kot dokazilo, in narocilo je racunovodski
    // dokument. Dogodek se v tem primeru odpove, ne izbrise.
    if (obstajajoNarocila) {
      const n = await pool.query(
        "SELECT COUNT(*)::int AS n FROM orders WHERE event_id=$1 AND status IN ('paid','partially_refunded')",
        [d.id]
      );
      if (n.rows[0].n > 0) {
        const r = await pool.query(
          "UPDATE events SET status='cancelled' WHERE id=$1 RETURNING *", [d.id]
        );
        return res.status(200).json({
          message: "Event has sold tickets and was cancelled instead of deleted.",
          orders: n.rows[0].n,
          event: r.rows[0],
        });
      }
    }

    await pool.query("DELETE FROM events WHERE id=$1", [d.id]);
    return res.status(200).json({ message: "Event deleted." });
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

// ---------------------------
// ISKANJE
// ---------------------------
// SearchView je doslej iskal na napravi, po prvih 100 klubih, ki jih je vrnil
// strezik, in samo po klubih — ceprav polje obljublja "Search clubs or events".
app.get("/search", async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();
    if (q.length < 2) return res.status(400).send("Query must be at least 2 characters.");

    const limit = stevilo(req.query.limit, 20, 50);
    const vzorec = `%${q}%`;

    const [klubi, dogodki] = await Promise.all([
      pool.query(
        `SELECT id, name, city, logo_url, lat, lng, genres
         FROM clubs
         WHERE hidden = FALSE
           AND (name ILIKE $1 OR city ILIKE $1 OR description ILIKE $1)
         ORDER BY (name ILIKE $2) DESC, name
         LIMIT $3`,
        [vzorec, `${q}%`, limit]
      ),
      pool.query(
        `SELECT e.id, e.club_id, e.title, e.poster_url, e.start_at,
                e.ticket_price_cents, e.currency, c.name AS club_name
         FROM events e JOIN clubs c ON c.id = e.club_id
         WHERE e.status = 'published' AND c.hidden = FALSE
           AND (e.title ILIKE $1 OR e.description ILIKE $1 OR c.name ILIKE $1)
         ORDER BY (e.start_at > NOW()) DESC, e.start_at
         LIMIT $2`,
        [vzorec, limit]
      ),
    ]);

    return res.status(200).json({
      query: q,
      clubs: klubi.rows,
      events: dogodki.rows,
      total: klubi.rows.length + dogodki.rows.length,
    });
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

// ---------------------------
// PROŠNJE USTVARJALCEV (javna oddaja) + ADMIN PANEL
// ---------------------------
// Do migracije 006 ni obstajala nobena pot, po kateri bi klub sploh nastal:
// prošnje s spletne strani so šle v Supabase, ki ga backend ne vidi, vlogo
// 'business' pa ni imel kdo dodeliti. Zdaj: aplikacija (ali kdorkoli) odda
// prošnjo sem, admin jo v panelu (/admin) odobri -> uporabnik dobi vlogo
// 'business' in prazen klub z imenom iz prošnje.
//
// Vse poti /admin/api/* zahtevajo vlogo admin (requireRole). Aplikacija in
// panel vlogo samo kažeta; uveljavlja jo strežnik.

const STOLPCI_PROSNJE = `id, user_id, business_name, business_type, business_address, city,
  licence_id, contact_name, contact_role, email, phone, message,
  status, decided_at, decided_by, decision_note, club_id, created_at`;

// Uporabnik brez password_hash in brez ničesar, kar bi bilo za panel odveč.
const ADMIN_POLJA_UPORABNIKA = `id, email, username, role, email_verified, avatar_url,
  phone, date_of_birth, country, onboarded_at, failed_login_count, locked_until, created_at`;

// Klub za admina: javni stolpci + hidden + stanje Stripa (brez stripe_account_id,
// ki ga panel ne potrebuje in ki ne sme uhajati nikamor).
const ADMIN_STOLPCI_KLUBA = `c.id, c.owner_user_id, c.name, c.logo_url, c.banner_url, c.description,
  c.contact_email, c.contact_phone, c.instagram, c.website, c.address, c.city, c.country,
  c.lat, c.lng, c.min_age, c.genres, c.hidden, c.stripe_charges_enabled, c.commission_bps, c.created_at,
  u.email AS owner_email, u.username AS owner_username`;

const VELJAVEN_EMAIL = /^[^@\s]+@[^@\s.]+\.[^@\s]+$/;

function besedilo(v, najvec) {
  if (v === undefined || v === null) return "";
  return String(v).trim().slice(0, najvec);
}

// Neobvezna prijava: če je žeton priložen in veljaven, req.user obstaja;
// če ga ni ali je neveljaven, pot vseeno teče naprej (kot neprijavljen).
async function neobveznaPrijava(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return next();
  try { req.user = await razberiUporabnika(token); } catch (_) { /* neprijavljen */ }
  if (req.user && req.user.role === "backup") req.user = undefined; // racun za kopije je povsod razen na izvozu kot neprijavljen
  next();
}

// POST /creator-applications — javno, omejeno. Aplikacija ga kliče iz
// "Request for creator"; prijavljenemu uporabniku se prošnja veže na račun.
// Maili ob novi prošnji: obvestilo ekipi (TEAM_EMAIL, več naslovov z vejico;
// privzeto luka@outly.si, fedja@outly.si) in potrdilo prijavitelju. Do 11. 9. 2026
// je to za spletni obrazec delal Supabase/Brevo; zdaj spletna stran in
// aplikacija uporabljata isto pot, zato maili tu. Napaka pri pošiljanju NE
// podre prošnje (ta je že shranjena).
function ubeziHtml(s) { return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
async function posljiMailProsnja(p) {
  if (!resend) return;
  const from = process.env.EMAIL_FROM || "onboarding@resend.dev";
  const appName = process.env.APP_NAME || "Outly";
  const ekipa = String(process.env.TEAM_EMAIL || "luka@outly.si,fedja@outly.si").split(",").map(e => e.trim()).filter(Boolean);
  const vrstica = (k, v) => v ? `<tr><td style="padding:4px 12px 4px 0;color:#666">${k}</td><td style="padding:4px 0"><b>${ubeziHtml(v)}</b></td></tr>` : "";
  try {
    const r1 = await resend.emails.send({
      from, to: ekipa, replyTo: p.email,
      subject: `Nova prošnja ustvarjalca: ${p.businessName}`,
      html: `
    <div style="font-family: Arial, sans-serif; line-height:1.5">
      <h2>${appName} – nova prošnja ustvarjalca (#${p.id})</h2>
      <table>${vrstica("Podjetje", p.businessName)}${vrstica("Vrsta", p.businessType)}${vrstica("Naslov", p.businessAddress)}${vrstica("Kraj", p.city)}${vrstica("Licenca", p.licenceId)}${vrstica("Kontakt", p.contactName)}${vrstica("Vloga", p.contactRole)}${vrstica("E-naslov", p.email)}${vrstica("Telefon", p.phone)}${vrstica("Sporočilo", p.message)}${vrstica("Vir", p.userId ? "aplikacija (uporabnik #" + p.userId + ")" : "spletna stran")}</table>
      <p>Odobri ali zavrni v admin panelu: <a href="https://outly-backend-roy3.onrender.com/admin/">outly-backend-roy3.onrender.com/admin</a> → Prošnje.</p>
    </div>`,
    });
    if (r1 && r1.error) console.error("Resend napaka (prošnja, ekipa):", JSON.stringify(r1.error));
    const r2 = await resend.emails.send({
      from, to: p.email,
      subject: `We received your application, ${p.contactName}`,
      html: `
    <div style="font-family: Arial, sans-serif; line-height:1.5">
      <h2>${appName} – application received</h2>
      <p>Thanks for applying to bring <b>${ubeziHtml(p.businessName)}</b> to ${appName}.</p>
      <p>A real person reads every application. If we need documents — business licence, proof of ownership, tax number or bank details — we will ask for them in our reply. Please don't send them before we ask.</p>
      <p>We'll get back to you at this address.</p>
    </div>`,
    });
    if (r2 && r2.error) console.error("Resend napaka (prošnja, potrdilo):", JSON.stringify(r2.error));
  } catch (e) { console.error("Resend napaka (prošnja):", e); }
}

app.post("/creator-applications", omeji({ kljuc: "prosnja", najvec: 5, oknoSekund: 3600 }), neobveznaPrijava, async (req, res) => {
  try {
    const b = req.body || {};
    if (typeof b !== "object" || Array.isArray(b)) return res.status(400).send("Invalid body.");

    const businessName = besedilo(b.businessName ?? b.business_name, 120);
    const contactName  = besedilo(b.contactName  ?? b.contact_name, 120);
    // Prijavljeni uporabnik: e-naslov je njegov, ne more oddati prošnje za tujega.
    const email = (req.user ? String(req.user.email) : besedilo(b.email, 254)).toLowerCase();

    if (businessName.length < 2) return res.status(400).send("businessName is required (2-120 characters).");
    if (contactName.length < 2)  return res.status(400).send("contactName is required (2-120 characters).");
    if (!VELJAVEN_EMAIL.test(email)) return res.status(400).send("Valid email is required.");

    const phoneRaw = besedilo(b.phone, 40).replace(/[\s\-()]/g, "");
    if (phoneRaw && !/^\+?[0-9]{6,15}$/.test(phoneRaw)) {
      return res.status(400).send("phone must contain 6-15 digits, optionally with leading +.");
    }

    const r = await pool.query(
      `INSERT INTO creator_applications
        (user_id, business_name, business_type, business_address, city, licence_id,
         contact_name, contact_role, email, phone, message)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       RETURNING id, status, created_at`,
      [
        req.user ? req.user.userId : null,
        businessName,
        besedilo(b.businessType ?? b.business_type, 80),
        besedilo(b.businessAddress ?? b.business_address, 200),
        besedilo(b.city, 80),
        besedilo(b.licenceId ?? b.licence_id, 80),
        contactName,
        besedilo(b.contactRole ?? b.contact_role, 80),
        email,
        phoneRaw,
        besedilo(b.message, 2000),
      ]
    );
    console.log("Nova prošnja ustvarjalca:", r.rows[0].id, businessName, email);
    posljiMailProsnja({
      id: r.rows[0].id, userId: req.user ? req.user.userId : null, businessName, contactName, email, phone: phoneRaw,
      businessType: besedilo(b.businessType ?? b.business_type, 80), businessAddress: besedilo(b.businessAddress ?? b.business_address, 200),
      city: besedilo(b.city, 80), licenceId: besedilo(b.licenceId ?? b.licence_id, 80), contactRole: besedilo(b.contactRole ?? b.contact_role, 80),
      message: besedilo(b.message, 2000),
    }).catch(() => {});
    return res.status(201).json({
      message: "Application received. We will review it and get back to you by email.",
      id: r.rows[0].id, status: r.rows[0].status, createdAt: r.rows[0].created_at,
    });
  } catch (e) {
    // Odprta prošnja s tem e-naslovom že obstaja (ca_email_open_key).
    if (e && e.code === "23505") return res.status(409).send("An application for this email is already pending.");
    if (e && e.code === "23514") return res.status(400).send("Invalid application data.");
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

// Prijavljeni uporabnik vidi svoje prošnje (aplikacija pokaže "prošnja oddana / odobrena / zavrnjena").
app.get("/creator-applications/me", requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT id, business_name, status, decided_at, decision_note, club_id, created_at
       FROM creator_applications
       WHERE user_id = $1 OR LOWER(email) = LOWER($2)
       ORDER BY created_at DESC LIMIT 20`,
      [req.user.userId, req.user.email]
    );
    return res.status(200).json(r.rows);
  } catch (e) {
    console.error(e);
    return res.status(500).send("Server error.");
  }
});

// Vse pod /admin/api zahteva admina. Napaka je namenoma enaka za "ni žetona"
// (401) in "napačna vloga" (403) kot drugod.
const admin = express.Router();
admin.use(requireAuth, requireRole("admin"));

function celoId(v) { return /^\d+$/.test(String(v)) ? Number(v) : null; }
// Kot celoId, a samo v obsegu int4 (users.id je INTEGER): vecji id bi dal 22003 -> 500 namesto 400 (issue #132).
function celoId4(v) { const n = celoId(v); return n !== null && n <= 2147483647 ? n : null; }

// --- pregled ---
admin.get("/summary", async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT
        (SELECT COUNT(*)::int FROM creator_applications WHERE status='new') AS new_applications,
        (SELECT COUNT(*)::int FROM clubs)                                    AS clubs,
        (SELECT COUNT(*)::int FROM clubs WHERE hidden)                       AS hidden_clubs,
        (SELECT COUNT(*)::int FROM users)                                    AS users,
        (SELECT COUNT(*)::int FROM users WHERE role='business')              AS business_users,
        (SELECT COUNT(*)::int FROM users WHERE role='admin')                 AS admins,
        (SELECT COUNT(*)::int FROM events)                                   AS events,
        (SELECT COUNT(*)::int FROM events WHERE status='published' AND start_at > NOW()) AS upcoming_events`);
    return res.json(r.rows[0]);
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// --- prošnje ---
admin.get("/creator-applications", async (req, res) => {
  try {
    const status = String(req.query.status || "new");
    if (!["new", "approved", "rejected", "all"].includes(status)) {
      return res.status(400).send("status must be new, approved, rejected or all.");
    }
    const p = [];
    let kje = "";
    if (status !== "all") { p.push(status); kje = "WHERE status = $1"; }
    const r = await pool.query(
      `SELECT ${STOLPCI_PROSNJE} FROM creator_applications ${kje}
       ORDER BY (status='new') DESC, created_at DESC LIMIT 500`, p
    );
    return res.json(r.rows);
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// Odobri: uporabnik z e-naslovom prošnje dobi vlogo business in prazen klub.
admin.post("/creator-applications/:id/approve", async (req, res) => {
  const id = celoId(req.params.id);
  if (!id) return res.status(400).send("Invalid application id.");
  const opomba = besedilo((req.body || {}).note, 500);

  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    // FOR UPDATE: dva admina ne moreta iste prošnje odobriti dvakrat.
    const pr = await c.query(
      `SELECT ${STOLPCI_PROSNJE} FROM creator_applications WHERE id=$1 FOR UPDATE`, [id]
    );
    if (pr.rows.length === 0) { await c.query("ROLLBACK"); return res.status(404).send("Application not found."); }
    const p = pr.rows[0];
    if (p.status !== "new") { await c.query("ROLLBACK"); return res.status(409).send(`Application already ${p.status}.`); }

    // Uporabnik: po vezi na račun ali po e-naslovu (male črke, kot pri registraciji).
    const ur = await c.query(
      `SELECT id, email, role, email_verified FROM users
       WHERE id = $1 OR email = $2 ORDER BY (id = $1) DESC LIMIT 1 FOR UPDATE`,
      [p.user_id ?? -1, p.email.toLowerCase()]
    );
    if (ur.rows.length === 0) {
      await c.query("ROLLBACK");
      return res.status(409).json({
        error: "user_not_found",
        message: `No Outly account with email ${p.email}. The applicant must register in the app first.`,
      });
    }
    const u = ur.rows[0];

    // Poslovni del aplikacije vidi samo PRVI klub lastnika (LIMIT 1). Drugi
    // klub bi bil neviden in neurejljiv — zato ne ustvarjamo drugega.
    const ima = await c.query("SELECT id, name FROM clubs WHERE owner_user_id=$1 LIMIT 1", [u.id]);
    if (ima.rows.length > 0) {
      await c.query("ROLLBACK");
      return res.status(409).json({
        error: "user_has_club",
        message: `User ${u.email} already owns club "${ima.rows[0].name}" (id ${ima.rows[0].id}).`,
      });
    }

    // Admin ostane admin (requireRole admina povsod spusti); navaden uporabnik postane business.
    if (u.role === "user") await c.query("UPDATE users SET role='business' WHERE id=$1", [u.id]);

    const kr = await c.query(
      `INSERT INTO clubs (owner_user_id, name, address, city, contact_email, contact_phone)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, name`,
      [u.id, p.business_name, p.business_address, p.city, p.email, p.phone]
    );

    const posodobljena = await c.query(
      `UPDATE creator_applications
       SET status='approved', decided_at=NOW(), decided_by=$2, decision_note=$3, club_id=$4
       WHERE id=$1 RETURNING ${STOLPCI_PROSNJE}`,
      [id, req.user.userId, opomba, kr.rows[0].id]
    );
    // Vloga je v JWT: stari dostopni žeton velja še do 1 h, osvežitev prinese novo vlogo.
    await c.query("COMMIT");
    console.log(`Prošnja ${id} odobrena (admin ${req.user.userId}): uporabnik ${u.id} -> business, klub ${kr.rows[0].id}`);
    return res.status(200).json({ application: posodobljena.rows[0], club: kr.rows[0], userId: u.id, userEmail: u.email });
  } catch (e) {
    await c.query("ROLLBACK").catch(() => {});
    if (e && e.code === "23514") return res.status(400).send("Application data violates club constraints: " + (e.constraint || ""));
    console.error(e);
    return res.status(500).send("Server error.");
  } finally { c.release(); }
});

admin.post("/creator-applications/:id/reject", async (req, res) => {
  try {
    const id = celoId(req.params.id);
    if (!id) return res.status(400).send("Invalid application id.");
    const opomba = besedilo((req.body || {}).note, 500);
    const r = await pool.query(
      `UPDATE creator_applications
       SET status='rejected', decided_at=NOW(), decided_by=$2, decision_note=$3
       WHERE id=$1 AND status='new' RETURNING ${STOLPCI_PROSNJE}`,
      [id, req.user.userId, opomba]
    );
    if (r.rows.length === 0) {
      const obstaja = await pool.query("SELECT status FROM creator_applications WHERE id=$1", [id]);
      if (obstaja.rows.length === 0) return res.status(404).send("Application not found.");
      return res.status(409).send(`Application already ${obstaja.rows[0].status}.`);
    }
    return res.status(200).json(r.rows[0]);
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// --- klubi ---
admin.get("/clubs", async (req, res) => {
  try {
    const p = [];
    let kje = "";
    if (req.query.q) { p.push(`%${String(req.query.q).trim()}%`); kje = `WHERE c.name ILIKE $1 OR c.city ILIKE $1 OR u.email ILIKE $1`; }
    const r = await pool.query(
      `SELECT ${ADMIN_STOLPCI_KLUBA},
              (SELECT COUNT(*)::int FROM events e WHERE e.club_id = c.id) AS event_count
       FROM clubs c LEFT JOIN users u ON u.id = c.owner_user_id
       ${kje} ORDER BY c.created_at DESC LIMIT 500`, p
    );
    return res.json(r.rows);
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// Skupno preverjanje polj kluba za POST in PATCH. Vrne { sets, vrednosti } ali napako.
// Provizija kluba iz telesa ADMIN zahtevka (samo admin poti; klub je ne more nastaviti): commissionPercent = stevilo 0-50
// (npr. 2.5) ali null/"" = privzeta. Vrne { napaka } | { bps } (bps null = privzeta) | null (polja ni v telesu).
function provizijaIzTelesa(b) {
  const v = b.commissionPercent !== undefined ? b.commissionPercent : b.commission_percent;
  if (v === undefined) return null;
  if (v === null || v === "") return { bps: null };
  const n = Number(String(v).replace(",", "."));
  if (!Number.isFinite(n) || n < 0 || n > 50) return { napaka: "commissionPercent must be a number 0-50 (or empty for the default)." };
  const bps = Math.round(n * 100);
  if (Math.abs(bps - n * 100) > 1e-6) return { napaka: "commissionPercent may have at most 2 decimals." };
  return { bps };
}

function poljaKluba(b, zaVstavljanje) {
  const out = {};
  const bes = (kljuc, ...imena) => {
    for (const ime of imena) if (b[ime] !== undefined) { out[kljuc] = b[ime] === null ? "" : String(b[ime]).trim(); return; }
  };
  bes("name", "name");
  bes("description", "description");
  bes("logo_url", "logoUrl", "logo_url");
  bes("banner_url", "bannerUrl", "banner_url");
  bes("contact_email", "contactEmail", "contact_email");
  bes("contact_phone", "contactPhone", "contact_phone");
  bes("instagram", "instagram");
  bes("website", "website");
  bes("address", "address");
  bes("city", "city");
  bes("country", "country");

  if (out.name !== undefined && (out.name.length === 0 || out.name.length > 120)) return { napaka: "name is required (1-120 characters)." };
  if (out.contact_email !== undefined && out.contact_email && !VELJAVEN_EMAIL.test(out.contact_email)) return { napaka: "contactEmail is not a valid email." };
  for (const k of ["logo_url", "banner_url", "website"]) {
    if (out[k] && !/^https?:\/\//i.test(out[k])) return { napaka: `${k} must start with http:// or https://.` };
    if (out[k] && out[k].length > 500) return { napaka: `${k} too long.` };
  }
  if (out.description !== undefined && out.description.length > 5000) return { napaka: "description too long (max 5000)." };

  const lat = b.lat, lng = b.lng;
  if ((lat === undefined) !== (lng === undefined)) return { napaka: "lat and lng must be sent together." };
  if (lat !== undefined) {
    if (lat === null && lng === null) { out.lat = null; out.lng = null; }
    else {
      const a = Number(lat), o = Number(lng);
      if (!Number.isFinite(a) || !Number.isFinite(o) || a < -90 || a > 90 || o < -180 || o > 180) return { napaka: "lat/lng out of range." };
      out.lat = a; out.lng = o;
    }
  }
  const minAge = b.minAge ?? b.min_age;
  if (minAge !== undefined) {
    const n = Number(minAge);
    if (!Number.isInteger(n) || n < 0 || n > 99) return { napaka: "minAge must be an integer 0-99." };
    out.min_age = n;
  }
  if (b.genres !== undefined) {
    if (!Array.isArray(b.genres)) return { napaka: "genres must be an array." };
    const izbrani = [...new Set(b.genres.map(g => String(g).trim().toLowerCase()))];
    const neznani = izbrani.filter(g => !ZANRI.includes(g));
    if (neznani.length) return { napaka: `unknown genres: ${neznani.join(", ")}` };
    out.genres = izbrani;
  }
  if (b.hidden !== undefined) {
    if (typeof b.hidden !== "boolean") return { napaka: "hidden must be true or false." };
    out.hidden = b.hidden;
  }
  if (zaVstavljanje && out.name === undefined) return { napaka: "name is required." };
  return { polja: out };
}

async function lastnikPoEmailu(c, email) {
  const e = String(email || "").trim().toLowerCase();
  if (!VELJAVEN_EMAIL.test(e)) return { napaka: "ownerEmail is not a valid email." };
  const r = await c.query("SELECT id, email, role FROM users WHERE email=$1", [e]);
  if (r.rows.length === 0) return { napaka: `No account with email ${e}. The owner must register in the app first.` };
  return { uporabnik: r.rows[0] };
}

admin.post("/clubs", async (req, res) => {
  const b = req.body || {};
  const c = await pool.connect();
  try {
    if (b.ownerEmail === undefined && b.owner_email === undefined) return res.status(400).send("ownerEmail is required.");
    const pk = poljaKluba(b, true);
    if (pk.napaka) return res.status(400).send(pk.napaka);
    const prov = provizijaIzTelesa(b);
    if (prov && prov.napaka) return res.status(400).send(prov.napaka);
    if (prov) pk.polja.commission_bps = prov.bps;

    await c.query("BEGIN");
    const l = await lastnikPoEmailu(c, b.ownerEmail ?? b.owner_email);
    if (l.napaka) { await c.query("ROLLBACK"); return res.status(400).send(l.napaka); }
    const u = l.uporabnik;

    const ima = await c.query("SELECT id, name FROM clubs WHERE owner_user_id=$1 LIMIT 1", [u.id]);
    if (ima.rows.length > 0) {
      await c.query("ROLLBACK");
      return res.status(409).send(`User ${u.email} already owns club "${ima.rows[0].name}" (id ${ima.rows[0].id}). One club per business account.`);
    }
    if (u.role === "user") await c.query("UPDATE users SET role='business' WHERE id=$1", [u.id]);

    const stolpci = ["owner_user_id", ...Object.keys(pk.polja)];
    const vrednosti = [u.id, ...Object.values(pk.polja)];
    const r = await c.query(
      `INSERT INTO clubs (${stolpci.join(", ")})
       VALUES (${vrednosti.map((_, i) => `$${i + 1}`).join(", ")}) RETURNING id`,
      vrednosti
    );
    const nov = await c.query(
      `SELECT ${ADMIN_STOLPCI_KLUBA}, 0 AS event_count FROM clubs c LEFT JOIN users u ON u.id=c.owner_user_id WHERE c.id=$1`,
      [r.rows[0].id]
    );
    await c.query("COMMIT");
    return res.status(201).json(nov.rows[0]);
  } catch (e) {
    await c.query("ROLLBACK").catch(() => {});
    if (e && e.code === "23514") return res.status(400).send("Invalid club data: " + (e.constraint || "constraint"));
    console.error(e);
    return res.status(500).send("Server error.");
  } finally { c.release(); }
});

admin.patch("/clubs/:id", async (req, res) => {
  const id = celoId(req.params.id);
  if (!id) return res.status(400).send("Invalid club id.");
  const b = req.body || {};
  const c = await pool.connect();
  try {
    const pk = poljaKluba(b, false);
    if (pk.napaka) return res.status(400).send(pk.napaka);
    const prov = provizijaIzTelesa(b);
    if (prov && prov.napaka) return res.status(400).send(prov.napaka);
    if (prov) pk.polja.commission_bps = prov.bps;
    const polja = pk.polja;

    await c.query("BEGIN");
    const obstaja = await c.query("SELECT id, owner_user_id FROM clubs WHERE id=$1 FOR UPDATE", [id]);
    if (obstaja.rows.length === 0) { await c.query("ROLLBACK"); return res.status(404).send("Club not found."); }

    // Prenos lastništva po e-naslovu. Novi lastnik ne sme že imeti kluba.
    const novEmail = b.ownerEmail ?? b.owner_email;
    if (novEmail !== undefined) {
      const l = await lastnikPoEmailu(c, novEmail);
      if (l.napaka) { await c.query("ROLLBACK"); return res.status(400).send(l.napaka); }
      if (l.uporabnik.id !== obstaja.rows[0].owner_user_id) {
        const ima = await c.query("SELECT id FROM clubs WHERE owner_user_id=$1 AND id<>$2 LIMIT 1", [l.uporabnik.id, id]);
        if (ima.rows.length > 0) { await c.query("ROLLBACK"); return res.status(409).send(`User ${l.uporabnik.email} already owns another club.`); }
        if (l.uporabnik.role === "user") await c.query("UPDATE users SET role='business' WHERE id=$1", [l.uporabnik.id]);
        polja.owner_user_id = l.uporabnik.id;
      }
    }

    const kljuci = Object.keys(polja);
    if (kljuci.length === 0) { await c.query("ROLLBACK"); return res.status(400).send("Nothing to update."); }
    const vrednosti = Object.values(polja);
    vrednosti.push(id);
    await c.query(
      `UPDATE clubs SET ${kljuci.map((k, i) => `${k} = $${i + 1}`).join(", ")} WHERE id = $${vrednosti.length}`,
      vrednosti
    );
    const r = await c.query(
      `SELECT ${ADMIN_STOLPCI_KLUBA}, (SELECT COUNT(*)::int FROM events e WHERE e.club_id=c.id) AS event_count
       FROM clubs c LEFT JOIN users u ON u.id=c.owner_user_id WHERE c.id=$1`, [id]
    );
    await c.query("COMMIT");
    return res.status(200).json(r.rows[0]);
  } catch (e) {
    await c.query("ROLLBACK").catch(() => {});
    if (e && e.code === "23514") return res.status(400).send("Invalid club data: " + (e.constraint || "constraint"));
    if (e && e.code === "22P02") return res.status(400).send("Invalid value type.");
    console.error(e);
    return res.status(500).send("Server error.");
  } finally { c.release(); }
});

// --- uporabniki ---
admin.get("/users", async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();
    const p = [];
    let kje = "";
    if (q) { p.push(`%${q}%`); kje = "WHERE email ILIKE $1 OR username ILIKE $1"; }
    const r = await pool.query(
      `SELECT ${ADMIN_POLJA_UPORABNIKA},
              (SELECT COUNT(*)::int FROM clubs c WHERE c.owner_user_id = users.id) AS club_count
       FROM users ${kje} ORDER BY created_at DESC LIMIT 200`, p
    );
    return res.json(r.rows);
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// PATCH /admin/api/users/:id — { role } | { unlock: true } | { emailVerified: true }
admin.patch("/users/:id", async (req, res) => {
  try {
    const id = celoId(req.params.id);
    if (!id) return res.status(400).send("Invalid user id.");
    const b = req.body || {};
    const sets = [], vrednosti = [];
    const dodaj = (k, v) => { vrednosti.push(v); sets.push(`${k} = $${vrednosti.length}`); };
    let prekliciZetone = false;

    if (b.role !== undefined) {
      if (!["user", "business", "admin", "backup"].includes(b.role)) return res.status(400).send("role must be user, business, admin or backup.");
      // Admin si sam ne more vzeti vloge: sicer bi lahko ostal panel brez admina.
      if (id === req.user.userId && b.role !== "admin") return res.status(400).send("You cannot remove your own admin role.");
      dodaj("role", b.role);
      prekliciZetone = true;
    }
    if (b.unlock !== undefined) {
      if (b.unlock !== true) return res.status(400).send("unlock must be true.");
      dodaj("failed_login_count", 0);
      dodaj("locked_until", null);
    }
    // Ročna potrditev e-naslova: nadomešča migracijo 005, dokler Resend ne
    // pošilja vsem (domena outly.si še ni potrjena).
    if (b.emailVerified !== undefined) {
      if (b.emailVerified !== true) return res.status(400).send("emailVerified can only be set to true.");
      dodaj("email_verified", true);
    }
    if (sets.length === 0) return res.status(400).send("Nothing to update.");

    vrednosti.push(id);
    const r = await pool.query(
      `UPDATE users SET ${sets.join(", ")} WHERE id = $${vrednosti.length}
       RETURNING ${ADMIN_POLJA_UPORABNIKA}`, vrednosti
    );
    if (r.rows.length === 0) return res.status(404).send("User not found.");
    // Vloga pride iz baze ob vsakem klicu (Supabase Auth), preklic žetonov ni več potreben.
    console.log(`Admin ${req.user.userId} spremenil uporabnika ${id}:`, JSON.stringify(b));
    return res.status(200).json(r.rows[0]);
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// --- dogodki ---
admin.get("/events", async (req, res) => {
  try {
    const p = [];
    const pogoji = [];
    if (req.query.status) {
      if (!["draft", "published", "cancelled"].includes(String(req.query.status))) return res.status(400).send("Invalid status.");
      p.push(String(req.query.status)); pogoji.push(`e.status = $${p.length}`);
    }
    if (req.query.clubId) {
      const cid = celoId(req.query.clubId);
      if (!cid) return res.status(400).send("Invalid clubId.");
      p.push(cid); pogoji.push(`e.club_id = $${p.length}`);
    }
    const kje = pogoji.length ? "WHERE " + pogoji.join(" AND ") : "";
    const r = await pool.query(
      `SELECT e.id, e.club_id, c.name AS club_name, c.hidden AS club_hidden, e.title, e.poster_url,
              e.start_at, e.end_at, e.min_age, e.genres, e.status, e.ticket_price_cents, e.currency,
              e.ticket_url, e.created_at
       FROM events e JOIN clubs c ON c.id = e.club_id
       ${kje} ORDER BY e.start_at DESC LIMIT 500`, p
    );
    return res.json(r.rows);
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// Umik dogodka: status -> cancelled. Ne briše: če bodo kdaj prodane vstopnice,
// so naročila računovodski dokument (glej DELETE /events/:id).
admin.patch("/events/:id", async (req, res) => {
  try {
    const id = celoId(req.params.id);
    if (!id) return res.status(400).send("Invalid event id.");
    const status = (req.body || {}).status;
    if (!["draft", "published", "cancelled"].includes(status)) return res.status(400).send("status must be draft, published or cancelled.");
    const r = await pool.query(
      `UPDATE events SET status=$2 WHERE id=$1
       RETURNING id, club_id, title, start_at, status`, [id, status]
    );
    if (r.rows.length === 0) return res.status(404).send("Event not found.");
    console.log(`Admin ${req.user.userId} dogodek ${id} -> ${status}`);
    return res.status(200).json(r.rows[0]);
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// --- finance ---
// GET /admin/api/finance?from=YYYY-MM-DD&to=YYYY-MM-DD
// Promet celotne platforme za admin panel: skupaj, po klubih, po dogodkih,
// po dnevih, zadnja naročila. Zneski v centih, EUR. "Prihodek Outlyja" =
// application_fee_cents (provizija PROVIZIJA_ODSTOTEK); "za klube" = bruto
// minus provizija minus vračila. Štejejo se samo plačana naročila
// (paid, partially_refunded); v testnem načinu (Stripe še ni) so to naročila
// s public_ref 'test_%' — panel to jasno označi.
admin.get("/finance", async (req, res) => {
  try {
    const dan = (v) => (typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v)) ? v : null;
    const do_ = dan(req.query.to) || new Date().toISOString().slice(0, 10);
    const od = dan(req.query.from) || new Date(Date.now() - 29 * 864e5).toISOString().slice(0, 10);
    if (od > do_) return res.status(400).send("from must be before to.");
    // Meji sta datuma; zgornja je vključujoča (do konca dneva).
    const p = [od, do_];
    // o.guest_list_id IS NULL: guest lista (035, I24) ni prodaja (brez zneska); ne sme v stevilo narocil, kupcev, vstopnic.
    const KJE = `o.status IN ('paid','partially_refunded') AND o.guest_list_id IS NULL AND o.created_at >= $1::date AND o.created_at < ($2::date + INTERVAL '1 day')`;

    const [skupaj, poKlubih, poDogodkih, poDnevih, zadnja, vseh] = await Promise.all([
      pool.query(
        `SELECT COALESCE(SUM(o.total_cents),0)::int AS gross_cents,
                COALESCE(SUM(o.application_fee_cents),0)::int AS fee_cents,
                COALESCE(SUM(o.refunded_cents),0)::int AS refunded_cents,
                COALESCE(SUM(o.total_cents - o.application_fee_cents - o.refunded_cents),0)::int AS clubs_net_cents,
                COALESCE(SUM(o.quantity) FILTER (WHERE o.table_id IS NULL),0)::int AS tickets_sold,
                COUNT(*)::int AS orders,
                COUNT(DISTINCT COALESCE(o.user_id::text, lower(o.guest_email)))::int AS buyers,
                COUNT(DISTINCT o.club_id)::int AS clubs_with_sales,
                COUNT(*) FILTER (WHERE o.stripe_payment_intent_id LIKE 'test_%')::int AS test_orders
         FROM orders o WHERE ${KJE}`, p),
      pool.query(
        `SELECT c.id, c.name, c.city, c.stripe_charges_enabled, c.stripe_payouts_enabled,
                COALESCE(SUM(o.total_cents),0)::int AS gross_cents,
                COALESCE(SUM(o.application_fee_cents),0)::int AS fee_cents,
                COALESCE(SUM(o.refunded_cents),0)::int AS refunded_cents,
                COALESCE(SUM(o.total_cents - o.application_fee_cents - o.refunded_cents),0)::int AS net_cents,
                COALESCE(SUM(o.quantity) FILTER (WHERE o.table_id IS NULL),0)::int AS tickets_sold,
                COUNT(o.id)::int AS orders
         FROM clubs c LEFT JOIN orders o ON o.club_id = c.id AND ${KJE}
         GROUP BY c.id ORDER BY gross_cents DESC, c.name`, p),
      pool.query(
        `SELECT e.id, e.title, e.start_at, e.status, e.ticket_price_cents, e.capacity, e.sold_count,
                c.name AS club_name,
                COALESCE(SUM(o.total_cents),0)::int AS gross_cents,
                COALESCE(SUM(o.application_fee_cents),0)::int AS fee_cents,
                COALESCE(SUM(o.quantity) FILTER (WHERE o.table_id IS NULL),0)::int AS tickets_sold,
                (SELECT COUNT(*)::int FROM tickets t WHERE t.event_id = e.id AND t.status = 'used') AS checked_in
         FROM events e JOIN clubs c ON c.id = e.club_id
         LEFT JOIN orders o ON o.event_id = e.id AND ${KJE}
         GROUP BY e.id, c.name HAVING COUNT(o.id) > 0
         ORDER BY gross_cents DESC LIMIT 50`, p),
      pool.query(
        `SELECT to_char(d.dan, 'YYYY-MM-DD') AS day,
                COALESCE(SUM(o.total_cents),0)::int AS gross_cents,
                COALESCE(SUM(o.application_fee_cents),0)::int AS fee_cents,
                COALESCE(SUM(o.quantity) FILTER (WHERE o.table_id IS NULL),0)::int AS tickets,
                COUNT(o.id)::int AS orders
         FROM generate_series($1::date, $2::date, '1 day') AS d(dan)
         LEFT JOIN orders o ON o.status IN ('paid','partially_refunded') AND o.guest_list_id IS NULL
              AND o.created_at >= d.dan AND o.created_at < d.dan + INTERVAL '1 day'
         GROUP BY d.dan ORDER BY d.dan`, p),
      pool.query(
        `SELECT ${STOLPCI_NAROCILA}, e.title AS event_title, c.name AS club_name, COALESCE(u.username, ${IME_GOSTA}) AS buyer_username
         FROM orders o JOIN events e ON e.id = o.event_id JOIN clubs c ON c.id = o.club_id
         LEFT JOIN users u ON u.id = o.user_id
         WHERE o.created_at >= $1::date AND o.created_at < ($2::date + INTERVAL '1 day') AND o.guest_list_id IS NULL
         ORDER BY o.created_at DESC LIMIT 100`, p),
      pool.query(
        `SELECT COALESCE(SUM(o.total_cents),0)::int AS gross_cents,
                COALESCE(SUM(o.application_fee_cents),0)::int AS fee_cents,
                COALESCE(SUM(o.quantity) FILTER (WHERE o.table_id IS NULL),0)::int AS tickets_sold, COUNT(*)::int AS orders
         FROM orders o WHERE o.status IN ('paid','partially_refunded') AND o.guest_list_id IS NULL`),
    ]);
    return res.json({
      mode: testniNacinPlacil() ? "test" : "live",
      fee_percent: PROVIZIJA_ODSTOTEK,
      from: od, to: do_,
      summary: skupaj.rows[0],
      all_time: vseh.rows[0],
      by_club: poKlubih.rows,
      by_event: poDogodkih.rows,
      by_day: poDnevih.rows,
      recent_orders: zadnja.rows,
    });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// --- varnostna kopija ---
// GET /admin/api/export — logični izvoz VSEH tabel v shemi public kot JSON
// (vrstice + trenutne vrednosti zaporedij), v enem posnetku (REPEATABLE READ),
// da so tabele med seboj skladne. Samo branje; nič se ne spremeni.
// Namenjeno varnostnim kopijam pred večjimi migracijami (Render brezplačni
// načrt kopij nima). Vsebuje tudi odtise gesel — datoteko hrani zasebno.
//
// IZVOZ JE TOK (issue #23): odgovor se piše sproti, tabelo za tabelo in
// po IZVOZ_VRSTIC vrstic naenkrat prek strežniškega kurzorja, zato poraba
// pomnilnika ni odvisna od velikosti baze (prej: 120k vstopnic = 56 MB
// odgovora, RSS +170 MB; pri 512 MB paketu OOM). Oblika izhoda je BAJT ZA BAJTOM
// enaka kot prej (isto kot JSON.stringify celotnega objekta) — obstoječe kopije in
// db/obnovi_izvoz.js jo berejo: {exported_at, postgres, tables:{ime:{count,columns,rows}}, sequences}.
// Test: _testi/test_export_tok.js (primerja z referenčno stari izvedbo, meri RSS, prekinitev odjemalca).
const IZVOZ_VRSTIC = 500;
// Varovalki pred bralcem, ki neha brati ali pred bazo, ki prekine povezavo (izvoz drži transakcijo z
// AccessShareLock na vseh prebranih tabelah: migracija ob deployu bi čakala nanjo, za njo pa vsa navadna branja):
//  - IZVOZ_DRAIN_TIMEOUT_MS: koliko čakamo, da odjemalec sprazni medpomnilnik ('drain'); nato res.destroy() + ROLLBACK;
//  - IZVOZ_IDLE_TX_MS: Postgres sam prekine sejo, ki miruje v transakciji (SET LOCAL idle_in_transaction_session_timeout).
// Drain mora biti krajši od idle, sicer prekine Postgres. Okolje je samo za teste (kratke meje).
const IZVOZ_DRAIN_MS = Number(process.env.EXPORT_DRAIN_TIMEOUT_MS) || 60000;
// Najvec 1 hkratni izvoz na proces (issue #116, pregled): izvoz drzi transakcijo in povezavo iz poola, racun za kopije pa je
// dosegljiv z enim geslom; vec hkratnih izvozov bi zasedlo pool in upocasnilo (ali zaustavilo) nakupe in sken. Drugi hkratni
// klic (admin ali backup) dobi 429 + Retry-After. Stevec je v pomnilniku procesa. Sprosti se vedno, ko rocnik konca:
//  - odjemalec je odsel ze PRED rocnikom ali med cakanjem na pool.connect() (res je ze unicen, 'close' je ze bil oddan,
//    zato ga ne cakamo, ampak preverimo res.destroyed): rocnik takoj vrne povezavo in sprosti stevec;
//  - sicer v `finally` (konec, prekinitev odjemalca, napaka baze, izpad povezave, bralec, ki ne bere IZVOZ_DRAIN_MS).
// Ni pa omejen cas, ko izvoz caka na zaklep tabele ali pocasen stavek v bazi: do takrat stevec ostane zaseden.
const IZVOZ_NAJVEC_HKRATNO = 1;
const IZVOZ_RETRY_AFTER_S = 30;
let izvozovTece = 0;
const IZVOZ_IDLE_TX_MS = Number(process.env.EXPORT_IDLE_TX_MS) || 120000;
// Pot je NAMENOMA na app (ne na routerju `admin`) in pred njim: `admin` zahteva vlogo admin, izvoz pa sme tudi `backup`
// (issue #116). Vse druge poti pod /admin/api gredo skozi `admin` in `backup` jih zavrne requireAuthNa (privzeto 403).
app.get("/admin/api/export", requireAuthIzvoz, requireRole("admin", "backup"), async (req, res) => {
  if (izvozovTece >= IZVOZ_NAJVEC_HKRATNO) {
    return res.status(429).set("Retry-After", String(IZVOZ_RETRY_AFTER_S))
      .json({ error: "export_busy", message: "Another export is already running. Try again later." });
  }
  // Odjemalec je ze odsel (zaprl povezavo med avtentikacijo): 'close' je ze oddan in ga ne bomo dobili vec.
  const odjemalecOdsel = () => res.destroyed || !res.socket || res.socket.destroyed;
  if (odjemalecOdsel()) return;
  izvozovTece++; // sprosti se natanko enkrat: spodaj (konec ali napaka pri pool.connect, odjemalec je odsel) ali v `finally`
  let prekinjeno = false;   // odjemalec je zaprl povezavo (ali smo jo zaprli mi), preden smo končali
  const dogodekZapiranja = () => { if (!res.writableEnded) prekinjeno = true; };
  res.on("close", dogodekZapiranja); // PRED pool.connect(): odjemalec lahko odide med cakanjem na povezavo
  let c;
  try { c = await pool.connect(); } catch (err) { res.off("close", dogodekZapiranja); izvozovTece--; throw err; }
  if (prekinjeno || odjemalecOdsel()) { res.off("close", dogodekZapiranja); izvozovTece--; c.release(); return; }
  let napaka = false;       // povezave ni več varno vrniti v pool
  let glavaPoslana = false;
  let razlog = "";          // zakaj je izvoz prekinjen (samo za log)
  // Povezava do baze se je med izvozom pokvarila (pg_terminate_backend, vzdrževanje, idle meja). Brez poslušalca bi
  // 'error' na odjemalcu, ki je izposojen iz poola, sesul CEL proces (Unhandled 'error' event): padel bi tudi sken na vratih.
  const naNapakoPovezave = (err) => {
    napaka = true;
    razlog = `povezava do baze prekinjena (${err && (err.code || err.message)})`;
    res.destroy(); // začet JSON se ne sme zaključiti kot poln: odjemalec dobi prekinjen odgovor
  };
  c.on("error", naNapakoPovezave);
  // Piše kos in upošteva povratni tlak (počasen odjemalec ne napolni pomnilnika). Bralec, ki ne bere dlje kot
  // IZVOZ_DRAIN_MS, je prekinjen: sicer bi transakcija (in zaklepi) ostala odprta za nedoločen čas.
  // Obljuba se vedno razresi: 'drain', 'close' ali rok; ce je res ze unicen, ne cakamo na dogodek, ki ga ne bo vec.
  const pisi = async (kos) => {
    if (prekinjeno || res.destroyed) throw new Error("odjemalec je prekinil izvoz");
    if (!res.write(kos)) {
      await new Promise((resolve) => {
        if (res.destroyed) return resolve();
        let rok = null;
        const konec = () => { clearTimeout(rok); res.off("drain", konec); res.off("close", konec); resolve(); };
        rok = setTimeout(() => { razlog = `bralec ne bere ${IZVOZ_DRAIN_MS} ms`; res.destroy(); konec(); }, IZVOZ_DRAIN_MS);
        res.on("drain", konec); res.on("close", konec);
      });
    }
    if (prekinjeno || res.destroyed) throw new Error("odjemalec je prekinil izvoz");
  };
  try {
    await c.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    // Varovalo: seja, ki miruje v tej transakciji, se prekine sama (set_config ne dovoli parametra v SET LOCAL).
    await c.query("SELECT set_config('idle_in_transaction_session_timeout', $1, true)", [String(IZVOZ_IDLE_TX_MS)]);
    // `omejitve` (omejevalnik poskusov) ni v izvozu: kratkotrajni stevci s hashi IP-jev niso podatki, ki bi jih kdo obnavljal,
    // in ne smejo v datoteko, ki jo admin prenese na disk.
    const t = await c.query(
      `SELECT table_name FROM information_schema.tables
       WHERE table_schema='public' AND table_type='BASE TABLE' AND table_name <> 'omejitve' ORDER BY table_name`
    );
    const v = await c.query("SELECT version() AS version, NOW() AS now");
    // DATE (OID 1082) v izvozu kot besedilo "YYYY-MM-DD": privzeti razčlenjevalnik
    // naredi Date v lokalnem času procesa in toISOString ga v pasu z odmikom
    // (Europe/Ljubljana) premakne za dan nazaj — date_of_birth bi po obnovi
    // pomenil drug rojstni dan (ujeto v _testi/test_obnova.js). Samo za ta klic,
    // odgovori API-ja se ne spremenijo.
    const tipiIzvoza = { getTypeParser: (oid, fmt) => (oid === 1082 ? (v) => v : pgTipi.getTypeParser(oid, fmt)) };
    // Od tu naprej so glave poslane: napaka ne more več postati 500 (glej catch).
    res.status(200);
    res.set("Content-Type", "application/json; charset=utf-8");
    res.set("Cache-Control", "no-store");
    glavaPoslana = true;
    await pisi(`{"exported_at":${JSON.stringify(v.rows[0].now)},"postgres":${JSON.stringify(v.rows[0].version)},"tables":{`);
    let prvaTabela = true;
    for (const { table_name } of t.rows) {
      const ime = `"${table_name.replace(/"/g, '""')}"`;
      // count mora biti pred vrsticami; isti posnetek (REPEATABLE READ), zato se ujema s prebranimi vrsticami.
      const n = (await c.query(`SELECT COUNT(*)::int AS n FROM ${ime}`)).rows[0].n;
      await c.query(`DECLARE izvoz_kurzor NO SCROLL CURSOR FOR SELECT * FROM ${ime}`);
      let prva = true, bilaVrstica = false;
      for (;;) {
        const r = await c.query({ text: `FETCH ${IZVOZ_VRSTIC} FROM izvoz_kurzor`, types: tipiIzvoza });
        let kos = "";
        if (prva) {
          // columns so v odgovoru FETCH tudi pri prazni tabeli
          kos = `${prvaTabela ? "" : ","}${JSON.stringify(table_name)}:{"count":${n},"columns":${JSON.stringify(r.fields.map((f) => f.name))},"rows":[`;
          prvaTabela = false; prva = false;
        }
        if (r.rows.length) {
          kos += (bilaVrstica ? "," : "") + r.rows.map((vrstica) => JSON.stringify(vrstica)).join(",");
          bilaVrstica = true;
        }
        if (r.rows.length < IZVOZ_VRSTIC) { await pisi(kos + "]}"); break; } // zadnji (nepolni ali prazni) kos
        await pisi(kos);
      }
      await c.query("CLOSE izvoz_kurzor");
    }
    const s = await c.query(
      `SELECT sequencename AS name, last_value FROM pg_sequences WHERE schemaname='public' ORDER BY sequencename`
    );
    await c.query("COMMIT");
    await pisi(`},"sequences":${JSON.stringify(s.rows)}}`);
    res.end();
    console.log(`Izvoz baze (${req.user.role} ${req.user.userId}, ${t.rows.length} tabel)`);
  } catch (e) {
    try { await c.query("ROLLBACK"); } catch (_) { napaka = true; }
    if (prekinjeno || razlog) {
      console.log(`Izvoz (${req.user.role} ${req.user.userId}) prekinjen (${razlog || "odjemalec je zaprl povezavo"})`);
    } else {
      console.error(e);
      // Glave so že poslane: začet JSON se ne sme zaključiti kot da je poln — povezavo prekinemo,
      // da odjemalec dobi napako, ne okrnjene kopije. Pred glavami je še vedno navaden 500.
      if (glavaPoslana) res.destroy(); else res.status(500).send("Server error.");
    }
  } finally {
    izvozovTece--; // PRVO: izjema v naslednjih vrsticah ne sme za vedno zakleniti stevca (potem bi kopija trajno dobivala 429)
    res.off("close", dogodekZapiranja);
    c.off("error", naNapakoPovezave);
    // Zavrzena povezava lahko izda se kasen 'error' (socket se zapre po release): ne sme sesuti procesa.
    if (napaka) c.on("error", () => {});
    c.release(napaka);
  }
});

app.use("/admin/api", admin);

// ---------------------------
// VSTOPNICE: nakup, moje vstopnice, prodaja kluba, skeniranje
// ---------------------------
// Model je v migraciji 002 (orders, tickets, sprožilci za zalogo). Denar:
// prodajalec je KLUB, Outly je posrednik s provizijo (application_fee).
//
// NAČIN PLAČILA. Stripe Connect še ni vključen (rabi Stripe račun in odločitev
// o proviziji). Do takrat deluje TESTNI NAČIN: naročilo se takoj označi kot
// plačano, denar se ne premakne, naročilo dobi oznako test_ v
// stripe_payment_intent_id in odgovor nosi mode:"test". Testni način je
// dovoljen SAMO, dokler STRIPE_SECRET_KEY ni nastavljen (ali izrecno
// TEST_PLACILA=true). Ko pride Stripe, ta pot dobi PaymentIntent in webhook;
// vse ostalo (zaloga, vstopnice, QR, skener, prodaja) ostane.
const PROVIZIJA_ODSTOTEK = Number(process.env.PROVIZIJA_ODSTOTEK || 10); // ODLOČITEV MARTINA — začasno 10 %
// Provizija za klub (migracija 031): clubs.commission_bps (bazne tocke, 100 = 1 %), sicer privzeta. Vrne cele cente (I9).
function provizijaCentov(znesekCentov, commissionBps) {
  const bps = commissionBps === null || commissionBps === undefined ? Math.round(PROVIZIJA_ODSTOTEK * 100) : commissionBps;
  return Math.round(znesekCentov * bps / 10000);
}
const NAJVEC_NA_NAROCILO = 10;

function testniNacinPlacil() {
  if (process.env.TEST_PLACILA === "true") return true;
  return !process.env.STRIPE_SECRET_KEY;
}

// ---------------------------
// STRIPE (issue #19): Checkout + Connect Express. Logika je v placila_stripe.js; tu so poti.
// ---------------------------
const placilaStripe = require("./placila_stripe");
// naPlacano: po COMMIT-u webhooka/pospravljalca poslje gostu mail z vstopnicami (nakup brez racuna, migracija 033); za navadna narocila ne stori nicesar.
const stripePlacila = placilaStripe.ustvari({ pool, naPlacano: (id) => posljiGostuVstopnice(id) });
stripePlacila.zazeni();
app.post("/stripe/webhook", express.raw({ type: "*/*", limit: "1mb" }), stripePlacila.webhook);

// Klub, za katerega gre (requireClub). Admin brez izbranega kluba ga mora izbrati (glava X-Outly-Club).
async function stripeKlub(req, res) {
  if (!req.klub || !req.klub.clubId) { res.status(400).send("Choose a club."); return null; }
  const r = await pool.query("SELECT id, name, stripe_account_id, stripe_charges_enabled, stripe_payouts_enabled FROM clubs WHERE id=$1", [req.klub.clubId]);
  if (!r.rows.length) { res.status(404).send("Club not found."); return null; }
  return r.rows[0];
}
function stripeNapaka(res, e, kaj) {
  console.error(`[stripe] ${kaj}:`, e && (e.message || e));
  return res.status(502).send("Payment provider error. Please try again.");
}

// Express racun kluba: ustvari ga najvec enkrat. Hkratna klika serializira zaklep na klub (velja med instancami), drugi
// po zaklepu vidi racun prvega. NAMENOMA brez Stripovega idempotentnega kljuca: Stripe si pod kljucem 24 h zapomni tudi
// ZAVRNITEV (3. 10. 2026: politika "Accounts v1" je bila izklopljena, po vklopu je isti kljuc se naprej vracal napako).
async function stripeRacunKluba(s, k, userId) {
  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    await c.query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))", [`stripe-racun:${k.id}`]);
    const ze = (await c.query("SELECT stripe_account_id FROM clubs WHERE id=$1", [k.id])).rows[0];
    if (ze && ze.stripe_account_id) { await c.query("COMMIT"); return ze.stripe_account_id; }
    const u = await c.query("SELECT email FROM users WHERE id=$1", [userId]);
    const nov = await s.accounts.create({
      type: "express",
      country: "SI",
      email: u.rows[0] ? u.rows[0].email : undefined,
      capabilities: { card_payments: { requested: true }, transfers: { requested: true } },
      business_profile: { name: k.name },
      metadata: { club_id: String(k.id) },
    });
    await c.query("UPDATE clubs SET stripe_account_id=$2 WHERE id=$1", [k.id, nov.id]);
    await c.query("COMMIT");
    console.log(`[stripe] klub ${k.id}: nov Connect racun`);
    return nov.id;
  } catch (e) { await c.query("ROLLBACK").catch(() => {}); throw e; }
  finally { c.release(); }
}

// POST /business/stripe/onboard — lastnik: ustvari (ce se ni) Express racun kluba in vrne povezavo do Stripovega obrazca.
// Odgovor: { url }. Povratni naslovi vodijo v spletne nastavitve kluba (?stripe=vrnitev | ?stripe=osvezi).
app.post("/business/stripe/onboard", requireAuth, requireClub("owner"), async (req, res) => {
  const s = placilaStripe.stripe();
  if (!s) return res.status(503).send("Payments are not configured yet.");
  try {
    const k = await stripeKlub(req, res);
    if (!k) return;
    let racun = k.stripe_account_id;
    if (!racun) racun = await stripeRacunKluba(s, k, req.user.userId);
    const nastavitve = `${placilaStripe.osnovaSpleta()}/app/business/${k.id}/settings`;
    const povezava = await s.accountLinks.create({
      account: racun, type: "account_onboarding",
      refresh_url: `${nastavitve}?stripe=osvezi`, return_url: `${nastavitve}?stripe=vrnitev`,
    });
    return res.json({ url: povezava.url });
  } catch (e) { return stripeNapaka(res, e, "onboarding"); }
});

// GET /business/stripe/status — lastnik/manager: ali klub sprejema placila. Osvezi stanje iz Stripa (ce webhook zamuja).
// stripe_account_id se NE vraca (STATE: lastnik ga ne vidi).
app.get("/business/stripe/status", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  try {
    const k = await stripeKlub(req, res);
    if (!k) return;
    const s = placilaStripe.stripe();
    const osnova = { configured: !!s, sandbox: placilaStripe.jeSandbox(), connected: !!k.stripe_account_id,
      charges_enabled: k.stripe_charges_enabled, payouts_enabled: k.stripe_payouts_enabled, details_submitted: false, requirements_due: [] };
    if (!s || !k.stripe_account_id) return res.json(osnova);
    const a = await s.accounts.retrieve(k.stripe_account_id);
    await pool.query(
      `UPDATE clubs SET stripe_charges_enabled=$2, stripe_payouts_enabled=$3,
              stripe_onboarded_at = CASE WHEN $4 AND stripe_onboarded_at IS NULL THEN NOW() ELSE stripe_onboarded_at END
        WHERE id=$1`, [k.id, !!a.charges_enabled, !!a.payouts_enabled, !!a.details_submitted]);
    return res.json({ ...osnova, charges_enabled: !!a.charges_enabled, payouts_enabled: !!a.payouts_enabled,
      details_submitted: !!a.details_submitted, requirements_due: (a.requirements && a.requirements.currently_due) || [],
      disabled_reason: (a.requirements && a.requirements.disabled_reason) || null });
  } catch (e) { return stripeNapaka(res, e, "status"); }
});

// POST /business/stripe/dashboard — lastnik: enkratna povezava v Stripov Express pregled (izplacila, vracila, podatki).
app.post("/business/stripe/dashboard", requireAuth, requireClub("owner"), async (req, res) => {
  const s = placilaStripe.stripe();
  if (!s) return res.status(503).send("Payments are not configured yet.");
  try {
    const k = await stripeKlub(req, res);
    if (!k) return;
    if (!k.stripe_account_id) return res.status(409).send("Connect Stripe first.");
    const l = await s.accounts.createLoginLink(k.stripe_account_id);
    return res.json({ url: l.url });
  } catch (e) {
    if (e && e.type === "StripeInvalidRequestError") return res.status(409).send("Finish Stripe onboarding first.");
    return stripeNapaka(res, e, "dashboard");
  }
});

// Po COMMIT-u nakupa v Stripe nacinu: Checkout seja za cakajoce narocilo. Ob napaki narocilo -> failed (sprosti zalogo/mizo).
// Vrne true, ce je seja ustvarjena; sicer je odgovor 502 ze poslan.
// odjemalec: "ios" (glava X-Outly-Client: ios) ali splet - doloci povratna naslova Checkouta (placila_stripe.js povratniNaslovi).
const odjemalecNakupa = (req) => (String(req.get("x-outly-client") || "").toLowerCase() === "ios" ? "ios" : "splet");
// Omejitev cakajocih (neplacanih) narocil (pregled 5. 10. 2026): cakajoce Stripe narocilo drzi zalogo ali mizo do ~35 min.
// Brez omejitve bi en racun z nekaj kliki zasedel razprodan dogodek ali vse VIP mize, ne da bi kaj placal.
// Pravilo: najvec 1 cakajoce narocilo na dogodek in najvec CAKAJOCA_NAJVEC skupaj na uporabnika. Kupec nedokoncano
// placilo nadaljuje prek checkout_url v GET /me/orders ali pocaka, da seja poteče (pospravljalec jo sprosti).
// Zaklep (uporabnik) v isti transakciji kot INSERT: dva hkratna nakupa istega uporabnika ne prideta mimo stetja oba.
// Ponovitev z istim Idempotency-Key se vrne prej (plast 3), zato je to pravilo ne zavrne.
const CAKAJOCA_NAJVEC = 3;
const CAKAJOCA_ZAKLEP_RAZRED = 73110;   // prvi del dvodelnega advisory kljuca (drugi = id uporabnika); ne trci z migrate.js (enodelni kljuc)
async function omejitevCakajocih(c, userId, eventId) {
  await c.query("SELECT pg_advisory_xact_lock($1::int, $2::int)", [CAKAJOCA_ZAKLEP_RAZRED, userId]);
  const r = await c.query(
    `SELECT COUNT(*)::int AS vse, COUNT(*) FILTER (WHERE event_id = $2)::int AS ta
       FROM orders WHERE user_id = $1 AND status = 'pending'`, [userId, eventId]);
  const { vse, ta } = r.rows[0];
  if (ta > 0) return "You already have an unfinished payment for this event. Finish it in My tickets, or wait up to 30 minutes for it to expire.";
  if (vse >= CAKAJOCA_NAJVEC) return "You have too many unfinished payments. Finish one in My tickets, or wait up to 30 minutes for them to expire.";
  return null;
}

async function nakupStripeSeja(res, c, { oid, opis, kolicina, cenaEnoteCents, racunKluba, email, eventId, odjemalec, povratna }) {
  try {
    const nr = await c.query("SELECT id, public_ref, currency, application_fee_cents FROM orders WHERE id=$1", [oid]);
    const seja = await placilaStripe.ustvariCheckout({ narocilo: nr.rows[0], opis, kolicina, cenaEnoteCents, racunKluba, email, eventId, odjemalec, povratna });
    await c.query(
      "UPDATE orders SET stripe_checkout_session_id=$2, checkout_url=$3, checkout_expires_at=to_timestamp($4) WHERE id=$1",
      [oid, seja.id, seja.url, seja.expires_at]);
    return true;
  } catch (e) {
    console.error(`[stripe] Checkout seja za narocilo ${oid} ni uspela:`, e && (e.message || e));
    await c.query("UPDATE orders SET status='failed', cancelled_at=NOW() WHERE id=$1 AND status='pending'", [oid]).catch(() => {});
    res.status(502).send("Payment provider is unavailable. Please try again.");
    return false;
  }
}

// Koda QR: podpisan JSON, da jo skener preveri tudi brez omrežja (opomba 3 v 002).
// Skrivnost je QR_SECRET, sicer JWT_SECRET. Zamenjava skrivnosti razveljavi vse kode.
//
// Dve obliki (spremembe API-ja so samo dodajanje, kode na telefonih morajo delovati naprej):
//   v1 (stara): base64url(JSON).HMAC-SHA256[:32]      — preveri samo strežnik (skrivnost je samo tu)
//   v2 (nova):  o2.base64url(JSON).base64url(Ed25519) — podpis preveri kdorkoli z JAVNIM ključem
//               (GET /business/scan-key), zato skener na vratih deluje tudi brez povezave (issue #86).
// v2: podpisano je besedilo "o2.<base64url(JSON)>" (UTF-8), podpis je 64 B surovo. Telo: { v:2, t:serial, e:event_id, i:ustvarjena, k:kid }.
// Ključni par je izpeljan deterministično iz skrivnosti (HKDF), zato nove okoljske spremenljivke ni:
// kdor ima skrivnost, lahko ponareja (tako kot pri v1); kdor ima samo javni ključ, ne more.
const QR_V2_PREDPONA = "o2";
const QR_V2_HKDF_INFO = "outly-qr-ed25519-v1";
const ED25519_PKCS8_PREDPONA = Buffer.from("302e020100300506032b657004220420", "hex");
function qrSkrivnost() { return process.env.QR_SECRET || process.env.JWT_SECRET || ""; }
function podpisiQr(telo) {
  const b = Buffer.from(JSON.stringify(telo)).toString("base64url");
  const s = crypto.createHmac("sha256", qrSkrivnost()).update(b).digest("base64url").slice(0, 32);
  return `${b}.${s}`;
}
// Ključni par v2: izračunan enkrat (ob zagonu); če se skrivnost spremeni med procesom (testi), se izračuna znova.
let qrKljuciPredpomnjeni = null;
function qrKljuci() {
  const skrivnost = qrSkrivnost();
  if (qrKljuciPredpomnjeni && qrKljuciPredpomnjeni.skrivnost === skrivnost) return qrKljuciPredpomnjeni;
  const seme = Buffer.from(crypto.hkdfSync("sha256", Buffer.from(skrivnost, "utf8"), Buffer.alloc(0), QR_V2_HKDF_INFO, 32));
  const zasebni = crypto.createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_PREDPONA, seme]), format: "der", type: "pkcs8" });
  const javni = crypto.createPublicKey(zasebni);
  const javniSurov = Buffer.from(javni.export({ format: "jwk" }).x, "base64url"); // 32 B
  const kid = crypto.createHash("sha256").update(javniSurov).digest("base64url").slice(0, 11);
  qrKljuciPredpomnjeni = { skrivnost, zasebni, javni, javniSurov, kid };
  return qrKljuciPredpomnjeni;
}
function podpisiQrV2(telo) {
  const k = qrKljuci();
  const b = Buffer.from(JSON.stringify({ ...telo, k: k.kid })).toString("base64url");
  const sporocilo = `${QR_V2_PREDPONA}.${b}`;
  const s = crypto.sign(null, Buffer.from(sporocilo, "utf8"), k.zasebni).toString("base64url");
  return `${sporocilo}.${s}`;
}
const QR_NAJVEC_ZNAKOV = 1024;
// preveriQr NIKOLI ne vrže izjeme (vrne null): koda je vhod neznane osebe na vratih, ena zlonamerna koda ne sme podreti
// ne /scan ne celega paketa v scan-batch. Primerjava podpisa v1 je po BAJTIH (dolžina v znakih != dolžina v bajtih, npr. "é" x 32).
function preveriQr(koda) {
  try {
    if (typeof koda !== "string" || koda.length > QR_NAJVEC_ZNAKOV) return null;
    const deli = koda.trim().split(".");
    if (deli.length === 3 && deli[0] === QR_V2_PREDPONA) {
      const [, b, s] = deli;
      if (!/^[A-Za-z0-9_-]+$/.test(b) || !/^[A-Za-z0-9_-]{86}$/.test(s)) return null;
      if (!crypto.verify(null, Buffer.from(`${QR_V2_PREDPONA}.${b}`, "utf8"), qrKljuci().javni, Buffer.from(s, "base64url"))) return null;
      const t = JSON.parse(Buffer.from(b, "base64url").toString("utf8"));
      return t && t.v === 2 ? t : null;
    }
    if (deli.length !== 2) return null;
    const [b, s] = deli;
    const pricakovan = Buffer.from(crypto.createHmac("sha256", qrSkrivnost()).update(b).digest("base64url").slice(0, 32), "utf8");
    const dobljen = Buffer.from(s, "utf8");
    if (dobljen.length !== pricakovan.length || !crypto.timingSafeEqual(dobljen, pricakovan)) return null;
    return JSON.parse(Buffer.from(b, "base64url").toString("utf8"));
  } catch (_) { return null; }
}
// Nove kode so v2 (Ed25519). Stare v1 kode (HMAC) preveriQr še sprejme, dokler jih imajo uporabniki na telefonih.
function qrVstopnice(t) {
  return podpisiQrV2({ v: 2, t: t.serial, e: t.event_id, i: Math.floor(new Date(t.created_at).getTime() / 1000) });
}
try {
  qrKljuci();
  // Vedenja NE spreminjamo (zavrnitev bi lahko ustavila skeniranje v produkciji), samo glasno opozorimo.
  if (qrSkrivnost().length < 32) console.error(`OPOZORILO: QR_SECRET (ali rezervna JWT_SECRET) je ${qrSkrivnost() ? "krajsa od 32 znakov" : "prazna"} - QR kode vstopnic so ponarejljive (kdor ugane skrivnost, izdela veljavne kode). Nastavi nakljucno skrivnost z vsaj 32 znaki (npr. openssl rand -base64 48); to razveljavi vse obstojece QR kode.`);
} catch (e) { console.error("QR ključ ni na voljo:", e.message); }
function javnaRef() {
  // 8 znakov brez zamenljivih (0/O, 1/I): OUT-7K3M9QPX
  const abc = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
  let s = ""; const b = crypto.randomBytes(8);
  for (let i = 0; i < 8; i++) s += abc[b[i] % abc.length];
  return "OUT-" + s;
}

const STOLPCI_NAROCILA = `o.id, o.public_ref, o.event_id, o.club_id, o.quantity, o.unit_price_cents, o.total_cents,
  o.currency, o.application_fee_cents, o.status, o.buyer_email, o.created_at, o.paid_at, o.cancelled_at,
  o.refunded_cents, COALESCE(o.stripe_payment_intent_id LIKE 'test_%', FALSE) AS is_test,
  (o.table_id IS NOT NULL) AS is_vip, o.table_id, o.table_label, o.table_seats, o.package_name, o.package_description,
  (o.user_id IS NULL AND o.guest_email IS NOT NULL) AS is_guest`;
// Gostujoce narocilo (nakup brez racuna, migracija 033): user_id NULL + guest_email. Po prevzemu v racun (GET /me) je user_id nastavljen
// in narocilo ni vec »gostujoce«. V poslovnih pogledih se gost pokaze kot »Guest« (brez e-naslova kot imetnik; vratar ne vidi e-naslovov).
const GOST_OZNAKA = `(o.user_id IS NULL AND o.guest_email IS NOT NULL)`;
const IME_GOSTA = `CASE WHEN ${GOST_OZNAKA} THEN 'Guest' END`;
// Gostujoci IMETNIK (prenos vstopnice na e-naslov brez racuna, migracija 034): tickets.holder_is_guest. Vstopnica ostane vstopnica narocila
// kupca (ta ima racun), imetnik pa je gost: ni vrstica v `users`, e-naslova NIKJER ne vracamo (tudi lastniku kluba ne). Zastavica je loceno od
// e-naslova, ker se ta po koncu dogodka + 30 dni anonimizira (NULL), vstopnica pa NE sme spet postati »kupceva«.
const IME_GOSTA_IMETNIKA = `CASE WHEN ${GOST_OZNAKA} OR t.holder_is_guest THEN 'Guest' END`;
const STOLPCI_VSTOPNICE = `t.id, t.order_id, t.event_id, t.serial, t.status, t.used_at, t.created_at, t.holder_user_id`;
// VIP polja vstopnice (migracija 025): VIP vstopnica je vstopnica narocila z mizo. Zahteva alias `o` = orders.
const STOLPCI_VIP_VSTOPNICE = `(o.table_id IS NOT NULL) AS is_vip, o.table_label, o.table_seats, o.package_name, o.package_description`;
// Imetnik vstopnice: kdor jo je prejel s prenosom, sicer kupec (008).
// Gostujoci imetnik (034) NI nobeden uporabnik: IMETNIK je NULL (ne pade nazaj na kupca), zato ga ne najdejo ne /me/tickets ne prijateljski nacrti.
const IMETNIK = `(CASE WHEN t.holder_is_guest THEN NULL ELSE COALESCE(t.holder_user_id, o.user_id) END)`;
// Guest lista (migracija 035, I24): vstopnica narocila z orders.guest_list_id. Polji v odgovorih (scan, scan-list, poslovne vstopnice, /me/tickets):
// is_guest_list (privzeto false) in guest_list_host_username (pri gostiteljevi vstopnici je to on sam; NULL, ce gostitelj ne obstaja vec).
// Podpoizvedba, ne JOIN: se izvede samo za vrstice guest liste (CASE), zato vroca pot skena ostane enako poceni. Zahteva alias `o` = orders.
const GUEST_LISTA_POLJA = `(o.guest_list_id IS NOT NULL) AS is_guest_list,
  CASE WHEN o.guest_list_id IS NOT NULL THEN (SELECT gu.username FROM guest_lists gl JOIN users gu ON gu.id = gl.host_user_id WHERE gl.id = o.guest_list_id) END AS guest_list_host_username`;
const STOLPCI_IMETNIKA = `${IMETNIK} AS holder_id, COALESCE(hu.username, ${IME_GOSTA_IMETNIKA}) AS holder_username, hu.email AS holder_email,
  (t.holder_is_guest OR (t.holder_user_id IS NOT NULL AND t.holder_user_id IS DISTINCT FROM o.user_id)) AS transferred, ${GOST_OZNAKA} AS is_guest,
  (t.holder_is_guest OR ${GOST_OZNAKA}) AS is_guest_holder, ${GUEST_LISTA_POLJA}`;
const JOIN_IMETNIK = `LEFT JOIN users hu ON hu.id = ${IMETNIK}`;

// db: neobvezen odjemalec iz pool.connect(); klicatelj, ki ga že drži, MORA
// poizvedovati prek njega, ne prek pool (glej opombo pri POST /events/:id/orders).
async function vstopniceNarocil(idsNarocil, db = pool) {
  if (!idsNarocil.length) return {};
  const r = await db.query(
    `SELECT ${STOLPCI_VSTOPNICE}, ${STOLPCI_VIP_VSTOPNICE}, ${STOLPCI_IMETNIKA} FROM tickets t JOIN orders o ON o.id = t.order_id ${JOIN_IMETNIK}
     WHERE t.order_id = ANY($1::bigint[]) ORDER BY t.id`, [idsNarocil]
  );
  const po = {};
  // Kupcev pogled (GET /me/orders, odgovor nakupa in njegova ponovitev z Idempotency-Key; I7, issue #124): vstopnice, ki jih je
  // kupec prenesel, kaze brez QR, brez seriala (prenos je dodelil NOV serial, ki pripada prejemniku; POST /business/tickets/scan
  // sprejme tudi gol serial) in brez e-naslova prejemnika. Kljuc `serial` ostane (null), `holder_username` in `transferred` ostaneta.
  // Prejemnik vidi serial in QR v GET /me/tickets, klub v poslovnih poteh - tam se STOLPCI_IMETNIKA ne spreminja.
  for (const t of r.rows) {
    if (t.transferred) {
      const { holder_email, ...brezEposte } = t;
      (po[t.order_id] ||= []).push({ ...brezEposte, serial: null, qr: null });
    } else {
      (po[t.order_id] ||= []).push({ ...t, qr: qrVstopnice(t) });
    }
  }
  return po;
}

// Skupna pravila nakupa za vstopnice IN VIP mize (da se ne razideta): dogodek mora biti objavljen,
// klub viden, dogodek se ne sme biti zacet, okno prodaje mora biti odprto.
// Vrne [status, besedilo] ali null. zahtevajCeno: vstopnice potrebujejo ticket_price_cents
// (dogodek z zunanjo prodajo nima vstopnic na Outlyju); mize ga ne rabijo.
function napakaProdaje(e, { zahtevajCeno }) {
  if (e.status !== "published" || e.hidden) return [409, "Event is not on sale."];
  if (zahtevajCeno && e.ticket_price_cents === null) return [409, "This event has no tickets on Outly."];
  const zdaj = Date.now();
  if (new Date(e.start_at).getTime() < zdaj) return [409, "Event has already started."];
  if (e.sales_open_at && new Date(e.sales_open_at).getTime() > zdaj) return [409, "Ticket sales have not opened yet."];
  if (e.sales_close_at && new Date(e.sales_close_at).getTime() < zdaj) return [409, "Ticket sales are closed."];
  return null;
}

// Starost: datum rojstva je izjava uporabnika (glej 003), a 17-letniku vstopnice za 18+ ne prodamo.
// Brez datuma rojstva nakup za 18+ ni mogoc (I8). c = odjemalec znotraj transakcije nakupa.
// Vrne { napaka: [status, besedilo] } ali { email }.
// kaj = besedilo za sporocilo napake (privzeto vstopnice za dogodek; VIP miza s paketom pijace ima svoje).
async function preveriStarostKupca(c, userId, minAge, kaj = "tickets for this event") {
  const ur = await c.query("SELECT email, starost(date_of_birth) AS leta FROM users WHERE id=$1", [userId]);
  if (ur.rows.length === 0) return { napaka: [404, "User not found."] };
  const u = ur.rows[0];
  if (minAge > 0) {
    if (u.leta === null) return { napaka: [403, `Add your date of birth to buy ${kaj}.`] };
    if (u.leta < minAge) return { napaka: [403, `You must be at least ${minAge} to buy ${kaj}.`] };
  }
  return { email: u.email };
}

// Paket pijace pri VIP mizi (issue #102, ZOPA 7/1): bottle paket je po zasnovi pijaca (alkohol), zato za mizo
// Z IZBRANIM PAKETOM velja starost >= 18 ne glede na min_age dogodka (ce je ta visji, velja ta). Polja
// "vsebuje alkohol" v shemi ni, zato vsak paket stejemo kot alkohol (najmanjsa varna resitev brez migracije).
const STAROST_PAKET_PIJACE = 18;
const starostZaPaket = (minAgeDogodka, jePaket) => Math.max(Number(minAgeDogodka) || 0, jePaket ? STAROST_PAKET_PIJACE : 0);

// ---------------------------
// Idempotentni kljuc nakupa (issue #112, invarianta I18, migracija 028)
// ---------------------------
// Glava `Idempotency-Key` (UUID) na POST /events/:id/orders in POST /events/:id/tables/:tableId/orders. Ponovni poskus
// istega nakupa (timeout, 503, dvojni pritisk, slaba povezava) z istim kljucem vrne ISTO narocilo, brez nove rezervacije.
// Brez glave je obnasanje nespremenjeno (star odjemalec). Kljuc je vezan na uporabnika: unikaten je (user_id, key).
//
// Tri plasti, od najcenejse do dokoncne:
//  1. PRED omejevalnikom in semaforjem (middleware `idempotenca`): ce narocilo s tem kljucem ze obstaja, takoj vrne
//     isto naročilo s TRENUTNIM stanjem (201 + `Idempotent-Replayed: true`; neaktivno -> 409 order_not_active); ponovitev ne porabi nakupnega poskusa (20/h) in ne caka v vrsti.
//     Isti kljuc, druga vsebina (dogodek, kolicina, miza, paket) -> 422. Pred zavrniRazprodano, da ponovitev zadnje
//     vstopnice ne dobi 409 »Only 0 tickets left«.
//  2. Zahtevek, ki je s kljucem ze v teku v TEM procesu, ne vzame mesta v semaforju: ceka v pomnilniku (najvec
//     IDEMPOTENCA_CAKANJE_MS) in dobi isti rezultat; ce prvi ne uspe, naslednji poskusi sam (neuspeh se ne zapomni);
//     po izteku roka 409 request_in_progress + Retry-After.
//  3. V nakupni transakciji (veljavno tudi med instancami): pg_advisory_xact_lock na kljuc, nato ponovno branje po
//     kljucu. Dva hkratna zahtevka istega kljuca se tako vrstita, drugi vidi commit prvega in vrne isto narocilo;
//     NE dobi »Only 0 tickets left« zaradi zaloge, ki jo je porabil prvi. Dokoncna resnica je unikaten indeks
//     orders_idempotency_key (23505 -> preberi obstojece).
const IDEM_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const IDEMPOTENCA_CAKANJE_MS = okoljeCelo("IDEMPOTENCA_CAKANJE_MS", 10000, 0, 60000);
const IDEMPOTENCA_PREVERBA_MS = 3000;                                        // branje po kljucu pred semaforjem; ob preseganju velja plast 3
const IDEMPOTENCA_STARO_MS = NAKUP_CAKANJE_MS + 4 * NAKUP_DB_TIMEOUT_MS + 5000;   // varovalka: zahtevek, ki visi dlje, ne drzi kljuca za vedno
const idemVObdelavi = new Map();   // "<userId>:<kljuc>" -> { vsebina, od, vTransakciji, dokoncano, sprosti }

// Vsebina nakupa, ki jo kljuc »podpisuje«: dogodek, kolicina, miza, paket. Cena (expected_price_cents) ni del identitete.
// Vrne null, ce je zahtevek neveljaven: tedaj ga obravnavalec zavrne s 400, kot prej.
function vsebinaNakupaVstopnic(req) {
  const id = celoId(req.params.id);
  const q = Number((req.body || {}).quantity ?? 1);
  if (!id || !Number.isInteger(q) || q < 1 || q > NAJVEC_NA_NAROCILO) return null;
  return { event_id: id, quantity: q, table_id: null, package_id: null };
}
function vsebinaNakupaMize(req) {
  const id = vipId(req.params.id), mizaId = vipId(req.params.tableId);
  if (!id || !mizaId) return null;
  const b = req.body || {};
  let paketId = null;
  if (b.package_id !== undefined && b.package_id !== null) {
    paketId = vipId(b.package_id);
    if (paketId === null) return null;
  }
  return { event_id: id, quantity: 1, table_id: mizaId, package_id: paketId };
}
function idemIstaVsebina(a, b) {
  return a.event_id === b.event_id && a.quantity === b.quantity
    && (a.table_id ?? null) === (b.table_id ?? null) && (a.package_id ?? null) === (b.package_id ?? null);
}
// Branje po kljucu (uporabnik IZ ZETONA, nikoli iz zahteve: kljuc drugega uporabnika je neviden, I3).
async function idemPoisci(db, userId, kljuc) {
  const r = await db.query(
    "SELECT id, event_id, quantity, table_id, package_id, status, checkout_url FROM orders WHERE user_id = $1 AND idempotency_key = $2", [userId, kljuc]);
  return r.rows[0] || null;
}
// V transakciji: najprej serializiraj zahtevke istega kljuca (zaklep traja do COMMIT/ROLLBACK), nato preberi po kljucu.
async function idemZakleniInPoisci(c, userId, kljuc) {
  await c.query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))", [`idem:${userId}:${kljuc}`]);
  return idemPoisci(c, userId, kljuc);
}
// Telo odgovora nakupa (enako ob prvem nakupu in ob ponovitvi). db: odjemalec, ki ga klicatelj ze drzi, ali pool.
async function odgovorNarocila(db, oid) {
  const nr = await db.query(`SELECT ${STOLPCI_NAROCILA}, e.title AS event_title, e.start_at, e.poster_url, cl.name AS club_name,
       CASE WHEN o.status = 'pending' THEN o.checkout_url END AS checkout_url
     FROM orders o JOIN events e ON e.id = o.event_id JOIN clubs cl ON cl.id = o.club_id WHERE o.id = $1`, [oid]);
  const vst = await vstopniceNarocil([oid], db);
  const o = nr.rows[0];
  // mode: "test" (takoj placano, nic zaracunano) | "stripe" (placa na checkout_url; vstopnice nastanejo po placilu).
  // checkout_url je samo pri cakajocem Stripe narocilu (spremembe API-ja so samo dodajanje: star odjemalec ga spregleda).
  const telo = { mode: o.is_test ? "test" : "stripe", order: o, tickets: vst[oid] || [] };
  if (!o.is_test) telo.checkout_url = o.status === "pending" ? o.checkout_url : null;
  return telo;
}
function idemNapacnaVsebina(res) {
  return res.status(422).json({ error: "idempotency_key_reused",
    message: "This Idempotency-Key was already used for a different purchase. Use a new key for a different event, quantity or table." });
}
// Aktivno narocilo = placano (enako kot status vstopnic v scan-list). Vrnjeno, preklicano ali neplacano ni »uspeh«.
const IDEM_AKTIVNA_NAROCILA = ["paid", "partially_refunded"];
// Obstojece narocilo s tem kljucem: isti nakup, narocilo aktivno -> 201 s TRENUTNIM stanjem narocila in vstopnic (po skenu
// `used`, po prenosu drug imetnik), z glavo Idempotent-Replayed; drug nakup -> 422; narocilo ni vec aktivno -> 409
// order_not_active (kljuc ostane vezan nanj, za nov nakup rabi odjemalec nov kljuc).
async function idemOdgovori(res, db, obst, v) {
  if (!idemIstaVsebina(obst, v)) return idemNapacnaVsebina(res);
  // Stripe: narocilo caka na placilo -> ponovitev vrne ISTI checkout_url (seja se ni ustvarjena -> se v teku).
  if (obst.status === "pending" && !obst.checkout_url) {
    res.set("Retry-After", "2");
    return res.status(409).json({ error: "request_in_progress", message: "Your previous attempt is still being processed. Please try again in a moment." });
  }
  if (!IDEM_AKTIVNA_NAROCILA.includes(obst.status) && obst.status !== "pending") {
    return res.status(409).json({ error: "order_not_active",
      message: "The order for this Idempotency-Key is no longer active (refunded, cancelled or unpaid). Use a new Idempotency-Key to buy again." });
  }
  const telo = await odgovorNarocila(db, obst.id);
  console.log(`Nakup (ponovitev kljuca): naročilo ${obst.id}`);
  res.set("Idempotent-Replayed", "true");
  res.locals.brezRazveljavitve = true;   // ponovitev ne spremeni nobenega podatka: javni predpomnilnik (I17) ostane
  return res.status(201).json(telo);
}
// Po 23505 (unikatni indeks): zmagovalec je ze commitan, preberi ga. true = odgovor poslan.
async function idemPoKonfliktu(req, res, c, v) {
  try {
    const obst = await idemPoisci(c, req.user.userId, req.idemKljuc);
    if (!obst) return false;
    await idemOdgovori(res, c, obst, v);
    return true;
  } catch (e) { console.error(e); return false; }
}
function sCasovnoMejo(obljuba, ms) {
  let t;
  return Promise.race([obljuba, new Promise((_, rej) => { t = setTimeout(() => rej(new Error("preverba kljuca predolga")), ms); })])
    .finally(() => clearTimeout(t));
}
// Zahtevek postane »lastnik« kljuca v tem procesu; sprosti ga konec odgovora, ali zaprtje zveze PRED transakcijo
// (odjemalec, ki odide iz vrste, ne kupi - I16). Po zaprtju sredi transakcije ostane do konca (commit se zgodi brez odjemalca).
function idemZahtevaj(req, res, mapKljuc, v) {
  let koncaj;
  const z = { vsebina: v, od: Date.now(), vTransakciji: false, sproscen: false, dokoncano: new Promise((r) => { koncaj = r; }) };
  z.sprosti = () => {
    if (z.sproscen) return;
    z.sproscen = true;
    if (idemVObdelavi.get(mapKljuc) === z) idemVObdelavi.delete(mapKljuc);
    koncaj();
  };
  idemVObdelavi.set(mapKljuc, z);
  req.idem = z;
  res.once("finish", z.sprosti);
  res.once("close", () => { if (!z.vTransakciji) z.sprosti(); });
}
// "koncano" | "cas" | "preklic" (odjemalec je odsel med cakanjem)
function idemCakaj(z, ms, res) {
  return new Promise((resolve) => {
    let t;
    const konec = (izid) => { clearTimeout(t); res.off("close", naZaprtje); resolve(izid); };
    const naZaprtje = () => konec("preklic");
    t = setTimeout(() => konec("cas"), ms);
    res.once("close", naZaprtje);
    z.dokoncano.then(() => konec("koncano"));
  });
}
// true = nadaljuj z obravnavalcem (kljuc je nas); false = odgovor je ze poslan (ali odjemalca ni vec).
async function idemPreveri(req, res, v) {
  const userId = req.user.userId, kljuc = req.idemKljuc;
  const mapKljuc = userId + ":" + kljuc;
  const rok = Date.now() + IDEMPOTENCA_CAKANJE_MS;
  for (;;) {
    if (res.destroyed) return false;
    const obst = await sCasovnoMejo(idemPoisci(pool, userId, kljuc), IDEMPOTENCA_PREVERBA_MS);
    if (res.destroyed) return false;   // odjemalec je odsel: ne postani lastnik in ne kupi (duh)
    if (obst) { await idemOdgovori(res, pool, obst, v); return false; }
    const tuji = idemVObdelavi.get(mapKljuc);
    if (!tuji) { idemZahtevaj(req, res, mapKljuc, v); return true; }
    if (Date.now() - tuji.od > IDEMPOTENCA_STARO_MS) { tuji.sprosti(); continue; }   // viseci lastnik: prevzemi
    if (!idemIstaVsebina(tuji.vsebina, v)) { idemNapacnaVsebina(res); return false; }
    const ostanek = rok - Date.now();
    const izid = ostanek > 0 ? await idemCakaj(tuji, ostanek, res) : "cas";
    if (izid === "preklic") return false;
    if (izid === "cas") {
      res.set("Retry-After", "2");
      res.status(409).json({ error: "request_in_progress", message: "Your previous attempt is still being processed. Please try again in a moment." });
      return false;
    }
    // "koncano": lastnik je zakljucil - ponovno preberi po kljucu (narocilo ali, ce ni uspel, nov poskus)
  }
}
// Middleware (za requireAuth, PRED zavrniRazprodano in omeji). vsebinaIzZahteve: vsebinaNakupaVstopnic | vsebinaNakupaMize.
function idempotenca(vsebinaIzZahteve) {
  return async (req, res, next) => {
    const surov = req.headers["idempotency-key"];
    if (surov === undefined) return next();
    if (typeof surov !== "string" || !IDEM_UUID.test(surov)) {
      return res.status(400).json({ error: "invalid_idempotency_key", message: "Idempotency-Key must be a UUID." });
    }
    req.idemKljuc = surov.toLowerCase();
    const v = vsebinaIzZahteve(req);
    if (!v) return next();   // neveljavno telo: obravnavalec vrne 400
    let dalje;
    try { dalje = await idemPreveri(req, res, v); }
    catch (e) {
      // Preverba ni uspela (baza, cas): plasti 3 (zaklep + unikaten indeks v transakciji) sta neodvisni, zato nadaljuj.
      console.error("[idempotenca] preverba pred semaforjem ni uspela:", e && e.message);
      dalje = !res.headersSent && !res.destroyed;
    }
    if (dalje) next();
  };
}

// POST /events/:id/orders — nakup. Telo: { quantity }.
app.post("/events/:id/orders", requireAuth, idempotenca(vsebinaNakupaVstopnic), zavrniRazprodano, omeji({ kljuc: "nakup", najvec: 20, oknoSekund: 3600, priNapaki: "lokalno" }), async (req, res) => {
  const id = celoId(req.params.id);
  if (!id) return res.status(400).send("Invalid event id.");
  const q = Number((req.body || {}).quantity ?? 1);
  if (!Number.isInteger(q) || q < 1 || q > NAJVEC_NA_NAROCILO) {
    return res.status(400).send(`quantity must be an integer between 1 and ${NAJVEC_NA_NAROCILO}.`);
  }
  if (!(await nakupDovoljenje(req, res))) return;
  let c;
  try { c = await pool.connect(); } catch (err) { nakupIzstopi(); console.error(err); return res.status(503).set("Retry-After", "5").send(NAKUP_ZASEDEN); }
  if (req.idem) req.idem.vTransakciji = true;   // zaprtje zveze od tu naprej kljuca ne sprosti (commit se zgodi brez odjemalca)
  const idemV = req.idemKljuc ? vsebinaNakupaVstopnic(req) : null;
  try {
    await nakupZacni(c);
    if (idemV) {
      // Plast 3: hkratni zahtevek z istim kljucem (tudi iz druge instance) pocaka na zaklepu, nato vidi commit prvega.
      const obst = await idemZakleniInPoisci(c, req.user.userId, req.idemKljuc);
      if (obst) { await c.query("ROLLBACK"); return await idemOdgovori(res, c, obst, idemV); }
    }
    const er = await c.query(
      `SELECT e.id, e.club_id, e.title, e.status, e.start_at, e.min_age, e.ticket_price_cents, e.currency,
              e.capacity, e.sold_count, e.sales_open_at, e.sales_close_at, e.vat_rate, c.hidden,
              c.stripe_account_id, c.stripe_charges_enabled, c.commission_bps
       FROM events e JOIN clubs c ON c.id = e.club_id WHERE e.id = $1`, [id]
    );
    if (er.rows.length === 0) { await c.query("ROLLBACK"); return res.status(404).send("Event not found."); }
    const e = er.rows[0];
    const np = napakaProdaje(e, { zahtevajCeno: true });
    if (np) { await c.query("ROLLBACK"); return res.status(np[0]).send(np[1]); }
    if (e.capacity !== null && e.sold_count + q > e.capacity) {
      if (e.capacity - e.sold_count <= 0) razprodanoOznaci("v:" + id);
      await c.query("ROLLBACK"); return res.status(409).send(`Only ${Math.max(0, e.capacity - e.sold_count)} tickets left.`);
    }

    // Starost (I8): skupna preverba za vstopnice in VIP mize.
    const starost = await preveriStarostKupca(c, req.user.userId, e.min_age);
    if (starost.napaka) { await c.query("ROLLBACK"); return res.status(starost.napaka[0]).send(starost.napaka[1]); }
    const u = { email: starost.email };

    // Nacin placila (placila_stripe.js): test = takoj placano; stripe = cakajoce narocilo + Checkout seja po COMMIT-u.
    const nacin = placilaStripe.nacinPlacila(e);
    if (nacin === "nastavitve") { await c.query("ROLLBACK"); return res.status(503).send("Payments are not available yet."); }
    if (nacin === "klub") { await c.query("ROLLBACK"); return res.status(409).send("This club does not accept online payments yet."); }
    const test = nacin === "test";
    if (!test) {
      const omejitev = await omejitevCakajocih(c, req.user.userId, e.id);
      if (omejitev) { await c.query("ROLLBACK"); return res.status(409).send(omejitev); }
    }

    const skupaj = e.ticket_price_cents * q;
    const provizija = provizijaCentov(skupaj, e.commission_bps);
    const ref = javnaRef();
    const pi = test ? "test_" + crypto.randomUUID() : null;

    // Sprožilec orders_rezerviraj zaklene dogodek in preveri zalogo še enkrat (tudi za cakajoce narocilo: zaloga je rezervirana).
    const or = await c.query(
      `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, currency,
                           application_fee_cents, vat_rate, status, stripe_payment_intent_id, buyer_email, paid_at, idempotency_key,
                           stripe_account_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,CASE WHEN $11 = 'paid' THEN NOW() END,$14,$15) RETURNING id`,
      [ref, req.user.userId, e.id, e.club_id, q, e.ticket_price_cents, skupaj, e.currency, provizija, e.vat_rate,
       test ? "paid" : "pending", pi, u.email, req.idemKljuc || null, test ? null : e.stripe_account_id]
    );
    const oid = or.rows[0].id;
    if (test) {
      await c.query(
        `INSERT INTO tickets (order_id, event_id) SELECT $1, $2 FROM generate_series(1, $3::int)`, [oid, e.id, q]
      );
    }
    await c.query("COMMIT");

    if (!test && !(await nakupStripeSeja(res, c, { oid, opis: `${e.title} – ${q === 1 ? "1 ticket" : q + " tickets"}`,
      kolicina: q, cenaEnoteCents: e.ticket_price_cents, racunKluba: e.stripe_account_id, email: u.email, eventId: e.id, odjemalec: odjemalecNakupa(req) }))) return;

    // POZOR: tu še držimo odjemalca c. Branje po COMMIT-u gre prek c, NE prek
    // pool: pri 10+ hkratnih nakupih (pool ima privzeto 10 povezav) bi vsak
    // zahtevek držal svojo povezavo in čakal na enajsto -> celoten backend
    // obvisi, dokler ga Render ne zažene znova (ugotovljeno s testom sočasnosti).
    const telo = await odgovorNarocila(c, oid);
    console.log(`Nakup (${nacin}): naročilo ${ref}, uporabnik ${req.user.userId}, dogodek ${e.id}, ${q}x ${e.ticket_price_cents} c`);
    return res.status(201).json(telo);
  } catch (err) {
    await c.query("ROLLBACK").catch(() => {});
    if (napakaZasedenosti(err)) { console.error(err.message); return res.status(503).set("Retry-After", "5").send(NAKUP_ZASEDEN); }
    // Unikatni indeks po kljucu je dokoncna resnica: zmagovalec je commitan, vrni njegovo narocilo (plast 3 to ze preprecuje).
    if (idemV && err && err.code === "23505" && err.constraint === "orders_idempotency_key" && await idemPoKonfliktu(req, res, c, idemV)) return;
    // Sprožilec: "Ni dovolj vstopnic" pride kot check_violation.
    if (err && err.code === "23514") return res.status(409).send(/Ni dovolj/.test(err.message) ? "Not enough tickets left." : "Order rejected: " + (err.constraint || err.message));
    console.error(err);
    return res.status(500).send("Server error.");
  } finally { try { c.release(); } finally { if (req.idem) req.idem.sprosti(); nakupIzstopi(); } }
});

// GET /me/orders — moja naročila z vstopnicami.
app.get("/me/orders", requireAuth, async (req, res) => {
  try {
    await prevzemiGostujocaNarocila(req.user.userId, true);
    const r = await pool.query(
      `SELECT ${STOLPCI_NAROCILA}, e.title AS event_title, e.start_at, e.poster_url, cl.name AS club_name,
              CASE WHEN o.status = 'pending' THEN o.checkout_url END AS checkout_url
       FROM orders o JOIN events e ON e.id = o.event_id JOIN clubs cl ON cl.id = o.club_id
       WHERE o.user_id = $1 AND NOT (o.status IN ('cancelled','failed') AND o.paid_at IS NULL)
         AND o.guest_list_id IS NULL   -- guest lista (035, I24) ni nakup: brez zneska/racuna; vstopnice so v GET /me/tickets, lista v GET /me/guest-lists
       ORDER BY o.created_at DESC LIMIT 100`, [req.user.userId]
    );
    const vst = await vstopniceNarocil(r.rows.map(o => o.id));
    return res.json(r.rows.map(o => ({ ...o, tickets: vst[o.id] || [] })));
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// GET /me/tickets — moje vstopnice (plačana naročila), prihajajoče najprej.
// ---------------------------
// PRILJUBLJENI DOGODKI (migracija 012)
// ---------------------------
// GET /me/favorites -> { ids: [..], events: [..] } (dogodki, ki še obstajajo;
// odpovedani/osnutki so izpuščeni iz seznama, id-ji pa ostanejo, da srček v
// aplikaciji ne "pade").
app.get("/me/favorites", requireAuth, async (req, res) => {
  try {
    const [ids, dogodki] = await Promise.all([
      pool.query("SELECT event_id FROM event_favorites WHERE user_id=$1 ORDER BY created_at DESC", [req.user.userId]),
      pool.query(
        `SELECT x.*, f.created_at AS favorited_at
         FROM event_favorites f
         JOIN (SELECT ${STOLPCI_DOGODKA} FROM events) x ON x.id = f.event_id
         WHERE f.user_id = $1 AND x.status = 'published'
           AND x.club_id NOT IN (SELECT id FROM clubs WHERE hidden)
         ORDER BY x.start_at ASC`,
        [req.user.userId]),
    ]);
    return res.json({ ids: ids.rows.map(r => r.event_id), events: dogodki.rows });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// PUT /me/favorites/:eventId — označi (idempotentno). 404, če dogodka ni.
app.put("/me/favorites/:eventId", requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.eventId, 10);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).send("Invalid event id.");
    const r = await pool.query(
      `INSERT INTO event_favorites (user_id, event_id)
       SELECT $1, e.id FROM events e WHERE e.id = $2
       ON CONFLICT DO NOTHING RETURNING event_id`, [req.user.userId, id]);
    const obstaja = r.rows.length || (await pool.query("SELECT 1 FROM events WHERE id=$1", [id])).rows.length;
    if (!obstaja) return res.status(404).send("Event not found.");
    return res.status(200).json({ event_id: id, favorite: true });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// DELETE /me/favorites/:eventId — odznači (idempotentno).
app.delete("/me/favorites/:eventId", requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.eventId, 10);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).send("Invalid event id.");
    await pool.query("DELETE FROM event_favorites WHERE user_id=$1 AND event_id=$2", [req.user.userId, id]);
    return res.status(200).json({ event_id: id, favorite: false });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// Oblika vstopnice za zaslon »moje vstopnice«; isti stolpci tudi pri gostu (GET /guest/order), da imata odjemalca eno obliko.
const SQL_VSTOPNICE_POGLED = `SELECT ${STOLPCI_VSTOPNICE}, ${STOLPCI_VIP_VSTOPNICE}, o.public_ref, o.status AS order_status,
              e.title AS event_title, e.start_at, e.end_at, e.poster_url, e.min_age,
              cl.id AS club_id, cl.name AS club_name, cl.address, cl.city, cl.logo_url,
              ${STOLPCI_IMETNIKA}, bu.username AS buyer_username,
              (t.status = 'valid' AND e.start_at > NOW() AND o.guest_list_id IS NULL) AS transferable   -- vstopnice guest liste se ne prenasajo (035)
       FROM tickets t JOIN orders o ON o.id = t.order_id
       JOIN events e ON e.id = t.event_id JOIN clubs cl ON cl.id = e.club_id
       ${JOIN_IMETNIK} LEFT JOIN users bu ON bu.id = o.user_id`;
app.get("/me/tickets", requireAuth, async (req, res) => {
  try {
    await prevzemiGostujocaNarocila(req.user.userId, true);
    const r = await pool.query(
      `${SQL_VSTOPNICE_POGLED}
       WHERE t.id IN (
         -- Dva indeksirana vira namesto COALESCE(...) = $1, ki je bral VSE
         -- vstopnice in naročila (pri 120.000 vstopnicah 30 ms, raste linearno).
         SELECT id FROM tickets WHERE holder_user_id = $1
         UNION ALL
         SELECT t2.id FROM orders o2 JOIN tickets t2 ON t2.order_id = o2.id
          WHERE o2.user_id = $1 AND t2.holder_user_id IS NULL AND NOT t2.holder_is_guest   -- 034: vstopnica, poslana gostu, ni vec kupceva
            AND o2.guest_list_id IS NULL   -- 035: vstopnice guest liste imajo VEDNO izrecnega imetnika (gostitelj ali prijatelj); brez njega (izbrisan racun) ne padejo na gostitelja
       ) AND o.status IN ('paid','partially_refunded')
         AND NOT (o.guest_list_id IS NOT NULL AND t.status = 'void')   -- odstranjen prijatelj / preklicana lista: razveljavljene vstopnice guest liste se ne kazejo
       ORDER BY (e.start_at >= NOW()) DESC, e.start_at ASC, t.id ASC LIMIT 200`, [req.user.userId]
    );
    return res.json(r.rows.map(t => ({ ...t, qr: qrVstopnice(t) })));
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// ---------------------------
// NAKUP BREZ RACUNA (gost) — migracija 033, invarianta I22
// ---------------------------
// Martin, 5. 10. 2026: kupec vpise samo e-naslov (brez kode iz maila, brez gesla, brez registracije). Samo navadne vstopnice, VIP mize NE.
// Naročilo: orders.user_id = NULL + guest_email (NI vrstice v `users`; DECISIONS 5. 10. 2026). Pogled gosta = ZETON v glavi X-Guest-Token
// (32 B nakljucnih, v bazi samo sha256, tabela gost_zetoni). Zloraba: 10 nakupov/uro/IP (GOST_NAKUP_NA_URO), najvec 1 neplacano narocilo na (e-naslov, dogodek)
// (unikaten delni indeks), Idempotency-Key vezan na e-naslov. Mail z vstopnico ob placilu (najvec enkrat; Resend ob napaki ne vrze).
const GOST_ZETON_DNI = 30;                 // zeton velja do konca dogodka + 30 dni
const GOST_ZETONOV_NA_NAROCILO = 10;       // odgovor nakupa, success_url Stripa, mail, ponovitve; starejsi se pozabijo
const GOST_NAKUP_NA_URO = okoljeCelo("GOST_NAKUP_NA_URO", 10, 1, 100000);   // nakupov gostov na IP na uro
const GOST_QUANTITY_NAJVEC = okoljeCelo("GOST_QUANTITY_NAJVEC", 6, 1, NAJVEC_NA_NAROCILO);   // vstopnic na gostujoce narocilo
const GOST_NEUSPESNI_NA_URO = okoljeCelo("GOST_NEUSPESNI_NA_URO", 60, 1, 100000);            // neuspesnih (404) ogledov/preklicev na IP na uro
const GOST_IDEM_ISKANJ_NA_URO = okoljeCelo("GOST_IDEM_ISKANJ_NA_URO", 300, 1, 100000);       // iskanj po Idempotency-Key (pred omejevalnikom nakupov) na IP na uro
const GOST_CAKAJOCIH_ODSTOTEK = okoljeCelo("GOST_CAKAJOCIH_ODSTOTEK", 20, 1, 100);           // skupno cakajocih gostujocih vstopnic na dogodek: odstotek kapacitete
const GOST_CAKAJOCIH_NAJMANJ = okoljeCelo("GOST_CAKAJOCIH_NAJMANJ", 10, 1, 10000);           // ... vendar vsaj toliko
const GOST_POSTA_DNEVNO = okoljeCelo("GOST_POSTA_DNEVNO", 300, 1, 1000000);                  // globalna dnevna meja gostujocih mailov
const GOST_POSTA_SOCASNIH = 3;                                                              // socasnih posiljanj v procesu
const GOST_POSTA_TIMEOUT_MS = okoljeCelo("GOST_POSTA_TIMEOUT_MS", 10000, 100, 60000);        // rok za klic Resenda
const GOST_POSTA_PONOVI_MS = okoljeCelo("GOST_POSTA_PONOVI_MS", 120000, 0, 3600000);   // pospravljalec neposlanih mailov; 0 = izklop
const GOST_POSTA_PREMOR_MS = okoljeCelo("GOST_POSTA_PREMOR_MS", 120000, 0, 3600000);   // premor po 1. neuspelem poskusu; naslednji so mnogokratniki
// Premor po n-tem neuspelem poskusu (indeks n; 0 = prvi poskus takoj): 2 min, 5 min, 15 min, 1 h, 3 h, 12 h, 24 h (pri privzetih 120000 ms), skupaj 8 poskusov.
const GOST_POSTA_PREMORI = [0, 1, 2.5, 7.5, 30, 90, 360, 720].map((x) => Math.round(x * GOST_POSTA_PREMOR_MS));
const GOST_POSTA_POSKUSOV = GOST_POSTA_PREMORI.length;
const GOST_PREVZEM_MS = okoljeCelo("GOST_PREVZEM_MS", 30000, 0, 3600000);   // kako pogosto /me/orders in /me/tickets znova iscejo gostujoca narocila
const GOST_PREKLIC_OKNO_MS = okoljeCelo("GOST_PREKLIC_OKNO_MS", 5000, 0, 600000);   // najmanjsi razmik med Stripovimi klici za isto narocilo (preklic)
const GOST_ZETON_VZOREC = /^[A-Za-z0-9_-]{43}$/;
const GOST_EMAIL_ATOM = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const GOST_POSTA_NIZ = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// Cenen stevec po IP v pomnilniku procesa (brez baze): za poti, kjer bi omejevalnik v bazi sam postal breme (neuspesni ogledi, iskanje po kljucu).
// Velja za en proces (danes teče ena instanca); po restartu se ponastavi. IP kot omeji(): IPv4 polno, IPv6 /64. Najvec 50000 vnosov.
function ipStevec(najvec, oknoMs) {
  const m = new Map();
  const vnos = (ip) => { const v = m.get(predponaIp(ip)); return v && v.doKdaj > Date.now() ? v : null; };
  return {
    presezeno: (ip) => { const v = vnos(ip); return !!v && v.n >= najvec; },
    preostaloSek: (ip) => { const v = vnos(ip); return v ? Math.max(1, Math.ceil((v.doKdaj - Date.now()) / 1000)) : 1; },
    dodaj: (ip) => {
      const k = predponaIp(ip), v = vnos(ip);
      if (v) { v.n++; return; }
      if (m.size >= 50000) { const zdaj = Date.now(); for (const [kk, vv] of m) if (vv.doKdaj <= zdaj) m.delete(kk); if (m.size >= 50000) return; }
      m.set(k, { n: 1, doKdaj: Date.now() + oknoMs });
    },
  };
}
const gostNeuspesni = ipStevec(GOST_NEUSPESNI_NA_URO, 3600 * 1000);
const gostIdemIskanja = ipStevec(GOST_IDEM_ISKANJ_NA_URO, 3600 * 1000);
const odgovoriPreVeliko = (res, st, ip) => { res.set("Retry-After", String(st.preostaloSek(ip))); return res.status(429).send("Too many requests. Please try again later."); };

// E-naslov: trim + lower, najvec 254, razumna oblika (ne popolna RFC 5322: potrditev je mail z vstopnico). null = neveljaven.
function gostEmail(v) {
  if (typeof v !== "string") return null;
  const e = v.trim().toLowerCase();
  if (!e || e.length > 254 || !GOST_EMAIL_ATOM.test(e)) return null;
  const [lokalni, domena] = e.split("@");
  if (lokalni.startsWith(".") || lokalni.endsWith(".") || lokalni.includes("..")) return null;
  if (domena.split(".").pop().length < 2) return null;
  return e;
}
// Datum rojstva YYYY-MM-DD, resnicen koledarski datum. null = neveljaven.
function gostDatumRojstva(v) {
  if (typeof v !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(v)) return null;
  const [l, m, d] = v.split("-").map(Number);
  const dt = new Date(Date.UTC(l, m - 1, d));
  return dt.getUTCFullYear() === l && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d ? v : null;
}

// Stikalo za pravi denar (GOST_NAKUP_LIVE=1): pogoji in politika zasebnosti morata biti objavljeni, preden gostje placujejo pravi denar.
// Sandbox (sk_test_) in testni nacin delata brez stikala.
function gostStikalo(req, res, next) {
  res.set("Cache-Control", "no-store");
  const live = !!process.env.STRIPE_SECRET_KEY && !placilaStripe.jeSandbox() && process.env.TEST_PLACILA !== "true";
  if (live && process.env.GOST_NAKUP_LIVE !== "1") return res.status(503).send("Guest checkout is not available yet.");
  next();
}
// Preverba telesa PRED omejevalnikom in bazo (brez poizvedbe): neveljaven zahtevek ne porabi nakupnega poskusa.
function gostTelo(req, res, next) {
  res.set("Cache-Control", "no-store");
  const b = req.body && typeof req.body === "object" && !Array.isArray(req.body) ? req.body : {};
  const eventId = celoId4(req.params.id);
  if (!eventId) return res.status(400).send("Invalid event id.");
  const email = gostEmail(b.email);
  if (!email) return res.status(400).send("Enter a valid email address.");
  const q = Number(b.quantity ?? 1);
  if (!Number.isInteger(q) || q < 1 || q > GOST_QUANTITY_NAJVEC) return res.status(400).send(`quantity must be an integer between 1 and ${GOST_QUANTITY_NAJVEC}.`);
  if (b.accept_terms !== true) return res.status(400).send("You must accept the terms to buy tickets.");
  if (typeof b.terms_version !== "string" || !/^[A-Za-z0-9._:-]{1,40}$/.test(b.terms_version)) return res.status(400).send("terms_version is required.");
  let dob = null;
  if (b.date_of_birth !== undefined && b.date_of_birth !== null) {
    dob = gostDatumRojstva(b.date_of_birth);
    if (!dob) return res.status(400).send("Enter your date of birth as YYYY-MM-DD.");
  }
  req.gost = { eventId, email, quantity: q, dob, terms: b.terms_version };
  next();
}

// --- zetoni ---
const gostZetonHash = (zeton) => crypto.createHash("sha256").update(zeton).digest("hex");   // TEXT (hex), ne bytea: izvoz in obnova baze (JSON)
// Nov zeton za narocilo (cistopisa ne hranimo, zato ga mail iz webhooka ne bi mogel ponoviti: vsak namen dobi svezega).
// null, ce narocilo ni (vec) gostujoce (prevzeto v racun): zetonov od prevzema naprej ni vec (N4).
async function gostKujZeton(db, oid) {
  const zeton = crypto.randomBytes(32).toString("base64url");
  const r = await db.query(
    "INSERT INTO gost_zetoni (token_hash, order_id) SELECT $1, o.id FROM orders o WHERE o.id = $2 AND o.user_id IS NULL AND o.guest_email IS NOT NULL", [gostZetonHash(zeton), oid]);
  if (!r.rowCount) return null;
  await db.query(
    `DELETE FROM gost_zetoni WHERE order_id = $1
       AND token_hash NOT IN (SELECT token_hash FROM gost_zetoni WHERE order_id = $1 ORDER BY created_at DESC LIMIT ${GOST_ZETONOV_NA_NAROCILO})`, [oid]);
  return zeton;
}
// id narocila za zeton ali null (napacen, potekel, preklicano neplacano narocilo, prevzeto v racun: vse enako, brez razlike).
async function gostNarociloPoZetonu(db, zeton) {
  if (typeof zeton !== "string" || !GOST_ZETON_VZOREC.test(zeton)) return null;
  const r = await db.query(
    `SELECT o.id FROM gost_zetoni z JOIN orders o ON o.id = z.order_id JOIN events e ON e.id = o.event_id
      WHERE z.token_hash = $1 AND o.user_id IS NULL AND o.guest_email IS NOT NULL AND o.table_id IS NULL
        AND NOT (o.status IN ('cancelled','failed') AND o.paid_at IS NULL)
        AND COALESCE(e.end_at, e.start_at + INTERVAL '8 hours') + INTERVAL '${GOST_ZETON_DNI} days' > NOW()`, [gostZetonHash(zeton)]);
  return r.rows.length ? r.rows[0].id : null;
}
// Zeton je v FRAGMENTU (#t=): brskalnik ga ne poslje strezniku (Cloudflare) in ga ne vkljuci v Referer.
const gostPovezava = (zeton) => `${placilaStripe.osnovaSpleta()}/app/guest/order#t=${zeton}`;

// --- idempotenca (kot I18, vezana na gostov e-naslov namesto uporabnika) ---
async function gostIdemPoisci(db, email, kljuc) {
  const r = await db.query("SELECT id, event_id, quantity, status, checkout_url, user_id FROM orders WHERE guest_email = $1 AND idempotency_key = $2", [email, kljuc]);
  return r.rows[0] || null;
}
// Isto kot idemOdgovori: isti nakup + aktivno narocilo -> 201 s trenutnim stanjem (in SVEZIM zetonom: cistopisa prvega ni); drug nakup -> 422;
// neaktivno -> 409. Odgovor je poslan vedno.
async function gostIdemOdgovori(req, res, db, obst) {
  const g = req.gost;
  if (obst.event_id !== g.eventId || obst.quantity !== g.quantity) return idemNapacnaVsebina(res);
  if (obst.status === "pending" && !obst.checkout_url) {
    res.set("Retry-After", "2");
    return res.status(409).json({ error: "request_in_progress", message: "Your previous attempt is still being processed. Please try again in a moment." });
  }
  if (!IDEM_AKTIVNA_NAROCILA.includes(obst.status) && obst.status !== "pending") {
    return res.status(409).json({ error: "order_not_active",
      message: "The order for this Idempotency-Key is no longer active (refunded, cancelled or unpaid). Use a new Idempotency-Key to buy again." });
  }
  const telo = await odgovorNarocila(db, obst.id);
  telo.guest_token = obst.user_id === null ? await gostKujZeton(db, obst.id) : null;   // prevzeto v racun: zetonov ni vec
  console.log(`Nakup gosta (ponovitev kljuca): naročilo ${obst.id}`);
  res.set("Idempotent-Replayed", "true");
  res.locals.brezRazveljavitve = true;   // ponovitev ne spremeni nobenega podatka: javni predpomnilnik (I17) ostane
  return res.status(201).json(telo);
}
// Plast 1 (pred omejevalnikom in semaforjem): ponovitev ne porabi nakupnega poskusa in ne caka v vrsti. Kot pri racunih (idemPreveri):
// zahtevek istega kljuca, ki je ze v teku v TEM procesu, ne porabi poskusa omejevalnika, ampak caka na prvega in dobi isti rezultat.
// Hkratna zahtevka iz dveh instanc se vrstita sele v transakciji (plast 3: advisory lock + unikaten indeks).
async function gostIdemPreveri(req, res) {
  const g = req.gost, kljuc = req.idemKljuc;
  const mapKljuc = `g:${g.email}:${kljuc}`;
  const v = { event_id: g.eventId, quantity: g.quantity };
  const rok = Date.now() + IDEMPOTENCA_CAKANJE_MS;
  for (;;) {
    if (res.destroyed) return false;
    const obst = await sCasovnoMejo(gostIdemPoisci(pool, g.email, kljuc), IDEMPOTENCA_PREVERBA_MS);
    if (res.destroyed) return false;   // odjemalec je odsel: ne postani lastnik in ne kupi (duh)
    if (obst) { await gostIdemOdgovori(req, res, pool, obst); return false; }
    const tuji = idemVObdelavi.get(mapKljuc);
    if (!tuji) { idemZahtevaj(req, res, mapKljuc, v); return true; }
    if (Date.now() - tuji.od > IDEMPOTENCA_STARO_MS) { tuji.sprosti(); continue; }   // viseci lastnik: prevzemi
    if (tuji.vsebina.event_id !== v.event_id || tuji.vsebina.quantity !== v.quantity) { idemNapacnaVsebina(res); return false; }
    const ostanek = rok - Date.now();
    const izid = ostanek > 0 ? await idemCakaj(tuji, ostanek, res) : "cas";
    if (izid === "preklic") return false;
    if (izid === "cas") {
      res.set("Retry-After", "2");
      res.status(409).json({ error: "request_in_progress", message: "Your previous attempt is still being processed. Please try again in a moment." });
      return false;
    }
  }
}
async function idempotencaGost(req, res, next) {
  const surov = req.headers["idempotency-key"];
  if (surov === undefined) return next();
  if (typeof surov !== "string" || !IDEM_UUID.test(surov)) {
    return res.status(400).json({ error: "invalid_idempotency_key", message: "Idempotency-Key must be a UUID." });
  }
  req.idemKljuc = surov.toLowerCase();
  // N3: iskanje po kljucu je poizvedba v bazi PRED omejevalnikom nakupov; cenen stevec v pomnilniku ga omeji na IP.
  if (gostIdemIskanja.presezeno(req.ip)) return odgovoriPreVeliko(res, gostIdemIskanja, req.ip);
  gostIdemIskanja.dodaj(req.ip);
  let dalje;
  try { dalje = await gostIdemPreveri(req, res); }
  catch (e) {
    console.error("[gost] preverba idempotence ni uspela:", e && e.message);   // plast 3 je neodvisna
    dalje = !res.headersSent && !res.destroyed;
  }
  if (dalje) next();
}

// POST /guest/events/:id/orders — nakup vstopnic brez racuna. Brez zetona.
// Telo: { email, quantity?, date_of_birth? (obvezen pri min_age > 0), accept_terms: true, terms_version }.
// 201 { mode, order, tickets, checkout_url?, guest_token }; napake kot besedilo (400, 403, 409, 429, 503) ali { error, message } (idempotenca).
app.post("/guest/events/:id/orders", gostStikalo, gostTelo, idempotencaGost, zavrniRazprodano,
  omeji({ kljuc: "nakup-gost", najvec: GOST_NAKUP_NA_URO, oknoSekund: 3600, priNapaki: "lokalno" }), async (req, res) => {
  const g = req.gost;
  if (!(await nakupDovoljenje(req, res))) return;
  let c;
  try { c = await pool.connect(); } catch (err) { nakupIzstopi(); console.error(err); return res.status(503).set("Retry-After", "5").send(NAKUP_ZASEDEN); }
  if (req.idem) req.idem.vTransakciji = true;   // zaprtje zveze od tu naprej kljuca ne sprosti (commit se zgodi brez odjemalca)
  try {
    await nakupZacni(c);
    if (req.idemKljuc) {
      await c.query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))", [`idem:g:${g.email}:${req.idemKljuc}`]);
      const obst = await gostIdemPoisci(c, g.email, req.idemKljuc);
      if (obst) { await c.query("ROLLBACK"); return await gostIdemOdgovori(req, res, c, obst); }
    }
    const er = await c.query(
      `SELECT e.id, e.club_id, e.title, e.status, e.start_at, e.min_age, e.ticket_price_cents, e.currency,
              e.capacity, e.sold_count, e.sales_open_at, e.sales_close_at, e.vat_rate, c.hidden,
              c.stripe_account_id, c.stripe_charges_enabled, c.commission_bps
       FROM events e JOIN clubs c ON c.id = e.club_id WHERE e.id = $1`, [g.eventId]
    );
    if (er.rows.length === 0) { await c.query("ROLLBACK"); return res.status(404).send("Event not found."); }
    const e = er.rows[0];
    const np = napakaProdaje(e, { zahtevajCeno: true });
    if (np) { await c.query("ROLLBACK"); return res.status(np[0]).send(np[1]); }
    if (e.capacity !== null && e.sold_count + g.quantity > e.capacity) {
      if (e.capacity - e.sold_count <= 0) razprodanoOznaci("v:" + e.id);
      await c.query("ROLLBACK"); return res.status(409).send(`Only ${Math.max(0, e.capacity - e.sold_count)} tickets left.`);
    }

    // Starost (I8): izjava gosta, preverjena na strezniku; datuma rojstva NE shranimo (nacelo najmanj podatkov, GDPR 5(1)(c)):
    // v narocilo gre samo guest_age_min = starostna meja, za katero je izjava prestala preverbo (NULL = datum ni bil podan).
    if (e.min_age > 0 && !g.dob) { await c.query("ROLLBACK"); return res.status(403).send("Enter your date of birth to buy tickets for this event."); }
    if (g.dob) {
      const a = (await c.query("SELECT starost($1::date) AS leta, ($1::date < CURRENT_DATE AND $1::date > CURRENT_DATE - INTERVAL '120 years') AS veljaven", [g.dob])).rows[0];
      if (!a.veljaven) { await c.query("ROLLBACK"); return res.status(400).send("Enter a valid date of birth."); }
      if (e.min_age > 0 && a.leta < e.min_age) { await c.query("ROLLBACK"); return res.status(403).send(`You must be at least ${e.min_age} to buy tickets for this event.`); }
    }

    // Nacin placila: isto kot pri racunih (test = takoj placano; stripe = cakajoce narocilo + Checkout seja po COMMIT-u).
    const nacin = placilaStripe.nacinPlacila(e);
    if (nacin === "nastavitve") { await c.query("ROLLBACK"); return res.status(503).send("Payments are not available yet."); }
    if (nacin === "klub") { await c.query("ROLLBACK"); return res.status(409).send("This club does not accept online payments yet."); }
    const test = nacin === "test";
    if (!test && e.capacity !== null) {
      // Skupna meja CAKAJOCIH gostujocih vstopnic na dogodek (zaloga je zaklenjena do ~35 min): zaklep vrstice dogodka (kot sprozilec
      // rezerviraj_zalogo) serializira hkratne nakupe, stetje v isti transakciji je zato tocno. Brez nje bi mnogo e-naslovov zaklenilo dogodek.
      await c.query("SELECT 1 FROM events WHERE id = $1 FOR UPDATE", [e.id]);
      const cak = (await c.query(
        "SELECT COALESCE(SUM(quantity), 0)::int AS n FROM orders WHERE event_id = $1 AND user_id IS NULL AND guest_email IS NOT NULL AND status = 'pending'", [e.id])).rows[0].n;
      const meja = Math.max(GOST_CAKAJOCIH_NAJMANJ, Math.ceil(e.capacity * GOST_CAKAJOCIH_ODSTOTEK / 100));
      if (cak + g.quantity > meja) {
        await c.query("ROLLBACK");
        return res.status(409).send("Too many unfinished payments for this event right now, try again in a few minutes.");
      }
    }

    const skupaj = e.ticket_price_cents * g.quantity;
    const provizija = provizijaCentov(skupaj, e.commission_bps);
    const ref = javnaRef();
    const pi = test ? "test_" + crypto.randomUUID() : null;
    const or = await c.query(
      `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, currency,
                           application_fee_cents, vat_rate, status, stripe_payment_intent_id, buyer_email, paid_at, idempotency_key,
                           stripe_account_id, guest_email, guest_terms_version, guest_terms_accepted_at, guest_age_min)
       VALUES ($1,NULL,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,CASE WHEN $10 = 'paid' THEN NOW() END,$13,$14,$12,$15,NOW(),$16) RETURNING id`,
      [ref, e.id, e.club_id, g.quantity, e.ticket_price_cents, skupaj, e.currency, provizija, e.vat_rate,
       test ? "paid" : "pending", pi, g.email, req.idemKljuc || null, test ? null : e.stripe_account_id, g.terms, g.dob ? e.min_age : null]
    );
    const oid = or.rows[0].id;
    if (test) {
      await c.query(`INSERT INTO tickets (order_id, event_id) SELECT $1, $2 FROM generate_series(1, $3::int)`, [oid, e.id, g.quantity]);
    }
    const zeton = await gostKujZeton(c, oid);   // v isti transakciji: zeton velja takoj, ko je narocilo vidno
    await c.query("COMMIT");

    if (!test) {
        const povratna = { success_url: gostPovezava(zeton), cancel_url: gostPovezava(zeton) };   // stran naroclia: »Complete payment« / »Cancel order«
      if (!(await nakupStripeSeja(res, c, { oid, opis: `${e.title} – ${g.quantity === 1 ? "1 ticket" : g.quantity + " tickets"}`,
        kolicina: g.quantity, cenaEnoteCents: e.ticket_price_cents, racunKluba: e.stripe_account_id, email: g.email, eventId: e.id,
        odjemalec: "splet", povratna }))) return;
    }

    const telo = await odgovorNarocila(c, oid);   // prek c (ne pool): glej opombo pri POST /events/:id/orders
    telo.guest_token = zeton;
    console.log(`Nakup gosta (${nacin}): naročilo ${ref}, dogodek ${e.id}, ${g.quantity}x ${e.ticket_price_cents} c`);
    if (test) posljiGostuVstopnice(oid);   // brez await: odgovor ne caka na Resend; napaka maila ne podre nakupa (pospravljalec ponovi)
    return res.status(201).json(telo);
  } catch (err) {
    await c.query("ROLLBACK").catch(() => {});
    if (napakaZasedenosti(err)) { console.error(err.message); return res.status(503).set("Retry-After", "5").send(NAKUP_ZASEDEN); }
    if (err && err.code === "23505") {
      if (err.constraint === "orders_gost_idempotency_key" && req.idemKljuc) {
        try {
          const obst = await gostIdemPoisci(c, g.email, req.idemKljuc);
          if (obst) return await gostIdemOdgovori(req, res, c, obst);
        } catch (e2) { console.error(e2); }
      }
      if (err.constraint === "orders_gost_cakajoce_key") {
        return res.status(409).send("You already have an unfinished payment for this event. Please wait up to 30 minutes for it to expire, then try again.");
      }
    }
    if (err && err.code === "23514") return res.status(409).send(/Ni dovolj/.test(err.message) ? "Not enough tickets left." : "Order rejected: " + (err.constraint || err.message));
    console.error(err);
    return res.status(500).send("Server error.");
  } finally { try { c.release(); } finally { if (req.idem) req.idem.sprosti(); nakupIzstopi(); } }
});

// Neuspesen zahtevek (zeton ne velja): 404; nad mejo neuspesnih na IP 429. VELJAVEN zeton se obdela vedno (iskanje je indeksirano in poceni):
// na skupnem wifiju kluba ali CGNAT napadalec (ali pokvarjen odjemalec) gostom na vratih ne sme onemogociti prikaza vstopnice.
// Zeton ima 256 bitov, ugibanje ni realno; meja je samo varovalo pred obremenitvijo.
function gostNeuspesen(req, res, sporocilo = "Order not found.") {
  if (gostNeuspesni.presezeno(req.ip)) return odgovoriPreVeliko(res, gostNeuspesni, req.ip);
  gostNeuspesni.dodaj(req.ip);
  return res.status(404).send(sporocilo);
}

// Narocilo gosta v obliki odgovora (GET /guest/order, POST /guest/order/cancel); brez e-naslova.
async function gostNarociloOdgovor(db, oid) {
  const nr = await db.query(
    `SELECT o.id, o.public_ref, o.status, o.quantity, o.unit_price_cents, o.total_cents, o.currency, o.refunded_cents,
            COALESCE(o.stripe_payment_intent_id LIKE 'test_%', FALSE) AS is_test, o.created_at, o.paid_at,
            CASE WHEN o.status = 'pending' THEN o.checkout_url END AS checkout_url,
            e.id AS event_id, e.title AS event_title, e.start_at, e.end_at, e.poster_url, e.min_age,
            cl.id AS club_id, cl.name AS club_name, cl.address, cl.city, cl.logo_url
       FROM orders o JOIN events e ON e.id = o.event_id JOIN clubs cl ON cl.id = o.club_id WHERE o.id = $1`, [oid]);
  if (!nr.rows.length) return null;
  const x = nr.rows[0];
  return {
    id: x.id, public_ref: x.public_ref, status: x.status, quantity: x.quantity, unit_price_cents: x.unit_price_cents,
    total_cents: x.total_cents, currency: x.currency, refunded_cents: x.refunded_cents, is_test: x.is_test,
    created_at: x.created_at, paid_at: x.paid_at, checkout_url: x.checkout_url,
    event_id: x.event_id, club_id: x.club_id, event_title: x.event_title, start_at: x.start_at, poster_url: x.poster_url, club_name: x.club_name,
    event: { id: x.event_id, title: x.event_title, start_at: x.start_at, end_at: x.end_at, poster_url: x.poster_url, min_age: x.min_age,
             club_id: x.club_id, club_name: x.club_name, address: x.address, city: x.city, logo_url: x.logo_url },
  };
}

// Zascita Stripove omejitve branja (si jo delita webhook in pospravljalec): preklic z veljavnim zetonom, ko seja ni ne odprta ne placana
// (npr. complete + unpaid), bi sicer ob vsakem klicu naredil checkout.sessions.retrieve. Stanje je v procesu (ena instanca):
// (a) narocila v obdelavi (vzporedni preklic istega narocila ne gre do Stripa), (b) cas zadnjega Stripovega klica po narocilu (najvec en na okno).
// Oboje se konca z 409 request_in_progress + Retry-After, nikoli 429 (veljaven zeton ne sme biti zavrnjen z omejitvijo).
const gostPreklicVObdelavi = new Set();
const gostPreklicStripe = new Map();   // order_id -> ms zadnjega Stripovega klica; najvec 5000 vnosov (najstarejsi se izrine)
function gostPreklicVstopi(oid) {
  if (gostPreklicVObdelavi.has(oid)) return 1;
  const zdaj = Date.now(), zadnji = gostPreklicStripe.get(oid);
  if (zadnji !== undefined && zdaj - zadnji < GOST_PREKLIC_OKNO_MS) return Math.max(1, Math.ceil((GOST_PREKLIC_OKNO_MS - (zdaj - zadnji)) / 1000));
  gostPreklicVObdelavi.add(oid);
  return 0;
}
function gostPreklicIzstopi(oid) {
  gostPreklicVObdelavi.delete(oid);
  gostPreklicStripe.delete(oid);   // ponovni vnos na konec vrstnega reda (Map hrani vrstni red vstavljanja)
  if (gostPreklicStripe.size >= 5000) {
    const meja = Date.now() - GOST_PREKLIC_OKNO_MS;
    for (const [k, t] of gostPreklicStripe) if (t <= meja) gostPreklicStripe.delete(k);
    while (gostPreklicStripe.size >= 5000) gostPreklicStripe.delete(gostPreklicStripe.keys().next().value);
  }
  gostPreklicStripe.set(oid, Date.now());
}

// GET /guest/order — pogled gosta: narocilo + vstopnice. Zeton v glavi X-Guest-Token (NE v URL-ju zahtevka: ne pride v dnevnike).
// Napacen/potekel zeton, preklicano neplacano narocilo, prevzeto v racun, VIP miza: 404 vedno enako (razlike ne razkrijemo).
// pending: tickets [] (odjemalec po vrnitvi s Stripa poizveduje, dokler ne pride paid).
// Omejitev: samo NEUSPESNI (404) zahtevki na IP (GOST_NEUSPESNI_NA_URO); veljaven zeton je vedno obdelan, tudi ce je IP nad mejo.
app.get("/guest/order", async (req, res) => {
  res.set("Cache-Control", "no-store");
  try {
    const oid = await gostNarociloPoZetonu(pool, req.get("x-guest-token"));
    if (!oid) return gostNeuspesen(req, res);
    const order = await gostNarociloOdgovor(pool, oid);
    if (!order) return res.status(404).send("Order not found.");
    let vstopnice = [];
    if (["paid", "partially_refunded"].includes(order.status)) {
      const r = await pool.query(`${SQL_VSTOPNICE_POGLED} WHERE t.order_id = $1 ORDER BY t.id`, [oid]);
      vstopnice = r.rows.map((t) => ({ ...t, qr: qrVstopnice(t), transferable: false }));   // prenos zahteva racun
    }
    return res.json({ order, tickets: vstopnice });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// POST /guest/order/cancel — gost prekliče svoje NEPLACANO naročilo (zaloga se sprosti takoj, ne šele čez ~35 min).
// Zeton v glavi X-Guest-Token, brez telesa. 200 { order } (status cancelled); naročilo, ki ni pending (placano ali ze preklicano
// v istem trenutku): 409 { error: "order_not_pending" }. Stripe seja se poteče (kot pospravljalec); če je bila med tem placana: 409.
// Brez omeji(): nepoznan zeton steje gostNeuspesni, veljaven nikoli ne dobi 429 (ponovitev na preklicanem narocilu se konca pri 409, brez Stripa).
// Stripov klic: najvec eden hkrati in najvec eden na GOST_PREKLIC_OKNO_MS (5 s) po narocilu, sicer 409 request_in_progress + Retry-After (glej gostPreklicVstopi).
app.post("/guest/order/cancel", async (req, res) => {
  res.set("Cache-Control", "no-store");
  let oid = null, vObdelavi = false;
  try {
    oid = await gostNarociloPoZetonu(pool, req.get("x-guest-token"));
    if (!oid) return gostNeuspesen(req, res);
    const k = (await pool.query("SELECT status, event_id, stripe_checkout_session_id, created_at FROM orders WHERE id = $1", [oid])).rows[0];
    if (!k) return res.status(404).send("Order not found.");
    const nePending = () => res.status(409).json({ error: "order_not_pending", message: "Only an unpaid order can be cancelled." });
    if (k.status !== "pending") return nePending();
    if (k.stripe_checkout_session_id) {
      const s = placilaStripe.stripe();
      if (!s) return res.status(503).send("Payments are not configured yet.");
      const cakaj = gostPreklicVstopi(oid);
      if (cakaj) {
        res.set("Retry-After", String(cakaj));
        return res.status(409).json({ error: "request_in_progress", message: "Your cancellation is already being processed. Please try again in a moment." });
      }
      vObdelavi = true;
      let seja;
      try {
        seja = await s.checkout.sessions.retrieve(k.stripe_checkout_session_id);
        if (seja.status === "open") seja = await s.checkout.sessions.expire(seja.id);
      } catch (e) {
        console.error(`[gost] preklic: Stripe seja ni dosegljiva (narocilo ${oid}):`, e && e.message);
        return res.status(502).send("Payment provider is unavailable. Please try again.");
      }
      if (seja.status === "complete") {
        return res.status(409).json({ error: "order_not_pending", message: "This order has just been paid. Your tickets will be ready in a moment." });
      }
    } else if (Date.now() - new Date(k.created_at).getTime() < 60 * 1000) {
      // Checkout seja se ustvarja: preklic bi lahko ostal brez seje, ki jo kupec nato placa (placilo za preklicano narocilo).
      res.set("Retry-After", "2");
      return res.status(409).json({ error: "request_in_progress", message: "Your order is still being set up. Please try again in a moment." });
    }
    // Pogoj status = 'pending': placilo, ki je med tem prispelo po webhooku, ni povozeno. Sprozilec sprosti zalogo.
    const u = await pool.query("UPDATE orders SET status = 'cancelled', cancelled_at = NOW() WHERE id = $1 AND status = 'pending' AND user_id IS NULL RETURNING id", [oid]);
    if (!u.rows.length) return nePending();
    razprodanoPozabi("v:" + k.event_id);
    console.log(`[gost] preklic neplacanega narocila ${oid}`);
    return res.json({ order: await gostNarociloOdgovor(pool, oid) });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
  finally { if (vObdelavi) gostPreklicIzstopi(oid); }
});

// --- prevzem v racun ---
// Ko uporabnik s POTRJENIM e-naslovom (users.email_verified) pride na /me, /me/orders ali /me/tickets, postanejo PLACANA gostujoca narocila
// (user_id NULL) z istim e-naslovom njegova: od tu naprej so v /me/orders, /me/tickets (tudi iOS). Zeton gosta se preklice.
// Napaka ne sme podreti prijave: poti za branje gredo naprej brez prevzema.
const gostPrevzemSpomin = new Map();   // userId -> ms zadnjega iskanja (omejitev bremena na /me/orders in /me/tickets)
async function prevzemiGostujocaNarocila(userId, zVmesnimSpominom = false) {
  try {
    const zdaj = Date.now();
    if (zVmesnimSpominom && GOST_PREVZEM_MS > 0) {
      const prej = gostPrevzemSpomin.get(userId);
      if (prej !== undefined && zdaj - prej < GOST_PREVZEM_MS) return;
      if (gostPrevzemSpomin.size >= 20000) gostPrevzemSpomin.clear();
      gostPrevzemSpomin.set(userId, zdaj);
    }
    // Samo placana narocila (cakajoce Stripe narocilo se prevzame, ko je placano: zeton iz success_url mora do takrat veljati).
    // Ob prevzemu se zetoni gosta PRESEKAJO (pravna analiza 2.6): vstopnice so od tu naprej v racunu, ne na dveh mestih.
    // NOT EXISTS: narocilo, katerega Idempotency-Key ze obstaja pri uporabniku (unikaten (user_id, kljuc)), se preskoci; ostala se prevzamejo.
    // Vstopnice, poslane temu e-naslovu s prenosom brez racuna (034), so v ISTEM stavku (en obisk baze na GET /me): postanejo njegove (holder_user_id),
    // zetoni se preklicejo, e-naslov gosta se izbrise. Serial se NE zamenja (PDF in koda v mailu veljata naprej: gost, ki se registrira dan pred
    // dogodkom, ne sme obstati pred vrati z neveljavno kodo). Zapis prenosa dobi prejemnika (obvestilo »X ti je poslal vstopnico«); seen_at ostane NULL.
    const r = await pool.query(
      `WITH p AS (UPDATE orders o SET user_id = u.id FROM users u
                   WHERE u.id = $1 AND u.email_verified AND o.user_id IS NULL AND o.guest_email = lower(u.email)
                     AND o.status IN ('paid','partially_refunded','refunded')
                     AND NOT EXISTS (SELECT 1 FROM orders x WHERE x.user_id = u.id AND x.idempotency_key IS NOT NULL AND x.idempotency_key = o.idempotency_key)
                   RETURNING o.id),
            d AS (DELETE FROM gost_zetoni WHERE order_id IN (SELECT id FROM p) RETURNING 1),
            pt AS (UPDATE tickets t SET holder_user_id = u.id, holder_is_guest = FALSE, holder_guest_email = NULL
                    FROM users u WHERE u.id = $1 AND u.email_verified AND t.holder_is_guest AND t.holder_guest_email = lower(u.email)
                    RETURNING t.id),
            zt AS (DELETE FROM gost_zetoni_vstopnic WHERE ticket_id IN (SELECT id FROM pt) RETURNING 1),
            tt AS (UPDATE ticket_transfers x SET to_user_id = $1
                    WHERE x.to_guest AND x.to_user_id IS NULL AND x.ticket_id IN (SELECT id FROM pt)
                      AND x.id = (SELECT MAX(y.id) FROM ticket_transfers y WHERE y.ticket_id = x.ticket_id AND y.to_guest) RETURNING 1)
       SELECT (SELECT COUNT(*)::int FROM p) AS n, (SELECT COUNT(*)::int FROM pt) AS nt`, [userId]);
    if (r.rows[0].n) console.log(`[gost] ${r.rows[0].n} gostujocih narocil prevzetih v racun ${userId}`);
    if (r.rows[0].nt) console.log(`[gost] ${r.rows[0].nt} prenesenih gostujocih vstopnic prevzetih v racun ${userId}`);
  } catch (e) { console.error("[gost] prevzem narocil ni uspel:", e && e.message); }
}

// --- mail z vstopnico ---
// Ko narocilo postane placano (test: takoj; Stripe: webhook ali pospravljalec), gost dobi mail. Mail je ZAKONSKO POTRDILO o sklenitvi pogodbe
// na trajnem nosilcu (ZVPot-1 132/6; pravna analiza 5. 10. 2026, 1.3): vse informacije so v BESEDILU maila, povezava je samo dodatek.
// Najvec enkrat OB USPEHU: narocilo si »rezervira« poskus z UPDATE ... RETURNING (stevec poskusov + cas), poslano se zapise sele po uspehu Resenda.
// Ob padcu procesa ali preteku roka MED posiljanjem se mail lahko poslje dvakrat (rezervacija poskusa ne ve, ali je Resend sprejel).
// Resend ob napaki NE vrze (vrne { error }): napaka se zapise v dnevnik (brez e-naslova), poskus ponovi pospravljalec z narascajocim premorom
// (GOST_POSTA_PREMORI, 8 poskusov ~ 42 h); ob izcrpanju console.error. Socasno najvec GOST_POSTA_SOCASNIH posiljanj; klic ima rok GOST_POSTA_TIMEOUT_MS.
// Meje: v TESTNEM nacinu (brez placila) najvec 1 mail na naslov na 24 h; globalno GOST_POSTA_DNEVNO na 24 h (testni se izpusti, resnicno placan se odlozi).
// Napaka maila NE sme podreti placila ali webhooka (klicatelji ne cakajo in ne vidijo izjem). Vrne true, ce je mail poslan.
const POSREDNIK_VRSTICA = "NEXT DIMENSIONS, družba za marketing, d.o.o., Trebče 81, 3256 Bistrica ob Sotli, luka@outly.si";
const POSTA_ODGOVOR = "luka@outly.si";
const znesek = (centi, valuta) => `${(centi / 100).toFixed(2)} ${String(valuta).trim()}`;
const ljDatum = (d) => new Intl.DateTimeFormat("en-GB", { dateStyle: "full", timeStyle: "short", timeZone: "Europe/Ljubljana" }).format(new Date(d)) + " (Ljubljana time)";
// Stavek o DDV glede na stopnjo, zamrznjeno na narocilu (events.vat_rate; NULL = klub ni dolocil): ne trdimo, da je DDV vkljucen, ce ne vemo.
function davekStavek(vat) {
  if (vat === null || vat === undefined) return "VAT is charged according to the seller's VAT status.";
  const p = Math.round(Number(vat) * 1000) / 10;
  return p > 0 ? `The price includes VAT (${p}%).` : "The seller does not charge VAT on this price.";
}
// Vsebina potrdila kot razdelki { naslov, vrstice[] }; iz njih nastaneta besedilo in HTML (isto besedilo, brez oglasov).
function gostPotrdilo(o, povezava, prevzeto, kode = []) {
  const klubKontakt = [o.club_address && o.club_city ? `${o.club_address}, ${o.club_city}` : (o.club_address || o.club_city), o.club_phone, o.club_email].filter(Boolean);
  const starost = o.min_age > 0 ? `Age limit: ${o.min_age}+. Every visitor must meet the age limit. ID is checked at the door; the club may refuse entry if you don't meet it.` : "No age limit.";
  const razdelki = [
    { naslov: "Order", vrstice: [`Order ${o.public_ref}, placed on ${ljDatum(o.paid_at || o.created_at)}.`] },
    { naslov: "Event", vrstice: [o.event_title, ljDatum(o.start_at), [o.club_name, o.club_address, o.club_city].filter(Boolean).join(", "), starost] },
    { naslov: "Tickets", vrstice: [`${o.quantity} x ${znesek(o.unit_price_cents, o.currency)} = ${znesek(o.total_cents, o.currency)}. ${davekStavek(o.vat_rate)}`] },
    { naslov: "Seller", vrstice: [`The ticket is sold by the club: ${[o.club_name, ...klubKontakt].join(", ")}.`, `Outly is only the intermediary: ${POSREDNIK_VRSTICA}.`] },
    { naslov: "No right of withdrawal", vrstice: ["There is no right of withdrawal for tickets to an event on a fixed date (Consumer Protection Act ZVPot-1, Article 135, point 12). If the event is cancelled or postponed, the rules in the terms apply."] },
    { naslov: "Terms", vrstice: [`You accepted the Outly terms, version ${o.guest_terms_version}: https://outly.si/terms`] },
    { naslov: "Your tickets", vrstice: (prevzeto
      ? [`Open your tickets in your Outly account: ${povezava}`]
      : [`Open your tickets (show the QR code at the door): ${povezava}`, "This link is your ticket. Don't share it except with people coming with you.", "If you create an Outly account with this email, your tickets will appear there."])
      .concat(kode.length > 1 ? ["The first QR code is below; all your QR codes (one per page) are in the attached PDF (outly-tickets.pdf). Show one code per person at the door."]
        : kode.length ? ["The QR code is below and in the attached PDF (outly-tickets.pdf). Show it at the door."] : []) },
    { naslov: "Complaints", vrstice: [`About the event: contact the club (details above). About the purchase or the payment: contact Outly at ${POSTA_ODGOVOR}.`] },
    { naslov: "Questions", vrstice: [`Reply to this email or write to ${POSTA_ODGOVOR}.`] },
  ];
  const besedilo = `Your Outly tickets - order ${o.public_ref}\n\n` + razdelki.map(r => `${r.naslov.toUpperCase()}\n${r.vrstice.join("\n")}`).join("\n\n") + "\n";
  const html = `<div style="font-family: Arial, sans-serif; line-height:1.5"><h2>Your Outly tickets</h2>` + razdelki.map(r =>
    `<h3>${GOST_POSTA_NIZ(r.naslov)}</h3>` + r.vrstice.map(v => {
      const e = GOST_POSTA_NIZ(v);
      return `<p>${povezava && v.includes(povezava) ? e.replace(GOST_POSTA_NIZ(povezava), `<a href="${GOST_POSTA_NIZ(povezava)}">${GOST_POSTA_NIZ(povezava)}</a>`) : e}</p>`;
    }).join("") + (r.naslov === "Your tickets" ? kode.slice(0, 1).map(k => qrSlikaHtml(k.cid, k.oznaka)).join("") : "")).join("") + `</div>`;
  return { besedilo, html };
}
// --- priloge: QR kot vgrajena slika (CID) + PDF (migracija 034, vstopnica_priloge.js) ---
const QR_STAVEK = "This email and the attached PDF are your ticket. The QR code is valid for one entry: whoever shows it first gets in. Don't forward this email, post the code or share the link.";
const qrSlikaHtml = (cid, oznaka) => `<div style="margin:12px 0">${oznaka ? `<p style="margin:0 0 4px">${GOST_POSTA_NIZ(oznaka)}</p>` : ""}<img src="cid:${cid}" width="228" height="228" alt="Ticket QR code" style="display:block;width:228px;height:228px;border:1px solid #ccc"></div>`;
// Resend 3.5 posreduje telo strezniku neprepisano (JSON, kljuci snake_case: content_type, content_id): vsebina priloge je BASE64 niz (Buffer bi se serializiral
// napacno), `content_id` vgradi sliko (cid:). SDK tega NE tipizira in ne preverja (verzija 3.5.0): PREVERI ob vsaki nadgradnji SDK (npr. 4.x je prepisal polja v camelCase).
// Inline slika SAMO za prvo kodo (zanesljivost: sestavljanje je CPU na glavni niti; ostale kode so v PDF, ena na stran); sestavljanje je asinhrono in prepusca zanko (vstopnica_priloge.js).
async function prilogeVstopnic(ev, kode, imePdf) {
  const starost = ev.min_age > 0 ? `Age limit: ${ev.min_age}+. Show a valid photo ID at the door.` : "";
  const priloge = [];
  if (kode.length) priloge.push({ filename: `${kode[0].cid}.png`, content: (await qrPng(kode[0].koda)).toString("base64"), content_type: "image/png", content_id: kode[0].cid });
  if (kode.length) {
    const pdf = await pdfVstopnice({
      dogodek: { naslov: ev.event_title, zacetek: ljDatum(ev.start_at), prizoriscePodatki: [ev.club_name, ev.club_address, ev.club_city].filter(Boolean).join(", "),
                 starost: ev.starostPdf || starost, organizator: [ev.club_phone, ev.club_email].filter(Boolean).join(" | ") },
      vstopnice: kode.map(k => ({ koda: k.koda, vrsta: k.vrsta, oznaka: k.oznaka })), varnost: QR_STAVEK });
    priloge.push({ filename: imePdf, content: pdf.toString("base64"), content_type: "application/pdf" });
  }
  return priloge;
}
// Klic Resenda z rokom (Promise.race: SDK nima AbortSignal); po izteku poskus velja za neuspel, klic lahko vseeno uspe (mozen dvojnik).
// Vrne { data } ali { error } (Resend ob napaki ne vrze). Brez sledenja: Resend ga nastavlja na domeni, ne na mailu (glej STATE).
async function gostResendPosli({ to, subject, html, text, attachments }) {
  let timer;
  const poslano = resend.emails.send({
    from: process.env.EMAIL_FROM || "onboarding@resend.dev", to, reply_to: POSTA_ODGOVOR, subject, html, text, ...(attachments && attachments.length ? { attachments } : {}),
  });
  poslano.catch(() => {});
  try {
    return await Promise.race([poslano, new Promise((_, rej) => { timer = setTimeout(() => rej(new Error("rok za Resend potekel")), GOST_POSTA_TIMEOUT_MS); })]);
  } catch (err) { return { error: { message: err && (err.message || String(err)) } }; }
  finally { clearTimeout(timer); }
}
// Socasna posiljanja v procesu (Resend ne sme zasesti procesa ob mnozici placil naenkrat); cakajoci v pomnilniku, najvec 200.
const gostPosta = { aktivnih: 0, cakajoci: [] };
async function gostPostaVstopi() {
  if (gostPosta.aktivnih < GOST_POSTA_SOCASNIH) { gostPosta.aktivnih++; return true; }
  if (gostPosta.cakajoci.length >= 200) return false;   // pospravljalec poskusi pozneje (poskus se se ni porabil)
  await new Promise((r) => gostPosta.cakajoci.push(r));
  return true;
}
function gostPostaIzstopi() { const n = gostPosta.cakajoci.shift(); if (n) n(); else gostPosta.aktivnih--; }
const gostPostaZadnjiDnevnik = new Map();   // vrsta zapisa -> ms; isti zapis najvec enkrat na uro (sweeper bi ga sicer ponavljal ob vsakem teku)
function gostPostaDnevnik(vrsta, sporocilo, raven = "error") {
  if (Date.now() - (gostPostaZadnjiDnevnik.get(vrsta) || 0) > 3600 * 1000) { gostPostaZadnjiDnevnik.set(vrsta, Date.now()); console[raven](sporocilo); }
}
const gostPostaIzcrpaj = (oid) => pool.query("UPDATE orders SET guest_mail_attempts = $2 WHERE id = $1 AND guest_mail_sent_at IS NULL", [oid, GOST_POSTA_POSKUSOV]);

async function posljiGostuVstopnice(oid) {
  if (!resend) return false;
  if (!(await gostPostaVstopi())) return false;
  try { return await gostPosljiEnoPosto(oid); }
  catch (err) { console.error(`Resend napaka (gost, vstopnice, narocilo ${oid}):`, err && (err.message || String(err))); return false; }
  finally { gostPostaIzstopi(); }
}
async function gostPosljiEnoPosto(oid) {
  const pre = (await pool.query(
    `SELECT guest_email, status, guest_mail_sent_at, guest_mail_attempts, public_ref, COALESCE(stripe_payment_intent_id LIKE 'test_%', FALSE) AS is_test
       FROM orders WHERE id = $1`, [oid])).rows[0];
  if (!pre || !pre.guest_email || pre.status !== "paid" || pre.guest_mail_sent_at || pre.guest_mail_attempts >= GOST_POSTA_POSKUSOV) return false;
  // Meje (zloraba: mail na tuj naslov brez placila) veljajo SAMO za testna narocila: globalno na dan in 1 mail na naslov na 24 h.
  // Potrdilo placanega narocila je zakonska obveznost (ZVPot-1): nikoli se ne odlozi ne izpusti, ob preseznem stevilu samo opozorilo (brez e-naslova).
  const dnevno = (await pool.query("SELECT COUNT(*)::int AS n FROM orders WHERE guest_mail_sent_at > NOW() - INTERVAL '24 hours'")).rows[0].n;
  if (pre.is_test) {
    if (dnevno >= GOST_POSTA_DNEVNO) { await gostPostaIzcrpaj(oid); gostPostaDnevnik("testni", `[gost] dnevna meja gostujocih mailov (${GOST_POSTA_DNEVNO}): testni mail izpuscen (narocilo ${pre.public_ref})`); return false; }
    const ze = await pool.query("SELECT 1 FROM orders WHERE guest_email = $1 AND id <> $2 AND guest_mail_sent_at > NOW() - INTERVAL '24 hours' LIMIT 1", [pre.guest_email, oid]);
    if (ze.rows.length) { await gostPostaIzcrpaj(oid); console.error(`[gost] testni nacin: mail na isti naslov je bil ze poslan v 24 h, izpuscen (narocilo ${pre.public_ref})`); return false; }
  } else if (dnevno >= GOST_POSTA_DNEVNO) {
    gostPostaDnevnik("placan", `[gost] opozorilo: ze ${dnevno} gostujocih mailov v 24 h (meja ${GOST_POSTA_DNEVNO} velja samo za testna narocila); potrdilo placanega narocila ${pre.public_ref} se poslje vseeno`, "warn");
  }
  const k = await pool.query(
    `UPDATE orders SET guest_mail_attempts = guest_mail_attempts + 1, guest_mail_claimed_at = NOW()
      WHERE id = $1 AND guest_email IS NOT NULL AND status = 'paid' AND guest_mail_sent_at IS NULL AND guest_mail_attempts < $2
        AND (guest_mail_claimed_at IS NULL OR guest_mail_claimed_at < NOW() - ($3::bigint[])[guest_mail_attempts + 1] * INTERVAL '1 millisecond')
      RETURNING public_ref, guest_email, quantity, event_id, club_id, user_id, unit_price_cents, total_cents, currency, vat_rate, created_at, paid_at, guest_terms_version, guest_mail_attempts`,
    [oid, GOST_POSTA_POSKUSOV, GOST_POSTA_PREMORI]);
  if (!k.rows.length) return false;
  const o = k.rows[0];
  const ev = await pool.query(
    `SELECT e.title AS event_title, e.start_at, e.min_age, cl.name AS club_name, cl.address AS club_address, cl.city AS club_city,
            cl.contact_phone AS club_phone, cl.contact_email AS club_email
       FROM events e JOIN clubs cl ON cl.id = e.club_id WHERE e.id = $1`, [o.event_id]);
  if (!ev.rows.length) return false;
  const x = { ...o, ...ev.rows[0] };
  const zeton = o.user_id === null ? await gostKujZeton(pool, oid) : null;
  const prevzeto = zeton === null;   // narocilo je ze v racunu (zeton gosta je preklican): povezava vodi v /app/tickets
  const povezava = prevzeto ? `${placilaStripe.osnovaSpleta()}/app/tickets` : gostPovezava(zeton);
  // Kode QR kot vgrajene slike (CID) + PDF v prilogi (migracija 034): samo vstopnice, ki so SE vedno kupceve in veljavne (prevzeto naročilo je lahko
  // medtem delno preneseno: stara koda ne velja vec in je v mailu ne kazemo).
  const kv = (await pool.query(
    `SELECT t.serial, t.event_id, t.created_at FROM tickets t WHERE t.order_id = $1 AND t.status = 'valid' AND t.holder_user_id IS NULL AND NOT t.holder_is_guest ORDER BY t.id`, [oid])).rows;
  const kode = kv.map((t, i) => ({ cid: `ticket-qr-${i + 1}`, oznaka: kv.length > 1 ? `Ticket ${i + 1} of ${kv.length}` : "", koda: qrVstopnice(t) }));
  const { besedilo, html } = gostPotrdilo(x, povezava, prevzeto, kode);
  const priloge = await prilogeVstopnic(x, kode.map(k => ({ ...k, vrsta: "Standard ticket" })), "outly-tickets.pdf");
  const r = await gostResendPosli({
    to: o.guest_email, subject: `Your tickets: ${x.event_title} (order ${o.public_ref})`.slice(0, 200), html, text: besedilo, attachments: priloge,
  });
  if (r && r.error) {
    console.error(`Resend napaka (gost, vstopnice, ${o.public_ref}, poskus ${o.guest_mail_attempts}/${GOST_POSTA_POSKUSOV}):`, JSON.stringify(r.error));
    if (o.guest_mail_attempts >= GOST_POSTA_POSKUSOV) console.error(`[gost] POZOR: potrdilo za narocilo ${o.public_ref} NI mogoce poslati (izcrpanih ${GOST_POSTA_POSKUSOV} poskusov); gost ima vstopnice samo prek povezave iz odgovora nakupa`);
    return false;
  }
  await pool.query("UPDATE orders SET guest_mail_sent_at = NOW() WHERE id = $1", [oid]);
  console.log(`[gost] mail z vstopnicami poslan: narocilo ${o.public_ref}`);
  return true;
}
// Pospravljalec: placana gostujoca narocila brez poslanega maila (Resend je padel, proces se je ugasnil med placilom in mailom).
let gostPostaTece = false;
async function gostPosljiNeposlane() {
  if (!resend || gostPostaTece) return;
  gostPostaTece = true;
  try {
    const r = await pool.query(
      `SELECT id FROM orders WHERE guest_email IS NOT NULL AND guest_mail_sent_at IS NULL AND status = 'paid'
          AND guest_mail_attempts < $1 AND paid_at > NOW() - INTERVAL '3 days'
          AND (guest_mail_claimed_at IS NULL OR guest_mail_claimed_at < NOW() - ($2::bigint[])[guest_mail_attempts + 1] * INTERVAL '1 millisecond')
        ORDER BY id LIMIT 20`, [GOST_POSTA_POSKUSOV, GOST_POSTA_PREMORI]);   // premor v SQL (isti pogoj kot pri zaklepu): najstarejsi v premoru ne stradajo novejsih
    for (const o of r.rows) await posljiGostuVstopnice(o.id);
    await prenosPosljiNeposlane();   // vstopnice, poslane prijateljem brez racuna (034)
  } catch (e) { console.error("[gost] pospravljanje mailov:", e && e.message); }
  finally { gostPostaTece = false; }
}
// Prvi tek NE takoj po zagonu (glavni pool je takrat najbolj zaseden).
if (GOST_POSTA_PONOVI_MS > 0) setInterval(gostPosljiNeposlane, GOST_POSTA_PONOVI_MS).unref();
// Hramba osebnih podatkov gosta (pravna analiza 5. 10. 2026, 2.3; roki so PREDPOSTAVKA, Martin jih lahko spremeni):
//   * potekli zetoni (konec dogodka + 30 dni) se brisejo (poizvedba po zetonu jih ze zavrne, to je higiena);
//   * neplacana (cancelled/failed) gostujoca narocila: e-naslov se anonimizira 24 h po preklicu (pogodbe ni; e-naslov je rabil samo pravilu »1 neplacano«);
//   * placana (tudi vrnjena): e-naslov se anonimizira GOST_HRAMBA_DNI (privzeto 180) po koncu dogodka (vracila ob odpovedi/prestavitvi, pritozbe, spori).
// Anonimizacija = kot ob izbrisu racuna: buyer_email 'izbrisan-<id>@outly.invalid', guest_email NULL; znesek, datum in dogodek ostanejo.
// Prevzeta narocila (user_id nastavljen): buyer_email je e-naslov racuna, zato se pocisti samo guest_email.
// Ob obnovi iz varnostne kopije se anonimizacija ponovi (isti tek).
const GOST_HRAMBA_DNI = okoljeCelo("GOST_HRAMBA_DNI", 180, 1, 3650);
async function pocistiGostZetone() {
  try {
    const r = await pool.query(
      `DELETE FROM gost_zetoni z USING orders o, events e
        WHERE o.id = z.order_id AND e.id = o.event_id
          AND COALESCE(e.end_at, e.start_at + INTERVAL '8 hours') + INTERVAL '${GOST_ZETON_DNI} days' < NOW()`);
    if (r.rowCount > 0) console.log(`[gost] pospravljenih ${r.rowCount} potecenih zetonov`);
    const an = await pool.query(
      `WITH k AS (
         SELECT o.id FROM orders o JOIN events e ON e.id = o.event_id
          WHERE o.guest_email IS NOT NULL AND (
                (o.status IN ('cancelled','failed') AND COALESCE(o.cancelled_at, o.created_at) < NOW() - INTERVAL '24 hours')
             OR (o.status IN ('paid','partially_refunded','refunded')
                 AND COALESCE(e.end_at, e.start_at + INTERVAL '8 hours') + $1::int * INTERVAL '1 day' < NOW()))
          LIMIT 1000),
       u AS (UPDATE orders o SET guest_email = NULL,
                    buyer_email = CASE WHEN o.user_id IS NULL THEN 'izbrisan-' || o.id || '@outly.invalid' ELSE o.buyer_email END
              FROM k WHERE o.id = k.id RETURNING o.id)
       DELETE FROM gost_zetoni WHERE order_id IN (SELECT id FROM u)`, [GOST_HRAMBA_DNI]);
    if (an.rowCount > 0) console.log(`[gost] anonimiziranih gostujocih narocil: zetonov ${an.rowCount}`);
    // Vstopnice, poslane gostu (034): zetoni potecejo in e-naslov imetnika se izbrise konec dogodka + 30 dni (GOST_ZETON_DNI; pravna presoja 1.4).
    // holder_is_guest OSTANE (vstopnica ne sme spet postati kupceva); zapis prenosa dobi neosebno oznako.
    const konec = `COALESCE(e.end_at, e.start_at + INTERVAL '8 hours') + INTERVAL '${GOST_ZETON_DNI} days' < NOW()`;
    await pool.query(`DELETE FROM gost_zetoni_vstopnic z USING tickets t, events e WHERE t.id = z.ticket_id AND e.id = t.event_id AND ${konec}`);
    const at = await pool.query(
      `WITH k AS (SELECT t.id FROM tickets t JOIN events e ON e.id = t.event_id WHERE t.holder_guest_email IS NOT NULL AND ${konec} LIMIT 1000),
            u AS (UPDATE tickets t SET holder_guest_email = NULL FROM k WHERE t.id = k.id RETURNING t.id),
            p AS (UPDATE ticket_transfers x SET to_email = 'izbrisan-' || x.id || '@outly.invalid', to_email_norm = NULL
                   WHERE x.to_guest AND x.to_user_id IS NULL AND x.ticket_id IN (SELECT id FROM u) RETURNING 1)
       SELECT (SELECT COUNT(*)::int FROM u) AS n`);
    if (at.rows[0].n > 0) console.log(`[gost] anonimiziranih prenesenih gostujocih vstopnic: ${at.rows[0].n}`);
  } catch (e) { console.error("[gost] pospravljanje ni uspelo:", e && e.message); }
}

// ---------------------------
// PRENOS VSTOPNICE PRIJATELJU BREZ RACUNA — migracija 034, invarianta I7/I23
// ---------------------------
// Martin, 5. 10. 2026: uporabnik z racunom vpise e-naslov prijatelja, ki racuna nima; prijatelj dobi mail s kodo QR (vgrajena slika), PDF in skrivno povezavo.
// Stikalo: PRENOS_BREZ_RACUNA (mozenPrenosGostu). Vstopnica dobi gostujocega IMETNIKA (tickets.holder_is_guest + holder_guest_email), serial se zamenja
// (posiljateljeva koda ne velja), pogled gosta je ZETON v glavi X-Guest-Token (gost_zetoni_vstopnic, v bazi samo sha256, hex TEXT). Posiljatelj zetona
// NIKOLI ne dobi (zeton se skuje sele ob posiljanju maila). Mail: najvec enkrat ob uspehu, ponovitve kot pri gostujocem nakupu (premor 2 min .. 24 h, 8 poskusov).
const GOST_PRENOS_NA_DAN = okoljeCelo("GOST_PRENOS_NA_DAN", 10, 1, 100000);                  // prenosov gostu na posiljatelja na 24 h (mail tujemu naslovu)
const GOST_PRENOS_NA_NASLOV = okoljeCelo("GOST_PRENOS_NA_NASLOV", 10, 1, 100000);           // prenosov z allow_guest na isti (normaliziran) e-naslov na 24 h (ne glede na posiljatelja)
const GOST_PRENOS_DNEVNO = okoljeCelo("GOST_PRENOS_DNEVNO", 500, 1, 10000000);                // globalno: prenosov gostu (maili tujcem) na 24 h; ob dosegu 429 + alarm v dnevniku
// Kljuc za mejo na prejemnika: mala crka, brez »+oznake« v lokalnem delu, pri gmail.com/googlemail.com tudi brez pik (»i.me+x@gmail.com« in »ime@gmail.com« sta isti nabiralnik).
// Ni varnostna meja kot taka (domene z lastnimi pravili ne poznamo), samo ovira najpreprostejse obhode.
function naslovKljuc(email) {
  const [lok0, dom0] = String(email).trim().toLowerCase().split("@");
  let lok = (lok0 || "").split("+")[0], dom = dom0 || "";
  if (dom === "gmail.com" || dom === "googlemail.com") { lok = lok.replace(/\./g, ""); dom = "gmail.com"; }
  return `${lok}@${dom}`;
}

async function gostKujZetonVstopnice(db, tid) {
  const zeton = crypto.randomBytes(32).toString("base64url");
  const r = await db.query("INSERT INTO gost_zetoni_vstopnic (token_hash, ticket_id) SELECT $1, t.id FROM tickets t WHERE t.id = $2 AND t.holder_is_guest", [gostZetonHash(zeton), tid]);
  if (!r.rowCount) return null;   // vstopnica ni (vec) gostujoca (prevzeta v racun): zetonov od prevzema naprej ni vec
  await db.query(
    `DELETE FROM gost_zetoni_vstopnic WHERE ticket_id = $1
       AND token_hash NOT IN (SELECT token_hash FROM gost_zetoni_vstopnic WHERE ticket_id = $1 ORDER BY created_at DESC LIMIT ${GOST_ZETONOV_NA_NAROCILO})`, [tid]);
  return zeton;
}
// id vstopnice za zeton ali null (napacen, potekel, prevzet v racun, ponovno prenesen: vse enako, brez razlike). Indeksirano (PK) in poceni.
async function gostVstopnicaPoZetonu(db, zeton) {
  if (typeof zeton !== "string" || !GOST_ZETON_VZOREC.test(zeton)) return null;
  const r = await db.query(
    `SELECT t.id FROM gost_zetoni_vstopnic z JOIN tickets t ON t.id = z.ticket_id JOIN events e ON e.id = t.event_id
      WHERE z.token_hash = $1 AND t.holder_is_guest
        AND COALESCE(e.end_at, e.start_at + INTERVAL '8 hours') + INTERVAL '${GOST_ZETON_DNI} days' > NOW()`, [gostZetonHash(zeton)]);
  return r.rows.length ? r.rows[0].id : null;
}
const gostVstopnicaPovezava = (zeton) => `${placilaStripe.osnovaSpleta()}/app/guest/ticket#t=${zeton}`;

// GET /guest/ticket — pogled gostujocega imetnika vstopnice. Zeton v glavi X-Guest-Token (NE v URL-ju). Enak 404 za vse neveljavne primere.
// Veljaven zeton NIKOLI ne dobi 429 (meja neuspesnih velja samo za neveljavne, kot GET /guest/order).
app.get("/guest/ticket", async (req, res) => {
  res.set("Cache-Control", "no-store");
  try {
    const tid = await gostVstopnicaPoZetonu(pool, req.get("x-guest-token"));
    if (!tid) return gostNeuspesen(req, res, "Ticket not found.");
    const r = await pool.query(`${SQL_VSTOPNICE_POGLED} WHERE t.id = $1`, [tid]);
    if (!r.rows.length) return res.status(404).send("Ticket not found.");
    const t = r.rows[0];
    // Posiljatelj (uporabniško ime zadnjega prenosa gostu; ze v mailu): buyer_username ima isto vrednost (splet ga ne bere, ohrani obliko /me/tickets).
    const od = (await pool.query(
      `SELECT u.username FROM ticket_transfers tt JOIN users u ON u.id = tt.from_user_id WHERE tt.ticket_id = $1 AND tt.to_guest ORDER BY tt.id DESC LIMIT 1`, [tid])).rows[0];
    const pos = od ? od.username : null;
    // BELI SEZNAM polj (ne SELECT-ova oblika /me/tickets): brez order_id, holder_user_id, holder_id, holder_email, is_guest, order_status (notranje/kupcevo).
    // public_ref ostane: spletna stran ga kaze kot »ORDER« (webapp/js/views/vstopnice.js QrTelo).
    const bel = {};
    for (const k of ["id", "serial", "status", "used_at", "created_at", "event_id", "event_title", "start_at", "end_at", "poster_url", "min_age", "club_id", "club_name",
      "address", "city", "logo_url", "is_vip", "table_label", "table_seats", "package_name", "package_description", "public_ref", "transferred", "holder_username", "is_guest_holder"]) bel[k] = t[k];
    return res.json({
      ticket: { ...bel, qr: qrVstopnice(t), transferable: false, from_username: pos, buyer_username: pos },   // gost vstopnice ne more naprej (brez racuna)
      event: { id: t.event_id, title: t.event_title, start_at: t.start_at, end_at: t.end_at, poster_url: t.poster_url, min_age: t.min_age,
               club_id: t.club_id, club_name: t.club_name, address: t.address, city: t.city, logo_url: t.logo_url },
    });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// --- mail prejemniku ---
// Vsebina po pravni presoji (outly-hq pravno/2026-10-05-prenos-brez-racuna.md, razdelki 1.3, 3, 5): obvestilo po GDPR 14 v CELOTI v mailu (politika prenosa brez racuna
// ne opisuje), pravica do ugovora (21(4)) v LOCENEM odstavku, varnostno besedilo, en nevtralen stavek o prevzemu v racun (ne trzenje, ZEKom-2 226), brez oglasov.
// Pošiljatelj = uporabniško ime (nikoli e-naslov). Brez sledenja (to nastavlja Resend na domeni). E-naslova prejemnika ni v PDF.
function prenosPotrdilo(x, povezava, kode) {
  const klubKontakt = [x.club_phone, x.club_email].filter(Boolean).join(", ");
  const meja = starostZaPaket(x.min_age, x.package_id !== null && x.package_id !== undefined);
  const starost = meja > 0
    ? `Age limit: ${meja}+${meja > x.min_age ? " (table with a drinks package)" : ""}. Show a valid photo ID at the door; if you are under ${meja}, the club will refuse entry.`
    : "No age limit.";
  const vrsta = x.table_label ? `VIP table ${x.table_label}${x.package_name ? `, package: ${x.package_name}` : ""}` : "Standard ticket";
  const posiljatelj = x.from_username || "An Outly user";
  const razdelki = [
    { naslov: "This is your ticket", vrstice: [QR_STAVEK] },
    { naslov: "Event", vrstice: [x.event_title, ljDatum(x.start_at), [x.club_name, x.club_address, x.club_city].filter(Boolean).join(", "),
        `Organiser: ${x.club_name}${klubKontakt ? ` (${klubKontakt})` : ""}. Contact the organiser about the event itself.`, starost] },
    { naslov: "Your ticket", vrstice: [vrsta, `Show this QR code at the door (it is also in the attached PDF, outly-ticket.pdf): ${povezava}`], slika: true },
    { naslov: "Ticket rules", vrstice: ["One entry per code.", "The organiser may refuse entry under its house rules or the law.", "Reselling the ticket is not allowed.",
        "If the event is cancelled, a refund goes to the person who bought the ticket, not to you.", "If you create an Outly account with this email, the ticket will appear there."] },
    { naslov: "Not for you?", vrstice: [`If you were not expecting this ticket, reply to this email and we will delete your email address.`] },
    { naslov: "About your email address (GDPR, Article 14)", vrstice: [
        `Who we are: ${POSREDNIK_VRSTICA}.`,
        `Why: we use your email address only to deliver this ticket and to allow entry. Legal basis: legitimate interest (GDPR Article 6(1)(f)): ${posiljatelj} wanted to pass this ticket on to you.`,
        `Where we got it: ${posiljatelj}, an Outly user, entered your email address.`,
        `Data: your email address, the ticket and event, the sender's confirmation that you meet the age limit (if there is one), and the time the ticket is scanned at entry.`,
        `Recipients: Resend (email delivery). The organiser (${x.club_name}) only sees that the ticket was passed on to a guest, not your email address.`,
        `Transfer outside the EEA: our email provider is based in the United States; the transfer relies on the EU standard contractual clauses or an adequacy decision, as described in our privacy policy.`,
        `Retention: we delete your email address 30 days after the event ends, unless you create an Outly account with it.`,
        `Your rights: access, rectification, erasure, restriction, and a complaint to the Information Commissioner of Slovenia (www.ip-rs.si). Privacy policy: https://outly.si/privacy` ] },
    { naslov: "Right to object", vrstice: [`Don't want us to process your email address? You have the right to object at any time: reply to this email and we will delete your address.`] },
    { naslov: "Questions", vrstice: [`Reply to this email or write to ${POSTA_ODGOVOR}.`] },
  ];
  const besedilo = `${posiljatelj} sent you a ticket for ${x.event_title}\n\n` + razdelki.map(r => `${r.naslov.toUpperCase()}\n${r.vrstice.join("\n")}`).join("\n\n") + "\n";
  const html = `<div style="font-family: Arial, sans-serif; line-height:1.5"><h2>${GOST_POSTA_NIZ(posiljatelj)} sent you a ticket</h2>` + razdelki.map(r => {
    const jeVarnost = r.naslov === "This is your ticket";
    return `<h3>${GOST_POSTA_NIZ(r.naslov)}</h3>` + r.vrstice.map(v => {
      const e = GOST_POSTA_NIZ(v);
      const z = povezava && v.includes(povezava) ? e.replace(GOST_POSTA_NIZ(povezava), `<a href="${GOST_POSTA_NIZ(povezava)}">${GOST_POSTA_NIZ(povezava)}</a>`) : e;
      return `<p>${jeVarnost ? `<strong>${z}</strong>` : z}</p>`;
    }).join("") + (r.slika ? kode.map(k => qrSlikaHtml(k.cid, k.oznaka)).join("") : "");
  }).join("") + `</div>`;
  return { besedilo, html };
}

// Meje maila (zloraba: mail na tuj naslov) so v transakciji prenosa (POST /tickets/:id/transfer): GOST_PRENOS_NA_DAN na posiljatelja, GOST_PRENOS_NA_NASLOV na naslov.
async function posljiPrenosGostu(tid) {
  if (!resend) return false;
  if (!(await gostPostaVstopi())) return false;
  try { return await prenosPosljiEnoPosto(tid); }
  catch (err) { console.error(`Resend napaka (prenos gostu, vstopnica ${tid}):`, err && (err.message || String(err))); return false; }
  finally { gostPostaIzstopi(); }
}
async function prenosPosljiEnoPosto(tid) {
  const k = await pool.query(
    `UPDATE tickets SET holder_guest_mail_attempts = holder_guest_mail_attempts + 1, holder_guest_mail_claimed_at = NOW()
      WHERE id = $1 AND holder_is_guest AND holder_guest_email IS NOT NULL AND status = 'valid' AND holder_guest_mail_sent_at IS NULL AND holder_guest_mail_attempts < $2
        AND (holder_guest_mail_claimed_at IS NULL OR holder_guest_mail_claimed_at < NOW() - ($3::bigint[])[holder_guest_mail_attempts + 1] * INTERVAL '1 millisecond')
      RETURNING id, holder_guest_email, serial, event_id, created_at, holder_guest_mail_attempts`,
    [tid, GOST_POSTA_POSKUSOV, GOST_POSTA_PREMORI]);
  if (!k.rows.length) return false;
  const t = k.rows[0];
  const ev = await pool.query(
    `SELECT e.title AS event_title, e.start_at, e.min_age, cl.name AS club_name, cl.address AS club_address, cl.city AS club_city,
            cl.contact_phone AS club_phone, cl.contact_email AS club_email, o.package_id, o.table_label, o.package_name,
            (SELECT u.username FROM ticket_transfers tt JOIN users u ON u.id = tt.from_user_id WHERE tt.ticket_id = t.id AND tt.to_guest ORDER BY tt.id DESC LIMIT 1) AS from_username
       FROM tickets t JOIN orders o ON o.id = t.order_id JOIN events e ON e.id = t.event_id JOIN clubs cl ON cl.id = e.club_id WHERE t.id = $1`, [tid]);
  if (!ev.rows.length) return false;
  const x = ev.rows[0];
  const zeton = await gostKujZetonVstopnice(pool, tid);
  if (!zeton) return false;   // medtem prevzeto v racun
  const kode = [{ cid: "ticket-qr-1", oznaka: "", koda: qrVstopnice(t) }];
  const meja = starostZaPaket(x.min_age, x.package_id !== null);
  const vrsta = x.table_label ? `VIP table ${x.table_label}${x.package_name ? ` - ${x.package_name}` : ""}` : "Standard ticket";
  const povezava = gostVstopnicaPovezava(zeton);
  const { besedilo, html } = prenosPotrdilo(x, povezava, kode);
  const priloge = await prilogeVstopnic({ ...x, starostPdf: meja > 0 ? `Age ${meja}+ - bring a valid photo ID` : "" }, kode.map(c => ({ ...c, vrsta })), "outly-ticket.pdf");
  const r = await gostResendPosli({ to: t.holder_guest_email, subject: `${x.from_username || "An Outly user"} sent you a ticket for ${x.event_title}`.slice(0, 200), html, text: besedilo, attachments: priloge });
  if (r && r.error) {
    console.error(`Resend napaka (prenos gostu, vstopnica ${tid}, poskus ${t.holder_guest_mail_attempts}/${GOST_POSTA_POSKUSOV}):`, JSON.stringify(r.error));
    if (t.holder_guest_mail_attempts >= GOST_POSTA_POSKUSOV) console.error(`[gost] POZOR: mail s prenesene vstopnice ${tid} NI mogoce poslati (izcrpanih ${GOST_POSTA_POSKUSOV} poskusov); prejemnik vstopnice ni dobil`);
    return false;
  }
  await pool.query("UPDATE tickets SET holder_guest_mail_sent_at = NOW() WHERE id = $1", [tid]);
  console.log(`[gost] mail s preneseno vstopnico poslan: vstopnica ${tid}`);
  return true;
}
// Pospravljalec (isti urnik in premori kot za potrdila gostujocih nakupov).
async function prenosPosljiNeposlane() {
  const r = await pool.query(
    `SELECT t.id FROM tickets t WHERE t.holder_is_guest AND t.holder_guest_email IS NOT NULL AND t.holder_guest_mail_sent_at IS NULL AND t.status = 'valid'
        AND t.holder_guest_mail_attempts < $1
        AND (t.holder_guest_mail_claimed_at IS NULL OR t.holder_guest_mail_claimed_at < NOW() - ($2::bigint[])[t.holder_guest_mail_attempts + 1] * INTERVAL '1 millisecond')
      ORDER BY t.id LIMIT 20`, [GOST_POSTA_POSKUSOV, GOST_POSTA_PREMORI]);
  for (const t of r.rows) await posljiPrenosGostu(t.id);
}

// POST /admin/api/guest-tickets/erase — ugovor prejemnika (GDPR 21) ali zahteva za izbris: prejemnik odgovori na mail, admin (ekipa) izbrise njegov e-naslov.
// Telo { email }. Vstopnicam, poslanim temu naslovu, se izbrise holder_guest_email in zetoni (povezava preneha delovati), zapisi prenosa dobijo neosebno
// oznako. Vstopnica OSTANE gostujoca (koda v mailu velja do konca dogodka; vrnitev posiljatelju ni avtomatizirana). Odgovor { tickets, transfers } (stevili).
admin.post("/guest-tickets/erase", async (req, res) => {
  try {
    const email = gostEmail((req.body || {}).email);
    if (!email) return res.status(400).json({ error: "invalid_email", message: "A valid email is required." });
    const r = await pool.query(
      `WITH t AS (UPDATE tickets SET holder_guest_email = NULL WHERE holder_is_guest AND holder_guest_email = $1 RETURNING id),
            z AS (DELETE FROM gost_zetoni_vstopnic WHERE ticket_id IN (SELECT id FROM t) RETURNING 1),
            x AS (UPDATE ticket_transfers SET to_email = 'izbrisan-' || id || '@outly.invalid', to_email_norm = NULL
                   WHERE to_guest AND to_user_id IS NULL AND to_email = $1 RETURNING 1)
       SELECT (SELECT COUNT(*)::int FROM t) AS tickets, (SELECT COUNT(*)::int FROM x) AS transfers`, [email]);
    console.log(`[gost] admin ${req.user.userId}: izbris e-naslova gostujocih vstopnic: ${r.rows[0].tickets} vstopnic, ${r.rows[0].transfers} zapisov prenosa`);
    return res.json(r.rows[0]);
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// --- poslovni del: prodaja ---
// Klub iz requireClub (lastnik ali član ekipe). Admin brez kluba -> null -> 404.
async function mojKlubId(req) {
  return req.klub ? req.klub.clubId : null;
}

// GET /business/sales — povzetek prodaje lastnega kluba, po dogodkih, zadnja naročila.
// Graf prodaje po obdobjih (Martin, 25. 9. 2026), poleg obstojecega sales_by_day (14 dni,
// star odjemalec ostane nespremenjen). week/month = dnevni kosi, year = mesecni kosi —
// vsi koraki vkljuceni tudi brez prodaje (0), da graf ne preskakuje dni/mesecev.
async function serijaProdaje(klub, range) {
  if (range === "year") {
    const r = await pool.query(
      `SELECT to_char(d.mesec, 'YYYY-MM') AS bucket,
              COALESCE(SUM(o.total_cents),0)::int AS gross_cents,
              COALESCE(SUM(o.quantity) FILTER (WHERE o.table_id IS NULL),0)::int AS tickets
         FROM generate_series(date_trunc('month', CURRENT_DATE - INTERVAL '11 months'),
                               date_trunc('month', CURRENT_DATE), '1 month') AS d(mesec)
         LEFT JOIN orders o ON o.club_id = $1 AND o.status IN ('paid','partially_refunded') AND o.guest_list_id IS NULL
              AND o.created_at >= d.mesec AND o.created_at < d.mesec + INTERVAL '1 month'
        GROUP BY d.mesec ORDER BY d.mesec`, [klub]
    );
    return r.rows;
  }
  const dni = range === "month" ? 29 : 6; // month: zadnjih 30 dni, week: zadnjih 7 dni.
  const r = await pool.query(
    `SELECT to_char(d.dan, 'YYYY-MM-DD') AS bucket,
            COALESCE(SUM(o.total_cents),0)::int AS gross_cents,
            COALESCE(SUM(o.quantity) FILTER (WHERE o.table_id IS NULL),0)::int AS tickets
       FROM generate_series((CURRENT_DATE - $2 * INTERVAL '1 day')::date, CURRENT_DATE, '1 day') AS d(dan)
       LEFT JOIN orders o ON o.club_id = $1 AND o.status IN ('paid','partially_refunded') AND o.guest_list_id IS NULL
            AND o.created_at >= d.dan AND o.created_at < d.dan + INTERVAL '1 day'
      GROUP BY d.dan ORDER BY d.dan`, [klub, dni]
  );
  return r.rows;
}

app.get("/business/sales", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  try {
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");
    const range = ["week", "month", "year"].includes(req.query.range) ? req.query.range : null;
    const [povzetek, poDogodkih, zadnja, poDnevih, serija] = await Promise.all([
      pool.query(
        `SELECT COALESCE(SUM(o.total_cents),0)::int AS gross_cents,
                COALESCE(SUM(o.application_fee_cents),0)::int AS fee_cents,
                COALESCE(SUM(o.total_cents - o.application_fee_cents - o.refunded_cents),0)::int AS net_cents,
                -- tickets_sold = samo navadne vstopnice (narocila brez mize); gross_cents vkljucuje mize (migracija 025).
                COALESCE(SUM(o.quantity) FILTER (WHERE o.table_id IS NULL),0)::int AS tickets_sold,
                COUNT(*)::int AS orders,
                COUNT(DISTINCT COALESCE(o.user_id::text, lower(o.guest_email)))::int AS buyers,
                COALESCE(SUM(o.total_cents) FILTER (WHERE o.created_at > NOW() - INTERVAL '7 days'),0)::int AS gross_7d_cents,
                COALESCE(SUM(o.quantity) FILTER (WHERE o.created_at > NOW() - INTERVAL '7 days' AND o.table_id IS NULL),0)::int AS tickets_7d,
                COUNT(*) FILTER (WHERE o.table_id IS NOT NULL)::int AS tables_sold,
                COALESCE(SUM(o.total_cents) FILTER (WHERE o.table_id IS NOT NULL),0)::int AS tables_gross_cents
         FROM orders o WHERE o.club_id = $1 AND o.status IN ('paid','partially_refunded') AND o.guest_list_id IS NULL`, [klub]),   // guest lista (035, I24) ni prodaja: ne v bruto, tickets_sold, stevilo narocil
      pool.query(
        `SELECT e.id, e.title, e.start_at, e.poster_url, e.status, e.ticket_price_cents, e.capacity, e.sold_count,
                COALESCE(SUM(o.total_cents) FILTER (WHERE o.status IN ('paid','partially_refunded')),0)::int AS gross_cents,
                COALESCE(SUM(o.quantity) FILTER (WHERE o.status IN ('paid','partially_refunded') AND o.table_id IS NULL),0)::int AS tickets_sold,
                COUNT(o.id) FILTER (WHERE o.status IN ('paid','partially_refunded') AND o.table_id IS NOT NULL)::int AS tables_sold,
                COALESCE(SUM(o.total_cents) FILTER (WHERE o.status IN ('paid','partially_refunded') AND o.table_id IS NOT NULL),0)::int AS tables_gross_cents,
                (SELECT COUNT(*)::int FROM tickets t WHERE t.event_id = e.id AND t.status = 'used') AS checked_in,
                -- Koliko oseb je oznacilo "I'm in" na tem dogodku (migracija 020). DODANO polje.
                (SELECT COUNT(*)::int FROM event_interest ei WHERE ei.event_id = e.id) AS interested_count
         FROM events e LEFT JOIN orders o ON o.event_id = e.id AND o.guest_list_id IS NULL
         WHERE e.club_id = $1 GROUP BY e.id ORDER BY e.start_at DESC LIMIT 100`, [klub]),
      pool.query(
        `SELECT ${STOLPCI_NAROCILA}, e.title AS event_title, COALESCE(u.username, ${IME_GOSTA}) AS buyer_username
         FROM orders o JOIN events e ON e.id = o.event_id LEFT JOIN users u ON u.id = o.user_id
         WHERE o.club_id = $1 AND o.guest_list_id IS NULL ORDER BY o.created_at DESC LIMIT 30`, [klub]),
      // Zadnjih 14 dni po dnevih (tudi dnevi brez prodaje), za graf v nadzorni plosci.
      pool.query(
        `SELECT to_char(d.dan, 'YYYY-MM-DD') AS day,
                COALESCE(SUM(o.total_cents),0)::int AS gross_cents,
                COALESCE(SUM(o.quantity) FILTER (WHERE o.table_id IS NULL),0)::int AS tickets
         FROM generate_series((CURRENT_DATE - INTERVAL '13 days')::date, CURRENT_DATE, '1 day') AS d(dan)
         LEFT JOIN orders o ON o.club_id = $1 AND o.status IN ('paid','partially_refunded') AND o.guest_list_id IS NULL
              AND o.created_at >= d.dan AND o.created_at < d.dan + INTERVAL '1 day'
         GROUP BY d.dan ORDER BY d.dan`, [klub]),
      // Novo, samo ce je ?range= navedеn — DODANO polje, star odjemalec (brez range) ga ne dobi.
      range ? serijaProdaje(klub, range) : Promise.resolve(null),
    ]);
    // Provizija TEGA kluba (031), ce jo je admin nastavil; sicer privzeta. Lastnik vidi svojo pogodbeno provizijo.
    const kp = (await pool.query("SELECT commission_bps FROM clubs WHERE id=$1", [klub])).rows[0];
    const odgovor = {
      mode: testniNacinPlacil() ? "test" : "live",
      fee_percent: kp && kp.commission_bps !== null ? kp.commission_bps / 100 : PROVIZIJA_ODSTOTEK,
      summary: povzetek.rows[0],
      events: poDogodkih.rows,
      recent_orders: zadnja.rows,
      sales_by_day: poDnevih.rows,
    };
    if (range) odgovor.series = serija;
    return res.json(odgovor);
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// GET /business/events/:id/tickets — vstopnice dogodka (za vrata: kdo je prišel).
app.get("/business/events/:id/tickets", requireAuth, requireClub(), async (req, res) => {
  try {
    const id = celoId(req.params.id);
    if (!id) return res.status(400).send("Invalid event id.");
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");
    const r = await pool.query(
      `SELECT ${STOLPCI_VSTOPNICE}, ${STOLPCI_VIP_VSTOPNICE}, o.public_ref, o.buyer_email, COALESCE(u.username, ${IME_GOSTA}) AS buyer_username, ${STOLPCI_IMETNIKA}
       FROM tickets t JOIN orders o ON o.id = t.order_id JOIN events e ON e.id = t.event_id
       LEFT JOIN users u ON u.id = o.user_id ${JOIN_IMETNIK}
       WHERE t.event_id = $1 AND e.club_id = $2 ORDER BY t.id LIMIT 1000`, [id, klub]
    );
    // Vratar (zacasno osebje) ne potrebuje e-naslovov kupcev (najmanj podatkov, GDPR); za rocni vstop zadostujeta
    // podpisan QR in uporabnisko ime. Lastnik in manager vidita vse kot doslej (pregled 5. 10. 2026).
    const vratar = req.klub && req.klub.role === "doorman";
    return res.json(r.rows.map(t => {
      const v = { ...t, qr: qrVstopnice(t) };
      // Guest lista (035): e-naslovov gostitelja in povabljenih prijateljev klub ne vidi (nobena vloga); samo uporabniska imena.
      if (vratar || t.is_guest_list) { delete v.buyer_email; delete v.holder_email; }
      return v;
    }));
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// GET /me/tickets/received — neprebrana obvestila "X ti je poslal vstopnico" (migracija 017).
// Samo prejemnik iz zetona (I3); o posiljatelju samo id/username/avatar_url (I11), nikoli e-naslov.
// Vstopnica sama je v GET /me/tickets — tu je le obvestilo, ki izgine ob POST .../seen.
app.get("/me/tickets/received", requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT tt.id, tt.ticket_id, tt.created_at, e.id AS event_id, e.title AS event_title, e.start_at AS event_start_at,
              c.name AS club_name, u.id AS from_id, u.username AS from_username, u.avatar_url AS from_avatar_url
       FROM ticket_transfers tt
       JOIN tickets t ON t.id = tt.ticket_id
       JOIN events e ON e.id = t.event_id
       JOIN clubs c ON c.id = e.club_id
       LEFT JOIN users u ON u.id = tt.from_user_id
       WHERE tt.to_user_id = $1 AND tt.seen_at IS NULL
       ORDER BY tt.created_at DESC LIMIT 50`, [req.user.userId]
    );
    return res.json({ received: r.rows.map(x => ({
      id: x.id, ticket_id: x.ticket_id, created_at: x.created_at,
      event_id: x.event_id, event_title: x.event_title, event_start_at: x.event_start_at, club_name: x.club_name,
      from: x.from_id ? { id: x.from_id, username: x.from_username, avatar_url: x.from_avatar_url } : null,
    })) });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// POST /me/tickets/received/:id/seen — prejemnik je obvestilo videl (dotik v meniju). Idempotentno.
// Tuje ali neobstojece obvestilo: 404 (ne razkrivamo, da obstaja).
app.post("/me/tickets/received/:id/seen", requireAuth, async (req, res) => {
  const id = celoId(req.params.id);
  if (!id) return res.status(400).send("Invalid id.");
  try {
    const r = await pool.query(
      `UPDATE ticket_transfers SET seen_at = COALESCE(seen_at, NOW()) WHERE id = $1 AND to_user_id = $2 RETURNING id`,
      [id, req.user.userId]
    );
    if (r.rows.length === 0) return res.status(404).send("Not found.");
    return res.json({ result: "ok" });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// POST /tickets/:id/transfer — prenos vstopnice prijatelju. Telo: { email } ALI { user_id }, neobvezno { allow_guest, age_confirmed }.
// Prenese lahko samo trenutni imetnik; samo veljavno vstopnico pred zacetkom dogodka. Serial se zamenja -> star QR (posnetek zaslona
// pri posiljatelju) ne velja vec. Narocilo ostane kupcu (008).
// Prejemnik: (a) Outly racun s potrjenim e-naslovom (kot doslej); (b) od 5. 10. 2026 GOST: `allow_guest: true` + e-naslov brez (potrjenega) racuna ->
//   vstopnica dobi gostujocega imetnika in prejemnik dobi mail s kodo QR, PDF in povezavo (migracija 034, stikalo PRENOS_BREZ_RACUNA).
// Starost (I8): meja = min_age, pri vstopnici mize s paketom pijace max(min_age, 18) (starostZaPaket). `age_confirmed: true` = POSILJATELJ potrjuje, da
//   prejemnik izpolnjuje mejo (Martin, 5. 10. 2026: »naj oznaci, da je prijatelj 18+, in to je to«; osebni dokument preveri klub na vratih):
//   gost: obvezno (brez -> 400 age_confirmation_required); racun brez datuma rojstva: z njo dovoljeno (brez nje 403 kot doslej);
//   racun z VPISANIM datumom rojstva pod mejo: 403 vedno (znan mladoletnik). Potrditev ni vezana na stikalo.
app.post("/tickets/:id/transfer", requireAuth, omeji({ kljuc: "prenos", najvec: 30, oknoSekund: 3600, priNapaki: "lokalno" }), async (req, res) => {
  const id = celoId(req.params.id);
  if (!id) return res.status(400).send("Invalid ticket id.");
  // Prejemnik: { user_id } prijatelja (izbira iz seznama, migracija 016) ALI { email } kot doslej.
  // Po id sme samo prijatelju — sicer bi se dalo z ugibanjem id-jev posiljati vstopnice
  // (in izvedeti uporabniska imena) neznancem.
  const b0 = req.body || {};
  const prejemnikId = b0.user_id !== undefined ? celoId4(b0.user_id) : null;
  const email = prejemnikId ? "" : String(b0.email || "").trim().toLowerCase();
  if (b0.user_id !== undefined && !prejemnikId) return res.status(400).send("Invalid user_id.");
  if (!prejemnikId && (!email || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) return res.status(400).send("A valid email is required.");
  if (prejemnikId && !(await staPrijatelja(req.user.userId, prejemnikId))) return res.status(404).send("You can only send a ticket by user to one of your friends.");
  const dovoliGosta = !prejemnikId && b0.allow_guest === true;           // gost samo pri { email } (po id sme samo prijatelju, ki ima racun)
  const starostPotrjena = b0.age_confirmed === true;                       // samo boolean true; niz »true« ali stevilo 1 NE zadostujeta
  const gEmail = dovoliGosta ? gostEmail(email) : null;
  // Pri allow_guest se vsi napacni vhodi in meje zavrnejo ENAKO ne glede na to, ali ima naslov racun (brez razkritja racuna): strog e-naslov,
  // potrditev starosti in meje so PRED iskanjem uporabnika.
  if (dovoliGosta && !gEmail) return res.status(400).json({ error: "invalid_email", message: "Enter a valid email address." });
  if (dovoliGosta && !mozenPrenosGostu(req.user.role)) {
    return res.status(403).json({ error: "guest_transfer_disabled", message: "Sending a ticket to someone without an Outly account is not available yet." });
  }

  const c = await pool.connect();
  try {
    await nakupZacni(c);   // lock_timeout/statement_timeout kot pri nakupu: zaklepi vrstice vstopnice, posiljatelja in naslova ne cakajo v neskoncnost
    const tr = await c.query(
      `SELECT t.id, t.serial, t.status, t.event_id, ${IMETNIK} AS holder_id, o.status AS order_status,
              e.title AS event_title, e.start_at, e.min_age, o.package_id, (o.guest_list_id IS NOT NULL) AS guest_lista
       FROM tickets t JOIN orders o ON o.id = t.order_id JOIN events e ON e.id = t.event_id
       WHERE t.id = $1 FOR UPDATE OF t`, [id]
    );
    if (tr.rows.length === 0) { await c.query("ROLLBACK"); return res.status(404).send("Ticket not found."); }
    const t = tr.rows[0];
    // Tuja vstopnica: 404, ne 403 — ne razkrivamo, da obstaja.
    if (Number(t.holder_id) !== Number(req.user.userId)) { await c.query("ROLLBACK"); return res.status(404).send("Ticket not found."); }
    // Guest lista (035, I24): vstopnica je vezana na povabljenca; prenos (tudi na gosta po e-naslovu) bi obsel preverbo prijateljstva in starosti pri vabilu.
    if (t.guest_lista) { await c.query("ROLLBACK"); return res.status(409).send("Guest list tickets can't be transferred."); }
    if (!["paid", "partially_refunded"].includes(t.order_status)) { await c.query("ROLLBACK"); return res.status(409).send("Order is not paid."); }
    if (t.status === "used") { await c.query("ROLLBACK"); return res.status(409).send("Ticket was already used."); }
    if (t.status !== "valid") { await c.query("ROLLBACK"); return res.status(409).send(`Ticket is ${t.status}.`); }
    if (new Date(t.start_at).getTime() <= Date.now()) { await c.query("ROLLBACK"); return res.status(409).send("Event has already started."); }

    // Starost: vstopnica mize s paketom pijace ima mejo najmanj 18 (#102), pri strozji meji dogodka velja ta.
    const potrebnaStarost = starostZaPaket(t.min_age, t.package_id !== null);
    const zaMizo = potrebnaStarost > t.min_age; // meja izhaja iz paketa, ne iz dogodka
    if (dovoliGosta) {
      // (1) potrditev starosti: ista 400 za vsak naslov (racun ali ne, z datumom ali brez), (2) meje na posiljatelja in naslov (steje VSE prenose z allow_guest).
      if (potrebnaStarost > 0 && !starostPotrjena) {
        await c.query("ROLLBACK");
        return res.status(400).json({ error: "age_confirmation_required", min_age: potrebnaStarost,
          message: `Confirm that the person you are sending this ticket to is at least ${potrebnaStarost}.` });
      }
      // Zaklepi VEDNO v vrstnem redu: vrstica vstopnice (zgoraj), posiljatelj, naslov — dva prenosa nikoli ne cakata drug na drugega v krogu.
      await c.query("SELECT pg_advisory_xact_lock(hashtext('prenos-gost'), $1)", [req.user.userId]);
      await c.query("SELECT pg_advisory_xact_lock(hashtext('prenos-gost-naslov:' || $1))", [naslovKljuc(gEmail)]);
      const st = (await c.query(
        `SELECT COUNT(*) FILTER (WHERE from_user_id = $1)::int AS posiljatelj, COUNT(*) FILTER (WHERE to_email_norm = $2)::int AS naslov
           FROM ticket_transfers WHERE allow_guest AND created_at > NOW() - INTERVAL '24 hours' AND (from_user_id = $1 OR to_email_norm = $2)`, [req.user.userId, naslovKljuc(gEmail)])).rows[0];
      if (st.posiljatelj >= GOST_PRENOS_NA_DAN || st.naslov >= GOST_PRENOS_NA_NASLOV) {
        await c.query("ROLLBACK");
        res.set("Retry-After", "3600");
        return res.status(429).json({ error: "guest_transfer_limit", message: "Too many tickets sent by email. Try again later." });
      }
    }

    const pr = prejemnikId
      ? await c.query("SELECT id, email, username, email_verified, starost(date_of_birth) AS leta FROM users WHERE id = $1", [prejemnikId])
      : await c.query("SELECT id, email, username, email_verified, starost(date_of_birth) AS leta FROM users WHERE LOWER(email) = $1", [email]);
    const p = pr.rows[0] || null;
    // GOST: allow_guest in e-naslov brez racuna ali z se nepotrjenim racunom (ob potrditvi se vstopnica prevzame v racun, GET /me).
    const gost = dovoliGosta && (!p || !p.email_verified);
    if (!p && !gost) { await c.query("ROLLBACK"); return res.status(404).send("No Outly account with this email. Ask your friend to sign up first."); }
    if (p && Number(p.id) === Number(req.user.userId)) { await c.query("ROLLBACK"); return res.status(400).send("You already hold this ticket."); }
    if (p && !gost && !p.email_verified) { await c.query("ROLLBACK"); return res.status(409).send("Your friend's account is not verified yet."); }
    if (gost) {
      // Znan mladoletnik: tudi nepotrjen racun z vpisanim datumom rojstva pod mejo je 403 (potrditev posiljatelja ga ne prevlada).
      // Prevzem v racun datuma NE preverja (koda je ze v mailu, klub preveri osebni dokument na vratih): zavestna odlocitev (DECISIONS, I8).
      if (p && p.leta !== null && p.leta < potrebnaStarost) {
        await c.query("ROLLBACK");
        return res.status(403).send(zaMizo ? `Your friend must be at least ${potrebnaStarost} to receive a ticket for a table with a bottle package.` : `Your friend must be at least ${t.min_age} for this event.`);
      }
    } else if (potrebnaStarost > 0) {
      if (p.leta !== null) {
        // Znan datum rojstva odloca (potrditev posiljatelja ga ne prevlada): znanega mladoletnika ne obdarujemo.
        if (p.leta < potrebnaStarost) { await c.query("ROLLBACK"); return res.status(403).send(zaMizo ? `Your friend must be at least ${potrebnaStarost} to receive a ticket for a table with a bottle package.` : `Your friend must be at least ${t.min_age} for this event.`); }
      } else if (!starostPotrjena) {
        await c.query("ROLLBACK");
        return res.status(403).send(zaMizo ? "Your friend must add a date of birth before receiving a ticket for a table with a bottle package." : "Your friend must add a date of birth before receiving a ticket for this event.");
      }
    }
    const potrditevStarosti = potrebnaStarost > 0 && starostPotrjena ? potrebnaStarost : null;

    let u, prejemnikEmail;
    if (gost) {
      prejemnikEmail = gEmail;
      // Posiljatelj mora imeti potrjen e-naslov (mail tujemu naslovu gre v imenu preverjenega racuna); requireAuth to ze zahteva, to je druga plast.
      if (!(await c.query("SELECT email_verified FROM users WHERE id = $1", [req.user.userId])).rows[0]?.email_verified) {
        await c.query("ROLLBACK");
        return res.status(403).json({ error: "email_not_verified", message: "Verify your email to send tickets to people without an account." });
      }
      // Globalna dnevna meja (zloraba: mail tujcem): ob dosegu 429 in alarm v dnevniku (brez e-naslova).
      const dnevno = (await c.query("SELECT COUNT(*)::int AS n FROM ticket_transfers WHERE to_guest AND created_at > NOW() - INTERVAL '24 hours'")).rows[0].n;
      if (dnevno >= GOST_PRENOS_DNEVNO) {
        await c.query("ROLLBACK");
        gostPostaDnevnik("prenos-dnevno", `[gost] ALARM: dosezena dnevna meja prenosov vstopnic gostom (${GOST_PRENOS_DNEVNO} na 24 h): nadaljnji prenosi gostu zavrnjeni (429); preveri zlorabo`);
        res.set("Retry-After", "3600");
        return res.status(429).json({ error: "guest_transfer_limit", message: "Too many tickets sent by email. Try again later." });
      }
      await c.query("DELETE FROM gost_zetoni_vstopnic WHERE ticket_id = $1", [t.id]);   // N2: nobenega ostanka zetonov z prejsnjega gostujocega obdobja
      u = await c.query(
        `UPDATE tickets SET holder_user_id = NULL, holder_is_guest = TRUE, holder_guest_email = $2, serial = gen_random_uuid(),
                holder_guest_mail_sent_at = NULL, holder_guest_mail_claimed_at = NULL, holder_guest_mail_attempts = 0
          WHERE id = $1 AND status = 'valid'
         RETURNING id, order_id, event_id, serial, status, used_at, created_at, holder_user_id`, [t.id, gEmail]);
    } else {
      prejemnikEmail = p.email;
      u = await c.query(
        `UPDATE tickets SET holder_user_id = $2, serial = gen_random_uuid() WHERE id = $1 AND status = 'valid'
         RETURNING id, order_id, event_id, serial, status, used_at, created_at, holder_user_id`, [t.id, p.id]
      );
    }
    if (u.rows.length === 0) { await c.query("ROLLBACK"); return res.status(409).send("Ticket is no longer valid."); }
    await c.query(
      `INSERT INTO ticket_transfers (ticket_id, from_user_id, to_user_id, to_email, old_serial, new_serial, to_guest, age_confirmed_min, allow_guest, to_email_norm) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [t.id, req.user.userId, gost ? null : p.id, prejemnikEmail, t.serial, u.rows[0].serial, gost, potrditevStarosti, dovoliGosta, naslovKljuc(prejemnikEmail)]
    );
    await c.query("COMMIT");
    console.log(`Prenos vstopnice ${t.id}: uporabnik ${req.user.userId} -> ${gost ? "gost" : p.id} (dogodek ${t.event_id})`);
    // Posiljatelj nove kode ne dobi — vstopnica ni vec njegova (gost: zetona posiljatelj NIKOLI ne dobi; kuje se ob posiljanju maila).
    if (gost) posljiPrenosGostu(t.id);   // brez await: odgovor ne caka na Resend; napaka maila ne podre prenosa (pospravljalec ponovi)
    if (dovoliGosta) {
      // ENOTEN odgovor za racun in gosta (brez razkritja, ali ima naslov racun): novi odjemalci so vedno poslali allow_guest.
      return res.status(200).json({
        result: "ok", message: `Ticket sent to ${prejemnikEmail}.`,
        ticket: { id: u.rows[0].id, event_id: t.event_id, event_title: t.event_title, status: u.rows[0].status,
                  holder_username: null, holder_email: prejemnikEmail, transferred: true }
      });
    }
    // E-naslov prejemnika (I7, issue #140): samo ce ga je posiljatelj vpisal sam; pri prenosu po user_id (prijatelj iz seznama)
    // posiljatelj naslova ne pozna in ga ne sme izvedeti. Kljuc `holder_email` ostane (null), ker je odstranitev polja brisanje.
    const naslovZnan = !prejemnikId;
    return res.status(200).json({
      result: "ok", message: `Ticket sent to ${p.username || (naslovZnan ? p.email : "your friend")}.`,
      ticket: { id: u.rows[0].id, event_id: t.event_id, event_title: t.event_title, status: u.rows[0].status,
                holder_username: p.username, holder_email: naslovZnan ? p.email : null, transferred: true }
    });
  } catch (e) {
    await c.query("ROLLBACK").catch(() => {});
    if (napakaZasedenosti(e)) { console.error(e.message); return res.status(503).set("Retry-After", "5").send(NAKUP_ZASEDEN); }
    console.error(e); return res.status(500).send("Server error.");
  } finally { c.release(); }
});

// ---------------------------
// GUEST LISTA (migracija 035, 8. 10. 2026, invarianta I24)
// ---------------------------
// Martin: admin za EN dogodek da uporabniku (gostitelju) stevilo mest; gostitelj brez placila povabi toliko PRIJATELJEV (samo friendships, ne e-naslova).
// Gostitelj in vsak povabljenec imata SVOJO vstopnico (svoja koda QR). Model: posebno narocilo (orders.guest_list_id; total 0, status paid, brez Stripa)
// z vstopnicami: skener, scan-list in /me/tickets delujejo brez sprememb. Guest lista NI prodaja: ne v sold_count/kapaciteto (sprozilca preskocita),
// ne v tickets_sold, bruto in stevilo narocil (vsaka agregacija izloci o.guest_list_id IS NOT NULL), ne v GET /me/orders; vstopnice se ne prenasajo (409).
// Preklic liste / odstranitev prijatelja = vstopnica `void` (nikoli brisanje: sled ostane); uporabljena vstopnica se ne razveljavi (409 »Already checked in.«).
const GUEST_LISTA_SPOTS_NAJVEC = 20;
const GUEST_LISTA_OPOMBA_NAJVEC = 200;
// Meja vseh vrstic povabljencev na listi (tudi odstranjenih): vsako vabilo naredi vstopnico, odstranitev jo razveljavi, zato bi neskoncno dodajanje/odstranjevanje
// napihovalo tickets. 60 = trikrat najvec mest. Nad mejo 409 (admin lahko listo preklice in izda novo).
const GUEST_LISTA_VRSTIC_NAJVEC = okoljeCelo("GUEST_LISTA_VRSTIC_NAJVEC", 60, 1, 1000);
// Dogodek je »koncan«, ko mine end_at, sicer start_at + 8 h (kot pri /me/plans). Lista ostane vidna gostitelju se 12 h po koncu.
const GUEST_LISTA_KONEC = `COALESCE(e.end_at, e.start_at + INTERVAL '8 hours')`;
// Neprebrano vabilo na guest listo (migracija 036): moje vabilo, ki ni odstranjeno, lista ni preklicana, vstopnica ni void, dogodek se ni koncal.
// Skupno stevcu v GET /me in seznamu GET /me/guest-list-invites/received ($1 = id uporabnika), da se ne razideta.
const GUEST_LISTA_NEPREBRANA_IZ = `FROM guest_list_members m
       JOIN guest_lists gl ON gl.id = m.guest_list_id
       JOIN tickets t ON t.id = m.ticket_id
       JOIN events e ON e.id = t.event_id`;
const GUEST_LISTA_NEPREBRANA_KJE = `WHERE m.user_id = $1 AND m.seen_at IS NULL AND m.removed_at IS NULL
        AND gl.revoked_at IS NULL AND gl.host_user_id IS NOT NULL AND t.status <> 'void'   -- brez gostitelja (ON DELETE SET NULL) vrstice ni mogoce prikazati: tudi ne steti
        AND ${GUEST_LISTA_KONEC} > NOW()`;

// Oblika liste (isto za uporabnika in admina; admin dobi se gostitelja, created_at, revoked_at). `kje`: SQL pogoj nad alias-i gl (guest_lists),
// e (events), cl (clubs). db: pool ali odjemalec, ki ga klicatelj ze drzi (branje po COMMIT-u gre prek njega, ne prek poola; glej nakup).
async function guestListeOdgovor(db, kje, params, admin = false) {
  const r = await db.query(
    `SELECT gl.id, gl.spots, gl.note, gl.created_at, gl.revoked_at, gl.host_user_id,
            e.id AS event_id, e.title AS event_title, e.start_at, e.end_at, e.poster_url, e.club_id, cl.name AS club_name, e.min_age, e.status AS event_status,
            (e.status = 'published' AND ${GUEST_LISTA_KONEC} > NOW()) AS dogodek_odprt,
            hu.username AS host_username, hu.email AS host_email,
            (SELECT MIN(t.id) FROM tickets t JOIN orders o ON o.id = t.order_id WHERE o.guest_list_id = gl.id) AS my_ticket_id
       FROM guest_lists gl JOIN events e ON e.id = gl.event_id JOIN clubs cl ON cl.id = e.club_id
       LEFT JOIN users hu ON hu.id = gl.host_user_id
      WHERE ${kje}
      ORDER BY e.start_at ASC, (gl.revoked_at IS NOT NULL), gl.id ASC LIMIT 200`, params);
  if (!r.rows.length) return [];
  const m = await db.query(
    `SELECT m.guest_list_id, u.id AS user_id, u.username, u.avatar_url, t.status
       FROM guest_list_members m JOIN users u ON u.id = m.user_id JOIN tickets t ON t.id = m.ticket_id
      WHERE m.guest_list_id = ANY($1::bigint[]) AND m.removed_at IS NULL ORDER BY m.id`, [r.rows.map(x => x.id)]);
  const povabljeni = new Map();
  for (const x of m.rows) (povabljeni.get(x.guest_list_id) || povabljeni.set(x.guest_list_id, []).get(x.guest_list_id))
    .push({ user_id: x.user_id, username: x.username, avatar_url: x.avatar_url || null, status: x.status });
  return r.rows.map(x => {
    const invited = povabljeni.get(x.id) || [];
    const o = {
      id: x.id,
      event: { id: x.event_id, title: x.event_title, start_at: x.start_at, end_at: x.end_at, poster_url: x.poster_url, club_id: x.club_id,
               club_name: x.club_name, min_age: x.min_age, status: x.event_status },
      spots: x.spots,
      remaining: Math.max(0, x.spots - invited.length),
      can_invite: !x.revoked_at && x.dogodek_odprt,
      my_ticket_id: x.my_ticket_id,
      note: x.note,
      invited,
    };
    if (admin) {
      o.host = { user_id: x.host_user_id, username: x.host_username || null, email: x.host_email || null };
      o.created_at = x.created_at;
      o.revoked_at = x.revoked_at;
    }
    return o;
  });
}

// Preklic liste (admin; izbris racuna gostitelja): neuporabljene vstopnice -> void, njihovi povabljenci odstranjeni. Uporabljene ostanejo (vstop je ze bil).
// Klicatelj drzi zaklep vrstice liste (FOR UPDATE) v svoji transakciji.
async function guestListaPreklici(c, listId) {
  await c.query("UPDATE guest_lists SET revoked_at = COALESCE(revoked_at, NOW()) WHERE id = $1", [listId]);
  await c.query(`UPDATE tickets t SET status = 'void' FROM orders o WHERE o.guest_list_id = $1 AND t.order_id = o.id AND t.status = 'valid'`, [listId]);
  await c.query(
    `UPDATE guest_list_members m SET removed_at = NOW() FROM tickets t
      WHERE m.guest_list_id = $1 AND m.removed_at IS NULL AND t.id = m.ticket_id AND t.status = 'void'`, [listId]);
}

// Izbris racuna (DELETE /me): gostiteljeve liste se preklicejo, vstopnice povabljenca so void in mesto je prosto. Brez tega bi vstopnica z izbrisanim
// imetnikom (tickets.holder_user_id ON DELETE SET NULL) zdrsnila nazaj na kupca = gostitelja.
async function guestListaPocistiUporabnika(c, userId) {
  const l = await c.query("SELECT id FROM guest_lists WHERE host_user_id = $1 AND revoked_at IS NULL ORDER BY id FOR UPDATE", [userId]);
  for (const x of l.rows) await guestListaPreklici(c, x.id);
  await c.query(
    `UPDATE tickets t SET status = 'void' FROM guest_list_members m
      WHERE m.user_id = $1 AND m.removed_at IS NULL AND t.id = m.ticket_id AND t.status = 'valid'`, [userId]);
  await c.query("UPDATE guest_list_members SET removed_at = NOW() WHERE user_id = $1 AND removed_at IS NULL", [userId]);
}

// GET /me/guest-lists — liste, kjer sem GOSTITELJ: ne preklicane, dogodek se ni koncal pred vec kot 12 h; po zacetku dogodka narascajoce.
app.get("/me/guest-lists", requireAuth, async (req, res) => {
  try {
    const lists = await guestListeOdgovor(pool,
      `gl.host_user_id = $1 AND gl.revoked_at IS NULL AND ${GUEST_LISTA_KONEC} > NOW() - INTERVAL '12 hours'`, [req.user.userId]);
    return res.json({ guest_lists: lists });
  } catch (e) { return odgovoriNaNapako(res, e, "GET /me/guest-lists"); }
});

// GET /me/guest-list-invites/received — neprebrana obvestila "X te je dodal na svojo guest listo" (migracija 036, zvonec). Samo povabljenec iz zetona (I3);
// o gostitelju samo username/avatar_url (I11), nikoli e-naslov. Vstopnica sama je v GET /me/tickets (ticket_id). Izgine ob POST .../seen ali ko vabilo ni vec
// aktivno (odstranjen z liste, lista preklicana, vstopnica void, dogodek koncan: isti pogoji kot stevec pending_guest_list_invites v GET /me).
app.get("/me/guest-list-invites/received", requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT m.id, m.guest_list_id, m.ticket_id, m.created_at, hu.username AS host_username, hu.avatar_url AS host_avatar_url,
              e.id AS event_id, e.title AS event_title, e.start_at AS event_start_at, e.poster_url AS event_poster_url, cl.name AS club_name
       ${GUEST_LISTA_NEPREBRANA_IZ}
       JOIN clubs cl ON cl.id = e.club_id
       JOIN users hu ON hu.id = gl.host_user_id
       ${GUEST_LISTA_NEPREBRANA_KJE}
       ORDER BY m.created_at DESC, m.id DESC LIMIT 50`, [req.user.userId]
    );
    return res.json({ invites: r.rows.map(x => ({
      id: x.id, guest_list_id: x.guest_list_id, ticket_id: x.ticket_id,
      host_username: x.host_username, host_avatar_url: x.host_avatar_url || null,
      created_at: x.created_at,
      event: { id: x.event_id, title: x.event_title, start_at: x.event_start_at, poster_url: x.event_poster_url, club_name: x.club_name },
    })) });
  } catch (e) { return odgovoriNaNapako(res, e, "GET /me/guest-list-invites/received"); }
});

// POST /me/guest-list-invites/received/:id/seen — povabljenec je obvestilo videl (dotik v meniju). Idempotentno (seen_at se ne prepise).
// Tuje ali neobstojece vabilo: 404 (ne razkrivamo, da obstaja). Moje odstranjeno/preklicano vabilo je tudi 200 (dotik tik po odstranitvi ni napaka).
app.post("/me/guest-list-invites/received/:id/seen", requireAuth, async (req, res) => {
  const id = celoId(req.params.id);
  if (id === null) return res.status(400).send("Invalid id.");
  if (!Number.isSafeInteger(id)) return res.status(404).send("Not found.");   // vecji od BIGINT bi dal 22003 -> 500
  try {
    const r = await pool.query(
      `UPDATE guest_list_members SET seen_at = COALESCE(seen_at, NOW()) WHERE id = $1 AND user_id = $2 RETURNING id`,
      [id, req.user.userId]
    );
    if (r.rows.length === 0) return res.status(404).send("Not found.");
    return res.json({ ok: true });
  } catch (e) { return odgovoriNaNapako(res, e, "POST /me/guest-list-invites/received/:id/seen"); }
});

// POST /me/guest-lists/:id/invites — telo { user_ids: [..], age_confirmed? }. Vse ali nic (ena transakcija pod zaklepom vrstice liste).
// Starost (I8): ista pravila kot pri prenosu (znan datum rojstva pod mejo dogodka: 403 vedno; brez datuma: obvezen age_confirmed).
// Zloraba: omejevalnik 30/h/IP (vabilo + odstranitev) in meja vseh vrstic povabljencev na listi (GUEST_LISTA_VRSTIC_NAJVEC).
app.post("/me/guest-lists/:id/invites", requireAuth, omeji({ kljuc: "guest-lista", najvec: 30, oknoSekund: 3600, priNapaki: "lokalno" }), async (req, res) => {
  const id = celoId4(req.params.id);
  if (!id) return res.status(400).send("Invalid guest list id.");
  const b = req.body && typeof req.body === "object" && !Array.isArray(req.body) ? req.body : {};
  const ids = b.user_ids;
  if (!Array.isArray(ids) || ids.length < 1) return res.status(400).send("user_ids must be a non-empty array of user ids.");
  if (ids.length > GUEST_LISTA_SPOTS_NAJVEC) return res.status(400).send(`You can invite at most ${GUEST_LISTA_SPOTS_NAJVEC} people at once.`);
  if (!ids.every(v => Number.isInteger(v) && v > 0 && v <= INT4_MAX)) return res.status(400).send("user_ids must be user ids (integers).");
  if (new Set(ids).size !== ids.length) return res.status(400).send("user_ids must not contain duplicates.");
  if (b.age_confirmed !== undefined && typeof b.age_confirmed !== "boolean") return res.status(400).send("age_confirmed must be true or false.");
  const starostPotrjena = b.age_confirmed === true;
  const userId = req.user.userId;

  const c = await pool.connect();
  try {
    await nakupZacni(c);   // lock_timeout/statement_timeout kot pri nakupu in prenosu
    // Zaklep vrstice liste: vabila, odstranitve, PATCH in preklic iste liste se vrstijo (mesta se ne morejo preseci).
    const lr = await c.query(
      `SELECT gl.id, gl.spots, gl.revoked_at, e.id AS event_id, e.min_age, e.status AS event_status, ${GUEST_LISTA_KONEC} AS konec, o.id AS order_id
         FROM guest_lists gl JOIN events e ON e.id = gl.event_id JOIN orders o ON o.guest_list_id = gl.id
        WHERE gl.id = $1 AND gl.host_user_id = $2 FOR UPDATE OF gl`, [id, userId]);
    if (!lr.rows.length) { await c.query("ROLLBACK"); return res.status(404).send("Guest list not found."); }
    const l = lr.rows[0];
    if (l.revoked_at || l.event_status !== "published" || new Date(l.konec).getTime() <= Date.now()) {
      await c.query("ROLLBACK"); return res.status(409).send("This guest list is closed.");
    }
    // Samo prijatelji (gostitelj sam in neznani id-ji = ista 403: ne razkrivamo obstoja uporabnikov).
    const fr = await c.query(
      `SELECT u.id, u.username, starost(u.date_of_birth) AS leta FROM users u
        WHERE u.id = ANY($2::int[]) AND u.id <> $1::int
          AND EXISTS (SELECT 1 FROM friendships f WHERE f.user_a = LEAST(u.id, $1::int) AND f.user_b = GREATEST(u.id, $1::int))`, [userId, ids]);
    if (fr.rows.length !== ids.length) { await c.query("ROLLBACK"); return res.status(403).send("You can only invite friends."); }
    const poId = new Map(fr.rows.map(x => [x.id, x]));
    const clani = await c.query("SELECT user_id FROM guest_list_members WHERE guest_list_id = $1 AND removed_at IS NULL", [id]);
    const ze = new Set(clani.rows.map(x => x.user_id));
    for (const uid of ids) {
      if (ze.has(uid)) { await c.query("ROLLBACK"); return res.status(409).send(`${poId.get(uid).username} is already on your guest list.`); }
    }
    const prosta = l.spots - clani.rows.length;
    if (ids.length > prosta) { await c.query("ROLLBACK"); return res.status(409).send(`Only ${Math.max(0, prosta)} spots left.`); }
    const vseVrstice = (await c.query("SELECT COUNT(*)::int AS n FROM guest_list_members WHERE guest_list_id = $1", [id])).rows[0].n;
    if (vseVrstice + ids.length > GUEST_LISTA_VRSTIC_NAJVEC) {
      await c.query("ROLLBACK"); return res.status(409).send("This guest list has reached its limit of changes. Contact Outly.");
    }
    // Starost (I8): znan datum rojstva pod mejo je 403 VEDNO (potrditev ga ne prevlada); brez datuma rabi age_confirmed.
    const meja = Number(l.min_age) || 0;
    if (meja > 0) {
      const mladoletnik = ids.map(uid => poId.get(uid)).find(x => x.leta !== null && x.leta < meja);
      if (mladoletnik) { await c.query("ROLLBACK"); return res.status(403).send(`${mladoletnik.username} is under ${meja}.`); }
      if (!starostPotrjena && ids.some(uid => poId.get(uid).leta === null)) {
        await c.query("ROLLBACK");
        return res.status(400).json({ error: "age_confirmation_required", min_age: meja,
          message: `Confirm that everyone you are inviting is at least ${meja}.` });
      }
    }
    for (const uid of ids) {
      const t = await c.query("INSERT INTO tickets (order_id, event_id, holder_user_id) VALUES ($1, $2, $3) RETURNING id", [l.order_id, l.event_id, uid]);
      await c.query("INSERT INTO guest_list_members (guest_list_id, user_id, ticket_id) VALUES ($1, $2, $3)", [id, uid, t.rows[0].id]);
    }
    await c.query("COMMIT");
    console.log(`Guest lista ${id}: gostitelj ${userId} je povabil ${ids.length} (dogodek ${l.event_id})`);
    const [guest_list] = await guestListeOdgovor(c, "gl.id = $1", [id]);
    return res.status(201).json({ guest_list, added: ids });
  } catch (e) {
    await c.query("ROLLBACK").catch(() => {});
    if (napakaZasedenosti(e)) { console.error(e.message); return res.status(503).set("Retry-After", "5").send(NAKUP_ZASEDEN); }
    if (e && e.code === "23505") return res.status(409).send("Someone you selected is already on your guest list.");
    return odgovoriNaNapako(res, e, "POST /me/guest-lists/:id/invites");
  } finally { c.release(); }
});

// DELETE /me/guest-lists/:id/invites/:userId — odstrani povabljenca: njegova vstopnica -> void, mesto se sprosti. Uporabljena vstopnica: 409.
app.delete("/me/guest-lists/:id/invites/:userId", requireAuth, omeji({ kljuc: "guest-lista", najvec: 30, oknoSekund: 3600, priNapaki: "lokalno" }), async (req, res) => {
  const id = celoId4(req.params.id), uid = celoId4(req.params.userId);
  if (!id) return res.status(400).send("Invalid guest list id.");
  if (!uid) return res.status(400).send("Invalid user id.");
  const c = await pool.connect();
  try {
    await nakupZacni(c);
    const lr = await c.query("SELECT revoked_at FROM guest_lists WHERE id = $1 AND host_user_id = $2 FOR UPDATE", [id, req.user.userId]);
    if (!lr.rows.length) { await c.query("ROLLBACK"); return res.status(404).send("Guest list not found."); }
    if (lr.rows[0].revoked_at) { await c.query("ROLLBACK"); return res.status(409).send("This guest list is closed."); }
    const m = await c.query(
      `SELECT m.id, m.ticket_id FROM guest_list_members m WHERE m.guest_list_id = $1 AND m.user_id = $2 AND m.removed_at IS NULL`, [id, uid]);
    if (!m.rows.length) { await c.query("ROLLBACK"); return res.status(404).send("That person is not on your guest list."); }
    // Pogojni UPDATE kot pri skenu (I1): sken in odstranitev se ne moreta oba izvesti nad isto vstopnico.
    const v = await c.query("UPDATE tickets SET status = 'void' WHERE id = $1 AND status = 'valid' RETURNING id", [m.rows[0].ticket_id]);
    if (!v.rows.length) {
      const st = (await c.query("SELECT status FROM tickets WHERE id = $1", [m.rows[0].ticket_id])).rows[0];
      if (st && st.status === "used") { await c.query("ROLLBACK"); return res.status(409).send("Already checked in."); }
    }
    await c.query("UPDATE guest_list_members SET removed_at = NOW() WHERE id = $1", [m.rows[0].id]);
    await c.query("COMMIT");
    console.log(`Guest lista ${id}: gostitelj ${req.user.userId} je odstranil povabljenca ${uid}`);
    const [guest_list] = await guestListeOdgovor(c, "gl.id = $1", [id]);
    return res.status(200).json({ guest_list });
  } catch (e) {
    await c.query("ROLLBACK").catch(() => {});
    if (napakaZasedenosti(e)) { console.error(e.message); return res.status(503).set("Retry-After", "5").send(NAKUP_ZASEDEN); }
    return odgovoriNaNapako(res, e, "DELETE /me/guest-lists/:id/invites/:userId");
  } finally { c.release(); }
});

// --- admin: /admin/api/guest-lists (requireRole admin prek routerja `admin`) ---
function guestListaVhod(b, { zahtevajMesta }) {
  const o = {};
  if (b.spots !== undefined || zahtevajMesta) {
    if (!Number.isInteger(b.spots) || b.spots < 0 || b.spots > GUEST_LISTA_SPOTS_NAJVEC) return { napaka: `spots must be an integer between 0 and ${GUEST_LISTA_SPOTS_NAJVEC}.` };
    o.spots = b.spots;
  }
  if (b.note !== undefined && b.note !== null) {
    if (typeof b.note !== "string" || b.note.trim().length > GUEST_LISTA_OPOMBA_NAJVEC) return { napaka: `note must be text of at most ${GUEST_LISTA_OPOMBA_NAJVEC} characters.` };
    o.note = b.note.trim();
  }
  return o;
}

// GET /admin/api/guest-lists?event_id=N — liste dogodka; brez parametra liste prihodnjih in tekocih dogodkov (se ne koncani). Vkljucno s preklicanimi (revoked_at).
admin.get("/guest-lists", async (req, res) => {
  try {
    let kje = `${GUEST_LISTA_KONEC} > NOW()`, p = [];
    if (req.query.event_id !== undefined) {
      const eid = celoId4(req.query.event_id);
      if (!eid) return res.status(400).send("Invalid event_id.");
      kje = "gl.event_id = $1"; p = [eid];
    }
    return res.json({ guest_lists: await guestListeOdgovor(pool, kje, p, true) });
  } catch (e) { return odgovoriNaNapako(res, e, "GET /admin/api/guest-lists"); }
});

// POST /admin/api/guest-lists — { event_id, user_id, spots (0-20), note? (0-200) } -> 201. Samo za objavljen dogodek, ki se ni koncal.
// 409, ce ima uporabnik na dogodku ze AKTIVNO listo (delni unikaten indeks); preklicana ne ovira nove.
admin.post("/guest-lists", async (req, res) => {
  const b = req.body && typeof req.body === "object" && !Array.isArray(req.body) ? req.body : {};
  const eventId = typeof b.event_id === "number" ? celoId4(b.event_id) : null;
  const hostId = typeof b.user_id === "number" ? celoId4(b.user_id) : null;
  if (!eventId) return res.status(400).send("event_id must be an event id (integer).");
  if (!hostId) return res.status(400).send("user_id must be a user id (integer).");
  const v = guestListaVhod(b, { zahtevajMesta: true });
  if (v.napaka) return res.status(400).send(v.napaka);
  const c = await pool.connect();
  try {
    await nakupZacni(c);
    const er = await c.query(
      `SELECT e.id, e.club_id, e.currency, e.status, ${GUEST_LISTA_KONEC} AS konec FROM events e WHERE e.id = $1`, [eventId]);
    if (!er.rows.length) { await c.query("ROLLBACK"); return res.status(404).send("Event not found."); }
    const e = er.rows[0];
    if (e.status !== "published" || new Date(e.konec).getTime() <= Date.now()) {
      await c.query("ROLLBACK"); return res.status(409).send("Guest lists can only be created for a published event that has not ended.");
    }
    const ur = await c.query("SELECT id, email FROM users WHERE id = $1 AND role <> 'backup'", [hostId]);
    if (!ur.rows.length) { await c.query("ROLLBACK"); return res.status(404).send("User not found."); }
    const gl = await c.query(
      "INSERT INTO guest_lists (event_id, host_user_id, spots, note, created_by) VALUES ($1, $2, $3, $4, $5) RETURNING id",
      [eventId, hostId, v.spots, v.note || "", req.user.userId]);
    const listId = gl.rows[0].id;
    // Narocilo liste: brez denarja in Stripa (CHECK orders_guest_lista_chk), sprozilec rezerviraj_zalogo ga preskoci (ne steje v kapaciteto).
    const or = await c.query(
      `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, currency, application_fee_cents,
                           status, buyer_email, paid_at, guest_list_id)
       VALUES ($1, $2, $3, $4, 1, 0, 0, $5, 0, 'paid', $6, NOW(), $7) RETURNING id`,
      [javnaRef(), hostId, eventId, e.club_id, e.currency, ur.rows[0].email, listId]);
    // Gostiteljeva vstopnica: izrecen imetnik (ne »kupec«), da vstopnica izbrisanega povabljenca nikoli ne zdrsne nanj (glej /me/tickets).
    await c.query("INSERT INTO tickets (order_id, event_id, holder_user_id) VALUES ($1, $2, $3)", [or.rows[0].id, eventId, hostId]);
    await c.query("COMMIT");
    console.log(`Admin ${req.user.userId}: guest lista ${listId} (dogodek ${eventId}, uporabnik ${hostId}, mest ${v.spots})`);
    const [guest_list] = await guestListeOdgovor(c, "gl.id = $1", [listId], true);
    return res.status(201).json({ guest_list });
  } catch (err) {
    await c.query("ROLLBACK").catch(() => {});
    if (napakaZasedenosti(err)) { console.error(err.message); return res.status(503).set("Retry-After", "5").send(NAKUP_ZASEDEN); }
    if (err && err.code === "23505" && err.constraint === "guest_lists_aktivna_key") return res.status(409).send("This user already has an active guest list for this event.");
    return odgovoriNaNapako(res, err, "POST /admin/api/guest-lists");
  } finally { c.release(); }
});

// PATCH /admin/api/guest-lists/:id — { spots?, note? }. Mest ne moremo zmanjsati pod stevilo aktivnih povabljenih (409). Preklicane liste ni mogoce urejati (409).
admin.patch("/guest-lists/:id", async (req, res) => {
  const id = celoId4(req.params.id);
  if (!id) return res.status(400).send("Invalid guest list id.");
  const b = req.body && typeof req.body === "object" && !Array.isArray(req.body) ? req.body : {};
  const v = guestListaVhod(b, { zahtevajMesta: false });
  if (v.napaka) return res.status(400).send(v.napaka);
  if (v.spots === undefined && v.note === undefined) return res.status(400).send("Nothing to update.");
  const c = await pool.connect();
  try {
    await nakupZacni(c);
    const lr = await c.query("SELECT revoked_at FROM guest_lists WHERE id = $1 FOR UPDATE", [id]);
    if (!lr.rows.length) { await c.query("ROLLBACK"); return res.status(404).send("Guest list not found."); }
    if (lr.rows[0].revoked_at) { await c.query("ROLLBACK"); return res.status(409).send("This guest list is revoked."); }
    if (v.spots !== undefined) {
      const n = (await c.query("SELECT COUNT(*)::int AS n FROM guest_list_members WHERE guest_list_id = $1 AND removed_at IS NULL", [id])).rows[0].n;
      if (v.spots < n) { await c.query("ROLLBACK"); return res.status(409).send(`Spots can't be below the number of people already invited (${n}).`); }
    }
    await c.query("UPDATE guest_lists SET spots = COALESCE($2::smallint, spots), note = COALESCE($3::text, note) WHERE id = $1", [id, v.spots ?? null, v.note ?? null]);
    await c.query("COMMIT");
    console.log(`Admin ${req.user.userId}: guest lista ${id} spremenjena (${Object.keys(v).join(", ")})`);
    const [guest_list] = await guestListeOdgovor(c, "gl.id = $1", [id], true);
    return res.status(200).json({ guest_list });
  } catch (e) {
    await c.query("ROLLBACK").catch(() => {});
    if (napakaZasedenosti(e)) { console.error(e.message); return res.status(503).set("Retry-After", "5").send(NAKUP_ZASEDEN); }
    return odgovoriNaNapako(res, e, "PATCH /admin/api/guest-lists/:id");
  } finally { c.release(); }
});

// DELETE /admin/api/guest-lists/:id — preklic: neuporabljene vstopnice liste -> void (uporabljene ostanejo). Ponovni preklic je brez ucinka (200).
admin.delete("/guest-lists/:id", async (req, res) => {
  const id = celoId4(req.params.id);
  if (!id) return res.status(400).send("Invalid guest list id.");
  const c = await pool.connect();
  try {
    await nakupZacni(c);
    const lr = await c.query("SELECT id FROM guest_lists WHERE id = $1 FOR UPDATE", [id]);
    if (!lr.rows.length) { await c.query("ROLLBACK"); return res.status(404).send("Guest list not found."); }
    await guestListaPreklici(c, id);
    await c.query("COMMIT");
    console.log(`Admin ${req.user.userId}: guest lista ${id} preklicana`);
    const [guest_list] = await guestListeOdgovor(c, "gl.id = $1", [id], true);
    return res.status(200).json({ guest_list });
  } catch (e) {
    await c.query("ROLLBACK").catch(() => {});
    if (napakaZasedenosti(e)) { console.error(e.message); return res.status(503).set("Retry-After", "5").send(NAKUP_ZASEDEN); }
    return odgovoriNaNapako(res, e, "DELETE /admin/api/guest-lists/:id");
  } finally { c.release(); }
});

// POST /business/tickets/scan — skener na vratih. Telo: { qr } (ali { serial } za ročni vnos).
// Preveri podpis, lastništvo, stanje; vstopnico označi kot uporabljeno. Ponovni sken -> 409.
app.post("/business/tickets/scan", requireAuthSken, requireClubSken(), async (req, res) => {
  try {
    const b = req.body || {};
    let serial = null, ev = null;
    if (b.qr !== undefined) {
      const v = preveriQr(b.qr);
      if (!v || !v.t) return res.status(400).json({ result: "invalid", message: "QR code is not valid (bad signature)." });
      serial = String(v.t); ev = v.e;
    } else if (typeof b.serial === "string") {
      serial = b.serial.trim();
    } else return res.status(400).send("qr or serial is required.");
    if (!/^[0-9a-f-]{36}$/i.test(serial)) return res.status(400).json({ result: "invalid", message: "Ticket code is not valid." });

    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");

    const r = await skenPool.query(
      `SELECT ${STOLPCI_VSTOPNICE}, ${STOLPCI_VIP_VSTOPNICE}, e.club_id, e.title AS event_title, e.start_at, e.end_at, e.status AS event_status, o.status AS order_status, o.public_ref, o.buyer_email,
              ${STOLPCI_IMETNIKA}
       FROM tickets t JOIN events e ON e.id = t.event_id JOIN orders o ON o.id = t.order_id ${JOIN_IMETNIK} WHERE t.serial = $1`, [serial]
    );
    if (r.rows.length === 0) return res.status(404).json({ result: "unknown", message: "Ticket not found." });
    const t = r.rows[0];
    if (t.is_guest) delete t.buyer_email;   // gost brez racuna: vratar ne vidi e-naslova (migracija 033); na zaslonu je imetnik »Guest«
    // Guest lista (035, I24): vratar vidi uporabnisko ime imetnika in gostitelja (is_guest_list, guest_list_host_username), nikoli e-naslova
    // (buyer_email = gostitelj, holder_email = povabljeni prijatelj); skener pokaze »Guest list · @host«.
    if (t.is_guest_list) { delete t.buyer_email; delete t.holder_email; }
    // Vratar (zacasno osebje, I21) e-naslovov navadnih kupcev ne vidi nikjer: brisanje je tu, na vrstici `t`, PRED vsemi vejami odgovora
    // (ok, already_used, event_cancelled, status != valid ...), ker vse vracajo `ticket: t`. Nova veja z `ticket: t` je s tem pokrita sama.
    if (req.klub.role === "doorman") { delete t.buyer_email; delete t.holder_email; }
    if (t.club_id !== klub) return res.status(403).json({ result: "wrong_club", message: "This ticket is for another club's event." });
    if (ev !== undefined && ev !== null && Number(ev) !== t.event_id) return res.status(400).json({ result: "invalid", message: "QR code does not match the ticket." });
    // Odpovedan dogodek: narocila ostanejo placana (vracilo je rocno), vstopnice pa na vratih ne smejo vec veljati.
    if (t.event_status === "cancelled") return res.status(409).json({ result: "event_cancelled", message: "This event was cancelled.", ticket: t });
    if (!["paid", "partially_refunded"].includes(t.order_status)) return res.status(409).json({ result: "unpaid", message: "Order is not paid." });
    if (t.status === "used") return res.status(409).json({ result: "already_used", message: "Ticket was already scanned.", used_at: t.used_at, ticket: t });
    if (t.status !== "valid") return res.status(409).json({ result: t.status, message: `Ticket is ${t.status}.`, ticket: t });
    // Casovno okno (I25, Martin 8. 10. 2026): dogodek je aktiven od 12 h pred zacetkom do 6 h po koncu. Isto pravilo imata odjemalca;
    // streznik ga uveljavi tudi za starejse gradnje in kode brez `e`. Brez nove poizvedbe: start_at/end_at sta ze v vrstici.
    if (!jeVOknuSkena(t.start_at, t.end_at, Date.now())) return res.status(409).json({ result: "not_today", message: "This ticket is not for today's event.", ticket: t });

    // Pogoj serial=$4: če je bila vstopnica med branjem zgoraj in tem UPDATE-om
    // prenesena prijatelju (prenos ji da NOV serial), stara koda ne sme več
    // veljati — sicer bi pošiljatelj vstopil s staro kodo, prejemnik pa bi
    // dobil že porabljeno vstopnico (ugotovljeno s testom sočasnosti).
    const u = await skenPool.query(
      `UPDATE tickets SET status='used', used_at=NOW(), used_by_user_id=$2, scan_device=$3
       WHERE id=$1 AND status='valid' AND serial=$4 RETURNING id, serial, status, used_at`,
      [t.id, req.user.userId, String(req.headers["user-agent"] || "").slice(0, 100), serial]
    );
    if (u.rows.length === 0) {
      const z = await skenPool.query(`SELECT status, serial FROM tickets WHERE id=$1`, [t.id]);
      const s = z.rows[0];
      if (s && s.serial !== serial) return res.status(409).json({ result: "transferred", message: "This ticket was passed on to someone else. Ask them to show their new code." });
      return res.status(409).json({ result: "already_used", message: "Ticket was already scanned." });
    }
    return res.status(200).json({ result: "ok", message: "Welcome in.", ticket: { ...t, ...u.rows[0] } });
  } catch (e) { return odgovoriNaNapako(res, e, "POST /business/tickets/scan"); }
});

// ---------------------------
// SKEN BREZ POVEZAVE (issue #86, 1. 10. 2026)
// ---------------------------
// Skener na vratih ne sme pasti nikoli. Zato telefon vstopnice preveri SAM: (1) podpis kode v2 z javnim ključem
// (GET /business/scan-key), (2) seznam vstopnic dogodka, ki ga prenese vnaprej (GET /business/events/:id/scan-list),
// (3) skene, opravljene brez povezave, pošlje naknadno (POST /business/tickets/scan-batch, idempotentno).
// Strežnik ostane razsodnik: dvojni sken iste vstopnice z dveh telefonov da NA STREŽNIKU samo en "ok" (invarianta I14).

// GET /business/scan-key — javni ključ za preverjanje kod v2 (vse vloge v klubu, tudi vratar).
app.get("/business/scan-key", requireAuthSken, requireClubSken(), (req, res) => {
  const k = qrKljuci();
  return res.json({
    alg: "Ed25519", kid: k.kid, public_key: k.javniSurov.toString("base64url"),
    qr_format: `${QR_V2_PREDPONA}.<base64url(JSON)>.<base64url(signature)>; signed message = "${QR_V2_PREDPONA}.<base64url(JSON)>" (UTF-8)`,
  });
});

// GET /business/events/:id/scan-list — VSE vstopnice dogodka za preverjanje brez povezave. Koda vstopnice (podpis v2) je veljavna
// za vsako naročilo, zato mora biti na seznamu tudi vstopnica vrnjenega/preklicanega/neplačanega naročila: status "unpaid"
// (odjemalec ga obravnava kot rdeče); če je vstopnica sama refunded ali void, ostane ta status.
// Brez e-naslovov in drugih osebnih podatkov (samo uporabniško ime imetnika, ki ga skener pokaže pri sprejemu).
// `transferred_serials`: stari serial-i prenesenih vstopnic — koda s takim serialom NE velja več (I7).
// ETag: osveževanje vsakih nekaj minut pri 1000+ telefonih ne sme vsakič vleči celega seznama (If-None-Match -> 304).
app.get("/business/events/:id/scan-list", requireAuthSken, requireClubSken(), async (req, res) => {
  try {
    const id = celoId4(req.params.id);
    if (!id) return res.status(400).json({ error: "invalid_id", message: "Invalid event id." });
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).json({ error: "not_found", message: "Club not found." });
    const ev = await skenPool.query("SELECT id, club_id FROM events WHERE id = $1", [id]);
    if (ev.rows.length === 0 || Number(ev.rows[0].club_id) !== Number(klub)) {
      return res.status(404).json({ error: "not_found", message: "Event not found." });
    }
    const [vst, prenosi] = await Promise.all([
      skenPool.query(
        `SELECT t.serial,
                CASE WHEN o.status IN ('paid','partially_refunded') OR t.status IN ('refunded','void') THEN t.status ELSE 'unpaid' END AS status,
                t.used_at, (o.table_id IS NOT NULL) AS is_vip, o.table_label, o.package_name,
                COALESCE(hu.username, ${IME_GOSTA_IMETNIKA}) AS holder_username, ${GUEST_LISTA_POLJA}
         FROM tickets t JOIN orders o ON o.id = t.order_id ${JOIN_IMETNIK}
         WHERE t.event_id = $1
         ORDER BY t.id`, [id]),
      skenPool.query(
        `SELECT tt.old_serial FROM ticket_transfers tt JOIN tickets t ON t.id = tt.ticket_id
         WHERE t.event_id = $1 ORDER BY tt.id`, [id]),
    ]);
    const kid = qrKljuci().kid;
    const tickets = vst.rows.map(t => ({
      serial: t.serial, status: t.status, used_at: t.used_at, is_vip: t.is_vip, table_label: t.table_label || null,
      package_name: t.package_name || null, holder_username: t.holder_username || null,
      is_guest_list: t.is_guest_list, guest_list_host_username: t.guest_list_host_username || null,   // 035: skener pokaze »Guest list · @host«
    }));
    const transferred_serials = prenosi.rows.map(x => x.old_serial);
    const etag = 'W/"' + crypto.createHash("sha256").update(JSON.stringify([kid, tickets, transferred_serials])).digest("base64url").slice(0, 27) + '"';
    res.set("ETag", etag);
    res.set("Cache-Control", "private, no-cache");
    return res.json({ event_id: id, generated_at: new Date().toISOString(), kid, tickets, transferred_serials });
  } catch (e) { return odgovoriNaNapako(res, e, "GET /business/events/:id/scan-list"); }
});

// POST /business/tickets/scan-batch — skeni, opravljeni brez povezave. Telo: { scans: [{ client_scan_id, qr | serial, scanned_at, device_id }] }.
// Za vsak element ista pravila kot POST /business/tickets/scan; en element = en atomaren stavek (brez skupne transakcije),
// zato ena slaba koda ne podre paketa. Odgovor ima rezultat za VSAK element, v istem vrstnem redu.
// Idempotentnost brez migracije: v tickets.scan_device ostane zaznamek "batch|<device_id>|<client_scan_id>". Ista kombinacija
// na že uporabljeni vstopnici je ponovitev paketa (-> "ok" z izvirnim used_at); drug zaznamek je pravi dvojni sken (-> "already_used").
const SKEN_BATCH_NAJVEC = 500;
const SKEN_NAJZGODNEJE_MS = Date.UTC(2020, 0, 1);
const SKEN_REZERVA_PRED_ZACETKOM_MS = SKEN_OKNO_PRED_MS; // vrata se odprejo pred zacetkom dogodka (isto kot casovno okno skena, I25)
const SKEN_ID_VZOREC = /^[A-Za-z0-9._:-]{1,64}$/;
const SERIAL_VZOREC = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const jsonVelik = express.json({ limit: "1mb" });
app.post("/business/tickets/scan-batch", requireAuthSken, requireClubSken(), jsonVelik, async (req, res) => {
  try {
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).json({ error: "not_found", message: "Club not found." });
    const b = req.body || {};
    if (!Array.isArray(b.scans)) return res.status(400).json({ error: "invalid_scans", message: "scans must be an array." });
    if (b.scans.length > SKEN_BATCH_NAJVEC) {
      return res.status(400).json({ error: "too_many_scans", message: `At most ${SKEN_BATCH_NAJVEC} scans per request.` });
    }
    const n = b.scans.length;
    const rezultati = new Array(n);
    const dela = [];
    for (let i = 0; i < n; i++) {
      const cidZaNapako = b.scans[i] && typeof b.scans[i].client_scan_id === "string" ? b.scans[i].client_scan_id : null;
      try {
      const it = b.scans[i];
      const o = it && typeof it === "object" && !Array.isArray(it) ? it : {};
      const cid = typeof o.client_scan_id === "string" && SKEN_ID_VZOREC.test(o.client_scan_id) ? o.client_scan_id : null;
      const dev = typeof (o.device_id ?? b.device_id) === "string" && SKEN_ID_VZOREC.test(o.device_id ?? b.device_id) ? (o.device_id ?? b.device_id) : null;
      const neveljavno = () => { rezultati[i] = { client_scan_id: cid, serial: null, result: "invalid", used_at: null }; };
      if (!cid || !dev) { neveljavno(); continue; }
      let serial = null, evId = null;
      if (typeof o.qr === "string") {
        const v = preveriQr(o.qr);
        if (!v || !v.t) { neveljavno(); continue; }
        serial = String(v.t); evId = v.e;
      } else if (typeof o.serial === "string") serial = o.serial.trim();
      if (!serial || !SERIAL_VZOREC.test(serial)) { neveljavno(); continue; }
      serial = serial.toLowerCase();
      // scanned_at: samo razsoden razpon (Date.parse sprejme tudi leto 0000 ali +010000, PostgreSQL ne -> trajen "error"); sicer NOW().
      const ms = typeof o.scanned_at === "string" ? Date.parse(o.scanned_at) : NaN;
      const kdaj = Number.isFinite(ms) && ms >= SKEN_NAJZGODNEJE_MS && ms <= Date.now() + 24 * 3600 * 1000 ? new Date(ms).toISOString() : null;
      dela.push({ i, cid, serial, evId, kdaj, zaznamek: `batch|${dev}|${cid}` });
      } catch (e) {
        // Varovalo za posamezen element: napaka pri enem ne podre paketa.
        console.error("scan-batch priprava elementa:", e.message);
        rezultati[i] = { client_scan_id: cidZaNapako, serial: null, result: "invalid", used_at: null };
      }
    }

    // Vse vstopnice paketa naenkrat; za serial-e, ki jih ni, še zgodovina prenosov (stara koda -> "transferred").
    const serijski = [...new Set(dela.map(d => d.serial))];
    const vrstice = new Map();
    const prenesene = new Map();
    if (serijski.length) {
      const r = await skenPool.query(
        `SELECT t.id, t.serial, t.status, t.used_at, t.used_by_user_id, t.scan_device, t.event_id, t.created_at, e.club_id, e.start_at, e.end_at, e.status AS event_status, o.status AS order_status
         FROM tickets t JOIN events e ON e.id = t.event_id JOIN orders o ON o.id = t.order_id
         WHERE t.serial = ANY($1::uuid[])`, [serijski]);
      for (const t of r.rows) vrstice.set(t.serial, t);
      const neznani = serijski.filter(s => !vrstice.has(s));
      if (neznani.length) {
        const p = await skenPool.query(
          `SELECT tt.old_serial, e.club_id FROM ticket_transfers tt JOIN tickets t ON t.id = tt.ticket_id JOIN events e ON e.id = t.event_id
           WHERE tt.old_serial = ANY($1::uuid[])`, [neznani]);
        for (const x of p.rows) prenesene.set(x.old_serial, x.club_id);
      }
    }

    const iso = (d) => (d ? new Date(d).toISOString() : null);
    // Cas skena za presojo okna (I25): ura na telefonu (scanned_at), ker skeni brez povezave pridejo s zamudo (tudi ure po koncu okna);
    // enaka razumnost kot za used_at v UPDATE spodaj (ne v prihodnosti, ne pred nastankom vstopnice, ne prej kot 12 h pred zacetkom) -> sicer zdaj.
    const casSkena = (kdaj, t) => {
      const zdaj = Date.now();
      if (!kdaj) return zdaj;
      const k = Date.parse(kdaj);
      const najprej = Math.max(new Date(t.created_at).getTime(), new Date(t.start_at).getTime() - SKEN_REZERVA_PRED_ZACETKOM_MS);
      return Number.isFinite(k) && Number.isFinite(najprej) && k <= zdaj && k >= najprej ? k : zdaj;
    };
    // Ponovitev paketa = isti zaznamek (device_id + client_scan_id) IN isti uporabnik. Zaznamek izbere odjemalec, zato bi brez
    // preverjanja uporabnika drug clan ekipe z istim parom dobil napacen "ok". Odjemalec naj device_id in client_scan_id generira nakljucno (UUID).
    const jePonovitev = (v, d) => v.scan_device === d.zaznamek && v.used_by_user_id !== null && Number(v.used_by_user_id) === Number(req.user.userId);
    for (const d of dela) {
      let rez;
      try {
        const t = vrstice.get(d.serial);
        if (!t) {
          const k = prenesene.get(d.serial);
          rez = { result: k !== undefined && Number(k) === Number(klub) ? "transferred" : "unknown", used_at: null };
        } else if (Number(t.club_id) !== Number(klub)) rez = { result: "wrong_club", used_at: null };
        else if (d.evId !== undefined && d.evId !== null && Number(d.evId) !== Number(t.event_id)) rez = { result: "invalid", used_at: null };
        else if (t.event_status === "cancelled" && t.status !== "used") rez = { result: "event_cancelled", used_at: null };
        else if (!["paid", "partially_refunded"].includes(t.order_status)) rez = { result: "unpaid", used_at: null };
        else if (t.status === "used") rez = { result: jePonovitev(t, d) ? "ok" : "already_used", used_at: iso(t.used_at) };
        else if (t.status !== "valid") rez = { result: t.status, used_at: null };
        else if (!jeVOknuSkena(t.start_at, t.end_at, casSkena(d.kdaj, t))) rez = { result: "not_today", used_at: null };
        else {
          // used_at = ura na telefonu, če je razumna: ne v prihodnosti, ne pred nastankom vstopnice, ne prej kot 12 h pred začetkom dogodka.
          // Pogoj serial = $4 kot pri /scan: prenos med branjem in pisanjem da vstopnici nov serial, stara koda ne sme več veljati.
          const u = await skenPool.query(
            `UPDATE tickets SET status = 'used',
                    used_at = CASE WHEN $5::timestamptz IS NOT NULL AND $5::timestamptz <= NOW()
                                    AND $5::timestamptz >= GREATEST(created_at, $6::timestamptz)
                                   THEN $5::timestamptz ELSE NOW() END,
                    used_by_user_id = $2, scan_device = $3
             WHERE id = $1 AND status = 'valid' AND serial = $4::uuid RETURNING used_at`,
            [t.id, req.user.userId, d.zaznamek, d.serial, d.kdaj, new Date(new Date(t.start_at).getTime() - SKEN_REZERVA_PRED_ZACETKOM_MS).toISOString()]);
          if (u.rows.length) {
            t.status = "used"; t.scan_device = d.zaznamek; t.used_at = u.rows[0].used_at; t.used_by_user_id = req.user.userId;
            rez = { result: "ok", used_at: iso(t.used_at) };
          } else {
            // Med branjem in pisanjem je vstopnico nekdo spremenil: preberi dejansko stanje.
            const z = await skenPool.query("SELECT serial, status, used_at, used_by_user_id, scan_device FROM tickets WHERE id = $1", [t.id]);
            const s = z.rows[0];
            if (!s || s.serial !== d.serial) rez = { result: "transferred", used_at: null };
            else if (s.status === "used") {
              t.status = "used"; t.scan_device = s.scan_device; t.used_at = s.used_at; t.used_by_user_id = s.used_by_user_id;
              rez = { result: jePonovitev(s, d) ? "ok" : "already_used", used_at: iso(s.used_at) };
            } else rez = { result: s.status, used_at: null };
          }
        }
      } catch (e) {
        // Napaka pri enem elementu (npr. baza) ne podre paketa; odjemalec element obdrži v vrsti in ga poskusi znova.
        console.error("scan-batch element:", e.message);
        rez = { result: "error", used_at: null };
      }
      rezultati[d.i] = { client_scan_id: d.cid, serial: d.serial, ...rez };
    }
    const stevilo = (r) => rezultati.filter(x => x.result === r).length;
    console.log(`Sken-batch: klub ${klub}, uporabnik ${req.user.userId}: ${n} skenov, ok ${stevilo("ok")}, already_used ${stevilo("already_used")}, transferred ${stevilo("transferred")}, not_today ${stevilo("not_today")}, error ${stevilo("error")}`);
    return res.status(200).json({ results: rezultati });
  } catch (e) { return odgovoriNaNapako(res, e, "POST /business/tickets/scan-batch"); }
});

// ---------------------------
// VIP MIZE S TLORISOM (migracija 025, Martinovo narocilo 1. 10. 2026)
// ---------------------------
// Klub enkrat narise tloris (orientacijski elementi + mize) in vpise bottle pakete (PUT /business/vip,
// urejevalnik je samo v spletni aplikaciji); pri vsakem dogodku VIP vklopi in po zelji spremeni ceno
// mize ali jo izklopi (PUT /business/events/:id/vip). Kupec izbere prosto mizo in paket (vstet v ceno)
// in dobi toliko VIP vstopnic, kolikor oseb sprejme miza (POST /events/:id/tables/:tableId/orders).
//
// Koordinate: mreza celic width x height (8..40), os y navzdol; element/miza = levi zgornji kot x, y in
// velikost w, h (cela stevila, x + w <= width, y + h <= height). VIP vstopnice NE stejejo v capacity /
// sold_count; ista miza se na istem dogodku ne proda dvakrat (I13: unikaten delni indeks na orders).
const TLORIS_MIN = 8;
const TLORIS_MAX = 40;
const TLORIS_NAJVEC_ELEMENTOV = 80;
const TIPI_ELEMENTOV = ["bar", "stage", "dj", "dancefloor", "entrance", "wc", "label", "wall"];
const VIP_NAJVEC_MIZ = 60;
const VIP_NAJVEC_PAKETOV = 30;
const VIP_NAJVEC_CENA_MIZE_CENTOV = 10000000; // 100.000 EUR: strop proti tipkarskim napakam
// Naročila, ki mizo zasedajo (isti pogoj kot unikatni indeks orders_miza_dogodek_key).
const VIP_ZASEDENA_STANJA = `('pending','paid','partially_refunded')`;

// Besedilo iz vhoda: samo niz; tabulator in novi vrstici -> presledek, rob obrezan; ostali nadzorni znaki
// so napaka (NUL ne gre v TEXT in JSONB). Vrne obrezan niz ali null (neveljavno).
function vipBesedilo(v, najmanj, najvec) {
  if (v === undefined || v === null) v = "";
  if (typeof v !== "string") return null;
  // Osamljen surrogat (neveljaven UTF-16): jsonb ga zavrne in bi bil 500.
  if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(v)) return null;
  const t = v.replace(/[\t\r\n]+/g, " ").trim();
  if (/[\u0000-\u001f\u007f]/.test(t)) return null;
  if (t.length < najmanj || t.length > najvec) return null;
  return t;
}

// Besedilo rezervacije po telefonu (ime gosta, opomba): kot vipBesedilo, a (1) dolzina je v ZNAKIH (kodnih tockah, kot char_length v bazi),
// ne v enotah UTF-16, in (2) nevidni znaki ničelne širine (U+200B-U+200D, U+2060, U+FEFF) se odstranijo PRED obrezovanjem, da ime ne more
// biti »nevidno« (osebje kluba bi videlo prazno vrstico). Vrne obrezan niz ali null (neveljavno).
function rezervacijaBesedilo(v, najmanj, najvec) {
  if (v === undefined || v === null) v = "";
  if (typeof v !== "string") return null;
  if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(v)) return null;
  const t = v.replace(/[\u200B-\u200D\u2060\uFEFF]/g, "").replace(/[\t\r\n]+/g, " ").trim();
  if (/[\u0000-\u001f\u007f]/.test(t)) return null;
  const n = [...t].length;
  if (n < najmanj || n > najvec) return null;
  return t;
}

// Id iz poti ali telesa v nove VIP poti: pozitivno celo stevilo, ki gre v PostgreSQL INTEGER (sicer bi
// "out of range" bil 500). Vrne stevilo ali null.
const PG_INT_MAX = 2147483647;
function vipId(v) {
  const n = typeof v === "string" ? (/^\d+$/.test(v) ? Number(v) : NaN) : v;
  return Number.isInteger(n) && n >= 1 && n <= PG_INT_MAX ? n : null;
}

// Pravokotnik v mrezi tlorisa (element ali miza): cela stevila, znotraj meja. Vrne { napaka } ali {}.
function vipPravokotnik(o, plan, ime) {
  for (const k of ["x", "y", "w", "h"]) {
    if (!Number.isInteger(o[k])) return { napaka: `${ime}.${k} must be an integer.` };
  }
  if (o.x < 0 || o.y < 0) return { napaka: `${ime}: x and y must be 0 or more.` };
  if (o.w < 1 || o.h < 1) return { napaka: `${ime}: w and h must be 1 or more.` };
  if (o.x + o.w > plan.width || o.y + o.h > plan.height) {
    return { napaka: `${ime} is outside the plan (${plan.width} x ${plan.height} cells).` };
  }
  return {};
}

// Tloris: null ali { width, height, elements }. Vrne { plan } (ociscena kopija) ali { napaka }.
function preveriTloris(p) {
  if (p === null) return { plan: null };
  if (!p || typeof p !== "object" || Array.isArray(p)) return { napaka: "plan must be an object or null." };
  for (const k of ["width", "height"]) {
    if (!Number.isInteger(p[k]) || p[k] < TLORIS_MIN || p[k] > TLORIS_MAX) {
      return { napaka: `plan.${k} must be an integer between ${TLORIS_MIN} and ${TLORIS_MAX}.` };
    }
  }
  const el = p.elements === undefined ? [] : p.elements;
  if (!Array.isArray(el)) return { napaka: "plan.elements must be an array." };
  if (el.length > TLORIS_NAJVEC_ELEMENTOV) return { napaka: `plan.elements: at most ${TLORIS_NAJVEC_ELEMENTOV} elements.` };
  const plan = { width: p.width, height: p.height, elements: [] };
  for (let i = 0; i < el.length; i++) {
    const e = el[i];
    const ime = `plan.elements[${i}]`;
    if (!e || typeof e !== "object" || Array.isArray(e)) return { napaka: `${ime} must be an object.` };
    if (!TIPI_ELEMENTOV.includes(e.type)) return { napaka: `${ime}.type must be one of: ${TIPI_ELEMENTOV.join(", ")}.` };
    const r = vipPravokotnik(e, plan, ime);
    if (r.napaka) return r;
    const label = vipBesedilo(e.label, 0, 30);
    if (label === null) return { napaka: `${ime}.label must be text of at most 30 characters.` };
    plan.elements.push({ type: e.type, x: e.x, y: e.y, w: e.w, h: e.h, label });
  }
  return { plan };
}

// Mize kluba: seznam { id?, label, x, y, w, h, shape, seats, price_cents }. Vrne { mize } ali { napaka }.
function preveriMize(vhod, plan) {
  if (!Array.isArray(vhod)) return { napaka: "tables must be an array." };
  if (vhod.length > VIP_NAJVEC_MIZ) return { napaka: `tables: at most ${VIP_NAJVEC_MIZ} tables.` };
  if (vhod.length > 0 && !plan) return { napaka: "plan is required when there are tables." };
  const mize = [];
  const ids = new Set();
  const oznake = new Set();
  for (let i = 0; i < vhod.length; i++) {
    const t = vhod[i];
    const ime = `tables[${i}]`;
    if (!t || typeof t !== "object" || Array.isArray(t)) return { napaka: `${ime} must be an object.` };
    let id = null;
    if (t.id !== undefined && t.id !== null) {
      if (vipId(t.id) === null) return { napaka: `${ime}.id must be a positive integer.` };
      if (ids.has(t.id)) return { napaka: `${ime}.id ${t.id} appears twice.` };
      ids.add(t.id);
      id = t.id;
    }
    const label = vipBesedilo(t.label, 1, 20);
    if (label === null) return { napaka: `${ime}.label must be 1-20 characters.` };
    const kljuc = label.toLowerCase();
    if (oznake.has(kljuc)) return { napaka: `Table labels must be unique: "${label}" is used twice.` };
    oznake.add(kljuc);
    const r = vipPravokotnik(t, plan, ime);
    if (r.napaka) return r;
    const shape = t.shape === undefined ? "round" : t.shape;
    if (shape !== "round" && shape !== "rect") return { napaka: `${ime}.shape must be "round" or "rect".` };
    if (!Number.isInteger(t.seats) || t.seats < 1 || t.seats > 20) return { napaka: `${ime}.seats must be an integer between 1 and 20.` };
    if (!Number.isInteger(t.price_cents) || t.price_cents < 0 || t.price_cents > VIP_NAJVEC_CENA_MIZE_CENTOV) {
      return { napaka: `${ime}.price_cents must be an integer (cents) between 0 and ${VIP_NAJVEC_CENA_MIZE_CENTOV}.` };
    }
    mize.push({ id, label, x: t.x, y: t.y, w: t.w, h: t.h, shape, seats: t.seats, price_cents: t.price_cents });
  }
  return { mize };
}

// Bottle paketi: seznam { id?, name, description }. Vrstni red v seznamu je vrstni red prikaza.
function preveriPakete(vhod) {
  if (!Array.isArray(vhod)) return { napaka: "packages must be an array." };
  if (vhod.length > VIP_NAJVEC_PAKETOV) return { napaka: `packages: at most ${VIP_NAJVEC_PAKETOV} packages.` };
  const paketi = [];
  const ids = new Set();
  for (let i = 0; i < vhod.length; i++) {
    const p = vhod[i];
    const ime = `packages[${i}]`;
    if (!p || typeof p !== "object" || Array.isArray(p)) return { napaka: `${ime} must be an object.` };
    let id = null;
    if (p.id !== undefined && p.id !== null) {
      if (vipId(p.id) === null) return { napaka: `${ime}.id must be a positive integer.` };
      if (ids.has(p.id)) return { napaka: `${ime}.id ${p.id} appears twice.` };
      ids.add(p.id);
      id = p.id;
    }
    const name = vipBesedilo(p.name, 1, 60);
    if (name === null) return { napaka: `${ime}.name must be 1-60 characters.` };
    const description = vipBesedilo(p.description, 0, 200);
    if (description === null) return { napaka: `${ime}.description must be at most 200 characters.` };
    paketi.push({ id, name, description });
  }
  return { paketi };
}

// Tloris, mize in paketi kluba (aktivni; arhivirani so skriti). db = pool ali odjemalec iz transakcije.
async function vipKlubaOdgovor(db, klub) {
  const k = await db.query("SELECT floor_plan FROM clubs WHERE id = $1", [klub]);
  const m = await db.query(
    `SELECT id, label, x, y, w, h, shape, seats, price_cents
       FROM club_tables WHERE club_id = $1 AND archived_at IS NULL ORDER BY id`, [klub]);
  const p = await db.query(
    `SELECT id, name, description FROM bottle_packages
      WHERE club_id = $1 AND archived_at IS NULL ORDER BY sort, id`, [klub]);
  return { plan: (k.rows[0] && k.rows[0].floor_plan) || null, tables: m.rows, packages: p.rows };
}

// GET /business/vip — tloris, mize in paketi kluba (owner, manager).
app.get("/business/vip", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  try {
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");
    return res.json(await vipKlubaOdgovor(pool, klub));
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// PUT /business/vip — celoten nadomestek (owner, manager). Miza/paket z id = posodobi (mora biti
// aktiven in od tega kluba, sicer 400); brez id = nova; aktivna, ki je v seznamu ni = arhivirana
// (narocila nanju kazejo in hranijo posnetek imen). Vse v eni transakciji; klub je zaklenjen, da
// dva hkratna shranjevanja ne prepisujeta drug drugega.
app.put("/business/vip", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  const klub = await mojKlubId(req);
  if (!klub) return res.status(404).send("Club not found.");
  const b = req.body || {};
  if (b.plan === undefined) return res.status(400).send("plan is required (an object or null).");
  const tl = preveriTloris(b.plan);
  if (tl.napaka) return res.status(400).send(tl.napaka);
  const mz = preveriMize(b.tables, tl.plan);
  if (mz.napaka) return res.status(400).send(mz.napaka);
  const pk = preveriPakete(b.packages);
  if (pk.napaka) return res.status(400).send(pk.napaka);

  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    // NO KEY UPDATE (ne UPDATE): nakup mize med transakcijo bere klub prek tujega kljuca (KEY SHARE)
    // in bi se s polnim zaklepom zaciklal (mrtva zanka).
    await c.query("SELECT id FROM clubs WHERE id = $1 FOR NO KEY UPDATE", [klub]);

    // --- mize ---
    const obst = await c.query("SELECT id FROM club_tables WHERE club_id = $1 AND archived_at IS NULL", [klub]);
    const aktivne = new Set(obst.rows.map(r => r.id));
    for (const t of mz.mize) {
      if (t.id !== null && !aktivne.has(t.id)) { await c.query("ROLLBACK"); return res.status(400).send(`tables: id ${t.id} does not belong to this club.`); }
    }
    const ostanejo = mz.mize.filter(t => t.id !== null).map(t => t.id);
    const arhiv = [...aktivne].filter(id => !ostanejo.includes(id));
    if (arhiv.length) await c.query("UPDATE club_tables SET archived_at = NOW() WHERE club_id = $1 AND id = ANY($2::int[])", [klub, arhiv]);
    // Zacasne oznake: zamenjava oznak med dvema mizama (T1 <-> T2) bi sicer trcila ob unikatnem indeksu.
    if (ostanejo.length) await c.query("UPDATE club_tables SET label = '~' || id WHERE club_id = $1 AND id = ANY($2::int[])", [klub, ostanejo]);
    for (const t of mz.mize) {
      if (t.id !== null) {
        await c.query(
          `UPDATE club_tables SET label=$3, x=$4, y=$5, w=$6, h=$7, shape=$8, seats=$9, price_cents=$10
            WHERE id=$1 AND club_id=$2`,
          [t.id, klub, t.label, t.x, t.y, t.w, t.h, t.shape, t.seats, t.price_cents]);
      } else {
        await c.query(
          `INSERT INTO club_tables (club_id, label, x, y, w, h, shape, seats, price_cents)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
          [klub, t.label, t.x, t.y, t.w, t.h, t.shape, t.seats, t.price_cents]);
      }
    }

    // --- paketi ---
    const obstP = await c.query("SELECT id FROM bottle_packages WHERE club_id = $1 AND archived_at IS NULL", [klub]);
    const aktivniP = new Set(obstP.rows.map(r => r.id));
    for (const p of pk.paketi) {
      if (p.id !== null && !aktivniP.has(p.id)) { await c.query("ROLLBACK"); return res.status(400).send(`packages: id ${p.id} does not belong to this club.`); }
    }
    const ostanejoP = pk.paketi.filter(p => p.id !== null).map(p => p.id);
    const arhivP = [...aktivniP].filter(id => !ostanejoP.includes(id));
    if (arhivP.length) await c.query("UPDATE bottle_packages SET archived_at = NOW() WHERE club_id = $1 AND id = ANY($2::int[])", [klub, arhivP]);
    for (let i = 0; i < pk.paketi.length; i++) {
      const p = pk.paketi[i];
      if (p.id !== null) {
        await c.query("UPDATE bottle_packages SET name=$3, description=$4, sort=$5 WHERE id=$1 AND club_id=$2", [p.id, klub, p.name, p.description, i]);
      } else {
        await c.query("INSERT INTO bottle_packages (club_id, name, description, sort) VALUES ($1,$2,$3,$4)", [klub, p.name, p.description, i]);
      }
    }

    // --- tloris (JSONB prek JSON.stringify, null = brez tlorisa) ---
    await c.query("UPDATE clubs SET floor_plan = $2::jsonb WHERE id = $1", [klub, tl.plan === null ? null : JSON.stringify(tl.plan)]);
    await c.query("COMMIT");
    // Branje po COMMIT-u prek istega odjemalca c (glej opombo pri POST /events/:id/orders).
    return res.json(await vipKlubaOdgovor(c, klub));
  } catch (err) {
    await c.query("ROLLBACK").catch(() => {});
    if (err && err.code === "23505" && err.constraint === "club_tables_label_key") return res.status(400).send("Table labels must be unique.");
    console.error(err);
    return res.status(500).send("Server error.");
  } finally { c.release(); }
});

// Stanje VIP miz dogodka za klub: tloris, mize s ceno, izjemo in rezervacijo, paketi. db = pool ali odjemalec.
// Vrne null, ce dogodek ne obstaja ali ni od tega kluba.
async function vipDogodkaOdgovor(db, klub, eventId) {
  const e = await db.query("SELECT id, vip_enabled, currency FROM events WHERE id = $1 AND club_id = $2", [eventId, klub]);
  if (e.rows.length === 0) return null;
  const k = await db.query("SELECT floor_plan FROM clubs WHERE id = $1", [klub]);
  const m = await db.query(
    `SELECT ct.id, ct.label, ct.x, ct.y, ct.w, ct.h, ct.shape, ct.seats,
            COALESCE(et.price_cents, ct.price_cents) AS price_cents,
            ct.price_cents AS default_price_cents,
            COALESCE(et.disabled, FALSE) AS disabled, (ct.archived_at IS NOT NULL) AS archived,
            b.order_id, b.public_ref, b.buyer_username, b.package_name, b.package_description,
            b.guests, b.checked_in, b.created_at AS booked_at,
            h.guest_name AS hold_guest_name, h.note AS hold_note, h.created_at AS hold_created_at, (h.id IS NOT NULL) AS hold_je
       FROM club_tables ct
       LEFT JOIN event_tables et ON et.event_id = $1 AND et.table_id = ct.id
       LEFT JOIN table_holds h ON h.event_id = $1 AND h.table_id = ct.id
       LEFT JOIN LATERAL (
         SELECT o.id AS order_id, o.public_ref, u.username AS buyer_username, o.package_name, o.package_description,
                o.created_at,
                (SELECT COUNT(*)::int FROM tickets t WHERE t.order_id = o.id AND t.status IN ('valid','used')) AS guests,
                (SELECT COUNT(*)::int FROM tickets t WHERE t.order_id = o.id AND t.status = 'used') AS checked_in
           FROM orders o LEFT JOIN users u ON u.id = o.user_id
          WHERE o.event_id = $1 AND o.table_id = ct.id AND o.status IN ${VIP_ZASEDENA_STANJA}
          ORDER BY o.id LIMIT 1
       ) b ON TRUE
      WHERE ct.club_id = $2 AND (ct.archived_at IS NULL OR b.order_id IS NOT NULL OR h.id IS NOT NULL)
      ORDER BY ct.id`, [eventId, klub]);
  const p = await db.query(
    `SELECT id, name, description FROM bottle_packages
      WHERE club_id = $1 AND archived_at IS NULL ORDER BY sort, id`, [klub]);
  return {
    event_id: e.rows[0].id,
    enabled: e.rows[0].vip_enabled,
    currency: e.rows[0].currency,
    plan: (k.rows[0] && k.rows[0].floor_plan) || null,
    tables: m.rows.map(r => ({
      id: r.id, label: r.label, x: r.x, y: r.y, w: r.w, h: r.h, shape: r.shape, seats: r.seats,
      price_cents: r.price_cents, default_price_cents: r.default_price_cents, disabled: r.disabled, archived: r.archived,
      booking: r.order_id ? {
        order_id: r.order_id, public_ref: r.public_ref, buyer_username: r.buyer_username,
        package_name: r.package_name, package_description: r.package_description,
        guests: r.guests, checked_in: r.checked_in, created_at: r.booked_at,
      } : null,
      // Rezervacija po telefonu (032): klub je mizo sam oznacil kot zasedeno. Ime in opomba sta SAMO v poslovnem pogledu.
      hold: r.hold_je ? { guest_name: r.hold_guest_name, note: r.hold_note, created_at: r.hold_created_at } : null,
    })),
    packages: p.rows,
  };
}

// GET /business/events/:id/vip — VSE vloge v klubu (tudi vratar/bar mora videti rezervacije).
// Tuj ali neobstojec dogodek: 404 (ne razkrivamo obstoja).
app.get("/business/events/:id/vip", requireAuth, requireClub(), async (req, res) => {
  try {
    const id = vipId(req.params.id);
    if (!id) return res.status(400).send("Invalid event id.");
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");
    const o = await vipDogodkaOdgovor(pool, klub, id);
    if (!o) return res.status(404).send("Event not found.");
    return res.json(o);
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// PUT /business/events/:id/vip — vklop VIP miz na dogodku in izjeme po mizah (owner, manager).
// Telo: { enabled, tables?: [{ table_id, price_cents | null, disabled }] }. Navedene mize prepisejo
// izjeme (price_cents null = privzeta cena kluba); mize, ki jih ni na seznamu, ostanejo, kot so bile.
app.put("/business/events/:id/vip", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  const id = vipId(req.params.id);
  if (!id) return res.status(400).send("Invalid event id.");
  const klub = await mojKlubId(req);
  if (!klub) return res.status(404).send("Club not found.");
  const b = req.body || {};
  if (typeof b.enabled !== "boolean") return res.status(400).send("enabled must be true or false.");
  const izjeme = [];
  if (b.tables !== undefined) {
    if (!Array.isArray(b.tables)) return res.status(400).send("tables must be an array.");
    if (b.tables.length > VIP_NAJVEC_MIZ) return res.status(400).send(`tables: at most ${VIP_NAJVEC_MIZ} tables.`);
    const videne = new Set();
    for (let i = 0; i < b.tables.length; i++) {
      const t = b.tables[i];
      const ime = `tables[${i}]`;
      if (!t || typeof t !== "object" || Array.isArray(t)) return res.status(400).send(`${ime} must be an object.`);
      if (vipId(t.table_id) === null) return res.status(400).send(`${ime}.table_id must be a positive integer.`);
      if (videne.has(t.table_id)) return res.status(400).send(`${ime}.table_id ${t.table_id} appears twice.`);
      videne.add(t.table_id);
      const cena = t.price_cents === undefined ? null : t.price_cents;
      if (cena !== null && (!Number.isInteger(cena) || cena < 0 || cena > VIP_NAJVEC_CENA_MIZE_CENTOV)) {
        return res.status(400).send(`${ime}.price_cents must be null or an integer (cents) between 0 and ${VIP_NAJVEC_CENA_MIZE_CENTOV}.`);
      }
      const disabled = t.disabled === undefined ? false : t.disabled;
      if (typeof disabled !== "boolean") return res.status(400).send(`${ime}.disabled must be true or false.`);
      izjeme.push({ table_id: t.table_id, price_cents: cena, disabled });
    }
  }

  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    const er = await c.query("SELECT id FROM events WHERE id = $1 AND club_id = $2 FOR NO KEY UPDATE", [id, klub]);
    if (er.rows.length === 0) { await c.query("ROLLBACK"); return res.status(404).send("Event not found."); }
    if (izjeme.length) {
      // Mize TEGA kluba, tudi arhivirane: GET vrne arhivirano mizo z rezervacijo na dogodku, odjemalec pa
      // poslje nazaj vse mize iz GET. Arhivirana miza se tiho preskoci (izjema zanjo nima pomena); 400 samo za tuje/neobstojece.
      const v = await c.query(
        "SELECT id, archived_at IS NOT NULL AS arhivirana FROM club_tables WHERE club_id = $1 AND id = ANY($2::int[])",
        [klub, izjeme.map(t => t.table_id)]);
      const mize = new Map(v.rows.map(r => [r.id, r.arhivirana]));
      const slaba = izjeme.find(t => !mize.has(t.table_id));
      if (slaba) { await c.query("ROLLBACK"); return res.status(400).send(`tables: id ${slaba.table_id} does not belong to this club.`); }
      for (let i = izjeme.length - 1; i >= 0; i--) if (mize.get(izjeme[i].table_id)) izjeme.splice(i, 1);
    }
    await c.query("UPDATE events SET vip_enabled = $2 WHERE id = $1", [id, b.enabled]);
    for (const t of izjeme) {
      if (t.price_cents === null && !t.disabled) {
        await c.query("DELETE FROM event_tables WHERE event_id = $1 AND table_id = $2", [id, t.table_id]);
      } else {
        await c.query(
          `INSERT INTO event_tables (event_id, table_id, price_cents, disabled) VALUES ($1,$2,$3,$4)
           ON CONFLICT (event_id, table_id) DO UPDATE SET price_cents = EXCLUDED.price_cents, disabled = EXCLUDED.disabled`,
          [id, t.table_id, t.price_cents, t.disabled]);
      }
    }
    await c.query("COMMIT");
    return res.json(await vipDogodkaOdgovor(c, klub, id));
  } catch (err) {
    await c.query("ROLLBACK").catch(() => {});
    console.error(err);
    return res.status(500).send("Server error.");
  } finally { c.release(); }
});

// ---------------------------
// REZERVACIJA MIZE PO TELEFONU (migracija 032, Martin 4. 10. 2026)
// ---------------------------
// Gost pokliče klub in rezervira VIP mizo: klub jo na dogodku sam označi kot zasedeno (owner, manager), da je prek Outly
// nihče ne more kupiti. Plačilo gre mimo Outly, zato rezervacija NI naročilo (ne šteje v prodajo, nima vstopnic).
// Ime gosta in opomba sta SAMO v poslovnem pogledu (GET /business/events/:id/vip, vse vloge v klubu), nikoli javno ali kupcu.
//
// I13 (miza se ne proda dvakrat) čez dve tabeli: unikatnega indeksa čez orders in table_holds ni, zato oba zaklepata
// ISTO vrstico club_tables. Nakup (POST /events/:id/tables/:tableId/orders) drži FOR SHARE in nato bere table_holds;
// rezervacija vzame FOR NO KEY UPDATE (konflikt s FOR SHARE, ne pa z FOR KEY SHARE tujih ključev: urejanje cen po dogodku
// in nakupi drugih miz je ne čakajo) in nato bere orders. Vsak zaklep je pred branjem, branje je NOV stavek (READ COMMITTED
// vzame svež posnetek), zato ena od strani vedno vidi drugo: ali rezervacija počaka nakup in vidi njegovo naročilo,
// ali nakup počaka rezervacijo in vidi njeno vrstico. Obe čakata največ NAKUP_DB_TIMEOUT_MS (lock_timeout -> 503).
app.post("/business/events/:id/tables/:tableId/hold", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  const id = vipId(req.params.id);
  if (!id) return res.status(400).send("Invalid event id.");
  const mizaId = vipId(req.params.tableId);
  if (!mizaId) return res.status(400).send("Invalid table id.");
  const b = req.body && typeof req.body === "object" && !Array.isArray(req.body) ? req.body : {};
  const ime = rezervacijaBesedilo(b.guest_name, 1, 60);
  if (ime === null) return res.status(400).send("guest_name must be 1 to 60 characters.");
  const opomba = rezervacijaBesedilo(b.note, 0, 200);
  if (opomba === null) return res.status(400).send("note must be at most 200 characters.");
  const klub = await mojKlubId(req);
  if (!klub) return res.status(404).send("Club not found.");
  let c;
  try { c = await pool.connect(); } catch (err) { console.error(err); return res.status(503).set("Retry-After", "5").send(NAKUP_ZASEDEN); }
  try {
    await nakupZacni(c);
    const er = await c.query(`SELECT id, (${KONEC_DOGODKA} <= NOW()) AS koncan FROM events WHERE id = $1 AND club_id = $2`, [id, klub]);
    if (er.rows.length === 0) { await c.query("ROLLBACK"); return res.status(404).send("Event not found."); }
    // Koncan dogodek (isti izraz kot »ended« drugje): ime gosta se ne shrani brez smisla. Dogodek, ki tece, rezervacijo se sprejme.
    if (er.rows[0].koncan) { await c.query("ROLLBACK"); return res.status(409).send("This event has already ended."); }
    // Miza TEGA kluba, ne arhivirana. Rezervacija je dovoljena tudi, ce je miza na dogodku izklopljena ali VIP na dogodku ni vklopljen
    // (klub tloris uporablja tudi samo za telefonske rezervacije).
    const mr = await c.query(
      "SELECT id FROM club_tables WHERE id = $1 AND club_id = $2 AND archived_at IS NULL FOR NO KEY UPDATE", [mizaId, klub]);
    if (mr.rows.length === 0) { await c.query("ROLLBACK"); return res.status(404).send("Table not found."); }
    // Zaklep imamo: aktivna naročila (isti pogoj kot unikatni indeks orders_miza_dogodek_key) so zdaj dokončna.
    const nr = await c.query(
      `SELECT 1 FROM orders WHERE event_id = $1 AND table_id = $2 AND status IN ${VIP_ZASEDENA_STANJA} LIMIT 1`, [id, mizaId]);
    if (nr.rows.length > 0) { await c.query("ROLLBACK"); return res.status(409).send("This table is already booked."); }
    const ins = await c.query(
      `INSERT INTO table_holds (event_id, table_id, guest_name, note, created_by_user_id) VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (event_id, table_id) DO NOTHING RETURNING id`,
      [id, mizaId, ime, opomba === "" ? null : opomba, req.user.userId]);
    if (ins.rows.length === 0) { await c.query("ROLLBACK"); return res.status(409).send("This table is already booked."); }
    await c.query("COMMIT");
    console.log(`Rezervacija po telefonu: dogodek ${id}, miza ${mizaId}, uporabnik ${req.user.userId}`);   // brez imena gosta
    return res.status(201).json(await vipDogodkaOdgovor(c, klub, id));
  } catch (err) {
    await c.query("ROLLBACK").catch(() => {});
    if (err && err.code === "23505") return res.status(409).send("This table is already booked.");
    if (napakaZasedenosti(err)) { console.error(err.message); return res.status(503).set("Retry-After", "5").send(NAKUP_ZASEDEN); }
    console.error(err);
    return res.status(500).send("Server error.");
  } finally { c.release(); }
});

// DELETE /business/events/:id/tables/:tableId/hold — klub prekliče rezervacijo po telefonu (miza je spet na voljo za nakup).
// Zaklepa ne rabi: nakup, ki je rezervacijo še videl, je dobil 409; kdor jo ni, je mizo že kupil pred rezervacijo (ta bi bila 409).
app.delete("/business/events/:id/tables/:tableId/hold", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  try {
    const id = vipId(req.params.id);
    if (!id) return res.status(400).send("Invalid event id.");
    const mizaId = vipId(req.params.tableId);
    if (!mizaId) return res.status(400).send("Invalid table id.");
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");
    const r = await pool.query(
      `DELETE FROM table_holds h USING events e
        WHERE h.event_id = e.id AND e.id = $1 AND e.club_id = $2 AND h.table_id = $3 RETURNING h.id`, [id, klub, mizaId]);
    if (r.rows.length === 0) return res.status(404).send("Reservation not found.");
    razprodanoPozabi("m:" + id + ":" + mizaId);   // nakup, zavrnjen zaradi rezervacije, je mizo označil »zasedena« v pomnilniku
    return res.json(await vipDogodkaOdgovor(pool, klub, id));
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// Hramba osebnega podatka (DECISIONS 4. 10. 2026): gost ni uporabnik Outly, ime je prosto besedilo. Rezervacije dogodka, ki se je
// končal pred več kot 24 h (end_at, sicer start_at + 12 h), se brišejo. Interval REZERVACIJE_CISCENJE_MS (privzeto 1 h; 0 = izklop).
const REZERVACIJE_CISCENJE_MS = okoljeCelo("REZERVACIJE_CISCENJE_MS", 60 * 60 * 1000, 0, 24 * 60 * 60 * 1000);
let rezervacijeCiscenjeTece = false;
async function pocistiRezervacije() {
  if (rezervacijeCiscenjeTece) return;
  rezervacijeCiscenjeTece = true;
  try {
    const r = await pool.query(
      `DELETE FROM table_holds h USING events e
        WHERE e.id = h.event_id AND COALESCE(e.end_at, e.start_at + INTERVAL '12 hours') < NOW() - INTERVAL '24 hours'`);
    if (r.rowCount > 0) console.log(`[rezervacije] pospravljeno ${r.rowCount} starih rezervacij po telefonu`);
  } catch (e) {
    console.error("[rezervacije] pospravljanje ni uspelo:", e && e.message);
  } finally {
    rezervacijeCiscenjeTece = false;
  }
}
if (REZERVACIJE_CISCENJE_MS > 0) {
  // Prvi tek NE takoj po zagonu (glavni pool je takrat najbolj zaseden: prvi nakupi, health check, sken): vsaj 5 min + nakljucnih do 60 s
  // (pri kratkem intervalu za teste sorazmerno krajse). Pospravljanje ni nujno, zato ne tekmuje z nakupi ob zagonu.
  const pocistiVse = () => { pocistiRezervacije(); pocistiGostZetone(); };   // gostujoci zetoni (migracija 033): isti urnik
  setTimeout(() => {
    pocistiVse();
    setInterval(pocistiVse, REZERVACIJE_CISCENJE_MS).unref();
  }, Math.min(REZERVACIJE_CISCENJE_MS, 5 * 60 * 1000) + Math.round(Math.random() * Math.min(REZERVACIJE_CISCENJE_MS, 60 * 1000))).unref();
}

// GET /events/:id/vip — javno (zeton ni potreben): tloris, proste/prodane mize, paketi. O kupcu NIC.
// 404, ce dogodka ni, ni objavljen ali je klub skrit. Izklopljene in arhivirane mize niso na seznamu.
app.get("/events/:id/vip", async (req, res) => {
  try {
    const id = vipId(req.params.id);
    if (!id) return res.status(400).send("Invalid event id.");
    const er = await pool.query(
      `SELECT e.id, e.club_id, e.vip_enabled, e.currency, e.status, e.start_at, e.sales_open_at, e.sales_close_at, e.min_age
         FROM events e JOIN clubs c ON c.id = e.club_id
        WHERE e.id = $1 AND e.status = 'published' AND NOT c.hidden`, [id]);
    if (er.rows.length === 0) return res.status(404).send("Event not found.");
    const e = er.rows[0];
    let mize = [];
    if (e.vip_enabled) {
      const m = await pool.query(
        `SELECT t.id, t.label, t.x, t.y, t.w, t.h, t.shape, t.seats, t.price_cents, NOT t.zasedena AS available
           FROM (
             SELECT ct.id, ct.label, ct.x, ct.y, ct.w, ct.h, ct.shape, ct.seats,
                    COALESCE(et.price_cents, ct.price_cents) AS price_cents,
                    (ct.archived_at IS NOT NULL OR COALESCE(et.disabled, FALSE)) AS skrita,
                    (EXISTS (SELECT 1 FROM orders o WHERE o.event_id = $1 AND o.table_id = ct.id
                               AND o.status IN ${VIP_ZASEDENA_STANJA})
                     -- Rezervacija po telefonu (032): za kupca je miza zasedena; ime gosta ni v tem odgovoru.
                     OR EXISTS (SELECT 1 FROM table_holds h WHERE h.event_id = $1 AND h.table_id = ct.id)) AS zasedena
               FROM club_tables ct LEFT JOIN event_tables et ON et.event_id = $1 AND et.table_id = ct.id
              WHERE ct.club_id = $2
           ) t
          -- Izklopljena ali arhivirana miza je skrita, RAZEN ce je na tem dogodku ze prodana: kupci vidijo "Booked".
          WHERE NOT t.skrita OR t.zasedena
          ORDER BY t.id`, [id, e.club_id]);
      mize = m.rows;
    }
    const enabled = e.vip_enabled && mize.length > 0;
    let plan = null, paketi = [];
    if (enabled) {
      const k = await pool.query("SELECT floor_plan FROM clubs WHERE id = $1", [e.club_id]);
      plan = (k.rows[0] && k.rows[0].floor_plan) || null;
      const p = await pool.query(
        `SELECT id, name, description FROM bottle_packages
          WHERE club_id = $1 AND archived_at IS NULL ORDER BY sort, id`, [e.club_id]);
      paketi = p.rows;
    }
    return res.json({
      event_id: e.id,
      enabled,
      on_sale: napakaProdaje({ ...e, hidden: false }, { zahtevajCeno: false }) === null,
      currency: e.currency,
      plan,
      tables: enabled ? mize : [],
      packages: paketi,
      // Najmanjsa starost za mizo Z IZBRANIM PAKETOM (paket = pijaca, #102): najmanj 18, pri strozji meji dogodka ta.
      package_min_age: starostZaPaket(e.min_age, true),
    });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// POST /events/:id/tables/:tableId/orders — nakup VIP mize. Telo: { package_id } (obvezen, ce ima klub
// aktivne pakete; sicer izpusti ali null). Pravila nakupa (testni nacin, okno prodaje, starost) so ista
// kot pri vstopnicah (napakaProdaje, preveriStarostKupca). Narocilo: quantity 1, cena = cena mize,
// vstopnic = table_seats; ne steje v sold_count. Ista miza dvakrat: 409 (I13, unikaten indeks).
app.post("/events/:id/tables/:tableId/orders", requireAuth, idempotenca(vsebinaNakupaMize), zavrniRazprodanoMizo, omeji({ kljuc: "nakup", najvec: 20, oknoSekund: 3600, priNapaki: "lokalno" }), async (req, res) => {
  const id = vipId(req.params.id);
  if (!id) return res.status(400).send("Invalid event id.");
  const mizaId = vipId(req.params.tableId);
  if (!mizaId) return res.status(400).send("Invalid table id.");
  const b = req.body || {};
  let paketId = null;
  if (b.package_id !== undefined && b.package_id !== null) {
    paketId = vipId(b.package_id);
    if (paketId === null) return res.status(400).send("package_id must be a positive integer.");
  }
  // Neobvezna potrditev cene: odjemalec poslje ceno, ki jo je kupec videl; ce se je med tem spremenila, 409.
  let pricakovana = null;
  if (b.expected_price_cents !== undefined && b.expected_price_cents !== null) {
    if (!Number.isInteger(b.expected_price_cents) || b.expected_price_cents < 0) return res.status(400).send("expected_price_cents must be a non-negative integer (cents).");
    pricakovana = b.expected_price_cents;
  }
  if (!(await nakupDovoljenje(req, res))) return;
  let c;
  try { c = await pool.connect(); } catch (err) { nakupIzstopi(); console.error(err); return res.status(503).set("Retry-After", "5").send(NAKUP_ZASEDEN); }
  if (req.idem) req.idem.vTransakciji = true;   // zaprtje zveze od tu naprej kljuca ne sprosti (commit se zgodi brez odjemalca)
  const idemV = req.idemKljuc ? vsebinaNakupaMize(req) : null;
  try {
    await nakupZacni(c);
    if (idemV) {
      // Plast 3 (glej POST /events/:id/orders): ponovitev iste mize z istim kljucem NI »miza ze zasedena«.
      const obst = await idemZakleniInPoisci(c, req.user.userId, req.idemKljuc);
      if (obst) { await c.query("ROLLBACK"); return await idemOdgovori(res, c, obst, idemV); }
    }
    const er = await c.query(
      `SELECT e.id, e.club_id, e.title, e.status, e.start_at, e.min_age, e.currency, e.vip_enabled,
              e.sales_open_at, e.sales_close_at, e.vat_rate, c.hidden, c.stripe_account_id, c.stripe_charges_enabled, c.commission_bps
         FROM events e JOIN clubs c ON c.id = e.club_id WHERE e.id = $1`, [id]);
    if (er.rows.length === 0) { await c.query("ROLLBACK"); return res.status(404).send("Event not found."); }
    const e = er.rows[0];
    if (e.status !== "published" || e.hidden) { await c.query("ROLLBACK"); return res.status(409).send("Event is not on sale."); }
    if (!e.vip_enabled) { await c.query("ROLLBACK"); return res.status(404).send("Table not found."); }

    // Miza: aktivna, od kluba dogodka in na tem dogodku ne izklopljena. FOR SHARE: cena in stanje mize se
    // med nakupom ne smeta spremeniti (PUT /business/vip jo posodablja, ta zahteva izkljucni zaklep vrstice).
    const mr = await c.query(
      `SELECT ct.id, ct.label, ct.seats, COALESCE(et.price_cents, ct.price_cents) AS price_cents
         FROM club_tables ct LEFT JOIN event_tables et ON et.event_id = $1 AND et.table_id = ct.id
        WHERE ct.id = $2 AND ct.club_id = $3 AND ct.archived_at IS NULL AND NOT COALESCE(et.disabled, FALSE)
        FOR SHARE OF ct`, [e.id, mizaId, e.club_id]);
    if (mr.rows.length === 0) { await c.query("ROLLBACK"); return res.status(404).send("Table not found."); }
    const miza = mr.rows[0];

    // Rezervacija po telefonu (032, I13): vrstico mize zdaj drzimo (FOR SHARE), rezervacija pa jo zaklepa z FOR NO KEY UPDATE in
    // v istem zaklepu preveri narocila - ena od obeh vidi drugo. Branje je NOV stavek (READ COMMITTED: svez posnetek po zaklepu).
    const hr = await c.query("SELECT 1 FROM table_holds WHERE event_id = $1 AND table_id = $2", [e.id, miza.id]);
    if (hr.rows.length > 0) {
      await c.query("ROLLBACK");
      razprodanoOznaci("m:" + id + ":" + mizaId);
      return res.status(409).send("This table is already booked.");
    }

    const np = napakaProdaje(e, { zahtevajCeno: false });
    if (np) { await c.query("ROLLBACK"); return res.status(np[0]).send(np[1]); }
    if (pricakovana !== null && pricakovana !== miza.price_cents) { await c.query("ROLLBACK"); return res.status(409).send("The table price has changed."); }

    // Paket je obvezen, ce ima klub vsaj en aktiven paket; sicer se miza kupi brez njega.
    const pr = await c.query(
      "SELECT id, name, description FROM bottle_packages WHERE club_id = $1 AND archived_at IS NULL", [e.club_id]);
    let paket = null;
    if (paketId !== null) {
      paket = pr.rows.find(p => p.id === paketId) || null;
      if (!paket) { await c.query("ROLLBACK"); return res.status(400).send("This package does not belong to this club."); }
    } else if (pr.rows.length > 0) {
      await c.query("ROLLBACK"); return res.status(400).send("Choose a bottle package.");
    }

    // Starost (I8): ista preverba kot pri vstopnicah; miza s paketom pijace zahteva najmanj 18 let (#102).
    const potrebnaStarost = starostZaPaket(e.min_age, paket !== null);
    const starost = await preveriStarostKupca(c, req.user.userId, potrebnaStarost,
      potrebnaStarost > e.min_age ? "a table with a bottle package" : undefined);
    if (starost.napaka) { await c.query("ROLLBACK"); return res.status(starost.napaka[0]).send(starost.napaka[1]); }

    const nacin = placilaStripe.nacinPlacila(e);
    if (nacin === "nastavitve") { await c.query("ROLLBACK"); return res.status(503).send("Payments are not available yet."); }
    if (nacin === "klub") { await c.query("ROLLBACK"); return res.status(409).send("This club does not accept online payments yet."); }
    const test = nacin === "test";
    if (!test) {
      const omejitev = await omejitevCakajocih(c, req.user.userId, e.id);
      if (omejitev) { await c.query("ROLLBACK"); return res.status(409).send(omejitev); }
    }

    const cena = miza.price_cents;
    const provizija = provizijaCentov(cena, e.commission_bps);
    const ref = javnaRef();
    const pi = test ? "test_" + crypto.randomUUID() : null;

    // Sprozilec orders_rezerviraj narocilo z mizo preskoci (ne steje v capacity). Zasedenost mize varuje
    // unikaten indeks orders_miza_dogodek_key (I13): ob hkratnem nakupu druga vstavitev pade z 23505.
    const or = await c.query(
      `INSERT INTO orders (public_ref, user_id, event_id, club_id, quantity, unit_price_cents, total_cents, currency,
                           application_fee_cents, vat_rate, status, stripe_payment_intent_id, buyer_email, paid_at,
                           table_id, table_label, table_seats, package_id, package_name, package_description, idempotency_key,
                           stripe_account_id)
       VALUES ($1,$2,$3,$4,1,$5,$5,$6,$7,$8,$18,$9,$10,CASE WHEN $18 = 'paid' THEN NOW() END,$11,$12,$13,$14,$15,$16,$17,$19) RETURNING id`,
      [ref, req.user.userId, e.id, e.club_id, cena, e.currency, provizija, e.vat_rate, pi, starost.email,
       miza.id, miza.label, miza.seats, paket ? paket.id : null, paket ? paket.name : null, paket ? paket.description : null,
       req.idemKljuc || null, test ? "paid" : "pending", test ? null : e.stripe_account_id]
    );
    const oid = or.rows[0].id;
    if (test) await c.query(`INSERT INTO tickets (order_id, event_id) SELECT $1, $2 FROM generate_series(1, $3::int)`, [oid, e.id, miza.seats]);
    await c.query("COMMIT");

    if (!test && !(await nakupStripeSeja(res, c, { oid, opis: `${e.title} – VIP ${miza.label}${paket ? " + " + paket.name : ""}`,
      kolicina: 1, cenaEnoteCents: cena, racunKluba: e.stripe_account_id, email: starost.email, eventId: e.id, odjemalec: odjemalecNakupa(req) }))) return;

    // Branje po COMMIT-u prek odjemalca c, NE prek pool (glej opombo pri POST /events/:id/orders).
    const telo = await odgovorNarocila(c, oid);
    console.log(`Nakup mize (${nacin}): naročilo ${ref}, uporabnik ${req.user.userId}, dogodek ${e.id}, miza ${miza.id}, ${miza.seats} vstopnic, ${cena} c`);
    return res.status(201).json(telo);
  } catch (err) {
    await c.query("ROLLBACK").catch(() => {});
    // Kljuc ima prednost pred »miza ze zasedena«: ce je mizo zasedlo ravno narocilo s TEM kljucem, je to ponovitev (ne 409, ne oznaka razprodano).
    if (idemV && err && err.code === "23505" && (err.constraint === "orders_idempotency_key" || err.constraint === "orders_miza_dogodek_key")
        && await idemPoKonfliktu(req, res, c, idemV)) return;
    if (err && err.code === "23505" && err.constraint === "orders_miza_dogodek_key") {
      razprodanoOznaci("m:" + id + ":" + mizaId);
      return res.status(409).send("This table is already booked.");
    }
    if (napakaZasedenosti(err)) { console.error(err.message); return res.status(503).set("Retry-After", "5").send(NAKUP_ZASEDEN); }
    console.error(err);
    return res.status(500).send("Server error.");
  } finally { try { c.release(); } finally { if (req.idem) req.idem.sprosti(); nakupIzstopi(); } }
});

// ---------------------------
// EKIPA KLUBA (migracija 009)
// ---------------------------
// Lastnik vabi managerje in vratarje; manager sme vabiti in odstranjevati
// samo vratarje. Od migracije 013 je dodajanje VABILO: uporabnik ga sprejme ali
// zavrne v aplikaciji (My clubs -> zvonec), član nastane ob sprejemu. Povabljeni
// mora že imeti Outly račun (po e-naslovu). Sodelavec je lahko v največ eni
// ekipi in lastnik kluba ne more biti hkrati član druge.
const VLOGE_EKIPE = ["manager", "doorman"];

async function seznamEkipe(clubId) {
  const r = await pool.query(
    `SELECT * FROM (
       SELECT u.id AS user_id, u.username, u.email, u.avatar_url, 'owner' AS role, c.created_at, NULL::int AS invited_by_user_id
         FROM clubs c JOIN users u ON u.id = c.owner_user_id WHERE c.id = $1
       UNION ALL
       SELECT u.id, u.username, u.email, u.avatar_url, m.role, m.created_at, m.invited_by_user_id
         FROM club_members m JOIN users u ON u.id = m.user_id WHERE m.club_id = $1
     ) e ORDER BY CASE role WHEN 'owner' THEN 0 WHEN 'manager' THEN 1 ELSE 2 END, created_at`,
    [clubId]
  );
  return r.rows;
}

// Mail sodelavcu ob VABILU (migracija 013): vabilo sprejme ali zavrne v aplikaciji
// (Profile -> My clubs -> zvonec). Prej je bil dodan neposredno.
async function posljiVabiloEkipi(toEmail, clubName, role) {
  if (!resend) return;
  const from = process.env.EMAIL_FROM || "onboarding@resend.dev";
  const appName = process.env.APP_NAME || "Outly";
  const vloga = role === "manager" ? "manager" : "door staff";
  try {
    const r = await resend.emails.send({
      from, to: toEmail,
      subject: `${clubName} invited you to their team on ${appName}`,
      html: `
    <div style="font-family: Arial, sans-serif; line-height:1.5">
      <h2>${appName} – Club team</h2>
      <p><b>${clubName}</b> has invited you to work with them as <b>${vloga}</b>.</p>
      <p>Open the ${appName} app, go to <b>Profile → My clubs</b> and tap the bell to accept or reject the invitation.</p>
      <p>If you don't know this club, simply reject the invitation or ignore this email.</p>
    </div>`,
    });
    if (r && r.error) console.error("Resend napaka (vabilo):", JSON.stringify(r.error));
  } catch (e) { console.error("Resend napaka (vabilo):", e); }
}

// Čakajoča vabila kluba (za GET /business/team).
async function seznamVabilKluba(clubId) {
  const r = await pool.query(
    `SELECT i.id, i.user_id, u.username, u.email, u.avatar_url, i.role, i.created_at, i.invited_by_user_id
       FROM club_invites i JOIN users u ON u.id = i.user_id
      WHERE i.club_id = $1 AND i.status = 'pending'
      ORDER BY i.created_at`,
    [clubId]
  );
  return r.rows;
}

async function odgovorEkipe(req, klub) {
  return { my_role: req.klub.role, members: await seznamEkipe(klub), invites: await seznamVabilKluba(klub) };
}

// GET /business/team — lastnik + člani + čakajoča vabila. Vratar ekipe ne vidi.
app.get("/business/team", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  try {
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");
    return res.json(await odgovorEkipe(req, klub));
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// POST /business/team — telo: { email, role }. Od migracije 013 ustvari VABILO
// (status pending); član nastane šele, ko uporabnik vabilo sprejme
// (POST /me/invites/:id/accept). Vrne posodobljen seznam (members + invites).
app.post("/business/team", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  try {
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");
    const b = req.body || {};
    const email = typeof b.email === "string" ? b.email.trim().toLowerCase() : "";
    const role = typeof b.role === "string" ? b.role.trim().toLowerCase() : "";
    if (!email || !email.includes("@")) return res.status(400).send("Valid email is required.");
    if (!VLOGE_EKIPE.includes(role)) return res.status(400).send("role must be manager or doorman.");
    if (req.klub.role === "manager" && role !== "doorman") {
      return res.status(403).send("Only the club owner can invite managers.");
    }

    const u = await pool.query("SELECT id, username, email FROM users WHERE LOWER(email)=$1", [email]);
    if (u.rows.length === 0) {
      return res.status(404).json({ error: "no_account", message: "No Outly account with this email. Ask them to sign up first." });
    }
    const clan = u.rows[0];
    if (Number(clan.id) === Number(req.user.userId)) return res.status(400).send("You are already in this team.");

    const jeLastnik = await pool.query("SELECT id FROM clubs WHERE owner_user_id=$1 LIMIT 1", [clan.id]);
    if (jeLastnik.rows.length) {
      const svoj = Number(jeLastnik.rows[0].id) === Number(klub);
      return res.status(409).json({ error: "is_owner", message: svoj ? "This user owns the club." : "This user already owns another club." });
    }
    // Od 018: clanstvo v drugem klubu ne moti — samo ce je ze v TEJ ekipi.
    const ze = await pool.query("SELECT role FROM club_members WHERE user_id=$1 AND club_id=$2", [clan.id, klub]);
    if (ze.rows.length) {
      return res.status(409).json({ error: "already_member", message: `Already in the team as ${ze.rows[0].role}.` });
    }
    const caka = await pool.query("SELECT id FROM club_invites WHERE club_id=$1 AND user_id=$2 AND status='pending'", [klub, clan.id]);
    if (caka.rows.length) {
      return res.status(409).json({ error: "already_invited", message: "This user already has a pending invitation from your club." });
    }

    await pool.query(
      "INSERT INTO club_invites (club_id, user_id, role, invited_by_user_id) VALUES ($1,$2,$3,$4)",
      [klub, clan.id, role, req.user.userId]
    );
    const ime = await pool.query("SELECT name FROM clubs WHERE id=$1", [klub]);
    posljiVabiloEkipi(clan.email, ime.rows[0] ? ime.rows[0].name : "A club", role); // brez await: mail ne sme zadrževati odgovora
    return res.status(201).json(await odgovorEkipe(req, klub));
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// DELETE /business/team/invites/:id — prekliče čakajoče vabilo. Manager sme samo vratarje.
// (Definirano PRED /business/team/:userId; poti se ne prekrivata, ker ima ta dodaten del.)
app.delete("/business/team/invites/:id", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  try {
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");
    const id = celoId(req.params.id);
    if (!id) return res.status(400).send("Invalid invite id.");
    const i = await pool.query("SELECT role FROM club_invites WHERE id=$1 AND club_id=$2 AND status='pending'", [id, klub]);
    if (i.rows.length === 0) return res.status(404).send("Invitation not found.");
    if (req.klub.role === "manager" && i.rows[0].role !== "doorman") {
      return res.status(403).send("Only the club owner can cancel manager invitations.");
    }
    await pool.query("UPDATE club_invites SET status='cancelled', responded_at=NOW() WHERE id=$1", [id]);
    return res.json(await odgovorEkipe(req, klub));
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// ---------------------------
// MOJA VABILA (uporabnik; migracija 013)
// ---------------------------
async function mojaVabila(userId) {
  const r = await pool.query(
    `SELECT i.id, i.club_id, c.name AS club_name, c.logo_url AS club_logo_url, c.city AS club_city,
            i.role, i.created_at, u.username AS invited_by_username
       FROM club_invites i
       JOIN clubs c ON c.id = i.club_id
       LEFT JOIN users u ON u.id = i.invited_by_user_id
      WHERE i.user_id = $1 AND i.status = 'pending'
      ORDER BY i.created_at DESC`,
    [userId]
  );
  return r.rows;
}

// GET /me/invites -> { invites: [...] } (samo čakajoča).
app.get("/me/invites", requireAuth, async (req, res) => {
  try {
    return res.json({ invites: await mojaVabila(req.user.userId) });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// POST /me/invites/:id/accept -> { club: {id, name, logo_url}, role, invites: [...] }.
// V eni transakciji: vabilo mora biti čakajoče in moje; uporabnik ne sme biti
// lastnik kluba ali že član (največ ena ekipa); ostala čakajoča vabila -> declined.
app.post("/me/invites/:id/accept", requireAuth, async (req, res) => {
  const id = celoId(req.params.id);
  if (!id) return res.status(400).send("Invalid invite id.");
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const i = await client.query(
      "SELECT i.id, i.club_id, i.role, i.invited_by_user_id, c.name, c.logo_url FROM club_invites i JOIN clubs c ON c.id=i.club_id WHERE i.id=$1 AND i.user_id=$2 AND i.status='pending' FOR UPDATE OF i",
      [id, req.user.userId]
    );
    if (i.rows.length === 0) { await client.query("ROLLBACK"); return res.status(404).send("Invitation not found or no longer pending."); }
    const v = i.rows[0];
    const lastnik = await client.query("SELECT id FROM clubs WHERE owner_user_id=$1 LIMIT 1", [req.user.userId]);
    if (lastnik.rows.length) { await client.query("ROLLBACK"); return res.status(409).json({ error: "is_owner", message: "You own a club and can't join another team." }); }
    // Od 018: sme biti v vec ekipah; blokira samo clanstvo v TEM klubu. Vabila drugih klubov ostanejo cakajoca.
    const clan = await client.query("SELECT club_id FROM club_members WHERE user_id=$1 AND club_id=$2", [req.user.userId, v.club_id]);
    if (clan.rows.length) { await client.query("ROLLBACK"); return res.status(409).json({ error: "already_member", message: "You are already in this club's team." }); }

    await client.query(
      "INSERT INTO club_members (club_id, user_id, role, invited_by_user_id) VALUES ($1,$2,$3,$4)",
      [v.club_id, req.user.userId, v.role, v.invited_by_user_id]
    );
    await client.query("UPDATE club_invites SET status='accepted', responded_at=NOW() WHERE id=$1", [id]);
    await client.query("COMMIT");
    return res.json({ club: { id: v.club_id, name: v.name, logo_url: v.logo_url }, role: v.role, invites: [] });
  } catch (e) {
    try { await client.query("ROLLBACK"); } catch (_) {}
    console.error(e); return res.status(500).send("Server error.");
  } finally { client.release(); }
});

// POST /me/invites/:id/decline -> { invites: [...] }.
app.post("/me/invites/:id/decline", requireAuth, async (req, res) => {
  try {
    const id = celoId(req.params.id);
    if (!id) return res.status(400).send("Invalid invite id.");
    const r = await pool.query(
      "UPDATE club_invites SET status='declined', responded_at=NOW() WHERE id=$1 AND user_id=$2 AND status='pending' RETURNING id",
      [id, req.user.userId]
    );
    if (r.rows.length === 0) return res.status(404).send("Invitation not found or no longer pending.");
    return res.json({ invites: await mojaVabila(req.user.userId) });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// ---------------------------
// PRIJATELJI (migracija 016)
// ---------------------------
// "My friends" v profilu, prošnje v obvestilih, "Your friends' plans" na domačem
// zaslonu, prenos vstopnice prijatelju z izbiro iz seznama. Prijateljstvo je
// simetrično in shranjeno enkrat (user_a < user_b). O tujem uporabniku se
// razkrije SAMO id, username in avatar_url — nikoli e-naslov, telefon, rojstvo.
const POLJA_PRIJATELJA = "u.id, u.username, u.avatar_url";

async function staPrijatelja(a, b) {
  const r = await pool.query(
    "SELECT 1 FROM friendships WHERE user_a = LEAST($1::int,$2::int) AND user_b = GREATEST($1::int,$2::int)", [a, b]
  );
  return r.rows.length > 0;
}

async function mojiPrijatelji(userId) {
  const r = await pool.query(
    `SELECT ${POLJA_PRIJATELJA}, f.created_at AS since
       FROM friendships f
       JOIN users u ON u.id = CASE WHEN f.user_a = $1 THEN f.user_b ELSE f.user_a END
      WHERE f.user_a = $1 OR f.user_b = $1
      ORDER BY LOWER(u.username)`, [userId]
  );
  return r.rows;
}

async function mojeProsnje(userId) {
  const r = await pool.query(
    `SELECT r.id, r.from_user_id, r.to_user_id, r.created_at,
            u.id AS other_id, u.username AS other_username, u.avatar_url AS other_avatar_url
       FROM friend_requests r
       JOIN users u ON u.id = CASE WHEN r.from_user_id = $1 THEN r.to_user_id ELSE r.from_user_id END
      WHERE (r.from_user_id = $1 OR r.to_user_id = $1) AND r.status = 'pending'
      ORDER BY r.created_at DESC`, [userId]
  );
  const oblikuj = (x) => ({ id: x.id, created_at: x.created_at, user: { id: x.other_id, username: x.other_username, avatar_url: x.other_avatar_url } });
  return {
    incoming: r.rows.filter(x => Number(x.to_user_id) === Number(userId)).map(oblikuj),
    outgoing: r.rows.filter(x => Number(x.from_user_id) === Number(userId)).map(oblikuj),
  };
}

// GET /users/search?q=ime — iskanje po uporabniškem imenu (predpona), samo prijavljeni,
// največ 10 zadetkov, brez sebe, samo potrjeni računi. Vrne id, username, avatar_url in
// relation: 'none' | 'friends' | 'request_sent' | 'request_received'. Omejeno, da se
// imenik ne da izluščiti z avtomatskim iskanjem.
app.get("/users/search", requireAuth, omeji({ kljuc: "iskanje", najvec: 120, oknoSekund: 3600, priNapaki: "odpri" }), async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();
    if (q.length < 2 || q.length > 20 || !/^[a-zA-Z0-9_]+$/.test(q)) return res.status(400).send("q must be 2-20 characters: letters, numbers, underscore.");
    // '_' je v LIKE nadomestni znak -> ubežimo ga, da "an_" ne najde "ana".
    const vzorec = q.replace(/_/g, "\\_");
    const r = await pool.query(
      `SELECT ${POLJA_PRIJATELJA},
              EXISTS (SELECT 1 FROM friendships f WHERE f.user_a = LEAST(u.id,$2::int) AND f.user_b = GREATEST(u.id,$2::int)) AS is_friend,
              (SELECT CASE WHEN r.from_user_id = $2 THEN 'request_sent' ELSE 'request_received' END
                 FROM friend_requests r
                WHERE r.status = 'pending'
                  AND LEAST(r.from_user_id, r.to_user_id) = LEAST(u.id,$2::int)
                  AND GREATEST(r.from_user_id, r.to_user_id) = GREATEST(u.id,$2::int)
                LIMIT 1) AS req_relation
         FROM users u
        WHERE u.username ILIKE $1 || '%' ESCAPE '\\' AND u.id <> $2 AND u.email_verified AND u.role <> 'backup'
        ORDER BY (LOWER(u.username) = LOWER($1)) DESC, LOWER(u.username)
        LIMIT 10`,
      [vzorec, req.user.userId]
    );
    return res.json({ users: r.rows.map(x => ({
      id: x.id, username: x.username, avatar_url: x.avatar_url,
      relation: x.is_friend ? "friends" : (x.req_relation || "none"),
    })) });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// GET /me/friends -> { friends: [...], requests_in: [...], requests_out: [...] }
app.get("/me/friends", requireAuth, async (req, res) => {
  try {
    const p = await mojeProsnje(req.user.userId);
    return res.json({ friends: await mojiPrijatelji(req.user.userId), requests_in: p.incoming, requests_out: p.outgoing });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// GET /me/friends/plans -> { events: [ {dogodek..., club_name, club_logo_url, friends: [...], interested: [...], my_plan} ] }
// Prihajajoči objavljeni dogodki, na katere ima vsaj en prijatelj VELJAVNO vstopnico (polje
// "friends", nespremenjeno = "going") ALI zanimanje (novo polje "interested", migracija 020) —
// samo prijatelji, ki imajo vklopljeno share_plans_with_friends (zasebnost, invarianta I11).
// Prijatelj z vstopnico IN zanimanjem je samo v "friends" (going), ne v obeh.
app.get("/me/friends/plans", requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      `WITH pr AS (
         SELECT CASE WHEN user_a = $1 THEN user_b ELSE user_a END AS id FROM friendships WHERE user_a = $1 OR user_b = $1
       ), gredo AS (
         -- Kdo od prijateljev drži veljavno vstopnico za kateri dogodek (imetnik = prejemnik prenosa, sicer kupec, 008).
         SELECT t.event_id, ${IMETNIK} AS uid
           FROM tickets t JOIN orders o ON o.id = t.order_id
          WHERE t.status = 'valid' AND o.status IN ('paid','partially_refunded')
            AND ${IMETNIK} IN (SELECT id FROM pr)
          GROUP BY 1, 2
       ), po_dogodku AS (
         SELECT g.event_id,
                jsonb_agg(jsonb_build_object('id', u.id, 'username', u.username, 'avatar_url', u.avatar_url) ORDER BY LOWER(u.username)) AS friends
           FROM gredo g JOIN users u ON u.id = g.uid
          WHERE u.share_plans_with_friends
          GROUP BY g.event_id
       ), zanimajo AS (
         -- Zanimanje (event_interest, 020) prijateljev, ki za ta dogodek NIMAJO ze vstopnice.
         SELECT ei.event_id, ei.user_id AS uid
           FROM event_interest ei
          WHERE ei.user_id IN (SELECT id FROM pr)
            AND NOT EXISTS (SELECT 1 FROM gredo g WHERE g.event_id = ei.event_id AND g.uid = ei.user_id)
       ), po_dogodku_zanimanje AS (
         SELECT z.event_id,
                jsonb_agg(jsonb_build_object('id', u.id, 'username', u.username, 'avatar_url', u.avatar_url) ORDER BY LOWER(u.username)) AS interested
           FROM zanimajo z JOIN users u ON u.id = z.uid
          WHERE u.share_plans_with_friends
          GROUP BY z.event_id
       ), dogodki AS (
         SELECT event_id FROM po_dogodku
         UNION
         SELECT event_id FROM po_dogodku_zanimanje
       )
       SELECT e.*, cl.name AS club_name, cl.logo_url AS club_logo_url,
              COALESCE(p.friends, '[]'::jsonb) AS friends,
              COALESCE(z.interested, '[]'::jsonb) AS interested,
              CASE
                WHEN EXISTS (SELECT 1 FROM tickets t JOIN orders o ON o.id = t.order_id
                              WHERE t.event_id = e.id AND t.status = 'valid' AND o.status IN ('paid','partially_refunded')
                                AND ${IMETNIK} = $1) THEN 'going'
                WHEN EXISTS (SELECT 1 FROM event_interest ei2 WHERE ei2.event_id = e.id AND ei2.user_id = $1) THEN 'interested'
                ELSE NULL
              END AS my_plan
         FROM dogodki d
         JOIN (SELECT ${STOLPCI_DOGODKA} FROM events) e ON e.id = d.event_id
         LEFT JOIN po_dogodku p ON p.event_id = e.id
         LEFT JOIN po_dogodku_zanimanje z ON z.event_id = e.id
         JOIN clubs cl ON cl.id = e.club_id
        WHERE COALESCE(e.end_at, e.start_at + INTERVAL '8 hours') > NOW()
          AND e.status = 'published' AND NOT cl.hidden
        ORDER BY e.start_at ASC
        LIMIT 50`,
      [req.user.userId]
    );
    return res.json({ events: r.rows });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// GET /me/plans -> { events: [ {dogodek..., club_name, club_logo_url, my_plan} ] }
// Moji lastni prihajajoci dogodki (going ali interested), za profil ("I'm in" + vstopnice).
app.get("/me/plans", requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      `WITH going AS (
         SELECT DISTINCT t.event_id
           FROM tickets t JOIN orders o ON o.id = t.order_id
          WHERE t.status = 'valid' AND o.status IN ('paid','partially_refunded') AND ${IMETNIK} = $1
       ), interested AS (
         SELECT event_id FROM event_interest WHERE user_id = $1
       ), moji AS (
         SELECT event_id FROM going
         UNION
         SELECT event_id FROM interested
       )
       SELECT e.*, cl.name AS club_name, cl.logo_url AS club_logo_url,
              CASE WHEN g.event_id IS NOT NULL THEN 'going' ELSE 'interested' END AS my_plan
         FROM moji m
         JOIN (SELECT ${STOLPCI_DOGODKA} FROM events) e ON e.id = m.event_id
         JOIN clubs cl ON cl.id = e.club_id
         LEFT JOIN going g ON g.event_id = e.id
        WHERE COALESCE(e.end_at, e.start_at + INTERVAL '8 hours') > NOW()
          AND e.status = 'published' AND NOT cl.hidden
        ORDER BY e.start_at ASC
        LIMIT 200`,
      [req.user.userId]
    );
    return res.json({ events: r.rows });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// POST /me/friends/requests — telo: { user_id } ali { username }.
// 201 { request } ko prošnja čaka; 200 { friend } če je nasprotna prošnja že čakala (takoj prijatelja).
// 409 already_friends | already_requested; 404 no_account; 400 self.
app.post("/me/friends/requests", requireAuth, omeji({ kljuc: "prijatelji", najvec: 30, oknoSekund: 3600 }), async (req, res) => {
  const b = req.body || {};
  let cilj = null;
  try {
    if (b.user_id !== undefined) {
      const id = celoId(b.user_id);
      if (!id) return res.status(400).send("Invalid user_id.");
      const r = await pool.query(`SELECT ${POLJA_PRIJATELJA}, u.email_verified, u.role FROM users u WHERE u.id = $1`, [id]);
      cilj = r.rows[0] || null;
    } else if (typeof b.username === "string") {
      const ime = b.username.trim();
      if (!/^[a-zA-Z0-9_]{3,20}$/.test(ime)) return res.status(400).send("Invalid username.");
      const r = await pool.query(`SELECT ${POLJA_PRIJATELJA}, u.email_verified, u.role FROM users u WHERE LOWER(u.username) = LOWER($1)`, [ime]);
      cilj = r.rows[0] || null;
    } else return res.status(400).send("user_id or username is required.");
    // Racun za kopije (vloga backup, #116) drugim ni viden: obnasa se kot neobstojec uporabnik (isti odgovor kot za neznano ime).
    if (!cilj || !cilj.email_verified || cilj.role === "backup") return res.status(404).json({ error: "no_account", message: "No Outly account with this username." });
    if (Number(cilj.id) === Number(req.user.userId)) return res.status(400).send("You can't add yourself.");
    if (await staPrijatelja(req.user.userId, cilj.id)) return res.status(409).json({ error: "already_friends", message: "You are already friends." });

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      // Nasprotna prošnja že čaka -> sprejmi jo (oba sta hotela isto).
      const obratna = await client.query(
        "SELECT id FROM friend_requests WHERE from_user_id = $1 AND to_user_id = $2 AND status = 'pending' FOR UPDATE", [cilj.id, req.user.userId]
      );
      if (obratna.rows.length) {
        await client.query("UPDATE friend_requests SET status='accepted', responded_at=NOW() WHERE id=$1", [obratna.rows[0].id]);
        await client.query(
          "INSERT INTO friendships (user_a, user_b) VALUES (LEAST($1::int,$2::int), GREATEST($1::int,$2::int)) ON CONFLICT DO NOTHING",
          [req.user.userId, cilj.id]
        );
        await client.query("COMMIT");
        return res.status(200).json({ friend: { id: cilj.id, username: cilj.username, avatar_url: cilj.avatar_url }, request: null });
      }
      const ins = await client.query(
        `INSERT INTO friend_requests (from_user_id, to_user_id) VALUES ($1, $2)
         ON CONFLICT DO NOTHING RETURNING id, created_at`, [req.user.userId, cilj.id]
      );
      await client.query("COMMIT");
      if (ins.rows.length === 0) return res.status(409).json({ error: "already_requested", message: "A request is already pending." });
      return res.status(201).json({ request: { id: ins.rows[0].id, created_at: ins.rows[0].created_at, user: { id: cilj.id, username: cilj.username, avatar_url: cilj.avatar_url } }, friend: null });
    } catch (e) {
      try { await client.query("ROLLBACK"); } catch (_) {}
      throw e;
    } finally { client.release(); }
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// POST /me/friends/requests/:id/accept -> { friend }. Samo naslovnik čakajoče prošnje.
app.post("/me/friends/requests/:id/accept", requireAuth, async (req, res) => {
  const id = celoId(req.params.id);
  if (!id) return res.status(400).send("Invalid request id.");
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const r = await client.query(
      `SELECT r.id, r.from_user_id, ${POLJA_PRIJATELJA} FROM friend_requests r JOIN users u ON u.id = r.from_user_id
        WHERE r.id = $1 AND r.to_user_id = $2 AND r.status = 'pending' FOR UPDATE OF r`, [id, req.user.userId]
    );
    if (r.rows.length === 0) { await client.query("ROLLBACK"); return res.status(404).send("Request not found or no longer pending."); }
    const p = r.rows[0];
    await client.query(
      "INSERT INTO friendships (user_a, user_b) VALUES (LEAST($1::int,$2::int), GREATEST($1::int,$2::int)) ON CONFLICT DO NOTHING",
      [req.user.userId, p.from_user_id]
    );
    await client.query("UPDATE friend_requests SET status='accepted', responded_at=NOW() WHERE id=$1", [id]);
    await client.query("COMMIT");
    return res.json({ friend: { id: p.id, username: p.username, avatar_url: p.avatar_url } });
  } catch (e) {
    try { await client.query("ROLLBACK"); } catch (_) {}
    console.error(e); return res.status(500).send("Server error.");
  } finally { client.release(); }
});

// POST /me/friends/requests/:id/decline -> { ok: true }. Samo naslovnik.
app.post("/me/friends/requests/:id/decline", requireAuth, async (req, res) => {
  try {
    const id = celoId(req.params.id);
    if (!id) return res.status(400).send("Invalid request id.");
    const r = await pool.query(
      "UPDATE friend_requests SET status='declined', responded_at=NOW() WHERE id=$1 AND to_user_id=$2 AND status='pending' RETURNING id", [id, req.user.userId]
    );
    if (r.rows.length === 0) return res.status(404).send("Request not found or no longer pending.");
    return res.json({ ok: true });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// DELETE /me/friends/requests/:id -> { ok: true }. Pošiljatelj prekliče svojo čakajočo prošnjo.
app.delete("/me/friends/requests/:id", requireAuth, async (req, res) => {
  try {
    const id = celoId(req.params.id);
    if (!id) return res.status(400).send("Invalid request id.");
    const r = await pool.query(
      "UPDATE friend_requests SET status='cancelled', responded_at=NOW() WHERE id=$1 AND from_user_id=$2 AND status='pending' RETURNING id", [id, req.user.userId]
    );
    if (r.rows.length === 0) return res.status(404).send("Request not found or no longer pending.");
    return res.json({ ok: true });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// DELETE /me/friends/:userId -> { ok: true }. Odstrani prijatelja (obojestransko, ker je ena vrstica).
app.delete("/me/friends/:userId", requireAuth, async (req, res) => {
  try {
    const uid = celoId(req.params.userId);
    if (!uid) return res.status(400).send("Invalid user id.");
    const r = await pool.query(
      "DELETE FROM friendships WHERE user_a = LEAST($1::int,$2::int) AND user_b = GREATEST($1::int,$2::int) RETURNING user_a", [req.user.userId, uid]
    );
    if (r.rows.length === 0) return res.status(404).send("Not friends.");
    return res.json({ ok: true });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// DELETE /business/team/me — član sam zapusti ekipo (tudi vratar).
app.delete("/business/team/me", requireAuth, async (req, res) => {
  try {
    // Od 018: z glavo X-Outly-Club (ali ?club_id=) zapusti samo ta klub; brez nje vsa clanstva (star odjemalec).
    const zeljeni = zeljeniKlub(req);
    const r = zeljeni
      ? await pool.query("DELETE FROM club_members WHERE user_id=$1 AND club_id=$2 RETURNING club_id", [req.user.userId, zeljeni])
      : await pool.query("DELETE FROM club_members WHERE user_id=$1 RETURNING club_id", [req.user.userId]);
    if (r.rows.length === 0) return res.status(404).send("You are not in a club team.");
    return res.status(204).send();
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// DELETE /business/team/:userId — odstrani člana. Manager sme samo vratarje.
app.delete("/business/team/:userId", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  try {
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");
    const uid = celoId(req.params.userId);
    if (!uid) return res.status(400).send("Invalid user id.");
    const m = await pool.query("SELECT role FROM club_members WHERE club_id=$1 AND user_id=$2", [klub, uid]);
    if (m.rows.length === 0) return res.status(404).send("Member not found.");
    if (req.klub.role === "manager" && m.rows[0].role !== "doorman" && Number(uid) !== Number(req.user.userId)) {
      return res.status(403).send("Only the club owner can remove managers.");
    }
    await pool.query("DELETE FROM club_members WHERE club_id=$1 AND user_id=$2", [klub, uid]);
    return res.json(await odgovorEkipe(req, klub));
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// ---------------------------
// "Check activity" na nadzorni plosci (migracija 021, Martin 25. 9. 2026)
// ---------------------------
// GET /business/activity — kliki na profil/dogodke (view_counts), sledilci, aktivnost ekipe
// (skeni po clanu). Samo lastnik/manager; vratar tuje stevilke skenov ne vidi (I5).
app.get("/business/activity", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  try {
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");
    const [klikiProfil, klikiDogodki, sledilci, ekipa] = await Promise.all([
      pool.query(
        `SELECT COALESCE(SUM(count),0)::int AS vsi,
                COALESCE(SUM(count) FILTER (WHERE day > CURRENT_DATE - INTERVAL '7 days'),0)::int AS n7d
         FROM view_counts WHERE club_id = $1 AND event_id IS NULL`, [klub]),
      pool.query(
        `SELECT COALESCE(SUM(count),0)::int AS vsi,
                COALESCE(SUM(count) FILTER (WHERE day > CURRENT_DATE - INTERVAL '7 days'),0)::int AS n7d
         FROM view_counts WHERE club_id = $1 AND event_id IS NOT NULL`, [klub]),
      pool.query(
        `SELECT COUNT(*)::int AS vsi,
                COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '7 days')::int AS n7d
         FROM club_follows WHERE club_id = $1`, [klub]),
      pool.query(
        `WITH ekipa AS (
           SELECT u.id AS user_id, u.username, u.avatar_url, 'owner' AS role
             FROM clubs c JOIN users u ON u.id = c.owner_user_id WHERE c.id = $1
           UNION ALL
           SELECT u.id, u.username, u.avatar_url, m.role
             FROM club_members m JOIN users u ON u.id = m.user_id WHERE m.club_id = $1
         )
         SELECT e.user_id AS id, e.username, e.avatar_url, e.role,
                COALESCE(s.scans, 0)::int AS scans,
                COALESCE(s.scans_7d, 0)::int AS scans_7d
           FROM ekipa e
           LEFT JOIN (
             SELECT t.used_by_user_id AS uid, COUNT(*)::int AS scans,
                    COUNT(*) FILTER (WHERE t.used_at > NOW() - INTERVAL '7 days')::int AS scans_7d
               FROM tickets t JOIN events ev ON ev.id = t.event_id
              WHERE ev.club_id = $1 AND t.status = 'used'
              GROUP BY t.used_by_user_id
           ) s ON s.uid = e.user_id
          ORDER BY scans DESC, e.username`, [klub]
      ),
    ]);
    return res.json({
      clicks_profile: klikiProfil.rows[0].vsi,
      clicks_profile_7d: klikiProfil.rows[0].n7d,
      clicks_events: klikiDogodki.rows[0].vsi,
      clicks_events_7d: klikiDogodki.rows[0].n7d,
      followers_count: sledilci.rows[0].vsi,
      followers_new_7d: sledilci.rows[0].n7d,
      staff: ekipa.rows,
    });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// GET /business/team/:userId/scans — po dogodkih, koliko je ta clan ekipe skeniral (samo
// dogodki z vsaj enim skenom). 404, ce oseba ni v ekipi tega kluba (ne razkrivamo obstoja).
app.get("/business/team/:userId/scans", requireAuth, requireClub("owner", "manager"), async (req, res) => {
  try {
    const klub = await mojKlubId(req);
    if (!klub) return res.status(404).send("Club not found.");
    const uid = celoId(req.params.userId);
    if (!uid) return res.status(400).send("Invalid user id.");
    const clan = await pool.query(
      `SELECT 1 FROM clubs WHERE id = $1 AND owner_user_id = $2
       UNION ALL
       SELECT 1 FROM club_members WHERE club_id = $1 AND user_id = $2`,
      [klub, uid]
    );
    if (clan.rows.length === 0) return res.status(404).send("Member not found.");
    const r = await pool.query(
      `SELECT e.id, e.title, e.start_at, e.poster_url, COUNT(*)::int AS scans
         FROM tickets t JOIN events e ON e.id = t.event_id
        WHERE e.club_id = $1 AND t.used_by_user_id = $2 AND t.status = 'used'
        GROUP BY e.id HAVING COUNT(*) > 0 ORDER BY e.start_at DESC`,
      [klub, uid]
    );
    return res.json({ events: r.rows });
  } catch (e) { console.error(e); return res.status(500).send("Server error."); }
});

// Obravnavalnik napak: MORA biti zadnji (za vsemi potmi). Napaka povezave -> 503 + Retry-After 5, ostalo 500 (issue #129, I10).
app.use(napakaRocnik);

const port = process.env.PORT || 3000;
// backlog 4096 (privzeto v Node 511): ob navalu (test_obremenitev 3b: 300 nakupov + 1000 bralcev + sken) je polna vrsta
// novih povezav jedro zavrglo 1100-1400 povezav na zagon; odjemalec (tudi vratarjev sken) jo je ponovil sele po ~1-3 s.
// Jedro omeji na net.core.somaxconn (4096 na sodobnem Linuxu, tudi GitHub Actions).
const streznik = app.listen({ port, backlog: 4096 }, () => console.log("Server running on port", port));
// Dnevnik povezav (#139): enkrat na DNEVNIK_POVEZAV_MS (privzeto 60000, 0 = izklop) vrstica `[povezave] ...`, samo ob prometu.
require("./dnevnik_povezav").zagoniDnevnikPovezav(streznik, stevilkaIzOkolja("DNEVNIK_POVEZAV_MS", 60000, 3600000));
